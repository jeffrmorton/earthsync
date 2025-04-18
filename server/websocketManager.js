// server/websocketManager.js
/**
 * Manages WebSocket connections, authentication, and message broadcasting.
 * No backslash escapes in template literals.
 */
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { getRedisClient } = require('./utils/redisClients');
const { websocketConnections } = require('./utils/metrics');
const { JWT_SECRET, REDIS_USER_KEY_PREFIX } = require('./config/constants');
const logger = require('./utils/logger');

let wss = null;

/**
 * Initializes the WebSocket server and sets up connection handling.
 * @param {http.Server} httpServer - The HTTP server instance to attach the WebSocket server to.
 */
function initializeWebSocketServer(httpServer) {
  if (wss) {
    logger.warn('WebSocket server already initialized.');
    return wss;
  }

  wss = new WebSocket.Server({ server: httpServer });

  wss.on('connection', async (ws, req) => {
    let username = 'unknown';
    try {
      // 1. Extract token from connection URL
      const requestUrl = new URL(req.url, `ws://${req.headers.host}`); // Corrected interpolation
      const token = requestUrl.searchParams.get('token');

      if (!token) {
        logger.warn('WebSocket connection denied: No token provided.', {
          ip: req.socket.remoteAddress,
        });
        ws.close(1008, 'Token required');
        return;
      }

      // 2. Verify JWT token
      const decoded = jwt.verify(token, JWT_SECRET);
      username = decoded.username;

      if (!username) {
        throw new Error('Token payload missing username');
      }

      ws.username = username;

      logger.info('WebSocket client connected and authenticated.', {
        username,
        ip: req.socket.remoteAddress,
      });
      websocketConnections.inc();

      // 3. Setup event listeners
      ws.on('message', (message) => {
        logger.debug('WebSocket message received (usually ignored)', {
          username,
          message: message.toString().substring(0, 100),
        });
      });

      ws.on('close', (code, reason) => {
        logger.info('WebSocket client disconnected.', {
          username,
          code,
          reason: reason.toString(),
        });
        websocketConnections.dec();
      });

      ws.on('error', (err) => {
        logger.error('WebSocket connection error.', { username, error: err.message });
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          websocketConnections.dec();
        }
      });
    } catch (err) {
      let closeCode = 1011;
      let closeReason = 'Internal server error during connection setup';
      if (err instanceof jwt.TokenExpiredError) {
        logger.warn('WebSocket connection failed: Token expired', {
          error: err.message,
          ip: req.socket.remoteAddress,
        });
        closeCode = 1008;
        closeReason = 'Token expired';
      } else if (err instanceof jwt.JsonWebTokenError) {
        logger.warn('WebSocket connection failed: Invalid token format/signature', {
          error: err.message,
          ip: req.socket.remoteAddress,
        });
        closeCode = 1008;
        closeReason = 'Invalid token';
      } else {
        logger.error('WebSocket connection setup error', {
          username,
          error: err.message,
          ip: req.socket.remoteAddress,
        });
      }
      ws.close(closeCode, closeReason);
    }
  });

  wss.on('error', (err) => {
    logger.error('WebSocket Server Instance Error', { error: err.message });
  });

  logger.info('WebSocket server initialized and attached to HTTP server.');
  return wss;
}

/**
 * Encrypts a message using AES-256-CBC.
 * @param {string} messageString - The message to encrypt.
 * @param {string} keyHex - The encryption key in hex format.
 * @returns {string|null} Encrypted message in "ciphertext:iv" format (Base64 encoded), or null on error.
 */
function encryptMessage(messageString, keyHex) {
  try {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(keyHex, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(messageString, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return `${encrypted}:${iv.toString('base64')}`; // Corrected interpolation
  } catch (error) {
    logger.error('Message encryption failed', { error: error.message });
    return null;
  }
}

/**
 * Broadcasts a processed data message to all authenticated WebSocket clients.
 * Retrieves user-specific encryption keys from Redis.
 * @param {object} wsMessagePayload - The payload object to broadcast (contains first spectrum results).
 */
async function broadcastMessage(wsMessagePayload) {
  if (!wss) {
    logger.warn('Cannot broadcast message: WebSocket server not initialized.');
    return;
  }

  const redisClient = getRedisClient();
  const wsMessageString = JSON.stringify(wsMessagePayload);
  let sentCount = 0;
  const totalClients = wss.clients.size;

  if (totalClients === 0) {
    return;
  }

  logger.debug(`Broadcasting message to ${totalClients} potential clients`, { // Corrected interpolation
    detectorId: wsMessagePayload.detectorId,
    peakCount: wsMessagePayload.detectedPeaks?.length || 0,
    transientType: wsMessagePayload.transientInfo?.type || 'none',
  });

  const broadcastPromises = [];
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN && ws.username) {
      const userRedisKey = `${ws.username}`; // Corrected interpolation

      const sendPromise = (async () => {
        try {
          const keyHex = await redisClient.get(userRedisKey);

          if (keyHex) {
            const encryptedMessage = encryptMessage(wsMessageString, keyHex);
            if (encryptedMessage) {
              await new Promise((resolve, reject) => {
                ws.send(encryptedMessage, (err) => {
                  if (err) {
                    logger.error('WebSocket send error', {
                      username: ws.username,
                      error: err.message,
                    });
                    reject(err);
                  } else {
                    resolve();
                  }
                });
              });
              sentCount++;
            } else {
              logger.warn('WebSocket send skipped: Encryption error', { username: ws.username });
            }
          } else {
            logger.warn('WebSocket send skipped: No encryption key found in Redis', {
              username: ws.username,
              redisKey: REDIS_USER_KEY_PREFIX + userRedisKey,
            });
          }
        } catch (redisErr) {
          logger.error('WebSocket send skipped: Redis error getting encryption key', {
            username: ws.username,
            error: redisErr.message,
          });
        }
      })();
      broadcastPromises.push(sendPromise.catch((e) => e));
    } else {
      logger.debug('WebSocket send skipped: Client not open or not authenticated', {
        username: ws.username || 'N/A',
        state: ws.readyState,
      });
    }
  });

  await Promise.allSettled(broadcastPromises);

  logger.debug(
    `Broadcast attempt complete. Sent successfully to ${sentCount} / ${totalClients} clients.` // Corrected interpolation
  );
}

/**
 * Closes all active WebSocket connections.
 */
function closeAllConnections() {
  if (!wss) return;
  logger.info(`Terminating all (${wss.clients.size}) WebSocket connections...`); // Corrected interpolation
  wss.clients.forEach((ws) => {
    ws.terminate();
  });
  logger.info('All WebSocket connections terminated.');
}

module.exports = {
  initializeWebSocketServer,
  broadcastMessage,
  closeAllConnections,
  encryptMessage,
};
