// server/websocketManager.js
/**
 * Manages WebSocket connections, authentication, and message broadcasting.
 */
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
// Import the *getter* function, not the client instance directly
const { getRedisClient } = require('./utils/redisClients');
const { websocketConnections } = require('./utils/metrics');
const { JWT_SECRET, REDIS_USER_KEY_PREFIX } = require('./config/constants');
const logger = require('./utils/logger');

// Remove the top-level client retrieval
// const redisClient = getRedisClient(); // <--- REMOVED
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
    let username = 'unknown'; // Default username for logging before auth
    try {
      // 1. Extract token from connection URL
      const requestUrl = new URL(req.url, `ws://${req.headers.host}`);
      const token = requestUrl.searchParams.get('token');

      if (!token) {
        logger.warn('WebSocket connection denied: No token provided.', {
          ip: req.socket.remoteAddress,
        });
        ws.close(1008, 'Token required'); // 1008: Policy Violation
        return;
      }

      // 2. Verify JWT token
      const decoded = jwt.verify(token, JWT_SECRET);
      username = decoded.username; // Assign username after successful verification

      if (!username) {
        throw new Error('Token payload missing username');
      }

      // Attach username to the WebSocket object for later reference
      ws.username = username;

      logger.info('WebSocket client connected and authenticated.', {
        username,
        ip: req.socket.remoteAddress,
      });
      websocketConnections.inc(); // Increment active connections metric

      // 3. Setup event listeners for the authenticated connection
      ws.on('message', (message) => {
        // Log received message (optional, could be noisy)
        // Avoid processing client messages unless specifically designed for it
        logger.debug('WebSocket message received (usually ignored)', {
          username,
          message: message.toString().substring(0, 100), // Log only a snippet
        });
      });

      ws.on('close', (code, reason) => {
        logger.info('WebSocket client disconnected.', {
          username,
          code,
          reason: reason.toString(),
        });
        websocketConnections.dec(); // Decrement active connections metric
      });

      ws.on('error', (err) => {
        logger.error('WebSocket connection error.', { username, error: err.message });
        // Check if connection is still open before decrementing (error might precede close)
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          websocketConnections.dec();
        }
        // No need to close here, 'close' event usually follows 'error'
      });
    } catch (err) {
      // Handle errors during connection setup (e.g., invalid token)
      let closeCode = 1011; // Internal Error default
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
        closeCode = 1008; // Policy Violation
        closeReason = 'Invalid token';
      } else {
        logger.error('WebSocket connection setup error', {
          username,
          error: err.message,
          ip: req.socket.remoteAddress,
        });
      }
      ws.close(closeCode, closeReason);
      // Do not increment websocketConnections if auth fails
    }
  });

  wss.on('error', (err) => {
    // Handle errors on the WebSocket server itself (e.g., port binding issues - less likely here as it attaches to http)
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
    const iv = crypto.randomBytes(16); // Generate a random IV for each encryption
    const key = Buffer.from(keyHex, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(messageString, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    // Return ciphertext and IV together, separated by a colon
    return `${encrypted}:${iv.toString('base64')}`;
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

  // Get the redisClient *inside* the function where it's needed
  const redisClient = getRedisClient();

  const wsMessageString = JSON.stringify(wsMessagePayload);
  let sentCount = 0;
  const totalClients = wss.clients.size;

  if (totalClients === 0) {
    return; // No clients, nothing to do
  }

  logger.debug(`Broadcasting message to ${totalClients} potential clients`, {
    detectorId: wsMessagePayload.detectorId,
    peakCount: wsMessagePayload.detectedPeaks?.length || 0,
    transientType: wsMessagePayload.transientInfo?.type || 'none',
  });

  // Iterate over all connected clients using a standard loop or forEach
  const broadcastPromises = [];
  wss.clients.forEach((ws) => {
    // Check if the connection is open and the client is authenticated (has a username)
    if (ws.readyState === WebSocket.OPEN && ws.username) {
      const userRedisKey = `${ws.username}`; // Prefix handled by Redis client config

      // Asynchronously retrieve key and send message for this client
      const sendPromise = (async () => {
        try {
          // Get client instance HERE
          const keyHex = await redisClient.get(userRedisKey);

          if (keyHex) {
            const encryptedMessage = encryptMessage(wsMessageString, keyHex);
            if (encryptedMessage) {
              // Promisify ws.send for cleaner error handling with Promise.allSettled
              await new Promise((resolve, reject) => {
                ws.send(encryptedMessage, (err) => {
                  if (err) {
                    logger.error('WebSocket send error', {
                      username: ws.username,
                      error: err.message,
                    });
                    reject(err); // Reject promise on send error
                  } else {
                    resolve(); // Resolve on successful send
                  }
                });
              });
              sentCount++; // Increment only if send was successful
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
      })(); // Immediately invoke the async function for this client
      broadcastPromises.push(sendPromise.catch((e) => e)); // Catch individual errors but continue broadcast
    } else {
      logger.debug('WebSocket send skipped: Client not open or not authenticated', {
        username: ws.username || 'N/A',
        state: ws.readyState,
      });
    }
  }); // End loop through clients

  // Wait for all send operations to complete (or fail)
  await Promise.allSettled(broadcastPromises);

  logger.debug(
    `Broadcast attempt complete. Sent successfully to ${sentCount} / ${totalClients} clients.`
  );
}

/**
 * Closes all active WebSocket connections.
 */
function closeAllConnections() {
  if (!wss) return;
  logger.info(`Terminating all (${wss.clients.size}) WebSocket connections...`);
  // Use terminate for immediate, forceful closure during shutdown
  wss.clients.forEach((ws) => {
    ws.terminate();
  });
  logger.info('All WebSocket connections terminated.');
}

module.exports = {
  initializeWebSocketServer,
  broadcastMessage,
  closeAllConnections,
  encryptMessage, // Export for potential testing or other uses
};
