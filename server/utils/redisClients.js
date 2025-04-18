// server/utils/redisClients.js
/**
 * Manages Redis client connections.
 */
const Redis = require('ioredis');
const {
  REDIS_HOST,
  REDIS_PORT,
  REDIS_PASSWORD,
  REDIS_USER_KEY_PREFIX,
  NODE_ENV,
} = require('../config/constants');
const logger = require('./logger'); // Use centralized logger

let redisClient = null;
let streamRedisClient = null;

const commonRedisOptions = {
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
  lazyConnect: true, // Connect explicitly
  retryStrategy: (times) => {
    const delay = Math.min(times * 150, 5000); // Exponential backoff with limit
    logger.warn(`Redis connection retry attempt ${times}. Retrying in ${delay}ms...`);
    return delay;
  },
  reconnectOnError: (err) => {
    logger.error(`Redis reconnect triggered by error: ${err.message}`);
    // Only retry on specific errors if needed, true allows retrying on most errors
    const targetError = 'READONLY'; // Example: Don't retry on cluster readonly error
    if (err.message.includes(targetError)) {
      return false; // Don't retry on this specific error
    }
    return true; // Retry on other errors
  },
  maxRetriesPerRequest: 3, // Limit retries for commands after connection is established
  showFriendlyErrorStack: NODE_ENV !== 'production', // Show better errors in dev
  connectTimeout: 10000, // 10 seconds connection timeout
  enableOfflineQueue: false, // Don't queue commands if connection is down
};

/**
 * Initializes and attempts to connect both Redis clients.
 * Returns a promise that resolves when connections are attempted or rejects on failure.
 * @returns {Promise<void>}
 */
async function initializeRedisClients() {
  // Make the outer function async
  if (redisClient && streamRedisClient) {
    logger.warn('Redis clients already initialized.');
    return; // Return directly if already done
  }

  logger.info('Initializing Redis clients...');

  try {
    // --- Main Client ---
    redisClient = new Redis({
      ...commonRedisOptions,
      keyPrefix: REDIS_USER_KEY_PREFIX,
    });
    redisClient.on('error', (err) =>
      logger.error('Main Redis Client Error', { error: err.message })
    );
    redisClient.on('connect', () => logger.info('Main Redis client connecting...'));
    redisClient.on('ready', () => logger.info('Main Redis client ready.'));
    redisClient.on('close', () => logger.warn('Main Redis client connection closed.'));
    redisClient.on('reconnecting', (delay) =>
      logger.warn(`Main Redis client reconnecting in ${delay}ms...`)
    );

    // --- Stream/History Client ---
    streamRedisClient = new Redis({
      ...commonRedisOptions,
    });
    streamRedisClient.on('error', (err) =>
      logger.error('Stream/History Redis Client Error', { error: err.message })
    );
    streamRedisClient.on('connect', () => logger.info('Stream/History Redis client connecting...'));
    streamRedisClient.on('ready', () => logger.info('Stream/History Redis client ready.'));
    streamRedisClient.on('close', () =>
      logger.warn('Stream/History Redis client connection closed.')
    );
    streamRedisClient.on('reconnecting', (delay) =>
      logger.warn(`Stream/History Redis client reconnecting in ${delay}ms...`)
    );

    // --- Attempt Connections ---
    logger.info('Attempting to connect Redis clients...');
    // Use Promise.all to attempt connections concurrently
    await Promise.all([
      redisClient.connect().catch((err) => {
        logger.error('Main Redis connect() method failed during initialization', {
          error: err.message,
        });
        throw new Error(`Main Redis connection failed: ${err.message}`);
      }),
      streamRedisClient.connect().catch((err) => {
        logger.error('Stream Redis connect() method failed during initialization', {
          error: err.message,
        });
        throw new Error(`Stream/History Redis connection failed: ${err.message}`);
      }),
    ]);

    logger.info('Redis clients initialized and connection attempts initiated successfully.');
    // No explicit resolve needed, successful await means success
  } catch (error) {
    logger.error('Failed to initialize or connect Redis clients', { error: error.message });
    // Attempt cleanup if one client connected but the other failed
    await closeRedisClients().catch(() => {}); // Ignore errors during cleanup on init failure
    throw error; // Re-throw the error to signal failure
  }
}

function getRedisClient() {
  if (!redisClient) {
    throw new Error(
      'FATAL: Main Redis client has not been initialized. Call initializeRedisClients first.'
    );
  }
  return redisClient;
}

function getStreamRedisClient() {
  if (!streamRedisClient) {
    throw new Error(
      'FATAL: Stream/History Redis client has not been initialized. Call initializeRedisClients first.'
    );
  }
  return streamRedisClient;
}

async function closeRedisClients() {
  logger.info('Closing Redis client connections...');
  const promises = [];
  if (redisClient && redisClient.status !== 'end') {
    promises.push(
      redisClient
        .quit()
        .catch((e) =>
          logger.error('Error closing main Redis client gracefully', { error: e.message })
        )
    );
  }
  if (streamRedisClient && streamRedisClient.status !== 'end') {
    promises.push(
      streamRedisClient
        .quit()
        .catch((e) =>
          logger.error('Error closing stream/history Redis client gracefully', { error: e.message })
        )
    );
  }

  if (promises.length > 0) {
    await Promise.allSettled(promises); // Wait for all quit commands to finish or fail
    logger.info('Redis client quit commands completed.');
  } else {
    logger.info('No active Redis clients to close.');
  }

  // Nullify references after attempting closure
  redisClient = null;
  streamRedisClient = null;
}

module.exports = {
  initializeRedisClients,
  getRedisClient,
  getStreamRedisClient,
  closeRedisClients,
};
