// server/routes/misc.js
/**
 * Miscellaneous API Routes:
 * - /health: Checks connectivity to dependencies.
 * - /metrics: Exposes Prometheus metrics.
 * - /key-exchange: Provides encryption keys for WebSocket.
 * - DELETE /users/{username}: Allows users to delete their own account.
 */
const express = require('express');
const crypto = require('crypto');
const { param } = require('express-validator');
const rateLimit = require('express-rate-limit');
// Remove direct imports of promClient registry if using centralized metrics
// const promClient = require('prom-client');
const { authenticateToken } = require('../middleware');
const db = require('../db');
// Import getter functions instead of direct clients
const { getRedisClient, getStreamRedisClient } = require('../utils/redisClients');
const { validateRequest } = require('../utils/validation');
// Import registry from centralized metrics utility
const { register } = require('../utils/metrics');
const {
  ENCRYPTION_KEY_TTL_SECONDS,
  REDIS_USER_KEY_PREFIX, // Used for logging clarity only
  HEALTH_OK,
  HEALTH_ERROR,
  STATUS_OK,
  STATUS_ERROR,
} = require('../config/constants');
const logger = require('../utils/logger');

const router = express.Router();
// Removed unused direct client assignments
// const redisClient = getRedisClient();
// const streamRedisClient = getStreamRedisClient();

// --- Rate Limiters ---
// General API limiter for less sensitive endpoints
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many API requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Routes ---

/**
 * GET /health
 * Checks the status of the server and its dependencies (Redis, PostgreSQL).
 */
router.get('/health', async (req, res, next) => {
  const healthStatus = {
    status: STATUS_ERROR, // Default to error
    uptime: process.uptime().toFixed(2),
    redis_main: HEALTH_ERROR,
    redis_stream: HEALTH_ERROR,
    postgres: HEALTH_ERROR,
    timestamp: new Date().toISOString(),
  };

  try {
    // Check Main Redis using getter
    try {
      const mainPing = await getRedisClient().ping();
      if (mainPing === 'PONG') healthStatus.redis_main = HEALTH_OK;
    } catch (e) {
      logger.warn('Health check: Main Redis ping failed', { error: e.message });
    }

    // Check Stream Redis using getter
    try {
      const streamPing = await getStreamRedisClient().ping();
      if (streamPing === 'PONG') healthStatus.redis_stream = HEALTH_OK;
    } catch (e) {
      logger.warn('Health check: Stream Redis ping failed', { error: e.message });
    }

    // Check PostgreSQL
    try {
      await db.query('SELECT 1');
      healthStatus.postgres = HEALTH_OK;
    } catch (e) {
      logger.warn('Health check: PostgreSQL query failed', { error: e.message });
    }

    // Determine overall status
    const isOverallOk =
      healthStatus.redis_main === HEALTH_OK &&
      healthStatus.redis_stream === HEALTH_OK &&
      healthStatus.postgres === HEALTH_OK;

    healthStatus.status = isOverallOk ? STATUS_OK : STATUS_ERROR;
    const httpStatus = isOverallOk ? 200 : 503; // Return 503 Service Unavailable if deps fail

    res.status(httpStatus).json(healthStatus);
  } catch (err) {
    // Catch unexpected errors during the health check execution itself
    logger.error('Health check execution failed unexpectedly', { error: err.message });
    next(err); // Pass to centralized handler
  }
});

/**
 * POST /key-exchange
 * Generates and stores an encryption key for the authenticated user.
 * Requires JWT authentication.
 */
router.post(
  '/key-exchange',
  apiLimiter, // Apply general API rate limit
  authenticateToken, // Require valid JWT
  async (req, res, next) => {
    const username = req.user.username; // Provided by authenticateToken middleware
    try {
      // Generate a new random AES-256 key (32 bytes)
      const key = crypto.randomBytes(32).toString('hex');
      // Redis key for storing the user's encryption key (prefix applied by client)
      const redisKey = `${username}`;

      // Store the key in Redis with an expiration time (Time-To-Live)
      // Use getter function to access the client instance
      await getRedisClient().setex(redisKey, ENCRYPTION_KEY_TTL_SECONDS, key);

      logger.info('Encryption key generated and stored for user', {
        username,
        redisKey: REDIS_USER_KEY_PREFIX + redisKey, // Log full key for debugging
        ttl: ENCRYPTION_KEY_TTL_SECONDS,
      });
      // Return the generated key to the client
      res.json({ key });
    } catch (err) {
      logger.error('Key exchange process failed', { username, error: err.message });
      next(err); // Pass error to centralized handler
    }
  }
);

/**
 * GET /metrics
 * Exposes application metrics in Prometheus format.
 */
router.get('/metrics', async (req, res, next) => {
  try {
    // Set the content type for Prometheus scrape endpoint
    res.set('Content-Type', register.contentType);
    // End the response with the metrics collected by the registry
    res.end(await register.metrics());
  } catch (err) {
    logger.error('Failed to generate Prometheus metrics', { error: err.message });
    // Send a plain text error if metrics generation fails
    res.status(500).contentType('text/plain').send(`Error generating metrics: ${err.message}`);
    // Do not call next() here as we've already sent a response
  }
});

// --- User Self-Deletion ---
const userDeleteValidationRules = [
  param('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_]+$/) // Consistent with registration validation
    .withMessage('Invalid username format in URL path.'),
];

/**
 * DELETE /users/{username}
 * Allows an authenticated user to delete their own account.
 */
router.delete(
  '/users/:username',
  apiLimiter, // Apply general API rate limit
  authenticateToken, // Require valid JWT
  userDeleteValidationRules,
  validateRequest, // Handle validation errors
  async (req, res, next) => {
    const targetUsername = req.params.username;
    const requesterUsername = req.user.username; // From JWT token
    const requesterId = req.user.id; // From JWT token

    // --- Authorization Check ---
    // Ensure the authenticated user matches the username in the path
    if (targetUsername !== requesterUsername) {
      logger.warn('User deletion forbidden: Attempt to delete another user account', {
        requester: requesterUsername,
        target: targetUsername,
      });
      // Return 403 Forbidden
      return res.status(403).json({ error: 'Forbidden: You can only delete your own account.' });
    }

    try {
      // --- Database Deletion ---
      // Delete the user record, ensuring ID also matches for extra safety
      const result = await db.query(
        'DELETE FROM users WHERE id = $1 AND username = $2 RETURNING username',
        [requesterId, targetUsername]
      );

      // Check if a row was actually deleted
      if (result.rowCount === 0) {
        // This case should be rare if authentication/path validation passed, but handles edge cases
        logger.warn('User deletion failed: User not found in database or ID mismatch', {
          username: targetUsername,
        });
        return res.status(404).json({ error: 'User account not found.' });
      }

      // --- Redis Key Deletion ---
      // Attempt to delete the corresponding encryption key from Redis
      const redisKey = `${targetUsername}`; // Prefix handled by client
      // Use getter function to access client
      const deletedKeysCount = await getRedisClient().del(redisKey);
      if (deletedKeysCount > 0) {
        logger.info('Deleted user encryption key from Redis', { username: targetUsername });
      } else {
        logger.info('No user encryption key found in Redis to delete (or already expired)', {
          username: targetUsername,
        });
      }

      // --- Success ---
      logger.info('User account deleted successfully', {
        username: targetUsername,
        deletedBy: requesterUsername, // Log who performed the action
        redisKeysDeleted: deletedKeysCount,
      });
      res.status(200).json({ message: 'User account deleted successfully.' });
    } catch (err) {
      logger.error('User deletion process failed', {
        username: targetUsername,
        error: err.message,
      });
      next(err); // Pass error to centralized handler
    }
  }
);

module.exports = router; // Export the router instance
