// server/routes/misc.js
/**
 * Miscellaneous API Routes:
 * - /health: Checks connectivity to dependencies.
 * - /metrics: Exposes Prometheus metrics.
 * - /key-exchange: Provides encryption keys for WebSocket.
 * - DELETE /users/{username}: Allows users to delete their own account.
 * No backslash escapes in template literals.
 */
const express = require('express');
const crypto = require('crypto');
const { param } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { authenticateToken } = require('../middleware');
const db = require('../db');
const { getRedisClient, getStreamRedisClient } = require('../utils/redisClients');
const { validateRequest } = require('../utils/validation');
const { register } = require('../utils/metrics');
const {
  ENCRYPTION_KEY_TTL_SECONDS,
  REDIS_USER_KEY_PREFIX,
  HEALTH_OK,
  HEALTH_ERROR,
  STATUS_OK,
  STATUS_ERROR,
} = require('../config/constants');
const logger = require('../utils/logger');

const router = express.Router();

// --- Rate Limiters ---
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
    status: STATUS_ERROR,
    uptime: process.uptime().toFixed(2),
    redis_main: HEALTH_ERROR,
    redis_stream: HEALTH_ERROR,
    postgres: HEALTH_ERROR,
    timestamp: new Date().toISOString(),
  };

  try {
    try {
      const mainPing = await getRedisClient().ping();
      if (mainPing === 'PONG') healthStatus.redis_main = HEALTH_OK;
    } catch (e) {
      logger.warn('Health check: Main Redis ping failed', { error: e.message });
    }
    try {
      const streamPing = await getStreamRedisClient().ping();
      if (streamPing === 'PONG') healthStatus.redis_stream = HEALTH_OK;
    } catch (e) {
      logger.warn('Health check: Stream Redis ping failed', { error: e.message });
    }
    try {
      await db.query('SELECT 1');
      healthStatus.postgres = HEALTH_OK;
    } catch (e) {
      logger.warn('Health check: PostgreSQL query failed', { error: e.message });
    }

    const isOverallOk =
      healthStatus.redis_main === HEALTH_OK &&
      healthStatus.redis_stream === HEALTH_OK &&
      healthStatus.postgres === HEALTH_OK;

    healthStatus.status = isOverallOk ? STATUS_OK : STATUS_ERROR;
    const httpStatus = isOverallOk ? 200 : 503;

    res.status(httpStatus).json(healthStatus);
  } catch (err) {
    logger.error('Health check execution failed unexpectedly', { error: err.message });
    next(err);
  }
});

/**
 * POST /key-exchange
 * Generates and stores an encryption key for the authenticated user.
 * Requires JWT authentication.
 */
router.post(
  '/key-exchange',
  apiLimiter,
  authenticateToken,
  async (req, res, next) => {
    const username = req.user.username;
    try {
      const key = crypto.randomBytes(32).toString('hex');
      const redisKey = `${username}`; // Corrected interpolation

      await getRedisClient().setex(redisKey, ENCRYPTION_KEY_TTL_SECONDS, key);

      logger.info('Encryption key generated and stored for user', {
        username,
        redisKey: REDIS_USER_KEY_PREFIX + redisKey,
        ttl: ENCRYPTION_KEY_TTL_SECONDS,
      });
      res.json({ key });
    } catch (err) {
      logger.error('Key exchange process failed', { username, error: err.message });
      next(err);
    }
  }
);

/**
 * GET /metrics
 * Exposes application metrics in Prometheus format.
 */
router.get('/metrics', async (req, res, next) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    logger.error('Failed to generate Prometheus metrics', { error: err.message });
    res.status(500).contentType('text/plain').send(`Error generating metrics: ${err.message}`); // Corrected interpolation
  }
});

// --- User Self-Deletion ---
const userDeleteValidationRules = [
  param('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_]+$/) // Corrected regex
    .withMessage('Invalid username format in URL path.'),
];

/**
 * DELETE /users/{username}
 * Allows an authenticated user to delete their own account.
 */
router.delete(
  '/users/:username',
  apiLimiter,
  authenticateToken,
  userDeleteValidationRules,
  validateRequest,
  async (req, res, next) => {
    const targetUsername = req.params.username;
    const requesterUsername = req.user.username;
    const requesterId = req.user.id;

    if (targetUsername !== requesterUsername) {
      logger.warn('User deletion forbidden: Attempt to delete another user account', {
        requester: requesterUsername,
        target: targetUsername,
      });
      return res.status(403).json({ error: 'Forbidden: You can only delete your own account.' });
    }

    try {
      const result = await db.query(
        'DELETE FROM users WHERE id = $1 AND username = $2 RETURNING username',
        [requesterId, targetUsername]
      );

      if (result.rowCount === 0) {
        logger.warn('User deletion failed: User not found in database or ID mismatch', {
          username: targetUsername,
        });
        return res.status(404).json({ error: 'User account not found.' });
      }

      const redisKey = `${targetUsername}`; // Corrected interpolation
      const deletedKeysCount = await getRedisClient().del(redisKey);
      if (deletedKeysCount > 0) {
        logger.info('Deleted user encryption key from Redis', { username: targetUsername });
      } else {
        logger.info('No user encryption key found in Redis to delete (or already expired)', {
          username: targetUsername,
        });
      }

      logger.info('User account deleted successfully', {
        username: targetUsername,
        deletedBy: requesterUsername,
        redisKeysDeleted: deletedKeysCount,
      });
      res.status(200).json({ message: 'User account deleted successfully.' });
    } catch (err) {
      logger.error('User deletion process failed', {
        username: targetUsername,
        error: err.message,
      });
      next(err);
    }
  }
);

module.exports = router;
