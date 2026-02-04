// server/routes/ingest.js
/**
 * API Route for Data Ingest using X-API-Key authentication.
 */
const express = require('express');
const { header, body } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { authenticateApiKey } = require('../utils/auth'); // Assuming an auth helper utility
const { validateRequest } = require('../utils/validation');
// Import the *getter* function only
const { getStreamRedisClient } = require('../utils/redisClients');
const { RAW_FREQUENCY_POINTS, REDIS_SPECTROGRAM_STREAM_KEY } = require('../config/constants'); // Use centralized constants
const { dataIngestCounter } = require('../utils/metrics'); // Assuming metrics are centralized
const logger = require('../utils/logger');

const router = express.Router();
// Removed top-level client retrieval
// const streamRedisClient = getStreamRedisClient();

// --- Rate Limiter ---
const ingestLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // limit each IP/key? to 120 requests per windowMs
  message: { error: 'Too many ingest requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.headers['x-api-key'] || req.ip, // Rate limit by API key if present, else IP
});

// --- Validation Rules ---
const ingestValidationRules = [
  // Header validation for API Key (presence checked by authenticateApiKey middleware)
  header('x-api-key')
    .notEmpty()
    .withMessage('API key is required in X-API-Key header.')
    .isString()
    .withMessage('API key must be a string.'), // Basic type check

  // Body validation rules
  body('detectorId')
    .isString()
    .trim()
    .notEmpty()
    .withMessage('detectorId is required and cannot be empty.')
    .isLength({ min: 1, max: 50 })
    .withMessage('detectorId must be between 1 and 50 characters.'),

  body('timestamp')
    .optional() // Timestamp is optional, defaults to server time if not provided
    .isISO8601()
    .withMessage('If provided, timestamp must be a valid ISO 8601 date string.'),

  body('location').isObject().withMessage('location object (with lat, lon) is required.'),
  body('location.lat')
    .exists({ checkFalsy: false }) // Allow 0 latitude
    .withMessage('location.lat is required.')
    .isFloat({ min: -90, max: 90 })
    .withMessage('Invalid latitude value (must be between -90 and 90).'),
  body('location.lon')
    .exists({ checkFalsy: false }) // Allow 0 longitude
    .withMessage('location.lon is required.')
    .isFloat({ min: -180, max: 180 })
    .withMessage('Invalid longitude value (must be between -180 and 180).'),

  body('spectrograms')
    .isArray({ min: 1 }) // Must be an array with at least one spectrogram
    .withMessage('spectrograms array (batch) containing at least one spectrogram is required.'),

  // Validation for each element within the 'spectrograms' array
  body('spectrograms.*')
    .isArray({ min: RAW_FREQUENCY_POINTS, max: RAW_FREQUENCY_POINTS })
    .withMessage(
      `Each spectrogram in the batch must be an array with exactly ${RAW_FREQUENCY_POINTS} data points.`
    ),

  // Validation for each number within each spectrogram array
  body('spectrograms.*.*')
    .isFloat({ min: 0 }) // Ensure values are numbers and non-negative
    .withMessage('Spectrogram amplitude values must be non-negative numbers.'),

  // Optional: Custom validation example (e.g., check max amplitude)
  body().custom((value) => {
    const spectrograms = value.spectrograms || [];
    let maxAmplitude = 0;
    // Iterate safely, checking if elements are arrays/numbers
    for (const spec of spectrograms) {
      if (Array.isArray(spec)) {
        for (const amp of spec) {
          if (typeof amp === 'number' && amp > maxAmplitude) {
            maxAmplitude = amp;
          }
        }
      }
    }
    // Example threshold - adjust as necessary
    if (maxAmplitude > 10000) {
      // Example threshold
      throw new Error(
        `Maximum amplitude (${maxAmplitude.toFixed(1)}) in batch exceeds acceptable limit (10000).`
      );
    }
    return true; // Indicate validation passed
  }),
];

// --- Route Definition ---

/**
 * POST /data-ingest
 * Endpoint for external sources to push raw spectrogram data batches.
 * Requires X-API-Key header for authentication.
 */
router.post(
  '/', // Mounted at /api/data-ingest by server.js
  ingestLimiter, // Apply rate limiting
  authenticateApiKey, // Check API key first
  ingestValidationRules, // Apply validation rules to the request body
  validateRequest, // Handle any validation errors
  async (req, res, next) => {
    // Main route handler
    const { detectorId, location, spectrograms } = req.body;
    // Use provided timestamp or default to current server time if missing
    const timestamp = req.body.timestamp || new Date().toISOString();
    const streamKey = REDIS_SPECTROGRAM_STREAM_KEY; // Use constant for stream name

    // Prepare the message payload matching the structure expected by the processor
    const messagePayload = {
      detectorId,
      timestamp,
      location,
      spectrogram: spectrograms, // Pass the raw batch as received
      interval: 0, // Indicate this is from ingest API, not a timed detector simulation
    };
    const messageString = JSON.stringify(messagePayload);

    try {
      // Get client instance *inside* the handler
      const streamRedisClient = getStreamRedisClient();
      // Add the message to the Redis stream using XADD
      // '*' tells Redis to auto-generate the message ID
      const messageId = await streamRedisClient.xadd(streamKey, '*', 'data', messageString);

      logger.info('Data batch ingested successfully to stream via API', {
        detectorId,
        batchSize: spectrograms.length,
        messageId, // Log the Redis message ID
        source: 'api_ingest',
      });
      dataIngestCounter.inc({ status: 'success' }); // Increment success counter metric
      // Respond with 202 Accepted as processing happens asynchronously
      res.status(202).json({ message: 'Data batch accepted for processing.', messageId });
    } catch (err) {
      logger.error('Data ingest via API failed: Could not add to Redis stream', {
        detectorId,
        error: err.message,
        source: 'api_ingest',
      });
      dataIngestCounter.inc({ status: 'error' }); // Increment error counter metric

      // Pass the error to the centralized error handling middleware
      next(err);
    }
  }
);

module.exports = router; // Export the router instance
