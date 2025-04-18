// server/routes/history.js
/**
 * API Routes for retrieving historical data (Spectrograms, Peaks)
 */
const express = require('express');
const { param, query: queryValidator } = require('express-validator');
const { authenticateToken } = require('../middleware'); // JWT Auth middleware
const db = require('../db'); // DB access
// Import the *getter* function only
const { getStreamRedisClient } = require('../utils/redisClients');
const { validateRequest } = require('../utils/validation'); // Validation helper
const {
  REDIS_SPEC_RETENTION_MS,
  REDIS_PEAK_RETENTION_MS,
  REDIS_SPEC_HISTORY_PREFIX,
  REDIS_PEAK_HISTORY_PREFIX,
  REDIS_HISTORY_CACHE_PREFIX,
  // STATUS_OK, // Not directly used here
  // STATUS_ERROR, // Not directly used here
} = require('../config/constants'); // Centralized constants
const logger = require('../utils/logger'); // Centralized logger

const router = express.Router();
// Removed top-level client retrieval
// const streamRedisClient = getStreamRedisClient();

// --- Validation Rules ---
const historyHoursValidationRules = [
  param('hours')
    .isInt({ min: 1, max: 168 })
    .withMessage('Hours must be between 1 and 168 (7 days).'),
  queryValidator('detectorId')
    .optional()
    .isString()
    .trim()
    .notEmpty()
    .isLength({ min: 1, max: 50 })
    .withMessage('Invalid detector ID format (must be 1-50 chars).'),
];

const historyRangeValidationRules = [
  queryValidator('startTime')
    .isISO8601()
    .withMessage('startTime must be a valid ISO 8601 date string.'),
  queryValidator('endTime')
    .isISO8601()
    .withMessage('endTime must be a valid ISO 8601 date string.'),
  queryValidator('detectorId')
    .optional()
    .isString()
    .trim()
    .notEmpty()
    .isLength({ min: 1, max: 50 })
    .withMessage('Invalid detector ID format (must be 1-50 chars).'),
  // Custom validator for time range logic
  queryValidator().custom((value, { req }) => {
    const { startTime, endTime } = req.query;
    if (!startTime || !endTime) {
      throw new Error('Both startTime and endTime query parameters are required for range query.');
    }
    const startMs = new Date(startTime).getTime();
    const endMs = new Date(endTime).getTime();
    if (isNaN(startMs) || isNaN(endMs)) {
      throw new Error('Invalid date format provided for startTime or endTime.');
    }
    if (endMs <= startMs) {
      throw new Error('endTime must be strictly after startTime.');
    }
    const maxRangeMs = 31 * 24 * 60 * 60 * 1000; // Example: 31 days
    if (endMs - startMs > maxRangeMs) {
      throw new Error(
        `Time range cannot exceed 31 days. Requested range: ${((endMs - startMs) / (1000 * 60 * 60 * 24)).toFixed(1)} days.`
      );
    }
    return true;
  }),
];

// --- Helper Functions ---

/** Parses query parameters to get standardized time range */
function getQueryTimeRange(hours, startTimeStr, endTimeStr) {
  let startTimeMs, endTimeMs;
  let rangeIdentifier;

  if (startTimeStr && endTimeStr) {
    startTimeMs = new Date(startTimeStr).getTime();
    endTimeMs = new Date(endTimeStr).getTime();
    rangeIdentifier = `${startTimeMs}_${endTimeMs}`;
  } else if (hours) {
    endTimeMs = Date.now();
    startTimeMs = endTimeMs - hours * 60 * 60 * 1000;
    rangeIdentifier = `h${hours}`;
  } else {
    endTimeMs = Date.now();
    startTimeMs = endTimeMs - 1 * 60 * 60 * 1000;
    rangeIdentifier = 'h1_default';
    logger.warn('getQueryTimeRange called without valid hours or range, using default 1h.');
  }
  return { startTimeMs, endTimeMs, rangeIdentifier };
}

/** Fetches combined spectrogram history from Redis and DB */
async function fetchCombinedSpectrogramHistory(startTimeMs, endTimeMs, detectorId = null) {
  const queryId = `spec-${detectorId || 'all'}-${startTimeMs}-${endTimeMs}`;
  logger.debug(`[${queryId}] Fetching combined spectrogram history...`);
  const redisBoundaryMs = Date.now() - REDIS_SPEC_RETENTION_MS;
  let redisResults = [];
  let dbResults = [];
  const redisStartTimeMs = Math.max(startTimeMs, redisBoundaryMs);
  // Get client instance inside function
  const streamRedisClient = getStreamRedisClient();

  // --- Fetch from Redis ---
  if (endTimeMs >= redisStartTimeMs) {
    const historyKeyPattern = detectorId
      ? `${REDIS_SPEC_HISTORY_PREFIX}${detectorId}`
      : `${REDIS_SPEC_HISTORY_PREFIX}*`;
    try {
      const historyKeys = await streamRedisClient.keys(historyKeyPattern);
      if (historyKeys.length > 0) {
        const fetchPromises = historyKeys.map((key) => streamRedisClient.lrange(key, 0, -1));
        const allRecordsNested = await Promise.all(fetchPromises);
        const allRecords = allRecordsNested.flat();

        redisResults = allRecords
          .map((r) => {
            try {
              const parsed = JSON.parse(r);
              if (!parsed?.timestamp) return null;
              const t = new Date(parsed.timestamp).getTime();
              if (t < redisStartTimeMs || t > endTimeMs) return null;
              if (detectorId && parsed.detectorId !== detectorId) return null;

              const resultsArray = Array.isArray(parsed.processingResults)
                ? parsed.processingResults
                : [];
              const downsampledBatch = Array.isArray(parsed.spectrogram) ? parsed.spectrogram : [];

              return downsampledBatch.map((specData, index) => {
                const procResult = resultsArray[index] || {
                  transientInfo: { type: 'none', details: null },
                };
                return {
                  detectorId: parsed.detectorId,
                  ts: t,
                  location: parsed.location,
                  spectrogram: specData || [],
                  transientInfo: procResult.transientInfo || { type: 'none', details: null },
                };
              });
            } catch (e) {
              logger.warn(`[${queryId}] Failed to parse spectrogram record from Redis`, {
                key: 'N/A',
                recordStart: r?.substring(0, 50),
                error: e.message,
              });
              return null;
            }
          })
          .flat()
          .filter((r) => r !== null);

        logger.debug(
          `[${queryId}] Fetched ${redisResults.length} valid spectrogram records from ${historyKeys.length} Redis keys.`
        );
      } else {
        logger.debug(`[${queryId}] No Redis keys found matching pattern: ${historyKeyPattern}`);
      }
    } catch (redisErr) {
      logger.error(`[${queryId}] Error fetching spectrograms from Redis`, {
        pattern: historyKeyPattern,
        error: redisErr.message,
      });
    }
  } else {
    logger.debug(
      `[${queryId}] Skipping Redis spectrogram fetch, entire range is before retention boundary.`
    );
  }

  // --- Fetch from Database ---
  if (startTimeMs < redisBoundaryMs) {
    const dbStartTimeISO = new Date(startTimeMs).toISOString();
    const dbEndTimeISO = new Date(redisBoundaryMs).toISOString();
    try {
      let queryText = `SELECT detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details FROM historical_spectrograms WHERE "timestamp" >= $1 AND "timestamp" < $2`;
      const queryParams = [dbStartTimeISO, dbEndTimeISO];
      if (detectorId) {
        queryText += ` AND detector_id = $3`;
        queryParams.push(detectorId);
      }
      queryText += ` ORDER BY "timestamp" ASC`;

      const dbRes = await db.query(queryText, queryParams);
      dbResults = dbRes.rows.map((row) => {
        const spectrogramData = Array.isArray(row.spectrogram_data) ? row.spectrogram_data : [];
        return {
          detectorId: row.detector_id,
          ts: row.timestamp.getTime(),
          location: { lat: row.location_lat, lon: row.location_lon },
          spectrogram: spectrogramData,
          transientInfo: {
            type: row.transient_detected
              ? row.transient_details?.toLowerCase().includes('broadband')
                ? 'broadband'
                : row.transient_details
                  ? 'narrowband'
                  : 'unknown'
              : 'none',
            details: row.transient_details,
          },
        };
      });
      logger.debug(`[${queryId}] Fetched ${dbResults.length} spectrogram records from DB.`);
    } catch (dbErr) {
      logger.error(`[${queryId}] Error querying historical spectrograms from DB`, {
        error: dbErr.message,
      });
    }
  } else {
    logger.debug(
      `[${queryId}] Skipping DB spectrogram fetch, entire range is within Redis retention.`
    );
  }

  // --- Combine and Group Results ---
  const combinedResults = [...dbResults, ...redisResults];
  combinedResults.sort((a, b) => a.ts - b.ts || a.detectorId.localeCompare(b.detectorId));

  const groupedData = combinedResults.reduce((acc, r) => {
    if (!r.detectorId || !r.spectrogram || !r.location || typeof r.ts !== 'number') {
      logger.warn(`[${queryId}] Skipping invalid record during grouping`, { record: r });
      return acc;
    }
    const detId = r.detectorId;
    acc[detId] = acc[detId] || { detectorId: detId, location: r.location, dataPoints: [] };
    acc[detId].dataPoints.push({
      ts: r.ts,
      spectrogram: r.spectrogram,
      transientInfo: r.transientInfo,
    });
    return acc;
  }, {});

  logger.debug(
    `[${queryId}] Finished combining/grouping spectrogram history. Found data for ${Object.keys(groupedData).length} detectors.`
  );
  return Object.values(groupedData);
}

/** Fetches combined peak history from Redis and DB */
async function fetchCombinedPeakHistory(startTimeMs, endTimeMs, detectorId = null) {
  const queryId = `peak-${detectorId || 'all'}-${startTimeMs}-${endTimeMs}`;
  logger.debug(`[${queryId}] Fetching combined peak history...`);
  const redisBoundaryMs = Date.now() - REDIS_PEAK_RETENTION_MS;
  let redisPeakResults = [];
  let dbPeakResults = [];
  const redisStartTimeMs = Math.max(startTimeMs, redisBoundaryMs);
  // Get client instance inside function
  const streamRedisClient = getStreamRedisClient();

  // --- Fetch from Redis ---
  if (endTimeMs >= redisStartTimeMs) {
    const peakKeyPattern = detectorId
      ? `${REDIS_PEAK_HISTORY_PREFIX}${detectorId}`
      : `${REDIS_PEAK_HISTORY_PREFIX}*`;
    try {
      const peakKeys = await streamRedisClient.keys(peakKeyPattern);
      if (peakKeys.length > 0) {
        const fetchPromises = peakKeys.map(async (key) => {
          const detId = key.substring(REDIS_PEAK_HISTORY_PREFIX.length);
          const peakStringsWithScores = await streamRedisClient.zrangebyscore(
            key,
            redisStartTimeMs,
            endTimeMs,
            'WITHSCORES'
          );
          const peaksWithTs = [];
          for (let i = 0; i < peakStringsWithScores.length; i += 2) {
            try {
              const score = parseInt(peakStringsWithScores[i + 1], 10);
              if (score >= redisStartTimeMs && score <= endTimeMs) {
                peaksWithTs.push({
                  ts: score,
                  peaks: JSON.parse(peakStringsWithScores[i]),
                });
              }
            } catch (e) {
              logger.warn(`[${queryId}] Failed to parse peak data from Redis`, {
                key,
                score: peakStringsWithScores[i + 1],
              });
            }
          }
          return { detectorId: detId, peaks: peaksWithTs.filter((p) => p.peaks?.length > 0) };
        });
        redisPeakResults = (await Promise.all(fetchPromises)).filter((d) => d.peaks.length > 0);
        logger.debug(
          `[${queryId}] Fetched ${redisPeakResults.reduce((sum, d) => sum + d.peaks.length, 0)} valid peak entries from ${peakKeys.length} Redis keys.`
        );
      } else {
        logger.debug(`[${queryId}] No Redis keys found matching pattern: ${peakKeyPattern}`);
      }
    } catch (redisErr) {
      logger.error(`[${queryId}] Error fetching peaks from Redis`, {
        pattern: peakKeyPattern,
        error: redisErr.message,
      });
    }
  } else {
    logger.debug(
      `[${queryId}] Skipping Redis peak fetch, entire range is before retention boundary.`
    );
  }

  // --- Fetch from Database ---
  if (startTimeMs < redisBoundaryMs) {
    const dbStartTimeISO = new Date(startTimeMs).toISOString();
    const dbEndTimeISO = new Date(redisBoundaryMs).toISOString();
    try {
      let queryText = `SELECT detector_id, "timestamp", peak_data FROM historical_peaks WHERE "timestamp" >= $1 AND "timestamp" < $2`;
      const queryParams = [dbStartTimeISO, dbEndTimeISO];
      if (detectorId) {
        queryText += ` AND detector_id = $3`;
        queryParams.push(detectorId);
      }
      queryText += ` ORDER BY detector_id ASC, "timestamp" ASC`;

      const dbRes = await db.query(queryText, queryParams);
      const dbResultsGrouped = dbRes.rows.reduce((acc, row) => {
        const dId = row.detector_id;
        const peaksArray = Array.isArray(row.peak_data) ? row.peak_data : [];
        if (peaksArray.length > 0) {
          acc[dId] = acc[dId] || { detectorId: dId, peaks: [] };
          acc[dId].peaks.push({ ts: row.timestamp.getTime(), peaks: peaksArray });
        }
        return acc;
      }, {});
      dbPeakResults = Object.values(dbResultsGrouped);
      logger.debug(
        `[${queryId}] Fetched ${dbPeakResults.reduce((sum, d) => sum + d.peaks.length, 0)} valid peak entries from DB.`
      );
    } catch (dbErr) {
      logger.error(`[${queryId}] Error querying historical peaks from DB`, {
        error: dbErr.message,
      });
    }
  } else {
    logger.debug(`[${queryId}] Skipping DB peak fetch, entire range is within Redis retention.`);
  }

  // --- Combine and Sort Results ---
  const combinedResultsMap = {};
  dbPeakResults.forEach((d) => {
    combinedResultsMap[d.detectorId] = { detectorId: d.detectorId, peaks: [...d.peaks] };
  });
  redisPeakResults.forEach((d) => {
    if (combinedResultsMap[d.detectorId]) {
      combinedResultsMap[d.detectorId].peaks.push(...d.peaks);
    } else {
      combinedResultsMap[d.detectorId] = { detectorId: d.detectorId, peaks: [...d.peaks] };
    }
  });
  Object.values(combinedResultsMap).forEach((d) => d.peaks.sort((a, b) => a.ts - b.ts));

  logger.debug(
    `[${queryId}] Finished combining/grouping peak history. Found data for ${Object.keys(combinedResultsMap).length} detectors.`
  );
  return Object.values(combinedResultsMap);
}

// --- Routes ---

// GET /history/hours/:hours
router.get(
  '/hours/:hours',
  authenticateToken, // Apply JWT authentication
  historyHoursValidationRules,
  validateRequest, // Handle validation errors
  async (req, res, next) => {
    const hours = parseInt(req.params.hours, 10);
    const { detectorId } = req.query;
    const username = req.user.username; // Available from authenticateToken middleware
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(hours, null, null);
    // Construct cache key
    const cacheKey = `${REDIS_HISTORY_CACHE_PREFIX}spec_struct_v2:${rangeIdentifier}:${detectorId || 'all'}`;
    // Get client instance inside handler
    const streamRedisClient = getStreamRedisClient();

    try {
      // Check cache first
      const cached = await streamRedisClient.get(cacheKey);
      if (cached) {
        logger.info('Serving structured spec history from cache (hours)', { cacheKey, username });
        // Send cached data directly (assuming it's stored as JSON string)
        return res.contentType('application/json').send(cached);
      }

      // Cache miss, fetch from storage
      logger.info('Fetching structured spec history from storage (hours)', {
        cacheKey,
        hours,
        detectorId,
        username,
      });
      const finalResult = await fetchCombinedSpectrogramHistory(startTimeMs, endTimeMs, detectorId);

      // Cache the result if data was found
      if (finalResult.length > 0) {
        // Cache result for 5 minutes (300 seconds)
        await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult));
        logger.info('Cached structured spec historical data (hours)', { cacheKey });
      } else {
        logger.info('No structured spec historical data found to cache (hours)', { cacheKey });
      }
      res.json(finalResult);
    } catch (err) {
      logger.error('Spectrogram history fetch error (hours)', {
        username,
        hours,
        detectorId,
        error: err.message,
      });
      next(err); // Pass to centralized error handler
    }
  }
);

// GET /history/range
router.get(
  '/range',
  authenticateToken,
  historyRangeValidationRules,
  validateRequest,
  async (req, res, next) => {
    const { startTime, endTime, detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(null, startTime, endTime);
    const cacheKey = `${REDIS_HISTORY_CACHE_PREFIX}spec_struct_v2:${rangeIdentifier}:${detectorId || 'all'}`;
    // Get client instance inside handler
    const streamRedisClient = getStreamRedisClient();

    try {
      const cached = await streamRedisClient.get(cacheKey);
      if (cached) {
        logger.info('Serving structured spec history from cache (range)', { cacheKey, username });
        return res.contentType('application/json').send(cached);
      }

      logger.info('Fetching structured spec history from storage (range)', {
        cacheKey,
        start: startTime,
        end: endTime,
        detectorId,
        username,
      });
      const finalResult = await fetchCombinedSpectrogramHistory(startTimeMs, endTimeMs, detectorId);

      if (finalResult.length > 0) {
        await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult));
        logger.info('Cached structured spec historical data (range)', { cacheKey });
      } else {
        logger.info('No structured spec historical data found to cache (range)', { cacheKey });
      }
      res.json(finalResult);
    } catch (err) {
      logger.error('Spectrogram history fetch error (range)', {
        username,
        detectorId,
        startTime,
        endTime,
        error: err.message,
      });
      next(err);
    }
  }
);

// GET /history/peaks/hours/:hours
router.get(
  '/peaks/hours/:hours',
  authenticateToken,
  historyHoursValidationRules,
  validateRequest,
  async (req, res, next) => {
    const hours = parseInt(req.params.hours, 10);
    const { detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(hours, null, null);
    const cacheKey = `${REDIS_HISTORY_CACHE_PREFIX}peaks:${rangeIdentifier}:${detectorId || 'all'}`;
    // Get client instance inside handler
    const streamRedisClient = getStreamRedisClient();

    try {
      const cached = await streamRedisClient.get(cacheKey);
      if (cached) {
        logger.info('Serving peak history from cache (hours)', { cacheKey, username });
        return res.contentType('application/json').send(cached);
      }
      logger.info('Fetching peak history from storage (hours)', {
        cacheKey,
        hours,
        detectorId,
        username,
      });
      const finalResult = await fetchCombinedPeakHistory(startTimeMs, endTimeMs, detectorId);
      if (finalResult.length > 0) {
        await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult));
        logger.info('Cached combined peak historical data (hours)', { cacheKey });
      } else {
        logger.info('No peak historical data found to cache (hours)', { cacheKey });
      }
      res.json(finalResult);
    } catch (err) {
      logger.error('Peak history fetch error (hours)', {
        username,
        hours,
        detectorId,
        error: err.message,
      });
      next(err);
    }
  }
);

// GET /history/peaks/range
router.get(
  '/peaks/range',
  authenticateToken,
  historyRangeValidationRules,
  validateRequest,
  async (req, res, next) => {
    const { startTime, endTime, detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(null, startTime, endTime);
    const cacheKey = `${REDIS_HISTORY_CACHE_PREFIX}peaks:${rangeIdentifier}:${detectorId || 'all'}`;
    // Get client instance inside handler
    const streamRedisClient = getStreamRedisClient();

    try {
      const cached = await streamRedisClient.get(cacheKey);
      if (cached) {
        logger.info('Serving peak history from cache (range)', { cacheKey, username });
        return res.contentType('application/json').send(cached);
      }
      logger.info('Fetching peak history from storage (range)', {
        cacheKey,
        start: startTime,
        end: endTime,
        detectorId,
        username,
      });
      const finalResult = await fetchCombinedPeakHistory(startTimeMs, endTimeMs, detectorId);
      if (finalResult.length > 0) {
        await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult));
        logger.info('Cached combined peak historical data (range)', { cacheKey });
      } else {
        logger.info('No peak historical data found to cache (range)', { cacheKey });
      }
      res.json(finalResult);
    } catch (err) {
      logger.error('Peak history fetch error (range)', {
        username,
        detectorId,
        startTime,
        endTime,
        error: err.message,
      });
      next(err);
    }
  }
);

module.exports = router;
