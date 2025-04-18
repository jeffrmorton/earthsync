// server/archiver.js
/**
 * Background task for archiving old data from Redis to PostgreSQL.
 */
const db = require('./db'); // DB access for inserts
// Import the *getter* function
const { getStreamRedisClient } = require('./utils/redisClients');
const { archiveRecordsCounter, archiveDuration } = require('./utils/metrics'); // Prometheus metrics
const {
  REDIS_SPEC_RETENTION_MS,
  REDIS_PEAK_RETENTION_MS,
  REDIS_SPEC_HISTORY_PREFIX,
  REDIS_PEAK_HISTORY_PREFIX,
  CLEANUP_INTERVAL_MS, // Use constant for scheduling interval
} = require('./config/constants'); // Centralized constants
const logger = require('./utils/logger'); // Centralized logger

// Removed top-level client retrieval
// const streamRedisClient = getStreamRedisClient();
let cleanupTimer = null; // Timer ID for scheduling
let isCleanupRunning = false; // Flag to prevent concurrent runs
let isShuttingDown = false; // Flag to prevent scheduling new runs during shutdown

/**
 * Archives old spectrogram data from a Redis list to the database.
 * @param {string} key - The Redis list key (e.g., "spectrogram_history:detector1").
 * @param {number} cutoffTimestampMs - Timestamp threshold for archiving (older records are archived).
 * @returns {Promise<number>} Number of individual spectrogram records successfully archived.
 */
async function archiveSpectrogramList(key, cutoffTimestampMs) {
  const detectorId = key.substring(REDIS_SPEC_HISTORY_PREFIX.length);
  if (!detectorId) {
    logger.warn(`Could not extract detectorId from spectrogram history key: ${key}`);
    return 0;
  }

  const recordsToArchive = []; // Holds individual DB records
  const recordsToKeep = []; // Holds original JSON strings of batches to keep
  let archivedCount = 0;
  const currentKey = key; // Use specific key for logging
  // Get client instance inside function
  const streamRedisClient = getStreamRedisClient();

  try {
    // Retrieve all records from the list
    const allRecordsStr = await streamRedisClient.lrange(currentKey, 0, -1);
    if (allRecordsStr.length === 0) {
      logger.debug(`Skipping spectrogram archive: List is empty`, { key: currentKey });
      archiveRecordsCounter.inc({ type: 'spec', status: 'skipped' }, 0);
      return 0; // Nothing to do
    }

    logger.debug(
      `Scanning ${allRecordsStr.length} batch records in ${currentKey} for archiving...`
    );

    // Iterate through the JSON strings from Redis
    for (const recordStr of allRecordsStr) {
      let keepThisRecord = true; // Assume we keep the record unless proven otherwise
      try {
        const record = JSON.parse(recordStr);
        // Basic validation of the parsed record structure
        if (record && record.timestamp && record.detectorId === detectorId) {
          // Ensure detectorId matches key
          const recordTime = new Date(record.timestamp).getTime();
          // Check if the record's timestamp is older than the cutoff
          if (recordTime < cutoffTimestampMs) {
            keepThisRecord = false; // Mark this batch record for removal from Redis later
            // Prepare individual DB records for each spectrum in the batch
            const downsampledBatch = Array.isArray(record.spectrogram) ? record.spectrogram : [];
            const processingResults = Array.isArray(record.processingResults)
              ? record.processingResults
              : [];

            downsampledBatch.forEach((specData, index) => {
              // Ensure specData is an array before trying to archive it
              if (Array.isArray(specData)) {
                const procResult = processingResults[index] || {
                  transientInfo: { type: 'none', details: null },
                };
                recordsToArchive.push({
                  detector_id: record.detectorId,
                  timestamp: record.timestamp, // Use original timestamp string (DB converts TIMESTAMPTZ)
                  location_lat: record.location?.lat ?? null,
                  location_lon: record.location?.lon ?? null,
                  spectrogram_data: specData, // Store the single downsampled array
                  transient_detected: procResult.transientInfo?.type !== 'none' || false,
                  transient_details: procResult.transientInfo?.details || null,
                });
              } else {
                logger.warn(
                  'Invalid spectrogram data found within batch record during archive prep',
                  { key: currentKey, index }
                );
              }
            });
          }
        } else {
          logger.warn(
            'Invalid record structure or detectorId mismatch found during spec archive scan, keeping.',
            { key: currentKey }
          );
        }
      } catch (parseErr) {
        logger.warn('Failed to parse record JSON during spec archive scan, keeping.', {
          key: currentKey,
          recordStart: recordStr.substring(0, 100),
          error: parseErr.message,
        });
        // Keep records that fail parsing in Redis
      }
      // If the record is not older than cutoff, add its original string to keep list
      if (keepThisRecord) {
        recordsToKeep.push(recordStr);
      }
    } // End loop through recordsStr

    // Perform DB insertion if there are records to archive
    if (recordsToArchive.length > 0) {
      logger.info(
        `Attempting to archive ${recordsToArchive.length} individual spectrogram records from ${currentKey}`
      );
      // Assuming insertHistoricalSpectrograms handles bulk insert efficiently
      const insertedCount = await db.insertHistoricalSpectrograms(recordsToArchive);
      archivedCount = insertedCount;
      archiveRecordsCounter.inc({ type: 'spec', status: 'archived' }, insertedCount);

      // Atomically replace the Redis list with only the records to keep
      const multi = streamRedisClient.multi();
      multi.del(currentKey); // Delete the old list
      if (recordsToKeep.length > 0) {
        // RPUSH pushes from left-to-right, needs spread operator
        multi.rpush(currentKey, ...recordsToKeep);
      }
      await multi.exec();

      logger.info(
        `Successfully archived ${insertedCount} spectrograms and updated Redis list for ${currentKey}. Kept ${recordsToKeep.length} original batch records.`
      );
    } else {
      logger.debug(`No spectrogram records older than cutoff found in ${currentKey}.`);
      // Only increment skipped if we actually processed the key
      if (allRecordsStr.length > 0) {
        archiveRecordsCounter.inc({ type: 'spec', status: 'skipped' }, 0);
      }
    }
  } catch (archiveError) {
    logger.error(`Error archiving spectrograms for ${currentKey}`, {
      error: archiveError.message,
      stack: archiveError.stack,
    });
    archiveRecordsCounter.inc({ type: 'spec', status: 'error' });
  }
  return archivedCount;
}

/**
 * Archives old peak data from a Redis sorted set to the database.
 * @param {string} key - The Redis sorted set key (e.g., "peaks:detector1").
 * @param {number} cutoffTimestampMs - Timestamp threshold for archiving (older records are archived).
 * @returns {Promise<number>} Number of records successfully archived.
 */
async function archivePeakSet(key, cutoffTimestampMs) {
  const detectorId = key.substring(REDIS_PEAK_HISTORY_PREFIX.length);
  if (!detectorId) {
    logger.warn(`Could not extract detectorId from peak history key: ${key}`);
    return 0;
  }

  const dbRecords = [];
  let archivedCount = 0;
  const currentKey = key; // Use specific key for logging
  // Get client instance inside function
  const streamRedisClient = getStreamRedisClient();

  try {
    // Fetch records older than the cutoff score (exclusive) using ZRANGE with BYSCORE
    const peaksWithScores = await streamRedisClient.zrangebyscore(
      currentKey,
      '-inf',
      `(${cutoffTimestampMs}`,
      'WITHSCORES'
    );

    if (peaksWithScores.length === 0) {
      logger.debug(`No peak records older than cutoff found in ${currentKey}.`);
      archiveRecordsCounter.inc({ type: 'peak', status: 'skipped' }, 0);
      return 0; // Nothing to archive
    }

    const numRecordsToArchive = peaksWithScores.length / 2;
    logger.info(`Found ${numRecordsToArchive} peak records to archive for ${currentKey}`);

    // Prepare records for DB insertion
    for (let i = 0; i < peaksWithScores.length; i += 2) {
      const peakJson = peaksWithScores[i];
      const timestampMs = parseInt(peaksWithScores[i + 1], 10);
      try {
        // Parse the JSON string containing the peak data array
        const peakData = JSON.parse(peakJson);
        // Basic validation: ensure peakData is an array
        if (Array.isArray(peakData)) {
          dbRecords.push({
            detector_id: detectorId,
            timestamp: new Date(timestampMs), // Store as Date object for DB (TIMESTAMPTZ)
            peak_data: peakData, // Store the parsed array
          });
        } else {
          logger.warn('Parsed peak data is not an array, skipping record.', {
            key: currentKey,
            score: timestampMs,
          });
        }
      } catch (parseErr) {
        logger.warn('Failed to parse peak JSON during archive, skipping record.', {
          key: currentKey,
          score: timestampMs,
          recordStart: peakJson.substring(0, 100),
          error: parseErr.message,
        });
      }
    }

    // Insert valid records into the database
    if (dbRecords.length > 0) {
      const insertedCount = await db.insertHistoricalPeaks(dbRecords);
      archivedCount = insertedCount;
      archiveRecordsCounter.inc({ type: 'peak', status: 'archived' }, insertedCount);

      // Remove the archived records from Redis ZSET using ZREMRANGEBYSCORE
      const removedCount = await streamRedisClient.zremrangebyscore(
        currentKey,
        '-inf',
        `(${cutoffTimestampMs}`
      );
      logger.info(
        `Successfully archived ${insertedCount} and removed ${removedCount} peak records from Redis ZSET for ${currentKey}.`
      );
      if (removedCount !== numRecordsToArchive) {
        // This might happen if some records failed parsing and weren't added to dbRecords, but were still in Redis range
        logger.warn(
          `Potential mismatch: ${numRecordsToArchive} records found, ${dbRecords.length} prepared for DB, ${removedCount} removed from Redis for ${currentKey}.`
        );
      }
    } else if (numRecordsToArchive > 0) {
      // Records existed in Redis range but failed parsing
      logger.warn(
        `Attempted to archive ${numRecordsToArchive} peak records for ${currentKey}, but none were successfully parsed for DB insertion. Removing from Redis.`
      );
      archiveRecordsCounter.inc({ type: 'peak', status: 'error' }, numRecordsToArchive);
      // Still remove the potentially corrupt old records from Redis
      const removedCount = await streamRedisClient.zremrangebyscore(
        currentKey,
        '-inf',
        `(${cutoffTimestampMs}`
      );
      logger.warn(
        `Removed ${removedCount} potentially unparseable old peak records from ${currentKey}.`
      );
    }
  } catch (archiveError) {
    logger.error(`Error archiving peaks for ${currentKey}`, {
      error: archiveError.message,
      stack: archiveError.stack,
    });
    archiveRecordsCounter.inc({ type: 'peak', status: 'error' });
  }
  return archivedCount;
}

/**
 * Main function for the cleanup and archiving task. Runs periodically.
 */
async function runCleanupAndArchiving() {
  // Prevent concurrent runs
  if (isCleanupRunning) {
    logger.warn('Cleanup task trigger skipped: Task already running.');
    return;
  }
  isCleanupRunning = true;
  const taskStartTime = Date.now();
  logger.info('Starting periodic history cleanup and archiving task...');

  // Calculate cutoff timestamps based on current time and configured retention
  const specCutoffTimestampMs = Date.now() - REDIS_SPEC_RETENTION_MS;
  const peakCutoffTimestampMs = Date.now() - REDIS_PEAK_RETENTION_MS;
  let totalSpecArchived = 0;
  let totalPeakArchived = 0;
  let specKeysProcessed = 0;
  let peakKeysProcessed = 0;

  try {
    // Get client instance inside function scope
    const streamRedisClientInstance = getStreamRedisClient();

    // --- Archive and Cleanup Spectrogram History Lists ---
    const specHistoryKeys = await streamRedisClientInstance.keys(`${REDIS_SPEC_HISTORY_PREFIX}*`);
    logger.debug(`Found ${specHistoryKeys.length} spectrogram history keys for potential cleanup.`);
    specKeysProcessed = specHistoryKeys.length;
    for (const key of specHistoryKeys) {
      // Pass client instance if needed by sub-functions, although archiveSpectrogramList gets it itself now
      totalSpecArchived += await archiveSpectrogramList(key, specCutoffTimestampMs);
    }

    // --- Archive and Cleanup Peak History Sorted Sets ---
    const peakHistoryKeys = await streamRedisClientInstance.keys(`${REDIS_PEAK_HISTORY_PREFIX}*`);
    logger.debug(`Found ${peakHistoryKeys.length} peak history keys for potential cleanup.`);
    peakKeysProcessed = peakHistoryKeys.length;
    for (const key of peakHistoryKeys) {
      totalPeakArchived += await archivePeakSet(key, peakCutoffTimestampMs);
    }
  } catch (err) {
    logger.error('Unhandled error during history cleanup/archiving task execution', {
      error: err.message,
      stack: err.stack,
    });
  } finally {
    const duration = (Date.now() - taskStartTime) / 1000;
    archiveDuration.set(duration); // Record duration metric
    logger.info('History cleanup/archiving task finished.', {
      duration_sec: duration.toFixed(2),
      spec_keys_checked: specKeysProcessed,
      peak_keys_checked: peakKeysProcessed,
      spec_records_archived: totalSpecArchived,
      peak_records_archived: totalPeakArchived,
    });
    isCleanupRunning = false; // Reset flag
    // Schedule the next run (only if not shutting down)
    scheduleNextCleanup();
  }
}

/**
 * Schedules the next cleanup run, ensuring timer is cleared first.
 */
function scheduleNextCleanup() {
  // Clear existing timer if it exists
  if (cleanupTimer) {
    clearTimeout(cleanupTimer);
    cleanupTimer = null;
  }
  // Schedule next run only if the application is not shutting down
  if (!isShuttingDown) {
    cleanupTimer = setTimeout(runCleanupAndArchiving, CLEANUP_INTERVAL_MS);
    logger.info(
      `Scheduled next history cleanup task in ${CLEANUP_INTERVAL_MS / 1000 / 60} minutes.`
    );
  } else {
    logger.info('Shutdown in progress, not scheduling next cleanup task.');
  }
}

/**
 * Starts the periodic cleanup task scheduler.
 */
function startArchiver() {
  logger.info('Starting archiver task scheduler.');
  // Run the first cleanup shortly after startup, then schedule subsequent runs via scheduleNextCleanup
  isShuttingDown = false; // Ensure shutdown flag is reset on start
  cleanupTimer = setTimeout(runCleanupAndArchiving, 30000); // Run 30 seconds after start
}

/**
 * Stops the periodic cleanup task scheduler.
 */
function stopArchiver() {
  logger.info('Stopping archiver task scheduler.');
  isShuttingDown = true; // Set flag to prevent rescheduling
  if (cleanupTimer) {
    clearTimeout(cleanupTimer);
    cleanupTimer = null;
  }
}

module.exports = {
  startArchiver,
  stopArchiver,
  runCleanupAndArchiving, // Export for potential manual trigger or testing
};
