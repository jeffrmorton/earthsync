// server/archiver.js
/**
 * Background task for archiving old data from Redis to PostgreSQL.
 * Handles individual spectrogram records in Redis lists. No backslash escapes in template literals.
 */
const db = require('./db'); // DB access for inserts
const { getStreamRedisClient } = require('./utils/redisClients');
const { archiveRecordsCounter, archiveDuration } = require('./utils/metrics');
const {
  REDIS_SPEC_RETENTION_MS,
  REDIS_PEAK_RETENTION_MS,
  REDIS_SPEC_HISTORY_PREFIX,
  REDIS_PEAK_HISTORY_PREFIX,
  CLEANUP_INTERVAL_MS,
} = require('./config/constants');
const logger = require('./utils/logger');

let cleanupTimer = null;
let isCleanupRunning = false;
let isShuttingDown = false;

/**
 * Archives old spectrogram data from a Redis list to the database.
 * Reads individual JSON records representing single spectra.
 * @param {string} key - The Redis list key (e.g., "spectrogram_history:detector1").
 * @param {number} cutoffTimestampMs - Timestamp threshold for archiving.
 * @returns {Promise<number>} Number of individual spectrogram records successfully archived.
 */
async function archiveSpectrogramList(key, cutoffTimestampMs) {
  const detectorId = key.substring(REDIS_SPEC_HISTORY_PREFIX.length);
  if (!detectorId) {
    logger.warn(`Could not extract detectorId from spectrogram history key: ${key}`);
    return 0;
  }

  const recordsToArchiveToDb = [];
  const recordStringsToKeep = [];
  let originalRedisCount = 0;
  const streamRedisClient = getStreamRedisClient();

  try {
    const allRecordStrings = await streamRedisClient.lrange(key, 0, -1);
    originalRedisCount = allRecordStrings.length;
    if (originalRedisCount === 0) {
      logger.debug(`Skipping spectrogram archive: List is empty`, { key });
      archiveRecordsCounter.inc({ type: 'spec', status: 'skipped' }, 0);
      return 0;
    }

    logger.debug(
      `Scanning ${originalRedisCount} individual spectrogram records in ${key} for archiving...`
    );

    for (const recordStr of allRecordStrings) {
      let keepThisRecord = true;
      let parsedRecord = null;
      try {
        parsedRecord = JSON.parse(recordStr);
        // Expecting the new single-spectrum record format stored by streamProcessor
        if (
          parsedRecord &&
          parsedRecord.timestamp &&
          parsedRecord.detectorId === detectorId &&
          Array.isArray(parsedRecord.spectrogram) // Check if spectrogram array exists
        ) {
          const recordTime = new Date(parsedRecord.timestamp).getTime();
          if (recordTime < cutoffTimestampMs) {
            keepThisRecord = false; // Mark for removal from Redis

            // Prepare DB record directly from the parsed record
            recordsToArchiveToDb.push({
              detector_id: parsedRecord.detectorId,
              timestamp: parsedRecord.timestamp, // Use ISO string for DB
              location_lat: parsedRecord.location?.lat ?? null,
              location_lon: parsedRecord.location?.lon ?? null,
              spectrogram_data: parsedRecord.spectrogram, // Store the single downsampled array
              // Access transient info from the nested processingResults array
              transient_detected:
                parsedRecord.processingResults?.[0]?.transientInfo?.type !== 'none' || false,
              transient_details:
                parsedRecord.processingResults?.[0]?.transientInfo?.details || null,
            });
          }
        } else {
          logger.warn(
            'Invalid record structure or detectorId mismatch found during spec archive scan, keeping.',
            { key }
          );
        }
      } catch (parseErr) {
        logger.warn('Failed to parse record JSON during spec archive scan, keeping.', {
          key,
          recordStart: recordStr.substring(0, 100),
          error: parseErr.message,
        });
      }
      if (keepThisRecord) {
        recordStringsToKeep.push(recordStr); // Keep original string if not archived
      }
    } // End loop

    if (recordsToArchiveToDb.length > 0) {
      logger.info(
        `Attempting to archive ${recordsToArchiveToDb.length} individual spectrogram records from ${key}`
      );
      const insertedCount = await db.insertHistoricalSpectrograms(recordsToArchiveToDb);
      archiveRecordsCounter.inc({ type: 'spec', status: 'archived' }, insertedCount);

      // Atomically replace the list
      const multi = streamRedisClient.multi();
      multi.del(key);
      if (recordStringsToKeep.length > 0) {
        multi.rpush(key, ...recordStringsToKeep);
      }
      await multi.exec();

      logger.info(
        `Successfully archived ${insertedCount} spectrograms and updated Redis list for ${key}. Kept ${recordStringsToKeep.length} records.`
      );
      return insertedCount;
    } else {
      logger.debug(`No spectrogram records older than cutoff found in ${key}.`);
      if (originalRedisCount > 0) {
        archiveRecordsCounter.inc({ type: 'spec', status: 'skipped' }, 0);
      }
      return 0;
    }
  } catch (archiveError) {
    logger.error(`Error archiving spectrograms for ${key}`, {
      error: archiveError.message,
      stack: archiveError.stack,
    });
    archiveRecordsCounter.inc({ type: 'spec', status: 'error' });
    return 0;
  }
}

/**
 * Archives old peak data from a Redis sorted set to the database.
 * @param {string} key - The Redis sorted set key (e.g., "peaks:detector1").
 * @param {number} cutoffTimestampMs - Timestamp threshold for archiving.
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
  const streamRedisClient = getStreamRedisClient();

  try {
    const peaksWithScores = await streamRedisClient.zrangebyscore(
      key,
      '-inf',
      `(${cutoffTimestampMs}`,
      'WITHSCORES'
    );

    if (peaksWithScores.length === 0) {
      logger.debug(`No peak records older than cutoff found in ${key}.`);
      archiveRecordsCounter.inc({ type: 'peak', status: 'skipped' }, 0);
      return 0;
    }

    const numRecordsToArchive = peaksWithScores.length / 2;
    logger.info(`Found ${numRecordsToArchive} peak records to archive for ${key}`);

    for (let i = 0; i < peaksWithScores.length; i += 2) {
      const peakJson = peaksWithScores[i];
      const timestampMs = parseInt(peaksWithScores[i + 1], 10);
      try {
        const peakData = JSON.parse(peakJson);
        if (Array.isArray(peakData)) {
          dbRecords.push({
            detector_id: detectorId,
            timestamp: new Date(timestampMs),
            peak_data: peakData,
          });
        } else {
          logger.warn('Parsed peak data is not an array, skipping record.', {
            key,
            score: timestampMs,
          });
        }
      } catch (parseErr) {
        logger.warn('Failed to parse peak JSON during archive, skipping record.', {
          key,
          score: timestampMs,
          recordStart: peakJson.substring(0, 100),
          error: parseErr.message,
        });
      }
    }

    if (dbRecords.length > 0) {
      const insertedCount = await db.insertHistoricalPeaks(dbRecords);
      archivedCount = insertedCount;
      archiveRecordsCounter.inc({ type: 'peak', status: 'archived' }, insertedCount);

      const removedCount = await streamRedisClient.zremrangebyscore(
        key,
        '-inf',
        `(${cutoffTimestampMs}`
      );
      logger.info(
        `Successfully archived ${insertedCount} and removed ${removedCount} peak records from Redis ZSET for ${key}.`
      );
      if (removedCount !== numRecordsToArchive) {
        logger.warn(
          `Potential mismatch: ${numRecordsToArchive} records found, ${dbRecords.length} prepared for DB, ${removedCount} removed from Redis for ${key}.`
        );
      }
    } else if (numRecordsToArchive > 0) {
      logger.warn(
        `Attempted to archive ${numRecordsToArchive} peak records for ${key}, but none were successfully parsed for DB insertion. Removing from Redis.`
      );
      archiveRecordsCounter.inc({ type: 'peak', status: 'error' }, numRecordsToArchive);
      const removedCount = await streamRedisClient.zremrangebyscore(
        key,
        '-inf',
        `(${cutoffTimestampMs}`
      );
      logger.warn(`Removed ${removedCount} potentially unparseable old peak records from ${key}.`);
    }
  } catch (archiveError) {
    logger.error(`Error archiving peaks for ${key}`, {
      error: archiveError.message,
      stack: archiveError.stack,
    });
    archiveRecordsCounter.inc({ type: 'peak', status: 'error' });
  }
  return archivedCount;
}

async function runCleanupAndArchiving() {
  if (isCleanupRunning) {
    logger.warn('Cleanup task trigger skipped: Task already running.');
    return;
  }
  isCleanupRunning = true;
  const taskStartTime = Date.now();
  logger.info('Starting periodic history cleanup and archiving task...');

  const specCutoffTimestampMs = Date.now() - REDIS_SPEC_RETENTION_MS;
  const peakCutoffTimestampMs = Date.now() - REDIS_PEAK_RETENTION_MS;
  let totalSpecArchived = 0;
  let totalPeakArchived = 0;
  let specKeysProcessed = 0;
  let peakKeysProcessed = 0;

  try {
    const streamRedisClientInstance = getStreamRedisClient();

    const specHistoryKeys = await streamRedisClientInstance.keys(`${REDIS_SPEC_HISTORY_PREFIX}*`);
    logger.debug(`Found ${specHistoryKeys.length} spectrogram history keys for potential cleanup.`);
    specKeysProcessed = specHistoryKeys.length;
    for (const key of specHistoryKeys) {
      totalSpecArchived += await archiveSpectrogramList(key, specCutoffTimestampMs);
    }

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
    archiveDuration.set(duration);
    logger.info('History cleanup/archiving task finished.', {
      duration_sec: duration.toFixed(2),
      spec_keys_checked: specKeysProcessed,
      peak_keys_checked: peakKeysProcessed,
      spec_records_archived: totalSpecArchived,
      peak_records_archived: totalPeakArchived,
    });
    isCleanupRunning = false;
    scheduleNextCleanup();
  }
}

function scheduleNextCleanup() {
  if (cleanupTimer) {
    clearTimeout(cleanupTimer);
    cleanupTimer = null;
  }
  if (!isShuttingDown) {
    cleanupTimer = setTimeout(runCleanupAndArchiving, CLEANUP_INTERVAL_MS);
    logger.info(
      `Scheduled next history cleanup task in ${CLEANUP_INTERVAL_MS / 1000 / 60} minutes.`
    );
  } else {
    logger.info('Shutdown in progress, not scheduling next cleanup task.');
  }
}

function startArchiver() {
  logger.info('Starting archiver task scheduler.');
  isShuttingDown = false;
  cleanupTimer = setTimeout(runCleanupAndArchiving, 30000);
}

function stopArchiver() {
  logger.info('Stopping archiver task scheduler.');
  isShuttingDown = true;
  if (cleanupTimer) {
    clearTimeout(cleanupTimer);
    cleanupTimer = null;
  }
}

module.exports = {
  startArchiver,
  stopArchiver,
  runCleanupAndArchiving,
};
