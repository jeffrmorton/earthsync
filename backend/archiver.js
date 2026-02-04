/**
 * Background task for archiving old data from Redis to PostgreSQL.
 * Handles individual spectrogram records in Redis lists.
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

  const streamRedisClient = getStreamRedisClient();

  try {
    // 1. Get the oldest 100 records from the tail (index N-100 to N-1)
    const batchSizeFromRedis = 100;
    const oldRecordStrings = await streamRedisClient.lrange(key, -batchSizeFromRedis, -1);

    if (oldRecordStrings.length === 0) {
      logger.debug(`Skipping spectrogram archive: List is empty or no records at tail`, { key });
      return 0;
    }

    const recordsToArchiveToDb = [];

    // 2. Iterate from the VERY END (tail) backwards to find consecutive old records
    // This ensures we can safely RPOP them later.
    for (let i = oldRecordStrings.length - 1; i >= 0; i--) {
      const recordStr = oldRecordStrings[i];
      try {
        const parsedRecord = JSON.parse(recordStr);
        if (
          parsedRecord &&
          parsedRecord.timestamp &&
          parsedRecord.detectorId === detectorId &&
          Array.isArray(parsedRecord.spectrogram)
        ) {
          const recordTime = new Date(parsedRecord.timestamp).getTime();
          if (recordTime < cutoffTimestampMs) {
            // Prepare DB record
            recordsToArchiveToDb.push({
              detector_id: parsedRecord.detectorId,
              timestamp: parsedRecord.timestamp,
              location_lat: parsedRecord.location?.lat ?? null,
              location_lon: parsedRecord.location?.lon ?? null,
              spectrogram_data: parsedRecord.spectrogram,
              transient_detected:
                parsedRecord.processingResults?.[0]?.transientInfo?.type !== 'none' || false,
              transient_details:
                parsedRecord.processingResults?.[0]?.transientInfo?.details || null,
            });
          } else {
            // Found a record that is too new. Stop here to keep list chronological.
            break;
          }
        } else {
          // Invalid record structure at the tail.
          // We could skip it or stop. Stopping is safer for RPOP.
          logger.warn(
            'Invalid record structure at tail during spec archive scan. Stopping batch.',
            {
              key,
            }
          );
          break;
        }
      } catch (parseErr) {
        logger.warn(
          'Failed to parse record JSON at tail during spec archive scan. Stopping batch.',
          {
            key,
            error: parseErr.message,
          }
        );
        break;
      }
    }

    // 3. If we found any consecutive old records at the tail, archive them
    if (recordsToArchiveToDb.length > 0) {
      logger.info(
        `Attempting to archive ${recordsToArchiveToDb.length} individual spectrogram records from ${key}`
      );

      // Insert into DB. Throws on error in db.js
      const insertedCount = await db.insertHistoricalSpectrograms(recordsToArchiveToDb);
      archiveRecordsCounter.inc({ type: 'spec', status: 'archived' }, insertedCount);

      // 4. Atomic RPOP only the ones we archived.
      // This is safe because even if new items were LPUSHed to the head during DB insert,
      // RPOP only removes from the tail.
      await streamRedisClient.rpop(key, recordsToArchiveToDb.length);

      logger.info(`Successfully archived ${insertedCount} spectrograms from tail of ${key}.`);
      return insertedCount;
    } else {
      logger.debug(`No spectrogram records at tail older than cutoff found in ${key}.`);
      return 0;
    }
  } catch (archiveError) {
    logger.error(`Error archiving spectrograms for ${key}`, {
      error: archiveError.message,
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

    // Use scanStream for non-blocking key discovery of spectrogram history
    logger.debug('Starting non-blocking scan for spectrogram history keys...');
    const specScanStream = streamRedisClientInstance.scanStream({
      match: `${REDIS_SPEC_HISTORY_PREFIX}*`,
      count: 100,
    });

    for await (const keys of specScanStream) {
      for (const key of keys) {
        specKeysProcessed++;
        const archivedCount = await archiveSpectrogramList(key, specCutoffTimestampMs);
        totalSpecArchived += archivedCount;
      }
    }

    // Use scanStream for non-blocking key discovery of peak history
    logger.debug('Starting non-blocking scan for peak history keys...');
    const peakScanStream = streamRedisClientInstance.scanStream({
      match: `${REDIS_PEAK_HISTORY_PREFIX}*`,
      count: 100,
    });

    for await (const keys of peakScanStream) {
      for (const key of keys) {
        peakKeysProcessed++;
        const archivedCount = await archivePeakSet(key, peakCutoffTimestampMs);
        totalPeakArchived += archivedCount;
      }
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
