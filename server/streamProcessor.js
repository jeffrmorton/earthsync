// server/streamProcessor.js
/**
 * Processes messages from the Redis spectrogram stream.
 * Handles downsampling (with anti-aliasing), peak detection/tracking, transient detection,
 * storing INDIVIDUAL processed results in history list, and initiating broadcasts.
 * Assumes batch size is 1 due to detector/ingest constraints. No backslash escapes in template literals.
 * Fixes potential race condition on startup/reconnect with XREADGROUP.
 */
const { getStreamRedisClient } = require('./utils/redisClients');
const {
  detectPeaksEnhanced,
  trackPeaks,
  detectTransients,
  downsampleWithAntiAliasing,
  RAW_FREQUENCY_POINTS,
} = require('./processingUtils');
const { broadcastMessage } = require('./websocketManager');
const { peaksDetectedCounter, transientsDetectedCounter } = require('./utils/metrics');
const {
  REDIS_SPECTROGRAM_STREAM_KEY,
  REDIS_STREAM_GROUP_NAME,
  REDIS_SPEC_HISTORY_PREFIX,
  REDIS_PEAK_HISTORY_PREFIX,
  DOWNSAMPLE_FACTOR,
  MAX_SPECTROGRAM_HISTORY_LENGTH,
} = require('./config/constants');
const logger = require('./utils/logger');

const CONSUMER_NAME = `consumer_${process.pid}`;

let processingActive = false;
let isShuttingDown = false;

/**
 * Parses a message from the Redis stream.
 * @param {Array} fields - The fields array from the stream message.
 * @param {string} messageId - The ID of the stream message for logging.
 * @returns {object|null} Parsed message object or null if invalid.
 */
function parseStreamMessage(fields, messageId) {
  const dataIndex = fields.indexOf('data');
  if (dataIndex === -1 || !fields[dataIndex + 1]) {
    logger.warn('Stream message missing data field', { messageId });
    return null;
  }
  try {
    const parsedMessage = JSON.parse(fields[dataIndex + 1]);
    if (
      !parsedMessage.spectrogram ||
      !parsedMessage.detectorId ||
      !parsedMessage.location ||
      !Array.isArray(parsedMessage.spectrogram) ||
      parsedMessage.spectrogram.length !== 1 ||
      !Array.isArray(parsedMessage.spectrogram[0])
    ) {
      logger.warn('Invalid message structure or batch size != 1 in stream', {
        messageId,
        detectorId: parsedMessage?.detectorId,
        batchSize: parsedMessage?.spectrogram?.length,
      });
      return null;
    }
    let messageTimestampMs = parsedMessage.timestamp
      ? new Date(parsedMessage.timestamp).getTime()
      : Date.now();
    if (isNaN(messageTimestampMs)) {
      logger.warn('Invalid timestamp in message, using current time', {
        messageId,
        detectorId: parsedMessage?.detectorId,
        providedTs: parsedMessage.timestamp,
      });
      messageTimestampMs = Date.now();
    }
    parsedMessage.timestampMs = messageTimestampMs;
    return parsedMessage;
  } catch (e) {
    logger.error('Failed to parse JSON from stream message', { messageId, error: e.message });
    return null;
  }
}

/**
 * Processes a single raw spectrogram.
 * @param {Array<number>} rawSpec - The raw spectrogram data.
 * @param {string} detectorId - The ID of the detector.
 * @param {number} timestampMs - The timestamp for this data.
 * @returns {Promise<object>} Object containing { downsampled, detectedPeaks, transientInfo }.
 */
async function processSingleSpectrum(rawSpec, detectorId, timestampMs) {
  let detectedPeaks = [];
  let transientInfo = { type: 'none', details: null };
  let downsampled = [];

  if (!Array.isArray(rawSpec) || rawSpec.length !== RAW_FREQUENCY_POINTS) {
    logger.warn('Received invalid raw spectrum data for processing', {
      detectorId,
      length: rawSpec?.length,
    });
    return {
      downsampled: [],
      detectedPeaks: [],
      transientInfo: { type: 'error', details: 'Invalid spectrum data provided.' },
    };
  }

  try {
    const streamRedisClient = getStreamRedisClient(); // Get client instance when needed

    downsampled = downsampleWithAntiAliasing(rawSpec, DOWNSAMPLE_FACTOR);
    const detectedPeaksRaw = detectPeaksEnhanced(rawSpec, {});
    detectedPeaks = await trackPeaks(detectorId, detectedPeaksRaw, timestampMs, {});
    transientInfo = await detectTransients(detectorId, rawSpec, streamRedisClient, {});

    if (detectedPeaks.length > 0) {
      peaksDetectedCounter.inc({ detectorId }, detectedPeaks.length);
    }
    if (transientInfo.type !== 'none' && transientInfo.type !== 'error') {
      transientsDetectedCounter.inc({ detectorId, type: transientInfo.type });
    }
  } catch (err) {
    logger.error('Error during single spectrum processing', {
      detectorId,
      timestampMs,
      error: err.message,
      stack: err.stack,
    });
    transientInfo = { type: 'error', details: `Spectrum processing error: ${err.message}` };
    detectedPeaks = [];
    downsampled = [];
  }

  return { downsampled, detectedPeaks, transientInfo };
}

/**
 * Main loop to read and process messages from the Redis stream group.
 */
async function startStreamProcessing() {
  if (processingActive) {
    logger.warn('Stream processing loop already active. Skipping new invocation.');
    return;
  }
  processingActive = true;
  isShuttingDown = false;
  logger.info(`Starting stream processing loop for consumer ${CONSUMER_NAME}...`);

  try {
    const streamRedisClient = getStreamRedisClient(); // Get client instance for setup

    // --- Ensure Consumer Group Exists (Run Once Before Loop) ---
    try {
      await streamRedisClient.xgroup(
        'CREATE',
        REDIS_SPECTROGRAM_STREAM_KEY,
        REDIS_STREAM_GROUP_NAME,
        '$',
        'MKSTREAM'
      );
      logger.info(`Created consumer group '${REDIS_STREAM_GROUP_NAME}'.`);
    } catch (err) {
      if (!err.message.includes('BUSYGROUP Consumer Group name already exists')) {
        logger.error('Failed to create/verify consumer group', {
          group: REDIS_STREAM_GROUP_NAME,
          error: err.message,
        });
        throw err; // Rethrow if it's not the expected error
      }
      logger.info(`Consumer group '${REDIS_STREAM_GROUP_NAME}' already exists.`);
    }
    // --- End Consumer Group Check ---

    logger.info(
      `Consumer ${CONSUMER_NAME} ready to process stream ${REDIS_SPECTROGRAM_STREAM_KEY}`
    );

    while (processingActive) {
      if (isShuttingDown) {
        logger.info('Shutdown signal received, exiting stream processing loop.');
        break;
      }
      try {
        // --- Check connection status before blocking read ---
        if (streamRedisClient.status !== 'ready') {
          logger.warn(`Redis stream client not ready (status: ${streamRedisClient.status}). Waiting...`);
          await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait 1s before retrying loop
          continue;
        }
        // --- End connection status check ---

        const results = await streamRedisClient.xreadgroup(
          'GROUP',
          REDIS_STREAM_GROUP_NAME,
          CONSUMER_NAME,
          'COUNT',
          10,
          'BLOCK',
          5000,
          'STREAMS',
          REDIS_SPECTROGRAM_STREAM_KEY,
          '>'
        );

        if (!results) {
          continue; // Timeout, loop again
        }

        for (const [streamName, messages] of results) {
          if (streamName !== REDIS_SPECTROGRAM_STREAM_KEY) continue;

          for (const [messageId, fields] of messages) {
            let shouldAck = true;
            const parsedMessage = parseStreamMessage(fields, messageId);

            if (!parsedMessage) {
              logger.warn('Acking invalid message due to parsing failure', { messageId });
              await streamRedisClient
                .xack(REDIS_SPECTROGRAM_STREAM_KEY, REDIS_STREAM_GROUP_NAME, messageId)
                .catch((ackErr) => logger.error('Failed to ACK invalid message', { messageId, error: ackErr.message }));
              continue;
            }

            const {
              detectorId,
              location,
              spectrogram: rawSpectrogramBatch,
              interval,
              timestampMs,
            } = parsedMessage;

            // Since batch size is fixed to 1, we process only the first (index 0)
            if (rawSpectrogramBatch.length !== 1) {
               logger.warn('Received unexpected batch size > 1, processing only first spectrum.', { messageId, detectorId });
            }

            try {
              const processingStartTime = Date.now();
              const historyPipeline = streamRedisClient.pipeline(); // Create pipeline for this message

              // Process the single raw spectrum
              const result = await processSingleSpectrum(
                rawSpectrogramBatch[0],
                detectorId,
                timestampMs
              );

              // Prepare single-spectrum data for history list
              const dataToStoreInHistory = {
                detectorId: detectorId,
                timestamp: new Date(timestampMs).toISOString(),
                location: location,
                interval: interval,
                spectrogram: result.downsampled || [],
                processingResults: [ { detectedPeaks: result.detectedPeaks, transientInfo: result.transientInfo } ],
              };
              const messageStringForHistory = JSON.stringify(dataToStoreInHistory);

              // Add individual record to Redis History List
              const historyKey = `${REDIS_SPEC_HISTORY_PREFIX}${detectorId}`;
              historyPipeline.lpush(historyKey, messageStringForHistory);
              historyPipeline.ltrim(historyKey, 0, MAX_SPECTROGRAM_HISTORY_LENGTH - 1);

              // Add Peaks to Redis History ZSet
              if (result.detectedPeaks.length > 0) {
                const peakKey = `${REDIS_PEAK_HISTORY_PREFIX}${detectorId}`;
                historyPipeline.zadd(peakKey, timestampMs, JSON.stringify(result.detectedPeaks));
              }

              // Execute Redis Pipeline
              await historyPipeline.exec();

              // Prepare and Broadcast WebSocket Message
              const wsMessagePayload = {
                detectorId: detectorId,
                timestamp: new Date(timestampMs).toISOString(),
                location: location,
                interval: interval,
                spectrogram: [result.downsampled || []],
                detectedPeaks: result.detectedPeaks,
                transientInfo: result.transientInfo,
              };
              broadcastMessage(wsMessagePayload).catch((broadcastErr) => {
                logger.error('Error during WebSocket broadcast', { error: broadcastErr.message });
              });

              const processingDuration = Date.now() - processingStartTime;
              logger.debug(
                `Finished processing message ${messageId} for ${detectorId}. Duration: ${processingDuration}ms`
              );

            } catch (processingError) {
              logger.error('Critical error during stream message processing', {
                messageId,
                detectorId: parsedMessage?.detectorId,
                error: processingError.message,
                stack: processingError.stack,
              });
              shouldAck = true;
            } finally {
              if (shouldAck) {
                await streamRedisClient
                  .xack(REDIS_SPECTROGRAM_STREAM_KEY, REDIS_STREAM_GROUP_NAME, messageId)
                  .catch((ackErr) => {
                    logger.error('Failed to ACK message', { messageId, error: ackErr.message });
                  });
              }
            }
          }
        }
      } catch (readError) {
        logger.error('Error reading from Redis stream group', {
          group: REDIS_STREAM_GROUP_NAME,
          error: readError.message,
          // Avoid logging full stack for potentially frequent connection errors
          // stack: readError.stack,
        });
        // Wait only if the error wasn't due to shutdown
        if (processingActive && !isShuttingDown) {
             logger.info('Waiting 5 seconds before retrying stream read...');
             await new Promise((resolve) => setTimeout(resolve, 5000));
        }
      }
    } // End while loop
  } catch (setupError) {
    logger.error('Stream processing setup failed fatally', {
      error: setupError.message,
      stack: setupError.stack,
    });
    processingActive = false; // Ensure loop flag is false on setup failure
  } finally {
    processingActive = false;
    logger.info('Stream processing loop has stopped.');
  }
}

/**
 * Signals the stream processing loop to stop gracefully.
 */
function stopStreamProcessing() {
  if (processingActive) {
    logger.info('Signaling stream processing loop to stop...');
    isShuttingDown = true;
    processingActive = false;
  } else {
    logger.info('Stream processing loop already stopped or not started.');
  }
}

module.exports = {
  startStreamProcessing,
  stopStreamProcessing,
};
