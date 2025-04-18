// server/streamProcessor.js
/**
 * Processes messages from the Redis spectrogram stream.
 * Handles downsampling, peak detection/tracking, transient detection,
 * storing results in history, and initiating broadcasts.
 */
// Import the *getter* function, not the client instance directly
const { getStreamRedisClient } = require('./utils/redisClients');
const {
  detectPeaksEnhanced,
  trackPeaks,
  detectTransients,
  RAW_FREQUENCY_POINTS, // Import constant
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

// Removed top-level client retrieval
// const streamRedisClient = getStreamRedisClient();
const CONSUMER_NAME = `consumer_${process.pid}`; // Unique consumer name per process

let processingActive = false; // Flag to control the main loop
let isShuttingDown = false; // Flag to signal shutdown process

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
    // Basic structure validation
    if (
      !parsedMessage.spectrogram ||
      !parsedMessage.detectorId ||
      !parsedMessage.location ||
      !Array.isArray(parsedMessage.spectrogram)
    ) {
      logger.warn('Invalid message structure in stream', {
        messageId,
        detectorId: parsedMessage?.detectorId,
      });
      return null;
    }
    // Validate timestamp or default to current time
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
    parsedMessage.timestampMs = messageTimestampMs; // Add parsed timestamp in ms
    return parsedMessage;
  } catch (e) {
    logger.error('Failed to parse JSON from stream message', { messageId, error: e.message });
    return null;
  }
}

/**
 * Processes a single raw spectrogram from a batch.
 * Performs downsampling, peak detection/tracking, and transient detection.
 * @param {Array<number>} rawSpec - The raw spectrogram data.
 * @param {string} detectorId - The ID of the detector.
 * @param {number} timestampMs - The timestamp for this data.
 * @param {number} specIndex - The index of this spectrum within its batch.
 * @returns {Promise<object>} Object containing { downsampled, detectedPeaks, transientInfo }.
 */
async function processSingleSpectrum(rawSpec, detectorId, timestampMs, specIndex) {
  let detectedPeaks = [];
  let transientInfo = { type: 'none', details: null };
  let downsampled = [];

  // Validate input spectrum
  if (!Array.isArray(rawSpec) || rawSpec.length !== RAW_FREQUENCY_POINTS) {
    logger.warn('Item in spectrogram batch is not valid raw spectrum', {
      detectorId,
      specIndex,
      length: rawSpec?.length,
    });
    // Return default error state if spectrum is invalid
    return {
      downsampled: [],
      detectedPeaks: [],
      transientInfo: { type: 'error', details: 'Invalid spectrum data provided.' },
    };
  }

  try {
    // Get stream client instance *inside* the function
    const streamRedisClient = getStreamRedisClient();

    // 1. Downsample
    downsampled = rawSpec.filter((_, i) => i % DOWNSAMPLE_FACTOR === 0);

    // 2. Peak Detection
    const peakDetectionStart = Date.now();
    // Pass empty config to use defaults defined within processingUtils
    const detectedPeaksRaw = detectPeaksEnhanced(rawSpec, {});
    const peakDetectionDuration = Date.now() - peakDetectionStart;
    if (peakDetectionDuration > 100) {
      // Log if detection takes longer than 100ms
      logger.warn('Peak detection took longer than expected', {
        detectorId,
        specIndex,
        durationMs: peakDetectionDuration,
        peakCount: detectedPeaksRaw.length,
      });
    } else {
      logger.debug('Peak detection duration', {
        detectorId,
        specIndex,
        durationMs: peakDetectionDuration,
        peakCount: detectedPeaksRaw.length,
      });
    }

    // 3. Peak Tracking (updates DB state internally)
    // Pass timestamp for state management and potential TTL logic (though DB handles persistence now)
    detectedPeaks = await trackPeaks(detectorId, detectedPeaksRaw, timestampMs, {}); // Pass empty config

    // 4. Transient Detection
    // Pass streamRedisClient instance for history lookup
    transientInfo = await detectTransients(detectorId, rawSpec, streamRedisClient, {}); // Pass empty config

    // --- Update Prometheus Metrics ---
    if (detectedPeaks.length > 0) {
      peaksDetectedCounter.inc({ detectorId }, detectedPeaks.length);
    }
    if (transientInfo.type !== 'none' && transientInfo.type !== 'error') {
      transientsDetectedCounter.inc({ detectorId, type: transientInfo.type });
    }
  } catch (err) {
    logger.error('Error during single spectrum processing', {
      detectorId,
      specIndex,
      timestampMs,
      error: err.message,
      stack: err.stack,
    });
    // Set error state for this specific spectrum's results
    transientInfo = { type: 'error', details: `Spectrum processing error: ${err.message}` };
    detectedPeaks = []; // Ensure no peaks are reported on error
    downsampled = []; // Clear downsampled data on error? Or keep it? Clearing for safety.
  }

  // Return results for this single spectrum
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
  processingActive = true; // Set flag immediately
  isShuttingDown = false; // Reset shutdown flag on start
  logger.info(`Starting stream processing loop for consumer ${CONSUMER_NAME}...`);

  try {
    // Get stream client instance here for setup
    const streamRedisClient = getStreamRedisClient();

    // Ensure consumer group exists or create it for the stream
    await streamRedisClient
      .xgroup('CREATE', REDIS_SPECTROGRAM_STREAM_KEY, REDIS_STREAM_GROUP_NAME, '$', 'MKSTREAM')
      .catch((err) => {
        // Ignore error if group already exists, throw others
        if (!err.message.includes('BUSYGROUP Consumer Group name already exists')) {
          logger.error('Failed to create/verify consumer group', {
            group: REDIS_STREAM_GROUP_NAME,
            error: err.message,
          });
          throw err;
        }
        logger.info(`Consumer group '${REDIS_STREAM_GROUP_NAME}' already exists.`);
      });

    logger.info(
      `Consumer ${CONSUMER_NAME} ready to process stream ${REDIS_SPECTROGRAM_STREAM_KEY}`
    );

    // Main processing loop - continues as long as processingActive is true
    while (processingActive) {
      if (isShuttingDown) {
        // Check shutdown flag
        logger.info('Shutdown signal received, exiting stream processing loop.');
        break;
      }
      try {
        // Read messages using XREADGROUP, blocking for up to 5 seconds if no messages
        // Use the already retrieved streamRedisClient instance
        const results = await streamRedisClient.xreadgroup(
          'GROUP',
          REDIS_STREAM_GROUP_NAME,
          CONSUMER_NAME,
          'COUNT',
          10, // Process up to 10 messages per iteration
          'BLOCK',
          5000, // Block for max 5000ms
          'STREAMS',
          REDIS_SPECTROGRAM_STREAM_KEY,
          '>' // Read only new messages delivered to this consumer
        );

        // results is null if the BLOCK timeout expires
        if (!results) {
          // logger.debug('No new messages in stream, continuing block.'); // Can be noisy
          continue; // Loop again to wait for messages
        }

        // Process messages received (results is an array of streams)
        for (const [streamName, messages] of results) {
          // Should only contain our stream key, but check just in case
          if (streamName !== REDIS_SPECTROGRAM_STREAM_KEY) continue;

          // Process each message within the stream result
          for (const [messageId, fields] of messages) {
            // Reset flag for each message, assume ACK unless critical failure
            let shouldAck = true;
            const parsedMessage = parseStreamMessage(fields, messageId);

            if (!parsedMessage) {
              // Invalid message format, log and ACK to remove from stream
              logger.warn('Acking invalid message due to parsing failure', { messageId });
              await streamRedisClient
                .xack(REDIS_SPECTROGRAM_STREAM_KEY, REDIS_STREAM_GROUP_NAME, messageId)
                .catch((ackErr) => {
                  logger.error('Failed to ACK invalid message', {
                    messageId,
                    error: ackErr.message,
                  });
                });
              continue; // Skip to next message
            }

            const {
              detectorId,
              location,
              spectrogram: rawSpectrogramBatch,
              interval,
              timestampMs,
            } = parsedMessage;

            try {
              const processingStartTime = Date.now();
              // Get a new pipeline instance for this message batch
              const historyPipeline = streamRedisClient.pipeline();
              const downsampledBatch = [];
              const allProcessingResults = []; // Array to hold { detectedPeaks, transientInfo } for each spec
              let firstSpectrumPeaksForWs = []; // Store results from the first spec for WS broadcast
              let firstSpectrumTransientForWs = { type: 'none', details: null };

              logger.debug(
                `Processing batch for ${detectorId} (size: ${rawSpectrogramBatch.length}) msgId: ${messageId}`
              );

              // --- Process Each Raw Spectrum in Batch ---
              for (let specIndex = 0; specIndex < rawSpectrogramBatch.length; specIndex++) {
                // Process each spectrum individually
                const result = await processSingleSpectrum(
                  rawSpectrogramBatch[specIndex],
                  detectorId,
                  timestampMs,
                  specIndex
                );

                // Collect results
                downsampledBatch.push(result.downsampled);
                allProcessingResults.push({
                  detectedPeaks: result.detectedPeaks,
                  transientInfo: result.transientInfo,
                });

                // Add individual peak results to Redis ZSET history using pipeline
                if (result.detectedPeaks.length > 0) {
                  const peakKey = `${REDIS_PEAK_HISTORY_PREFIX}${detectorId}`;
                  // Use timestamp + index offset for score to ensure unique scores if multiple spectra in batch have same timestamp
                  const peakScore = timestampMs + specIndex;
                  historyPipeline.zadd(peakKey, peakScore, JSON.stringify(result.detectedPeaks));
                  // logger.debug("Adding tracked peaks to history ZSET", { key: peakKey, specIndex, score: peakScore, count: result.detectedPeaks.length });
                }

                // Capture results from the first spectrum for WebSocket broadcast
                if (specIndex === 0) {
                  firstSpectrumPeaksForWs = result.detectedPeaks;
                  firstSpectrumTransientForWs = result.transientInfo;
                }
              } // End loop through raw spectra in batch

              // --- Prepare Data for History List ---
              // Store the *entire* batch's downsampled data and processing results
              const dataToStoreInHistory = {
                detectorId: detectorId,
                timestamp: new Date(timestampMs).toISOString(), // Store ISO string in history
                location: location,
                interval: interval,
                spectrogram: downsampledBatch, // Store the array of downsampled spectra
                processingResults: allProcessingResults, // Store the array of corresponding results
              };
              const messageStringForHistory = JSON.stringify(dataToStoreInHistory);

              // --- Add to Redis History List using Pipeline ---
              const historyKey = `${REDIS_SPEC_HISTORY_PREFIX}${detectorId}`;
              historyPipeline.lpush(historyKey, messageStringForHistory);
              // Trim the list to keep only the most recent entries
              historyPipeline.ltrim(historyKey, 0, MAX_SPECTROGRAM_HISTORY_LENGTH - 1);
              logger.debug('Adding processed data batch to history list (and trimming)', {
                key: historyKey,
                numSpectra: downsampledBatch.length,
              });

              // --- Execute Redis Pipeline ---
              // This atomically executes ZADD(s) and LPUSH/LTRIM
              await historyPipeline.exec();

              // --- Prepare and Broadcast WebSocket Message ---
              // Payload contains ONLY the results from the *first* spectrum in the batch
              const wsMessagePayload = {
                detectorId: detectorId,
                timestamp: new Date(timestampMs).toISOString(),
                location: location,
                interval: interval,
                spectrogram: [downsampledBatch[0] || []], // Send only the first downsampled
                detectedPeaks: firstSpectrumPeaksForWs,
                transientInfo: firstSpectrumTransientForWs,
              };
              // Asynchronously broadcast the message (don't block processing loop)
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
              // Decide if message should be ACKed or retried.
              // For persistent errors, ACK to avoid reprocessing loops.
              shouldAck = true;
            } finally {
              // Acknowledge the message was processed (or failed non-transiently)
              if (shouldAck) {
                await streamRedisClient
                  .xack(REDIS_SPECTROGRAM_STREAM_KEY, REDIS_STREAM_GROUP_NAME, messageId)
                  .catch((ackErr) => {
                    logger.error('Failed to ACK message', { messageId, error: ackErr.message });
                  });
              }
            }
          } // End processing messages in this read
        } // End processing results from xreadgroup
      } catch (readError) {
        // Handle errors reading from the stream (e.g., connection issues)
        logger.error('Error reading from Redis stream group', {
          group: REDIS_STREAM_GROUP_NAME,
          error: readError.message,
          stack: readError.stack,
        });
        // Wait before retrying to avoid tight loop on persistent connection errors
        if (processingActive && !isShuttingDown) {
          // Avoid sleeping if shutting down
          await new Promise((resolve) => setTimeout(resolve, 5000)); // Wait 5 seconds
        }
      }
    } // End while loop
  } catch (setupError) {
    // Handle errors during initial setup (e.g., creating consumer group)
    logger.error('Stream processing setup failed fatally', {
      error: setupError.message,
      stack: setupError.stack,
    });
    // Optionally retry setup after a delay? Or signal failure to main process?
    processingActive = false; // Ensure loop flag is false
  } finally {
    processingActive = false; // Ensure flag is reset if loop exits unexpectedly
    logger.info('Stream processing loop has stopped.');
  }
}

/**
 * Signals the stream processing loop to stop gracefully.
 */
function stopStreamProcessing() {
  if (processingActive) {
    logger.info('Signaling stream processing loop to stop...');
    isShuttingDown = true; // Set shutdown flag
    processingActive = false; // Allow loop condition to terminate
  } else {
    logger.info('Stream processing loop already stopped or not started.');
  }
}

module.exports = {
  startStreamProcessing,
  stopStreamProcessing,
};
