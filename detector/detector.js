// detector/detector.js
/**
 * Detector module to generate and publish simulated spectrogram data to Redis streams.
 * Includes enhanced simulation features: diurnal variation, randomized parameters, Q-bursts.
 * v1.1.10 - Linter Fixes (unused imports).
 */
require('dotenv').config(); // Load .env file if present
const Redis = require('ioredis');
const winston = require('winston');

// --- Import Constants ---
const {
  REDIS_HOST,
  REDIS_PORT,
  REDIS_PASSWORD,
  INTERVAL_MS,
  DETECTOR_BATCH_SIZE,
  DETECTOR_ID: CFG_DETECTOR_ID, // Use CFG_ prefix to avoid local redeclaration if needed
  LATITUDE: CFG_LATITUDE,
  LONGITUDE: CFG_LONGITUDE,
  LOG_LEVEL,
  REDIS_CONNECT_TIMEOUT_MS,
  RAW_FREQUENCY_POINTS, // MAX_FREQUENCY_HZ, HZ_PER_POINT, // <= REMOVED THESE UNUSED IMPORTS
  POINTS_PER_HZ,
  SCHUMANN_FREQUENCIES,
  BASE_NOISE_LEVEL,
  BASE_AMPLITUDE,
  AMPLITUDE_DECREASE_FACTOR,
  FREQUENCY_SHIFT_MAX,
  PEAK_SHARPNESS_BASE_AVG,
  PEAK_SHARPNESS_BASE_FLUCTUATION,
  PEAK_SHARPNESS_RANDOM_VARIATION,
  AMPLITUDE_VARIATION_FACTOR,
  AMPLITUDE_CYCLE_DURATION_MS,
  Q_BURST_PROBABILITY,
  Q_BURST_MODE_INDICES,
  Q_BURST_AMP_MULTIPLIER,
  Q_BURST_SHARPNESS_DIVISOR,
  Q_BURST_DURATION_INTERVALS,
  REDIS_STREAM_KEY,
} = require('./constants'); // Import from the constants file

// --- Assign Constants for Local Use (and handle potential NaN for coords) ---
const DETECTOR_ID = CFG_DETECTOR_ID;
let LATITUDE = CFG_LATITUDE;
let LONGITUDE = CFG_LONGITUDE;

// --- Logger Setup ---
// Use LOG_LEVEL from constants
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }), // Include stack traces in logs
    winston.format.splat(),
    winston.format.json() // Log in JSON format to file
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
    // Use DETECTOR_ID constant in filename
    new winston.transports.File({
      filename: `detector-${DETECTOR_ID}.log`,
      maxsize: 5242880, // 5MB
      maxFiles: 3,
    }),
  ],
});

logger.info(`Starting detector ${DETECTOR_ID}... Log level: ${LOG_LEVEL}`);

// --- Configuration Validation ---
if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD) {
  logger.error(
    'FATAL: Redis configuration missing (REDIS_HOST, REDIS_PORT, REDIS_PASSWORD). Exiting.'
  );
  // Throw error instead of process.exit(1)
  throw new Error('Redis configuration missing.');
}
// Handle potentially invalid LAT/LON from constants/env
if (
  isNaN(LATITUDE) ||
  isNaN(LONGITUDE) ||
  LATITUDE < -90 ||
  LATITUDE > 90 ||
  LONGITUDE < -180 ||
  LONGITUDE > 180
) {
  logger.warn(
    `Invalid/missing LAT/LON (${LATITUDE}, ${LONGITUDE}). Generating random coordinates for ${DETECTOR_ID}.`
  );
  LATITUDE = Math.random() * 180 - 90; // Random latitude between -90 and 90
  LONGITUDE = Math.random() * 360 - 180; // Random longitude between -180 and 180
}
if (INTERVAL_MS < 500) {
  logger.warn(`Detector interval ${INTERVAL_MS}ms is very low. Ensure system can handle the load.`);
}
// DETECTOR_BATCH_SIZE validation is now handled in constants.js

// --- Redis Client Setup ---
const redisClient = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
  lazyConnect: true, // Connect explicitly in startDetector
  connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
  retryStrategy: (times) => {
    const delay = Math.min(times * 150, 3000); // Use 150ms base, max 3s delay
    logger.warn(
      `Redis connection retry attempt ${times}. Retrying in ${delay}ms... (${DETECTOR_ID})`
    );
    return delay;
  },
  reconnectOnError: (err) => {
    logger.error(`Redis reconnect triggered on error (${DETECTOR_ID})`, { error: err.message });
    return true; // Attempt reconnect on all errors for simplicity
  },
  maxRetriesPerRequest: 3, // Limit retries for commands after connection established
  showFriendlyErrorStack: process.env.NODE_ENV !== 'production',
});

// Attach Redis event listeners
redisClient.on('error', (err) =>
  logger.error(`Redis Client Error (${DETECTOR_ID})`, { error: err.message })
);
redisClient.on('connect', () => logger.info(`Redis client connecting... (${DETECTOR_ID})`));
redisClient.on('ready', () => logger.info(`Redis client ready. (${DETECTOR_ID})`));
redisClient.on('close', () => logger.warn(`Redis client connection closed. (${DETECTOR_ID})`));
redisClient.on('reconnecting', (delay) =>
  logger.warn(`Redis client reconnecting (delay: ${delay}ms)... (${DETECTOR_ID})`)
);

// --- Simulation Logic ---
// Q-Burst State
let activeQBursts = {}; // Format: { modeIndex: intervalsRemaining }

/** Generates a single simulated raw spectrogram */
function generateSpectrogram() {
  const spectrogram = new Array(RAW_FREQUENCY_POINTS).fill(0);
  const now = Date.now();

  // Calculate diurnal amplitude modulation factor
  const timeOfDayFactor = Math.sin(
    (2 * Math.PI * (now % AMPLITUDE_CYCLE_DURATION_MS)) / AMPLITUDE_CYCLE_DURATION_MS - Math.PI / 2
  ); // Ranges from -1 (night) to +1 (day peak)
  const amplitudeModulation = 1 + AMPLITUDE_VARIATION_FACTOR * timeOfDayFactor;
  const currentBaseAmplitude = BASE_AMPLITUDE * amplitudeModulation;
  // Add some randomness and diurnal variation to noise level
  const currentNoiseLevel =
    BASE_NOISE_LEVEL * (0.8 + Math.random() * 0.4) * (1 + 0.2 * timeOfDayFactor);

  // Add base noise
  for (let i = 0; i < RAW_FREQUENCY_POINTS; i++) {
    spectrogram[i] += Math.random() * currentNoiseLevel;
  }

  // --- Q-Burst State Update ---
  const nextActiveQBursts = {};
  for (const modeIndexStr in activeQBursts) {
    const remaining = activeQBursts[modeIndexStr] - 1;
    if (remaining > 0) {
      nextActiveQBursts[modeIndexStr] = remaining; // Keep burst active
    } else {
      logger.info(`Q-Burst ended for SR mode index ${modeIndexStr} on ${DETECTOR_ID}`);
    }
  }
  activeQBursts = nextActiveQBursts;

  // Check for new Q-bursts triggering
  if (Math.random() < Q_BURST_PROBABILITY) {
    // Select a mode index eligible for bursting
    const burstModeIndex =
      Q_BURST_MODE_INDICES[Math.floor(Math.random() * Q_BURST_MODE_INDICES.length)];
    // Only start if the selected mode is not already bursting
    if (!activeQBursts[burstModeIndex]) {
      activeQBursts[burstModeIndex] = Q_BURST_DURATION_INTERVALS;
      logger.info(
        `*** Q-Burst triggered for SR mode index ${burstModeIndex} on ${DETECTOR_ID} ***`
      );
    }
  }

  // --- Add Schumann Resonance Peaks ---
  SCHUMANN_FREQUENCIES.forEach((baseFreq, index) => {
    // Random frequency shift for this peak
    const freqShift = (Math.random() - 0.5) * 2 * FREQUENCY_SHIFT_MAX;
    const currentFreq = baseFreq + freqShift;
    const centerIndex = Math.round(currentFreq * POINTS_PER_HZ); // Index in the raw spectrum

    // Calculate amplitude for this mode (decreases for higher modes, random variation)
    let modeAmplitude =
      currentBaseAmplitude *
      Math.pow(AMPLITUDE_DECREASE_FACTOR, index) *
      (0.9 + Math.random() * 0.2);

    // Calculate peak sharpness (base + base fluctuation + random variation per generation)
    const currentBaseSharpness =
      PEAK_SHARPNESS_BASE_AVG + (Math.random() - 0.5) * 2 * PEAK_SHARPNESS_BASE_FLUCTUATION;
    let peakSharpness =
      currentBaseSharpness + (Math.random() - 0.5) * 2 * PEAK_SHARPNESS_RANDOM_VARIATION;
    peakSharpness = Math.max(50, peakSharpness); // Ensure sharpness doesn't go too low (too wide)

    // Apply Q-burst effect if active for this mode index
    if (activeQBursts[index]) {
      modeAmplitude *= Q_BURST_AMP_MULTIPLIER; // Increase amplitude
      peakSharpness /= Q_BURST_SHARPNESS_DIVISOR; // Decrease sharpness value (makes peak sharper)
      peakSharpness = Math.max(20, peakSharpness); // Ensure burst sharpness doesn't go too low
      logger.debug(`Applying Q-Burst effect to SR mode index ${index}`);
    }

    // Generate Gaussian peak shape around the center index
    const peakWidthPoints = Math.round(Math.sqrt(peakSharpness) * 3); // Adjust multiplier as needed
    const startIndex = Math.max(0, centerIndex - peakWidthPoints);
    const endIndex = Math.min(RAW_FREQUENCY_POINTS, centerIndex + peakWidthPoints + 1); // +1 for loop end

    for (let i = startIndex; i < endIndex; i++) {
      const distanceSq = (i - centerIndex) * (i - centerIndex);
      spectrogram[i] += modeAmplitude * Math.exp(-distanceSq / peakSharpness);
    }
  });

  // Ensure all values are non-negative
  for (let i = 0; i < RAW_FREQUENCY_POINTS; i++) {
    spectrogram[i] = Math.max(0, spectrogram[i]);
  }

  return spectrogram;
}

// --- Publishing Logic ---
let publishIntervalTimer = null; // Store timer ID for cleanup

/** Publishes a batch of generated spectrograms to Redis Stream */
async function publishSpectrogramBatch() {
  // Check Redis connection status before attempting to publish
  if (redisClient.status !== 'ready') {
    logger.warn(
      `Redis not ready (status: ${redisClient.status}), skipping publish cycle for ${DETECTOR_ID}.`
    );
    return;
  }

  // Generate the batch of spectrograms
  const batch = [];
  for (let i = 0; i < DETECTOR_BATCH_SIZE; i++) {
    batch.push(generateSpectrogram());
  }

  // Prepare the message payload
  const message = {
    spectrogram: batch,
    timestamp: new Date().toISOString(),
    interval: INTERVAL_MS, // Include the simulation interval
    detectorId: DETECTOR_ID,
    location: { lat: LATITUDE, lon: LONGITUDE },
  };
  const messageString = JSON.stringify(message);

  try {
    // Publish to the stream using XADD
    const messageId = await redisClient.xadd(REDIS_STREAM_KEY, '*', 'data', messageString);
    logger.info(`Batch published successfully (${DETECTOR_ID})`, {
      messageId,
      batchSize: batch.length,
    });
  } catch (err) {
    logger.error(`Failed to publish batch to Redis stream (${DETECTOR_ID})`, {
      error: err.message,
    });
    // Optional: Attempt reconnect if error seems connection-related
    if (redisClient.status !== 'reconnecting' && redisClient.status !== 'connecting') {
      logger.warn(`Attempting explicit Redis reconnect due to publish error (${DETECTOR_ID})`);
      redisClient.connect().catch((connectErr) => {
        // Log additional error if explicit reconnect attempt fails
        logger.error(`Explicit reconnect attempt failed (${DETECTOR_ID})`, {
          error: connectErr.message,
        });
      });
    }
  }
}

// --- Startup Logic ---
async function startDetector() {
  logger.info(
    `Detector ${DETECTOR_ID} attempting to connect to Redis at ${REDIS_HOST}:${REDIS_PORT}...`
  );
  try {
    // Explicitly connect and wait for 'ready' or timeout/error
    await redisClient.connect(); // connect() promise resolves after 'ready' or rejects on error/timeout

    // If the promise resolved, we are connected and ready
    logger.info(
      `Detector ${DETECTOR_ID} started successfully. Redis connection established. Publishing interval: ${INTERVAL_MS}ms, Batch Size: ${DETECTOR_BATCH_SIZE}.`,
      { lat: LATITUDE.toFixed(4), lon: LONGITUDE.toFixed(4) }
    );
    // Start the periodic publishing
    publishIntervalTimer = setInterval(publishSpectrogramBatch, INTERVAL_MS);
  } catch (err) {
    // Log the error that caused connection failure (timeout or specific error)
    logger.error(
      `Detector ${DETECTOR_ID} failed to start due to Redis connection error. Exiting.`,
      {
        error: err.message,
      }
    );
    // Ensure disconnection attempt even on startup failure
    if (redisClient.status !== 'end') {
      redisClient.disconnect();
    }
    // Throw error instead of process.exit(1)
    throw new Error(`Detector ${DETECTOR_ID} failed to start: Redis connection error.`);
  }
}

// --- Shutdown Logic ---
let shuttingDown = false;
async function shutdownDetector(signal = 'UNKNOWN') {
  // Add signal parameter
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info(`Received ${signal}. Shutting down detector ${DETECTOR_ID}...`);
  process.exitCode = 0; // Default to success exit code

  // 1. Clear the interval timer to stop new publishes
  if (publishIntervalTimer) {
    clearInterval(publishIntervalTimer);
    logger.debug(`Cleared publishing interval timer for ${DETECTOR_ID}.`);
  }

  // 2. Close Redis connection gracefully
  try {
    if (
      redisClient.status !== 'end' &&
      redisClient.status !== 'closing' &&
      redisClient.status !== 'close'
    ) {
      // Check status more carefully
      logger.info(`Closing Redis connection for ${DETECTOR_ID} (Status: ${redisClient.status})...`);
      await redisClient.quit();
      logger.info(`Redis connection closed for ${DETECTOR_ID}.`);
    } else {
      logger.info(`Redis connection already closed or closing for ${DETECTOR_ID}.`);
    }
  } catch (err) {
    logger.error(`Error during Redis graceful shutdown for ${DETECTOR_ID}:`, {
      error: err.message,
    });
    process.exitCode = 1; // Set error exit code
  } finally {
    logger.info(`Detector ${DETECTOR_ID} shutdown complete. Final exit code: ${process.exitCode}.`);
    // Let Node exit naturally now that timers are cleared and connections closed
  }
}

// --- Signal Handling ---
// Listen for termination signals for graceful shutdown
process.on('SIGINT', () => shutdownDetector('SIGINT'));
process.on('SIGTERM', () => shutdownDetector('SIGTERM'));

// --- Start the Detector ---
// Use an async IIFE to handle potential startup errors
(async () => {
  try {
    await startDetector();
    logger.info(`Detector ${DETECTOR_ID} running.`);
  } catch (startupError) {
    // Startup error is already logged in startDetector
    process.exitCode = 1; // Ensure exit code reflects startup failure
    // Allow process to exit naturally with the failure code
  }
})(); // Immediately invoke the async function
