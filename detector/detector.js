// detector/detector.js
/**
 * Detector module to generate and publish simulated spectrogram data to Redis streams.
 * Includes enhanced simulation features: diurnal variation, randomized parameters, Q-bursts.
 * v1.1.28 - Linter Fixes (unused imports). Batch size fixed to 1. No backslash escapes in template literals.
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
  DETECTOR_BATCH_SIZE, // This is now fixed to 1 in constants.js
  DETECTOR_ID: CFG_DETECTOR_ID,
  LATITUDE: CFG_LATITUDE,
  LONGITUDE: CFG_LONGITUDE,
  LOG_LEVEL,
  REDIS_CONNECT_TIMEOUT_MS,
  RAW_FREQUENCY_POINTS,
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
const BATCH_SIZE = DETECTOR_BATCH_SIZE; // Use the constant (fixed at 1)

// --- Logger Setup ---
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    }),
    new winston.transports.File({
      filename: `detector-${DETECTOR_ID}.log`, // Corrected interpolation
      maxsize: 5242880,
      maxFiles: 3,
    }),
  ],
});

logger.info(`Starting detector ${DETECTOR_ID}... Log level: ${LOG_LEVEL}`); // Corrected interpolation

// --- Configuration Validation ---
if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD) {
  logger.error(
    'FATAL: Redis configuration missing (REDIS_HOST, REDIS_PORT, REDIS_PASSWORD). Exiting.'
  );
  throw new Error('Redis configuration missing.');
}
if (
  isNaN(LATITUDE) ||
  isNaN(LONGITUDE) ||
  LATITUDE < -90 ||
  LATITUDE > 90 ||
  LONGITUDE < -180 ||
  LONGITUDE > 180
) {
  logger.warn(
    `Invalid/missing LAT/LON (${LATITUDE}, ${LONGITUDE}). Generating random coordinates for ${DETECTOR_ID}.` // Corrected interpolation
  );
  LATITUDE = Math.random() * 180 - 90;
  LONGITUDE = Math.random() * 360 - 180;
}
if (INTERVAL_MS < 500) {
  logger.warn(`Detector interval ${INTERVAL_MS}ms is very low. Ensure system can handle the load.`); // Corrected interpolation
}
// --- BATCH SIZE WARNING ---
if (parseInt(process.env.DETECTOR_BATCH_SIZE, 10) > 1) {
  logger.warn(
    `DETECTOR_BATCH_SIZE environment variable is set > 1, but batch size is fixed to 1 internally for compatibility. Ignoring env var.`
  );
}
// --- END BATCH SIZE WARNING ---

// --- Redis Client Setup ---
const redisClient = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
  lazyConnect: true,
  connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
  retryStrategy: (times) => {
    const delay = Math.min(times * 150, 3000);
    logger.warn(
      `Redis connection retry attempt ${times}. Retrying in ${delay}ms... (${DETECTOR_ID})` // Corrected interpolation
    );
    return delay;
  },
  reconnectOnError: (err) => {
    logger.error(`Redis reconnect triggered on error (${DETECTOR_ID})`, { error: err.message }); // Corrected interpolation
    return true;
  },
  maxRetriesPerRequest: 3,
  showFriendlyErrorStack: process.env.NODE_ENV !== 'production',
});

redisClient.on('error', (err) =>
  logger.error(`Redis Client Error (${DETECTOR_ID})`, { error: err.message }) // Corrected interpolation
);
redisClient.on('connect', () => logger.info(`Redis client connecting... (${DETECTOR_ID})`)); // Corrected interpolation
redisClient.on('ready', () => logger.info(`Redis client ready. (${DETECTOR_ID})`)); // Corrected interpolation
redisClient.on('close', () => logger.warn(`Redis client connection closed. (${DETECTOR_ID})`)); // Corrected interpolation
redisClient.on('reconnecting', (delay) =>
  logger.warn(`Redis client reconnecting (delay: ${delay}ms)... (${DETECTOR_ID})`) // Corrected interpolation
);

// --- Simulation Logic ---
let activeQBursts = {};

function generateSpectrogram() {
  const spectrogram = new Array(RAW_FREQUENCY_POINTS).fill(0);
  const now = Date.now();
  const timeOfDayFactor = Math.sin(
    (2 * Math.PI * (now % AMPLITUDE_CYCLE_DURATION_MS)) / AMPLITUDE_CYCLE_DURATION_MS - Math.PI / 2
  );
  const amplitudeModulation = 1 + AMPLITUDE_VARIATION_FACTOR * timeOfDayFactor;
  const currentBaseAmplitude = BASE_AMPLITUDE * amplitudeModulation;
  const currentNoiseLevel =
    BASE_NOISE_LEVEL * (0.8 + Math.random() * 0.4) * (1 + 0.2 * timeOfDayFactor);

  for (let i = 0; i < RAW_FREQUENCY_POINTS; i++) {
    spectrogram[i] += Math.random() * currentNoiseLevel;
  }

  const nextActiveQBursts = {};
  for (const modeIndexStr in activeQBursts) {
    const remaining = activeQBursts[modeIndexStr] - 1;
    if (remaining > 0) {
      nextActiveQBursts[modeIndexStr] = remaining;
    } else {
      logger.info(`Q-Burst ended for SR mode index ${modeIndexStr} on ${DETECTOR_ID}`); // Corrected interpolation
    }
  }
  activeQBursts = nextActiveQBursts;

  if (Math.random() < Q_BURST_PROBABILITY) {
    const burstModeIndex =
      Q_BURST_MODE_INDICES[Math.floor(Math.random() * Q_BURST_MODE_INDICES.length)];
    if (!activeQBursts[burstModeIndex]) {
      activeQBursts[burstModeIndex] = Q_BURST_DURATION_INTERVALS;
      logger.info(
        `*** Q-Burst triggered for SR mode index ${burstModeIndex} on ${DETECTOR_ID} ***` // Corrected interpolation
      );
    }
  }

  SCHUMANN_FREQUENCIES.forEach((baseFreq, index) => {
    const freqShift = (Math.random() - 0.5) * 2 * FREQUENCY_SHIFT_MAX;
    const currentFreq = baseFreq + freqShift;
    const centerIndex = Math.round(currentFreq * POINTS_PER_HZ);
    let modeAmplitude =
      currentBaseAmplitude *
      Math.pow(AMPLITUDE_DECREASE_FACTOR, index) *
      (0.9 + Math.random() * 0.2);
    const currentBaseSharpness =
      PEAK_SHARPNESS_BASE_AVG + (Math.random() - 0.5) * 2 * PEAK_SHARPNESS_BASE_FLUCTUATION;
    let peakSharpness =
      currentBaseSharpness + (Math.random() - 0.5) * 2 * PEAK_SHARPNESS_RANDOM_VARIATION;
    peakSharpness = Math.max(50, peakSharpness);

    if (activeQBursts[index]) {
      modeAmplitude *= Q_BURST_AMP_MULTIPLIER;
      peakSharpness /= Q_BURST_SHARPNESS_DIVISOR;
      peakSharpness = Math.max(20, peakSharpness);
      logger.debug(`Applying Q-Burst effect to SR mode index ${index}`); // Corrected interpolation
    }

    const peakWidthPoints = Math.round(Math.sqrt(peakSharpness) * 3);
    const startIndex = Math.max(0, centerIndex - peakWidthPoints);
    const endIndex = Math.min(RAW_FREQUENCY_POINTS, centerIndex + peakWidthPoints + 1);

    for (let i = startIndex; i < endIndex; i++) {
      const distanceSq = (i - centerIndex) * (i - centerIndex);
      spectrogram[i] += modeAmplitude * Math.exp(-distanceSq / peakSharpness);
    }
  });

  for (let i = 0; i < RAW_FREQUENCY_POINTS; i++) {
    spectrogram[i] = Math.max(0, spectrogram[i]);
  }

  return spectrogram;
}

// --- Publishing Logic ---
let publishIntervalTimer = null;

async function publishSpectrogramBatch() {
  if (redisClient.status !== 'ready') {
    logger.warn(
      `Redis not ready (status: ${redisClient.status}), skipping publish cycle for ${DETECTOR_ID}.` // Corrected interpolation
    );
    return;
  }

  // --- BATCH SIZE FIXED TO 1 ---
  const batch = [generateSpectrogram()]; // Generate exactly one spectrogram
  // --- END BATCH SIZE FIX ---

  const message = {
    spectrogram: batch, // Send array containing the single spectrum
    timestamp: new Date().toISOString(),
    interval: INTERVAL_MS,
    detectorId: DETECTOR_ID,
    location: { lat: LATITUDE, lon: LONGITUDE },
  };
  const messageString = JSON.stringify(message);

  try {
    const messageId = await redisClient.xadd(REDIS_STREAM_KEY, '*', 'data', messageString);
    logger.info(`Published successfully (${DETECTOR_ID})`, { // Corrected interpolation
      messageId,
      batchSize: batch.length, // Will always be 1 now
    });
  } catch (err) {
    logger.error(`Failed to publish to Redis stream (${DETECTOR_ID})`, { // Corrected interpolation
      error: err.message,
    });
    if (redisClient.status !== 'reconnecting' && redisClient.status !== 'connecting') {
      logger.warn(`Attempting explicit Redis reconnect due to publish error (${DETECTOR_ID})`); // Corrected interpolation
      redisClient.connect().catch((connectErr) => {
        logger.error(`Explicit reconnect attempt failed (${DETECTOR_ID})`, { // Corrected interpolation
          error: connectErr.message,
        });
      });
    }
  }
}

// --- Startup Logic ---
async function startDetector() {
  logger.info(
    `Detector ${DETECTOR_ID} attempting to connect to Redis at ${REDIS_HOST}:${REDIS_PORT}...` // Corrected interpolation
  );
  try {
    await redisClient.connect();
    logger.info(
      `Detector ${DETECTOR_ID} started successfully. Redis connection established. Publishing interval: ${INTERVAL_MS}ms, Batch Size: ${BATCH_SIZE}.`, // Corrected interpolation
      { lat: LATITUDE.toFixed(4), lon: LONGITUDE.toFixed(4) }
    );
    publishIntervalTimer = setInterval(publishSpectrogramBatch, INTERVAL_MS);
  } catch (err) {
    logger.error(
      `Detector ${DETECTOR_ID} failed to start due to Redis connection error. Exiting.`, // Corrected interpolation
      {
        error: err.message,
      }
    );
    if (redisClient.status !== 'end') {
      redisClient.disconnect();
    }
    throw new Error(`Detector ${DETECTOR_ID} failed to start: Redis connection error.`); // Corrected interpolation
  }
}

// --- Shutdown Logic ---
let shuttingDown = false;
async function shutdownDetector(signal = 'UNKNOWN') {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info(`Received ${signal}. Shutting down detector ${DETECTOR_ID}...`); // Corrected interpolation
  process.exitCode = 0;

  if (publishIntervalTimer) {
    clearInterval(publishIntervalTimer);
    logger.debug(`Cleared publishing interval timer for ${DETECTOR_ID}.`); // Corrected interpolation
  }

  try {
    if (
      redisClient.status !== 'end' &&
      redisClient.status !== 'closing' &&
      redisClient.status !== 'close'
    ) {
      logger.info(`Closing Redis connection for ${DETECTOR_ID} (Status: ${redisClient.status})...`); // Corrected interpolation
      await redisClient.quit();
      logger.info(`Redis connection closed for ${DETECTOR_ID}.`); // Corrected interpolation
    } else {
      logger.info(`Redis connection already closed or closing for ${DETECTOR_ID}.`); // Corrected interpolation
    }
  } catch (err) {
    logger.error(`Error during Redis graceful shutdown for ${DETECTOR_ID}:`, { // Corrected interpolation
      error: err.message,
    });
    process.exitCode = 1;
  } finally {
    logger.info(`Detector ${DETECTOR_ID} shutdown complete. Final exit code: ${process.exitCode}.`); // Corrected interpolation
    // Let Node exit naturally
  }
}

// --- Signal Handling ---
process.on('SIGINT', () => shutdownDetector('SIGINT'));
process.on('SIGTERM', () => shutdownDetector('SIGTERM'));

// --- Start the Detector ---
(async () => {
  try {
    await startDetector();
    logger.info(`Detector ${DETECTOR_ID} running.`); // Corrected interpolation
  } catch (startupError) {
    process.exitCode = 1;
  }
})();
