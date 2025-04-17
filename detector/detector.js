// detector/detector.js
/**
 * Detector module to generate and publish simulated spectrogram data to Redis streams.
 * Includes enhanced simulation features: diurnal variation, randomized parameters.
 * v1.1.9 - Increased Redis connection timeout during startup.
 */
require('dotenv').config();
const Redis = require('ioredis');
const winston = require('winston');
const crypto = require('crypto');

// --- Logger Setup ---
const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({ format: winston.format.combine( winston.format.colorize(), winston.format.simple() ) }),
    process.env.DETECTOR_ID ? new winston.transports.File({ filename: `detector-${process.env.DETECTOR_ID}.log` }) : new winston.transports.File({ filename: 'detector.log' })
  ]
});

// --- Configuration ---
const redisHost = process.env.REDIS_HOST;
const redisPort = parseInt(process.env.REDIS_PORT, 10);
const redisPassword = process.env.REDIS_PASSWORD;
const INTERVAL_MS = parseInt(process.env.DETECTOR_INTERVAL_MS, 10) || 5000;
let DETECTOR_BATCH_SIZE = parseInt(process.env.DETECTOR_BATCH_SIZE, 10) || 1;
const DETECTOR_ID = process.env.DETECTOR_ID || crypto.randomUUID();
let LATITUDE = parseFloat(process.env.LATITUDE);
let LONGITUDE = parseFloat(process.env.LONGITUDE);
// Increased connection timeout (was 10000)
const REDIS_CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS, 10) || 20000;


if (!redisHost || !redisPort || !redisPassword) { logger.error('FATAL: Redis configuration missing.'); process.exit(1); }
if (isNaN(LATITUDE) || isNaN(LONGITUDE)) { logger.warn(`Invalid/missing LAT/LON. Using random coords for ${DETECTOR_ID}.`); LATITUDE = Math.random() * 180 - 90; LONGITUDE = Math.random() * 360 - 180; }
if (INTERVAL_MS < 500) { logger.warn(`Detector interval ${INTERVAL_MS}ms is very low.`); }
if (DETECTOR_BATCH_SIZE < 1) { logger.warn(`Detector batch size must be >= 1. Using 1.`); DETECTOR_BATCH_SIZE = 1; }

// --- Redis Client Setup ---
const redisClient = new Redis({
    host: redisHost,
    port: redisPort,
    password: redisPassword,
    lazyConnect: true, // Important: connect explicitly in startDetector
    connectTimeout: REDIS_CONNECT_TIMEOUT_MS, // Use the configured timeout for initial connect attempt
    retryStrategy: (times) => {
        const delay = Math.min(times * 100, 3000); // Shorter retry delay after initial attempt
        logger.warn(`Redis retry ${times} in ${delay}ms (${DETECTOR_ID})`);
        return delay;
    },
    reconnectOnError: (err) => {
        logger.error(`Redis reconnect on error trigger (${DETECTOR_ID})`, { error: err.message });
        // Only retry on specific errors if needed, true allows retrying on most errors
        return true;
    },
    maxRetriesPerRequest: 3 // Limit retries for commands after connection
});

redisClient.on('error', (err) => logger.error(`Redis Client Error (${DETECTOR_ID})`, { error: err.message }));
redisClient.on('connect', () => logger.info(`Redis client connecting... (${DETECTOR_ID}).`)); // Changed log slightly
redisClient.on('ready', () => logger.info(`Redis client ready (${DETECTOR_ID}).`)); // Changed log slightly
redisClient.on('close', () => logger.warn(`Redis client connection closed (${DETECTOR_ID}).`));
redisClient.on('reconnecting', () => logger.warn(`Redis client reconnecting... (${DETECTOR_ID}).`));

// --- Simulation Parameters ---
const RAW_FREQUENCY_POINTS = 5501;
const HZ_PER_POINT = 55 / (RAW_FREQUENCY_POINTS - 1);
const POINTS_PER_HZ = (RAW_FREQUENCY_POINTS - 1) / 55;
const SCHUMANN_FREQUENCIES = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0];
const BASE_NOISE_LEVEL = 1.5;
const BASE_AMPLITUDE = 12.0;
const AMPLITUDE_DECREASE_FACTOR = 0.75;
const FREQUENCY_SHIFT_MAX = 0.2;
const PEAK_SHARPNESS_BASE = 250;
const PEAK_SHARPNESS_VARIATION = 100;
const AMPLITUDE_VARIATION_FACTOR = 0.4;
const AMPLITUDE_CYCLE_DURATION_MS = 24 * 60 * 60 * 1000;

function generateSpectrogram() {
  const spectrogram = new Array(RAW_FREQUENCY_POINTS).fill(0);
  const now = Date.now();
  const timeOfDayFactor = Math.sin((2 * Math.PI * (now % AMPLITUDE_CYCLE_DURATION_MS)) / AMPLITUDE_CYCLE_DURATION_MS - (Math.PI / 2)); // Approx day/night cycle
  const amplitudeModulation = 1 + AMPLITUDE_VARIATION_FACTOR * timeOfDayFactor;
  const currentBaseAmplitude = BASE_AMPLITUDE * amplitudeModulation;
  const currentNoiseLevel = BASE_NOISE_LEVEL * (0.8 + Math.random() * 0.4) * (1 + 0.2 * timeOfDayFactor);
  // Add base noise
  for (let i = 0; i < RAW_FREQUENCY_POINTS; i++) { spectrogram[i] += Math.random() * currentNoiseLevel; }
  // Add SR peaks
  SCHUMANN_FREQUENCIES.forEach((baseFreq, index) => {
    const freqShift = (Math.random() - 0.5) * 2 * FREQUENCY_SHIFT_MAX;
    const currentFreq = baseFreq + freqShift;
    const centerIndex = Math.round(currentFreq * POINTS_PER_HZ);
    const modeAmplitude = currentBaseAmplitude * Math.pow(AMPLITUDE_DECREASE_FACTOR, index) * (0.9 + Math.random() * 0.2); // Add small random amplitude variation
    const peakSharpness = PEAK_SHARPNESS_BASE + (Math.random() - 0.5) * 2 * PEAK_SHARPNESS_VARIATION;
    const peakWidthPoints = Math.round(Math.sqrt(peakSharpness * 6) * 1.5); // Approximate width for iteration
    const startIndex = Math.max(0, centerIndex - peakWidthPoints);
    const endIndex = Math.min(RAW_FREQUENCY_POINTS, centerIndex + peakWidthPoints);
    for (let i = startIndex; i < endIndex; i++) {
      const distanceSq = (i - centerIndex) * (i - centerIndex);
      spectrogram[i] += modeAmplitude * Math.exp(-distanceSq / peakSharpness);
    }
  });
  // Ensure non-negative values
  for (let i = 0; i < RAW_FREQUENCY_POINTS; i++) { spectrogram[i] = Math.max(0, spectrogram[i]); }
  return spectrogram;
}

async function publishSpectrogramBatch() {
  // Check connection status before publishing
  if (redisClient.status !== 'ready') {
       logger.warn(`Redis not ready, skipping publish (${DETECTOR_ID}) (Status: ${redisClient.status})`);
       return;
  }

  const batch = [];
  for (let i = 0; i < DETECTOR_BATCH_SIZE; i++) { batch.push(generateSpectrogram()); }
  const message = { spectrogram: batch, timestamp: new Date().toISOString(), interval: INTERVAL_MS, detectorId: DETECTOR_ID, location: { lat: LATITUDE, lon: LONGITUDE } };
  const messageString = JSON.stringify(message);
  try {
    const messageId = await redisClient.xadd('spectrogram_stream', '*', 'data', messageString);
    logger.info(`Batch published (${DETECTOR_ID})`, { messageId, batchSize: batch.length });
  } catch (err) {
    logger.error(`Failed publish batch (${DETECTOR_ID})`, { error: err.message });
    // Optional: check if the error is connection related and attempt reconnect if status isn't 'connecting'
    if (redisClient.status !== 'reconnecting' && redisClient.status !== 'connecting') {
        logger.warn(`Attempting explicit reconnect due to publish error (${DETECTOR_ID})`);
        redisClient.connect().catch(connectErr => {
            logger.error(`Explicit reconnect attempt failed (${DETECTOR_ID})`, { error: connectErr.message });
        });
    }
  }
}

async function startDetector() {
  logger.info(`Detector ${DETECTOR_ID} attempting to connect to Redis at ${redisHost}:${redisPort}...`);
  try {
    // Explicitly connect and wait for 'ready' or timeout/error
    await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error(`Redis connection timeout after ${REDIS_CONNECT_TIMEOUT_MS}ms`));
            // Attempt to disconnect if timeout occurs to prevent lingering connection attempts
            redisClient.disconnect();
        }, REDIS_CONNECT_TIMEOUT_MS);

        redisClient.once('ready', () => {
            clearTimeout(timeout);
            resolve();
        });

        redisClient.once('error', (err) => { // Catch errors during the initial connect sequence
            clearTimeout(timeout);
            logger.error(`Redis initial connection error (${DETECTOR_ID})`, { error: err.message });
            reject(err);
        });

        // Start the connection attempt
        redisClient.connect().catch(err => {
            // This catch might be redundant if the 'error' event fires, but good for safety
             clearTimeout(timeout);
             logger.error(`Redis .connect() promise rejected (${DETECTOR_ID})`, { error: err.message });
             reject(err);
        });
    });

    // If the promise resolved, we are connected and ready
    logger.info(`Detector ${DETECTOR_ID} started. Redis connection successful. Pub interval ${INTERVAL_MS}ms, Batch ${DETECTOR_BATCH_SIZE}.`, { lat: LATITUDE.toFixed(4), lon: LONGITUDE.toFixed(4) });
    setInterval(publishSpectrogramBatch, INTERVAL_MS);

  } catch (err) {
    // Log the error that caused the promise rejection (timeout or connection error)
    logger.error(`Detector ${DETECTOR_ID} failed start/connect`, { error: err.message });
    // Ensure disconnection before exiting
    if (redisClient.status !== 'end') {
      redisClient.disconnect();
    }
    process.exit(1);
  }
}

// Graceful shutdown
let shuttingDown = false;
async function shutdownDetector() {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info(`Shutting down detector ${DETECTOR_ID}...`);
    // Clear the interval timer to prevent further publishes during shutdown
    const intervalTimers = setInterval(() => {}, 10000); // Get all interval timers
    for (let i = 0; i <= intervalTimers; i++) { // This is a bit hacky, might need a specific timer handle
        clearInterval(i);
    }
    logger.debug(`Cleared interval timers for ${DETECTOR_ID}.`);

    try {
        if (redisClient.status !== 'end') { // Check if already closed/disconnected
            logger.info(`Closing Redis connection for ${DETECTOR_ID} (Status: ${redisClient.status})...`);
            // Give Redis a moment to send any buffered commands if needed, then quit.
            // Using disconnect() is immediate, quit() tries to wait. Let's use disconnect() for faster shutdown.
            redisClient.disconnect();
            logger.info(`Redis disconnected for ${DETECTOR_ID}.`);
        } else {
             logger.info(`Redis connection already closed for ${DETECTOR_ID}.`);
        }
    } catch (err) {
        logger.error(`Error closing Redis for ${DETECTOR_ID}:`, { error: err.message });
    } finally {
        logger.info(`Detector ${DETECTOR_ID} shutdown complete.`);
        process.exit(0);
    }
}

process.on('SIGINT', shutdownDetector);
process.on('SIGTERM', shutdownDetector);

// Start the detector logic
startDetector();
