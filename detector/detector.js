/**
 * Detector module to generate and publish simulated spectrogram data to Redis streams.
 * Includes enhanced simulation features: diurnal variation, randomized parameters.
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
const DETECTOR_BATCH_SIZE = parseInt(process.env.DETECTOR_BATCH_SIZE, 10) || 1;
const DETECTOR_ID = process.env.DETECTOR_ID || crypto.randomUUID();
let LATITUDE = parseFloat(process.env.LATITUDE);
let LONGITUDE = parseFloat(process.env.LONGITUDE);

if (!redisHost || !redisPort || !redisPassword) { logger.error('FATAL: Redis configuration missing.'); process.exit(1); }
if (isNaN(LATITUDE) || isNaN(LONGITUDE)) { logger.warn(`Invalid/missing LAT/LON. Using random coords for ${DETECTOR_ID}.`); LATITUDE = Math.random() * 180 - 90; LONGITUDE = Math.random() * 360 - 180; }
if (INTERVAL_MS < 500) { logger.warn(`Detector interval ${INTERVAL_MS}ms is very low.`); }
if (DETECTOR_BATCH_SIZE < 1) { logger.warn(`Detector batch size must be >= 1. Using 1.`); DETECTOR_BATCH_SIZE = 1; }

// --- Redis Client Setup ---
const redisClient = new Redis({ host: redisHost, port: redisPort, password: redisPassword, retryStrategy: (times) => { const d = Math.min(times*100, 5000); logger.warn(`Redis retry ${times} in ${d}ms (${DETECTOR_ID})`); return d; }, lazyConnect: true });
redisClient.on('error', (err) => logger.error(`Redis Client Error (${DETECTOR_ID})`, { error: err.message }));
redisClient.on('connect', () => logger.info(`Redis client connected (${DETECTOR_ID}).`));

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
  const batch = [];
  for (let i = 0; i < DETECTOR_BATCH_SIZE; i++) { batch.push(generateSpectrogram()); }
  const message = { spectrogram: batch, timestamp: new Date().toISOString(), interval: INTERVAL_MS, detectorId: DETECTOR_ID, location: { lat: LATITUDE, lon: LONGITUDE } };
  const messageString = JSON.stringify(message);
  try {
    const messageId = await redisClient.xadd('spectrogram_stream', '*', 'data', messageString);
    logger.info(`Batch published (${DETECTOR_ID})`, { messageId, batchSize: batch.length });
  } catch (err) { logger.error(`Failed publish batch (${DETECTOR_ID})`, { error: err.message }); }
}

async function startDetector() {
  try {
    await redisClient.connect();
    await redisClient.ping(); // Verify connection
    logger.info(`Detector ${DETECTOR_ID} started. Pub interval ${INTERVAL_MS}ms, Batch ${DETECTOR_BATCH_SIZE}.`, { lat: LATITUDE.toFixed(4), lon: LONGITUDE.toFixed(4) });
    setInterval(publishSpectrogramBatch, INTERVAL_MS);
  } catch (err) { logger.error(`Detector ${DETECTOR_ID} failed start/connect`, { error: err.message }); process.exit(1); }
}

async function shutdownDetector() {
    logger.info(`Shutting down detector ${DETECTOR_ID}...`);
    try { if (redisClient.status === 'ready' || redisClient.status === 'connecting') { await redisClient.quit(); logger.info(`Redis closed for ${DETECTOR_ID}.`); } } catch (err) { logger.error(`Error closing Redis for ${DETECTOR_ID}:`, { error: err.message }); } finally { logger.info(`Detector ${DETECTOR_ID} shutdown complete.`); process.exit(0); }
}
process.on('SIGINT', shutdownDetector); process.on('SIGTERM', shutdownDetector);
startDetector();
