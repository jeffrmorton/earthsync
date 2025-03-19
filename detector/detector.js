/**
 * Detector module to generate and publish spectrogram data to Redis streams with multi-detector support.
 */
require('dotenv').config();
const Redis = require('ioredis');
const winston = require('winston');
const crypto = require('crypto');

const logLevel = process.env.LOG_LEVEL || 'warn';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console(), new winston.transports.File({ filename: 'detector.log' })]
});

const redisHost = process.env.REDIS_HOST;
const redisPort = parseInt(process.env.REDIS_PORT, 10);
const redisPassword = process.env.REDIS_PASSWORD;
const INTERVAL = parseInt(process.env.DETECTOR_INTERVAL, 10) || 5000;
const DETECTOR_BATCH_SIZE = parseInt(process.env.DETECTOR_BATCH_SIZE, 10) || 2;
const DETECTOR_ID = process.env.DETECTOR_ID || crypto.randomUUID();
const LATITUDE = parseFloat(process.env.LATITUDE) || (Math.random() * 180 - 90);
const LONGITUDE = parseFloat(process.env.LONGITUDE) || (Math.random() * 360 - 180);

if (!redisHost || !redisPort || !redisPassword) {
  logger.error('Configuration missing');
  process.exit(1);
}

const redisClient = new Redis({
  host: redisHost,
  port: redisPort,
  password: redisPassword,
  retryStrategy: (times) => Math.min(times * 50, 10000)
});

const FREQUENCY_RANGE = 5501;
const SCHUMANN_FREQUENCIES = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0];
const NOISE_LEVEL_BASE = 2.0;
const FREQUENCY_SHIFT = 0.3;
const BASE_AMPLITUDE = 15.0;
const AMPLITUDE_VARIATION = 0.3;
const AMPLITUDE_CYCLE_DURATION = 24 * 60 * 60 * 1000;
const AMPLITUDE_DECREASE_FACTOR_BASE = 0.8;

function generateSpectrogram() {
  const spectrogram = new Array(FREQUENCY_RANGE).fill(0);
  const noiseLevel = NOISE_LEVEL_BASE * (0.8 + Math.random() * 0.4);
  const amplitudeDecreaseFactor = AMPLITUDE_DECREASE_FACTOR_BASE * (0.9 + Math.random() * 0.2);
  const now = Date.now();
  const timeFactor = Math.sin(2 * Math.PI * (now % AMPLITUDE_CYCLE_DURATION) / AMPLITUDE_CYCLE_DURATION);
  const amplitudeMod = 1 + AMPLITUDE_VARIATION * timeFactor;

  SCHUMANN_FREQUENCIES.forEach((freq, index) => {
    const shift = (Math.random() - 0.5) * FREQUENCY_SHIFT;
    const indexHz = Math.floor((freq + shift) * 100);
    const amplitudeScale = BASE_AMPLITUDE * amplitudeMod * Math.pow(amplitudeDecreaseFactor, index);
    for (let i = Math.max(0, indexHz - 50); i < Math.min(FREQUENCY_RANGE, indexHz + 50); i++) {
      const distance = Math.abs(i - indexHz);
      spectrogram[i] += amplitudeScale * Math.exp(-(distance * distance) / 200);
    }
  });
  for (let i = 0; i < FREQUENCY_RANGE; i++) spectrogram[i] += Math.random() * noiseLevel;
  logger.info('Spectrogram generated', { sample: spectrogram.slice(0, 5), sampleEnd: spectrogram.slice(-5), amplitudeMod });
  return spectrogram;
}

async function publishSpectrogramBatch() {
  const batch = [];
  for (let i = 0; i < DETECTOR_BATCH_SIZE; i++) {
    batch.push(generateSpectrogram());
  }
  const message = { 
    spectrogram: batch, 
    timestamp: new Date().toISOString(), 
    interval: INTERVAL, 
    detectorId: DETECTOR_ID, 
    location: { lat: LATITUDE, lon: LONGITUDE } 
  };
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await redisClient.xadd('spectrogram_stream', '*', 'data', JSON.stringify(message));
      logger.info('Spectrogram batch published to stream', { detectorId: DETECTOR_ID, timestamp: message.timestamp, count: batch.length });
      return;
    } catch (err) {
      logger.error(`Publish attempt ${attempt} failed`, { error: err.message });
      if (attempt === 3) {
        logger.error('Max retries reached, giving up');
      } else {
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }
}

async function startDetector() {
  try {
    await redisClient.ping();
    logger.info('Connected to Redis', { detectorId: DETECTOR_ID, lat: LATITUDE, lon: LONGITUDE });
    setInterval(publishSpectrogramBatch, INTERVAL * DETECTOR_BATCH_SIZE);
  } catch (err) {
    logger.error('Detector start failed', { error: err.message });
    process.exit(1);
  }
}

startDetector();

process.on('SIGINT', async () => {
  logger.info('Shutting down detector...', { detectorId: DETECTOR_ID });
  try {
    await redisClient.quit();
    logger.info('Detector shut down');
    process.exit(0);
  } catch (err) {
    logger.error('Shutdown failed', { error: err.message });
    process.exit(1);
  }
});
