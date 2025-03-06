/**
 * Detector module to generate and publish spectrogram data.
 */
require('dotenv').config();
const Redis = require('ioredis');
const winston = require('winston');

const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'detector.log' })
  ]
});

const redisHost = process.env.REDIS_HOST;
const redisPort = parseInt(process.env.REDIS_PORT, 10);
const redisPassword = process.env.REDIS_PASSWORD;
const INTERVAL = parseInt(process.env.DETECTOR_INTERVAL, 10);

if (!redisHost || !redisPort || !redisPassword || !INTERVAL) {
  logger.error('Configuration missing');
  process.exit(1);
}

const redisClient = new Redis({
  host: redisHost,
  port: redisPort,
  password: redisPassword,
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

const FREQUENCY_RANGE = 5501;
const SCHUMANN_FREQUENCIES = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0];
const NOISE_LEVEL = 2.0;
const FREQUENCY_SHIFT = 0.3;
const BASE_AMPLITUDE = 15.0;
const AMPLITUDE_DECREASE_FACTOR = 0.8;

function generateSpectrogram() {
  const spectrogram = new Array(FREQUENCY_RANGE).fill(0);
  SCHUMANN_FREQUENCIES.forEach((freq, index) => {
    const shift = (Math.random() - 0.5) * FREQUENCY_SHIFT;
    const indexHz = Math.floor((freq + shift) * 100);
    const amplitudeScale = BASE_AMPLITUDE * Math.pow(AMPLITUDE_DECREASE_FACTOR, index);
    for (let i = Math.max(0, indexHz - 50); i < Math.min(FREQUENCY_RANGE, indexHz + 50); i++) {
      const distance = Math.abs(i - indexHz);
      spectrogram[i] += amplitudeScale * Math.exp(-(distance * distance) / 200);
    }
  });
  for (let i = 0; i < FREQUENCY_RANGE; i++) spectrogram[i] += Math.random() * NOISE_LEVEL;
  logger.info('Spectrogram generated', { sample: spectrogram.slice(780, 790) });
  return spectrogram;
}

async function publishSpectrogram() {
  try {
    const spectrogram = generateSpectrogram();
    const message = { spectrogram, timestamp: new Date().toISOString(), interval: INTERVAL };
    await redisClient.publish('spectrogram_updates', JSON.stringify(message));
    logger.info('Spectrogram published', { timestamp: message.timestamp });
  } catch (err) {
    logger.error('Publish failed', { error: err.message });
  }
}

async function startDetector() {
  try {
    await redisClient.ping();
    logger.info('Connected to Redis');
    setInterval(publishSpectrogram, INTERVAL);
  } catch (err) {
    logger.error('Detector start failed', { error: err.message });
    process.exit(1);
  }
}

startDetector();

process.on('SIGINT', async () => {
  logger.info('Shutting down detector...');
  try {
    await redisClient.quit();
    logger.info('Detector shut down');
    process.exit(0);
  } catch (err) {
    logger.error('Shutdown failed', { error: err.message });
    process.exit(1);
  }
});
