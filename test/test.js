/**
 * Test module to validate EarthSync API endpoints and data flow.
 */
require('dotenv').config();
const Redis = require('ioredis');
const winston = require('winston');
const axios = require('axios');

const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'test.log' })
  ]
});

const redisHost = process.env.REDIS_HOST;
const redisPort = parseInt(process.env.REDIS_PORT, 10);
const redisPassword = process.env.REDIS_PASSWORD;

if (!redisHost || !redisPort || !redisPassword) {
  logger.error('Redis configuration missing');
  process.exit(1);
}

const redisClient = new Redis({
  host: redisHost,
  port: redisPort,
  password: redisPassword,
  retryStrategy: (times) => (times > 10 ? null : Math.min(times * 50, 2000))
});

const FREQUENCY_RANGE = 5501;
const SCHUMANN_FREQUENCIES = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0];
const NOISE_LEVEL = 2.0;
const FREQUENCY_SHIFT = 0.3;
const BASE_AMPLITUDE = 15.0;
const AMPLITUDE_DECREASE_FACTOR = 0.8;
const API_BASE_URL = 'http://earthsync-server:3000';

async function waitForRedis(client, clientName) {
  return new Promise((resolve, reject) => {
    client.on('connect', () => resolve());
    client.on('error', (err) => reject(err));
    client.on('reconnecting', () => logger.info(`${clientName} reconnecting...`));
    setTimeout(() => reject(new Error(`${clientName} timed out`)), 15000);
  });
}

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
  logger.info('Test spectrogram generated', { sample: spectrogram.slice(780, 790) });
  return spectrogram;
}

async function waitForServer() {
  for (let attempt = 1; attempt <= 30; attempt++) {
    try {
      const response = await axios.get(`${API_BASE_URL}/health`);
      if (response.status === 200) {
        logger.info('Server ready');
        return true;
      }
    } catch (err) {
      logger.info(`Waiting for server (attempt ${attempt}/30)...`);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
  logger.error('Server not ready within timeout');
  return false;
}

async function cleanupTestUser() {
  try {
    await axios.delete(`${API_BASE_URL}/users/testuser`, {
      headers: { Authorization: `Bearer ${process.env.TEST_TOKEN || ''}` }
    });
    logger.info('Cleaned up existing test user');
  } catch (err) {
    if (err.response?.status !== 404) {
      logger.warn('Cleanup failed or user not found', { error: err.message });
    }
  }
}

async function seedHistoricalData() {
  try {
    await redisClient.del('spectrogram_history'); // Clear existing data
    for (let i = 0; i < 5; i++) {
      const spectrogram = generateSpectrogram();
      const timestamp = new Date(Date.now() - (60 - i * 10) * 60 * 1000).toISOString(); // Data from 60 to 20 minutes ago
      const message = { spectrogram, timestamp, interval: 5000 };
      await redisClient.lpush('spectrogram_history', JSON.stringify(message));
      logger.info('Seeded historical data', { timestamp, sample: spectrogram.slice(780, 790) });
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    logger.info('Historical data seeding completed');
  } catch (err) {
    logger.error('Failed to seed historical data', { error: err.message });
    throw err;
  }
}

async function runTests() {
  try {
    await waitForRedis(redisClient, 'Redis client');
    await waitForServer();

    logger.info('Testing /health endpoint...');
    const healthResponse = await axios.get(`${API_BASE_URL}/health`);
    if (healthResponse.status === 200 && healthResponse.data.status === 'OK') logger.info('Health check passed');
    else throw new Error('Health check failed');

    // Cleanup existing test user before registration
    await cleanupTestUser();

    logger.info('Testing /register with valid data...');
    const registerResponse = await axios.post(`${API_BASE_URL}/register`, { username: 'testuser', password: 'testpass123' });
    if (registerResponse.status === 201) logger.info('Registration passed');
    else if (registerResponse.status === 400 && registerResponse.data.error === 'Username already exists') {
      logger.warn('Registration skipped: testuser already exists');
    } else {
      throw new Error('Registration failed');
    }

    logger.info('Testing /register with existing username...');
    try {
      await axios.post(`${API_BASE_URL}/register`, { username: 'testuser', password: 'anotherpass' });
      throw new Error('Registration with existing user should fail');
    } catch (err) {
      if (err.response?.status === 400) logger.info('Existing user check passed');
      else throw err;
    }

    logger.info('Testing /login with valid credentials...');
    const loginResponse = await axios.post(`${API_BASE_URL}/login`, { username: 'testuser', password: 'testpass123' });
    if (loginResponse.status === 200 && loginResponse.data.token) {
      logger.info('Login passed');
      const token = loginResponse.data.token;

      logger.info('Testing /key-exchange...');
      const keyResponse = await axios.post(`${API_BASE_URL}/key-exchange`, {}, { headers: { Authorization: `Bearer ${token}` } });
      if (keyResponse.status === 200 && keyResponse.data.key) logger.info('Key exchange passed');
      else throw new Error('Key exchange failed');

      // Seed historical data before testing /history
      await seedHistoricalData();

      logger.info('Testing /history with valid hours...');
      const historyResponse = await axios.get(`${API_BASE_URL}/history/1`, { headers: { Authorization: `Bearer ${token}` } });
      if (historyResponse.status === 200 && Array.isArray(historyResponse.data)) {
        logger.info('History passed', { dataLength: historyResponse.data.length });
      } else {
        throw new Error('History failed');
      }

      logger.info('Testing /history with invalid hours...');
      try {
        await axios.get(`${API_BASE_URL}/history/25`, { headers: { Authorization: `Bearer ${token}` } });
        throw new Error('Invalid hours should fail');
      } catch (err) {
        if (err.response?.status === 400) logger.info('Invalid hours check passed');
        else throw err;
      }

      logger.info('Testing /login with invalid password...');
      try {
        await axios.post(`${API_BASE_URL}/login`, { username: 'testuser', password: 'wrongpass' });
        throw new Error('Invalid password should fail');
      } catch (err) {
        if (err.response?.status === 401) logger.info('Invalid password check passed');
        else throw err;
      }
    } else throw new Error('Login failed');

    logger.info('All tests completed successfully');
  } catch (err) {
    logger.error('Test failed', { error: err.message, stack: err.stack });
    process.exit(1);
  } finally {
    for (let i = 0; i < 5; i++) {
      const spectrogram = generateSpectrogram();
      const timestamp = new Date(Date.now() - (4 - i) * 5000).toISOString();
      await redisClient.publish('spectrogram_updates', JSON.stringify({ spectrogram, timestamp, interval: 5000 }));
      logger.info('Test message published', { timestamp });
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    logger.info('Test messages published');
  }
}

runTests();

process.on('SIGINT', async () => {
  logger.info('Shutting down test...');
  try {
    await redisClient.quit();
    logger.info('Test shut down');
    process.exit(0);
  } catch (err) {
    logger.error('Shutdown failed', { error: err.message });
    process.exit(1);
  }
});
