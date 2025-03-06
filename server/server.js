/**
 * Main server entry point for EarthSync.
 * Handles API requests, WebSocket connections, and data processing.
 */
require('dotenv').config();
const express = require('express');
const Redis = require('ioredis');
const winston = require('winston');
const crypto = require('crypto');
const cors = require('cors');
const { query, end } = require('./db.js');
const { authenticateToken } = require('./middleware.js');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'server.log' })
  ]
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.error('JWT_SECRET is not defined in environment variables');
  process.exit(1);
}

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection', { reason: reason.toString(), promise });
  process.exit(1);
});

logger.info('Starting server script');

const redisHost = process.env.REDIS_HOST;
const redisPort = parseInt(process.env.REDIS_PORT, 10);
const redisPassword = process.env.REDIS_PASSWORD;

if (!redisHost || !redisPort || !redisPassword) {
  logger.error('Redis configuration missing in environment variables');
  process.exit(1);
}

logger.info('Redis configuration', { host: redisHost, port: redisPort });

const redisClient = new Redis({
  host: redisHost,
  port: redisPort,
  password: redisPassword,
  retryStrategy: (times) => (times > 10 ? null : Math.min(times * 50, 2000))
});

const redisSubscriberOptions = {
  host: redisHost,
  port: redisPort,
  password: redisPassword,
  retryStrategy: (times) => (times > 10 ? null : Math.min(times * 50, 2000))
};

async function waitForRedis(client, clientName) {
  return new Promise((resolve, reject) => {
    client.on('connect', () => resolve());
    client.on('error', (err) => reject(err));
    client.on('reconnecting', () => logger.info(`${clientName} reconnecting...`));
    setTimeout(() => reject(new Error(`${clientName} connection timed out`)), 15000);
  });
}

function encryptMessage(message, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(message, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return `${encrypted}:${iv.toString('base64')}`;
}

const userKeys = new Map();

waitForRedis(redisClient, 'Redis client').then(async () => {
  const app = express();

  app.use(cors({
    origin: 'http://localhost:3001',
    methods: ['GET', 'POST', 'DELETE'], // Added DELETE for user cleanup
    allowedHeaders: ['Content-Type', 'Authorization']
  }));

  app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      logger.error('Invalid JSON in request body', { error: err.message, body: req.body });
      return res.status(400).json({ error: 'Invalid JSON' });
    }
    next();
  });

  app.use(express.json());

  app.get('/health', (req, res) => res.status(200).json({ status: 'OK', uptime: process.uptime() }));

  app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    try {
      const checkUser = await query('SELECT username FROM users WHERE username = $1', [username]);
      if (checkUser.rows.length > 0) return res.status(400).json({ error: 'Username already exists' });

      const hashedPassword = await bcrypt.hash(password, 10);
      await query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
      logger.info('User registered', { username });
      res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
      logger.error('Registration error', { error: err.message });
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Credentials required' });

    try {
      const result = await query('SELECT password FROM users WHERE username = $1', [username]);
      if (result.rows.length === 0) return res.status(400).json({ error: 'User not found' });

      const match = await bcrypt.compare(password, result.rows[0].password);
      if (!match) return res.status(401).json({ error: 'Invalid password' });

      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
      logger.info('User logged in', { username });
      res.json({ token });
    } catch (err) {
      logger.error('Login error', { error: err.message });
      res.status(500).json({ error: 'Login failed' });
    }
  });

  app.post('/key-exchange', authenticateToken, (req, res) => {
    try {
      const key = crypto.randomBytes(32).toString('hex');
      userKeys.set(req.user.username, key);
      logger.info('Key exchanged', { username: req.user.username });
      res.json({ key });
    } catch (err) {
      logger.error('Key exchange error', { error: err.message });
      res.status(500).json({ error: 'Key exchange failed' });
    }
  });

  app.get('/history/:hours', authenticateToken, async (req, res) => {
    const hours = parseInt(req.params.hours, 10);
    if (isNaN(hours) || hours < 1 || hours > 24) return res.status(400).json({ error: 'Invalid hours' });

    try {
      const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
      const records = await redisClient.lrange('spectrogram_history', 0, -1);
      logger.info('Raw records from Redis:', records); // Debug log
      const filteredRecords = records.filter(record => {
        try {
          const parsed = JSON.parse(record);
          return parsed.timestamp >= cutoff && Array.isArray(parsed.spectrogram) && parsed.interval;
        } catch (err) {
          logger.error('Malformed record during filtering', { error: err.message, record });
          return false;
        }
      });

      const spectrograms = filteredRecords.map(record => {
        try {
          const parsed = JSON.parse(record);
          if (!Array.isArray(parsed.spectrogram)) throw new Error('Invalid spectrogram');
          return parsed.spectrogram;
        } catch (err) {
          logger.error('Malformed spectrogram record', { error: err.message, record });
          return [];
        }
      });

      if (spectrograms.length === 0) {
        logger.warn('No valid historical data found within the time range');
        return res.status(200).json([]); // Return empty array instead of 404
      }
      logger.info('Processed spectrograms:', spectrograms);
      res.json(spectrograms);
    } catch (err) {
      logger.error('History fetch error', { error: err.message });
      res.status(500).json({ error: err.message });
    }
  });

  // New DELETE endpoint for user cleanup
  app.delete('/users/:username', authenticateToken, async (req, res) => {
    try {
      const { username } = req.params;
      const result = await query('DELETE FROM users WHERE username = $1 RETURNING *', [username]);
      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      logger.info('User deleted', { username });
      res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
      logger.error('User deletion error', { error: err.message });
      res.status(500).json({ error: 'Deletion failed' });
    }
  });

  const server = app.listen(3000, () => logger.info('Server running on port 3000'));
  const wss = new WebSocket.Server({ server });

  wss.on('connection', async (ws, req) => {
    try {
      const token = new URLSearchParams(req.url.split('?')[1]).get('token');
      if (!token) {
        ws.close(1008, 'Token required');
        return;
      }

      const user = jwt.verify(token, JWT_SECRET);
      ws.user = user;
      logger.info('WebSocket client connected', { username: user.username });

      const redisSubscriber = new Redis(redisSubscriberOptions);
      redisSubscriber.subscribe('spectrogram_updates', (err) => {
        if (err) {
          logger.error('Subscription error', { error: err.message });
          ws.close(1011, 'Internal error');
        }
      });

      redisSubscriber.on('message', async (channel, message) => {
        try {
          const parsedMessage = JSON.parse(message);
          if (!parsedMessage.spectrogram || !parsedMessage.timestamp || !parsedMessage.interval) {
            throw new Error('Missing message fields');
          }

          await redisClient.lpush('spectrogram_history', JSON.stringify(parsedMessage));
          await redisClient.ltrim('spectrogram_history', 0, 999);

          const key = userKeys.get(ws.user.username);
          if (!key) {
            logger.warn('No encryption key, skipping message', { username: ws.user.username });
            return;
          }
          const encryptedMessage = encryptMessage(message, key);
          if (ws.readyState === WebSocket.OPEN) ws.send(encryptedMessage);
        } catch (err) {
          logger.error('Message processing error', { error: err.message });
        }
      });

      ws.on('close', () => {
        redisSubscriber.unsubscribe('spectrogram_updates', (err) => {
          if (err) logger.error('Unsubscribe error', { error: err.message });
        });
        redisSubscriber.quit();
        userKeys.delete(ws.user.username);
        logger.info('WebSocket client disconnected', { username: ws.user.username });
      });

      ws.on('error', (err) => logger.error('WebSocket error', { error: err.message }));
    } catch (err) {
      logger.error('Connection handler error', { error: err.message });
      ws.close(1011, 'Internal error');
    }
  });

  wss.on('error', (err) => logger.error('WebSocket server error', { error: err.message }));

  setInterval(async () => {
    try {
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const records = await redisClient.lrange('spectrogram_history', 0, -1);
      const recordsToKeep = records.filter(record => {
        try {
          return JSON.parse(record).timestamp >= cutoff;
        } catch (err) {
          logger.error('Malformed record during cleanup', { error: err.message });
          return false;
        }
      });

      await redisClient.del('spectrogram_history');
      if (recordsToKeep.length > 0) await redisClient.lpush('spectrogram_history', recordsToKeep);
      logger.info('Cleaned up spectrogram history', { remainingRecords: recordsToKeep.length });
    } catch (err) {
      logger.error('Cleanup error', { error: err.message });
    }
  }, 60 * 60 * 1000);

  process.on('SIGINT', async () => {
    logger.info('Shutting down server...');
    try {
      await redisClient.quit();
      await end();
      server.close(() => {
        logger.info('Server shut down');
        process.exit(0);
      });
    } catch (err) {
      logger.error('Shutdown error', { error: err.message });
      process.exit(1);
    }
  });
}).catch((err) => {
  logger.error('Redis initialization failed', { error: err.message });
  process.exit(1);
});
