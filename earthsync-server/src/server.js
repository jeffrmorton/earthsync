const express = require('express');
const WebSocket = require('ws');
const { createClient } = require('redis');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { registerUser, loginUser, saveFrequency, getRecentFrequencies, getHistoricalFrequencies, logUsage, getUserStats, getUsageTrends, getPresetUsage, registerApiKey, verifyApiKey } = require('./db');
const { verifyToken, verifyWebSocketToken } = require('./middleware');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

// Catch unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason.stack || reason);
  process.exit(1);
});

const app = express();
app.use(express.json());
const server = app.listen(process.env.PORT || 3000, () => console.log(`Server running on port ${process.env.PORT || 3000}`));
const wss = new WebSocket.Server({ server });

// Redis clients setup
const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 50, 500),
    connectTimeout: 10000
  }
});
redisClient.on('error', (err) => console.error('Redis client error:', err));

const redisSubscriber = redisClient.duplicate();
redisSubscriber.on('error', (err) => console.error('Redis subscriber error:', err));

const redisPublisher = redisClient.duplicate();
redisPublisher.on('error', (err) => console.error('Redis publisher error:', err));

let currentFrequency = 7.83;
let updateInterval = 5000;
const keyStore = new Map();

// Initialize Redis
async function initialize() {
  try {
    console.log('Attempting to connect to Redis client...');
    await redisClient.connect();
    console.log('Redis client connected');
    
    console.log('Attempting to connect to Redis subscriber...');
    await redisSubscriber.connect();
    console.log('Redis subscriber connected');
    
    console.log('Attempting to connect to Redis publisher...');
    await redisPublisher.connect();
    console.log('Redis publisher connected');
    
    console.log('Redis connections initialized successfully');
  } catch (err) {
    console.error('Initialization failed:', err.stack);
    process.exit(1);
  }
}

initialize().catch(err => {
  console.error('Initialize catch block triggered:', err.stack);
  process.exit(1);
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

// Middleware definition moved before route usage
const verifyApiKeyMiddleware = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API key required' });
  try {
    const userId = await verifyApiKey(apiKey);
    if (!userId) return res.status(403).json({ error: 'Invalid API key' });
    req.userId = userId;
    next();
  } catch (err) {
    console.error('API key verification error:', err);
    res.status(500).json({ error: 'API key verification failed' });
  }
};

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    await registerUser(req.body.username, req.body.password);
    res.json({ message: 'User registered' });
  } catch (err) {
    console.error('Register error:', err.message, err.stack);
    res.status(400).json({ error: err.message || 'Username taken or database error' });
  }
});

app.post('/login', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('password').isLength({ min: 6 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const user = await loginUser(req.body.username, req.body.password);
    const token = require('jsonwebtoken').sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(401).json({ error: err.message });
  }
});

app.get('/schumann-frequency', verifyToken, async (req, res) => {
  try {
    res.json({ frequency: currentFrequency, timestamp: new Date().toISOString(), interval: updateInterval });
  } catch (err) {
    console.error('Get frequency error:', err);
    res.status(500).json({ error: 'Failed to fetch frequency' });
  }
});

app.post('/schumann-frequency', verifyApiKeyMiddleware, [
  body('frequency').isFloat().notEmpty(),
  body('timestamp').optional().isString()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { frequency, timestamp } = req.body;
    await saveFrequency(frequency);
    res.json({ message: 'Frequency recorded', frequency, timestamp });
  } catch (err) {
    console.error('Post frequency error:', err);
    res.status(500).json({ error: 'Failed to record frequency' });
  }
});

app.post('/set-interval', verifyToken, [
  body('interval').isInt({ min: 1000, max: 60000 }),
  body('activity').optional().isIn(['Active', 'Background']),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    updateInterval = req.body.activity === 'Background' ? Math.max(req.body.interval, 30000) : req.body.interval;
    res.json({ message: 'Update interval set', interval: updateInterval });
  } catch (err) {
    console.error('Set interval error:', err);
    res.status(500).json({ error: 'Failed to set interval' });
  }
});

app.get('/history/:hours', verifyToken, async (req, res) => {
  try {
    const hours = parseInt(req.params.hours);
    if (isNaN(hours)) throw new Error('Invalid hours parameter');
    const data = await getHistoricalFrequencies(hours);
    res.json(data);
  } catch (err) {
    console.error('Get history error:', err);
    res.status(400).json({ error: err.message || 'Failed to fetch history' });
  }
});

app.post('/log-usage', verifyToken, [
  body('duration').isInt({ min: 0 }),
  body('preset_mode').optional().isString(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    await logUsage(req.user.id, req.body.duration, req.body.preset_mode);
    res.json({ message: 'Usage logged' });
  } catch (err) {
    console.error('Log usage error:', err);
    res.status(500).json({ error: 'Failed to log usage' });
  }
});

app.get('/stats', verifyToken, async (req, res) => {
  try {
    const stats = await getUserStats(req.user.id);
    res.json(stats);
  } catch (err) {
    console.error('Get stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/usage-trends', verifyToken, async (req, res) => {
  try {
    const trends = await getUsageTrends(req.user.id);
    res.json(trends);
  } catch (err) {
    console.error('Get usage trends error:', err);
    res.status(500).json({ error: 'Failed to fetch usage trends' });
  }
});

app.get('/preset-usage', verifyToken, async (req, res) => {
  try {
    const usage = await getPresetUsage(req.user.id);
    res.json(usage);
  } catch (err) {
    console.error('Get preset usage error:', err);
    res.status(500).json({ error: 'Failed to fetch preset usage' });
  }
});

app.post('/register-api-key', verifyToken, async (req, res) => {
  try {
    const apiKey = await registerApiKey(req.user.id);
    res.json({ api_key: apiKey });
  } catch (err) {
    console.error('Register API key error:', err);
    res.status(500).json({ error: 'Failed to register API key' });
  }
});

app.post('/key-exchange', verifyToken, async (req, res) => {
  try {
    const key = crypto.randomBytes(32);
    keyStore.set(req.user.id, key);
    res.json({ key: key.toString('hex') });
  } catch (err) {
    console.error('Key exchange error:', err);
    res.status(500).json({ error: 'Failed to exchange key' });
  }
});

app.get('/public/frequency', apiLimiter, verifyApiKeyMiddleware, async (req, res) => {
  try {
    res.json({ frequency: currentFrequency, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error('Get public frequency error:', err);
    res.status(500).json({ error: 'Failed to fetch public frequency' });
  }
});

app.get('/public/history/:hours', apiLimiter, verifyApiKeyMiddleware, async (req, res) => {
  try {
    const hours = parseInt(req.params.hours);
    if (isNaN(hours)) throw new Error('Invalid hours parameter');
    const data = await getHistoricalFrequencies(hours);
    res.json(data);
  } catch (err) {
    console.error('Get public history error:', err);
    res.status(400).json({ error: err.message || 'Failed to fetch public history' });
  }
});

app.get('/global-stats', async (req, res) => {
  try {
    const activeUsers = await redisClient.zCard('active_users');
    const avgFreq = await pool.query(`SELECT AVG(frequency) as avg FROM frequency_history WHERE timestamp > NOW() - INTERVAL '24 hours'`);
    res.json({ active_users: activeUsers, average_frequency: avgFreq.rows[0].avg });
  } catch (err) {
    console.error('Get global stats error:', err);
    res.status(500).json({ error: 'Failed to fetch global stats' });
  }
});

wss.on('connection', async (ws, req) => {
  const token = req.url.split('token=')[1];
  let userId;
  try {
    if (!token) throw new Error('No token provided');
    const decoded = await verifyWebSocketToken(token);
    userId = decoded.id;
    const key = keyStore.get(userId);
    if (!key) {
      ws.close(1008, 'No encryption key. Call /key-exchange first.');
      return;
    }
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify({ frequency: currentFrequency, timestamp: new Date().toISOString(), interval: updateInterval })), cipher.final()]);
    const authTag = cipher.getAuthTag();
    ws.send(`${encrypted.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}`);
    console.log('Client connected:', userId);

    const channel = `user:${userId}`;
    await redisSubscriber.subscribe(channel, (message) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    });
    await redisClient.zAdd('active_users', { score: Date.now(), value: userId.toString() });
  } catch (err) {
    console.error('WebSocket connection error:', err.message);
    ws.close(1008, err.message === 'jwt must be provided' ? 'Authentication required: No token' : err.message);
    return;
  }

  ws.on('close', async () => {
    console.log('Client disconnected:', userId);
    try {
      await redisSubscriber.unsubscribe(`user:${userId}`);
      await redisClient.zRem('active_users', userId.toString());
    } catch (err) {
      console.error('WebSocket close error:', err);
    }
  });

  ws.on('error', (err) => console.error('WebSocket error:', err));
});

const fetchSchumannData = async () => {
  try {
    return 7.83 + (Math.random() - 0.5) * 0.4; // Placeholder
  } catch (err) {
    console.error('Fetch Schumann data error:', err);
    return currentFrequency;
  }
};

const broadcastFrequency = async () => {
  try {
    const newFreq = await fetchSchumannData();
    currentFrequency = newFreq;
    const timestamp = new Date().toISOString();
    await saveFrequency(currentFrequency);

    const message = JSON.stringify({ frequency: currentFrequency, timestamp, interval: updateInterval });
    const clients = await redisClient.keys('user:*');
    for (const clientChannel of clients) {
      const userId = clientChannel.split(':')[1];
      const key = keyStore.get(parseInt(userId));
      if (key) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
        const authTag = cipher.getAuthTag();
        await redisPublisher.publish(clientChannel, `${encrypted.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}`).catch(err => console.error('Redis publish error:', err));
      }
    }
  } catch (err) {
    console.error('Broadcast frequency error:', err);
  }
  setTimeout(broadcastFrequency, updateInterval);
};

setTimeout(broadcastFrequency, updateInterval);

process.on('SIGINT', async () => {
  await redisClient.quit().catch(err => console.error('Redis client quit error:', err));
  await redisSubscriber.quit().catch(err => console.error('Redis subscriber quit error:', err));
  await redisPublisher.quit().catch(err => console.error('Redis publisher quit error:', err));
  await pool.end();
  server.close();
  process.exit();
});