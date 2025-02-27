const express = require('express');
const WebSocket = require('ws');
const admin = require('firebase-admin');
const { createClient } = require('redis');
const Sentry = require('@sentry/node');
const rateLimit = require('express-rate-limit');
const tf = require('@tensorflow/tfjs-node');
const crypto = require('crypto');
const { registerUser, loginUser, saveFrequency, getRecentFrequencies, getHistoricalFrequencies, logUsage, getUserStats, getUsageTrends, getPresetUsage, registerApiKey, verifyApiKey } = require('./db');
const { verifyToken, verifyWebSocketToken } = require('./middleware');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

Sentry.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.2 });

admin.initializeApp({ credential: admin.credential.cert(process.env.FIREBASE_SERVICE_ACCOUNT) });

const app = express();
app.use(express.json());
const server = app.listen(process.env.PORT || 3000, () => console.log(`Server running on port ${process.env.PORT || 3000}`));
const wss = new WebSocket.Server({ server });

const redisClient = createClient({
  url: process.env.REDIS_URL,
  socket: { tls: true, rejectUnauthorized: false }
});
redisClient.on('error', (err) => Sentry.captureException(err));
await redisClient.connect().catch(err => Sentry.captureException(err));
const redisSubscriber = redisClient.duplicate();
await redisSubscriber.connect().catch(err => Sentry.captureException(err));
const redisPublisher = redisClient.duplicate();
await redisPublisher.connect().catch(err => Sentry.captureException(err));

let currentFrequency = 7.83;
let updateInterval = 5000;
const keyStore = new Map();

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(Sentry.Handlers.requestHandler());
app.use((err, req, res, next) => {
  Sentry.captureException(err);
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
    Sentry.captureException(err);
    res.status(400).json({ error: 'Username taken or database error' });
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
    Sentry.captureException(err);
    res.status(401).json({ error: err.message });
  }
});

app.get('/schumann-frequency', verifyToken, async (req, res) => {
  try {
    res.json({ frequency: currentFrequency, timestamp: new Date().toISOString(), interval: updateInterval });
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to fetch frequency' });
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
    Sentry.captureException(err);
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
    Sentry.captureException(err);
    res.status(400).json({ error: err.message || 'Failed to fetch history' });
  }
});

app.post('/log-usage', verifyToken, [
  body('duration').isInt({ min: 0 }),
  body('preset_mode').optional().isString(),
], async (req, res) => {
  try {
    await logUsage(req.user.id, req.body.duration, req.body.preset_mode);
    res.json({ message: 'Usage logged' });
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to log usage' });
  }
});

app.get('/stats', verifyToken, async (req, res) => {
  try {
    const stats = await getUserStats(req.user.id);
    res.json(stats);
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/usage-trends', verifyToken, async (req, res) => {
  try {
    const trends = await getUsageTrends(req.user.id);
    res.json(trends);
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to fetch usage trends' });
  }
});

app.get('/preset-usage', verifyToken, async (req, res) => {
  try {
    const usage = await getPresetUsage(req.user.id);
    res.json(usage);
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to fetch preset usage' });
  }
});

app.post('/register-api-key', verifyToken, async (req, res) => {
  try {
    const apiKey = await registerApiKey(req.user.id);
    res.json({ api_key: apiKey });
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to register API key' });
  }
});

app.post('/key-exchange', verifyToken, async (req, res) => {
  try {
    const key = crypto.randomBytes(32);
    keyStore.set(req.user.id, key);
    res.json({ key: key.toString('hex') });
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to exchange key' });
  }
});

app.get('/predict-frequency', verifyToken, async (req, res) => {
  try {
    const history = await getRecentFrequencies(100);
    const xs = tf.tensor2d(history.map(h => [h.frequency]), [history.length, 1]);
    const model = tf.sequential();
    model.add(tf.layers.lstm({ units: 10, inputShape: [null, 1] }));
    model.add(tf.layers.dense({ units: 1 }));
    model.compile({ optimizer: 'adam', loss: 'meanSquaredError' });
    const prediction = model.predict(xs.reshape([1, history.length, 1]));
    const predictedFreq = prediction.dataSync()[0];
    res.json({ predicted_frequency: predictedFreq });
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Prediction failed' });
  }
});

const verifyApiKeyMiddleware = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API key required' });
  try {
    const userId = await verifyApiKey(apiKey);
    if (!userId) return res.status(403).json({ error: 'Invalid API key' });
    req.userId = userId;
    next();
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'API key verification failed' });
  }
};

app.get('/public/frequency', apiLimiter, verifyApiKeyMiddleware, async (req, res) => {
  try {
    res.json({ frequency: currentFrequency, timestamp: new Date().toISOString() });
  } catch (err) {
    Sentry.captureException(err);
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
    Sentry.captureException(err);
    res.status(400).json({ error: err.message || 'Failed to fetch public history' });
  }
});

app.get('/global-stats', async (req, res) => {
  try {
    const activeUsers = await redisClient.zCard('active_users');
    const avgFreq = await pool.query(`SELECT AVG(frequency) as avg FROM frequency_history WHERE timestamp > NOW() - INTERVAL '24 hours'`);
    res.json({ active_users: activeUsers, average_frequency: avgFreq.rows[0].avg });
  } catch (err) {
    Sentry.captureException(err);
    res.status(500).json({ error: 'Failed to fetch global stats' });
  }
});

wss.on('connection', async (ws, req) => {
  const token = req.url.split('token=')[1];
  let userId;
  try {
    const decoded = await verifyWebSocketToken(token);
    userId = decoded.id;
    const key = keyStore.get(userId);
    if (!key) throw new Error('No encryption key for user');
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
    Sentry.captureException(err);
    ws.close(1008, 'Authentication required');
    return;
  }

  ws.on('close', async () => {
    console.log('Client disconnected:', userId);
    try {
      await redisSubscriber.unsubscribe(`user:${userId}`);
      await redisClient.zRem('active_users', userId.toString());
    } catch (err) {
      Sentry.captureException(err);
    }
  });

  ws.on('error', (err) => Sentry.captureException(err));
});

const fetchSchumannData = async () => {
  try {
    return 7.83 + (Math.random() - 0.5) * 0.4; // Placeholder
  } catch (err) {
    Sentry.captureException(err);
    return currentFrequency;
  }
};

const broadcastFrequency = async () => {
  try {
    const newFreq = await fetchSchumannData();
    if (Math.abs(newFreq - currentFrequency) > 0.5) {
      await admin.messaging().send({
        notification: { title: 'EarthSync Alert', body: `Frequency shifted to ${newFreq.toFixed(2)} Hz!` },
        topic: 'earthsync',
      }).catch(err => Sentry.captureException(err));
    }
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
        await redisPublisher.publish(clientChannel, `${encrypted.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}`).catch(err => Sentry.captureException(err));
      }
    }
  } catch (err) {
    Sentry.captureException(err);
  }
  setTimeout(broadcastFrequency, updateInterval);
};

setTimeout(broadcastFrequency, updateInterval);

process.on('SIGINT', async () => {
  await redisClient.quit().catch(err => Sentry.captureException(err));
  await redisSubscriber.quit().catch(err => Sentry.captureException(err));
  await redisPublisher.quit().catch(err => Sentry.captureException(err));
  await pool.end();
  server.close();
  process.exit();
});

app.use(Sentry.Handlers.errorHandler());