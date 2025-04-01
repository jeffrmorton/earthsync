/**
 * Main server entry point for EarthSync (v1.1.8).
 * Handles API requests, WebSocket connections, and data processing.
 * Includes Enhanced Peak Detection (Smoothing, Prominence, Min Distance, Interpolated Q-Factor).
 * Placeholders added for Peak Tracking & Transient Detection.
 */
require('dotenv').config();
const express = require('express');
const Redis = require('ioredis');
const winston = require('winston');
const crypto = require('crypto');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { query, end: endDbPool } = require('./db.js');
const { authenticateToken } = require('./middleware.js');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const promClient = require('prom-client');
const http = require('http');
const { body, header, param, query: queryValidator, validationResult } = require('express-validator');

// --- Winston Logger Setup ---
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
    new winston.transports.Console({ format: winston.format.combine(winston.format.colorize(), winston.format.simple()) }),
    new winston.transports.File({ filename: 'server.log' })
  ],
  exitOnError: false
});

// --- Prometheus Metrics Setup ---
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });
const httpRequestCounter = new promClient.Counter({ name: 'http_requests_total', help: 'Total HTTP requests', labelNames: ['method', 'route', 'status'], registers: [register] });
const websocketConnections = new promClient.Gauge({ name: 'websocket_connections_active', help: 'Active WebSocket connections', registers: [register] });
const httpRequestLatency = new promClient.Histogram({ name: 'http_request_latency_seconds', help: 'HTTP request latency', labelNames: ['method', 'route'], buckets: [0.1, 0.5, 1, 2, 5], registers: [register] });
const dataIngestCounter = new promClient.Counter({ name: 'data_ingest_requests_total', help: 'Total data ingest requests', labelNames: ['status'], registers: [register] });
const peaksDetectedCounter = new promClient.Counter({ name: 'peaks_detected_total', help: 'Total peaks detected during processing', labelNames: ['detectorId'], registers: [register] });


// --- Environment Variables & Constants ---
const JWT_SECRET = process.env.JWT_SECRET;
const CLEANUP_INTERVAL_MS = parseInt(process.env.CLEANUP_INTERVAL_MS, 10) || 3600000;
const DOWNSAMPLE_FACTOR = parseInt(process.env.DOWNSAMPLE_FACTOR, 10) || 5;
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = parseInt(process.env.REDIS_PORT, 10);
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || 'http://localhost:3001').split(',');
const ENCRYPTION_KEY_TTL_SECONDS = 3600;
const REDIS_KEY_PREFIX = 'userkey:';
const API_INGEST_KEY = process.env.API_INGEST_KEY;
const RAW_FREQUENCY_POINTS = 5501; // Expected length of raw spectrum data
const FREQUENCY_RESOLUTION_HZ = 55 / (RAW_FREQUENCY_POINTS - 1);

// Peak Detection Parameters from .env
let PEAK_SMOOTHING_WINDOW = parseInt(process.env.PEAK_SMOOTHING_WINDOW, 10) || 5; // Points for moving average
let PEAK_PROMINENCE_FACTOR = parseFloat(process.env.PEAK_PROMINENCE_FACTOR || 1.5); // Factor applied to baseline noise for prominence
let PEAK_MIN_DISTANCE_HZ = parseFloat(process.env.PEAK_MIN_DISTANCE_HZ || 1.0); // Minimum Hz between peaks
let PEAK_MIN_DISTANCE_POINTS = Math.max(1, Math.round(PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ));
let PEAK_ABSOLUTE_THRESHOLD = parseFloat(process.env.PEAK_ABSOLUTE_THRESHOLD || 1.0); // Minimum absolute amplitude for a peak

if (!JWT_SECRET) { logger.error('FATAL: JWT_SECRET is not defined.'); process.exit(1); }
if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD) { logger.error('FATAL: Redis configuration missing.'); process.exit(1); }
if (!API_INGEST_KEY) { logger.warn('API_INGEST_KEY is not set. Data ingest endpoint will be disabled.'); }
if (PEAK_SMOOTHING_WINDOW < 1 || PEAK_SMOOTHING_WINDOW % 2 === 0) { logger.warn(`PEAK_SMOOTHING_WINDOW must be a positive odd integer. Using default 5.`); PEAK_SMOOTHING_WINDOW = 5; }
if (PEAK_PROMINENCE_FACTOR <= 0) { logger.warn(`PEAK_PROMINENCE_FACTOR must be positive. Using default 1.5.`); PEAK_PROMINENCE_FACTOR = 1.5; }
if (PEAK_MIN_DISTANCE_HZ <= 0) { logger.warn(`PEAK_MIN_DISTANCE_HZ must be positive. Using default 1.0.`); PEAK_MIN_DISTANCE_HZ = 1.0; PEAK_MIN_DISTANCE_POINTS = Math.max(1, Math.round(PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ)); }
if (PEAK_ABSOLUTE_THRESHOLD < 0) { logger.warn(`PEAK_ABSOLUTE_THRESHOLD cannot be negative. Using default 1.0.`); PEAK_ABSOLUTE_THRESHOLD = 1.0; }

// --- Global Error Handling ---
process.on('uncaughtException', (err) => { logger.error('UNCAUGHT EXCEPTION', { error: err.message, stack: err.stack }); process.exit(1); });
process.on('unhandledRejection', (reason, promise) => { logger.error('UNHANDLED REJECTION', { reason: reason?.toString(), stack: reason?.stack, promise }); });

logger.info(`Starting EarthSync server v1.1.8 on port ${PORT}...`);
logger.info(`Allowed CORS origins: ${ALLOWED_ORIGINS.join(', ')}`);
logger.info(`Peak Detection Params: SmoothWin=${PEAK_SMOOTHING_WINDOW}, PromFactor=${PEAK_PROMINENCE_FACTOR}, MinDistHz=${PEAK_MIN_DISTANCE_HZ} (${PEAK_MIN_DISTANCE_POINTS}pts), AbsThresh=${PEAK_ABSOLUTE_THRESHOLD}`);


// --- Redis Client Setup ---
const redisClient = new Redis({ host: REDIS_HOST, port: REDIS_PORT, password: REDIS_PASSWORD, keyPrefix: REDIS_KEY_PREFIX, retryStrategy: (times) => { const d = Math.min(times*100, 5000); logger.warn(`Redis(main) retry ${times} in ${d}ms`); return d; }, reconnectOnError: (err) => { logger.error('Redis(main) reconn err', {e:err.message}); return true; }, lazyConnect: true });
const streamRedisClient = new Redis({ host: REDIS_HOST, port: REDIS_PORT, password: REDIS_PASSWORD, retryStrategy: (times) => Math.min(times*100, 5000), reconnectOnError: () => true, lazyConnect: true });

redisClient.on('error', (err) => logger.error('Main Redis Client Error', { error: err.message }));
redisClient.on('connect', () => logger.info('Main Redis client connected.'));
redisClient.on('ready', () => logger.info('Main Redis client ready.'));
streamRedisClient.on('error', (err) => logger.error('Stream/History Redis Client Error', { error: err.message }));
streamRedisClient.on('connect', () => logger.info('Stream/History Redis client connected.'));
streamRedisClient.on('ready', () => logger.info('Stream/History Redis client ready.'));


// --- Express App Setup ---
const app = express();
const server = http.createServer(app);
app.use(cors({ origin: (origin, callback) => { if (!origin || ALLOWED_ORIGINS.includes(origin)) { callback(null, true); } else { logger.warn('CORS blocked', { origin }); callback(new Error('Not allowed by CORS')); } }, methods: ['GET', 'POST', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'] }));
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// --- Request Logging and Latency Middleware ---
app.use((req, res, next) => {
  const start = process.hrtime();
  res.on('finish', () => {
    const diff = process.hrtime(start); const latency = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(3);
    const route = req.originalUrl.split('?')[0];
    httpRequestCounter.inc({ method: req.method, route: route, status: res.statusCode });
    httpRequestLatency.observe({ method: req.method, route: route }, parseFloat(latency) / 1000);
    logger.debug('HTTP Request', { method: req.method, url: req.originalUrl, status: res.statusCode, latency_ms: latency, ip: req.ip });
  });
  next();
});

// --- Input Validation Middleware ---
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) { logger.warn('Input validation failed', { errors: errors.array(), url: req.originalUrl }); return res.status(400).json({ error: errors.array()[0].msg }); }
  next();
};

// --- API Key Authentication Middleware ---
const authenticateApiKey = (req, res, next) => {
    if (!API_INGEST_KEY) { logger.error('Data ingest fail: API_INGEST_KEY not configured.'); return res.status(503).json({ error: 'Data ingest service unavailable.' }); }
    const providedKey = req.headers['x-api-key'];
    if (!providedKey || providedKey !== API_INGEST_KEY) { logger.warn('Data ingest fail: Invalid API key.', { ip: req.ip }); dataIngestCounter.inc({ status: 'forbidden' }); return res.status(403).json({ error: 'Forbidden: Invalid API Key' }); }
    next();
};

// --- Rate Limiting ---
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many auth attempts.' }, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 1*60*1000, max: 100, message: { error: 'Too many API requests.' }, standardHeaders: true, legacyHeaders: false });
const ingestLimiter = rateLimit({ windowMs: 1*60*1000, max: 120, message: { error: 'Too many ingest requests.' }, standardHeaders: true, legacyHeaders: false });

// --- API Routes (Health, Register, Login, Key Exchange) ---
app.get('/health', async (req, res, next) => { /* ... unchanged ... */
  try {
    const redisPing = await redisClient.ping();
    const streamRedisPing = await streamRedisClient.ping();
    await query('SELECT 1');
    res.status(200).json({ status: 'OK', uptime: process.uptime().toFixed(2), redis_main: redisPing === 'PONG' ? 'OK' : 'Error', redis_stream: streamRedisPing === 'PONG' ? 'OK' : 'Error', postgres: 'OK' });
  } catch (err) { logger.error('Health check failed', { error: err.message }); next(err); }
});
const registerValidationRules = [ body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 chars.').matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid chars in username.'), body('password').isLength({ min: 8 }).withMessage('Password must be >= 8 chars.') ];
app.post('/register', authLimiter, registerValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged ... */
  const { username, password } = req.body; try { const checkUser = await query('SELECT username FROM users WHERE username = $1', [username]); if (checkUser.rows.length > 0) { return res.status(409).json({ error: 'Username already exists' }); } const hashedPassword = await bcrypt.hash(password, 10); await query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]); logger.info('User registered', { username }); res.status(201).json({ message: 'Registration successful' }); } catch (err) { logger.error('Registration error', { username, error: err.message }); next(err); }
});
const loginValidationRules = [ body('username').trim().notEmpty().withMessage('Username required.'), body('password').notEmpty().withMessage('Password required.') ];
app.post('/login', authLimiter, loginValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged ... */
  const { username, password } = req.body; try { const result = await query('SELECT id, username, password FROM users WHERE username = $1', [username]); if (result.rows.length === 0) { logger.warn('Login fail: User not found', { username }); return res.status(401).json({ error: 'Invalid username or password' }); } const user = result.rows[0]; const match = await bcrypt.compare(password, user.password); if (!match) { logger.warn('Login fail: Invalid password', { username }); return res.status(401).json({ error: 'Invalid username or password' }); } const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: `${ENCRYPTION_KEY_TTL_SECONDS}s` }); logger.info('User logged in', { username }); res.json({ token }); } catch (err) { logger.error('Login error', { username, error: err.message }); next(err); }
});
app.post('/key-exchange', apiLimiter, authenticateToken, async (req, res, next) => { /* ... unchanged ... */
  const username = req.user.username; try { const key = crypto.randomBytes(32).toString('hex'); const redisKey = `${username}`; await redisClient.setex(redisKey, ENCRYPTION_KEY_TTL_SECONDS, key); logger.info('Key generated/stored', { username, redisKey: REDIS_KEY_PREFIX + redisKey }); res.json({ key }); } catch (err) { logger.error('Key exchange error', { username, error: err.message }); next(err); }
});

// Historical Data (Spectrogram Only)
const historyValidationRules = [ param('hours').isInt({ min: 1, max: 72 }).withMessage('Hours must be 1-72.'), queryValidator('detectorId').optional().isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detector ID.') ];
app.get('/history/:hours', apiLimiter, authenticateToken, historyValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged structure, logic was okay ... */
  const hours = parseInt(req.params.hours, 10); const { detectorId } = req.query; const username = req.user.username; const cacheKey = `history_spec:${hours}:${detectorId || 'all'}`;
  try {
    const cached = await streamRedisClient.get(cacheKey);
    if (cached) { logger.info('Serving spec history from cache', { username, hours, detectorId }); return res.json(JSON.parse(cached)); }
    logger.info('Fetching spec history from storage', { username, hours, detectorId });
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
    const historyKeyPattern = detectorId ? `spectrogram_history:${detectorId}` : 'spectrogram_history:*';
    const historyKeys = await streamRedisClient.keys(historyKeyPattern);
    if (historyKeys.length === 0) { logger.info('No spec history keys found', { pattern: historyKeyPattern }); return res.json([]); }
    const fetchPromises = historyKeys.map(key => streamRedisClient.lrange(key, 0, -1));
    const allRecordsNested = await Promise.all(fetchPromises);
    const allRecords = allRecordsNested.flat();
    const filteredData = allRecords
      .map(r => { try { return JSON.parse(r); } catch (e) { logger.warn('Failed to parse spec history record', { record: r?.substring(0, 100) }); return null; } })
      .filter(r => r && r.timestamp >= cutoff && (detectorId ? r.detectorId === detectorId : true));
    const groupedData = filteredData.reduce((acc, r) => {
        if (!r.detectorId || !r.spectrogram || !r.location || !Array.isArray(r.spectrogram)) return acc;
        acc[r.detectorId] = acc[r.detectorId] || { detectorId: r.detectorId, location: r.location, spectrograms: [] };
        r.spectrogram.forEach(specRow => { if(Array.isArray(specRow)) { acc[r.detectorId].spectrograms.push(...specRow); } });
        return acc;
    }, {});
    const result = Object.values(groupedData).map(group => ({ detectorId: group.detectorId, location: group.location, spectrogram: group.spectrograms }));
    if (result.length > 0) { await streamRedisClient.setex(cacheKey, 300, JSON.stringify(result)); logger.info('Cached spec historical data', { cacheKey, count: result.length }); }
    res.json(result);
  } catch (err) { logger.error('Spec history fetch error', { username, hours, detectorId, error: err.message }); next(err); }
});

// Historical Peak Data
const peakHistoryValidationRules = [ param('hours').isInt({ min: 1, max: 72 }).withMessage('Hours must be 1-72.'), queryValidator('detectorId').optional().isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detector ID.') ];
app.get('/history/peaks/:hours', apiLimiter, authenticateToken, peakHistoryValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged structure, logic was okay ... */
    const hours = parseInt(req.params.hours, 10); const { detectorId } = req.query; const username = req.user.username; const cacheKey = `history_peaks:${hours}:${detectorId || 'all'}`;
    try {
        const cached = await streamRedisClient.get(cacheKey); if (cached) { logger.info('Serving peak history from cache', { username, hours, detectorId }); return res.json(JSON.parse(cached)); }
        logger.info('Fetching peak history from storage', { username, hours, detectorId });
        const endTimeMs = Date.now(); const startTimeMs = endTimeMs - hours * 60 * 60 * 1000;
        const peakKeyPattern = detectorId ? `peaks:${detectorId}` : 'peaks:*';
        const peakKeys = await streamRedisClient.keys(peakKeyPattern);

        if (peakKeys.length === 0) {
            logger.info('No peak history keys found', { pattern: peakKeyPattern });
            return res.json([]);
        }

        const fetchPromises = peakKeys.map(async (key) => {
            const detId = key.split(':')[1]; // Extract detectorId from key
            // Fetch peaks WITH SCORES within the time range from the sorted set
            const peakStringsWithScores = await streamRedisClient.zrangebyscore(key, startTimeMs, endTimeMs, 'WITHSCORES');
            const peaksWithTimestamps = [];
            for (let i = 0; i < peakStringsWithScores.length; i += 2) {
                 try {
                     // The stored member is JSON array of peaks for that timestamp
                     const peakDataArray = JSON.parse(peakStringsWithScores[i]);
                     const timestamp = parseInt(peakStringsWithScores[i+1], 10);
                     // Ensure we have a valid timestamp and data
                     if (!isNaN(timestamp) && Array.isArray(peakDataArray)) {
                         peaksWithTimestamps.push({ ts: timestamp, peaks: peakDataArray });
                     } else {
                         logger.warn('Invalid peak data or timestamp in sorted set', { key, value: peakStringsWithScores[i], score: peakStringsWithScores[i+1] });
                     }
                 } catch (e) {
                     logger.warn('Failed to parse peak data array from sorted set', { key, value: peakStringsWithScores[i], error: e.message });
                 }
            }
             // Sort by timestamp ascending (although ZRANGEBYSCORE should already do this)
            peaksWithTimestamps.sort((a, b) => a.ts - b.ts);
            return { detectorId: detId, peaks: peaksWithTimestamps }; // Return object per detector
        });

        const resultsByDetector = await Promise.all(fetchPromises);
        const filteredResults = resultsByDetector.filter(r => r.peaks.length > 0); // Only include detectors with peaks in the range

        if (filteredResults.length > 0) {
            await streamRedisClient.setex(cacheKey, 300, JSON.stringify(filteredResults));
            logger.info('Cached peak historical data', { cacheKey, detectorCount: filteredResults.length });
        }

        res.json(filteredResults);

    } catch (err) {
        logger.error('Peak history fetch error', { username, hours, detectorId, error: err.message });
        next(err);
    }
});


// Data Ingest Endpoint (Updated for Batch)
const ingestValidationRules = [
    header('x-api-key').notEmpty().withMessage('API key is required in X-API-Key header.'),
    body('detectorId').isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detectorId.'),
    body('timestamp').optional().isISO8601().withMessage('Invalid timestamp format (ISO 8601 expected).'),
    body('location').isObject().withMessage('Location object is required.'),
    body('location.lat').isFloat({ min: -90, max: 90 }).withMessage('Invalid latitude.'),
    body('location.lon').isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude.'),
    // Expect 'spectrograms' as an array of raw spectra arrays
    body('spectrograms').isArray({ min: 1 }).withMessage('Spectrograms array (batch) is required.'),
    body('spectrograms.*').isArray({ min: RAW_FREQUENCY_POINTS, max: RAW_FREQUENCY_POINTS }).withMessage(`Each spectrogram in the batch must contain exactly ${RAW_FREQUENCY_POINTS} points.`),
    body('spectrograms.*.*').isFloat({ min: 0 }).withMessage('Spectrogram values must be non-negative numbers.'),
    // Basic Sanity Check (Example: Max amplitude shouldn't be absurdly high)
    body().custom(value => {
        const maxAmplitude = value.spectrograms.flat().reduce((max, val) => Math.max(max, val), 0);
        if (maxAmplitude > 1000) { // Adjust threshold as needed
            throw new Error('Maximum amplitude seems implausibly high.');
        }
        return true;
    })
];
app.post('/data-ingest', ingestLimiter, authenticateApiKey, ingestValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged ... */
    const { detectorId, location, spectrograms } = req.body; const timestamp = req.body.timestamp || new Date().toISOString(); const streamKey = 'spectrogram_stream';
    const messagePayload = { detectorId, timestamp, location, spectrogram: spectrograms, interval: 0 };
    const messageString = JSON.stringify(messagePayload);
    try { const messageId = await streamRedisClient.xadd(streamKey, '*', 'data', messageString); logger.info('Data batch ingested', { detectorId, batchSize: spectrograms.length, messageId }); dataIngestCounter.inc({ status: 'success' }); res.status(202).json({ message: 'Data batch accepted.', messageId }); } catch (err) { logger.error('Data ingest stream error', { detectorId, error: err.message }); dataIngestCounter.inc({ status: 'error' }); next(err); }
});


// User Deletion
const userDeleteValidationRules = [ param('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid username format.') ];
app.delete('/users/:username', apiLimiter, authenticateToken, userDeleteValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged ... */
  const targetUsername = req.params.username; const requesterUsername = req.user.username; if (targetUsername !== requesterUsername) { logger.warn('User deletion forbidden', { requester: requesterUsername, target: targetUsername }); return res.status(403).json({ error: 'Forbidden: You can only delete your own account.' }); }
  try { const result = await query('DELETE FROM users WHERE username = $1 RETURNING username', [targetUsername]); if (result.rowCount === 0) { logger.warn('User deletion failed: Not found', { username: targetUsername }); return res.status(404).json({ error: 'User not found' }); } const redisKey = `${targetUsername}`; const deletedKeys = await redisClient.del(redisKey); logger.info('User deleted successfully', { username: targetUsername, deletedBy: requesterUsername, redisKeysDeleted: deletedKeys }); res.status(200).json({ message: 'User deleted successfully' }); } catch (err) { logger.error('User deletion error', { username: targetUsername, error: err.message }); next(err); }
});

// Prometheus Metrics Endpoint
app.get('/metrics', async (req, res, next) => { /* ... unchanged ... */
  try { res.set('Content-Type', register.contentType); res.end(await register.metrics()); } catch (err) { logger.error('Metrics endpoint error', { error: err.message }); next(err); }
});


// --- WebSocket Server Setup ---
const wss = new WebSocket.Server({ server });
wss.on('connection', async (ws, req) => { /* ... unchanged ... */
  let username = 'unknown'; try { const requestUrl = new URL(req.url, `ws://${req.headers.host}`); const token = requestUrl.searchParams.get('token'); if (!token) { logger.warn('WS connection attempt without token'); ws.close(1008, 'Token required'); return; } const decoded = jwt.verify(token, JWT_SECRET); username = decoded.username; if (!username) throw new Error("Token payload missing username"); ws.username = username; logger.info('WS client connected', { username }); websocketConnections.inc(); ws.on('message', (message) => { logger.debug('WS message received', { username, message: message.toString().substring(0,100) }); }); ws.on('close', (code, reason) => { logger.info('WS client disconnected', { username, code, reason: reason.toString() }); websocketConnections.dec(); }); ws.on('error', (err) => { logger.error('WS connection error', { username, error: err.message }); }); } catch (err) { if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) { logger.warn('WS connection failed: Invalid token', { error: err.message }); ws.close(1008, 'Invalid or expired token'); } else { logger.error('WS connection setup error', { username, error: err.message }); ws.close(1011, 'Internal server error'); } }
});
wss.on('error', (err) => { logger.error('WebSocket Server Error', { error: err.message }); });


// --- Data Processing Logic ---

/**
 * Applies a simple moving average filter.
 * @param {number[]} data - The input data array.
 * @param {number} windowSize - The odd integer window size for the average.
 * @returns {number[]} The smoothed data array.
 */
function movingAverage(data, windowSize) {
    if (!data || data.length === 0 || windowSize < 1 || windowSize % 2 === 0) {
        return data; // Return original if invalid input
    }
    const halfWindow = Math.floor(windowSize / 2);
    const smoothed = new Array(data.length);
    let sum = 0;

    // Initial window sum
    for (let i = 0; i < windowSize; i++) {
        sum += data[i] || 0;
    }
    smoothed[halfWindow] = sum / windowSize;

    // Slide the window
    for (let i = windowSize; i < data.length; i++) {
        sum += (data[i] || 0) - (data[i - windowSize] || 0);
        smoothed[i - halfWindow] = sum / windowSize;
    }

    // Handle edges (simple replication for now)
    for (let i = 0; i < halfWindow; i++) {
        smoothed[i] = smoothed[halfWindow];
        smoothed[data.length - 1 - i] = smoothed[data.length - 1 - halfWindow];
    }

    return smoothed;
}

/**
 * Enhanced Peak detection on RAW spectrum.
 * Includes smoothing, prominence relative to baseline, minimum distance, and interpolated Q-Factor.
 * @param {number[]} rawSpectrum - The raw, high-resolution amplitude spectrum (5501 points).
 * @returns {Array<{freq: number, amp: number, qFactor: number|null}>} Array of detected peaks.
 */
function detectPeaks(rawSpectrum) {
    if (!rawSpectrum || rawSpectrum.length !== RAW_FREQUENCY_POINTS) {
        logger.warn('Invalid rawSpectrum input to detectPeaks', { length: rawSpectrum?.length });
        return [];
    }

    // 1. Smooth the data
    const smoothedSpectrum = movingAverage(rawSpectrum, PEAK_SMOOTHING_WINDOW);

    // 2. Estimate baseline noise (e.g., using a percentile or robust mean/std dev)
    // Simple approach: Use mean + std dev of the *smoothed* data as baseline reference
    const numericSpectrum = smoothedSpectrum.map(v => Number(v)).filter(v => !isNaN(v));
    if (numericSpectrum.length < 3) return [];
    const mean = numericSpectrum.reduce((a, b) => a + b, 0) / numericSpectrum.length;
    const variance = numericSpectrum.map(x => Math.pow(x - mean, 2)).reduce((a, b) => a + b, 0) / numericSpectrum.length;
    const stdDev = Math.sqrt(variance);
    const prominenceThreshold = stdDev * PEAK_PROMINENCE_FACTOR; // Prominence relative to std dev

    const candidatePeaks = [];
    const n = smoothedSpectrum.length;

    // 3. Find initial peak candidates (local maxima above absolute threshold)
    for (let i = 1; i < n - 1; i++) {
        const currentVal = smoothedSpectrum[i];
        const prevVal = smoothedSpectrum[i - 1];
        const nextVal = smoothedSpectrum[i + 1];

        if (currentVal > prevVal && currentVal > nextVal && currentVal > PEAK_ABSOLUTE_THRESHOLD) {
             // Basic check passed, now check prominence
             // Find local minima to the left and right to determine prominence base
             let leftMin = currentVal;
             for (let j = i - 1; j >= 0; j--) {
                 leftMin = Math.min(leftMin, smoothedSpectrum[j]);
                 if (smoothedSpectrum[j] > smoothedSpectrum[j + 1]) break; // Stop if going uphill again
             }
             let rightMin = currentVal;
             for (let j = i + 1; j < n; j++) {
                 rightMin = Math.min(rightMin, smoothedSpectrum[j]);
                 if (smoothedSpectrum[j] > smoothedSpectrum[j - 1]) break; // Stop if going uphill again
             }
             const prominence = currentVal - Math.max(leftMin, rightMin);

             if (prominence >= prominenceThreshold) {
                candidatePeaks.push({ index: i, amp: rawSpectrum[i], freq: i * FREQUENCY_RESOLUTION_HZ, prominence: prominence }); // Use raw amplitude
             }
        }
    }

    if (candidatePeaks.length === 0) return [];

    // 4. Sort candidates by amplitude (descending) to prioritize stronger peaks
    candidatePeaks.sort((a, b) => b.amp - a.amp);

    // 5. Filter peaks based on minimum distance
    const finalPeakIndices = [];
    const isPeakIncluded = new Array(n).fill(false);

    for (const peak of candidatePeaks) {
        if (!isPeakIncluded[peak.index]) {
            finalPeakIndices.push(peak.index);
            // Mark peaks within the minimum distance as excluded
            const start = Math.max(0, peak.index - PEAK_MIN_DISTANCE_POINTS);
            const end = Math.min(n, peak.index + PEAK_MIN_DISTANCE_POINTS + 1);
            for (let j = start; j < end; j++) {
                isPeakIncluded[j] = true;
            }
        }
    }

    if (finalPeakIndices.length === 0) return [];

    // 6. Calculate Q-Factor for final peaks using interpolation around half-max
    const finalPeaks = [];
    finalPeakIndices.sort((a, b) => a - b); // Sort by index/frequency

    for (const peakIndex of finalPeakIndices) {
        const peakAmp = rawSpectrum[peakIndex];
        const peakFreq = peakIndex * FREQUENCY_RESOLUTION_HZ;
        const halfMax = peakAmp / 2;
        let leftFreq = null, rightFreq = null;

        // Find left crossing (interpolate)
        for (let i = peakIndex - 1; i >= 0; i--) {
            if (rawSpectrum[i] <= halfMax) {
                if (i + 1 < n && rawSpectrum[i+1] > halfMax) { // Found crossing interval
                    // Linear interpolation: y = mx + c => x = (y - c) / m
                    const y1 = rawSpectrum[i], y2 = rawSpectrum[i+1];
                    const x1 = i * FREQUENCY_RESOLUTION_HZ, x2 = (i+1) * FREQUENCY_RESOLUTION_HZ;
                    if (y2 > y1) { // Ensure non-zero slope
                       leftFreq = x1 + (x2 - x1) * (halfMax - y1) / (y2 - y1);
                    } else {
                       leftFreq = x1; // Fallback if flat or decreasing
                    }
                } else {
                   leftFreq = i * FREQUENCY_RESOLUTION_HZ; // Landed exactly on a point <= halfMax
                }
                break;
            }
        }
        if (leftFreq === null && rawSpectrum[0] <= halfMax) leftFreq = 0; // Handle edge case near start

        // Find right crossing (interpolate)
        for (let i = peakIndex + 1; i < n; i++) {
            if (rawSpectrum[i] <= halfMax) {
                 if (i - 1 >= 0 && rawSpectrum[i-1] > halfMax) { // Found crossing interval
                    const y1 = rawSpectrum[i-1], y2 = rawSpectrum[i];
                    const x1 = (i-1) * FREQUENCY_RESOLUTION_HZ, x2 = i * FREQUENCY_RESOLUTION_HZ;
                     if (y1 > y2) { // Ensure non-zero slope
                        rightFreq = x1 + (x2 - x1) * (halfMax - y1) / (y2 - y1);
                     } else {
                        rightFreq = x2; // Fallback if flat or increasing
                     }
                } else {
                   rightFreq = i * FREQUENCY_RESOLUTION_HZ; // Landed exactly on a point <= halfMax
                }
                break;
            }
        }
         if (rightFreq === null && rawSpectrum[n-1] <= halfMax) rightFreq = (n-1) * FREQUENCY_RESOLUTION_HZ; // Handle edge case near end

        let qFactor = null;
        if (leftFreq !== null && rightFreq !== null && rightFreq > leftFreq) {
            const fwhm = rightFreq - leftFreq;
            if (fwhm > 1e-6 && peakFreq > 1e-6) { // Avoid division by zero/tiny numbers
                qFactor = peakFreq / fwhm;
            }
        }

        finalPeaks.push({
            freq: peakFreq,
            amp: peakAmp,
            qFactor: qFactor
        });
    }

    return finalPeaks;
}


function encryptMessage(messageString, keyHex) {
  try {
    const iv = crypto.randomBytes(16); const key = Buffer.from(keyHex, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(messageString, 'utf8', 'base64'); encrypted += cipher.final('base64');
    return `${encrypted}:${iv.toString('base64')}`;
  } catch (error) { logger.error("Encryption failed", { error: error.message }); return null; }
}

async function processStreamMessages() {
    const streamKey = 'spectrogram_stream'; const groupName = 'earthsync_group'; const consumerName = `consumer_${process.pid}`;
    try {
        await streamRedisClient.xgroup('CREATE', streamKey, groupName, '$', 'MKSTREAM').catch(err => { if (!err.message.includes('BUSYGROUP')) { logger.error('Failed to create consumer group', { group: groupName, error: err.message }); throw err; } else { logger.info(`Consumer group '${groupName}' exists.`); } });
        logger.info(`Consumer ${consumerName} joining group ${groupName} for stream ${streamKey}`);

        while (true) {
            try {
                const results = await streamRedisClient.xreadgroup( 'GROUP', groupName, consumerName, 'COUNT', 10, 'BLOCK', 5000, 'STREAMS', streamKey, '>' );
                if (!results) continue;

                for (const [/*streamName*/, messages] of results) {
                    for (const [messageId, fields] of messages) {
                        let parsedMessage = null; let messageTimestampMs = Date.now();
                        try {
                            const dataIndex = fields.indexOf('data'); if (dataIndex === -1 || !fields[dataIndex + 1]) { logger.warn('Stream message missing data field', { messageId }); await streamRedisClient.xack(streamKey, groupName, messageId); continue; }
                            parsedMessage = JSON.parse(fields[dataIndex + 1]);
                            messageTimestampMs = parsedMessage.timestamp ? new Date(parsedMessage.timestamp).getTime() : Date.now(); if (isNaN(messageTimestampMs)) messageTimestampMs = Date.now();

                            if (!parsedMessage.spectrogram || !parsedMessage.detectorId || !parsedMessage.location || !Array.isArray(parsedMessage.spectrogram)) { logger.warn('Invalid message structure in stream', { messageId, detectorId: parsedMessage?.detectorId }); await streamRedisClient.xack(streamKey, groupName, messageId); continue; }

                            let allDetectedPeaksForWs = []; let downsampledBatch = []; const pipeline = streamRedisClient.pipeline(); const peakKey = `peaks:${parsedMessage.detectorId}`;

                            parsedMessage.spectrogram.forEach((rawSpec, index) => {
                                if (!Array.isArray(rawSpec) || rawSpec.length !== RAW_FREQUENCY_POINTS) { logger.warn('Invalid raw spectrum in batch', { messageId, detectorId: parsedMessage.detectorId, index, length: rawSpec?.length }); downsampledBatch.push([]); return; }

                                // --- Peak Detection (on RAW data) ---
                                const detectedPeaks = detectPeaks(rawSpec);
                                if (detectedPeaks.length > 0) {
                                    // Store the SET of peaks for this specific timestamp
                                    pipeline.zadd(peakKey, messageTimestampMs + index, JSON.stringify(detectedPeaks)); // Use timestamp + index for score uniqueness if needed
                                }

                                // --- Downsample ---
                                downsampledBatch.push(rawSpec.filter((_, i) => i % DOWNSAMPLE_FACTOR === 0));

                                // Use peaks from the *first* spectrum for the outgoing WS message & counter
                                if (index === 0) {
                                    allDetectedPeaksForWs = detectedPeaks;
                                    if (detectedPeaks.length > 0) peaksDetectedCounter.inc({ detectorId: parsedMessage.detectorId }, detectedPeaks.length);
                                }
                            });

                            // --- Peak Tracking Placeholder ---
                            // trackPeaks(parsedMessage.detectorId, messageTimestampMs, allDetectedPeaksForWs);

                            // --- Transient Detection Placeholder ---
                            // detectTransients(parsedMessage.detectorId, messageTimestampMs, rawSpec); // Need original raw spec here

                            const dataToProcess = { ...parsedMessage, spectrogram: downsampledBatch, detectedPeaks: allDetectedPeaksForWs };
                            const messageString = JSON.stringify(dataToProcess);

                            // --- Store History (Spectrogram List) ---
                            const historyKey = `spectrogram_history:${parsedMessage.detectorId}`;
                            pipeline.lpush(historyKey, messageString); pipeline.ltrim(historyKey, 0, 999);

                            // Execute Redis pipeline (ZADD peaks, LPUSH/LTRIM history)
                            await pipeline.exec();

                            // --- Broadcast ---
                            let sentCount = 0;
                            for (const ws of wss.clients) {
                                if (ws.readyState === WebSocket.OPEN && ws.username) {
                                    const userRedisKey = `${ws.username}`; const key = await redisClient.get(userRedisKey);
                                    if (key) { const encryptedMessage = encryptMessage(messageString, key); if (encryptedMessage) { ws.send(encryptedMessage, (err) => { if (err) logger.error('WS send error', { username: ws.username, error: err.message }); }); sentCount++; } else { logger.warn('WS send skip: encryption error', { username: ws.username }); } } else { logger.warn('WS send skip: No key found', { username: ws.username, redisKey: REDIS_KEY_PREFIX + userRedisKey }); }
                                }
                            }
                             if (sentCount > 0) logger.debug(`Broadcasted msg ${messageId} to ${sentCount} clients`, { detectorId: parsedMessage.detectorId, peaks: allDetectedPeaksForWs.length });

                            await streamRedisClient.xack(streamKey, groupName, messageId);

                        } catch (processingError) { logger.error('Error processing stream message', { messageId, detectorId: parsedMessage?.detectorId, error: processingError.message, stack: processingError.stack }); await streamRedisClient.xack(streamKey, groupName, messageId).catch(ackErr => { logger.error('Failed to ACK message after error', { messageId, error: ackErr.message }); }); }
                    }
                }
            } catch (readError) { logger.error('Error reading from stream group', { group: groupName, error: readError.message, stack: readError.stack }); await new Promise(resolve => setTimeout(resolve, 1000)); }
        }
    } catch (streamError) { logger.error('Stream processing fatal error', { error: streamError.message, stack: streamError.stack }); setTimeout(processStreamMessages, 5000); }
}


// --- Placeholders for Future Features ---
// function trackPeaks(detectorId, timestamp, currentPeaks) {
//     logger.debug("Peak Tracking Placeholder", { detectorId, timestamp, peakCount: currentPeaks.length });
//     // TODO: Implement logic to compare currentPeaks with previous peaks for this detector
//     // - Store previous peaks state (e.g., in Redis or memory with TTL)
//     // - Match peaks based on frequency proximity
//     // - Identify drifts, appearances, disappearances
//     // - Potentially store tracked peak history separately
// }
// function detectTransients(detectorId, timestamp, rawSpectrum) {
//     logger.debug("Transient Detection Placeholder", { detectorId, timestamp });
//     // TODO: Implement logic to detect sudden broadband energy increases or other anomalies
//     // - Compare current spectrum energy/shape to recent baseline
//     // - Use algorithms like CWT, thresholding on derivatives, etc.
//     // - Flag transient events in the data stream or a separate event log
// }


// --- Periodic Cleanup Task ---
async function cleanupOldHistory() { /* ... unchanged ... */
    logger.info('Running periodic history cleanup task...');
    const historyHours = 25; const peakHours = 73; const specCutoffTimestampMs = Date.now() - (historyHours * 60 * 60 * 1000); const peakCutoffTimestampMs = Date.now() - (peakHours * 60 * 60 * 1000);
    try {
        // Cleanup Spectrogram History Lists
        const historyKeys = await streamRedisClient.keys('spectrogram_history:*'); let cleanedHistKeys = 0; let removedHistRecords = 0; const pipelineHist = streamRedisClient.pipeline();
        for (const key of historyKeys) { const records = await streamRedisClient.lrange(key, 0, -1); const recordsToKeep = []; let originalCount = records.length; for(const record of records) { try { const parsed = JSON.parse(record); if (parsed.timestamp && new Date(parsed.timestamp).getTime() >= specCutoffTimestampMs) { recordsToKeep.push(record); } } catch (e) { logger.warn('Cleanup: Skipping unparseable spec record', { key }); } } if (recordsToKeep.length < originalCount) { pipelineHist.del(key); if (recordsToKeep.length > 0) { pipelineHist.rpush(key, recordsToKeep); } removedHistRecords += (originalCount - recordsToKeep.length); cleanedHistKeys++; } }
        if(cleanedHistKeys > 0) { await pipelineHist.exec(); logger.info('Spec history list cleanup complete', { cleanedKeys: cleanedHistKeys, removedRecords: removedHistRecords }); } else { logger.info('Spec history list cleanup: No keys required cleaning.'); }

        // Cleanup Peak History Sorted Sets
        const peakKeys = await streamRedisClient.keys('peaks:*'); let cleanedPeakKeys = 0; let removedPeakRecords = 0; const pipelinePeaks = streamRedisClient.pipeline();
        for (const key of peakKeys) { pipelinePeaks.zremrangebyscore(key, '-inf', `(${peakCutoffTimestampMs}`); cleanedPeakKeys++; }
        if(cleanedPeakKeys > 0) { const results = await pipelinePeaks.exec(); results.forEach(([err, count], index) => { if (!err && count > 0) { removedPeakRecords += count; logger.debug('Cleaned peak history key', { key: peakKeys[index], removed: count }); } else if (err) { logger.error('Error cleaning peak key', { key: peakKeys[index], error: err.message }); } }); if (removedPeakRecords > 0) logger.info('Peak history ZSET cleanup complete', { cleanedKeys: cleanedPeakKeys, removedRecords: removedPeakRecords }); else logger.info('Peak history ZSET cleanup: No keys required cleaning.'); } else { logger.info('Peak history ZSET cleanup: No keys found.'); }
    } catch (err) { logger.error('History cleanup task error', { error: err.message }); } finally { setTimeout(cleanupOldHistory, CLEANUP_INTERVAL_MS); }
}

// --- Centralized Error Handling Middleware ---
app.use((err, req, res, next) => { /* ... unchanged ... */
  logger.error('Unhandled API Error', { error: err.message, stack: err.stack, url: req.originalUrl, method: req.method, ip: req.ip, status: err.status || 500 });
  const status = err.status || err.statusCode || 500; const message = (process.env.NODE_ENV === 'production' && status >= 500) ? 'Internal server error.' : err.message || 'Unexpected error.';
  if (!res.headersSent) { res.status(status).json({ error: message }); } else { next(err); }
});

// --- Start Server and Background Tasks ---
async function startServer() { /* ... unchanged ... */
    try { await redisClient.connect(); await streamRedisClient.connect(); logger.info('Redis clients connected, starting HTTP server...'); server.listen(PORT, () => { logger.info(`HTTP Server listening on port ${PORT}`); processStreamMessages(); setTimeout(cleanupOldHistory, 10000); }); } catch (err) { logger.error('Server startup failed', { error: err.message }); await redisClient.quit().catch(()=>{}); await streamRedisClient.quit().catch(()=>{}); process.exit(1); }
}

// --- Graceful Shutdown ---
async function gracefulShutdown(signal) { /* ... unchanged ... */
  logger.info(`Received ${signal}. Shutting down...`); let exitCode = 0;
  server.close(async () => { logger.info('HTTP server closed.'); logger.info('Closing WS connections...'); wss.clients.forEach(ws => ws.terminate());
    try { if (redisClient.status === 'ready' || redisClient.status === 'connecting') { await redisClient.quit(); logger.info('Main Redis closed.'); } } catch (err) { logger.error('Error closing main Redis:', { error: err.message }); exitCode = 1; }
     try { if (streamRedisClient.status === 'ready' || streamRedisClient.status === 'connecting') { await streamRedisClient.quit(); logger.info('Stream Redis closed.'); } } catch (err) { logger.error('Error closing stream Redis:', { error: err.message }); exitCode = 1; }
    try { await endDbPool(); logger.info('DB pool closed.'); } catch (err) { logger.error('Error closing DB pool:', { error: err.message }); exitCode = 1; }
    logger.info('Shutdown complete.'); process.exit(exitCode);
  });
  setTimeout(() => { logger.error('Graceful shutdown timeout. Forcing exit.'); process.exit(1); }, 15000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();
