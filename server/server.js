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
        if (peakKeys.length === 0) { logger.info('No peak history keys found', { pattern: peakKeyPattern }); return res.json([]); }
        const fetchPromises = peakKeys.map(async (key) => {
            const detId = key.split(':')[1];
            const peakStringsWithScores = await streamRedisClient.zrangebyscore(key, startTimeMs, endTimeMs, 'WITHSCORES');
            const peaksWithTimestamps = [];
            for (let i = 0; i < peakStringsWithScores.length; i += 2) {
                 try { const peakData = JSON.parse(peakStringsWithScores[i]); const timestamp = parseInt(peakStringsWithScores[i+1], 10); peaksWithTimestamps.push({ ts: timestamp, peaks: peakData }); } catch (e) { logger.warn('Failed to parse peak data from ZSET', { key, value: peakStringsWithScores[i] }); }
            }
            peaksWithTimestamps.sort((a, b) => a.ts - b.ts); // Ensure sorted by time
            return { detectorId: detId, peaks: peaksWithTimestamps };
        });
        const resultsByDetector = await Promise.all(fetchPromises);
        const filteredResults = resultsByDetector.filter(r => r.peaks.length > 0);
        if (filteredResults.length > 0) { await streamRedisClient.setex(cacheKey, 300, JSON.stringify(filteredResults)); logger.info('Cached peak historical data', { cacheKey, count: filteredResults.length }); }
        res.json(filteredResults);
    } catch (err) { logger.error('Peak history fetch error', { username, hours, detectorId, error: err.message }); next(err); }
});

// Data Ingest Endpoint
const ingestValidationRules = [
    header('x-api-key').notEmpty().withMessage('API key is required in X-API-Key header.'),
    body('detectorId').isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detectorId.'),
    body('timestamp').optional().isISO8601().withMessage('Invalid timestamp format (ISO 8601 expected).'),
    body('location').isObject().withMessage('Location object is required.'),
    body('location.lat').isFloat({ min: -90, max: 90 }).withMessage('Invalid latitude.'),
    body('location.lon').isFloat({ min: -180, max: 180 }).withMessage('Invalid longitude.'),
    body('spectrograms').isArray({ min: 1 }).withMessage('Spectrograms array (batch) is required.'),
    body('spectrograms.*').isArray({ min: RAW_FREQUENCY_POINTS, max: RAW_FREQUENCY_POINTS }).withMessage(`Each spectrogram must have ${RAW_FREQUENCY_POINTS} points.`),
    body('spectrograms.*.*').isFloat({ min: 0 }).withMessage('Spectrogram values must be non-negative numbers.'),
    body().custom(value => { const maxAmp = value.spectrograms.flat().reduce((max, val) => Math.max(max, val), 0); if (maxAmp > 1000) { throw new Error('Max amplitude too high.'); } return true; })
];
app.post('/data-ingest', ingestLimiter, authenticateApiKey, ingestValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged ... */
    const { detectorId, location, spectrograms } = req.body; const timestamp = req.body.timestamp || new Date().toISOString(); const streamKey = 'spectrogram_stream';
    const messagePayload = { detectorId, timestamp, location, spectrogram: spectrograms, interval: 0 }; const messageString = JSON.stringify(messagePayload);
    try { const messageId = await streamRedisClient.xadd(streamKey, '*', 'data', messageString); logger.info('Data batch ingested to stream', { detectorId, batchSize: spectrograms.length, messageId }); dataIngestCounter.inc({ status: 'success' }); res.status(202).json({ message: 'Data batch accepted.', messageId }); } catch (err) { logger.error('Data ingest stream add error', { detectorId, error: err.message }); dataIngestCounter.inc({ status: 'error' }); next(err); }
});

// User Deletion
const userDeleteValidationRules = [ param('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid username format.') ];
app.delete('/users/:username', apiLimiter, authenticateToken, userDeleteValidationRules, validateRequest, async (req, res, next) => { /* ... unchanged ... */
  const targetUsername = req.params.username; const requesterUsername = req.user.username;
  if (targetUsername !== requesterUsername) { logger.warn('User delete forbidden', { requester: requesterUsername, target: targetUsername }); return res.status(403).json({ error: 'Forbidden: Cannot delete other users.' }); }
  try { const result = await query('DELETE FROM users WHERE username = $1 RETURNING username', [targetUsername]); if (result.rowCount === 0) { logger.warn('User delete failed: Not found', { username: targetUsername }); return res.status(404).json({ error: 'User not found' }); }
    const redisKey = `${targetUsername}`; const deletedKeys = await redisClient.del(redisKey); logger.info('User deleted', { username: targetUsername, deletedBy: requesterUsername, redisKeysDel: deletedKeys }); res.status(200).json({ message: 'User deleted successfully' }); } catch (err) { logger.error('User deletion error', { username: targetUsername, error: err.message }); next(err); }
});

// Prometheus Metrics Endpoint
app.get('/metrics', async (req, res, next) => { /* ... unchanged ... */
  try { res.set('Content-Type', register.contentType); res.end(await register.metrics()); } catch (err) { logger.error('Metrics endpoint error', { error: err.message }); next(err); }
});

// --- WebSocket Server Setup ---
const wss = new WebSocket.Server({ server });
wss.on('connection', async (ws, req) => { /* ... unchanged ... */
  let username = 'unknown'; try { const requestUrl = new URL(req.url, `ws://${req.headers.host}`); const token = requestUrl.searchParams.get('token'); if (!token) { logger.warn('WS connection no token'); ws.close(1008, 'Token required'); return; } const decoded = jwt.verify(token, JWT_SECRET); username = decoded.username; if (!username) throw new Error("Token missing username"); ws.username = username; logger.info('WS client connected', { username }); websocketConnections.inc(); ws.on('message', (message) => { logger.debug('WS message received', { username, message: message.toString().substring(0,100) }); }); ws.on('close', (code, reason) => { logger.info('WS client disconnected', { username, code, reason: reason.toString() }); websocketConnections.dec(); }); ws.on('error', (err) => { logger.error('WS connection error', { username, error: err.message }); }); } catch (err) { if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) { logger.warn('WS connection failed: Invalid token', { error: err.message }); ws.close(1008, 'Invalid or expired token'); } else { logger.error('WS connection setup error', { username, error: err.message }); ws.close(1011, 'Internal server error'); } }
});
wss.on('error', (err) => { logger.error('WebSocket Server Error', { error: err.message }); });


// --- Data Processing Logic ---

/** Apply moving average smoothing */
function smooth(data, windowSize) {
    if (windowSize <= 1) return data;
    const smoothed = [];
    const halfWindow = Math.floor(windowSize / 2);
    for (let i = 0; i < data.length; i++) {
        const start = Math.max(0, i - halfWindow);
        const end = Math.min(data.length, i + halfWindow + 1);
        let sum = 0;
        for (let j = start; j < end; j++) {
            sum += data[j];
        }
        smoothed.push(sum / (end - start));
    }
    return smoothed;
}

/**
 * Enhanced Peak detection on RAW spectrum.
 * Includes smoothing, prominence check, minimum distance, and interpolated Q-Factor.
 * @param {number[]} rawSpectrum - The raw, high-resolution amplitude spectrum.
 * @returns {Array<{freq: number, amp: number, qFactor: number|null}>} Array of detected peaks.
 */
function detectPeaksEnhanced(rawSpectrum) {
    if (!rawSpectrum || rawSpectrum.length < PEAK_SMOOTHING_WINDOW) return [];

    const n = rawSpectrum.length;
    const numericSpectrum = rawSpectrum.map(v => Number(v)).filter(v => !isNaN(v));
    if (numericSpectrum.length !== n) {
        logger.warn('Invalid values found in raw spectrum, peak detection might be affected.');
        // Option: return [] or try to proceed with valid points if enough exist
        if (numericSpectrum.length < PEAK_SMOOTHING_WINDOW) return [];
        // If proceeding, need to handle potential index mismatches - simpler to return []
        return [];
    }

    // 1. Smoothing
    const smoothedSpectrum = smooth(numericSpectrum, PEAK_SMOOTHING_WINDOW);

    // 2. Find potential peak candidates (local maxima)
    const candidates = [];
    for (let i = 1; i < n - 1; i++) {
        if (smoothedSpectrum[i] > smoothedSpectrum[i - 1] && smoothedSpectrum[i] > smoothedSpectrum[i + 1] && smoothedSpectrum[i] >= PEAK_ABSOLUTE_THRESHOLD) {
            candidates.push({ index: i, amp: smoothedSpectrum[i] });
        }
    }

    if (candidates.length === 0) return [];

    // 3. Calculate baseline (e.g., median or percentile of non-peak regions - simplified here as local minimums)
    // A more robust baseline calculation might be needed for very noisy data.
    // Simple baseline estimation: minimum value within a window around the peak candidate
    const windowSizeForBaseline = PEAK_MIN_DISTANCE_POINTS * 2 + 1;

    // 4. Filter by Prominence
    const prominentPeaks = candidates.filter(candidate => {
        const i = candidate.index;
        const windowStart = Math.max(0, i - Math.floor(windowSizeForBaseline / 2));
        const windowEnd = Math.min(n, i + Math.floor(windowSizeForBaseline / 2) + 1);
        let localMin = candidate.amp;
        for (let k = windowStart; k < windowEnd; k++) {
            if (k !== i) { // Don't consider the peak itself for baseline
               localMin = Math.min(localMin, smoothedSpectrum[k]);
            }
        }
        // Calculate local standard deviation (optional, could use global or rolling std dev)
        let localSumSq = 0;
        let localSum = 0;
        for (let k = windowStart; k < windowEnd; k++) {
            localSum += smoothedSpectrum[k];
            localSumSq += smoothedSpectrum[k] * smoothedSpectrum[k];
        }
        const localMean = localSum / (windowEnd - windowStart);
        const localVariance = (localSumSq / (windowEnd - windowStart)) - (localMean * localMean);
        const localStdDev = localVariance > 0 ? Math.sqrt(localVariance) : 0;

        // Prominence: How much the peak stands out from the estimated baseline/noise
        const prominence = candidate.amp - localMin;
        // Threshold can be combination of absolute and relative (factor * noise)
        const prominenceThreshold = PEAK_PROMINENCE_FACTOR * (localStdDev || 0.5); // Use a minimum noise floor
        return prominence >= prominenceThreshold;
    });

    if (prominentPeaks.length === 0) return [];

    // 5. Filter by Minimum Distance
    prominentPeaks.sort((a, b) => b.amp - a.amp); // Process highest peaks first
    const finalPeakIndices = [];
    const excludedIndices = new Set();

    for (const peak of prominentPeaks) {
        if (!excludedIndices.has(peak.index)) {
            finalPeakIndices.push(peak.index);
            // Exclude points within PEAK_MIN_DISTANCE_POINTS on either side
            for (let k = 1; k <= PEAK_MIN_DISTANCE_POINTS; k++) {
                excludedIndices.add(peak.index + k);
                excludedIndices.add(peak.index - k);
            }
        }
    }

    if (finalPeakIndices.length === 0) return [];

    // 6. Calculate Properties (Frequency, Amplitude, Q-Factor) for final peaks
    const finalPeaks = finalPeakIndices.map(index => {
        // Use original (unsmoothed) data for precise amplitude and Q-factor if desired, or smoothed
        const peakAmp = numericSpectrum[index]; // Or smoothedSpectrum[index]
        const peakFreq = index * FREQUENCY_RESOLUTION_HZ;

        // Estimate FWHM using original data around the peak index found in smoothed data
        const halfMax = peakAmp / 2;
        let leftIndex = index, rightIndex = index;
        while (leftIndex > 0 && numericSpectrum[leftIndex] > halfMax) { leftIndex--; }
        while (rightIndex < n - 1 && numericSpectrum[rightIndex] > halfMax) { rightIndex++; }

        // Interpolate edges for better FWHM
        let fwhm = (rightIndex - leftIndex) * FREQUENCY_RESOLUTION_HZ; // Basic width
        try { // Add interpolation guards
            const y1 = numericSpectrum[leftIndex]; const y2 = numericSpectrum[leftIndex+1];
            const leftInterp = (halfMax - y1) / (y2 - y1); // Linear interpolation factor
            const x1 = numericSpectrum[rightIndex]; const x2 = numericSpectrum[rightIndex-1];
            const rightInterp = (halfMax - x1) / (x2 - x1); // Linear interpolation factor

            if(isFinite(leftInterp) && leftInterp >= 0 && leftInterp <= 1 &&
               isFinite(rightInterp) && rightInterp >= 0 && rightInterp <= 1 ) {
                 const interpolatedLeft = leftIndex + leftInterp;
                 const interpolatedRight = rightIndex - rightInterp; // Subtract as we moved right->left
                 fwhm = (interpolatedRight - interpolatedLeft) * FREQUENCY_RESOLUTION_HZ;
            }
        } catch(interpErr){ logger.debug("FWHM interpolation failed", {index, error: interpErr.message})}


        let qFactor = null;
        if (fwhm > 1e-6) { // Avoid division by zero
            qFactor = peakFreq / fwhm;
        }

        return { freq: peakFreq, amp: peakAmp, qFactor: qFactor };
    });

    finalPeaks.sort((a,b) => a.freq - b.freq); // Sort by frequency
    return finalPeaks;
}

// --- Placeholder Functions ---
async function trackPeaks(detectorId, currentPeaks, timestamp) {
    // TODO: Implement logic to compare currentPeaks with previous peaks for this detector.
    // - Identify corresponding peaks (e.g., based on frequency proximity).
    // - Calculate drift, amplitude change, Q-factor change.
    // - Store or flag significant changes/trends.
    // logger.debug("Peak tracking placeholder", { detectorId, count: currentPeaks.length, ts: timestamp });
}

async function detectTransients(detectorId, rawSpectrum, timestamp) {
    // TODO: Implement logic to detect anomalies.
    // - Look for broadband energy spikes (e.g., power exceeds threshold across many frequencies).
    // - Look for rapid changes compared to a baseline or previous spectrum.
    // - Could use statistical methods (e.g., deviation from mean/median) or signal processing techniques.
    // logger.debug("Transient detection placeholder", { detectorId, ts: timestamp });
}


function encryptMessage(messageString, keyHex) {
  try {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(keyHex, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(messageString, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return `${encrypted}:${iv.toString('base64')}`;
  } catch (error) {
      logger.error("Encryption failed", { error: error.message });
      return null;
  }
}

async function processStreamMessages() {
    const streamKey = 'spectrogram_stream';
    const groupName = 'earthsync_group';
    const consumerName = `consumer_${process.pid}`;

    try {
        await streamRedisClient.xgroup('CREATE', streamKey, groupName, '$', 'MKSTREAM').catch(err => {
            if (!err.message.includes('BUSYGROUP Consumer Group name already exists')) { logger.error('Failed to create/verify consumer group', { group: groupName, error: err.message }); throw err; }
            else { logger.info(`Consumer group '${groupName}' already exists.`); }
        });
        logger.info(`Consumer ${consumerName} joining group ${groupName} for stream ${streamKey}`);

        while (true) {
            try {
                const results = await streamRedisClient.xreadgroup( 'GROUP', groupName, consumerName, 'COUNT', 10, 'BLOCK', 5000, 'STREAMS', streamKey, '>' );
                if (!results) continue;

                for (const [/*streamName*/, messages] of results) {
                    for (const [messageId, fields] of messages) {
                        let parsedMessage = null;
                        let messageTimestampMs = Date.now();
                        let shouldAck = true; // Acknowledge by default

                        try {
                            const dataIndex = fields.indexOf('data');
                            if (dataIndex === -1 || !fields[dataIndex + 1]) { logger.warn('Stream message missing data field', { messageId }); continue; } // Ack handled in finally
                            parsedMessage = JSON.parse(fields[dataIndex + 1]);
                            messageTimestampMs = parsedMessage.timestamp ? new Date(parsedMessage.timestamp).getTime() : Date.now();
                            if (isNaN(messageTimestampMs)) messageTimestampMs = Date.now();

                            if (!parsedMessage.spectrogram || !parsedMessage.detectorId || !parsedMessage.location || !Array.isArray(parsedMessage.spectrogram)) { logger.warn('Invalid message structure in stream', { messageId, detectorId: parsedMessage?.detectorId }); continue; }

                            let allDetectedPeaksForWs = [];
                            let downsampledBatch = [];
                            const pipeline = streamRedisClient.pipeline();
                            let firstRawSpecForProcessing = null; // Store the first valid raw spectrum

                            parsedMessage.spectrogram.forEach((rawSpec, index) => {
                                if (!Array.isArray(rawSpec) || rawSpec.length !== RAW_FREQUENCY_POINTS) {
                                    logger.warn('Item in spectrogram batch is not valid raw spectrum', { messageId, detectorId: parsedMessage.detectorId, index, length: rawSpec?.length });
                                    downsampledBatch.push([]); return;
                                }
                                if (index === 0) firstRawSpecForProcessing = rawSpec; // Keep first for WS peaks

                                // --- Downsample ---
                                downsampledBatch.push(rawSpec.filter((_, i) => i % DOWNSAMPLE_FACTOR === 0));
                            });

                            // --- Process First Raw Spectrum (Peaks, Track, Transients) ---
                            if (firstRawSpecForProcessing) {
                                allDetectedPeaksForWs = detectPeaksEnhanced(firstRawSpecForProcessing);
                                if (allDetectedPeaksForWs.length > 0) {
                                    peaksDetectedCounter.inc({ detectorId: parsedMessage.detectorId }, allDetectedPeaksForWs.length);
                                    // Store only the peaks from the first spectrum in the sorted set for this timestamp
                                    const peakKey = `peaks:${parsedMessage.detectorId}`;
                                    pipeline.zadd(peakKey, messageTimestampMs, JSON.stringify(allDetectedPeaksForWs)); // Store the array of peaks
                                }
                                // --- Peak Tracking & Transient Detection Placeholders ---
                                await trackPeaks(parsedMessage.detectorId, allDetectedPeaksForWs, messageTimestampMs);
                                await detectTransients(parsedMessage.detectorId, firstRawSpecForProcessing, messageTimestampMs);
                            } else {
                                allDetectedPeaksForWs = []; // Ensure it's empty if no valid first spectrum
                                logger.warn("No valid raw spectrum found in batch for peak detection", { messageId, detectorId: parsedMessage.detectorId });
                            }

                            // Data to store/send
                            const dataToProcess = { ...parsedMessage, spectrogram: downsampledBatch, detectedPeaks: allDetectedPeaksForWs };
                            const messageString = JSON.stringify(dataToProcess);

                            // --- Store History (Spectrogram List) ---
                            const historyKey = `spectrogram_history:${parsedMessage.detectorId}`;
                            pipeline.lpush(historyKey, messageString);
                            pipeline.ltrim(historyKey, 0, 999);

                            // Execute Redis pipeline (ZADD peaks, LPUSH/LTRIM history)
                            await pipeline.exec();

                            // --- Broadcast ---
                            let sentCount = 0;
                            let keyFoundCount = 0;
                            let keyNotFoundCount = 0;
                            for (const ws of wss.clients) {
                                if (ws.readyState === WebSocket.OPEN && ws.username) {
                                    const userRedisKey = `${ws.username}`;
                                    try {
                                        const key = await redisClient.get(userRedisKey); // Use main client with prefix
                                        if (key) {
                                            keyFoundCount++;
                                            const encryptedMessage = encryptMessage(messageString, key);
                                            if (encryptedMessage) {
                                                 ws.send(encryptedMessage, (err) => { if (err) logger.error('WS send error', { username: ws.username, error: err.message }); });
                                                 sentCount++;
                                            } else { logger.warn('WS send skip: encryption error', { username: ws.username }); }
                                        } else {
                                            keyNotFoundCount++;
                                            logger.warn('WS send skip: No encryption key found', { username: ws.username });
                                        }
                                    } catch (redisErr) {
                                        logger.error('WS send skip: Redis error getting key', {username: ws.username, error: redisErr.message});
                                    }
                                }
                            }
                             if (keyFoundCount > 0 || keyNotFoundCount > 0) {
                                 logger.debug(`Broadcast attempt ${messageId}`, { detectorId: parsedMessage.detectorId, peaks: allDetectedPeaksForWs.length, clients: wss.clients.size, sent: sentCount, keysFound: keyFoundCount, keysNotFound: keyNotFoundCount });
                             }

                        } catch (processingError) {
                            logger.error('Error processing stream message', { messageId, detectorId: parsedMessage?.detectorId, error: processingError.message, stack: processingError.stack });
                            // Still attempt to ACK to avoid reprocessing loops on bad data
                        } finally {
                            if (shouldAck) {
                                await streamRedisClient.xack(streamKey, groupName, messageId).catch(ackErr => {
                                    logger.error('Failed to ACK message', { messageId, error: ackErr.message });
                                });
                            }
                        }
                    }
                }
            } catch (readError) {
                 logger.error('Error reading from stream group', { group: groupName, error: readError.message, stack: readError.stack });
                 await new Promise(resolve => setTimeout(resolve, 1000)); // Avoid tight loop
            }
        }
    } catch (streamError) {
        logger.error('Stream processing setup/fatal loop error', { error: streamError.message, stack: streamError.stack });
        setTimeout(processStreamMessages, 5000); // Retry setup
    }
}


// --- Periodic Cleanup Task ---
async function cleanupOldHistory() { /* ... unchanged ... */
    logger.info('Running periodic history cleanup task...');
    const historyHours = 25; const peakHours = 73;
    const specCutoffTimestampMs = Date.now() - (historyHours * 60 * 60 * 1000);
    const peakCutoffTimestampMs = Date.now() - (peakHours * 60 * 60 * 1000);
    try {
        // Cleanup Spectrogram History Lists
        const historyKeys = await streamRedisClient.keys('spectrogram_history:*');
        let cleanedHistKeys = 0; let removedHistRecords = 0;
        const pipelineHist = streamRedisClient.pipeline();
        for (const key of historyKeys) {
            const records = await streamRedisClient.lrange(key, 0, -1);
            const recordsToKeep = []; let originalCount = records.length;
            for(const record of records) { try { const parsed = JSON.parse(record); if (parsed.timestamp && new Date(parsed.timestamp).getTime() >= specCutoffTimestampMs) { recordsToKeep.push(record); } } catch (e) { logger.warn('Cleanup: Skip unparseable spec hist record', { key }); } }
            if (recordsToKeep.length < originalCount) { pipelineHist.del(key); if (recordsToKeep.length > 0) { pipelineHist.rpush(key, recordsToKeep); } removedHistRecords += (originalCount - recordsToKeep.length); cleanedHistKeys++; }
        }
        if(cleanedHistKeys > 0) { await pipelineHist.exec(); logger.info('Spec history list cleanup complete', { cleanedKeys: cleanedHistKeys, removedRecords: removedHistRecords }); }
        else { logger.info('Spec history list cleanup: No keys needed cleaning.'); }

        // Cleanup Peak History Sorted Sets
        const peakKeys = await streamRedisClient.keys('peaks:*');
        let cleanedPeakKeys = 0; let removedPeakRecords = 0;
        const pipelinePeaks = streamRedisClient.pipeline();
        for (const key of peakKeys) { pipelinePeaks.zremrangebyscore(key, '-inf', `(${peakCutoffTimestampMs}`); cleanedPeakKeys++; }
        if(cleanedPeakKeys > 0) {
             const results = await pipelinePeaks.exec();
             results.forEach(([err, count], index) => { if (!err && count > 0) { removedPeakRecords += count; logger.debug('Cleaned peak history key', { key: peakKeys[index], removed: count }); } else if (err) { logger.error('Error cleaning peak history key', { key: peakKeys[index], error: err.message }); } });
             if (removedPeakRecords > 0) logger.info('Peak history ZSET cleanup complete', { cleanedKeys: cleanedPeakKeys, removedRecords: removedPeakRecords });
             else logger.info('Peak history ZSET cleanup: No keys needed cleaning.');
        } else { logger.info('Peak history ZSET cleanup: No keys found.'); }

    } catch (err) { logger.error('History cleanup task error', { error: err.message }); } finally { setTimeout(cleanupOldHistory, CLEANUP_INTERVAL_MS); }
}

// --- Centralized Error Handling Middleware ---
app.use((err, req, res, next) => { /* ... unchanged ... */
  logger.error('Unhandled API Error', { error: err.message, stack: err.stack, url: req.originalUrl, method: req.method, ip: req.ip, status: err.status || err.statusCode || 500 });
  const status = err.status || err.statusCode || 500; const message = (process.env.NODE_ENV === 'production' && status >= 500) ? 'Internal server error.' : err.message || 'Unexpected error.';
  if (!res.headersSent) { res.status(status).json({ error: message }); } else { next(err); }
});

// --- Start Server and Background Tasks ---
async function startServer() { /* ... unchanged ... */
    try { await redisClient.connect(); await streamRedisClient.connect(); logger.info('Redis clients connected, starting HTTP server...'); server.listen(PORT, () => { logger.info(`HTTP Server listening on port ${PORT}`); processStreamMessages(); setTimeout(cleanupOldHistory, 10000); }); } catch (err) { logger.error('Server startup failed', { error: err.message }); await redisClient.quit().catch(()=>{}); await streamRedisClient.quit().catch(()=>{}); process.exit(1); }
}

// --- Graceful Shutdown ---
async function gracefulShutdown(signal) { /* ... unchanged ... */
  logger.info(`Received ${signal}. Shutting down gracefully...`); let exitCode = 0;
  server.close(async () => { logger.info('HTTP server closed.'); logger.info('Closing WS connections...'); wss.clients.forEach(ws => ws.terminate());
    try { if (redisClient.status === 'ready' || redisClient.status === 'connecting') { await redisClient.quit(); logger.info('Main Redis closed.'); } } catch (err) { logger.error('Error closing main Redis:', { error: err.message }); exitCode = 1; }
    try { if (streamRedisClient.status === 'ready' || streamRedisClient.status === 'connecting') { await streamRedisClient.quit(); logger.info('Stream/Hist Redis closed.'); } } catch (err) { logger.error('Error closing stream/hist Redis:', { error: err.message }); exitCode = 1; }
    try { await endDbPool(); logger.info('DB pool closed.'); } catch (err) { logger.error('Error closing DB pool:', { error: err.message }); exitCode = 1; }
    logger.info('Shutdown complete.'); process.exit(exitCode);
  });
  setTimeout(() => { logger.error('Graceful shutdown timed out. Forcing exit.'); process.exit(1); }, 15000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();
