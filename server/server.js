// server/server.js
/**
 * Main server entry point for EarthSync (v1.1.15 - Phase 4e Fix).
 * Handles API requests, WebSocket connections, and data processing.
 * Uses external processing utilities. Includes Enhanced Peak Detection,
 * Basic Peak Tracking & Enhanced Transient Detection.
 * Refactors history routes, fixes integration tests. Returns transient details in history API.
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
// Renamed db functions import for clarity
const db = require('./db.js');
const { authenticateToken } = require('./middleware.js');
const {
    detectPeaksEnhanced,
    trackPeaks,
    detectTransients
} = require('./processingUtils');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const promClient = require('prom-client');
const http = require('http');
const { body, header, param, query: queryValidator, validationResult } = require('express-validator');

// --- Winston Logger Setup ---
const logLevel = process.env.LOG_LEVEL || 'info';
const loggerFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
);
const loggerTransports = [
    new winston.transports.Console({ format: winston.format.combine(winston.format.colorize(), winston.format.simple()) }),
    new winston.transports.File({ filename: 'server.log' })
];
const logger = winston.createLogger({
  level: logLevel,
  format: loggerFormat,
  transports: loggerTransports,
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
const transientsDetectedCounter = new promClient.Counter({ name: 'transients_detected_total', help: 'Total transient events detected', labelNames: ['detectorId', 'type'], registers: [register] });
const archiveRecordsCounter = new promClient.Counter({ name: 'archive_records_processed_total', help: 'Total records processed by archive task', labelNames: ['type', 'status'], registers: [register] });
const archiveDuration = new promClient.Gauge({ name: 'archive_last_duration_seconds', help: 'Duration of the last archive task run', registers: [register] });

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
const RAW_FREQUENCY_POINTS = 5501;
const REDIS_SPEC_RETENTION_MS = (parseInt(process.env.REDIS_SPEC_RETENTION_HOURS, 10) || 24) * 60 * 60 * 1000;
const REDIS_PEAK_RETENTION_MS = (parseInt(process.env.REDIS_PEAK_RETENTION_HOURS, 10) || 72) * 60 * 60 * 1000;

// --- Log Startup Info ---
logger.info(`Starting EarthSync server v1.1.15 (Phase 4e Fix) on port ${PORT}...`);
logger.info(`Allowed CORS origins: ${ALLOWED_ORIGINS.join(', ')}`);
logger.info(`Redis Spectrogram Retention: ${process.env.REDIS_SPEC_RETENTION_HOURS || 24} hours`);
logger.info(`Redis Peak Retention: ${process.env.REDIS_PEAK_RETENTION_HOURS || 72} hours`);

// --- Check Critical Env Vars ---
if (!JWT_SECRET) { logger.error('FATAL: JWT_SECRET is not defined.'); process.exit(1); }
if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD) { logger.error('FATAL: Redis configuration missing.'); process.exit(1); }
if (!API_INGEST_KEY) { logger.warn('API_INGEST_KEY is not set. Data ingest endpoint will be disabled.'); }

// --- Global Error Handling ---
process.on('uncaughtException', (err) => { logger.error('UNCAUGHT EXCEPTION', { error: err.message, stack: err.stack }); process.exit(1); });
process.on('unhandledRejection', (reason, promise) => { logger.error('UNHANDLED REJECTION', { reason: reason?.toString(), stack: reason?.stack, promise }); });

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
app.get('/health', async (req, res, next) => {
  try {
    const redisPing = await redisClient.ping();
    const streamRedisPing = await streamRedisClient.ping();
    await db.query('SELECT 1'); // Use db module query
    res.status(200).json({ status: 'OK', uptime: process.uptime().toFixed(2), redis_main: redisPing === 'PONG' ? 'OK' : 'Error', redis_stream: streamRedisPing === 'PONG' ? 'OK' : 'Error', postgres: 'OK' });
  } catch (err) { logger.error('Health check failed', { error: err.message }); next(err); }
});
const registerValidationRules = [ body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 chars.').matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid chars in username.'), body('password').isLength({ min: 8 }).withMessage('Password must be >= 8 chars.') ];
app.post('/register', authLimiter, registerValidationRules, validateRequest, async (req, res, next) => {
  const { username, password } = req.body; try { const checkUser = await db.query('SELECT username FROM users WHERE username = $1', [username]); if (checkUser.rows.length > 0) { return res.status(409).json({ error: 'Username already exists' }); } const hashedPassword = await bcrypt.hash(password, 10); await db.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]); logger.info('User registered', { username }); res.status(201).json({ message: 'Registration successful' }); } catch (err) { logger.error('Registration error', { username, error: err.message }); next(err); }
});
const loginValidationRules = [ body('username').trim().notEmpty().withMessage('Username required.'), body('password').notEmpty().withMessage('Password required.') ];
app.post('/login', authLimiter, loginValidationRules, validateRequest, async (req, res, next) => {
  const { username, password } = req.body; try { const result = await db.query('SELECT id, username, password FROM users WHERE username = $1', [username]); if (result.rows.length === 0) { logger.warn('Login fail: User not found', { username }); return res.status(401).json({ error: 'Invalid username or password' }); } const user = result.rows[0]; const match = await bcrypt.compare(password, user.password); if (!match) { logger.warn('Login fail: Invalid password', { username }); return res.status(401).json({ error: 'Invalid username or password' }); } const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: `${ENCRYPTION_KEY_TTL_SECONDS}s` }); logger.info('User logged in', { username }); res.json({ token }); } catch (err) { logger.error('Login error', { username, error: err.message }); next(err); }
});
app.post('/key-exchange', apiLimiter, authenticateToken, async (req, res, next) => {
  const username = req.user.username; try { const key = crypto.randomBytes(32).toString('hex'); const redisKey = `${username}`;
    await redisClient.setex(redisKey, ENCRYPTION_KEY_TTL_SECONDS, key); logger.info('Key generated/stored', { username, redisKey: REDIS_KEY_PREFIX + redisKey }); res.json({ key }); } catch (err) { logger.error('Key exchange error', { username, error: err.message }); next(err); }
});


// --- Refactored History Routes ---

// Validation for routes using :hours parameter
const historyHoursValidationRules = [
    param('hours').isInt({ min: 1, max: 72 }).withMessage('Hours must be 1-72.'),
    queryValidator('detectorId').optional().isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detector ID.')
];

// Validation for routes using startTime/endTime query parameters
const historyRangeValidationRules = [
    queryValidator('startTime').isISO8601().withMessage('startTime must be a valid ISO 8601 date.'),
    queryValidator('endTime').isISO8601().withMessage('endTime must be a valid ISO 8601 date.'),
    queryValidator('detectorId').optional().isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detector ID.'),
    queryValidator().custom((value, { req }) => {
        const { startTime, endTime } = req.query;
        if (startTime && endTime) {
            if (new Date(endTime) < new Date(startTime)) { throw new Error('endTime must be after startTime.'); }
        } else {
             throw new Error('Both startTime and endTime query parameters are required for range query.');
        }
        return true;
    })
];

// Helper function to determine time range and cache key
function getQueryTimeRange(hours, startTimeStr, endTimeStr) {
    let startTimeMs, endTimeMs;
    let rangeIdentifier;
    if (startTimeStr && endTimeStr) {
        startTimeMs = new Date(startTimeStr).getTime();
        endTimeMs = new Date(endTimeStr).getTime();
        rangeIdentifier = `${startTimeMs}_${endTimeMs}`;
    } else if (hours) {
        endTimeMs = Date.now();
        startTimeMs = endTimeMs - hours * 60 * 60 * 1000;
        rangeIdentifier = `h${hours}`;
    } else {
        endTimeMs = Date.now();
        startTimeMs = endTimeMs - 1 * 60 * 60 * 1000;
        rangeIdentifier = 'h1_default';
    }
    return { startTimeMs, endTimeMs, rangeIdentifier };
}

// --- Route for Spectrogram History by HOURS ---
app.get('/history/hours/:hours', apiLimiter, authenticateToken, historyHoursValidationRules, validateRequest, async (req, res, next) => {
    const hours = parseInt(req.params.hours, 10);
    const { detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(hours, null, null);
    const cacheKey = `history_spec_transient:${rangeIdentifier}:${detectorId || 'all'}`;

    try {
        const cached = await streamRedisClient.get(cacheKey);
        if (cached) { logger.info('Serving spec+transient history from cache (hours)', { cacheKey }); return res.json(JSON.parse(cached)); }
        logger.info('Fetching spec+transient history from storage (hours)', { cacheKey, hours, detectorId });

        const redisBoundaryMs = Date.now() - REDIS_SPEC_RETENTION_MS;
        let redisResults = []; let dbResults = [];
        const redisStartTimeMs = Math.max(startTimeMs, redisBoundaryMs);

        if (endTimeMs >= redisStartTimeMs) {
            const historyKeyPattern = detectorId ? `spectrogram_history:${detectorId}` : 'spectrogram_history:*';
            const historyKeys = await streamRedisClient.keys(historyKeyPattern);
            if (historyKeys.length > 0) {
                const fetchPromises = historyKeys.map(key => streamRedisClient.lrange(key, 0, -1));
                const allRecordsNested = await Promise.all(fetchPromises);
                const allRecords = allRecordsNested.flat();
                redisResults = allRecords
                  .map(r => { try { return JSON.parse(r); } catch { return null; } })
                  .filter(r => { if (!r?.timestamp) return false; const t = new Date(r.timestamp).getTime(); return t >= redisStartTimeMs && t <= endTimeMs && (!detectorId || r.detectorId === detectorId); });
                 logger.debug(`Fetched ${redisResults.length} spectrogram records from Redis (hours).`);
            }
        }
        if (startTimeMs < redisBoundaryMs) {
            const dbStartTimeISO = new Date(startTimeMs).toISOString();
            const dbEndTimeISO = new Date(redisBoundaryMs).toISOString();
            try {
                let queryText = `SELECT detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details FROM historical_spectrograms WHERE timestamp >= $1 AND timestamp < $2`;
                const queryParams = [dbStartTimeISO, dbEndTimeISO];
                if (detectorId) { queryText += ` AND detector_id = $3 ORDER BY timestamp ASC`; queryParams.push(detectorId); }
                else { queryText += ` ORDER BY detector_id ASC, timestamp ASC`; }
                const dbRes = await db.query(queryText, queryParams);
                dbResults = dbRes.rows.map(row => ({ detectorId: row.detector_id, timestamp: row.timestamp.toISOString(), location: { lat: row.location_lat, lon: row.location_lon }, spectrogram: row.spectrogram_data, transientInfo: { type: row.transient_detected ? (row.transient_details?.toLowerCase().includes('broadband') ? 'broadband' : (row.transient_details ? 'narrowband' : 'unknown')) : 'none', details: row.transient_details } }));
                logger.debug(`Fetched ${dbResults.length} spectrogram records from DB (hours).`);
            } catch (dbErr) { logger.error("Error querying historical spectrograms from DB (hours)", { error: dbErr.message }); }
        }
        const combinedResults = [...dbResults, ...redisResults];
        combinedResults.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        const groupedData = combinedResults.reduce((acc, r) => {
            if (!r.detectorId || !r.spectrogram || !r.location || !Array.isArray(r.spectrogram)) return acc;
            const detId = r.detectorId;
            acc[detId] = acc[detId] || { detectorId: detId, location: r.location, spectrograms: [], transientEvents: [] };
            if (Array.isArray(r.spectrogram) && Array.isArray(r.spectrogram[0])) { r.spectrogram.forEach(specRow => { if(Array.isArray(specRow)) { acc[detId].spectrograms.push(...specRow); } }); }
            if (r.transientInfo && r.transientInfo.type !== 'none') { acc[detId].transientEvents.push({ ts: new Date(r.timestamp).getTime(), type: r.transientInfo.type, details: r.transientInfo.details }); }
            return acc;
         }, {});
        const finalResult = Object.values(groupedData).map(group => ({ detectorId: group.detectorId, location: group.location, spectrogram: group.spectrograms, transientEvents: group.transientEvents }));
        if (finalResult.length > 0) { await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult)); logger.info('Cached combined spec+transient historical data (hours)', { cacheKey }); }
        res.json(finalResult);
    } catch (err) { logger.error('Spec history fetch error (hours)', { username, hours, detectorId, error: err.message }); next(err); }
});

// --- Route for Spectrogram History by RANGE ---
app.get('/history/range', apiLimiter, authenticateToken, historyRangeValidationRules, validateRequest, async (req, res, next) => {
    const { startTime, endTime, detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(null, startTime, endTime);
    const cacheKey = `history_spec_transient:${rangeIdentifier}:${detectorId || 'all'}`;

     try {
        const cached = await streamRedisClient.get(cacheKey);
        if (cached) { logger.info('Serving spec+transient history from cache (range)', { cacheKey }); return res.json(JSON.parse(cached)); }
        logger.info('Fetching spec+transient history from storage (range)', { cacheKey, start: startTime, end: endTime, detectorId });

        const redisBoundaryMs = Date.now() - REDIS_SPEC_RETENTION_MS;
        let redisResults = []; let dbResults = [];
        const redisStartTimeMs = Math.max(startTimeMs, redisBoundaryMs);

        if (endTimeMs >= redisStartTimeMs) {
             const historyKeyPattern = detectorId ? `spectrogram_history:${detectorId}` : 'spectrogram_history:*';
             const historyKeys = await streamRedisClient.keys(historyKeyPattern);
             if (historyKeys.length > 0) {
                 const fetchPromises = historyKeys.map(key => streamRedisClient.lrange(key, 0, -1));
                 const allRecordsNested = await Promise.all(fetchPromises);
                 const allRecords = allRecordsNested.flat();
                 redisResults = allRecords
                   .map(r => { try { return JSON.parse(r); } catch { return null; } })
                   .filter(r => { if (!r?.timestamp) return false; const t = new Date(r.timestamp).getTime(); return t >= redisStartTimeMs && t <= endTimeMs && (!detectorId || r.detectorId === detectorId); });
                  logger.debug(`Fetched ${redisResults.length} spectrogram records from Redis (range).`);
             }
        }
        if (startTimeMs < redisBoundaryMs) {
             const dbStartTimeISO = new Date(startTimeMs).toISOString();
             const dbEndTimeISO = new Date(redisBoundaryMs).toISOString();
             try {
                 let queryText = `SELECT detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details FROM historical_spectrograms WHERE timestamp >= $1 AND timestamp < $2`;
                 const queryParams = [dbStartTimeISO, dbEndTimeISO];
                 if (detectorId) { queryText += ` AND detector_id = $3 ORDER BY timestamp ASC`; queryParams.push(detectorId); }
                 else { queryText += ` ORDER BY detector_id ASC, timestamp ASC`; }
                 const dbRes = await db.query(queryText, queryParams);
                 dbResults = dbRes.rows.map(row => ({ detectorId: row.detector_id, timestamp: row.timestamp.toISOString(), location: { lat: row.location_lat, lon: row.location_lon }, spectrogram: row.spectrogram_data, transientInfo: { type: row.transient_detected ? (row.transient_details?.toLowerCase().includes('broadband') ? 'broadband' : (row.transient_details ? 'narrowband' : 'unknown')) : 'none', details: row.transient_details } }));
                 logger.debug(`Fetched ${dbResults.length} spectrogram records from DB (range).`);
             } catch (dbErr) { logger.error("Error querying historical spectrograms from DB (range)", { error: dbErr.message }); }
        }
        const combinedResults = [...dbResults, ...redisResults];
        combinedResults.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        const groupedData = combinedResults.reduce((acc, r) => {
            if (!r.detectorId || !r.spectrogram || !r.location || !Array.isArray(r.spectrogram)) return acc;
            const detId = r.detectorId;
            acc[detId] = acc[detId] || { detectorId: detId, location: r.location, spectrograms: [], transientEvents: [] };
            if (Array.isArray(r.spectrogram) && Array.isArray(r.spectrogram[0])) { r.spectrogram.forEach(specRow => { if(Array.isArray(specRow)) { acc[detId].spectrograms.push(...specRow); } }); }
            if (r.transientInfo && r.transientInfo.type !== 'none') { acc[detId].transientEvents.push({ ts: new Date(r.timestamp).getTime(), type: r.transientInfo.type, details: r.transientInfo.details }); }
            return acc;
        }, {});
        const finalResult = Object.values(groupedData).map(group => ({ detectorId: group.detectorId, location: group.location, spectrogram: group.spectrograms, transientEvents: group.transientEvents }));
        if (finalResult.length > 0) { await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult)); logger.info('Cached combined spec+transient historical data (range)', { cacheKey }); }
        res.json(finalResult);
    } catch (err) { logger.error('Spec history fetch error (range)', { username, detectorId, startTime, endTime, error: err.message }); next(err); }
});

// --- Route for Peak History by HOURS ---
app.get('/history/peaks/hours/:hours', apiLimiter, authenticateToken, historyHoursValidationRules, validateRequest, async (req, res, next) => {
    const hours = parseInt(req.params.hours, 10);
    const { detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(hours, null, null);
    const cacheKey = `history_peaks:${rangeIdentifier}:${detectorId || 'all'}`;

    try {
        const cached = await streamRedisClient.get(cacheKey);
        if (cached) { logger.info('Serving peak history from cache (hours)', { cacheKey }); return res.json(JSON.parse(cached)); }
        logger.info('Fetching peak history from storage (hours)', { cacheKey, hours, detectorId });

        const redisBoundaryMs = Date.now() - REDIS_PEAK_RETENTION_MS;
        let redisPeakResults = []; let dbPeakResults = [];
        const redisStartTimeMs = Math.max(startTimeMs, redisBoundaryMs);

        if (endTimeMs >= redisStartTimeMs) {
            const peakKeyPattern = detectorId ? `peaks:${detectorId}` : 'peaks:*';
            const peakKeys = await streamRedisClient.keys(peakKeyPattern);
            if (peakKeys.length > 0) {
                const fetchPromises = peakKeys.map(async (key) => {
                    const detId = key.split(':')[1];
                    const peakStringsWithScores = await streamRedisClient.zrangebyscore(key, redisStartTimeMs, endTimeMs, 'WITHSCORES');
                    const peaksWithTs = [];
                    for (let i = 0; i < peakStringsWithScores.length; i += 2) { try { peaksWithTs.push({ ts: parseInt(peakStringsWithScores[i+1], 10), peaks: JSON.parse(peakStringsWithScores[i]) }); } catch {} }
                    return { detectorId: detId, peaks: peaksWithTs };
                });
                 redisPeakResults = await Promise.all(fetchPromises);
                 logger.debug(`Fetched ${redisPeakResults.reduce((sum, d) => sum + d.peaks.length, 0)} peak entries from Redis (hours).`);
            }
        }
        if (startTimeMs < redisBoundaryMs) {
            const dbStartTimeISO = new Date(startTimeMs).toISOString();
            const dbEndTimeISO = new Date(redisBoundaryMs).toISOString();
            try {
                let queryText = `SELECT detector_id, timestamp, peak_data FROM historical_peaks WHERE timestamp >= $1 AND timestamp < $2`;
                const queryParams = [dbStartTimeISO, dbEndTimeISO];
                if (detectorId) { queryText += ` AND detector_id = $3 ORDER BY timestamp ASC`; queryParams.push(detectorId); }
                else { queryText += ` ORDER BY detector_id ASC, timestamp ASC`; }
                const dbRes = await db.query(queryText, queryParams);
                const dbResultsGrouped = dbRes.rows.reduce((acc, row) => { const dId = row.detector_id; acc[dId]=acc[dId]||{detectorId:dId, peaks:[]}; acc[dId].peaks.push({ts:row.timestamp.getTime(), peaks:row.peak_data}); return acc; }, {});
                dbPeakResults = Object.values(dbResultsGrouped);
                logger.debug(`Fetched ${dbRes.rows.length} peak entries from DB (hours).`);
            } catch(dbErr) { logger.error("Error querying historical peaks from DB (hours)", { error: dbErr.message }); }
        }
        const combinedResultsMap = {};
        dbPeakResults.forEach(d => { combinedResultsMap[d.detectorId] = {detectorId:d.detectorId, peaks:[...d.peaks]}; });
        redisPeakResults.forEach(d => { if(combinedResultsMap[d.detectorId]) {combinedResultsMap[d.detectorId].peaks.push(...d.peaks);} else {combinedResultsMap[d.detectorId]={detectorId:d.detectorId, peaks:[...d.peaks]};} });
        Object.values(combinedResultsMap).forEach(d => d.peaks.sort((a, b) => a.ts - b.ts));
        const finalResult = Object.values(combinedResultsMap);
        if (finalResult.length > 0) { await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult)); logger.info('Cached combined peak historical data (hours)', { cacheKey }); }
        res.json(finalResult);
    } catch (err) { logger.error('Peak history fetch error (hours)', { username, hours, detectorId, error: err.message }); next(err); }
});

// --- Route for Peak History by RANGE ---
app.get('/history/peaks/range', apiLimiter, authenticateToken, historyRangeValidationRules, validateRequest, async (req, res, next) => {
    const { startTime, endTime, detectorId } = req.query;
    const username = req.user.username;
    const { startTimeMs, endTimeMs, rangeIdentifier } = getQueryTimeRange(null, startTime, endTime);
    const cacheKey = `history_peaks:${rangeIdentifier}:${detectorId || 'all'}`;

    try {
        const cached = await streamRedisClient.get(cacheKey);
        if (cached) { logger.info('Serving peak history from cache (range)', { cacheKey }); return res.json(JSON.parse(cached)); }
        logger.info('Fetching peak history from storage (range)', { cacheKey, start: startTime, end: endTime, detectorId });

        const redisBoundaryMs = Date.now() - REDIS_PEAK_RETENTION_MS;
        let redisPeakResults = []; let dbPeakResults = [];
        const redisStartTimeMs = Math.max(startTimeMs, redisBoundaryMs);

        if (endTimeMs >= redisStartTimeMs) {
            const peakKeyPattern = detectorId ? `peaks:${detectorId}` : 'peaks:*';
            const peakKeys = await streamRedisClient.keys(peakKeyPattern);
            if (peakKeys.length > 0) {
                const fetchPromises = peakKeys.map(async (key) => {
                    const detId = key.split(':')[1];
                    const peakStringsWithScores = await streamRedisClient.zrangebyscore(key, redisStartTimeMs, endTimeMs, 'WITHSCORES');
                    const peaksWithTs = [];
                    for (let i = 0; i < peakStringsWithScores.length; i += 2) { try { peaksWithTs.push({ ts: parseInt(peakStringsWithScores[i+1], 10), peaks: JSON.parse(peakStringsWithScores[i]) }); } catch {} }
                    return { detectorId: detId, peaks: peaksWithTs };
                });
                 redisPeakResults = await Promise.all(fetchPromises);
                 logger.debug(`Fetched ${redisPeakResults.reduce((sum, d) => sum + d.peaks.length, 0)} peak entries from Redis (range).`);
            }
        }
        if (startTimeMs < redisBoundaryMs) {
            const dbStartTimeISO = new Date(startTimeMs).toISOString();
            const dbEndTimeISO = new Date(redisBoundaryMs).toISOString();
            try {
                let queryText = `SELECT detector_id, timestamp, peak_data FROM historical_peaks WHERE timestamp >= $1 AND timestamp < $2`;
                const queryParams = [dbStartTimeISO, dbEndTimeISO];
                if (detectorId) { queryText += ` AND detector_id = $3 ORDER BY timestamp ASC`; queryParams.push(detectorId); }
                else { queryText += ` ORDER BY detector_id ASC, timestamp ASC`; }
                const dbRes = await db.query(queryText, queryParams);
                const dbResultsGrouped = dbRes.rows.reduce((acc, row) => { const dId = row.detector_id; acc[dId]=acc[dId]||{detectorId:dId, peaks:[]}; acc[dId].peaks.push({ts:row.timestamp.getTime(), peaks:row.peak_data}); return acc; }, {});
                dbPeakResults = Object.values(dbResultsGrouped);
                logger.debug(`Fetched ${dbRes.rows.length} peak entries from DB (range).`);
            } catch(dbErr) { logger.error("Error querying historical peaks from DB (range)", { error: dbErr.message }); }
        }
        const combinedResultsMap = {};
        dbPeakResults.forEach(d => { combinedResultsMap[d.detectorId] = {detectorId:d.detectorId, peaks:[...d.peaks]}; });
        redisPeakResults.forEach(d => { if(combinedResultsMap[d.detectorId]) {combinedResultsMap[d.detectorId].peaks.push(...d.peaks);} else {combinedResultsMap[d.detectorId]={detectorId:d.detectorId, peaks:[...d.peaks]};} });
        Object.values(combinedResultsMap).forEach(d => d.peaks.sort((a, b) => a.ts - b.ts));
        const finalResult = Object.values(combinedResultsMap);
        if (finalResult.length > 0) { await streamRedisClient.setex(cacheKey, 300, JSON.stringify(finalResult)); logger.info('Cached combined peak historical data (range)', { cacheKey }); }
        res.json(finalResult);
    } catch (err) { logger.error('Peak history fetch error (range)', { username, detectorId, startTime, endTime, error: err.message }); next(err); }
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
app.post('/data-ingest', ingestLimiter, authenticateApiKey, ingestValidationRules, validateRequest, async (req, res, next) => {
    const { detectorId, location, spectrograms } = req.body; const timestamp = req.body.timestamp || new Date().toISOString(); const streamKey = 'spectrogram_stream';
    const messagePayload = { detectorId, timestamp, location, spectrogram: spectrograms, interval: 0 }; const messageString = JSON.stringify(messagePayload);
    try {
        const messageId = await streamRedisClient.xadd(streamKey, '*', 'data', messageString);
        logger.info('Data batch ingested to stream', { detectorId, batchSize: spectrograms.length, messageId }); dataIngestCounter.inc({ status: 'success' }); res.status(202).json({ message: 'Data batch accepted.', messageId });
    } catch (err) { logger.error('Data ingest stream add error', { detectorId, error: err.message }); dataIngestCounter.inc({ status: 'error' }); next(err); }
});

// User Deletion
const userDeleteValidationRules = [ param('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid username format.') ];
app.delete('/users/:username', apiLimiter, authenticateToken, userDeleteValidationRules, validateRequest, async (req, res, next) => {
  const targetUsername = req.params.username; const requesterUsername = req.user.username;
  if (targetUsername !== requesterUsername) { logger.warn('User delete forbidden', { requester: requesterUsername, target: targetUsername }); return res.status(403).json({ error: 'Forbidden: Cannot delete other users.' }); }
  try { const result = await db.query('DELETE FROM users WHERE username = $1 RETURNING username', [targetUsername]); if (result.rowCount === 0) { logger.warn('User delete failed: Not found', { username: targetUsername }); return res.status(404).json({ error: 'User not found' }); }
    const redisKey = `${targetUsername}`; const deletedKeys = await redisClient.del(redisKey); logger.info('User deleted', { username: targetUsername, deletedBy: requesterUsername, redisKeysDel: deletedKeys }); res.status(200).json({ message: 'User deleted successfully' }); } catch (err) { logger.error('User deletion error', { username: targetUsername, error: err.message }); next(err); }
});

// Prometheus Metrics Endpoint
app.get('/metrics', async (req, res, next) => {
  try { res.set('Content-Type', register.contentType); res.end(await register.metrics()); } catch (err) { logger.error('Metrics endpoint error', { error: err.message }); next(err); }
});

// --- WebSocket Server Setup ---
const wss = new WebSocket.Server({ server });
wss.on('connection', async (ws, req) => {
  let username = 'unknown'; try { const requestUrl = new URL(req.url, `ws://${req.headers.host}`); const token = requestUrl.searchParams.get('token'); if (!token) { logger.warn('WS connection no token'); ws.close(1008, 'Token required'); return; } const decoded = jwt.verify(token, JWT_SECRET); username = decoded.username; if (!username) throw new Error("Token missing username"); ws.username = username; logger.info('WS client connected', { username }); websocketConnections.inc(); ws.on('message', (message) => { logger.debug('WS message received', { username, message: message.toString().substring(0,100) }); }); ws.on('close', (code, reason) => { logger.info('WS client disconnected', { username, code, reason: reason.toString() }); websocketConnections.dec(); }); ws.on('error', (err) => { logger.error('WS connection error', { username, error: err.message }); }); } catch (err) { if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) { logger.warn('WS connection failed: Invalid token', { error: err.message }); ws.close(1008, 'Invalid or expired token'); } else { logger.error('WS connection setup error', { username, error: err.message }); ws.close(1011, 'Internal server error'); } }
});
wss.on('error', (err) => { logger.error('WebSocket Server Error', { error: err.message }); });


// --- Data Processing Logic (Utilizing processingUtils.js) ---

/** Encrypt Message */
function encryptMessage(messageString, keyHex) {
  try { const iv = crypto.randomBytes(16); const key = Buffer.from(keyHex, 'hex'); const cipher = crypto.createCipheriv('aes-256-cbc', key, iv); let encrypted = cipher.update(messageString, 'utf8', 'base64'); encrypted += cipher.final('base64'); return `${encrypted}:${iv.toString('base64')}`; } catch (error) { logger.error("Encryption failed", { error: error.message }); return null; }
}

/** Process Stream Messages - Updated for Phase 4a */
async function processStreamMessages() {
    const streamKey = 'spectrogram_stream'; const groupName = 'earthsync_group'; const consumerName = `consumer_${process.pid}`;
    try { await streamRedisClient.xgroup('CREATE', streamKey, groupName, '$', 'MKSTREAM').catch(err => { if (!err.message.includes('BUSYGROUP Consumer Group name already exists')) { logger.error('Failed to create/verify consumer group', { group: groupName, error: err.message }); throw err; } else { logger.info(`Consumer group '${groupName}' already exists.`); } }); logger.info(`Consumer ${consumerName} joining group ${groupName} for stream ${streamKey}`);
        while (true) {
            try { const results = await streamRedisClient.xreadgroup( 'GROUP', groupName, consumerName, 'COUNT', 10, 'BLOCK', 5000, 'STREAMS', streamKey, '>' ); if (!results) continue;
                for (const [/*streamName*/, messages] of results) {
                    for (const [messageId, fields] of messages) {
                        let parsedMessage = null; let messageTimestampMs = Date.now(); let shouldAck = true;
                        try { const dataIndex = fields.indexOf('data'); if (dataIndex === -1 || !fields[dataIndex + 1]) { logger.warn('Stream message missing data field', { messageId }); continue; } parsedMessage = JSON.parse(fields[dataIndex + 1]); messageTimestampMs = parsedMessage.timestamp ? new Date(parsedMessage.timestamp).getTime() : Date.now(); if (isNaN(messageTimestampMs)) messageTimestampMs = Date.now(); if (!parsedMessage.spectrogram || !parsedMessage.detectorId || !parsedMessage.location || !Array.isArray(parsedMessage.spectrogram)) { logger.warn('Invalid message structure in stream', { messageId, detectorId: parsedMessage?.detectorId }); continue; }
                            let allDetectedPeaksForWs = []; let trackedPeaksForStorage = []; let downsampledBatch = []; const historyPipeline = streamRedisClient.pipeline(); let firstRawSpecForProcessing = null;
                            let transientResult = { type: 'none', details: null };

                            parsedMessage.spectrogram.forEach((rawSpec, index) => { if (!Array.isArray(rawSpec) || rawSpec.length !== RAW_FREQUENCY_POINTS) { logger.warn('Item in spectrogram batch is not valid raw spectrum', { messageId, detectorId: parsedMessage.detectorId, index, length: rawSpec?.length }); downsampledBatch.push([]); return; } if (index === 0) firstRawSpecForProcessing = rawSpec; downsampledBatch.push(rawSpec.filter((_, i) => i % DOWNSAMPLE_FACTOR === 0)); });

                            if (firstRawSpecForProcessing) {
                                const peakDetectionStart = Date.now();
                                const detectedPeaksRaw = detectPeaksEnhanced(firstRawSpecForProcessing);
                                const peakDetectionDuration = Date.now() - peakDetectionStart;
                                logger.debug("Peak detection duration", { detectorId: parsedMessage.detectorId, durationMs: peakDetectionDuration, peakCount: detectedPeaksRaw.length });

                                trackedPeaksForStorage = await trackPeaks(parsedMessage.detectorId, detectedPeaksRaw, redisClient);
                                allDetectedPeaksForWs = trackedPeaksForStorage;
                                if (trackedPeaksForStorage.length > 0) {
                                    peaksDetectedCounter.inc({ detectorId: parsedMessage.detectorId }, trackedPeaksForStorage.length);
                                    const peakKey = `peaks:${parsedMessage.detectorId}`;
                                    historyPipeline.zadd(peakKey, messageTimestampMs, JSON.stringify(trackedPeaksForStorage));
                                    logger.debug("Adding tracked peaks to history", { key: peakKey, score: messageTimestampMs, count: trackedPeaksForStorage.length });
                                }

                                transientResult = await detectTransients(parsedMessage.detectorId, firstRawSpecForProcessing, streamRedisClient);
                                if (transientResult.type !== 'none' && transientResult.type !== 'error') {
                                    transientsDetectedCounter.inc({ detectorId: parsedMessage.detectorId, type: transientResult.type });
                                }

                             } else {
                                 allDetectedPeaksForWs = [];
                                 trackedPeaksForStorage = [];
                                 logger.warn("No valid raw spectrum found in batch for peak detection", { messageId, detectorId: parsedMessage.detectorId });
                             }

                            const dataToProcess = {
                                ...parsedMessage,
                                spectrogram: downsampledBatch,
                                detectedPeaks: allDetectedPeaksForWs,
                                transientInfo: transientResult
                            };
                            const messageString = JSON.stringify(dataToProcess);

                            const historyKey = `spectrogram_history:${parsedMessage.detectorId}`;
                            historyPipeline.lpush(historyKey, messageString);
                            historyPipeline.ltrim(historyKey, 0, 999);
                            logger.debug("Adding processed data to history list", { key: historyKey, numRows: downsampledBatch.length, transientType: transientResult.type });

                            await historyPipeline.exec();

                            let sentCount = 0;
                            logger.debug(`Broadcasting message ${messageId} to ${wss.clients.size} potential clients`, { detectorId: parsedMessage.detectorId, peakCount: allDetectedPeaksForWs.length, transientType: transientResult.type });
                            for (const ws of wss.clients) {
                                if (ws.readyState === WebSocket.OPEN && ws.username) {
                                    const userRedisKey = `${ws.username}`;
                                    try {
                                        const key = await redisClient.get(userRedisKey);
                                        if (key) {
                                            const encryptedMessage = encryptMessage(messageString, key);
                                            if (encryptedMessage) { ws.send(encryptedMessage, (err) => { if (err) logger.error('WS send error', { username: ws.username, error: err.message }); }); sentCount++; }
                                            else { logger.warn('WS send skip: encryption error', { username: ws.username }); }
                                        } else { logger.warn('WS send skip: No key found in Redis', { username: ws.username, redisKey: REDIS_KEY_PREFIX + userRedisKey }); }
                                    } catch (redisErr) { logger.error('WS send skip: Redis error getting key', {username: ws.username, error: redisErr.message}); }
                                } else { logger.debug('WS send skip: Client not open or no username', { username: ws.username, state: ws.readyState }); }
                            }
                            logger.debug(`Broadcast ${messageId} complete`, { sent: sentCount });

                        } catch (processingError) { logger.error('Error processing stream message', { messageId, detectorId: parsedMessage?.detectorId, error: processingError.message, stack: processingError.stack }); }
                        finally { if (shouldAck) { await streamRedisClient.xack(streamKey, groupName, messageId).catch(ackErr => { logger.error('Failed to ACK message', { messageId, error: ackErr.message }); }); } }
                    }
                }
            } catch (readError) { logger.error('Error reading from stream group', { group: groupName, error: readError.message, stack: readError.stack }); await new Promise(resolve => setTimeout(resolve, 1000)); }
        }
    } catch (streamError) { logger.error('Stream processing setup/fatal loop error', { error: streamError.message, stack: streamError.stack }); setTimeout(processStreamMessages, 5000); }
}


// --- Periodic Cleanup Task (UPDATED FOR ARCHIVING Details) ---
async function cleanupOldHistory() {
    const startTime = Date.now();
    logger.info('Running periodic history cleanup and archiving task...');
    const specCutoffTimestampMs = Date.now() - REDIS_SPEC_RETENTION_MS;
    const peakCutoffTimestampMs = Date.now() - REDIS_PEAK_RETENTION_MS;
    let totalSpecArchived = 0; let totalPeakArchived = 0; let specErrors = 0; let peakErrors = 0;
    try {
        // --- Archive and Cleanup Spectrogram History Lists ---
        const specHistoryKeys = await streamRedisClient.keys('spectrogram_history:*');
        logger.debug(`Found ${specHistoryKeys.length} spectrogram history keys for potential cleanup.`);
        for (const key of specHistoryKeys) {
            const detectorId = key.split(':')[1]; if (!detectorId) continue;
            try {
                const recordsToArchive = []; const recordsToKeep = [];
                const allRecords = await streamRedisClient.lrange(key, 0, -1);
                for (const recordStr of allRecords) {
                    try { const record = JSON.parse(recordStr); if (record && record.timestamp) { const recordTime = new Date(record.timestamp).getTime(); if (recordTime < specCutoffTimestampMs) { recordsToArchive.push(record); } else { recordsToKeep.push(recordStr); } } else { recordsToKeep.push(recordStr); } } catch (parseErr) { logger.warn("Failed to parse record during spec archive scan, keeping.", { key, record: recordStr.substring(0,100), error: parseErr.message }); recordsToKeep.push(recordStr); }
                }
                if (recordsToArchive.length > 0) {
                    logger.info(`Found ${recordsToArchive.length} spectrogram records to archive for ${key}`);
                    // Phase 4d: Map including transient_details
                    const dbRecords = recordsToArchive.map(r => ({
                         detector_id: r.detectorId,
                         timestamp: r.timestamp,
                         location_lat: r.location?.lat,
                         location_lon: r.location?.lon,
                         spectrogram_data: r.spectrogram,
                         transient_detected: r.transientInfo?.type !== 'none' || false, // Boolean flag based on type
                         transient_details: r.transientInfo?.details || null // Get details string
                    }));
                    const insertedCount = await db.insertHistoricalSpectrograms(dbRecords); // Use updated insert function
                    totalSpecArchived += insertedCount; archiveRecordsCounter.inc({ type: 'spec', status: 'archived' }, insertedCount);
                    await streamRedisClient.del(key);
                    if (recordsToKeep.length > 0) { await streamRedisClient.rpush(key, recordsToKeep); }
                    logger.info(`Successfully archived ${insertedCount} and trimmed Redis list for ${key}. Kept ${recordsToKeep.length} records.`);
                } else { archiveRecordsCounter.inc({ type: 'spec', status: 'skipped' }, 0); }
            } catch (archiveError) { logger.error(`Error archiving spectrograms for ${key}`, { error: archiveError.message }); specErrors++; archiveRecordsCounter.inc({ type: 'spec', status: 'error' }); }
        }
        // --- Archive and Cleanup Peak History Sorted Sets ---
        const peakHistoryKeys = await streamRedisClient.keys('peaks:*');
        logger.debug(`Found ${peakHistoryKeys.length} peak history keys for potential cleanup.`);
        for (const key of peakHistoryKeys) {
             const detectorId = key.split(':')[1]; if (!detectorId) continue;
             try {
                 const peaksWithScores = await streamRedisClient.zrangebyscore(key, '-inf', `(${peakCutoffTimestampMs}`, 'WITHSCORES');
                 if (peaksWithScores.length > 0) {
                     const numRecords = peaksWithScores.length / 2; logger.info(`Found ${numRecords} peak records to archive for ${key}`);
                     const dbRecords = []; const scoresToRemove = [];
                     for(let i=0; i<peaksWithScores.length; i+=2){
                         const peakJson = peaksWithScores[i]; const timestampMs = parseInt(peaksWithScores[i+1], 10);
                         try { const peakData = JSON.parse(peakJson); dbRecords.push({ detector_id: detectorId, timestamp: new Date(timestampMs), peak_data: peakData }); scoresToRemove.push(timestampMs); } catch(parseErr){ logger.warn("Failed to parse peak JSON during archive, skipping record.", { key, score: timestampMs, record: peakJson.substring(0,100), error: parseErr.message }); }
                     }
                     if (dbRecords.length > 0) {
                         const insertedCount = await db.insertHistoricalPeaks(dbRecords); // No change needed here
                         totalPeakArchived += insertedCount; archiveRecordsCounter.inc({ type: 'peak', status: 'archived' }, insertedCount);
                         const removedCount = await streamRedisClient.zremrangebyscore(key, '-inf', `(${peakCutoffTimestampMs}`);
                         logger.info(`Successfully archived ${insertedCount} and removed ${removedCount} records from Redis ZSET for ${key}.`);
                     } else if (numRecords > 0) { logger.warn(`Attempted to archive ${numRecords} peak records for ${key}, but none were successfully prepared for DB.`); archiveRecordsCounter.inc({ type: 'peak', status: 'error' }, numRecords); }
                 } else { archiveRecordsCounter.inc({ type: 'peak', status: 'skipped' }, 0); }
             } catch (archiveError) { logger.error(`Error archiving peaks for ${key}`, { error: archiveError.message }); peakErrors++; archiveRecordsCounter.inc({ type: 'peak', status: 'error' }); }
        }
        const trackStateKeys = await redisClient.keys('track_state:*'); logger.debug("Checked peak tracking state keys (relying on Redis TTL)", { keyCount: trackStateKeys.length });
    } catch (err) { logger.error('History cleanup/archiving task error', { error: err.message });
    } finally {
        const duration = (Date.now() - startTime) / 1000; archiveDuration.set(duration);
        logger.info('History cleanup/archiving task finished.', { duration_sec: duration, spec_archived: totalSpecArchived, peak_archived: totalPeakArchived, spec_errors: specErrors, peak_errors: peakErrors });
        setTimeout(cleanupOldHistory, CLEANUP_INTERVAL_MS);
    }
}

// --- Centralized Error Handling Middleware ---
app.use((err, req, res, next) => {
  logger.error('Unhandled API Error', { error: err.message, stack: err.stack, url: req.originalUrl, method: req.method, ip: req.ip, status: err.status || err.statusCode || 500 });
  const status = err.status || err.statusCode || 500; const message = (process.env.NODE_ENV === 'production' && status >= 500) ? 'Internal server error.' : err.message || 'Unexpected error.';
  if (!res.headersSent) { res.status(status).json({ error: message }); } else { next(err); }
});

// --- Start Server and Background Tasks ---
async function startServer() {
    try {
        await redisClient.connect();
        await streamRedisClient.connect();
        logger.info('Redis clients connected.');
        await db.initialize(); // Await DB initialization
        logger.info('Dependencies ready, starting HTTP server...');
        server.listen(PORT, () => {
             logger.info(`HTTP Server listening on port ${PORT}`);
             processStreamMessages();
             setTimeout(cleanupOldHistory, 15000); // Start cleanup shortly after server start (15s)
        });
    } catch (err) {
        logger.error('Server startup failed', { error: err.message, stack: err.stack });
        await redisClient.quit().catch(()=>{});
        await streamRedisClient.quit().catch(()=>{});
        await db.end().catch(()=>{}); // Use exported end function
        process.exit(1);
    }
}

// --- Graceful Shutdown ---
async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Shutting down gracefully...`); let exitCode = 0;
  server.close(async () => { logger.info('HTTP server closed.'); logger.info('Closing WS connections...'); wss.clients.forEach(ws => ws.terminate());
    try { if (redisClient.status === 'ready' || redisClient.status === 'connecting') { await redisClient.quit(); logger.info('Main Redis closed.'); } } catch (err) { logger.error('Error closing main Redis:', { error: err.message }); exitCode = 1; }
    try { if (streamRedisClient.status === 'ready' || streamRedisClient.status === 'connecting') { await streamRedisClient.quit(); logger.info('Stream/Hist Redis closed.'); } } catch (err) { logger.error('Error closing stream/hist Redis:', { error: err.message }); exitCode = 1; }
    try { await db.end(); logger.info('DB pool closed.'); } catch (err) { logger.error('Error closing DB pool:', { error: err.message }); exitCode = 1; } // Use exported end function
    logger.info('Shutdown complete.'); process.exit(exitCode);
  });
  setTimeout(() => { logger.error('Graceful shutdown timed out. Forcing exit.'); process.exit(1); }, 15000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server only if not in test environment
if (process.env.NODE_ENV !== 'test') {
    startServer();
}

module.exports = server;
