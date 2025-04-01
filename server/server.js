/**
 * Main server entry point for EarthSync.
 * Handles API requests, WebSocket connections, and data processing.
 * Includes Input Validation, Centralized Error Handling, and Redis-based key storage.
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
const { body, param, query: queryValidator, validationResult } = require('express-validator');

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
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
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

if (!JWT_SECRET) { logger.error('FATAL: JWT_SECRET is not defined.'); process.exit(1); }
if (!REDIS_HOST || !REDIS_PORT || !REDIS_PASSWORD) { logger.error('FATAL: Redis configuration missing.'); process.exit(1); }

// --- Global Error Handling ---
process.on('uncaughtException', (err) => {
  logger.error('UNCAUGHT EXCEPTION', { error: err.message, stack: err.stack });
  process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
  logger.error('UNHANDLED REJECTION', { reason: reason?.toString(), stack: reason?.stack, promise });
});

logger.info(`Starting EarthSync server on port ${PORT}...`);
logger.info(`Allowed CORS origins: ${ALLOWED_ORIGINS.join(', ')}`);


// --- Redis Client Setup ---
const redisClient = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
  keyPrefix: REDIS_KEY_PREFIX, // Prefix for user keys
  retryStrategy: (times) => {
    const delay = Math.min(times * 100, 5000);
    logger.warn(`Redis connection failed, retrying in ${delay}ms (attempt ${times})`);
    return delay;
  },
  reconnectOnError: (err) => {
    logger.error('Redis reconnection error', { error: err.message });
    return true;
  },
   lazyConnect: true
});

// Separate client for stream/history (no prefix)
const streamRedisClient = new Redis({
    host: REDIS_HOST,
    port: REDIS_PORT,
    password: REDIS_PASSWORD,
    retryStrategy: (times) => Math.min(times * 100, 5000),
    reconnectOnError: (err) => true,
    lazyConnect: true
});


redisClient.on('error', (err) => logger.error('Main Redis Client Error', { error: err.message }));
redisClient.on('connect', () => logger.info('Main Redis client connected.'));
redisClient.on('reconnecting', () => logger.info('Main Redis client reconnecting...'));
redisClient.on('ready', () => logger.info('Main Redis client ready.'));

streamRedisClient.on('error', (err) => logger.error('Stream/History Redis Client Error', { error: err.message }));
streamRedisClient.on('connect', () => logger.info('Stream/History Redis client connected.'));
streamRedisClient.on('reconnecting', () => logger.info('Stream/History Redis client reconnecting...'));
streamRedisClient.on('ready', () => logger.info('Stream/History Redis client ready.'));


// --- Express App Setup ---
const app = express();
const server = http.createServer(app);

// --- Core Middleware ---
app.use(cors({
    origin: function (origin, callback) {
      if (!origin || ALLOWED_ORIGINS.indexOf(origin) !== -1) {
        callback(null, true)
      } else {
        logger.warn('CORS blocked request from origin:', { origin });
        callback(new Error('Not allowed by CORS'))
      }
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// --- Request Logging and Latency Middleware ---
app.use((req, res, next) => {
  const start = process.hrtime();
  res.on('finish', () => {
    const diff = process.hrtime(start);
    const latency = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(3);
    const route = req.originalUrl.split('?')[0];
    httpRequestCounter.inc({ method: req.method, route: route, status: res.statusCode });
    httpRequestLatency.observe({ method: req.method, route: route }, parseFloat(latency) / 1000);
    logger.info('HTTP Request', { method: req.method, url: req.originalUrl, status: res.statusCode, latency_ms: latency, ip: req.ip });
  });
  next();
});

// --- Input Validation Middleware ---
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn('Input validation failed', { errors: errors.array(), url: req.originalUrl });
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
};

// --- Rate Limiting ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login/register attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: { error: 'Too many API requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- API Routes ---

// Health Check
app.get('/health', async (req, res, next) => {
  try {
    const redisPing = await redisClient.ping(); // Check main client
    const streamRedisPing = await streamRedisClient.ping(); // Check stream client
    await query('SELECT 1');
    res.status(200).json({
        status: 'OK',
        uptime: process.uptime().toFixed(2),
        redis_main: redisPing === 'PONG' ? 'OK' : 'Error',
        redis_stream: streamRedisPing === 'PONG' ? 'OK' : 'Error',
        postgres: 'OK'
    });
  } catch (err) {
    logger.error('Health check failed', { error: err.message });
    next(err);
  }
});

// User Registration
const registerValidationRules = [
  body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters long.').matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores.'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.')
];
app.post('/register', authLimiter, registerValidationRules, validateRequest, async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const checkUser = await query('SELECT username FROM users WHERE username = $1', [username]);
    if (checkUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    logger.info('User registered successfully', { username });
    res.status(201).json({ message: 'Registration successful' });
  } catch (err) {
    logger.error('Registration error', { username, error: err.message });
    next(err);
  }
});

// User Login
const loginValidationRules = [
  body('username').trim().notEmpty().withMessage('Username is required.'),
  body('password').notEmpty().withMessage('Password is required.')
];
app.post('/login', authLimiter, loginValidationRules, validateRequest, async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const result = await query('SELECT id, username, password FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      logger.warn('Login attempt failed: User not found', { username });
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      logger.warn('Login attempt failed: Invalid password', { username });
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: `${ENCRYPTION_KEY_TTL_SECONDS}s` });
    logger.info('User logged in successfully', { username });
    res.json({ token });
  } catch (err) {
    logger.error('Login error', { username, error: err.message });
    next(err);
  }
});

// Key Exchange
app.post('/key-exchange', apiLimiter, authenticateToken, async (req, res, next) => {
  const username = req.user.username;
  try {
    const key = crypto.randomBytes(32).toString('hex');
    const redisKey = `${username}`; // Prefix handled by redisClient
    await redisClient.setex(redisKey, ENCRYPTION_KEY_TTL_SECONDS, key);
    logger.info('Encryption key generated and stored in Redis', { username, redisKey: REDIS_KEY_PREFIX + redisKey });
    res.json({ key });
  } catch (err) {
    logger.error('Key exchange error', { username, error: err.message });
    next(err);
  }
});

// Historical Data
const historyValidationRules = [
  param('hours').isInt({ min: 1, max: 72 }).withMessage('Hours must be an integer between 1 and 72.'),
  queryValidator('detectorId').optional().isString().trim().isLength({ min: 1, max: 50 }).withMessage('Invalid detector ID format.')
];
app.get('/history/:hours', apiLimiter, authenticateToken, historyValidationRules, validateRequest, async (req, res, next) => {
  const hours = parseInt(req.params.hours, 10);
  const { detectorId } = req.query;
  const username = req.user.username;
  const cacheKey = `history:${hours}:${detectorId || 'all'}`; // Cache keys don't need prefix

  try {
    // Use stream/history client for cache and history lists
    const cached = await streamRedisClient.get(cacheKey);
    if (cached) {
      logger.info('Serving history from cache', { username, hours, detectorId, cacheKey });
      return res.json(JSON.parse(cached));
    }

    logger.info('Fetching history from storage', { username, hours, detectorId });
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();

    const historyKeyPattern = detectorId ? `spectrogram_history:${detectorId}` : 'spectrogram_history:*';
    const historyKeys = await streamRedisClient.keys(historyKeyPattern);

    if (historyKeys.length === 0) {
        logger.info('No history keys found matching pattern', { pattern: historyKeyPattern });
        return res.json([]);
    }

    const fetchPromises = historyKeys.map(key => streamRedisClient.lrange(key, 0, -1));
    const allRecordsNested = await Promise.all(fetchPromises);
    const allRecords = allRecordsNested.flat();

    const filteredData = allRecords
      .map(r => { try { return JSON.parse(r); } catch (e) { logger.warn('Failed to parse history record', { record: r?.substring(0, 100) }); return null; } })
      .filter(r => r && r.timestamp >= cutoff && (detectorId ? r.detectorId === detectorId : true));

    const groupedData = filteredData.reduce((acc, r) => {
        if (!r.detectorId || !r.spectrogram || !r.location || !Array.isArray(r.spectrogram)) return acc;
        acc[r.detectorId] = acc[r.detectorId] || { detectorId: r.detectorId, location: r.location, spectrograms: [] };
        acc[r.detectorId].spectrograms.push(...r.spectrogram.flat());
        return acc;
    }, {});

    const result = Object.values(groupedData).map(group => ({
        detectorId: group.detectorId,
        location: group.location,
        spectrogram: group.spectrograms
    }));

    if (result.length > 0) {
       await streamRedisClient.setex(cacheKey, 300, JSON.stringify(result)); // Use stream client for cache
       logger.info('Cached historical data', { cacheKey, recordCount: result.length });
    }

    res.json(result);

  } catch (err) {
    logger.error('History fetch error', { username, hours, detectorId, error: err.message });
    next(err);
  }
});


// User Deletion
const userDeleteValidationRules = [
  param('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid username format.')
];
app.delete('/users/:username', apiLimiter, authenticateToken, userDeleteValidationRules, validateRequest, async (req, res, next) => {
  const targetUsername = req.params.username;
  const requesterUsername = req.user.username;

  if (targetUsername !== requesterUsername) {
    logger.warn('User deletion forbidden', { requester: requesterUsername, target: targetUsername });
    return res.status(403).json({ error: 'Forbidden: You can only delete your own account.' });
  }

  try {
    const result = await query('DELETE FROM users WHERE username = $1 RETURNING username', [targetUsername]);
    if (result.rowCount === 0) {
      logger.warn('User deletion failed: User not found', { username: targetUsername });
      return res.status(404).json({ error: 'User not found' });
    }
    const redisKey = `${targetUsername}`; // Prefix handled by redisClient
    const deletedKeys = await redisClient.del(redisKey);
    logger.info('User deleted successfully', { username: targetUsername, deletedBy: requesterUsername, redisKeysDeleted: deletedKeys });
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (err) {
    logger.error('User deletion error', { username: targetUsername, error: err.message });
    next(err);
  }
});

// Prometheus Metrics Endpoint
app.get('/metrics', async (req, res, next) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    logger.error('Metrics endpoint error', { error: err.message });
    next(err);
  }
});


// --- WebSocket Server Setup ---
const wss = new WebSocket.Server({ server });

wss.on('connection', async (ws, req) => {
  let username = 'unknown';
  try {
     const requestUrl = new URL(req.url, `ws://${req.headers.host}`);
     const token = requestUrl.searchParams.get('token');

    if (!token) {
      logger.warn('WebSocket connection attempt without token');
      ws.close(1008, 'Token required');
      return;
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    username = decoded.username;
    if (!username) throw new Error("Token payload missing username");

    ws.username = username;
    logger.info('WebSocket client connected', { username });
    websocketConnections.inc();

    ws.on('message', (message) => {
      logger.debug('WebSocket message received', { username, message: message.toString().substring(0,100) });
    });

    ws.on('close', (code, reason) => {
      logger.info('WebSocket client disconnected', { username, code, reason: reason.toString() });
      websocketConnections.dec();
    });

    ws.on('error', (err) => {
      logger.error('WebSocket connection error', { username, error: err.message });
    });

  } catch (err) {
    if (err instanceof jwt.JsonWebTokenError || err instanceof jwt.TokenExpiredError) {
      logger.warn('WebSocket connection failed: Invalid token', { error: err.message });
      ws.close(1008, 'Invalid or expired token');
    } else {
      logger.error('WebSocket connection setup error', { username, error: err.message });
      ws.close(1011, 'Internal server error during connection setup');
    }
  }
});

wss.on('error', (err) => {
  logger.error('WebSocket Server Error', { error: err.message });
});


// --- Data Processing Logic ---

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
    const streamKey = 'spectrogram_stream'; // No prefix needed for stream key itself
    const groupName = 'earthsync_group';
    const consumerName = `consumer_${process.pid}`;

    try {
        // Use streamRedisClient (no prefix) for stream operations
        await streamRedisClient.xgroup('CREATE', streamKey, groupName, '$', 'MKSTREAM').catch(err => {
            if (!err.message.includes('BUSYGROUP Consumer Group name already exists')) {
                 logger.error('Failed to create or verify consumer group', { group: groupName, error: err.message });
                 throw err;
            } else {
                 logger.info(`Consumer group '${groupName}' already exists.`);
            }
        });
        logger.info(`Consumer ${consumerName} joining group ${groupName} for stream ${streamKey}`);

        while (true) {
            try {
                const results = await streamRedisClient.xreadgroup(
                    'GROUP', groupName, consumerName,
                    'COUNT', 10, 'BLOCK', 5000, 'STREAMS', streamKey, '>'
                );

                if (!results) continue;

                for (const [/*streamName*/, messages] of results) {
                    for (const [messageId, fields] of messages) {
                        let parsedMessage = null;
                        try {
                            const dataIndex = fields.indexOf('data');
                            if (dataIndex === -1 || !fields[dataIndex + 1]) {
                                 logger.warn('Stream message missing data field', { messageId });
                                 await streamRedisClient.xack(streamKey, groupName, messageId);
                                 continue;
                            }
                            parsedMessage = JSON.parse(fields[dataIndex + 1]);

                            if (!parsedMessage.spectrogram || !parsedMessage.detectorId || !parsedMessage.location || !Array.isArray(parsedMessage.spectrogram)) {
                                logger.warn('Invalid message structure in stream', { messageId, detectorId: parsedMessage?.detectorId });
                                await streamRedisClient.xack(streamKey, groupName, messageId);
                                continue;
                            }

                            const downsampledSpectrograms = parsedMessage.spectrogram.map(spec =>
                                 Array.isArray(spec) ? spec.filter((_, i) => i % DOWNSAMPLE_FACTOR === 0) : []
                            );

                            const dataToProcess = {
                                ...parsedMessage,
                                spectrogram: downsampledSpectrograms,
                            };
                            const messageString = JSON.stringify(dataToProcess);

                            const historyKey = `spectrogram_history:${parsedMessage.detectorId}`; // No prefix
                            await streamRedisClient.pipeline()
                                .lpush(historyKey, messageString)
                                .ltrim(historyKey, 0, 999)
                                .exec();

                            // --- Broadcast ---
                            let sentCount = 0;
                            for (const ws of wss.clients) {
                                if (ws.readyState === WebSocket.OPEN && ws.username) {
                                    // Use main client (with prefix) to get key
                                    const userRedisKey = `${ws.username}`;
                                    const key = await redisClient.get(userRedisKey);

                                    if (key) {
                                        const encryptedMessage = encryptMessage(messageString, key);
                                        if (encryptedMessage) {
                                             ws.send(encryptedMessage, (err) => {
                                                 if (err) logger.error('WebSocket send error', { username: ws.username, error: err.message });
                                             });
                                             sentCount++;
                                        } else {
                                             logger.warn('Skipping WebSocket send due to encryption error', { username: ws.username });
                                        }
                                    } else {
                                        logger.warn('No encryption key found in Redis for user, skipping send.', { username: ws.username, redisKey: REDIS_KEY_PREFIX + userRedisKey });
                                    }
                                }
                            }
                             if (sentCount > 0) logger.debug(`Broadcasted message ${messageId} to ${sentCount} clients`);

                            await streamRedisClient.xack(streamKey, groupName, messageId);

                        } catch (processingError) {
                            logger.error('Error processing stream message', { messageId, detectorId: parsedMessage?.detectorId, error: processingError.message, stack: processingError.stack });
                            await streamRedisClient.xack(streamKey, groupName, messageId).catch(ackErr => {
                                logger.error('Failed to ACK message after processing error', { messageId, error: ackErr.message });
                            });
                        }
                    }
                }
            } catch (readError) {
                 logger.error('Error reading from stream group', { group: groupName, error: readError.message, stack: readError.stack });
                 await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    } catch (streamError) {
        logger.error('Stream processing setup or fatal loop error', { error: streamError.message, stack: streamError.stack });
        setTimeout(processStreamMessages, 5000);
    }
}


// --- Periodic Cleanup Task ---
async function cleanupOldHistory() {
    logger.info('Running periodic history cleanup task...');
    try {
        const cutoffTimestamp = Date.now() - (25 * 60 * 60 * 1000);
        // Use stream client (no prefix) for history keys
        const historyKeys = await streamRedisClient.keys('spectrogram_history:*');
        let cleanedKeys = 0;
        let removedRecords = 0;

        for (const key of historyKeys) {
            const records = await streamRedisClient.lrange(key, 0, -1);
            const recordsToKeep = [];
            let originalCount = records.length;

            for(const record of records) {
                try {
                    const parsed = JSON.parse(record);
                    if (new Date(parsed.timestamp).getTime() >= cutoffTimestamp) {
                        recordsToKeep.push(record);
                    }
                } catch (e) {
                     logger.warn('Cleanup: Skipping unparseable record in key', { key });
                }
            }

            if (recordsToKeep.length < originalCount) {
                await streamRedisClient.del(key);
                if (recordsToKeep.length > 0) {
                    await streamRedisClient.rpush(key, recordsToKeep);
                }
                removedRecords += (originalCount - recordsToKeep.length);
                cleanedKeys++;
                 logger.debug('Cleaned history key', { key, remaining: recordsToKeep.length, removed: originalCount - recordsToKeep.length });
            }
        }
        if(cleanedKeys > 0) {
            logger.info('History cleanup task complete', { cleanedKeys, removedRecords });
        } else {
             logger.info('History cleanup task complete: No keys required cleaning.');
        }
    } catch (err) {
        logger.error('History cleanup task error', { error: err.message });
    } finally {
        // Schedule next cleanup using the configured interval
        setTimeout(cleanupOldHistory, CLEANUP_INTERVAL_MS);
    }
}

// --- Centralized Error Handling Middleware ---
app.use((err, req, res, next) => {
  logger.error('Unhandled API Error', {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    status: err.status || err.statusCode || 500
  });

  const status = err.status || err.statusCode || 500;
  const message = (process.env.NODE_ENV === 'production' && status >= 500)
    ? 'An internal server error occurred.'
    : err.message || 'An unexpected error occurred.';

  if (!res.headersSent) {
     res.status(status).json({ error: message });
  } else {
     next(err);
  }
});


// --- Start Server and Background Tasks ---
async function startServer() {
    try {
        await redisClient.connect(); // Connect main client
        await streamRedisClient.connect(); // Connect stream/history client
        logger.info('Redis clients connected, starting HTTP server...');
        server.listen(PORT, () => {
            logger.info(`HTTP Server listening on port ${PORT}`);
            processStreamMessages();
            setTimeout(cleanupOldHistory, 10000);
        });
    } catch (err) {
        logger.error('Server startup failed', { error: err.message });
        await redisClient.quit().catch(()=>{});
        await streamRedisClient.quit().catch(()=>{});
        process.exit(1);
    }
}


// --- Graceful Shutdown ---
async function gracefulShutdown(signal) {
  logger.info(`Received ${signal}. Shutting down gracefully...`);
  let exitCode = 0;

  // Stop processing new messages first? Might be complex to pause the loop.
  // Rely on server close stopping new WS connections & API reqs.

  server.close(async () => {
    logger.info('HTTP server closed.');
    logger.info('Closing WebSocket connections...');
    wss.clients.forEach(ws => ws.terminate());

    // Close Redis connections
    try {
      if (redisClient.status === 'ready' || redisClient.status === 'connecting') {
         await redisClient.quit();
         logger.info('Main Redis connection closed.');
      }
    } catch (err) {
      logger.error('Error closing main Redis connection:', { error: err.message });
      exitCode = 1;
    }
     try {
      if (streamRedisClient.status === 'ready' || streamRedisClient.status === 'connecting') {
         await streamRedisClient.quit();
         logger.info('Stream/History Redis connection closed.');
      }
    } catch (err) {
      logger.error('Error closing stream/history Redis connection:', { error: err.message });
      exitCode = 1;
    }

    // Close DB pool
    try {
        await endDbPool();
        logger.info('Database pool closed.');
    } catch (err) {
        logger.error('Error closing database pool:', { error: err.message });
        exitCode = 1;
    }

    logger.info('Shutdown complete.');
    process.exit(exitCode);
  });

  setTimeout(() => {
    logger.error('Graceful shutdown timed out. Forcing exit.');
    process.exit(1);
  }, 15000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();
