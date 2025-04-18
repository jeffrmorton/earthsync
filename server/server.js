// server/server.js
/**
 * Main server entry point for EarthSync (v1.1.28 - Linter Fixes).
 * Orchestrates API routes, WebSocket connections, stream processing, and archival tasks.
 * Initializes dependencies, sets up middleware, mounts routes, and handles graceful shutdown.
 * No backslash escapes in template literals.
 */
require('dotenv').config(); // Load environment variables early
const express = require('express');
const compression = require('compression');
const helmet = require('helmet');
const cors = require('cors');
const http = require('http');

// --- Centralized Configuration & Constants ---
const constants = require('./config/constants');
const { PORT, ALLOWED_ORIGINS, NODE_ENV } = constants;

// --- Utilities ---
const logger = require('./utils/logger'); // Centralized logger
const db = require('./db.js'); // Database utilities (including initialization)
const { initializeRedisClients, closeRedisClients } = require('./utils/redisClients'); // Redis client management
const { initializeMetrics, metricsMiddleware } = require('./utils/metrics'); // Prometheus metrics setup & middleware

// --- Core Modules ---
const { initializeWebSocketServer, closeAllConnections } = require('./websocketManager'); // WebSocket handling
const { startStreamProcessing, stopStreamProcessing } = require('./streamProcessor'); // Redis stream processing logic
const { startArchiver, stopArchiver } = require('./archiver'); // Background archival task

// --- Route Handlers ---
const authRoutes = require('./routes/auth');
const historyRoutes = require('./routes/history');
const ingestRoutes = require('./routes/ingest');
const miscRoutes = require('./routes/misc'); // Health, metrics, etc.

// --- Log Startup Info ---
logger.info(`Starting EarthSync server v1.1.28 (Refactored) on port ${PORT}...`); // Corrected interpolation
logger.info(`Node Environment: ${NODE_ENV}`); // Corrected interpolation
logger.info(`Allowed CORS origins: ${ALLOWED_ORIGINS.join(', ')}`); // Corrected interpolation

// --- Global Error Handling Setup ---
process.on('uncaughtException', (err, origin) => {
  logger.error('UNCAUGHT EXCEPTION', { error: err.message, stack: err.stack, origin });
  console.error('Uncaught exception detected! Forcing shutdown immediately.', err);
  process.exitCode = 1;
  process.kill(process.pid, 'SIGKILL');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('UNHANDLED REJECTION', {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
    promise: promise,
  });
});

// --- Express App Setup ---
const app = express();
const server = http.createServer(app);

// --- Security Middleware ---
app.use(helmet());
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
        callback(null, true);
      } else {
        logger.warn('CORS blocked for origin:', { origin });
        callback(new Error('This origin is not allowed by CORS policy.'));
      }
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  })
);

// --- Performance Middleware ---
app.use(compression());

// --- Body Parsers ---
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// --- Metrics & Request Logging Middleware ---
app.use(metricsMiddleware);

// --- Mount API Routes ---
app.use('/api/auth', authRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/data-ingest', ingestRoutes);
app.use('/', miscRoutes);

// --- Centralized Error Handling Middleware ---
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const statusCode = err.status || err.statusCode || 500;
  const errorMessage =
    NODE_ENV === 'production' && statusCode >= 500
      ? 'An internal server error occurred.'
      : err.message || 'An unexpected error occurred.';

  logger.error('Unhandled API Error Caught by Middleware', {
    error: err.message,
    status: statusCode,
    stack: NODE_ENV !== 'production' ? err.stack : undefined,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
  });

  if (!res.headersSent) {
    res.status(statusCode).json({ error: errorMessage });
  }
});

// --- Start Server and Background Tasks ---
async function startServer() {
  try {
    await initializeRedisClients();
    await db.initialize();
    initializeMetrics(app);
    initializeWebSocketServer(server);
    startStreamProcessing();
    startArchiver();

    await new Promise((resolve, reject) => {
      server.on('error', (error) => {
        logger.error('HTTP server failed to start listening', { error: error.message });
        reject(error);
      });

      server.listen(PORT, () => {
        logger.info(`HTTP Server listening successfully on port ${PORT}`); // Corrected interpolation
        resolve();
      });
    });

    logger.info('EarthSync server startup sequence completed successfully.');
  } catch (err) {
    logger.error('Server startup sequence failed', { error: err.message, stack: err.stack });
    process.exitCode = 1;
    await gracefulShutdown('STARTUP_FAILURE').catch(() => {
      logger.error('Graceful shutdown failed during startup error handling.');
    });
  }
}

// --- Graceful Shutdown Logic ---
let isShuttingDown = false;
async function gracefulShutdown(signal = 'UNKNOWN') {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress.');
    return;
  }
  isShuttingDown = true;
  logger.info(`Received ${signal}. Initiating graceful shutdown...`); // Corrected interpolation
  const initialExitCode = process.exitCode ?? 0;

  const shutdownTimeout = setTimeout(() => {
    logger.error('Graceful shutdown timed out after 15 seconds. Forcing exit.');
    process.exitCode = 1;
    // eslint-disable-next-line no-process-exit
    process.exit(1);
  }, 15000);

  let shutdownError = false;

  try {
    logger.info('Stopping background tasks...');
    stopStreamProcessing();
    stopArchiver();

    logger.info('Closing HTTP server...');
    await new Promise((resolve, reject) => {
      server.close((err) => {
        if (err) {
          logger.error('Error closing HTTP server:', { error: err.message });
          shutdownError = true;
          reject(err);
        } else {
          logger.info('HTTP server closed successfully.');
          resolve();
        }
      });
    });

    logger.info('Closing WebSocket connections...');
    closeAllConnections();

    logger.info('Closing database and Redis connections...');
    await Promise.allSettled([
      closeRedisClients(),
      db.end(),
    ]).then((results) => {
      results.forEach((result, i) => {
        if (result.status === 'rejected') {
          const source = i === 0 ? 'Redis' : 'Database';
          logger.error(`Error closing ${source} connections:`, { // Corrected interpolation
            error: result.reason?.message || result.reason,
          });
          shutdownError = true;
        }
      });
    });
  } catch (err) {
    logger.error('Error during graceful shutdown process:', { error: err.message });
    shutdownError = true;
  } finally {
    clearTimeout(shutdownTimeout);
    const finalExitCode = shutdownError ? 1 : initialExitCode;
    logger.info(`Graceful shutdown complete. Exiting with code ${finalExitCode}.`); // Corrected interpolation
    process.exitCode = finalExitCode;
  }
}

// --- Setup Signal Handlers ---
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// --- Main Execution ---
if (NODE_ENV !== 'test') {
  startServer();
}

module.exports = server;
