// server/server.js
/**
 * Main server entry point for EarthSync (v1.1.28 - Linter Fixes).
 * Orchestrates API routes, WebSocket connections, stream processing, and archival tasks.
 * Initializes dependencies, sets up middleware, mounts routes, and handles graceful shutdown.
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
logger.info(`Starting EarthSync server v1.1.28 (Refactored) on port ${PORT}...`);
logger.info(`Node Environment: ${NODE_ENV}`);
logger.info(`Allowed CORS origins: ${ALLOWED_ORIGINS.join(', ')}`);

// --- Check Critical Env Vars ---
// (Checks moved inside constants.js or individual modules where needed)

// --- Global Error Handling Setup ---
// Catch uncaught exceptions - Should ideally restart the process using a process manager
process.on('uncaughtException', (err, origin) => {
  logger.error('UNCAUGHT EXCEPTION', { error: err.message, stack: err.stack, origin });
  // Perform minimal cleanup if possible, then exit forcefully
  console.error('Uncaught exception detected! Forcing shutdown immediately.', err); // Log directly to console as logger might fail
  process.exitCode = 1; // Set exit code
  // Do NOT attempt graceful shutdown here, process state is unstable
  process.kill(process.pid, 'SIGKILL'); // Force kill after logging
});

// Catch unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('UNHANDLED REJECTION', {
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
    promise: promise, // Log the promise that was rejected
  });
  // Optionally exit, or improve error reporting
  // Recommend NOT exiting automatically here unless critical
});

// --- Express App Setup ---
const app = express();
const server = http.createServer(app); // Create HTTP server for WebSocket compatibility

// --- Security Middleware ---
app.use(helmet()); // Apply various security headers (CSP, HSTS, etc.)
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (server-to-server, curl) or from whitelisted origins
      if (!origin || ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
        callback(null, true);
      } else {
        logger.warn('CORS blocked for origin:', { origin });
        callback(new Error('This origin is not allowed by CORS policy.'));
      }
    },
    methods: ['GET', 'POST', 'DELETE'], // Specify allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'], // Specify allowed headers
  })
);

// --- Performance Middleware ---
app.use(compression()); // Enable gzip/deflate compression for responses

// --- Body Parsers ---
app.use(express.json({ limit: '5mb' })); // Parse JSON request bodies (limit size)
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded request bodies

// --- Metrics & Request Logging Middleware ---
// This should come *before* the main routes to measure latency accurately
app.use(metricsMiddleware);

// --- Mount API Routes ---
// Use dedicated router instances for different parts of the API
app.use('/api/auth', authRoutes); // Authentication routes (prefix /api)
app.use('/api/history', historyRoutes); // History data routes (prefix /api)
app.use('/api/data-ingest', ingestRoutes); // Data ingest route (prefix /api)
app.use('/', miscRoutes); // Miscellaneous routes (health, metrics at root)

// --- Centralized Error Handling Middleware ---
// This must be the *last* middleware added using app.use
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const statusCode = err.status || err.statusCode || 500;
  // Avoid exposing internal error details in production
  const errorMessage =
    NODE_ENV === 'production' && statusCode >= 500
      ? 'An internal server error occurred.'
      : err.message || 'An unexpected error occurred.';

  // Log the detailed error internally
  logger.error('Unhandled API Error Caught by Middleware', {
    error: err.message,
    status: statusCode,
    stack: NODE_ENV !== 'production' ? err.stack : undefined, // Only log stack in dev/test
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
  });

  // Send standardized error response
  // Check if headers were already sent (e.g., by a streaming response)
  if (!res.headersSent) {
    res.status(statusCode).json({ error: errorMessage });
  }
  // No next(err) needed here as this is the final error handler
});

// --- Start Server and Background Tasks ---
async function startServer() {
  try {
    // 1. Initialize dependencies (Redis, DB)
    await initializeRedisClients(); // Connect Redis clients
    await db.initialize(); // Initialize DB pool and schema

    // 2. Initialize metrics system
    initializeMetrics(app); // Setup metrics registry

    // 3. Initialize WebSocket server, attaching to the HTTP server
    initializeWebSocketServer(server);

    // 4. Start background tasks (Stream Processor, Archiver)
    // These should run indefinitely until stopped during shutdown
    startStreamProcessing();
    startArchiver();

    // 5. Start the HTTP server listening for requests
    await new Promise((resolve, reject) => {
      server.on('error', (error) => {
        logger.error('HTTP server failed to start listening', { error: error.message });
        reject(error); // Reject the promise on server error
      });

      server.listen(PORT, () => {
        logger.info(`HTTP Server listening successfully on port ${PORT}`);
        resolve(); // Resolve the promise once listening starts
      });
    });

    logger.info('EarthSync server startup sequence completed successfully.');
  } catch (err) {
    logger.error('Server startup sequence failed', { error: err.message, stack: err.stack });
    // Attempt graceful shutdown of any partially initialized resources
    // Use process.exitCode instead of process.exit(1)
    process.exitCode = 1;
    await gracefulShutdown('STARTUP_FAILURE').catch(() => {
      // Log if shutdown itself fails during startup error handling
      logger.error('Graceful shutdown failed during startup error handling.');
    });
    // Process should exit via gracefulShutdown's logic now
  }
}

// --- Graceful Shutdown Logic ---
let isShuttingDown = false;
async function gracefulShutdown(signal = 'UNKNOWN') {
  // Add default value for signal
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress.');
    return;
  }
  isShuttingDown = true;
  logger.info(`Received ${signal}. Initiating graceful shutdown...`);
  const initialExitCode = process.exitCode ?? 0; // Preserve exit code if set by startup failure

  // Create a timeout to force exit if shutdown takes too long
  const shutdownTimeout = setTimeout(() => {
    logger.error('Graceful shutdown timed out after 15 seconds. Forcing exit.');
    process.exitCode = 1; // Set exit code to indicate error before forcing exit
    // eslint-disable-next-line no-process-exit
    process.exit(1); // Force exit - justification: prevent hung process after timeout
  }, 15000); // 15 seconds timeout

  let shutdownError = false; // Flag to track errors during shutdown

  try {
    // 1. Stop background tasks from starting new work
    logger.info('Stopping background tasks...');
    stopStreamProcessing(); // Signals the loop to stop
    stopArchiver(); // Stops the timer for the next run

    // 2. Close HTTP server to stop accepting new incoming requests
    logger.info('Closing HTTP server...');
    await new Promise((resolve, reject) => {
      server.close((err) => {
        if (err) {
          logger.error('Error closing HTTP server:', { error: err.message });
          shutdownError = true;
          reject(err); // Reject if server closing fails
        } else {
          logger.info('HTTP server closed successfully.');
          resolve();
        }
      });
    });

    // 3. Close WebSocket connections forcefully
    logger.info('Closing WebSocket connections...');
    closeAllConnections(); // Uses terminate()

    // 4. Close Database and Redis connections
    logger.info('Closing database and Redis connections...');
    await Promise.allSettled([
      // Use allSettled to ensure all attempts are made
      closeRedisClients(),
      db.end(), // Close DB pool
    ]).then((results) => {
      results.forEach((result, i) => {
        if (result.status === 'rejected') {
          const source = i === 0 ? 'Redis' : 'Database';
          logger.error(`Error closing ${source} connections:`, {
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
    clearTimeout(shutdownTimeout); // Clear the force exit timeout
    // Set final exit code based on initial code and shutdown errors
    const finalExitCode = shutdownError ? 1 : initialExitCode;
    logger.info(`Graceful shutdown complete. Exiting with code ${finalExitCode}.`);
    process.exitCode = finalExitCode; // Set exit code for Node.js to use
    // Let Node.js exit naturally now - Removed explicit process.exit() here
  }
}

// --- Setup Signal Handlers ---
// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // Standard signal for termination
process.on('SIGINT', () => gracefulShutdown('SIGINT')); // Signal from Ctrl+C

// --- Main Execution ---
// Start the server only if not running in a test environment
if (NODE_ENV !== 'test') {
  startServer();
}

// Export the HTTP server instance, primarily for testing frameworks like Supertest
module.exports = server;
