// server/utils/metrics.js
/**
 * Centralized Prometheus metrics setup and middleware. No backslash escapes in template literals.
 */
const promClient = require('prom-client');
const logger = require('./logger'); // Use centralized logger

// Create a Registry which registers the metrics
const register = new promClient.Registry();

// --- Default Metrics ---
// Enable default metrics collection (e.g., process stats, GC stats)
promClient.collectDefaultMetrics({ register });
logger.info('Default Prometheus metrics collection enabled.');

// --- Custom Metrics Definitions ---

const httpRequestCounter = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests processed by the server',
  labelNames: ['method', 'route', 'status'], // Labels for method, normalized route, and status code
  registers: [register],
});

const httpRequestLatency = new promClient.Histogram({
  name: 'http_request_latency_seconds',
  help: 'HTTP request latency distribution in seconds',
  labelNames: ['method', 'route'], // Labels for method and normalized route
  // Buckets good for typical web request latencies (in seconds)
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register],
});

const websocketConnections = new promClient.Gauge({
  name: 'websocket_connections_active',
  help: 'Number of currently active WebSocket connections',
  registers: [register],
});

const dataIngestCounter = new promClient.Counter({
  name: 'data_ingest_requests_total',
  help: 'Total data ingest API requests received',
  labelNames: ['status'], // e.g., 'success', 'error', 'forbidden'
  registers: [register],
});

const peaksDetectedCounter = new promClient.Counter({
  name: 'peaks_detected_total',
  help: 'Total number of peaks detected during spectrogram processing',
  labelNames: ['detectorId'],
  registers: [register],
});

const transientsDetectedCounter = new promClient.Counter({
  name: 'transients_detected_total',
  help: 'Total number of transient events detected',
  labelNames: ['detectorId', 'type'], // e.g., 'broadband', 'narrowband', 'error'
  registers: [register],
});

const archiveRecordsCounter = new promClient.Counter({
  name: 'archive_records_processed_total',
  help: 'Total number of records processed by the archival task',
  labelNames: ['type', 'status'], // type: 'spec'/'peak', status: 'archived'/'error'/'skipped'
  registers: [register],
});

const archiveDuration = new promClient.Gauge({
  name: 'archive_last_duration_seconds',
  help: 'Duration of the last data archival task run in seconds',
  registers: [register],
});

/**
 * Initializes metrics (currently just logs). Placeholder if more setup needed.
 * @param {Express.Application} _app - The Express application instance (optional, marked as unused).
 */
function initializeMetrics(_app) {
  logger.info('Custom Prometheus metrics defined and registered.');
}

/**
 * Express middleware to track HTTP request latency and count requests.
 */
function metricsMiddleware(req, res, next) {
  if (req.path === '/metrics') {
    return next();
  }

  const start = process.hrtime();

  res.on('finish', () => {
    try {
      const diff = process.hrtime(start);
      const latencySeconds = diff[0] + diff[1] * 1e-9;
      const routeLabel = normalizeRoutePath(req.route?.path, req.originalUrl);

      httpRequestCounter.inc({
        method: req.method,
        route: routeLabel,
        status: res.statusCode,
      });

      httpRequestLatency.observe(
        {
          method: req.method,
          route: routeLabel,
        },
        latencySeconds
      );

    } catch (err) {
      logger.error('Error recording HTTP metrics', { error: err.message, path: req.originalUrl });
    }
  });

  next();
}

/**
 * Normalizes an Express route path for consistent metrics labeling.
 * @param {string | undefined} routePath - The route path (e.g., from req.route.path).
 * @param {string} originalUrlPath - The original URL path (e.g., from req.originalUrl).
 * @returns {string} The normalized route path.
 */
function normalizeRoutePath(routePath, originalUrlPath) {
  let path = routePath || originalUrlPath?.split('?')[0] || '/unknown';

  path = path.replace(/\/\d+(\/|\$)/g, '/:id$1');
  path = path.replace(/\/[0-9a-fA-F]{24}(\/|\$)/g, '/:mongoId$1');
  path = path.replace(
    /\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\/|\$)/g,
    '/:uuid$1'
  );

  if (path.startsWith('/api/auth/')) path = path.replace('/api/auth', '/auth');
  else if (path.startsWith('/api/history/peaks/hours/')) path = '/history/peaks/hours/:hours';
  else if (path.startsWith('/api/history/hours/')) path = '/history/hours/:hours';
  else if (path.startsWith('/api/history/peaks/range')) path = '/history/peaks/range';
  else if (path.startsWith('/api/history/range')) path = '/history/range';
  else if (path.startsWith('/api/data-ingest')) path = '/data-ingest';
  else if (path.startsWith('/users/')) {
    path = '/users/:username';
  }

  return path;
}

module.exports = {
  register,
  initializeMetrics,
  metricsMiddleware,
  httpRequestCounter,
  httpRequestLatency,
  websocketConnections,
  dataIngestCounter,
  peaksDetectedCounter,
  transientsDetectedCounter,
  archiveRecordsCounter,
  archiveDuration,
};
