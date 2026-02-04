// server/utils/auth.js
/**
 * Authentication related utilities, like API key check.
 * Note: JWT authentication middleware remains in middleware.js for now,
 * but could be moved here later if desired.
 */
const { API_INGEST_KEY } = require('../config/constants'); // Use centralized constants
const { dataIngestCounter } = require('./metrics'); // Use centralized metrics instance
const logger = require('./logger'); // Use centralized logger

/**
 * Middleware to authenticate requests using the X-API-Key header,
 * specifically intended for the data ingest endpoint.
 */
function authenticateApiKey(req, res, next) {
  // Check if the API_INGEST_KEY is configured on the server
  if (!API_INGEST_KEY) {
    logger.error('Data ingest failed: API_INGEST_KEY is not configured on the server.');
    // Return 503 Service Unavailable if the key isn't set up, preventing ingest
    return res.status(503).json({ error: 'Data ingest service is not configured or available.' });
  }

  // Retrieve the API key provided by the client from the 'x-api-key' header
  const providedKey = req.headers['x-api-key'];

  // Check if the key was provided
  if (!providedKey) {
    logger.warn('Data ingest failed: Missing X-API-Key header.', { ip: req.ip });
    dataIngestCounter.inc({ status: 'forbidden' }); // Increment metric for forbidden access
    // Return 401 Unauthorized suggests authentication is required but wasn't provided
    return res.status(401).json({ error: 'Unauthorized: API Key required in X-API-Key header.' });
  }

  // Compare the provided key with the configured server key
  if (providedKey !== API_INGEST_KEY) {
    logger.warn('Data ingest failed: Invalid API key provided.', { ip: req.ip });
    dataIngestCounter.inc({ status: 'forbidden' }); // Increment metric for forbidden access
    // Return 403 Forbidden indicates authentication was provided but is invalid/insufficient
    return res.status(403).json({ error: 'Forbidden: Invalid API Key provided.' });
  }

  // API key is valid, proceed to the next middleware or route handler
  logger.debug('API Key authentication successful for data ingest.');
  next();
}

module.exports = {
  authenticateApiKey,
};
