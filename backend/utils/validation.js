// server/utils/validation.js
/**
 * Request validation helper middleware using express-validator.
 */
const { validationResult } = require('express-validator');
const logger = require('./logger'); // Use centralized logger

/**
 * Middleware to handle validation results from express-validator chains.
 * Extracts errors and sends a standardized 400 Bad Request response if any exist.
 * Logs the validation failure.
 */
function validateRequest(req, res, next) {
  // Get validation errors from the request object
  const errors = validationResult(req);

  // Check if there are any validation errors
  if (!errors.isEmpty()) {
    // Log the validation failure, including the first error message for context
    logger.warn('Input validation failed', {
      error: errors.array()[0].msg, // Log the message of the first validation error
      path: req.originalUrl, // Log the requested path
      method: req.method, // Log the HTTP method
      ip: req.ip, // Log the client IP address
      // errors: errors.array()    // Optionally log the full array of errors for detailed debugging
    });

    // Send a 400 Bad Request response to the client
    // Include only the message of the *first* validation error for simplicity
    return res.status(400).json({ error: errors.array()[0].msg });
  }

  // No validation errors found, proceed to the next middleware or route handler
  next();
}

module.exports = {
  validateRequest,
};
