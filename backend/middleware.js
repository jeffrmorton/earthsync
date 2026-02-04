// server/middleware.js
/**
 * Authentication middleware for Express routes using JWT.
 */
const jwt = require('jsonwebtoken');
const logger = require('./utils/logger'); // Use centralized logger
const { JWT_SECRET } = require('./config/constants'); // Use centralized JWT_SECRET constant

// Validate JWT_SECRET at startup (handled better in server.js or constants.js now)
if (!JWT_SECRET) {
  // Log error and potentially throw to prevent startup if critical
  logger.error('FATAL: JWT_SECRET is not defined. Authentication middleware cannot function.');
  // throw new Error('JWT_SECRET is required for authentication middleware.');
}

/**
 * Express middleware to authenticate requests using a JWT Bearer token.
 * Verifies the token, extracts user information, and attaches it to req.user.
 * Sends appropriate 401 or 403 responses for authentication failures.
 *
 * @param {express.Request} req - Express request object.
 * @param {express.Response} res - Express response object.
 * @param {express.NextFunction} next - Express next middleware function.
 */
const authenticateToken = (req, res, next) => {
  // 1. Get token from Authorization header
  const authHeader = req.headers['authorization'];
  // Check if header exists and follows 'Bearer <token>' format
  const token = authHeader?.startsWith('Bearer ') && authHeader.split(' ')[1];

  // 2. Handle missing token
  if (!token) {
    logger.warn('Authentication failed: No token provided.', { url: req.originalUrl, ip: req.ip });
    // 401 Unauthorized: Authentication credentials required but missing.
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  // 3. Verify the token
  try {
    // Use the secret from constants to verify the token signature and expiration
    const decoded = jwt.verify(token, JWT_SECRET);

    // 4. Validate token payload (ensure necessary user info is present)
    if (!decoded || !decoded.id || !decoded.username) {
      logger.error('Authentication failed: Invalid token payload structure.', {
        payloadKeys: decoded ? Object.keys(decoded) : null,
        url: req.originalUrl,
        ip: req.ip,
      });
      // 403 Forbidden: Token is valid format/signature, but content is unexpected/insufficient.
      return res.status(403).json({ error: 'Invalid token payload.' });
    }

    // 5. Attach user info to the request object
    // Only attach necessary info (id, username) to avoid exposing sensitive data from token
    req.user = {
      id: decoded.id,
      username: decoded.username,
      // Add other roles/permissions here if they exist in the token payload
    };

    logger.debug('JWT authentication successful.', {
      username: req.user.username,
      url: req.originalUrl,
    });

    // 6. Proceed to the next middleware or route handler
    next();
  } catch (err) {
    // 7. Handle specific JWT errors
    if (err instanceof jwt.TokenExpiredError) {
      logger.warn('Authentication failed: Token has expired.', {
        url: req.originalUrl,
        ip: req.ip,
        expiredAt: err.expiredAt,
      });
      // 401 Unauthorized: Credentials expired.
      return res.status(401).json({ error: 'Access denied. Token has expired.' });
    }
    if (err instanceof jwt.JsonWebTokenError) {
      // This catches various signature/format errors
      logger.warn('Authentication failed: Invalid token signature or format.', {
        url: req.originalUrl,
        ip: req.ip,
        error: err.message, // Log the specific JWT error message
      });
      // 403 Forbidden: Token provided but is invalid/malformed.
      return res.status(403).json({ error: 'Access denied. Invalid token.' });
    }

    // 8. Handle unexpected errors during verification
    logger.error('Unexpected error during JWT verification.', {
      url: req.originalUrl,
      ip: req.ip,
      error: err.message,
      stack: err.stack,
    });
    // Pass error to the centralized Express error handler
    next(err);
  }
};

module.exports = {
  authenticateToken,
};
