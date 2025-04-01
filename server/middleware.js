const jwt = require('jsonwebtoken');
const winston = require('winston');
require('dotenv').config();

const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({ level: logLevel, format: winston.format.combine(winston.format.timestamp(), winston.format.json()), transports: [new winston.transports.Console({ format: winston.format.simple() })] });
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { logger.error('FATAL: JWT_SECRET is not defined for middleware.'); }

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']; const token = authHeader?.startsWith('Bearer ') && authHeader.split(' ')[1];
  if (!token) { logger.warn('Auth failed: No token', { url: req.originalUrl }); return res.status(401).json({ error: 'Access denied. No token provided.' }); }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.id || !decoded.username) { logger.error('Auth failed: Invalid token payload', { payload: decoded }); return res.status(403).json({ error: 'Invalid token payload.' }); }
    req.user = decoded; logger.debug('Auth successful', { username: req.user.username, url: req.originalUrl }); next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) { logger.warn('Auth failed: Token expired', { url: req.originalUrl, e: err.message }); return res.status(401).json({ error: 'Access denied. Token has expired.' }); }
    if (err instanceof jwt.JsonWebTokenError) { logger.warn('Auth failed: Invalid token', { url: req.originalUrl, e: err.message }); return res.status(403).json({ error: 'Access denied. Invalid token.' }); }
    logger.error('Auth error: Unexpected', { url: req.originalUrl, error: err.message }); next(err);
  }
};
module.exports = { authenticateToken };
