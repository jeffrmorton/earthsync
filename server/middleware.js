const jwt = require('jsonwebtoken');
const winston = require('winston');

const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'server.log' })
  ]
});

require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  logger.error('JWT_SECRET missing');
  process.exit(1);
}

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  try {
    req.user = await jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    logger.error('Token verification failed', { error: err.message });
    res.status(403).json({ error: 'Invalid token' });
  }
};

module.exports = { authenticateToken };
