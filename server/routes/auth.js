// server/routes/auth.js
/**
 * Authentication Routes (Register, Login)
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('../db'); // Assuming db.js is in the parent directory
const { validateRequest } = require('../utils/validation'); // Use centralized validation helper
const {
  JWT_SECRET,
  BCRYPT_SALT_ROUNDS,
  ENCRYPTION_KEY_TTL_SECONDS,
} = require('../config/constants'); // Use centralized constants
const logger = require('../utils/logger'); // Use centralized logger

const router = express.Router();

// --- Rate Limiter ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 auth requests (register or login) per window
  message: {
    error: 'Too many authentication attempts from this IP, please try again after 15 minutes.',
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// --- Validation Rules ---
const registerValidationRules = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters long.')
    .matches(/^[a-zA-Z0-9_]+$/) // Corrected regex - no backslash needed
    .withMessage('Username can only contain letters, numbers, and underscores.'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
];

const loginValidationRules = [
  body('username').trim().notEmpty().withMessage('Username is required.'),
  body('password').notEmpty().withMessage('Password is required.'),
];

// --- Routes ---

/**
 * POST /register
 * Registers a new user.
 */
router.post(
  '/register',
  authLimiter,
  registerValidationRules,
  validateRequest,
  async (req, res, next) => {
    const { username, password } = req.body;
    try {
      const checkUser = await db.query('SELECT username FROM users WHERE username = $1', [
        username,
      ]);
      if (checkUser.rows.length > 0) {
        logger.warn('Registration attempt failed: Username already exists', { username });
        return res.status(409).json({ error: 'Username already taken. Please choose another.' });
      }

      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      await db.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
        username,
        hashedPassword,
      ]);
      logger.info('User registered successfully', { username });

      res.status(201).json({ message: 'Registration successful. You can now log in.' });
    } catch (err) {
      logger.error('Registration process failed', { username, error: err.message });
      next(err);
    }
  }
);

/**
 * POST /login
 * Logs in an existing user and returns a JWT.
 */
router.post(
  '/login',
  authLimiter,
  loginValidationRules,
  validateRequest,
  async (req, res, next) => {
    const { username, password } = req.body;
    try {
      const result = await db.query(
        'SELECT id, username, password FROM users WHERE username = $1',
        [username]
      );

      if (result.rows.length === 0) {
        logger.warn('Login attempt failed: User not found', { username });
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        logger.warn('Login attempt failed: Invalid password', { username });
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      const tokenPayload = { id: user.id, username: user.username };
      const token = jwt.sign(tokenPayload, JWT_SECRET, {
        expiresIn: `${ENCRYPTION_KEY_TTL_SECONDS}s`, // Corrected interpolation
      });

      logger.info('User logged in successfully', { username });
      res.json({ token });
    } catch (err) {
      logger.error('Login process failed', { username, error: err.message });
      next(err);
    }
  }
);

module.exports = router;
