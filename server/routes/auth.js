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
// Apply rate limiting specifically to authentication attempts
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
    // Simple pattern: letters, numbers, underscores only
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores.'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
  // Optional: Add complexity requirements if needed
  // .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/)
  // .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
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
  authLimiter, // Apply rate limiting
  registerValidationRules, // Apply validation rules
  validateRequest, // Handle validation results
  async (req, res, next) => {
    // Route handler
    const { username, password } = req.body;
    try {
      // 1. Check if username already exists
      const checkUser = await db.query('SELECT username FROM users WHERE username = $1', [
        username,
      ]);
      if (checkUser.rows.length > 0) {
        logger.warn('Registration attempt failed: Username already exists', { username });
        // Return 409 Conflict status code
        return res.status(409).json({ error: 'Username already taken. Please choose another.' });
      }

      // 2. Hash the password
      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      // 3. Insert the new user into the database
      await db.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
        username,
        hashedPassword,
      ]);
      logger.info('User registered successfully', { username });

      // 4. Send success response
      res.status(201).json({ message: 'Registration successful. You can now log in.' });
    } catch (err) {
      logger.error('Registration process failed', { username, error: err.message });
      // Pass the error to the centralized error handling middleware
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
  authLimiter, // Apply rate limiting
  loginValidationRules, // Apply validation rules
  validateRequest, // Handle validation results
  async (req, res, next) => {
    // Route handler
    const { username, password } = req.body;
    try {
      // 1. Find the user by username
      const result = await db.query(
        'SELECT id, username, password FROM users WHERE username = $1',
        [username]
      );

      // Check if user exists
      if (result.rows.length === 0) {
        logger.warn('Login attempt failed: User not found', { username });
        // Return 401 Unauthorized for invalid username or password
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      const user = result.rows[0];

      // 2. Compare the provided password with the stored hash
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        logger.warn('Login attempt failed: Invalid password', { username });
        // Return 401 Unauthorized for invalid username or password
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      // 3. Generate JWT token upon successful login
      const tokenPayload = { id: user.id, username: user.username };
      const token = jwt.sign(tokenPayload, JWT_SECRET, {
        expiresIn: `${ENCRYPTION_KEY_TTL_SECONDS}s`, // Use constant for expiration time
      });

      logger.info('User logged in successfully', { username });

      // 4. Send the JWT token in the response
      res.json({ token });
    } catch (err) {
      logger.error('Login process failed', { username, error: err.message });
      // Pass the error to the centralized error handling middleware
      next(err);
    }
  }
);

module.exports = router; // Export the router instance
