const { Pool } = require('pg');
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

const dbConfig = {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
};

logger.info('Database configuration', { dbConfig });

if (!dbConfig.user || !dbConfig.host || !dbConfig.database || !dbConfig.password || !dbConfig.port) {
  logger.error('Database configuration missing', { dbConfig });
  process.exit(1);
}

const pool = new Pool(dbConfig);

async function initializeDatabase() {
  try {
    const result = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'users'
      )
    `);
    if (result.rows[0].exists) {
      logger.info('Users table exists, skipping initialization');
      return;
    }

    await pool.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    await pool.query('CREATE INDEX idx_users_username ON users(username)');
    logger.info('Users table and index created');
  } catch (err) {
    logger.error('Database initialization failed', { error: err.message });
    process.exit(1);
  }
}

pool.connect((err) => {
  if (err) {
    logger.error('Database connection failed', { error: err.message });
    process.exit(1);
  }
  logger.info('Connected to PostgreSQL');
  initializeDatabase();
});

module.exports = { query: (text, params) => pool.query(text, params), end: () => pool.end() };
