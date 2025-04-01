const { Pool } = require('pg');
const winston = require('winston');
require('dotenv').config();

const logLevel = process.env.LOG_LEVEL || 'info';
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
      new winston.transports.Console({ format: winston.format.simple() }),
      new winston.transports.File({ filename: 'db.log' })
    ]
});

const dbConfig = {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
};

if (!dbConfig.user || !dbConfig.host || !dbConfig.database || !dbConfig.password || !dbConfig.port) {
  logger.error('FATAL: Database configuration missing or incomplete.', { config: { ...dbConfig, password: '***' } });
  process.exit(1);
} else {
    logger.info('Database configuration loaded.', { config: { ...dbConfig, password: '***' } });
}

const pool = new Pool(dbConfig);

pool.on('connect', (client) => { logger.info('DB client connected.', { processID: client.processID }); });
pool.on('acquire', (client) => { logger.debug('DB client acquired.', { processID: client.processID }); });
pool.on('error', (err, client) => { logger.error('Idle DB client error', { error: err.message, stack: err.stack, processID: client?.processID }); });
pool.on('remove', (client) => { logger.info('DB client removed.', { processID: client.processID }); });

async function initializeDatabase() {
  let client;
  try {
    client = await pool.connect();
    logger.info('Initializing database schema...');
    const checkTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users');`;
    const { rows } = await client.query(checkTableQuery);
    if (rows[0].exists) { logger.info('Users table exists.'); }
    else {
      logger.info('Users table not found, creating...');
      await client.query('BEGIN');
      const createTableQuery = `CREATE TABLE users ( id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW() );`;
      await client.query(createTableQuery);
      const createIndexQuery = 'CREATE INDEX idx_users_username ON users(username);';
      await client.query(createIndexQuery);
      await client.query('COMMIT');
      logger.info('Users table/index created.');
    }
  } catch (err) {
    logger.error('DB init failed.', { error: err.message, stack: err.stack });
    if (client) { await client.query('ROLLBACK').catch(rbErr => logger.error('Rollback failed', {e:rbErr.message})); }
    process.exit(1);
  } finally {
    if (client) client.release();
    logger.info('DB schema init check complete.');
  }
}

module.exports = {
  query: async (text, params) => { /* ... unchanged ... */
    const start = Date.now(); try { const res = await pool.query(text, params); const duration = Date.now() - start; logger.debug('DB query executed', { text: text.substring(0, 100), duration_ms: duration, rows: res.rowCount }); return res; } catch (err) { logger.error('DB query error', { text: text.substring(0, 100), params, error: err.message, code: err.code }); throw err; }
  },
  getClient: async () => { /* ... unchanged ... */
      const client = await pool.connect(); logger.debug('Manual DB client checkout', { processID: client.processID }); return client;
  },
  end: async () => { /* ... unchanged ... */
    logger.info('Closing DB pool...'); await pool.end();
  },
  initialize: initializeDatabase
};

module.exports.initialize().catch(err => { logger.error("Failed to initialize database on load.", { error: err.message }); });
