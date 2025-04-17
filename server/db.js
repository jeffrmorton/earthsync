// server/db.js
const { Pool } = require('pg');
const winston = require('winston');
require('dotenv').config();

const logLevel = process.env.LOG_LEVEL || 'info';
// Minimal logger setup for db module
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
      new winston.transports.Console({
          format: winston.format.simple(),
          silent: process.env.NODE_ENV === 'test' // Silence console in tests
        }),
      new winston.transports.File({ filename: 'db.log' })
    ]
});

const dbConfig = {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT, 10) || 5432,
  max: 20, // Max connections in pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: process.env.NODE_ENV === 'test' ? 500 : 5000 // Shorter timeout for tests
};

let pool; // Initialize later

function getPool() {
    if (!pool) {
        if (!dbConfig.user || !dbConfig.host || !dbConfig.database || !dbConfig.password || !dbConfig.port) {
          logger.error('FATAL: Database configuration missing or incomplete.', { config: { ...dbConfig, password: '***' } });
          throw new Error('Database configuration missing or incomplete.');
        } else {
            logger.info('Database configuration loaded, creating pool.', { config: { ...dbConfig, password: '***' } });
            pool = new Pool(dbConfig);

            pool.on('connect', (client) => { logger.info('DB client connected.', { processID: client.processID }); });
            pool.on('acquire', (client) => { logger.debug('DB client acquired.', { processID: client.processID }); });
            pool.on('error', (err, client) => { logger.error('Idle DB client error', { error: err.message, stack: err.stack, processID: client?.processID }); });
            pool.on('remove', (client) => { logger.info('DB client removed.', { processID: client.processID }); });
        }
    }
    return pool;
}


async function initializeDatabase() {
  const currentPool = getPool();
  let client;
  logger.info('Attempting database connection and schema initialization...');
  try {
    client = await currentPool.connect();
    logger.info('Database connection successful. Checking schema...');

    // Transaction for schema checks/creations
    await client.query('BEGIN');

    // Check/Create Users Table
    const checkUsersTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users');`;
    let { rows } = await client.query(checkUsersTableQuery);
    if (rows[0].exists) { logger.info('Users table exists.'); }
    else {
      logger.info('Users table not found, creating...');
      const createTableQuery = `CREATE TABLE users ( id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW() );`;
      await client.query(createTableQuery);
      const createIndexQuery = 'CREATE INDEX idx_users_username ON users(username);';
      await client.query(createIndexQuery);
      logger.info('Users table/index created.');
    }

    // --- Phase 3b: Check/Create Historical Spectrograms Table ---
    const specTableName = 'historical_spectrograms';
    const checkSpecTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '${specTableName}');`;
    ({ rows } = await client.query(checkSpecTableQuery));
    if (rows[0].exists) {
        logger.info(`${specTableName} table exists.`);
        // Phase 4d: Check if the transient_details column exists, add if not
        const checkColumnQuery = `
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = '${specTableName}'
              AND column_name = 'transient_details';
        `;
        const colRes = await client.query(checkColumnQuery);
        if (colRes.rowCount === 0) {
            logger.info(`Column 'transient_details' not found in ${specTableName}, adding...`);
            await client.query(`ALTER TABLE ${specTableName} ADD COLUMN transient_details TEXT NULL;`);
            logger.info(`Column 'transient_details' added.`);
        } else {
            logger.info(`Column 'transient_details' exists in ${specTableName}.`);
        }
    }
    else {
        logger.info(`${specTableName} table not found, creating...`);
        const createSpecTableQuery = `
            CREATE TABLE ${specTableName} (
                id BIGSERIAL PRIMARY KEY,
                detector_id VARCHAR(50) NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                location_lat DOUBLE PRECISION NOT NULL,
                location_lon DOUBLE PRECISION NOT NULL,
                spectrogram_data JSONB NOT NULL,
                transient_detected BOOLEAN DEFAULT FALSE,
                transient_details TEXT NULL, -- Phase 4d: Add details column
                archived_at TIMESTAMPTZ DEFAULT NOW()
            );
        `;
        await client.query(createSpecTableQuery);
        const createSpecIndexQuery = `CREATE INDEX idx_hist_spec_detector_time ON ${specTableName}(detector_id, timestamp);`;
        await client.query(createSpecIndexQuery);
        logger.info(`${specTableName} table and index created.`);
    }

    // --- Phase 3b: Check/Create Historical Peaks Table ---
    const peaksTableName = 'historical_peaks';
    const checkPeaksTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '${peaksTableName}');`;
    ({ rows } = await client.query(checkPeaksTableQuery));
     if (rows[0].exists) { logger.info(`${peaksTableName} table exists.`); }
     else {
         logger.info(`${peaksTableName} table not found, creating...`);
         const createPeaksTableQuery = `
            CREATE TABLE ${peaksTableName} (
                id BIGSERIAL PRIMARY KEY,
                detector_id VARCHAR(50) NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                peak_data JSONB NOT NULL,
                archived_at TIMESTAMPTZ DEFAULT NOW()
            );
         `;
         await client.query(createPeaksTableQuery);
         const createPeaksIndexQuery = `CREATE INDEX idx_hist_peaks_detector_time ON ${peaksTableName}(detector_id, timestamp);`;
         await client.query(createPeaksIndexQuery);
         logger.info(`${peaksTableName} table and index created.`);
     }

    // Commit transaction if all checks/creations succeeded
    await client.query('COMMIT');
    logger.info('DB schema initialization check complete.');

  } catch (err) {
    logger.error('DB initialization failed.', { error: err.message, stack: err.stack });
    if (client) {
      await client.query('ROLLBACK').catch(rbErr => logger.error('Rollback failed during init error handling', {e:rbErr.message}));
    }
    throw err;
  } finally {
    if (client) client.release();
  }
}

// --- Phase 3b/4d: Function to insert historical spectrogram data ---
/**
 * Inserts a batch of historical spectrogram records into the database.
 * Now includes transient_details.
 * @param {Array<Object>} records - Array of objects, each matching the historical_spectrograms schema structure.
 *                                  Example: { detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details }
 * @returns {Promise<number>} The number of rows inserted.
 */
async function insertHistoricalSpectrograms(records) {
    if (!records || records.length === 0) {
        return 0;
    }
    const currentPool = getPool();
    const client = await currentPool.connect();
    let insertedRows = 0;
    try {
        await client.query('BEGIN');
        // Phase 4d: Include transient_details in the INSERT statement
        const queryText = `
            INSERT INTO historical_spectrograms
            (detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        for (const record of records) {
            const timestamp = typeof record.timestamp === 'string' ? new Date(record.timestamp) : record.timestamp;
            const values = [
                record.detector_id,
                timestamp,
                record.location_lat,
                record.location_lon,
                JSON.stringify(record.spectrogram_data),
                record.transient_detected || false,
                record.transient_details || null // Phase 4d: Add details (or null)
            ];
            const res = await client.query(queryText, values);
            insertedRows += res.rowCount;
        }
        await client.query('COMMIT');
        logger.info(`Successfully inserted ${insertedRows} historical spectrogram records.`);
        return insertedRows;
    } catch (err) {
        logger.error('Error inserting historical spectrograms batch', { error: err.message, recordCount: records.length });
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

// --- Phase 3b: Function to insert historical peak data ---
/**
 * Inserts a batch of historical peak records into the database.
 * @param {Array<Object>} records - Array of objects, each matching the historical_peaks schema structure.
 *                                  Example: { detector_id, timestamp, peak_data }
 * @returns {Promise<number>} The number of rows inserted.
 */
async function insertHistoricalPeaks(records) {
     if (!records || records.length === 0) {
         return 0;
     }
     const currentPool = getPool();
     const client = await currentPool.connect();
     let insertedRows = 0;
     try {
         await client.query('BEGIN');
         const queryText = `
             INSERT INTO historical_peaks
             (detector_id, timestamp, peak_data)
             VALUES ($1, $2, $3)
         `;
         for (const record of records) {
             const timestamp = typeof record.timestamp === 'string' ? new Date(record.timestamp) : record.timestamp;
             const values = [
                 record.detector_id,
                 timestamp,
                 JSON.stringify(record.peak_data)
             ];
             const res = await client.query(queryText, values);
             insertedRows += res.rowCount;
         }
         await client.query('COMMIT');
         logger.info(`Successfully inserted ${insertedRows} historical peak records.`);
         return insertedRows;
     } catch (err) {
         logger.error('Error inserting historical peaks batch', { error: err.message, recordCount: records.length });
         await client.query('ROLLBACK');
         throw err;
     } finally {
         client.release();
     }
}


module.exports = {
  query: async (text, params) => {
    const currentPool = getPool();
    const start = Date.now();
    try {
        const res = await currentPool.query(text, params);
        const duration = Date.now() - start;
        logger.debug('DB query executed', { text: text.substring(0, 100), duration_ms: duration, rows: res.rowCount });
        return res;
    } catch (err) {
        logger.error('DB query error', { text: text.substring(0, 100), params, error: err.message, code: err.code });
        throw err;
    }
  },
  getClient: async () => {
      const currentPool = getPool();
      const client = await currentPool.connect();
      logger.debug('Manual DB client checkout', { processID: client.processID });
      return client;
  },
  end: async () => {
    if (pool) {
        logger.info('Closing DB pool...');
        await pool.end();
        pool = null;
    } else {
         logger.info('DB pool already closed or not initialized.');
    }
  },
  initialize: initializeDatabase,
  insertHistoricalSpectrograms,
  insertHistoricalPeaks,
};
