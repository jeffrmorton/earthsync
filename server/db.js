// server/db.js
/**
 * Database interaction module for PostgreSQL.
 * Handles connection pooling, schema initialization, and data access,
 * including peak tracking state persistence.
 * v1.1.28 - Linter Fixes (no-process-exit).
 */
const { Pool } = require('pg');
const { DB_USER, DB_HOST, DB_NAME, DB_PASSWORD, DB_PORT, NODE_ENV } = require('./config/constants'); // Use centralized constants
const logger = require('./utils/logger'); // Use centralized logger

// --- DB Configuration ---
const dbConfig = {
  user: DB_USER,
  host: DB_HOST,
  database: DB_NAME,
  password: DB_PASSWORD,
  port: DB_PORT,
  max: 20, // Max connections in pool
  idleTimeoutMillis: 30000, // Keeps connections active for 30s
  // Use different connection timeouts for test vs other environments
  connectionTimeoutMillis: NODE_ENV === 'test' ? 5000 : 10000, // Increased slightly
};

// --- Initialize Pool ---
let pool = null; // Initialize pool variable

function initializePool() {
  // Prevent re-initialization
  if (pool) {
    logger.warn('Database pool already initialized.');
    return pool;
  }

  // Validate essential configuration
  if (
    !dbConfig.user ||
    !dbConfig.host ||
    !dbConfig.database ||
    !dbConfig.password ||
    !dbConfig.port
  ) {
    const safeConfig = { ...dbConfig, password: '***' }; // Mask password for logging
    logger.error('FATAL: Database configuration missing or incomplete.', { config: safeConfig });
    // Throw error instead of process.exit()
    throw new Error('Database configuration missing or incomplete. Check environment variables.');
  }

  const safeConfigForLog = { ...dbConfig, password: '***' };
  logger.info('Database configuration loaded, creating connection pool...', {
    config: safeConfigForLog,
  });
  pool = new Pool(dbConfig);

  // --- Pool Event Listeners ---
  pool.on('connect', (client) => {
    // Note: client.processID might not always be available depending on server/client versions
    logger.info('Database client connected.', { processID: client?.processID });
  });

  pool.on('acquire', (client) => {
    logger.debug('Database client acquired from pool.', { processID: client?.processID });
  });

  pool.on('error', (err, client) => {
    // This handles errors for idle clients in the pool
    logger.error('Idle database client error', {
      error: err.message,
      stack: err.stack,
      processID: client?.processID,
    });
  });

  pool.on('remove', (client) => {
    logger.info('Database client removed from pool.', { processID: client?.processID });
  });

  logger.info('Database pool created and event listeners attached.');
  return pool;
}

// Initialize the pool when the module loads
try {
  initializePool();
} catch (err) {
  // Log the fatal error and re-throw it so the main server startup fails
  logger.error(`FATAL DB Pool Initialization Error: ${err.message}`);
  throw err; // Re-throw error
}

/**
 * Gets the initialized pool instance. Throws if not initialized.
 * @returns {pg.Pool} The PostgreSQL connection pool.
 */
function getPool() {
  if (!pool) {
    // This state should ideally not be reached due to immediate initialization,
    // but serves as a safeguard during development or unexpected scenarios.
    logger.error('FATAL: Attempted to get DB Pool before it was initialized!');
    throw new Error('Database Pool not initialized. Server cannot operate.');
  }
  return pool;
}

// --- Schema Initialization Function ---
async function initializeDatabase() {
  const currentPool = getPool(); // Throws if pool is null
  let client = null; // Define client outside try block for finally scope
  logger.info('Attempting database connection and schema initialization...');

  try {
    client = await currentPool.connect(); // Acquire a client from the pool
    logger.info('Database connection successful. Checking schema...');

    // Use a transaction for schema modifications
    await client.query('BEGIN');

    // --- Users Table ---
    const usersTableName = 'users';
    const checkUsersTableQuery = `SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1);`;
    let res = await client.query(checkUsersTableQuery, [usersTableName]);
    if (!res.rows[0].exists) {
      logger.info(`Table '${usersTableName}' not found, creating...`);
      const createTableQuery = `
                CREATE TABLE ${usersTableName} (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );`;
      await client.query(createTableQuery);
      // Add index on username for faster lookups during login
      const createIndexQuery = `CREATE INDEX idx_${usersTableName}_username ON ${usersTableName}(username);`;
      await client.query(createIndexQuery);
      logger.info(`Table '${usersTableName}' and index created.`);
    } else {
      logger.info(`Table '${usersTableName}' already exists.`);
    }

    // --- Historical Spectrograms Table ---
    const specTableName = 'historical_spectrograms';
    const checkSpecTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1);`;
    res = await client.query(checkSpecTableQuery, [specTableName]);
    if (!res.rows[0].exists) {
      logger.info(`Table '${specTableName}' not found, creating...`);
      // Ensure column types match expected data (JSONB for flexible data, TIMESTAMPTZ for time)
      const createSpecTableQuery = `
                CREATE TABLE ${specTableName} (
                    id BIGSERIAL PRIMARY KEY,
                    detector_id VARCHAR(50) NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    location_lat DOUBLE PRECISION,
                    location_lon DOUBLE PRECISION,
                    spectrogram_data JSONB NOT NULL, -- Store downsampled spectrum array
                    transient_detected BOOLEAN DEFAULT FALSE,
                    transient_details TEXT NULL,
                    archived_at TIMESTAMPTZ DEFAULT NOW()
                );`;
      await client.query(createSpecTableQuery);
      // Index for efficient querying by detector and time range
      const createSpecIndexQuery = `CREATE INDEX idx_${specTableName}_detector_time ON ${specTableName}(detector_id, timestamp);`;
      await client.query(createSpecIndexQuery);
      // Optional: Add index just on timestamp if range queries across all detectors are common
      // await client.query(`CREATE INDEX idx_${specTableName}_timestamp ON ${specTableName}(timestamp);`);
      logger.info(`Table '${specTableName}' and index created.`);
    } else {
      logger.info(`Table '${specTableName}' already exists.`);
      // Example: Check and add a missing column if schema evolved (idempotent check)
      const checkColumnQuery = `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2;`;
      const colRes = await client.query(checkColumnQuery, [specTableName, 'transient_details']);
      if (colRes.rowCount === 0) {
        logger.info(`Column 'transient_details' not found in ${specTableName}, adding...`);
        await client.query(`ALTER TABLE ${specTableName} ADD COLUMN transient_details TEXT NULL;`);
        logger.info(`Column 'transient_details' added to ${specTableName}.`);
      } // else { logger.debug(`Column 'transient_details' exists in ${specTableName}.`); }
    }

    // --- Historical Peaks Table ---
    const peaksTableName = 'historical_peaks';
    const checkPeaksTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1);`;
    res = await client.query(checkPeaksTableQuery, [peaksTableName]);
    if (!res.rows[0].exists) {
      logger.info(`Table '${peaksTableName}' not found, creating...`);
      // Store peak data as JSONB array
      const createPeaksTableQuery = `
              CREATE TABLE ${peaksTableName} (
                  id BIGSERIAL PRIMARY KEY,
                  detector_id VARCHAR(50) NOT NULL,
                  "timestamp" TIMESTAMPTZ NOT NULL, -- Use quotes for reserved keyword 'timestamp'
                  peak_data JSONB NOT NULL, -- Array of peak objects {freq, amp, qFactor, trackStatus, trackId}
                  archived_at TIMESTAMPTZ DEFAULT NOW()
              );`;
      await client.query(createPeaksTableQuery);
      // Index for efficient querying
      const createPeaksIndexQuery = `CREATE INDEX idx_${peaksTableName}_detector_time ON ${peaksTableName}(detector_id, "timestamp");`;
      await client.query(createPeaksIndexQuery);
      logger.info(`Table '${peaksTableName}' and index created.`);
    } else {
      logger.info(`Table '${peaksTableName}' already exists.`);
    }

    // --- Peak Tracking State Table ---
    const trackStateTableName = 'peak_tracking_state';
    const checkTrackStateTableQuery = `SELECT EXISTS ( SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1);`;
    res = await client.query(checkTrackStateTableQuery, [trackStateTableName]);
    if (!res.rows[0].exists) {
      logger.info(`Table '${trackStateTableName}' not found, creating...`);
      // Stores the *last known state* for each detector's tracked peaks
      const createTrackStateTableQuery = `
              CREATE TABLE ${trackStateTableName} (
                  detector_id VARCHAR(50) PRIMARY KEY, -- Unique constraint on detector ID
                  last_update TIMESTAMPTZ NOT NULL,   -- Timestamp of the last update
                  state_data JSONB NOT NULL          -- Array of state objects {id, freq, amp, lastTs}
              );`;
      await client.query(createTrackStateTableQuery);
      logger.info(`Table '${trackStateTableName}' created.`);
    } else {
      logger.info(`Table '${trackStateTableName}' already exists.`);
    }

    // Commit the transaction if all checks/creations were successful
    await client.query('COMMIT');
    logger.info('Database schema initialization check complete.');
  } catch (err) {
    logger.error('Database initialization failed during transaction.', {
      error: err.message,
      stack: err.stack,
    });
    // Rollback the transaction if an error occurred
    if (client) {
      await client
        .query('ROLLBACK')
        .catch((rbErr) =>
          logger.error('Rollback failed during init error handling', { error: rbErr.message })
        );
    }
    throw err; // Re-throw error so server startup knows initialization failed
  } finally {
    // Ensure the client is always released back to the pool
    if (client) {
      client.release();
      logger.debug('Database client released after schema initialization.');
    }
  }
}

// --- Historical Data Insertion ---
/**
 * Inserts multiple historical spectrogram records into the database.
 * Assumes records are pre-formatted correctly.
 * @param {Array<object>} records - Array of record objects to insert.
 * @returns {Promise<number>} The number of rows inserted.
 */
async function insertHistoricalSpectrograms(records) {
  if (!records || records.length === 0) return 0;
  const currentPool = getPool();
  let client = null;
  let insertedCount = 0;
  // Use smaller batches for insertion to avoid overly large queries
  const batchSize = 100;
  logger.debug(
    `Attempting to insert ${records.length} spectrogram records in batches of ${batchSize}.`
  );

  try {
    client = await currentPool.connect();
    await client.query('BEGIN'); // Start transaction

    for (let i = 0; i < records.length; i += batchSize) {
      const batch = records.slice(i, i + batchSize);
      const values = [];
      const queryParams = [];
      let paramIndex = 1;

      batch.forEach((record) => {
        // Ensure all required fields are present before pushing
        if (record.detector_id && record.timestamp && record.spectrogram_data) {
          values.push(
            `($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`
          );
          queryParams.push(
            record.detector_id,
            record.timestamp, // Should be ISO string or Date object
            record.location_lat ?? null, // Use nullish coalescing for optional fields
            record.location_lon ?? null,
            JSON.stringify(record.spectrogram_data), // Stringify JSONB data
            record.transient_detected ?? false, // Default to false
            record.transient_details ?? null // Default to null
          );
        } else {
          logger.warn('Skipping invalid record during spectrogram batch insertion prep', {
            record,
          });
        }
      });

      // Only execute query if there are valid records in the batch
      if (values.length > 0) {
        const queryText = `
                  INSERT INTO historical_spectrograms
                  (detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details)
                  VALUES ${values.join(', ')}
                  ON CONFLICT DO NOTHING; -- Avoid errors on duplicate entries if primary key conflicts
              `;
        const res = await client.query(queryText, queryParams);
        insertedCount += res.rowCount;
      } else {
        logger.debug(`Skipping empty batch insertion at index ${i}.`);
      }
    }

    await client.query('COMMIT'); // Commit transaction
    logger.debug(`Successfully inserted ${insertedCount} / ${records.length} spectrogram records.`);
    return insertedCount;
  } catch (err) {
    logger.error('Error inserting historical spectrograms', {
      error: err.message,
      recordCount: records.length,
    });
    if (client) {
      await client
        .query('ROLLBACK')
        .catch((rbErr) =>
          logger.error('Rollback failed after spec insert error', { error: rbErr.message })
        );
    }
    // Decide whether to throw or return 0? Returning 0 for now.
    return 0;
  } finally {
    if (client) client.release();
  }
}

/**
 * Inserts multiple historical peak records into the database.
 * Assumes records are pre-formatted correctly.
 * @param {Array<object>} records - Array of record objects to insert.
 * @returns {Promise<number>} The number of rows inserted.
 */
async function insertHistoricalPeaks(records) {
  if (!records || records.length === 0) return 0;
  const currentPool = getPool();
  let client = null;
  let insertedCount = 0;
  const batchSize = 100; // Adjust batch size as needed
  logger.debug(`Attempting to insert ${records.length} peak records in batches of ${batchSize}.`);

  try {
    client = await currentPool.connect();
    await client.query('BEGIN');

    for (let i = 0; i < records.length; i += batchSize) {
      const batch = records.slice(i, i + batchSize);
      const values = [];
      const queryParams = [];
      let paramIndex = 1;

      batch.forEach((record) => {
        // Ensure required fields are present
        if (record.detector_id && record.timestamp && record.peak_data) {
          values.push(`($${paramIndex++}, $${paramIndex++}, $${paramIndex++})`);
          queryParams.push(
            record.detector_id,
            record.timestamp, // Should be ISO string or Date object
            JSON.stringify(record.peak_data) // Stringify JSONB data
          );
        } else {
          logger.warn('Skipping invalid record during peak batch insertion prep', { record });
        }
      });

      // Only execute if there are valid records
      if (values.length > 0) {
        // Use quotes around "timestamp" as it's a reserved keyword
        const queryText = `
                  INSERT INTO historical_peaks (detector_id, "timestamp", peak_data)
                  VALUES ${values.join(', ')}
                  ON CONFLICT DO NOTHING;
              `;
        const res = await client.query(queryText, queryParams);
        insertedCount += res.rowCount;
      } else {
        logger.debug(`Skipping empty batch insertion at index ${i}.`);
      }
    }

    await client.query('COMMIT');
    logger.debug(`Successfully inserted ${insertedCount} / ${records.length} peak records.`);
    return insertedCount;
  } catch (err) {
    logger.error('Error inserting historical peaks', {
      error: err.message,
      recordCount: records.length,
    });
    if (client) {
      await client
        .query('ROLLBACK')
        .catch((rbErr) =>
          logger.error('Rollback failed after peak insert error', { error: rbErr.message })
        );
    }
    return 0;
  } finally {
    if (client) client.release();
  }
}

// --- Peak Tracking State Functions ---
/**
 * Retrieves the last saved peak tracking state for a detector.
 * @param {string} detectorId - The detector ID.
 * @returns {Promise<Array|null>} The state data array or null if not found/error.
 */
async function getPeakTrackingState(detectorId) {
  const currentPool = getPool();
  const queryText = `SELECT state_data, last_update FROM peak_tracking_state WHERE detector_id = $1`;
  try {
    const res = await currentPool.query(queryText, [detectorId]);
    if (res.rows.length > 0) {
      logger.debug(`Retrieved peak tracking state for ${detectorId}`, {
        last_update: res.rows[0].last_update,
      });
      // Ensure state_data is parsed correctly, default to empty array if null/invalid
      // Check if it's already an object/array (pg might parse JSONB automatically)
      if (typeof res.rows[0].state_data === 'object' && res.rows[0].state_data !== null) {
        return Array.isArray(res.rows[0].state_data) ? res.rows[0].state_data : [];
      }
      // If it's a string, try parsing
      if (typeof res.rows[0].state_data === 'string') {
        try {
          const parsed = JSON.parse(res.rows[0].state_data);
          return Array.isArray(parsed) ? parsed : [];
        } catch (e) {
          logger.error(`Failed to parse state_data JSON from DB for ${detectorId}`, {
            error: e.message,
          });
          return []; // Return empty on parse failure
        }
      }
      return []; // Default to empty array if type is unexpected
    }
    logger.debug(`No peak tracking state found in DB for ${detectorId}`);
    return null; // Return null if no state exists for this detector
  } catch (err) {
    logger.error('Error getting peak tracking state from DB', { detectorId, error: err.message });
    return null; // Return null on error to allow processing to continue (treat as new)
  }
}

/**
 * Saves or updates the peak tracking state for a detector.
 * @param {string} detectorId - The detector ID.
 * @param {Array} stateData - The peak state data array to save.
 * @returns {Promise<boolean>} True on success, false on failure.
 */
async function savePeakTrackingState(detectorId, stateData) {
  const currentPool = getPool();
  // Use INSERT ... ON CONFLICT ... DO UPDATE for atomicity (upsert)
  const queryText = `
      INSERT INTO peak_tracking_state (detector_id, last_update, state_data)
      VALUES ($1, NOW(), $2)
      ON CONFLICT (detector_id)
      DO UPDATE SET last_update = EXCLUDED.last_update, state_data = EXCLUDED.state_data;
  `;
  try {
    // Ensure stateData is an array, default to empty array if not
    const validStateData = Array.isArray(stateData) ? stateData : [];
    const stateJson = JSON.stringify(validStateData); // Stringify the validated array
    await currentPool.query(queryText, [detectorId, stateJson]);
    logger.debug(`Saved peak tracking state to DB for ${detectorId}`, {
      peakCount: validStateData.length,
    });
    return true;
  } catch (err) {
    logger.error('Error saving peak tracking state to DB', { detectorId, error: err.message });
    return false;
  }
}

/**
 * Deletes the peak tracking state for a detector.
 * @param {string} detectorId - The detector ID.
 * @returns {Promise<boolean>} True on success or if state didn't exist, false on failure.
 */
async function deletePeakTrackingState(detectorId) {
  const currentPool = getPool();
  const queryText = `DELETE FROM peak_tracking_state WHERE detector_id = $1`;
  try {
    const res = await currentPool.query(queryText, [detectorId]);
    logger.debug(`Deleted peak tracking state from DB for ${detectorId}`, {
      deleted: res.rowCount > 0,
    });
    return true; // Return true even if row didn't exist (goal achieved)
  } catch (err) {
    logger.error('Error deleting peak tracking state from DB', { detectorId, error: err.message });
    return false;
  }
}

// --- Standard Query/Client Functions (Simplified) ---
module.exports = {
  // Execute a single query using the pool
  query: async (text, params) => {
    const currentPool = getPool(); // Ensures pool is initialized
    const start = Date.now();
    try {
      const res = await currentPool.query(text, params);
      const duration = Date.now() - start;
      // Avoid logging sensitive params by default
      logger.debug('DB query executed', {
        text: text.substring(0, 150).replace(/\s+/g, ' ') + (text.length > 150 ? '...' : ''), // Log truncated query
        duration_ms: duration,
        rows: res.rowCount,
      });
      return res;
    } catch (err) {
      logger.error('DB query error', {
        text: text.substring(0, 150).replace(/\s+/g, ' ') + (text.length > 150 ? '...' : ''), // Log truncated query
        params: Array.isArray(params) ? `[${params.length} params]` : params, // Log only param count
        error: err.message,
        code: err.code, // PostgreSQL error code can be useful
      });
      throw err; // Re-throw the error for upstream handling
    }
  },
  // Get a client for manual transaction management
  getClient: async () => {
    const currentPool = getPool();
    const client = await currentPool.connect();
    logger.debug('Manual DB client checkout requested.', { processID: client?.processID });
    // Note: Caller is responsible for client.release()
    return client;
  },
  // End the pool (used during shutdown)
  end: async () => {
    if (pool) {
      logger.info('Closing DB connection pool...');
      await pool.end();
      pool = null; // Ensure pool is nullified after ending
      logger.info('DB connection pool closed.');
    } else {
      logger.warn('Attempted to end DB pool, but it was not initialized or already closed.');
    }
  },
  // Export core functions
  initialize: initializeDatabase,
  insertHistoricalSpectrograms,
  insertHistoricalPeaks,
  getPeakTrackingState,
  savePeakTrackingState,
  deletePeakTrackingState,
};
