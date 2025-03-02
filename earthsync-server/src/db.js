const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.on('connect', () => console.log('Connected to PostgreSQL'));

const initDb = async () => {
  try {
    console.log('Initializing database schema...');

    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );
    `);
    console.log('Users table created or already exists');

    // Create frequency_history table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS frequency_history (
        id SERIAL PRIMARY KEY,
        frequency REAL NOT NULL,
        timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Frequency_history table created or already exists');

    // Create usage_logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usage_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        start_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        duration INTEGER,
        preset_mode VARCHAR(50)
      );
    `);
    console.log('Usage_logs table created or already exists');

    // Create api_keys table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        api_key VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('Api_keys table created or already exists');

    // Insert test user
    const hashedPassword = await bcrypt.hash('password123', 10);
    await pool.query(`
      INSERT INTO users (username, password) 
      VALUES ($1, $2) 
      ON CONFLICT (username) DO NOTHING
    `, ['test', hashedPassword]);
    console.log('Test user inserted or already exists');

    console.log('Database schema initialized successfully');
  } catch (err) {
    console.error('Failed to initialize database schema:', err.stack);
    throw err; // Propagate error to halt execution
  }
};

// Run initDb and exit process on failure
initDb().catch(err => {
  console.error('initDb failed:', err.stack);
  process.exit(1);
});

// Define database functions
const registerUser = async (username, password) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  return pool.query(`INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id`, [username, hashedPassword]);
};

const loginUser = async (username, password) => {
  const { rows } = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
  if (!rows[0]) throw new Error('User not found');
  const match = await bcrypt.compare(password, rows[0].password);
  if (!match) throw new Error('Invalid password');
  return rows[0];
};

const saveFrequency = async (frequency) => {
  await pool.query(`INSERT INTO frequency_history (frequency) VALUES ($1)`, [frequency]);
};

const getRecentFrequencies = async (limit = 60) => {
  const { rows } = await pool.query(`SELECT frequency, timestamp FROM frequency_history ORDER BY timestamp DESC LIMIT $1`, [limit]);
  return rows;
};

const getHistoricalFrequencies = async (hours) => {
  const { rows } = await pool.query(
    `SELECT frequency, timestamp FROM frequency_history WHERE timestamp > NOW() - $1::interval ORDER BY timestamp ASC`,
    [`${hours} hours`]
  );
  return rows;
};

const logUsage = async (userId, duration, presetMode) => {
  await pool.query(`INSERT INTO usage_logs (user_id, duration, preset_mode) VALUES ($1, $2, $3)`, [userId, duration, presetMode]);
};

const getUserStats = async (userId) => {
  const { rows } = await pool.query(`SELECT SUM(duration) as total_seconds, COUNT(*) as sessions FROM usage_logs WHERE user_id = $1`, [userId]);
  return rows[0];
};

const getUsageTrends = async (userId) => {
  const { rows } = await pool.query(`SELECT DATE(start_time) as date, SUM(duration) as total FROM usage_logs WHERE user_id = $1 GROUP BY DATE(start_time) ORDER BY date`, [userId]);
  return rows;
};

const getPresetUsage = async (userId) => {
  const { rows } = await pool.query(`SELECT preset_mode, COUNT(*) as count FROM usage_logs WHERE user_id = $1 AND preset_mode IS NOT NULL GROUP BY preset_mode`, [userId]);
  return rows;
};

const registerApiKey = async (userId) => {
  const apiKey = require('crypto').randomBytes(32).toString('hex');
  await pool.query(`INSERT INTO api_keys (user_id, api_key) VALUES ($1, $2)`, [userId, apiKey]);
  return apiKey;
};

const verifyApiKey = async (apiKey) => {
  const { rows } = await pool.query(`SELECT user_id FROM api_keys WHERE api_key = $1`, [apiKey]);
  return rows[0]?.user_id;
};

module.exports = { 
  registerUser, 
  loginUser, 
  saveFrequency, 
  getRecentFrequencies, 
  getHistoricalFrequencies, 
  logUsage, 
  getUserStats, 
  getUsageTrends, 
  getPresetUsage, 
  registerApiKey, 
  verifyApiKey 
};