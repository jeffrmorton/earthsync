// detector/constants.js
/**
 * Centralized constants for the EarthSync detector.
 */
const crypto = require('crypto');

// Environment variables with defaults
const REDIS_HOST = process.env.REDIS_HOST;
const REDIS_PORT = parseInt(process.env.REDIS_PORT, 10);
const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
const INTERVAL_MS = parseInt(process.env.DETECTOR_INTERVAL_MS, 10) || 5000;
// --- BATCH SIZE CHANGE ---
// Enforce batch size of 1 for simpler processing and broadcasting alignment.
// Log a warning in detector.js if the environment variable attempts to override this.
const DETECTOR_BATCH_SIZE = 1;
// --- END BATCH SIZE CHANGE ---
const DETECTOR_ID = process.env.DETECTOR_ID || crypto.randomUUID();
const LATITUDE = parseFloat(process.env.LATITUDE); // Validation happens in detector.js
const LONGITUDE = parseFloat(process.env.LONGITUDE); // Validation happens in detector.js
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const REDIS_CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS, 10) || 20000;

// Simulation constants
const RAW_FREQUENCY_POINTS = 5501;
// Removed unused MAX_FREQUENCY_HZ and HZ_PER_POINT as they are derived in processingUtils if needed
const MAX_FREQUENCY_HZ_INTERNAL = 55; // Keep internal value if needed for POINTS_PER_HZ derivation
const POINTS_PER_HZ = (RAW_FREQUENCY_POINTS - 1) / MAX_FREQUENCY_HZ_INTERNAL; // Derived from internal const
const SCHUMANN_FREQUENCIES = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0];
const BASE_NOISE_LEVEL = 1.5;
const BASE_AMPLITUDE = 12.0;
const AMPLITUDE_DECREASE_FACTOR = 0.75;
const FREQUENCY_SHIFT_MAX = 0.2;
const PEAK_SHARPNESS_BASE_AVG = 250;
const PEAK_SHARPNESS_BASE_FLUCTUATION = 50;
const PEAK_SHARPNESS_RANDOM_VARIATION = 50;
const AMPLITUDE_VARIATION_FACTOR = 0.4; // For diurnal cycle
const AMPLITUDE_CYCLE_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

// Q-Burst Simulation Parameters
const Q_BURST_PROBABILITY = 0.005; // 0.5% chance per interval
const Q_BURST_MODE_INDICES = [0, 1]; // Modes likely to burst (7.83Hz, 14.3Hz)
const Q_BURST_AMP_MULTIPLIER = 2.5;
const Q_BURST_SHARPNESS_DIVISOR = 3.0;
const Q_BURST_DURATION_INTERVALS = 2;

// Redis constants
const REDIS_STREAM_KEY = 'spectrogram_stream';

module.exports = {
  REDIS_HOST,
  REDIS_PORT,
  REDIS_PASSWORD,
  INTERVAL_MS,
  DETECTOR_BATCH_SIZE, // Export the constant value (now fixed at 1)
  DETECTOR_ID,
  LATITUDE, // Export potentially NaN value, handle in main script
  LONGITUDE, // Export potentially NaN value, handle in main script
  LOG_LEVEL,
  REDIS_CONNECT_TIMEOUT_MS,
  RAW_FREQUENCY_POINTS,
  // MAX_FREQUENCY_HZ, // Not exported
  // HZ_PER_POINT, // Not exported
  POINTS_PER_HZ, // Export derived value
  SCHUMANN_FREQUENCIES,
  BASE_NOISE_LEVEL,
  BASE_AMPLITUDE,
  AMPLITUDE_DECREASE_FACTOR,
  FREQUENCY_SHIFT_MAX,
  PEAK_SHARPNESS_BASE_AVG,
  PEAK_SHARPNESS_BASE_FLUCTUATION,
  PEAK_SHARPNESS_RANDOM_VARIATION,
  AMPLITUDE_VARIATION_FACTOR,
  AMPLITUDE_CYCLE_DURATION_MS,
  Q_BURST_PROBABILITY,
  Q_BURST_MODE_INDICES,
  Q_BURST_AMP_MULTIPLIER,
  Q_BURST_SHARPNESS_DIVISOR,
  Q_BURST_DURATION_INTERVALS,
  REDIS_STREAM_KEY,
};
