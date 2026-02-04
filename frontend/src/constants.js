// client/src/constants.js
/**
 * Centralized constants for the EarthSync client application.
 */

// --- Environment Variables ---
const REACT_APP_API_BASE_URL = window.REACT_APP_API_BASE_URL || 'http://localhost:3000';
const REACT_APP_WS_URL = window.REACT_APP_WS_URL || 'ws://localhost:3000';

const API_URL_FROM_ENV = REACT_APP_API_BASE_URL;
const WS_URL_FROM_ENV = REACT_APP_WS_URL;

export const DEFAULT_API_BASE_URL = API_URL_FROM_ENV;
export const DEFAULT_WS_URL = WS_URL_FROM_ENV;
export const FALLBACK_API_BASE_URL = 'http://localhost:3000';
export const FALLBACK_WS_URL = 'ws://localhost:3000';

// --- Layout Constants ---
export const DRAWER_WIDTH = 300;
export const MAIN_CONTENT_MARGIN = 16; // Reduced slightly for more plot space
export const DEFAULT_APP_BAR_HEIGHT = 64;

// --- Visualization Defaults & Options ---
export const DEFAULT_TIME_STEPS = 45;
export const DEFAULT_COLOR_SCALE = 'Viridis'; // Changed default from Jet to Viridis
export const DEFAULT_PLOT_TYPE = '3d';
export const DEFAULT_NORMALIZE = false;
export const DEFAULT_HISTORICAL_HOURS = 1;
export const DEFAULT_SELECTED_DETECTOR = 'all';

export const PLOT_COLOR_SCALES = ['Viridis', 'Plasma', 'Jet', 'Greys']; // Put perceptually uniform first

// --- Spectrogram Data Dimensions ---
export const RAW_FREQUENCY_POINTS = 5501;
export const DOWNSAMPLE_FACTOR = 5;
export const EXPECTED_DOWNSAMPLED_POINTS = Math.ceil(RAW_FREQUENCY_POINTS / DOWNSAMPLE_FACTOR);
export const SPECTROGRAM_FREQUENCY_MAX_HZ = 55;

// --- Schumann Resonance Mode Definitions ---
export const SCHUMANN_MODE_RANGES = {
  'Mode 1 (7.8Hz)': { min: 6.5, max: 9.5 },
  'Mode 2 (14Hz)': { min: 12.5, max: 16.5 },
  'Mode 3 (21Hz)': { min: 18.5, max: 23.5 },
  'Mode 4 (27Hz)': { min: 24.5, max: 30.5 },
  'Mode 5 (34Hz)': { min: 31.5, max: 36.5 },
};
export const SCHUMANN_FUNDAMENTALS = [7.83, 14.3, 20.8, 27.3, 33.8];

// --- WebSocket Status Enum ---
export const WebSocketStatusEnum = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
};

// --- Local Storage Keys ---
export const LS_KEY_DARK_MODE = 'darkMode';
export const LS_KEY_TIME_STEPS = 'timeSteps';
export const LS_KEY_COLOR_SCALE = 'colorScale';
export const LS_KEY_NORMALIZE = 'normalize';
export const LS_KEY_SELECTED_DETECTOR = 'selectedDetector';
export const LS_KEY_DRAWER_OPEN = 'drawerOpen';
export const LS_KEY_PLOT_TYPE = 'plotType';
export const LS_KEY_AUTH_TOKEN = 'token';

// --- Timing Constants (ms) ---
export const SLIDER_DEBOUNCE_MS = 300;
export const SPECTROGRAM_UPDATE_THROTTLE_MS = 500;
export const HEALTH_CHECK_TIMEOUT_MS = 3000;
export const TRANSIENT_INDICATOR_TIMEOUT_MS = 5000;
