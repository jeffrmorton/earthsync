// client/src/constants.js
/**
 * Centralized constants for the EarthSync client application.
 */

// --- Environment Variables ---
// Access REACT_APP_* variables directly (injected by Create React App build process)
// Provide fallback defaults for development when .env might not be set or during tests
const REACT_APP_API_BASE_URL = window.REACT_APP_API_BASE_URL || 'http://localhost:3000';
const REACT_APP_WS_URL = window.REACT_APP_WS_URL || 'ws://localhost:3000';
// ^^^ Note: Accessing directly or via `window.` might not work reliably depending
// on CRA version and context. The standard way CRA makes these available is
// simply by referencing the variable name directly IF the code consuming this
// constant file is part of the CRA build process.

// Let's try the direct reference method, which is standard for CRA:
// If this still fails, it indicates an issue with the build process or environment setup.
const API_URL_FROM_ENV = REACT_APP_API_BASE_URL; // Direct reference
const WS_URL_FROM_ENV = REACT_APP_WS_URL; // Direct reference

// API and WebSocket URLs
export const DEFAULT_API_BASE_URL = API_URL_FROM_ENV;
export const DEFAULT_WS_URL = WS_URL_FROM_ENV;
// Fallbacks remain hardcoded as they are used if the default fails the health check
export const FALLBACK_API_BASE_URL = 'http://localhost:3000';
export const FALLBACK_WS_URL = 'ws://localhost:3000';

// --- Layout Constants ---
export const DRAWER_WIDTH = 300;
export const MAIN_CONTENT_MARGIN = 20;
export const DEFAULT_APP_BAR_HEIGHT = 64; // Initial guess

// --- Visualization Defaults & Options ---
export const DEFAULT_TIME_STEPS = 45; // Corresponds to 45 * 5 = 225 seconds initially
export const DEFAULT_COLOR_SCALE = 'Viridis';
export const DEFAULT_PLOT_TYPE = '3d'; // '2d' or '3d'
export const DEFAULT_NORMALIZE = false;
export const DEFAULT_HISTORICAL_HOURS = 1;
export const DEFAULT_SELECTED_DETECTOR = 'all';

export const PLOT_COLOR_SCALES = ['Jet', 'Greys', 'Viridis', 'Plasma'];

// --- Spectrogram Data Dimensions ---
export const RAW_FREQUENCY_POINTS = 5501; // Original points before downsampling
export const DOWNSAMPLE_FACTOR = 5; // Assumed factor matching server default
export const EXPECTED_DOWNSAMPLED_POINTS = Math.ceil(RAW_FREQUENCY_POINTS / DOWNSAMPLE_FACTOR);
export const SPECTROGRAM_FREQUENCY_MAX_HZ = 55;

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
