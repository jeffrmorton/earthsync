// client/src/App.js
/**
 * Main application component for EarthSync client (v1.1.28 - Final Linter Fixes).
 * Handles authentication, theme toggling, and renders the main page layout.
 * Delegates drawer content to ControlsDrawer and main plot area to MainContent.
 * Filters Peak Info display to show only SR modes. Handles auth errors via logout.
 * Fixes heatmap time direction and adds axis titles. Implements UI polish.
 * Uses useWebSocket and useApiClient hooks for logic encapsulation.
 * Uses centralized constants. No backslash escapes in template literals.
 */
import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import debounce from 'lodash.debounce';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  CssBaseline,
  Box,
  ThemeProvider,
  createTheme,
  CircularProgress,
  Alert,
  Snackbar,
  LinearProgress,
  useTheme,
  FormControl,
  FormLabel,
  Tooltip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Brightness4 as Brightness4Icon,
  Brightness7 as Brightness7Icon,
  History as HistoryIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Bolt as BoltIcon,
  Grain as GrainIcon,
  NotificationsActive as NotificationsActiveIcon,
} from '@mui/icons-material';

// Import project constants
import {
  DEFAULT_API_BASE_URL,
  DEFAULT_WS_URL,
  FALLBACK_API_BASE_URL,
  FALLBACK_WS_URL,
  DRAWER_WIDTH,
  MAIN_CONTENT_MARGIN,
  DEFAULT_APP_BAR_HEIGHT,
  DEFAULT_TIME_STEPS,
  DEFAULT_COLOR_SCALE,
  DEFAULT_PLOT_TYPE,
  DEFAULT_NORMALIZE,
  DEFAULT_HISTORICAL_HOURS,
  DEFAULT_SELECTED_DETECTOR,
  LS_KEY_DARK_MODE,
  LS_KEY_TIME_STEPS,
  LS_KEY_COLOR_SCALE,
  LS_KEY_NORMALIZE,
  LS_KEY_SELECTED_DETECTOR,
  LS_KEY_DRAWER_OPEN,
  LS_KEY_PLOT_TYPE,
  LS_KEY_AUTH_TOKEN,
  EXPECTED_DOWNSAMPLED_POINTS,
  SPECTROGRAM_FREQUENCY_MAX_HZ,
  SLIDER_DEBOUNCE_MS,
  HEALTH_CHECK_TIMEOUT_MS,
  TRANSIENT_INDICATOR_TIMEOUT_MS,
  SCHUMANN_MODE_RANGES,
} from './constants';

// Import Child Components
import ControlsDrawer from './components/ControlsDrawer';
import MainContent from './components/MainContent';
// Import Custom Hooks
import useWebSocket, { WebSocketStatus } from './hooks/useWebSocket';
import useApiClient from './hooks/useApiClient';

// Helper to get value from localStorage or default
const getLocalStorage = (key, defaultValue, parseJson = true) => {
  try {
    const saved = localStorage.getItem(key);
    if (saved === null) {
      return defaultValue;
    }
    return parseJson ? JSON.parse(saved) : saved;
  } catch (error) {
    console.error(`Error reading localStorage key "${key}":`, error);
    return defaultValue;
  }
};

// Function to determine the working API and WS URLs with localhost fallback
async function determineServerUrls(defaultApiUrl, defaultWsUrl) {
  try {
    await axios.get(`${defaultApiUrl}/health`, { timeout: HEALTH_CHECK_TIMEOUT_MS });
    return { apiUrl: defaultApiUrl, wsUrl: defaultWsUrl };
  } catch (err) {
    console.warn(
      `Default server URL (${defaultApiUrl}) not reachable: ${err.message}. Trying fallback...`
    );
    try {
      await axios.get(`${FALLBACK_API_BASE_URL}/health`, { timeout: HEALTH_CHECK_TIMEOUT_MS });
      return { apiUrl: FALLBACK_API_BASE_URL, wsUrl: FALLBACK_WS_URL };
    } catch (fallbackErr) {
      console.error(
        `Fallback server URL (${FALLBACK_API_BASE_URL}) also not reachable: ${fallbackErr.message}.`
      );
      return {
        apiUrl: FALLBACK_API_BASE_URL,
        wsUrl: FALLBACK_WS_URL,
        error: `Could not connect to API at ${defaultApiUrl} or ${FALLBACK_API_BASE_URL}`,
      };
    }
  }
}

// --- Auth Component ---
function App() {
  const [token, setToken] = useState(() => getLocalStorage(LS_KEY_AUTH_TOKEN, null, false));
  const [isAuthenticated, setIsAuthenticated] = useState(!!token);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [serverUrls, setServerUrls] = useState(null);
  const [initializationError, setInitializationError] = useState(null);
  const [darkMode, setDarkMode] = useState(() => getLocalStorage(LS_KEY_DARK_MODE, true));

  // --- Theme ---
  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: darkMode ? 'dark' : 'light',
          primary: { main: '#1976d2' },
          secondary: { main: '#f50057' },
          background: {
            default: darkMode ? '#121212' : '#f4f6f8',
            paper: darkMode ? '#1e1e1e' : '#ffffff',
          },
        },
        typography: {},
        components: {
          MuiListItemButton: {
            styleOverrides: {
              root: ({ theme: currentTheme }) => ({
                '&:hover': {
                  backgroundColor: currentTheme.palette.action.hover,
                },
              }),
            },
          },
        },
      }),
    [darkMode]
  );

  // --- Effects ---
  useEffect(() => {
    localStorage.setItem(LS_KEY_DARK_MODE, JSON.stringify(darkMode));
  }, [darkMode]);

  useEffect(() => {
    setIsAuthenticated(!!token);
  }, [token]);

  useEffect(() => {
    setIsLoading(true);
    determineServerUrls(DEFAULT_API_BASE_URL, DEFAULT_WS_URL)
      .then((urls) => {
        setServerUrls(urls);
        if (urls.error) {
          setInitializationError(urls.error);
        }
      })
      .finally(() => setIsLoading(false));
  }, []);

  // --- Event Handlers ---
  const handleAuthAction = async (e, action) => {
    e.preventDefault();
    if (!serverUrls || isLoading) return;
    setIsLoading(true);
    setAuthError(null);
    const registerPath = '/api/auth/register';
    const loginPath = '/api/auth/login';
    const url =
      action === 'register'
        ? `${serverUrls.apiUrl}${registerPath}`
        : `${serverUrls.apiUrl}${loginPath}`;

    try {
      const response = await axios.post(url, { username, password });
      if (action === 'register') {
        setIsRegistering(false);
        setAuthError('Registration successful! Please log in.');
      } else {
        localStorage.setItem(LS_KEY_AUTH_TOKEN, response.data.token);
        setToken(response.data.token);
      }
    } catch (err) {
      console.error(`${action} failed:`, err);
      let message = err.message;
      if (err.response) {
        message =
          err.response.data?.error ||
          `Server error: ${err.response.status} (${err.response.statusText})`;
      } else if (err.request) {
        message = 'Network error. Could not reach the server.';
      }
      setAuthError(`${action.charAt(0).toUpperCase() + action.slice(1)} failed: ${message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = useCallback(() => {
    localStorage.removeItem(LS_KEY_AUTH_TOKEN);
    setToken(null);
  }, []);

  // --- Conditional Rendering ---
  if (isLoading && !serverUrls) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            height: '100vh',
            flexDirection: 'column',
            gap: 2,
          }}
        >
          <CircularProgress />
          <Typography variant="h6">Connecting to EarthSync server...</Typography>
          {initializationError && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              {initializationError}
            </Alert>
          )}
        </Box>
      </ThemeProvider>
    );
  }

  if (serverUrls && initializationError && !isAuthenticated) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box sx={{ padding: 3, textAlign: 'center' }}>
          <Alert severity="error">
            <Typography variant="h6">Failed to connect to the EarthSync API.</Typography>
            <Typography>{initializationError}</Typography>
            <Typography>
              Please ensure the server is running and accessible. You might need to refresh the page
              later.
            </Typography>
          </Alert>
        </Box>
      </ThemeProvider>
    );
  }

  // --- Main Render Logic ---
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {isAuthenticated && serverUrls ? (
        <SpectrogramPage
          token={token}
          onLogout={handleLogout}
          darkMode={darkMode}
          setDarkMode={setDarkMode}
          apiUrl={serverUrls.apiUrl}
          wsUrl={serverUrls.wsUrl}
        />
      ) : (
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            p: 3,
          }}
        >
          <Box
            sx={{
              padding: 3,
              maxWidth: 400,
              width: '100%',
              border: `1px solid ${theme.palette.divider}`,
              borderRadius: 1,
              bgcolor: 'background.paper',
            }}
          >
            <Typography variant="h5" component="h1" gutterBottom align="center">
              EarthSync {isRegistering ? 'Register' : 'Login'}
            </Typography>
            {authError && (
              <Alert
                severity={authError.startsWith('Registration successful') ? 'success' : 'error'}
                sx={{ mb: 2 }}
              >
                {authError}
              </Alert>
            )}
            <form onSubmit={(e) => handleAuthAction(e, isRegistering ? 'register' : 'login')}>
              <FormControl fullWidth margin="normal">
                <FormLabel htmlFor="username-input">Username</FormLabel>
                <input
                  id="username-input"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  style={{
                    padding: '10px',
                    borderRadius: '4px',
                    border: `1px solid ${theme.palette.divider}`,
                    width: 'calc(100% - 22px)',
                    background: theme.palette.background.default,
                    color: theme.palette.text.primary,
                  }}
                  aria-required="true"
                />
              </FormControl>
              <FormControl fullWidth margin="normal">
                <FormLabel htmlFor="password-input">Password</FormLabel>
                <input
                  id="password-input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  style={{
                    padding: '10px',
                    borderRadius: '4px',
                    border: `1px solid ${theme.palette.divider}`,
                    width: 'calc(100% - 22px)',
                    background: theme.palette.background.default,
                    color: theme.palette.text.primary,
                  }}
                  aria-required="true"
                />
              </FormControl>
              <Box
                sx={{
                  mt: 2,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <button
                  type="submit"
                  style={{
                    padding: '10px 20px',
                    borderRadius: '4px',
                    cursor: isLoading ? 'not-allowed' : 'pointer',
                    opacity: isLoading ? 0.6 : 1,
                    border: 'none',
                    backgroundColor: theme.palette.primary.main,
                    color: theme.palette.primary.contrastText,
                  }}
                  disabled={isLoading}
                  aria-live="polite"
                >
                  {isLoading ? (
                    <CircularProgress size={20} color="inherit" />
                  ) : isRegistering ? (
                    'Register'
                  ) : (
                    'Login'
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setIsRegistering(!isRegistering);
                    setAuthError(null);
                  }}
                  style={{
                    padding: '10px 20px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    border: `1px solid ${theme.palette.divider}`,
                    background: 'transparent',
                    color: theme.palette.text.primary,
                  }}
                  disabled={isLoading}
                >
                  {isRegistering ? 'Switch to Login' : 'Switch to Register'}
                </button>
              </Box>
            </form>
          </Box>
        </Box>
      )}
    </ThemeProvider>
  );
}

// --- Transient Indicator ---
const pulseKeyframes = `@keyframes pulse {
  0% { opacity: 0.6; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.15); }
  100% { opacity: 0.6; transform: scale(1); }
}`;

const TransientIndicator = ({ transientInfo }) => {
  let IconComponent = NotificationsActiveIcon;
  let iconColor = 'warning.main';
  let title = 'Transient event detected!';

  if (transientInfo?.type === 'broadband') {
    IconComponent = BoltIcon;
    title = `Broadband transient detected!`;
    iconColor = 'error.light';
  } else if (transientInfo?.type === 'narrowband') {
    IconComponent = GrainIcon;
    title = `Narrowband transient detected!`;
    iconColor = 'warning.light';
  }

  if (transientInfo?.details) {
    title += ` Details: ${transientInfo.details}`;
  }

  return (
    <>
      <style>{pulseKeyframes}</style>
      <Tooltip title={title}>
        <IconComponent
          sx={{
            color: iconColor,
            fontSize: '1.3rem',
            ml: 1,
            animation: 'pulse 1.5s infinite ease-in-out',
          }}
        />
      </Tooltip>
    </>
  );
};
TransientIndicator.propTypes = {
  transientInfo: PropTypes.shape({
    type: PropTypes.string,
    details: PropTypes.string,
  }),
};

// --- Spectrogram Page Component (Main authenticated view) ---
const SpectrogramPage = React.memo(({ token, onLogout, darkMode, setDarkMode, apiUrl, wsUrl }) => {
  const [spectrogramData, setSpectrogramData] = useState({});
  const [detectorActivity, setDetectorActivity] = useState({});
  const [peakData, setPeakData] = useState({});
  const [appError, setAppError] = useState(null);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarSeverity, setSnackbarSeverity] = useState('error');
  const [lastTransientInfo, setLastTransientInfo] = useState(null);
  const [isTransitioning, setIsTransitioning] = useState(false);

  const [timeSteps, setTimeSteps] = useState(() =>
    getLocalStorage(LS_KEY_TIME_STEPS, DEFAULT_TIME_STEPS)
  );
  const [historicalMode, setHistoricalMode] = useState(false);
  const [historicalHours, setHistoricalHours] = useState(DEFAULT_HISTORICAL_HOURS);
  const [colorScale, setColorScale] = useState(() =>
    getLocalStorage(LS_KEY_COLOR_SCALE, DEFAULT_COLOR_SCALE)
  );
  const [normalize, setNormalize] = useState(() =>
    getLocalStorage(LS_KEY_NORMALIZE, DEFAULT_NORMALIZE)
  );
  const [selectedDetector, setSelectedDetector] = useState(() =>
    getLocalStorage(LS_KEY_SELECTED_DETECTOR, DEFAULT_SELECTED_DETECTOR)
  );
  const [drawerOpen, setDrawerOpen] = useState(() => getLocalStorage(LS_KEY_DRAWER_OPEN, true));
  const [plotType, setPlotType] = useState(() =>
    getLocalStorage(LS_KEY_PLOT_TYPE, DEFAULT_PLOT_TYPE)
  );

  const appBarRef = useRef(null);
  const theme = useTheme();
  const historicalModeRef = useRef(historicalMode);

  const stableSetTimeSteps = useCallback((val) => setTimeSteps(val), []);
  const stableSetSpectrogramData = useCallback((val) => setSpectrogramData(val), []);
  const stableSetDetectorActivity = useCallback((val) => setDetectorActivity(val), []);
  const stableSetPeakData = useCallback((val) => setPeakData(val), []);
  const stableSetColorScale = useCallback((val) => setColorScale(val), []);
  const stableSetNormalize = useCallback((val) => setNormalize(val), []);
  const stableSetSelectedDetector = useCallback((val) => setSelectedDetector(val), []);
  const stableSetHistoricalHours = useCallback((val) => setHistoricalHours(val), []);
  const stableSetPlotType = useCallback((val) => setPlotType(val), []);
  const stableSetLastTransientInfo = useCallback((val) => setLastTransientInfo(val), []);

  const showSnackbar = useCallback((message, severity = 'error') => {
    setAppError(message);
    setSnackbarSeverity(severity);
    setSnackbarOpen(true);
  }, []);

  const {
    encryptionKey,
    isLoadingKey,
    loadHistoricalData,
    historicalSpectrograms,
    historicalPeaks,
    historicalActivity,
    historicalTransients,
    isLoadingHistory,
    authenticationErrorOccurred,
  } = useApiClient(apiUrl, token, showSnackbar);

  const wsStatus = useWebSocket(
    wsUrl,
    token,
    encryptionKey,
    historicalMode,
    stableSetSpectrogramData,
    stableSetPeakData,
    stableSetDetectorActivity,
    stableSetLastTransientInfo,
    showSnackbar
  );

  useEffect(() => {
    if (authenticationErrorOccurred) {
      console.warn('Authentication error detected by API client, logging out.');
      onLogout();
    }
  }, [authenticationErrorOccurred, onLogout]);

  useEffect(() => {
    historicalModeRef.current = historicalMode;
  }, [historicalMode]);
  useEffect(() => {
    localStorage.setItem(LS_KEY_DRAWER_OPEN, JSON.stringify(drawerOpen));
  }, [drawerOpen]);
  useEffect(() => {
    localStorage.setItem(LS_KEY_TIME_STEPS, JSON.stringify(timeSteps));
  }, [timeSteps]);
  useEffect(() => {
    localStorage.setItem(LS_KEY_COLOR_SCALE, JSON.stringify(colorScale));
  }, [colorScale]);
  useEffect(() => {
    localStorage.setItem(LS_KEY_NORMALIZE, JSON.stringify(normalize));
  }, [normalize]);
  useEffect(() => {
    localStorage.setItem(LS_KEY_SELECTED_DETECTOR, JSON.stringify(selectedDetector));
  }, [selectedDetector]);
  useEffect(() => {
    localStorage.setItem(LS_KEY_PLOT_TYPE, JSON.stringify(plotType));
  }, [plotType]);

  const [appBarHeight, setAppBarHeight] = useState(DEFAULT_APP_BAR_HEIGHT);
  useEffect(() => {
    if (appBarRef.current) {
      const resizeObserver = new ResizeObserver((entries) => {
        if (entries[0]) setAppBarHeight(entries[0].contentRect.height);
      });
      resizeObserver.observe(appBarRef.current);
      return () => resizeObserver.disconnect();
    }
  }, []);

  const displaySpectrogramData = historicalMode ? historicalSpectrograms : spectrogramData;
  const displayDetectorActivity = historicalMode ? historicalActivity : detectorActivity;
  const displayHistoricalPeaks = historicalMode ? historicalPeaks : null;
  const displayHistoricalTransients = historicalMode ? historicalTransients : [];

  const {
    xLabels,
    yLabels,
    displayData,
    minAmplitude,
    maxAmplitude,
    timestamps,
    xLabelsHeatmap,
    timestampsHeatmap,
  } = useMemo(() => {
    const numPoints = EXPECTED_DOWNSAMPLED_POINTS;
    const calculatedXLabels = Array.from(
      { length: numPoints },
      (_, i) => i * (SPECTROGRAM_FREQUENCY_MAX_HZ / (numPoints - 1))
    );

    let sourceDataPoints = [];
    let sourceRows = [];

    if (historicalMode) {
      const historyData =
        selectedDetector === 'all'
          ? Object.values(displaySpectrogramData).flatMap((det) => det.dataPoints || [])
          : displaySpectrogramData[selectedDetector]?.dataPoints || [];

      historyData.sort((a, b) => a.ts - b.ts);
      sourceDataPoints = historyData;
      sourceRows = historyData.map((dp) => dp.spectrogram || []);
    } else {
      sourceRows =
        selectedDetector === 'all'
          ? Object.values(displaySpectrogramData).flat()
          : displaySpectrogramData[selectedDetector] || [];
    }

    const validSourceRows = Array.isArray(sourceRows)
      ? sourceRows.filter(
          (row) =>
            Array.isArray(row) && row.length >= numPoints - 10 && row.length <= numPoints + 10
        )
      : [];
    const recentRows = validSourceRows.slice(-timeSteps);

    const finalRows = recentRows.map((row) => {
      if (row.length === numPoints) return row;
      const newRow = [...row];
      if (row.length < numPoints) {
        newRow.push(...Array(numPoints - row.length).fill(0));
      } else {
        newRow.length = numPoints;
      }
      return newRow;
    });

    const paddedRows =
      finalRows.length < timeSteps
        ? [...Array(timeSteps - finalRows.length).fill(Array(numPoints).fill(0)), ...finalRows]
        : finalRows;

    const yLabels_reversed = [];
    const timestamps_reversed = [];
    const yLabels_unreversed = [];
    const timestamps_unreversed = [];
    const nowMs = Date.now();
    const approxIntervalMs = 5000;

    for (let i = 0; i < paddedRows.length; i++) {
      const rowIndex = paddedRows.length - 1 - i;
      let label = '';
      let timestamp = null;
      if (historicalMode && sourceDataPoints.length > 0) {
        const sourceIndex = sourceDataPoints.length - (paddedRows.length - i);
        if (sourceIndex >= 0 && sourceDataPoints[sourceIndex]?.ts) {
          timestamp = sourceDataPoints[sourceIndex].ts;
          label = new Date(timestamp).toLocaleTimeString();
        } else {
          label = `Hist ~${rowIndex * 5}s?`;
          timestamp = nowMs - rowIndex * approxIntervalMs;
        }
      } else {
        const secondsAgo = rowIndex * 5;
        label = secondsAgo === 0 ? 'Now' : `-${secondsAgo}s`;
        timestamp = nowMs - rowIndex * approxIntervalMs;
      }
      yLabels_unreversed.push(label);
      timestamps_unreversed.push(timestamp);
    }
    yLabels_reversed.push(...yLabels_unreversed);
    yLabels_reversed.reverse();
    timestamps_reversed.push(...timestamps_unreversed);
    timestamps_reversed.reverse();

    const normalizeFn = (data) => {
      const vals = data.flat().filter((v) => typeof v === 'number' && !isNaN(v));
      if (vals.length === 0) return data;
      const min = Math.min(...vals);
      const max = Math.max(...vals);
      const range = max - min;
      if (range === 0) return data.map((r) => r.map(() => 0));
      return data.map((r) =>
        r.map((v) => (typeof v === 'number' && !isNaN(v) ? ((v - min) / range) * 15 : 0))
      );
    };

    const finalDisplayData =
      paddedRows.length > 0 ? (normalize ? normalizeFn(paddedRows) : paddedRows) : [];
    const allFlatValues = finalDisplayData.flat().filter((v) => typeof v === 'number' && !isNaN(v));
    const calculatedMinAmplitude = allFlatValues.length
      ? Math.max(0, Math.min(...allFlatValues))
      : 0;
    const amplitudeCap = normalize ? 16 : 25;
    const calculatedMaxAmplitude = allFlatValues.length
      ? Math.min(amplitudeCap, Math.max(...allFlatValues) + 1)
      : amplitudeCap;

    return {
      xLabels: calculatedXLabels,
      yLabels: yLabels_reversed,
      displayData: finalDisplayData,
      minAmplitude: calculatedMinAmplitude,
      maxAmplitude: calculatedMaxAmplitude,
      timestamps: timestamps_reversed,
      xLabelsHeatmap: yLabels_unreversed,
      timestampsHeatmap: timestamps_unreversed,
    };
  }, [displaySpectrogramData, selectedDetector, timeSteps, normalize, historicalMode]);

  const plotData = useMemo(() => {
    if (
      !displayData ||
      displayData.length === 0 ||
      !Array.isArray(displayData[0]) ||
      displayData[0].length === 0
    ) {
      return [];
    }

    const commonPlotProps = {
      colorscale: colorScale,
      showscale: true,
      colorbar: {
        title: 'Amplitude',
        titleside: 'right',
        tickfont: { color: darkMode ? '#ffffff' : '#000000' },
        titlefont: { color: darkMode ? '#ffffff' : '#000000' },
      },
      zmin: minAmplitude,
      zmax: maxAmplitude,
    };

    if (plotType === '2d') {
      const transposedZ = displayData[0].map((_, colIndex) =>
        displayData.map((row) => row[colIndex])
      );
      return [
        {
          ...commonPlotProps,
          x: xLabelsHeatmap,
          y: xLabels,
          z: transposedZ,
          type: 'heatmapgl',
          customdata: timestampsHeatmap,
          hovertemplate: `<b>Frequency:</b> %{y:.2f} Hz<br><b>Time:</b> %{x}<br><b>Amplitude:</b> %{z:.2f}<br><b>Timestamp:</b> %{customdata|%Y-%m-%d %H:%M:%S}<extra></extra>`,
          hoverinfo: 'none',
        },
      ];
    } else {
      return [
        {
          ...commonPlotProps,
          x: xLabels,
          y: yLabels,
          z: displayData,
          type: 'surface',
          customdata: timestamps,
          hovertemplate: `<b>Frequency:</b> %{x:.2f} Hz<br><b>Time:</b> %{y}<br><b>Amplitude:</b> %{z:.2f}<br><b>Timestamp:</b> %{customdata|%Y-%m-%d %H:%M:%S}<extra></extra>`,
          hoverinfo: 'none',
          contours: {
            z: { show: true, usecolormap: true, highlightcolor: '#42f462', project: { z: true } },
          },
          lighting: { ambient: 0.8, diffuse: 0.8, specular: 0.1 },
          lightposition: { x: 100, y: 100, z: 2000 },
        },
      ];
    }
  }, [
    displayData,
    xLabels,
    yLabels,
    xLabelsHeatmap,
    timestamps,
    timestampsHeatmap,
    colorScale,
    darkMode,
    minAmplitude,
    maxAmplitude,
    plotType,
  ]);

  const layout = useMemo(() => {
    const freqLabels = xLabels;
    const timeLabels = plotType === '2d' ? xLabelsHeatmap : yLabels;

    const timeTickIndices = Array.isArray(timeLabels)
      ? timeLabels
          .map((_, i) => i)
          .filter((_, i) => i % Math.max(1, Math.floor(timeLabels.length / 10)) === 0)
      : [];
    const safeTimeTickVals = timeTickIndices.map((i) => timeLabels[i]);
    const safeTimeTickText = timeTickIndices.map((i) => timeLabels[i]);

    const freqTickIndices = Array.isArray(freqLabels)
      ? freqLabels
          .map((_, i) => i)
          .filter((_, i) => i % Math.max(1, Math.floor(freqLabels.length / 10)) === 0)
      : [];
    const safeFreqTickVals = freqTickIndices.map((i) => freqLabels[i]);
    const safeFreqTickText = freqTickIndices.map((i) =>
      typeof freqLabels[i] === 'number' ? freqLabels[i].toFixed(1) : String(freqLabels[i] ?? '')
    );

    const baseLayout = {
      title: {
        text: `Schumann Resonance ${selectedDetector === 'all' ? '(All Detectors)' : `(${selectedDetector})`} ${historicalMode ? `(Past ${historicalHours}h)` : '(Real-time)'} (${plotType === '2d' ? '2D Heatmap' : '3D Surface'})`,
        font: { size: 16, color: darkMode ? '#ffffff' : '#000000' },
        y: 0.98,
        x: 0.5,
        xanchor: 'center',
        yanchor: 'top',
      },
      margin: { t: 60, r: 20, b: 70, l: 70 }, // Adjusted margins for titles
      autosize: true,
      paper_bgcolor: 'rgba(0,0,0,0)',
      plot_bgcolor: 'rgba(0,0,0,0)',
      font: { color: darkMode ? '#ffffff' : '#000000' },
      hovermode: 'closest',
    };
    if (plotType === '2d') {
      return {
        ...baseLayout,
        xaxis: { // TIME AXIS
          title: { // Use explicit title object
            text: 'Time',
            font: { size: 12, color: darkMode ? '#ffffff' : '#000000' }
          },
          tickvals: safeTimeTickVals,
          ticktext: safeTimeTickText,
          tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' },
          gridcolor: darkMode ? '#555555' : '#d3d3d3',
          automargin: true, // Use automargin
        },
        yaxis: { // FREQUENCY AXIS
          title: { // Use explicit title object
            text: 'Frequency (Hz)',
            font: { size: 12, color: darkMode ? '#ffffff' : '#000000' }
          },
          tickvals: safeFreqTickVals,
          ticktext: safeFreqTickText,
          tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' },
          gridcolor: darkMode ? '#555555' : '#d3d3d3',
          range: [0, SPECTROGRAM_FREQUENCY_MAX_HZ],
          automargin: true, // Use automargin
        },
        modebar: {
          orientation: 'h',
          bgcolor: 'rgba(0,0,0,0.1)',
          color: darkMode ? '#ffffff' : '#000000',
          activecolor: theme.palette.primary.main,
        },
      };
    } else { // 3D Surface
      baseLayout.margin = { t: 50, r: 10, b: 10, l: 10 };
      return {
        ...baseLayout,
        scene: {
          xaxis: { // FREQUENCY AXIS
            title: {
                text: 'Frequency (Hz)',
                font: { size: 12, color: darkMode ? '#ffffff' : '#000000' }
            },
            tickvals: safeFreqTickVals,
            ticktext: safeFreqTickText,
            tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' },
            gridcolor: darkMode ? '#555555' : '#d3d3d3',
            zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
            backgroundcolor: 'rgba(0,0,0,0)',
            range: [0, SPECTROGRAM_FREQUENCY_MAX_HZ],
          },
          yaxis: { // TIME AXIS
            title: {
                text: 'Time',
                font: { size: 12, color: darkMode ? '#ffffff' : '#000000' }
            },
            tickvals: safeTimeTickVals,
            ticktext: safeTimeTickText,
            tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' },
            gridcolor: darkMode ? '#555555' : '#d3d3d3',
            zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
            backgroundcolor: 'rgba(0,0,0,0)',
            autorange: 'reversed',
          },
          zaxis: { // AMPLITUDE AXIS
            title: {
                text: 'Amplitude',
                font: { size: 12, color: darkMode ? '#ffffff' : '#000000' }
            },
            tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' },
            range: [minAmplitude, maxAmplitude],
            gridcolor: darkMode ? '#555555' : '#d3d3d3',
            zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
            backgroundcolor: 'rgba(0,0,0,0)',
          },
          camera: { eye: { x: 1.5, y: 1.5, z: 0.8 } },
          aspectmode: 'cube',
        },
        modebar: {
          orientation: 'v',
          bgcolor: 'rgba(0,0,0,0.1)',
          color: darkMode ? '#ffffff' : '#000000',
          activecolor: theme.palette.primary.main,
        },
      };
    }
  }, [
    darkMode,
    minAmplitude,
    maxAmplitude,
    yLabels,
    xLabels,
    xLabelsHeatmap,
    selectedDetector,
    historicalMode,
    historicalHours,
    theme.palette.primary.main,
    plotType,
  ]);

  // --- Memoize Globe data & Options ---
  const globePoints = useMemo(
    () =>
      Object.values(displayDetectorActivity).map(({ lat, lon, lastUpdate, id }) => {
        const timeSinceUpdate = Date.now() - lastUpdate;
        const isActive = !historicalMode && timeSinceUpdate < 10000;
        const sizePulse = isActive ? (timeSinceUpdate < 2000 ? 0.6 : 0.5) : 0.2;
        const latestPeaks = peakData[id] || [];
        const avgAmplitude =
          latestPeaks.length > 0
            ? latestPeaks.reduce((sum, p) => sum + p.amp, 0) / latestPeaks.length
            : 0;
        const baseColor = isActive ? 'red' : historicalMode ? 'grey' : 'blue';
        let pointColor = baseColor;
        if (isActive && avgAmplitude > 10) pointColor = avgAmplitude > 15 ? 'darkred' : 'indianred';
        else if (!isActive && !historicalMode && avgAmplitude > 5) pointColor = 'cornflowerblue';
        const peakInfo =
          latestPeaks.length > 0
            ? `\nPeaks: ${latestPeaks.map((p) => `${p.freq.toFixed(1)}Hz (A:${p.amp.toFixed(1)}, Q:${p.qFactor ? p.qFactor.toFixed(1) : 'N/A'}, S:${p.trackStatus ? p.trackStatus.charAt(0) : '?'})`).join(', ')}`
            : '';
        return {
          lat,
          lng: lon,
          size: sizePulse,
          color: pointColor,
          label: `Detector: ${id}\nCoords: ${lat.toFixed(2)}, ${lon.toFixed(2)}\nStatus: ${isActive ? 'Active' : historicalMode ? 'Historical' : 'Idle'}${peakInfo}`,
          id,
        };
      }),
    [displayDetectorActivity, historicalMode, peakData]
  );
  const detectorOptions = useMemo(
    () => [
      { id: 'all', label: 'All Detectors' },
      ...Object.keys(displayDetectorActivity)
        .sort()
        .map((id) => ({ id, label: id })),
    ],
    [displayDetectorActivity]
  );

  // --- Debounced Sliders ---
  const debouncedSetTimeSteps = useCallback(
    debounce((value) => stableSetTimeSteps(Math.max(6, Math.floor(value / 5))), SLIDER_DEBOUNCE_MS),
    [stableSetTimeSteps]
  );
  const debouncedSetHistoricalHours = useCallback(
    debounce((value) => stableSetHistoricalHours(value), SLIDER_DEBOUNCE_MS),
    [stableSetHistoricalHours]
  );

  // --- Interaction Handlers ---
  const handlePlotHover = useCallback(() => {}, []);
  const handlePlotClick = useCallback(
    (data) => {
      if (data.points.length > 0) {
        const point = data.points[0];
        let freq, timeLabel, amp, ts;
        if (plotType === '2d') {
          timeLabel = point.x;
          freq = point.y;
          amp = point.z;
          ts = point.customdata ? new Date(point.customdata).toLocaleString() : 'N/A';
        } else {
          freq = point.x;
          timeLabel = point.y;
          amp = point.z;
          ts = point.customdata ? new Date(point.customdata).toLocaleString() : 'N/A';
        }
        showSnackbar(
          `Plot Point Clicked: Freq=${freq.toFixed(2)}, TimeLabel=${timeLabel}, Amp=${amp.toFixed(2)}, Timestamp=${ts}`,
          'info'
        );
      }
    },
    [showSnackbar, plotType]
  );
  const handlePlotRelayout = useCallback(() => {}, []);
  const handleGlobePointClick = useCallback(
    (point) => {
      if (point?.id && detectorOptions.some((opt) => opt.id === point.id)) {
        stableSetSelectedDetector(point.id);
        showSnackbar(`Selected detector ${point.id} from globe.`, 'info');
      }
    },
    [detectorOptions, showSnackbar, stableSetSelectedDetector]
  );
  const handleGlobePointHover = useCallback(() => {}, []);
  const handleCloseSnackbar = useCallback((event, reason) => {
    if (reason === 'clickaway') return;
    setSnackbarOpen(false);
  }, []);
  const handleModeChange = useCallback(
    (newMode) => {
      if (newMode === historicalMode) return;
      setIsTransitioning(true);
      setHistoricalMode(newMode);
      stableSetLastTransientInfo(null);
      if (newMode) {
        loadHistoricalData(historicalHours, selectedDetector).finally(() =>
          setIsTransitioning(false)
        );
      } else {
        stableSetSpectrogramData({});
        stableSetDetectorActivity({});
        stableSetPeakData({});
        setIsTransitioning(false);
      }
    },
    [
      historicalMode,
      loadHistoricalData,
      historicalHours,
      selectedDetector,
      stableSetSpectrogramData,
      stableSetDetectorActivity,
      stableSetPeakData,
      stableSetLastTransientInfo,
      setHistoricalMode,
      setIsTransitioning,
    ]
  );
  const handleDetectorChange = useCallback(
    (event) => {
      const newDetector = event.target.value;
      if (newDetector === selectedDetector) return;
      stableSetSelectedDetector(newDetector);
      if (historicalModeRef.current) {
        setIsTransitioning(true);
        loadHistoricalData(historicalHours, newDetector).finally(() =>
          setIsTransitioning(false)
        );
      }
    },
    [
      selectedDetector,
      stableSetSelectedDetector,
      loadHistoricalData,
      historicalHours,
      setIsTransitioning,
    ]
  );

  // --- Filtered SR Peaks Memo ---
  const schumannPeaks = useMemo(() => {
    if (selectedDetector === 'all') return null;
    const latestPeaks = peakData[selectedDetector] || [];
    if (latestPeaks.length === 0) return [];

    const srPeaks = latestPeaks.filter((peak) => {
      for (const modeName in SCHUMANN_MODE_RANGES) {
        if (
          peak.freq >= SCHUMANN_MODE_RANGES[modeName].min &&
          peak.freq < SCHUMANN_MODE_RANGES[modeName].max
        ) {
          return true;
        }
      }
      return false;
    });
    return srPeaks.sort((a, b) => a.freq - b.freq);
  }, [peakData, selectedDetector]);


  // --- Render Logic ---
  return (
    <Box
      sx={{ display: 'flex', height: '100vh', overflow: 'hidden', bgcolor: 'background.default' }}
    >
      <AppBar
        ref={appBarRef}
        position="fixed"
        sx={{
          width: '100%',
          zIndex: (theme) => theme.zIndex.drawer + 1,
          bgcolor: 'background.paper',
          color: 'text.primary',
        }}
      >
        <Toolbar sx={{ justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <IconButton
              color="inherit"
              edge="start"
              onClick={() => setDrawerOpen(!drawerOpen)}
              sx={{ mr: 1 }}
              aria-label={drawerOpen ? 'Close settings drawer' : 'Open settings drawer'}
            >
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" component="div" noWrap>
              EarthSync
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            {!historicalMode && lastTransientInfo && (
              <TransientIndicator transientInfo={lastTransientInfo} />
            )}
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                border: `1px solid ${theme.palette.divider}`,
                borderRadius: 1,
                px: 1,
                py: 0.5,
              }}
              aria-live="polite"
            >
              {historicalMode ? (
                <HistoryIcon
                  sx={{ color: 'info.main', fontSize: '1.1rem' }}
                  aria-label="Historical Mode Active"
                />
              ) : wsStatus === WebSocketStatus.CONNECTED ? (
                <CheckCircleIcon
                  sx={{ color: 'success.main', fontSize: '1.1rem' }}
                  aria-label="WebSocket Connected"
                />
              ) : wsStatus === WebSocketStatus.CONNECTING ? (
                <CircularProgress size={16} color="inherit" aria-label="WebSocket Connecting" />
              ) : (
                <ErrorIcon
                  sx={{
                    color: wsStatus === WebSocketStatus.ERROR ? 'error.main' : 'warning.main',
                    fontSize: '1.1rem',
                  }}
                  aria-label="WebSocket Disconnected or Error"
                />
              )}
              <Typography variant="caption" sx={{ ml: 0.5, display: { xs: 'none', sm: 'block' } }}>
                {historicalMode
                  ? 'Historical Mode'
                  : wsStatus === WebSocketStatus.CONNECTED
                    ? 'Real-time Connected'
                    : wsStatus === WebSocketStatus.CONNECTING
                      ? 'Connecting...'
                      : wsStatus === WebSocketStatus.ERROR
                        ? 'Connection Error'
                        : 'Disconnected'}
              </Typography>
            </Box>
            <IconButton
              color="inherit"
              onClick={() => setDarkMode(!darkMode)}
              aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
          </Box>
        </Toolbar>
        {(isLoadingKey || isLoadingHistory) && (
          <LinearProgress sx={{ position: 'absolute', bottom: 0, left: 0, width: '100%' }} />
        )}
      </AppBar>

      <Box sx={{ display: 'flex', flexGrow: 1, mt: `${appBarHeight}px` }}>
        <ControlsDrawer
          drawerWidth={DRAWER_WIDTH}
          appBarHeight={appBarHeight}
          drawerOpen={drawerOpen}
          darkMode={darkMode}
          theme={theme}
          historicalMode={historicalMode}
          handleModeChange={handleModeChange}
          onLogout={onLogout}
          selectedDetector={selectedDetector}
          handleDetectorChange={handleDetectorChange}
          detectorOptions={detectorOptions}
          timeSteps={timeSteps}
          debouncedSetTimeSteps={debouncedSetTimeSteps}
          colorScale={colorScale}
          setColorScale={stableSetColorScale}
          normalize={normalize}
          setNormalize={stableSetNormalize}
          historicalHours={historicalHours}
          debouncedSetHistoricalHours={debouncedSetHistoricalHours}
          isLoadingData={isLoadingKey || isLoadingHistory}
          isTransitioning={isTransitioning}
          schumannPeaks={schumannPeaks} // Pass filtered peak array
          historicalTransientEvents={displayHistoricalTransients}
          globePoints={globePoints}
          handleGlobePointClick={handleGlobePointClick}
          handleGlobePointHover={handleGlobePointHover}
          plotType={plotType}
          setPlotType={stableSetPlotType}
        />

        <MainContent
          drawerOpen={drawerOpen}
          drawerWidth={DRAWER_WIDTH}
          appBarHeight={appBarHeight}
          margin={MAIN_CONTENT_MARGIN}
          theme={theme}
          isLoadingData={isLoadingKey || isLoadingHistory}
          isTransitioning={isTransitioning}
          plotType={plotType}
          plotData={plotData}
          layout={layout}
          displayData={displayData}
          spectrogramData={displaySpectrogramData}
          handlePlotHover={handlePlotHover}
          handlePlotClick={handlePlotClick}
          handlePlotRelayout={handlePlotRelayout}
          historicalMode={historicalMode}
          selectedDetector={selectedDetector}
          historicalPeakData={displayHistoricalPeaks}
          historicalTransientEvents={displayHistoricalTransients}
          darkMode={darkMode}
        />
      </Box>

      <Snackbar
        open={snackbarOpen}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbarSeverity}
          sx={{ width: '100%' }}
          variant="filled"
        >
          {appError || 'An unknown error occurred.'}
        </Alert>
      </Snackbar>
    </Box>
  );
});
SpectrogramPage.displayName = 'SpectrogramPage';

SpectrogramPage.propTypes = {
  token: PropTypes.string,
  onLogout: PropTypes.func.isRequired,
  darkMode: PropTypes.bool.isRequired,
  setDarkMode: PropTypes.func.isRequired,
  apiUrl: PropTypes.string.isRequired,
  wsUrl: PropTypes.string.isRequired,
};

export default App;
