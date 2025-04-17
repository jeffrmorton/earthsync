// client/src/App.js
/**
 * Main application component for EarthSync client (v1.1.14 - Phase 4e Impl).
 * Handles authentication, theme toggling, and renders the SpectrogramPage.
 * Displays historical transient details in chart tooltips.
 * Includes previous features and fixes.
 */
import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import Plotly from 'react-plotly.js';
import debounce from 'lodash.debounce';
import throttle from 'lodash.throttle';
import Globe from 'react-globe.gl';
import {
  AppBar, Toolbar, Typography, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText,
  IconButton, CssBaseline, Box, Slider, FormControl, FormLabel, FormControlLabel, Switch, useTheme,
  ThemeProvider, createTheme, Select, MenuItem, Divider, CircularProgress, Alert, Snackbar,
  LinearProgress, Paper, Tooltip
} from '@mui/material';
import {
  Menu as MenuIcon, Brightness4 as Brightness4Icon, Brightness7 as Brightness7Icon,
  BarChart as BarChartIcon, Logout as LogoutIcon, History as HistoryIcon,
  Public as GlobeIcon, Info as InfoIcon, Error as ErrorIcon, CheckCircle as CheckCircleIcon,
  Insights as InsightsIcon, ShowChart as ShowChartIcon,
  WarningAmber as WarningAmberIcon,
  Bolt as BoltIcon,
  Grain as GrainIcon,
  NotificationsActive as NotificationsActiveIcon
} from '@mui/icons-material';

// Load environment variables as defaults
const DEFAULT_API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:3000';
const DEFAULT_WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:3000';

// Helper to get value from localStorage or default
const getLocalStorage = (key, defaultValue) => {
  try {
    const saved = localStorage.getItem(key);
    return saved !== null ? JSON.parse(saved) : defaultValue;
  } catch (error) {
    console.error(`Error reading localStorage key “${key}”:`, error);
    return defaultValue;
  }
};

// Function to determine the working API and WS URLs with localhost fallback
async function determineServerUrls(defaultApiUrl, defaultWsUrl) {
  const fallbackApiUrl = 'http://localhost:3000';
  const fallbackWsUrl = 'ws://localhost:3000';
  try {
    await axios.get(`${defaultApiUrl}/health`, { timeout: 3000 });
    console.log(`Using default server URLs: API=${defaultApiUrl}, WS=${defaultWsUrl}`);
    return { apiUrl: defaultApiUrl, wsUrl: defaultWsUrl };
  } catch (err) {
    console.warn(`Default server URL (${defaultApiUrl}) not reachable: ${err.message}. Trying fallback...`);
    try {
       await axios.get(`${fallbackApiUrl}/health`, { timeout: 3000 });
       console.log(`Using fallback server URLs: API=${fallbackApiUrl}, WS=${fallbackWsUrl}`);
       return { apiUrl: fallbackApiUrl, wsUrl: fallbackWsUrl };
    } catch (fallbackErr) {
        console.error(`Fallback server URL (${fallbackApiUrl}) also not reachable: ${fallbackErr.message}.`);
        return { apiUrl: fallbackApiUrl, wsUrl: fallbackWsUrl, error: `Could not connect to API at ${defaultApiUrl} or ${fallbackApiUrl}` };
    }
  }
}


// --- Historical Peak Chart Component (Updated for Transient Details Tooltip) ---
const HistoricalPeakChart = React.memo(({ historicalPeakData, transientEvents, selectedDetector, darkMode }) => { // Changed prop name
    const theme = useTheme();
    const chartData = useMemo(() => {
        if (!historicalPeakData || !selectedDetector || selectedDetector === 'all') { return null; }
        const detectorData = historicalPeakData.find(d => d.detectorId === selectedDetector);
        if (!detectorData || !detectorData.peaks || detectorData.peaks.length === 0) { return null; }

        const freqData = []; const ampData = []; const qFactorData = [];

        // Group peaks by mode temporarily
        const modeRanges = {
          'Mode 1 (7.8Hz)': { min: 6, max: 10, data: [] },
          'Mode 2 (14Hz)': { min: 12, max: 17, data: [] },
          'Mode 3 (21Hz)': { min: 18, max: 24, data: [] },
          'Mode 4 (27Hz)': { min: 25, max: 30, data: [] },
          'Mode 5 (34Hz)': { min: 31, max: 37, data: [] },
          'Other': { min: -Infinity, max: Infinity, data: [] },
        };

        // 1. Group all peaks by mode, preserving timestamp and status
        detectorData.peaks.forEach(entry => {
          const ts = new Date(entry.ts);
          const peaksArray = Array.isArray(entry.peaks) ? entry.peaks : [entry.peaks];

          peaksArray.forEach(peak => {
              if (!peak || typeof peak.freq !== 'number') return;
              let assigned = false;
              for (const modeName in modeRanges) {
                  if (modeName !== 'Other' && peak.freq >= modeRanges[modeName].min && peak.freq < modeRanges[modeName].max) {
                      // Store the full peak object along with its timestamp
                      modeRanges[modeName].data.push({ ...peak, ts: ts });
                      assigned = true;
                      break;
                  }
              }
              if (!assigned) { modeRanges['Other'].data.push({ ...peak, ts: ts }); }
          });
        });

        const createTrace = (x, y, name, yaxis) => ({
          x, y, mode: 'lines+markers', type: 'scatter', name,
          marker: { size: 4 },
          // Style line breaks caused by null values
          connectgaps: false, // Ensure null values create gaps
          line: { width: 1.5 } // Slightly thicker line maybe
        });

        // 2. Process each mode to create plotting arrays with nulls for line breaks
        Object.keys(modeRanges).forEach(modeName => {
            const modeData = modeRanges[modeName].data;
            if (modeData.length === 0) return;

            // Sort data by timestamp first
            modeData.sort((a, b) => a.ts - b.ts);

            const plot_t = []; const plot_f = []; const plot_a = []; const plot_q = [];

            modeData.forEach((peak, index) => {
                const currentStatus = peak.trackStatus || 'unknown';

                // Insert null to break line if this peak is 'new' AND it's not the very first point
                if (currentStatus === 'new' && index > 0) {
                    plot_t.push(null);
                    plot_f.push(null);
                    plot_a.push(null);
                    plot_q.push(null);
                }

                // Add the actual peak data
                plot_t.push(peak.ts);
                plot_f.push(peak.freq);
                plot_a.push(peak.amp);
                plot_q.push(peak.qFactor); // Keep pushing qFactor even if null/undefined
            });

            // Add traces for this mode if data exists
            if (plot_t.length > 0) {
                freqData.push(createTrace(plot_t, plot_f, `${modeName}`, 'y1'));
                ampData.push(createTrace(plot_t, plot_a, `${modeName}`, 'y2'));
                qFactorData.push(createTrace(plot_t, plot_q, `${modeName}`, 'y3'));
            }
        });

        if (freqData.length === 0 && ampData.length === 0 && qFactorData.length === 0) { return null; }
        return { freqData, ampData, qFactorData };
    }, [historicalPeakData, selectedDetector]);

    // Phase 4e: Update transientAnnotations to use event details in hovertext
    const transientAnnotations = useMemo(() => {
      if (!transientEvents || transientEvents.length === 0) return [];
      return transientEvents.map(event => ({
          type: 'line',
          x0: event.ts, x1: event.ts, // Use timestamp from event object
          y0: 0, y1: 1,
          yref: 'paper',
          line: { color: theme.palette.warning.light, width: 1, dash: 'dot' },
          name: `Transient (${event.type})`, // Add type to name if desired
          showlegend: false,
          // Use details if available, otherwise construct a default message
          hovertext: `${event.type?.toUpperCase() || 'TRANSIENT'} @ ${new Date(event.ts).toLocaleString()}${event.details ? `: ${event.details}` : ''}`,
          hoverinfo: 'text'
      }));
    }, [transientEvents, theme.palette.warning.light]); // Depend on transientEvents

    const commonLayout = useMemo(() => ({
        autosize: true,
        margin: { l: 50, r: 20, t: 40, b: 40 },
        legend: { orientation: 'h', yanchor: 'bottom', y: -0.3, xanchor: 'center', x: 0.5 },
        paper_bgcolor: 'rgba(0,0,0,0)',
        plot_bgcolor: 'rgba(0,0,0,0)',
        font: { color: darkMode ? '#ffffff' : '#000000' },
        xaxis: {
            gridcolor: darkMode ? '#555555' : '#d3d3d3',
            linecolor: darkMode ? '#aaaaaa' : '#000000',
            tickfont: { color: darkMode ? '#ffffff' : '#000000' },
        },
        shapes: transientAnnotations, // Use updated annotations
        hovermode: 'closest'
    }), [darkMode, transientAnnotations]); // Depend on updated annotations

    const freqLayout = useMemo(() => ({
        ...commonLayout,
        title: { text: 'Peak Frequency', font: { size: 14 } },
        yaxis: {
            title: 'Frequency (Hz)',
            gridcolor: darkMode ? '#555555' : '#d3d3d3',
            linecolor: darkMode ? '#aaaaaa' : '#000000',
            zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
            tickfont: { color: darkMode ? '#ffffff' : '#000000' },
            titlefont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
         }
    }), [commonLayout, darkMode]);

    const ampLayout = useMemo(() => ({
        ...commonLayout,
        title: { text: 'Peak Amplitude', font: { size: 14 } },
        yaxis: {
            title: 'Amplitude',
            gridcolor: darkMode ? '#555555' : '#d3d3d3',
            linecolor: darkMode ? '#aaaaaa' : '#000000',
             zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
            tickfont: { color: darkMode ? '#ffffff' : '#000000' },
            titlefont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
        }
    }), [commonLayout, darkMode]);

    const qFactorLayout = useMemo(() => ({
       ...commonLayout,
        title: { text: 'Peak Q-Factor', font: { size: 14 } },
        yaxis: {
            title: 'Q-Factor',
             gridcolor: darkMode ? '#555555' : '#d3d3d3',
            linecolor: darkMode ? '#aaaaaa' : '#000000',
            zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
            tickfont: { color: darkMode ? '#ffffff' : '#000000' },
            titlefont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
            // range: [0, 50] // Example range cap
        }
    }), [commonLayout, darkMode]);

    if (!chartData) {
        return <Typography sx={{ p: 2, textAlign: 'center', color: 'text.secondary' }}>No historical peak data available for {selectedDetector}.</Typography>;
    }
    const plotConfig = { responsive: true, displaylogo: false, modeBarButtonsToRemove: ['lasso2d', 'select2d'] };

    return (
        <Paper elevation={2} sx={{ mt: 2, p: 1, bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.100', display: 'flex', flexDirection: 'column', height: '100%', width: '100%' }}>
             <Typography variant="h6" sx={{ textAlign: 'center', mb: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                 Historical Peaks: {selectedDetector}
                 {/* Use transientEvents prop for count */}
                 {transientEvents && transientEvents.length > 0 && (
                     <Tooltip title={`${transientEvents.length} transient event(s) detected in this period (dotted lines)`}>
                         <WarningAmberIcon sx={{ ml: 1, color: 'warning.main', fontSize: '1.1rem' }}/>
                     </Tooltip>
                 )}
             </Typography>
            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 1, flexGrow: 1, minHeight: 0 }}>
                <Box sx={{ flex: 1, minHeight: { xs: 200, md: 250 }, height: '100%' }}>
                     <Plotly data={chartData.freqData} layout={freqLayout} config={plotConfig} style={{ width: '100%', height: '100%' }} useResizeHandler />
                </Box>
                 <Box sx={{ flex: 1, minHeight: { xs: 200, md: 250 }, height: '100%' }}>
                     <Plotly data={chartData.ampData} layout={ampLayout} config={plotConfig} style={{ width: '100%', height: '100%' }} useResizeHandler />
                </Box>
                 <Box sx={{ flex: 1, minHeight: { xs: 200, md: 250 }, height: '100%' }}>
                     <Plotly data={chartData.qFactorData} layout={qFactorLayout} config={plotConfig} style={{ width: '100%', height: '100%' }} useResizeHandler />
                </Box>
            </Box>
        </Paper>
    );
});
HistoricalPeakChart.displayName = 'HistoricalPeakChart';

// --- Main App Component ---
function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [darkMode, setDarkMode] = useState(() => getLocalStorage('darkMode', true));
  const [isLoading, setIsLoading] = useState(false);
  const [serverUrls, setServerUrls] = useState(null);
  const [initializationError, setInitializationError] = useState(null);

  const theme = useMemo(() => createTheme({
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
            root: ({ theme }) => ({
              '&:hover': {
                backgroundColor: theme.palette.action.hover,
              },
            }),
          },
        },
    }
  }), [darkMode]);

  useEffect(() => { localStorage.setItem('darkMode', JSON.stringify(darkMode)); }, [darkMode]);
  useEffect(() => { if (token) { setIsAuthenticated(true); } else { setIsAuthenticated(false); } }, [token]);

  useEffect(() => {
    setIsLoading(true);
    determineServerUrls(DEFAULT_API_BASE_URL, DEFAULT_WS_URL)
      .then(urls => { setServerUrls(urls); if(urls.error) { setInitializationError(urls.error); } })
      .finally(() => setIsLoading(false));
  }, []);

  const handleAuthAction = async (e, action) => {
    e.preventDefault();
    if (!serverUrls || isLoading) return;
    setIsLoading(true);
    setAuthError(null);
    const url = action === 'register' ? `${serverUrls.apiUrl}/register` : `${serverUrls.apiUrl}/login`;
    try {
      const response = await axios.post(url, { username, password });
      if (action === 'register') {
        console.log('Registration successful:', response.data);
        setIsRegistering(false);
        setAuthError("Registration successful! Please log in.");
      } else {
        console.log('Login successful:', response.data);
        localStorage.setItem('token', response.data.token);
        setToken(response.data.token);
      }
    } catch (err) {
      console.error(`${action} failed:`, err);
      let message = err.message;
      if (err.response) {
        message = err.response.data?.error || `Server error: ${err.response.status}`;
      } else if (err.request) {
        message = "Network error. Could not reach server.";
      }
      setAuthError(`${action.charAt(0).toUpperCase() + action.slice(1)} failed: ${message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => { localStorage.removeItem('token'); setToken(null); };

  if (isLoading && !serverUrls) {
     return (
       <ThemeProvider theme={theme}>
         <CssBaseline />
         <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', flexDirection: 'column', gap: 2 }}>
           <CircularProgress />
           <Typography variant="h6">Connecting to EarthSync server...</Typography>
           {initializationError && <Alert severity="warning" sx={{mt: 2}}>{initializationError}</Alert>}
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
             <Typography>Please ensure the server is running and accessible. You might need to refresh the page later.</Typography>
           </Alert>
         </Box>
       </ThemeProvider>
     );
   }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {isAuthenticated && serverUrls ? (
        <SpectrogramPage
          token={token} onLogout={handleLogout} darkMode={darkMode} setDarkMode={setDarkMode}
          apiUrl={serverUrls.apiUrl} wsUrl={serverUrls.wsUrl}
        />
      ) : (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', p: 3 }}>
          <Box sx={{ padding: 3, maxWidth: 400, width: '100%', border: `1px solid ${theme.palette.divider}`, borderRadius: 1, bgcolor: 'background.paper' }}>
            <Typography variant="h5" component="h1" gutterBottom align="center">EarthSync {isRegistering ? 'Register' : 'Login'}</Typography>
            {authError && <Alert severity={authError.startsWith("Registration successful") ? "success" : "error"} sx={{ mb: 2 }}>{authError}</Alert>}
            <form onSubmit={(e) => handleAuthAction(e, isRegistering ? 'register' : 'login')}>
              <FormControl fullWidth margin="normal">
                <FormLabel htmlFor="username-input">Username</FormLabel>
                <input id="username-input" type="text" value={username} onChange={(e) => setUsername(e.target.value)} required style={{ padding: '10px', borderRadius: '4px', border: `1px solid ${theme.palette.divider}`, width: 'calc(100% - 22px)', background: theme.palette.background.default, color: theme.palette.text.primary }} aria-required="true"/>
              </FormControl>
              <FormControl fullWidth margin="normal">
                <FormLabel htmlFor="password-input">Password</FormLabel>
                <input id="password-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required style={{ padding: '10px', borderRadius: '4px', border: `1px solid ${theme.palette.divider}`, width: 'calc(100% - 22px)', background: theme.palette.background.default, color: theme.palette.text.primary }} aria-required="true"/>
              </FormControl>
              <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <button type="submit" style={{ padding: '10px 20px', borderRadius: '4px', cursor: isLoading ? 'not-allowed' : 'pointer', opacity: isLoading ? 0.6 : 1, border: 'none', backgroundColor: theme.palette.primary.main, color: theme.palette.primary.contrastText }} disabled={isLoading} aria-live="polite">
                  {isLoading ? <CircularProgress size={20} color="inherit" /> : (isRegistering ? 'Register' : 'Login')}
                </button>
                <button type="button" onClick={() => { setIsRegistering(!isRegistering); setAuthError(null); }} style={{ padding: '10px 20px', borderRadius: '4px', cursor: 'pointer', border: `1px solid ${theme.palette.divider}`, background: 'transparent', color: theme.palette.text.primary }} disabled={isLoading}>
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


// --- Spectrogram Page Component ---
const WebSocketStatus = { CONNECTING: 'connecting', CONNECTED: 'connected', DISCONNECTED: 'disconnected', ERROR: 'error' };

// Updated Transient Indicator Component for Phase 4b
const pulseKeyframes = `
  @keyframes pulse {
    0% { opacity: 0.6; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.15); }
    100% { opacity: 0.6; transform: scale(1); }
  }
`;
const TransientIndicator = ({ transientInfo }) => {
    let IconComponent = NotificationsActiveIcon; // Default pulsing icon
    let iconColor = 'warning.main';
    let title = "Transient event detected!";

    if (transientInfo?.type === 'broadband') {
        IconComponent = BoltIcon;
        title = `Broadband transient detected!`;
        iconColor = 'error.light'; // Use a different color maybe
    } else if (transientInfo?.type === 'narrowband') {
        IconComponent = GrainIcon;
        title = `Narrowband transient detected!`;
        iconColor = 'warning.light';
    }

    // Append details if available
    if (transientInfo?.details) {
        title += ` Details: ${transientInfo.details}`;
    }

    return (
        <>
            <style>{pulseKeyframes}</style>
            <Tooltip title={title}>
                <IconComponent sx={{
                    color: iconColor,
                    fontSize: '1.3rem',
                    ml: 1,
                    animation: 'pulse 1.5s infinite ease-in-out'
                }}/>
            </Tooltip>
        </>
    );
};


const SpectrogramPage = React.memo(({ token, onLogout, darkMode, setDarkMode, apiUrl, wsUrl }) => {
  const [spectrogramData, setSpectrogramData] = useState({});
  const [detectorActivity, setDetectorActivity] = useState({});
  const [peakData, setPeakData] = useState({});
  const [historicalPeakData, setHistoricalPeakData] = useState(null);
  // Phase 4e: Store full transient event objects {ts, type, details}
  const [historicalTransientEvents, setHistoricalTransientEvents] = useState([]);
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [appError, setAppError] = useState(null);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
  const [snackbarSeverity, setSnackbarSeverity] = useState('error');
  const [timeSteps, setTimeSteps] = useState(() => getLocalStorage('timeSteps', 60));
  const [historicalMode, setHistoricalMode] = useState(false);
  const [historicalHours, setHistoricalHours] = useState(1);
  const [colorScale, setColorScale] = useState(() => getLocalStorage('colorScale', 'Jet'));
  const [normalize, setNormalize] = useState(() => getLocalStorage('normalize', false));
  const [selectedDetector, setSelectedDetector] = useState(() => getLocalStorage('selectedDetector', 'all'));
  const [drawerOpen, setDrawerOpen] = useState(() => getLocalStorage('drawerOpen', true));
  const [isLoadingData, setIsLoadingData] = useState(false);
  const [isTransitioning, setIsTransitioning] = useState(false);
  const [wsStatus, setWsStatus] = useState(WebSocketStatus.DISCONNECTED);
  const [lastTransientInfo, setLastTransientInfo] = useState(null); // Phase 4b: Store transient details
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const recentTransientTimeoutRef = useRef(null);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);

  const globeRef = useRef();
  const appBarRef = useRef(null);
  const plotContainerRef = useRef(null);
  const theme = useTheme();
  const historicalModeRef = useRef(historicalMode);

   useEffect(() => { historicalModeRef.current = historicalMode; }, [historicalMode]);
   useEffect(() => { localStorage.setItem('drawerOpen', JSON.stringify(drawerOpen)); }, [drawerOpen]);
   useEffect(() => { localStorage.setItem('timeSteps', JSON.stringify(timeSteps)); }, [timeSteps]);
   useEffect(() => { localStorage.setItem('colorScale', JSON.stringify(colorScale)); }, [colorScale]);
   useEffect(() => { localStorage.setItem('normalize', JSON.stringify(normalize)); }, [normalize]);
   useEffect(() => { localStorage.setItem('selectedDetector', JSON.stringify(selectedDetector)); }, [selectedDetector]);
   useEffect(() => { return () => { if (recentTransientTimeoutRef.current) clearTimeout(recentTransientTimeoutRef.current); }; }, []);


  const drawerWidth = 300;
  const [appBarHeight, setAppBarHeight] = useState(64);
  const margin = 20;

  useEffect(() => {
    if (appBarRef.current) {
      const resizeObserver = new ResizeObserver(entries => { if (entries[0]) setAppBarHeight(entries[0].contentRect.height); });
      resizeObserver.observe(appBarRef.current);
      return () => resizeObserver.disconnect();
    }
  }, []);

  const stableSetTimeSteps = useCallback(setTimeSteps, []);
  const stableSetDetectorActivity = useCallback(setDetectorActivity, []);
  const stableSetPeakData = useCallback(setPeakData, []);
  const stableSetHistoricalPeakData = useCallback(setHistoricalPeakData, []);
  // Phase 4e: Rename state setter for clarity
  const stableSetHistoricalTransientEvents = useCallback(setHistoricalTransientEvents, []);


  // --- Throttled Spectrogram & Peak Data Update (Phase 4b) ---
  const updateSpectrogram = useMemo(() => throttle((newData) => {
        let transientInBatch = null; // Store transient info object if detected
        setSpectrogramData(prev => {
            const updated = { ...prev };
            newData.forEach(message => {
                if (!message.detectorId || !message.location || !Array.isArray(message.spectrogram)) return;
                const detectorId = message.detectorId;
                const incomingSpectrogramRows = message.spectrogram;
                if (!Array.isArray(incomingSpectrogramRows) || incomingSpectrogramRows.length === 0) return;
                const expectedPointsApprox = 1101;
                const validIncomingRows = incomingSpectrogramRows.filter(row => Array.isArray(row) && row.length > expectedPointsApprox - 10 && row.length < expectedPointsApprox + 10);
                if(validIncomingRows.length === 0) return;
                const currentRows = updated[detectorId] || [];
                const newRows = [...currentRows, ...validIncomingRows].slice(-stableSetTimeSteps(ts => ts));
                updated[detectorId] = newRows;

                // Check for transient info object
                if (message.transientInfo && message.transientInfo.type !== 'none') {
                    transientInBatch = message.transientInfo; // Store the info object
                    console.log("Transient Detected (WS):", message.transientInfo); // Log details
                }
            });
            return updated;
         });
        stableSetPeakData(prevPeaks => {
            const updatedPeaks = { ...prevPeaks };
            newData.forEach(message => {
                if (message.detectorId && Array.isArray(message.detectedPeaks)) {
                    updatedPeaks[message.detectorId] = message.detectedPeaks;
                }
            });
            return updatedPeaks;
         });
        newData.forEach(data => {
             if (!data.detectorId || !data.location) return;
             stableSetDetectorActivity(prev => ({ ...prev, [data.detectorId]: { lat: data.location.lat, lon: data.location.lon, lastUpdate: Date.now(), id: data.detectorId } }));
         });

         // Handle real-time transient indicator pulse and store details
         if (transientInBatch && !historicalModeRef.current) {
             setLastTransientInfo(transientInBatch); // Store details for tooltip
             if (recentTransientTimeoutRef.current) clearTimeout(recentTransientTimeoutRef.current);
             recentTransientTimeoutRef.current = setTimeout(() => {
                 setLastTransientInfo(null); // Clear details after pulse duration
                 recentTransientTimeoutRef.current = null;
             }, 5000); // Keep indicator pulsing/visible for 5 seconds
         }

    }, 500, { leading: true, trailing: true }), [stableSetTimeSteps, stableSetDetectorActivity, stableSetPeakData]);


   const showSnackbar = useCallback((message, severity = 'error') => {
        setAppError(message);
        setSnackbarSeverity(severity);
        setSnackbarOpen(true);
   }, []);

  // Fetch encryption key
  useEffect(() => {
    const fetchKey = async () => {
      if (!token) { setEncryptionKey(null); return; };
      setIsLoadingData(true); setAppError(null);
      try {
        console.log('Fetching encryption key...');
        const response = await axios.post(`${apiUrl}/key-exchange`, {}, { headers: { Authorization: `Bearer ${token}` } });
        console.log('Key exchange successful.');
        setEncryptionKey(response.data.key);
      } catch (err) {
        console.error('Key exchange failed:', err);
        const errorMsg = `Key Exchange Failed: ${err.response?.data?.error || (err.request ? 'Network Error' : err.message)}`;
        showSnackbar(errorMsg, 'error');
        setEncryptionKey(null);
      } finally { setIsLoadingData(false); }
    };
    fetchKey();
  }, [token, apiUrl, showSnackbar]);

  // Fetch Historical Data (Phase 4e - Extract full transient events)
  const fetchHistoricalData = useCallback(async () => {
    if (!token) return;
    setIsLoadingData(true); setIsTransitioning(true); setAppError(null);
    setSpectrogramData({}); setDetectorActivity({}); setPeakData({});
    stableSetHistoricalPeakData(null); stableSetHistoricalTransientEvents([]); // Reset events state
    let fetchError = null; let noDataMessage = null;

    try {
      console.log(`Fetching historical data: ${historicalHours} hours, detector: ${selectedDetector}`);
      const headers = { Authorization: `Bearer ${token}` };
      const params = selectedDetector !== 'all' ? { detectorId: selectedDetector } : {};

      // Fetch BOTH spectrogram history (which now includes transient events) and peak history
      const [specResponse, peakResponse] = await Promise.all([
        // Phase 4e: Use the spectrogram history endpoint to get transient events
        axios.get(`${apiUrl}/history/${historicalHours}`, { headers, params }).catch(err => { throw { type: 'spectrogram', error: err }; }),
        axios.get(`${apiUrl}/history/peaks/${historicalHours}`, { headers, params }).catch(err => { throw { type: 'peaks', error: err }; })
      ]);

      // Process Spectrograms (and Extract Transient Events)
      console.log('Historical spectrogram+transient data received:', specResponse.data?.length);
      const historicalSpecAndTransients = Array.isArray(specResponse.data) ? specResponse.data : [];
      const newSpectrogramData = {}; const newDetectorActivity = {};
      const collectedTransientEvents = []; // Temporary array for all detectors
      const expectedPointsApprox = 1101;

      historicalSpecAndTransients.forEach(dataEntry => {
          // Expect structure: { detectorId, location, spectrogram: [...], transientEvents: [{ts, type, details}, ...] }
          if (dataEntry.detectorId && dataEntry.location) {
              // Process Spectrogram part
              if(Array.isArray(dataEntry.spectrogram)) {
                    const rowsFromHistory = [];
                    for (let i = 0; i < dataEntry.spectrogram.length; i += expectedPointsApprox) {
                        const row = dataEntry.spectrogram.slice(i, i + expectedPointsApprox);
                        if (row.length >= expectedPointsApprox - 10 && row.length <= expectedPointsApprox + 10) {
                            if (row.length < expectedPointsApprox) row.push(...Array(expectedPointsApprox - row.length).fill(0));
                            if (row.length > expectedPointsApprox) row.length = expectedPointsApprox;
                            rowsFromHistory.push(row);
                        } else if (rowsFromHistory.length === 0 && i + expectedPointsApprox >= dataEntry.spectrogram.length) {
                            row.push(...Array(expectedPointsApprox - row.length).fill(0));
                            rowsFromHistory.push(row);
                        }
                    }
                    if (rowsFromHistory.length > 0) {
                       newSpectrogramData[dataEntry.detectorId] = (newSpectrogramData[dataEntry.detectorId] || []).concat(rowsFromHistory).slice(-stableSetTimeSteps(ts => ts));
                    }
              }
              // Update Detector Activity
              newDetectorActivity[dataEntry.detectorId] = { lat: dataEntry.location.lat, lon: dataEntry.location.lon, lastUpdate: Date.now(), id: dataEntry.detectorId };

              // Phase 4e: Collect transient events if they exist in the response
              if (Array.isArray(dataEntry.transientEvents)) {
                  // Add detectorId to each event for filtering later
                  collectedTransientEvents.push(...dataEntry.transientEvents.map(ev => ({...ev, detectorId: dataEntry.detectorId})));
              }
          }
       });
       setSpectrogramData(newSpectrogramData);
       setDetectorActivity(newDetectorActivity);
       if (Object.keys(newSpectrogramData).length === 0) noDataMessage = `No historical spectrogram data found`;

      // Process Peaks (No change needed here, peak data is separate)
      console.log('Historical peak data received:', peakResponse.data?.length);
      const historicalPeaksRaw = Array.isArray(peakResponse.data) ? peakResponse.data : [];
      stableSetHistoricalPeakData(historicalPeaksRaw);
      const latestPeakData = {};
      historicalPeaksRaw.forEach(detHistory => {
          if (detHistory.detectorId && Array.isArray(detHistory.peaks) && detHistory.peaks.length > 0) {
              const lastEntry = detHistory.peaks[detHistory.peaks.length - 1];
              const lastEntryPeaks = Array.isArray(lastEntry.peaks) ? lastEntry.peaks : [];
              latestPeakData[detHistory.detectorId] = lastEntryPeaks;
          }
      });
      setPeakData(latestPeakData);

      // Phase 4e: Store the collected transient events (filter by selected detector if needed)
      const relevantTransientEvents = selectedDetector === 'all'
          ? collectedTransientEvents
          : collectedTransientEvents.filter(event => event.detectorId === selectedDetector);
      stableSetHistoricalTransientEvents(relevantTransientEvents.sort((a,b) => a.ts - b.ts)); // Store sorted events
      if (relevantTransientEvents.length > 0) {
           console.log(`Stored ${relevantTransientEvents.length} historical transient events for detector ${selectedDetector}.`);
      }


      if (historicalPeaksRaw.length === 0 && Object.keys(newSpectrogramData).length === 0) {
           noDataMessage = `No historical spectrogram or peak data found`;
      } else if (historicalPeaksRaw.length === 0) {
           noDataMessage = noDataMessage ? `${noDataMessage} or peak data found` : `No historical peak data found`;
      }
      if (noDataMessage) noDataMessage += ` for ${selectedDetector === 'all' ? 'any detector' : `detector ${selectedDetector}`} in the last ${historicalHours}h.`;

    } catch (errWrapper) {
        const err = errWrapper.error || errWrapper;
        const type = errWrapper.type || 'general';
        console.error(`Historical ${type} data fetch error:`, err);
        fetchError = `Failed to fetch historical ${type} data: ${err.response?.data?.error || (err.request ? 'Network Error' : err.message)}`;
    } finally {
      setIsLoadingData(false); setIsTransitioning(false);
      if (fetchError) showSnackbar(fetchError, 'error');
      else if (noDataMessage) showSnackbar(noDataMessage, 'info');
    }
    // Update dependencies for the new state setter name
  }, [token, apiUrl, historicalHours, selectedDetector, stableSetTimeSteps, stableSetHistoricalPeakData, stableSetHistoricalTransientEvents, showSnackbar]);


   // WebSocket Connection Management Effect
   useEffect(() => {
        let currentWs = null;
        const clearReconnectTimeout = () => { if (reconnectTimeoutRef.current) { clearTimeout(reconnectTimeoutRef.current); reconnectTimeoutRef.current = null; } };
        const scheduleReconnect = (attempt) => {
            clearReconnectTimeout();
            const delay = Math.min(1000 * Math.pow(2, attempt), 60000);
            console.log(`Scheduling WS reconnect in ${delay / 1000} seconds... (Attempt ${attempt + 1})`);
            reconnectTimeoutRef.current = setTimeout(() => setReconnectAttempt(prev => prev + 1), delay);
        };

        if (historicalMode) {
            console.log("Switching to historical mode..."); setIsTransitioning(true);
            clearReconnectTimeout();
            if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close(1000, 'Switching to historical mode'); wsRef.current = null; }
            setWsStatus(WebSocketStatus.DISCONNECTED); setReconnectAttempt(0);
            setLastTransientInfo(null); // Clear transient indicator
            if (recentTransientTimeoutRef.current) clearTimeout(recentTransientTimeoutRef.current);
        } else if (token && encryptionKey) {
            if (!wsRef.current && wsStatus !== WebSocketStatus.CONNECTING) {
                console.log(`Attempting WS Connection (Attempt: ${reconnectAttempt})...`);
                setWsStatus(WebSocketStatus.CONNECTING); setIsTransitioning(true); setAppError(null);
                 if (reconnectAttempt === 0) { setSpectrogramData({}); setDetectorActivity({}); setPeakData({}); stableSetHistoricalPeakData(null); stableSetHistoricalTransientEvents([]); } // Use correct state setter

                currentWs = new WebSocket(`${wsUrl}/?token=${token}`); wsRef.current = currentWs;

                currentWs.onopen = () => {
                    if (wsRef.current === currentWs) { console.log('WebSocket connected.'); setWsStatus(WebSocketStatus.CONNECTED); setReconnectAttempt(0); clearReconnectTimeout(); setIsTransitioning(false); }
                };
                currentWs.onmessage = (event) => {
                     if (wsRef.current !== currentWs) return;
                     try {
                        const [encrypted, iv] = event.data.split(':'); if (!encrypted || !iv) throw new Error("Invalid message format");
                        const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
                        const decrypted = CryptoJS.AES.decrypt({ ciphertext: CryptoJS.enc.Base64.parse(encrypted) }, keyWordArray, { iv: CryptoJS.enc.Base64.parse(iv), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
                        const messageJson = decrypted.toString(CryptoJS.enc.Utf8); if (!messageJson) throw new Error("Decryption resulted in empty message");
                        const messageData = JSON.parse(messageJson);
                        // Pass the full message object, which includes transientInfo and trackStatus in peaks
                        updateSpectrogram([messageData]);
                     } catch (err) { console.error('WebSocket message processing error:', err); showSnackbar(`WebSocket Data Error: ${err.message}. Check console.`, 'error'); }
                };
                currentWs.onerror = (error) => { console.error('WebSocket error event:', error); if (wsRef.current === currentWs) { setWsStatus(WebSocketStatus.ERROR); setIsTransitioning(false); showSnackbar('WebSocket connection error.', 'error'); }};
                currentWs.onclose = (event) => {
                    console.log(`WebSocket closed: Code=${event.code}, Reason=${event.reason || 'N/A'}`);
                     if (wsRef.current !== currentWs) return;
                     wsRef.current = null; setWsStatus(WebSocketStatus.DISCONNECTED); setIsTransitioning(false);
                    if (event.code !== 1000 && !historicalModeRef.current) {
                       showSnackbar(`WebSocket disconnected (${event.code}). Attempting to reconnect...`, 'warning');
                       scheduleReconnect(reconnectAttempt);
                    } else { setReconnectAttempt(0); if (event.code === 1000) setAppError(null); }
                };
            }
        } else {
             console.log("WebSocket prerequisites (token/key) not met."); clearReconnectTimeout();
             if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close(1000, 'Token or Key missing'); wsRef.current = null; }
             setWsStatus(WebSocketStatus.DISCONNECTED); setIsTransitioning(false); setReconnectAttempt(0);
        }

        return () => { // Cleanup
            console.log("Cleaning up WebSocket effect..."); clearReconnectTimeout();
            if (currentWs) { currentWs.onclose = null; currentWs.onerror = null; currentWs.close(1000, 'Component unmounting'); }
            if (wsRef.current === currentWs) { wsRef.current = null; }
            if (recentTransientTimeoutRef.current) clearTimeout(recentTransientTimeoutRef.current);
        };
   // Update dependencies for the new state setter name
   }, [historicalMode, token, encryptionKey, wsUrl, updateSpectrogram, reconnectAttempt, stableSetHistoricalPeakData, stableSetHistoricalTransientEvents, showSnackbar]);


  // --- Memoized Plot Data & Layout ---
   const { xLabels, yLabels, displayData, minAmplitude, maxAmplitude } = useMemo(() => {
     const numPointsApprox = 1101;
     const calculatedXLabels = Array.from({ length: numPointsApprox }, (_, i) => (i * 5 * (55 / 5500)).toFixed(2));
     const sourceRows = selectedDetector === 'all' ? Object.values(spectrogramData).flat() : spectrogramData[selectedDetector] || [];
     const validRows = sourceRows.filter(row => Array.isArray(row) && row.length > numPointsApprox - 10 && row.length < numPointsApprox + 10);
     const recentRows = validRows.slice(-timeSteps);
     const finalRows = recentRows.map(row => {
         if (row.length === numPointsApprox) return row;
         const newRow = [...row];
         if (row.length < numPointsApprox) { newRow.push(...Array(numPointsApprox - row.length).fill(0)); }
         else { newRow.length = numPointsApprox; }
         return newRow;
     });
     const paddedRows = finalRows.length < timeSteps ? [...Array(timeSteps - finalRows.length).fill(Array(numPointsApprox).fill(0)), ...finalRows] : finalRows;
     const calculatedYLabels = paddedRows.map((_, i) => { const secondsAgo = (paddedRows.length - 1 - i) * 5; return secondsAgo === 0 ? 'Now' : `-${secondsAgo}s`; });
     const normalizeFn = (data) => { const vals=data.flat().filter(v=>typeof v==='number'&&!isNaN(v)); if(vals.length===0) return data; const min=Math.min(...vals); const max=Math.max(...vals); const range=max-min; if(range===0) return data.map(r=>r.map(()=>0)); return data.map(r=>r.map(v=>typeof v==='number'&&!isNaN(v)?((v-min)/range)*15:0)); };
     const finalDisplayData = normalize ? normalizeFn(paddedRows) : paddedRows;
     const allFlatValues = finalDisplayData.flat().filter(v => typeof v === 'number' && !isNaN(v));
     const calculatedMinAmplitude = allFlatValues.length ? Math.max(0, Math.min(...allFlatValues)) : 0;
     const amplitudeCap = normalize ? 16 : 25; const calculatedMaxAmplitude = allFlatValues.length ? Math.min(amplitudeCap, Math.max(...allFlatValues) + 1) : amplitudeCap;
     return { xLabels: calculatedXLabels, yLabels: calculatedYLabels, displayData: finalDisplayData, minAmplitude: calculatedMinAmplitude, maxAmplitude: calculatedMaxAmplitude };
   }, [spectrogramData, selectedDetector, timeSteps, normalize]);

   const plotData = useMemo(() => [{ z: displayData, x: xLabels, y: yLabels, type: 'surface', colorscale: colorScale, showscale: true, colorbar: { title: 'Amplitude', titleside: 'right', tickfont: { color: darkMode ? '#ffffff' : '#000000' }, titlefont: { color: darkMode ? '#ffffff' : '#000000' } }, contours: { z: { show: true, usecolormap: true, highlightcolor: "#42f462", project: { z: true } } }, lighting: { ambient: 0.8, diffuse: 0.8, specular: 0.1 }, lightposition: { x: 100, y: 100, z: 2000 } }], [displayData, xLabels, yLabels, colorScale, darkMode]);
   const layout = useMemo(() => ({ title: { text: `Schumann Resonance ${selectedDetector === 'all' ? '(All Detectors)' : `(${selectedDetector})`} ${historicalMode ? `(Past ${historicalHours}h)` : '(Real-time)'}`, font: { size: 16, color: darkMode ? '#ffffff' : '#000000' }, y: 0.98 }, scene: { xaxis: { title: { text: 'Frequency (Hz)', font: { size: 12, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' }, gridcolor: darkMode ? '#555555' : '#d3d3d3', zerolinecolor: darkMode ? '#aaaaaa' : '#000000', backgroundcolor: "rgba(0,0,0,0)" }, yaxis: { title: { text: 'Time', font: { size: 12, color: darkMode ? '#ffffff' : '#000000' } }, tickvals: yLabels.filter((_, i) => i % Math.max(1, Math.floor(yLabels.length / 10)) === 0), ticktext: yLabels.filter((_, i) => i % Math.max(1, Math.floor(yLabels.length / 10)) === 0), tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' }, gridcolor: darkMode ? '#555555' : '#d3d3d3', zerolinecolor: darkMode ? '#aaaaaa' : '#000000', backgroundcolor: "rgba(0,0,0,0)" }, zaxis: { title: { text: 'Amplitude', font: { size: 12, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' }, range: [minAmplitude, maxAmplitude], gridcolor: darkMode ? '#555555' : '#d3d3d3', zerolinecolor: darkMode ? '#aaaaaa' : '#000000', backgroundcolor: "rgba(0,0,0,0)" }, camera: { eye: { x: 1.5, y: 1.5, z: 0.8 } }, aspectmode: 'cube' }, margin: { t: 40, r: margin, b: margin, l: margin }, autosize: true, paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)', font: { color: darkMode ? '#ffffff' : '#000000' }, modebar: { orientation: 'v', bgcolor: 'rgba(0,0,0,0.1)', color: darkMode ? '#ffffff' : '#000000', activecolor: theme.palette.primary.main } }), [darkMode, minAmplitude, maxAmplitude, yLabels, selectedDetector, historicalMode, historicalHours, theme.palette.primary.main, margin]);

  // --- Memoized Globe data & Options ---
   const globePoints = useMemo(() => Object.values(detectorActivity).map(({ lat, lon, lastUpdate, id }) => {
       const timeSinceUpdate = Date.now() - lastUpdate; const isActive = !historicalMode && (timeSinceUpdate < 10000);
       const sizePulse = isActive ? (timeSinceUpdate < 2000 ? 0.6 : 0.5) : 0.2;
       const latestPeaks = peakData[id] || [];
       const avgAmplitude = latestPeaks.length > 0 ? latestPeaks.reduce((sum, p) => sum + p.amp, 0) / latestPeaks.length : 0;
       const baseColor = isActive ? 'red' : (historicalMode ? 'grey' : 'blue');
       let pointColor = baseColor;
       if (isActive && avgAmplitude > 10) pointColor = avgAmplitude > 15 ? 'darkred' : 'indianred';
       else if (!isActive && !historicalMode && avgAmplitude > 5) pointColor = 'cornflowerblue';
       const peakInfo = latestPeaks.length > 0 ? `\nPeaks: ${latestPeaks.map(p => `${p.freq.toFixed(1)}Hz (A:${p.amp.toFixed(1)}, Q:${p.qFactor ? p.qFactor.toFixed(1) : 'N/A'}, S:${p.trackStatus ? p.trackStatus.charAt(0) : '?'})`).join(', ')}` : '';
       return { lat, lng: lon, size: sizePulse, color: pointColor, label: `Detector: ${id}\nCoords: ${lat.toFixed(2)}, ${lon.toFixed(2)}\nStatus: ${isActive ? 'Active' : (historicalMode ? 'Historical' : 'Idle')}${peakInfo}`, id };
   }), [detectorActivity, historicalMode, peakData]);

   const detectorOptions = useMemo(() => [ { id: 'all', label: 'All Detectors' }, ...Object.keys(detectorActivity).sort().map(id => ({ id, label: id })) ], [detectorActivity]);

  // --- Debounced Sliders ---
  const debouncedSetTimeSteps = useCallback(debounce((value) => stableSetTimeSteps(Math.max(6, Math.floor(value / 5))), 300), [stableSetTimeSteps]);
  const debouncedSetHistoricalHours = useCallback(debounce((value) => setHistoricalHours(value), 300), [setHistoricalHours]);

  // --- Interaction Handlers ---
   const handlePlotHover = useCallback((data) => { /* Placeholder */ }, []);
   const handlePlotClick = useCallback((data) => { if(data.points.length > 0) { showSnackbar(`Plot Point Clicked: Freq=${data.points[0].x}, Time=${data.points[0].y}, Amp=${data.points[0].z.toFixed(2)}`, 'info'); } }, [showSnackbar]);
   const handlePlotRelayout = useCallback((eventData) => { /* Placeholder */ }, []);
   const handleGlobePointClick = useCallback((point) => {
       if (point?.id && detectorOptions.some(opt => opt.id === point.id)) {
           setSelectedDetector(point.id);
           showSnackbar(`Selected detector ${point.id} from globe.`, 'info');
       } else {
            console.log("Clicked on globe background or invalid point:", point);
       }
   }, [detectorOptions, showSnackbar, setSelectedDetector]);
   const handleGlobePointHover = useCallback((point) => { /* Placeholder */ }, []);
   const handleCloseSnackbar = useCallback((event, reason) => { if (reason === 'clickaway') return; setSnackbarOpen(false); }, []);
   const handleModeChange = (newMode) => {
       if (newMode === historicalMode) return;
       setHistoricalMode(newMode);
       setLastTransientInfo(null); // Clear transient indicator info
       if (recentTransientTimeoutRef.current) clearTimeout(recentTransientTimeoutRef.current);

       if (newMode) {
           fetchHistoricalData();
           setSpectrogramData({}); setDetectorActivity({}); setPeakData({});
       } else {
           setSpectrogramData({}); setDetectorActivity({}); setPeakData({});
           stableSetHistoricalPeakData(null); stableSetHistoricalTransientEvents([]); // Clear events state too
       }
    };
   const handleDetectorChange = (event) => {
       const newDetector = event.target.value;
       if (newDetector === selectedDetector) return;
       setSelectedDetector(newDetector);
       if (historicalMode) {
           fetchHistoricalData();
       }
   };

  const showTopLoader = isLoadingData || isTransitioning;
  const currentPeakInfo = useMemo(() => {
    if (selectedDetector === 'all') return null;
    const peaks = peakData[selectedDetector];
    if (!peaks || peaks.length === 0) return "No peaks detected.";
    return peaks.map(p => `Freq: ${p.freq.toFixed(2)} Hz, Amp: ${p.amp.toFixed(1)}, Q: ${p.qFactor ? p.qFactor.toFixed(1) : 'N/A'}, S: ${p.trackStatus ? p.trackStatus.charAt(0) : '?'}`).join(' | ');
  }, [peakData, selectedDetector]);

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden', bgcolor: 'background.default' }}>
      {/* --- App Bar --- */}
      <AppBar ref={appBarRef} position="fixed" sx={{ width: '100%', zIndex: (theme) => theme.zIndex.drawer + 1, bgcolor: 'background.paper', color: 'text.primary' }}>
        <Toolbar>
          <IconButton color="inherit" edge="start" onClick={() => setDrawerOpen(!drawerOpen)} sx={{ mr: 2 }} aria-label={drawerOpen ? "Close settings drawer" : "Open settings drawer"}><MenuIcon /></IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>EarthSync</Typography>
           {/* Phase 4b: Real-time Transient Indicator (shows details on hover) */}
           {!historicalMode && lastTransientInfo && <TransientIndicator transientInfo={lastTransientInfo} />}
           <Box sx={{ display: 'flex', alignItems: 'center', mr: 2, border: `1px solid ${theme.palette.divider}`, borderRadius: 1, px: 1, py: 0.5 }} aria-live="polite">
             {historicalMode ? <HistoryIcon sx={{ color: 'info.main', fontSize: '1.1rem' }} aria-label="Historical Mode Active"/>
              : wsStatus === WebSocketStatus.CONNECTED ? <CheckCircleIcon sx={{ color: 'success.main', fontSize: '1.1rem' }} aria-label="WebSocket Connected"/>
              : wsStatus === WebSocketStatus.CONNECTING ? <CircularProgress size={16} color="inherit" aria-label="WebSocket Connecting"/>
              : <ErrorIcon sx={{ color: wsStatus === WebSocketStatus.ERROR ? 'error.main' : 'warning.main', fontSize: '1.1rem' }} aria-label="WebSocket Disconnected or Error"/> }
             <Typography variant="caption" sx={{ ml: 0.5, display: { xs: 'none', sm: 'block' } }}>
                 {historicalMode ? 'Historical Mode' : wsStatus === WebSocketStatus.CONNECTED ? 'Real-time Connected' : wsStatus === WebSocketStatus.CONNECTING ? 'Connecting...' : wsStatus === WebSocketStatus.ERROR ? 'Connection Error' : 'Disconnected'}
             </Typography>
           </Box>
          <IconButton color="inherit" onClick={() => setDarkMode(!darkMode)} aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}> {darkMode ? <Brightness7Icon /> : <Brightness4Icon />} </IconButton>
        </Toolbar>
         {showTopLoader && <LinearProgress sx={{ position: 'absolute', bottom: 0, left: 0, width: '100%' }} />}
      </AppBar>

      <Box sx={{ display: 'flex', flexGrow: 1, mt: `${appBarHeight}px` }}>
        {/* --- Drawer --- */}
        <Drawer variant="persistent" anchor="left" open={drawerOpen}
          sx={{ width: drawerWidth, flexShrink: 0, '& .MuiDrawer-paper': { width: drawerWidth, boxSizing: 'border-box', overflowX: 'hidden', mt: `${appBarHeight}px`, height: `calc(100% - ${appBarHeight}px)`, transition: theme.transitions.create('width', { easing: theme.transitions.easing.sharp, duration: drawerOpen ? theme.transitions.duration.enteringScreen : theme.transitions.duration.leavingScreen }), display: 'flex', flexDirection: 'column', borderRight: `1px solid ${theme.palette.divider}` } }}
        >
          <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
            <List>
               <ListItem disablePadding> <ListItemButton onClick={() => handleModeChange(false)} selected={!historicalMode} aria-current={!historicalMode ? "page" : "false"}> <ListItemIcon><BarChartIcon /></ListItemIcon> <ListItemText primary="Real-time Data" /> </ListItemButton> </ListItem>
               <ListItem disablePadding> <ListItemButton onClick={() => handleModeChange(true)} selected={historicalMode} aria-current={historicalMode ? "page" : "false"}> <ListItemIcon><HistoryIcon /></ListItemIcon> <ListItemText primary="Historical Data" /> </ListItemButton> </ListItem>
               <ListItem disablePadding> <ListItemButton onClick={onLogout}> <ListItemIcon><LogoutIcon /></ListItemIcon> <ListItemText primary="Logout" /> </ListItemButton> </ListItem>
            </List>
            <Divider />
            <Box sx={{ p: 2 }}>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <FormLabel id="detector-select-label" sx={{ mb: 0.5 }}>Detector</FormLabel>
                <Select labelId="detector-select-label" value={selectedDetector} onChange={handleDetectorChange} size="small" aria-describedby="detector-select-desc">
                  {detectorOptions.map(({ id, label }) => (<MenuItem key={id} value={id}>{label}</MenuItem>))}
                </Select>
                <Typography variant="caption" id="detector-select-desc" sx={{ mt: 0.5, color: 'text.secondary' }}>Select detector(s) to display.</Typography>
              </FormControl>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <FormLabel id="time-window-label" sx={{ mb: 0.5 }}>Time Window (seconds)</FormLabel>
                <Slider aria-labelledby="time-window-label" value={timeSteps * 5} onChange={(_, val) => debouncedSetTimeSteps(val)} min={30} max={600} step={5} marks valueLabelDisplay="auto" size="small" />
              </FormControl>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <FormLabel id="colorscale-label" sx={{ mb: 0.5 }}>Color Scale</FormLabel>
                <Select labelId="colorscale-label" value={colorScale} onChange={(e) => setColorScale(e.target.value)} size="small"> <MenuItem value="Jet">Jet</MenuItem><MenuItem value="Greys">Greys</MenuItem><MenuItem value="Viridis">Viridis</MenuItem><MenuItem value="Plasma">Plasma</MenuItem> </Select>
              </FormControl>
              <FormControlLabel control={<Switch checked={normalize} onChange={() => setNormalize(!normalize)} />} label="Normalize Amplitude" sx={{ mb: 1, display: 'block' }}/>
              {historicalMode && ( <FormControl fullWidth sx={{ mb: 2 }}> <FormLabel id="historical-hours-label" sx={{ mb: 0.5 }}>Historical Hours</FormLabel> <Slider aria-labelledby="historical-hours-label" value={historicalHours} onChange={(_, val) => debouncedSetHistoricalHours(val)} min={1} max={72} step={1} marks valueLabelDisplay="auto" size="small"/> </FormControl> )}
               {selectedDetector !== 'all' && ( /* Peak Info Box */
                   <Box sx={{ mt: 2, p: 1, border: `1px dashed ${theme.palette.divider}`, borderRadius: 1 }}>
                       <Typography variant="caption" sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                           <InsightsIcon sx={{ fontSize: '1rem', mr: 0.5 }}/>
                           {historicalMode ? 'Latest Hist.' : 'Detected'} Peaks ({selectedDetector}):
                           {/* Phase 4e: Use historicalTransientEvents for count */}
                           {historicalMode && historicalTransientEvents.length > 0 && (
                                <Tooltip title={`${historicalTransientEvents.length} transient event(s) detected in this period`}>
                                   <WarningAmberIcon sx={{ ml: 1, color: 'warning.main', fontSize: '1.1rem' }}/>
                                </Tooltip>
                           )}
                       </Typography>
                       <Typography variant="caption" sx={{ display: 'block', wordBreak: 'break-word' }}> {currentPeakInfo || (isTransitioning ? 'Loading...' : 'N/A')} </Typography>
                   </Box>
               )}
              {(isLoadingData || isTransitioning) && (<Box sx={{ display: 'flex', alignItems: 'center', mt: 1, color: theme.palette.text.secondary }}><CircularProgress size={16} sx={{ mr: 1 }} /><Typography variant="caption">Loading data...</Typography></Box>)}
            </Box>
          </Box>
          {/* Globe */}
          <Box sx={{ p: 1, display: 'flex', justifyContent: 'center', borderTop: `1px solid ${theme.palette.divider}` }}>
             {drawerOpen && (
                 <Globe
                     ref={globeRef}
                     globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
                     bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
                     backgroundColor='rgba(0,0,0,0)'
                     pointsData={globePoints}
                     pointLat="lat"
                     pointLng="lng"
                     pointColor="color"
                     pointRadius={0.25}
                     pointAltitude="size"
                     pointLabel="label"
                     onPointClick={handleGlobePointClick}
                     onPointHover={handleGlobePointHover}
                     width={drawerWidth - 16}
                     height={drawerWidth - 16}
                     atmosphereColor={darkMode ? 'lightblue' : 'dodgerblue'}
                     atmosphereAltitude={0.25}
                     animateIn={true}
                     pointResolution={4}
                 />
             )}
           </Box>
        </Drawer>

        {/* --- Main Content Area (Spectrogram + Historical Charts) --- */}
        <Box component="main" ref={plotContainerRef}
          sx={{
              flexGrow: 1,
              width: `calc(100% - ${drawerOpen ? drawerWidth : 0}px)`,
              height: `calc(100vh - ${appBarHeight}px)`,
              padding: `${margin}px`,
              boxSizing: 'border-box',
              transition: theme.transitions.create(['margin', 'width'], { easing: theme.transitions.easing.sharp, duration: drawerOpen ? theme.transitions.duration.enteringScreen : theme.transitions.duration.leavingScreen }),
              marginLeft: drawerOpen ? 0 : `-${drawerWidth}px`,
              position: 'relative',
              display: 'flex',
              flexDirection: 'column'
          }}
        >
           {/* Spectrogram Plot */}
           <Box sx={{
                height: historicalMode && selectedDetector !== 'all' && historicalPeakData && historicalPeakData.some(d => d.detectorId === selectedDetector && d.peaks?.length > 0) ? '60%' : '100%',
                minHeight: 300,
                position: 'relative',
                flexShrink: 0
           }}>
               {(isLoadingData || isTransitioning) && !Object.keys(spectrogramData).length ? (
                 <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', flexDirection: 'column', gap: 1 }}> <CircularProgress /> <Typography sx={{ mt: 2 }}>Loading Spectrogram Data...</Typography> </Box>
               ) : (displayData && displayData.length > 0 && displayData[0]?.length > 0) ? (
                 <Box className="plot-container fade-in" sx={{ opacity: isTransitioning ? 0.5 : 1, transition: 'opacity 0.3s ease-in-out', height: '100%' }}>
                     <Plotly data={plotData} layout={layout} revision={Date.now()} style={{ width: '100%', height: '100%' }} useResizeHandler config={{ responsive: true, displayModeBar: true, displaylogo: false, modeBarButtonsToRemove: ['lasso2d', 'select2d'], willReadFrequently: true }} onHover={handlePlotHover} onClick={handlePlotClick} onRelayout={handlePlotRelayout}/>
                 </Box>
               ) : ( <Typography sx={{ textAlign: 'center', mt: 4 }}>No spectrogram data available for selected detector(s).</Typography> )
              }
           </Box>

           {/* Historical Peak Charts Wrapper Box */}
           {historicalMode && selectedDetector !== 'all' && historicalPeakData && historicalPeakData.some(d => d.detectorId === selectedDetector && d.peaks?.length > 0) && (
                // Removed display:flex from this wrapper Box
                <Box sx={{ height: 'auto', mt: 2, flexGrow: 1, minHeight: 0 }}>
                   {/* Phase 4e: Pass historicalTransientEvents */}
                   <HistoricalPeakChart
                       historicalPeakData={historicalPeakData}
                       transientEvents={historicalTransientEvents} // Pass full events
                       selectedDetector={selectedDetector}
                       darkMode={darkMode}
                   />
                </Box>
            )}
        </Box>
      </Box>

       {/* --- Snackbar for Notifications --- */}
      <Snackbar open={snackbarOpen} autoHideDuration={6000} onClose={handleCloseSnackbar} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
         <Alert onClose={handleCloseSnackbar} severity={snackbarSeverity} sx={{ width: '100%' }} variant="filled">{appError || "An unknown error occurred."}</Alert>
       </Snackbar>
    </Box>
  );
});

SpectrogramPage.displayName = 'SpectrogramPage';
export default App;