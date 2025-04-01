/**
 * Main application component for EarthSync client.
 * Handles authentication, theme toggling, and renders the SpectrogramPage.
 * Includes improvements: Loading/Feedback, Plot/Globe Interaction placeholders, Accessibility hints.
 * Fixes WebSocket reconnect loop.
 * Fixes client data processing logic in updateSpectrogram.
 * UX Improvements: State persistence, Smoother transitions.
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
  LinearProgress
} from '@mui/material';
import {
  Menu as MenuIcon, Brightness4 as Brightness4Icon, Brightness7 as Brightness7Icon,
  BarChart as BarChartIcon, Logout as LogoutIcon, History as HistoryIcon,
  Public as GlobeIcon, Info as InfoIcon, Error as ErrorIcon, CheckCircle as CheckCircleIcon
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

  // Memoize theme creation
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

  // Handle dark mode persistence
  useEffect(() => {
    localStorage.setItem('darkMode', JSON.stringify(darkMode));
  }, [darkMode]);


  // Determine server URLs on initial load
  useEffect(() => {
    setIsLoading(true);
    determineServerUrls(DEFAULT_API_BASE_URL, DEFAULT_WS_URL)
      .then(urls => {
          setServerUrls(urls);
          if(urls.error) {
              setInitializationError(urls.error);
          }
      })
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(() => {
    if (token) {
      setIsAuthenticated(true);
    } else {
      setIsAuthenticated(false);
    }
  }, [token]);

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!serverUrls || isLoading) return;
    setIsLoading(true);
    setAuthError(null);
    try {
      const response = await axios.post(`${serverUrls.apiUrl}/register`, { username, password });
      console.log('Registration successful:', response.data);
      setIsRegistering(false);
      setAuthError("Registration successful! Please log in.");
    } catch (err) {
      console.error('Registration failed:', err);
      const message = err.response?.data?.error || err.message || 'Registration failed';
      setAuthError(`Registration failed: ${message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!serverUrls || isLoading) return;
    setIsLoading(true);
    setAuthError(null);
    try {
      const response = await axios.post(`${serverUrls.apiUrl}/login`, { username, password });
      console.log('Login successful:', response.data);
      localStorage.setItem('token', response.data.token);
      setToken(response.data.token);
    } catch (err) {
      console.error('Login failed:', err);
      const message = err.response?.data?.error || err.message || 'Login failed';
      setAuthError(`Login failed: ${message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  // Loading state for server URL check
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

  // If server URLs are determined but there was an error
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


  // Render main app if authenticated, otherwise show login/register
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
        // Login/Register Form
        <Box sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            p: 3,
         }}>
          <Box sx={{ padding: 3, maxWidth: 400, width: '100%', border: `1px solid ${theme.palette.divider}`, borderRadius: 1, bgcolor: 'background.paper' }}>
            <Typography variant="h5" component="h1" gutterBottom align="center">
              EarthSync {isRegistering ? 'Register' : 'Login'}
            </Typography>
            {authError && <Alert severity={authError.startsWith("Registration successful") ? "success" : "error"} sx={{ mb: 2 }}>{authError}</Alert>}
            <form onSubmit={isRegistering ? handleRegister : handleLogin}>
              <FormControl fullWidth margin="normal">
                <FormLabel htmlFor="username-input">Username</FormLabel>
                <input
                  id="username-input"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  style={{ padding: '10px', borderRadius: '4px', border: `1px solid ${theme.palette.divider}`, width: 'calc(100% - 22px)', background: theme.palette.background.default, color: theme.palette.text.primary }}
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
                  style={{ padding: '10px', borderRadius: '4px', border: `1px solid ${theme.palette.divider}`, width: 'calc(100% - 22px)', background: theme.palette.background.default, color: theme.palette.text.primary }}
                  aria-required="true"
                />
              </FormControl>
              <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <button
                    type="submit"
                    style={{ padding: '10px 20px', borderRadius: '4px', cursor: isLoading ? 'not-allowed' : 'pointer', opacity: isLoading ? 0.6 : 1, border: 'none', backgroundColor: theme.palette.primary.main, color: theme.palette.primary.contrastText }}
                    disabled={isLoading}
                    aria-live="polite"
                 >
                  {isLoading ? <CircularProgress size={20} color="inherit" /> : (isRegistering ? 'Register' : 'Login')}
                </button>
                <button
                  type="button"
                  onClick={() => { setIsRegistering(!isRegistering); setAuthError(null); }}
                  style={{ padding: '10px 20px', borderRadius: '4px', cursor: 'pointer', border: `1px solid ${theme.palette.divider}`, background: 'transparent', color: theme.palette.text.primary }}
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


// Type definition for WebSocket status
const WebSocketStatus = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
};


const SpectrogramPage = React.memo(({ token, onLogout, darkMode, setDarkMode, apiUrl, wsUrl }) => {
  const [spectrogramData, setSpectrogramData] = useState({});
  const [detectorActivity, setDetectorActivity] = useState({});
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [appError, setAppError] = useState(null);
  const [snackbarOpen, setSnackbarOpen] = useState(false);
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
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
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

  const drawerWidth = 300;
  const [appBarHeight, setAppBarHeight] = useState(64);
  const margin = 20;

  useEffect(() => {
    if (appBarRef.current) {
      const resizeObserver = new ResizeObserver(entries => {
         if (entries[0]) setAppBarHeight(entries[0].contentRect.height);
      });
      resizeObserver.observe(appBarRef.current);
      return () => resizeObserver.disconnect();
    }
  }, []);

  const stableSetTimeSteps = useCallback(setTimeSteps, []);
  const stableSetDetectorActivity = useCallback(setDetectorActivity, []);

  const updateSpectrogram = useMemo(() => throttle((newData) => {
        setSpectrogramData(prev => {
            const updated = { ...prev };
            newData.forEach(message => {
                if (!message.detectorId || !message.location || !Array.isArray(message.spectrogram)) return;
                const detectorId = message.detectorId;
                const incomingSpectrogramRows = message.spectrogram;
                if (!Array.isArray(incomingSpectrogramRows) || incomingSpectrogramRows.length === 0) return;
                const currentRows = updated[detectorId] || [];
                const newRows = [...currentRows, ...incomingSpectrogramRows].slice(-stableSetTimeSteps(ts => ts));
                updated[detectorId] = newRows;
            });
            return updated;
        });
        newData.forEach(data => {
             if (!data.detectorId || !data.location) return;
             stableSetDetectorActivity(prev => ({
               ...prev,
               [data.detectorId]: { lat: data.location.lat, lon: data.location.lon, lastUpdate: Date.now(), id: data.detectorId }
             }));
         });
    }, 500, { leading: true, trailing: true }), [stableSetTimeSteps, stableSetDetectorActivity]);


  // Fetch encryption key
  useEffect(() => {
    const fetchKey = async () => {
      if (!token) { setEncryptionKey(null); return; };
      setIsLoadingData(true);
      setAppError(null);
      try {
        console.log('Fetching encryption key...');
        const response = await axios.post(`${apiUrl}/key-exchange`, {}, { headers: { Authorization: `Bearer ${token}` } });
        console.log('Key exchange successful.');
        setEncryptionKey(response.data.key);
      } catch (err) {
        console.error('Key exchange failed:', err);
        const errorMsg = `Failed to fetch encryption key: ${err.response?.data?.error || err.message}`;
        setAppError(errorMsg);
        setSnackbarOpen(true);
        setEncryptionKey(null);
      } finally {
        setIsLoadingData(false);
      }
    };
    fetchKey();
  }, [token, apiUrl]);


  // Fetch Historical Data
  const fetchHistoricalData = useCallback(async () => {
    if (!token) return;
    setIsLoadingData(true);
    setIsTransitioning(true);
    setAppError(null);
    setSpectrogramData({});
    setDetectorActivity({});
    try {
      console.log(`Fetching historical data: ${historicalHours} hours, detector: ${selectedDetector}`);
      const endpoint = selectedDetector === 'all'
        ? `${apiUrl}/history/${historicalHours}`
        : `${apiUrl}/history/${historicalHours}?detectorId=${selectedDetector}`;

      const response = await axios.get(endpoint, { headers: { Authorization: `Bearer ${token}` } });
      console.log('Historical data received:', response.data?.length);

      const historicalData = Array.isArray(response.data) ? response.data : [];
      const newSpectrogramData = {};
      const newDetectorActivity = {};

      historicalData.forEach(data => {
        if (data.detectorId && Array.isArray(data.spectrogram) && data.location) {
            const currentSpectrograms = newSpectrogramData[data.detectorId] || [];
            const numPoints = 1101;
            const rowsFromHistory = [];
            for (let i = 0; i < data.spectrogram.length; i += numPoints) {
                rowsFromHistory.push(data.spectrogram.slice(i, i + numPoints));
            }
            newSpectrogramData[data.detectorId] = [...currentSpectrograms, ...rowsFromHistory].slice(-stableSetTimeSteps(ts => ts));
            newDetectorActivity[data.detectorId] = { lat: data.location.lat, lon: data.location.lon, lastUpdate: Date.now(), id: data.detectorId };
        }
      });

      setSpectrogramData(newSpectrogramData);
      setDetectorActivity(newDetectorActivity);
       if (historicalData.length === 0) {
            const errorMsg = `No historical data found for ${selectedDetector === 'all' ? 'any detector' : `detector ${selectedDetector}`} in the last ${historicalHours}h.`;
            setAppError(errorMsg);
            setSnackbarOpen(true);
        }

    } catch (err) {
      console.error('Historical data fetch error:', err);
      const errorMsg = `Failed to fetch historical data: ${err.response?.data?.error || err.message}`;
      setAppError(errorMsg);
      setSnackbarOpen(true);
    } finally {
      setIsLoadingData(false);
      setIsTransitioning(false);
    }
  }, [token, apiUrl, historicalHours, selectedDetector, stableSetTimeSteps]);


   // WebSocket Connection Management Effect
   useEffect(() => {
        let currentWs = null;

        const clearReconnectTimeout = () => {
            if (reconnectTimeoutRef.current) {
                clearTimeout(reconnectTimeoutRef.current);
                reconnectTimeoutRef.current = null;
            }
        };

        const scheduleReconnect = (attempt) => {
            clearReconnectTimeout();
            const delay = Math.min(1000 * Math.pow(2, attempt), 60000);
            console.log(`Scheduling WS reconnect in ${delay / 1000} seconds... (Attempt ${attempt + 1})`);
            reconnectTimeoutRef.current = setTimeout(() => {
                setReconnectAttempt(prev => prev + 1);
            }, delay);
        };

        if (historicalMode) {
            console.log("Switching to historical mode...");
            setIsTransitioning(true);
            clearReconnectTimeout();
            if (wsRef.current) {
                wsRef.current.onclose = null;
                wsRef.current.close(1000, 'Switching to historical mode');
                wsRef.current = null;
            }
            setWsStatus(WebSocketStatus.DISCONNECTED);
            setReconnectAttempt(0);
            fetchHistoricalData();

        } else if (token && encryptionKey) {
            if (!wsRef.current && wsStatus !== WebSocketStatus.CONNECTING) {
                console.log(`Attempting WS Connection (Attempt: ${reconnectAttempt})...`);
                setWsStatus(WebSocketStatus.CONNECTING);
                setIsTransitioning(true);
                setAppError(null);
                 if (reconnectAttempt === 0) {
                    setSpectrogramData({});
                    setDetectorActivity({});
                 }

                currentWs = new WebSocket(`${wsUrl}/?token=${token}`);
                wsRef.current = currentWs;

                currentWs.onopen = () => {
                    console.log('WebSocket connected successfully.');
                    if (wsRef.current === currentWs) {
                        setWsStatus(WebSocketStatus.CONNECTED);
                        setReconnectAttempt(0);
                        clearReconnectTimeout();
                        setIsTransitioning(false);
                    }
                };

                currentWs.onmessage = (event) => {
                     if (wsRef.current !== currentWs) return;
                     try {
                        const [encrypted, iv] = event.data.split(':');
                        if (!encrypted || !iv) throw new Error("Invalid message format");
                        const encryptedBuf = CryptoJS.enc.Base64.parse(encrypted);
                        const ivBuf = CryptoJS.enc.Base64.parse(iv);
                        if (!encryptionKey) throw new Error("Encryption key not available for decryption");
                        const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
                        const decrypted = CryptoJS.AES.decrypt({ ciphertext: encryptedBuf }, keyWordArray, { iv: ivBuf, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
                        const messageJson = decrypted.toString(CryptoJS.enc.Utf8);
                        if (!messageJson) throw new Error("Decryption resulted in empty message");
                        const message = JSON.parse(messageJson);
                        updateSpectrogram([message]);
                     } catch (err) {
                         console.error('WebSocket message processing error:', err);
                         setAppError(`WebSocket message error: ${err.message}. Check console.`);
                         setSnackbarOpen(true);
                     }
                };

                currentWs.onerror = (error) => {
                    console.error('WebSocket error event:', error);
                     if (wsRef.current !== currentWs) return;
                     setWsStatus(WebSocketStatus.ERROR);
                     setIsTransitioning(false);
                };

                currentWs.onclose = (event) => {
                    console.log(`WebSocket closed: Code=${event.code}, Reason=${event.reason || 'N/A'}`);
                     if (wsRef.current !== currentWs) { return; }
                     wsRef.current = null;

                    if (event.code !== 1000 && !historicalModeRef.current) {
                        setWsStatus(WebSocketStatus.DISCONNECTED);
                        setIsTransitioning(false);
                        if (!appError && event.code !== 1006) {
                           setAppError('WebSocket disconnected. Attempting to reconnect...');
                           setSnackbarOpen(true);
                        }
                        scheduleReconnect(reconnectAttempt);
                    } else {
                        setWsStatus(WebSocketStatus.DISCONNECTED);
                        setIsTransitioning(false);
                        setReconnectAttempt(0);
                         if (event.code === 1000) setAppError(null);
                    }
                };
            }
        } else {
             console.log("WebSocket connection prerequisites (token/key) not met.");
             clearReconnectTimeout();
             if (wsRef.current) {
                 wsRef.current.onclose = null;
                 wsRef.current.close(1000, 'Token or Key missing');
                 wsRef.current = null;
             }
             setWsStatus(WebSocketStatus.DISCONNECTED);
             setIsTransitioning(false);
             setReconnectAttempt(0);
        }

        return () => {
            console.log("Cleaning up WebSocket effect...");
            clearReconnectTimeout();
            if (currentWs) {
                currentWs.onclose = null;
                currentWs.onerror = null;
                currentWs.close(1000, 'Effect cleanup');
            }
             if (wsRef.current === currentWs) {
                 wsRef.current = null;
             }
        };
    }, [historicalMode, token, encryptionKey, wsUrl, apiUrl, fetchHistoricalData, updateSpectrogram, reconnectAttempt]);


  // --- Memoized Plot Data & Layout ---
   const { xLabels, yLabels, displayData, minAmplitude, maxAmplitude } = useMemo(() => {
     const numPoints = 1101;
     const calculatedXLabels = Array.from({ length: numPoints }, (_, i) => (i * 5 * (55 / 5500)).toFixed(2));

     const sourceRows = selectedDetector === 'all'
         ? Object.values(spectrogramData).flat()
         : spectrogramData[selectedDetector] || [];

     const validRows = sourceRows.filter(row => Array.isArray(row) && row.length === numPoints);
     const recentRows = validRows.slice(-timeSteps);

     const finalRows = recentRows.length < timeSteps
       ? [...Array(timeSteps - recentRows.length).fill().map(() => Array(numPoints).fill(0)), ...recentRows]
       : recentRows;

     const calculatedYLabels = finalRows.map((_, i) => {
       const secondsAgo = (finalRows.length - 1 - i) * 5;
       return secondsAgo === 0 ? 'Now' : `-${secondsAgo}s`;
     });

     const normalizeFn = (data) => {
         const allValues = data.flat().filter(v => typeof v === 'number' && !isNaN(v));
         if (allValues.length === 0) return data;
         const min = Math.min(...allValues);
         const max = Math.max(...allValues);
         const range = max - min;
         if (range === 0) return data.map(row => row.map(() => 0));
         return data.map(row => row.map(value => typeof value === 'number' && !isNaN(value) ? ((value - min) / range) * 15 : 0));
     };
     const finalDisplayData = normalize ? normalizeFn(finalRows) : finalRows;

     const allFlatValues = finalDisplayData.flat().filter(v => typeof v === 'number' && !isNaN(v));
     const calculatedMinAmplitude = allFlatValues.length ? Math.max(0, Math.min(...allFlatValues)) : 0;
     const amplitudeCap = normalize ? 16 : 25;
     const calculatedMaxAmplitude = allFlatValues.length ? Math.min(amplitudeCap, Math.max(...allFlatValues) + 1) : amplitudeCap;

     return {
         xLabels: calculatedXLabels,
         yLabels: calculatedYLabels,
         displayData: finalDisplayData,
         minAmplitude: calculatedMinAmplitude,
         maxAmplitude: calculatedMaxAmplitude
     };
   }, [spectrogramData, selectedDetector, timeSteps, normalize]);


   const plotData = useMemo(() => [{
       z: displayData, x: xLabels, y: yLabels, type: 'surface',
       colorscale: colorScale, showscale: true,
       colorbar: { title: 'Amplitude', titleside: 'right', tickfont: { color: darkMode ? '#ffffff' : '#000000' }, titlefont: { color: darkMode ? '#ffffff' : '#000000' } },
       contours: { z: { show: true, usecolormap: true, highlightcolor: "#42f462", project: { z: true } } },
       lighting: { ambient: 0.8, diffuse: 0.8, specular: 0.1 }, lightposition: { x: 100, y: 100, z: 2000 }
   }], [displayData, xLabels, yLabels, colorScale, darkMode]);

   const layout = useMemo(() => ({
       title: { text: `Schumann Resonance ${selectedDetector === 'all' ? '(All Detectors)' : `(${selectedDetector})`} ${historicalMode ? `(Past ${historicalHours}h)` : '(Real-time)'}`, font: { size: 16, color: darkMode ? '#ffffff' : '#000000' }, y: 0.98 },
       scene: {
           xaxis: { title: { text: 'Frequency (Hz)', font: { size: 12, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' }, gridcolor: darkMode ? '#555555' : '#d3d3d3', zerolinecolor: darkMode ? '#aaaaaa' : '#000000', backgroundcolor: "rgba(0,0,0,0)" },
           yaxis: { title: { text: 'Time', font: { size: 12, color: darkMode ? '#ffffff' : '#000000' } }, tickvals: yLabels.filter((_, i) => i % Math.max(1, Math.floor(yLabels.length / 10)) === 0), ticktext: yLabels.filter((_, i) => i % Math.max(1, Math.floor(yLabels.length / 10)) === 0), tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' }, gridcolor: darkMode ? '#555555' : '#d3d3d3', zerolinecolor: darkMode ? '#aaaaaa' : '#000000', backgroundcolor: "rgba(0,0,0,0)" },
           zaxis: { title: { text: 'Amplitude', font: { size: 12, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 10, color: darkMode ? '#ffffff' : '#000000' }, range: [minAmplitude, maxAmplitude], gridcolor: darkMode ? '#555555' : '#d3d3d3', zerolinecolor: darkMode ? '#aaaaaa' : '#000000', backgroundcolor: "rgba(0,0,0,0)" },
           camera: { eye: { x: 1.5, y: 1.5, z: 0.8 } }, aspectmode: 'cube'
       },
       margin: { t: 40, r: margin, b: margin, l: margin }, autosize: true,
       paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)',
       font: { color: darkMode ? '#ffffff' : '#000000' },
       modebar: { orientation: 'v', bgcolor: 'rgba(0,0,0,0.1)', color: darkMode ? '#ffffff' : '#000000', activecolor: theme.palette.primary.main }
   }), [darkMode, minAmplitude, maxAmplitude, yLabels, selectedDetector, historicalMode, historicalHours, theme.palette.primary.main, margin]);

  // --- Memoized Globe data & Options ---
   const globePoints = useMemo(() => Object.values(detectorActivity).map(({ lat, lon, lastUpdate, id }) => {
       const timeSinceUpdate = Date.now() - lastUpdate;
       const isActive = !historicalMode && (timeSinceUpdate < 10000);
       const sizePulse = isActive ? (timeSinceUpdate < 2000 ? 0.6 : 0.5) : 0.2;
       return { lat, lng: lon, size: sizePulse, color: isActive ? 'red' : (historicalMode ? 'grey' : 'blue'), label: `Detector: ${id}\nCoords: ${lat.toFixed(2)}, ${lon.toFixed(2)}\nStatus: ${isActive ? 'Active' : (historicalMode ? 'Historical' : 'Idle')}`, id };
   }), [detectorActivity, historicalMode]);

   const detectorOptions = useMemo(() => [
       { id: 'all', label: 'All Detectors' },
       ...Object.keys(detectorActivity).sort().map(id => ({ id, label: id }))
   ], [detectorActivity]);

  // --- Debounced Sliders ---
  const debouncedSetTimeSteps = useCallback(debounce((value) => stableSetTimeSteps(Math.max(6, Math.floor(value / 5))), 300), [stableSetTimeSteps]);
  const debouncedSetHistoricalHours = useCallback(debounce((value) => setHistoricalHours(value), 300), [setHistoricalHours]);

  // --- Interaction Handlers ---
   const handlePlotHover = useCallback((data) => { /* Placeholder */ }, []);
   const handlePlotClick = useCallback((data) => { if(data.points.length > 0) { setAppError(`Plot Point Clicked: Freq=${data.points[0].x}, Time=${data.points[0].y}, Amp=${data.points[0].z.toFixed(2)}`); setSnackbarOpen(true); } }, []);
   const handlePlotRelayout = useCallback((eventData) => { /* Placeholder */ }, []);
   const handleGlobePointClick = useCallback((point) => { if (point?.id && detectorOptions.some(opt => opt.id === point.id)) { setSelectedDetector(point.id); setAppError(`Selected detector ${point.id} from globe.`); setSnackbarOpen(true); } }, [detectorOptions]);
   const handleGlobePointHover = useCallback((point) => { /* Placeholder */ }, []);
   const handleCloseSnackbar = useCallback((event, reason) => { if (reason === 'clickaway') return; setSnackbarOpen(false); }, []);

   const handleModeChange = (newMode) => {
       if (newMode === historicalMode) return;
       setHistoricalMode(newMode);
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

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden', bgcolor: 'background.default' }}>
      <AppBar ref={appBarRef} position="fixed" sx={{ width: '100%', zIndex: (theme) => theme.zIndex.drawer + 1, bgcolor: 'background.paper', color: 'text.primary' }}>
        <Toolbar>
          <IconButton color="inherit" edge="start" onClick={() => setDrawerOpen(!drawerOpen)} sx={{ mr: 2 }} aria-label={drawerOpen ? "Close settings drawer" : "Open settings drawer"}>
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>EarthSync</Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', mr: 2, border: `1px solid ${theme.palette.divider}`, borderRadius: 1, px: 1, py: 0.5 }} aria-live="polite">
             {wsStatus === WebSocketStatus.CONNECTED && <CheckCircleIcon sx={{ color: 'success.main', fontSize: '1.1rem' }} aria-label="WebSocket Connected"/>}
             {wsStatus === WebSocketStatus.CONNECTING && <CircularProgress size={16} color="inherit" aria-label="WebSocket Connecting"/>}
             {(wsStatus === WebSocketStatus.DISCONNECTED || wsStatus === WebSocketStatus.ERROR) && <ErrorIcon sx={{ color: wsStatus === WebSocketStatus.ERROR ? 'error.main' : 'warning.main', fontSize: '1.1rem' }} aria-label="WebSocket Disconnected or Error"/>}
             <Typography variant="caption" sx={{ ml: 0.5, display: { xs: 'none', sm: 'block' } }}>
                 {wsStatus === WebSocketStatus.CONNECTED ? 'Real-time Connected' :
                  wsStatus === WebSocketStatus.CONNECTING ? 'Connecting...' :
                  wsStatus === WebSocketStatus.ERROR ? 'Connection Error' : 'Disconnected'}
             </Typography>
           </Box>
          <IconButton color="inherit" onClick={() => setDarkMode(!darkMode)} aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}>
            {darkMode ? <Brightness7Icon /> : <Brightness4Icon />}
          </IconButton>
        </Toolbar>
         {showTopLoader && <LinearProgress sx={{ position: 'absolute', bottom: 0, left: 0, width: '100%' }} />}
      </AppBar>

      <Box sx={{ display: 'flex', flexGrow: 1, mt: `${appBarHeight}px` }}>
        <Drawer variant="persistent" anchor="left" open={drawerOpen}
          sx={{ width: drawerWidth, flexShrink: 0, '& .MuiDrawer-paper': { width: drawerWidth, boxSizing: 'border-box', overflowX: 'hidden', mt: `${appBarHeight}px`, height: `calc(100% - ${appBarHeight}px)`, transition: theme.transitions.create('width', { easing: theme.transitions.easing.sharp, duration: drawerOpen ? theme.transitions.duration.enteringScreen : theme.transitions.duration.leavingScreen }), display: 'flex', flexDirection: 'column', borderRight: `1px solid ${theme.palette.divider}` } }}
        >
          <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
            <List>
               <ListItem disablePadding>
                   <ListItemButton onClick={() => handleModeChange(false)} selected={!historicalMode} aria-current={!historicalMode ? "page" : "false"}>
                     <ListItemIcon><BarChartIcon /></ListItemIcon>
                     <ListItemText primary="Real-time Data" />
                   </ListItemButton>
                 </ListItem>
                 <ListItem disablePadding>
                   <ListItemButton onClick={() => handleModeChange(true)} selected={historicalMode} aria-current={historicalMode ? "page" : "false"}>
                     <ListItemIcon><HistoryIcon /></ListItemIcon>
                     <ListItemText primary="Historical Data" />
                   </ListItemButton>
                 </ListItem>
                 <ListItem disablePadding>
                   <ListItemButton onClick={onLogout}>
                     <ListItemIcon><LogoutIcon /></ListItemIcon>
                     <ListItemText primary="Logout" />
                   </ListItemButton>
                 </ListItem>
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
                <Select labelId="colorscale-label" value={colorScale} onChange={(e) => setColorScale(e.target.value)} size="small">
                  <MenuItem value="Jet">Jet</MenuItem><MenuItem value="Greys">Greys</MenuItem><MenuItem value="Viridis">Viridis</MenuItem><MenuItem value="Plasma">Plasma</MenuItem>
                </Select>
              </FormControl>
              <FormControlLabel control={<Switch checked={normalize} onChange={() => setNormalize(!normalize)} />} label="Normalize Amplitude" sx={{ mb: 1, display: 'block' }}/>
              {historicalMode && (
                <FormControl fullWidth sx={{ mb: 2 }}>
                  <FormLabel id="historical-hours-label" sx={{ mb: 0.5 }}>Historical Hours</FormLabel>
                  <Slider aria-labelledby="historical-hours-label" value={historicalHours} onChange={(_, val) => debouncedSetHistoricalHours(val)} min={1} max={72} step={1} marks valueLabelDisplay="auto" size="small"/>
                </FormControl>
              )}
              {(isLoadingData || isTransitioning) && (<Box sx={{ display: 'flex', alignItems: 'center', mt: 1, color: theme.palette.text.secondary }}><CircularProgress size={16} sx={{ mr: 1 }} /><Typography variant="caption">Loading data...</Typography></Box>)}
            </Box>
          </Box>
          <Box sx={{ p: 1, display: 'flex', justifyContent: 'center', borderTop: `1px solid ${theme.palette.divider}` }}>
             {drawerOpen && (
                <Globe ref={globeRef} globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg" bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png" backgroundColor='rgba(0,0,0,0)' pointsData={globePoints} pointLat="lat" pointLng="lng" pointColor="color" pointRadius={0.25} pointAltitude="size" pointLabel="label" onPointClick={handleGlobePointClick} onPointHover={handleGlobePointHover} width={drawerWidth - 16} height={drawerWidth - 16} atmosphereColor={darkMode ? 'lightblue' : 'dodgerblue'} atmosphereAltitude={0.25} animateIn={true} pointResolution={4} />
             )}
           </Box>
        </Drawer>

        <Box component="main" ref={plotContainerRef}
          sx={{ flexGrow: 1, width: `calc(100% - ${drawerOpen ? drawerWidth : 0}px)`, height: `calc(100vh - ${appBarHeight}px)`, overflow: 'hidden', padding: `${margin}px`, boxSizing: 'border-box', transition: theme.transitions.create(['margin', 'width'], { easing: theme.transitions.easing.sharp, duration: drawerOpen ? theme.transitions.duration.enteringScreen : theme.transitions.duration.leavingScreen }), marginLeft: drawerOpen ? 0 : `-${drawerWidth}px`, position: 'relative' }}
        >
           {(isLoadingData || isTransitioning) && !Object.keys(spectrogramData).length ? (
             <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', flexDirection: 'column', gap: 1 }}>
                 <CircularProgress />
                 <Typography sx={{ mt: 2 }}>Loading Spectrogram Data...</Typography>
             </Box>
           ) : (displayData && displayData.length > 0 && displayData[0]?.length > 0) ? (
             <Box sx={{ width: '100%', height: '100%', opacity: isTransitioning ? 0.5 : 1, transition: 'opacity 0.3s ease-in-out' }} className="fade-in">
                 <Plotly data={plotData} layout={layout} revision={Date.now()} style={{ width: '100%', height: '100%' }} useResizeHandler config={{ responsive: true, displayModeBar: true, displaylogo: false, modeBarButtonsToRemove: ['lasso2d', 'select2d'], willReadFrequently: true }} onHover={handlePlotHover} onClick={handlePlotClick} onRelayout={handlePlotRelayout}/>
             </Box>
           ) : (
             <Typography sx={{ textAlign: 'center', mt: 4 }}>No spectrogram data available for selected detector(s).</Typography>
           )
          }
        </Box>
      </Box>

      <Snackbar open={snackbarOpen} autoHideDuration={6000} onClose={handleCloseSnackbar} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
         <Alert onClose={handleCloseSnackbar} severity={appError?.toLowerCase().includes("selected detector") ? "info" : "error"} sx={{ width: '100%' }} variant="filled">{appError || "An unknown error occurred."}</Alert>
       </Snackbar>
    </Box>
  );
});

SpectrogramPage.displayName = 'SpectrogramPage';
export default App;
