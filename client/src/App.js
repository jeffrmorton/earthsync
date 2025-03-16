/**
 * Main application component for EarthSync client.
 * Handles authentication, theme toggling, and renders the SpectrogramPage.
 */
import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import Plotly from 'react-plotly.js';
import debounce from 'lodash.debounce';
import throttle from 'lodash.throttle';
import {
  AppBar, Toolbar, Typography, Drawer, List, ListItem, ListItemIcon, ListItemText,
  IconButton, CssBaseline, Box, Slider, FormControl, FormLabel, Switch, useTheme,
  ThemeProvider, createTheme, Select, MenuItem, Divider,
} from '@mui/material';
import {
  Menu as MenuIcon, Brightness4 as Brightness4Icon, Brightness7 as Brightness7Icon,
  BarChart as BarChartIcon, Logout as LogoutIcon, History as HistoryIcon,
} from '@mui/icons-material';

// Load environment variables as defaults
const DEFAULT_API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://server:3000';
const DEFAULT_WS_URL = process.env.REACT_APP_WS_URL || 'ws://server:3000';

// Function to determine the working API and WS URLs with localhost fallback
async function determineServerUrls(defaultApiUrl, defaultWsUrl) {
  const fallbackApiUrl = 'http://localhost:3000';
  const fallbackWsUrl = 'ws://localhost:3000';

  // Test if the default API URL is reachable (useful for WSL2 or local dev)
  try {
    await axios.get(`${defaultApiUrl}/health`, { timeout: 2000 });
    console.log(`Using default server URLs: API=${defaultApiUrl}, WS=${defaultWsUrl}`);
    return { apiUrl: defaultApiUrl, wsUrl: defaultWsUrl };
  } catch (err) {
    console.warn(`Default server URL (${defaultApiUrl}) not reachable: ${err.message}. Falling back to localhost.`);
    return { apiUrl: fallbackApiUrl, wsUrl: fallbackWsUrl };
  }
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [error, setError] = useState(null);
  const [darkMode, setDarkMode] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [serverUrls, setServerUrls] = useState(null);

  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: { main: '#1976d2' },
      secondary: { main: '#f50057' },
    },
  });

  useEffect(() => {
    async function initializeServerUrls() {
      const urls = await determineServerUrls(DEFAULT_API_BASE_URL, DEFAULT_WS_URL);
      setServerUrls(urls);
    }
    initializeServerUrls();
  }, []);

  useEffect(() => {
    if (token) setIsAuthenticated(true);
  }, [token]);

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!serverUrls) return;
    setIsLoading(true);
    try {
      const response = await axios.post(`${serverUrls.apiUrl}/register`, { username, password });
      console.log('Registration successful:', response.data);
      setError(null);
      setIsRegistering(false);
    } catch (err) {
      console.error('Registration failed:', err);
      setError(`Failed to register: ${err.response?.data?.error || err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!serverUrls) return;
    setIsLoading(true);
    try {
      const response = await axios.post(`${serverUrls.apiUrl}/login`, { username, password });
      console.log('Login successful:', response.data);
      localStorage.setItem('token', response.data.token);
      setToken(response.data.token);
      setIsAuthenticated(true);
      setError(null);
    } catch (err) {
      console.error('Login failed:', err);
      setError(`Failed to log in: ${err.response?.data?.error || err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setIsAuthenticated(false);
  };

  if (!serverUrls) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box sx={{ padding: 3, textAlign: 'center' }}>
          <Typography variant="h6">Initializing server connection...</Typography>
        </Box>
      </ThemeProvider>
    );
  }

  if (isAuthenticated) {
    return (
      <ThemeProvider theme={theme}>
        <SpectrogramPage
          token={token}
          onLogout={handleLogout}
          darkMode={darkMode}
          setDarkMode={setDarkMode}
          apiUrl={serverUrls.apiUrl}
          wsUrl={serverUrls.wsUrl}
        />
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ padding: 3, maxWidth: 400, margin: '0 auto' }}>
        <Typography variant="h4" gutterBottom>
          {isRegistering ? 'Register' : 'Login'}
        </Typography>
        {isLoading && <Typography>Loading...</Typography>}
        {error && <Typography color="error">{error}</Typography>}
        <form onSubmit={isRegistering ? handleRegister : handleLogin}>
          <Box sx={{ mb: 2 }}>
            <FormLabel>Username</FormLabel>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid' }}
            />
          </Box>
          <Box sx={{ mb: 2 }}>
            <FormLabel>Password</FormLabel>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid' }}
            />
          </Box>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <button type="submit" style={{ padding: '10px 20px', borderRadius: '4px' }} disabled={isLoading}>
              {isRegistering ? 'Register' : 'Login'}
            </button>
            <button
              type="button"
              onClick={() => setIsRegistering(!isRegistering)}
              style={{ padding: '10px 20px', borderRadius: '4px' }}
              disabled={isLoading}
            >
              {isRegistering ? 'Switch to Login' : 'Switch to Register'}
            </button>
          </Box>
        </form>
      </Box>
    </ThemeProvider>
  );
}

const SpectrogramPage = React.memo(({ token, onLogout, darkMode, setDarkMode, apiUrl, wsUrl }) => {
  const [spectrogramData, setSpectrogramData] = useState([]);
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [error, setError] = useState(null);
  const [timeSteps, setTimeSteps] = useState(60);
  const [historicalMode, setHistoricalMode] = useState(false);
  const [historicalHours, setHistoricalHours] = useState(1);
  const [colorScale, setColorScale] = useState('Jet');
  const [normalize, setNormalize] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(() => {
    const saved = localStorage.getItem('drawerOpen');
    return saved ? JSON.parse(saved) : true;
  });
  const [isLoading, setIsLoading] = useState(false);
  const wsRef = useRef(null);
  const theme = useTheme();

  useEffect(() => {
    localStorage.setItem('drawerOpen', JSON.stringify(drawerOpen));
  }, [drawerOpen]);

  const drawerWidth = 240;
  const appBarHeight = 64;

  const updateSpectrogram = useMemo(() => throttle((newData) => {
    console.log('Received spectrogram data:', newData); // Log raw incoming data
    if (!Array.isArray(newData)) {
      console.error('Invalid spectrogram data received: not an array', newData);
      setError('Received invalid spectrogram data');
      return;
    }
    const validSpectrograms = newData.filter(subArray => 
      Array.isArray(subArray) && subArray.length > 0 && subArray.every(v => typeof v === 'number' && !isNaN(v))
    );
    if (validSpectrograms.length === 0) {
      console.error('No valid spectrograms in batch:', newData);
      setError('Received invalid spectrogram batch');
      return;
    }
    setSpectrogramData((prev) => {
      const newDataFlat = [...prev, ...validSpectrograms].slice(-timeSteps);
      console.log('Updated spectrogramData length:', newDataFlat.length);
      return newDataFlat;
    });
  }, 500), [timeSteps]);

  useEffect(() => {
    const fetchKey = async () => {
      setIsLoading(true);
      try {
        const response = await axios.post(
          `${apiUrl}/key-exchange`,
          {},
          { headers: { Authorization: `Bearer ${token}` } }
        );
        console.log('Key exchange successful:', response.data);
        setEncryptionKey(response.data.key);
      } catch (err) {
        console.error('Key exchange failed:', err);
        setError(`Failed to fetch encryption key: ${err.response?.data?.error || err.message}`);
      } finally {
        setIsLoading(false);
      }
    };
    if (token) fetchKey();
  }, [token, apiUrl]);

  const connectWebSocket = useCallback(() => {
    if (!token || !encryptionKey) {
      console.log('Skipping WebSocket connection: token or encryptionKey missing', { token, encryptionKey });
      return;
    }

    const ws = new WebSocket(`${wsUrl}/?token=${token}`);
    wsRef.current = ws;

    console.log('Attempting WebSocket connection to:', wsUrl);
    console.log('Encryption key (hex):', encryptionKey);

    ws.onopen = () => console.log('WebSocket connected');

    ws.onmessage = (event) => {
      try {
        const messageStr = event.data;
        console.log('Raw WebSocket message:', messageStr); // Log raw message
        if (!messageStr) {
          console.log('Received empty WebSocket message');
          return;
        }
        const [encrypted, iv] = messageStr.split(':');
        if (!encrypted || !iv) throw new Error('Invalid message format');

        const encryptedBuf = CryptoJS.enc.Base64.parse(encrypted);
        const ivBuf = CryptoJS.enc.Base64.parse(iv);
        const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
        const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: encryptedBuf });
        const decrypted = CryptoJS.AES.decrypt(cipherParams, keyWordArray, { iv: ivBuf, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        const messageStrDecrypted = decrypted.toString(CryptoJS.enc.Utf8);
        if (!messageStrDecrypted) throw new Error('Decryption failed');

        const message = JSON.parse(messageStrDecrypted);
        console.log('Decrypted message:', message); // Log full decrypted message
        if (!message.spectrogram) throw new Error('Invalid spectrogram data');

        console.log('Decrypted message sample (around 7.83 Hz):', 
          Array.isArray(message.spectrogram[0]) 
            ? message.spectrogram.map(s => s.slice(780, 790)) 
            : message.spectrogram.slice(780, 790)
        );
        updateSpectrogram(message.spectrogram);
      } catch (err) {
        console.error('WebSocket decryption error:', err);
        setError(`Failed to process WebSocket message: ${err.message}`);
      }
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
      setError('WebSocket connection error');
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
      const reconnectWithBackoff = async (maxAttempts = 10) => {
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
          console.log(`Reconnecting in ${delay / 1000}s (attempt ${attempt}/${maxAttempts})...`);
          await new Promise(resolve => setTimeout(resolve, delay));
          try {
            connectWebSocket();
            return;
          } catch (err) {
            if (attempt === maxAttempts) setError('WebSocket connection failed after max retries');
          }
        }
      };
      reconnectWithBackoff();
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [token, encryptionKey, wsUrl]);

  const fetchHistoricalData = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(`${apiUrl}/history/${historicalHours}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      console.log('Historical data response:', response.data);
      // Flatten batched spectrograms into a single array of individual spectrograms
      const historicalSpectrograms = Array.isArray(response.data)
        ? response.data.flatMap(batch => {
            if (!Array.isArray(batch)) {
              console.log('Invalid historical batch (not an array):', batch);
              return [];
            }
            return batch.filter(s => {
              const isValid = Array.isArray(s) && s.length > 0 && s.every(v => typeof v === 'number' && !isNaN(v));
              if (!isValid) console.log('Invalid historical spectrogram:', s);
              return isValid;
            });
          })
        : [];
      if (historicalSpectrograms.length === 0) {
        console.warn('No valid historical spectrograms found');
        setError('No valid historical data available');
      } else {
        console.log('Valid historical spectrograms found:', historicalSpectrograms.length);
      }
      setSpectrogramData(historicalSpectrograms.slice(-timeSteps));
    } catch (err) {
      console.error('Historical data fetch error:', err);
      setError(`Failed to fetch historical data: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!encryptionKey) {
      console.log('Waiting for encryption key before connecting WebSocket...');
      return;
    }
    if (historicalMode) fetchHistoricalData();
    else return connectWebSocket();
  }, [historicalMode, historicalHours, token, encryptionKey, timeSteps, connectWebSocket]);

  // Downsampling factor of 5 reduces data points for performance (5501 -> 1101 frequencies)
  const downsampleFactor = 5;
  const xLabels = useMemo(() => Array(5501).fill(0)
    .map((_, i) => (i / 100).toFixed(2))
    .filter((_, i) => i % downsampleFactor === 0), []);
  const zData = useMemo(() => spectrogramData
    .filter(data => Array.isArray(data) && data.length > 0 && data.every(v => typeof v === 'number' && !isNaN(v)))
    .map(data => data.filter((_, i) => i % downsampleFactor === 0)), [spectrogramData]);
  console.log('Z data (first few rows, around 7.83 Hz):', zData.map(row => row.slice(156, 162)));

  const yLabels = useMemo(() => zData.map((_, i) => {
    const secondsAgo = (zData.length - 1 - i) * 5;
    return secondsAgo === 0 ? 'Now' : `-${secondsAgo}s`;
  }), [zData]);

  const normalizeData = (data) => {
    const allValues = data.flat();
    if (allValues.length === 0 || allValues.some(v => typeof v !== 'number' || isNaN(v))) {
      console.error('Invalid data for normalization:', allValues);
      return data;
    }
    const min = Math.min(...allValues);
    const max = Math.max(...allValues);
    const range = max - min;
    return data.map(row => row.map(value => range > 0 ? ((value - min) / range) * 15 : 0));
  };

  const displayData = useMemo(() => normalize ? normalizeData(zData) : zData, [normalize, zData]);
  const { minAmplitude, maxAmplitude } = useMemo(() => {
    if (displayData.length === 0) return { min: 0, max: 15 };
    const allValues = displayData.flat();
    if (allValues.length === 0 || allValues.some(v => typeof v !== 'number' || isNaN(v))) {
      console.error('Invalid display data:', allValues);
      return { min: 0, max: 15 };
    }
    const min = Math.min(...allValues);
    const max = Math.max(...allValues);
    return { min: Math.max(0, min), max: Math.min(15, max + 1) };
  }, [displayData]);

  const plotData = useMemo(() => [{
    z: displayData.length > 0 ? displayData : [[0]],
    x: xLabels,
    y: yLabels.length > 0 ? yLabels : ['Now'],
    type: 'surface',
    colorscale: colorScale === 'Jet' ? 'Jet' : 'Greys',
    showscale: true,
    colorbar: { title: 'Amplitude', titleside: 'right' },
  }], [displayData, xLabels, yLabels, colorScale]);

  const layout = useMemo(() => ({
    title: {
      text: 'Schumann Resonance 3D Surface Plot',
      font: { size: 18, color: darkMode ? '#ffffff' : '#000000' },
      x: 0.5,
      xanchor: 'center',
      y: 0.95,
      yanchor: 'top',
    },
    scene: {
      xaxis: {
        title: { text: 'Frequency (Hz)', font: { size: 14, color: darkMode ? '#ffffff' : '#000000' } },
        tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
        gridcolor: darkMode ? '#444444' : '#d3d3d3',
        zerolinecolor: darkMode ? '#ffffff' : '#000000',
      },
      yaxis: {
        title: { text: 'Time (seconds)', font: { size: 14, color: darkMode ? '#ffffff' : '#000000' } },
        tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
        gridcolor: darkMode ? '#444444' : '#d3d3d3',
        zerolinecolor: darkMode ? '#ffffff' : '#000000',
      },
      zaxis: {
        title: { text: 'Amplitude', font: { size: 14, color: darkMode ? '#ffffff' : '#000000' } },
        tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
        range: [minAmplitude, maxAmplitude],
        gridcolor: darkMode ? '#444444' : '#d3d3d3',
        zerolinecolor: darkMode ? '#ffffff' : '#000000',
      },
      camera: { eye: { x: 1.5, y: 1.5, z: 0.8 } },
    },
    margin: { t: appBarHeight + 10, r: 50, b: 50, l: 50 },
    autosize: true,
    paper_bgcolor: darkMode ? '#1a1a1a' : '#ffffff',
    plot_bgcolor: darkMode ? '#1a1a1a' : '#ffffff',
    modebar: { orientation: 'h', y: 0, yanchor: 'top', x: 1, xanchor: 'right' },
  }), [darkMode, minAmplitude, maxAmplitude, appBarHeight]);

  // Debounced handlers for user inputs to reduce re-renders
  const debouncedSetTimeSteps = useCallback(debounce((value) => setTimeSteps(Math.floor(value / 5)), 300), []);
  const debouncedSetHistoricalHours = useCallback(debounce((value) => setHistoricalHours(value), 300), []);

  return (
    <>
      <Box sx={{ display: 'flex' }}>
        <CssBaseline />
        <AppBar position="fixed" sx={{ width: '100%', ml: 0, zIndex: (theme) => theme.zIndex.drawer + 1 }}>
          <Toolbar>
            <IconButton color="inherit" edge="start" onClick={() => setDrawerOpen(!drawerOpen)} sx={{ mr: 2 }}>
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" sx={{ flexGrow: 1 }}>
              EarthSync Client - Schumann Resonance 3D Surface Plot
            </Typography>
            <IconButton color="inherit" onClick={() => setDarkMode(!darkMode)}>
              {darkMode ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
          </Toolbar>
        </AppBar>
        <Drawer
          variant="permanent"
          sx={{
            width: drawerOpen ? drawerWidth : 0,
            flexShrink: 0,
            '& .MuiDrawer-paper': {
              width: drawerOpen ? drawerWidth : 0,
              boxSizing: 'border-box',
              overflowX: 'hidden',
              transition: theme.transitions.create('width', {
                easing: theme.transitions.easing.easeInOut,
                duration: 500,
              }),
            },
          }}
        >
          <Toolbar />
          <List>
            <ListItem onClick={() => setHistoricalMode(false)}>
              <ListItemIcon><BarChartIcon /></ListItemIcon>
              <ListItemText primary="Spectrogram" />
            </ListItem>
            <ListItem onClick={() => setHistoricalMode(true)}>
              <ListItemIcon><HistoryIcon /></ListItemIcon>
              <ListItemText primary="Historical Data" />
            </ListItem>
            <ListItem onClick={onLogout}>
              <ListItemIcon><LogoutIcon /></ListItemIcon>
              <ListItemText primary="Logout" />
            </ListItem>
          </List>
          <Divider />
          <Box sx={{ p: 2 }}>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <FormLabel>Time Window (seconds)</FormLabel>
              <Slider
                value={timeSteps * 5}
                onChange={(_, newValue) => debouncedSetTimeSteps(newValue)}
                min={30}
                max={600}
                step={5}
                marks
                valueLabelDisplay="auto"
              />
            </FormControl>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <FormLabel>Color Scale</FormLabel>
              <Select value={colorScale} onChange={(e) => setColorScale(e.target.value)}>
                <MenuItem value="Jet">Jet</MenuItem>
                <MenuItem value="Greys">Greys</MenuItem>
              </Select>
            </FormControl>
            <FormControl sx={{ mb: 2 }}>
              <FormLabel>Normalize Data</FormLabel>
              <Switch checked={normalize} onChange={() => setNormalize(!normalize)} />
            </FormControl>
            {historicalMode && (
              <FormControl fullWidth sx={{ mb: 2 }}>
                <FormLabel>Historical Data (hours)</FormLabel>
                <Slider
                  value={historicalHours}
                  onChange={(_, newValue) => debouncedSetHistoricalHours(newValue)}
                  min={1}
                  max={24}
                  step={1}
                  marks
                  valueLabelDisplay="auto"
                />
              </FormControl>
            )}
          </Box>
        </Drawer>
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            pt: `${appBarHeight + 16}px`,
            pb: 2,
            pl: 2,
            pr: 2,
            width: drawerOpen ? `calc(100% - ${drawerWidth}px)` : '100%',
            height: `calc(100vh - ${appBarHeight}px)`,
            display: 'flex',
            flexDirection: 'column',
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.easeInOut,
              duration: 500,
            }),
          }}
        >
          {isLoading && <Typography>Loading...</Typography>}
          {error && <Typography color="error">{error}</Typography>}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Connected to server at: {apiUrl}
          </Typography>
          <Box sx={{ flex: 1, minHeight: 0 }}>
            <Plotly
              data={plotData}
              layout={layout}
              revision={spectrogramData.length}
              style={{ width: '100%', height: '100%' }}
              useResizeHandler
            />
          </Box>
        </Box>
      </Box>
    </>
  );
});

SpectrogramPage.displayName = 'SpectrogramPage';

export default App;
