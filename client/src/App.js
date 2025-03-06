/**
 * Main application component for EarthSync client.
 * Handles authentication, theme toggling, and renders the SpectrogramPage.
 */
import React, { useEffect, useState, useRef } from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import { AES, enc, mode, pad } from 'crypto-js';
import Plotly from 'react-plotly.js';
import {
  AppBar, Toolbar, Typography, Drawer, List, ListItem, ListItemIcon, ListItemText,
  IconButton, CssBaseline, Box, Slider, FormControl, FormLabel, Switch, useTheme,
  ThemeProvider, createTheme, Select, MenuItem, Divider,
} from '@mui/material';
import {
  Menu as MenuIcon, Brightness4 as Brightness4Icon, Brightness7 as Brightness7Icon,
  BarChart as BarChartIcon, Logout as LogoutIcon, History as HistoryIcon,
} from '@mui/icons-material';

// Load environment variables
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;
const WS_URL = process.env.REACT_APP_WS_URL;

if (!API_BASE_URL || !WS_URL) {
  console.error('API_BASE_URL or WS_URL is not defined in environment variables');
  throw new Error('Missing required environment variables');
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [error, setError] = useState(null);
  const [darkMode, setDarkMode] = useState(true);

  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: { main: '#1976d2' },
      secondary: { main: '#f50057' },
    },
  });

  useEffect(() => {
    if (token) setIsAuthenticated(true);
  }, [token]);

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API_BASE_URL}/register`, { username, password });
      console.log('Registration successful:', response.data);
      setError(null);
      setIsRegistering(false);
    } catch (err) {
      console.error('Registration failed:', err);
      setError(`Failed to register: ${err.response?.data?.error || err.message}`);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API_BASE_URL}/login`, { username, password });
      console.log('Login successful:', response.data);
      localStorage.setItem('token', response.data.token);
      setToken(response.data.token);
      setIsAuthenticated(true);
      setError(null);
    } catch (err) {
      console.error('Login failed:', err);
      setError(`Failed to log in: ${err.response?.data?.error || err.message}`);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setIsAuthenticated(false);
  };

  if (isAuthenticated) {
    return (
      <ThemeProvider theme={theme}>
        <SpectrogramPage token={token} onLogout={handleLogout} darkMode={darkMode} setDarkMode={setDarkMode} />
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
            <button type="submit" style={{ padding: '10px 20px', borderRadius: '4px' }}>
              {isRegistering ? 'Register' : 'Login'}
            </button>
            <button
              type="button"
              onClick={() => setIsRegistering(!isRegistering)}
              style={{ padding: '10px 20px', borderRadius: '4px' }}
            >
              {isRegistering ? 'Switch to Login' : 'Switch to Register'}
            </button>
          </Box>
        </form>
      </Box>
    </ThemeProvider>
  );
}

/**
 * Component to display the spectrogram data in 3D.
 * @param {string} token - Authentication token for API requests
 * @param {function} onLogout - Callback to handle logout
 * @param {boolean} darkMode - Current theme mode
 * @param {function} setDarkMode - Function to toggle dark mode
 */
function SpectrogramPage({ token, onLogout, darkMode, setDarkMode }) {
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
  const wsRef = useRef(null);
  const theme = useTheme();

  useEffect(() => {
    localStorage.setItem('drawerOpen', JSON.stringify(drawerOpen));
  }, [drawerOpen]);

  const drawerWidth = 240;
  const appBarHeight = 64;

  useEffect(() => {
    const fetchKey = async () => {
      try {
        const response = await axios.post(
          `${API_BASE_URL}/key-exchange`,
          {},
          { headers: { Authorization: `Bearer ${token}` } }
        );
        console.log('Key exchange successful:', response.data);
        setEncryptionKey(response.data.key);
      } catch (err) {
        console.error('Key exchange failed:', err);
        setError(`Failed to fetch encryption key: ${err.response?.data?.error || err.message}`);
      }
    };
    if (token) fetchKey();
  }, [token]);

  const connectWebSocket = () => {
    if (!token || !encryptionKey) {
      console.log('Skipping WebSocket connection: token or encryptionKey missing', { token, encryptionKey });
      return;
    }

    const ws = new WebSocket(`${WS_URL}/?token=${token}`);
    wsRef.current = ws;

    console.log('Attempting WebSocket connection to:', WS_URL);
    console.log('Encryption key (hex):', encryptionKey);

    ws.onopen = () => console.log('WebSocket connected');
    ws.onmessage = (event) => {
      try {
        const messageStr = event.data;
        if (!messageStr) {
          console.log('Received empty WebSocket message');
          return;
        }
        const [encrypted, iv] = messageStr.split(':');
        if (!encrypted || !iv) throw new Error('Invalid message format');

        const encryptedBuf = enc.Base64.parse(encrypted);
        const ivBuf = enc.Base64.parse(iv);
        const keyWordArray = enc.Hex.parse(encryptionKey);
        const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: encryptedBuf });
        const decrypted = AES.decrypt(cipherParams, keyWordArray, { iv: ivBuf, mode: mode.CBC, padding: pad.Pkcs7 });
        const messageStrDecrypted = decrypted.toString(enc.Utf8);
        if (!messageStrDecrypted) throw new Error('Decryption failed');

        const message = JSON.parse(messageStrDecrypted);
        if (!message.spectrogram || !Array.isArray(message.spectrogram)) throw new Error('Invalid spectrogram data');

        console.log('Decrypted message sample (around 7.83 Hz):', message.spectrogram.slice(780, 790));
        setSpectrogramData((prev) => {
          const newData = [...prev, message.spectrogram].slice(-timeSteps);
          console.log('Spectrogram data length:', newData.length);
          console.log('Latest sample (around 7.83 Hz):', newData[newData.length - 1]?.slice(780, 790));
          return newData;
        });
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
      console.log('WebSocket disconnected, attempting to reconnect...');
      const reconnectWithBackoff = (attempt = 1) => {
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        console.log(`Reconnecting in ${delay / 1000}s (attempt ${attempt})...`);
        setTimeout(() => reconnectWithBackoff(attempt + 1), delay);
      };
      reconnectWithBackoff();
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  };

  const fetchHistoricalData = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/history/${historicalHours}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      console.log('Historical data response:', response.data); // Debug log
      const historicalSpectrograms = Array.isArray(response.data) ? response.data : [];
      setSpectrogramData(historicalSpectrograms.slice(-timeSteps).map(s => s || [])); // Handle empty or invalid data
    } catch (err) {
      console.error('Historical data fetch error:', err);
      setError(`Failed to fetch historical data: ${err.message}`);
    }
  };

  useEffect(() => {
    if (!encryptionKey) {
      console.log('Waiting for encryption key before connecting WebSocket...');
      return;
    }
    if (historicalMode) fetchHistoricalData();
    else return connectWebSocket();
  }, [historicalMode, historicalHours, token, encryptionKey, timeSteps]);

  const downsampleFactor = 5;
  const xLabels = Array(5501).fill(0)
    .map((_, i) => (i / 100).toFixed(2))
    .filter((_, i) => i % downsampleFactor === 0);
  const zData = spectrogramData.map(data => data.filter((_, i) => i % downsampleFactor === 0));
  console.log('Z data (first few rows, around 7.83 Hz):', zData.map(row => row.slice(156, 162)));

  const yLabels = spectrogramData.map((_, i) => {
    const secondsAgo = (spectrogramData.length - 1 - i) * 5;
    return secondsAgo === 0 ? 'Now' : `-${secondsAgo}s`;
  });

  const normalizeData = (data) => {
    const allValues = data.flat();
    const min = Math.min(...allValues);
    const max = Math.max(...allValues);
    const range = max - min;
    return data.map(row => row.map(value => range > 0 ? ((value - min) / range) * 15 : 0));
  };

  const displayData = normalize ? normalizeData(zData) : zData;
  const getMinMaxAmplitude = () => {
    if (displayData.length === 0) return { min: 0, max: 15 };
    const allValues = displayData.flat();
    const min = Math.min(...allValues);
    const max = Math.max(...allValues);
    return { min: Math.max(0, min), max: Math.min(15, max + 1) };
  };
  const { min: minAmplitude, max: maxAmplitude } = getMinMaxAmplitude();

  const plotData = [{
    z: displayData,
    x: xLabels,
    y: yLabels,
    type: 'surface',
    colorscale: colorScale === 'Jet' ? 'Jet' : 'Greys',
    showscale: true,
    colorbar: { title: 'Amplitude', titleside: 'right' },
  }];

  const layout = {
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
        title: {
          text: 'Frequency (Hz)',
          font: { size: 14, color: darkMode ? '#ffffff' : '#000000' },
        },
        tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
        gridcolor: darkMode ? '#444444' : '#d3d3d3',
        zerolinecolor: darkMode ? '#ffffff' : '#000000',
      },
      yaxis: {
        title: {
          text: 'Time (seconds)',
          font: { size: 14, color: darkMode ? '#ffffff' : '#000000' },
        },
        tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
        gridcolor: darkMode ? '#444444' : '#d3d3d3',
        zerolinecolor: darkMode ? '#ffffff' : '#000000',
      },
      zaxis: {
        title: {
          text: 'Amplitude',
          font: { size: 14, color: darkMode ? '#ffffff' : '#000000' },
        },
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
  };

  // Debug log to verify layout
  console.log('Plotly layout:', JSON.stringify(layout, null, 2));
  console.log('Computed main Box height:', `calc(100vh - ${appBarHeight}px)`);

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
                onChange={(_, newValue) => setTimeSteps(Math.floor(newValue / 5))}
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
                  onChange={(_, newValue) => setHistoricalHours(newValue)}
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
            height: `calc(100vh - ${appBarHeight}px)`, // Ensure height is correctly calculated
            display: 'flex',
            flexDirection: 'column',
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.easeInOut,
              duration: 500,
            }),
          }}
        >
          {error && <Typography color="error">{error}</Typography>}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Connected to server at: {API_BASE_URL}
          </Typography>
          <Box sx={{ flex: 1, minHeight: 0 }}>
            <Plotly
              data={plotData}
              layout={layout}
              style={{ width: '100%', height: '100%' }} // Explicitly set height and width
              useResizeHandler
              key={`plot-${darkMode}-${timeSteps}-${historicalMode}-${colorScale}-${normalize}`} // Force re-render on state changes
            />
          </Box>
        </Box>
      </Box>
    </>
  );
}

export default App;
