/**
 * Main application component for EarthSync client.
 * Handles authentication, theme toggling, and renders the SpectrogramPage with a globe at the bottom of the sidebar matching width and invisible backgrounds, 
 * a properly scaling chart with equal margins, and hover feedback on sidebar buttons.
 */
import React, { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import axios from 'axios';
import CryptoJS from 'crypto-js';
import Plotly from 'react-plotly.js';
import debounce from 'lodash.debounce';
import throttle from 'lodash.throttle';
import Globe from 'react-globe.gl';
import {
  AppBar, Toolbar, Typography, Drawer, List, ListItem, ListItemIcon, ListItemText,
  IconButton, CssBaseline, Box, Slider, FormControl, FormLabel, Switch, useTheme,
  ThemeProvider, createTheme, Select, MenuItem, Divider
} from '@mui/material';
import {
  Menu as MenuIcon, Brightness4 as Brightness4Icon, Brightness7 as Brightness7Icon,
  BarChart as BarChartIcon, Logout as LogoutIcon, History as HistoryIcon
} from '@mui/icons-material';

// Load environment variables as defaults
const DEFAULT_API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:3000';
const DEFAULT_WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:3000';

// Function to determine the working API and WS URLs with localhost fallback
async function determineServerUrls(defaultApiUrl, defaultWsUrl) {
  const fallbackApiUrl = 'http://localhost:3000';
  const fallbackWsUrl = 'ws://localhost:3000';
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
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [error, setError] = useState(null);
  const [darkMode, setDarkMode] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [serverUrls, setServerUrls] = useState(null);

  const theme = createTheme({
    palette: { mode: darkMode ? 'dark' : 'light', primary: { main: '#1976d2' }, secondary: { main: '#f50057' } }
  });

  useEffect(() => { determineServerUrls(DEFAULT_API_BASE_URL, DEFAULT_WS_URL).then(setServerUrls); }, []);
  useEffect(() => { if (token) setIsAuthenticated(true); }, [token]);

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
      setError(`Failed to register: ${err.message}`);
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
      setError(`Failed to log in: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setIsAuthenticated(false);
  };

  if (!serverUrls) return <ThemeProvider theme={theme}><CssBaseline /><Box sx={{ padding: 3, textAlign: 'center' }}><Typography variant="h6">Initializing server connection...</Typography></Box></ThemeProvider>;

  if (isAuthenticated) {
    return (
      <ThemeProvider theme={theme}>
        <SpectrogramPage token={token} onLogout={handleLogout} darkMode={darkMode} setDarkMode={setDarkMode} apiUrl={serverUrls.apiUrl} wsUrl={serverUrls.wsUrl} />
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ padding: 3, maxWidth: 400, margin: '0 auto' }}>
        <Typography variant="h6" gutterBottom>{isRegistering ? 'Register' : 'Login'}</Typography>
        {isLoading && <Typography>Loading...</Typography>}
        {error && <Typography color="error">{error}</Typography>}
        <form onSubmit={isRegistering ? handleRegister : handleLogin}>
          <Box sx={{ mb: 2 }}>
            <FormLabel htmlFor="username-input">Username</FormLabel>
            <input id="username-input" type="text" value={username} onChange={(e) => setUsername(e.target.value)} required style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid' }} />
          </Box>
          <Box sx={{ mb: 2 }}>
            <FormLabel htmlFor="password-input">Password</FormLabel>
            <input id="password-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required style={{ width: '100%', padding: '8px', borderRadius: '4px', border: '1px solid' }} />
          </Box>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <button type="submit" style={{ padding: '10px 20px', borderRadius: '4px' }} disabled={isLoading}>{isRegistering ? 'Register' : 'Login'}</button>
            <button type="button" onClick={() => setIsRegistering(!isRegistering)} style={{ padding: '10px 20px', borderRadius: '4px' }} disabled={isLoading}>{isRegistering ? 'Switch to Login' : 'Switch to Register'}</button>
          </Box>
        </form>
      </Box>
    </ThemeProvider>
  );
}

const SpectrogramPage = React.memo(({ token, onLogout, darkMode, setDarkMode, apiUrl, wsUrl }) => {
  const [spectrogramData, setSpectrogramData] = useState({});
  const [detectorActivity, setDetectorActivity] = useState({});
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [error, setError] = useState(null);
  const [timeSteps, setTimeSteps] = useState(60);
  const [historicalMode, setHistoricalMode] = useState(false);
  const [historicalHours, setHistoricalHours] = useState(1);
  const [colorScale, setColorScale] = useState('Jet');
  const [normalize, setNormalize] = useState(false);
  const [selectedDetector, setSelectedDetector] = useState('all');
  const [drawerOpen, setDrawerOpen] = useState(() => JSON.parse(localStorage.getItem('drawerOpen') || 'true'));
  const [isLoading, setIsLoading] = useState(false);
  const [lastActiveDetector, setLastActiveDetector] = useState(null);
  const wsRef = useRef(null);
  const globeRef = useRef();
  const appBarRef = useRef(null);
  const theme = useTheme();

  useEffect(() => {
    localStorage.setItem('drawerOpen', JSON.stringify(drawerOpen));
  }, [drawerOpen]);

  const drawerWidth = 300;
  const [appBarHeight, setAppBarHeight] = useState(64); // Initial value, will be updated
  const margin = 20; // Uniform margin value

  useEffect(() => {
    if (appBarRef.current) {
      const height = appBarRef.current.offsetHeight;
      setAppBarHeight(height);
      console.log('AppBar height updated:', height);
    }
  }, []);

  const updateSpectrogram = useMemo(() => throttle((newData) => {
    let lastActiveId = null;
    newData.forEach(data => {
      if (!data.detectorId || !data.location) return;
      setSpectrogramData(prev => ({
        ...prev,
        [data.detectorId]: (prev[data.detectorId] || []).concat(data.spectrogram).slice(-timeSteps)
      }));
      setDetectorActivity(prev => ({
        ...prev,
        [data.detectorId]: { lat: data.location.lat, lon: data.location.lon, lastUpdate: Date.now() }
      }));
      lastActiveId = data.detectorId;
    });
    if (lastActiveId) setLastActiveDetector(lastActiveId);
    console.log('Spectrogram data updated:', { lastActiveId, dataLength: newData.length, sample: newData[0]?.spectrogram?.slice(0, 5) || 'empty' });
  }, 1000), [timeSteps]);

  useEffect(() => {
    const fetchKey = async () => {
      setIsLoading(true);
      try {
        const response = await axios.post(`${apiUrl}/key-exchange`, {}, { headers: { Authorization: `Bearer ${token}` } });
        console.log('Key exchange successful:', response.data);
        setEncryptionKey(response.data.key);
      } catch (err) {
        console.error('Key exchange failed:', err);
        setError(`Failed to fetch encryption key: ${err.message}`);
      } finally {
        setIsLoading(false);
      }
    };
    if (token) fetchKey();
  }, [token, apiUrl]);

  const connectWebSocket = useCallback(() => {
    if (!token || !encryptionKey) return;
    const ws = new WebSocket(`${wsUrl}/?token=${token}`);
    wsRef.current = ws;

    console.log('Attempting WebSocket connection to:', wsUrl);
    ws.onopen = () => console.log('WebSocket connected');
    ws.onmessage = (event) => {
      try {
        const [encrypted, iv] = event.data.split(':');
        const encryptedBuf = CryptoJS.enc.Base64.parse(encrypted);
        const ivBuf = CryptoJS.enc.Base64.parse(iv);
        const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
        const decrypted = CryptoJS.AES.decrypt({ ciphertext: encryptedBuf }, keyWordArray, { iv: ivBuf, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        const message = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
        updateSpectrogram([message]);
      } catch (err) {
        console.error('WebSocket message processing error:', err);
        setError(`WebSocket error: ${err.message}`);
      }
    };
    ws.onerror = (err) => setError('WebSocket connection error');
    ws.onclose = () => {
      console.log('WebSocket disconnected, reconnecting...');
      setTimeout(() => connectWebSocket(), 1000 * Math.pow(2, Math.min(10, 1)));
    };
    return () => ws.close();
  }, [token, encryptionKey, wsUrl]);

  const fetchHistoricalData = async () => {
    setIsLoading(true);
    try {
      const response = await axios.get(`${apiUrl}/history/${historicalHours}${selectedDetector !== 'all' ? `?detectorId=${selectedDetector}` : ''}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      console.log('Historical data response:', response.data);
      const historicalData = Array.isArray(response.data) ? response.data : Object.values(response.data).flat();
      const updatedSpectrogramData = {};
      historicalData.forEach(data => {
        if (data.detectorId && Array.isArray(data.spectrogram)) {
          updatedSpectrogramData[data.detectorId] = (updatedSpectrogramData[data.detectorId] || []).concat(data.spectrogram).slice(-timeSteps);
        }
      });
      setSpectrogramData(prev => ({ ...prev, ...updatedSpectrogramData }));
      console.log('Updated spectrogramData:', updatedSpectrogramData);
    } catch (err) {
      console.error('Historical data fetch error:', err);
      setError(`Failed to fetch historical data: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!encryptionKey) return;
    if (historicalMode) fetchHistoricalData();
    else connectWebSocket();
  }, [historicalMode, historicalHours, token, encryptionKey, selectedDetector]);

  const downsampleFactor = 5;
  const xLabels = useMemo(() => {
    const labels = Array.from({ length: 5501 }, (_, i) => (i * (55 / 5500)).toFixed(2)); // Map 0-5500 to 0-55 Hz
    const downsampledLabels = labels.filter((_, i) => i % downsampleFactor === 0);
    console.log('xLabels:', downsampledLabels.slice(0, 5), '...', downsampledLabels.slice(-5)); // Debug xLabels
    return downsampledLabels;
  }, []);
  const zData = useMemo(() => {
    const data = selectedDetector === 'all' 
      ? Object.values(spectrogramData).flat().slice(-timeSteps)
      : (spectrogramData[selectedDetector] || []).slice(-timeSteps);
    const validData = data.length > 0 ? data.map(row => {
      const downsampled = row.filter((_, i) => i % downsampleFactor === 0);
      return downsampled.length < xLabels.length 
        ? [...downsampled, ...Array(xLabels.length - downsampled.length).fill(0)]
        : downsampled.slice(0, xLabels.length);
    }) : Array(timeSteps).fill().map(() => Array(xLabels.length).fill(0));
    console.log('zData computed:', { length: validData.length, cols: validData[0]?.length || 0, sample: validData[0]?.slice(0, 5) || 'empty' });
    return validData;
  }, [spectrogramData, selectedDetector, timeSteps, xLabels.length]);
  const yLabels = useMemo(() => zData.map((_, i) => {
    const secondsAgo = (zData.length - 1 - i) * 5;
    return secondsAgo === 0 ? 'Now' : `-${secondsAgo}s`;
  }), [zData]);

  const normalizeData = (data) => {
    const allValues = data.flat();
    if (allValues.length === 0 || allValues.some(v => typeof v !== 'number' || isNaN(v))) return data;
    const min = Math.min(...allValues);
    const max = Math.max(...allValues);
    const range = max - min;
    return data.map(row => row.map(value => range > 0 ? ((value - min) / range) * 15 : 0));
  };

  const displayData = useMemo(() => {
    const normalized = normalize ? normalizeData(zData) : zData;
    console.log('displayData:', { rows: normalized.length, cols: normalized[0]?.length || 0, sample: normalized[0]?.slice(0, 5) || 'empty' });
    return normalized;
  }, [normalize, zData]);
  const { minAmplitude, maxAmplitude } = useMemo(() => {
    const allValues = displayData.flat();
    return allValues.length ? { min: Math.max(0, Math.min(...allValues)), max: Math.min(15, Math.max(...allValues) + 1) } : { min: 0, max: 15 };
  }, [displayData]);

  const plotData = useMemo(() => {
    console.log('plotData.z:', displayData); // Debug the final data
    const baseData = [{
      z: displayData,
      x: xLabels,
      y: yLabels,
      type: 'surface',
      colorscale: colorScale === 'Jet' ? 'Jet' : 'Greys',
      showscale: true,
      colorbar: { title: 'Amplitude', titleside: 'right' },
      contours: { z: { show: true, usecolormap: true } }
    }];
    return baseData;
  }, [displayData, xLabels, yLabels, colorScale]);

  // Dynamically update layout dimensions based on window size
  const [chartWidth, setChartWidth] = useState(Math.max(100, window.innerWidth - (drawerOpen ? drawerWidth : 0) - 2 * margin));
  const [chartHeight, setChartHeight] = useState(Math.max(100, window.innerHeight - appBarHeight - 2 * margin));
  useEffect(() => {
    const handleResize = () => {
      const newWidth = Math.max(100, window.innerWidth - (drawerOpen ? drawerWidth : 0) - 2 * margin);
      const newHeight = Math.max(100, window.innerHeight - appBarHeight - 2 * margin);
      setChartWidth(newWidth);
      setChartHeight(newHeight);
      console.log('Resize:', { windowWidth: window.innerWidth, windowHeight: window.innerHeight, appBarHeight, drawerWidth, margin, chartWidth: newWidth, chartHeight: newHeight });
    };
    window.addEventListener('resize', handleResize);
    handleResize(); // Initial call
    return () => window.removeEventListener('resize', handleResize);
  }, [appBarHeight, drawerOpen, drawerWidth, margin]);

  const layout = useMemo(() => ({
    title: { text: 'Schumann Resonance 3D Surface Plot', font: { size: 18, color: darkMode ? '#ffffff' : '#000000' }, x: 0.5, xanchor: 'center', y: 0.95, yanchor: 'top' },
    scene: {
      xaxis: { title: { text: 'Frequency (Hz)', font: { size: 14, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' }, gridcolor: darkMode ? '#444444' : '#d3d3d3', zerolinecolor: darkMode ? '#ffffff' : '#000000' },
      yaxis: { title: { text: 'Time (seconds)', font: { size: 14, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' }, gridcolor: darkMode ? '#444444' : '#d3d3d3', zerolinecolor: darkMode ? '#ffffff' : '#000000' },
      zaxis: { title: { text: 'Amplitude', font: { size: 14, color: darkMode ? '#ffffff' : '#000000' } }, tickfont: { size: 12, color: darkMode ? '#ffffff' : '#000000' }, range: [minAmplitude, maxAmplitude], gridcolor: darkMode ? '#444444' : '#d3d3d3', zerolinecolor: darkMode ? '#ffffff' : '#000000' },
      camera: { eye: { x: 1.5, y: 1.5, z: 0.8 } }
    },
    margin: { t: margin, r: margin, b: margin, l: margin }, // Equal margins on all sides
    autosize: false, // Disable autosize to respect manual width and height
    width: chartWidth - 2 * margin, // Adjust for padding
    height: chartHeight - 2 * margin, // Adjust for padding
    paper_bgcolor: 'rgba(0, 0, 0, 0)', // Invisible background
    plot_bgcolor: 'rgba(0, 0, 0, 0)', // Invisible background
    modebar: { orientation: 'h', y: 0, yanchor: 'top', x: 1, xanchor: 'right', bgcolor: 'transparent', color: 'white', activecolor: '#1976d2' }
  }), [darkMode, minAmplitude, maxAmplitude, chartWidth, chartHeight, margin]);

  const globePoints = useMemo(() => Object.entries(detectorActivity).map(([id, { lat, lon, lastUpdate }]) => ({
    lat,
    lng: lon,
    size: (Date.now() - lastUpdate < 5000) ? 0.5 : 0.2,
    color: (Date.now() - lastUpdate < 5000) ? 'red' : 'blue',
    label: `${lat.toFixed(2)}, ${lon.toFixed(2)}`
  })), [detectorActivity]);

  const detectorOptions = useMemo(() => Object.entries(detectorActivity).map(([id]) => ({
    id,
    label: id
  })), [detectorActivity]);

  const debouncedSetTimeSteps = useCallback(debounce((value) => setTimeSteps(Math.floor(value / 5)), 300), []);
  const debouncedSetHistoricalHours = useCallback(debounce((value) => setHistoricalHours(value), 300), []);

  return (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <CssBaseline />
      <AppBar ref={appBarRef} position="fixed" sx={{ width: '100%', ml: 0, zIndex: (theme) => theme.zIndex.drawer + 2 }}>
        <Toolbar>
          <IconButton color="inherit" edge="start" onClick={() => setDrawerOpen(!drawerOpen)} sx={{ mr: 2 }}><MenuIcon /></IconButton>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>EarthSync - Schumann Resonance</Typography>
          <IconButton color="inherit" onClick={() => setDarkMode(!darkMode)}>{darkMode ? <Brightness7Icon /> : <Brightness4Icon />}</IconButton>
        </Toolbar>
      </AppBar>
      <Box sx={{ mt: `${appBarHeight}px`, display: 'flex', flexGrow: 1 }}> {/* Wrapper to push content below app bar */}
        <Drawer
          variant="permanent"
          sx={{
            width: drawerOpen ? drawerWidth : 0,
            flexShrink: 0,
            '& .MuiDrawer-paper': {
              width: drawerOpen ? drawerWidth : 0,
              boxSizing: 'border-box',
              overflowX: 'hidden',
              transition: theme.transitions.create('width', { easing: theme.transitions.easing.easeInOut, duration: 500 }),
              display: 'flex',
              flexDirection: 'column',
              zIndex: (theme) => theme.zIndex.drawer + 1 // Ensure drawer is above main content
            }
          }}
        >
          <Toolbar />
          <Box sx={{ flexGrow: 1 }}>
            <List>
              <ListItem onClick={() => setHistoricalMode(false)} sx={{ '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.1)' } }}>
                <ListItemIcon><BarChartIcon /></ListItemIcon><ListItemText primary="Spectrogram" />
              </ListItem>
              <ListItem onClick={() => setHistoricalMode(true)} sx={{ '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.1)' } }}>
                <ListItemIcon><HistoryIcon /></ListItemIcon><ListItemText primary="Historical Data" />
              </ListItem>
              <ListItem onClick={onLogout} sx={{ '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.1)' } }}>
                <ListItemIcon><LogoutIcon /></ListItemIcon><ListItemText primary="Logout" />
              </ListItem>
            </List>
            <Divider />
            <Box sx={{ p: 2 }}>
              <FormControl fullWidth sx={{ mb: 2, minWidth: '200px' }}>
                <FormLabel>Detector</FormLabel>
                <Select value={selectedDetector} onChange={(e) => setSelectedDetector(e.target.value)}>
                  <MenuItem value="all">All Detectors</MenuItem>
                  {detectorOptions.map(({ id, label }) => (
                    <MenuItem key={id} value={id}>{label}</MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <FormLabel>Time Window (seconds)</FormLabel>
                <Slider value={timeSteps * 5} onChange={(_, val) => debouncedSetTimeSteps(val)} min={30} max={600} step={5} marks valueLabelDisplay="auto" />
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
                  <Slider value={historicalHours} onChange={(_, val) => debouncedSetHistoricalHours(val)} min={1} max={24} step={1} marks valueLabelDisplay="auto" />
                </FormControl>
              )}
            </Box>
          </Box>
          <Box sx={{ p: 2, display: 'flex', justifyContent: 'center' }}>
            <Globe
              ref={globeRef}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              backgroundColor='rgba(0, 0, 0, 0)' // Invisible background
              pointsData={globePoints}
              pointLat="lat"
              pointLng="lng"
              pointColor="color"
              pointRadius="size"
              pointAltitude={0.1}
              labelLat="lat"
              labelLng="lng"
              labelText="label"
              labelSize={0.5}
              labelDotRadius={0.2}
              labelColor={() => 'white'}
              labelAltitude={0.2}
              pointLightColor="white"
              pointLightIntensity={1.5}
              pointLightAltitude={100}
              width={drawerWidth} // Match sidebar width
              height={drawerWidth} // Match sidebar height for square aspect
            />
          </Box>
        </Drawer>
        <Box 
          component="main" 
          sx={{ 
            flexGrow: 1, 
            width: drawerOpen ? `calc(100% - ${drawerWidth}px)` : '100%', // Dynamic width based on sidebar
            mx: 'auto', // Center the chart when sidebar is closed
            height: `calc(100vh - ${appBarHeight}px - ${2 * margin}px)`, // Full height minus app bar and margins
            display: 'flex', 
            flexDirection: 'column', 
            overflow: 'hidden',
            padding: `${margin}px`, // Equal padding on all sides
            boxSizing: 'border-box', // Ensure padding is included in height/width
          }}
        >
          {isLoading && <Typography>Loading...</Typography>}
          {error && <Typography color="error">{error}</Typography>}
          <Box sx={{ flex: 1, overflow: 'hidden', minHeight: 0, minWidth: 0, padding: 0 }}>
            <Plotly 
              data={plotData} 
              layout={layout} 
              revision={Object.values(spectrogramData).flat().length} 
              style={{ width: '100%', height: '100%' }} 
              useResizeHandler 
              config={{ responsive: true, displayModeBar: false, willReadFrequently: true }} // Address warning
            />
          </Box>
        </Box>
      </Box>
    </Box>
  );
});

SpectrogramPage.displayName = 'SpectrogramPage';
export default App;
