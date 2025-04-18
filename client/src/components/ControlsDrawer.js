// client/src/components/ControlsDrawer.js
/**
 * Component responsible for rendering the controls drawer, including mode switching,
 * plot controls, peak/transient info, and the detector globe.
 * v1.1.28 - Use Centralized Constants.
 */
import React, { useRef } from 'react';
import PropTypes from 'prop-types';
import Globe from 'react-globe.gl';
import {
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Divider,
  Box,
  FormControl,
  FormLabel,
  Select,
  MenuItem,
  Typography,
  Slider,
  FormControlLabel,
  Switch,
  CircularProgress,
  Tooltip,
  Button,
  ButtonGroup,
} from '@mui/material';
import {
  BarChart as BarChartIcon,
  Logout as LogoutIcon,
  History as HistoryIcon,
  Insights as InsightsIcon,
  WarningAmber as WarningAmberIcon,
  ViewInAr as ViewInArIcon, // Icon for 3D Surface
  Map as MapIcon, // Icon for 2D Heatmap
} from '@mui/icons-material';
// Import relevant constants
import { PLOT_COLOR_SCALES } from '../constants';

// Extracted Drawer Component
const ControlsDrawer = React.memo(
  ({
    // Props for Drawer state and appearance
    drawerWidth, // Use constant passed from parent
    appBarHeight,
    drawerOpen,
    darkMode,
    theme, // Pass theme for consistent styling

    // Props for Data Mode
    historicalMode,
    handleModeChange,
    onLogout,

    // Props for Controls
    selectedDetector,
    handleDetectorChange,
    detectorOptions,
    timeSteps, // Used to display current slider value
    debouncedSetTimeSteps, // Function to call on slider change
    colorScale,
    setColorScale, // Use stable setter
    normalize,
    setNormalize, // Use stable setter
    historicalHours, // Used to display current slider value
    debouncedSetHistoricalHours, // Function to call on slider change
    isLoadingData,
    isTransitioning,

    // Props for Peak/Transient Info Display
    currentPeakInfo, // Formatted string or null
    historicalTransientEvents, // Array of transient events

    // Props for Globe
    globePoints, // Array of points for the globe
    handleGlobePointClick,
    handleGlobePointHover,

    // Props for Plot Type Toggle
    plotType,
    setPlotType, // Use stable setter
  }) => {
    const globeRef = useRef(null); // Ref for the Globe component instance

    // Callback for internal slider changes BEFORE debouncing
    // This updates the displayed value immediately for better UX
    const handleTimeStepsSliderChange = (event, newValue) => {
      // Call the debounced function to update the actual state after a delay
      debouncedSetTimeSteps(newValue);
    };
    const handleHistoricalHoursSliderChange = (event, newValue) => {
      debouncedSetHistoricalHours(newValue);
    };

    return (
      <Drawer
        variant="persistent" // Drawer stays visible when open
        anchor="left"
        open={drawerOpen}
        sx={{
          width: drawerWidth, // Use width from props/constants
          flexShrink: 0, // Prevent drawer from shrinking when content grows
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            overflowX: 'hidden', // Prevent horizontal scrollbar
            mt: `${appBarHeight}px`, // Position below AppBar
            height: `calc(100% - ${appBarHeight}px)`, // Fill remaining height
            // Smooth transition for drawer width when opening/closing
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: drawerOpen
                ? theme.transitions.duration.enteringScreen
                : theme.transitions.duration.leavingScreen,
            }),
            display: 'flex',
            flexDirection: 'column',
            borderRight: `1px solid ${theme.palette.divider}`, // Subtle border
          },
        }}
        aria-label="Controls Drawer"
      >
        {/* --- Scrollable Area for Controls --- */}
        <Box sx={{ flexGrow: 1, overflowY: 'auto', p: 2 }}>
          {' '}
          {/* Add padding */}
          {/* Mode Selection List */}
          <List dense>
            {' '}
            {/* Use dense list for slightly smaller items */}
            <ListItem disablePadding>
              <ListItemButton
                onClick={() => handleModeChange(false)}
                selected={!historicalMode}
                aria-current={!historicalMode ? 'page' : 'false'}
              >
                <ListItemIcon>
                  <BarChartIcon />
                </ListItemIcon>
                <ListItemText primary="Real-time Data" />
              </ListItemButton>
            </ListItem>
            <ListItem disablePadding>
              <ListItemButton
                onClick={() => handleModeChange(true)}
                selected={historicalMode}
                aria-current={historicalMode ? 'page' : 'false'}
              >
                <ListItemIcon>
                  <HistoryIcon />
                </ListItemIcon>
                <ListItemText primary="Historical Data" />
              </ListItemButton>
            </ListItem>
            <ListItem disablePadding>
              <ListItemButton onClick={onLogout}>
                <ListItemIcon>
                  <LogoutIcon />
                </ListItemIcon>
                <ListItemText primary="Logout" />
              </ListItemButton>
            </ListItem>
          </List>
          <Divider sx={{ my: 2 }} />
          {/* --- Spectrogram View Controls Section --- */}
          <Typography variant="overline" display="block" gutterBottom sx={{ px: 1 }}>
            {' '}
            {/* Use overline style */}
            Spectrogram View
          </Typography>
          {/* Plot Type Toggle */}
          <FormControl fullWidth sx={{ mb: 2, px: 1 }}>
            <FormLabel id="plot-type-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
              Plot Type
            </FormLabel>
            <ButtonGroup
              variant="outlined"
              aria-labelledby="plot-type-label"
              fullWidth
              size="small"
            >
              <Button
                onClick={() => setPlotType('3d')}
                variant={plotType === '3d' ? 'contained' : 'outlined'}
                startIcon={<ViewInArIcon />}
                aria-pressed={plotType === '3d'}
              >
                3D Surface
              </Button>
              <Button
                onClick={() => setPlotType('2d')}
                variant={plotType === '2d' ? 'contained' : 'outlined'}
                startIcon={<MapIcon />}
                aria-pressed={plotType === '2d'}
              >
                2D Heatmap
              </Button>
            </ButtonGroup>
          </FormControl>
          {/* Detector Selection */}
          <FormControl fullWidth sx={{ mb: 2, px: 1 }}>
            <FormLabel id="detector-select-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
              Detector
            </FormLabel>
            <Select
              labelId="detector-select-label"
              value={selectedDetector}
              onChange={handleDetectorChange}
              size="small"
              aria-describedby="detector-select-desc"
              MenuProps={{ PaperProps: { sx: { maxHeight: 200 } } }} // Limit dropdown height
            >
              {detectorOptions.map(({ id, label }) => (
                <MenuItem key={id} value={id}>
                  {label}
                </MenuItem>
              ))}
            </Select>
            <Typography
              variant="caption"
              id="detector-select-desc"
              sx={{ mt: 0.5, color: 'text.secondary' }}
            >
              Select detector(s) to display data for.
            </Typography>
          </FormControl>
          {/* Time Window Slider */}
          <FormControl fullWidth sx={{ mb: 2, px: 1 }}>
            <FormLabel id="time-window-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
              Time Window (seconds)
            </FormLabel>
            <Slider
              aria-labelledby="time-window-label"
              value={timeSteps * 5} // Display value in seconds
              onChange={handleTimeStepsSliderChange} // Update display immediately
              // onChangeCommitted={(_, val) => debouncedSetTimeSteps(val)} // Use debouncedSetTimeSteps for final update? No, handled in App.js
              min={30}
              max={600}
              step={5}
              marks
              valueLabelDisplay="auto"
              size="small"
            />
            <Typography
              variant="caption"
              id="time-window-desc"
              sx={{ mt: 0.5, color: 'text.secondary' }}
            >
              Real-time view duration & history plot length.
            </Typography>
          </FormControl>
          {/* Color Scale */}
          <FormControl fullWidth sx={{ mb: 2, px: 1 }}>
            <FormLabel id="colorscale-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
              Color Scale
            </FormLabel>
            <Select
              labelId="colorscale-label"
              value={colorScale}
              onChange={(e) => setColorScale(e.target.value)}
              size="small"
            >
              {/* Use constant for options */}
              {PLOT_COLOR_SCALES.map((scaleName) => (
                <MenuItem key={scaleName} value={scaleName}>
                  {scaleName}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {/* Normalize Switch */}
          <FormControlLabel
            control={
              <Switch checked={normalize} onChange={() => setNormalize(!normalize)} size="small" />
            }
            label="Normalize Amplitude"
            sx={{ mb: 1, display: 'block', px: 1 }}
          />
          {/* Historical Hours Slider (Conditional) */}
          {historicalMode && (
            <FormControl fullWidth sx={{ mb: 2, px: 1 }}>
              <FormLabel id="historical-hours-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
                Historical Hours
              </FormLabel>
              <Slider
                aria-labelledby="historical-hours-label"
                value={historicalHours}
                onChange={handleHistoricalHoursSliderChange} // Update display immediately
                // onChangeCommitted={(_, val) => debouncedSetHistoricalHours(val)} // Use debouncedSetHistoricalHours for final update? No, handled in App.js
                min={1}
                max={72}
                step={1}
                marks
                valueLabelDisplay="auto"
                size="small"
              />
            </FormControl>
          )}
          <Divider sx={{ my: 2 }} />
          {/* --- Peak Info Section --- */}
          <Typography variant="overline" display="block" gutterBottom sx={{ px: 1 }}>
            Peak Information
          </Typography>
          {selectedDetector !== 'all' ? (
            <Box
              sx={{
                mt: 1,
                p: 1.5,
                border: `1px dashed ${theme.palette.divider}`,
                borderRadius: 1,
                mx: 1,
                bgcolor: 'action.hover',
              }}
            >
              <Typography
                variant="caption"
                sx={{ display: 'flex', alignItems: 'center', mb: 0.5, fontWeight: 'medium' }}
              >
                <InsightsIcon sx={{ fontSize: '1rem', mr: 0.5, color: 'primary.main' }} />
                {historicalMode ? 'Latest Hist.' : 'Detected'} Peaks ({selectedDetector}):
                {/* Show warning icon if historical transients exist */}
                {historicalMode && historicalTransientEvents.length > 0 && (
                  <Tooltip
                    title={`${historicalTransientEvents.length} transient event(s) detected in this period`}
                  >
                    <WarningAmberIcon sx={{ ml: 1, color: 'warning.main', fontSize: '1.1rem' }} />
                  </Tooltip>
                )}
              </Typography>
              {/* Display peak info string or loading/NA message */}
              <Typography
                variant="caption"
                sx={{ display: 'block', wordBreak: 'break-word', pl: 2.5 /* Indent text */ }}
              >
                {currentPeakInfo || (isTransitioning || isLoadingData ? 'Loading peaks...' : 'N/A')}
              </Typography>
            </Box>
          ) : (
            <Typography
              variant="caption"
              sx={{ color: 'text.secondary', fontStyle: 'italic', px: 1 }}
            >
              Select a specific detector to view peak information.
            </Typography>
          )}
          {/* Loading Indicator */}
          {(isLoadingData || isTransitioning) && (
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                mt: 2,
                px: 1,
                color: theme.palette.text.secondary,
              }}
            >
              <CircularProgress size={16} sx={{ mr: 1 }} />
              <Typography variant="caption">Loading data...</Typography>
            </Box>
          )}
        </Box>{' '}
        {/* End Scrollable Controls Area */}
        {/* --- Globe Section --- */}
        {/* Fixed at the bottom of the drawer */}
        <Box
          sx={{
            p: 1,
            display: 'flex',
            justifyContent: 'center',
            borderTop: `1px solid ${theme.palette.divider}`,
            flexShrink: 0,
          }}
        >
          {/* Render Globe only if the drawer is open to avoid unnecessary background processing */}
          {drawerOpen && (
            <Globe
              ref={globeRef}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
              backgroundColor="rgba(0,0,0,0)" // Transparent background
              pointsData={globePoints} // Data for detector markers
              pointLat="lat"
              pointLng="lng"
              pointColor="color" // Use color defined in App.js memo
              pointRadius={0.25} // Base radius
              pointAltitude="size" // Use size defined in App.js memo for pulsing effect
              pointLabel="label" // Tooltip label
              onPointClick={handleGlobePointClick} // Handler for clicking points
              onPointHover={handleGlobePointHover} // Handler for hovering points (optional)
              width={drawerWidth - 16} // Fit globe within drawer padding
              height={drawerWidth - 16}
              atmosphereColor={darkMode ? 'lightblue' : 'dodgerblue'} // Theme-aware atmosphere
              atmosphereAltitude={0.25}
              animateIn={true} // Animate globe appearance
              pointResolution={4} // Adjust resolution for performance vs detail
            />
          )}
        </Box>
      </Drawer>
    );
  }
);

// --- PropTypes ---
// Define expected prop types for type checking and documentation
ControlsDrawer.propTypes = {
  drawerWidth: PropTypes.number.isRequired,
  appBarHeight: PropTypes.number.isRequired,
  drawerOpen: PropTypes.bool.isRequired,
  darkMode: PropTypes.bool.isRequired,
  theme: PropTypes.object.isRequired,
  historicalMode: PropTypes.bool.isRequired,
  handleModeChange: PropTypes.func.isRequired,
  onLogout: PropTypes.func.isRequired,
  selectedDetector: PropTypes.string.isRequired,
  handleDetectorChange: PropTypes.func.isRequired,
  detectorOptions: PropTypes.arrayOf(
    PropTypes.shape({ id: PropTypes.string, label: PropTypes.string })
  ).isRequired,
  timeSteps: PropTypes.number.isRequired,
  debouncedSetTimeSteps: PropTypes.func.isRequired,
  colorScale: PropTypes.string.isRequired,
  setColorScale: PropTypes.func.isRequired,
  normalize: PropTypes.bool.isRequired,
  setNormalize: PropTypes.func.isRequired,
  historicalHours: PropTypes.number.isRequired,
  debouncedSetHistoricalHours: PropTypes.func.isRequired,
  isLoadingData: PropTypes.bool.isRequired,
  isTransitioning: PropTypes.bool.isRequired,
  currentPeakInfo: PropTypes.string, // Can be null or string
  historicalTransientEvents: PropTypes.array.isRequired, // Array of transient objects
  globePoints: PropTypes.array.isRequired, // Array of points for the globe
  handleGlobePointClick: PropTypes.func.isRequired,
  handleGlobePointHover: PropTypes.func.isRequired,
  plotType: PropTypes.oneOf(['2d', '3d']).isRequired,
  setPlotType: PropTypes.func.isRequired,
};

ControlsDrawer.displayName = 'ControlsDrawer';

export default ControlsDrawer;
