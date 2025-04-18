// client/src/components/ControlsDrawer.js
/**
 * Component responsible for rendering the controls drawer, including mode switching,
 * plot controls, filtered peak/transient info, and the detector globe.
 * v1.1.28 - UI/UX improvements: Slider feedback, Peak list format/scrolling, Spacing.
 */
import React, { useState, useEffect, useRef } from 'react';
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
  Stack,
} from '@mui/material';
import {
  BarChart as BarChartIcon,
  Logout as LogoutIcon,
  History as HistoryIcon,
  Insights as InsightsIcon,
  WarningAmber as WarningAmberIcon,
  ViewInAr as ViewInArIcon,
  Map as MapIcon,
} from '@mui/icons-material';
import { PLOT_COLOR_SCALES, DEFAULT_TIME_STEPS, DEFAULT_HISTORICAL_HOURS } from '../constants';

// Extracted Drawer Component
const ControlsDrawer = React.memo(
  ({
    drawerWidth,
    appBarHeight,
    drawerOpen,
    darkMode,
    theme,
    historicalMode,
    handleModeChange,
    onLogout,
    selectedDetector,
    handleDetectorChange,
    detectorOptions,
    timeSteps: actualTimeSteps,
    debouncedSetTimeSteps,
    colorScale,
    setColorScale,
    normalize,
    setNormalize,
    historicalHours: actualHistoricalHours,
    debouncedSetHistoricalHours,
    isLoadingData,
    isTransitioning,
    schumannPeaks, // Renamed prop - receives the filtered array
    historicalTransientEvents,
    globePoints,
    handleGlobePointClick,
    handleGlobePointHover,
    plotType,
    setPlotType,
  }) => {
    const globeRef = useRef(null);

    const [displayTimeSeconds, setDisplayTimeSeconds] = useState(
      typeof actualTimeSteps === 'number' ? actualTimeSteps * 5 : DEFAULT_TIME_STEPS * 5
    );
    const [displayHistoricalHours, setDisplayHistoricalHours] = useState(
      typeof actualHistoricalHours === 'number' ? actualHistoricalHours : DEFAULT_HISTORICAL_HOURS
    );

    useEffect(() => {
      setDisplayTimeSeconds(actualTimeSteps * 5);
    }, [actualTimeSteps]);

    useEffect(() => {
      setDisplayHistoricalHours(actualHistoricalHours);
    }, [actualHistoricalHours]);

    const handleTimeStepsSliderChange = (event, newValue) => {
      setDisplayTimeSeconds(newValue);
      debouncedSetTimeSteps(newValue);
    };
    const handleHistoricalHoursSliderChange = (event, newValue) => {
      setDisplayHistoricalHours(newValue);
      debouncedSetHistoricalHours(newValue);
    };

    return (
      <Drawer
        variant="persistent"
        anchor="left"
        open={drawerOpen}
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            overflow: 'hidden', // Prevent drawer paper itself from scrolling
            mt: `${appBarHeight}px`,
            height: `calc(100% - ${appBarHeight}px)`,
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: drawerOpen
                ? theme.transitions.duration.enteringScreen
                : theme.transitions.duration.leavingScreen,
            }),
            display: 'flex', // Use flexbox for vertical layout
            flexDirection: 'column', // Stack sections vertically
            borderRight: `1px solid ${theme.palette.divider}`,
          },
        }}
        aria-label="Controls Drawer"
      >
        {/* Scrollable Area for Controls (Excluding Globe) */}
        {/* Make this box the primary scroll container */}
        <Box sx={{ flexGrow: 1, overflowY: 'auto', p: 1.5 }}>
          <List dense sx={{ py: 0 }}>
            <ListItem disablePadding>
              <ListItemButton
                onClick={() => handleModeChange(false)}
                selected={!historicalMode}
                aria-current={!historicalMode ? 'page' : 'false'}
                sx={{ py: 0.75 }}
              >
                <ListItemIcon sx={{ minWidth: 36 }}>
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
                sx={{ py: 0.75 }}
              >
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <HistoryIcon />
                </ListItemIcon>
                <ListItemText primary="Historical Data" />
              </ListItemButton>
            </ListItem>
            <ListItem disablePadding>
              <ListItemButton onClick={onLogout} sx={{ py: 0.75 }}>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  <LogoutIcon />
                </ListItemIcon>
                <ListItemText primary="Logout" />
              </ListItemButton>
            </ListItem>
          </List>
          <Divider sx={{ my: 1.5 }} />

          {/* Spectrogram View Controls */}
          <Box sx={{ px: 1 }}>
            <Typography variant="overline" display="block" gutterBottom >
              Spectrogram View
            </Typography>
            <FormControl fullWidth sx={{ mb: 1.5 }}>
              <FormLabel id="plot-type-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
                Plot Type
              </FormLabel>
              <ButtonGroup variant="outlined" aria-labelledby="plot-type-label" fullWidth size="small">
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
            <FormControl fullWidth sx={{ mb: 1.5 }}>
              <FormLabel id="detector-select-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
                Detector
              </FormLabel>
              <Select
                labelId="detector-select-label"
                value={selectedDetector}
                onChange={handleDetectorChange}
                size="small"
                aria-describedby="detector-select-desc"
                MenuProps={{ PaperProps: { sx: { maxHeight: 200 } } }}
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
            <FormControl fullWidth sx={{ mb: 1.5 }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{mb: 0.5}}>
                  <FormLabel id="time-window-label" sx={{ fontSize: '0.8rem' }}>
                      Time Window
                  </FormLabel>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      {displayTimeSeconds}s
                  </Typography>
              </Stack>
              <Slider
                aria-labelledby="time-window-label"
                value={displayTimeSeconds}
                onChange={handleTimeStepsSliderChange}
                min={30}
                max={600}
                step={5}
                marks
                valueLabelDisplay="auto"
                size="small"
              />
               <Typography variant="caption" id="time-window-desc" sx={{ mt: 0.5, color: 'text.secondary' }}>
                 Plot length & Real-time view duration.
               </Typography>
            </FormControl>
            <FormControl fullWidth sx={{ mb: 1.5 }}>
              <FormLabel id="colorscale-label" sx={{ mb: 0.5, fontSize: '0.8rem' }}>
                Color Scale
              </FormLabel>
              <Select
                labelId="colorscale-label"
                value={colorScale}
                onChange={(e) => setColorScale(e.target.value)}
                size="small"
              >
                {PLOT_COLOR_SCALES.map((scaleName) => (
                  <MenuItem key={scaleName} value={scaleName}>
                    {scaleName}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControlLabel
              control={
                <Switch checked={normalize} onChange={() => setNormalize(!normalize)} size="small" />
              }
              label="Normalize Amplitude"
              sx={{ display: 'flex', alignItems: 'center', mb: 1 }}
            />
            {historicalMode && (
              <FormControl fullWidth sx={{ mb: 1.5 }}>
                 <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{mb: 0.5}}>
                     <FormLabel id="historical-hours-label" sx={{ fontSize: '0.8rem' }}>
                         Historical Hours
                     </FormLabel>
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                         {displayHistoricalHours}h
                     </Typography>
                 </Stack>
                <Slider
                  aria-labelledby="historical-hours-label"
                  value={displayHistoricalHours}
                  onChange={handleHistoricalHoursSliderChange}
                  min={1}
                  max={72}
                  step={1}
                  marks
                  valueLabelDisplay="auto"
                  size="small"
                />
              </FormControl>
            )}
          </Box>
          <Divider sx={{ my: 1.5 }} />

          {/* SR Peak Info Section - Adjust structure for flex grow */}
          <Box sx={{ px: 1, display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 /* Allow shrinking if needed initially */ }}>
            <Typography variant="overline" display="block" gutterBottom sx={{ flexShrink: 0 }}> {/* Prevent title shrinking */}
              Schumann Resonance Peaks
            </Typography>
            {selectedDetector !== 'all' ? (
              <Box
                sx={{
                  mt: 0.5, // Reduce top margin
                  p: 1, // Slightly reduce padding
                  border: `1px dashed ${theme.palette.divider}`,
                  borderRadius: 1,
                  bgcolor: 'action.hover',
                  flexGrow: 1, // Allow this box to grow
                  display: 'flex', // Use flex for internal layout
                  flexDirection: 'column', // Stack title and list
                  overflow: 'hidden', // Hide overflow until inner box handles it
                  minHeight: '80px', // Ensure it doesn't collapse completely when empty
                }}
              >
                <Typography
                  variant="caption"
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    mb: 0.5, // Reduce margin below title
                    fontWeight: 'medium',
                    flexShrink: 0, // Prevent title shrinking
                  }}
                >
                  <InsightsIcon sx={{ fontSize: '1rem', mr: 0.5, color: 'primary.main' }} />
                  {historicalMode ? 'Latest Hist.' : 'Detected'} SR Peaks ({selectedDetector}):
                  {historicalMode && historicalTransientEvents.length > 0 && (
                    <Tooltip
                      title={`${historicalTransientEvents.length} transient event(s) detected in this period`}
                    >
                      <WarningAmberIcon sx={{ ml: 1, color: 'warning.main', fontSize: '1.1rem' }} />
                    </Tooltip>
                  )}
                </Typography>
                {/* Scrollable Container for Peak List */}
                <Box sx={{ flexGrow: 1, overflowY: 'auto', pr: 0.5 }}> {/* Add slight right padding for scrollbar */}
                  {(isLoadingData || isTransitioning) ? (
                     <Box sx={{display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%'}}>
                         <CircularProgress size={20} />
                     </Box>
                  ) : schumannPeaks && schumannPeaks.length > 0 ? (
                     schumannPeaks.map((peak, index) => (
                      <Typography key={index} variant="caption" display="block" sx={{ mb: 0.5, pl: '10px' /* Indent slightly */ }}>
                        {`F: ${peak.freq.toFixed(2)}, A: ${peak.amp.toFixed(1)}, Q: ${peak.qFactor ? peak.qFactor.toFixed(1) : 'N/A'}, S: ${peak.trackStatus === 'new' ? 'New' : 'Cont.'}`}
                      </Typography>
                    ))
                  ) : (
                      <Typography variant="caption" sx={{ color: 'text.secondary', pl: '10px' }}>
                         {schumannPeaks === null ? 'Select detector' : 'No SR peaks detected.'}
                      </Typography>
                  )}
                </Box>
              </Box>
            ) : (
              <Typography
                variant="caption"
                sx={{ color: 'text.secondary', fontStyle: 'italic', px: 1, mb: 2, display: 'block' }}
              >
                Select a specific detector to view SR peak information.
              </Typography>
            )}
          </Box>

        </Box> {/* End Scrollable Controls Area */}

        {/* Globe Section (Fixed at bottom) */}
        <Box
          sx={{
            p: 1.5,
            display: 'flex',
            justifyContent: 'center',
            borderTop: `1px solid ${theme.palette.divider}`,
            flexShrink: 0, // Keep globe fixed size
            mt: 'auto' // Push globe to the bottom
          }}
        >
          {drawerOpen && (
            <Globe
              ref={globeRef}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
              backgroundColor="rgba(0,0,0,0)"
              pointsData={globePoints}
              pointLat="lat"
              pointLng="lng"
              pointColor="color"
              pointRadius={0.25}
              pointAltitude="size"
              pointLabel="label"
              onPointClick={handleGlobePointClick}
              onPointHover={handleGlobePointHover}
              width={drawerWidth - 24}
              height={drawerWidth - 24}
              atmosphereColor={darkMode ? 'lightblue' : 'dodgerblue'}
              atmosphereAltitude={0.25}
              animateIn={true}
              pointResolution={4}
            />
          )}
        </Box>
      </Drawer>
    );
  }
);

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
  schumannPeaks: PropTypes.array,
  historicalTransientEvents: PropTypes.array.isRequired,
  globePoints: PropTypes.array.isRequired,
  handleGlobePointClick: PropTypes.func.isRequired,
  handleGlobePointHover: PropTypes.func.isRequired,
  plotType: PropTypes.oneOf(['2d', '3d']).isRequired,
  setPlotType: PropTypes.func.isRequired,
};

ControlsDrawer.displayName = 'ControlsDrawer';

export default ControlsDrawer;
