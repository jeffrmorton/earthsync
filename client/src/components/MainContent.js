// client/src/components/MainContent.js
/**
 * Component responsible for rendering the main content area, including the
 * primary spectrogram plot and the historical peak chart (when applicable).
 * Shows loading overlay during mode transitions.
 * v1.1.28 - Use Centralized Constants. No backslash escapes in template literals.
 */
import React, { useRef } from 'react';
import PropTypes from 'prop-types';
import Plotly from 'react-plotly.js';
import { Box, CircularProgress, Typography, Fade } from '@mui/material';
// Import HistoricalPeakChart from its dedicated file
import HistoricalPeakChart from './HistoricalPeakChart';

// Extracted Main Content Area Component
const MainContent = React.memo(
  ({
    // Layout Props
    drawerOpen,
    drawerWidth,
    appBarHeight,
    margin,
    theme,

    // Data Loading State
    isLoadingData, // For initial data or explicit history fetch
    isTransitioning, // Specifically for mode changes

    // Plot Data and Configuration
    plotType,
    plotData,
    layout,
    displayData,
    spectrogramData, // Used for initial loading check

    // Plot Interaction Handlers
    handlePlotHover,
    handlePlotClick,
    handlePlotRelayout,

    // Historical Data Props
    historicalMode,
    selectedDetector,
    historicalPeakData,
    historicalTransientEvents,
    darkMode,
  }) => {
    const plotContainerRef = useRef(null);

    const showHistoricalChart =
      historicalMode &&
      selectedDetector !== 'all' &&
      historicalPeakData &&
      historicalPeakData.some((d) => d.detectorId === selectedDetector && d.peaks?.length > 0);

    const mainPlotHeight = showHistoricalChart ? '60%' : '100%';

    // Determine if the initial loading indicator should be shown
    const showInitialLoader = (isLoadingData || isTransitioning) && Object.keys(spectrogramData).length === 0;

    // Determine if the transition overlay should be shown
    const showTransitionLoader = isTransitioning && !showInitialLoader;

    return (
      <Box
        component="main"
        ref={plotContainerRef}
        sx={{
          flexGrow: 1,
          width: `calc(100% - ${drawerOpen ? drawerWidth : 0}px)`,
          height: `calc(100vh - ${appBarHeight}px)`,
          padding: `${margin}px`,
          boxSizing: 'border-box',
          transition: theme.transitions.create(['margin', 'width'], {
            easing: theme.transitions.easing.sharp,
            duration: drawerOpen
              ? theme.transitions.duration.enteringScreen
              : theme.transitions.duration.leavingScreen,
          }),
          marginLeft: drawerOpen ? 0 : `-${drawerWidth}px`,
          position: 'relative',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* --- Spectrogram Plot Area --- */}
        <Box
          sx={{
            height: mainPlotHeight,
            minHeight: 300,
            position: 'relative', // Crucial for overlay positioning
            flexShrink: 0,
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
          }}
        >
          {/* Initial Loading Indicator */}
          {showInitialLoader && (
            <Box sx={{ textAlign: 'center' }}>
              <CircularProgress />
              <Typography sx={{ mt: 2 }}>Loading Spectrogram Data...</Typography>
            </Box>
          )}

          {/* Plot Container (conditionally hidden/shown by loader presence) */}
          {!showInitialLoader &&
            displayData &&
            displayData.length > 0 &&
            displayData.some((row) => Array.isArray(row) && row.length > 0) && (
              <Box
                className="plot-container"
                sx={{
                  opacity: 1,
                  transition: 'opacity 0.3s ease-in-out',
                  height: '100%',
                  width: '100%',
                }}
              >
                <Plotly
                  key={`${plotType}-${selectedDetector}-${historicalMode}`}
                  data={plotData}
                  layout={layout}
                  revision={Date.now()}
                  style={{ width: '100%', height: '100%' }}
                  useResizeHandler
                  config={{
                    responsive: true,
                    displayModeBar: true,
                    displaylogo: false,
                    modeBarButtonsToRemove: ['lasso2d', 'select2d', 'toImage'],
                  }}
                  onHover={handlePlotHover}
                  onClick={handlePlotClick}
                  onRelayout={handlePlotRelayout}
                />
              </Box>
          )}

          {/* No Data Message */}
          {!showInitialLoader &&
            !isTransitioning &&
            (!displayData ||
              displayData.length === 0 ||
              !displayData.some((row) => Array.isArray(row) && row.length > 0)) && (
              <Typography sx={{ textAlign: 'center', mt: 4, color: 'text.secondary' }}>
                No spectrogram data available for the selected detector(s) and time range.
              </Typography>
          )}

          {/* --- Transition Loading Overlay --- */}
          <Fade in={showTransitionLoader} timeout={300}>
            <Box
              sx={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: 'rgba(0, 0, 0, 0.5)', // Semi-transparent overlay
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                zIndex: 10, // Ensure overlay is on top
                borderRadius: 1,
                color: '#fff',
              }}
            >
              <CircularProgress color="inherit" />
              <Typography sx={{ mt: 2 }}>
                {historicalMode ? 'Loading Historical Data...' : 'Switching to Real-time...'}
              </Typography>
            </Box>
          </Fade>
          {/* --- End Transition Loading Overlay --- */}
        </Box>

        {/* --- Historical Peak Charts Area (Conditional) --- */}
        {showHistoricalChart && (
          <Box sx={{ height: 'auto', mt: 2, flexGrow: 1, minHeight: 0, overflowY: 'auto' }}>
            <HistoricalPeakChart
              historicalPeakData={historicalPeakData}
              transientEvents={historicalTransientEvents}
              selectedDetector={selectedDetector}
              darkMode={darkMode}
            />
          </Box>
        )}
      </Box>
    );
  }
);

// --- PropTypes ---
MainContent.propTypes = {
  drawerOpen: PropTypes.bool.isRequired,
  drawerWidth: PropTypes.number.isRequired,
  appBarHeight: PropTypes.number.isRequired,
  margin: PropTypes.number.isRequired,
  theme: PropTypes.object.isRequired,
  isLoadingData: PropTypes.bool.isRequired,
  isTransitioning: PropTypes.bool.isRequired,
  plotType: PropTypes.oneOf(['2d', '3d']).isRequired,
  plotData: PropTypes.array.isRequired,
  layout: PropTypes.object.isRequired,
  displayData: PropTypes.array.isRequired,
  spectrogramData: PropTypes.object.isRequired,
  handlePlotHover: PropTypes.func.isRequired,
  handlePlotClick: PropTypes.func.isRequired,
  handlePlotRelayout: PropTypes.func.isRequired,
  historicalMode: PropTypes.bool.isRequired,
  selectedDetector: PropTypes.string.isRequired,
  historicalPeakData: PropTypes.array,
  historicalTransientEvents: PropTypes.array.isRequired,
  darkMode: PropTypes.bool.isRequired,
};

MainContent.displayName = 'MainContent';

export default MainContent;
