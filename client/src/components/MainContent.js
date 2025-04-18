// client/src/components/MainContent.js
/**
 * Component responsible for rendering the main content area, including the
 * primary spectrogram plot and the historical peak chart (when applicable).
 * v1.1.28 - Use Centralized Constants.
 */
import React, { useRef } from 'react';
import PropTypes from 'prop-types';
import Plotly from 'react-plotly.js';
import { Box, CircularProgress, Typography } from '@mui/material';
// Import HistoricalPeakChart from its dedicated file
import HistoricalPeakChart from './HistoricalPeakChart';
// Import relevant constants (though only 'margin' is used directly here)
// import { MAIN_CONTENT_MARGIN } from '../constants'; // Not strictly needed if passed as prop

// Extracted Main Content Area Component
const MainContent = React.memo(
  ({
    // Layout Props
    drawerOpen,
    drawerWidth,
    appBarHeight,
    margin, // Use margin passed as prop from App.js (which uses MAIN_CONTENT_MARGIN)
    theme, // Theme object for styling transitions etc.

    // Data Loading State
    isLoadingData,
    isTransitioning,

    // Plot Data and Configuration
    plotType, // '2d' or '3d'
    plotData, // Array of traces for Plotly
    layout, // Layout object for Plotly
    displayData, // The processed Z-data used for the plot (used for conditional check)
    spectrogramData, // Original spectrogram data source (used for loading check)

    // Plot Interaction Handlers
    handlePlotHover,
    handlePlotClick,
    handlePlotRelayout,

    // Historical Data Props (passed down to HistoricalPeakChart)
    historicalMode,
    selectedDetector,
    historicalPeakData, // Data for the historical chart
    historicalTransientEvents, // Array of transient events for historical chart
    darkMode, // Needed by HistoricalPeakChart for theming
  }) => {
    const plotContainerRef = useRef(null); // Ref for the main plot container

    // Determine the height ratio for the main plot vs historical chart
    // Show historical chart only if in historical mode, a specific detector is selected,
    // and there's actual peak data for that detector.
    const showHistoricalChart =
      historicalMode &&
      selectedDetector !== 'all' &&
      historicalPeakData &&
      historicalPeakData.some((d) => d.detectorId === selectedDetector && d.peaks?.length > 0);

    // Adjust main plot height based on whether the historical chart is visible
    const mainPlotHeight = showHistoricalChart ? '60%' : '100%'; // e.g., 60% height if historical chart shown

    return (
      <Box
        component="main"
        ref={plotContainerRef}
        sx={{
          flexGrow: 1, // Take up remaining space
          // Calculate width based on whether drawer is open
          width: `calc(100% - ${drawerOpen ? drawerWidth : 0}px)`,
          height: `calc(100vh - ${appBarHeight}px)`, // Fill vertical space below AppBar
          padding: `${margin}px`, // Apply margin from props/constants
          boxSizing: 'border-box',
          // Apply smooth transitions for margin and width when drawer opens/closes
          transition: theme.transitions.create(['margin', 'width'], {
            easing: theme.transitions.easing.sharp,
            duration: drawerOpen
              ? theme.transitions.duration.enteringScreen
              : theme.transitions.duration.leavingScreen,
          }),
          // Adjust left margin when drawer is closed to shift content
          marginLeft: drawerOpen ? 0 : `-${drawerWidth}px`,
          position: 'relative', // Needed for absolute positioning of loaders?
          display: 'flex',
          flexDirection: 'column', // Stack main plot and historical chart vertically
          overflow: 'hidden', // Prevent main content area from scrolling independently
        }}
      >
        {/* --- Spectrogram Plot Area --- */}
        <Box
          sx={{
            height: mainPlotHeight, // Dynamically set height
            minHeight: 300, // Ensure a minimum height for the plot
            position: 'relative', // For positioning loading indicator
            flexShrink: 0, // Prevent this box from shrinking when historical chart appears
            display: 'flex', // Use flex to center loading indicator
            justifyContent: 'center',
            alignItems: 'center',
          }}
        >
          {/* Conditional Rendering: Loading Indicator OR Plot OR No Data Message */}
          {(isLoadingData || isTransitioning) && !Object.keys(spectrogramData).length ? (
            // Show loader only if loading AND no data is currently displayed
            <Box sx={{ textAlign: 'center' }}>
              <CircularProgress />
              <Typography sx={{ mt: 2 }}>Loading Spectrogram Data...</Typography>
            </Box>
          ) : displayData &&
            displayData.length > 0 &&
            displayData.some((row) => Array.isArray(row) && row.length > 0) ? (
            // Render Plotly chart if data exists
            <Box
              // Apply fade-in and opacity transition for smoothness
              className="plot-container fade-in"
              sx={{
                opacity: isTransitioning ? 0.5 : 1,
                transition: 'opacity 0.3s ease-in-out',
                height: '100%',
                width: '100%', // Ensure plot container takes full space
              }}
            >
              <Plotly
                key={`${plotType}-${selectedDetector}-${historicalMode}`} // Force re-render on type/mode/detector change
                data={plotData}
                layout={layout}
                revision={Date.now()} // Force update based on timestamp? Maybe needed if layout/data objects don't change refs
                style={{ width: '100%', height: '100%' }}
                useResizeHandler // Automatically handle container resizing
                config={{
                  responsive: true, // Make plot responsive
                  displayModeBar: true, // Show Plotly mode bar (zoom, pan, etc.)
                  displaylogo: false, // Hide Plotly logo
                  // Remove less common mode bar buttons
                  modeBarButtonsToRemove: ['lasso2d', 'select2d', 'toImage'],
                  // Hint for performance with frequent updates (WebGL plots)
                  // Not needed for heatmapgl / surface as they are inherently WebGL
                  // plotGlPixelRatio: window.devicePixelRatio || 1, // Use device pixel ratio for sharp WebGL
                  // scrollZoom: true, // Enable zooming with scroll wheel
                }}
                onHover={handlePlotHover}
                onClick={handlePlotClick}
                onRelayout={handlePlotRelayout} // Catches zoom/pan events
              />
            </Box>
          ) : (
            // Show message if loading is finished but no valid data was found/processed
            !isLoadingData &&
            !isTransitioning && (
              <Typography sx={{ textAlign: 'center', mt: 4, color: 'text.secondary' }}>
                No spectrogram data available for the selected detector(s) and time range.
              </Typography>
            )
          )}
        </Box>

        {/* --- Historical Peak Charts Area (Conditional) --- */}
        {showHistoricalChart && (
          <Box sx={{ height: 'auto', mt: 2, flexGrow: 1, minHeight: 0, overflowY: 'auto' }}>
            {' '}
            {/* Allow vertical scroll if needed */}
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
  plotData: PropTypes.array.isRequired, // Array of Plotly trace objects
  layout: PropTypes.object.isRequired, // Plotly layout object
  displayData: PropTypes.array.isRequired, // Processed Z-data for the plot
  spectrogramData: PropTypes.object.isRequired, // Source data object (used for loading check)
  handlePlotHover: PropTypes.func.isRequired,
  handlePlotClick: PropTypes.func.isRequired,
  handlePlotRelayout: PropTypes.func.isRequired,
  historicalMode: PropTypes.bool.isRequired,
  selectedDetector: PropTypes.string.isRequired,
  historicalPeakData: PropTypes.array, // Can be null or array of peak history objects
  historicalTransientEvents: PropTypes.array.isRequired, // Array of transient event objects
  darkMode: PropTypes.bool.isRequired,
};

MainContent.displayName = 'MainContent';

export default MainContent;
