// client/src/components/HistoricalPeakChart.js
/**
 * Component to display historical peak data (frequency, amplitude, Q-factor)
 * for a selected detector using Plotly charts.
 * v1.1.28 - Minor cleanup, no direct constant usage needed here.
 */
import React, { useMemo } from 'react'; // Ensure React is imported
import PropTypes from 'prop-types';
import Plotly from 'react-plotly.js'; // Ensure Plotly is imported
import { Box, Paper, Tooltip, Typography, useTheme } from '@mui/material'; // Ensure needed MUI components are imported
import { WarningAmber as WarningAmberIcon } from '@mui/icons-material'; // Ensure icon is imported

// Historical Peak Chart Component
const HistoricalPeakChart = React.memo(
  ({
    historicalPeakData, // Array: [{ detectorId, peaks: [{ts, peaks: [{freq, amp, qFactor, trackStatus}]}] }]
    transientEvents, // Array: [{ type, details, detectorId, ts }]
    selectedDetector,
    darkMode,
  }) => {
    const theme = useTheme(); // Access theme for styling

    // Memoize chart data calculation
    const chartData = useMemo(() => {
      // Ensure data is valid and a specific detector is selected
      if (!historicalPeakData || !selectedDetector || selectedDetector === 'all') {
        return null;
      }
      // Find the data for the selected detector
      const detectorData = historicalPeakData.find((d) => d.detectorId === selectedDetector);
      if (!detectorData || !detectorData.peaks || detectorData.peaks.length === 0) {
        return null; // No data for this detector
      }

      // Initialize trace arrays for each parameter (Freq, Amp, Q-Factor)
      const freqTraces = [];
      const ampTraces = [];
      const qFactorTraces = [];

      // Define approximate SR mode ranges for grouping peaks
      const modeRanges = {
        'Mode 1 (7.8Hz)': { min: 6, max: 10, data: [] },
        'Mode 2 (14Hz)': { min: 12, max: 17, data: [] },
        'Mode 3 (21Hz)': { min: 18, max: 24, data: [] },
        'Mode 4 (27Hz)': { min: 25, max: 30, data: [] },
        'Mode 5 (34Hz)': { min: 31, max: 37, data: [] },
        Other: { min: -Infinity, max: Infinity, data: [] }, // Catch-all for other peaks
      };

      // --- Group Peaks by Mode ---
      // Iterate through each timestamp entry for the detector
      detectorData.peaks.forEach((entry) => {
        const ts = new Date(entry.ts); // Convert timestamp to Date object
        // Ensure entry.peaks is an array (it should be based on API response)
        const peaksArray = Array.isArray(entry.peaks) ? entry.peaks : [];

        // Iterate through the peaks detected at this timestamp
        peaksArray.forEach((peak) => {
          if (!peak || typeof peak.freq !== 'number') return; // Skip invalid peaks

          let assigned = false;
          // Assign peak to the first matching mode range
          for (const modeName in modeRanges) {
            if (
              modeName !== 'Other' &&
              peak.freq >= modeRanges[modeName].min &&
              peak.freq < modeRanges[modeName].max
            ) {
              modeRanges[modeName].data.push({ ...peak, ts: ts }); // Add peak with timestamp
              assigned = true;
              break;
            }
          }
          // If not assigned to a specific mode, add to 'Other'
          if (!assigned) {
            modeRanges['Other'].data.push({ ...peak, ts: ts });
          }
        });
      });

      // --- Generate Plotly Traces for Each Mode ---
      Object.keys(modeRanges).forEach((modeName) => {
        const modeData = modeRanges[modeName].data;
        if (modeData.length === 0) return; // Skip modes with no data

        // Sort data points by timestamp for line plotting
        modeData.sort((a, b) => a.ts - b.ts);

        // Segment data based on 'new' trackStatus to break lines
        let currentSegment = { x: [], f: [], a: [], q: [], status: 'unknown' };
        const segments = { freq: [], amp: [], qFactor: [] };

        modeData.forEach((peak, index) => {
          const status = peak.trackStatus || 'unknown';
          // If a 'new' peak is encountered (and it's not the very first point),
          // push the previous segment and start a new one.
          if (status === 'new' && index > 0 && currentSegment.x.length > 0) {
            segments.freq.push({
              ...currentSegment,
              y: currentSegment.f,
              nameSuffix: ` (Seg ${segments.freq.length + 1})`,
            });
            segments.amp.push({
              ...currentSegment,
              y: currentSegment.a,
              nameSuffix: ` (Seg ${segments.amp.length + 1})`,
            });
            segments.qFactor.push({
              ...currentSegment,
              y: currentSegment.q,
              nameSuffix: ` (Seg ${segments.qFactor.length + 1})`,
            });
            currentSegment = { x: [], f: [], a: [], q: [], status: 'new' }; // Reset for new segment
          } else if (index === 0 || currentSegment.x.length === 0) {
            // Set status for the first point of a segment
            currentSegment.status = status;
          }
          // Add data to the current segment
          currentSegment.x.push(peak.ts);
          currentSegment.f.push(peak.freq);
          currentSegment.a.push(peak.amp);
          // Handle potentially null qFactor
          currentSegment.q.push(peak.qFactor === null ? undefined : peak.qFactor);
        });

        // Push the last segment if it has data
        if (currentSegment.x.length > 0) {
          segments.freq.push({
            ...currentSegment,
            y: currentSegment.f,
            nameSuffix: segments.freq.length > 0 ? ` (Seg ${segments.freq.length + 1})` : '',
          });
          segments.amp.push({
            ...currentSegment,
            y: currentSegment.a,
            nameSuffix: segments.amp.length > 0 ? ` (Seg ${segments.amp.length + 1})` : '',
          });
          segments.qFactor.push({
            ...currentSegment,
            y: currentSegment.q,
            nameSuffix: segments.qFactor.length > 0 ? ` (Seg ${segments.qFactor.length + 1})` : '',
          });
        }

        // Helper to create Plotly trace objects from segments
        const generateTraces = (segmentList, baseName) => {
          return segmentList.map((segment, i) => {
            const isNewSegmentStart = segment.status === 'new';
            // Only show legend for the first segment of each mode group
            const showLegend = i === 0;
            return {
              x: segment.x, // Timestamps
              y: segment.y, // Parameter values (freq, amp, or Q)
              mode: 'lines+markers',
              type: 'scattergl', // Use WebGL for better performance
              name: `${baseName}${segment.nameSuffix}`, // e.g., "Mode 1 (7.8Hz) (Seg 2)"
              legendgroup: baseName, // Group segments in legend
              showlegend: showLegend,
              marker: {
                size: isNewSegmentStart ? 7 : 4, // Larger marker for new segment start
                symbol: isNewSegmentStart ? 'diamond-open' : 'circle', // Different symbol
                opacity: isNewSegmentStart ? 1.0 : 0.7,
              },
              line: { width: 1.5, dash: 'solid' }, // Style for connecting line
              connectgaps: false, // Do not connect across gaps (where segments break)
            };
          });
        };

        // Generate traces for each parameter and add to the main trace arrays
        freqTraces.push(...generateTraces(segments.freq, modeName));
        ampTraces.push(...generateTraces(segments.amp, modeName));
        qFactorTraces.push(...generateTraces(segments.qFactor, modeName));
      }); // End loop through modeRanges

      // Return null if no valid traces were generated
      if (freqTraces.length === 0 && ampTraces.length === 0 && qFactorTraces.length === 0) {
        return null;
      }

      return { freqData: freqTraces, ampData: ampTraces, qFactorData: qFactorTraces };
    }, [historicalPeakData, selectedDetector]); // Dependency array for memoization

    // Memoize shapes for transient events
    const transientShapes = useMemo(() => {
      if (!transientEvents || transientEvents.length === 0) return [];
      const shapeWidthMs = 5 * 1000; // Visual width of the transient marker (e.g., 5 seconds)
      return transientEvents.map((event, index) => ({
        type: 'rect', // Use rectangle shape
        xref: 'x', // Position based on X-axis (time)
        yref: 'paper', // Position based on plot height (0 to 1)
        x0: event.ts - shapeWidthMs / 2, // Start time of rect
        x1: event.ts + shapeWidthMs / 2, // End time of rect
        y0: 0, // Bottom of plot area
        y1: 1, // Top of plot area
        fillcolor: theme.palette.warning.main, // Use theme color
        opacity: 0.15, // Semi-transparent fill
        line: { width: 0 }, // No border line
        layer: 'below', // Draw below data traces
        name: `Transient ${index + 1}`, // Unique name for potential interaction later
        // Tooltip text for the shape
        hovertext: `${event.type?.toUpperCase() || 'TRANSIENT'} @ ${new Date(
          event.ts
        ).toLocaleString()}${event.details ? `: ${event.details}` : ''}`,
        hoverinfo: 'text', // Show only the hovertext
      }));
    }, [transientEvents, theme.palette.warning.main]); // Dependencies for memoization

    // Memoize common layout settings for all three charts
    const commonLayout = useMemo(
      () => ({
        autosize: true,
        margin: { l: 50, r: 20, t: 40, b: 40 }, // Adjust margins
        legend: {
          orientation: 'h', // Horizontal legend
          yanchor: 'bottom',
          y: -0.3, // Position below plot
          xanchor: 'center',
          x: 0.5,
          tracegroupgap: 10, // Gap between legend groups
        },
        paper_bgcolor: 'rgba(0,0,0,0)', // Transparent background
        plot_bgcolor: 'rgba(0,0,0,0)', // Transparent plot area
        font: { color: darkMode ? '#ffffff' : '#000000' }, // Theme-aware font color
        xaxis: {
          gridcolor: darkMode ? '#555555' : '#d3d3d3', // Theme-aware grid lines
          linecolor: darkMode ? '#aaaaaa' : '#000000', // Axis line color
          tickfont: { color: darkMode ? '#ffffff' : '#000000' }, // Tick label color
          // autorange: true, // Let Plotly determine range based on data
          // type: 'date', // Treat x-axis as dates
        },
        shapes: transientShapes, // Add transient markers
        hovermode: 'closest', // Show hover info for closest data point
      }),
      [darkMode, transientShapes]
    ); // Dependencies for memoization

    // Memoize specific layouts for each parameter chart, extending common layout
    const freqLayout = useMemo(
      () => ({
        ...commonLayout,
        title: { text: 'Peak Frequency', font: { size: 14 } },
        yaxis: {
          title: 'Frequency (Hz)',
          gridcolor: darkMode ? '#555555' : '#d3d3d3',
          linecolor: darkMode ? '#aaaaaa' : '#000000',
          zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
          tickfont: { color: darkMode ? '#ffffff' : '#000000' },
          titlefont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
          // autorange: true, // Allow Plotly to determine Y range
          range: [0, 40], // Or set a fixed range if preferred
        },
      }),
      [commonLayout, darkMode]
    );
    const ampLayout = useMemo(
      () => ({
        ...commonLayout,
        title: { text: 'Peak Amplitude', font: { size: 14 } },
        yaxis: {
          title: 'Amplitude', // Unitless or specify if known
          gridcolor: darkMode ? '#555555' : '#d3d3d3',
          linecolor: darkMode ? '#aaaaaa' : '#000000',
          zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
          tickfont: { color: darkMode ? '#ffffff' : '#000000' },
          titlefont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
          rangemode: 'tozero', // Ensure Y-axis starts at 0
          // autorange: true,
        },
      }),
      [commonLayout, darkMode]
    );
    const qFactorLayout = useMemo(
      () => ({
        ...commonLayout,
        title: { text: 'Peak Q-Factor', font: { size: 14 } },
        yaxis: {
          title: 'Q-Factor', // Unitless
          gridcolor: darkMode ? '#555555' : '#d3d3d3',
          linecolor: darkMode ? '#aaaaaa' : '#000000',
          zerolinecolor: darkMode ? '#aaaaaa' : '#000000',
          tickfont: { color: darkMode ? '#ffffff' : '#000000' },
          titlefont: { size: 12, color: darkMode ? '#ffffff' : '#000000' },
          rangemode: 'tozero', // Ensure Y-axis starts at 0
          // autorange: true,
        },
      }),
      [commonLayout, darkMode]
    );

    // --- Render Logic ---
    // Show message if no data available for the selected detector
    if (!chartData) {
      return (
        <Paper
          elevation={2}
          sx={{ mt: 2, p: 2, textAlign: 'center', bgcolor: theme.palette.background.paper }}
        >
          <Typography sx={{ color: 'text.secondary' }}>
            No historical peak data available for{' '}
            {selectedDetector === 'all' ? 'selection' : selectedDetector}.
          </Typography>
        </Paper>
      );
    }

    // Common Plotly config options
    const plotConfig = {
      responsive: true, // Allow plots to resize
      displaylogo: false, // Hide Plotly logo
      modeBarButtonsToRemove: ['lasso2d', 'select2d', 'toImage'], // Simplify mode bar
    };

    return (
      <Paper
        elevation={2}
        sx={{
          mt: 2,
          p: 1,
          bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.100', // Slightly different background
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
          width: '100%', // Fill container from MainContent
        }}
      >
        {/* Chart Title */}
        <Typography
          variant="h6"
          sx={{
            textAlign: 'center',
            mb: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0, // Prevent title from shrinking
            fontSize: '1rem', // Slightly smaller title
          }}
        >
          Historical Peaks: {selectedDetector}
          {/* Add transient warning icon if applicable */}
          {transientEvents && transientEvents.length > 0 && (
            <Tooltip
              title={`${transientEvents.length} transient event(s) detected (shaded regions)`}
            >
              <WarningAmberIcon sx={{ ml: 1, color: 'warning.main', fontSize: '1.1rem' }} />
            </Tooltip>
          )}
        </Typography>
        {/* Container for the three charts */}
        <Box
          sx={{
            display: 'flex',
            flexDirection: { xs: 'column', md: 'row' }, // Stack vertically on small screens, row on medium+
            gap: 1,
            flexGrow: 1, // Allow chart area to grow
            minHeight: 0, // Needed for flex-grow in flex column
          }}
        >
          {/* Frequency Chart */}
          <Box sx={{ flex: 1, minHeight: { xs: 200, md: 0 }, height: '100%' }}>
            <Plotly
              data={chartData.freqData}
              layout={freqLayout}
              config={plotConfig}
              style={{ width: '100%', height: '100%' }}
              useResizeHandler
            />
          </Box>
          {/* Amplitude Chart */}
          <Box sx={{ flex: 1, minHeight: { xs: 200, md: 0 }, height: '100%' }}>
            <Plotly
              data={chartData.ampData}
              layout={ampLayout}
              config={plotConfig}
              style={{ width: '100%', height: '100%' }}
              useResizeHandler
            />
          </Box>
          {/* Q-Factor Chart */}
          <Box sx={{ flex: 1, minHeight: { xs: 200, md: 0 }, height: '100%' }}>
            <Plotly
              data={chartData.qFactorData}
              layout={qFactorLayout}
              config={plotConfig}
              style={{ width: '100%', height: '100%' }}
              useResizeHandler
            />
          </Box>
        </Box>
      </Paper>
    );
  }
);

// Add PropTypes definition
HistoricalPeakChart.propTypes = {
  historicalPeakData: PropTypes.arrayOf(
    // Expect an array of detector data
    PropTypes.shape({
      detectorId: PropTypes.string.isRequired,
      peaks: PropTypes.arrayOf(
        // Each detector has an array of peak entries
        PropTypes.shape({
          ts: PropTypes.number.isRequired, // Timestamp in ms
          peaks: PropTypes.arrayOf(
            // Each entry has an array of actual peaks
            PropTypes.shape({
              freq: PropTypes.number.isRequired,
              amp: PropTypes.number.isRequired,
              qFactor: PropTypes.number, // Can be null
              trackStatus: PropTypes.string, // Optional 'new'/'continuing'
              trackId: PropTypes.string, // Optional track ID
            })
          ).isRequired,
        })
      ).isRequired,
    })
  ), // Can be null if no data fetched yet
  transientEvents: PropTypes.arrayOf(
    // Expect an array of transient event objects
    PropTypes.shape({
      type: PropTypes.string.isRequired,
      details: PropTypes.string,
      detectorId: PropTypes.string.isRequired,
      ts: PropTypes.number.isRequired,
    })
  ).isRequired,
  selectedDetector: PropTypes.string.isRequired,
  darkMode: PropTypes.bool.isRequired,
};

HistoricalPeakChart.displayName = 'HistoricalPeakChart';

export default HistoricalPeakChart; // Ensure default export
