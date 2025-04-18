// server/processingUtils.js
/**
 * Utility functions for EarthSync data processing (Peak Detection, Tracking, Transients).
 * Extracted for testability.
 * v1.1.28 - Use Centralized Constants.
 */
const crypto = require('crypto');
// Import constants from the centralized configuration file
const {
  RAW_FREQUENCY_POINTS, // Use directly
  DEFAULT_PEAK_SMOOTHING_WINDOW,
  DEFAULT_PEAK_PROMINENCE_FACTOR,
  DEFAULT_PEAK_MIN_DISTANCE_HZ,
  DEFAULT_PEAK_ABSOLUTE_THRESHOLD,
  DEFAULT_PEAK_TRACKING_FREQ_TOLERANCE_HZ,
  DEFAULT_TRANSIENT_HISTORY_LOOKBACK,
  DEFAULT_TRANSIENT_BROADBAND_FACTOR,
  DEFAULT_TRANSIENT_BROADBAND_THRESHOLD_PCT,
  DEFAULT_TRANSIENT_NARROWBAND_FACTOR,
  DEFAULT_TRANSIENT_NARROWBAND_MIN_AMP_DELTA,
  DEFAULT_TRANSIENT_NARROWBAND_IGNORE_HZ,
  DOWNSAMPLE_FACTOR, // Use directly
  SCHUMANN_FREQUENCIES, // Use directly
  REDIS_SPEC_HISTORY_PREFIX, // Needed for transient detection history key
} = require('./config/constants');
// Import DB functions needed for peak tracking
const { getPeakTrackingState, savePeakTrackingState, deletePeakTrackingState } = require('./db');
// Import centralized logger
const logger = require('./utils/logger');

// --- Constants derived locally or reused from imports ---
// RAW_FREQUENCY_POINTS is imported
const MAX_FREQUENCY_HZ = 55; // Define max frequency locally or import if added to constants
const FREQUENCY_RESOLUTION_HZ = MAX_FREQUENCY_HZ / (RAW_FREQUENCY_POINTS - 1);
const POINTS_PER_HZ = (RAW_FREQUENCY_POINTS - 1) / MAX_FREQUENCY_HZ;
// SCHUMANN_FREQUENCIES is imported

// --- Algorithm Parameters (Use defaults from constants, potentially overridden by process.env) ---
// Note: It's generally better practice to pass these as arguments to the functions
// if they need to be configurable per-call, rather than relying on process.env here.
// However, maintaining the current structure for now:
const PEAK_SMOOTHING_WINDOW =
  parseInt(process.env.PEAK_SMOOTHING_WINDOW, 10) || DEFAULT_PEAK_SMOOTHING_WINDOW;
const PEAK_PROMINENCE_FACTOR = parseFloat(
  process.env.PEAK_PROMINENCE_FACTOR || DEFAULT_PEAK_PROMINENCE_FACTOR
);
const PEAK_MIN_DISTANCE_HZ = parseFloat(
  process.env.PEAK_MIN_DISTANCE_HZ || DEFAULT_PEAK_MIN_DISTANCE_HZ
);
const PEAK_MIN_DISTANCE_POINTS = Math.max(
  1,
  Math.round(PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ)
); // Derived
const PEAK_ABSOLUTE_THRESHOLD = parseFloat(
  process.env.PEAK_ABSOLUTE_THRESHOLD || DEFAULT_PEAK_ABSOLUTE_THRESHOLD
);
const PEAK_TRACKING_FREQ_TOLERANCE_HZ = parseFloat(
  process.env.PEAK_TRACKING_FREQ_TOLERANCE_HZ || DEFAULT_PEAK_TRACKING_FREQ_TOLERANCE_HZ
);
const TRANSIENT_HISTORY_LOOKBACK =
  parseInt(process.env.TRANSIENT_HISTORY_LOOKBACK, 10) || DEFAULT_TRANSIENT_HISTORY_LOOKBACK;
const TRANSIENT_BROADBAND_FACTOR = parseFloat(
  process.env.TRANSIENT_BROADBAND_FACTOR || DEFAULT_TRANSIENT_BROADBAND_FACTOR
);
const TRANSIENT_BROADBAND_THRESHOLD_PCT = parseFloat(
  process.env.TRANSIENT_BROADBAND_THRESHOLD_PCT || DEFAULT_TRANSIENT_BROADBAND_THRESHOLD_PCT
);
const TRANSIENT_NARROWBAND_FACTOR = parseFloat(
  process.env.TRANSIENT_NARROWBAND_FACTOR || DEFAULT_TRANSIENT_NARROWBAND_FACTOR
);
const TRANSIENT_NARROWBAND_MIN_AMP_DELTA = parseFloat(
  process.env.TRANSIENT_NARROWBAND_MIN_AMP_DELTA || DEFAULT_TRANSIENT_NARROWBAND_MIN_AMP_DELTA
);
const TRANSIENT_NARROWBAND_IGNORE_HZ = parseFloat(
  process.env.TRANSIENT_NARROWBAND_IGNORE_HZ || DEFAULT_TRANSIENT_NARROWBAND_IGNORE_HZ
);
// DOWNSAMPLE_FACTOR is imported

/** Apply moving average smoothing */
function smooth(data, windowSize) {
  // Use the configured smoothing window size
  const safeWindowSize =
    typeof windowSize !== 'number' || windowSize < 1 || windowSize % 2 === 0
      ? PEAK_SMOOTHING_WINDOW
      : windowSize;
  if (safeWindowSize <= 1) return data.map(Number); // Ensure numeric output even if no smoothing

  const smoothed = [];
  const halfWindow = Math.floor(safeWindowSize / 2);
  const n = data.length;

  for (let i = 0; i < n; i++) {
    const start = Math.max(0, i - halfWindow);
    const end = Math.min(n, i + halfWindow + 1);
    let sum = 0;
    let count = 0;
    for (let j = start; j < end; j++) {
      // Ensure value is numeric before adding
      const val = Number(data[j]);
      if (!isNaN(val)) {
        sum += val;
        count++;
      }
    }
    // Handle cases where the window contains non-numeric data or is at edges
    const currentValNumeric = Number(data[i]);
    smoothed.push(count > 0 ? sum / count : !isNaN(currentValNumeric) ? currentValNumeric : 0);
  }
  return smoothed;
}

/** Helper function to calculate the median of an array of numbers */
function calculateMedian(arr) {
  // Filter out non-numeric values before sorting
  const numericArr = arr.filter((v) => typeof v === 'number' && !isNaN(v));
  if (numericArr.length === 0) return 0; // Return 0 if no valid numbers

  const sortedArr = [...numericArr].sort((a, b) => a - b);
  const mid = Math.floor(sortedArr.length / 2);

  if (sortedArr.length % 2 === 0) {
    // Even number of elements, average the two middle ones
    return (sortedArr[mid - 1] + sortedArr[mid]) / 2;
  } else {
    // Odd number of elements, return the middle one
    return sortedArr[mid];
  }
}

/**
 * Enhanced Peak detection on RAW spectrum using Parabolic Interpolation.
 * Uses globally defined parameters (PEAK_*, FREQUENCY_RESOLUTION_HZ).
 * @param {Array<number>} rawSpectrum - The input raw spectrogram data (5501 points).
 * @param {object} [configOverrides={}] - Optional overrides for detection parameters.
 * @returns {Array<object>} Array of detected peak objects: { freq, amp, qFactor }.
 */
function detectPeaksEnhanced(rawSpectrum, configOverrides = {}) {
  // Use overrides or fall back to global/constants defaults
  const smoothingWindow = configOverrides.smoothingWindow || PEAK_SMOOTHING_WINDOW;
  const absoluteThreshold = configOverrides.absoluteThreshold || PEAK_ABSOLUTE_THRESHOLD;
  const minDistancePoints = configOverrides.minDistancePoints || PEAK_MIN_DISTANCE_POINTS;
  const prominenceFactor = configOverrides.prominenceFactor || PEAK_PROMINENCE_FACTOR;

  // Basic validation
  if (!rawSpectrum || rawSpectrum.length < Math.max(3, smoothingWindow)) {
    logger.debug('Peak detection skipped: Insufficient data points.', {
      length: rawSpectrum?.length,
    });
    return [];
  }

  const n = rawSpectrum.length;
  // Convert to numbers and handle potential non-numeric values early
  const numericSpectrum = rawSpectrum.map((v) => {
    const num = Number(v);
    return isNaN(num) ? 0 : num; // Replace NaN/invalid with 0
  });

  // Smooth the numeric data
  const smoothedSpectrum = smooth(numericSpectrum, smoothingWindow);

  // --- Find Peak Candidates based on smoothed data ---
  const candidates = [];
  for (let i = 1; i < n - 1; i++) {
    // Check if it's a local maximum in the smoothed data and above threshold
    if (
      smoothedSpectrum[i] > smoothedSpectrum[i - 1] &&
      smoothedSpectrum[i] > smoothedSpectrum[i + 1] &&
      smoothedSpectrum[i] >= absoluteThreshold // Check against smoothed threshold first
    ) {
      // Store candidate index and its *smoothed* amplitude for prominence check
      candidates.push({ index: i, smoothedAmp: smoothedSpectrum[i] });
    }
  }

  if (candidates.length === 0) {
    // logger.debug('Peak detection: No candidates found above absolute threshold after smoothing.');
    return [];
  }

  // --- Filter by Prominence based on smoothed data ---
  // Prominence window size ensures we look beyond the minimum peak distance
  const windowSizeForProminence = minDistancePoints * 2 + 1;
  const prominentPeakCandidates = candidates.filter((candidate) => {
    const i = candidate.index;
    const windowStart = Math.max(0, i - Math.floor(windowSizeForProminence / 2));
    const windowEnd = Math.min(n, i + Math.floor(windowSizeForProminence / 2) + 1);

    // Find the minimum value in the prominence window (excluding the peak itself)
    let localMin = Infinity;
    for (let k = windowStart; k < windowEnd; k++) {
      if (k !== i) {
        localMin = Math.min(localMin, smoothedSpectrum[k]);
      }
    }

    // If localMin remains Infinity, it means the window was too small or contained only the peak point
    if (!isFinite(localMin)) {
      localMin = smoothedSpectrum[i]; // Fallback to peak value? Or a baseline? Using peak value for now.
      // This might happen for peaks very close to the edge.
    }

    // Calculate local standard deviation within the window for dynamic thresholding
    let localSum = 0;
    let localSumSq = 0;
    let count = 0;
    for (let k = windowStart; k < windowEnd; k++) {
      localSum += smoothedSpectrum[k];
      localSumSq += smoothedSpectrum[k] * smoothedSpectrum[k];
      count++;
    }

    if (count <= 1) return false; // Not enough points to calculate variance/stddev reliably

    const localMean = localSum / count;
    // Ensure variance is non-negative
    const localVariance = Math.max(0, localSumSq / count - localMean * localMean);
    // Use a small epsilon if stddev is zero to avoid division by zero or overly strict prominence
    const localStdDev = Math.sqrt(localVariance) || 0.1;

    // Calculate prominence relative to the local minimum
    const prominence = candidate.smoothedAmp - localMin;
    // Calculate the prominence threshold based on local standard deviation
    const prominenceThreshold = prominenceFactor * localStdDev;

    // Check prominence AND ensure the *original* peak value meets the absolute threshold
    const meetsProminence = prominence >= prominenceThreshold;
    const meetsAbsolute = numericSpectrum[i] >= absoluteThreshold;

    // if (!meetsProminence) logger.debug(`Peak at index ${i} failed prominence check: ${prominence.toFixed(2)} < ${prominenceThreshold.toFixed(2)}`);
    // if (!meetsAbsolute) logger.debug(`Peak at index ${i} failed absolute threshold check on original data: ${numericSpectrum[i].toFixed(2)} < ${absoluteThreshold}`);

    return meetsProminence && meetsAbsolute;
  });

  if (prominentPeakCandidates.length === 0) {
    // logger.debug('Peak detection: No candidates passed prominence filter.');
    return [];
  }

  // --- Ensure Minimum Distance between remaining peaks ---
  // Sort candidates by original amplitude (descending) to prioritize stronger peaks
  prominentPeakCandidates.sort((a, b) => numericSpectrum[b.index] - numericSpectrum[a.index]);

  const finalPeakIndices = [];
  const excludedIndices = new Set(); // Keep track of indices excluded due to proximity

  for (const peak of prominentPeakCandidates) {
    const peakIndex = peak.index;
    // If this peak's index hasn't been excluded by a stronger nearby peak
    if (!excludedIndices.has(peakIndex)) {
      finalPeakIndices.push(peakIndex); // Keep this peak
      // Exclude indices within the minimum distance on both sides
      for (let k = 1; k <= minDistancePoints; k++) {
        excludedIndices.add(peakIndex + k);
        excludedIndices.add(peakIndex - k);
      }
    }
  }

  if (finalPeakIndices.length === 0) {
    // This should be rare if prominentPeakCandidates was non-empty
    logger.debug('Peak detection: No peaks remained after minimum distance filtering.');
    return [];
  }

  // --- Calculate Final Peak Parameters with Parabolic Interpolation ---
  const finalPeaks = finalPeakIndices
    .map((index) => {
      let interpolatedIndex = index;
      let interpolatedAmp = numericSpectrum[index];
      let peakFreq = index * FREQUENCY_RESOLUTION_HZ;

      // Apply Parabolic Interpolation if valid neighbors exist in the *original* spectrum
      if (index > 0 && index < n - 1) {
        const yLeft = numericSpectrum[index - 1];
        const yCenter = numericSpectrum[index]; // Original amplitude at the detected index
        const yRight = numericSpectrum[index + 1];

        // Check for valid numeric neighbors
        if (!isNaN(yLeft) && !isNaN(yCenter) && !isNaN(yRight)) {
          const denominator = yLeft - 2 * yCenter + yRight;
          // Avoid division by zero or near-zero (flat peak or noise artifact)
          if (Math.abs(denominator) > 1e-6) {
            const indexOffset = (0.5 * (yLeft - yRight)) / denominator;
            // Only accept interpolation if the offset is reasonable (e.g., within +/- 1 index point)
            // A large offset suggests the peak isn't well-represented by a parabola at this point.
            if (Math.abs(indexOffset) < 1.0) {
              interpolatedIndex = index + indexOffset;
              interpolatedAmp = yCenter - 0.25 * (yLeft - yRight) * indexOffset; // Interpolated amplitude
              peakFreq = interpolatedIndex * FREQUENCY_RESOLUTION_HZ; // Use interpolated index for freq
            } else {
              // logger.debug(`Parabolic interpolation offset too large (${indexOffset.toFixed(3)}) for peak at index ${index}, using original index.`);
            }
          } // else { logger.debug(`Parabolic interpolation denominator too small for peak at index ${index}, using original index.`); }
        }
      } // End parabolic interpolation check

      // --- Q-Factor Calculation (using original index and amplitude for FWHM search) ---
      const originalPeakAmp = numericSpectrum[index]; // Use original amplitude for half-max calc
      const halfMax = originalPeakAmp / 2;
      let qFactor = null;

      // Proceed only if peak amp is significant enough
      if (originalPeakAmp >= absoluteThreshold && halfMax > 0) {
        let leftIndex = index;
        let rightIndex = index;

        // Find rough indices where spectrum drops below half max on left/right
        // Stop searching if we hit array bounds
        while (leftIndex > 0 && numericSpectrum[leftIndex - 1] >= halfMax) {
          leftIndex--;
        }
        while (rightIndex < n - 1 && numericSpectrum[rightIndex + 1] >= halfMax) {
          rightIndex++;
        }

        // --- Linear Interpolation for more precise FWHM ---
        let fwhmHz = (rightIndex - leftIndex + 1) * FREQUENCY_RESOLUTION_HZ; // Initial estimate

        try {
          // Get points surrounding the half-max crossing points
          const yL1 = numericSpectrum[leftIndex - 1] || 0; // Point below half-max on left
          const yL2 = numericSpectrum[leftIndex]; // Point at or above half-max on left
          const yR1 = numericSpectrum[rightIndex]; // Point at or above half-max on right
          const yR2 = numericSpectrum[rightIndex + 1] || 0; // Point below half-max on right

          let interpolatedLeftIdx = leftIndex;
          let interpolatedRightIdx = rightIndex;

          // Interpolate left edge if possible
          if (yL2 >= halfMax && yL1 < halfMax && yL2 > yL1) {
            interpolatedLeftIdx = leftIndex - 1 + (halfMax - yL1) / (yL2 - yL1);
          }

          // Interpolate right edge if possible
          if (yR1 >= halfMax && yR2 < halfMax && yR1 > yR2) {
            interpolatedRightIdx = rightIndex + (halfMax - yR1) / (yR2 - yR1); // Note: yR2-yR1 is negative
          }

          // Calculate FWHM in Hz using interpolated indices
          fwhmHz = Math.max(
            FREQUENCY_RESOLUTION_HZ,
            (interpolatedRightIdx - interpolatedLeftIdx) * FREQUENCY_RESOLUTION_HZ
          );
        } catch (interpErr) {
          // Fallback to rough estimate if interpolation fails
          logger.debug(`FWHM interpolation failed for peak at index ${index}`, {
            error: interpErr.message,
          });
          fwhmHz = Math.max(
            FREQUENCY_RESOLUTION_HZ,
            (rightIndex - leftIndex + 1) * FREQUENCY_RESOLUTION_HZ
          );
        }

        // Calculate Q-Factor (avoid division by zero)
        if (peakFreq > 1e-6 && fwhmHz > 1e-6) {
          qFactor = peakFreq / fwhmHz;
        }
      } // End Q-factor calculation block

      // Return the refined peak data object
      return {
        freq: peakFreq, // Use interpolated frequency
        amp: interpolatedAmp, // Use interpolated amplitude
        qFactor: qFactor, // Calculated Q-factor (can be null)
      };
    })
    .filter((p) => p.amp >= absoluteThreshold); // Final filter by absolute threshold on interpolated amp

  // Sort final peaks by frequency before returning
  finalPeaks.sort((a, b) => a.freq - b.freq);
  logger.debug(`Detected ${finalPeaks.length} peaks after all filters.`);
  return finalPeaks;
}

/**
 * Phase 2/v1.1.26: Robust Peak Tracking with DB Persistence and Track IDs.
 * Assigns a unique trackId to each peak sequence.
 * @param {string} detectorId - The detector ID.
 * @param {Array<object>} currentPeaks - Array of peak objects ({freq, amp, qFactor}) detected in the current spectrum.
 * @param {number} currentTimestampMs - The timestamp (Unix ms) of the current detection.
 * @param {object} [config={}] - Tracking configuration overrides (optional).
 * @returns {Promise<Array<object>>} Array of peak objects with added 'trackStatus' ('new'/'continuing') and 'trackId'.
 */
async function trackPeaks(detectorId, currentPeaks, currentTimestampMs, config = {}) {
  // Use configured tolerance or default from constants
  const freqTolerance = config.freqTolerance || PEAK_TRACKING_FREQ_TOLERANCE_HZ;
  let previousState = []; // Format: [{id, freq, amp, lastTs}, ...]

  try {
    // Fetch the last known state for this detector from the database
    const dbState = await getPeakTrackingState(detectorId);
    if (dbState && Array.isArray(dbState)) {
      previousState = dbState;
      // Optional: Could filter out very old tracks from previousState here based on lastTs if needed,
      // but the current approach relies on continuous updates or natural disappearance.
      // const trackTTL = (config.stateTTL || 300) * 1000; // Example TTL
      // previousState = previousState.filter(p => (currentTimestampMs - p.lastTs) < trackTTL);
    }
    logger.debug(`Retrieved ${previousState.length} previous peak states for tracking`, {
      detectorId,
    });
  } catch (err) {
    // Error logged within getPeakTrackingState, default to empty previous state
    logger.error(
      `Failed to retrieve previous peak state for ${detectorId}, assuming all new peaks.`,
      { error: err.message }
    );
    previousState = [];
  }

  const matchedPrevIndices = new Set(); // Track which previous peaks have been matched
  const trackedPeaksResult = []; // Build the array of current peaks with tracking info
  const nextStateToSave = []; // Build the state to save for the *next* iteration

  // Iterate through each peak detected in the current spectrum
  for (const currentPeak of currentPeaks) {
    let bestMatch = null; // Stores the best matching previous peak state
    let minFreqDiff = freqTolerance; // Initialize with max allowed difference

    // Find the best matching previous peak within frequency tolerance
    for (let i = 0; i < previousState.length; i++) {
      // Skip previous peaks that have already been matched to a current peak
      if (matchedPrevIndices.has(i)) continue;

      const prevPeakState = previousState[i];
      const freqDiff = Math.abs(currentPeak.freq - prevPeakState.freq);

      // Check if within tolerance AND is a better match than any previous found
      if (freqDiff <= minFreqDiff) {
        // If this is the first match or a closer match than the previous best
        if (!bestMatch || freqDiff < minFreqDiff) {
          minFreqDiff = freqDiff;
          bestMatch = { index: i, state: prevPeakState };
        }
        // Optional tie-breaking: Could prioritize peaks with closer amplitude if frequencies are very similar
        // else if (freqDiff === minFreqDiff && Math.abs(currentPeak.amp - prevPeakState.amp) < Math.abs(currentPeak.amp - bestMatch.state.amp)) {
        //    bestMatch = { index: i, state: prevPeakState };
        // }
      }
    } // End loop through previous peaks

    let trackId;
    let trackStatus;

    if (bestMatch) {
      // Matched an existing track
      matchedPrevIndices.add(bestMatch.index); // Mark this previous peak as used
      trackId = bestMatch.state.id; // Reuse the existing track ID
      trackStatus = 'continuing';
      // logger.debug(`Peak at ${currentPeak.freq.toFixed(2)}Hz matched existing track ${trackId}`, { detectorId });
    } else {
      // No suitable match found, this is the start of a new track
      trackId = crypto.randomUUID(); // Generate a new unique ID for the track
      trackStatus = 'new';
      logger.debug(`Peak at ${currentPeak.freq.toFixed(2)}Hz starting new track ${trackId}`, {
        detectorId,
      });
    }

    // Add tracking info to the peak object that will be returned/broadcast
    trackedPeaksResult.push({ ...currentPeak, trackStatus, trackId });

    // Add this peak's essential info to the state that will be saved for the *next* detection cycle
    nextStateToSave.push({
      id: trackId, // The ID of the track this peak belongs to
      freq: currentPeak.freq,
      amp: currentPeak.amp,
      lastTs: currentTimestampMs, // Store the timestamp of this detection
    });
  } // End loop through current peaks

  // Persist the *next* state (representing the peaks just detected) to the database
  try {
    if (nextStateToSave.length > 0) {
      // Save the new state, overwriting the previous state for this detector
      await savePeakTrackingState(detectorId, nextStateToSave);
    } else if (previousState.length > 0) {
      // If there were previous peaks but no current peaks, delete the state
      await deletePeakTrackingState(detectorId);
      logger.debug(`No current peaks detected, deleted tracking state from DB for ${detectorId}`);
    }
    // If no current peaks AND no previous state, do nothing.
  } catch (err) {
    // Error is logged within save/delete functions, but log here too for context
    logger.error(`Failed to save/delete peak tracking state for ${detectorId}`, {
      error: err.message,
    });
  }

  // Log summary of tracking results
  // logger.debug("Peak tracking results summary", {
  //   detectorId,
  //   currentPeakCount: currentPeaks.length,
  //   previousStateCount: previousState.length,
  //   newStateCount: nextStateToSave.length,
  //   newTracks: trackedPeaksResult.filter(p => p.trackStatus === 'new').length,
  //   continuingTracks: trackedPeaksResult.filter(p => p.trackStatus === 'continuing').length
  // });

  return trackedPeaksResult; // Return the array of current peaks with tracking info added
}

/**
 * Phase 4a/v1.1.19: Enhanced Transient Detection using Median Baseline.
 * Compares the current raw spectrum against a baseline derived from recent history.
 * @param {string} detectorId - The ID of the detector.
 * @param {Array<number>} rawSpectrum - The current raw spectrum data (5501 points).
 * @param {Redis.Redis} redisHistoryClient - Redis client instance for reading history.
 * @param {object} [config={}] - Optional overrides for transient detection parameters.
 * @returns {Promise<object>} Object describing the detected transient: { type: 'none'|'broadband'|'narrowband'|'error', details: string|null }.
 */
async function detectTransients(detectorId, rawSpectrum, redisHistoryClient, config = {}) {
  // Use configuration overrides or fall back to global/constant defaults
  const historyKey = `${REDIS_SPEC_HISTORY_PREFIX}${detectorId}`; // Use constant prefix
  const historyLookback = config.historyLookback || TRANSIENT_HISTORY_LOOKBACK;
  const broadbandFactor = config.broadbandFactor || TRANSIENT_BROADBAND_FACTOR;
  const broadbandThresholdPct = config.broadbandThresholdPct || TRANSIENT_BROADBAND_THRESHOLD_PCT;
  const narrowbandFactor = config.narrowbandFactor || TRANSIENT_NARROWBAND_FACTOR;
  const narrowbandMinAmpDelta = config.narrowbandMinAmpDelta || TRANSIENT_NARROWBAND_MIN_AMP_DELTA;
  const narrowbandIgnoreHz = config.narrowbandIgnoreHz || TRANSIENT_NARROWBAND_IGNORE_HZ;
  const absoluteThreshold = config.absoluteThreshold || PEAK_ABSOLUTE_THRESHOLD;
  const downsampleFactor = config.downsampleFactor || DOWNSAMPLE_FACTOR; // Use configured downsample factor

  let result = { type: 'none', details: null }; // Default result

  try {
    // --- Fetch Recent History ---
    // Get recent processed records (which include downsampled data) from the Redis LIST
    const historyJSONs = await redisHistoryClient.lrange(historyKey, 0, historyLookback - 1);

    // Need at least 2 historical points to form a reasonable baseline median
    if (historyJSONs.length < Math.min(2, historyLookback)) {
      logger.debug('Not enough history available for transient baseline calculation', {
        detectorId,
        count: historyJSONs.length,
        required: Math.min(2, historyLookback),
      });
      return result; // Not enough history, assume 'none'
    }

    // --- Calculate Baseline Spectrum ---
    // Extract the first downsampled spectrum from each valid historical record
    const historicalSpectra = historyJSONs
      .map((json) => {
        try {
          const parsed = JSON.parse(json);
          // Check structure: expect 'spectrogram' to be an array of arrays
          if (parsed && Array.isArray(parsed.spectrogram) && Array.isArray(parsed.spectrogram[0])) {
            return parsed.spectrogram[0]; // Use the first downsampled spectrum from the history entry
          }
          return null;
        } catch {
          return null; // Ignore records that fail parsing
        }
      })
      .filter((spec) => spec && spec.length > 0); // Filter out nulls or empty spectra

    if (historicalSpectra.length < 1) {
      logger.warn('No valid historical downsampled spectra found for baseline calculation', {
        detectorId,
      });
      return result; // Cannot calculate baseline
    }

    const baselineLength = historicalSpectra[0].length; // Length of downsampled spectra
    const baselineSpectrum = new Array(baselineLength).fill(0);

    // Calculate the median value at each frequency point across the historical spectra
    for (let i = 0; i < baselineLength; i++) {
      const valuesAtFreq = [];
      for (const spec of historicalSpectra) {
        // Ensure the historical spectrum has data at this index
        if (spec.length > i) {
          const val = Number(spec[i]);
          if (!isNaN(val)) {
            // Only use valid numbers
            valuesAtFreq.push(val);
          }
        }
      }
      baselineSpectrum[i] = calculateMedian(valuesAtFreq); // Calculate median for this frequency point
    }
    // logger.debug("Calculated baseline spectrum", { detectorId, length: baselineSpectrum.length, firstVal: baselineSpectrum[0], medianVal: baselineSpectrum[Math.floor(baselineLength / 2)] });

    // --- Compare Current Raw Spectrum to Baseline ---
    let broadbandExceedCount = 0;
    const narrowBandPeakCandidates = [];
    // Map SR frequencies to *raw* spectrum indices for narrowband ignore check
    const SCHUMANN_INDICES_RAW = SCHUMANN_FREQUENCIES.map((f) => Math.round(f * POINTS_PER_HZ));
    const NARROWBAND_IGNORE_POINTS_RAW = Math.round(narrowbandIgnoreHz * POINTS_PER_HZ);

    const rawNumericSpectrum = rawSpectrum.map((v) => Number(v) || 0); // Ensure raw spectrum is numeric

    for (let i = 0; i < rawNumericSpectrum.length; i++) {
      // Find the corresponding index in the *downsampled* baseline
      const baselineIndex = Math.floor(i / downsampleFactor);
      const currentAmp = rawNumericSpectrum[i];
      const baselineAmp =
        baselineIndex < baselineSpectrum.length ? baselineSpectrum[baselineIndex] : 0; // Use baseline value

      // 1. Check for Broadband criteria
      // Compare current amplitude to baseline multiplied by factor, OR absolute threshold (whichever is higher)
      const broadbandCompareValue = Math.max(
        baselineAmp * broadbandFactor,
        absoluteThreshold * 1.1
      ); // Add small buffer to abs threshold
      if (currentAmp > broadbandCompareValue) {
        broadbandExceedCount++;
      }

      // 2. Check for Narrowband criteria
      let isNearSR = false;
      for (const srIndex of SCHUMANN_INDICES_RAW) {
        if (Math.abs(i - srIndex) <= NARROWBAND_IGNORE_POINTS_RAW) {
          isNearSR = true;
          break;
        }
      }

      // Check if it's NOT near an SR freq AND exceeds narrowband thresholds
      const narrowbandCompareValue = Math.max(
        baselineAmp * narrowbandFactor,
        baselineAmp + narrowbandMinAmpDelta,
        absoluteThreshold
      );
      if (!isNearSR && currentAmp >= narrowbandCompareValue) {
        // Check if it's a local maximum in the *raw* spectrum
        const isLocalMax =
          (i === 0 || currentAmp >= rawNumericSpectrum[i - 1]) && // >= allows plateaus to be potential peaks
          (i === rawNumericSpectrum.length - 1 || currentAmp >= rawNumericSpectrum[i + 1]);

        if (isLocalMax) {
          // Store potential narrowband peak candidate
          narrowBandPeakCandidates.push({
            freq: i * FREQUENCY_RESOLUTION_HZ,
            amp: currentAmp,
            delta: currentAmp - baselineAmp, // Difference from baseline
            index: i,
          });
        }
      }
    } // End loop through raw spectrum

    // --- Determine Final Transient Type ---
    const broadbandPct = broadbandExceedCount / rawNumericSpectrum.length;
    if (broadbandPct > broadbandThresholdPct) {
      // Broadband event detected
      result.type = 'broadband';
      result.details = `Broadband power increase detected (${(broadbandPct * 100).toFixed(
        1
      )}% of points > ${broadbandFactor}x baseline)`;
      logger.info('Broadband transient detected', {
        detectorId,
        exceedCount: broadbandExceedCount,
        thresholdPct: broadbandThresholdPct * 100,
        actualPct: broadbandPct * 100,
      });
    } else if (narrowBandPeakCandidates.length > 0) {
      // --- Refine Narrowband Peaks ---
      // If multiple candidates, sort by amplitude delta and potentially filter nearby ones?
      // For now, just take the strongest one based on amplitude delta from baseline.
      narrowBandPeakCandidates.sort((a, b) => b.delta - a.delta);
      const strongestPeak = narrowBandPeakCandidates[0];

      // Check if the strongest peak is distinct enough (optional refinement)
      // Could add a check here comparing strongestPeak.amp to neighbors in raw spectrum

      result.type = 'narrowband';
      result.details = `Narrowband signal detected near ${strongestPeak.freq.toFixed(
        1
      )} Hz (Amp: ${strongestPeak.amp.toFixed(1)}, Delta: ${strongestPeak.delta.toFixed(1)})`;
      logger.info('Narrowband transient detected', {
        detectorId,
        peakFreq: strongestPeak.freq.toFixed(1),
        peakAmp: strongestPeak.amp.toFixed(1),
        delta: strongestPeak.delta.toFixed(1),
        candidateCount: narrowBandPeakCandidates.length,
      });
    }
    // Else: result remains { type: 'none', details: null }
  } catch (err) {
    logger.error('Error during transient detection process', {
      detectorId,
      error: err.message,
      stack: err.stack,
    });
    result = { type: 'error', details: 'Transient detection encountered an error.' };
  }

  return result;
}

module.exports = {
  smooth,
  detectPeaksEnhanced,
  trackPeaks,
  detectTransients,
  // Export constants used by functions if needed externally (like tests)
  RAW_FREQUENCY_POINTS,
  FREQUENCY_RESOLUTION_HZ,
  SCHUMANN_FREQUENCIES,
  POINTS_PER_HZ,
  DOWNSAMPLE_FACTOR, // Export DOWNSAMPLE_FACTOR if needed by callers
};
