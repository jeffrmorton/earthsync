// server/processingUtils.js
/**
 * Utility functions for EarthSync data processing (Peak Detection, Tracking, Transients).
 * Extracted for testability.
 * v1.1.28 - Use Centralized Constants & Anti-Aliasing Downsampling. No backslash escapes in template literals.
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
const MAX_FREQUENCY_HZ = 55;
const FREQUENCY_RESOLUTION_HZ = MAX_FREQUENCY_HZ / (RAW_FREQUENCY_POINTS - 1);
const POINTS_PER_HZ = (RAW_FREQUENCY_POINTS - 1) / MAX_FREQUENCY_HZ;

// --- Algorithm Parameters (Use defaults from constants) ---
const PEAK_SMOOTHING_WINDOW = DEFAULT_PEAK_SMOOTHING_WINDOW;
const PEAK_PROMINENCE_FACTOR = DEFAULT_PEAK_PROMINENCE_FACTOR;
const PEAK_MIN_DISTANCE_HZ = DEFAULT_PEAK_MIN_DISTANCE_HZ;
const PEAK_MIN_DISTANCE_POINTS = Math.max(
  1,
  Math.round(PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ)
);
const PEAK_ABSOLUTE_THRESHOLD = DEFAULT_PEAK_ABSOLUTE_THRESHOLD;
const PEAK_TRACKING_FREQ_TOLERANCE_HZ = DEFAULT_PEAK_TRACKING_FREQ_TOLERANCE_HZ;
const TRANSIENT_HISTORY_LOOKBACK = DEFAULT_TRANSIENT_HISTORY_LOOKBACK;
const TRANSIENT_BROADBAND_FACTOR = DEFAULT_TRANSIENT_BROADBAND_FACTOR;
const TRANSIENT_BROADBAND_THRESHOLD_PCT = DEFAULT_TRANSIENT_BROADBAND_THRESHOLD_PCT;
const TRANSIENT_NARROWBAND_FACTOR = DEFAULT_TRANSIENT_NARROWBAND_FACTOR;
const TRANSIENT_NARROWBAND_MIN_AMP_DELTA = DEFAULT_TRANSIENT_NARROWBAND_MIN_AMP_DELTA;
const TRANSIENT_NARROWBAND_IGNORE_HZ = DEFAULT_TRANSIENT_NARROWBAND_IGNORE_HZ;
// DOWNSAMPLE_FACTOR is imported

/** Apply moving average smoothing */
function smooth(data, windowSize) {
  const safeWindowSize =
    typeof windowSize !== 'number' || windowSize < 1 || windowSize % 2 === 0
      ? PEAK_SMOOTHING_WINDOW
      : windowSize;
  if (safeWindowSize <= 1) return data.map(Number);

  const smoothed = [];
  const halfWindow = Math.floor(safeWindowSize / 2);
  const n = data.length;

  for (let i = 0; i < n; i++) {
    const start = Math.max(0, i - halfWindow);
    const end = Math.min(n, i + halfWindow + 1);
    let sum = 0;
    let count = 0;
    for (let j = start; j < end; j++) {
      const val = Number(data[j]);
      if (!isNaN(val)) {
        sum += val;
        count++;
      }
    }
    const currentValNumeric = Number(data[i]);
    smoothed.push(count > 0 ? sum / count : !isNaN(currentValNumeric) ? currentValNumeric : 0);
  }
  return smoothed;
}

/** Helper function to calculate the median of an array of numbers */
function calculateMedian(arr) {
  const numericArr = arr.filter((v) => typeof v === 'number' && !isNaN(v));
  if (numericArr.length === 0) return 0;
  const sortedArr = [...numericArr].sort((a, b) => a - b);
  const mid = Math.floor(sortedArr.length / 2);
  return sortedArr.length % 2 === 0 ? (sortedArr[mid - 1] + sortedArr[mid]) / 2 : sortedArr[mid];
}

// --- ANTI-ALIASING DOWNSAMPLE ---
/**
 * Downsamples the raw spectrum using boxcar averaging to prevent aliasing.
 * @param {Array<number>} rawSpectrum - The full-resolution spectrum.
 * @param {number} factor - The downsampling factor.
 * @returns {Array<number>} The downsampled spectrum.
 */
function downsampleWithAntiAliasing(rawSpectrum, factor) {
  if (factor <= 1) {
    return rawSpectrum.map(Number); // No downsampling needed, just ensure numbers
  }
  const downsampledLength = Math.ceil(rawSpectrum.length / factor);
  const downsampledSpectrum = new Array(downsampledLength);

  for (let i = 0; i < downsampledLength; i++) {
    const start = i * factor;
    const end = Math.min(start + factor, rawSpectrum.length); // Ensure we don't go past the end
    let sum = 0;
    let count = 0;
    for (let j = start; j < end; j++) {
      const val = Number(rawSpectrum[j]);
      if (!isNaN(val)) {
        sum += val;
        count++;
      }
    }
    downsampledSpectrum[i] = count > 0 ? sum / count : 0; // Use average, or 0 if no valid points
  }
  return downsampledSpectrum;
}
// --- END ANTI-ALIASING DOWNSAMPLE ---

/**
 * Enhanced Peak detection on RAW spectrum using Parabolic Interpolation.
 * Uses globally defined parameters (PEAK_*, FREQUENCY_RESOLUTION_HZ).
 * @param {Array<number>} rawSpectrum - The input raw spectrogram data (5501 points).
 * @param {object} [configOverrides={}] - Optional overrides for detection parameters.
 * @returns {Array<object>} Array of detected peak objects: { freq, amp, qFactor }.
 */
function detectPeaksEnhanced(rawSpectrum, configOverrides = {}) {
  const smoothingWindow = configOverrides.smoothingWindow || PEAK_SMOOTHING_WINDOW;
  const absoluteThreshold = configOverrides.absoluteThreshold || PEAK_ABSOLUTE_THRESHOLD;
  const minDistancePoints = configOverrides.minDistancePoints || PEAK_MIN_DISTANCE_POINTS;
  const prominenceFactor = configOverrides.prominenceFactor || PEAK_PROMINENCE_FACTOR;

  if (!rawSpectrum || rawSpectrum.length < Math.max(3, smoothingWindow)) {
    logger.debug('Peak detection skipped: Insufficient data points.', {
      length: rawSpectrum?.length,
    });
    return [];
  }

  const n = rawSpectrum.length;
  const numericSpectrum = rawSpectrum.map((v) => {
    const num = Number(v);
    return isNaN(num) ? 0 : num;
  });

  const smoothedSpectrum = smooth(numericSpectrum, smoothingWindow);

  const candidates = [];
  for (let i = 1; i < n - 1; i++) {
    if (
      smoothedSpectrum[i] > smoothedSpectrum[i - 1] &&
      smoothedSpectrum[i] > smoothedSpectrum[i + 1] &&
      smoothedSpectrum[i] >= absoluteThreshold
    ) {
      candidates.push({ index: i, smoothedAmp: smoothedSpectrum[i] });
    }
  }

  if (candidates.length === 0) {
    return [];
  }

  const windowSizeForProminence = minDistancePoints * 2 + 1;
  const prominentPeakCandidates = candidates.filter((candidate) => {
    const i = candidate.index;
    const windowStart = Math.max(0, i - Math.floor(windowSizeForProminence / 2));
    const windowEnd = Math.min(n, i + Math.floor(windowSizeForProminence / 2) + 1);
    let localMin = Infinity;
    for (let k = windowStart; k < windowEnd; k++) {
      if (k !== i) {
        localMin = Math.min(localMin, smoothedSpectrum[k]);
      }
    }
    if (!isFinite(localMin)) {
      localMin = smoothedSpectrum[i];
    }
    let localSum = 0;
    let localSumSq = 0;
    let count = 0;
    for (let k = windowStart; k < windowEnd; k++) {
      localSum += smoothedSpectrum[k];
      localSumSq += smoothedSpectrum[k] * smoothedSpectrum[k];
      count++;
    }
    if (count <= 1) return false;
    const localMean = localSum / count;
    const localVariance = Math.max(0, localSumSq / count - localMean * localMean);
    const localStdDev = Math.sqrt(localVariance) || 0.1;
    const prominence = candidate.smoothedAmp - localMin;
    const prominenceThreshold = prominenceFactor * localStdDev;
    const meetsProminence = prominence >= prominenceThreshold;
    const meetsAbsolute = numericSpectrum[i] >= absoluteThreshold;
    return meetsProminence && meetsAbsolute;
  });

  if (prominentPeakCandidates.length === 0) {
    return [];
  }

  prominentPeakCandidates.sort((a, b) => numericSpectrum[b.index] - numericSpectrum[a.index]);
  const finalPeakIndices = [];
  const excludedIndices = new Set();
  for (const peak of prominentPeakCandidates) {
    const peakIndex = peak.index;
    if (!excludedIndices.has(peakIndex)) {
      finalPeakIndices.push(peakIndex);
      for (let k = 1; k <= minDistancePoints; k++) {
        excludedIndices.add(peakIndex + k);
        excludedIndices.add(peakIndex - k);
      }
    }
  }

  if (finalPeakIndices.length === 0) {
    logger.debug('Peak detection: No peaks remained after minimum distance filtering.');
    return [];
  }

  const finalPeaks = finalPeakIndices
    .map((index) => {
      let interpolatedIndex = index;
      let interpolatedAmp = numericSpectrum[index];
      let peakFreq = index * FREQUENCY_RESOLUTION_HZ;
      if (index > 0 && index < n - 1) {
        const yLeft = numericSpectrum[index - 1];
        const yCenter = numericSpectrum[index];
        const yRight = numericSpectrum[index + 1];
        if (!isNaN(yLeft) && !isNaN(yCenter) && !isNaN(yRight)) {
          const denominator = yLeft - 2 * yCenter + yRight;
          if (Math.abs(denominator) > 1e-6) {
            const indexOffset = (0.5 * (yLeft - yRight)) / denominator;
            if (Math.abs(indexOffset) < 1.0) {
              interpolatedIndex = index + indexOffset;
              interpolatedAmp = yCenter - 0.25 * (yLeft - yRight) * indexOffset;
              peakFreq = interpolatedIndex * FREQUENCY_RESOLUTION_HZ;
            }
          }
        }
      }
      const originalPeakAmp = numericSpectrum[index];
      const halfMax = originalPeakAmp / 2;
      let qFactor = null;
      if (originalPeakAmp >= absoluteThreshold && halfMax > 0) {
        let leftIndex = index;
        let rightIndex = index;
        while (leftIndex > 0 && numericSpectrum[leftIndex - 1] >= halfMax) {
          leftIndex--;
        }
        while (rightIndex < n - 1 && numericSpectrum[rightIndex + 1] >= halfMax) {
          rightIndex++;
        }
        let fwhmHz = (rightIndex - leftIndex + 1) * FREQUENCY_RESOLUTION_HZ;
        try {
          const yL1 = numericSpectrum[leftIndex - 1] || 0;
          const yL2 = numericSpectrum[leftIndex];
          const yR1 = numericSpectrum[rightIndex];
          const yR2 = numericSpectrum[rightIndex + 1] || 0;
          let interpolatedLeftIdx = leftIndex;
          let interpolatedRightIdx = rightIndex;
          if (yL2 >= halfMax && yL1 < halfMax && yL2 > yL1) {
            interpolatedLeftIdx = leftIndex - 1 + (halfMax - yL1) / (yL2 - yL1);
          }
          if (yR1 >= halfMax && yR2 < halfMax && yR1 > yR2) {
            interpolatedRightIdx = rightIndex + (halfMax - yR1) / (yR2 - yR1);
          }
          fwhmHz = Math.max(
            FREQUENCY_RESOLUTION_HZ,
            (interpolatedRightIdx - interpolatedLeftIdx) * FREQUENCY_RESOLUTION_HZ
          );
        } catch (interpErr) {
          logger.debug(`FWHM interpolation failed for peak at index ${index}`, { // Corrected interpolation
            error: interpErr.message,
          });
          fwhmHz = Math.max(
            FREQUENCY_RESOLUTION_HZ,
            (rightIndex - leftIndex + 1) * FREQUENCY_RESOLUTION_HZ
          );
        }
        if (peakFreq > 1e-6 && fwhmHz > 1e-6) {
          qFactor = peakFreq / fwhmHz;
        }
      }
      return { freq: peakFreq, amp: interpolatedAmp, qFactor: qFactor };
    })
    .filter((p) => p.amp >= absoluteThreshold);

  finalPeaks.sort((a, b) => a.freq - b.freq);
  logger.debug(`Detected ${finalPeaks.length} peaks after all filters.`); // Corrected interpolation
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
  const freqTolerance = config.freqTolerance || PEAK_TRACKING_FREQ_TOLERANCE_HZ;
  let previousState = [];

  try {
    const dbState = await getPeakTrackingState(detectorId);
    if (dbState && Array.isArray(dbState)) {
      previousState = dbState;
    }
    logger.debug(`Retrieved ${previousState.length} previous peak states for tracking`, { // Corrected interpolation
      detectorId,
    });
  } catch (err) {
    logger.error(
      `Failed to retrieve previous peak state for ${detectorId}, assuming all new peaks.`, // Corrected interpolation
      { error: err.message }
    );
    previousState = [];
  }

  const matchedPrevIndices = new Set();
  const trackedPeaksResult = [];
  const nextStateToSave = [];

  for (const currentPeak of currentPeaks) {
    let bestMatch = null;
    let minFreqDiff = freqTolerance;

    for (let i = 0; i < previousState.length; i++) {
      if (matchedPrevIndices.has(i)) continue;
      const prevPeakState = previousState[i];
      const freqDiff = Math.abs(currentPeak.freq - prevPeakState.freq);
      if (freqDiff <= minFreqDiff) {
        if (!bestMatch || freqDiff < minFreqDiff) {
          minFreqDiff = freqDiff;
          bestMatch = { index: i, state: prevPeakState };
        }
      }
    }

    let trackId;
    let trackStatus;

    if (bestMatch) {
      matchedPrevIndices.add(bestMatch.index);
      trackId = bestMatch.state.id;
      trackStatus = 'continuing';
    } else {
      trackId = crypto.randomUUID();
      trackStatus = 'new';
      logger.debug(`Peak at ${currentPeak.freq.toFixed(2)}Hz starting new track ${trackId}`, { // Corrected interpolation
        detectorId,
      });
    }

    trackedPeaksResult.push({ ...currentPeak, trackStatus, trackId });
    nextStateToSave.push({
      id: trackId,
      freq: currentPeak.freq,
      amp: currentPeak.amp,
      lastTs: currentTimestampMs,
    });
  }

  try {
    if (nextStateToSave.length > 0) {
      await savePeakTrackingState(detectorId, nextStateToSave);
    } else if (previousState.length > 0) {
      await deletePeakTrackingState(detectorId);
      logger.debug(`No current peaks detected, deleted tracking state from DB for ${detectorId}`); // Corrected interpolation
    }
  } catch (err) {
    logger.error(`Failed to save/delete peak tracking state for ${detectorId}`, { // Corrected interpolation
      error: err.message,
    });
  }

  return trackedPeaksResult;
}

/**
 * Phase 4a/v1.1.19: Enhanced Transient Detection using Median Baseline.
 * Compares the current raw spectrum against a baseline derived from recent history.
 * Relies on Redis history containing individual spectrum records.
 * @param {string} detectorId - The ID of the detector.
 * @param {Array<number>} rawSpectrum - The current raw spectrum data (5501 points).
 * @param {Redis.Redis} redisHistoryClient - Redis client instance for reading history.
 * @param {object} [config={}] - Optional overrides for transient detection parameters.
 * @returns {Promise<object>} Object describing the detected transient: { type: 'none'|'broadband'|'narrowband'|'error', details: string|null }.
 */
async function detectTransients(detectorId, rawSpectrum, redisHistoryClient, config = {}) {
  const historyKey = `${REDIS_SPEC_HISTORY_PREFIX}${detectorId}`; // Corrected interpolation
  const historyLookback = config.historyLookback || TRANSIENT_HISTORY_LOOKBACK;
  const broadbandFactor = config.broadbandFactor || TRANSIENT_BROADBAND_FACTOR;
  const broadbandThresholdPct = config.broadbandThresholdPct || TRANSIENT_BROADBAND_THRESHOLD_PCT;
  const narrowbandFactor = config.narrowbandFactor || TRANSIENT_NARROWBAND_FACTOR;
  const narrowbandMinAmpDelta = config.narrowbandMinAmpDelta || TRANSIENT_NARROWBAND_MIN_AMP_DELTA;
  const narrowbandIgnoreHz = config.narrowbandIgnoreHz || TRANSIENT_NARROWBAND_IGNORE_HZ;
  const absoluteThreshold = config.absoluteThreshold || PEAK_ABSOLUTE_THRESHOLD;
  const downsampleFactor = config.downsampleFactor || DOWNSAMPLE_FACTOR;

  let result = { type: 'none', details: null };

  try {
    const historyJSONs = await redisHistoryClient.lrange(historyKey, 0, historyLookback - 1);

    if (historyJSONs.length < Math.min(2, historyLookback)) {
      logger.debug('Not enough history available for transient baseline calculation', {
        detectorId,
        count: historyJSONs.length,
        required: Math.min(2, historyLookback),
      });
      return result;
    }

    const historicalSpectra = historyJSONs
      .map((json) => {
        try {
          const parsed = JSON.parse(json);
          // Use the downsampled spectrum stored in the record
          return Array.isArray(parsed?.spectrogram) ? parsed.spectrogram : null;
        } catch {
          return null;
        }
      })
      .filter((spec) => spec && spec.length > 0);

    if (historicalSpectra.length < 1) {
      logger.warn('No valid historical downsampled spectra found for baseline calculation', {
        detectorId,
      });
      return result;
    }

    const baselineLength = historicalSpectra[0].length;
    const baselineSpectrum = new Array(baselineLength).fill(0);
    for (let i = 0; i < baselineLength; i++) {
      const valuesAtFreq = [];
      for (const spec of historicalSpectra) {
        if (spec.length > i) {
          const val = Number(spec[i]);
          if (!isNaN(val)) {
            valuesAtFreq.push(val);
          }
        }
      }
      baselineSpectrum[i] = calculateMedian(valuesAtFreq);
    }

    let broadbandExceedCount = 0;
    const narrowBandPeakCandidates = [];
    const SCHUMANN_INDICES_RAW = SCHUMANN_FREQUENCIES.map((f) => Math.round(f * POINTS_PER_HZ));
    const NARROWBAND_IGNORE_POINTS_RAW = Math.round(narrowbandIgnoreHz * POINTS_PER_HZ);
    const rawNumericSpectrum = rawSpectrum.map((v) => Number(v) || 0);

    for (let i = 0; i < rawNumericSpectrum.length; i++) {
      const baselineIndex = Math.floor(i / downsampleFactor);
      const currentAmp = rawNumericSpectrum[i];
      const baselineAmp =
        baselineIndex < baselineSpectrum.length ? baselineSpectrum[baselineIndex] : 0;

      const broadbandCompareValue = Math.max(
        baselineAmp * broadbandFactor,
        absoluteThreshold * 1.1
      );
      if (currentAmp > broadbandCompareValue) {
        broadbandExceedCount++;
      }

      let isNearSR = false;
      for (const srIndex of SCHUMANN_INDICES_RAW) {
        if (Math.abs(i - srIndex) <= NARROWBAND_IGNORE_POINTS_RAW) {
          isNearSR = true;
          break;
        }
      }
      const narrowbandCompareValue = Math.max(
        baselineAmp * narrowbandFactor,
        baselineAmp + narrowbandMinAmpDelta,
        absoluteThreshold
      );
      if (!isNearSR && currentAmp >= narrowbandCompareValue) {
        const isLocalMax =
          (i === 0 || currentAmp >= rawNumericSpectrum[i - 1]) &&
          (i === rawNumericSpectrum.length - 1 || currentAmp >= rawNumericSpectrum[i + 1]);
        if (isLocalMax) {
          narrowBandPeakCandidates.push({
            freq: i * FREQUENCY_RESOLUTION_HZ,
            amp: currentAmp,
            delta: currentAmp - baselineAmp,
            index: i,
          });
        }
      }
    }

    const broadbandPct = broadbandExceedCount / rawNumericSpectrum.length;
    if (broadbandPct > broadbandThresholdPct) {
      result.type = 'broadband';
      result.details = `Broadband power increase detected (${(broadbandPct * 100).toFixed(1)}% of points > ${broadbandFactor}x baseline)`; // Corrected interpolation
      logger.info('Broadband transient detected', {
        detectorId,
        exceedCount: broadbandExceedCount,
        thresholdPct: broadbandThresholdPct * 100,
        actualPct: broadbandPct * 100,
      });
    } else if (narrowBandPeakCandidates.length > 0) {
      narrowBandPeakCandidates.sort((a, b) => b.delta - a.delta);
      const strongestPeak = narrowBandPeakCandidates[0];
      result.type = 'narrowband';
      result.details = `Narrowband signal detected near ${strongestPeak.freq.toFixed(1)} Hz (Amp: ${strongestPeak.amp.toFixed(1)}, Delta: ${strongestPeak.delta.toFixed(1)})`; // Corrected interpolation
      logger.info('Narrowband transient detected', {
        detectorId,
        peakFreq: strongestPeak.freq.toFixed(1),
        peakAmp: strongestPeak.amp.toFixed(1),
        delta: strongestPeak.delta.toFixed(1),
        candidateCount: narrowBandPeakCandidates.length,
      });
    }
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
  downsampleWithAntiAliasing, // Export the new downsampling function
  RAW_FREQUENCY_POINTS,
  FREQUENCY_RESOLUTION_HZ,
  SCHUMANN_FREQUENCIES,
  POINTS_PER_HZ,
  DOWNSAMPLE_FACTOR,
};
