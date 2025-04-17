// server/processingUtils.js
/**
 * Utility functions for EarthSync data processing (Peak Detection, Tracking, Transients).
 * Extracted for testability.
 * v1.1.14a - Phase 4a Fix: Adjusted transient check to use >=.
 */
const winston = require('winston');

// --- Logger Setup (Minimal for utilities) ---
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: [new winston.transports.Console({
      format: winston.format.simple(),
      silent: process.env.NODE_ENV === 'test'
    })]
});


// --- Constants needed by processing functions ---
const RAW_FREQUENCY_POINTS = 5501;
const FREQUENCY_RESOLUTION_HZ = 55 / (RAW_FREQUENCY_POINTS - 1);
const POINTS_PER_HZ = (RAW_FREQUENCY_POINTS - 1) / 55;
const SCHUMANN_FREQUENCIES = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0];

// --- Re-evaluate default parameters here or pass them in ---
const PEAK_SMOOTHING_WINDOW = parseInt(process.env.PEAK_SMOOTHING_WINDOW, 10) || 5;
const PEAK_PROMINENCE_FACTOR = parseFloat(process.env.PEAK_PROMINENCE_FACTOR || 1.5);
const PEAK_MIN_DISTANCE_HZ = parseFloat(process.env.PEAK_MIN_DISTANCE_HZ || 1.0);
const PEAK_MIN_DISTANCE_POINTS = Math.max(1, Math.round(PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ));
const PEAK_ABSOLUTE_THRESHOLD = parseFloat(process.env.PEAK_ABSOLUTE_THRESHOLD || 1.0);
const PEAK_TRACKING_FREQ_TOLERANCE_HZ = parseFloat(process.env.PEAK_TRACKING_FREQ_TOLERANCE_HZ || PEAK_MIN_DISTANCE_HZ / 2 || 0.5);
const PEAK_TRACKING_STATE_TTL_SECONDS = parseInt(process.env.PEAK_TRACKING_STATE_TTL_SECONDS, 10) || 300;
const TRANSIENT_HISTORY_LOOKBACK = parseInt(process.env.TRANSIENT_HISTORY_LOOKBACK, 10) || 5;
const TRANSIENT_BROADBAND_FACTOR = parseFloat(process.env.TRANSIENT_BROADBAND_FACTOR || 3.0);
const TRANSIENT_BROADBAND_THRESHOLD_PCT = parseFloat(process.env.TRANSIENT_BROADBAND_THRESHOLD_PCT || 0.10);
const TRANSIENT_NARROWBAND_FACTOR = parseFloat(process.env.TRANSIENT_NARROWBAND_FACTOR || 5.0);
const TRANSIENT_NARROWBAND_MIN_AMP_DELTA = parseFloat(process.env.TRANSIENT_NARROWBAND_MIN_AMP_DELTA || 3.0);
const TRANSIENT_NARROWBAND_IGNORE_HZ = parseFloat(process.env.TRANSIENT_NARROWBAND_IGNORE_HZ || 1.5);
const DOWNSAMPLE_FACTOR = parseInt(process.env.DOWNSAMPLE_FACTOR, 10) || 5;


/** Apply moving average smoothing */
function smooth(data, windowSize) {
    const safeWindowSize = (typeof windowSize !== 'number' || windowSize < 1 || windowSize % 2 === 0) ? 5 : windowSize;
    if (safeWindowSize <= 1) return data;

    const smoothed = [];
    const halfWindow = Math.floor(safeWindowSize / 2);
    for (let i = 0; i < data.length; i++) {
        const start = Math.max(0, i - halfWindow);
        const end = Math.min(data.length, i + halfWindow + 1);
        let sum = 0;
        let count = 0;
        for (let j = start; j < end; j++) {
            if (typeof data[j] === 'number' && !isNaN(data[j])) {
                sum += data[j];
                count++;
            }
        }
        smoothed.push(count > 0 ? sum / count : (typeof data[i] === 'number' && !isNaN(data[i]) ? data[i] : 0) );
    }
    return smoothed;
}


/**
 * Enhanced Peak detection on RAW spectrum.
 */
function detectPeaksEnhanced(rawSpectrum, config = {}) {
    const smoothingWindow = config.smoothingWindow || PEAK_SMOOTHING_WINDOW;
    const absoluteThreshold = config.absoluteThreshold || PEAK_ABSOLUTE_THRESHOLD;
    const minDistancePoints = config.minDistancePoints || PEAK_MIN_DISTANCE_POINTS;
    const prominenceFactor = config.prominenceFactor || PEAK_PROMINENCE_FACTOR;

    if (!rawSpectrum || rawSpectrum.length < smoothingWindow) return [];

    const n = rawSpectrum.length;
    const numericSpectrum = rawSpectrum.map(v => { const num = Number(v); return isNaN(num) ? 0 : num; });

    const smoothedSpectrum = smooth(numericSpectrum, smoothingWindow);

    const candidates = [];
    for (let i = 1; i < n - 1; i++) {
        if (smoothedSpectrum[i] > smoothedSpectrum[i - 1] &&
            smoothedSpectrum[i] > smoothedSpectrum[i + 1] &&
            smoothedSpectrum[i] >= absoluteThreshold) {
            candidates.push({ index: i, amp: smoothedSpectrum[i] });
        }
    }
    if (candidates.length === 0) return [];

    const windowSizeForProminence = minDistancePoints * 2 + 1;
    const prominentPeaks = candidates.filter(candidate => {
        const i = candidate.index;
        const windowStart = Math.max(0, i - Math.floor(windowSizeForProminence / 2));
        const windowEnd = Math.min(n, i + Math.floor(windowSizeForProminence / 2) + 1);
        let localMin = Infinity;
        for (let k = windowStart; k < windowEnd; k++) {
            if (k !== i) localMin = Math.min(localMin, smoothedSpectrum[k]);
        }
        if (!isFinite(localMin)) return false;

        let localSumSq = 0; let localSum = 0; let count = 0;
        for (let k = windowStart; k < windowEnd; k++) {
            localSum += smoothedSpectrum[k];
            localSumSq += smoothedSpectrum[k] * smoothedSpectrum[k];
            count++;
        }
        if (count === 0) return false;
        const localMean = localSum / count;
        const localVariance = Math.max(0, (localSumSq / count) - (localMean * localMean));
        const localStdDev = Math.sqrt(localVariance) || 0.1;

        const prominence = candidate.amp - localMin;
        const prominenceThreshold = prominenceFactor * localStdDev;

        return prominence >= prominenceThreshold && candidate.amp >= absoluteThreshold;
    });

    if (prominentPeaks.length === 0) return [];

    prominentPeaks.sort((a, b) => b.amp - a.amp);
    const finalPeakIndices = [];
    const excludedIndices = new Set();
    for (const peak of prominentPeaks) {
        if (!excludedIndices.has(peak.index)) {
            finalPeakIndices.push(peak.index);
            for (let k = 1; k <= minDistancePoints; k++) {
                excludedIndices.add(peak.index + k);
                excludedIndices.add(peak.index - k);
            }
        }
    }
    if (finalPeakIndices.length === 0) return [];

    const finalPeaks = finalPeakIndices.map(index => {
        const peakAmp = numericSpectrum[index];
        const peakFreq = index * FREQUENCY_RESOLUTION_HZ;
        const halfMax = peakAmp / 2;

        if (peakAmp < absoluteThreshold || halfMax <= 0) {
             return { freq: peakFreq, amp: peakAmp, qFactor: null };
        }

        let leftIndex = index, rightIndex = index;
        while (leftIndex > 0 && numericSpectrum[leftIndex - 1] > halfMax) { leftIndex--; }
        while (rightIndex < n - 1 && numericSpectrum[rightIndex + 1] > halfMax) { rightIndex++; }

        let fwhm = (rightIndex - leftIndex + 1) * FREQUENCY_RESOLUTION_HZ;
        try {
            const y1 = numericSpectrum[leftIndex - 1] || 0;
            const y2 = numericSpectrum[leftIndex];
            const y3 = numericSpectrum[rightIndex];
            const y4 = numericSpectrum[rightIndex + 1] || 0;

            const leftInterpFactor = (y2 > halfMax && y1 < halfMax && y2 > y1) ? (halfMax - y1) / (y2 - y1) : 0;
            const rightInterpFactor = (y3 > halfMax && y4 < halfMax && y3 > y4) ? (halfMax - y4) / (y3 - y4) : 0;

            const interpolatedLeftIdx = (leftIndex - 1) + leftInterpFactor;
            const interpolatedRightIdx = (rightIndex + 1) - rightInterpFactor;

             fwhm = Math.max(FREQUENCY_RESOLUTION_HZ, (interpolatedRightIdx - interpolatedLeftIdx) * FREQUENCY_RESOLUTION_HZ);

        } catch (interpErr) {
             logger.debug("FWHM interpolation failed", { index, error: interpErr.message });
             fwhm = Math.max(FREQUENCY_RESOLUTION_HZ, (rightIndex - leftIndex + 1) * FREQUENCY_RESOLUTION_HZ);
        }

        let qFactor = null;
        if (peakFreq > 1e-6 && fwhm > 1e-6) { qFactor = peakFreq / fwhm; }

        return { freq: peakFreq, amp: peakAmp, qFactor: qFactor };
    }).filter(p => p.amp >= absoluteThreshold);

    finalPeaks.sort((a,b) => a.freq - b.freq);
    return finalPeaks;
}


/**
 * Phase 1: Basic Peak Tracking.
 */
async function trackPeaks(detectorId, currentPeaks, redisStateClient, config = {}) {
    const freqTolerance = config.freqTolerance || PEAK_TRACKING_FREQ_TOLERANCE_HZ;
    const stateTTL = config.stateTTL || PEAK_TRACKING_STATE_TTL_SECONDS;
    const trackStateKey = `track_state:${detectorId}`;
    let previousPeaks = [];

    try {
        const previousStateJSON = await redisStateClient.get(trackStateKey);
        if (previousStateJSON) {
            previousPeaks = JSON.parse(previousStateJSON);
            if (!Array.isArray(previousPeaks)) previousPeaks = [];
        }
    } catch (err) {
        logger.warn('Failed to get previous peak state from Redis', { detectorId, key: trackStateKey, error: err.message });
        previousPeaks = [];
    }

    const matchedPrevIndices = new Set();
    const trackedPeaks = currentPeaks.map(currentPeak => {
        let bestMatch = null;
        let minFreqDiff = freqTolerance;

        for (let i = 0; i < previousPeaks.length; i++) {
            if (matchedPrevIndices.has(i)) continue;

            const prevPeak = previousPeaks[i];
            const freqDiff = Math.abs(currentPeak.freq - prevPeak.freq);

            if (freqDiff <= minFreqDiff) {
                if (!bestMatch || freqDiff < minFreqDiff) {
                    minFreqDiff = freqDiff;
                    bestMatch = { index: i, peak: prevPeak };
                }
            }
        }

        if (bestMatch) {
             matchedPrevIndices.add(bestMatch.index);
             return { ...currentPeak, trackStatus: 'continuing' };
        } else {
             return { ...currentPeak, trackStatus: 'new' };
        }
    });

    try {
        if (currentPeaks.length > 0) {
            const stateToStore = currentPeaks.map(p => ({ freq: p.freq, amp: p.amp }));
            await redisStateClient.setex(trackStateKey, stateTTL, JSON.stringify(stateToStore));
        } else {
            const exists = await redisStateClient.exists(trackStateKey);
            if (exists) {
                await redisStateClient.del(trackStateKey);
                logger.debug("No current peaks, removed tracking state", { detectorId, key: trackStateKey });
            }
        }
    } catch (err) {
        logger.error('Failed to set peak tracking state in Redis', { detectorId, key: trackStateKey, error: err.message });
    }

    logger.debug("Peak tracking results", { detectorId, counts: { new: trackedPeaks.filter(p=>p.trackStatus==='new').length, continuing: trackedPeaks.filter(p=>p.trackStatus==='continuing').length }});
    return trackedPeaks;
}


/**
 * Phase 4a: Enhanced Transient Detection.
 */
async function detectTransients(detectorId, rawSpectrum, redisHistoryClient, config = {}) {
    const historyKey = `spectrogram_history:${detectorId}`;
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
             logger.debug("Not enough history for transient baseline", { detectorId, count: historyJSONs.length });
             return result;
        }

        const historicalSpectra = historyJSONs.map(json => {
            try {
                const parsed = JSON.parse(json);
                if (parsed && Array.isArray(parsed.spectrogram) && Array.isArray(parsed.spectrogram[0])) { return parsed.spectrogram[0]; }
                return null;
            } catch { return null; }
        }).filter(spec => spec && spec.length > 0);

        if (historicalSpectra.length < 1) {
             logger.warn("No valid historical spectra found for baseline calculation", { detectorId });
             return result;
        }

        const baselineLength = historicalSpectra[0].length;
        const baselineSpectrum = new Array(baselineLength).fill(0);
        let validSpectraCount = 0;
        for (const spec of historicalSpectra) {
            if (spec.length !== baselineLength) continue;
            for (let i = 0; i < baselineLength; i++) { baselineSpectrum[i] += (Number(spec[i]) || 0); }
            validSpectraCount++;
        }
        if (validSpectraCount === 0) { logger.warn("No valid hist spectra matching length", { detectorId }); return result; }
        for (let i = 0; i < baselineLength; i++) { baselineSpectrum[i] /= validSpectraCount; }

        let broadbandExceedCount = 0;
        let narrowBandPeaks = [];

        const SCHUMANN_INDICES = SCHUMANN_FREQUENCIES.map(f => Math.round(f * POINTS_PER_HZ));
        const NARROWBAND_IGNORE_POINTS = Math.round(narrowbandIgnoreHz * POINTS_PER_HZ);
        const rawNumericSpectrum = rawSpectrum.map(v => Number(v) || 0);

        for (let i = 0; i < rawNumericSpectrum.length; i++) {
            const baselineIndex = Math.floor(i / downsampleFactor);
            const currentAmp = rawNumericSpectrum[i];
            const baselineAmp = baselineSpectrum[baselineIndex] || 0;
            const ampDelta = currentAmp - baselineAmp;

            if (currentAmp > baselineAmp * broadbandFactor && currentAmp > absoluteThreshold) {
                broadbandExceedCount++;
            }

            let isNearSR = false;
            for(const srIndex of SCHUMANN_INDICES){ if(Math.abs(i - srIndex) <= NARROWBAND_IGNORE_POINTS){ isNearSR = true; break; } }

            // Phase 4a Fix: Use >= for factor comparison
            if (!isNearSR &&
                currentAmp >= baselineAmp * narrowbandFactor && // Changed > to >=
                currentAmp > absoluteThreshold &&
                ampDelta >= narrowbandMinAmpDelta)
            {
                 const isLocalMax = (i > 0 ? currentAmp > rawNumericSpectrum[i-1] : true) &&
                                  (i < rawNumericSpectrum.length - 1 ? currentAmp > rawNumericSpectrum[i+1] : true);
                 if(isLocalMax) {
                    narrowBandPeaks.push({ freq: i * FREQUENCY_RESOLUTION_HZ, amp: currentAmp, delta: ampDelta });
                 }
            }
        }

        const broadbandPct = broadbandExceedCount / rawNumericSpectrum.length;
        if (broadbandPct > broadbandThresholdPct) {
            result.type = 'broadband';
            result.details = `Broadband power increase detected (${(broadbandPct * 100).toFixed(1)}% of points > ${broadbandFactor}x baseline)`;
             logger.info("Broadband transient detected", { detectorId, exceedCount: broadbandExceedCount, thresholdPct: broadbandThresholdPct });
        } else if (narrowBandPeaks.length > 0) {
            narrowBandPeaks.sort((a, b) => b.delta - a.delta);
            const strongestPeak = narrowBandPeaks[0];
            result.type = 'narrowband';
            result.details = `Narrowband signal detected near ${strongestPeak.freq.toFixed(1)} Hz (Amp: ${strongestPeak.amp.toFixed(1)}, Delta: ${strongestPeak.delta.toFixed(1)})`;
             logger.info("Narrowband transient detected", { detectorId, peakFreq: strongestPeak.freq.toFixed(1), peakAmp: strongestPeak.amp.toFixed(1), delta: strongestPeak.delta.toFixed(1), count: narrowBandPeaks.length });
        }

    } catch (err) {
        logger.error('Error during transient detection', { detectorId, error: err.message, stack: err.stack });
        result = { type: 'error', details: 'Transient detection failed' };
    }
    return result;
}


module.exports = {
    smooth,
    detectPeaksEnhanced,
    trackPeaks,
    detectTransients,
    RAW_FREQUENCY_POINTS,
    FREQUENCY_RESOLUTION_HZ,
    SCHUMANN_FREQUENCIES,
    POINTS_PER_HZ,
};
