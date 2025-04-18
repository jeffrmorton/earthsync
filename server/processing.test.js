// server/processing.test.js
// Unit Tests for Data Processing Utilities (v1.1.28 - Linter Fixes)

// Mock Redis client methods needed for detectTransients
// Removed unused mockRedisClient definition
const mockStreamRedisClient = {
  lrange: jest.fn(),
};

// Mock DB functions used by trackPeaks
const mockDb = {
  getPeakTrackingState: jest.fn(),
  savePeakTrackingState: jest.fn(),
  deletePeakTrackingState: jest.fn(),
};
jest.mock('./db', () => mockDb); // Mock the entire db module

// Mock winston logger to prevent actual logging during tests
const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};
jest.mock('./utils/logger', () => mockLogger); // Mock the centralized logger utility

// Import the functions to test *from the utility file*
const {
  detectPeaksEnhanced,
  trackPeaks,
  detectTransients,
  // Import constants used within tests or functions
  RAW_FREQUENCY_POINTS,
  FREQUENCY_RESOLUTION_HZ,
  POINTS_PER_HZ,
  // SCHUMANN_FREQUENCIES, // Removed unused import
} = require('./processingUtils');
const constants = require('./config/constants'); // Import constants for default values

// Constants for tests (using defaults from imported constants)
const TEST_PEAK_ABSOLUTE_THRESHOLD = constants.DEFAULT_PEAK_ABSOLUTE_THRESHOLD;
const TEST_PEAK_MIN_DISTANCE_HZ = constants.DEFAULT_PEAK_MIN_DISTANCE_HZ;
const TEST_PEAK_MIN_DISTANCE_POINTS = Math.max(
  1,
  Math.round(TEST_PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ)
);
const TEST_PEAK_SMOOTHING_WINDOW = constants.DEFAULT_PEAK_SMOOTHING_WINDOW;
const TEST_PEAK_PROMINENCE_FACTOR = constants.DEFAULT_PEAK_PROMINENCE_FACTOR;
const TEST_TRACKING_FREQ_TOLERANCE_HZ = constants.DEFAULT_PEAK_TRACKING_FREQ_TOLERANCE_HZ;
const TEST_TRANSIENT_NARROWBAND_IGNORE_HZ = constants.DEFAULT_TRANSIENT_NARROWBAND_IGNORE_HZ;
const TEST_DOWNSAMPLE_FACTOR = constants.DOWNSAMPLE_FACTOR;
const TEST_NARROWBAND_MIN_AMP_DELTA = constants.DEFAULT_TRANSIENT_NARROWBAND_MIN_AMP_DELTA;
const TEST_BROADBAND_FACTOR = constants.DEFAULT_TRANSIENT_BROADBAND_FACTOR;
const TEST_BROADBAND_THRESHOLD_PCT = constants.DEFAULT_TRANSIENT_BROADBAND_THRESHOLD_PCT;

describe('Data Processing Functions', () => {
  beforeEach(() => {
    // Reset mocks before each test
    mockDb.getPeakTrackingState.mockReset();
    mockDb.savePeakTrackingState.mockReset();
    mockDb.deletePeakTrackingState.mockReset();
    mockStreamRedisClient.lrange.mockReset();
    // Reset logger mocks too
    mockLogger.info.mockClear();
    mockLogger.warn.mockClear();
    mockLogger.error.mockClear();
    mockLogger.debug.mockClear();
  });

  // --- detectPeaksEnhanced Tests ---
  describe('detectPeaksEnhanced', () => {
    const testConfigDefault = {
      smoothingWindow: TEST_PEAK_SMOOTHING_WINDOW,
      absoluteThreshold: TEST_PEAK_ABSOLUTE_THRESHOLD,
      minDistancePoints: TEST_PEAK_MIN_DISTANCE_POINTS,
      prominenceFactor: TEST_PEAK_PROMINENCE_FACTOR,
    };

    it('should return an empty array for insufficient data', () => {
      const spectrum = [1, 2];
      expect(detectPeaksEnhanced(spectrum, testConfigDefault)).toEqual([]);
    });

    it('should return an empty array for flat spectrum below threshold', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(0.5);
      expect(detectPeaksEnhanced(spectrum, testConfigDefault)).toEqual([]);
    });

    it('should detect a simple peak correctly', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
      const peakFreq = 10;
      const peakIndex = Math.round(peakFreq / FREQUENCY_RESOLUTION_HZ);
      spectrum[peakIndex - 2] = 3.0;
      spectrum[peakIndex - 1] = 7.0;
      spectrum[peakIndex] = 10.0;
      spectrum[peakIndex + 1] = 7.0;
      spectrum[peakIndex + 2] = 3.0;

      const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
      expect(peaks.length).toBe(1);
      expect(peaks[0].freq).toBeCloseTo(peakFreq, 1);
      expect(peaks[0].amp).toBeCloseTo(10.0);
      expect(peaks[0].qFactor).toBeGreaterThan(2);
    });

    it('should detect peak at the start of the spectrum', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
      spectrum[2] = 10.0;
      spectrum[1] = 7.0;
      spectrum[3] = 7.0;
      spectrum[0] = 3.0;
      spectrum[4] = 3.0;
      const peaksAdjusted = detectPeaksEnhanced(spectrum, testConfigDefault);
      expect(peaksAdjusted.length).toBeGreaterThanOrEqual(1);
      const targetPeak = peaksAdjusted.reduce(
        (closest, current) =>
          Math.abs(current.freq - 2 * FREQUENCY_RESOLUTION_HZ) <
          Math.abs(closest.freq - 2 * FREQUENCY_RESOLUTION_HZ)
            ? current
            : closest,
        { freq: Infinity }
      );
      expect(targetPeak.freq).toBeCloseTo(2 * FREQUENCY_RESOLUTION_HZ, 1);
      expect(targetPeak.amp).toBeGreaterThan(TEST_PEAK_ABSOLUTE_THRESHOLD);
      expect(targetPeak.amp).toBeLessThanOrEqual(10.0);
    });

    it('should detect peak at the end of the spectrum', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
      const peakIndex = RAW_FREQUENCY_POINTS - 3;
      spectrum[peakIndex] = 10.0;
      spectrum[peakIndex - 1] = 7.0;
      spectrum[peakIndex + 1] = 7.0;
      spectrum[peakIndex - 2] = 3.0;
      spectrum[peakIndex + 2] = 3.0;
      const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
      expect(peaks.length).toBeGreaterThanOrEqual(1);
      // Removed unused targetPeak assignment
      expect(peaks[peaks.length - 1].freq).toBeCloseTo(peakIndex * FREQUENCY_RESOLUTION_HZ, 1);
      expect(peaks[peaks.length - 1].amp).toBeGreaterThan(TEST_PEAK_ABSOLUTE_THRESHOLD);
      expect(peaks[peaks.length - 1].amp).toBeLessThanOrEqual(10.0);
    });

    it('should ignore peaks below absolute threshold', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(0.1);
      const peakIndex = 500;
      spectrum[peakIndex - 1] = 0.3;
      spectrum[peakIndex] = 0.8;
      spectrum[peakIndex + 1] = 0.3;
      const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
      expect(peaks.length).toBe(0);
    });

    it('should handle multiple peaks respecting min distance', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
      const peakFreq1 = 10;
      const peakIndex1 = Math.round(peakFreq1 / FREQUENCY_RESOLUTION_HZ);
      spectrum[peakIndex1] = 10.0;
      spectrum[peakIndex1 - 1] = 5.0;
      spectrum[peakIndex1 + 1] = 5.0;
      const peakFreq2 = 10.5;
      const peakIndex2 = Math.round(peakFreq2 / FREQUENCY_RESOLUTION_HZ);
      spectrum[peakIndex2] = 8.0;
      spectrum[peakIndex2 - 1] = 4.0;
      spectrum[peakIndex2 + 1] = 4.0;
      const peakFreq3 = 15;
      const peakIndex3 = Math.round(peakFreq3 / FREQUENCY_RESOLUTION_HZ);
      spectrum[peakIndex3] = 9.0;
      spectrum[peakIndex3 - 1] = 4.5;
      spectrum[peakIndex3 + 1] = 4.5;

      const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
      expect(peaks.length).toBe(2);
      expect(peaks.find((p) => Math.abs(p.freq - peakFreq1) < 0.1)).toBeDefined();
      expect(peaks.find((p) => Math.abs(p.freq - peakFreq3) < 0.1)).toBeDefined();
      expect(peaks.find((p) => Math.abs(p.freq - peakFreq2) < 0.1)).toBeUndefined();
    });

    it('should handle NaN or non-numeric values gracefully', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
      const peakFreq = 20;
      const peakIndex = Math.round(peakFreq / FREQUENCY_RESOLUTION_HZ);
      spectrum[peakIndex] = 15.0;
      spectrum[peakIndex - 1] = 7.0;
      spectrum[peakIndex + 1] = 7.0;
      spectrum[peakIndex + 10] = NaN;
      spectrum[peakIndex + 11] = undefined;
      spectrum[peakIndex - 5] = 'text';
      const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
      expect(peaks.length).toBeGreaterThanOrEqual(1);
      expect(peaks.find((p) => Math.abs(p.freq - peakFreq) < 1)).toBeDefined();
    });

    it('should use config overrides when provided', () => {
      const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(0.3);
      const peakFreq1 = 10;
      const peakIndex1 = Math.round(peakFreq1 / FREQUENCY_RESOLUTION_HZ);
      spectrum[peakIndex1] = 1.5;
      spectrum[peakIndex1 - 1] = 0.8;
      spectrum[peakIndex1 + 1] = 0.8;
      const lowerThresholdConfig = { ...testConfigDefault, absoluteThreshold: 0.5 };
      const peaks = detectPeaksEnhanced(spectrum, lowerThresholdConfig);
      expect(peaks.length).toBe(1);
      expect(peaks[0].amp).toBeCloseTo(1.5);
    });
  });

  // --- trackPeaks Tests ---
  describe('trackPeaks', () => {
    const detectorId = 'test-tracker';
    const now = Date.now();
    const peak1 = { freq: 7.8, amp: 10, qFactor: 5 };
    const peak2 = { freq: 14.2, amp: 8, qFactor: 6 };
    const peak1_shifted_close = { freq: 7.9, amp: 11, qFactor: 4.8 };
    const peak1_shifted_far = { freq: 8.4, amp: 11, qFactor: 4.8 };
    const peak3_new = { freq: 20.5, amp: 5, qFactor: 7 };
    const trackConfig = { freqTolerance: TEST_TRACKING_FREQ_TOLERANCE_HZ };

    it('should mark all peaks as new if no previous state exists in DB', async () => {
      mockDb.getPeakTrackingState.mockResolvedValue(null);
      const currentPeaks = [peak1, peak2];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);

      expect(mockDb.getPeakTrackingState).toHaveBeenCalledWith(detectorId);
      expect(tracked.length).toBe(2);
      expect(tracked[0].trackStatus).toBe('new');
      expect(tracked[0].trackId).toBeDefined();
      expect(tracked[1].trackStatus).toBe('new');
      expect(tracked[1].trackId).toBeDefined();
      expect(tracked[0].trackId).not.toEqual(tracked[1].trackId);
      expect(mockDb.savePeakTrackingState).toHaveBeenCalledWith(detectorId, expect.any(Array));
      expect(mockDb.deletePeakTrackingState).not.toHaveBeenCalled();
    });

    it('should mark continuing peaks within tolerance using DB state', async () => {
      const prevState = [
        { id: 'uuid-1', freq: 7.7, amp: 9, lastTs: now - 5000 },
        { id: 'uuid-2', freq: 14.3, amp: 8.5, lastTs: now - 5000 },
      ];
      mockDb.getPeakTrackingState.mockResolvedValue(prevState);
      const currentPeaks = [peak1_shifted_close, peak2];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);

      expect(tracked.length).toBe(2);
      expect(tracked[0].trackStatus).toBe('continuing');
      expect(tracked[0].trackId).toBe('uuid-1');
      expect(tracked[1].trackStatus).toBe('continuing');
      expect(tracked[1].trackId).toBe('uuid-2');
      expect(mockDb.savePeakTrackingState).toHaveBeenCalled();
    });

    it('should mark peaks as new if frequency shift exceeds tolerance', async () => {
      const prevState = [{ id: 'uuid-1', freq: 7.8, amp: 9, lastTs: now - 5000 }];
      mockDb.getPeakTrackingState.mockResolvedValue(prevState);
      const currentPeaks = [peak1_shifted_far];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);

      expect(tracked.length).toBe(1);
      expect(tracked[0].trackStatus).toBe('new');
      expect(tracked[0].trackId).toBeDefined();
      expect(tracked[0].trackId).not.toEqual('uuid-1');
      expect(mockDb.savePeakTrackingState).toHaveBeenCalled();
    });

    it('should handle multiple new and continuing peaks', async () => {
      const prevState = [
        { id: 'uuid-1', freq: 7.7, amp: 9, lastTs: now - 5000 },
        { id: 'uuid-2', freq: 14.3, amp: 8.5, lastTs: now - 5000 },
      ];
      mockDb.getPeakTrackingState.mockResolvedValue(prevState);
      const currentPeaks = [peak1_shifted_close, peak3_new];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);

      expect(tracked.length).toBe(2);
      const trackedPeak1 = tracked.find((p) => p.freq === peak1_shifted_close.freq);
      const trackedPeak3 = tracked.find((p) => p.freq === peak3_new.freq);

      expect(trackedPeak1.trackStatus).toBe('continuing');
      expect(trackedPeak1.trackId).toBe('uuid-1');
      expect(trackedPeak3.trackStatus).toBe('new');
      expect(trackedPeak3.trackId).toBeDefined();
      expect(trackedPeak3.trackId).not.toEqual('uuid-1');
      expect(trackedPeak3.trackId).not.toEqual('uuid-2');
      expect(mockDb.savePeakTrackingState).toHaveBeenCalled();
    });

    it('should handle disappearance of peaks correctly', async () => {
      const prevState = [
        { id: 'uuid-1', freq: 7.7, amp: 9, lastTs: now - 5000 },
        { id: 'uuid-2', freq: 14.3, amp: 8.5, lastTs: now - 5000 },
      ];
      mockDb.getPeakTrackingState.mockResolvedValue(prevState);
      const currentPeaks = [peak1_shifted_close];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);

      expect(tracked.length).toBe(1);
      expect(tracked[0].trackStatus).toBe('continuing');
      expect(tracked[0].trackId).toBe('uuid-1');
      expect(mockDb.savePeakTrackingState).toHaveBeenCalledWith(
        detectorId,
        expect.not.arrayContaining([expect.objectContaining({ id: 'uuid-2' })])
      );
      expect(mockDb.deletePeakTrackingState).not.toHaveBeenCalled();
    });

    it('should delete state from DB if no current peaks are detected', async () => {
      const prevState = [{ id: 'uuid-1', freq: 7.7, amp: 9, lastTs: now - 5000 }];
      mockDb.getPeakTrackingState.mockResolvedValue(prevState);
      const currentPeaks = [];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);

      expect(tracked.length).toBe(0);
      expect(mockDb.savePeakTrackingState).not.toHaveBeenCalled();
      expect(mockDb.deletePeakTrackingState).toHaveBeenCalledWith(detectorId);
    });

    it('should do nothing if no current peaks and no previous state', async () => {
      mockDb.getPeakTrackingState.mockResolvedValue(null);
      const currentPeaks = [];
      const tracked = await trackPeaks(detectorId, currentPeaks, now, trackConfig);
      expect(tracked.length).toBe(0);
      expect(mockDb.savePeakTrackingState).not.toHaveBeenCalled();
      expect(mockDb.deletePeakTrackingState).not.toHaveBeenCalled();
    });
  });

  // --- detectTransients Tests ---
  describe('detectTransients', () => {
    const detectorId = 'test-transient';
    const downsampledLength = Math.ceil(RAW_FREQUENCY_POINTS / TEST_DOWNSAMPLE_FACTOR);
    const testConfig = {
      downsampleFactor: TEST_DOWNSAMPLE_FACTOR,
      absoluteThreshold: TEST_PEAK_ABSOLUTE_THRESHOLD,
      narrowbandIgnoreHz: TEST_TRANSIENT_NARROWBAND_IGNORE_HZ,
      broadbandFactor: TEST_BROADBAND_FACTOR,
      broadbandThresholdPct: TEST_BROADBAND_THRESHOLD_PCT,
      narrowbandMinAmpDelta: TEST_NARROWBAND_MIN_AMP_DELTA,
      narrowbandFactor: constants.DEFAULT_TRANSIENT_NARROWBAND_FACTOR,
      historyLookback: constants.DEFAULT_TRANSIENT_HISTORY_LOOKBACK,
    };

    const createHistoryEntry = (spectrumData, ts = new Date().toISOString()) =>
      JSON.stringify({
        detectorId,
        timestamp: ts,
        location: { lat: 0, lon: 0 },
        spectrogram: [spectrumData], // History stores downsampled spectrum in nested array
        processingResults: [{ detectedPeaks: [], transientInfo: { type: 'none', details: null } }],
      });

    it('should return type none if insufficient history', async () => {
      mockStreamRedisClient.lrange.mockResolvedValue([
        createHistoryEntry(new Array(downsampledLength).fill(1.0)),
      ]);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.5);
      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('none');
      expect(mockStreamRedisClient.lrange).toHaveBeenCalledWith(
        `spectrogram_history:${detectorId}`,
        0,
        testConfig.historyLookback - 1
      );
    });

    it('should detect broadband transient', async () => {
      const baselineVal = 1.0;
      const history = [
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
      ];
      mockStreamRedisClient.lrange.mockResolvedValue(history);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(
        baselineVal * (TEST_BROADBAND_FACTOR + 0.5)
      );
      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('broadband');
      expect(result.details).toMatch(/Broadband power increase detected/);
    });

    it('should NOT detect broadband if below threshold percentage', async () => {
      const baselineVal = 1.0;
      const history = [
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
      ];
      mockStreamRedisClient.lrange.mockResolvedValue(history);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
      const exceedCount = Math.floor(RAW_FREQUENCY_POINTS * (TEST_BROADBAND_THRESHOLD_PCT / 2));
      for (let i = 0; i < exceedCount; i++) {
        rawSpectrum[i] = baselineVal * (TEST_BROADBAND_FACTOR + 0.5);
      }
      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('none');
    });

    it('should detect narrowband transient outside SR ranges', async () => {
      const baselineVal = 1.0;
      const history = [
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
      ];
      mockStreamRedisClient.lrange.mockResolvedValue(history);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
      const transientFreq = 4.0;
      const transientIndex = Math.round(transientFreq * POINTS_PER_HZ);
      const transientAmp =
        Math.max(
          baselineVal * testConfig.narrowbandFactor,
          baselineVal + TEST_NARROWBAND_MIN_AMP_DELTA,
          TEST_PEAK_ABSOLUTE_THRESHOLD * 1.1
        ) + 0.1;
      rawSpectrum[transientIndex] = transientAmp;
      rawSpectrum[transientIndex - 1] = baselineVal + 0.5;
      rawSpectrum[transientIndex + 1] = baselineVal + 0.5;

      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('narrowband');
      expect(result.details).toMatch(/Narrowband signal detected near 4.0 Hz/);
      expect(result.details).toMatch(`Amp: ${transientAmp.toFixed(1)}`);
      expect(result.details).toMatch(`Delta: ${(transientAmp - baselineVal).toFixed(1)}`);
    });

    it('should ignore narrowband peaks near SR frequencies', async () => {
      const baselineVal = 1.0;
      const history = [
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
      ];
      mockStreamRedisClient.lrange.mockResolvedValue(history);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
      const transientFreq = 7.5;
      const transientIndex = Math.round(transientFreq * POINTS_PER_HZ);
      rawSpectrum[transientIndex] = baselineVal + TEST_NARROWBAND_MIN_AMP_DELTA + 1.0;
      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('none');
    });

    it('should ignore narrowband peaks if delta is below minimum', async () => {
      const baselineVal = 4.0;
      const history = [
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
      ];
      mockStreamRedisClient.lrange.mockResolvedValue(history);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
      const transientFreq = 4.0;
      const transientIndex = Math.round(transientFreq * POINTS_PER_HZ);
      rawSpectrum[transientIndex] = baselineVal + TEST_NARROWBAND_MIN_AMP_DELTA - 0.1;
      rawSpectrum[transientIndex - 1] = baselineVal;
      rawSpectrum[transientIndex + 1] = baselineVal;

      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('none');
    });

    it('should return type none for normal spectrum without significant peaks/broadband', async () => {
      const baselineVal = 1.0;
      const history = [
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
        createHistoryEntry(new Array(downsampledLength).fill(baselineVal)),
      ];
      mockStreamRedisClient.lrange.mockResolvedValue(history);
      const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal * 1.1);
      const result = await detectTransients(
        detectorId,
        rawSpectrum,
        mockStreamRedisClient,
        testConfig
      );
      expect(result.type).toBe('none');
    });
  });
});
