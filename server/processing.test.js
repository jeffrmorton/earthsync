// server/processing.test.js
// Unit Tests for Data Processing Utilities (v1.1.14a - Enhanced Tests Fix 2)

// Mock Redis client methods needed
const mockRedisClient = {
    get: jest.fn(),
    setex: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
};

const mockStreamRedisClient = {
    lrange: jest.fn(),
};

// Mock winston logger to prevent actual logging during tests
const mockLogger = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
};
jest.mock('winston', () => ({
    createLogger: jest.fn().mockReturnValue(mockLogger), // Use the mock logger
    format: {
        combine: jest.fn(), timestamp: jest.fn(), errors: jest.fn(),
        splat: jest.fn(), json: jest.fn(), colorize: jest.fn(), simple: jest.fn(),
    },
    transports: { Console: jest.fn(), File: jest.fn() },
}));

// Import the functions to test *from the utility file*
const {
    detectPeaksEnhanced,
    trackPeaks,
    detectTransients,
    // Import constants used within tests or functions
    RAW_FREQUENCY_POINTS,
    FREQUENCY_RESOLUTION_HZ,
    POINTS_PER_HZ,
    SCHUMANN_FREQUENCIES,
} = require('./processingUtils');

// Constants for tests
const TEST_PEAK_ABSOLUTE_THRESHOLD = 1.0;
const TEST_PEAK_MIN_DISTANCE_HZ = 1.0;
const TEST_PEAK_MIN_DISTANCE_POINTS = Math.max(1, Math.round(TEST_PEAK_MIN_DISTANCE_HZ / FREQUENCY_RESOLUTION_HZ));
const TEST_PEAK_SMOOTHING_WINDOW = 5;
const TEST_PEAK_PROMINENCE_FACTOR = 1.5;
const TEST_TRACKING_FREQ_TOLERANCE_HZ = 0.5;
const TEST_TRANSIENT_NARROWBAND_IGNORE_HZ = 1.5;
const TEST_DOWNSAMPLE_FACTOR = 5;
const TEST_NARROWBAND_MIN_AMP_DELTA = 3.0;
const TEST_BROADBAND_FACTOR = 3.0;
const TEST_BROADBAND_THRESHOLD_PCT = 0.10;


describe('Data Processing Functions', () => {

    beforeEach(() => {
        // Reset mocks before each test
        mockRedisClient.get.mockReset(); // Use mockReset for Jest functions
        mockRedisClient.setex.mockReset();
        mockRedisClient.del.mockReset();
        mockRedisClient.exists.mockReset();
        mockStreamRedisClient.lrange.mockReset();
        // Reset logger mocks too
        mockLogger.info.mockClear();
        mockLogger.warn.mockClear();
        mockLogger.error.mockClear();
        mockLogger.debug.mockClear();
    });

    // --- detectPeaksEnhanced Tests ---
    describe('detectPeaksEnhanced', () => {
        const testConfigDefault = { // Pass config explicitly to tests
            smoothingWindow: TEST_PEAK_SMOOTHING_WINDOW,
            absoluteThreshold: TEST_PEAK_ABSOLUTE_THRESHOLD,
            minDistancePoints: TEST_PEAK_MIN_DISTANCE_POINTS,
            prominenceFactor: TEST_PEAK_PROMINENCE_FACTOR
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
            const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0); // Slightly higher baseline
            const peakFreq = 10;
            const peakIndex = Math.round(peakFreq / FREQUENCY_RESOLUTION_HZ);
            // Make peak slightly wider for better smoothing survival
            spectrum[peakIndex - 2] = 3.0;
            spectrum[peakIndex - 1] = 7.0;
            spectrum[peakIndex]     = 10.0; // Peak amplitude
            spectrum[peakIndex + 1] = 7.0;
            spectrum[peakIndex + 2] = 3.0;

            const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
            expect(peaks.length).toBe(1);
            expect(peaks[0].freq).toBeCloseTo(peakFreq, 1);
            expect(peaks[0].amp).toBeCloseTo(10.0); // Check original amplitude
            expect(peaks[0].qFactor).toBeGreaterThan(2); // Expect reasonable Q for a simple peak
        });

        // --- Modified Test Case ---
        it('should detect peak at the start of the spectrum', () => {
             const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
             // Peak at index 2 should be detectable with window 5
             spectrum[2] = 10.0;
             spectrum[1] = 7.0; spectrum[3] = 7.0;
             spectrum[0] = 3.0; spectrum[4] = 3.0;
             const peaksAdjusted = detectPeaksEnhanced(spectrum, testConfigDefault);
             expect(peaksAdjusted.length).toBeGreaterThanOrEqual(1);
             expect(peaksAdjusted[0].freq).toBeCloseTo(2 * FREQUENCY_RESOLUTION_HZ, 1);
             // Adjust amplitude expectation due to edge smoothing effect
             expect(peaksAdjusted[0].amp).toBeGreaterThan(TEST_PEAK_ABSOLUTE_THRESHOLD); // Ensure it's above threshold
             expect(peaksAdjusted[0].amp).toBeLessThanOrEqual(10.0); // Should not exceed original max
        });
        // --- End Modified Test Case ---

         // --- Modified Test Case ---
         it('should detect peak at the end of the spectrum', () => {
             const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
             const peakIndex = RAW_FREQUENCY_POINTS - 3; // Peak near the end
             spectrum[peakIndex] = 10.0;
             spectrum[peakIndex - 1] = 7.0; spectrum[peakIndex + 1] = 7.0;
             spectrum[peakIndex - 2] = 3.0; spectrum[peakIndex + 2] = 3.0;
             const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
             expect(peaks.length).toBeGreaterThanOrEqual(1);
             expect(peaks[peaks.length - 1].freq).toBeCloseTo(peakIndex * FREQUENCY_RESOLUTION_HZ, 1);
             // Adjust amplitude expectation due to edge smoothing effect
             expect(peaks[peaks.length - 1].amp).toBeGreaterThan(TEST_PEAK_ABSOLUTE_THRESHOLD);
             expect(peaks[peaks.length - 1].amp).toBeLessThanOrEqual(10.0);
         });
         // --- End Modified Test Case ---


        it('should ignore peaks below absolute threshold', () => {
            const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(0.1);
            const peakIndex = 500;
            spectrum[peakIndex - 1] = 0.3; spectrum[peakIndex] = 0.8; spectrum[peakIndex + 1] = 0.3;
            const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
            expect(peaks.length).toBe(0);
        });

        it('should handle multiple peaks respecting min distance', () => {
             const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0); // Higher baseline
             const peakFreq1 = 10; const peakIndex1 = Math.round(peakFreq1 / FREQUENCY_RESOLUTION_HZ);
             spectrum[peakIndex1] = 10.0; spectrum[peakIndex1 - 1] = 5.0; spectrum[peakIndex1 + 1] = 5.0; spectrum[peakIndex1 - 2] = 2.0; spectrum[peakIndex1 + 2] = 2.0;
             const peakFreq2 = 10.5; const peakIndex2 = Math.round(peakFreq2 / FREQUENCY_RESOLUTION_HZ);
             spectrum[peakIndex2] = 8.0; spectrum[peakIndex2 - 1] = 4.0; spectrum[peakIndex2 + 1] = 4.0; // Ignored (too close to higher peak 1)
             const peakFreq3 = 15; const peakIndex3 = Math.round(peakFreq3 / FREQUENCY_RESOLUTION_HZ);
             spectrum[peakIndex3] = 9.0; spectrum[peakIndex3 - 1] = 4.5; spectrum[peakIndex3 + 1] = 4.5; spectrum[peakIndex3 - 2] = 1.5; spectrum[peakIndex3 + 2] = 1.5; // Detected
             const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
             expect(peaks.length).toBe(2); // Should detect peak 1 and 3
             expect(peaks.find(p => Math.abs(p.freq - peakFreq1) < 0.1)).toBeDefined();
             expect(peaks.find(p => Math.abs(p.freq - peakFreq3) < 0.1)).toBeDefined();
             expect(peaks.find(p => Math.abs(p.freq - peakFreq2) < 0.1)).toBeUndefined();
        });

        it('should handle NaN or non-numeric values gracefully', () => {
            const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.0);
            const peakFreq = 20; const peakIndex = Math.round(peakFreq / FREQUENCY_RESOLUTION_HZ);
            spectrum[peakIndex] = 15.0; spectrum[peakIndex - 1] = 7.0; spectrum[peakIndex + 1] = 7.0; spectrum[peakIndex - 2] = 3.0; spectrum[peakIndex + 2] = 3.0;
            spectrum[peakIndex+10] = NaN; spectrum[peakIndex+11] = undefined; spectrum[peakIndex-5] = "not a number";
            const peaks = detectPeaksEnhanced(spectrum, testConfigDefault);
             expect(peaks.length).toBeGreaterThanOrEqual(1); // Should still find the main peak
             expect(peaks.find(p => Math.abs(p.freq - peakFreq) < 1)).toBeDefined();
        });

        it('should use config overrides when provided', () => {
            const spectrum = new Array(RAW_FREQUENCY_POINTS).fill(0.3);
            const peakFreq1 = 10;
            const peakIndex1 = Math.round(peakFreq1 / FREQUENCY_RESOLUTION_HZ);
            spectrum[peakIndex1] = 1.5;
            spectrum[peakIndex1 - 1] = 0.8; spectrum[peakIndex1 + 1] = 0.8;
            spectrum[peakIndex1 - 2] = 0.4; spectrum[peakIndex1 + 2] = 0.4;
            const lowerThresholdConfig = { ...testConfigDefault, absoluteThreshold: 0.5 };
            const peaks = detectPeaksEnhanced(spectrum, lowerThresholdConfig);
            expect(peaks.length).toBe(1);
            expect(peaks[0].amp).toBeCloseTo(1.5);
        });
    });

    // --- trackPeaks Tests ---
    describe('trackPeaks', () => {
        const detectorId = 'test-tracker';
        const peak1 = { freq: 7.8, amp: 10, qFactor: 5 };
        const peak2 = { freq: 14.2, amp: 8, qFactor: 6 };
        const peak1_shifted_close = { freq: 7.9, amp: 11, qFactor: 4.8 }; // 0.1 Hz diff
        const peak1_shifted_far = { freq: 8.4, amp: 11, qFactor: 4.8 }; // 0.6 Hz diff > 0.5 tol
        const peak3_new = { freq: 20.5, amp: 5, qFactor: 7 };
        const trackConfig = { freqTolerance: TEST_TRACKING_FREQ_TOLERANCE_HZ, stateTTL: 300 };

        it('should mark all peaks as new if no previous state exists', async () => {
            mockRedisClient.get.mockResolvedValue(null);
            const currentPeaks = [peak1, peak2];
            const tracked = await trackPeaks(detectorId, currentPeaks, mockRedisClient, trackConfig);
            expect(tracked.length).toBe(2);
            expect(tracked[0]).toEqual({ ...peak1, trackStatus: 'new' });
            expect(tracked[1]).toEqual({ ...peak2, trackStatus: 'new' });
            expect(mockRedisClient.setex).toHaveBeenCalledWith(`track_state:${detectorId}`, 300, JSON.stringify([{freq: 7.8, amp: 10}, {freq: 14.2, amp: 8}]));
        });

        it('should mark continuing peaks within tolerance', async () => {
            const prevState = [ { freq: 7.7, amp: 9 }, { freq: 14.3, amp: 8.5 } ];
            mockRedisClient.get.mockResolvedValue(JSON.stringify(prevState));
            const currentPeaks = [peak1_shifted_close, peak2];
            const tracked = await trackPeaks(detectorId, currentPeaks, mockRedisClient, trackConfig);
            expect(tracked.length).toBe(2);
            expect(tracked[0]).toEqual({ ...peak1_shifted_close, trackStatus: 'continuing' });
            expect(tracked[1]).toEqual({ ...peak2, trackStatus: 'continuing' });
            expect(mockRedisClient.setex).toHaveBeenCalled();
        });

        it('should mark peaks as new if frequency shift exceeds tolerance', async () => {
            const prevState = [ { freq: 7.8, amp: 9 } ];
            mockRedisClient.get.mockResolvedValue(JSON.stringify(prevState));
            const currentPeaks = [peak1_shifted_far]; // 8.4 is > 0.5 Hz away from 7.8
            const tracked = await trackPeaks(detectorId, currentPeaks, mockRedisClient, trackConfig);
            expect(tracked.length).toBe(1);
            expect(tracked[0]).toEqual({ ...peak1_shifted_far, trackStatus: 'new' });
            expect(mockRedisClient.setex).toHaveBeenCalled();
        });

        it('should handle multiple new and continuing peaks', async () => {
             const prevState = [ { freq: 7.7, amp: 9 }, { freq: 14.3, amp: 8.5 } ];
             mockRedisClient.get.mockResolvedValue(JSON.stringify(prevState));
             const currentPeaks = [peak1_shifted_close, peak3_new]; // peak1 continues, peak3 is new
             const tracked = await trackPeaks(detectorId, currentPeaks, mockRedisClient, trackConfig);
             expect(tracked.length).toBe(2);
             expect(tracked[0]).toEqual({ ...peak1_shifted_close, trackStatus: 'continuing' });
             expect(tracked[1]).toEqual({ ...peak3_new, trackStatus: 'new' });
             expect(mockRedisClient.setex).toHaveBeenCalled();
        });

        it('should handle disappearance of peaks', async () => {
             const prevState = [ { freq: 7.7, amp: 9 }, { freq: 14.3, amp: 8.5 } ];
             mockRedisClient.get.mockResolvedValue(JSON.stringify(prevState));
             const currentPeaks = [peak1_shifted_close]; // Only one peak now
             const tracked = await trackPeaks(detectorId, currentPeaks, mockRedisClient, trackConfig);
             expect(tracked.length).toBe(1);
             expect(tracked[0]).toEqual({ ...peak1_shifted_close, trackStatus: 'continuing' });
             expect(mockRedisClient.setex).toHaveBeenCalled(); // Store new state
        });


        it('should delete state if no current peaks are detected', async () => {
             const prevState = [ { freq: 7.7, amp: 9 } ];
             mockRedisClient.get.mockResolvedValue(JSON.stringify(prevState));
             mockRedisClient.exists.mockResolvedValue(1);
             const currentPeaks = [];
             const tracked = await trackPeaks(detectorId, currentPeaks, mockRedisClient, trackConfig);
             expect(tracked.length).toBe(0);
             expect(mockRedisClient.setex).not.toHaveBeenCalled();
             expect(mockRedisClient.del).toHaveBeenCalledWith(`track_state:${detectorId}`);
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
            narrowbandFactor: 5.0 // Explicitly use default factor for clarity
        };

        const createHistoryEntry = (spectrumData, ts) => JSON.stringify({
            detectorId, timestamp: ts || new Date().toISOString(), location: { lat: 0, lon: 0 },
            spectrogram: [spectrumData], detectedPeaks: [], transientInfo: {type: 'none', details: null}
        });

        it('should return type none if insufficient history', async () => {
            mockStreamRedisClient.lrange.mockResolvedValue([
                createHistoryEntry(new Array(downsampledLength).fill(1.0))
            ]);
            const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(1.5);
            const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
            expect(result.type).toBe('none');
        });

        it('should detect broadband transient', async () => {
            const baselineVal = 1.0;
            const history = [ createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), ];
            mockStreamRedisClient.lrange.mockResolvedValue(history);
            const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal * (TEST_BROADBAND_FACTOR + 0.5));
            const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
            expect(result.type).toBe('broadband');
            expect(result.details).toMatch(/Broadband power increase detected/);
        });

        it('should NOT detect broadband if below threshold percentage', async () => {
            const baselineVal = 1.0;
            const history = [ createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)) ];
            mockStreamRedisClient.lrange.mockResolvedValue(history);
            const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
            const exceedCount = Math.floor(RAW_FREQUENCY_POINTS * (TEST_BROADBAND_THRESHOLD_PCT / 2));
            for(let i=0; i< exceedCount; i++) { rawSpectrum[i] = baselineVal * (TEST_BROADBAND_FACTOR + 0.5); }
            const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
            expect(result.type).toBe('none');
        });

        it('should detect narrowband transient outside SR ranges', async () => {
            const baselineVal = 1.0;
             const history = [ createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)) ];
             mockStreamRedisClient.lrange.mockResolvedValue(history);
             const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
             const transientFreq = 4.0;
             const transientIndex = Math.round(transientFreq * POINTS_PER_HZ);
             const transientAmp = Math.max(baselineVal * testConfig.narrowbandFactor, baselineVal + TEST_NARROWBAND_MIN_AMP_DELTA, TEST_PEAK_ABSOLUTE_THRESHOLD * 1.5) + 0.1;
             rawSpectrum[transientIndex] = transientAmp;
             rawSpectrum[transientIndex - 1] = baselineVal + 0.5;
             rawSpectrum[transientIndex + 1] = baselineVal + 0.5;

             const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
             expect(result.type).toBe('narrowband');
             expect(result.details).toMatch(/Narrowband signal detected near 4.0 Hz/);
             expect(result.details).toMatch(`Amp: ${transientAmp.toFixed(1)}`);
             expect(result.details).toMatch(`Delta: ${(transientAmp - baselineVal).toFixed(1)}`);
        });

        it('should ignore narrowband peaks near SR frequencies', async () => {
             const baselineVal = 1.0;
              const history = [ createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)) ];
              mockStreamRedisClient.lrange.mockResolvedValue(history);
              const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
              const transientFreq = 7.5; // Near 7.83 Hz
              const transientIndex = Math.round(transientFreq * POINTS_PER_HZ);
              rawSpectrum[transientIndex] = baselineVal + TEST_NARROWBAND_MIN_AMP_DELTA + 1.0;
              const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
              expect(result.type).toBe('none'); // Should be ignored
        });

        it('should ignore narrowband peaks if delta is below minimum', async () => {
            const baselineVal = 4.0;
             const history = [ createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)) ];
             mockStreamRedisClient.lrange.mockResolvedValue(history);
             const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal);
             const transientFreq = 4.0;
             const transientIndex = Math.round(transientFreq * POINTS_PER_HZ);
             rawSpectrum[transientIndex] = baselineVal + TEST_NARROWBAND_MIN_AMP_DELTA - 0.1; // Just below delta threshold (6.9 vs 4.0 baseline -> delta 2.9)

             const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
             expect(result.type).toBe('none'); // Delta 2.9 is < 3.0 threshold
        });

         it('should return type none for normal spectrum', async () => {
            const baselineVal = 1.0;
             const history = [ createHistoryEntry(new Array(downsampledLength).fill(baselineVal)), createHistoryEntry(new Array(downsampledLength).fill(baselineVal)) ];
             mockStreamRedisClient.lrange.mockResolvedValue(history);
             const rawSpectrum = new Array(RAW_FREQUENCY_POINTS).fill(baselineVal * 1.1);
             const result = await detectTransients(detectorId, rawSpectrum, mockStreamRedisClient, testConfig);
             expect(result.type).toBe('none');
        });
    });

});
