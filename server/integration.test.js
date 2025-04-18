// server/integration.test.js
const axios = require('axios');
const WebSocket = require('ws');
const Redis = require('ioredis');
// const jwt = require('jsonwebtoken'); // Removed unused import
const CryptoJS = require('crypto-js');
const { Pool } = require('pg'); // Import pg Pool

// Use constants where applicable (ensure constants.js is created first if used)
// Example: const { RAW_FREQUENCY_POINTS, DOWNSAMPLE_FACTOR } = require('./config/constants');
// Using hardcoded or env vars for now as constants file might not exist yet
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
const WS_URL = process.env.WS_URL || 'ws://localhost:3000';
// const JWT_SECRET = process.env.JWT_SECRET || '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p'; // Removed unused variable
const API_INGEST_KEY = process.env.API_INGEST_KEY || 'changeme-in-production';
const TEST_TIMEOUT = parseInt(process.env.JEST_TIMEOUT || '45000', 10);
const WS_MESSAGE_TIMEOUT = 30000;
const DOWNSAMPLE_FACTOR = parseInt(process.env.DOWNSAMPLE_FACTOR || '5');
const RAW_FREQUENCY_POINTS = 5501; // Or import from constants
const EXPECTED_DOWNSAMPLED_LENGTH = Math.ceil(RAW_FREQUENCY_POINTS / DOWNSAMPLE_FACTOR);
const REDIS_SPEC_RETENTION_MS =
  (parseFloat(process.env.REDIS_SPEC_RETENTION_HOURS) || 0.01) * 3600 * 1000;
const REDIS_PEAK_RETENTION_MS =
  (parseFloat(process.env.REDIS_PEAK_RETENTION_HOURS) || 0.02) * 3600 * 1000;

// Test-specific connection timeout
const TEST_REDIS_CONNECT_TIMEOUT = 10000; // 10 seconds

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Redis clients with increased test timeout
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD || 'password',
  lazyConnect: true,
  keyPrefix: 'userkey:', // Consistent with server config
  retryStrategy: (times) => Math.min(times * 150, 3000),
  reconnectOnError: () => true,
  maxRetriesPerRequest: 3,
  connectTimeout: TEST_REDIS_CONNECT_TIMEOUT,
});
const streamRedis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD || 'password',
  lazyConnect: true,
  retryStrategy: (times) => Math.min(times * 150, 3000),
  reconnectOnError: () => true,
  maxRetriesPerRequest: 3,
  connectTimeout: TEST_REDIS_CONNECT_TIMEOUT,
});

// PostgreSQL client pool for tests
const dbPool = new Pool({
  user: process.env.DB_USER || 'user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'earthsync',
  password: process.env.DB_PASSWORD || 'password',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  max: 5, // Smaller pool for tests
  idleTimeoutMillis: 5000,
  connectionTimeoutMillis: 5000,
});

describe('EarthSync Integration Tests (v1.1.16 - Structured History)', () => {
  let authToken;
  let encryptionKey;
  const testUser = 'ci_testuser_hist_struct';
  const testPassword = 'ci_password123';
  const testDetectorId = 'ci_detector_hist_struct';
  const specHistKey = `spectrogram_history:${testDetectorId}`; // Use prefix from constants if available
  const peakHistKey = `peaks:${testDetectorId}`; // Use prefix from constants if available
  let setupError = null; // Flag to indicate setup failure

  jest.setTimeout(TEST_TIMEOUT);

  // --- Setup and Teardown ---
  beforeAll(async () => {
    setupError = null; // Reset error flag
    let dbClient = null; // Initialize to null
    try {
      console.log('Connecting Redis & DB for tests...');
      await sleep(2000);

      // Connect Redis clients
      await Promise.all([redis.connect(), streamRedis.connect()]);
      // Ping to verify connection
      await Promise.all([redis.ping(), streamRedis.ping()]);

      // Test DB connection
      dbClient = await dbPool.connect();
      await dbClient.query('SELECT 1');
      dbClient.release(); // Release client immediately after check
      dbClient = null; // Nullify to indicate it's released
      console.log('Redis & DB connections successful.');

      console.log('Cleaning up previous test data...');
      // Use correct prefix for user keys
      const userKeys = await redis.keys(`${testUser}`); // No prefix needed, client adds it
      if (userKeys.length > 0) await redis.del(userKeys);
      // Use streamRedis (no prefix) for stream/history keys
      const dataKeys = await streamRedis.keys(`*${testDetectorId}*`);
      if (dataKeys.length > 0) await streamRedis.del(dataKeys);
      // Use main redis (no prefix) for tracking state keys (assuming trackPeaks uses main client)
      // Confirm where trackPeaks stores state if changed from original Redis setup
      const trackStateKey = `track_state:${testDetectorId}`; // Use constant if defined
      await redis.del(trackStateKey);

      // Clear DB tables for the test detector/user
      await dbPool.query(`DELETE FROM historical_spectrograms WHERE detector_id = $1`, [
        testDetectorId,
      ]);
      await dbPool.query(`DELETE FROM historical_peaks WHERE detector_id = $1`, [testDetectorId]);
      await dbPool.query(`DELETE FROM peak_tracking_state WHERE detector_id = $1`, [
        testDetectorId,
      ]); // Clean tracking state table too
      await dbPool.query(`DELETE FROM users WHERE username = $1`, [testUser]);

      console.log('Previous test data cleaned.');

      // Register test user
      console.log('Registering test user...');
      await axios.post(`${API_BASE_URL}/register`, { username: testUser, password: testPassword });
      console.log('Test user registered.');
    } catch (err) {
      setupError = `Setup failed: ${err.message}\n${err.stack || ''}`; // Store error message and stack
      console.error(setupError);
      // Attempt cleanup even on failure
      if (dbClient) {
        try {
          dbClient.release();
        } catch {
          /* ignore */
        }
      }
      // Don't end pool/quit redis here, let afterAll handle it based on status
      throw new Error(setupError); // Make Jest aware setup failed
    }
  });

  afterAll(async () => {
    try {
      console.log('Cleaning up test resources after all tests...');
      // Clean up DB first
      await dbPool.query(`DELETE FROM historical_spectrograms WHERE detector_id = $1`, [
        testDetectorId,
      ]);
      await dbPool.query(`DELETE FROM historical_peaks WHERE detector_id = $1`, [testDetectorId]);
      await dbPool.query(`DELETE FROM peak_tracking_state WHERE detector_id = $1`, [
        testDetectorId,
      ]);
      await dbPool.query(`DELETE FROM users WHERE username = $1`, [testUser]);
      console.log('Test data cleaned from DB.');
      // Clean up Redis
      const userKeys = await redis.keys(`${testUser}`); // Client handles prefix
      if (userKeys.length > 0) await redis.del(userKeys);
      const dataKeys = await streamRedis.keys(`*${testDetectorId}*`); // No prefix
      if (dataKeys.length > 0) await streamRedis.del(dataKeys);
      const trackStateKey = `track_state:${testDetectorId}`; // Use constant if defined
      await redis.del(trackStateKey); // Uses main client
      console.log('Test data cleaned from Redis.');
    } catch (err) {
      console.warn('Test cleanup failed:', err.message);
    } finally {
      // Ensure connections are closed, checking status first
      if (redis.status === 'ready' || redis.status === 'connecting') {
        await redis.quit().catch(() => {});
      }
      if (streamRedis.status === 'ready' || streamRedis.status === 'connecting') {
        await streamRedis.quit().catch(() => {});
      }
      await dbPool.end().catch(() => {}); // End pool gracefully
      console.log('Redis & DB connections closed after tests.');
    }
  });

  // Helper to skip tests if setup failed
  const runIfSetupOK = (testName, testFn) => {
    if (setupError) {
      test.skip(`${testName} (skipped due to setup failure: ${setupError.split('\n')[0]})`, () => {});
    } else {
      test(testName, testFn);
    }
  };

  // --- Basic Auth & Setup Tests ---
  runIfSetupOK('GET /health should return 200 OK with dependencies OK', async () => {
    const response = await axios.get(`${API_BASE_URL}/health`);
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('OK');
    expect(response.data.redis_main).toBe('OK');
    expect(response.data.redis_stream).toBe('OK');
    expect(response.data.postgres).toBe('OK');
  });

  runIfSetupOK('POST /login returns JWT for registered user', async () => {
    const response = await axios.post(`${API_BASE_URL}/login`, {
      username: testUser,
      password: testPassword,
    });
    expect(response.status).toBe(200);
    expect(response.data.token).toBeDefined();
    expect(typeof response.data.token).toBe('string');
    authToken = response.data.token; // Store for subsequent tests
  });

  runIfSetupOK('POST /key-exchange returns key and stores it in Redis', async () => {
    expect(authToken).toBeDefined(); // Ensure login succeeded
    const response = await axios.post(
      `${API_BASE_URL}/key-exchange`,
      {},
      {
        headers: { Authorization: `Bearer ${authToken}` },
      }
    );
    expect(response.status).toBe(200);
    expect(response.data.key).toMatch(/^[a-f0-9]{64}$/); // Check key format (64 hex chars)
    encryptionKey = response.data.key;

    // Verify key storage in Redis (client handles prefix)
    const storedKey = await redis.get(`${testUser}`);
    expect(storedKey).toBe(encryptionKey);
  });

  // --- Data Ingest & WS Tests ---
  runIfSetupOK('POST /data-ingest accepts valid batch and adds to stream', async () => {
    const ingestDetectorId = `${testDetectorId}_ingest`; // Use specific ID for this test
    const payload = {
      detectorId: ingestDetectorId,
      location: { lat: 1.23, lon: -4.56 },
      // Batch of 2 raw spectrograms
      spectrograms: [Array(RAW_FREQUENCY_POINTS).fill(1.0), Array(RAW_FREQUENCY_POINTS).fill(2.0)],
    };
    const headers = { 'X-API-Key': API_INGEST_KEY };

    const response = await axios.post(`${API_BASE_URL}/data-ingest`, payload, { headers });
    expect(response.status).toBe(202); // Check for Accepted status
    expect(response.data.messageId).toMatch(/^\d+-\d+$/); // Check format of Redis stream ID

    await sleep(500); // Allow time for stream processing (might need adjustment)

    // Verify message in Redis stream (use streamRedis)
    const streamMessages = await streamRedis.xrevrange('spectrogram_stream', '+', '-', 'COUNT', 5); // Read last 5
    expect(streamMessages.length).toBeGreaterThan(0);

    // Find the specific message we ingested
    const targetMessage = streamMessages.find((msg) => {
      try {
        const data = JSON.parse(msg[1][1]); // data is at index 1 of the field array
        return data.detectorId === ingestDetectorId;
      } catch {
        return false;
      }
    });
    expect(targetMessage).toBeDefined(); // Ensure the message was found

    // Verify the content of the message in the stream
    const streamData = JSON.parse(targetMessage[1][1]);
    expect(streamData.detectorId).toBe(ingestDetectorId);
    expect(streamData.location).toEqual(payload.location);
    expect(streamData.spectrogram.length).toBe(2); // Raw batch size should be stored
    expect(streamData.spectrogram[0].length).toBe(RAW_FREQUENCY_POINTS);
    expect(streamData.spectrogram[1].length).toBe(RAW_FREQUENCY_POINTS);
    expect(streamData.interval).toBe(0); // Indicates API ingest
  });

  runIfSetupOK('WebSocket receives processed data including peaks and transients', async () => {
    expect(authToken).toBeDefined();
    expect(encryptionKey).toBeDefined();
    const wsDetectorId = `${testDetectorId}_ws`; // Specific ID for this test
    const ws = new WebSocket(`${WS_URL}/?token=${authToken}`);
    let receivedTargetMessage = false;
    let decryptedData = null;
    let wsError = null;
    let wsClosedCode = null;
    let closeReason = '';

    // Promise to handle WebSocket message reception or timeout/error
    const messagePromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (!receivedTargetMessage) {
          ws.terminate(); // Close immediately on timeout
          reject(
            new Error(
              `WebSocket target message timeout after ${WS_MESSAGE_TIMEOUT}ms (State: ${ws.readyState})`
            )
          );
        }
        // If message was received, timeout is cleared, promise already resolved
      }, WS_MESSAGE_TIMEOUT);

      ws.on('message', (data) => {
        try {
          const messageString = data.toString('utf8');
          const [encrypted, iv] = messageString.split(':');
          if (!encrypted || !iv) throw new Error('Invalid WS message format (missing separator)');

          const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
          const ivWordArray = CryptoJS.enc.Base64.parse(iv);
          const decryptedBytes = CryptoJS.AES.decrypt(
            { ciphertext: CryptoJS.enc.Base64.parse(encrypted) },
            keyWordArray,
            { iv: ivWordArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
          );
          const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
          if (!decryptedText) throw new Error('Decryption resulted in empty message');

          const messageData = JSON.parse(decryptedText);

          // Check if this message is for the detector ID we are testing
          if (messageData.detectorId === wsDetectorId) {
            console.log(`Received target WS message for ${wsDetectorId}`);
            receivedTargetMessage = true;
            decryptedData = messageData; // Store the relevant data
            clearTimeout(timeout); // Cancel the timeout
            ws.close(1000, 'Test complete'); // Close connection normally
            resolve(); // Resolve the promise successfully
          } else {
            // Ignore messages from other detectors potentially running
            console.log(`Ignoring WS message from other detector: ${messageData.detectorId}`);
          }
        } catch (err) {
          console.error('WebSocket message processing error:', err);
          clearTimeout(timeout); // Clear timeout on error too
          ws.close(1011, 'Message processing error'); // Close with error code
          reject(err); // Reject the promise on processing error
        }
      });

      ws.on('error', (err) => {
        clearTimeout(timeout);
        wsError = err;
        console.error('WebSocket connection error event:', err);
        reject(err); // Reject promise on connection error
      });

      ws.on('close', (code, reason) => {
        wsClosedCode = code;
        closeReason = reason.toString();
        console.log(`WebSocket connection closed event: Code=${code}, Reason="${closeReason}"`); // Log close event always
        // Reject only if closed unexpectedly *before* target message received and not already rejected
        if (code !== 1000 && code !== 1005 && !receivedTargetMessage && !wsError) {
          clearTimeout(timeout); // Ensure timeout is cleared
          reject(
            new Error(
              `WS closed unexpectedly (${code} - ${closeReason}) before target message received.`
            )
          );
        }
      });
    }); // End of messagePromise definition

    // Establish WebSocket connection
    await new Promise((resolve, reject) => {
      const connTimeout = setTimeout(
        () => reject(new Error('WebSocket connection attempt timed out')),
        5000
      );
      ws.once('open', () => {
        clearTimeout(connTimeout);
        console.log('WebSocket connected for peak/transient test.');
        resolve();
      });
      ws.once('error', (err) => {
        clearTimeout(connTimeout);
        reject(err);
      }); // Handle error during initial connection
    });
    await sleep(300); // Small pause after connection established

    // Prepare and ingest data designed to trigger peak and transient detection
    const rawSpectrogramWithPeak = Array(RAW_FREQUENCY_POINTS).fill(1.0);
    // Create a noticeable peak around 10 Hz
    const peakFreqHz = 10.0;
    const peakIndex = Math.round((peakFreqHz * (RAW_FREQUENCY_POINTS - 1)) / 55); // Calculate index based on Hz
    rawSpectrogramWithPeak[peakIndex - 2] = 3.0;
    rawSpectrogramWithPeak[peakIndex - 1] = 8.0;
    rawSpectrogramWithPeak[peakIndex] = 20.0; // Peak amplitude
    rawSpectrogramWithPeak[peakIndex + 1] = 7.0;
    rawSpectrogramWithPeak[peakIndex + 2] = 2.5;
    // Also add a small narrowband transient away from SR freqs (e.g., 4Hz)
    const transientFreqHz = 4.0;
    const transientIndex = Math.round((transientFreqHz * (RAW_FREQUENCY_POINTS - 1)) / 55);
    rawSpectrogramWithPeak[transientIndex] = 6.0; // Amplitude likely above baseline*factor + delta

    const ingestPayload = {
      detectorId: wsDetectorId,
      location: { lat: 45, lon: 45 },
      spectrograms: [rawSpectrogramWithPeak], // Send single spectrum batch
    };
    const peakKeyWs = `peaks:${wsDetectorId}`; // Use constant if defined
    await streamRedis.del(peakKeyWs); // Clear previous peak history for this detector

    await axios.post(`${API_BASE_URL}/data-ingest`, ingestPayload, {
      headers: { 'X-API-Key': API_INGEST_KEY },
    });
    console.log(`Test message ingested for ${wsDetectorId}. Waiting for WS response...`);

    // Wait for the WebSocket message promise to resolve or reject
    try {
      await messagePromise;
    } catch (e) {
      // Log details if promise rejected
      console.error('WebSocket test failed. Error:', e.message);
      console.error('WebSocket Error Object:', wsError);
      console.error('WebSocket Closed Code/Reason:', wsClosedCode, closeReason);
      throw e; // Re-throw error to fail the test
    }

    // --- Assertions on the received and decrypted data ---
    expect(receivedTargetMessage).toBe(true);
    expect(decryptedData).toBeDefined();
    expect(decryptedData.detectorId).toBe(wsDetectorId);
    expect(Array.isArray(decryptedData.spectrogram)).toBe(true);
    expect(decryptedData.spectrogram.length).toBe(1); // WS message contains only the first processed spectrum
    expect(decryptedData.spectrogram[0].length).toBe(EXPECTED_DOWNSAMPLED_LENGTH);

    // Check detected peaks
    expect(Array.isArray(decryptedData.detectedPeaks)).toBe(true);
    expect(decryptedData.detectedPeaks.length).toBeGreaterThanOrEqual(1); // Expect at least the 10Hz peak
    const detectedPeak = decryptedData.detectedPeaks.find(
      (p) => Math.abs(p.freq - peakFreqHz) < 1.0
    );
    expect(detectedPeak).toBeDefined();
    if (!detectedPeak) {
      console.error(
        `Expected peak near ${peakFreqHz.toFixed(2)}Hz not found in ${JSON.stringify(decryptedData.detectedPeaks)}`
      );
    } else {
      expect(detectedPeak.amp).toBeCloseTo(20.0, 0); // Check amplitude (should be close to original max)
      expect(detectedPeak.qFactor).toBeGreaterThan(1); // Expect a reasonable Q-factor
      expect(detectedPeak.trackStatus).toBeDefined(); // Check trackStatus exists
      expect(detectedPeak.trackId).toBeDefined(); // Check trackId exists
    }

    // Check transient info
    expect(decryptedData.transientInfo).toBeDefined();
    expect(decryptedData.transientInfo.type).toBe('narrowband'); // Expect narrowband due to the 4Hz peak
    expect(decryptedData.transientInfo.details).toMatch(/near 4.0 Hz/); // Check details match

    console.log('Received WS Peaks:', JSON.stringify(decryptedData.detectedPeaks));
    console.log('Received WS TransientInfo:', JSON.stringify(decryptedData.transientInfo));

    // --- Verify peak was stored in Redis history (ZSET) ---
    const storedPeaks = await streamRedis.zrange(peakKeyWs, 0, -1); // Get all members
    expect(storedPeaks.length).toBeGreaterThan(0); // Expect at least one entry for this spectrum
    // Parse the most recent entry (assuming test runs quickly)
    const storedPeakDataArray = JSON.parse(storedPeaks[storedPeaks.length - 1]);
    expect(Array.isArray(storedPeakDataArray)).toBe(true);
    const storedMainPeak = storedPeakDataArray.find((p) => Math.abs(p.freq - peakFreqHz) < 1.0);
    expect(storedMainPeak).toBeDefined(); // Verify the 10Hz peak was stored
    expect(storedMainPeak.trackStatus).toBeDefined();
    expect(storedMainPeak.trackId).toBeDefined();

    // Clean up specific key used in this test
    await streamRedis.del(peakKeyWs);
  });

  // --- UPDATED History Tests ---
  describe('Combined History API (Structured Response)', () => {
    const now = Date.now();
    // Timestamps relative to retention boundaries
    const recentTimeMs = now - REDIS_SPEC_RETENTION_MS / 2; // Within Redis spectrogram retention
    const oldTimeMs = now - REDIS_SPEC_RETENTION_MS * 1.5; // Older than Redis spec retention, within peak retention
    const ancientTimeMs = now - REDIS_PEAK_RETENTION_MS * 1.5; // Older than Redis peak retention

    const recentTimestampISO = new Date(recentTimeMs).toISOString();
    const oldTimestampISO = new Date(oldTimeMs).toISOString();
    const ancientTimestampISO = new Date(ancientTimeMs).toISOString(); // Used for ancient peak test
    // const ancientTimestamp = ancientTimestampISO; // Removed unused variable

    // --- Data for Seeding ---
    // Data for seeding Redis list (processed structure)
    const recentSpecRedisData = {
      detectorId: testDetectorId,
      timestamp: recentTimestampISO,
      location: { lat: 10, lon: 10 },
      spectrogram: [new Array(EXPECTED_DOWNSAMPLED_LENGTH).fill(5.5)], // Single downsampled row in nested array
      processingResults: [
        {
          // Results corresponding to the single spectrum
          detectedPeaks: [
            { freq: 7.8, amp: 15, qFactor: 4, trackStatus: 'continuing', trackId: 'uuid-recent-1' },
          ],
          transientInfo: { type: 'none', details: null },
        },
      ],
    };
    // Data for seeding DB (spectrogram table)
    const oldSpecDbData = {
      detector_id: testDetectorId,
      timestamp: oldTimestampISO, // Stored as TIMESTAMPTZ
      location_lat: 10,
      location_lon: 10,
      // DB stores the single downsampled spectrum directly (assuming archiver does this)
      spectrogram_data: new Array(EXPECTED_DOWNSAMPLED_LENGTH).fill(3.3),
      transient_detected: true,
      transient_details: 'DB Test Broadband Details',
    };
    // Peak data for Redis ZSET (associated with recentSpecRedisData)
    const recentPeakData = [
      { freq: 7.8, amp: 15, qFactor: 4, trackStatus: 'continuing', trackId: 'uuid-recent-1' },
    ];
    // Peak data for DB (associated with oldSpecDbData time)
    const oldPeakData = [
      { freq: 14.1, amp: 10, qFactor: 5, trackStatus: 'new', trackId: 'uuid-old-1' },
    ];
    // Ancient peak data for DB (outside peak retention)
    const ancientPeakData = [
      { freq: 20.5, amp: 5, qFactor: 6, trackStatus: 'new', trackId: 'uuid-ancient-1' },
    ];

    beforeAll(async () => {
      if (setupError) return; // Skip seeding if setup failed
      console.log('Seeding history data for combined API tests...');
      // Seed recent data into Redis list (spectrogram history)
      await streamRedis.lpush(specHistKey, JSON.stringify(recentSpecRedisData));
      // Seed recent peak data into Redis sorted set
      await streamRedis.zadd(peakHistKey, recentTimeMs, JSON.stringify(recentPeakData));
      // Seed old spectrogram data into DB
      await dbPool.query(
        `INSERT INTO historical_spectrograms (detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          oldSpecDbData.detector_id,
          oldSpecDbData.timestamp,
          oldSpecDbData.location_lat,
          oldSpecDbData.location_lon,
          JSON.stringify(oldSpecDbData.spectrogram_data), // Store as JSON array
          oldSpecDbData.transient_detected,
          oldSpecDbData.transient_details,
        ]
      );
      // Seed old peak data into DB
      await dbPool.query(
        `INSERT INTO historical_peaks (detector_id, "timestamp", peak_data) VALUES ($1, $2, $3)`,
        [testDetectorId, oldTimestampISO, JSON.stringify(oldPeakData)]
      );
      // Seed ancient peak data into DB
      await dbPool.query(
        `INSERT INTO historical_peaks (detector_id, "timestamp", peak_data) VALUES ($1, $2, $3)`,
        [testDetectorId, ancientTimestampISO, JSON.stringify(ancientPeakData)]
      );
      console.log('History data seeded.');
      // Ensure auth token is available
      if (!authToken) {
        const response = await axios.post(`${API_BASE_URL}/login`, {
          username: testUser,
          password: testPassword,
        });
        authToken = response.data.token;
      }
      expect(authToken).toBeDefined();
    });

    runIfSetupOK(
      'GET /history/range should return structured spectrogram data from Redis and DB',
      async () => {
        const queryStartTimeISO = new Date(oldTimeMs - 1000).toISOString(); // Start slightly before old DB data
        const queryEndTimeISO = new Date(recentTimeMs + 1000).toISOString(); // End slightly after recent Redis data

        const response = await axios.get(`${API_BASE_URL}/history/range`, {
          params: {
            startTime: queryStartTimeISO,
            endTime: queryEndTimeISO,
            detectorId: testDetectorId,
          },
          headers: { Authorization: `Bearer ${authToken}` },
        });

        expect(response.status).toBe(200);
        expect(Array.isArray(response.data)).toBe(true);
        // Expect one entry in the outer array, grouping by detectorId
        expect(response.data.length).toBe(1);
        const detectorData = response.data[0];
        expect(detectorData.detectorId).toBe(testDetectorId);
        expect(detectorData.location).toEqual({ lat: 10, lon: 10 }); // Check location consistency
        expect(Array.isArray(detectorData.dataPoints)).toBe(true);
        // Expecting two data points: one from DB (old), one from Redis (recent)
        expect(detectorData.dataPoints.length).toBe(2);

        // Verify data points (sorted chronologically by fetch function)
        const dbPoint = detectorData.dataPoints[0]; // Oldest should be first
        const redisPoint = detectorData.dataPoints[1]; // Newest should be second

        // Check DB data point
        expect(dbPoint.ts).toBeCloseTo(oldTimeMs, -2); // Check timestamp (ms precision)
        expect(Array.isArray(dbPoint.spectrogram)).toBe(true);
        expect(dbPoint.spectrogram.length).toBe(EXPECTED_DOWNSAMPLED_LENGTH);
        expect(dbPoint.spectrogram[0]).toBeCloseTo(3.3); // Check content value
        expect(dbPoint.transientInfo.type).toBe('broadband'); // Should derive 'broadband'
        expect(dbPoint.transientInfo.details).toBe('DB Test Broadband Details');

        // Check Redis data point
        expect(redisPoint.ts).toBeCloseTo(recentTimeMs, -2); // Check timestamp
        expect(Array.isArray(redisPoint.spectrogram)).toBe(true);
        expect(redisPoint.spectrogram.length).toBe(EXPECTED_DOWNSAMPLED_LENGTH);
        expect(redisPoint.spectrogram[0]).toBeCloseTo(5.5); // Check content value
        expect(redisPoint.transientInfo.type).toBe('none'); // Check transient info from Redis record
      }
    );

    runIfSetupOK(
      'GET /history/peaks/range should return combined peaks from Redis and DB',
      async () => {
        const queryStartTimeISO = new Date(ancientTimeMs - 1000).toISOString(); // Start before ancient peak
        const queryEndTimeISO = new Date(recentTimeMs + 1000).toISOString(); // End after recent peak

        const response = await axios.get(`${API_BASE_URL}/history/peaks/range`, {
          params: {
            startTime: queryStartTimeISO,
            endTime: queryEndTimeISO,
            detectorId: testDetectorId,
          },
          headers: { Authorization: `Bearer ${authToken}` },
        });

        expect(response.status).toBe(200);
        expect(Array.isArray(response.data)).toBe(true);
        // Expect one entry in the outer array for the detector
        expect(response.data.length).toBe(1);
        const detectorHistory = response.data[0];
        expect(detectorHistory.detectorId).toBe(testDetectorId);
        expect(Array.isArray(detectorHistory.peaks)).toBe(true);
        // Expecting 3 peak entries: ancient (DB), old (DB), recent (Redis)
        expect(detectorHistory.peaks.length).toBe(3);

        // Verify entries are sorted by timestamp and contain correct peak data
        expect(detectorHistory.peaks[0].ts).toBeCloseTo(ancientTimeMs, -2);
        expect(detectorHistory.peaks[0].peaks[0].freq).toBe(ancientPeakData[0].freq);
        expect(detectorHistory.peaks[0].peaks[0].trackId).toBe(ancientPeakData[0].trackId); // Check trackId consistency

        expect(detectorHistory.peaks[1].ts).toBeCloseTo(oldTimeMs, -2);
        expect(detectorHistory.peaks[1].peaks[0].freq).toBe(oldPeakData[0].freq);
        expect(detectorHistory.peaks[1].peaks[0].trackStatus).toBe(oldPeakData[0].trackStatus); // Check trackStatus

        expect(detectorHistory.peaks[2].ts).toBeCloseTo(recentTimeMs, -2);
        expect(detectorHistory.peaks[2].peaks[0].freq).toBe(recentPeakData[0].freq);
        expect(detectorHistory.peaks[2].peaks[0].trackStatus).toBeDefined(); // Ensure trackStatus from Redis is included
        expect(detectorHistory.peaks[2].peaks[0].trackId).toBeDefined(); // Ensure trackId from Redis is included
      }
    );

    runIfSetupOK(
      'GET /history/peaks/hours/:hours should return only recent (Redis) peak data if within retention',
      async () => {
        // Query for a duration shorter than the peak retention but longer than spectrogram retention
        const hoursToQuery = Math.ceil((REDIS_PEAK_RETENTION_MS / (3600 * 1000)) * 0.8); // e.g., 80% of peak retention

        const response = await axios.get(`${API_BASE_URL}/history/peaks/hours/${hoursToQuery}`, {
          params: { detectorId: testDetectorId }, // Filter by detector
          headers: { Authorization: `Bearer ${authToken}` },
        });

        expect(response.status).toBe(200);
        expect(response.data.length).toBe(1); // Only data for the specified detector
        const detectorHistory = response.data[0];
        expect(detectorHistory.detectorId).toBe(testDetectorId);
        expect(detectorHistory.peaks.length).toBe(1); // Should *only* contain the recent Redis peak
        expect(detectorHistory.peaks[0].ts).toBeCloseTo(recentTimeMs, -2);
        expect(detectorHistory.peaks[0].peaks[0].freq).toBe(recentPeakData[0].freq);
      }
    );
  }); // End describe block for History API tests
}); // End describe block for all Integration Tests
