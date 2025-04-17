// server/integration.test.js
const axios = require('axios');
const WebSocket = require('ws');
const Redis = require('ioredis');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const { Pool } = require('pg'); // Import pg Pool

const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000';
const WS_URL = process.env.WS_URL || 'ws://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET || '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p';
const API_INGEST_KEY = process.env.API_INGEST_KEY || 'changeme-in-production';
const TEST_TIMEOUT = parseInt(process.env.JEST_TIMEOUT || '45000', 10); // Increased timeout
const WS_MESSAGE_TIMEOUT = 30000; // Increased WS timeout slightly more
const DOWNSAMPLE_FACTOR = 5;
const RAW_FREQUENCY_POINTS = 5501;
const EXPECTED_DOWNSAMPLED_LENGTH = Math.ceil(RAW_FREQUENCY_POINTS / DOWNSAMPLE_FACTOR);
// Get retention from env (used for calculating timestamps relative to boundary)
const REDIS_SPEC_RETENTION_MS = (parseFloat(process.env.REDIS_SPEC_RETENTION_HOURS) || 0.01) * 3600 * 1000;
const REDIS_PEAK_RETENTION_MS = (parseFloat(process.env.REDIS_PEAK_RETENTION_HOURS) || 0.02) * 3600 * 1000;

// Test-specific connection timeout
const TEST_REDIS_CONNECT_TIMEOUT = 10000; // 10 seconds

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// Redis clients with increased test timeout
const redis = new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || 'password',
    lazyConnect: true,
    keyPrefix: 'userkey:',
    retryStrategy: times => Math.min(times * 150, 3000), // Slightly slower retry
    reconnectOnError: () => true,
    maxRetriesPerRequest: 3,
    connectTimeout: TEST_REDIS_CONNECT_TIMEOUT // Explicit timeout for tests
});
const streamRedis = new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || 'password',
    lazyConnect: true,
    retryStrategy: times => Math.min(times * 150, 3000),
    reconnectOnError: () => true,
    maxRetriesPerRequest: 3,
    connectTimeout: TEST_REDIS_CONNECT_TIMEOUT // Explicit timeout for tests
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
    connectionTimeoutMillis: 5000 // Increased DB connect timeout slightly
});


describe('EarthSync Integration Tests (v1.1.15 - History Routes)', () => {
    let authToken;
    let encryptionKey;
    const testUser = 'ci_testuser_hist';
    const testPassword = 'ci_password123';
    const testDetectorId = 'ci_detector_hist';
    const specHistKey = `spectrogram_history:${testDetectorId}`;
    const peakHistKey = `peaks:${testDetectorId}`;
    let setupError = null; // Flag to indicate setup failure

    jest.setTimeout(TEST_TIMEOUT);

    // --- Setup and Teardown ---
    beforeAll(async () => {
        setupError = null; // Reset error flag
        let dbClient;
        try {
            console.log('Connecting Redis & DB for tests...');
            // Add delay before connecting
            await sleep(2000); // Wait 2 seconds after potential health check pass

            await redis.connect();
            await streamRedis.connect();
            await redis.ping();
            await streamRedis.ping();
            dbClient = await dbPool.connect(); // Test DB connection
            await dbClient.query('SELECT 1'); // Verify query works
            dbClient.release();
            console.log('Redis & DB connections successful.');

            console.log('Cleaning up previous test data...');
            const userKeys = await redis.keys(`${testUser}`);
            if (userKeys.length > 0) await redis.del(userKeys);
            const dataKeys = await streamRedis.keys(`*${testDetectorId}*`);
            if (dataKeys.length > 0) await streamRedis.del(dataKeys);
            const trackStateKey = `track_state:${testDetectorId}`; // Key used by trackPeaks
            await redis.del(trackStateKey); // Clear track state too (uses main client)

            // Clear DB tables
            await dbPool.query(`DELETE FROM historical_spectrograms WHERE detector_id = $1`, [testDetectorId]);
            await dbPool.query(`DELETE FROM historical_peaks WHERE detector_id = $1`, [testDetectorId]);
            // Delete test user if exists
            await dbPool.query(`DELETE FROM users WHERE username = $1`, [testUser]);

            console.log('Previous test data cleaned.');

            // Register test user
            console.log('Registering test user...');
            await axios.post(`${API_BASE_URL}/register`, { username: testUser, password: testPassword });
            console.log('Test user registered.');

        } catch (err) {
            setupError = `Setup failed: ${err.message}`; // Store error message
            console.error(setupError);
            // Attempt cleanup even on failure
            if (dbClient) dbClient.release();
            // Don't end pool/quit redis here, let afterAll handle it based on status
            throw new Error(setupError);
        }
    });

    afterAll(async () => {
        try {
           console.log('Cleaning up test resources...');
           // Clean up DB first
           await dbPool.query(`DELETE FROM historical_spectrograms WHERE detector_id = $1`, [testDetectorId]);
           await dbPool.query(`DELETE FROM historical_peaks WHERE detector_id = $1`, [testDetectorId]);
           await dbPool.query(`DELETE FROM users WHERE username = $1`, [testUser]);
            console.log('Test data cleaned from DB.');
           // Clean up Redis
           const userKeys = await redis.keys(`${testUser}`);
           if (userKeys.length > 0) await redis.del(userKeys);
           const dataKeys = await streamRedis.keys(`*${testDetectorId}*`);
           if (dataKeys.length > 0) await streamRedis.del(dataKeys);
           const trackStateKey = `track_state:${testDetectorId}`;
           await redis.del(trackStateKey);
            console.log('Test data cleaned from Redis.');

        } catch (err) {
            console.warn('Test cleanup failed:', err.message); // Log only message
        } finally {
            // Ensure connections are closed, checking status first
            if (redis.status === 'ready' || redis.status === 'connecting') await redis.quit().catch(()=>{});
            if (streamRedis.status === 'ready' || streamRedis.status === 'connecting') await streamRedis.quit().catch(()=>{});
            await dbPool.end().catch(()=>{}); // End pool gracefully
            console.log('Redis & DB connections closed.');
        }
    });

    // Helper to skip tests if setup failed
    const runIfSetupOK = (testName, testFn) => {
        if (setupError) {
            test.skip(`${testName} (skipped due to setup failure)`, () => {});
        } else {
            test(testName, testFn);
        }
    };

    // --- Basic Auth & Setup Tests ---
    runIfSetupOK('GET /health should return 200 OK', async () => {
        const response = await axios.get(`${API_BASE_URL}/health`);
        expect(response.status).toBe(200);
        expect(response.data.status).toBe('OK');
        expect(response.data.redis_main).toBe('OK');
        expect(response.data.redis_stream).toBe('OK');
        expect(response.data.postgres).toBe('OK');
    });
    runIfSetupOK('POST /login returns JWT', async () => {
        const response = await axios.post(`${API_BASE_URL}/login`, { username: testUser, password: testPassword });
        expect(response.status).toBe(200);
        expect(response.data.token).toBeDefined();
        authToken = response.data.token; // Store for subsequent tests
    });
    runIfSetupOK('POST /key-exchange returns key', async () => {
        expect(authToken).toBeDefined();
        const response = await axios.post(`${API_BASE_URL}/key-exchange`, {}, { headers: { Authorization: `Bearer ${authToken}` } });
        expect(response.status).toBe(200);
        expect(response.data.key).toMatch(/^[a-f0-9]{64}$/);
        encryptionKey = response.data.key;
        const storedKey = await redis.get(`${testUser}`); // Prefix is handled by client
        expect(storedKey).toBe(encryptionKey);
    });

    // --- Data Ingest & WS Tests ---
     runIfSetupOK('POST /data-ingest accepts valid batch', async () => {
         const ingestDetectorId = testDetectorId + "_ingest"; // Use specific ID
         const payload = { detectorId: ingestDetectorId, location: { lat: 1.23, lon: -4.56 }, spectrograms: [ Array(RAW_FREQUENCY_POINTS).fill(1.0), Array(RAW_FREQUENCY_POINTS).fill(2.0) ] };
         const headers = { 'X-API-Key': API_INGEST_KEY };
         const response = await axios.post(`${API_BASE_URL}/data-ingest`, payload, { headers });
         expect(response.status).toBe(202);
         expect(response.data.messageId).toBeDefined();
         await sleep(500); // Increase sleep slightly

         // Read more messages to find the specific one
         const streamMessages = await streamRedis.xrevrange('spectrogram_stream', '+', '-', 'COUNT', 5); // Read last 5
         expect(streamMessages.length).toBeGreaterThan(0);

         // Find the message with the correct detectorId
         const targetMessage = streamMessages.find(msg => {
             try {
                 const data = JSON.parse(msg[1][1]); // data is at index 1 of the field array
                 return data.detectorId === ingestDetectorId;
             } catch {
                 return false;
             }
         });
         expect(targetMessage).toBeDefined(); // Ensure we found the message

         const streamData = JSON.parse(targetMessage[1][1]);
         expect(streamData.detectorId).toBe(ingestDetectorId);
         expect(streamData.spectrogram.length).toBe(2);
         expect(streamData.spectrogram[0].length).toBe(RAW_FREQUENCY_POINTS);
         // Clean up only the processed message if needed, or rely on test isolation
         // await streamRedis.xdel('spectrogram_stream', targetMessage[0]);
     });

     runIfSetupOK('WebSocket receives processed data with peaks and transient info', async () => {
         expect(authToken).toBeDefined(); expect(encryptionKey).toBeDefined();
         const wsDetectorId = testDetectorId + "_ws";
         const ws = new WebSocket(`${WS_URL}/?token=${authToken}`);
         let receivedTargetMessage = false; // Flag to indicate if target message received
         let decryptedData = null; // Store the target message data
         let wsError = null;
         let wsClosedCode = null;
         let closeReason = '';

         // Promise that resolves only when the correct message arrives or times out
         const messagePromise = new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                if (!receivedTargetMessage) { // Only reject if target not received
                    ws.terminate();
                    reject(new Error(`WebSocket target message timeout after ${WS_MESSAGE_TIMEOUT}ms (State: ${ws.readyState})`));
                }
            }, WS_MESSAGE_TIMEOUT);

            ws.on('message', (data) => {
                try {
                    const [encrypted, iv] = data.toString('utf8').split(':');
                    if (!encrypted || !iv) throw new Error("Invalid WS message format");
                    const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
                    const decryptedBytes = CryptoJS.AES.decrypt({ ciphertext: CryptoJS.enc.Base64.parse(encrypted) }, keyWordArray, { iv: CryptoJS.enc.Base64.parse(iv), mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
                    const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
                    if (!decryptedText) throw new Error("Decryption resulted in empty message");

                    const messageData = JSON.parse(decryptedText);

                    // Check if this is the message we are waiting for
                    if (messageData.detectorId === wsDetectorId) {
                        console.log(`Received target WS message for ${wsDetectorId}`);
                        receivedTargetMessage = true;
                        decryptedData = messageData; // Store the correct data
                        clearTimeout(timeout); // Clear timeout as we got the message
                        ws.close(1000, 'Test complete'); // Close connection cleanly
                        resolve(); // Resolve the promise
                    } else {
                        console.log(`Ignoring WS message from ${messageData.detectorId}`);
                    }
                } catch (err) {
                    console.error('WebSocket message processing error:', err);
                    // Don't reject here, allow timeout to handle cases where target never arrives
                }
            });

            ws.on('error', (err) => { clearTimeout(timeout); wsError = err; console.error("WS direct error:", err); reject(err); }); // Reject on direct error
            ws.on('close', (code, reason) => {
                wsClosedCode = code; closeReason = reason.toString();
                // Only reject if closed unexpectedly *before* target message received
                if (code !== 1000 && code !== 1005 && !receivedTargetMessage) {
                    clearTimeout(timeout);
                    reject(new Error(`WS closed unexpectedly (${code} - ${closeReason}) before target message received.`));
                } else if (!receivedTargetMessage && code !== 1000 && code !== 1005) {
                    // If closed after timeout/error, this is expected.
                     console.log(`WS closed (${code}) after test failure/timeout.`);
                }
            });
         });

         // Connection logic
         await new Promise((resolve, reject) => { const ct = setTimeout(() => reject(new Error('WS connection timeout')), 5000); ws.on('open', () => { clearTimeout(ct); console.log('WebSocket connected for peak test.'); resolve(); }); ws.on('error', (err) => { clearTimeout(ct); reject(err); }); });
         await sleep(300);

         // Ingest data
         const rawSpectrogramWithPeak = Array(RAW_FREQUENCY_POINTS).fill(1.0);
         const peakIndex = Math.floor(RAW_FREQUENCY_POINTS / 4); const peakFreq = peakIndex * (55 / (RAW_FREQUENCY_POINTS - 1));
         rawSpectrogramWithPeak[peakIndex - 2] = 3.0; rawSpectrogramWithPeak[peakIndex - 1] = 8.0; rawSpectrogramWithPeak[peakIndex] = 20.0; rawSpectrogramWithPeak[peakIndex + 1] = 7.0; rawSpectrogramWithPeak[peakIndex + 2] = 2.5;
         const ingestPayload = { detectorId: wsDetectorId, location: { lat: 45, lon: 45 }, spectrograms: [rawSpectrogramWithPeak] };
         const peakKeyWs = `peaks:${wsDetectorId}`; await streamRedis.del(peakKeyWs);

         await axios.post(`${API_BASE_URL}/data-ingest`, ingestPayload, { headers: { 'X-API-Key': API_INGEST_KEY } });
         console.log('Test message ingested for WS test.');

         // Wait for the promise (either resolves on correct message or rejects on timeout/error)
         try { await messagePromise; } catch(e) { console.error("WS Error Obj:", wsError); console.error("WS Closed Code/Reason:", wsClosedCode, closeReason); throw e; }

         // Assertions on the stored decryptedData
         expect(receivedTargetMessage).toBe(true); // Ensure we actually got the target
         expect(decryptedData).toBeDefined();
         expect(decryptedData.detectorId).toBe(wsDetectorId);
         expect(decryptedData.spectrogram[0].length).toBe(EXPECTED_DOWNSAMPLED_LENGTH);
         expect(Array.isArray(decryptedData.detectedPeaks)).toBe(true);
         expect(decryptedData.detectedPeaks.length).toBeGreaterThanOrEqual(1);
         const detectedPeak = decryptedData.detectedPeaks.find(p => Math.abs(p.freq - peakFreq) < 1.0);
         expect(detectedPeak).withContext(`Expected peak near ${peakFreq.toFixed(2)}Hz not found in ${JSON.stringify(decryptedData.detectedPeaks)}`).toBeDefined();
         expect(detectedPeak.amp).toBeCloseTo(20.0, 0);
         expect(detectedPeak.qFactor).toBeGreaterThan(0);
         expect(detectedPeak.trackStatus).toBeDefined(); // Check trackStatus exists
         expect(decryptedData.transientInfo).toBeDefined(); // Check transientInfo exists
         expect(decryptedData.transientInfo.type).toBeDefined(); // Check type exists

         console.log('Received WS Peaks:', JSON.stringify(decryptedData.detectedPeaks));
         console.log('Received WS TransientInfo:', JSON.stringify(decryptedData.transientInfo));

         // Verify peak was stored in Redis history too
         const storedPeaks = await streamRedis.zrange(peakKeyWs, 0, -1);
         expect(storedPeaks.length).toBeGreaterThan(0); // Expect at least one entry
         const storedPeakDataArray = JSON.parse(storedPeaks[0]); // Check first entry
         expect(Array.isArray(storedPeakDataArray)).toBe(true);
         const storedMainPeak = storedPeakDataArray.find(p => Math.abs(p.freq - peakFreq) < 1.0);
         expect(storedMainPeak).toBeDefined();

         // ws.close(1000, 'Test complete'); // Closed within promise handler now
         await streamRedis.del(peakKeyWs); // Clean up specific key
     });

    // --- Phase 3b/4e: Combined History Tests ---
    describe('Combined History API', () => {
        const now = Date.now();
        const recentTimeMs = now - REDIS_SPEC_RETENTION_MS / 2; // Within Redis retention
        const oldTimeMs = now - REDIS_SPEC_RETENTION_MS * 2; // Older than Redis retention
        const ancientTimeMs = now - REDIS_PEAK_RETENTION_MS * 2; // Older than peak retention

        const recentTimestamp = new Date(recentTimeMs).toISOString();
        const oldTimestamp = new Date(oldTimeMs).toISOString();
        const ancientTimestamp = new Date(ancientTimeMs).toISOString(); // For peaks

        // Correct structure for recentSpecData (array of arrays)
        const recentSpecData = {
            detectorId: testDetectorId, timestamp: recentTimestamp, location: { lat: 10, lon: 10 },
            spectrogram: [new Array(EXPECTED_DOWNSAMPLED_LENGTH).fill(5.5)], // Example downsampled
            transientInfo: { type: 'none', details: null }
        };
        // Correct structure for oldSpecData (array of arrays)
        const oldSpecData = {
            detector_id: testDetectorId, timestamp: oldTimestamp, location_lat: 10, location_lon: 10,
            spectrogram_data: [new Array(EXPECTED_DOWNSAMPLED_LENGTH).fill(3.3)], // Array of arrays
            transient_detected: true, // Simulating a detected transient stored in DB
            transient_details: "DB Test Broadband Details"
        };
        const recentPeakData = [{ freq: 7.8, amp: 15, qFactor: 4, trackStatus: 'continuing' }];
        const oldPeakData = [{ freq: 14.1, amp: 10, qFactor: 5, trackStatus: 'new' }];
        const ancientPeakData = [{ freq: 20.5, amp: 5, qFactor: 6, trackStatus: 'new' }];


        beforeAll(async () => {
            // Skip seeding if setup already failed
            if (setupError) return;
            // Seed data
            console.log("Seeding history data for combined tests...");
            // Seed recent data into Redis
            await streamRedis.lpush(specHistKey, JSON.stringify(recentSpecData));
            await streamRedis.zadd(peakHistKey, recentTimeMs, JSON.stringify(recentPeakData));
            // Seed old data into DB
            await dbPool.query(
                `INSERT INTO historical_spectrograms (detector_id, timestamp, location_lat, location_lon, spectrogram_data, transient_detected, transient_details) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [oldSpecData.detector_id, oldSpecData.timestamp, oldSpecData.location_lat, oldSpecData.location_lon, JSON.stringify(oldSpecData.spectrogram_data), oldSpecData.transient_detected, oldSpecData.transient_details]
            );
            await dbPool.query(
                `INSERT INTO historical_peaks (detector_id, "timestamp", peak_data) VALUES ($1, $2, $3)`,
                [testDetectorId, new Date(oldTimeMs), JSON.stringify(oldPeakData)]
            );
            await dbPool.query( // Add ancient peak data too
                `INSERT INTO historical_peaks (detector_id, "timestamp", peak_data) VALUES ($1, $2, $3)`,
                [testDetectorId, new Date(ancientTimeMs), JSON.stringify(ancientPeakData)]
            );
            console.log("History data seeded.");
            if (!authToken) {
                const response = await axios.post(`${API_BASE_URL}/login`, { username: testUser, password: testPassword });
                authToken = response.data.token;
            }
            expect(authToken).toBeDefined();
        });

        runIfSetupOK('GET /history/range should return combined data from Redis and DB', async () => { // Use new route
            const queryStartTime = new Date(oldTimeMs - 1000).toISOString();
            const queryEndTime = new Date(recentTimeMs + 1000).toISOString();

            // Use the new /history/range route
            const response = await axios.get(`${API_BASE_URL}/history/range?startTime=${queryStartTime}&endTime=${queryEndTime}&detectorId=${testDetectorId}`, {
                headers: { Authorization: `Bearer ${authToken}` }
            });

            expect(response.status).toBe(200);
            expect(Array.isArray(response.data)).toBe(true);
            expect(response.data.length).toBe(1); // Grouped by detector
            const detectorData = response.data[0];
            expect(detectorData.detectorId).toBe(testDetectorId);
            // Expect combined spectrogram data (1 DB row + 1 Redis row -> 2 rows * length)
            const expectedLength = EXPECTED_DOWNSAMPLED_LENGTH * 2;
             expect(detectorData.spectrogram.length).toBe(expectedLength); // This should now pass
             expect(detectorData.spectrogram.includes(3.3)).toBe(true);
             expect(detectorData.spectrogram.includes(5.5)).toBe(true);
            expect(Array.isArray(detectorData.transientEvents)).toBe(true);
            expect(detectorData.transientEvents.length).toBe(1); // Only the one from DB
            expect(detectorData.transientEvents[0].type).not.toBe('none');
            expect(detectorData.transientEvents[0].details).toBe("DB Test Broadband Details");
             expect(detectorData.transientEvents[0].ts).toBeCloseTo(oldTimeMs, -2); // Check timestamp
        });

        runIfSetupOK('GET /history/peaks/range should return combined peaks from Redis and DB', async () => { // Use new route
            const queryStartTime = new Date(ancientTimeMs - 1000).toISOString();
            const queryEndTime = new Date(recentTimeMs + 1000).toISOString();

            // Use the new /history/peaks/range route
            const response = await axios.get(`${API_BASE_URL}/history/peaks/range?startTime=${queryStartTime}&endTime=${queryEndTime}&detectorId=${testDetectorId}`, {
                 headers: { Authorization: `Bearer ${authToken}` }
             });

            expect(response.status).toBe(200); // Expect 200 now, not 400
            expect(Array.isArray(response.data)).toBe(true);
            expect(response.data.length).toBe(1); // Grouped by detector
            const detectorHistory = response.data[0];
            expect(detectorHistory.detectorId).toBe(testDetectorId);
            expect(Array.isArray(detectorHistory.peaks)).toBe(true);
            // Expecting 3 entries: ancient (DB), old (DB), recent (Redis)
            expect(detectorHistory.peaks.length).toBe(3);

            // Check timestamps are close and data matches (approx)
            expect(detectorHistory.peaks[0].ts).toBeCloseTo(ancientTimeMs, -2);
            expect(detectorHistory.peaks[0].peaks[0].freq).toBe(ancientPeakData[0].freq);
            expect(detectorHistory.peaks[1].ts).toBeCloseTo(oldTimeMs, -2);
            expect(detectorHistory.peaks[1].peaks[0].freq).toBe(oldPeakData[0].freq);
            expect(detectorHistory.peaks[2].ts).toBeCloseTo(recentTimeMs, -2);
            expect(detectorHistory.peaks[2].peaks[0].freq).toBe(recentPeakData[0].freq);
            expect(detectorHistory.peaks[2].peaks[0].trackStatus).toBeDefined(); // Ensure trackStatus from Redis is included
        });

        runIfSetupOK('GET /history/peaks/hours/:hours should only return recent (Redis) data', async () => { // Use new route
            // Calculate hours to *only* cover the recent Redis data based on retention
            const hoursToQuery = Math.ceil(REDIS_PEAK_RETENTION_MS / (3600 * 1000) * 0.8); // Query < retention period
             // Use the new /history/peaks/hours/:hours route
             const response = await axios.get(`${API_BASE_URL}/history/peaks/hours/${hoursToQuery}?detectorId=${testDetectorId}`, {
                 headers: { Authorization: `Bearer ${authToken}` }
             });
             expect(response.status).toBe(200);
             expect(response.data.length).toBe(1);
             const detectorHistory = response.data[0];
             expect(detectorHistory.detectorId).toBe(testDetectorId);
             // Should only contain the recent peak from Redis
             expect(detectorHistory.peaks.length).toBe(1);
             expect(detectorHistory.peaks[0].ts).toBeCloseTo(recentTimeMs, -2);
             expect(detectorHistory.peaks[0].peaks[0].freq).toBe(recentPeakData[0].freq);
        });
    });

});
