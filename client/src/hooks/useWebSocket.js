// client/src/hooks/useWebSocket.js
/**
 * Custom hook for managing WebSocket connections, including authentication,
 * message decryption, state updates, and automatic reconnection.
 * v1.1.28 - Remove Console Logs.
 */
import { useState, useEffect, useRef, useMemo } from 'react';
import CryptoJS from 'crypto-js';
import throttle from 'lodash.throttle';
// Import constants used by the hook
import {
  SPECTROGRAM_UPDATE_THROTTLE_MS,
  EXPECTED_DOWNSAMPLED_POINTS,
  TRANSIENT_INDICATOR_TIMEOUT_MS,
} from '../constants';

// Define WebSocket status enum
export const WebSocketStatus = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
};

// Custom Hook for WebSocket Management
function useWebSocket(
  wsUrl,
  token,
  encryptionKey,
  historicalMode,
  stableSetSpectrogramData,
  stableSetPeakData,
  stableSetDetectorActivity,
  stableSetLastTransientInfo,
  showSnackbar
) {
  const [wsStatus, setWsStatus] = useState(WebSocketStatus.DISCONNECTED);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const recentTransientTimeoutRef = useRef(null);
  const historicalModeRef = useRef(historicalMode);

  useEffect(() => {
    historicalModeRef.current = historicalMode;
  }, [historicalMode]);

  useEffect(() => {
    return () => {
      if (recentTransientTimeoutRef.current) {
        clearTimeout(recentTransientTimeoutRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        // console.debug('WS Hook: Closing WebSocket connection on cleanup...');
        wsRef.current.onopen = null;
        wsRef.current.onmessage = null;
        wsRef.current.onerror = null;
        wsRef.current.onclose = null;
        wsRef.current.close(1000, 'WebSocket hook cleanup');
        wsRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wsUrl, token, encryptionKey]);

  const updateSpectrogramDataThrottled = useMemo(
    () =>
      throttle(
        (newDataBatch) => {
          let transientInBatch = null;
          stableSetSpectrogramData((prev) => {
            const updated = { ...prev };
            newDataBatch.forEach((message) => {
              if (
                !message?.detectorId ||
                !message.location ||
                !Array.isArray(message.spectrogram)
              ) {
                return;
              }
              const detectorId = message.detectorId;
              const incomingSpectrogramRow = message.spectrogram[0];
              if (!Array.isArray(incomingSpectrogramRow)) {
                return;
              }
              if (
                incomingSpectrogramRow.length < EXPECTED_DOWNSAMPLED_POINTS - 10 ||
                incomingSpectrogramRow.length > EXPECTED_DOWNSAMPLED_POINTS + 10
              ) {
                return;
              }
              const currentRows = updated[detectorId] || [];
              const newRows = [...currentRows, incomingSpectrogramRow];
              updated[detectorId] = newRows;
              if (message.transientInfo && message.transientInfo.type !== 'none') {
                transientInBatch = message.transientInfo;
                // console.debug('WS Hook: Transient Detected:', message.transientInfo); // Removed
              }
            });
            return updated;
          });
          stableSetPeakData((prevPeaks) => {
            const updatedPeaks = { ...prevPeaks };
            newDataBatch.forEach((message) => {
              if (message?.detectorId && Array.isArray(message.detectedPeaks)) {
                updatedPeaks[message.detectorId] = message.detectedPeaks;
              }
            });
            return updatedPeaks;
          });
          stableSetDetectorActivity((prevActivity) => {
            const updatedActivity = { ...prevActivity };
            newDataBatch.forEach((data) => {
              if (data?.detectorId && data.location) {
                updatedActivity[data.detectorId] = {
                  lat: data.location.lat,
                  lon: data.location.lon,
                  lastUpdate: Date.now(),
                  id: data.detectorId,
                };
              }
            });
            return updatedActivity;
          });
          if (transientInBatch && !historicalModeRef.current) {
            stableSetLastTransientInfo(transientInBatch);
            if (recentTransientTimeoutRef.current) {
              clearTimeout(recentTransientTimeoutRef.current);
            }
            recentTransientTimeoutRef.current = setTimeout(() => {
              stableSetLastTransientInfo(null);
              recentTransientTimeoutRef.current = null;
            }, TRANSIENT_INDICATOR_TIMEOUT_MS);
          }
        },
        SPECTROGRAM_UPDATE_THROTTLE_MS,
        { leading: true, trailing: true }
      ),
    [
      stableSetSpectrogramData,
      stableSetPeakData,
      stableSetDetectorActivity,
      stableSetLastTransientInfo,
    ]
  );

  useEffect(() => {
    let currentWsInstance = null;
    const clearReconnectTimeout = () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };
    const scheduleReconnect = (attempt) => {
      clearReconnectTimeout();
      const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
      // console.debug(`WS Hook: Scheduling reconnect in ${delay / 1000} seconds... (Attempt ${attempt + 1})`); // Removed
      reconnectTimeoutRef.current = setTimeout(() => {
        if (token && encryptionKey && wsUrl && !historicalModeRef.current) {
          setReconnectAttempt((prev) => prev + 1);
        } else {
          // console.debug("WS Hook: Skipping scheduled reconnect as conditions changed."); // Removed
          setReconnectAttempt(0);
        }
      }, delay);
    };

    if (historicalModeRef.current) {
      // console.debug("WS Hook: Historical mode active, ensuring WebSocket is closed."); // Removed
      clearReconnectTimeout();
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close(1000, 'Switching to historical mode');
        wsRef.current = null;
      }
      if (wsStatus !== WebSocketStatus.DISCONNECTED) {
        setWsStatus(WebSocketStatus.DISCONNECTED);
      }
      setReconnectAttempt(0);
      return;
    }

    if (token && encryptionKey && wsUrl) {
      if (!wsRef.current && wsStatus !== WebSocketStatus.CONNECTING) {
        // console.debug(`WS Hook: Attempting connection to ${wsUrl} (Attempt: ${reconnectAttempt})...`); // Removed
        setWsStatus(WebSocketStatus.CONNECTING);
        try {
          currentWsInstance = new WebSocket(`${wsUrl}/?token=${token}`);
          wsRef.current = currentWsInstance;
        } catch (error) {
          console.error('WS Hook: Failed to create WebSocket instance:', error); // Keep error
          setWsStatus(WebSocketStatus.ERROR);
          showSnackbar(`WebSocket creation failed: ${error.message}`, 'error');
          wsRef.current = null;
          scheduleReconnect(reconnectAttempt);
          return;
        }

        currentWsInstance.onopen = () => {
          if (wsRef.current === currentWsInstance) {
            // console.debug('WS Hook: WebSocket connection established.'); // Removed
            setWsStatus(WebSocketStatus.CONNECTED);
            setReconnectAttempt(0);
            clearReconnectTimeout();
          } else {
            // console.debug('WS Hook: Stale WebSocket instance opened, closing it.'); // Removed
            currentWsInstance.close(1000, 'Stale connection attempt');
          }
        };

        currentWsInstance.onmessage = (event) => {
          if (wsRef.current !== currentWsInstance) {
            return;
          }
          try {
            const messageParts = event.data.toString('utf8').split(':');
            if (messageParts.length !== 2) {
              throw new Error('Invalid WebSocket message format (missing separator)');
            }
            const [encrypted, iv] = messageParts;
            if (!encrypted || !iv) {
              throw new Error('Invalid WebSocket message format (empty parts)');
            }
            const keyWordArray = CryptoJS.enc.Hex.parse(encryptionKey);
            const ivWordArray = CryptoJS.enc.Base64.parse(iv);
            const decryptedBytes = CryptoJS.AES.decrypt(
              { ciphertext: CryptoJS.enc.Base64.parse(encrypted) },
              keyWordArray,
              { iv: ivWordArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
            );
            const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
            if (!decryptedText) {
              throw new Error('Decryption resulted in empty message');
            }
            const messageData = JSON.parse(decryptedText);
            updateSpectrogramDataThrottled([messageData]);
          } catch (err) {
            console.error('WS Hook: Error processing incoming message:', err); // Keep error
            showSnackbar(`WebSocket Data Error: ${err.message}. Check console.`, 'error');
          }
        };

        currentWsInstance.onerror = (error) => {
          console.error('WS Hook: WebSocket error event occurred.', error); // Keep error
          if (wsRef.current === currentWsInstance) {
            setWsStatus(WebSocketStatus.ERROR);
            showSnackbar('WebSocket connection error occurred.', 'error');
            wsRef.current = null;
            if (!historicalModeRef.current) {
              scheduleReconnect(reconnectAttempt);
            }
          }
        };

        currentWsInstance.onclose = (event) => {
          // console.debug(`WS Hook: WebSocket closed. Code: ${event.code}, Reason: "${event.reason || 'N/A'}"`); // Removed
          if (wsRef.current === currentWsInstance) {
            wsRef.current = null;
            setWsStatus(WebSocketStatus.DISCONNECTED);
            if (event.code !== 1000 && !historicalModeRef.current) {
              showSnackbar(
                `WebSocket disconnected (Code: ${event.code}). Attempting reconnect...`,
                'warning'
              );
              scheduleReconnect(reconnectAttempt);
            } else {
              setReconnectAttempt(0);
              clearReconnectTimeout();
            }
          } else {
            // console.debug("WS Hook: Ignoring close event from stale WebSocket instance."); // Removed
          }
        };
      }
    } else {
      // console.debug('WS Hook: Prerequisites (token, key, url) not met, ensuring WS is closed.'); // Removed
      clearReconnectTimeout();
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close(1000, 'Prerequisites no longer met');
        wsRef.current = null;
      }
      if (wsStatus !== WebSocketStatus.DISCONNECTED) {
        setWsStatus(WebSocketStatus.DISCONNECTED);
      }
      setReconnectAttempt(0);
    }

    return () => {
      clearReconnectTimeout();
      if (currentWsInstance && currentWsInstance !== wsRef.current) {
        // console.debug('WS Hook: Closing intermediate WebSocket instance during effect cleanup.'); // Removed
        currentWsInstance.onopen = null;
        currentWsInstance.onmessage = null;
        currentWsInstance.onerror = null;
        currentWsInstance.onclose = null;
        currentWsInstance.close(1000, 'Effect cleanup for stale instance');
      }
    };
  }, [
    token,
    encryptionKey,
    wsUrl,
    reconnectAttempt,
    updateSpectrogramDataThrottled,
    showSnackbar,
    wsStatus,
    setWsStatus,
  ]);

  return wsStatus;
}

export default useWebSocket;
