// client/src/hooks/useApiClient.js
/**
 * Custom hook for managing API interactions:
 * - Fetches encryption key for WebSocket.
 * - Fetches historical spectrogram and peak data.
 * - Signals authentication errors (401/403) back to the component.
 * v1.1.28 - Add Auth Error Signaling. No backslash escapes in template literals.
 */
import { useState, useCallback, useEffect } from 'react';
import axios from 'axios';
// Import relevant constants
import { EXPECTED_DOWNSAMPLED_POINTS } from '../constants';

// Hook to manage API interactions for key exchange and historical data
function useApiClient(apiUrl, token, showSnackbar) {
  const [encryptionKey, setEncryptionKey] = useState(null);
  const [isLoadingKey, setIsLoadingKey] = useState(false);
  const [authenticationErrorOccurred, setAuthenticationErrorOccurred] = useState(false); // New state

  // State for historical data
  const [historicalSpectrograms, setHistoricalSpectrograms] = useState({});
  const [historicalPeaks, setHistoricalPeaks] = useState(null);
  const [historicalActivity, setHistoricalActivity] = useState({});
  const [historicalTransients, setHistoricalTransients] = useState([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [historyError, setHistoryError] = useState(null);

  // --- Fetch Encryption Key ---
  const fetchKey = useCallback(async () => {
    if (!token || !apiUrl) {
      setEncryptionKey(null);
      return;
    }
    setIsLoadingKey(true);
    setAuthenticationErrorOccurred(false); // Reset auth error on new attempt
    try {
      const response = await axios.post(
        `${apiUrl}/key-exchange`, // Corrected interpolation
        {},
        {
          headers: { Authorization: `Bearer ${token}` }, // Corrected interpolation
        }
      );
      setEncryptionKey(response.data.key);
    } catch (err) {
      console.error('API Hook: Key exchange failed:', err);
      const status = err.response?.status;
      const errorMsg = `Key Exchange Failed: ${ // Corrected interpolation
        err.response?.data?.error || (err.request ? 'Network Error' : err.message)
      }`;
      showSnackbar(errorMsg, 'error');
      setEncryptionKey(null);
      // Signal auth error if 401 or 403
      if (status === 401 || status === 403) {
        setAuthenticationErrorOccurred(true);
      }
    } finally {
      setIsLoadingKey(false);
    }
  }, [apiUrl, token, showSnackbar]);

  // --- Fetch Historical Data ---
  const loadHistoricalData = useCallback(
    async (hours, detectorId) => {
      if (!token || !apiUrl) {
        setHistoryError('Missing token or API URL');
        showSnackbar('Cannot load history: Missing token or API URL.', 'error');
        return;
      }

      setIsLoadingHistory(true);
      setHistoryError(null);
      setAuthenticationErrorOccurred(false); // Reset auth error on new attempt
      setHistoricalSpectrograms({});
      setHistoricalPeaks(null);
      setHistoricalActivity({});
      setHistoricalTransients([]);

      let fetchError = null;
      let noDataMessage = null;

      try {
        const headers = { Authorization: `Bearer ${token}` }; // Corrected interpolation
        const params = detectorId !== 'all' ? { detectorId: detectorId } : {};

        // Use correct prefixed API paths
        const specHistoryUrl = `${apiUrl}/api/history/hours/${hours}`; // Corrected interpolation
        const peakHistoryUrl = `${apiUrl}/api/history/peaks/hours/${hours}`; // Corrected interpolation

        const [specResponse, peakResponse] = await Promise.all([
          axios.get(specHistoryUrl, { headers, params }).catch((err) => {
            throw { type: 'spectrogram', error: err };
          }),
          axios.get(peakHistoryUrl, { headers, params }).catch((err) => {
            throw { type: 'peaks', error: err };
          }),
        ]);

        // --- Process Spectrogram History Response ---
        const historicalSpecRaw = Array.isArray(specResponse.data) ? specResponse.data : [];
        const newSpectrogramData = {};
        const newDetectorActivityData = {};
        const collectedTransientEvents = [];
        const expectedPoints = EXPECTED_DOWNSAMPLED_POINTS;

        historicalSpecRaw.forEach((detectorHistory) => {
          if (
            !detectorHistory?.detectorId ||
            !detectorHistory.location ||
            !Array.isArray(detectorHistory.dataPoints)
          ) {
            return;
          }

          const currentDetectorId = detectorHistory.detectorId;
          const validDataPointsForDetector = [];

          detectorHistory.dataPoints.forEach((dataPoint) => {
            // Use the single downsampled spectrum array directly
            const specData = dataPoint?.spectrogram;
            if (
              dataPoint?.ts &&
              Array.isArray(specData) &&
              specData.length >= expectedPoints - 10 &&
              specData.length <= expectedPoints + 10
            ) {
              let row = specData; // It's already the single downsampled array
              if (row.length !== expectedPoints) {
                const newRow = [...row];
                if (row.length < expectedPoints) {
                  newRow.push(...Array(expectedPoints - row.length).fill(0));
                } else {
                  newRow.length = expectedPoints;
                }
                row = newRow;
              }

              validDataPointsForDetector.push({
                ts: dataPoint.ts,
                spectrogram: row, // Store the corrected single array
                transientInfo: dataPoint.transientInfo || { type: 'none', details: null },
              });

              if (dataPoint.transientInfo && dataPoint.transientInfo.type !== 'none') {
                collectedTransientEvents.push({
                  ...dataPoint.transientInfo,
                  detectorId: currentDetectorId,
                  ts: dataPoint.ts,
                });
              }
            }
          });

          if (validDataPointsForDetector.length > 0) {
            newSpectrogramData[currentDetectorId] = {
              detectorId: currentDetectorId,
              location: detectorHistory.location,
              dataPoints: validDataPointsForDetector,
            };
          }

          newDetectorActivityData[currentDetectorId] = {
            lat: detectorHistory.location.lat,
            lon: detectorHistory.location.lon,
            lastUpdate: Date.now(), // Use current time as this is just for display
            id: currentDetectorId,
          };
        });

        setHistoricalSpectrograms(newSpectrogramData);
        setHistoricalActivity(newDetectorActivityData);
        if (Object.keys(newSpectrogramData).length === 0) {
          noDataMessage = `No historical spectrogram data found`;
        }

        // --- Process Peak History Response ---
        const historicalPeaksRaw = Array.isArray(peakResponse.data) ? peakResponse.data : [];
        setHistoricalPeaks(historicalPeaksRaw);

        // --- Process Transient Events ---
        const relevantTransientEvents =
          detectorId === 'all'
            ? collectedTransientEvents
            : collectedTransientEvents.filter((event) => event.detectorId === detectorId);
        setHistoricalTransients(relevantTransientEvents.sort((a, b) => a.ts - b.ts));

        // --- Check for "No Data" Conditions ---
        if (historicalPeaksRaw.length === 0 && Object.keys(newSpectrogramData).length === 0) {
          noDataMessage = `No historical spectrogram or peak data found`;
        } else if (historicalPeaksRaw.length === 0) {
          noDataMessage = noDataMessage
            ? `${noDataMessage} or peak data found` // Corrected interpolation
            : `No historical peak data found`;
        } else if (Object.keys(newSpectrogramData).length === 0) {
          noDataMessage = noDataMessage
            ? `${noDataMessage} or spectrogram data found` // Corrected interpolation
            : `No historical spectrogram data found`;
        }
        if (noDataMessage) {
          noDataMessage += ` for ${detectorId === 'all' ? 'any detector' : `detector ${detectorId}`} in the last ${hours}h.`; // Corrected interpolation
        }
      } catch (errWrapper) {
        const err = errWrapper.error || errWrapper;
        const type = errWrapper.type || 'general';
        const status = err.response?.status;
        fetchError = `Failed to fetch historical ${type} data: ${ // Corrected interpolation
          err.response?.data?.error || (err.request ? 'Network Error' : err.message)
        }`;
        setHistoryError(fetchError);
        // Signal auth error if 401 or 403
        if (status === 401 || status === 403) {
          setAuthenticationErrorOccurred(true);
          // Optionally customize the snackbar message for auth errors
          showSnackbar(
            `Authentication error fetching history (${status}). Please log in again.`,
            'error'
          );
          // Avoid showing the generic fetch error snackbar below if it was an auth error
          fetchError = null;
        } else {
          // Only log the error details for non-auth errors here, auth error handled above
          console.error(`API Hook: Historical ${type} data fetch error:`, err); // Corrected interpolation
        }
      } finally {
        setIsLoadingHistory(false);
        if (fetchError) {
          showSnackbar(fetchError, 'error'); // Show non-auth fetch errors
        } else if (noDataMessage) {
          showSnackbar(noDataMessage, 'info');
        }
      }
    },
    [apiUrl, token, showSnackbar] // Dependencies
  );

  // --- Effect to Fetch Key ---
  useEffect(() => {
    fetchKey();
  }, [fetchKey]); // fetchKey depends on apiUrl, token

  // --- Return Hook State and Functions ---
  return {
    encryptionKey,
    isLoadingKey,
    fetchKey,
    loadHistoricalData,
    historicalSpectrograms,
    historicalPeaks,
    historicalActivity,
    historicalTransients,
    isLoadingHistory,
    historyError,
    authenticationErrorOccurred, // Return the new state
  };
}

export default useApiClient;
