import { describe, it, expect } from 'vitest';
import { createStore } from 'jotai';
import { peakDataAtom, updatePeaksAtom, selectedPeaksAtom } from './peaks';
import { selectedStationAtom } from './spectrogram';
import type { TrackedPeak } from '@/types/websocket';

const makePeak = (freq: number): TrackedPeak => ({
  freq,
  amp: 80,
  qFactor: 3.5,
  freqErr: 0.01,
  ampErr: 0.5,
  qErr: 0.1,
  snr: 12,
  trackStatus: 'continuing',
  trackId: `track-${freq}`,
});

describe('peak atoms', () => {
  describe('peakDataAtom', () => {
    it('starts with empty record', () => {
      const store = createStore();
      expect(store.get(peakDataAtom)).toEqual({});
    });
  });

  describe('updatePeaksAtom', () => {
    it('sets peaks for a station', () => {
      const store = createStore();
      const peaks = [makePeak(7.83), makePeak(14.3)];
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks });
      expect(store.get(peakDataAtom)['st-1']).toEqual(peaks);
    });

    it('replaces peaks for an existing station', () => {
      const store = createStore();
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks: [makePeak(7.83)] });
      const newPeaks = [makePeak(14.3)];
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks: newPeaks });
      expect(store.get(peakDataAtom)['st-1']).toEqual(newPeaks);
    });

    it('handles multiple stations', () => {
      const store = createStore();
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks: [makePeak(7.83)] });
      store.set(updatePeaksAtom, { stationId: 'st-2', peaks: [makePeak(14.3)] });
      expect(store.get(peakDataAtom)['st-1']).toHaveLength(1);
      expect(store.get(peakDataAtom)['st-2']).toHaveLength(1);
    });

    it('sets empty peaks array', () => {
      const store = createStore();
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks: [] });
      expect(store.get(peakDataAtom)['st-1']).toEqual([]);
    });
  });

  describe('selectedPeaksAtom', () => {
    it('returns empty array when no station selected', () => {
      const store = createStore();
      expect(store.get(selectedPeaksAtom)).toEqual([]);
    });

    it('returns empty array when selected station has no peaks', () => {
      const store = createStore();
      store.set(selectedStationAtom, 'st-missing');
      expect(store.get(selectedPeaksAtom)).toEqual([]);
    });

    it('returns peaks for selected station', () => {
      const store = createStore();
      const peaks = [makePeak(7.83), makePeak(14.3)];
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks });
      store.set(selectedStationAtom, 'st-1');
      expect(store.get(selectedPeaksAtom)).toEqual(peaks);
    });

    it('updates when selected station changes', () => {
      const store = createStore();
      store.set(updatePeaksAtom, { stationId: 'st-1', peaks: [makePeak(7.83)] });
      store.set(updatePeaksAtom, { stationId: 'st-2', peaks: [makePeak(14.3)] });
      store.set(selectedStationAtom, 'st-1');
      expect(store.get(selectedPeaksAtom)[0].freq).toBe(7.83);
      store.set(selectedStationAtom, 'st-2');
      expect(store.get(selectedPeaksAtom)[0].freq).toBe(14.3);
    });
  });
});
