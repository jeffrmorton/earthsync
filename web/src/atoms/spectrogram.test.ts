import { describe, it, expect } from 'vitest';
import { createStore } from 'jotai';
import {
  spectrogramDataAtom,
  addSpectrogramRowAtom,
  selectedStationAtom,
  selectedSpectrogramAtom,
} from './spectrogram';

describe('spectrogram atoms', () => {
  describe('spectrogramDataAtom', () => {
    it('starts with empty record', () => {
      const store = createStore();
      expect(store.get(spectrogramDataAtom)).toEqual({});
    });
  });

  describe('addSpectrogramRowAtom', () => {
    it('adds a row for a new station', () => {
      const store = createStore();
      const row = [1, 2, 3];
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row });
      const data = store.get(spectrogramDataAtom);
      expect(data['st-1']).toEqual([[1, 2, 3]]);
    });

    it('appends rows for existing station', () => {
      const store = createStore();
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [1] });
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [2] });
      const data = store.get(spectrogramDataAtom);
      expect(data['st-1']).toEqual([[1], [2]]);
    });

    it('handles multiple stations independently', () => {
      const store = createStore();
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [1] });
      store.set(addSpectrogramRowAtom, { stationId: 'st-2', row: [2] });
      const data = store.get(spectrogramDataAtom);
      expect(data['st-1']).toEqual([[1]]);
      expect(data['st-2']).toEqual([[2]]);
    });

    it('trims to MAX_ROWS (120) when exceeded', () => {
      const store = createStore();
      // Add 125 rows
      for (let i = 0; i < 125; i++) {
        store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [i] });
      }
      const data = store.get(spectrogramDataAtom);
      expect(data['st-1']).toHaveLength(120);
      // Should keep the last 120 rows (5 through 124)
      expect(data['st-1'][0]).toEqual([5]);
      expect(data['st-1'][119]).toEqual([124]);
    });

    it('does not trim at exactly MAX_ROWS', () => {
      const store = createStore();
      for (let i = 0; i < 120; i++) {
        store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [i] });
      }
      const data = store.get(spectrogramDataAtom);
      expect(data['st-1']).toHaveLength(120);
      expect(data['st-1'][0]).toEqual([0]);
    });
  });

  describe('selectedStationAtom', () => {
    it('starts as null', () => {
      const store = createStore();
      expect(store.get(selectedStationAtom)).toBeNull();
    });

    it('can be set to a station ID', () => {
      const store = createStore();
      store.set(selectedStationAtom, 'st-1');
      expect(store.get(selectedStationAtom)).toBe('st-1');
    });
  });

  describe('selectedSpectrogramAtom', () => {
    it('returns empty array when no station selected', () => {
      const store = createStore();
      expect(store.get(selectedSpectrogramAtom)).toEqual([]);
    });

    it('returns empty array when selected station has no data', () => {
      const store = createStore();
      store.set(selectedStationAtom, 'st-unknown');
      expect(store.get(selectedSpectrogramAtom)).toEqual([]);
    });

    it('returns rows for the selected station', () => {
      const store = createStore();
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [10, 20] });
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [30, 40] });
      store.set(selectedStationAtom, 'st-1');
      expect(store.get(selectedSpectrogramAtom)).toEqual([
        [10, 20],
        [30, 40],
      ]);
    });

    it('updates when selected station changes', () => {
      const store = createStore();
      store.set(addSpectrogramRowAtom, { stationId: 'st-1', row: [1] });
      store.set(addSpectrogramRowAtom, { stationId: 'st-2', row: [2] });
      store.set(selectedStationAtom, 'st-1');
      expect(store.get(selectedSpectrogramAtom)).toEqual([[1]]);
      store.set(selectedStationAtom, 'st-2');
      expect(store.get(selectedSpectrogramAtom)).toEqual([[2]]);
    });
  });
});
