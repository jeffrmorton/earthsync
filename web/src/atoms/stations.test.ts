import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createStore } from 'jotai';
import { stationsAtom, updateStationAtom, activeStationsAtom, stationCountAtom } from './stations';
import type { StationMeta } from '@/types/station';

function makeStation(id: string, lastUpdate: number): StationMeta {
  return {
    id,
    location: { lat: 37.0, lon: -3.4 },
    lastUpdate,
    noiseFloor: { median: 0.5, std: 0.1 },
    algorithmVersion: '0.1.1',
    calibrationStatus: 'calibrated',
    qualityFlags: [],
    sampleRateHz: 256,
    frequencyResolutionHz: 0.05,
  };
}

describe('station atoms', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('stationsAtom', () => {
    it('starts with empty record', () => {
      const store = createStore();
      expect(store.get(stationsAtom)).toEqual({});
    });
  });

  describe('updateStationAtom', () => {
    it('adds a new station', () => {
      const store = createStore();
      const station = makeStation('st-1', Date.now());
      store.set(updateStationAtom, station);
      expect(store.get(stationsAtom)['st-1']).toEqual(station);
    });

    it('updates an existing station', () => {
      const store = createStore();
      store.set(updateStationAtom, makeStation('st-1', 1000));
      const updated = makeStation('st-1', 2000);
      store.set(updateStationAtom, updated);
      expect(store.get(stationsAtom)['st-1'].lastUpdate).toBe(2000);
    });

    it('does not affect other stations', () => {
      const store = createStore();
      store.set(updateStationAtom, makeStation('st-1', 1000));
      store.set(updateStationAtom, makeStation('st-2', 2000));
      expect(store.get(stationsAtom)['st-1'].lastUpdate).toBe(1000);
      expect(store.get(stationsAtom)['st-2'].lastUpdate).toBe(2000);
    });
  });

  describe('activeStationsAtom', () => {
    it('returns empty array when no stations', () => {
      const store = createStore();
      expect(store.get(activeStationsAtom)).toEqual([]);
    });

    it('returns stations updated within last 60s', () => {
      vi.setSystemTime(100_000);
      const store = createStore();
      store.set(updateStationAtom, makeStation('st-1', Date.now()));
      const active = store.get(activeStationsAtom);
      expect(active).toHaveLength(1);
      expect(active[0].id).toBe('st-1');
    });

    it('excludes stations not updated within 60s', () => {
      vi.setSystemTime(200_000);
      const store = createStore();
      // Station last updated 61 seconds ago
      store.set(updateStationAtom, makeStation('st-old', Date.now() - 61_000));
      // Station last updated 30 seconds ago
      store.set(updateStationAtom, makeStation('st-new', Date.now() - 30_000));
      const active = store.get(activeStationsAtom);
      expect(active).toHaveLength(1);
      expect(active[0].id).toBe('st-new');
    });

    it('returns all active stations', () => {
      vi.setSystemTime(300_000);
      const store = createStore();
      store.set(updateStationAtom, makeStation('st-1', Date.now() - 10_000));
      store.set(updateStationAtom, makeStation('st-2', Date.now() - 20_000));
      store.set(updateStationAtom, makeStation('st-3', Date.now() - 59_999));
      const active = store.get(activeStationsAtom);
      expect(active).toHaveLength(3);
    });
  });

  describe('stationCountAtom', () => {
    it('returns 0 when empty', () => {
      const store = createStore();
      expect(store.get(stationCountAtom)).toBe(0);
    });

    it('returns correct count', () => {
      const store = createStore();
      store.set(updateStationAtom, makeStation('st-1', 1000));
      store.set(updateStationAtom, makeStation('st-2', 2000));
      expect(store.get(stationCountAtom)).toBe(2);
    });

    it('counts all stations including inactive', () => {
      vi.setSystemTime(500_000);
      const store = createStore();
      store.set(updateStationAtom, makeStation('st-old', 0)); // very old
      store.set(updateStationAtom, makeStation('st-new', Date.now()));
      expect(store.get(stationCountAtom)).toBe(2);
    });
  });
});
