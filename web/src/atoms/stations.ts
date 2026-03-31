import { atom } from 'jotai';
import type { StationMeta } from '@/types/station';

/** All known stations. */
export const stationsAtom = atom<Record<string, StationMeta>>({});

/** Update metadata for a station. */
export const updateStationAtom = atom(null, (get, set, meta: StationMeta) => {
  const stations = { ...get(stationsAtom) };
  stations[meta.id] = meta;
  set(stationsAtom, stations);
});

/** Derived: list of active stations (updated within last 60s). */
export const activeStationsAtom = atom((get) => {
  const stations = get(stationsAtom);
  const now = Date.now();
  return Object.values(stations).filter((s) => now - s.lastUpdate < 60_000);
});

/** Derived: station count. */
export const stationCountAtom = atom((get) => Object.keys(get(stationsAtom)).length);
