import { atom } from 'jotai';
import type { TrackedPeak } from '@/types/websocket';
import { selectedStationAtom } from '@/atoms/spectrogram';

/** Current peaks per station. */
export const peakDataAtom = atom<Record<string, TrackedPeak[]>>({});

/** Update peaks for a station. */
export const updatePeaksAtom = atom(
  null,
  (get, set, { stationId, peaks }: { stationId: string; peaks: TrackedPeak[] }) => {
    const data = { ...get(peakDataAtom) };
    data[stationId] = peaks;
    set(peakDataAtom, data);
  },
);

/** Derived: peaks for the selected station. */
export const selectedPeaksAtom = atom((get) => {
  const id = get(selectedStationAtom);
  if (!id) return [];
  return get(peakDataAtom)[id] ?? [];
});
