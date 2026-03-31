import { atom } from 'jotai';

/** Maximum number of time steps to retain per station. */
const MAX_ROWS = 120;

/** Per-station spectrogram ring buffer: station ID -> rows of 1101 frequency bins. */
export const spectrogramDataAtom = atom<Record<string, number[][]>>({});

/** Add a new spectrogram row for a station. */
export const addSpectrogramRowAtom = atom(
  null,
  (get, set, { stationId, row }: { stationId: string; row: number[] }) => {
    const data = { ...get(spectrogramDataAtom) };
    const rows = [...(data[stationId] ?? []), row];
    data[stationId] = rows.length > MAX_ROWS ? rows.slice(-MAX_ROWS) : rows;
    set(spectrogramDataAtom, data);
  },
);

/** Selected station ID for display. */
export const selectedStationAtom = atom<string | null>(null);

/** Derived: spectrogram rows for the selected station. */
export const selectedSpectrogramAtom = atom((get) => {
  const id = get(selectedStationAtom);
  if (!id) return [];
  return get(spectrogramDataAtom)[id] ?? [];
});
