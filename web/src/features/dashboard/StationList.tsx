interface Station {
  id: string;
  location: { lat: number; lon: number };
  lastUpdate: number;
}

interface StationListProps {
  stations: Station[];
  selectedStation: string | null;
  onSelect: (id: string) => void;
}

export function StationList({ stations, selectedStation, onSelect }: StationListProps) {
  if (stations.length === 0) {
    return (
      <div className="text-text-muted text-sm p-2" data-testid="station-list-empty">
        Waiting for stations...
      </div>
    );
  }

  return (
    <div className="space-y-3" data-testid="station-list">
      <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
        Stations
      </h3>
      <div className="space-y-1">
        {stations.map((s) => {
          const active = Date.now() - s.lastUpdate < 30000;
          return (
            <button
              key={s.id}
              onClick={() => onSelect(s.id)}
              className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                selectedStation === s.id
                  ? 'bg-bg-hover text-text-primary'
                  : 'text-text-secondary hover:bg-bg-hover'
              }`}
            >
              <div
                className={`w-2 h-2 rounded-full ${active ? 'bg-accent-green' : 'bg-accent-red'}`}
              />
              <div>
                <div className="font-mono text-xs">{s.id}</div>
                <div className="text-[10px] text-text-muted">
                  {s.location.lat.toFixed(1)}, {s.location.lon.toFixed(1)}
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
