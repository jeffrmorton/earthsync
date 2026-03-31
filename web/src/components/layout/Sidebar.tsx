interface SidebarProps {
  stations: Array<{ id: string; location: { lat: number; lon: number } }>;
  selectedStation: string | null;
  onSelectStation: (id: string | null) => void;
}

export function Sidebar({
  stations,
  selectedStation,
  onSelectStation,
}: SidebarProps) {
  return (
    <aside
      className="w-64 bg-bg-secondary border-r border-border p-4 space-y-4"
      data-testid="sidebar"
    >
      <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
        Stations
      </h2>
      <div className="space-y-1">
        <button
          onClick={() => onSelectStation(null)}
          className={`w-full text-left px-3 py-2 rounded text-sm ${!selectedStation ? 'bg-bg-hover text-text-primary' : 'text-text-secondary hover:bg-bg-hover'}`}
          data-testid="station-all"
        >
          All Stations
        </button>
        {stations.map((s) => (
          <button
            key={s.id}
            onClick={() => onSelectStation(s.id)}
            className={`w-full text-left px-3 py-2 rounded text-sm ${selectedStation === s.id ? 'bg-bg-hover text-text-primary' : 'text-text-secondary hover:bg-bg-hover'}`}
            data-testid={`station-${s.id}`}
          >
            {s.id}
            <span className="text-xs text-text-muted ml-2">
              {s.location.lat.toFixed(1)}, {s.location.lon.toFixed(1)}
            </span>
          </button>
        ))}
      </div>
    </aside>
  );
}
