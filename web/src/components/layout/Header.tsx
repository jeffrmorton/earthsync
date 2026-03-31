interface HeaderProps {
  connected: boolean;
  stationCount: number;
  onToggleTheme?: () => void;
  activeQBurst?: { stationId: string; details: string } | null;
}

export function Header({ connected, stationCount, onToggleTheme, activeQBurst }: HeaderProps) {
  return (
    <header
      className="flex items-center justify-between px-4 py-3 bg-bg-secondary border-b border-border"
      data-testid="header"
    >
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-bold text-text-primary">EarthSync</h1>
        <span className="text-xs text-text-muted">Schumann Resonance Monitor</span>
      </div>
      <div className="flex items-center gap-4">
        {activeQBurst && (
          <div
            className="flex items-center gap-2 px-2 py-1 bg-accent-yellow/20 rounded animate-pulse"
            data-testid="qburst-indicator"
          >
            <span className="text-accent-yellow text-xs font-bold">Q-BURST</span>
            <span className="text-xs text-text-secondary">{activeQBurst.stationId}</span>
          </div>
        )}
        <div className="flex items-center gap-2">
          <div
            className={`w-2 h-2 rounded-full ${connected ? 'bg-accent-green' : 'bg-accent-red'}`}
          />
          <span className="text-xs text-text-secondary">
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
        <span className="text-xs text-text-muted">
          {stationCount} station{stationCount !== 1 ? 's' : ''}
        </span>
        {onToggleTheme && (
          <button
            onClick={onToggleTheme}
            className="text-text-secondary hover:text-text-primary text-sm"
            data-testid="theme-toggle"
          >
            Theme
          </button>
        )}
      </div>
    </header>
  );
}
