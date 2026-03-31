import { Provider } from 'jotai';
import { useEffect, useRef, useState } from 'react';
import { DashboardPage } from '@/features/dashboard/DashboardPage';
import { Header } from '@/components/layout/Header';

const MAX_ROWS = 360;

type Page = 'signals' | 'stations' | 'settings';

interface PeakData {
  freq: number;
  amp: number;
  qFactor: number | null;
  snr: number | null;
  freqErr: number | null;
  ampErr: number | null;
  qErr: number | null;
}

interface StationInfo {
  id: string;
  location: { lat: number; lon: number };
  lastUpdate: number;
}

interface StationMeta {
  noiseFloor: { median: number; std: number } | null;
  algorithmVersion: string;
  calibrationStatus: string;
  qualityFlags: string[];
  sampleRateHz: number;
}

function Dashboard() {
  const [connected, setConnected] = useState(false);
  const [spectrogramRows, setSpectrogramRows] = useState<Record<string, number[][]>>({});
  const [peakData, setPeakData] = useState<Record<string, PeakData[]>>({});
  const [stationMap, setStationMap] = useState<Record<string, StationInfo>>({});
  const [metaMap, setMetaMap] = useState<Record<string, StationMeta>>({});
  const [selectedStation, setSelectedStation] = useState<string | null>(null);
  const [latestPsd, setLatestPsd] = useState<number[]>([]);
  const [currentPage, setCurrentPage] = useState<Page>('signals');
  const [lorentzianFits, setLorentzianFits] = useState<Record<string, any>>({});
  const [activeQBurst, setActiveQBurst] = useState<{ stationId: string; details: string } | null>(
    null,
  );
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const wsRef = useRef<WebSocket | undefined>(undefined);

  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/data`;

    function connect() {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        reconnectTimerRef.current = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (event) => {
        try {
          const p = JSON.parse(event.data);
          const id: string = p.station_id;
          if (!id) return;

          setSpectrogramRows((prev) => {
            const rows = [...(prev[id] ?? []), p.spectrogram];
            return { ...prev, [id]: rows.length > MAX_ROWS ? rows.slice(-MAX_ROWS) : rows };
          });

          const peaks: PeakData[] = (p.detected_peaks ?? []).map(
            (pk: Record<string, unknown>) => ({
              freq: pk.freq as number,
              amp: pk.amp as number,
              qFactor: (pk.q_factor as number | null) ?? null,
              snr: (pk.snr as number | null) ?? null,
              freqErr: (pk.freq_err as number | null) ?? null,
              ampErr: (pk.amp_err as number | null) ?? null,
              qErr: (pk.q_err as number | null) ?? null,
            }),
          );
          setPeakData((prev) => ({ ...prev, [id]: peaks }));

          // Lorentzian fit
          if (p.lorentzian_fit) {
            setLorentzianFits((prev) => ({ ...prev, [id]: p.lorentzian_fit }));
          }

          // Q-burst transient
          if (p.transient_info?.type !== 'none' && p.transient_info?.type != null) {
            setActiveQBurst({
              stationId: id,
              details: p.transient_info.details || 'Q-burst detected',
            });
            setTimeout(() => setActiveQBurst(null), 5000);
          }

          setStationMap((prev) => ({
            ...prev,
            [id]: { id, location: p.location ?? { lat: 0, lon: 0 }, lastUpdate: Date.now() },
          }));

          setMetaMap((prev) => ({
            ...prev,
            [id]: {
              noiseFloor: p.noise_floor ?? null,
              algorithmVersion: p.algorithm_version ?? '0.1.1',
              calibrationStatus: p.calibration_status ?? 'uncalibrated',
              qualityFlags: p.quality_flags ?? [],
              sampleRateHz: p.sample_rate_hz ?? 256,
            },
          }));

          if (!selectedStation || id === selectedStation) {
            setLatestPsd(p.spectrogram);
          }
          setSelectedStation((prev) => prev ?? id);
        } catch {
          /* ignore */
        }
      };
    }

    connect();
    return () => {
      clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [selectedStation]);

  const stations = Object.values(stationMap);
  const displayRows = selectedStation ? (spectrogramRows[selectedStation] ?? []) : [];
  const displayPeaks = selectedStation ? (peakData[selectedStation] ?? []) : [];
  const stationMeta = selectedStation ? (metaMap[selectedStation] ?? null) : null;
  const currentLorentzianFit = selectedStation ? (lorentzianFits[selectedStation] ?? null) : null;

  const pages: { id: Page; label: string; icon: string }[] = [
    { id: 'signals', label: 'Signals', icon: '~' },
    { id: 'stations', label: 'Stations', icon: '@' },
    { id: 'settings', label: 'Settings', icon: '#' },
  ];

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary flex flex-col">
      <Header connected={connected} stationCount={stations.length} activeQBurst={activeQBurst} />
      <div className="flex flex-1 overflow-hidden">
        {/* Left sidebar like Lucid */}
        <nav className="w-48 bg-bg-secondary border-r border-border flex flex-col" data-testid="sidebar">
          <div className="p-3 space-y-1">
            {pages.map((page) => (
              <button
                key={page.id}
                onClick={() => setCurrentPage(page.id)}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 transition-colors ${
                  currentPage === page.id
                    ? 'bg-bg-hover text-text-primary'
                    : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary'
                }`}
              >
                <span className="font-mono text-accent-blue">{page.icon}</span>
                {page.label}
              </button>
            ))}
          </div>

          {/* Station selector in sidebar */}
          <div className="mt-4 px-3 flex-1 overflow-y-auto">
            <h3 className="text-[10px] font-semibold text-text-muted uppercase tracking-wider mb-2">
              Active Stations
            </h3>
            <div className="space-y-0.5">
              {stations.map((s) => {
                const active = Date.now() - s.lastUpdate < 30000;
                return (
                  <button
                    key={s.id}
                    onClick={() => setSelectedStation(s.id)}
                    className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center gap-2 ${
                      selectedStation === s.id
                        ? 'bg-bg-hover text-text-primary'
                        : 'text-text-secondary hover:bg-bg-hover'
                    }`}
                  >
                    <div className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-accent-green' : 'bg-accent-red'}`} />
                    <span className="font-mono">{s.id}</span>
                  </button>
                );
              })}
              {stations.length === 0 && (
                <div className="text-text-muted text-[10px] py-2">Waiting for data...</div>
              )}
            </div>
          </div>
        </nav>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto">
          {currentPage === 'signals' && (
            <DashboardPage
              spectrogramData={displayRows}
              psdData={latestPsd}
              peaks={displayPeaks}
              stations={stations}
              selectedStation={selectedStation}
              onSelectStation={setSelectedStation}
              stationMeta={stationMeta}
              lorentzianFit={currentLorentzianFit}
              activeQBurst={activeQBurst}
            />
          )}
          {currentPage === 'stations' && (
            <div className="p-4 space-y-4">
              <h2 className="text-lg font-bold">Station Management</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {stations.map((s) => {
                  const meta = metaMap[s.id];
                  const active = Date.now() - s.lastUpdate < 30000;
                  return (
                    <div key={s.id} className="bg-bg-panel rounded-lg p-4 border border-border">
                      <div className="flex items-center gap-2 mb-3">
                        <div className={`w-2 h-2 rounded-full ${active ? 'bg-accent-green' : 'bg-accent-red'}`} />
                        <span className="font-mono font-bold">{s.id}</span>
                      </div>
                      <div className="space-y-1 text-sm text-text-secondary">
                        <div>Location: {s.location.lat.toFixed(2)}, {s.location.lon.toFixed(2)}</div>
                        <div>Sample Rate: {meta?.sampleRateHz ?? '—'} Hz</div>
                        <div>Calibration: {meta?.calibrationStatus ?? '—'}</div>
                        <div>Algorithm: {meta?.algorithmVersion ?? '—'}</div>
                        {meta?.noiseFloor && (
                          <div>Noise Floor: {meta.noiseFloor.median.toExponential(2)}</div>
                        )}
                        {meta?.qualityFlags && meta.qualityFlags.length > 0 && (
                          <div className="flex gap-1 mt-1">
                            {meta.qualityFlags.map((f) => (
                              <span key={f} className="px-1 py-0.5 text-xs bg-accent-red/20 text-accent-red rounded">
                                {f}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
              {stations.length === 0 && (
                <div className="text-text-muted">No stations connected yet.</div>
              )}
            </div>
          )}
          {currentPage === 'settings' && (
            <div className="p-4 space-y-4">
              <h2 className="text-lg font-bold">Settings</h2>
              <div className="bg-bg-panel rounded-lg p-4 border border-border space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-text-secondary">Version</span>
                  <span className="font-mono">0.1.1</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-text-secondary">WebSocket</span>
                  <span className={connected ? 'text-accent-green' : 'text-accent-red'}>
                    {connected ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-text-secondary">Stations</span>
                  <span className="font-mono">{stations.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-text-secondary">Display Grid</span>
                  <span className="font-mono">1101 pts, 0-55 Hz</span>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <Provider>
      <Dashboard />
    </Provider>
  );
}
