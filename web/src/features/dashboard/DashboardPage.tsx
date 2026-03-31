import { SpectrogramCanvas } from '@/components/viz/SpectrogramCanvas';
import { PSDCurve } from '@/components/viz/PSDCurve';
import { PeakTrends } from '@/components/viz/PeakTrends';
import { StationGlobe } from '@/components/viz/StationGlobe';
import { DashboardLayout } from './DashboardLayout';
import { QualityPanel } from './QualityPanel';

interface Station {
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

interface LorentzianFitData {
  modes: Array<{ freq: number; amp: number; q_factor: number }>;
  background: { slope: number; intercept: number };
  converged: boolean;
  chi_squared?: number | null;
  degrees_of_freedom?: number;
}

interface DashboardPageProps {
  spectrogramData: number[][];
  psdData: number[];
  peaks: Array<{
    freq: number;
    amp: number;
    qFactor: number | null;
    snr: number | null;
    freqErr: number | null;
    ampErr: number | null;
    qErr: number | null;
  }>;
  stations: Station[];
  selectedStation: string | null;
  onSelectStation: (id: string) => void;
  stationMeta: StationMeta | null;
  lorentzianFit?: LorentzianFitData | null;
  activeQBurst?: { stationId: string; details: string } | null;
}

export function DashboardPage({
  spectrogramData,
  psdData,
  peaks,
  stations,
  selectedStation,
  onSelectStation,
  stationMeta,
  lorentzianFit,
}: DashboardPageProps) {
  return (
    <DashboardLayout
      spectrogram={
        <div>
          <h3 className="text-xs font-semibold text-text-secondary uppercase mb-2">
            Spectrogram
            {spectrogramData.length > 0 && (
              <span className="ml-2 text-text-muted font-normal">
                {spectrogramData.length} rows &times; {spectrogramData[0]?.length ?? 0} bins
              </span>
            )}
          </h3>
          <SpectrogramCanvas data={spectrogramData} />
        </div>
      }
      psd={
        <div>
          <h3 className="text-xs font-semibold text-text-secondary uppercase mb-2">
            Power Spectral Density
          </h3>
          <PSDCurve psd={psdData} lorentzianFit={lorentzianFit} />
        </div>
      }
      peaks={
        <div>
          <h3 className="text-xs font-semibold text-text-secondary uppercase mb-2">
            Detected Peaks
            {peaks.length > 0 && (
              <span className="ml-2 text-text-muted font-normal">{peaks.length} modes</span>
            )}
          </h3>
          <PeakTrends peaks={peaks} />
        </div>
      }
      globe={
        <div>
          <h3 className="text-xs font-semibold text-text-secondary uppercase mb-2">
            Station Network
          </h3>
          <StationGlobe
            stations={stations.map((s) => ({
              id: s.id,
              lat: s.location.lat,
              lng: s.location.lon,
              active: Date.now() - s.lastUpdate < 30000,
            }))}
            selectedStation={selectedStation}
            onSelect={onSelectStation}
          />
        </div>
      }
      quality={
        stationMeta ? (
          <QualityPanel
            noiseFloor={stationMeta.noiseFloor}
            qualityFlags={stationMeta.qualityFlags}
            algorithmVersion={stationMeta.algorithmVersion}
            calibrationStatus={stationMeta.calibrationStatus}
            sampleRateHz={stationMeta.sampleRateHz}
            peakCount={peaks.length}
            lorentzianConverged={lorentzianFit?.converged}
            chiSquared={lorentzianFit?.chi_squared ?? null}
          />
        ) : (
          <div className="text-text-muted text-sm p-2" data-testid="quality-waiting">
            Select a station
          </div>
        )
      }
    />
  );
}
