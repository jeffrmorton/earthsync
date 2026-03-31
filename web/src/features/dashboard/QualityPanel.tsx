interface QualityPanelProps {
  noiseFloor: { median: number; std: number } | null;
  qualityFlags: string[];
  algorithmVersion: string;
  calibrationStatus: string;
  sampleRateHz: number;
  peakCount: number;
  lorentzianConverged?: boolean;
  chiSquared?: number | null;
}

export function QualityPanel({
  noiseFloor,
  qualityFlags,
  algorithmVersion,
  calibrationStatus,
  sampleRateHz,
  peakCount,
  lorentzianConverged,
  chiSquared,
}: QualityPanelProps) {
  return (
    <div className="space-y-3 text-sm" data-testid="quality-panel">
      <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
        Quality
      </h3>

      <div className="space-y-1">
        <div className="flex justify-between">
          <span className="text-text-muted">Peaks</span>
          <span className="text-text-primary font-mono">{peakCount}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-text-muted">Sample Rate</span>
          <span className="text-text-primary font-mono">{sampleRateHz} Hz</span>
        </div>
        <div className="flex justify-between">
          <span className="text-text-muted">Calibration</span>
          <span
            className={
              calibrationStatus === 'calibrated' ? 'text-accent-green' : 'text-accent-yellow'
            }
          >
            {calibrationStatus}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-text-muted">Algorithm</span>
          <span className="text-text-primary font-mono">{algorithmVersion}</span>
        </div>
        {lorentzianConverged !== undefined && (
          <div className="flex justify-between" data-testid="lorentzian-status">
            <span className="text-text-muted">Lorentzian Fit</span>
            <span className={lorentzianConverged ? 'text-accent-green' : 'text-accent-red'}>
              {lorentzianConverged ? 'Converged' : 'Failed'}
            </span>
          </div>
        )}
        {chiSquared != null && (
          <div className="flex justify-between" data-testid="chi-squared">
            <span className="text-text-muted">Chi²/dof</span>
            <span
              className={`font-mono ${chiSquared < 2 ? 'text-accent-green' : chiSquared < 5 ? 'text-accent-yellow' : 'text-accent-red'}`}
            >
              {chiSquared.toFixed(2)}
            </span>
          </div>
        )}
      </div>

      {noiseFloor && (
        <div className="space-y-1">
          <h4 className="text-xs text-text-muted">Noise Floor</h4>
          <div className="flex justify-between">
            <span className="text-text-muted">Median</span>
            <span className="font-mono text-text-primary">{noiseFloor.median.toExponential(2)}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-text-muted">Std</span>
            <span className="font-mono text-text-primary">{noiseFloor.std.toExponential(2)}</span>
          </div>
        </div>
      )}

      {qualityFlags.length > 0 && (
        <div className="space-y-1">
          <h4 className="text-xs text-text-muted">Flags</h4>
          {qualityFlags.map((flag) => (
            <span
              key={flag}
              className="inline-block px-2 py-0.5 mr-1 text-xs rounded bg-accent-red/20 text-accent-red"
            >
              {flag}
            </span>
          ))}
        </div>
      )}

      {qualityFlags.length === 0 && (
        <div className="text-accent-green text-xs">No quality issues</div>
      )}
    </div>
  );
}
