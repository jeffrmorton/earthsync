interface PeakTrendsProps {
  peaks: Array<{
    freq: number;
    amp: number;
    qFactor: number | null;
    snr: number | null;
    freqErr: number | null;
    ampErr: number | null;
    qErr: number | null;
  }>;
}

export function PeakTrends({ peaks }: PeakTrendsProps) {
  if (peaks.length === 0) {
    return (
      <div className="text-text-muted text-sm p-4" data-testid="peak-trends-empty">
        No peaks detected
      </div>
    );
  }
  return (
    <div className="space-y-1 text-sm font-mono" data-testid="peak-trends">
      {peaks.map((p, i) => (
        <div
          key={`peak-${i}-${p.freq.toFixed(2)}`}
          className="flex justify-between px-2 py-1 bg-bg-hover rounded"
        >
          <span className="text-accent-blue">{p.freq.toFixed(2)}{p.freqErr != null ? ` \u00b1${p.freqErr.toFixed(2)}` : ''} Hz</span>
          <span className="text-accent-green">A: {p.amp.toFixed(3)}{p.ampErr != null ? ` \u00b1${p.ampErr.toFixed(3)}` : ''}</span>
          {p.qFactor != null && (
            <span className="text-accent-yellow">Q: {p.qFactor.toFixed(1)}{p.qErr != null ? ` \u00b1${p.qErr.toFixed(1)}` : ''}</span>
          )}
          {p.snr != null && (
            <span
              className={
                p.snr >= 10
                  ? 'text-accent-green'
                  : p.snr >= 3
                    ? 'text-accent-yellow'
                    : 'text-accent-red'
              }
            >
              SNR: {p.snr.toFixed(1)} dB
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
