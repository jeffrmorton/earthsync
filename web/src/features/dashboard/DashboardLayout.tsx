import type { ReactNode } from 'react';

interface DashboardLayoutProps {
  spectrogram: ReactNode;
  psd: ReactNode;
  peaks: ReactNode;
  globe: ReactNode;
  quality: ReactNode;
}

export function DashboardLayout({
  spectrogram,
  psd,
  peaks,
  globe,
  quality,
}: DashboardLayoutProps) {
  return (
    <div
      className="grid grid-cols-[1fr_320px] items-start gap-2 p-2"
      data-testid="dashboard-layout"
    >
      {/* Left column: stacked panels */}
      <div className="space-y-2">
        <div className="bg-bg-panel rounded-lg p-3">{spectrogram}</div>
        <div className="bg-bg-panel rounded-lg p-3">{psd}</div>
        <div className="bg-bg-panel rounded-lg p-3">{peaks}</div>
      </div>
      {/* Right column: globe + quality */}
      <div className="space-y-2">
        <div className="bg-bg-panel rounded-lg p-3">{globe}</div>
        <div className="bg-bg-panel rounded-lg p-3">{quality}</div>
      </div>
    </div>
  );
}
