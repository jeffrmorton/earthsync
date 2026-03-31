import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DashboardPage } from './DashboardPage';

const defaultProps = {
  spectrogramData: [] as number[][],
  psdData: [] as number[],
  peaks: [] as Array<{
    freq: number;
    amp: number;
    qFactor: number | null;
    snr: number | null;
    freqErr: number | null;
    ampErr: number | null;
    qErr: number | null;
  }>,
  stations: [],
  selectedStation: null,
  onSelectStation: vi.fn(),
  stationMeta: null,
  lorentzianFit: null,
  activeQBurst: null,
};

describe('DashboardPage', () => {
  it('renders dashboard layout', () => {
    const { container } = render(<DashboardPage {...defaultProps} />);
    expect(container.querySelector('[data-testid="dashboard-layout"]')).toBeTruthy();
  });

  it('renders with empty data', () => {
    render(<DashboardPage {...defaultProps} />);
    expect(screen.getByText('Spectrogram')).toBeTruthy();
    expect(screen.getByText('Power Spectral Density')).toBeTruthy();
    expect(screen.getByText('Detected Peaks')).toBeTruthy();
  });

  it('renders station globe', () => {
    render(
      <DashboardPage
        {...defaultProps}
        stations={[{ id: 'sim1', location: { lat: 37, lon: -3 }, lastUpdate: Date.now() }]}
      />,
    );
    expect(screen.getByText('Station Network')).toBeTruthy();
    expect(screen.getByTestId('mock-globe')).toBeTruthy();
  });

  it('renders quality panel when station selected', () => {
    render(
      <DashboardPage
        {...defaultProps}
        selectedStation="sim1"
        stationMeta={{
          noiseFloor: { median: 0.01, std: 0.005 },
          algorithmVersion: '0.1.1',
          calibrationStatus: 'uncalibrated',
          qualityFlags: [],
          sampleRateHz: 256,
        }}
      />,
    );
    expect(screen.getByTestId('quality-panel')).toBeTruthy();
  });

  it('shows waiting message when no station selected', () => {
    render(<DashboardPage {...defaultProps} />);
    expect(screen.getByText('Select a station')).toBeTruthy();
  });

  it('passes lorentzian convergence status to quality panel', () => {
    render(
      <DashboardPage
        {...defaultProps}
        selectedStation="sim1"
        stationMeta={{
          noiseFloor: { median: 0.01, std: 0.005 },
          algorithmVersion: '0.1.1',
          calibrationStatus: 'uncalibrated',
          qualityFlags: [],
          sampleRateHz: 256,
        }}
        lorentzianFit={{
          modes: [{ freq: 7.83, amp: 0.34, q_factor: 3.5 }],
          background: { slope: 0.0, intercept: 0.01 },
          converged: true,
          chi_squared: 1.42,
          degrees_of_freedom: 1090,
        }}
      />,
    );
    expect(screen.getByTestId('lorentzian-status')).toBeTruthy();
    expect(screen.getByTestId('lorentzian-status').textContent).toContain('Converged');
    expect(screen.getByTestId('chi-squared')).toBeTruthy();
    expect(screen.getByTestId('chi-squared').textContent).toContain('1.42');
  });

  it('renders without lorentzianFit prop', () => {
    render(
      <DashboardPage
        {...defaultProps}
        selectedStation="sim1"
        stationMeta={{
          noiseFloor: { median: 0.01, std: 0.005 },
          algorithmVersion: '0.1.1',
          calibrationStatus: 'uncalibrated',
          qualityFlags: [],
          sampleRateHz: 256,
        }}
      />,
    );
    expect(screen.getByTestId('quality-panel')).toBeTruthy();
  });
});
