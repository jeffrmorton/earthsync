import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QualityPanel } from './QualityPanel';

const baseProps = {
  noiseFloor: { median: 0.01, std: 0.005 },
  qualityFlags: [] as string[],
  algorithmVersion: '0.1.1',
  calibrationStatus: 'uncalibrated',
  sampleRateHz: 256,
  peakCount: 3,
};

describe('QualityPanel', () => {
  it('renders basic quality info', () => {
    render(<QualityPanel {...baseProps} />);
    const panel = screen.getByTestId('quality-panel');
    expect(panel).toBeDefined();
    expect(panel.textContent).toContain('3');
    expect(panel.textContent).toContain('256 Hz');
    expect(panel.textContent).toContain('uncalibrated');
    expect(panel.textContent).toContain('0.1.1');
  });

  it('shows noise floor details', () => {
    render(<QualityPanel {...baseProps} />);
    const panel = screen.getByTestId('quality-panel');
    expect(panel.textContent).toContain('Noise Floor');
    expect(panel.textContent).toContain('1.00e-2');
  });

  it('hides noise floor when null', () => {
    render(<QualityPanel {...baseProps} noiseFloor={null} />);
    const panel = screen.getByTestId('quality-panel');
    expect(panel.textContent).not.toContain('Noise Floor');
  });

  it('shows quality flags', () => {
    render(<QualityPanel {...baseProps} qualityFlags={['clipping', 'mains']} />);
    const panel = screen.getByTestId('quality-panel');
    expect(panel.textContent).toContain('clipping');
    expect(panel.textContent).toContain('mains');
  });

  it('shows no quality issues when flags empty', () => {
    render(<QualityPanel {...baseProps} qualityFlags={[]} />);
    const panel = screen.getByTestId('quality-panel');
    expect(panel.textContent).toContain('No quality issues');
  });

  it('shows calibrated status in green', () => {
    const { container } = render(
      <QualityPanel {...baseProps} calibrationStatus="calibrated" />,
    );
    const greenSpan = container.querySelector('.text-accent-green');
    expect(greenSpan?.textContent).toBe('calibrated');
  });

  it('shows Lorentzian converged status', () => {
    render(<QualityPanel {...baseProps} lorentzianConverged={true} />);
    const status = screen.getByTestId('lorentzian-status');
    expect(status.textContent).toContain('Converged');
  });

  it('shows Lorentzian failed status', () => {
    render(<QualityPanel {...baseProps} lorentzianConverged={false} />);
    const status = screen.getByTestId('lorentzian-status');
    expect(status.textContent).toContain('Failed');
  });

  it('hides Lorentzian status when undefined', () => {
    render(<QualityPanel {...baseProps} />);
    expect(screen.queryByTestId('lorentzian-status')).toBeNull();
  });

  it('shows chi-squared in green when < 2', () => {
    const { container } = render(
      <QualityPanel {...baseProps} chiSquared={1.1} />,
    );
    const chiEl = screen.getByTestId('chi-squared');
    expect(chiEl.textContent).toContain('1.10');
    const greenSpan = chiEl.querySelector('.text-accent-green');
    expect(greenSpan).toBeTruthy();
  });

  it('shows chi-squared in yellow when 2-5', () => {
    render(<QualityPanel {...baseProps} chiSquared={3.5} />);
    const chiEl = screen.getByTestId('chi-squared');
    expect(chiEl.textContent).toContain('3.50');
    const yellowSpan = chiEl.querySelector('.text-accent-yellow');
    expect(yellowSpan).toBeTruthy();
  });

  it('shows chi-squared in red when >= 5', () => {
    render(<QualityPanel {...baseProps} chiSquared={7.2} />);
    const chiEl = screen.getByTestId('chi-squared');
    expect(chiEl.textContent).toContain('7.20');
    const redSpan = chiEl.querySelector('.text-accent-red');
    expect(redSpan).toBeTruthy();
  });

  it('hides chi-squared when null', () => {
    render(<QualityPanel {...baseProps} chiSquared={null} />);
    expect(screen.queryByTestId('chi-squared')).toBeNull();
  });

  it('hides chi-squared when undefined', () => {
    render(<QualityPanel {...baseProps} />);
    expect(screen.queryByTestId('chi-squared')).toBeNull();
  });
});
