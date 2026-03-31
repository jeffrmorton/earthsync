import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PeakTrends } from './PeakTrends';

describe('PeakTrends', () => {
  it('shows empty state when no peaks', () => {
    render(<PeakTrends peaks={[]} />);
    const empty = screen.getByTestId('peak-trends-empty');
    expect(empty).toBeDefined();
    expect(empty.textContent).toBe('No peaks detected');
  });

  it('renders peaks with frequency and amplitude', () => {
    const peaks = [
      { freq: 7.83, amp: 0.5, qFactor: null, snr: null, freqErr: null, ampErr: null, qErr: null },
      { freq: 14.3, amp: 0.3, qFactor: null, snr: null, freqErr: null, ampErr: null, qErr: null },
    ];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container).toBeDefined();
    expect(container.textContent).toContain('7.83 Hz');
    expect(container.textContent).toContain('14.30 Hz');
    expect(container.textContent).toContain('A: 0.500');
    expect(container.textContent).toContain('A: 0.300');
  });

  it('renders Q-factor when present', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: 3.5, snr: null, freqErr: null, ampErr: null, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).toContain('Q: 3.5');
  });

  it('does not render Q-factor when null', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: null, freqErr: null, ampErr: null, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).not.toContain('Q:');
  });

  it('renders SNR with green color for high SNR (>= 10)', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: 15.0, freqErr: null, ampErr: null, qErr: null }];
    const { container } = render(<PeakTrends peaks={peaks} />);
    const snrSpan = container.querySelector('.text-accent-green:last-child');
    expect(snrSpan).toBeDefined();
    expect(snrSpan?.textContent).toContain('SNR: 15.0 dB');
  });

  it('renders SNR with yellow color for medium SNR (3-10)', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: 5.0, freqErr: null, ampErr: null, qErr: null }];
    const { container } = render(<PeakTrends peaks={peaks} />);
    const snrSpan = container.querySelector('.text-accent-yellow');
    expect(snrSpan).toBeDefined();
    expect(snrSpan?.textContent).toContain('SNR: 5.0 dB');
  });

  it('renders SNR with red color for low SNR (< 3)', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: 1.5, freqErr: null, ampErr: null, qErr: null }];
    const { container } = render(<PeakTrends peaks={peaks} />);
    const snrSpan = container.querySelector('.text-accent-red');
    expect(snrSpan).toBeDefined();
    expect(snrSpan?.textContent).toContain('SNR: 1.5 dB');
  });

  it('does not render SNR when null', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: null, freqErr: null, ampErr: null, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).not.toContain('SNR:');
  });

  it('renders all fields together', () => {
    const peaks = [{ freq: 20.8, amp: 1.234, qFactor: 5.0, snr: 12.3, freqErr: null, ampErr: null, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).toContain('20.80 Hz');
    expect(container.textContent).toContain('A: 1.234');
    expect(container.textContent).toContain('Q: 5.0');
    expect(container.textContent).toContain('SNR: 12.3 dB');
  });

  it('renders SNR at boundary value 10 as green', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: 10.0, freqErr: null, ampErr: null, qErr: null }];
    const { container } = render(<PeakTrends peaks={peaks} />);
    const greenSpans = container.querySelectorAll('.text-accent-green');
    // amplitude span + SNR span
    const snrFound = Array.from(greenSpans).some((el) =>
      el.textContent?.includes('SNR:'),
    );
    expect(snrFound).toBe(true);
  });

  it('renders SNR at boundary value 3 as yellow', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: 3.0, freqErr: null, ampErr: null, qErr: null }];
    const { container } = render(<PeakTrends peaks={peaks} />);
    const yellowSpan = container.querySelector('.text-accent-yellow');
    expect(yellowSpan?.textContent).toContain('SNR: 3.0 dB');
  });

  it('displays frequency uncertainty when freqErr is present', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: null, freqErr: 0.02, ampErr: null, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).toContain('\u00b10.02');
  });

  it('displays amplitude uncertainty when ampErr is present', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: null, snr: null, freqErr: null, ampErr: 0.01, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).toContain('\u00b10.010');
  });

  it('displays Q-factor uncertainty when qErr is present', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: 3.5, snr: null, freqErr: null, ampErr: null, qErr: 0.3 }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).toContain('Q: 3.5');
    expect(container.textContent).toContain('\u00b10.3');
  });

  it('does not display uncertainties when errors are null', () => {
    const peaks = [{ freq: 7.83, amp: 0.5, qFactor: 3.5, snr: null, freqErr: null, ampErr: null, qErr: null }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).not.toContain('\u00b1');
  });

  it('displays all uncertainties together', () => {
    const peaks = [{ freq: 7.83, amp: 0.34, qFactor: 3.5, snr: 15.2, freqErr: 0.02, ampErr: 0.01, qErr: 0.3 }];
    render(<PeakTrends peaks={peaks} />);
    const container = screen.getByTestId('peak-trends');
    expect(container.textContent).toContain('7.83');
    expect(container.textContent).toContain('\u00b10.02');
    expect(container.textContent).toContain('A: 0.340');
    expect(container.textContent).toContain('\u00b10.010');
    expect(container.textContent).toContain('Q: 3.5');
    expect(container.textContent).toContain('\u00b10.3');
  });
});
