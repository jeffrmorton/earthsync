import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PSDCurve, drawPSD } from './PSDCurve';

function createMockCtx() {
  return {
    fillStyle: '',
    strokeStyle: '',
    lineWidth: 0,
    font: '',
    fillRect: vi.fn(),
    fillText: vi.fn(),
    setLineDash: vi.fn(),
    beginPath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    stroke: vi.fn(),
  } as unknown as CanvasRenderingContext2D;
}

describe('drawPSD', () => {
  it('clears canvas with background color when psd is empty', () => {
    const ctx = createMockCtx();
    drawPSD(ctx, [], 55, 800, 150);

    expect(ctx.fillRect).toHaveBeenCalledWith(0, 0, 800, 150);
    // Should not draw any curve
    expect(ctx.stroke).not.toHaveBeenCalled();
  });

  it('draws SR mode markers and PSD curve for non-empty data', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100, 50, 5];
    drawPSD(ctx, psd, 55, 800, 150);

    // Should set line dash for SR markers
    expect(ctx.setLineDash).toHaveBeenCalledWith([4, 4]);
    // Should reset line dash
    expect(ctx.setLineDash).toHaveBeenCalledWith([]);
    // Should draw the PSD curve
    expect(ctx.beginPath).toHaveBeenCalled();
    expect(ctx.moveTo).toHaveBeenCalled();
    expect(ctx.lineTo).toHaveBeenCalled();
    expect(ctx.stroke).toHaveBeenCalled();
    // Should draw axis labels
    expect(ctx.fillText).toHaveBeenCalledWith('0 Hz', 4, 146);
    expect(ctx.fillText).toHaveBeenCalledWith('55 Hz', 760, 146);
    expect(ctx.fillText).toHaveBeenCalledWith('PSD (dB)', 4, 12);
  });

  it('uses custom Schumann frequencies', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100];
    const customFreqs = [8.0, 15.0];
    drawPSD(ctx, psd, 55, 800, 150, customFreqs);

    // beginPath called for each SR marker + the PSD curve
    expect(ctx.beginPath).toHaveBeenCalledTimes(customFreqs.length + 1);
  });

  it('uses default Schumann frequencies when none provided', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100];
    drawPSD(ctx, psd, 55, 800, 150);

    // 5 default SR markers + 1 PSD curve = 6 beginPath calls
    expect(ctx.beginPath).toHaveBeenCalledTimes(6);
  });

  it('handles uniform PSD values (max === min in dB)', () => {
    const ctx = createMockCtx();
    const psd = [10, 10, 10];
    drawPSD(ctx, psd, 55, 800, 150);

    expect(ctx.stroke).toHaveBeenCalled();
  });

  it('handles very small PSD values (near zero)', () => {
    const ctx = createMockCtx();
    const psd = [0, 1e-30, 0];
    drawPSD(ctx, psd, 55, 800, 150);

    expect(ctx.stroke).toHaveBeenCalled();
  });

  it('draws Lorentzian fit overlay when converged', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100, 50, 5];
    const fit = {
      modes: [{ freq: 7.83, amp: 0.34, q_factor: 3.5 }],
      background: { slope: 0.0, intercept: 0.01 },
      converged: true,
    };
    drawPSD(ctx, psd, 55, 800, 150, undefined, fit);

    // Should draw a dashed line for the Lorentzian fit
    expect(ctx.setLineDash).toHaveBeenCalledWith([4, 4]);
    // Should draw the label
    expect(ctx.fillText).toHaveBeenCalledWith('Lorentzian fit', 710, 12);
  });

  it('does not draw Lorentzian overlay when not converged', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100, 50, 5];
    const fit = {
      modes: [{ freq: 7.83, amp: 0.34, q_factor: 3.5 }],
      background: { slope: 0.0, intercept: 0.01 },
      converged: false,
    };
    drawPSD(ctx, psd, 55, 800, 150, undefined, fit);

    const fillTextCalls = (ctx.fillText as ReturnType<typeof vi.fn>).mock.calls;
    const hasLorentzianLabel = fillTextCalls.some(
      (call: unknown[]) => call[0] === 'Lorentzian fit',
    );
    expect(hasLorentzianLabel).toBe(false);
  });

  it('does not draw Lorentzian overlay when modes array is empty', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100, 50, 5];
    const fit = {
      modes: [],
      background: { slope: 0.0, intercept: 0.01 },
      converged: true,
    };
    drawPSD(ctx, psd, 55, 800, 150, undefined, fit);

    const fillTextCalls = (ctx.fillText as ReturnType<typeof vi.fn>).mock.calls;
    const hasLorentzianLabel = fillTextCalls.some(
      (call: unknown[]) => call[0] === 'Lorentzian fit',
    );
    expect(hasLorentzianLabel).toBe(false);
  });

  it('does not draw Lorentzian overlay when fit is null', () => {
    const ctx = createMockCtx();
    const psd = [1, 10, 100, 50, 5];
    drawPSD(ctx, psd, 55, 800, 150, undefined, null);

    const fillTextCalls = (ctx.fillText as ReturnType<typeof vi.fn>).mock.calls;
    const hasLorentzianLabel = fillTextCalls.some(
      (call: unknown[]) => call[0] === 'Lorentzian fit',
    );
    expect(hasLorentzianLabel).toBe(false);
  });
});

describe('PSDCurve component', () => {
  beforeEach(() => {
    HTMLCanvasElement.prototype.getContext = vi.fn(() =>
      createMockCtx(),
    ) as never;
  });

  it('renders a canvas element', () => {
    render(<PSDCurve psd={[]} />);
    const canvas = screen.getByTestId('psd-canvas');
    expect(canvas).toBeDefined();
    expect(canvas.tagName).toBe('CANVAS');
  });

  it('uses default dimensions', () => {
    render(<PSDCurve psd={[]} />);
    const canvas = screen.getByTestId('psd-canvas') as HTMLCanvasElement;
    expect(canvas.width).toBe(800);
    expect(canvas.height).toBe(150);
  });

  it('accepts custom dimensions and maxHz', () => {
    render(<PSDCurve psd={[]} width={600} height={200} maxHz={100} />);
    const canvas = screen.getByTestId('psd-canvas') as HTMLCanvasElement;
    expect(canvas.width).toBe(600);
    expect(canvas.height).toBe(200);
  });

  it('calls getContext on mount', () => {
    render(<PSDCurve psd={[1, 2, 3]} />);
    expect(HTMLCanvasElement.prototype.getContext).toHaveBeenCalledWith('2d');
  });

  it('handles getContext returning null', () => {
    HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as never;
    render(<PSDCurve psd={[1, 2, 3]} />);
    expect(screen.getByTestId('psd-canvas')).toBeDefined();
  });

  it('passes schumannFreqs prop through', () => {
    const ctx = createMockCtx();
    HTMLCanvasElement.prototype.getContext = vi.fn(() => ctx) as never;
    render(<PSDCurve psd={[1, 2, 3]} schumannFreqs={[8.0]} />);
    // 1 SR marker + 1 PSD curve
    expect(ctx.beginPath).toHaveBeenCalledTimes(2);
  });

  it('passes lorentzianFit prop and draws overlay', () => {
    const ctx = createMockCtx();
    HTMLCanvasElement.prototype.getContext = vi.fn(() => ctx) as never;
    const fit = {
      modes: [{ freq: 7.83, amp: 0.34, q_factor: 3.5 }],
      background: { slope: 0.0, intercept: 0.01 },
      converged: true,
    };
    render(<PSDCurve psd={[1, 2, 3]} lorentzianFit={fit} />);
    const fillTextCalls = (ctx.fillText as ReturnType<typeof vi.fn>).mock.calls;
    const hasLorentzianLabel = fillTextCalls.some(
      (call: unknown[]) => call[0] === 'Lorentzian fit',
    );
    expect(hasLorentzianLabel).toBe(true);
  });

  it('renders without lorentzianFit prop', () => {
    const ctx = createMockCtx();
    HTMLCanvasElement.prototype.getContext = vi.fn(() => ctx) as never;
    render(<PSDCurve psd={[1, 2, 3]} />);
    const fillTextCalls = (ctx.fillText as ReturnType<typeof vi.fn>).mock.calls;
    const hasLorentzianLabel = fillTextCalls.some(
      (call: unknown[]) => call[0] === 'Lorentzian fit',
    );
    expect(hasLorentzianLabel).toBe(false);
  });
});
