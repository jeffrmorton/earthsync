import { describe, it, expect } from 'vitest';
import { viridisColor, valueToColor } from './colormap';
import type { RGB } from './colormap';

describe('viridisColor', () => {
  it('returns dark color at t=0', () => {
    const [r, g, b] = viridisColor(0);
    expect(r).toBe(0);
    expect(g).toBe(0);
    expect(b).toBe(100);
  });

  it('returns mid-range color at t=0.5', () => {
    const [r, g, b] = viridisColor(0.5);
    expect(r).toBe(80);
    expect(g).toBe(94);
    expect(b).toBe(200);
  });

  it('returns bright color at t=1', () => {
    const [r, g, b] = viridisColor(1);
    expect(r).toBe(255);
    expect(g).toBe(255);
    expect(b).toBe(0);
  });

  it('clamps values below 0', () => {
    const result = viridisColor(-0.5);
    expect(result).toEqual(viridisColor(0));
  });

  it('clamps values above 1', () => {
    const result = viridisColor(1.5);
    expect(result).toEqual(viridisColor(1));
  });

  it('returns integer RGB values', () => {
    const [r, g, b] = viridisColor(0.33);
    expect(Number.isInteger(r)).toBe(true);
    expect(Number.isInteger(g)).toBe(true);
    expect(Number.isInteger(b)).toBe(true);
  });

  it('keeps all channels in 0-255 range', () => {
    for (const t of [0, 0.1, 0.25, 0.3, 0.5, 0.75, 1]) {
      const [r, g, b] = viridisColor(t);
      expect(r).toBeGreaterThanOrEqual(0);
      expect(r).toBeLessThanOrEqual(255);
      expect(g).toBeGreaterThanOrEqual(0);
      expect(g).toBeLessThanOrEqual(255);
      expect(b).toBeGreaterThanOrEqual(0);
      expect(b).toBeLessThanOrEqual(255);
    }
  });

  it('handles the 0.3 boundary for green channel', () => {
    const [, g] = viridisColor(0.3);
    expect(g).toBe(30);
  });
});

describe('valueToColor', () => {
  it('maps min value to t=0 color', () => {
    const result = valueToColor(0, 0, 100);
    expect(result).toEqual(viridisColor(0));
  });

  it('maps max value to t=1 color', () => {
    const result = valueToColor(100, 0, 100);
    expect(result).toEqual(viridisColor(1));
  });

  it('maps mid value to t=0.5 color', () => {
    const result = valueToColor(50, 0, 100);
    expect(result).toEqual(viridisColor(0.5));
  });

  it('handles equal min and max (division by zero guard)', () => {
    const result = valueToColor(5, 5, 5);
    // range becomes 1, so t = (5-5)/1 = 0
    expect(result).toEqual(viridisColor(0));
  });

  it('handles negative ranges', () => {
    const result = valueToColor(-50, -100, 0);
    expect(result).toEqual(viridisColor(0.5));
  });

  it('returns valid RGB type', () => {
    const result: RGB = valueToColor(25, 0, 100);
    expect(result).toHaveLength(3);
  });
});
