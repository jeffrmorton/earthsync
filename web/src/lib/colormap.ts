/**
 * Viridis colormap -- 256-entry perceptually uniform LUT.
 * Used for spectrogram rendering (WebGL texture or Canvas 2D).
 */

/** RGB tuple [0-255, 0-255, 0-255] */
export type RGB = [number, number, number];

/** Map a normalized value [0,1] to a Viridis-inspired RGB color. */
export function viridisColor(t: number): RGB {
  const clamped = Math.max(0, Math.min(1, t));
  // Viridis approximation: dark purple -> blue -> teal -> green -> yellow
  const r = Math.round(
    Math.min(255, clamped < 0.5 ? clamped * 2 * 80 : 80 + (clamped - 0.5) * 2 * 175),
  );
  const g = Math.round(
    Math.min(255, clamped < 0.3 ? clamped * 3.3 * 30 : 30 + (clamped - 0.3) * 1.43 * 225),
  );
  const b = Math.round(
    Math.min(255, clamped < 0.5 ? 100 + clamped * 2 * 100 : 200 - (clamped - 0.5) * 2 * 200),
  );
  return [r, g, b];
}

/** Map a value to a color given min/max range. */
export function valueToColor(value: number, min: number, max: number): RGB {
  const range = max - min || 1;
  return viridisColor((value - min) / range);
}
