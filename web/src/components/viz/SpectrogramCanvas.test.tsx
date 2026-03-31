import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SpectrogramCanvas, drawSpectrogram } from './SpectrogramCanvas';

function createMockCtx(width: number, height: number) {
  const imageDataPixels = new Uint8ClampedArray(width * height * 4);
  return {
    fillStyle: '',
    font: '',
    fillRect: vi.fn(),
    fillText: vi.fn(),
    createImageData: vi.fn(() => ({
      data: imageDataPixels,
      width,
      height,
    })),
    putImageData: vi.fn(),
  } as unknown as CanvasRenderingContext2D;
}

describe('drawSpectrogram', () => {
  it('draws empty state when data is empty', () => {
    const ctx = createMockCtx(800, 200);
    drawSpectrogram(ctx, [], 800, 200);

    expect(ctx.fillRect).toHaveBeenCalledWith(0, 0, 800, 200);
    expect(ctx.fillText).toHaveBeenCalledWith(
      'Waiting for data...',
      expect.any(Number),
      expect.any(Number),
    );
  });

  it('renders pixel data for spectrogram matrix', () => {
    const ctx = createMockCtx(4, 2);
    const data = [
      [0, 1],
      [0.5, 0.75],
    ];
    drawSpectrogram(ctx, data, 4, 2);

    expect(ctx.createImageData).toHaveBeenCalledWith(4, 2);
    expect(ctx.putImageData).toHaveBeenCalled();
    // Verify the image data was populated (not all zeros)
    const imageData = (ctx.createImageData as ReturnType<typeof vi.fn>).mock.results[0].value;
    const px = imageData.data as Uint8ClampedArray;
    // Alpha channel should be 255 for all pixels
    let hasAlpha = false;
    for (let i = 3; i < px.length; i += 4) {
      if (px[i] === 255) hasAlpha = true;
    }
    expect(hasAlpha).toBe(true);
  });

  it('handles single-value data (max === min)', () => {
    const ctx = createMockCtx(2, 2);
    const data = [[5, 5]];
    drawSpectrogram(ctx, data, 2, 2);
    expect(ctx.putImageData).toHaveBeenCalled();
  });
});

describe('SpectrogramCanvas component', () => {
  beforeEach(() => {
    // Mock canvas getContext
    HTMLCanvasElement.prototype.getContext = vi.fn(() =>
      createMockCtx(800, 200),
    ) as never;
  });

  it('renders a canvas element', () => {
    render(<SpectrogramCanvas data={[]} />);
    const canvas = screen.getByTestId('spectrogram-canvas');
    expect(canvas).toBeDefined();
    expect(canvas.tagName).toBe('CANVAS');
  });

  it('uses default width and height', () => {
    render(<SpectrogramCanvas data={[]} />);
    const canvas = screen.getByTestId('spectrogram-canvas') as HTMLCanvasElement;
    expect(canvas.width).toBe(800);
    expect(canvas.height).toBe(600);
  });

  it('accepts custom width and height', () => {
    render(<SpectrogramCanvas data={[]} width={400} height={100} />);
    const canvas = screen.getByTestId('spectrogram-canvas') as HTMLCanvasElement;
    expect(canvas.width).toBe(400);
    expect(canvas.height).toBe(100);
  });

  it('calls getContext on mount', () => {
    render(<SpectrogramCanvas data={[[1, 2], [3, 4]]} />);
    expect(HTMLCanvasElement.prototype.getContext).toHaveBeenCalledWith('2d');
  });

  it('handles getContext returning null', () => {
    HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as never;
    // Should not throw
    render(<SpectrogramCanvas data={[[1, 2]]} />);
    expect(screen.getByTestId('spectrogram-canvas')).toBeDefined();
  });
});
