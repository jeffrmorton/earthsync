import { useRef, useEffect, useCallback } from 'react';
import { viridisColor } from '@/lib/colormap';

interface SpectrogramCanvasProps {
  data: number[][];
  width?: number;
  height?: number;
}

export function drawSpectrogram(
  ctx: CanvasRenderingContext2D,
  data: number[][],
  width: number,
  height: number,
): void {
  if (data.length === 0) {
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = '#606070';
    ctx.font = '14px sans-serif';
    ctx.fillText('Waiting for data...', width / 2 - 60, height / 2);
    return;
  }
  const rows = data.length;
  const cols = data[0].length;
  let min = Infinity;
  let max = -Infinity;
  for (const row of data)
    for (const v of row) {
      if (v < min) min = v;
      if (v > max) max = v;
    }
  const cellW = width / cols;
  const cellH = height / rows;
  const imageData = ctx.createImageData(width, height);
  const px = imageData.data;
  for (let r = 0; r < rows; r++) {
    const y0 = Math.floor(r * cellH);
    const y1 = Math.floor((r + 1) * cellH);
    for (let c = 0; c < cols; c++) {
      const x0 = Math.floor(c * cellW);
      const x1 = Math.floor((c + 1) * cellW);
      const [cr, cg, cb] = viridisColor((data[r][c] - min) / (max - min || 1));
      for (let y = y0; y < y1 && y < height; y++)
        for (let x = x0; x < x1 && x < width; x++) {
          const i = (y * width + x) * 4;
          px[i] = cr;
          px[i + 1] = cg;
          px[i + 2] = cb;
          px[i + 3] = 255;
        }
    }
  }
  ctx.putImageData(imageData, 0, 0);
}

export function SpectrogramCanvas({
  data,
  width = 800,
  height = 600,
}: SpectrogramCanvasProps) {
  const ref = useRef<HTMLCanvasElement>(null);
  const render = useCallback(() => {
    const canvas = ref.current;
    /* v8 ignore next 2 -- ref is always attached after mount */
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    drawSpectrogram(ctx, data, canvas.width, canvas.height);
  }, [data]);
  useEffect(() => {
    render();
  }, [render]);
  return (
    <canvas
      ref={ref}
      width={width}
      height={height}
      data-testid="spectrogram-canvas"
      className="w-full rounded block"
      style={{ height: `${height}px` }}
    />
  );
}
