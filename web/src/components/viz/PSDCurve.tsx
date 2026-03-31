import { useRef, useEffect } from 'react';

interface LorentzianFitData {
  modes: Array<{ freq: number; amp: number; q_factor: number }>;
  background: { slope: number; intercept: number };
  converged: boolean;
}

interface PSDCurveProps {
  psd: number[];
  maxHz?: number;
  width?: number;
  height?: number;
  schumannFreqs?: number[];
  lorentzianFit?: LorentzianFitData | null;
}

export function drawPSD(
  ctx: CanvasRenderingContext2D,
  psd: number[],
  maxHz: number,
  width: number,
  height: number,
  schumannFreqs: number[] = [7.83, 14.3, 20.8, 27.3, 33.8],
  lorentzianFit?: LorentzianFitData | null,
): void {
  ctx.fillStyle = '#1a1a2e';
  ctx.fillRect(0, 0, width, height);
  if (psd.length === 0) return;

  // Convert to dB
  const dB = psd.map((v) => 10 * Math.log10(Math.max(v, 1e-20)));
  const min = Math.min(...dB);
  const max = Math.max(...dB);
  const range = max - min || 1;

  // Draw SR mode markers
  ctx.strokeStyle = 'rgba(74, 158, 255, 0.2)';
  ctx.setLineDash([4, 4]);
  for (const f of schumannFreqs) {
    const x = (f / maxHz) * width;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // Draw PSD curve
  ctx.strokeStyle = '#4ade80';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  for (let i = 0; i < psd.length; i++) {
    const x = (i / psd.length) * width;
    const y = height - ((dB[i] - min) / range) * height;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // Draw Lorentzian model curve
  if (lorentzianFit?.converged && lorentzianFit.modes.length > 0) {
    ctx.strokeStyle = '#fbbf24';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();

    for (let i = 0; i < psd.length; i++) {
      const f = (i / psd.length) * maxHz;
      let model = lorentzianFit.background.slope * f + lorentzianFit.background.intercept;
      for (const mode of lorentzianFit.modes) {
        const gamma = mode.freq / (2 * mode.q_factor);
        model += mode.amp / ((f - mode.freq) ** 2 + gamma ** 2);
      }
      const modelDb = 10 * Math.log10(Math.max(model, 1e-20));
      const x = (i / psd.length) * width;
      const y = height - ((modelDb - min) / range) * height;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.setLineDash([]);

    // Label
    ctx.fillStyle = '#fbbf24';
    ctx.font = '10px monospace';
    ctx.fillText('Lorentzian fit', width - 90, 12);
  }

  // Axis labels
  ctx.fillStyle = '#a0a0b0';
  ctx.font = '10px monospace';
  ctx.fillText('0 Hz', 4, height - 4);
  ctx.fillText(`${maxHz} Hz`, width - 40, height - 4);
  ctx.fillText('PSD (dB)', 4, 12);
}

export function PSDCurve({
  psd,
  maxHz = 55,
  width = 800,
  height = 150,
  schumannFreqs,
  lorentzianFit,
}: PSDCurveProps) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    /* v8 ignore next 2 -- ref is always attached after mount */
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    drawPSD(ctx, psd, maxHz, width, height, schumannFreqs, lorentzianFit);
  }, [psd, maxHz, width, height, schumannFreqs, lorentzianFit]);
  return (
    <canvas
      ref={ref}
      width={width}
      height={height}
      data-testid="psd-canvas"
      className="w-full h-full rounded"
    />
  );
}
