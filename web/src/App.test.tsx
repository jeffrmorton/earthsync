import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { App } from './App';

function createMockCtx() {
  const imageDataPixels = new Uint8ClampedArray(800 * 200 * 4);
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
    createImageData: vi.fn(() => ({
      data: imageDataPixels,
      width: 800,
      height: 200,
    })),
    putImageData: vi.fn(),
  } as unknown as CanvasRenderingContext2D;
}

class MockWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  readonly CONNECTING = 0;
  readonly OPEN = 1;
  readonly CLOSING = 2;
  readonly CLOSED = 3;
  readyState = MockWebSocket.CONNECTING;
  url: string;
  onopen: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  protocol = '';
  extensions = '';
  binaryType: BinaryType = 'blob';
  bufferedAmount = 0;
  constructor(url: string) {
    this.url = url;
  }
  close = vi.fn();
  send = vi.fn();
  addEventListener = vi.fn();
  removeEventListener = vi.fn();
  dispatchEvent = vi.fn(() => true);
}

describe('App', () => {
  const OriginalWebSocket = globalThis.WebSocket;

  beforeEach(() => {
    globalThis.WebSocket = MockWebSocket as unknown as typeof WebSocket;
    HTMLCanvasElement.prototype.getContext = vi.fn(() =>
      createMockCtx(),
    ) as never;
  });

  afterEach(() => {
    globalThis.WebSocket = OriginalWebSocket;
  });

  it('renders without crashing', () => {
    render(<App />);
    expect(screen.getByTestId('header')).toBeDefined();
  });

  it('renders the EarthSync header', () => {
    render(<App />);
    expect(screen.getByTestId('header').textContent).toContain('EarthSync');
  });

  it('shows disconnected status by default', () => {
    render(<App />);
    expect(screen.getByTestId('header').textContent).toContain('Disconnected');
  });

  it('shows 0 stations by default', () => {
    render(<App />);
    expect(screen.getByTestId('header').textContent).toContain('0 stations');
  });

  it('renders the dashboard layout', () => {
    render(<App />);
    expect(screen.getByTestId('dashboard-layout')).toBeDefined();
  });

  it('renders spectrogram canvas in empty state', () => {
    render(<App />);
    expect(screen.getByTestId('spectrogram-canvas')).toBeDefined();
  });

  it('renders PSD canvas', () => {
    render(<App />);
    expect(screen.getByTestId('psd-canvas')).toBeDefined();
  });

  it('renders peaks empty state', () => {
    render(<App />);
    expect(screen.getByTestId('peak-trends-empty')).toBeDefined();
  });
});
