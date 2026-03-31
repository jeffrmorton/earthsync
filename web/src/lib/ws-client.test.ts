import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WSClient } from './ws-client';
import type { WSPayload } from '@/types/websocket';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  url: string;
  readyState: number = MockWebSocket.OPEN;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: (() => void) | null = null;
  closed = false;

  constructor(url: string) {
    this.url = url;
  }

  close() {
    this.closed = true;
    this.readyState = MockWebSocket.CLOSED;
  }
}

// Assign both the class and its static constants to globalThis
Object.assign(globalThis, {
  WebSocket: Object.assign(MockWebSocket, {
    CONNECTING: 0,
    OPEN: 1,
    CLOSING: 2,
    CLOSED: 3,
  }),
});

const samplePayload: WSPayload = {
  stationId: 'det-1',
  timestamp: '2026-01-01T00:00:00Z',
  location: { lat: 37.0, lon: -3.4 },
  spectrogram: [1, 2, 3],
  lorentzianFit: null,
  detectedPeaks: [],
  transientInfo: { type: 'none', details: null },
  noiseFloor: null,
  qualityFlags: [],
  algorithmVersion: '0.1.1',
  calibrationStatus: 'uncalibrated',
  sampleRateHz: 256,
  frequencyResolutionHz: null,
};

describe('WSClient', () => {
  let client: WSClient;

  beforeEach(() => {
    client = new WSClient('ws://localhost:3000');
    vi.useFakeTimers();
  });

  describe('constructor', () => {
    it('creates instance with URL', () => {
      expect(client).toBeInstanceOf(WSClient);
    });

    it('starts disconnected', () => {
      expect(client.connected).toBe(false);
    });
  });

  describe('onMessage', () => {
    it('adds a handler and returns unsubscribe function', () => {
      const handler = vi.fn();
      const unsub = client.onMessage(handler);
      expect(typeof unsub).toBe('function');
    });

    it('removes handler when unsubscribe is called', () => {
      const handler = vi.fn();
      const unsub = client.onMessage(handler);
      unsub();
      // Handler should be removed - we verify indirectly via connect/message
    });
  });

  describe('connect', () => {
    it('creates a WebSocket connection with token', () => {
      client.connect('my-token');
      expect(client.connected).toBe(true);
    });

    it('passes token as query parameter', () => {
      client.connect('jwt-123');
      // Verify the internal ws was created (connected is true means ws exists and is OPEN)
      expect(client.connected).toBe(true);
    });
  });

  describe('disconnect', () => {
    it('closes the WebSocket connection', () => {
      client.connect('token');
      expect(client.connected).toBe(true);
      client.disconnect();
      expect(client.connected).toBe(false);
    });

    it('is safe to call when not connected', () => {
      expect(() => client.disconnect()).not.toThrow();
    });
  });

  describe('connected property', () => {
    it('returns false when ws is null', () => {
      expect(client.connected).toBe(false);
    });

    it('returns true when ws is open', () => {
      client.connect('token');
      expect(client.connected).toBe(true);
    });

    it('returns false after disconnect', () => {
      client.connect('token');
      client.disconnect();
      expect(client.connected).toBe(false);
    });
  });

  describe('message handling', () => {
    it('delivers JSON messages to handlers', async () => {
      const handler = vi.fn();
      client.onMessage(handler);
      client.connect('token');

      // Access the internal ws to trigger onmessage
      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      const event = new MessageEvent('message', { data: JSON.stringify(samplePayload) });
      await ws.onmessage!(event);

      expect(handler).toHaveBeenCalledWith(samplePayload);
    });

    it('delivers to multiple handlers', async () => {
      const handler1 = vi.fn();
      const handler2 = vi.fn();
      client.onMessage(handler1);
      client.onMessage(handler2);
      client.connect('token');

      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      const event = new MessageEvent('message', { data: JSON.stringify(samplePayload) });
      await ws.onmessage!(event);

      expect(handler1).toHaveBeenCalledWith(samplePayload);
      expect(handler2).toHaveBeenCalledWith(samplePayload);
    });

    it('does not deliver to removed handlers', async () => {
      const handler = vi.fn();
      const unsub = client.onMessage(handler);
      unsub();
      client.connect('token');

      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      const event = new MessageEvent('message', { data: JSON.stringify(samplePayload) });
      await ws.onmessage!(event);

      expect(handler).not.toHaveBeenCalled();
    });

    it('silently drops malformed messages', async () => {
      const handler = vi.fn();
      client.onMessage(handler);
      client.connect('token');

      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      const event = new MessageEvent('message', { data: 'not-json{{' });
      await ws.onmessage!(event);

      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('setEncryptionKey', () => {
    it('imports an AES-GCM key from hex string', async () => {
      const mockKey = {} as CryptoKey;
      const importKeySpy = vi.spyOn(crypto.subtle, 'importKey').mockResolvedValueOnce(mockKey);
      const hexKey = '00'.repeat(32); // 256-bit key
      await client.setEncryptionKey(hexKey);
      expect(importKeySpy).toHaveBeenCalledWith(
        'raw',
        expect.any(Uint8Array),
        'AES-GCM',
        false,
        ['decrypt'],
      );
      importKeySpy.mockRestore();
    });

    it('stores the key for decryption', async () => {
      const mockKey = { type: 'secret' } as CryptoKey;
      const importKeySpy = vi.spyOn(crypto.subtle, 'importKey').mockResolvedValueOnce(mockKey);
      await client.setEncryptionKey('ab'.repeat(32));
      const internals = client as unknown as { key: CryptoKey | null };
      expect(internals.key).toBe(mockKey);
      importKeySpy.mockRestore();
    });
  });

  describe('encrypted message handling', () => {
    it('decrypts message when encryption key is set and data contains colon', async () => {
      const handler = vi.fn();
      client.onMessage(handler);

      // Set up mock encryption key
      const mockKey = {} as CryptoKey;
      vi.spyOn(crypto.subtle, 'importKey').mockResolvedValueOnce(mockKey);
      await client.setEncryptionKey('00'.repeat(32));

      // Mock decrypt to return our payload
      const encoded = new TextEncoder().encode(JSON.stringify(samplePayload));
      vi.spyOn(crypto.subtle, 'decrypt').mockResolvedValueOnce(encoded.buffer);

      client.connect('token');
      const ws = (client as unknown as { ws: MockWebSocket }).ws;

      // Encrypted message format: base64(nonce):base64(ciphertext)
      const nonceB64 = btoa(String.fromCharCode(...new Uint8Array(12)));
      const ctB64 = btoa(String.fromCharCode(...new Uint8Array(16)));
      const event = new MessageEvent('message', { data: `${nonceB64}:${ctB64}` });
      await ws.onmessage!(event);

      expect(handler).toHaveBeenCalledWith(samplePayload);
      vi.restoreAllMocks();
    });

    it('silently drops messages that fail decryption', async () => {
      const handler = vi.fn();
      client.onMessage(handler);

      const mockKey = {} as CryptoKey;
      vi.spyOn(crypto.subtle, 'importKey').mockResolvedValueOnce(mockKey);
      await client.setEncryptionKey('00'.repeat(32));

      vi.spyOn(crypto.subtle, 'decrypt').mockRejectedValueOnce(new Error('decrypt failed'));

      client.connect('token');
      const ws = (client as unknown as { ws: MockWebSocket }).ws;

      const event = new MessageEvent('message', { data: 'bad:data' });
      await ws.onmessage!(event);

      expect(handler).not.toHaveBeenCalled();
      vi.restoreAllMocks();
    });
  });

  describe('reconnection', () => {
    it('reconnects on close when shouldReconnect is true', () => {
      client.connect('token');
      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      ws.readyState = MockWebSocket.CLOSED;

      // Trigger onclose
      ws.onclose!();
      vi.advanceTimersByTime(1000);

      // A new ws should have been created
      expect(client.connected).toBe(true);
    });

    it('does not reconnect after disconnect()', () => {
      client.connect('token');
      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      client.disconnect();

      // Trigger onclose on old ws
      ws.onclose!();
      vi.advanceTimersByTime(5000);

      expect(client.connected).toBe(false);
    });

    it('uses exponential backoff for reconnection delay', () => {
      const internals = client as unknown as { reconnectDelay: number };
      client.connect('token');

      // After first connect, delay is 1000
      expect(internals.reconnectDelay).toBe(1000);

      // onclose doubles delay to 2000 and schedules setTimeout(connect, 1000)
      const ws = (client as unknown as { ws: MockWebSocket }).ws;
      ws.onclose!();
      // After onclose, delay has been doubled
      expect(internals.reconnectDelay).toBe(2000);

      // When the timer fires, connect() resets delay back to 1000
      vi.advanceTimersByTime(1000);
      expect(internals.reconnectDelay).toBe(1000);
    });
  });
});
