/**
 * WebSocket client with AES-256-GCM decryption.
 * Uses native Web Crypto API -- no crypto-js dependency.
 */
import type { WSPayload } from '@/types/websocket';

export type WSMessageHandler = (payload: WSPayload) => void;

export class WSClient {
  private ws: WebSocket | null = null;
  private key: CryptoKey | null = null;
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;
  private handlers: Set<WSMessageHandler> = new Set();
  private _url: string;
  private _shouldReconnect = false;

  constructor(url: string) {
    this._url = url;
  }

  async setEncryptionKey(hexKey: string): Promise<void> {
    const keyBytes = new Uint8Array(hexKey.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
    this.key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  }

  onMessage(handler: WSMessageHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  connect(token: string): void {
    this._shouldReconnect = true;
    this.reconnectDelay = 1000;
    const url = `${this._url}?token=${token}`;
    this.ws = new WebSocket(url);
    this.ws.onmessage = (event) => this.handleMessage(event);
    this.ws.onclose = () => {
      if (this._shouldReconnect) {
        setTimeout(() => this.connect(token), this.reconnectDelay);
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
      }
    };
  }

  disconnect(): void {
    this._shouldReconnect = false;
    this.ws?.close();
    this.ws = null;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private async handleMessage(event: MessageEvent): Promise<void> {
    try {
      let payload: WSPayload;
      if (this.key && typeof event.data === 'string' && event.data.includes(':')) {
        payload = await this.decrypt(event.data);
      } else {
        payload = JSON.parse(event.data as string);
      }
      for (const handler of this.handlers) handler(payload);
    } catch {
      // Silently drop malformed messages
    }
  }

  private async decrypt(encrypted: string): Promise<WSPayload> {
    const [nonceB64, ctB64] = encrypted.split(':');
    const nonce = Uint8Array.from(atob(nonceB64), (c) => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ctB64), (c) => c.charCodeAt(0));
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      this.key!,
      ciphertext,
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
}
