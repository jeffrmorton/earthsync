import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiClient, ApiError } from './api-client';

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

function jsonResponse(data: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  };
}

function errorResponse(status: number, body: string) {
  return {
    ok: false,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(body),
  };
}

describe('ApiClient', () => {
  let client: ApiClient;

  beforeEach(() => {
    client = new ApiClient('http://test');
    mockFetch.mockReset();
  });

  describe('constructor', () => {
    it('uses default base URL when none provided', () => {
      const defaultClient = new ApiClient();
      mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
      defaultClient.get('/test');
      expect(mockFetch).toHaveBeenCalledWith('/api/test', expect.any(Object));
    });
  });

  describe('get', () => {
    it('sends GET request with correct URL', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: 'test' }));
      const result = await client.get('/items');
      expect(mockFetch).toHaveBeenCalledWith('http://test/items', {
        headers: { 'Content-Type': 'application/json' },
      });
      expect(result).toEqual({ data: 'test' });
    });

    it('throws ApiError on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(404, 'Not found'));
      await expect(client.get('/missing')).rejects.toThrow(ApiError);
    });

    it('includes status in ApiError message', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(404, 'Not found'));
      await expect(client.get('/missing')).rejects.toThrow('API error');
    });
  });

  describe('post', () => {
    it('sends POST request with JSON body', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ id: 1 }));
      const result = await client.post('/items', { name: 'test' });
      expect(mockFetch).toHaveBeenCalledWith('http://test/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"name":"test"}',
      });
      expect(result).toEqual({ id: 1 });
    });

    it('sends POST request without body', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
      await client.post('/action');
      expect(mockFetch).toHaveBeenCalledWith('http://test/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: undefined,
      });
    });

    it('throws ApiError on server error', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(500, 'Internal error'));
      try {
        await client.post('/fail', {});
      } catch (e) {
        expect(e).toBeInstanceOf(ApiError);
        expect((e as ApiError).status).toBe(500);
        expect((e as ApiError).body).toBe('Internal error');
      }
    });
  });

  describe('put', () => {
    it('sends PUT request with JSON body', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ updated: true }));
      const result = await client.put('/items/1', { name: 'updated' });
      expect(mockFetch).toHaveBeenCalledWith('http://test/items/1', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: '{"name":"updated"}',
      });
      expect(result).toEqual({ updated: true });
    });

    it('sends PUT request without body', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
      await client.put('/items/1');
      expect(mockFetch).toHaveBeenCalledWith('http://test/items/1', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: undefined,
      });
    });

    it('throws ApiError on failure', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(403, 'Forbidden'));
      await expect(client.put('/restricted')).rejects.toThrow(ApiError);
    });
  });

  describe('setToken', () => {
    it('includes Authorization header after setting token', async () => {
      client.setToken('my-jwt-token');
      mockFetch.mockResolvedValueOnce(jsonResponse({}));
      await client.get('/protected');
      expect(mockFetch).toHaveBeenCalledWith('http://test/protected', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer my-jwt-token',
        },
      });
    });

    it('removes Authorization header when token set to null', async () => {
      client.setToken('token');
      client.setToken(null);
      mockFetch.mockResolvedValueOnce(jsonResponse({}));
      await client.get('/public');
      expect(mockFetch).toHaveBeenCalledWith('http://test/public', {
        headers: { 'Content-Type': 'application/json' },
      });
    });
  });
});

describe('ApiError', () => {
  it('has correct name, status, and body', () => {
    const err = new ApiError(422, 'Validation failed');
    expect(err.name).toBe('ApiError');
    expect(err.status).toBe(422);
    expect(err.body).toBe('Validation failed');
    expect(err.message).toBe('API error 422: Validation failed');
  });

  it('is an instance of Error', () => {
    const err = new ApiError(400, 'Bad request');
    expect(err).toBeInstanceOf(Error);
  });
});
