import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useAuth } from './use-auth';

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

describe('useAuth', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('starts unauthenticated', () => {
    const { result } = renderHook(() => useAuth());
    expect(result.current.token).toBeNull();
    expect(result.current.username).toBeNull();
    expect(result.current.error).toBeNull();
    expect(result.current.isAuthenticated).toBe(false);
  });

  describe('login', () => {
    it('sets token and username on success', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ token: 'jwt-123', expiresIn: 3600 }),
      );
      const { result } = renderHook(() => useAuth());

      let success: boolean;
      await act(async () => {
        success = await result.current.login('alice', 'password123');
      });

      expect(success!).toBe(true);
      expect(result.current.token).toBe('jwt-123');
      expect(result.current.username).toBe('alice');
      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.error).toBeNull();
    });

    it('sets error on failure', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(401, 'Invalid credentials'));
      const { result } = renderHook(() => useAuth());

      let success: boolean;
      await act(async () => {
        success = await result.current.login('alice', 'wrong');
      });

      expect(success!).toBe(false);
      expect(result.current.token).toBeNull();
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.error).toContain('API error');
    });

    it('handles non-Error exceptions', async () => {
      mockFetch.mockRejectedValueOnce('network failure');
      const { result } = renderHook(() => useAuth());

      let success: boolean;
      await act(async () => {
        success = await result.current.login('alice', 'pass');
      });

      expect(success!).toBe(false);
      expect(result.current.error).toBe('Login failed');
    });

    it('clears previous error on new attempt', async () => {
      // First: fail
      mockFetch.mockResolvedValueOnce(errorResponse(401, 'Bad'));
      const { result } = renderHook(() => useAuth());
      await act(async () => {
        await result.current.login('alice', 'wrong');
      });
      expect(result.current.error).not.toBeNull();

      // Second: succeed
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ token: 'jwt-456', expiresIn: 3600 }),
      );
      await act(async () => {
        await result.current.login('alice', 'correct');
      });
      expect(result.current.error).toBeNull();
      expect(result.current.token).toBe('jwt-456');
    });
  });

  describe('register', () => {
    it('returns true on success', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
      const { result } = renderHook(() => useAuth());

      let success: boolean;
      await act(async () => {
        success = await result.current.register('bob', 'password123');
      });

      expect(success!).toBe(true);
      expect(result.current.error).toBeNull();
    });

    it('sets error on failure', async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(409, 'Username taken'));
      const { result } = renderHook(() => useAuth());

      let success: boolean;
      await act(async () => {
        success = await result.current.register('bob', 'password123');
      });

      expect(success!).toBe(false);
      expect(result.current.error).toContain('API error');
    });

    it('handles non-Error exceptions', async () => {
      mockFetch.mockRejectedValueOnce(42);
      const { result } = renderHook(() => useAuth());

      let success: boolean;
      await act(async () => {
        success = await result.current.register('bob', 'pass');
      });

      expect(success!).toBe(false);
      expect(result.current.error).toBe('Registration failed');
    });
  });

  describe('logout', () => {
    it('clears token and username', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ token: 'jwt-123', expiresIn: 3600 }),
      );
      const { result } = renderHook(() => useAuth());

      await act(async () => {
        await result.current.login('alice', 'password123');
      });
      expect(result.current.isAuthenticated).toBe(true);

      act(() => {
        result.current.logout();
      });

      expect(result.current.token).toBeNull();
      expect(result.current.username).toBeNull();
      expect(result.current.isAuthenticated).toBe(false);
    });
  });
});
