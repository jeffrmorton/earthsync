import { useState, useCallback } from 'react';
import { ApiClient } from '@/lib/api-client';
import type { LoginResponse } from '@/types/api';

const client = new ApiClient();

export function useAuth() {
  const [token, setToken] = useState<string | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (user: string, password: string) => {
    try {
      setError(null);
      const res = await client.post<LoginResponse>('/auth/login', { username: user, password });
      setToken(res.token);
      setUsername(user);
      client.setToken(res.token);
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed');
      return false;
    }
  }, []);

  const register = useCallback(async (user: string, password: string) => {
    try {
      setError(null);
      await client.post('/auth/register', { username: user, password });
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Registration failed');
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setUsername(null);
    client.setToken(null);
  }, []);

  return { token, username, error, login, register, logout, isAuthenticated: !!token };
}
