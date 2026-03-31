import { describe, it, expect } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useTheme } from './use-theme';

describe('useTheme', () => {
  it('defaults to dark mode', () => {
    const { result } = renderHook(() => useTheme());
    expect(result.current.darkMode).toBe(true);
  });

  it('toggles to light mode', () => {
    const { result } = renderHook(() => useTheme());
    act(() => {
      result.current.toggle();
    });
    expect(result.current.darkMode).toBe(false);
  });

  it('toggles back to dark mode', () => {
    const { result } = renderHook(() => useTheme());
    act(() => {
      result.current.toggle();
    });
    act(() => {
      result.current.toggle();
    });
    expect(result.current.darkMode).toBe(true);
  });

  it('returns stable toggle function reference', () => {
    const { result, rerender } = renderHook(() => useTheme());
    const firstToggle = result.current.toggle;
    rerender();
    expect(result.current.toggle).toBe(firstToggle);
  });
});
