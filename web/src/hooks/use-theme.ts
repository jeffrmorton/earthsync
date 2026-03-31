import { useState, useCallback } from 'react';

export function useTheme() {
  const [darkMode, setDarkMode] = useState(true); // Dark by default
  const toggle = useCallback(() => setDarkMode((d) => !d), []);
  return { darkMode, toggle };
}
