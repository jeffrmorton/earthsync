import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 3080,
    proxy: {
      '/api': 'http://localhost:3000',
      '/ws': {
        target: 'ws://localhost:3000',
        ws: true,
        rewrite: (path) => path.replace(/^\/ws/, ''),
      },
      '/health': 'http://localhost:3000',
      '/metrics': 'http://localhost:3000',
      '/key-exchange': 'http://localhost:3000',
    },
  },
  build: {
    target: 'es2025',
  },
});
