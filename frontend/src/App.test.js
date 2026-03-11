// src/App.test.js
import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

// Mock plotly to avoid canvas issues in test environment
jest.mock('react-plotly.js', () => {
  const MockPlot = () => <div data-testid="mock-plot">Plot</div>;
  MockPlot.displayName = 'MockPlot';
  return MockPlot;
});

// Mock react-globe.gl — use require('react') inside mock factory to avoid scope issue
jest.mock('react-globe.gl', () => {
  const mockReact = require('react');
  const MockGlobe = mockReact.forwardRef((_props, _ref) => (
    <div data-testid="mock-globe">Globe</div>
  ));
  MockGlobe.displayName = 'MockGlobe';
  return MockGlobe;
});

// Mock axios to prevent network calls
jest.mock('axios', () => ({
  get: jest.fn(() => Promise.reject(new Error('Network Error'))),
  post: jest.fn(() => Promise.reject(new Error('Network Error'))),
  create: jest.fn(() => ({
    get: jest.fn(),
    post: jest.fn(),
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() },
    },
  })),
}));

describe('App', () => {
  test('renders without crashing', () => {
    render(<App />);
    // The app should render some form of UI
    const appElement = document.querySelector('#root') || document.body;
    expect(appElement).toBeTruthy();
  });

  test('shows EarthSync branding', () => {
    render(<App />);
    // EarthSync text should appear somewhere (header, login title, etc.)
    const brandingElements = screen.queryAllByText(/EarthSync/i);
    expect(brandingElements.length).toBeGreaterThan(0);
  });
});
