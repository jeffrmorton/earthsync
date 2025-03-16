module.exports = {
  transformIgnorePatterns: [
    '/node_modules/(?!axios|crypto-js|react-plotly.js|lodash.debounce|lodash.throttle|@mui|@emotion)'
  ],
  testEnvironment: 'jsdom',
};
