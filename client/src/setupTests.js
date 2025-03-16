// Polyfill for window.URL.createObjectURL
if (!window.URL.createObjectURL) {
  window.URL.createObjectURL = jest.fn(() => 'mocked-url');
}
