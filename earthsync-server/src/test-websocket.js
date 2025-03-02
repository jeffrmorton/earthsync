const WebSocket = require('ws');

if (process.argv.length < 3) {
  console.error('Usage: node test-websocket.js <token>');
  process.exit(1);
}

const token = process.argv[2];
const wsUrl = `ws://localhost:3000?token=${token}`;

const ws = new WebSocket(wsUrl);

ws.on('open', () => {
  console.log('Connected to WebSocket server');
});

ws.on('message', (data) => {
  console.log('Received:', data.toString());
  ws.close(); // Close after receiving one message
});

ws.on('close', (code, reason) => {
  console.log(`Disconnected with code ${code}: ${reason}`);
  process.exit(0); // Exit cleanly
});

ws.on('error', (err) => {
  console.error('WebSocket error:', err.message);
  process.exit(1); // Exit with error
});

// Timeout after 15 seconds if no message received
setTimeout(() => {
  console.error('Timeout: No message received within 15 seconds');
  ws.close();
  process.exit(1);
}, 15000);