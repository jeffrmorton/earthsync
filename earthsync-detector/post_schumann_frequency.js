#!/usr/bin/env node

const fetch = require('node-fetch');

// Server configuration
const SERVER_URL = 'http://earthsync-server:3000'; // Use container name for linking
const USERNAME = 'test'; // Default test user from db.js
const PASSWORD = 'password123'; // Default test password from db.js
const INTERVAL_SECONDS = 60; // Post every 1 minute (60 seconds)

// Authenticate with the server and return a JWT token
async function authenticateUser() {
  const url = `${SERVER_URL}/login`;
  const payload = {
    username: USERNAME,
    password: PASSWORD,
  };
  const headers = { 'Content-Type': 'application/json' };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
    const data = await response.json();
    if (!data.token) throw new Error('No token in response');
    console.log(`Authenticated successfully. JWT: ${data.token.slice(0, 10)}...`);
    return data.token;
  } catch (error) {
    console.error('Authentication failed:', error.message);
    process.exit(1);
  }
}

// Obtain an API key using the JWT token
async function getApiKey(jwtToken) {
  const url = `${SERVER_URL}/register-api-key`;
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwtToken}`,
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
    });
    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
    const data = await response.json();
    if (!data.api_key) throw new Error('No API key in response');
    console.log(`API key obtained: ${data.api_key.slice(0, 10)}...`);
    return data.api_key;
  } catch (error) {
    console.error('Failed to get API key:', error.message);
    process.exit(1);
  }
}

// Post a random Schumann frequency to the server
async function postFrequency(apiKey) {
  const url = `${SERVER_URL}/schumann-frequency`;
  const frequency = 7.83 + (Math.random() - 0.5) * 0.4; // Random around 7.83 Hz
  const payload = {
    frequency,
    timestamp: new Date().toISOString(),
  };
  const headers = {
    'Content-Type': 'application/json',
    'x-api-key': apiKey,
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
    const data = await response.json();
    console.log(`Posted frequency ${frequency} Hz:`, JSON.stringify(data));
  } catch (error) {
    console.error('Failed to post frequency:', error.message);
  }
}

// Main function to run the script
async function main() {
  console.log('Starting Schumann frequency poster...');
  
  // Authenticate and get API key once
  const jwtToken = await authenticateUser();
  const apiKey = await getApiKey(jwtToken);
  
  // Post frequency every minute
  setInterval(() => postFrequency(apiKey), INTERVAL_SECONDS * 1000);
}

// Run the script
main();