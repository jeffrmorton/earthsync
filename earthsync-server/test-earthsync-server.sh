#!/bin/bash

# Configuration
SERVER_URL="http://localhost:3000"
WS_URL="ws://localhost:3000"
USERNAME="testuser$RANDOM"
PASSWORD="testpass123"
API_KEY=""
JWT_TOKEN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Check for required tools
command -v curl >/dev/null 2>&1 || { echo -e "${RED}Error: curl is required but not installed.${NC}"; exit 1; }
command -v node >/dev/null 2>&1 || { echo -e "${RED}Error: node is required but not installed. Install with 'apt install nodejs' or 'nvm install node'.${NC}"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${RED}Error: docker is required but not installed.${NC}"; exit 1; }

# Test 1: Register a new user
echo "Testing /register endpoint..."
REGISTER_RESPONSE=$(curl -s -X POST "$SERVER_URL/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
if echo "$REGISTER_RESPONSE" | grep -q "User registered"; then
  echo -e "${GREEN}Register successful: $REGISTER_RESPONSE${NC}"
else
  echo -e "${RED}Register failed: $REGISTER_RESPONSE${NC}"
  exit 1
fi

# Test 2: Login with the new user
echo "Testing /login endpoint..."
LOGIN_RESPONSE=$(curl -s -X POST "$SERVER_URL/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
if echo "$LOGIN_RESPONSE" | grep -q "Login successful"; then
  JWT_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
  echo -e "${GREEN}Login successful: Token acquired${NC}"
else
  echo -e "${RED}Login failed: $LOGIN_RESPONSE${NC}"
  exit 1
fi

# Test 3: Key Exchange
echo "Testing /key-exchange endpoint..."
KEY_RESPONSE=$(curl -s -X POST "$SERVER_URL/key-exchange" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json")
if echo "$KEY_RESPONSE" | grep -q '"key":"'; then
  echo -e "${GREEN}Key exchange successful: $KEY_RESPONSE${NC}"
else
  echo -e "${RED}Key exchange failed: $KEY_RESPONSE${NC}"
  exit 1
fi

# Test 4: Register API Key
echo "Testing /register-api-key endpoint..."
API_KEY_RESPONSE=$(curl -s -X POST "$SERVER_URL/register-api-key" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json")
if echo "$API_KEY_RESPONSE" | grep -q '"api_key":"'; then
  API_KEY=$(echo "$API_KEY_RESPONSE" | grep -o '"api_key":"[^"]*' | cut -d'"' -f4)
  echo -e "${GREEN}API key registered: $API_KEY${NC}"
else
  echo -e "${RED}API key registration failed: $API_KEY_RESPONSE${NC}"
  exit 1
fi

# Test 5: Post Schumann Frequency
echo "Testing /schumann-frequency endpoint..."
FREQ_RESPONSE=$(curl -s -X POST "$SERVER_URL/schumann-frequency" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d '{"frequency":7.85}')
if echo "$FREQ_RESPONSE" | grep -q "Frequency recorded"; then
  echo -e "${GREEN}Frequency post successful: $FREQ_RESPONSE${NC}"
else
  echo -e "${RED}Frequency post failed: $FREQ_RESPONSE${NC}"
  exit 1
fi

# Test 6: WebSocket Connection
echo "Testing WebSocket connection..."
echo "Starting WebSocket test with token: $JWT_TOKEN" > ws_log.txt
node src/test-websocket.js "$JWT_TOKEN" > ws_output.txt 2>&1

if grep -q "Connected" ws_output.txt && grep -q "Received:" ws_output.txt; then
  echo -e "${GREEN}WebSocket connection successful:${NC}"
  cat ws_output.txt
else
  echo -e "${RED}WebSocket connection failed:${NC}"
  cat ws_output.txt
  echo -e "${RED}Full log:${NC}"
  cat ws_log.txt
  exit 1
fi

# Cleanup
rm -f ws_output.txt ws_log.txt

echo -e "${GREEN}All tests passed successfully!${NC}"