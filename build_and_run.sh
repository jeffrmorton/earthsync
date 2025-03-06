#!/bin/bash

# Script to build and run all EarthSync project containers

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Stop and remove existing containers
log "Stopping and removing containers..."
docker stop client earthsync-server earthsync-detector redis postgres earthsync-test 2>/dev/null || true
docker rm client earthsync-server earthsync-detector redis postgres earthsync-test 2>/dev/null || true

# Remove existing network
log "Removing network..."
docker network rm earthsync-network 2>/dev/null || true

# Build Docker images
log "Building images..."
docker build -t earthsync-client:latest ./client || error "Client build failed"
docker build -t earthsync-server:latest ./server || error "Server build failed"
docker build -t earthsync-detector:latest ./detector || error "Detector build failed"
docker build -t earthsync-test:latest ./test || error "Test build failed"

# Create Docker network
log "Creating network..."
docker network create earthsync-network || error "Network creation failed"

# Run containers
log "Starting Redis..."
docker run -d --name redis --network earthsync-network -p 6379:6379 redis:6 --requirepass password || error "Redis failed"

log "Starting PostgreSQL..."
docker run -d --name postgres --network earthsync-network -p 5432:5432 -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRES_DB=earthsync postgres:13 || error "PostgreSQL failed"

log "Waiting for Redis and PostgreSQL (15s)..."
sleep 15

log "Starting server..."
docker run -d --name earthsync-server --network earthsync-network -p 3000:3000 -e JWT_SECRET=1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p --env-file ./server/.env earthsync-server:latest || error "Server failed"

log "Waiting for server (15s)..."
sleep 15

log "Starting detector..."
docker run -d --name earthsync-detector --network earthsync-network --env-file ./detector/.env earthsync-detector:latest || error "Detector failed"

log "Waiting for detector (30s)..."
sleep 30

log "Starting client..."
docker run -d --name client --network earthsync-network --env-file ./client/.env -p 3001:80 earthsync-client:latest || error "Client failed"

log "Waiting for client (15s)..."
sleep 15

log "Starting test..."
docker run -d --name earthsync-test --network earthsync-network --env-file ./test/.env earthsync-test:latest || error "Test failed"

log "Waiting for test (15s)..."
sleep 15

log "All containers running!"
log "Access the app at http://localhost:3001"
log "Check logs: docker logs <container_name> (e.g., docker logs earthsync-server)"
