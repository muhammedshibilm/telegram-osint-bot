#!/bin/bash

echo " Deploying Telegram OSINT Bot..."

# Check if .env exists
if [ ! -f .env ]; then
    echo " .env file not found!"
    echo "Copy .env.example to .env and configure it first."
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed!"
    exit 1
fi

# Check if Docker Compose V2 is installed
if ! docker compose version &> /dev/null; then
    echo " Docker Compose V2 is not installed!"
    exit 1
fi

# Stop existing containers
echo "Stopping existing containers..."
docker compose down

# Build and start
echo " Building and starting containers..."
docker compose up -d --build

# Show logs
echo " Showing logs (Ctrl+C to exit)..."
docker compose logs -f
