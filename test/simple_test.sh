#!/bin/bash

# Simple test script for quick HTTP requests
SERVER_URL="http://localhost:5000"

echo "Testing eBPF HTTP tracer with simple requests..."

# Test basic GET requests
echo "1. GET /"
curl -s "$SERVER_URL/" | head -3

echo -e "\n2. GET /health"
curl -s "$SERVER_URL/health" | head -3

echo -e "\n3. GET /users"
curl -s "$SERVER_URL/users" | head -3

echo -e "\n4. POST /data"
curl -s -X POST -H "Content-Type: application/json" \
     -d '{"test": "data", "timestamp": "'$(date)'"}' \
     "$SERVER_URL/data" | head -3

echo -e "\nTest completed."
