#!/bin/bash

# Test script for eBPF HTTP tracing PoC
# Generates various HTTP requests to test the tracing system

SERVER_URL="http://localhost:5000"
DELAY=2  # Delay between requests in seconds

echo "=== eBPF HTTP Tracing Test Script ==="
echo "Server URL: $SERVER_URL"
echo "Delay between requests: ${DELAY}s"
echo "Press Ctrl+C to stop"
echo

# Function to make a request and show the command
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo "[$description]"
    if [ "$method" = "GET" ]; then
        echo "Command: curl -s $SERVER_URL$endpoint"
        curl -s "$SERVER_URL$endpoint" | jq . 2>/dev/null || curl -s "$SERVER_URL$endpoint"
    elif [ "$method" = "POST" ]; then
        echo "Command: curl -s -X POST -H 'Content-Type: application/json' -d '$data' $SERVER_URL$endpoint"
        curl -s -X POST -H "Content-Type: application/json" -d "$data" "$SERVER_URL$endpoint" | jq . 2>/dev/null || curl -s -X POST -H "Content-Type: application/json" -d "$data" "$SERVER_URL$endpoint"
    fi
    echo
    sleep $DELAY
}

# Check if server is running
echo "Checking if server is running..."
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    echo "Error: Server is not running at $SERVER_URL"
    echo "Please start the Flask server first:"
    echo "  python3 test/flask_server.py"
    exit 1
fi

echo "Server is running. Starting test requests..."
echo

# Test sequence
while true; do
    echo "=== Test Cycle $(date) ==="
    
    # Basic GET requests
    make_request "GET" "/" "Home page"
    make_request "GET" "/health" "Health check"
    make_request "GET" "/users" "Get all users"
    make_request "GET" "/users/1" "Get specific user"
    make_request "GET" "/users/999" "Get non-existent user (404)"
    
    # POST requests
    make_request "POST" "/users" "" "Create new user"
    make_request "POST" "/data" '{"name":"test","value":123}' "POST JSON data"
    
    # Slow endpoint
    make_request "GET" "/slow" "Slow processing endpoint"
    
    # External API call (creates outbound connection)
    make_request "GET" "/external" "External API call"
    
    echo "=== End of cycle ===\n"
    sleep 5
done
