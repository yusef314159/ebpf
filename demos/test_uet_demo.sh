#!/bin/bash

# UET Demo Test Script
# ====================
# This script demonstrates UET's language-agnostic tracing capabilities
# by testing HTTP traffic that UET should capture.

echo "🚀 UET DEMONSTRATION TEST SCRIPT"
echo "================================="
echo "This script will generate HTTP traffic that UET should capture"
echo "Make sure UET is running in another terminal!"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test server URL
SERVER_URL="http://localhost:8080"

# Function to test if server is running
check_server() {
    echo -e "${BLUE}🔍 Checking if test server is running...${NC}"
    if curl -s "$SERVER_URL/api/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Test server is running${NC}"
        return 0
    else
        echo -e "${RED}❌ Test server is not running${NC}"
        echo "Please start the test server first:"
        echo "  python3 test/simple_http_server.py"
        return 1
    fi
}

# Function to make HTTP request and show what UET should capture
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo ""
    echo -e "${YELLOW}🔍 UET SHOULD CAPTURE: $description${NC}"
    echo "Request: $method $endpoint"
    
    if [ -n "$data" ]; then
        echo "Data: $data"
        response=$(curl -s -X "$method" "$SERVER_URL$endpoint" \
                       -H "Content-Type: application/json" \
                       -d "$data" \
                       -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\nBytes Received: %{size_download}")
    else
        response=$(curl -s -X "$method" "$SERVER_URL$endpoint" \
                       -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\nBytes Received: %{size_download}")
    fi
    
    echo "Response: $response"
    echo -e "${GREEN}✅ Request completed - UET should have captured this${NC}"
    
    # Small delay between requests
    sleep 1
}

# Main demo function
run_demo() {
    echo -e "${BLUE}🎯 Starting UET HTTP Tracing Demo${NC}"
    echo "UET should capture all of the following HTTP traffic:"
    echo ""
    
    # Test 1: Simple GET request
    make_request "GET" "/api/health" "" "Health check endpoint"
    
    # Test 2: GET user list
    make_request "GET" "/api/users" "" "Get all users"
    
    # Test 3: GET specific user
    make_request "GET" "/api/users/123" "" "Get specific user (ID: 123)"
    
    # Test 4: POST create user
    make_request "POST" "/api/users" '{"name":"John Doe","email":"john@example.com"}' "Create new user"
    
    # Test 5: POST login
    make_request "POST" "/api/login" '{"username":"admin","password":"secret"}' "User login"
    
    # Test 6: Slow endpoint (for timing analysis)
    echo ""
    echo -e "${YELLOW}⏱️  Testing slow endpoint - UET should capture timing details${NC}"
    make_request "GET" "/api/slow" "" "Slow response (2 second delay)"
    
    # Test 7: 404 error
    make_request "GET" "/api/nonexistent" "" "404 error response"
    
    # Test 8: Invalid JSON POST
    make_request "POST" "/api/users" 'invalid json' "Invalid JSON (400 error)"
    
    echo ""
    echo -e "${GREEN}🎉 DEMO COMPLETE!${NC}"
    echo "================================="
    echo "UET should have captured:"
    echo "  ✅ 8 HTTP requests (GET and POST)"
    echo "  ✅ Request/response timing"
    echo "  ✅ HTTP status codes (200, 201, 400, 404)"
    echo "  ✅ Request and response payloads"
    echo "  ✅ Network I/O (accept, read, write syscalls)"
    echo "  ✅ Function calls in Python HTTP server"
    echo ""
    echo "🔍 Check UET output to see captured events!"
}

# Function to generate continuous traffic
generate_traffic() {
    echo -e "${BLUE}🔄 Generating continuous HTTP traffic...${NC}"
    echo "Press Ctrl+C to stop"
    echo ""
    
    counter=1
    while true; do
        echo -e "${YELLOW}Request #$counter${NC}"
        
        # Rotate through different endpoints
        case $((counter % 4)) in
            1) make_request "GET" "/api/users/123" "" "Continuous traffic - User detail" ;;
            2) make_request "GET" "/api/health" "" "Continuous traffic - Health check" ;;
            3) make_request "POST" "/api/users" "{\"name\":\"User$counter\"}" "Continuous traffic - Create user" ;;
            0) make_request "GET" "/api/users" "" "Continuous traffic - User list" ;;
        esac
        
        counter=$((counter + 1))
        sleep 2
    done
}

# Main script logic
main() {
    # Check if server is running
    if ! check_server; then
        exit 1
    fi
    
    echo ""
    echo "Choose demo mode:"
    echo "1) Single demo run (8 test requests)"
    echo "2) Continuous traffic generation"
    echo "3) Exit"
    echo ""
    read -p "Enter choice (1-3): " choice
    
    case $choice in
        1)
            run_demo
            ;;
        2)
            generate_traffic
            ;;
        3)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please run the script again."
            exit 1
            ;;
    esac
}

# Run the main function
main
