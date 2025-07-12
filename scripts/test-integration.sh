#!/bin/bash

# Test script for Universal eBPF Tracer <-> Vector eBPF Platform integration
# This script tests the communication bridge between the two systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SOCKET_PATH="/var/run/ebpf-tracer.sock"
TRACER_CONFIG="configs/tracer-with-vector.yaml"
VECTOR_CONFIG="vector-ebpf-platform/config/integration-pipeline.toml"
TEST_DURATION=30

echo -e "${BLUE}=== Universal eBPF Tracer <-> Vector eBPF Platform Integration Test ===${NC}"
echo

# Check if running as root (required for eBPF)
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root for eBPF functionality${NC}"
   echo "Please run: sudo $0"
   exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    
    # Kill background processes
    if [[ -n $TRACER_PID ]]; then
        echo "Stopping Universal eBPF Tracer (PID: $TRACER_PID)"
        kill $TRACER_PID 2>/dev/null || true
    fi
    
    if [[ -n $VECTOR_PID ]]; then
        echo "Stopping Vector eBPF Platform (PID: $VECTOR_PID)"
        kill $VECTOR_PID 2>/dev/null || true
    fi
    
    # Remove socket file
    rm -f $SOCKET_PATH
    
    echo -e "${GREEN}Cleanup completed${NC}"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

# Check if Universal eBPF Tracer binary exists
if [[ ! -f "cmd/tracer/tracer" ]]; then
    echo -e "${YELLOW}Building Universal eBPF Tracer...${NC}"
    cd cmd/tracer
    go build -o tracer .
    cd ../..
fi

# Check if Vector eBPF Platform binary exists
if [[ ! -f "vector-ebpf-platform/target/release/vector-ebpf" ]]; then
    echo -e "${YELLOW}Building Vector eBPF Platform...${NC}"
    cd vector-ebpf-platform
    cargo build --release
    cd ..
fi

# Check if configuration files exist
if [[ ! -f "$TRACER_CONFIG" ]]; then
    echo -e "${RED}Error: Tracer configuration file not found: $TRACER_CONFIG${NC}"
    exit 1
fi

if [[ ! -f "$VECTOR_CONFIG" ]]; then
    echo -e "${RED}Error: Vector configuration file not found: $VECTOR_CONFIG${NC}"
    exit 1
fi

echo -e "${GREEN}Prerequisites check passed${NC}"
echo

# Start Vector eBPF Platform first
echo -e "${BLUE}Starting Vector eBPF Platform...${NC}"
cd vector-ebpf-platform
./target/release/vector-ebpf --config ../config/integration-pipeline.toml &
VECTOR_PID=$!
cd ..

# Wait for Vector to start
sleep 3

# Check if Vector is running
if ! kill -0 $VECTOR_PID 2>/dev/null; then
    echo -e "${RED}Error: Vector eBPF Platform failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}Vector eBPF Platform started (PID: $VECTOR_PID)${NC}"

# Start Universal eBPF Tracer
echo -e "${BLUE}Starting Universal eBPF Tracer...${NC}"
./cmd/tracer/tracer --config $TRACER_CONFIG &
TRACER_PID=$!

# Wait for tracer to start
sleep 3

# Check if tracer is running
if ! kill -0 $TRACER_PID 2>/dev/null; then
    echo -e "${RED}Error: Universal eBPF Tracer failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}Universal eBPF Tracer started (PID: $TRACER_PID)${NC}"

# Check if Unix socket was created
if [[ ! -S "$SOCKET_PATH" ]]; then
    echo -e "${RED}Error: Unix socket not created at $SOCKET_PATH${NC}"
    exit 1
fi

echo -e "${GREEN}Unix socket created successfully${NC}"

# Generate some test traffic
echo -e "${BLUE}Generating test traffic for $TEST_DURATION seconds...${NC}"

# Function to generate HTTP traffic
generate_traffic() {
    local duration=$1
    local end_time=$((SECONDS + duration))
    
    while [[ $SECONDS -lt $end_time ]]; do
        # Make HTTP requests to generate events
        curl -s http://localhost:8080/ >/dev/null 2>&1 || true
        curl -s http://localhost:3000/api/health >/dev/null 2>&1 || true
        curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1 || true
        
        # Generate some TCP connections
        nc -z localhost 22 >/dev/null 2>&1 || true
        nc -z localhost 80 >/dev/null 2>&1 || true
        
        sleep 0.5
    done
}

# Start traffic generation in background
generate_traffic $TEST_DURATION &
TRAFFIC_PID=$!

# Monitor the integration
echo -e "${BLUE}Monitoring integration...${NC}"

# Check socket connectivity
echo "Testing socket connectivity..."
if timeout 5 bash -c "echo 'test' | nc -U $SOCKET_PATH" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Socket is accepting connections${NC}"
else
    echo -e "${YELLOW}⚠ Socket connectivity test inconclusive${NC}"
fi

# Monitor for a few seconds
for i in {1..10}; do
    echo -n "."
    sleep 1
done
echo

# Check process status
echo -e "${BLUE}Checking process status...${NC}"

if kill -0 $TRACER_PID 2>/dev/null; then
    echo -e "${GREEN}✓ Universal eBPF Tracer is running${NC}"
else
    echo -e "${RED}✗ Universal eBPF Tracer stopped unexpectedly${NC}"
fi

if kill -0 $VECTOR_PID 2>/dev/null; then
    echo -e "${GREEN}✓ Vector eBPF Platform is running${NC}"
else
    echo -e "${RED}✗ Vector eBPF Platform stopped unexpectedly${NC}"
fi

# Check socket status
if [[ -S "$SOCKET_PATH" ]]; then
    echo -e "${GREEN}✓ Unix socket is active${NC}"
    ls -la $SOCKET_PATH
else
    echo -e "${RED}✗ Unix socket is missing${NC}"
fi

# Wait for traffic generation to complete
wait $TRAFFIC_PID 2>/dev/null || true

echo
echo -e "${BLUE}Integration test completed!${NC}"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Check Vector eBPF Platform logs for received events"
echo "2. Verify events are being processed through the pipeline"
echo "3. Check configured sinks (Kafka, ClickHouse, etc.) for data"
echo "4. Monitor the web interface at http://localhost:3001"
echo
echo -e "${GREEN}Integration test finished successfully!${NC}"
