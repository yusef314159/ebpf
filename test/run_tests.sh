#!/bin/bash

# eBPF Tracer Test Runner
# This script runs all tests for the eBPF HTTP tracer project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
VERBOSE=${VERBOSE:-false}
SKIP_ROOT_TESTS=${SKIP_ROOT_TESTS:-false}
TEST_TIMEOUT=${TEST_TIMEOUT:-300s}

# Directories
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$PROJECT_ROOT/test"
BUILD_DIR="$PROJECT_ROOT/build"

echo -e "${BLUE}eBPF Tracer Test Suite${NC}"
echo "=========================="
echo "Project root: $PROJECT_ROOT"
echo "Test timeout: $TEST_TIMEOUT"
echo ""

# Function to print test section headers
print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to print warning messages
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Function to run tests with proper error handling
run_test() {
    local test_name="$1"
    local test_command="$2"
    local require_root="${3:-false}"
    
    if [[ "$require_root" == "true" ]] && ! check_root; then
        if [[ "$SKIP_ROOT_TESTS" == "true" ]]; then
            print_warning "Skipping $test_name (requires root, SKIP_ROOT_TESTS=true)"
            return 0
        else
            print_warning "Skipping $test_name (requires root privileges)"
            return 0
        fi
    fi
    
    echo "Running: $test_name"
    
    if [[ "$VERBOSE" == "true" ]]; then
        if eval "$test_command"; then
            print_success "$test_name passed"
            return 0
        else
            print_error "$test_name failed"
            return 1
        fi
    else
        if eval "$test_command" >/dev/null 2>&1; then
            print_success "$test_name passed"
            return 0
        else
            print_error "$test_name failed"
            echo "Run with VERBOSE=true for detailed output"
            return 1
        fi
    fi
}

# Change to project root
cd "$PROJECT_ROOT"

# Check prerequisites
print_section "Prerequisites Check"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed"
    exit 1
fi
print_success "Go is available"

# Check if clang is installed
if ! command -v clang &> /dev/null; then
    print_error "Clang is not installed"
    exit 1
fi
print_success "Clang is available"

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python3 is not installed"
    exit 1
fi
print_success "Python3 is available"

# Check if project is built
if [[ ! -f "$BUILD_DIR/http-tracer" ]]; then
    print_warning "Project not built, building now..."
    if ! make all; then
        print_error "Failed to build project"
        exit 1
    fi
    print_success "Project built successfully"
else
    print_success "Project is built"
fi

# Check if eBPF object exists
if [[ ! -f "http_tracer.o" ]]; then
    print_error "eBPF object file not found. Run 'make all' first."
    exit 1
fi
print_success "eBPF object file exists"

# Initialize test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Function to update test counters
update_counters() {
    local result=$1
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    case $result in
        0) PASSED_TESTS=$((PASSED_TESTS + 1)) ;;
        1) FAILED_TESTS=$((FAILED_TESTS + 1)) ;;
        *) SKIPPED_TESTS=$((SKIPPED_TESTS + 1)) ;;
    esac
}

# Run unit tests
print_section "Unit Tests"

run_test "Go unit tests" "go test -timeout $TEST_TIMEOUT -v ./test/unit/..."
update_counters $?

run_test "HTTP parser tests" "go test -timeout $TEST_TIMEOUT -v ./test/ebpf/ -run TestHTTP"
update_counters $?

# Run eBPF program tests (require root)
print_section "eBPF Program Tests"

run_test "eBPF program loading" "go test -timeout $TEST_TIMEOUT -v ./test/ebpf/ -run TestEBPFProgramLoading" true
update_counters $?

run_test "eBPF map operations" "go test -timeout $TEST_TIMEOUT -v ./test/ebpf/ -run TestEBPFMapOperations" true
update_counters $?

run_test "eBPF program verification" "go test -timeout $TEST_TIMEOUT -v ./test/ebpf/ -run TestEBPFProgramVerification" true
update_counters $?

# Run integration tests (require root)
print_section "Integration Tests"

# Check if Flask is available for integration tests
if python3 -c "import flask" 2>/dev/null; then
    run_test "Basic HTTP tracing" "go test -timeout $TEST_TIMEOUT -v ./test/integration/ -run TestBasicHTTPTracing" true
    update_counters $?
    
    run_test "Concurrent HTTP tracing" "go test -timeout $TEST_TIMEOUT -v ./test/integration/ -run TestConcurrentHTTPTracing" true
    update_counters $?
else
    print_warning "Flask not available, skipping integration tests"
    print_warning "Install with: pip3 install flask"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 2))
fi

# Run existing shell-based tests
print_section "Legacy Tests"

if [[ -f "$TEST_DIR/simple_test.sh" ]]; then
    run_test "Simple shell tests" "cd $TEST_DIR && ./simple_test.sh"
    update_counters $?
else
    print_warning "Simple test script not found"
fi

# Run benchmarks (optional)
if [[ "${RUN_BENCHMARKS:-false}" == "true" ]]; then
    print_section "Benchmarks"
    
    run_test "Unit test benchmarks" "go test -bench=. -benchmem ./test/unit/..."
    update_counters $?
    
    run_test "eBPF benchmarks" "go test -bench=. -benchmem ./test/ebpf/..." true
    update_counters $?
fi

# Print test summary
print_section "Test Summary"

echo "Total tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
echo -e "Skipped: ${YELLOW}$SKIPPED_TESTS${NC}"

if [[ $FAILED_TESTS -eq 0 ]]; then
    print_success "All tests passed!"
    exit 0
else
    print_error "$FAILED_TESTS test(s) failed"
    exit 1
fi
