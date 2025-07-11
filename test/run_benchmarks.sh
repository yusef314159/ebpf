#!/bin/bash

# eBPF Tracer Performance Benchmark Runner
# This script runs comprehensive performance benchmarks for the eBPF HTTP tracer

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERBOSE=${VERBOSE:-false}
SKIP_ROOT_TESTS=${SKIP_ROOT_TESTS:-false}
BENCHMARK_DURATION=${BENCHMARK_DURATION:-60s}
OUTPUT_DIR=${OUTPUT_DIR:-benchmark_results}

# Directories
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$PROJECT_ROOT/test"
BUILD_DIR="$PROJECT_ROOT/build"

echo -e "${BLUE}eBPF Tracer Performance Benchmark Suite${NC}"
echo "=========================================="
echo "Project root: $PROJECT_ROOT"
echo "Output directory: $OUTPUT_DIR"
echo "Benchmark duration: $BENCHMARK_DURATION"
echo ""

# Function to print section headers
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

# Change to project root
cd "$PROJECT_ROOT"

# Check prerequisites
print_section "Prerequisites Check"

# Check if running as root
if ! check_root; then
    if [[ "$SKIP_ROOT_TESTS" == "true" ]]; then
        print_warning "Not running as root, will skip eBPF benchmarks"
    else
        print_error "Performance benchmarks require root privileges"
        echo "Run with: sudo $0"
        echo "Or set SKIP_ROOT_TESTS=true to skip eBPF benchmarks"
        exit 1
    fi
else
    print_success "Running as root"
fi

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

# Check if Flask is available
if ! python3 -c "import flask" 2>/dev/null; then
    print_error "Flask is required for benchmarks"
    echo "Install with: pip3 install flask requests"
    exit 1
fi
print_success "Flask is available"

# Create output directory
mkdir -p "$OUTPUT_DIR"
print_success "Output directory created: $OUTPUT_DIR"

# Initialize results
BENCHMARK_START_TIME=$(date +%s)
RESULTS_FILE="$OUTPUT_DIR/benchmark_summary_$(date +%Y%m%d_%H%M%S).txt"

echo "eBPF Tracer Performance Benchmark Results" > "$RESULTS_FILE"
echo "=========================================" >> "$RESULTS_FILE"
echo "Date: $(date)" >> "$RESULTS_FILE"
echo "System: $(uname -a)" >> "$RESULTS_FILE"
echo "Go Version: $(go version)" >> "$RESULTS_FILE"
echo "Clang Version: $(clang --version | head -n1)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Function to run benchmark and capture results
run_benchmark() {
    local benchmark_name="$1"
    local benchmark_command="$2"
    local require_root="${3:-false}"
    
    if [[ "$require_root" == "true" ]] && ! check_root; then
        if [[ "$SKIP_ROOT_TESTS" == "true" ]]; then
            print_warning "Skipping $benchmark_name (requires root, SKIP_ROOT_TESTS=true)"
            return 0
        else
            print_warning "Skipping $benchmark_name (requires root privileges)"
            return 0
        fi
    fi
    
    echo "Running: $benchmark_name"
    echo "Command: $benchmark_command"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/${benchmark_name// /_}_output.txt"
    
    if [[ "$VERBOSE" == "true" ]]; then
        if eval "$benchmark_command" 2>&1 | tee "$output_file"; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_success "$benchmark_name completed in ${duration}s"
            
            # Add to summary
            echo "$benchmark_name: SUCCESS (${duration}s)" >> "$RESULTS_FILE"
            return 0
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_error "$benchmark_name failed after ${duration}s"
            
            # Add to summary
            echo "$benchmark_name: FAILED (${duration}s)" >> "$RESULTS_FILE"
            return 1
        fi
    else
        if eval "$benchmark_command" > "$output_file" 2>&1; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_success "$benchmark_name completed in ${duration}s"
            
            # Add to summary
            echo "$benchmark_name: SUCCESS (${duration}s)" >> "$RESULTS_FILE"
            return 0
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            print_error "$benchmark_name failed after ${duration}s"
            echo "Check output in: $output_file"
            
            # Add to summary
            echo "$benchmark_name: FAILED (${duration}s)" >> "$RESULTS_FILE"
            return 1
        fi
    fi
}

# Run unit benchmarks
print_section "Unit Benchmarks"

run_benchmark "Event Processing Benchmark" \
    "go test -bench=BenchmarkEventProcessing -benchmem -benchtime=10s ./test/benchmark/"

run_benchmark "Concurrent Event Processing Benchmark" \
    "go test -bench=BenchmarkConcurrentEventProcessing -benchmem -benchtime=10s ./test/benchmark/"

run_benchmark "HTTP Request Latency Benchmark" \
    "go test -bench=BenchmarkHTTPRequestLatency -benchmem -benchtime=10s ./test/benchmark/"

run_benchmark "Memory Allocation Benchmark" \
    "go test -bench=BenchmarkMemoryAllocation -benchmem -benchtime=10s ./test/benchmark/"

# Run baseline performance test
print_section "Baseline Performance"

run_benchmark "Baseline Performance Test" \
    "go test -timeout=120s -v ./test/benchmark/ -run TestBaselinePerformance"

# Run integration benchmarks (require root)
print_section "Integration Benchmarks"

run_benchmark "Tracer Performance Benchmark" \
    "go test -timeout=600s -v ./test/benchmark/ -run TestTracerPerformanceBenchmark" true

# Run memory leak tests
print_section "Memory Analysis"

run_benchmark "Memory Leak Test" \
    "go test -timeout=300s -v ./test/benchmark/ -run TestMemoryLeaks"

# Generate system information
print_section "System Information"

echo "Collecting system information..."
{
    echo "System Information"
    echo "=================="
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "CPU Info:"
    if [[ -f /proc/cpuinfo ]]; then
        grep "model name" /proc/cpuinfo | head -n1
        grep "cpu cores" /proc/cpuinfo | head -n1
    fi
    echo "Memory Info:"
    if [[ -f /proc/meminfo ]]; then
        grep "MemTotal" /proc/meminfo
        grep "MemAvailable" /proc/meminfo
    fi
    echo "Go Version: $(go version)"
    echo "Clang Version: $(clang --version | head -n1)"
    echo ""
} > "$OUTPUT_DIR/system_info.txt"

print_success "System information saved to $OUTPUT_DIR/system_info.txt"

# Calculate total benchmark time
BENCHMARK_END_TIME=$(date +%s)
TOTAL_DURATION=$((BENCHMARK_END_TIME - BENCHMARK_START_TIME))

# Finalize results summary
{
    echo ""
    echo "Benchmark Summary"
    echo "================="
    echo "Total Duration: ${TOTAL_DURATION}s"
    echo "Output Directory: $OUTPUT_DIR"
    echo ""
    echo "Individual benchmark results are available in the output directory."
    echo "Check the *_output.txt files for detailed results."
} >> "$RESULTS_FILE"

# Print final summary
print_section "Benchmark Summary"

echo "Total benchmark duration: ${TOTAL_DURATION}s"
echo "Results saved to: $RESULTS_FILE"
echo "Detailed outputs in: $OUTPUT_DIR/"

# Check if any benchmarks failed
if grep -q "FAILED" "$RESULTS_FILE"; then
    print_warning "Some benchmarks failed. Check the results for details."
    exit 1
else
    print_success "All benchmarks completed successfully!"
    exit 0
fi
