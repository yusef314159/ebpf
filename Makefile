# Makefile for Universal eBPF Tracing PoC

# Variables
CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
KERNEL_VERSION := $(shell uname -r)

# Directories
SRC_DIR := src
CMD_DIR := cmd
BUILD_DIR := build
TEST_DIR := test

# Files
EBPF_SRCS := $(SRC_DIR)/http_tracer.c $(SRC_DIR)/xdp_tracer.c $(SRC_DIR)/stack_tracer.c
EBPF_OBJS := http_tracer.o xdp_tracer.o stack_tracer.o
GO_MAIN := $(CMD_DIR)/tracer/main.go
BINARY := $(BUILD_DIR)/universal-tracer

# eBPF compilation flags
EBPF_CFLAGS := -O2 -g -Wall \
	-target bpf \
	-D__TARGET_ARCH_x86 \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-mllvm -bpf-stack-size=8192 \
	-Wno-pass-failed

# Default target
.PHONY: all
all: $(BINARY)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile individual eBPF programs
http_tracer.o: $(SRC_DIR)/http_tracer.c
	@echo "Compiling HTTP tracer eBPF program..."
	$(CLANG) $(EBPF_CFLAGS) -c $(SRC_DIR)/http_tracer.c -o http_tracer.o

xdp_tracer.o: $(SRC_DIR)/xdp_tracer.c
	@echo "Compiling XDP tracer eBPF program..."
	$(CLANG) $(EBPF_CFLAGS) -c $(SRC_DIR)/xdp_tracer.c -o xdp_tracer.o

stack_tracer.o: $(SRC_DIR)/stack_tracer.c
	@echo "Compiling Stack tracer eBPF program..."
	$(CLANG) $(EBPF_CFLAGS) -c $(SRC_DIR)/stack_tracer.c -o stack_tracer.o

# Compile all eBPF programs
.PHONY: ebpf
ebpf: $(EBPF_OBJS)
	@echo "All eBPF programs compiled successfully!"

# Build userspace binary (explicit target)
.PHONY: build
build: $(BINARY)
	@echo "Userspace binary built successfully: $(BINARY)"

# Build Go binary
$(BINARY): $(EBPF_OBJS) $(GO_MAIN) | $(BUILD_DIR)
	@echo "Building Go userspace program..."
	$(GO) mod tidy
	$(GO) build -o $(BINARY) $(GO_MAIN)

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	@echo "Installing Python dependencies for test server..."
	pip3 install flask requests

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(EBPF_OBJS)
	rm -rf $(BUILD_DIR)
	$(GO) clean

# Deep clean including Go module cache
.PHONY: clean-all
clean-all: clean
	@echo "Deep cleaning Go module cache..."
	$(GO) clean -modcache
	$(GO) mod tidy

# Run the tracer (requires root privileges)
.PHONY: run
run: $(BINARY)
	@echo "Running HTTP tracer (requires root privileges)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: This program requires root privileges to load eBPF programs."; \
		echo "Please run: sudo make run"; \
		exit 1; \
	fi
	./$(BINARY)

# Start test server
.PHONY: test-server
test-server:
	@echo "Starting Flask test server..."
	python3 $(TEST_DIR)/flask_server.py

# Run simple tests
.PHONY: test
test:
	@echo "Running simple HTTP tests..."
	./$(TEST_DIR)/simple_test.sh

# Run comprehensive tests
.PHONY: test-full
test-full:
	@echo "Running comprehensive HTTP tests..."
	./$(TEST_DIR)/test_requests.sh

# Run unit tests
.PHONY: test-unit
test-unit:
	@echo "Running unit tests..."
	$(GO) test -v ./test/unit/...

# Run eBPF program tests
.PHONY: test-ebpf
test-ebpf: $(EBPF_OBJS)
	@echo "Running eBPF program tests..."
	$(GO) test -v ./test/ebpf/...

# Run all tests
.PHONY: test-all
test-all: test-unit test-ebpf test test-full
	@echo "All tests completed!"

# Run comprehensive test suite
.PHONY: test-suite
test-suite:
	@echo "Running comprehensive test suite..."
	./$(TEST_DIR)/run_tests.sh

# Run tests with verbose output
.PHONY: test-verbose
test-verbose:
	@echo "Running tests with verbose output..."
	VERBOSE=true ./$(TEST_DIR)/run_tests.sh

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	RUN_BENCHMARKS=true ./$(TEST_DIR)/run_tests.sh

# Run comprehensive performance benchmarks
.PHONY: benchmark-performance
benchmark-performance:
	@echo "Running comprehensive performance benchmarks..."
	./$(TEST_DIR)/run_benchmarks.sh

# Run performance benchmarks with verbose output
.PHONY: benchmark-verbose
benchmark-verbose:
	@echo "Running performance benchmarks with verbose output..."
	VERBOSE=true ./$(TEST_DIR)/run_benchmarks.sh

# Run unit benchmarks only
.PHONY: benchmark-unit
benchmark-unit:
	@echo "Running unit benchmarks..."
	$(GO) test -bench=. -benchmem ./test/benchmark/

# Run baseline performance test
.PHONY: benchmark-baseline
benchmark-baseline:
	@echo "Running baseline performance test..."
	$(GO) test -timeout=120s -v ./test/benchmark/ -run TestBaselinePerformance

# Check system requirements
.PHONY: check-system
check-system:
	@echo "Checking system requirements..."
	@echo "Kernel version: $(KERNEL_VERSION)"
	@echo "Architecture: $(ARCH)"
	@which $(CLANG) > /dev/null || (echo "Error: clang not found. Please install clang." && exit 1)
	@which $(GO) > /dev/null || (echo "Error: go not found. Please install Go." && exit 1)
	@echo "Checking eBPF support..."
	@ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_accept > /dev/null 2>&1 || \
		(echo "Warning: Tracepoint sys_enter_accept not found. eBPF tracing may not work." && exit 1)
	@echo "System requirements check passed!"

# Show help
.PHONY: help
help:
	@echo "Universal eBPF Tracer - Available targets:"
	@echo ""
	@echo "  all           - Build the complete project (default)"
	@echo "  ebpf          - Compile eBPF programs only"
	@echo "  build         - Build userspace binary only"
	@echo "  deps          - Install Go and Python dependencies"
	@echo "  clean         - Clean build artifacts"
	@echo "  clean-all     - Deep clean including Go module cache"
	@echo "  run           - Run the HTTP tracer (requires root)"
	@echo "  test-server   - Start the Flask test server"
	@echo "  test          - Run simple HTTP tests"
	@echo "  test-full     - Run comprehensive HTTP tests"
	@echo "  check-system  - Check system requirements"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Usage example:"
	@echo "  1. make deps          # Install dependencies"
	@echo "  2. make ebpf          # Compile eBPF programs"
	@echo "  3. make build         # Build userspace binary"
	@echo "  4. make check-system  # Verify system requirements"
	@echo "  5. Terminal 1: make test-server"
	@echo "  6. Terminal 2: sudo make run"
	@echo "  7. Terminal 3: make test"
	@echo ""
	@echo "Quick build:"
	@echo "  make all              # Build everything (eBPF + userspace)"

# Development targets
.PHONY: dev-setup
dev-setup: deps check-system
	@echo "Development environment setup complete!"

.PHONY: rebuild
rebuild: clean all

# Install system dependencies (Ubuntu/Debian)
.PHONY: install-system-deps
install-system-deps:
	@echo "Installing system dependencies (Ubuntu/Debian)..."
	sudo apt-get update
	sudo apt-get install -y \
		clang \
		llvm \
		golang-go \
		python3 \
		python3-pip \
		libbpf-dev \
		linux-headers-$(shell uname -r) \
		build-essential
	@echo "System dependencies installed!"
