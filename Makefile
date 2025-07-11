# Makefile for eBPF HTTP Tracing PoC

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
EBPF_SRC := $(SRC_DIR)/http_tracer.c
EBPF_OBJ := http_tracer.o
GO_MAIN := $(CMD_DIR)/tracer/main.go
BINARY := $(BUILD_DIR)/http-tracer

# eBPF compilation flags
EBPF_CFLAGS := -O2 -g -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/$(shell uname -m)-linux-gnu

# Default target
.PHONY: all
all: $(BINARY)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile eBPF program
$(EBPF_OBJ): $(EBPF_SRC)
	@echo "Compiling eBPF program..."
	$(CLANG) $(EBPF_CFLAGS) -c $(EBPF_SRC) -o $(EBPF_OBJ)

# Build Go binary
$(BINARY): $(EBPF_OBJ) $(GO_MAIN) | $(BUILD_DIR)
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
	rm -f $(EBPF_OBJ)
	rm -rf $(BUILD_DIR)
	$(GO) clean

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
	@echo "eBPF HTTP Tracing PoC - Available targets:"
	@echo ""
	@echo "  all           - Build the complete project (default)"
	@echo "  deps          - Install Go and Python dependencies"
	@echo "  clean         - Clean build artifacts"
	@echo "  run           - Run the HTTP tracer (requires root)"
	@echo "  test-server   - Start the Flask test server"
	@echo "  test          - Run simple HTTP tests"
	@echo "  test-full     - Run comprehensive HTTP tests"
	@echo "  check-system  - Check system requirements"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Usage example:"
	@echo "  1. make deps          # Install dependencies"
	@echo "  2. make all           # Build the project"
	@echo "  3. make check-system  # Verify system requirements"
	@echo "  4. Terminal 1: make test-server"
	@echo "  5. Terminal 2: sudo make run"
	@echo "  6. Terminal 3: make test"

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
