# eBPF Tracer Test Suite

This directory contains comprehensive tests for the eBPF HTTP tracer project. The test suite is designed to validate functionality, performance, and reliability across different scenarios.

## Test Structure

```
test/
├── README.md                 # This file
├── run_tests.sh             # Main test runner script
├── unit/                    # Unit tests
│   └── event_test.go        # Event structure and serialization tests
├── ebpf/                    # eBPF-specific tests
│   ├── http_parser_test.go  # HTTP parsing logic tests
│   └── program_test.go      # eBPF program loading and verification tests
├── integration/             # Integration tests
│   └── tracer_test.go       # End-to-end tracing tests
├── flask_server.py          # Test HTTP server
├── simple_test.sh           # Legacy shell tests
└── test_requests.sh         # Legacy HTTP request tests
```

## Test Categories

### 1. Unit Tests (`test/unit/`)

Tests individual components and data structures:

- **Event Structure Tests**: Validate event serialization/deserialization
- **IP Conversion Tests**: Test IP address conversion functions
- **Field Validation Tests**: Ensure event fields are properly validated
- **Performance Benchmarks**: Measure event creation and serialization performance

**Run with:**
```bash
make test-unit
# or
go test -v ./test/unit/...
```

### 2. eBPF Program Tests (`test/ebpf/`)

Tests eBPF program functionality:

- **HTTP Parser Tests**: Validate HTTP request parsing logic
- **Program Loading Tests**: Test eBPF program compilation and loading
- **Map Operations Tests**: Verify BPF map functionality
- **Program Verification Tests**: Ensure programs pass kernel verifier
- **Security Tests**: Validate input sanitization and security measures

**Run with:**
```bash
make test-ebpf  # Requires root privileges
# or
sudo go test -v ./test/ebpf/...
```

### 3. Integration Tests (`test/integration/`)

End-to-end testing with real HTTP traffic:

- **Basic HTTP Tracing**: Test tracing of different HTTP methods
- **Concurrent Request Handling**: Validate concurrent request tracing
- **Performance Under Load**: Measure performance with high request volumes
- **Request Correlation**: Test request-response correlation

**Run with:**
```bash
# Requires root privileges and Flask
sudo make test-all
# or
sudo go test -v ./test/integration/...
```

## Test Runner

The main test runner (`test/run_tests.sh`) provides a comprehensive test execution framework:

### Basic Usage

```bash
# Run all tests
./test/run_tests.sh

# Run with verbose output
VERBOSE=true ./test/run_tests.sh

# Skip tests requiring root privileges
SKIP_ROOT_TESTS=true ./test/run_tests.sh

# Run with benchmarks
RUN_BENCHMARKS=true ./test/run_tests.sh
```

### Makefile Targets

```bash
# Run comprehensive test suite
make test-suite

# Run with verbose output
make test-verbose

# Run benchmarks
make benchmark

# Run specific test categories
make test-unit      # Unit tests only
make test-ebpf      # eBPF tests only (requires root)
make test-all       # All test categories
```

## Prerequisites

### System Requirements

- **Linux kernel 4.18+** with eBPF support
- **Root privileges** for eBPF and integration tests
- **Go 1.21+** for test execution
- **Clang/LLVM** for eBPF compilation
- **Python 3** with Flask for integration tests

### Installation

```bash
# Install system dependencies (Ubuntu/Debian)
make install-system-deps

# Install Go and Python dependencies
make deps

# Build the project
make all

# Verify system requirements
make check-system
```

## Test Configuration

### Environment Variables

- `VERBOSE`: Enable verbose test output (default: false)
- `SKIP_ROOT_TESTS`: Skip tests requiring root privileges (default: false)
- `TEST_TIMEOUT`: Test timeout duration (default: 300s)
- `RUN_BENCHMARKS`: Include benchmark tests (default: false)

### Test Server Configuration

The Flask test server (`flask_server.py`) provides various endpoints for testing:

- `GET /health` - Health check endpoint
- `GET /` - Root endpoint
- `GET /api/users` - API endpoint
- `POST /api/users` - POST endpoint
- `PUT /api/users/{id}` - PUT endpoint
- `DELETE /api/users/{id}` - DELETE endpoint

## Continuous Integration

The test suite is designed for CI/CD integration:

```yaml
# Example GitHub Actions workflow
- name: Run eBPF Tracer Tests
  run: |
    make deps
    make all
    sudo make test-suite
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: eBPF tests require root privileges
   ```bash
   sudo ./test/run_tests.sh
   ```

2. **eBPF Program Loading Failed**: Check kernel version and eBPF support
   ```bash
   make check-system
   ```

3. **Flask Import Error**: Install Flask for integration tests
   ```bash
   pip3 install flask requests
   ```

4. **Test Timeout**: Increase timeout for slow systems
   ```bash
   TEST_TIMEOUT=600s ./test/run_tests.sh
   ```

### Debug Mode

Enable verbose output for debugging:

```bash
VERBOSE=true ./test/run_tests.sh
```

### Selective Testing

Run specific test patterns:

```bash
# Run only HTTP parsing tests
go test -v ./test/ebpf/ -run TestHTTP

# Run only basic tracing tests
sudo go test -v ./test/integration/ -run TestBasicHTTPTracing
```

## Performance Testing

### Benchmarks

The test suite includes performance benchmarks:

```bash
# Run all benchmarks
make benchmark

# Run specific benchmarks
go test -bench=. -benchmem ./test/unit/...
go test -bench=. -benchmem ./test/ebpf/...
```

### Performance Metrics

Integration tests measure:

- **Request throughput**: Requests per second
- **Event capture rate**: Events per request
- **Latency impact**: Additional latency introduced by tracing
- **Memory usage**: Memory footprint during operation

## Contributing

When adding new tests:

1. **Follow naming conventions**: `Test*` for tests, `Benchmark*` for benchmarks
2. **Add appropriate categories**: Unit, eBPF, or integration
3. **Include error handling**: Proper error messages and cleanup
4. **Document test purpose**: Clear test descriptions and comments
5. **Update this README**: Document new test categories or requirements

## Test Results

Test results are categorized as:

- ✅ **Passed**: Test completed successfully
- ❌ **Failed**: Test failed with errors
- ⚠️ **Skipped**: Test skipped due to missing requirements

The test runner provides a comprehensive summary at the end of execution.
