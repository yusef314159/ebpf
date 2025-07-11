# eBPF Tracer Performance Benchmarking

This directory contains comprehensive performance benchmarking tools for the eBPF HTTP tracer project. The benchmarking suite is designed to measure CPU overhead, memory usage, event throughput, and latency impact to ensure the tracer meets production-grade performance requirements.

## Benchmark Structure

```
test/benchmark/
├── README.md                           # This file
├── performance_test.go                 # Unit-level performance tests
├── system_monitor.go                   # System resource monitoring
├── tracer_benchmark.go                 # Tracer-specific benchmarking
├── integration_benchmark_test.go       # End-to-end performance tests
└── ../run_benchmarks.sh               # Comprehensive benchmark runner
```

## Performance Requirements

Based on the project specification, the eBPF tracer must meet these performance targets:

- **CPU Overhead**: <5% under normal load
- **Memory Usage**: <100MB for userspace agent
- **Event Throughput**: >10,000 events/second
- **Latency Impact**: <1ms additional latency
- **System Stability**: 99.9% uptime

## Benchmark Categories

### 1. Unit Benchmarks (`performance_test.go`)

Measures individual component performance:

- **Event Processing**: Event creation and processing overhead
- **Concurrent Processing**: Multi-threaded event handling performance
- **Memory Allocation**: Memory allocation patterns and efficiency
- **HTTP Request Latency**: Request processing latency measurement

**Example Results:**
```
BenchmarkEventProcessing-8         1914296      1265 ns/op      87 B/op       3 allocs/op
BenchmarkMemoryAllocation-8        5213846       387 ns/op     112 B/op       5 allocs/op
```

### 2. System Monitoring (`system_monitor.go`)

Provides real-time system resource monitoring:

- **CPU Usage**: Process-level CPU utilization tracking
- **Memory Usage**: RSS and VSZ memory monitoring
- **File Descriptors**: Open file handle tracking
- **Context Switches**: System call and context switch counting

### 3. Tracer Benchmarks (`tracer_benchmark.go`)

End-to-end tracer performance measurement:

- **Request Throughput**: Requests per second under load
- **Latency Distribution**: P95, P99 latency percentiles
- **Error Rate**: Request failure percentage
- **System Impact**: Resource usage during operation

### 4. Integration Benchmarks (`integration_benchmark_test.go`)

Comprehensive performance validation:

- **Load Scenarios**: Light, medium, heavy, and stress testing
- **Performance Validation**: Automated requirement checking
- **Baseline Comparison**: Performance with/without tracing
- **Memory Leak Detection**: Extended operation memory analysis

## Running Benchmarks

### Quick Start

```bash
# Run all unit benchmarks
make benchmark-unit

# Run comprehensive performance benchmarks (requires root)
sudo make benchmark-performance

# Run with verbose output
sudo VERBOSE=true make benchmark-verbose

# Run baseline performance test
make benchmark-baseline
```

### Detailed Usage

#### Unit Benchmarks Only
```bash
# Event processing benchmarks
go test -bench=BenchmarkEventProcessing -benchmem ./test/benchmark/

# Memory allocation benchmarks
go test -bench=BenchmarkMemoryAllocation -benchmem ./test/benchmark/

# All unit benchmarks
go test -bench=. -benchmem ./test/benchmark/
```

#### Integration Benchmarks (Requires Root)
```bash
# Full performance test suite
sudo go test -timeout=600s -v ./test/benchmark/ -run TestTracerPerformanceBenchmark

# Baseline performance (no tracing)
go test -timeout=120s -v ./test/benchmark/ -run TestBaselinePerformance

# Memory leak detection
go test -timeout=300s -v ./test/benchmark/ -run TestMemoryLeaks
```

#### Comprehensive Benchmark Runner
```bash
# Run all benchmarks with automatic result collection
sudo ./test/run_benchmarks.sh

# With custom configuration
sudo BENCHMARK_DURATION=120s OUTPUT_DIR=my_results ./test/run_benchmarks.sh
```

## Benchmark Configuration

### Environment Variables

- `VERBOSE`: Enable verbose output (default: false)
- `SKIP_ROOT_TESTS`: Skip tests requiring root privileges (default: false)
- `BENCHMARK_DURATION`: Individual benchmark duration (default: 60s)
- `OUTPUT_DIR`: Results output directory (default: benchmark_results)

### Load Test Parameters

The integration benchmarks include multiple load scenarios:

| Scenario    | Requests/sec | Concurrency | Duration |
|-------------|--------------|-------------|----------|
| Light Load  | 50           | 5           | 30s      |
| Medium Load | 200          | 10          | 60s      |
| Heavy Load  | 500          | 20          | 60s      |
| Stress Test | 1000         | 50          | 30s      |

## Performance Metrics

### Measured Metrics

1. **Throughput Metrics**
   - Requests per second
   - Events per second
   - Event processing rate

2. **Latency Metrics**
   - Average request latency
   - 95th percentile latency
   - 99th percentile latency
   - Minimum/maximum latency

3. **Resource Metrics**
   - CPU usage percentage
   - Memory usage (RSS/VSZ)
   - File descriptor count
   - Context switches

4. **Quality Metrics**
   - Error rate percentage
   - Request success rate
   - System stability

### Performance Validation

Benchmarks automatically validate against project requirements:

```go
// CPU overhead validation
if result.SystemMetrics.CPUOverhead > 5.0 {
    t.Errorf("CPU overhead too high: %.2f%% (limit: 5%%)", 
        result.SystemMetrics.CPUOverhead)
}

// Memory overhead validation
if result.SystemMetrics.MemoryOverhead > 100*1024*1024 {
    t.Errorf("Memory overhead too high: %.2f MB (limit: 100MB)", 
        result.SystemMetrics.MemoryOverhead/1024/1024)
}
```

## Results Analysis

### Output Files

Benchmark results are saved in structured formats:

- `benchmark_summary_YYYYMMDD_HHMMSS.txt`: Overall summary
- `*_output.txt`: Detailed benchmark outputs
- `system_info.txt`: System configuration
- `baseline_performance.txt`: Baseline measurements

### Sample Results

```
=== Benchmark Results: Medium Load ===
Duration: 1m0s
Requests Sent: 12000
Requests Succeeded: 11987
Throughput: 199.78 req/sec
Error Rate: 0.11%

Latency Statistics:
  Average: 2.3ms
  95th Percentile: 4.1ms
  99th Percentile: 7.8ms

System Performance:
  Average CPU: 3.2%
  Peak CPU: 4.8%
  Average Memory: 45.2 MB
  Memory Overhead: 12.3 MB
```

## Continuous Integration

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
- name: Run Performance Benchmarks
  run: |
    make deps
    make all
    sudo make benchmark-performance
    
- name: Upload Benchmark Results
  uses: actions/upload-artifact@v3
  with:
    name: benchmark-results
    path: benchmark_results/
```

### Performance Regression Detection

The benchmark suite can detect performance regressions by comparing results with baseline measurements:

```bash
# Generate baseline
make benchmark-baseline

# Compare with current performance
sudo make benchmark-performance

# Results include comparison metrics
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Integration benchmarks require root privileges
   ```bash
   sudo ./test/run_benchmarks.sh
   ```

2. **Flask Not Available**: Install Flask for integration tests
   ```bash
   pip3 install flask requests
   ```

3. **High Memory Usage**: Check for memory leaks
   ```bash
   go test -v ./test/benchmark/ -run TestMemoryLeaks
   ```

4. **Low Performance**: Verify system resources and eBPF support
   ```bash
   make check-system
   ```

### Debug Mode

Enable verbose output for detailed analysis:

```bash
VERBOSE=true sudo ./test/run_benchmarks.sh
```

## Performance Optimization

### Identified Bottlenecks

Based on benchmark results, common performance bottlenecks include:

1. **Event Processing**: String formatting and JSON serialization
2. **Memory Allocation**: Frequent small allocations
3. **System Calls**: eBPF map operations
4. **Network I/O**: HTTP request processing overhead

### Optimization Strategies

1. **Object Pooling**: Reuse event structures
2. **Batch Processing**: Process events in batches
3. **Memory Pre-allocation**: Reduce garbage collection pressure
4. **Efficient Serialization**: Use binary formats where possible

## Contributing

When adding new benchmarks:

1. **Follow naming conventions**: `Benchmark*` for benchmarks
2. **Include resource measurement**: Use `b.ReportAllocs()`
3. **Add validation**: Check against performance requirements
4. **Document results**: Include expected performance ranges
5. **Update this README**: Document new benchmark categories
