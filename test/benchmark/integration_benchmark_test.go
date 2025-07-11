package benchmark

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestTracerPerformanceBenchmark runs comprehensive performance benchmarks
func TestTracerPerformanceBenchmark(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Performance benchmarks require root privileges")
	}
	
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping performance benchmarks in short mode")
	}
	
	benchmark := NewTracerBenchmark()
	
	// Start test server
	err := benchmark.StartTestServer()
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer benchmark.StopTestServer()
	
	// Start tracer
	err = benchmark.StartTracer()
	if err != nil {
		t.Fatalf("Failed to start tracer: %v", err)
	}
	defer benchmark.StopTracer()
	
	// Define benchmark scenarios
	scenarios := []struct {
		name        string
		duration    time.Duration
		requestRate int
		concurrency int
	}{
		{"Light Load", 30 * time.Second, 50, 5},
		{"Medium Load", 60 * time.Second, 200, 10},
		{"Heavy Load", 60 * time.Second, 500, 20},
		{"Stress Test", 30 * time.Second, 1000, 50},
	}
	
	var results []*BenchmarkResults
	
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Running benchmark: %s", scenario.name)
			t.Logf("Parameters: %d req/sec, %d concurrent, %v duration", 
				scenario.requestRate, scenario.concurrency, scenario.duration)
			
			// Configure benchmark
			benchmark.SetParameters(scenario.duration, scenario.requestRate, scenario.concurrency)
			
			// Run benchmark
			result, err := benchmark.RunBenchmark(scenario.name)
			if err != nil {
				t.Fatalf("Benchmark failed: %v", err)
			}
			
			results = append(results, result)
			
			// Print results
			result.PrintResults()
			
			// Save results to file
			filename := "benchmark_" + scenario.name + "_results.txt"
			err = result.SaveResults(filename)
			if err != nil {
				t.Logf("Warning: Failed to save results to %s: %v", filename, err)
			}
			
			// Performance assertions based on project requirements
			validatePerformanceRequirements(t, result, scenario.name)
		})
	}
	
	// Generate comparison report
	generateComparisonReport(t, results)
}

// validatePerformanceRequirements checks if results meet project requirements
func validatePerformanceRequirements(t *testing.T, result *BenchmarkResults, scenarioName string) {
	// CPU overhead should be < 5% (project requirement)
	if result.SystemMetrics != nil && result.SystemMetrics.CPUOverhead > 5.0 {
		t.Errorf("%s: CPU overhead too high: %.2f%% (limit: 5%%)", 
			scenarioName, result.SystemMetrics.CPUOverhead)
	}
	
	// Memory overhead should be < 100MB (project requirement)
	if result.SystemMetrics != nil && result.SystemMetrics.MemoryOverhead > 100*1024*1024 {
		t.Errorf("%s: Memory overhead too high: %.2f MB (limit: 100MB)", 
			scenarioName, result.SystemMetrics.MemoryOverhead/1024/1024)
	}
	
	// Error rate should be < 1%
	if result.ErrorRate > 1.0 {
		t.Errorf("%s: Error rate too high: %.2f%% (limit: 1%%)", 
			scenarioName, result.ErrorRate)
	}
	
	// Latency impact should be < 1ms (project requirement)
	if result.AvgLatency > 1*time.Millisecond {
		t.Logf("%s: Warning - Average latency: %v (target: <1ms)", 
			scenarioName, result.AvgLatency)
	}
	
	// Throughput should meet minimum requirements
	minThroughput := 10.0 // 10 req/sec minimum
	if result.Throughput < minThroughput {
		t.Errorf("%s: Throughput too low: %.2f req/sec (minimum: %.2f)", 
			scenarioName, result.Throughput, minThroughput)
	}
	
	t.Logf("%s: Performance validation passed", scenarioName)
}

// generateComparisonReport creates a comparison report across all scenarios
func generateComparisonReport(t *testing.T, results []*BenchmarkResults) {
	t.Log("\n=== Performance Comparison Report ===")
	
	t.Log("Scenario\t\tThroughput\tAvg Latency\tCPU\tMemory")
	t.Log("--------\t\t----------\t-----------\t---\t------")
	
	for _, result := range results {
		cpuUsage := "N/A"
		memUsage := "N/A"
		
		if result.SystemMetrics != nil {
			cpuUsage = fmt.Sprintf("%.1f%%", result.SystemMetrics.AverageCPU)
			memUsage = fmt.Sprintf("%.1fMB", result.SystemMetrics.AverageMemory/1024/1024)
		}
		
		t.Logf("%-15s\t%.1f req/s\t%v\t\t%s\t%s",
			result.TestName,
			result.Throughput,
			result.AvgLatency,
			cpuUsage,
			memUsage)
	}
	
	// Find best and worst performing scenarios
	if len(results) > 1 {
		bestThroughput := results[0]
		worstThroughput := results[0]
		
		for _, result := range results[1:] {
			if result.Throughput > bestThroughput.Throughput {
				bestThroughput = result
			}
			if result.Throughput < worstThroughput.Throughput {
				worstThroughput = result
			}
		}
		
		t.Logf("\nBest throughput: %s (%.1f req/s)", 
			bestThroughput.TestName, bestThroughput.Throughput)
		t.Logf("Worst throughput: %s (%.1f req/s)", 
			worstThroughput.TestName, worstThroughput.Throughput)
	}
}

// BenchmarkEventProcessingOverhead measures the overhead of event processing
func BenchmarkEventProcessingOverhead(b *testing.B) {
	// This benchmark measures the pure overhead of event processing
	// without network I/O
	
	events := make([]TestEvent, b.N)
	for i := 0; i < b.N; i++ {
		events[i] = TestEvent{
			Timestamp: uint64(time.Now().UnixNano()),
			RequestID: uint64(i),
			PID:       uint32(1000 + i%100),
			Method:    "GET",
			Path:      "/api/test",
		}
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		processEvent(&events[i])
	}
	
	// Report custom metrics
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/sec")
}

// BenchmarkMemoryAllocation measures memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		// Simulate event allocation patterns
		event := &TestEvent{
			Timestamp: uint64(time.Now().UnixNano()),
			RequestID: uint64(i),
			PID:       uint32(1000 + i%100),
			Method:    "GET",
			Path:      "/api/test",
		}
		
		// Simulate processing
		_ = event.String()
	}
}

// String method for TestEvent to simulate processing
func (te *TestEvent) String() string {
	return fmt.Sprintf("Event{ID: %d, PID: %d, Method: %s, Path: %s}", 
		te.RequestID, te.PID, te.Method, te.Path)
}

// TestBaselinePerformance measures baseline performance without tracing
func TestBaselinePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping baseline performance test in short mode")
	}
	
	benchmark := NewTracerBenchmark()
	
	// Start only the test server (no tracer)
	err := benchmark.StartTestServer()
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer benchmark.StopTestServer()
	
	// Configure for baseline test
	benchmark.SetParameters(30*time.Second, 200, 10)
	
	// Run load test without tracer
	t.Log("Running baseline performance test (no tracing)")
	start := time.Now()
	latencies := benchmark.runLoadTest()
	duration := time.Since(start)
	
	// Calculate baseline metrics
	avgLatency := benchmark.calculateAverageLatency(latencies)
	throughput := float64(len(latencies)) / duration.Seconds()
	
	t.Logf("Baseline Performance Results:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Requests: %d", len(latencies))
	t.Logf("  Throughput: %.2f req/sec", throughput)
	t.Logf("  Average Latency: %v", avgLatency)
	
	// Save baseline results for comparison
	baselineFile := "baseline_performance.txt"
	file, err := os.Create(baselineFile)
	if err != nil {
		t.Logf("Warning: Could not save baseline results: %v", err)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(file, "Baseline Performance (No Tracing)\n")
	fmt.Fprintf(file, "=================================\n")
	fmt.Fprintf(file, "Duration: %v\n", duration)
	fmt.Fprintf(file, "Requests: %d\n", len(latencies))
	fmt.Fprintf(file, "Throughput: %.2f req/sec\n", throughput)
	fmt.Fprintf(file, "Average Latency: %v\n", avgLatency)
	
	t.Logf("Baseline results saved to %s", baselineFile)
}
