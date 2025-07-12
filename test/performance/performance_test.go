package performance

import (
	"context"
	"testing"
	"time"

	"ebpf-tracing/pkg/performance"
	"ebpf-tracing/pkg/resilience"
	"ebpf-tracing/pkg/tracing"
)

// MockTracer is a simple mock tracer for testing
type MockTracer struct {}

// TestPerformanceOptimizer tests the performance optimizer
func TestPerformanceOptimizer(t *testing.T) {
	config := performance.DefaultOptimizerConfig()
	config.ProfilingInterval = 100 * time.Millisecond
	config.OptimizationInterval = 500 * time.Millisecond
	
	optimizer := performance.NewPerformanceOptimizer(config)
	if optimizer == nil {
		t.Fatal("Expected optimizer to be created")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start optimizer
	err := optimizer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start optimizer: %v", err)
	}
	defer optimizer.Stop()

	// Test event optimization
	event := &tracing.TraceEvent{
		Timestamp:   uint64(time.Now().UnixNano()),
		RequestID:   1,
		EventType:   "test",
		ServiceName: "test-service",
		Payload:     "test payload",
	}

	optimizedEvent := optimizer.OptimizeEvent(event)
	if optimizedEvent == nil {
		t.Error("Expected optimized event to be returned")
	}

	// Release event
	optimizer.ReleaseEvent(optimizedEvent)

	// Test buffer management
	buffer := optimizer.GetBuffer("test-buffer", 1024)
	if len(buffer) != 1024 {
		t.Errorf("Expected buffer size 1024, got %d", len(buffer))
	}

	optimizer.ReleaseBuffer("test-buffer", buffer)

	// Wait for some profiling cycles
	time.Sleep(1 * time.Second)

	// Get statistics
	stats := optimizer.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	if stats.EventsProcessed == 0 {
		t.Error("Expected events processed to be > 0")
	}

	detailedStats := optimizer.GetDetailedStats()
	if detailedStats == nil {
		t.Error("Expected detailed stats to be non-nil")
	}

	t.Logf("Performance stats: %+v", stats)
	t.Logf("Detailed stats keys: %v", getMapKeys(detailedStats))
}

// TestBenchmarkSuite tests the benchmark suite
func TestBenchmarkSuite(t *testing.T) {
	config := performance.DefaultBenchmarkConfig()
	config.DurationSeconds = 5 // Short test
	config.EventsPerSecond = 100
	config.ConcurrentWorkers = 2
	config.WarmupSeconds = 1
	config.CooldownSeconds = 1

	// Create a mock tracer
	tracer := &MockTracer{} // Simplified for testing

	// Create optimizer
	optimizerConfig := performance.DefaultOptimizerConfig()
	optimizer := performance.NewPerformanceOptimizer(optimizerConfig)

	suite := performance.NewBenchmarkSuite(config, tracer, optimizer)
	if suite == nil {
		t.Fatal("Expected benchmark suite to be created")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run benchmark
	results, err := suite.RunBenchmark(ctx)
	if err != nil {
		t.Fatalf("Benchmark failed: %v", err)
	}

	// Validate results
	if results.TotalEvents == 0 {
		t.Error("Expected total events to be > 0")
	}

	if results.EventsPerSecond <= 0 {
		t.Error("Expected events per second to be > 0")
	}

	if results.Duration <= 0 {
		t.Error("Expected duration to be > 0")
	}

	if results.PerformanceGrade == "" {
		t.Error("Expected performance grade to be set")
	}

	if len(results.Recommendations) == 0 {
		t.Error("Expected recommendations to be provided")
	}

	// Check latency stats
	if results.LatencyStats != nil {
		if results.LatencyStats.SampleCount == 0 {
			t.Error("Expected latency samples to be collected")
		}
		
		if results.LatencyStats.Min <= 0 {
			t.Error("Expected min latency to be > 0")
		}
	}

	// Check throughput stats
	if results.ThroughputStats != nil {
		if results.ThroughputStats.AverageThroughput <= 0 {
			t.Error("Expected average throughput to be > 0")
		}
	}

	t.Logf("Benchmark Results:")
	t.Logf("  Total Events: %d", results.TotalEvents)
	t.Logf("  Events/sec: %.2f", results.EventsPerSecond)
	t.Logf("  Duration: %v", results.Duration)
	t.Logf("  Performance Grade: %s", results.PerformanceGrade)
	t.Logf("  Success Rate: %.2f%%", results.SuccessRate)
	
	if results.LatencyStats != nil {
		t.Logf("  Latency P95: %v", results.LatencyStats.P95)
		t.Logf("  Latency P99: %v", results.LatencyStats.P99)
	}
	
	t.Logf("  Recommendations: %v", results.Recommendations)
}

// TestStressTester tests the stress tester
func TestStressTester(t *testing.T) {
	config := resilience.DefaultStressTestConfig()
	config.MaxEventsPerSecond = 100
	config.RampUpDuration = 2 * time.Second
	config.SustainDuration = 3 * time.Second
	config.RampDownDuration = 1 * time.Second
	config.ChaosTestingEnabled = false // Disable for unit test
	config.MemoryPressureTest = false  // Disable for unit test
	config.FailureInjectionRate = 0.01 // 1% failure rate

	// Create a mock tracer
	tracer := &MockTracer{} // Simplified for testing

	// Create optimizer
	optimizerConfig := performance.DefaultOptimizerConfig()
	optimizer := performance.NewPerformanceOptimizer(optimizerConfig)

	stressTester := resilience.NewStressTester(config, tracer, optimizer)
	if stressTester == nil {
		t.Fatal("Expected stress tester to be created")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run stress test
	results, err := stressTester.RunStressTest(ctx)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	// Validate results
	if results.TotalEvents == 0 {
		t.Error("Expected total events to be > 0")
	}

	if results.TotalDuration <= 0 {
		t.Error("Expected total duration to be > 0")
	}

	if results.SystemStability == "" {
		t.Error("Expected system stability to be set")
	}

	if results.ResilienceScore < 0 || results.ResilienceScore > 100 {
		t.Errorf("Expected resilience score between 0-100, got %.2f", results.ResilienceScore)
	}

	if len(results.Recommendations) == 0 {
		t.Error("Expected recommendations to be provided")
	}

	// Check phase results
	if len(results.PhaseResults) == 0 {
		t.Error("Expected phase results to be recorded")
	}

	// Validate specific phases
	phases := []string{"ramp_up", "sustain", "ramp_down"}
	for _, phase := range phases {
		if phaseResult, exists := results.PhaseResults[phase]; exists {
			if phaseResult.EventsProcessed == 0 {
				t.Errorf("Expected events processed in %s phase to be > 0", phase)
			}
			if phaseResult.Duration <= 0 {
				t.Errorf("Expected duration in %s phase to be > 0", phase)
			}
		} else {
			t.Errorf("Expected %s phase results to be recorded", phase)
		}
	}

	t.Logf("Stress Test Results:")
	t.Logf("  Total Events: %d", results.TotalEvents)
	t.Logf("  Successful Events: %d", results.SuccessfulEvents)
	t.Logf("  Failed Events: %d", results.FailedEvents)
	t.Logf("  Peak Events/sec: %.2f", results.PeakEventsPerSecond)
	t.Logf("  Peak Memory: %d bytes", results.PeakMemoryUsage)
	t.Logf("  Peak Goroutines: %d", results.PeakGoroutines)
	t.Logf("  System Stability: %s", results.SystemStability)
	t.Logf("  Resilience Score: %.2f", results.ResilienceScore)
	t.Logf("  Failure Points: %d", len(results.FailurePoints))
	t.Logf("  Memory Leaks: %d", results.MemoryLeaksDetected)
	t.Logf("  Recommendations: %v", results.Recommendations)

	// Log phase results
	for phase, result := range results.PhaseResults {
		t.Logf("  Phase %s: %d events, %d errors, %v duration, stable: %v",
			phase, result.EventsProcessed, result.ErrorCount, result.Duration, result.Stable)
	}
}

// TestEventPool tests the event pool functionality
func TestEventPool(t *testing.T) {
	config := performance.DefaultOptimizerConfig()
	config.EnableEventPooling = true
	config.MaxEventPoolSize = 100

	optimizer := performance.NewPerformanceOptimizer(config)
	defer optimizer.Stop()

	// Test event pooling
	events := make([]*tracing.TraceEvent, 10)
	
	// Get events from pool
	for i := 0; i < 10; i++ {
		event := &tracing.TraceEvent{
			RequestID: uint64(i),
			EventType: "test",
		}
		events[i] = optimizer.OptimizeEvent(event)
	}

	// Release events back to pool
	for _, event := range events {
		optimizer.ReleaseEvent(event)
	}

	// Get stats
	stats := optimizer.GetStats()
	if stats.EventsPooled == 0 {
		t.Error("Expected some events to be pooled")
	}

	t.Logf("Event pool stats: Pooled=%d, Allocated=%d", stats.EventsPooled, stats.EventsAllocated)
}

// TestBufferManager tests the buffer manager functionality
func TestBufferManager(t *testing.T) {
	config := performance.DefaultOptimizerConfig()
	config.EnableBufferOptimization = true
	config.BufferSize = 1024

	optimizer := performance.NewPerformanceOptimizer(config)
	defer optimizer.Stop()

	// Test buffer management
	buffers := make([][]byte, 5)
	
	// Get buffers
	for i := 0; i < 5; i++ {
		buffers[i] = optimizer.GetBuffer("test-buffer", 512)
		if len(buffers[i]) != 512 {
			t.Errorf("Expected buffer size 512, got %d", len(buffers[i]))
		}
	}

	// Release buffers
	for i, buffer := range buffers {
		optimizer.ReleaseBuffer("test-buffer", buffer)
		_ = i // Use the index
	}

	// Get detailed stats
	detailedStats := optimizer.GetDetailedStats()
	if bufferStats, exists := detailedStats["buffer_manager"]; exists {
		t.Logf("Buffer manager stats: %+v", bufferStats)
	}
}

// TestMemoryProfiling tests memory profiling functionality
func TestMemoryProfiling(t *testing.T) {
	config := performance.DefaultOptimizerConfig()
	config.EnableMemoryProfiling = true
	config.ProfilingInterval = 100 * time.Millisecond

	optimizer := performance.NewPerformanceOptimizer(config)
	defer optimizer.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Start optimizer
	err := optimizer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start optimizer: %v", err)
	}

	// Allocate some memory to trigger profiling
	data := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		data[i] = make([]byte, 1024)
	}

	// Wait for profiling
	time.Sleep(500 * time.Millisecond)

	// Get detailed stats
	detailedStats := optimizer.GetDetailedStats()
	if memoryStats, exists := detailedStats["memory_profiler"]; exists {
		t.Logf("Memory profiler stats: %+v", memoryStats)
	}

	// Keep reference to data to prevent GC
	_ = data
}

// TestCPUProfiling tests CPU profiling functionality
func TestCPUProfiling(t *testing.T) {
	config := performance.DefaultOptimizerConfig()
	config.EnableCPUProfiling = true
	config.ProfilingInterval = 100 * time.Millisecond

	optimizer := performance.NewPerformanceOptimizer(config)
	defer optimizer.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Start optimizer
	err := optimizer.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start optimizer: %v", err)
	}

	// Create some CPU load
	done := make(chan bool)
	go func() {
		for i := 0; i < 1000000; i++ {
			_ = i * i
		}
		done <- true
	}()

	// Wait for profiling
	time.Sleep(500 * time.Millisecond)

	// Get detailed stats
	detailedStats := optimizer.GetDetailedStats()
	if cpuStats, exists := detailedStats["cpu_profiler"]; exists {
		t.Logf("CPU profiler stats: %+v", cpuStats)
	}

	<-done
}

// Helper function to get map keys
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
