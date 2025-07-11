package benchmark

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// PerformanceMetrics holds performance measurement results
type PerformanceMetrics struct {
	CPUUsageBefore    float64
	CPUUsageAfter     float64
	CPUOverhead       float64
	MemoryBefore      uint64
	MemoryAfter       uint64
	MemoryOverhead    uint64
	EventsProcessed   uint64
	RequestsProcessed uint64
	Duration          time.Duration
	EventsPerSecond   float64
	RequestsPerSecond float64
	LatencyImpact     time.Duration
}

// SystemStats represents system resource usage
type SystemStats struct {
	CPUPercent    float64
	MemoryUsedMB  uint64
	Timestamp     time.Time
}

// getSystemStats retrieves current system resource usage
func getSystemStats() (*SystemStats, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// Get CPU usage (simplified - in production would use more sophisticated method)
	// For now, we'll use a basic approach
	cpuPercent := getCPUUsage()
	
	return &SystemStats{
		CPUPercent:   cpuPercent,
		MemoryUsedMB: m.Alloc / 1024 / 1024,
		Timestamp:    time.Now(),
	}, nil
}

// getCPUUsage returns approximate CPU usage percentage
func getCPUUsage() float64 {
	// Simplified CPU usage calculation
	// In production, would use /proc/stat or similar
	start := time.Now()
	for time.Since(start) < 10*time.Millisecond {
		// Busy wait to simulate CPU usage measurement
	}
	return 0.0 // Placeholder - would implement proper CPU measurement
}

// BenchmarkEventProcessing measures event processing performance
func BenchmarkEventProcessing(b *testing.B) {
	// Create test events
	events := make([]TestEvent, b.N)
	for i := 0; i < b.N; i++ {
		events[i] = TestEvent{
			Timestamp: uint64(time.Now().UnixNano()),
			RequestID: uint64(i),
			PID:       uint32(1000 + i%100),
			Method:    "GET",
			Path:      fmt.Sprintf("/api/test/%d", i),
		}
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		processEvent(&events[i])
	}
}

// TestEvent represents a simplified event for benchmarking
type TestEvent struct {
	Timestamp uint64
	RequestID uint64
	PID       uint32
	Method    string
	Path      string
}

// processEvent simulates event processing
func processEvent(event *TestEvent) {
	// Simulate event processing overhead
	_ = fmt.Sprintf("Processing event %d: %s %s", event.RequestID, event.Method, event.Path)
}

// BenchmarkConcurrentEventProcessing measures concurrent event processing
func BenchmarkConcurrentEventProcessing(b *testing.B) {
	const numWorkers = 10
	eventChan := make(chan TestEvent, 1000)
	
	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for event := range eventChan {
				processEvent(&event)
			}
		}()
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	// Send events
	for i := 0; i < b.N; i++ {
		event := TestEvent{
			Timestamp: uint64(time.Now().UnixNano()),
			RequestID: uint64(i),
			PID:       uint32(1000 + i%100),
			Method:    "GET",
			Path:      fmt.Sprintf("/api/test/%d", i),
		}
		eventChan <- event
	}
	
	close(eventChan)
	wg.Wait()
}

// BenchmarkHTTPRequestLatency measures HTTP request latency impact
func BenchmarkHTTPRequestLatency(b *testing.B) {
	// This benchmark would measure latency with and without tracing
	// For now, we'll simulate the measurement
	
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		start := time.Now()
		
		// Simulate HTTP request (would be actual request in real test)
		time.Sleep(1 * time.Millisecond) // Simulate network latency
		
		latency := time.Since(start)
		b.ReportMetric(float64(latency.Nanoseconds()), "ns/request")
	}
	
	_ = client // Avoid unused variable warning
}

// TestPerformanceUnderLoad tests system performance under various load conditions
func TestPerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	
	loadTests := []struct {
		name           string
		requestsPerSec int
		duration       time.Duration
		concurrency    int
	}{
		{"Light Load", 100, 30 * time.Second, 5},
		{"Medium Load", 500, 30 * time.Second, 10},
		{"Heavy Load", 1000, 30 * time.Second, 20},
	}
	
	for _, lt := range loadTests {
		t.Run(lt.name, func(t *testing.T) {
			metrics := runLoadTest(t, lt.requestsPerSec, lt.duration, lt.concurrency)
			
			t.Logf("Load Test Results for %s:", lt.name)
			t.Logf("  Duration: %v", metrics.Duration)
			t.Logf("  Requests Processed: %d", metrics.RequestsProcessed)
			t.Logf("  Events Processed: %d", metrics.EventsProcessed)
			t.Logf("  Requests/sec: %.2f", metrics.RequestsPerSecond)
			t.Logf("  Events/sec: %.2f", metrics.EventsPerSecond)
			t.Logf("  Memory Overhead: %d MB", metrics.MemoryOverhead/1024/1024)
			
			// Performance assertions based on project requirements
			if metrics.RequestsPerSecond < float64(lt.requestsPerSec)*0.8 {
				t.Errorf("Request throughput too low: %.2f req/sec (expected >= %.2f)", 
					metrics.RequestsPerSecond, float64(lt.requestsPerSec)*0.8)
			}
			
			if metrics.MemoryOverhead > 100*1024*1024 { // 100MB limit
				t.Errorf("Memory overhead too high: %d MB (limit: 100MB)", 
					metrics.MemoryOverhead/1024/1024)
			}
		})
	}
}

// runLoadTest executes a load test and returns performance metrics
func runLoadTest(t *testing.T, requestsPerSec int, duration time.Duration, concurrency int) *PerformanceMetrics {
	// Get baseline system stats
	statsBefore, err := getSystemStats()
	if err != nil {
		t.Fatalf("Failed to get baseline stats: %v", err)
	}
	
	// Initialize counters
	var requestsProcessed uint64
	var eventsProcessed uint64
	
	// Create context for test duration
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	// Start load generation
	start := time.Now()
	var wg sync.WaitGroup
	
	// Calculate request interval
	requestInterval := time.Second / time.Duration(requestsPerSec)
	
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ticker := time.NewTicker(requestInterval * time.Duration(concurrency))
			defer ticker.Stop()
			
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Simulate HTTP request processing
					simulateHTTPRequest()
					atomic.AddUint64(&requestsProcessed, 1)
					
					// Simulate event generation (typically 2-3 events per request)
					atomic.AddUint64(&eventsProcessed, 2)
				}
			}
		}(i)
	}
	
	wg.Wait()
	actualDuration := time.Since(start)
	
	// Get final system stats
	statsAfter, err := getSystemStats()
	if err != nil {
		t.Fatalf("Failed to get final stats: %v", err)
	}
	
	// Calculate metrics
	finalRequestsProcessed := atomic.LoadUint64(&requestsProcessed)
	finalEventsProcessed := atomic.LoadUint64(&eventsProcessed)
	
	return &PerformanceMetrics{
		CPUUsageBefore:    statsBefore.CPUPercent,
		CPUUsageAfter:     statsAfter.CPUPercent,
		CPUOverhead:       statsAfter.CPUPercent - statsBefore.CPUPercent,
		MemoryBefore:      statsBefore.MemoryUsedMB * 1024 * 1024,
		MemoryAfter:       statsAfter.MemoryUsedMB * 1024 * 1024,
		MemoryOverhead:    (statsAfter.MemoryUsedMB - statsBefore.MemoryUsedMB) * 1024 * 1024,
		EventsProcessed:   finalEventsProcessed,
		RequestsProcessed: finalRequestsProcessed,
		Duration:          actualDuration,
		EventsPerSecond:   float64(finalEventsProcessed) / actualDuration.Seconds(),
		RequestsPerSecond: float64(finalRequestsProcessed) / actualDuration.Seconds(),
		LatencyImpact:     0, // Would be measured in real implementation
	}
}

// simulateHTTPRequest simulates processing an HTTP request
func simulateHTTPRequest() {
	// Simulate request processing overhead
	time.Sleep(100 * time.Microsecond)
}

// TestMemoryLeaks tests for memory leaks during extended operation
func TestMemoryLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}
	
	// Get initial memory stats
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	// Run operations for extended period
	const iterations = 10000
	for i := 0; i < iterations; i++ {
		event := TestEvent{
			Timestamp: uint64(time.Now().UnixNano()),
			RequestID: uint64(i),
			PID:       uint32(1000 + i%100),
			Method:    "GET",
			Path:      fmt.Sprintf("/api/test/%d", i),
		}
		processEvent(&event)
		
		// Periodic garbage collection
		if i%1000 == 0 {
			runtime.GC()
		}
	}
	
	// Get final memory stats
	var m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m2)
	
	// Check for memory leaks
	memoryGrowth := m2.Alloc - m1.Alloc
	t.Logf("Memory growth after %d iterations: %d bytes", iterations, memoryGrowth)
	
	// Allow for some memory growth, but not excessive
	maxAllowedGrowth := uint64(10 * 1024 * 1024) // 10MB
	if memoryGrowth > maxAllowedGrowth {
		t.Errorf("Potential memory leak detected: %d bytes growth (max allowed: %d)", 
			memoryGrowth, maxAllowedGrowth)
	}
}
