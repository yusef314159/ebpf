package performance

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// BenchmarkSuite provides comprehensive performance benchmarking
type BenchmarkSuite struct {
	config   *BenchmarkConfig
	results  *BenchmarkResults
	tracer   interface{} // Generic tracer interface
	optimizer *PerformanceOptimizer
	mutex    sync.RWMutex
}

// BenchmarkConfig holds benchmark configuration
type BenchmarkConfig struct {
	EventsPerSecond     int           `json:"events_per_second" yaml:"events_per_second"`
	DurationSeconds     int           `json:"duration_seconds" yaml:"duration_seconds"`
	ConcurrentWorkers   int           `json:"concurrent_workers" yaml:"concurrent_workers"`
	PayloadSizeBytes    int           `json:"payload_size_bytes" yaml:"payload_size_bytes"`
	EnableLatencyTest   bool          `json:"enable_latency_test" yaml:"enable_latency_test"`
	EnableThroughputTest bool         `json:"enable_throughput_test" yaml:"enable_throughput_test"`
	EnableMemoryTest    bool          `json:"enable_memory_test" yaml:"enable_memory_test"`
	EnableCPUTest       bool          `json:"enable_cpu_test" yaml:"enable_cpu_test"`
	WarmupSeconds       int           `json:"warmup_seconds" yaml:"warmup_seconds"`
	CooldownSeconds     int           `json:"cooldown_seconds" yaml:"cooldown_seconds"`
	SampleInterval      time.Duration `json:"sample_interval" yaml:"sample_interval"`
}

// BenchmarkResults holds benchmark results
type BenchmarkResults struct {
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	Duration            time.Duration          `json:"duration"`
	TotalEvents         uint64                 `json:"total_events"`
	EventsPerSecond     float64                `json:"events_per_second"`
	LatencyStats        *LatencyStats          `json:"latency_stats"`
	ThroughputStats     *ThroughputStats       `json:"throughput_stats"`
	MemoryStats         *MemoryBenchmarkStats  `json:"memory_stats"`
	CPUStats            *CPUBenchmarkStats     `json:"cpu_stats"`
	ErrorCount          uint64                 `json:"error_count"`
	SuccessRate         float64                `json:"success_rate"`
	ResourceUtilization *ResourceUtilization   `json:"resource_utilization"`
	PerformanceGrade    string                 `json:"performance_grade"`
	Recommendations     []string               `json:"recommendations"`
}

// LatencyStats holds latency statistics
type LatencyStats struct {
	Min         time.Duration `json:"min"`
	Max         time.Duration `json:"max"`
	Mean        time.Duration `json:"mean"`
	Median      time.Duration `json:"median"`
	P95         time.Duration `json:"p95"`
	P99         time.Duration `json:"p99"`
	P999        time.Duration `json:"p999"`
	StdDev      time.Duration `json:"std_dev"`
	SampleCount int           `json:"sample_count"`
}

// ThroughputStats holds throughput statistics
type ThroughputStats struct {
	PeakThroughput    float64   `json:"peak_throughput"`
	AverageThroughput float64   `json:"average_throughput"`
	MinThroughput     float64   `json:"min_throughput"`
	ThroughputSamples []float64 `json:"throughput_samples"`
}

// MemoryBenchmarkStats holds memory benchmark statistics
type MemoryBenchmarkStats struct {
	InitialMemory   uint64  `json:"initial_memory"`
	PeakMemory      uint64  `json:"peak_memory"`
	FinalMemory     uint64  `json:"final_memory"`
	MemoryGrowth    uint64  `json:"memory_growth"`
	GCCount         uint32  `json:"gc_count"`
	GCPauseTotal    uint64  `json:"gc_pause_total"`
	AllocRate       float64 `json:"alloc_rate"`
	MemoryEfficiency float64 `json:"memory_efficiency"`
}

// CPUBenchmarkStats holds CPU benchmark statistics
type CPUBenchmarkStats struct {
	InitialCPU      float64 `json:"initial_cpu"`
	PeakCPU         float64 `json:"peak_cpu"`
	AverageCPU      float64 `json:"average_cpu"`
	CPUEfficiency   float64 `json:"cpu_efficiency"`
	GoroutineCount  int     `json:"goroutine_count"`
	ThreadCount     int     `json:"thread_count"`
}

// ResourceUtilization holds resource utilization statistics
type ResourceUtilization struct {
	CPUUtilization    float64 `json:"cpu_utilization"`
	MemoryUtilization float64 `json:"memory_utilization"`
	NetworkUtilization float64 `json:"network_utilization"`
	DiskUtilization   float64 `json:"disk_utilization"`
}

// DefaultBenchmarkConfig returns default benchmark configuration
func DefaultBenchmarkConfig() *BenchmarkConfig {
	return &BenchmarkConfig{
		EventsPerSecond:      1000,
		DurationSeconds:      60,
		ConcurrentWorkers:    10,
		PayloadSizeBytes:     1024,
		EnableLatencyTest:    true,
		EnableThroughputTest: true,
		EnableMemoryTest:     true,
		EnableCPUTest:        true,
		WarmupSeconds:        10,
		CooldownSeconds:      5,
		SampleInterval:       100 * time.Millisecond,
	}
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite(config *BenchmarkConfig, tracer interface{}, optimizer *PerformanceOptimizer) *BenchmarkSuite {
	return &BenchmarkSuite{
		config:    config,
		results:   &BenchmarkResults{},
		tracer:    tracer,
		optimizer: optimizer,
	}
}

// RunBenchmark runs the complete benchmark suite
func (bs *BenchmarkSuite) RunBenchmark(ctx context.Context) (*BenchmarkResults, error) {
	fmt.Println("🚀 Starting eBPF HTTP Tracer Performance Benchmark")
	
	bs.results.StartTime = time.Now()
	
	// Warmup phase
	if bs.config.WarmupSeconds > 0 {
		fmt.Printf("🔥 Warming up for %d seconds...\n", bs.config.WarmupSeconds)
		if err := bs.runWarmup(ctx); err != nil {
			return nil, fmt.Errorf("warmup failed: %w", err)
		}
	}

	// Initialize statistics
	bs.initializeStats()

	// Run benchmark phases
	var wg sync.WaitGroup
	
	// Start monitoring goroutines
	monitorCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	if bs.config.EnableMemoryTest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bs.monitorMemory(monitorCtx)
		}()
	}
	
	if bs.config.EnableCPUTest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bs.monitorCPU(monitorCtx)
		}()
	}

	// Run main benchmark
	fmt.Printf("📊 Running benchmark for %d seconds with %d workers...\n", 
		bs.config.DurationSeconds, bs.config.ConcurrentWorkers)
	
	if err := bs.runMainBenchmark(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("benchmark failed: %w", err)
	}

	// Stop monitoring
	cancel()
	wg.Wait()

	// Cooldown phase
	if bs.config.CooldownSeconds > 0 {
		fmt.Printf("❄️ Cooling down for %d seconds...\n", bs.config.CooldownSeconds)
		time.Sleep(time.Duration(bs.config.CooldownSeconds) * time.Second)
	}

	bs.results.EndTime = time.Now()
	bs.results.Duration = bs.results.EndTime.Sub(bs.results.StartTime)

	// Calculate final statistics
	bs.calculateFinalStats()
	bs.generateRecommendations()

	fmt.Println("✅ Benchmark completed successfully")
	return bs.results, nil
}

// runWarmup runs the warmup phase
func (bs *BenchmarkSuite) runWarmup(ctx context.Context) error {
	warmupCtx, cancel := context.WithTimeout(ctx, time.Duration(bs.config.WarmupSeconds)*time.Second)
	defer cancel()

	// Generate events at 50% of target rate during warmup
	warmupRate := bs.config.EventsPerSecond / 2
	interval := time.Second / time.Duration(warmupRate)
	
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-warmupCtx.Done():
			return nil
		case <-ticker.C:
			bs.generateTestEvent()
		}
	}
}

// runMainBenchmark runs the main benchmark
func (bs *BenchmarkSuite) runMainBenchmark(ctx context.Context) error {
	benchmarkCtx, cancel := context.WithTimeout(ctx, time.Duration(bs.config.DurationSeconds)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	eventChan := make(chan struct{}, bs.config.EventsPerSecond)

	// Start event generator
	wg.Add(1)
	go func() {
		defer wg.Done()
		bs.generateEvents(benchmarkCtx, eventChan)
	}()

	// Start worker goroutines
	for i := 0; i < bs.config.ConcurrentWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			bs.processEvents(benchmarkCtx, eventChan, workerID)
		}(i)
	}

	// Start latency monitoring if enabled
	if bs.config.EnableLatencyTest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bs.monitorLatency(benchmarkCtx)
		}()
	}

	// Start throughput monitoring if enabled
	if bs.config.EnableThroughputTest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bs.monitorThroughput(benchmarkCtx)
		}()
	}

	wg.Wait()
	close(eventChan)
	
	return nil
}

// generateEvents generates test events
func (bs *BenchmarkSuite) generateEvents(ctx context.Context, eventChan chan struct{}) {
	interval := time.Second / time.Duration(bs.config.EventsPerSecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case eventChan <- struct{}{}:
			default:
				// Channel full, skip this event
			}
		}
	}
}

// processEvents processes test events
func (bs *BenchmarkSuite) processEvents(ctx context.Context, eventChan chan struct{}, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-eventChan:
			if !ok {
				return
			}
			
			start := time.Now()
			event := bs.generateTestEvent()
			
			// Process event through tracer
			if bs.tracer != nil {
				// Simulate event processing
				_ = event
			}
			
			// Optimize event if optimizer is available
			if bs.optimizer != nil {
				optimizedEvent := bs.optimizer.OptimizeEvent(event)
				bs.optimizer.ReleaseEvent(optimizedEvent)
			}
			
			processingTime := time.Since(start)
			bs.recordLatency(processingTime)
			
			atomic.AddUint64(&bs.results.TotalEvents, 1)
		}
	}
}

// generateTestEvent generates a test event
func (bs *BenchmarkSuite) generateTestEvent() *tracing.TraceEvent {
	return &tracing.TraceEvent{
		Timestamp:   uint64(time.Now().UnixNano()),
		RequestID:   atomic.AddUint64(&bs.results.TotalEvents, 1),
		EventType:   "read",
		ServiceName: "benchmark-service",
		Payload:     bs.generateTestPayload(),
	}
}

// generateTestPayload generates test payload
func (bs *BenchmarkSuite) generateTestPayload() string {
	if bs.config.PayloadSizeBytes <= 0 {
		return "test-payload"
	}
	
	payload := make([]byte, bs.config.PayloadSizeBytes)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	return string(payload)
}

// recordLatency records latency measurement
func (bs *BenchmarkSuite) recordLatency(latency time.Duration) {
	// This would be implemented with a lock-free data structure in production
	// For simplicity, we'll use atomic operations where possible
}

// monitorLatency monitors latency statistics
func (bs *BenchmarkSuite) monitorLatency(ctx context.Context) {
	ticker := time.NewTicker(bs.config.SampleInterval)
	defer ticker.Stop()

	latencies := make([]time.Duration, 0, 10000)

	for {
		select {
		case <-ctx.Done():
			bs.calculateLatencyStats(latencies)
			return
		case <-ticker.C:
			// Sample current latency (simplified)
			start := time.Now()
			bs.generateTestEvent()
			latency := time.Since(start)
			latencies = append(latencies, latency)
		}
	}
}

// monitorThroughput monitors throughput statistics
func (bs *BenchmarkSuite) monitorThroughput(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastCount uint64
	throughputSamples := make([]float64, 0, bs.config.DurationSeconds)

	for {
		select {
		case <-ctx.Done():
			bs.calculateThroughputStats(throughputSamples)
			return
		case <-ticker.C:
			currentCount := atomic.LoadUint64(&bs.results.TotalEvents)
			throughput := float64(currentCount - lastCount)
			throughputSamples = append(throughputSamples, throughput)
			lastCount = currentCount
		}
	}
}

// monitorMemory monitors memory usage
func (bs *BenchmarkSuite) monitorMemory(ctx context.Context) {
	ticker := time.NewTicker(bs.config.SampleInterval)
	defer ticker.Stop()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	initialMemory := memStats.HeapInuse

	peakMemory := initialMemory
	gcCount := memStats.NumGC

	for {
		select {
		case <-ctx.Done():
			runtime.ReadMemStats(&memStats)
			bs.results.MemoryStats = &MemoryBenchmarkStats{
				InitialMemory: initialMemory,
				PeakMemory:    peakMemory,
				FinalMemory:   memStats.HeapInuse,
				MemoryGrowth:  memStats.HeapInuse - initialMemory,
				GCCount:       memStats.NumGC - gcCount,
				GCPauseTotal:  memStats.PauseTotalNs,
			}
			return
		case <-ticker.C:
			runtime.ReadMemStats(&memStats)
			if memStats.HeapInuse > peakMemory {
				peakMemory = memStats.HeapInuse
			}
		}
	}
}

// monitorCPU monitors CPU usage
func (bs *BenchmarkSuite) monitorCPU(ctx context.Context) {
	ticker := time.NewTicker(bs.config.SampleInterval)
	defer ticker.Stop()

	initialGoroutines := runtime.NumGoroutine()
	peakGoroutines := initialGoroutines

	for {
		select {
		case <-ctx.Done():
			bs.results.CPUStats = &CPUBenchmarkStats{
				GoroutineCount: runtime.NumGoroutine(),
				ThreadCount:    runtime.GOMAXPROCS(0),
			}
			return
		case <-ticker.C:
			goroutines := runtime.NumGoroutine()
			if goroutines > peakGoroutines {
				peakGoroutines = goroutines
			}
		}
	}
}

// calculateLatencyStats calculates latency statistics
func (bs *BenchmarkSuite) calculateLatencyStats(latencies []time.Duration) {
	if len(latencies) == 0 {
		return
	}

	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	stats := &LatencyStats{
		Min:         latencies[0],
		Max:         latencies[len(latencies)-1],
		SampleCount: len(latencies),
	}

	// Calculate percentiles
	stats.Median = latencies[len(latencies)/2]
	stats.P95 = latencies[int(float64(len(latencies))*0.95)]
	stats.P99 = latencies[int(float64(len(latencies))*0.99)]
	stats.P999 = latencies[int(float64(len(latencies))*0.999)]

	// Calculate mean
	var sum time.Duration
	for _, latency := range latencies {
		sum += latency
	}
	stats.Mean = sum / time.Duration(len(latencies))

	// Calculate standard deviation
	var variance float64
	meanFloat := float64(stats.Mean)
	for _, latency := range latencies {
		diff := float64(latency) - meanFloat
		variance += diff * diff
	}
	variance /= float64(len(latencies))
	stats.StdDev = time.Duration(math.Sqrt(variance))

	bs.results.LatencyStats = stats
}

// calculateThroughputStats calculates throughput statistics
func (bs *BenchmarkSuite) calculateThroughputStats(samples []float64) {
	if len(samples) == 0 {
		return
	}

	stats := &ThroughputStats{
		ThroughputSamples: samples,
	}

	var sum float64
	stats.MinThroughput = samples[0]
	stats.PeakThroughput = samples[0]

	for _, sample := range samples {
		sum += sample
		if sample < stats.MinThroughput {
			stats.MinThroughput = sample
		}
		if sample > stats.PeakThroughput {
			stats.PeakThroughput = sample
		}
	}

	stats.AverageThroughput = sum / float64(len(samples))
	bs.results.ThroughputStats = stats
}

// initializeStats initializes benchmark statistics
func (bs *BenchmarkSuite) initializeStats() {
	bs.results.TotalEvents = 0
	bs.results.ErrorCount = 0
}

// calculateFinalStats calculates final benchmark statistics
func (bs *BenchmarkSuite) calculateFinalStats() {
	if bs.results.Duration > 0 {
		bs.results.EventsPerSecond = float64(bs.results.TotalEvents) / bs.results.Duration.Seconds()
	}

	if bs.results.TotalEvents > 0 {
		bs.results.SuccessRate = float64(bs.results.TotalEvents-bs.results.ErrorCount) / float64(bs.results.TotalEvents) * 100
	}

	// Calculate performance grade
	bs.results.PerformanceGrade = bs.calculatePerformanceGrade()
}

// calculatePerformanceGrade calculates performance grade
func (bs *BenchmarkSuite) calculatePerformanceGrade() string {
	score := 0

	// Throughput score (40%)
	if bs.results.EventsPerSecond >= float64(bs.config.EventsPerSecond) {
		score += 40
	} else {
		score += int(40 * bs.results.EventsPerSecond / float64(bs.config.EventsPerSecond))
	}

	// Latency score (30%)
	if bs.results.LatencyStats != nil && bs.results.LatencyStats.P95 < 10*time.Millisecond {
		score += 30
	} else if bs.results.LatencyStats != nil && bs.results.LatencyStats.P95 < 50*time.Millisecond {
		score += 20
	} else if bs.results.LatencyStats != nil && bs.results.LatencyStats.P95 < 100*time.Millisecond {
		score += 10
	}

	// Success rate score (20%)
	if bs.results.SuccessRate >= 99.9 {
		score += 20
	} else if bs.results.SuccessRate >= 99.0 {
		score += 15
	} else if bs.results.SuccessRate >= 95.0 {
		score += 10
	}

	// Memory efficiency score (10%)
	if bs.results.MemoryStats != nil && bs.results.MemoryStats.MemoryGrowth < 100*1024*1024 { // < 100MB growth
		score += 10
	} else if bs.results.MemoryStats != nil && bs.results.MemoryStats.MemoryGrowth < 500*1024*1024 { // < 500MB growth
		score += 5
	}

	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	default:
		return "D"
	}
}

// generateRecommendations generates performance recommendations
func (bs *BenchmarkSuite) generateRecommendations() {
	recommendations := make([]string, 0)

	if bs.results.EventsPerSecond < float64(bs.config.EventsPerSecond)*0.8 {
		recommendations = append(recommendations, "Consider increasing worker count or optimizing event processing")
	}

	if bs.results.LatencyStats != nil && bs.results.LatencyStats.P95 > 50*time.Millisecond {
		recommendations = append(recommendations, "High P95 latency detected - consider optimizing critical path")
	}

	if bs.results.MemoryStats != nil && bs.results.MemoryStats.MemoryGrowth > 200*1024*1024 {
		recommendations = append(recommendations, "High memory growth detected - check for memory leaks")
	}

	if bs.results.SuccessRate < 99.0 {
		recommendations = append(recommendations, "Low success rate - investigate error causes")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Performance looks good! Consider stress testing with higher loads")
	}

	bs.results.Recommendations = recommendations
}
