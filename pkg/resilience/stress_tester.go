package resilience

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"ebpf-tracing/pkg/performance"
	"ebpf-tracing/pkg/tracing"
)

// StressTester provides comprehensive stress testing capabilities
type StressTester struct {
	config    *StressTestConfig
	results   *StressTestResults
	tracer    interface{} // Generic tracer interface
	optimizer *performance.PerformanceOptimizer
	running   atomic.Bool
	stopChan  chan struct{}
	mutex     sync.RWMutex
}

// StressTestConfig holds stress test configuration
type StressTestConfig struct {
	MaxEventsPerSecond   int           `json:"max_events_per_second" yaml:"max_events_per_second"`
	RampUpDuration       time.Duration `json:"ramp_up_duration" yaml:"ramp_up_duration"`
	SustainDuration      time.Duration `json:"sustain_duration" yaml:"sustain_duration"`
	RampDownDuration     time.Duration `json:"ramp_down_duration" yaml:"ramp_down_duration"`
	MaxConcurrentWorkers int           `json:"max_concurrent_workers" yaml:"max_concurrent_workers"`
	MemoryPressureTest   bool          `json:"memory_pressure_test" yaml:"memory_pressure_test"`
	CPUPressureTest      bool          `json:"cpu_pressure_test" yaml:"cpu_pressure_test"`
	NetworkPressureTest  bool          `json:"network_pressure_test" yaml:"network_pressure_test"`
	ChaosTestingEnabled  bool          `json:"chaos_testing_enabled" yaml:"chaos_testing_enabled"`
	FailureInjectionRate float64       `json:"failure_injection_rate" yaml:"failure_injection_rate"`
	MaxPayloadSize       int           `json:"max_payload_size" yaml:"max_payload_size"`
	EnableGCPressure     bool          `json:"enable_gc_pressure" yaml:"enable_gc_pressure"`
	EnableLeakDetection  bool          `json:"enable_leak_detection" yaml:"enable_leak_detection"`
}

// StressTestResults holds stress test results
type StressTestResults struct {
	StartTime           time.Time              `json:"start_time"`
	EndTime             time.Time              `json:"end_time"`
	TotalDuration       time.Duration          `json:"total_duration"`
	TotalEvents         uint64                 `json:"total_events"`
	SuccessfulEvents    uint64                 `json:"successful_events"`
	FailedEvents        uint64                 `json:"failed_events"`
	PeakEventsPerSecond float64                `json:"peak_events_per_second"`
	PeakMemoryUsage     uint64                 `json:"peak_memory_usage"`
	PeakCPUUsage        float64                `json:"peak_cpu_usage"`
	PeakGoroutines      int                    `json:"peak_goroutines"`
	MemoryLeaksDetected int                    `json:"memory_leaks_detected"`
	SystemStability     string                 `json:"system_stability"`
	FailurePoints       []FailurePoint         `json:"failure_points"`
	RecoveryTime        time.Duration          `json:"recovery_time"`
	ResilienceScore     float64                `json:"resilience_score"`
	Recommendations     []string               `json:"recommendations"`
	PhaseResults        map[string]*PhaseResult `json:"phase_results"`
}

// FailurePoint represents a point where the system failed
type FailurePoint struct {
	Timestamp   time.Time `json:"timestamp"`
	EventRate   float64   `json:"event_rate"`
	MemoryUsage uint64    `json:"memory_usage"`
	CPUUsage    float64   `json:"cpu_usage"`
	ErrorType   string    `json:"error_type"`
	Description string    `json:"description"`
}

// PhaseResult represents results for a specific test phase
type PhaseResult struct {
	Phase           string        `json:"phase"`
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	Duration        time.Duration `json:"duration"`
	EventsProcessed uint64        `json:"events_processed"`
	ErrorCount      uint64        `json:"error_count"`
	AvgLatency      time.Duration `json:"avg_latency"`
	MaxLatency      time.Duration `json:"max_latency"`
	MemoryUsage     uint64        `json:"memory_usage"`
	CPUUsage        float64       `json:"cpu_usage"`
	Stable          bool          `json:"stable"`
}

// DefaultStressTestConfig returns default stress test configuration
func DefaultStressTestConfig() *StressTestConfig {
	return &StressTestConfig{
		MaxEventsPerSecond:   10000,
		RampUpDuration:       2 * time.Minute,
		SustainDuration:      5 * time.Minute,
		RampDownDuration:     1 * time.Minute,
		MaxConcurrentWorkers: 100,
		MemoryPressureTest:   true,
		CPUPressureTest:      true,
		NetworkPressureTest:  false,
		ChaosTestingEnabled:  true,
		FailureInjectionRate: 0.01, // 1% failure rate
		MaxPayloadSize:       10 * 1024, // 10KB
		EnableGCPressure:     true,
		EnableLeakDetection:  true,
	}
}

// NewStressTester creates a new stress tester
func NewStressTester(config *StressTestConfig, tracer interface{}, optimizer *performance.PerformanceOptimizer) *StressTester {
	return &StressTester{
		config:    config,
		results:   &StressTestResults{PhaseResults: make(map[string]*PhaseResult)},
		tracer:    tracer,
		optimizer: optimizer,
		stopChan:  make(chan struct{}),
	}
}

// RunStressTest runs the complete stress test
func (st *StressTester) RunStressTest(ctx context.Context) (*StressTestResults, error) {
	if !st.running.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("stress test already running")
	}
	defer st.running.Store(false)

	fmt.Println("🔥 Starting Comprehensive Stress Test")
	st.results.StartTime = time.Now()

	// Start monitoring
	monitorCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		st.monitorSystem(monitorCtx)
	}()

	// Phase 1: Ramp Up
	fmt.Printf("📈 Phase 1: Ramp Up (%v)\n", st.config.RampUpDuration)
	if err := st.runRampUpPhase(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("ramp up phase failed: %w", err)
	}

	// Phase 2: Sustain Load
	fmt.Printf("⚡ Phase 2: Sustain Load (%v)\n", st.config.SustainDuration)
	if err := st.runSustainPhase(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("sustain phase failed: %w", err)
	}

	// Phase 3: Chaos Testing (if enabled)
	if st.config.ChaosTestingEnabled {
		fmt.Println("🌪️ Phase 3: Chaos Testing")
		if err := st.runChaosPhase(ctx); err != nil {
			fmt.Printf("⚠️ Chaos testing encountered issues: %v\n", err)
			st.recordFailurePoint("chaos_testing", err.Error())
		}
	}

	// Phase 4: Memory Pressure (if enabled)
	if st.config.MemoryPressureTest {
		fmt.Println("🧠 Phase 4: Memory Pressure Test")
		if err := st.runMemoryPressurePhase(ctx); err != nil {
			fmt.Printf("⚠️ Memory pressure test failed: %v\n", err)
			st.recordFailurePoint("memory_pressure", err.Error())
		}
	}

	// Phase 5: Ramp Down
	fmt.Printf("📉 Phase 5: Ramp Down (%v)\n", st.config.RampDownDuration)
	if err := st.runRampDownPhase(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("ramp down phase failed: %w", err)
	}

	// Stop monitoring
	cancel()
	wg.Wait()

	st.results.EndTime = time.Now()
	st.results.TotalDuration = st.results.EndTime.Sub(st.results.StartTime)

	// Calculate final results
	st.calculateFinalResults()

	fmt.Println("✅ Stress Test Completed")
	return st.results, nil
}

// runRampUpPhase runs the ramp up phase
func (st *StressTester) runRampUpPhase(ctx context.Context) error {
	phaseCtx, cancel := context.WithTimeout(ctx, st.config.RampUpDuration)
	defer cancel()

	phaseResult := &PhaseResult{
		Phase:     "ramp_up",
		StartTime: time.Now(),
	}

	maxRate := float64(st.config.MaxEventsPerSecond)
	duration := st.config.RampUpDuration
	interval := 100 * time.Millisecond
	steps := int(duration / interval)

	for i := 0; i < steps; i++ {
		select {
		case <-phaseCtx.Done():
			phaseResult.EndTime = time.Now()
			phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
			st.results.PhaseResults["ramp_up"] = phaseResult
			return phaseCtx.Err()
		default:
		}

		// Calculate current rate (linear ramp up)
		progress := float64(i) / float64(steps)
		currentRate := maxRate * progress

		// Generate events at current rate
		eventsToGenerate := int(currentRate * interval.Seconds())
		for j := 0; j < eventsToGenerate; j++ {
			if err := st.generateStressEvent(); err != nil {
				atomic.AddUint64(&phaseResult.ErrorCount, 1)
			} else {
				atomic.AddUint64(&phaseResult.EventsProcessed, 1)
			}
		}

		time.Sleep(interval)
	}

	phaseResult.EndTime = time.Now()
	phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
	phaseResult.Stable = phaseResult.ErrorCount < phaseResult.EventsProcessed/100 // < 1% error rate
	st.results.PhaseResults["ramp_up"] = phaseResult

	return nil
}

// runSustainPhase runs the sustain load phase
func (st *StressTester) runSustainPhase(ctx context.Context) error {
	phaseCtx, cancel := context.WithTimeout(ctx, st.config.SustainDuration)
	defer cancel()

	phaseResult := &PhaseResult{
		Phase:     "sustain",
		StartTime: time.Now(),
	}

	rate := float64(st.config.MaxEventsPerSecond)
	interval := 100 * time.Millisecond
	eventsPerInterval := int(rate * interval.Seconds())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-phaseCtx.Done():
			phaseResult.EndTime = time.Now()
			phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
			st.results.PhaseResults["sustain"] = phaseResult
			return nil
		case <-ticker.C:
			for i := 0; i < eventsPerInterval; i++ {
				if err := st.generateStressEvent(); err != nil {
					atomic.AddUint64(&phaseResult.ErrorCount, 1)
				} else {
					atomic.AddUint64(&phaseResult.EventsProcessed, 1)
				}
			}
		}
	}
}

// runChaosPhase runs the chaos testing phase
func (st *StressTester) runChaosPhase(ctx context.Context) error {
	phaseCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	phaseResult := &PhaseResult{
		Phase:     "chaos",
		StartTime: time.Now(),
	}

	// Inject various types of failures
	failures := []func() error{
		st.injectMemorySpike,
		st.injectCPUSpike,
		st.injectGoroutineLeak,
		st.injectRandomErrors,
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-phaseCtx.Done():
			phaseResult.EndTime = time.Now()
			phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
			st.results.PhaseResults["chaos"] = phaseResult
			return nil
		case <-ticker.C:
			// Randomly inject a failure
			if rand.Float64() < 0.5 { // 50% chance
				failure := failures[rand.Intn(len(failures))]
				if err := failure(); err != nil {
					atomic.AddUint64(&phaseResult.ErrorCount, 1)
				}
			}

			// Continue generating events
			for i := 0; i < 100; i++ {
				if err := st.generateStressEvent(); err != nil {
					atomic.AddUint64(&phaseResult.ErrorCount, 1)
				} else {
					atomic.AddUint64(&phaseResult.EventsProcessed, 1)
				}
			}
		}
	}
}

// runMemoryPressurePhase runs the memory pressure test
func (st *StressTester) runMemoryPressurePhase(ctx context.Context) error {
	phaseCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	phaseResult := &PhaseResult{
		Phase:     "memory_pressure",
		StartTime: time.Now(),
	}

	// Allocate large amounts of memory to create pressure
	memoryHogs := make([][]byte, 0)
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-phaseCtx.Done():
			// Clean up memory
			memoryHogs = nil
			runtime.GC()
			
			phaseResult.EndTime = time.Now()
			phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
			st.results.PhaseResults["memory_pressure"] = phaseResult
			return nil
		case <-ticker.C:
			// Allocate 50MB chunks
			chunk := make([]byte, 50*1024*1024)
			memoryHogs = append(memoryHogs, chunk)
			
			// Continue processing events under memory pressure
			for i := 0; i < 1000; i++ {
				if err := st.generateStressEvent(); err != nil {
					atomic.AddUint64(&phaseResult.ErrorCount, 1)
				} else {
					atomic.AddUint64(&phaseResult.EventsProcessed, 1)
				}
			}
			
			// Force GC if enabled
			if st.config.EnableGCPressure {
				runtime.GC()
			}
		}
	}
}

// runRampDownPhase runs the ramp down phase
func (st *StressTester) runRampDownPhase(ctx context.Context) error {
	phaseCtx, cancel := context.WithTimeout(ctx, st.config.RampDownDuration)
	defer cancel()

	phaseResult := &PhaseResult{
		Phase:     "ramp_down",
		StartTime: time.Now(),
	}

	maxRate := float64(st.config.MaxEventsPerSecond)
	duration := st.config.RampDownDuration
	interval := 100 * time.Millisecond
	steps := int(duration / interval)

	for i := 0; i < steps; i++ {
		select {
		case <-phaseCtx.Done():
			phaseResult.EndTime = time.Now()
			phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
			st.results.PhaseResults["ramp_down"] = phaseResult
			return phaseCtx.Err()
		default:
		}

		// Calculate current rate (linear ramp down)
		progress := 1.0 - (float64(i) / float64(steps))
		currentRate := maxRate * progress

		// Generate events at current rate
		eventsToGenerate := int(currentRate * interval.Seconds())
		for j := 0; j < eventsToGenerate; j++ {
			if err := st.generateStressEvent(); err != nil {
				atomic.AddUint64(&phaseResult.ErrorCount, 1)
			} else {
				atomic.AddUint64(&phaseResult.EventsProcessed, 1)
			}
		}

		time.Sleep(interval)
	}

	phaseResult.EndTime = time.Now()
	phaseResult.Duration = phaseResult.EndTime.Sub(phaseResult.StartTime)
	st.results.PhaseResults["ramp_down"] = phaseResult

	return nil
}

// generateStressEvent generates a stress test event
func (st *StressTester) generateStressEvent() error {
	// Inject random failures if enabled
	if st.config.ChaosTestingEnabled && rand.Float64() < st.config.FailureInjectionRate {
		atomic.AddUint64(&st.results.FailedEvents, 1)
		return fmt.Errorf("injected failure")
	}

	// Generate event with random payload size
	payloadSize := rand.Intn(st.config.MaxPayloadSize) + 1
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	event := &tracing.TraceEvent{
		Timestamp:   uint64(time.Now().UnixNano()),
		RequestID:   atomic.AddUint64(&st.results.TotalEvents, 1),
		EventType:   "stress_test",
		ServiceName: "stress-test-service",
		Payload:     string(payload),
	}

	// Process through optimizer if available
	if st.optimizer != nil {
		optimizedEvent := st.optimizer.OptimizeEvent(event)
		st.optimizer.ReleaseEvent(optimizedEvent)
	}

	atomic.AddUint64(&st.results.SuccessfulEvents, 1)
	return nil
}

// monitorSystem monitors system resources during stress test
func (st *StressTester) monitorSystem(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st.collectSystemMetrics()
		}
	}
}

// collectSystemMetrics collects system metrics
func (st *StressTester) collectSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Update peak memory usage
	if memStats.HeapInuse > st.results.PeakMemoryUsage {
		st.results.PeakMemoryUsage = memStats.HeapInuse
	}

	// Update peak goroutines
	goroutines := runtime.NumGoroutine()
	if goroutines > st.results.PeakGoroutines {
		st.results.PeakGoroutines = goroutines
	}

	// Calculate events per second
	if st.results.TotalDuration > 0 {
		currentRate := float64(atomic.LoadUint64(&st.results.TotalEvents)) / st.results.TotalDuration.Seconds()
		if currentRate > st.results.PeakEventsPerSecond {
			st.results.PeakEventsPerSecond = currentRate
		}
	}
}

// recordFailurePoint records a failure point
func (st *StressTester) recordFailurePoint(errorType, description string) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	failurePoint := FailurePoint{
		Timestamp:   time.Now(),
		EventRate:   st.results.PeakEventsPerSecond,
		MemoryUsage: memStats.HeapInuse,
		ErrorType:   errorType,
		Description: description,
	}

	st.mutex.Lock()
	st.results.FailurePoints = append(st.results.FailurePoints, failurePoint)
	st.mutex.Unlock()
}

// Chaos injection methods
func (st *StressTester) injectMemorySpike() error {
	// Allocate 100MB temporarily
	spike := make([]byte, 100*1024*1024)
	time.Sleep(2 * time.Second)
	_ = spike // Use the memory
	return nil
}

func (st *StressTester) injectCPUSpike() error {
	// Create CPU spike for 2 seconds
	done := make(chan bool)
	go func() {
		start := time.Now()
		for time.Since(start) < 2*time.Second {
			// Busy loop
		}
		done <- true
	}()
	<-done
	return nil
}

func (st *StressTester) injectGoroutineLeak() error {
	// Create some goroutines that will exit after a delay
	for i := 0; i < 10; i++ {
		go func() {
			time.Sleep(30 * time.Second)
		}()
	}
	return nil
}

func (st *StressTester) injectRandomErrors() error {
	// Simulate random processing errors
	if rand.Float64() < 0.1 {
		return fmt.Errorf("random processing error")
	}
	return nil
}

// calculateFinalResults calculates final stress test results
func (st *StressTester) calculateFinalResults() {
	// Calculate system stability
	totalErrors := atomic.LoadUint64(&st.results.FailedEvents)
	totalEvents := atomic.LoadUint64(&st.results.TotalEvents)
	
	if totalEvents > 0 {
		errorRate := float64(totalErrors) / float64(totalEvents)
		switch {
		case errorRate < 0.001: // < 0.1%
			st.results.SystemStability = "Excellent"
		case errorRate < 0.01: // < 1%
			st.results.SystemStability = "Good"
		case errorRate < 0.05: // < 5%
			st.results.SystemStability = "Fair"
		default:
			st.results.SystemStability = "Poor"
		}
	}

	// Calculate resilience score
	st.results.ResilienceScore = st.calculateResilienceScore()

	// Generate recommendations
	st.generateResilienceRecommendations()
}

// calculateResilienceScore calculates resilience score
func (st *StressTester) calculateResilienceScore() float64 {
	score := 100.0

	// Deduct points for failures
	totalEvents := atomic.LoadUint64(&st.results.TotalEvents)
	totalErrors := atomic.LoadUint64(&st.results.FailedEvents)
	
	if totalEvents > 0 {
		errorRate := float64(totalErrors) / float64(totalEvents)
		score -= errorRate * 50 // Up to 50 points deduction for errors
	}

	// Deduct points for failure points
	score -= float64(len(st.results.FailurePoints)) * 10

	// Deduct points for memory leaks
	score -= float64(st.results.MemoryLeaksDetected) * 15

	if score < 0 {
		score = 0
	}

	return score
}

// generateResilienceRecommendations generates resilience recommendations
func (st *StressTester) generateResilienceRecommendations() {
	recommendations := make([]string, 0)

	if st.results.ResilienceScore < 70 {
		recommendations = append(recommendations, "System resilience needs improvement - investigate failure points")
	}

	if len(st.results.FailurePoints) > 0 {
		recommendations = append(recommendations, "Multiple failure points detected - implement better error handling")
	}

	if st.results.PeakMemoryUsage > 1024*1024*1024 { // > 1GB
		recommendations = append(recommendations, "High memory usage detected - optimize memory allocation")
	}

	if st.results.MemoryLeaksDetected > 0 {
		recommendations = append(recommendations, "Memory leaks detected - investigate and fix memory management")
	}

	if st.results.SystemStability == "Poor" {
		recommendations = append(recommendations, "Poor system stability - implement circuit breakers and rate limiting")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "System shows good resilience under stress")
	}

	st.results.Recommendations = recommendations
}

// Stop stops the stress test
func (st *StressTester) Stop() error {
	if st.running.Load() {
		close(st.stopChan)
		st.running.Store(false)
	}
	return nil
}
