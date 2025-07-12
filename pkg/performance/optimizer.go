package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// PerformanceOptimizer handles performance optimization and monitoring
type PerformanceOptimizer struct {
	config           *OptimizerConfig
	stats            *PerformanceStats
	eventPool        *EventPool
	bufferManager    *BufferManager
	cpuProfiler      *CPUProfiler
	memoryProfiler   *MemoryProfiler
	mutex            sync.RWMutex
	running          atomic.Bool
	stopChan         chan struct{}
}

// OptimizerConfig holds configuration for performance optimization
type OptimizerConfig struct {
	EnableCPUProfiling     bool          `json:"enable_cpu_profiling" yaml:"enable_cpu_profiling"`
	EnableMemoryProfiling  bool          `json:"enable_memory_profiling" yaml:"enable_memory_profiling"`
	EnableEventPooling     bool          `json:"enable_event_pooling" yaml:"enable_event_pooling"`
	EnableBufferOptimization bool        `json:"enable_buffer_optimization" yaml:"enable_buffer_optimization"`
	MaxEventPoolSize       int           `json:"max_event_pool_size" yaml:"max_event_pool_size"`
	BufferSize             int           `json:"buffer_size" yaml:"buffer_size"`
	GCTargetPercent        int           `json:"gc_target_percent" yaml:"gc_target_percent"`
	MaxGoroutines          int           `json:"max_goroutines" yaml:"max_goroutines"`
	ProfilingInterval      time.Duration `json:"profiling_interval" yaml:"profiling_interval"`
	OptimizationInterval   time.Duration `json:"optimization_interval" yaml:"optimization_interval"`
	MemoryThreshold        uint64        `json:"memory_threshold" yaml:"memory_threshold"`
	CPUThreshold           float64       `json:"cpu_threshold" yaml:"cpu_threshold"`
}

// PerformanceStats holds performance statistics
type PerformanceStats struct {
	EventsProcessed       uint64        `json:"events_processed"`
	EventsPooled          uint64        `json:"events_pooled"`
	EventsAllocated       uint64        `json:"events_allocated"`
	BufferHits            uint64        `json:"buffer_hits"`
	BufferMisses          uint64        `json:"buffer_misses"`
	GCRuns                uint64        `json:"gc_runs"`
	MemoryUsage           uint64        `json:"memory_usage"`
	CPUUsage              float64       `json:"cpu_usage"`
	GoroutineCount        int           `json:"goroutine_count"`
	LastOptimization      time.Time     `json:"last_optimization"`
	OptimizationCount     uint64        `json:"optimization_count"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	PeakMemoryUsage       uint64        `json:"peak_memory_usage"`
	PeakCPUUsage          float64       `json:"peak_cpu_usage"`
	mutex                 sync.RWMutex
}

// EventPool manages a pool of reusable event objects
type EventPool struct {
	pool     sync.Pool
	maxSize  int
	created  uint64
	reused   uint64
	mutex    sync.RWMutex
}

// BufferManager manages optimized buffers for event processing
type BufferManager struct {
	buffers   map[string]*Buffer
	maxSize   int
	hits      uint64
	misses    uint64
	mutex     sync.RWMutex
}

// Buffer represents an optimized buffer
type Buffer struct {
	Data     []byte
	Size     int
	LastUsed time.Time
	InUse    bool
}

// CPUProfiler handles CPU profiling and optimization
type CPUProfiler struct {
	samples       []CPUSample
	currentUsage  float64
	peakUsage     float64
	sampleCount   int
	lastSample    time.Time
	mutex         sync.RWMutex
}

// CPUSample represents a CPU usage sample
type CPUSample struct {
	Timestamp time.Time `json:"timestamp"`
	Usage     float64   `json:"usage"`
	Goroutines int      `json:"goroutines"`
}

// MemoryProfiler handles memory profiling and optimization
type MemoryProfiler struct {
	samples       []MemorySample
	currentUsage  uint64
	peakUsage     uint64
	gcStats       runtime.MemStats
	lastGC        time.Time
	mutex         sync.RWMutex
}

// MemorySample represents a memory usage sample
type MemorySample struct {
	Timestamp    time.Time `json:"timestamp"`
	HeapAlloc    uint64    `json:"heap_alloc"`
	HeapSys      uint64    `json:"heap_sys"`
	HeapInuse    uint64    `json:"heap_inuse"`
	StackInuse   uint64    `json:"stack_inuse"`
	GCCycles     uint32    `json:"gc_cycles"`
}

// DefaultOptimizerConfig returns default optimizer configuration
func DefaultOptimizerConfig() *OptimizerConfig {
	return &OptimizerConfig{
		EnableCPUProfiling:       true,
		EnableMemoryProfiling:    true,
		EnableEventPooling:       true,
		EnableBufferOptimization: true,
		MaxEventPoolSize:         10000,
		BufferSize:               64 * 1024, // 64KB
		GCTargetPercent:          100,
		MaxGoroutines:            1000,
		ProfilingInterval:        5 * time.Second,
		OptimizationInterval:     30 * time.Second,
		MemoryThreshold:          500 * 1024 * 1024, // 500MB
		CPUThreshold:             80.0, // 80%
	}
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(config *OptimizerConfig) *PerformanceOptimizer {
	optimizer := &PerformanceOptimizer{
		config:    config,
		stats:     &PerformanceStats{},
		stopChan:  make(chan struct{}),
	}

	if config.EnableEventPooling {
		optimizer.eventPool = NewEventPool(config.MaxEventPoolSize)
	}

	if config.EnableBufferOptimization {
		optimizer.bufferManager = NewBufferManager(config.BufferSize)
	}

	if config.EnableCPUProfiling {
		optimizer.cpuProfiler = NewCPUProfiler()
	}

	if config.EnableMemoryProfiling {
		optimizer.memoryProfiler = NewMemoryProfiler()
	}

	return optimizer
}

// Start starts the performance optimizer
func (po *PerformanceOptimizer) Start(ctx context.Context) error {
	if !po.running.CompareAndSwap(false, true) {
		return fmt.Errorf("optimizer already running")
	}

	// Set GC target if configured
	if po.config.GCTargetPercent > 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
		runtime.GC()
	}

	// Start profiling goroutines
	go po.profilingLoop(ctx)
	go po.optimizationLoop(ctx)

	return nil
}

// Stop stops the performance optimizer
func (po *PerformanceOptimizer) Stop() error {
	if !po.running.CompareAndSwap(true, false) {
		return fmt.Errorf("optimizer not running")
	}

	close(po.stopChan)
	return nil
}

// OptimizeEvent optimizes event processing
func (po *PerformanceOptimizer) OptimizeEvent(event *tracing.TraceEvent) *tracing.TraceEvent {
	start := time.Now()
	defer func() {
		processingTime := time.Since(start)
		po.updateProcessingTime(processingTime)
	}()

	// Use event pool if enabled
	if po.config.EnableEventPooling && po.eventPool != nil {
		optimizedEvent := po.eventPool.Get()
		if optimizedEvent != nil {
			// Copy event data to pooled event
			*optimizedEvent = *event
			atomic.AddUint64(&po.stats.EventsPooled, 1)
			atomic.AddUint64(&po.stats.EventsProcessed, 1)
			return optimizedEvent
		}
	}

	atomic.AddUint64(&po.stats.EventsAllocated, 1)

	atomic.AddUint64(&po.stats.EventsProcessed, 1)
	return event
}

// ReleaseEvent releases an event back to the pool
func (po *PerformanceOptimizer) ReleaseEvent(event *tracing.TraceEvent) {
	if po.config.EnableEventPooling && po.eventPool != nil {
		po.eventPool.Put(event)
	}
}

// GetBuffer gets an optimized buffer
func (po *PerformanceOptimizer) GetBuffer(name string, size int) []byte {
	if po.config.EnableBufferOptimization && po.bufferManager != nil {
		return po.bufferManager.GetBuffer(name, size)
	}
	return make([]byte, size)
}

// ReleaseBuffer releases a buffer back to the manager
func (po *PerformanceOptimizer) ReleaseBuffer(name string, buffer []byte) {
	if po.config.EnableBufferOptimization && po.bufferManager != nil {
		po.bufferManager.ReleaseBuffer(name, buffer)
	}
}

// profilingLoop runs the profiling loop
func (po *PerformanceOptimizer) profilingLoop(ctx context.Context) {
	ticker := time.NewTicker(po.config.ProfilingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-po.stopChan:
			return
		case <-ticker.C:
			po.collectMetrics()
		}
	}
}

// optimizationLoop runs the optimization loop
func (po *PerformanceOptimizer) optimizationLoop(ctx context.Context) {
	ticker := time.NewTicker(po.config.OptimizationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-po.stopChan:
			return
		case <-ticker.C:
			po.performOptimizations()
		}
	}
}

// collectMetrics collects performance metrics
func (po *PerformanceOptimizer) collectMetrics() {
	// Collect CPU metrics
	if po.config.EnableCPUProfiling && po.cpuProfiler != nil {
		po.cpuProfiler.Sample()
	}

	// Collect memory metrics
	if po.config.EnableMemoryProfiling && po.memoryProfiler != nil {
		po.memoryProfiler.Sample()
	}

	// Update general stats
	po.stats.mutex.Lock()
	po.stats.GoroutineCount = runtime.NumGoroutine()
	
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	po.stats.MemoryUsage = memStats.HeapInuse
	
	if po.stats.MemoryUsage > po.stats.PeakMemoryUsage {
		po.stats.PeakMemoryUsage = po.stats.MemoryUsage
	}
	po.stats.mutex.Unlock()
}

// performOptimizations performs automatic optimizations
func (po *PerformanceOptimizer) performOptimizations() {
	po.stats.mutex.Lock()
	defer po.stats.mutex.Unlock()

	po.stats.OptimizationCount++
	po.stats.LastOptimization = time.Now()

	// Memory optimization
	if po.stats.MemoryUsage > po.config.MemoryThreshold {
		runtime.GC()
		po.stats.GCRuns++
	}

	// Goroutine optimization
	if po.stats.GoroutineCount > po.config.MaxGoroutines {
		// Log warning about high goroutine count
		// In practice, you might implement goroutine limiting here
	}

	// Buffer cleanup
	if po.config.EnableBufferOptimization && po.bufferManager != nil {
		po.bufferManager.Cleanup()
	}
}

// updateProcessingTime updates average processing time
func (po *PerformanceOptimizer) updateProcessingTime(duration time.Duration) {
	po.stats.mutex.Lock()
	defer po.stats.mutex.Unlock()

	// Simple moving average
	if po.stats.AverageProcessingTime == 0 {
		po.stats.AverageProcessingTime = duration
	} else {
		po.stats.AverageProcessingTime = (po.stats.AverageProcessingTime + duration) / 2
	}
}

// GetStats returns performance statistics
func (po *PerformanceOptimizer) GetStats() *PerformanceStats {
	po.stats.mutex.RLock()
	defer po.stats.mutex.RUnlock()

	// Create a copy to avoid race conditions
	stats := *po.stats
	return &stats
}

// GetDetailedStats returns detailed performance statistics
func (po *PerformanceOptimizer) GetDetailedStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["general"] = po.GetStats()

	if po.eventPool != nil {
		stats["event_pool"] = po.eventPool.GetStats()
	}

	if po.bufferManager != nil {
		stats["buffer_manager"] = po.bufferManager.GetStats()
	}

	if po.cpuProfiler != nil {
		stats["cpu_profiler"] = po.cpuProfiler.GetStats()
	}

	if po.memoryProfiler != nil {
		stats["memory_profiler"] = po.memoryProfiler.GetStats()
	}

	return stats
}

// NewEventPool creates a new event pool
func NewEventPool(maxSize int) *EventPool {
	return &EventPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &tracing.TraceEvent{}
			},
		},
		maxSize: maxSize,
	}
}

// Get gets an event from the pool
func (ep *EventPool) Get() *tracing.TraceEvent {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	event := ep.pool.Get().(*tracing.TraceEvent)
	atomic.AddUint64(&ep.reused, 1)
	return event
}

// Put puts an event back to the pool
func (ep *EventPool) Put(event *tracing.TraceEvent) {
	// Reset event
	*event = tracing.TraceEvent{}
	ep.pool.Put(event)
}

// GetStats returns event pool statistics
func (ep *EventPool) GetStats() map[string]interface{} {
	ep.mutex.RLock()
	defer ep.mutex.RUnlock()

	return map[string]interface{}{
		"max_size": ep.maxSize,
		"created":  atomic.LoadUint64(&ep.created),
		"reused":   atomic.LoadUint64(&ep.reused),
	}
}

// NewBufferManager creates a new buffer manager
func NewBufferManager(defaultSize int) *BufferManager {
	return &BufferManager{
		buffers: make(map[string]*Buffer),
		maxSize: defaultSize,
	}
}

// GetBuffer gets a buffer from the manager
func (bm *BufferManager) GetBuffer(name string, size int) []byte {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	if buffer, exists := bm.buffers[name]; exists && !buffer.InUse {
		if len(buffer.Data) >= size {
			buffer.InUse = true
			buffer.LastUsed = time.Now()
			atomic.AddUint64(&bm.hits, 1)
			return buffer.Data[:size]
		}
	}

	atomic.AddUint64(&bm.misses, 1)
	return make([]byte, size)
}

// ReleaseBuffer releases a buffer back to the manager
func (bm *BufferManager) ReleaseBuffer(name string, buffer []byte) {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	bm.buffers[name] = &Buffer{
		Data:     buffer,
		Size:     len(buffer),
		LastUsed: time.Now(),
		InUse:    false,
	}
}

// Cleanup cleans up old buffers
func (bm *BufferManager) Cleanup() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for name, buffer := range bm.buffers {
		if !buffer.InUse && buffer.LastUsed.Before(cutoff) {
			delete(bm.buffers, name)
		}
	}
}

// GetStats returns buffer manager statistics
func (bm *BufferManager) GetStats() map[string]interface{} {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()

	return map[string]interface{}{
		"buffer_count": len(bm.buffers),
		"hits":         atomic.LoadUint64(&bm.hits),
		"misses":       atomic.LoadUint64(&bm.misses),
		"hit_ratio":    float64(atomic.LoadUint64(&bm.hits)) / float64(atomic.LoadUint64(&bm.hits)+atomic.LoadUint64(&bm.misses)),
	}
}

// NewCPUProfiler creates a new CPU profiler
func NewCPUProfiler() *CPUProfiler {
	return &CPUProfiler{
		samples: make([]CPUSample, 0, 1000),
	}
}

// Sample takes a CPU usage sample
func (cp *CPUProfiler) Sample() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	sample := CPUSample{
		Timestamp:  time.Now(),
		Usage:      cp.getCurrentCPUUsage(),
		Goroutines: runtime.NumGoroutine(),
	}

	cp.samples = append(cp.samples, sample)
	cp.currentUsage = sample.Usage
	
	if sample.Usage > cp.peakUsage {
		cp.peakUsage = sample.Usage
	}

	// Keep only last 1000 samples
	if len(cp.samples) > 1000 {
		cp.samples = cp.samples[1:]
	}

	cp.sampleCount++
	cp.lastSample = sample.Timestamp
}

// getCurrentCPUUsage gets current CPU usage (simplified)
func (cp *CPUProfiler) getCurrentCPUUsage() float64 {
	// This is a simplified implementation
	// In practice, you would use more sophisticated CPU monitoring
	return float64(runtime.NumGoroutine()) / 100.0
}

// GetStats returns CPU profiler statistics
func (cp *CPUProfiler) GetStats() map[string]interface{} {
	cp.mutex.RLock()
	defer cp.mutex.RUnlock()

	return map[string]interface{}{
		"current_usage": cp.currentUsage,
		"peak_usage":    cp.peakUsage,
		"sample_count":  cp.sampleCount,
		"last_sample":   cp.lastSample,
	}
}

// NewMemoryProfiler creates a new memory profiler
func NewMemoryProfiler() *MemoryProfiler {
	return &MemoryProfiler{
		samples: make([]MemorySample, 0, 1000),
	}
}

// Sample takes a memory usage sample
func (mp *MemoryProfiler) Sample() {
	mp.mutex.Lock()
	defer mp.mutex.Unlock()

	runtime.ReadMemStats(&mp.gcStats)

	sample := MemorySample{
		Timestamp:  time.Now(),
		HeapAlloc:  mp.gcStats.HeapAlloc,
		HeapSys:    mp.gcStats.HeapSys,
		HeapInuse:  mp.gcStats.HeapInuse,
		StackInuse: mp.gcStats.StackInuse,
		GCCycles:   mp.gcStats.NumGC,
	}

	mp.samples = append(mp.samples, sample)
	mp.currentUsage = sample.HeapInuse
	
	if sample.HeapInuse > mp.peakUsage {
		mp.peakUsage = sample.HeapInuse
	}

	// Keep only last 1000 samples
	if len(mp.samples) > 1000 {
		mp.samples = mp.samples[1:]
	}
}

// GetStats returns memory profiler statistics
func (mp *MemoryProfiler) GetStats() map[string]interface{} {
	mp.mutex.RLock()
	defer mp.mutex.RUnlock()

	return map[string]interface{}{
		"current_usage": mp.currentUsage,
		"peak_usage":    mp.peakUsage,
		"gc_cycles":     mp.gcStats.NumGC,
		"last_gc":       time.Unix(0, int64(mp.gcStats.LastGC)),
	}
}
