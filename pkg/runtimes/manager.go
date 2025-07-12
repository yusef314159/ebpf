package runtimes

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ebpf-tracing/pkg/runtimes/jvm"
	"ebpf-tracing/pkg/runtimes/python"
	"ebpf-tracing/pkg/runtimes/v8"
)

// RuntimeManager coordinates all runtime tracers
type RuntimeManager struct {
	config      *RuntimeConfig
	jvmTracer   *jvm.JVMTracer
	pythonTracer *python.PythonTracer
	v8Tracer    *v8.V8Tracer
	eventChan   chan *RuntimeEvent
	mutex       sync.RWMutex
	running     bool
	stopChan    chan struct{}
}

// RuntimeConfig holds configuration for all runtime tracers
type RuntimeConfig struct {
	EnableJVMTracing    bool                `json:"enable_jvm_tracing" yaml:"enable_jvm_tracing"`
	EnablePythonTracing bool                `json:"enable_python_tracing" yaml:"enable_python_tracing"`
	EnableV8Tracing     bool                `json:"enable_v8_tracing" yaml:"enable_v8_tracing"`
	JVMConfig           *jvm.JVMConfig      `json:"jvm_config" yaml:"jvm_config"`
	PythonConfig        *python.PythonConfig `json:"python_config" yaml:"python_config"`
	V8Config            *v8.V8Config        `json:"v8_config" yaml:"v8_config"`
	EventBufferSize     int                 `json:"event_buffer_size" yaml:"event_buffer_size"`
	CorrelationEnabled  bool                `json:"correlation_enabled" yaml:"correlation_enabled"`
	MetricsEnabled      bool                `json:"metrics_enabled" yaml:"metrics_enabled"`
}

// RuntimeEvent represents a unified runtime event
type RuntimeEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	Runtime     string            `json:"runtime"` // "jvm", "python", "v8"
	EventType   string            `json:"event_type"`
	ProcessID   int               `json:"process_id"`
	ThreadID    int               `json:"thread_id"`
	FunctionName string           `json:"function_name"`
	ModuleName  string            `json:"module_name"`
	Duration    time.Duration     `json:"duration"`
	Arguments   []interface{}     `json:"arguments"`
	ReturnValue interface{}       `json:"return_value"`
	Exception   *RuntimeException `json:"exception"`
	Metadata    map[string]string `json:"metadata"`
	TraceID     string            `json:"trace_id"`
	SpanID      string            `json:"span_id"`
}

// RuntimeException represents a runtime exception
type RuntimeException struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	StackTrace string `json:"stack_trace"`
}

// RuntimeStats holds statistics for all runtimes
type RuntimeStats struct {
	JVMStats    *JVMRuntimeStats    `json:"jvm_stats"`
	PythonStats *PythonRuntimeStats `json:"python_stats"`
	V8Stats     *V8RuntimeStats     `json:"v8_stats"`
	TotalEvents uint64              `json:"total_events"`
	StartTime   time.Time           `json:"start_time"`
	Uptime      time.Duration       `json:"uptime"`
}

// JVMRuntimeStats holds JVM runtime statistics
type JVMRuntimeStats struct {
	ProcessesTracked  int           `json:"processes_tracked"`
	MethodsCalled     uint64        `json:"methods_called"`
	ClassesLoaded     int           `json:"classes_loaded"`
	GCEvents          uint64        `json:"gc_events"`
	TotalGCTime       time.Duration `json:"total_gc_time"`
	HeapUsage         uint64        `json:"heap_usage"`
	ThreadCount       int           `json:"thread_count"`
}

// PythonRuntimeStats holds Python runtime statistics
type PythonRuntimeStats struct {
	ProcessesTracked  int           `json:"processes_tracked"`
	FunctionsCalled   uint64        `json:"functions_called"`
	ModulesLoaded     int           `json:"modules_loaded"`
	CoroutinesActive  int           `json:"coroutines_active"`
	GCEvents          uint64        `json:"gc_events"`
	TotalGCTime       time.Duration `json:"total_gc_time"`
	ThreadCount       int           `json:"thread_count"`
}

// V8RuntimeStats holds V8 runtime statistics
type V8RuntimeStats struct {
	ProcessesTracked    int           `json:"processes_tracked"`
	FunctionsCalled     uint64        `json:"functions_called"`
	ScriptsLoaded       int           `json:"scripts_loaded"`
	CompilationEvents   uint64        `json:"compilation_events"`
	OptimizationEvents  uint64        `json:"optimization_events"`
	GCEvents            uint64        `json:"gc_events"`
	TotalGCTime         time.Duration `json:"total_gc_time"`
	HeapUsage           uint64        `json:"heap_usage"`
	IsolateCount        int           `json:"isolate_count"`
}

// DefaultRuntimeConfig returns default runtime configuration
func DefaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		EnableJVMTracing:    true,
		EnablePythonTracing: true,
		EnableV8Tracing:     true,
		JVMConfig:           jvm.DefaultJVMConfig(),
		PythonConfig:        python.DefaultPythonConfig(),
		V8Config:            v8.DefaultV8Config(),
		EventBufferSize:     50000,
		CorrelationEnabled:  true,
		MetricsEnabled:      true,
	}
}

// NewRuntimeManager creates a new runtime manager
func NewRuntimeManager(config *RuntimeConfig) *RuntimeManager {
	rm := &RuntimeManager{
		config:    config,
		eventChan: make(chan *RuntimeEvent, config.EventBufferSize),
		stopChan:  make(chan struct{}),
	}

	// Initialize runtime tracers based on configuration
	if config.EnableJVMTracing {
		rm.jvmTracer = jvm.NewJVMTracer(config.JVMConfig)
	}

	if config.EnablePythonTracing {
		rm.pythonTracer = python.NewPythonTracer(config.PythonConfig)
	}

	if config.EnableV8Tracing {
		rm.v8Tracer = v8.NewV8Tracer(config.V8Config)
	}

	return rm
}

// Start starts all enabled runtime tracers
func (rm *RuntimeManager) Start(ctx context.Context) error {
	if rm.running {
		return fmt.Errorf("runtime manager already running")
	}

	// Start JVM tracer if enabled
	if rm.config.EnableJVMTracing && rm.jvmTracer != nil {
		if err := rm.jvmTracer.Start(ctx); err != nil {
			fmt.Printf("Warning: Failed to start JVM tracer: %v\n", err)
		} else {
			fmt.Println("JVM tracer started successfully")
		}
	}

	// Start Python tracer if enabled
	if rm.config.EnablePythonTracing && rm.pythonTracer != nil {
		if err := rm.pythonTracer.Start(ctx); err != nil {
			fmt.Printf("Warning: Failed to start Python tracer: %v\n", err)
		} else {
			fmt.Println("Python tracer started successfully")
		}
	}

	// Start V8 tracer if enabled
	if rm.config.EnableV8Tracing && rm.v8Tracer != nil {
		if err := rm.v8Tracer.Start(ctx); err != nil {
			fmt.Printf("Warning: Failed to start V8 tracer: %v\n", err)
		} else {
			fmt.Println("V8 tracer started successfully")
		}
	}

	rm.running = true

	// Start event processing and correlation
	go rm.processEvents(ctx)
	go rm.correlateEvents(ctx)
	go rm.collectMetrics(ctx)

	return nil
}

// Stop stops all runtime tracers
func (rm *RuntimeManager) Stop() error {
	if !rm.running {
		return fmt.Errorf("runtime manager not running")
	}

	rm.running = false
	close(rm.stopChan)

	// Stop all tracers
	if rm.jvmTracer != nil {
		if err := rm.jvmTracer.Stop(); err != nil {
			fmt.Printf("Warning: Failed to stop JVM tracer: %v\n", err)
		}
	}

	if rm.pythonTracer != nil {
		if err := rm.pythonTracer.Stop(); err != nil {
			fmt.Printf("Warning: Failed to stop Python tracer: %v\n", err)
		}
	}

	if rm.v8Tracer != nil {
		if err := rm.v8Tracer.Stop(); err != nil {
			fmt.Printf("Warning: Failed to stop V8 tracer: %v\n", err)
		}
	}

	close(rm.eventChan)
	return nil
}

// processEvents processes runtime events from all tracers
func (rm *RuntimeManager) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case event := <-rm.eventChan:
			rm.handleRuntimeEvent(event)
		}
	}
}

// correlateEvents correlates events across different runtimes
func (rm *RuntimeManager) correlateEvents(ctx context.Context) {
	if !rm.config.CorrelationEnabled {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.performCorrelation()
		}
	}
}

// collectMetrics collects metrics from all runtime tracers
func (rm *RuntimeManager) collectMetrics(ctx context.Context) {
	if !rm.config.MetricsEnabled {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.updateMetrics()
		}
	}
}

// handleRuntimeEvent handles a runtime event
func (rm *RuntimeManager) handleRuntimeEvent(event *RuntimeEvent) {
	if event == nil {
		return
	}

	// Process the event - logging, forwarding, analysis, etc.
	fmt.Printf("Runtime Event: %s %s.%s took %v\n",
		event.Runtime, event.ModuleName, event.FunctionName, event.Duration)
}

// performCorrelation performs cross-runtime event correlation
func (rm *RuntimeManager) performCorrelation() {
	// Implement correlation logic to link events across runtimes
	// This could involve matching trace IDs, timestamps, process relationships, etc.
}

// updateMetrics updates runtime metrics
func (rm *RuntimeManager) updateMetrics() {
	// Collect and update metrics from all runtime tracers
}

// GetStats returns comprehensive runtime statistics
func (rm *RuntimeManager) GetStats() *RuntimeStats {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	stats := &RuntimeStats{
		StartTime: time.Now(), // This should be set when starting
		Uptime:    time.Since(time.Now()), // This should be calculated properly
	}

	// Collect JVM stats
	if rm.jvmTracer != nil && rm.jvmTracer.IsRunning() {
		stats.JVMStats = &JVMRuntimeStats{
			ProcessesTracked: 1, // This should be calculated from actual data
			// Other stats would be collected from the JVM tracer
		}
	}

	// Collect Python stats
	if rm.pythonTracer != nil && rm.pythonTracer.IsRunning() {
		stats.PythonStats = &PythonRuntimeStats{
			ProcessesTracked: 1, // This should be calculated from actual data
			// Other stats would be collected from the Python tracer
		}
	}

	// Collect V8 stats
	if rm.v8Tracer != nil && rm.v8Tracer.IsRunning() {
		stats.V8Stats = &V8RuntimeStats{
			ProcessesTracked: 1, // This should be calculated from actual data
			// Other stats would be collected from the V8 tracer
		}
	}

	return stats
}

// GetJVMStats returns JVM-specific statistics
func (rm *RuntimeManager) GetJVMStats() map[string]*jvm.MethodInfo {
	if rm.jvmTracer != nil {
		return rm.jvmTracer.GetMethodStats()
	}
	return nil
}

// GetPythonStats returns Python-specific statistics
func (rm *RuntimeManager) GetPythonStats() map[string]*python.FunctionInfo {
	if rm.pythonTracer != nil {
		return rm.pythonTracer.GetFunctionStats()
	}
	return nil
}

// GetV8Stats returns V8-specific statistics
func (rm *RuntimeManager) GetV8Stats() map[string]*v8.JSFunctionInfo {
	if rm.v8Tracer != nil {
		return rm.v8Tracer.GetFunctionStats()
	}
	return nil
}

// IsRunning returns whether the runtime manager is running
func (rm *RuntimeManager) IsRunning() bool {
	return rm.running
}

// GetActiveRuntimes returns a list of active runtime tracers
func (rm *RuntimeManager) GetActiveRuntimes() []string {
	runtimes := make([]string, 0)

	if rm.jvmTracer != nil && rm.jvmTracer.IsRunning() {
		runtimes = append(runtimes, "jvm")
	}

	if rm.pythonTracer != nil && rm.pythonTracer.IsRunning() {
		runtimes = append(runtimes, "python")
	}

	if rm.v8Tracer != nil && rm.v8Tracer.IsRunning() {
		runtimes = append(runtimes, "v8")
	}

	return runtimes
}

// SendEvent sends a runtime event to the event channel
func (rm *RuntimeManager) SendEvent(event *RuntimeEvent) {
	select {
	case rm.eventChan <- event:
	default:
		// Channel is full, drop the event or handle overflow
		fmt.Printf("Warning: Runtime event channel full, dropping event\n")
	}
}

// GetEventChannel returns the event channel for external consumers
func (rm *RuntimeManager) GetEventChannel() <-chan *RuntimeEvent {
	return rm.eventChan
}

// UpdateConfig updates the runtime configuration
func (rm *RuntimeManager) UpdateConfig(config *RuntimeConfig) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.running {
		return fmt.Errorf("cannot update configuration while running")
	}

	rm.config = config
	return nil
}

// GetConfig returns the current runtime configuration
func (rm *RuntimeManager) GetConfig() *RuntimeConfig {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return rm.config
}
