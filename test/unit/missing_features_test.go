package unit

import (
	"context"
	"testing"
	"time"

	"ebpf-tracing/pkg/correlation"
	"ebpf-tracing/pkg/optimization"
	"ebpf-tracing/pkg/stack"
	"ebpf-tracing/pkg/xdp"
)

// TestXDPManagerCreation tests XDP manager creation
func TestXDPManagerCreation(t *testing.T) {
	config := xdp.DefaultXDPConfig()
	if config == nil {
		t.Fatal("Expected XDP config to be created")
	}

	manager := xdp.NewXDPManager(config)
	if manager == nil {
		t.Fatal("Expected XDP manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected XDP manager to not be running initially")
	}

	// Test configuration
	if !config.EnableHTTPDetection {
		t.Error("Expected HTTP detection to be enabled by default")
	}

	if !config.EnableFlowTracking {
		t.Error("Expected flow tracking to be enabled by default")
	}

	if !config.EnablePacketCapture {
		t.Error("Expected packet capture to be enabled by default")
	}

	if config.SamplingRate != 1 {
		t.Errorf("Expected sampling rate to be 1, got %d", config.SamplingRate)
	}

	if config.MaxPacketSize != 1500 {
		t.Errorf("Expected max packet size to be 1500, got %d", config.MaxPacketSize)
	}

	if len(config.HTTPPorts) == 0 {
		t.Error("Expected some HTTP ports to be configured")
	}

	t.Logf("XDP manager created successfully with config: %+v", config)
}

// TestXDPManagerLifecycle tests XDP manager lifecycle
func TestXDPManagerLifecycle(t *testing.T) {
	config := xdp.DefaultXDPConfig()
	// Use loopback interface for testing
	config.Interfaces = []string{"lo"}
	config.EnableEgressCapture = false // Disable for unit test
	
	manager := xdp.NewXDPManager(config)
	
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Note: XDP requires root privileges and actual network interfaces
	// For unit testing, we'll test the creation and configuration only
	if !manager.IsRunning() {
		t.Log("XDP manager correctly reports not running initially")
	}

	// Test getting packet stats (should work even without starting)
	stats := manager.GetPacketStats()
	if stats == nil {
		t.Error("Expected packet stats to be non-nil")
	}

	if stats.StartTime.IsZero() {
		t.Error("Expected start time to be set")
	}

	// Test getting event channel
	eventChan := manager.GetEventChannel()
	if eventChan == nil {
		t.Error("Expected event channel to be non-nil")
	}

	t.Logf("XDP manager lifecycle test completed successfully")
}

// TestStackManagerCreation tests stack manager creation
func TestStackManagerCreation(t *testing.T) {
	config := stack.DefaultStackConfig()
	if config == nil {
		t.Fatal("Expected stack config to be created")
	}

	manager := stack.NewStackManager(config)
	if manager == nil {
		t.Fatal("Expected stack manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected stack manager to not be running initially")
	}

	// Test configuration
	if !config.EnableKernelStacks {
		t.Error("Expected kernel stacks to be enabled by default")
	}

	if !config.EnableUserStacks {
		t.Error("Expected user stacks to be enabled by default")
	}

	if !config.EnableMixedStacks {
		t.Error("Expected mixed stacks to be enabled by default")
	}

	if config.SamplingFrequency != 99 {
		t.Errorf("Expected sampling frequency to be 99, got %d", config.SamplingFrequency)
	}

	if config.MaxStackDepth != 127 {
		t.Errorf("Expected max stack depth to be 127, got %d", config.MaxStackDepth)
	}

	if !config.EnableDWARFUnwinding {
		t.Error("Expected DWARF unwinding to be enabled by default")
	}

	if !config.EnableFramePointers {
		t.Error("Expected frame pointers to be enabled by default")
	}

	t.Logf("Stack manager created successfully with config: %+v", config)
}

// TestStackManagerLifecycle tests stack manager lifecycle
func TestStackManagerLifecycle(t *testing.T) {
	config := stack.DefaultStackConfig()
	// Disable actual eBPF for unit test
	config.EnableKernelStacks = false
	config.EnableUserStacks = false
	config.SamplingFrequency = 0 // Disable sampling
	
	manager := stack.NewStackManager(config)
	
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Note: Stack tracing requires root privileges and eBPF support
	// For unit testing, we'll test the creation and basic functionality
	if !manager.IsRunning() {
		t.Log("Stack manager correctly reports not running initially")
	}

	// Test getting event channel
	eventChan := manager.GetEventChannel()
	if eventChan == nil {
		t.Error("Expected event channel to be non-nil")
	}

	// Test getting flame graph
	flamegraph := manager.GetFlameGraph()
	if flamegraph == nil {
		t.Error("Expected flame graph to be non-nil")
	}

	if flamegraph.Root == nil {
		t.Error("Expected flame graph root to be non-nil")
	}

	t.Logf("Stack manager lifecycle test completed successfully")
}

// TestVerifierOptimizerCreation tests verifier optimizer creation
func TestVerifierOptimizerCreation(t *testing.T) {
	config := optimization.DefaultOptimizerConfig()
	if config == nil {
		t.Fatal("Expected optimizer config to be created")
	}

	optimizer := optimization.NewVerifierOptimizer(config)
	if optimizer == nil {
		t.Fatal("Expected verifier optimizer to be created")
	}

	// Test configuration
	if !config.EnableComplexityAnalysis {
		t.Error("Expected complexity analysis to be enabled by default")
	}

	if !config.EnableInstructionOptimization {
		t.Error("Expected instruction optimization to be enabled by default")
	}

	if !config.EnableLoopUnrolling {
		t.Error("Expected loop unrolling to be enabled by default")
	}

	if !config.EnableDeadCodeElimination {
		t.Error("Expected dead code elimination to be enabled by default")
	}

	if config.MaxInstructions != 4096 {
		t.Errorf("Expected max instructions to be 4096, got %d", config.MaxInstructions)
	}

	if config.MaxComplexity != 1000000 {
		t.Errorf("Expected max complexity to be 1000000, got %d", config.MaxComplexity)
	}

	if config.OptimizationLevel != 2 {
		t.Errorf("Expected optimization level to be 2, got %d", config.OptimizationLevel)
	}

	t.Logf("Verifier optimizer created successfully with config: %+v", config)
}

// TestVerifierOptimizerStats tests verifier optimizer statistics
func TestVerifierOptimizerStats(t *testing.T) {
	config := optimization.DefaultOptimizerConfig()
	optimizer := optimization.NewVerifierOptimizer(config)

	// Test getting stats
	stats := optimizer.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	if stats.TotalPrograms != 0 {
		t.Errorf("Expected total programs to be 0 initially, got %d", stats.TotalPrograms)
	}

	if stats.OptimizedPrograms != 0 {
		t.Errorf("Expected optimized programs to be 0 initially, got %d", stats.OptimizedPrograms)
	}

	if stats.ComplexityReductions == nil {
		t.Error("Expected complexity reductions to be non-nil")
	}

	// Test cache clearing
	optimizer.ClearCache()

	t.Logf("Verifier optimizer stats test completed successfully")
}

// TestCorrelationManagerCreation tests correlation manager creation
func TestCorrelationManagerCreation(t *testing.T) {
	config := correlation.DefaultCorrelationConfig()
	if config == nil {
		t.Fatal("Expected correlation config to be created")
	}

	manager := correlation.NewCorrelationManager(config)
	if manager == nil {
		t.Fatal("Expected correlation manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected correlation manager to not be running initially")
	}

	// Test configuration
	if !config.EnableHTTPCorrelation {
		t.Error("Expected HTTP correlation to be enabled by default")
	}

	if !config.EnableGRPCCorrelation {
		t.Error("Expected gRPC correlation to be enabled by default")
	}

	if !config.EnableAsyncCorrelation {
		t.Error("Expected async correlation to be enabled by default")
	}

	if !config.EnableRuntimeCorrelation {
		t.Error("Expected runtime correlation to be enabled by default")
	}

	if !config.EnableDistributedTracing {
		t.Error("Expected distributed tracing to be enabled by default")
	}

	if config.TraceIDHeader != "X-Trace-ID" {
		t.Errorf("Expected trace ID header to be 'X-Trace-ID', got %s", config.TraceIDHeader)
	}

	if config.SamplingRate != 1.0 {
		t.Errorf("Expected sampling rate to be 1.0, got %f", config.SamplingRate)
	}

	t.Logf("Correlation manager created successfully with config: %+v", config)
}

// TestCorrelationManagerLifecycle tests correlation manager lifecycle
func TestCorrelationManagerLifecycle(t *testing.T) {
	config := correlation.DefaultCorrelationConfig()
	manager := correlation.NewCorrelationManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test start
	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlation manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Expected correlation manager to be running after start")
	}

	// Test stats
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	if stats["total_traces"] == nil {
		t.Error("Expected total_traces stat to be present")
	}

	if stats["http_correlation_enabled"] != true {
		t.Error("Expected HTTP correlation to be enabled")
	}

	// Test stop
	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop correlation manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Expected correlation manager to not be running after stop")
	}

	t.Logf("Correlation manager lifecycle test completed successfully")
}

// TestHTTPCorrelation tests HTTP event correlation
func TestHTTPCorrelation(t *testing.T) {
	config := correlation.DefaultCorrelationConfig()
	manager := correlation.NewCorrelationManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlation manager: %v", err)
	}
	defer manager.Stop()

	// Create test HTTP event
	httpEvent := &correlation.HTTPEvent{
		Timestamp:  uint64(time.Now().UnixNano()),
		PID:        1234,
		TID:        5678,
		Type:       "request",
		Method:     "GET",
		URL:        "/api/test",
		StatusCode: 200,
		Duration:   100 * time.Millisecond,
		Headers: map[string]string{
			"X-Trace-ID": "test-trace-123",
			"X-Span-ID":  "test-span-456",
		},
	}

	// Correlate HTTP event
	correlatedEvent, err := manager.CorrelateHTTPEvent(httpEvent)
	if err != nil {
		t.Fatalf("Failed to correlate HTTP event: %v", err)
	}

	if correlatedEvent == nil {
		t.Fatal("Expected correlated event to be non-nil")
	}

	if correlatedEvent.EventType != "http" {
		t.Errorf("Expected event type to be 'http', got %s", correlatedEvent.EventType)
	}

	if correlatedEvent.TraceID != "test-trace-123" {
		t.Errorf("Expected trace ID to be 'test-trace-123', got %s", correlatedEvent.TraceID)
	}

	if correlatedEvent.SpanID != "test-span-456" {
		t.Errorf("Expected span ID to be 'test-span-456', got %s", correlatedEvent.SpanID)
	}

	// Test trace retrieval
	trace, found := manager.GetTrace("test-trace-123")
	if !found {
		t.Error("Expected to find trace")
	}

	if trace == nil {
		t.Error("Expected trace to be non-nil")
	}

	t.Logf("HTTP correlation test completed successfully")
}

// TestRuntimeCorrelation tests runtime event correlation
func TestRuntimeCorrelation(t *testing.T) {
	config := correlation.DefaultCorrelationConfig()
	manager := correlation.NewCorrelationManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlation manager: %v", err)
	}
	defer manager.Stop()

	// Create test runtime event
	runtimeEvent := &correlation.RuntimeEvent{
		Timestamp:    time.Now(),
		Runtime:      "jvm",
		EventType:    "function_call",
		ProcessID:    1234,
		ThreadID:     5678,
		FunctionName: "processRequest",
		ModuleName:   "com.example.Service",
		Duration:     50 * time.Millisecond,
		TraceID:      "test-trace-789",
		SpanID:       "test-span-012",
		Arguments:    []interface{}{"arg1", "arg2"},
		Metadata:     map[string]string{"class": "Service"},
	}

	// Correlate runtime event
	correlatedEvent, err := manager.CorrelateRuntimeEvent(runtimeEvent)
	if err != nil {
		t.Fatalf("Failed to correlate runtime event: %v", err)
	}

	if correlatedEvent == nil {
		t.Fatal("Expected correlated event to be non-nil")
	}

	if correlatedEvent.EventType != "runtime" {
		t.Errorf("Expected event type to be 'runtime', got %s", correlatedEvent.EventType)
	}

	if correlatedEvent.Runtime != "jvm" {
		t.Errorf("Expected runtime to be 'jvm', got %s", correlatedEvent.Runtime)
	}

	if correlatedEvent.TraceID != "test-trace-789" {
		t.Errorf("Expected trace ID to be 'test-trace-789', got %s", correlatedEvent.TraceID)
	}

	// Test span retrieval
	span, found := manager.GetSpan("test-span-012")
	if !found {
		t.Error("Expected to find span")
	}

	if span == nil {
		t.Error("Expected span to be non-nil")
	}

	t.Logf("Runtime correlation test completed successfully")
}

// TestAsyncCorrelation tests async event correlation
func TestAsyncCorrelation(t *testing.T) {
	config := correlation.DefaultCorrelationConfig()
	manager := correlation.NewCorrelationManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlation manager: %v", err)
	}
	defer manager.Stop()

	// Test async correlation
	asyncContext, err := manager.CorrelateAsyncEvent("async-123", "promise", "parent-async-456")
	if err != nil {
		t.Fatalf("Failed to correlate async event: %v", err)
	}

	if asyncContext == nil {
		t.Fatal("Expected async context to be non-nil")
	}

	if asyncContext.AsyncID != "async-123" {
		t.Errorf("Expected async ID to be 'async-123', got %s", asyncContext.AsyncID)
	}

	if asyncContext.AsyncType != "promise" {
		t.Errorf("Expected async type to be 'promise', got %s", asyncContext.AsyncType)
	}

	if asyncContext.ParentAsync != "parent-async-456" {
		t.Errorf("Expected parent async to be 'parent-async-456', got %s", asyncContext.ParentAsync)
	}

	t.Logf("Async correlation test completed successfully")
}

// TestIntegratedCorrelation tests integrated correlation across all types
func TestIntegratedCorrelation(t *testing.T) {
	config := correlation.DefaultCorrelationConfig()
	manager := correlation.NewCorrelationManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start correlation manager: %v", err)
	}
	defer manager.Stop()

	traceID := "integrated-trace-123"
	
	// Correlate HTTP event
	httpEvent := &correlation.HTTPEvent{
		Timestamp:  uint64(time.Now().UnixNano()),
		PID:        1234,
		TID:        5678,
		Type:       "request",
		Method:     "POST",
		URL:        "/api/process",
		StatusCode: 200,
		Headers:    map[string]string{"X-Trace-ID": traceID},
	}
	
	httpCorrelated, err := manager.CorrelateHTTPEvent(httpEvent)
	if err != nil {
		t.Fatalf("Failed to correlate HTTP event: %v", err)
	}

	// Correlate runtime event with same trace ID
	runtimeEvent := &correlation.RuntimeEvent{
		Timestamp:    time.Now(),
		Runtime:      "python",
		ProcessID:    1234,
		ThreadID:     5678,
		FunctionName: "handle_request",
		TraceID:      traceID,
	}
	
	runtimeCorrelated, err := manager.CorrelateRuntimeEvent(runtimeEvent)
	if err != nil {
		t.Fatalf("Failed to correlate runtime event: %v", err)
	}

	// Verify both events have the same trace ID
	if httpCorrelated.TraceID != runtimeCorrelated.TraceID {
		t.Errorf("Expected same trace ID, got HTTP: %s, Runtime: %s", 
			httpCorrelated.TraceID, runtimeCorrelated.TraceID)
	}

	// Verify trace contains both events
	trace, found := manager.GetTrace(traceID)
	if !found {
		t.Fatal("Expected to find integrated trace")
	}

	if len(trace.Spans) == 0 {
		t.Error("Expected trace to have spans")
	}

	// Check final stats
	stats := manager.GetStats()
	totalTraces := stats["total_traces"].(int)
	if totalTraces == 0 {
		t.Error("Expected at least one trace")
	}

	t.Logf("Integrated correlation test completed successfully with %d traces", totalTraces)
}
