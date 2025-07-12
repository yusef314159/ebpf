package unit

import (
	"context"
	"testing"
	"time"

	"ebpf-tracing/pkg/runtimes"
	"ebpf-tracing/pkg/runtimes/jvm"
	"ebpf-tracing/pkg/runtimes/python"
	"ebpf-tracing/pkg/runtimes/v8"
)

// TestJVMTracerCreation tests JVM tracer creation
func TestJVMTracerCreation(t *testing.T) {
	config := jvm.DefaultJVMConfig()
	if config == nil {
		t.Fatal("Expected JVM config to be created")
	}

	tracer := jvm.NewJVMTracer(config)
	if tracer == nil {
		t.Fatal("Expected JVM tracer to be created")
	}

	if tracer.IsRunning() {
		t.Error("Expected JVM tracer to not be running initially")
	}

	// Test configuration
	if !config.EnableMethodTracing {
		t.Error("Expected method tracing to be enabled by default")
	}

	if !config.EnableGCMonitoring {
		t.Error("Expected GC monitoring to be enabled by default")
	}

	if !config.EnableThreadTracking {
		t.Error("Expected thread tracking to be enabled by default")
	}

	if config.SamplingRate != 1.0 {
		t.Errorf("Expected sampling rate to be 1.0, got %f", config.SamplingRate)
	}

	if config.MaxMethodsTracked != 10000 {
		t.Errorf("Expected max methods tracked to be 10000, got %d", config.MaxMethodsTracked)
	}

	t.Logf("JVM tracer created successfully with config: %+v", config)
}

// TestPythonTracerCreation tests Python tracer creation
func TestPythonTracerCreation(t *testing.T) {
	config := python.DefaultPythonConfig()
	if config == nil {
		t.Fatal("Expected Python config to be created")
	}

	tracer := python.NewPythonTracer(config)
	if tracer == nil {
		t.Fatal("Expected Python tracer to be created")
	}

	if tracer.IsRunning() {
		t.Error("Expected Python tracer to not be running initially")
	}

	// Test configuration
	if !config.EnableFunctionTracing {
		t.Error("Expected function tracing to be enabled by default")
	}

	if !config.EnableAsyncTracing {
		t.Error("Expected async tracing to be enabled by default")
	}

	if !config.EnableGCMonitoring {
		t.Error("Expected GC monitoring to be enabled by default")
	}

	if config.SamplingRate != 1.0 {
		t.Errorf("Expected sampling rate to be 1.0, got %f", config.SamplingRate)
	}

	if config.MaxFunctionsTracked != 15000 {
		t.Errorf("Expected max functions tracked to be 15000, got %d", config.MaxFunctionsTracked)
	}

	t.Logf("Python tracer created successfully with config: %+v", config)
}

// TestV8TracerCreation tests V8 tracer creation
func TestV8TracerCreation(t *testing.T) {
	config := v8.DefaultV8Config()
	if config == nil {
		t.Fatal("Expected V8 config to be created")
	}

	tracer := v8.NewV8Tracer(config)
	if tracer == nil {
		t.Fatal("Expected V8 tracer to be created")
	}

	if tracer.IsRunning() {
		t.Error("Expected V8 tracer to not be running initially")
	}

	// Test configuration
	if !config.EnableFunctionTracing {
		t.Error("Expected function tracing to be enabled by default")
	}

	if !config.EnableCompilationTracing {
		t.Error("Expected compilation tracing to be enabled by default")
	}

	if !config.EnableGCMonitoring {
		t.Error("Expected GC monitoring to be enabled by default")
	}

	if !config.EnableOptimizationTracing {
		t.Error("Expected optimization tracing to be enabled by default")
	}

	if config.SamplingRate != 1.0 {
		t.Errorf("Expected sampling rate to be 1.0, got %f", config.SamplingRate)
	}

	if config.MaxFunctionsTracked != 20000 {
		t.Errorf("Expected max functions tracked to be 20000, got %d", config.MaxFunctionsTracked)
	}

	t.Logf("V8 tracer created successfully with config: %+v", config)
}

// TestRuntimeManagerCreation tests runtime manager creation
func TestRuntimeManagerCreation(t *testing.T) {
	config := runtimes.DefaultRuntimeConfig()
	if config == nil {
		t.Fatal("Expected runtime config to be created")
	}

	manager := runtimes.NewRuntimeManager(config)
	if manager == nil {
		t.Fatal("Expected runtime manager to be created")
	}

	if manager.IsRunning() {
		t.Error("Expected runtime manager to not be running initially")
	}

	// Test configuration
	if !config.EnableJVMTracing {
		t.Error("Expected JVM tracing to be enabled by default")
	}

	if !config.EnablePythonTracing {
		t.Error("Expected Python tracing to be enabled by default")
	}

	if !config.EnableV8Tracing {
		t.Error("Expected V8 tracing to be enabled by default")
	}

	if !config.CorrelationEnabled {
		t.Error("Expected correlation to be enabled by default")
	}

	if !config.MetricsEnabled {
		t.Error("Expected metrics to be enabled by default")
	}

	if config.EventBufferSize != 50000 {
		t.Errorf("Expected event buffer size to be 50000, got %d", config.EventBufferSize)
	}

	t.Logf("Runtime manager created successfully with config: %+v", config)
}

// TestRuntimeManagerLifecycle tests runtime manager start/stop lifecycle
func TestRuntimeManagerLifecycle(t *testing.T) {
	config := runtimes.DefaultRuntimeConfig()
	
	// Disable actual runtime tracing for unit test
	config.EnableJVMTracing = false
	config.EnablePythonTracing = false
	config.EnableV8Tracing = false
	
	manager := runtimes.NewRuntimeManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test start
	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start runtime manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Expected runtime manager to be running after start")
	}

	// Test active runtimes
	activeRuntimes := manager.GetActiveRuntimes()
	if len(activeRuntimes) != 0 {
		t.Errorf("Expected 0 active runtimes (all disabled), got %d", len(activeRuntimes))
	}

	// Test stats
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	// Test stop
	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop runtime manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Expected runtime manager to not be running after stop")
	}

	t.Logf("Runtime manager lifecycle test completed successfully")
}

// TestRuntimeEventHandling tests runtime event handling
func TestRuntimeEventHandling(t *testing.T) {
	config := runtimes.DefaultRuntimeConfig()
	config.EnableJVMTracing = false
	config.EnablePythonTracing = false
	config.EnableV8Tracing = false
	config.EventBufferSize = 100
	
	manager := runtimes.NewRuntimeManager(config)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start runtime manager: %v", err)
	}
	defer manager.Stop()

	// Create test event
	event := &runtimes.RuntimeEvent{
		Timestamp:    time.Now(),
		Runtime:      "test",
		EventType:    "function_call",
		ProcessID:    12345,
		ThreadID:     1,
		FunctionName: "testFunction",
		ModuleName:   "testModule",
		Duration:     100 * time.Microsecond,
		Arguments:    []interface{}{"arg1", "arg2"},
		ReturnValue:  "result",
		Metadata:     map[string]string{"test": "value"},
		TraceID:      "trace-123",
		SpanID:       "span-456",
	}

	// Send event
	manager.SendEvent(event)

	// Give some time for event processing
	time.Sleep(100 * time.Millisecond)

	t.Logf("Runtime event handling test completed successfully")
}

// TestRuntimeConfiguration tests runtime configuration management
func TestRuntimeConfiguration(t *testing.T) {
	config := runtimes.DefaultRuntimeConfig()
	manager := runtimes.NewRuntimeManager(config)

	// Test getting configuration
	currentConfig := manager.GetConfig()
	if currentConfig == nil {
		t.Error("Expected configuration to be non-nil")
	}

	if currentConfig.EventBufferSize != config.EventBufferSize {
		t.Errorf("Expected event buffer size %d, got %d", 
			config.EventBufferSize, currentConfig.EventBufferSize)
	}

	// Test updating configuration
	newConfig := runtimes.DefaultRuntimeConfig()
	newConfig.EventBufferSize = 25000
	newConfig.CorrelationEnabled = false

	err := manager.UpdateConfig(newConfig)
	if err != nil {
		t.Fatalf("Failed to update configuration: %v", err)
	}

	updatedConfig := manager.GetConfig()
	if updatedConfig.EventBufferSize != 25000 {
		t.Errorf("Expected updated event buffer size 25000, got %d", 
			updatedConfig.EventBufferSize)
	}

	if updatedConfig.CorrelationEnabled {
		t.Error("Expected correlation to be disabled after update")
	}

	t.Logf("Runtime configuration test completed successfully")
}

// TestJVMTracerMethods tests JVM tracer methods
func TestJVMTracerMethods(t *testing.T) {
	config := jvm.DefaultJVMConfig()
	tracer := jvm.NewJVMTracer(config)

	// Test getting method stats (should be empty initially)
	methodStats := tracer.GetMethodStats()
	if methodStats == nil {
		t.Error("Expected method stats to be non-nil")
	}

	if len(methodStats) != 0 {
		t.Errorf("Expected 0 method stats initially, got %d", len(methodStats))
	}

	// Test getting class info
	classInfo := tracer.GetClassInfo()
	if classInfo == nil {
		t.Error("Expected class info to be non-nil")
	}

	if len(classInfo) != 0 {
		t.Errorf("Expected 0 class info initially, got %d", len(classInfo))
	}

	// Test getting thread info
	threadInfo := tracer.GetThreadInfo()
	if threadInfo == nil {
		t.Error("Expected thread info to be non-nil")
	}

	if len(threadInfo) != 0 {
		t.Errorf("Expected 0 thread info initially, got %d", len(threadInfo))
	}

	t.Logf("JVM tracer methods test completed successfully")
}

// TestPythonTracerMethods tests Python tracer methods
func TestPythonTracerMethods(t *testing.T) {
	config := python.DefaultPythonConfig()
	tracer := python.NewPythonTracer(config)

	// Test getting function stats
	functionStats := tracer.GetFunctionStats()
	if functionStats == nil {
		t.Error("Expected function stats to be non-nil")
	}

	if len(functionStats) != 0 {
		t.Errorf("Expected 0 function stats initially, got %d", len(functionStats))
	}

	// Test getting module info
	moduleInfo := tracer.GetModuleInfo()
	if moduleInfo == nil {
		t.Error("Expected module info to be non-nil")
	}

	if len(moduleInfo) != 0 {
		t.Errorf("Expected 0 module info initially, got %d", len(moduleInfo))
	}

	// Test getting coroutine info
	coroutineInfo := tracer.GetCoroutineInfo()
	if coroutineInfo == nil {
		t.Error("Expected coroutine info to be non-nil")
	}

	if len(coroutineInfo) != 0 {
		t.Errorf("Expected 0 coroutine info initially, got %d", len(coroutineInfo))
	}

	t.Logf("Python tracer methods test completed successfully")
}

// TestV8TracerMethods tests V8 tracer methods
func TestV8TracerMethods(t *testing.T) {
	config := v8.DefaultV8Config()
	tracer := v8.NewV8Tracer(config)

	// Test getting function stats
	functionStats := tracer.GetFunctionStats()
	if functionStats == nil {
		t.Error("Expected function stats to be non-nil")
	}

	if len(functionStats) != 0 {
		t.Errorf("Expected 0 function stats initially, got %d", len(functionStats))
	}

	// Test getting script info
	scriptInfo := tracer.GetScriptInfo()
	if scriptInfo == nil {
		t.Error("Expected script info to be non-nil")
	}

	if len(scriptInfo) != 0 {
		t.Errorf("Expected 0 script info initially, got %d", len(scriptInfo))
	}

	// Test getting isolate info
	isolateInfo := tracer.GetIsolateInfo()
	if isolateInfo == nil {
		t.Error("Expected isolate info to be non-nil")
	}

	if len(isolateInfo) != 0 {
		t.Errorf("Expected 0 isolate info initially, got %d", len(isolateInfo))
	}

	t.Logf("V8 tracer methods test completed successfully")
}

// TestRuntimeManagerStats tests runtime manager statistics
func TestRuntimeManagerStats(t *testing.T) {
	config := runtimes.DefaultRuntimeConfig()
	config.EnableJVMTracing = false
	config.EnablePythonTracing = false
	config.EnableV8Tracing = false
	
	manager := runtimes.NewRuntimeManager(config)

	// Test getting stats
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	// Test getting JVM stats (should be nil since disabled)
	jvmStats := manager.GetJVMStats()
	if jvmStats != nil {
		t.Error("Expected JVM stats to be nil when JVM tracing is disabled")
	}

	// Test getting Python stats (should be nil since disabled)
	pythonStats := manager.GetPythonStats()
	if pythonStats != nil {
		t.Error("Expected Python stats to be nil when Python tracing is disabled")
	}

	// Test getting V8 stats (should be nil since disabled)
	v8Stats := manager.GetV8Stats()
	if v8Stats != nil {
		t.Error("Expected V8 stats to be nil when V8 tracing is disabled")
	}

	t.Logf("Runtime manager stats test completed successfully")
}
