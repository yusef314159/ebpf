package v8

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// V8Tracer provides deep integration with V8 JavaScript engine
type V8Tracer struct {
	config         *V8Config
	programs       map[string]*ebpf.Program
	links          []link.Link
	functionMap    map[string]*JSFunctionInfo
	scriptMap      map[string]*ScriptInfo
	isolateMap     map[string]*IsolateInfo
	contextMap     map[string]*ContextInfo
	functionEvents chan *JSFunctionEvent
	gcEvents       chan *V8GCEvent
	compileEvents  chan *CompileEvent
	mutex          sync.RWMutex
	running        bool
	stopChan       chan struct{}
}

// V8Config holds V8 tracer configuration
type V8Config struct {
	EnableFunctionTracing    bool     `json:"enable_function_tracing" yaml:"enable_function_tracing"`
	EnableCompilationTracing bool     `json:"enable_compilation_tracing" yaml:"enable_compilation_tracing"`
	EnableGCMonitoring       bool     `json:"enable_gc_monitoring" yaml:"enable_gc_monitoring"`
	EnableOptimizationTracing bool    `json:"enable_optimization_tracing" yaml:"enable_optimization_tracing"`
	EnableEventLoopMonitoring bool    `json:"enable_event_loop_monitoring" yaml:"enable_event_loop_monitoring"`
	EnableModuleTracking     bool     `json:"enable_module_tracking" yaml:"enable_module_tracking"`
	NodePaths                []string `json:"node_paths" yaml:"node_paths"`
	TargetProcesses          []string `json:"target_processes" yaml:"target_processes"`
	FunctionFilters          []string `json:"function_filters" yaml:"function_filters"`
	ScriptFilters            []string `json:"script_filters" yaml:"script_filters"`
	SamplingRate             float64  `json:"sampling_rate" yaml:"sampling_rate"`
	MaxFunctionsTracked      int      `json:"max_functions_tracked" yaml:"max_functions_tracked"`
	MaxScriptsTracked        int      `json:"max_scripts_tracked" yaml:"max_scripts_tracked"`
	FunctionEventBufferSize  int      `json:"function_event_buffer_size" yaml:"function_event_buffer_size"`
	GCEventBufferSize        int      `json:"gc_event_buffer_size" yaml:"gc_event_buffer_size"`
	CompileEventBufferSize   int      `json:"compile_event_buffer_size" yaml:"compile_event_buffer_size"`
}

// JSFunctionInfo holds information about a JavaScript function
type JSFunctionInfo struct {
	FunctionName    string            `json:"function_name"`
	ScriptName      string            `json:"script_name"`
	LineNumber      int               `json:"line_number"`
	ColumnNumber    int               `json:"column_number"`
	FunctionType    string            `json:"function_type"` // "function", "arrow", "async", "generator"
	IsNative        bool              `json:"is_native"`
	IsOptimized     bool              `json:"is_optimized"`
	IsInlined       bool              `json:"is_inlined"`
	OptimizationTier string           `json:"optimization_tier"` // "ignition", "turbofan", "maglev"
	SharedFunctionInfo uint64         `json:"shared_function_info"`
	CodeObject      uint64            `json:"code_object"`
	Parameters      []ParameterInfo   `json:"parameters"`
	SourceCode      string            `json:"source_code"`
	Metadata        map[string]string `json:"metadata"`
	CallCount       uint64            `json:"call_count"`
	TotalTime       time.Duration     `json:"total_time"`
	CompileTime     time.Duration     `json:"compile_time"`
	LastCalled      time.Time         `json:"last_called"`
}

// ScriptInfo holds information about a JavaScript script
type ScriptInfo struct {
	ScriptID      int               `json:"script_id"`
	ScriptName    string            `json:"script_name"`
	SourceURL     string            `json:"source_url"`
	SourceMapURL  string            `json:"source_map_url"`
	ScriptType    string            `json:"script_type"` // "classic", "module", "eval"
	Functions     []string          `json:"functions"`
	LoadTime      time.Time         `json:"load_time"`
	CompileTime   time.Duration     `json:"compile_time"`
	Size          int64             `json:"size"`
	IsModule      bool              `json:"is_module"`
	IsEval        bool              `json:"is_eval"`
	Metadata      map[string]string `json:"metadata"`
}

// IsolateInfo holds information about a V8 isolate
type IsolateInfo struct {
	IsolateID     string            `json:"isolate_id"`
	CreationTime  time.Time         `json:"creation_time"`
	HeapSize      uint64            `json:"heap_size"`
	UsedHeapSize  uint64            `json:"used_heap_size"`
	ExternalMemory uint64           `json:"external_memory"`
	Contexts      []string          `json:"contexts"`
	Scripts       []string          `json:"scripts"`
	Metadata      map[string]string `json:"metadata"`
}

// ContextInfo holds information about a V8 context
type ContextInfo struct {
	ContextID     string            `json:"context_id"`
	IsolateID     string            `json:"isolate_id"`
	CreationTime  time.Time         `json:"creation_time"`
	GlobalObject  uint64            `json:"global_object"`
	SecurityToken uint64            `json:"security_token"`
	IsDefault     bool              `json:"is_default"`
	Metadata      map[string]string `json:"metadata"`
}

// JSFunctionEvent represents a JavaScript function call event
type JSFunctionEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	IsolateID     string            `json:"isolate_id"`
	ContextID     string            `json:"context_id"`
	FunctionInfo  *JSFunctionInfo   `json:"function_info"`
	EventType     string            `json:"event_type"` // "call", "return", "exception", "yield"
	Arguments     []interface{}     `json:"arguments"`
	ReturnValue   interface{}       `json:"return_value"`
	Exception     *JSException      `json:"exception"`
	Duration      time.Duration     `json:"duration"`
	StackDepth    int               `json:"stack_depth"`
	IsAsync       bool              `json:"is_async"`
	PromiseID     string            `json:"promise_id"`
	Metadata      map[string]string `json:"metadata"`
}

// V8GCEvent represents a V8 garbage collection event
type V8GCEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	IsolateID     string            `json:"isolate_id"`
	GCType        string            `json:"gc_type"` // "scavenge", "mark_compact", "incremental"
	GCReason      string            `json:"gc_reason"`
	Duration      time.Duration     `json:"duration"`
	BeforeSize    uint64            `json:"before_size"`
	AfterSize     uint64            `json:"after_size"`
	ExternalBefore uint64           `json:"external_before"`
	ExternalAfter uint64            `json:"external_after"`
	Metadata      map[string]string `json:"metadata"`
}

// CompileEvent represents a V8 compilation event
type CompileEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	IsolateID     string            `json:"isolate_id"`
	ScriptID      int               `json:"script_id"`
	FunctionName  string            `json:"function_name"`
	CompileType   string            `json:"compile_type"` // "parse", "compile", "optimize", "deoptimize"
	OptimizationTier string         `json:"optimization_tier"`
	Duration      time.Duration     `json:"duration"`
	CodeSize      int               `json:"code_size"`
	Success       bool              `json:"success"`
	Reason        string            `json:"reason"`
	Metadata      map[string]string `json:"metadata"`
}

// ParameterInfo represents function parameter information
type ParameterInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	IsOptional   bool   `json:"is_optional"`
	DefaultValue string `json:"default_value"`
}

// JSException represents a JavaScript exception
type JSException struct {
	Name       string      `json:"name"`
	Message    string      `json:"message"`
	Stack      string      `json:"stack"`
	StackTrace []JSFrame   `json:"stack_trace"`
}

// JSFrame represents a JavaScript stack frame
type JSFrame struct {
	FunctionName string `json:"function_name"`
	ScriptName   string `json:"script_name"`
	LineNumber   int    `json:"line_number"`
	ColumnNumber int    `json:"column_number"`
}

// NodeProcess represents a Node.js process
type NodeProcess struct {
	PID         int    `json:"pid"`
	CommandLine string `json:"command_line"`
	NodePath    string `json:"node_path"`
	Version     string `json:"version"`
	MainScript  string `json:"main_script"`
	Arguments   string `json:"arguments"`
}

// DefaultV8Config returns default V8 tracer configuration
func DefaultV8Config() *V8Config {
	return &V8Config{
		EnableFunctionTracing:     true,
		EnableCompilationTracing:  true,
		EnableGCMonitoring:        true,
		EnableOptimizationTracing: true,
		EnableEventLoopMonitoring: true,
		EnableModuleTracking:      true,
		NodePaths: []string{
			"/usr/bin/node",
			"/usr/local/bin/node",
			"/opt/node*/bin/node",
		},
		TargetProcesses: []string{"node", "nodejs", "npm", "yarn", "electron"},
		FunctionFilters: []string{
			"*.js",
			"*.mjs",
			"*.ts",
		},
		ScriptFilters: []string{
			"*.js",
			"*.mjs",
			"*.ts",
			"*.json",
		},
		SamplingRate:            1.0, // 100% sampling by default
		MaxFunctionsTracked:     20000,
		MaxScriptsTracked:       5000,
		FunctionEventBufferSize: 20000,
		GCEventBufferSize:       2000,
		CompileEventBufferSize:  5000,
	}
}

// NewV8Tracer creates a new V8 tracer
func NewV8Tracer(config *V8Config) *V8Tracer {
	return &V8Tracer{
		config:         config,
		programs:       make(map[string]*ebpf.Program),
		links:          make([]link.Link, 0),
		functionMap:    make(map[string]*JSFunctionInfo),
		scriptMap:      make(map[string]*ScriptInfo),
		isolateMap:     make(map[string]*IsolateInfo),
		contextMap:     make(map[string]*ContextInfo),
		functionEvents: make(chan *JSFunctionEvent, config.FunctionEventBufferSize),
		gcEvents:       make(chan *V8GCEvent, config.GCEventBufferSize),
		compileEvents:  make(chan *CompileEvent, config.CompileEventBufferSize),
		stopChan:       make(chan struct{}),
	}
}

// Start starts the V8 tracer
func (vt *V8Tracer) Start(ctx context.Context) error {
	if vt.running {
		return fmt.Errorf("V8 tracer already running")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memory limit: %w", err)
	}

	// Find Node.js processes
	nodeProcesses, err := vt.findNodeProcesses()
	if err != nil {
		return fmt.Errorf("failed to find Node.js processes: %w", err)
	}

	if len(nodeProcesses) == 0 {
		return fmt.Errorf("no Node.js processes found")
	}

	// Load eBPF programs
	if err := vt.loadPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Attach to Node.js processes
	for _, process := range nodeProcesses {
		if err := vt.attachToProcess(process); err != nil {
			fmt.Printf("Warning: failed to attach to process %d: %v\n", process.PID, err)
			continue
		}
	}

	vt.running = true

	// Start event processing goroutines
	go vt.processFunctionEvents(ctx)
	go vt.processGCEvents(ctx)
	go vt.processCompileEvents(ctx)
	go vt.monitorV8Health(ctx)

	return nil
}

// Stop stops the V8 tracer
func (vt *V8Tracer) Stop() error {
	if !vt.running {
		return fmt.Errorf("V8 tracer not running")
	}

	vt.running = false
	close(vt.stopChan)

	// Close all links
	for _, l := range vt.links {
		l.Close()
	}

	// Close all programs
	for _, prog := range vt.programs {
		prog.Close()
	}

	// Close channels
	close(vt.functionEvents)
	close(vt.gcEvents)
	close(vt.compileEvents)

	return nil
}

// findNodeProcesses finds running Node.js processes
func (vt *V8Tracer) findNodeProcesses() ([]*NodeProcess, error) {
	processes := make([]*NodeProcess, 0)

	// Read /proc to find Node.js processes
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid := entry.Name()
		if !regexp.MustCompile(`^\d+$`).MatchString(pid) {
			continue
		}

		// Read command line
		cmdlinePath := filepath.Join("/proc", pid, "cmdline")
		cmdlineBytes, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		cmdline := string(cmdlineBytes)
		if !vt.isNodeProcess(cmdline) {
			continue
		}

		// Parse Node.js process information
		process, err := vt.parseNodeProcess(pid, cmdline)
		if err != nil {
			continue
		}

		processes = append(processes, process)
	}

	return processes, nil
}

// isNodeProcess checks if a command line represents a Node.js process
func (vt *V8Tracer) isNodeProcess(cmdline string) bool {
	for _, target := range vt.config.TargetProcesses {
		if strings.Contains(cmdline, target) {
			return true
		}
	}
	return false
}

// parseNodeProcess parses Node.js process information
func (vt *V8Tracer) parseNodeProcess(pidStr, cmdline string) (*NodeProcess, error) {
	process := &NodeProcess{
		CommandLine: cmdline,
	}

	// Parse PID
	if n, err := fmt.Sscanf(pidStr, "%d", &process.PID); n != 1 || err != nil {
		return nil, fmt.Errorf("invalid PID: %s", pidStr)
	}

	// Extract main script (simplified)
	parts := strings.Split(cmdline, "\x00")
	for i, part := range parts {
		if strings.Contains(part, "node") && i+1 < len(parts) {
			process.MainScript = parts[i+1]
			break
		}
	}

	return process, nil
}

// loadPrograms loads eBPF programs for V8 tracing
func (vt *V8Tracer) loadPrograms() error {
	// This would load actual eBPF programs for V8 tracing
	// For now, we'll create placeholder programs
	
	// Function call tracing program
	if vt.config.EnableFunctionTracing {
		// Load function tracing eBPF program
		// This would hook into V8 function calls
	}

	// Compilation tracing program
	if vt.config.EnableCompilationTracing {
		// Load compilation tracing eBPF program
		// This would hook into V8 compilation events
	}

	// GC monitoring program
	if vt.config.EnableGCMonitoring {
		// Load GC monitoring eBPF program
		// This would hook into V8 GC events
	}

	return nil
}

// attachToProcess attaches eBPF programs to a Node.js process
func (vt *V8Tracer) attachToProcess(process *NodeProcess) error {
	// Find V8 library
	v8Lib, err := vt.findV8Library(process.PID)
	if err != nil {
		return fmt.Errorf("failed to find V8 library: %w", err)
	}

	// Attach uprobe to V8 functions
	if vt.config.EnableFunctionTracing {
		if err := vt.attachFunctionTracing(process.PID, v8Lib); err != nil {
			return fmt.Errorf("failed to attach function tracing: %w", err)
		}
	}

	if vt.config.EnableGCMonitoring {
		if err := vt.attachGCMonitoring(process.PID, v8Lib); err != nil {
			return fmt.Errorf("failed to attach GC monitoring: %w", err)
		}
	}

	return nil
}

// findV8Library finds the V8 library for a process
func (vt *V8Tracer) findV8Library(pid int) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(mapsData), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libv8") || strings.Contains(line, "node") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				return parts[5], nil
			}
		}
	}

	return "", fmt.Errorf("V8 library not found")
}

// attachFunctionTracing attaches function tracing to V8
func (vt *V8Tracer) attachFunctionTracing(pid int, v8Lib string) error {
	// This would attach uprobe to V8 function call/return points
	// Implementation would depend on V8 engine internals
	return nil
}

// attachGCMonitoring attaches GC monitoring to V8
func (vt *V8Tracer) attachGCMonitoring(pid int, v8Lib string) error {
	// This would attach uprobe to V8 GC functions
	// Implementation would hook into GC start/end events
	return nil
}

// processFunctionEvents processes JavaScript function call events
func (vt *V8Tracer) processFunctionEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-vt.stopChan:
			return
		case event := <-vt.functionEvents:
			vt.handleFunctionEvent(event)
		}
	}
}

// processGCEvents processes garbage collection events
func (vt *V8Tracer) processGCEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-vt.stopChan:
			return
		case event := <-vt.gcEvents:
			vt.handleGCEvent(event)
		}
	}
}

// processCompileEvents processes compilation events
func (vt *V8Tracer) processCompileEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-vt.stopChan:
			return
		case event := <-vt.compileEvents:
			vt.handleCompileEvent(event)
		}
	}
}

// monitorV8Health monitors V8 engine health
func (vt *V8Tracer) monitorV8Health(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-vt.stopChan:
			return
		case <-ticker.C:
			vt.collectV8Metrics()
		}
	}
}

// handleFunctionEvent handles a JavaScript function call event
func (vt *V8Tracer) handleFunctionEvent(event *JSFunctionEvent) {
	vt.mutex.Lock()
	defer vt.mutex.Unlock()

	functionKey := fmt.Sprintf("%s:%s", event.FunctionInfo.ScriptName, event.FunctionInfo.FunctionName)
	if function, exists := vt.functionMap[functionKey]; exists {
		function.CallCount++
		function.LastCalled = event.Timestamp
		if event.Duration > 0 {
			function.TotalTime += event.Duration
		}
	}
}

// handleGCEvent handles a garbage collection event
func (vt *V8Tracer) handleGCEvent(event *V8GCEvent) {
	// Process GC event - update statistics, trigger alerts, etc.
	fmt.Printf("V8 GC Event: %s took %v (before: %d, after: %d)\n", 
		event.GCType, event.Duration, event.BeforeSize, event.AfterSize)
}

// handleCompileEvent handles a compilation event
func (vt *V8Tracer) handleCompileEvent(event *CompileEvent) {
	// Process compile event - track optimization, deoptimization, etc.
	fmt.Printf("V8 Compile Event: %s %s for %s took %v\n", 
		event.CompileType, event.OptimizationTier, event.FunctionName, event.Duration)
}

// collectV8Metrics collects V8 engine metrics
func (vt *V8Tracer) collectV8Metrics() {
	// Collect V8 metrics like heap usage, compilation stats, etc.
	// This would integrate with V8 monitoring APIs
}

// GetFunctionStats returns JavaScript function call statistics
func (vt *V8Tracer) GetFunctionStats() map[string]*JSFunctionInfo {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()

	stats := make(map[string]*JSFunctionInfo)
	for k, v := range vt.functionMap {
		stats[k] = v
	}
	return stats
}

// GetScriptInfo returns script information
func (vt *V8Tracer) GetScriptInfo() map[string]*ScriptInfo {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()

	info := make(map[string]*ScriptInfo)
	for k, v := range vt.scriptMap {
		info[k] = v
	}
	return info
}

// GetIsolateInfo returns isolate information
func (vt *V8Tracer) GetIsolateInfo() map[string]*IsolateInfo {
	vt.mutex.RLock()
	defer vt.mutex.RUnlock()

	info := make(map[string]*IsolateInfo)
	for k, v := range vt.isolateMap {
		info[k] = v
	}
	return info
}

// IsRunning returns whether the tracer is running
func (vt *V8Tracer) IsRunning() bool {
	return vt.running
}
