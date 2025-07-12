package python

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

// PythonTracer provides deep integration with Python interpreter
type PythonTracer struct {
	config         *PythonConfig
	programs       map[string]*ebpf.Program
	links          []link.Link
	functionMap    map[string]*FunctionInfo
	moduleMap      map[string]*ModuleInfo
	threadMap      map[int]*PythonThreadInfo
	coroutineMap   map[string]*CoroutineInfo
	functionEvents chan *FunctionEvent
	gcEvents       chan *PythonGCEvent
	mutex          sync.RWMutex
	running        bool
	stopChan       chan struct{}
}

// PythonConfig holds Python tracer configuration
type PythonConfig struct {
	EnableFunctionTracing  bool     `json:"enable_function_tracing" yaml:"enable_function_tracing"`
	EnableAsyncTracing     bool     `json:"enable_async_tracing" yaml:"enable_async_tracing"`
	EnableGCMonitoring     bool     `json:"enable_gc_monitoring" yaml:"enable_gc_monitoring"`
	EnableThreadTracking   bool     `json:"enable_thread_tracking" yaml:"enable_thread_tracking"`
	EnableModuleTracking   bool     `json:"enable_module_tracking" yaml:"enable_module_tracking"`
	EnableBytecodeTracing  bool     `json:"enable_bytecode_tracing" yaml:"enable_bytecode_tracing"`
	PythonPaths            []string `json:"python_paths" yaml:"python_paths"`
	TargetProcesses        []string `json:"target_processes" yaml:"target_processes"`
	FunctionFilters        []string `json:"function_filters" yaml:"function_filters"`
	ModuleFilters          []string `json:"module_filters" yaml:"module_filters"`
	SamplingRate           float64  `json:"sampling_rate" yaml:"sampling_rate"`
	MaxFunctionsTracked    int      `json:"max_functions_tracked" yaml:"max_functions_tracked"`
	MaxModulesTracked      int      `json:"max_modules_tracked" yaml:"max_modules_tracked"`
	FunctionEventBufferSize int     `json:"function_event_buffer_size" yaml:"function_event_buffer_size"`
	GCEventBufferSize      int      `json:"gc_event_buffer_size" yaml:"gc_event_buffer_size"`
}

// FunctionInfo holds information about a Python function
type FunctionInfo struct {
	ModuleName    string            `json:"module_name"`
	FunctionName  string            `json:"function_name"`
	FileName      string            `json:"file_name"`
	LineNumber    int               `json:"line_number"`
	CodeObject    uint64            `json:"code_object"`
	IsCoroutine   bool              `json:"is_coroutine"`
	IsGenerator   bool              `json:"is_generator"`
	IsAsync       bool              `json:"is_async"`
	Arguments     []ArgumentInfo    `json:"arguments"`
	LocalVars     []LocalVarInfo    `json:"local_vars"`
	Decorators    []string          `json:"decorators"`
	Docstring     string            `json:"docstring"`
	Metadata      map[string]string `json:"metadata"`
	CallCount     uint64            `json:"call_count"`
	TotalTime     time.Duration     `json:"total_time"`
	LastCalled    time.Time         `json:"last_called"`
}

// ModuleInfo holds information about a Python module
type ModuleInfo struct {
	ModuleName   string            `json:"module_name"`
	FileName     string            `json:"file_name"`
	Package      string            `json:"package"`
	Functions    []string          `json:"functions"`
	Classes      []string          `json:"classes"`
	Imports      []string          `json:"imports"`
	LoadTime     time.Time         `json:"load_time"`
	Size         int64             `json:"size"`
	IsBuiltin    bool              `json:"is_builtin"`
	IsPackage    bool              `json:"is_package"`
	Metadata     map[string]string `json:"metadata"`
}

// PythonThreadInfo holds information about a Python thread
type PythonThreadInfo struct {
	ThreadID      int               `json:"thread_id"`
	ThreadName    string            `json:"thread_name"`
	IsMainThread  bool              `json:"is_main_thread"`
	IsDaemon      bool              `json:"is_daemon"`
	State         string            `json:"state"`
	StackTrace    []PythonFrame     `json:"stack_trace"`
	CreationTime  time.Time         `json:"creation_time"`
	GILTime       time.Duration     `json:"gil_time"`
	BlockedTime   time.Duration     `json:"blocked_time"`
	Metadata      map[string]string `json:"metadata"`
}

// CoroutineInfo holds information about a Python coroutine
type CoroutineInfo struct {
	CoroutineID   string            `json:"coroutine_id"`
	FunctionName  string            `json:"function_name"`
	ModuleName    string            `json:"module_name"`
	State         string            `json:"state"` // "created", "running", "suspended", "closed"
	CreationTime  time.Time         `json:"creation_time"`
	RunTime       time.Duration     `json:"run_time"`
	SuspendTime   time.Duration     `json:"suspend_time"`
	AwaitedBy     string            `json:"awaited_by"`
	StackTrace    []PythonFrame     `json:"stack_trace"`
	Metadata      map[string]string `json:"metadata"`
}

// FunctionEvent represents a Python function call event
type FunctionEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	ThreadID      int               `json:"thread_id"`
	FunctionInfo  *FunctionInfo     `json:"function_info"`
	EventType     string            `json:"event_type"` // "call", "return", "exception", "yield"
	Arguments     []interface{}     `json:"arguments"`
	LocalVars     map[string]interface{} `json:"local_vars"`
	ReturnValue   interface{}       `json:"return_value"`
	Exception     *PythonException  `json:"exception"`
	Duration      time.Duration     `json:"duration"`
	StackDepth    int               `json:"stack_depth"`
	CoroutineID   string            `json:"coroutine_id"`
	Metadata      map[string]string `json:"metadata"`
}

// PythonGCEvent represents a Python garbage collection event
type PythonGCEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	Generation    int               `json:"generation"`
	Collected     int               `json:"collected"`
	Collections   int               `json:"collections"`
	Uncollectable int               `json:"uncollectable"`
	Duration      time.Duration     `json:"duration"`
	BeforeCount   int               `json:"before_count"`
	AfterCount    int               `json:"after_count"`
	Metadata      map[string]string `json:"metadata"`
}

// ArgumentInfo represents function argument information
type ArgumentInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	DefaultValue string `json:"default_value"`
	IsVarArgs    bool   `json:"is_var_args"`
	IsKwArgs     bool   `json:"is_kw_args"`
}

// LocalVarInfo represents local variable information
type LocalVarInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Scope string `json:"scope"`
}

// PythonFrame represents a Python stack frame
type PythonFrame struct {
	FunctionName string `json:"function_name"`
	ModuleName   string `json:"module_name"`
	FileName     string `json:"file_name"`
	LineNumber   int    `json:"line_number"`
	Code         string `json:"code"`
}

// PythonException represents a Python exception
type PythonException struct {
	ExceptionType string        `json:"exception_type"`
	Message       string        `json:"message"`
	StackTrace    []PythonFrame `json:"stack_trace"`
}

// PythonProcess represents a Python process
type PythonProcess struct {
	PID         int    `json:"pid"`
	CommandLine string `json:"command_line"`
	PythonPath  string `json:"python_path"`
	Version     string `json:"version"`
	MainModule  string `json:"main_module"`
	Arguments   string `json:"arguments"`
}

// DefaultPythonConfig returns default Python tracer configuration
func DefaultPythonConfig() *PythonConfig {
	return &PythonConfig{
		EnableFunctionTracing:  true,
		EnableAsyncTracing:     true,
		EnableGCMonitoring:     true,
		EnableThreadTracking:   true,
		EnableModuleTracking:   true,
		EnableBytecodeTracing:  false, // Disabled by default due to overhead
		PythonPaths: []string{
			"/usr/bin/python*",
			"/usr/local/bin/python*",
			"/opt/python*/bin/python*",
		},
		TargetProcesses: []string{"python", "python3", "gunicorn", "uwsgi", "celery"},
		FunctionFilters: []string{
			"__main__.*",
			"*.main",
			"*.handler",
			"*.process",
		},
		ModuleFilters: []string{
			"__main__",
			"*.views",
			"*.models",
			"*.handlers",
		},
		SamplingRate:            1.0, // 100% sampling by default
		MaxFunctionsTracked:     15000,
		MaxModulesTracked:       2000,
		FunctionEventBufferSize: 15000,
		GCEventBufferSize:       1000,
	}
}

// NewPythonTracer creates a new Python tracer
func NewPythonTracer(config *PythonConfig) *PythonTracer {
	return &PythonTracer{
		config:         config,
		programs:       make(map[string]*ebpf.Program),
		links:          make([]link.Link, 0),
		functionMap:    make(map[string]*FunctionInfo),
		moduleMap:      make(map[string]*ModuleInfo),
		threadMap:      make(map[int]*PythonThreadInfo),
		coroutineMap:   make(map[string]*CoroutineInfo),
		functionEvents: make(chan *FunctionEvent, config.FunctionEventBufferSize),
		gcEvents:       make(chan *PythonGCEvent, config.GCEventBufferSize),
		stopChan:       make(chan struct{}),
	}
}

// Start starts the Python tracer
func (pt *PythonTracer) Start(ctx context.Context) error {
	if pt.running {
		return fmt.Errorf("Python tracer already running")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memory limit: %w", err)
	}

	// Find Python processes
	pythonProcesses, err := pt.findPythonProcesses()
	if err != nil {
		return fmt.Errorf("failed to find Python processes: %w", err)
	}

	if len(pythonProcesses) == 0 {
		return fmt.Errorf("no Python processes found")
	}

	// Load eBPF programs
	if err := pt.loadPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Attach to Python processes
	for _, process := range pythonProcesses {
		if err := pt.attachToProcess(process); err != nil {
			fmt.Printf("Warning: failed to attach to process %d: %v\n", process.PID, err)
			continue
		}
	}

	pt.running = true

	// Start event processing goroutines
	go pt.processFunctionEvents(ctx)
	go pt.processGCEvents(ctx)
	go pt.monitorPythonHealth(ctx)

	return nil
}

// Stop stops the Python tracer
func (pt *PythonTracer) Stop() error {
	if !pt.running {
		return fmt.Errorf("Python tracer not running")
	}

	pt.running = false
	close(pt.stopChan)

	// Close all links
	for _, l := range pt.links {
		l.Close()
	}

	// Close all programs
	for _, prog := range pt.programs {
		prog.Close()
	}

	// Close channels
	close(pt.functionEvents)
	close(pt.gcEvents)

	return nil
}

// findPythonProcesses finds running Python processes
func (pt *PythonTracer) findPythonProcesses() ([]*PythonProcess, error) {
	processes := make([]*PythonProcess, 0)

	// Read /proc to find Python processes
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
		if !pt.isPythonProcess(cmdline) {
			continue
		}

		// Parse Python process information
		process, err := pt.parsePythonProcess(pid, cmdline)
		if err != nil {
			continue
		}

		processes = append(processes, process)
	}

	return processes, nil
}

// isPythonProcess checks if a command line represents a Python process
func (pt *PythonTracer) isPythonProcess(cmdline string) bool {
	for _, target := range pt.config.TargetProcesses {
		if strings.Contains(cmdline, target) {
			return true
		}
	}
	return false
}

// parsePythonProcess parses Python process information
func (pt *PythonTracer) parsePythonProcess(pidStr, cmdline string) (*PythonProcess, error) {
	process := &PythonProcess{
		CommandLine: cmdline,
	}

	// Parse PID
	if n, err := fmt.Sscanf(pidStr, "%d", &process.PID); n != 1 || err != nil {
		return nil, fmt.Errorf("invalid PID: %s", pidStr)
	}

	// Extract main module (simplified)
	parts := strings.Split(cmdline, "\x00")
	for i, part := range parts {
		if strings.Contains(part, "python") && i+1 < len(parts) {
			process.MainModule = parts[i+1]
			break
		}
	}

	return process, nil
}

// loadPrograms loads eBPF programs for Python tracing
func (pt *PythonTracer) loadPrograms() error {
	// This would load actual eBPF programs for Python tracing
	// For now, we'll create placeholder programs
	
	// Function call tracing program
	if pt.config.EnableFunctionTracing {
		// Load function tracing eBPF program
		// This would hook into Python function calls
	}

	// Async/await tracing program
	if pt.config.EnableAsyncTracing {
		// Load async tracing eBPF program
		// This would hook into coroutine creation/suspension
	}

	// GC monitoring program
	if pt.config.EnableGCMonitoring {
		// Load GC monitoring eBPF program
		// This would hook into Python GC events
	}

	return nil
}

// attachToProcess attaches eBPF programs to a Python process
func (pt *PythonTracer) attachToProcess(process *PythonProcess) error {
	// Find Python library
	pythonLib, err := pt.findPythonLibrary(process.PID)
	if err != nil {
		return fmt.Errorf("failed to find Python library: %w", err)
	}

	// Attach uprobe to Python functions
	if pt.config.EnableFunctionTracing {
		if err := pt.attachFunctionTracing(process.PID, pythonLib); err != nil {
			return fmt.Errorf("failed to attach function tracing: %w", err)
		}
	}

	if pt.config.EnableGCMonitoring {
		if err := pt.attachGCMonitoring(process.PID, pythonLib); err != nil {
			return fmt.Errorf("failed to attach GC monitoring: %w", err)
		}
	}

	return nil
}

// findPythonLibrary finds the Python library for a process
func (pt *PythonTracer) findPythonLibrary(pid int) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(mapsData), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libpython") || strings.Contains(line, "python") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				return parts[5], nil
			}
		}
	}

	return "", fmt.Errorf("Python library not found")
}

// attachFunctionTracing attaches function tracing to Python
func (pt *PythonTracer) attachFunctionTracing(pid int, pythonLib string) error {
	// This would attach uprobe to Python function call/return points
	// Implementation would depend on Python interpreter internals
	return nil
}

// attachGCMonitoring attaches GC monitoring to Python
func (pt *PythonTracer) attachGCMonitoring(pid int, pythonLib string) error {
	// This would attach uprobe to Python GC functions
	// Implementation would hook into GC start/end events
	return nil
}

// processFunctionEvents processes function call events
func (pt *PythonTracer) processFunctionEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-pt.stopChan:
			return
		case event := <-pt.functionEvents:
			pt.handleFunctionEvent(event)
		}
	}
}

// processGCEvents processes garbage collection events
func (pt *PythonTracer) processGCEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-pt.stopChan:
			return
		case event := <-pt.gcEvents:
			pt.handleGCEvent(event)
		}
	}
}

// monitorPythonHealth monitors Python interpreter health
func (pt *PythonTracer) monitorPythonHealth(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-pt.stopChan:
			return
		case <-ticker.C:
			pt.collectPythonMetrics()
		}
	}
}

// handleFunctionEvent handles a function call event
func (pt *PythonTracer) handleFunctionEvent(event *FunctionEvent) {
	pt.mutex.Lock()
	defer pt.mutex.Unlock()

	functionKey := fmt.Sprintf("%s.%s", event.FunctionInfo.ModuleName, event.FunctionInfo.FunctionName)
	if function, exists := pt.functionMap[functionKey]; exists {
		function.CallCount++
		function.LastCalled = event.Timestamp
		if event.Duration > 0 {
			function.TotalTime += event.Duration
		}
	}
}

// handleGCEvent handles a garbage collection event
func (pt *PythonTracer) handleGCEvent(event *PythonGCEvent) {
	// Process GC event - update statistics, trigger alerts, etc.
	fmt.Printf("Python GC Event: Generation %d collected %d objects in %v\n", 
		event.Generation, event.Collected, event.Duration)
}

// collectPythonMetrics collects Python interpreter metrics
func (pt *PythonTracer) collectPythonMetrics() {
	// Collect Python metrics like memory usage, thread count, etc.
	// This would integrate with Python monitoring APIs
}

// GetFunctionStats returns function call statistics
func (pt *PythonTracer) GetFunctionStats() map[string]*FunctionInfo {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	stats := make(map[string]*FunctionInfo)
	for k, v := range pt.functionMap {
		stats[k] = v
	}
	return stats
}

// GetModuleInfo returns module information
func (pt *PythonTracer) GetModuleInfo() map[string]*ModuleInfo {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	info := make(map[string]*ModuleInfo)
	for k, v := range pt.moduleMap {
		info[k] = v
	}
	return info
}

// GetCoroutineInfo returns coroutine information
func (pt *PythonTracer) GetCoroutineInfo() map[string]*CoroutineInfo {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()

	info := make(map[string]*CoroutineInfo)
	for k, v := range pt.coroutineMap {
		info[k] = v
	}
	return info
}

// IsRunning returns whether the tracer is running
func (pt *PythonTracer) IsRunning() bool {
	return pt.running
}
