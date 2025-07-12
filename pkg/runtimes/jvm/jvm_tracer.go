package jvm

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

// JVMTracer provides deep integration with JVM runtime
type JVMTracer struct {
	config       *JVMConfig
	programs     map[string]*ebpf.Program
	links        []link.Link
	methodMap    map[string]*MethodInfo
	classMap     map[string]*ClassInfo
	threadMap    map[int]*ThreadInfo
	gcEvents     chan *GCEvent
	methodEvents chan *MethodEvent
	mutex        sync.RWMutex
	running      bool
	stopChan     chan struct{}
}

// JVMConfig holds JVM tracer configuration
type JVMConfig struct {
	EnableMethodTracing    bool     `json:"enable_method_tracing" yaml:"enable_method_tracing"`
	EnableGCMonitoring     bool     `json:"enable_gc_monitoring" yaml:"enable_gc_monitoring"`
	EnableThreadTracking   bool     `json:"enable_thread_tracking" yaml:"enable_thread_tracking"`
	EnableClassLoading     bool     `json:"enable_class_loading" yaml:"enable_class_loading"`
	EnableHeapAnalysis     bool     `json:"enable_heap_analysis" yaml:"enable_heap_analysis"`
	JVMPaths               []string `json:"jvm_paths" yaml:"jvm_paths"`
	TargetProcesses        []string `json:"target_processes" yaml:"target_processes"`
	MethodFilters          []string `json:"method_filters" yaml:"method_filters"`
	ClassFilters           []string `json:"class_filters" yaml:"class_filters"`
	SamplingRate           float64  `json:"sampling_rate" yaml:"sampling_rate"`
	MaxMethodsTracked      int      `json:"max_methods_tracked" yaml:"max_methods_tracked"`
	MaxClassesTracked      int      `json:"max_classes_tracked" yaml:"max_classes_tracked"`
	GCEventBufferSize      int      `json:"gc_event_buffer_size" yaml:"gc_event_buffer_size"`
	MethodEventBufferSize  int      `json:"method_event_buffer_size" yaml:"method_event_buffer_size"`
}

// MethodInfo holds information about a JVM method
type MethodInfo struct {
	ClassName    string            `json:"class_name"`
	MethodName   string            `json:"method_name"`
	Signature    string            `json:"signature"`
	Address      uint64            `json:"address"`
	Size         uint32            `json:"size"`
	IsNative     bool              `json:"is_native"`
	IsStatic     bool              `json:"is_static"`
	AccessFlags  uint16            `json:"access_flags"`
	LineNumbers  map[int]int       `json:"line_numbers"`
	LocalVars    []LocalVariable   `json:"local_vars"`
	Metadata     map[string]string `json:"metadata"`
	CallCount    uint64            `json:"call_count"`
	TotalTime    time.Duration     `json:"total_time"`
	LastCalled   time.Time         `json:"last_called"`
}

// ClassInfo holds information about a JVM class
type ClassInfo struct {
	ClassName     string            `json:"class_name"`
	SuperClass    string            `json:"super_class"`
	Interfaces    []string          `json:"interfaces"`
	Methods       []string          `json:"methods"`
	Fields        []FieldInfo       `json:"fields"`
	LoadTime      time.Time         `json:"load_time"`
	ClassLoader   string            `json:"class_loader"`
	SourceFile    string            `json:"source_file"`
	AccessFlags   uint16            `json:"access_flags"`
	ConstantPool  []ConstantInfo    `json:"constant_pool"`
	Metadata      map[string]string `json:"metadata"`
}

// ThreadInfo holds information about a JVM thread
type ThreadInfo struct {
	ThreadID      int               `json:"thread_id"`
	ThreadName    string            `json:"thread_name"`
	ThreadGroup   string            `json:"thread_group"`
	State         string            `json:"state"`
	Priority      int               `json:"priority"`
	IsDaemon      bool              `json:"is_daemon"`
	StackTrace    []StackFrame      `json:"stack_trace"`
	CreationTime  time.Time         `json:"creation_time"`
	CPUTime       time.Duration     `json:"cpu_time"`
	BlockedTime   time.Duration     `json:"blocked_time"`
	WaitedTime    time.Duration     `json:"waited_time"`
	Metadata      map[string]string `json:"metadata"`
}

// GCEvent represents a garbage collection event
type GCEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	GCType        string            `json:"gc_type"`
	Generation    string            `json:"generation"`
	Cause         string            `json:"cause"`
	Duration      time.Duration     `json:"duration"`
	BeforeSize    uint64            `json:"before_size"`
	AfterSize     uint64            `json:"after_size"`
	TotalSize     uint64            `json:"total_size"`
	Collections   uint64            `json:"collections"`
	Metadata      map[string]string `json:"metadata"`
}

// MethodEvent represents a method call event
type MethodEvent struct {
	Timestamp     time.Time         `json:"timestamp"`
	ThreadID      int               `json:"thread_id"`
	MethodInfo    *MethodInfo       `json:"method_info"`
	EventType     string            `json:"event_type"` // "entry", "exit", "exception"
	Arguments     []interface{}     `json:"arguments"`
	ReturnValue   interface{}       `json:"return_value"`
	Exception     *ExceptionInfo    `json:"exception"`
	Duration      time.Duration     `json:"duration"`
	StackDepth    int               `json:"stack_depth"`
	Metadata      map[string]string `json:"metadata"`
}

// LocalVariable represents a local variable in a method
type LocalVariable struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Slot      int    `json:"slot"`
	StartPC   int    `json:"start_pc"`
	Length    int    `json:"length"`
}

// FieldInfo represents a class field
type FieldInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	AccessFlags uint16 `json:"access_flags"`
	IsStatic    bool   `json:"is_static"`
	IsFinal     bool   `json:"is_final"`
}

// ConstantInfo represents a constant pool entry
type ConstantInfo struct {
	Tag   uint8       `json:"tag"`
	Value interface{} `json:"value"`
}

// StackFrame represents a stack frame
type StackFrame struct {
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name"`
	FileName   string `json:"file_name"`
	LineNumber int    `json:"line_number"`
}

// ExceptionInfo represents exception information
type ExceptionInfo struct {
	ClassName   string       `json:"class_name"`
	Message     string       `json:"message"`
	StackTrace  []StackFrame `json:"stack_trace"`
}

// DefaultJVMConfig returns default JVM tracer configuration
func DefaultJVMConfig() *JVMConfig {
	return &JVMConfig{
		EnableMethodTracing:   true,
		EnableGCMonitoring:    true,
		EnableThreadTracking:  true,
		EnableClassLoading:    true,
		EnableHeapAnalysis:    false, // Disabled by default due to overhead
		JVMPaths: []string{
			"/usr/lib/jvm/*/lib/server/libjvm.so",
			"/usr/lib/jvm/*/jre/lib/*/server/libjvm.so",
			"/opt/java/*/lib/server/libjvm.so",
		},
		TargetProcesses: []string{"java", "javac", "gradle", "maven"},
		MethodFilters: []string{
			"java.lang.*",
			"java.util.*",
			"java.io.*",
			"java.net.*",
		},
		ClassFilters: []string{
			"java.*",
			"javax.*",
			"sun.*",
			"com.sun.*",
		},
		SamplingRate:          1.0, // 100% sampling by default
		MaxMethodsTracked:     10000,
		MaxClassesTracked:     5000,
		GCEventBufferSize:     1000,
		MethodEventBufferSize: 10000,
	}
}

// NewJVMTracer creates a new JVM tracer
func NewJVMTracer(config *JVMConfig) *JVMTracer {
	return &JVMTracer{
		config:       config,
		programs:     make(map[string]*ebpf.Program),
		links:        make([]link.Link, 0),
		methodMap:    make(map[string]*MethodInfo),
		classMap:     make(map[string]*ClassInfo),
		threadMap:    make(map[int]*ThreadInfo),
		gcEvents:     make(chan *GCEvent, config.GCEventBufferSize),
		methodEvents: make(chan *MethodEvent, config.MethodEventBufferSize),
		stopChan:     make(chan struct{}),
	}
}

// Start starts the JVM tracer
func (jt *JVMTracer) Start(ctx context.Context) error {
	if jt.running {
		return fmt.Errorf("JVM tracer already running")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memory limit: %w", err)
	}

	// Find JVM processes and libraries
	jvmProcesses, err := jt.findJVMProcesses()
	if err != nil {
		return fmt.Errorf("failed to find JVM processes: %w", err)
	}

	if len(jvmProcesses) == 0 {
		return fmt.Errorf("no JVM processes found")
	}

	// Load eBPF programs
	if err := jt.loadPrograms(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Attach to JVM processes
	for _, process := range jvmProcesses {
		if err := jt.attachToProcess(process); err != nil {
			fmt.Printf("Warning: failed to attach to process %d: %v\n", process.PID, err)
			continue
		}
	}

	jt.running = true

	// Start event processing goroutines
	go jt.processGCEvents(ctx)
	go jt.processMethodEvents(ctx)
	go jt.monitorJVMHealth(ctx)

	return nil
}

// Stop stops the JVM tracer
func (jt *JVMTracer) Stop() error {
	if !jt.running {
		return fmt.Errorf("JVM tracer not running")
	}

	jt.running = false
	close(jt.stopChan)

	// Close all links
	for _, l := range jt.links {
		l.Close()
	}

	// Close all programs
	for _, prog := range jt.programs {
		prog.Close()
	}

	// Close channels
	close(jt.gcEvents)
	close(jt.methodEvents)

	return nil
}

// JVMProcess represents a JVM process
type JVMProcess struct {
	PID         int    `json:"pid"`
	CommandLine string `json:"command_line"`
	JVMPath     string `json:"jvm_path"`
	MainClass   string `json:"main_class"`
	JVMArgs     string `json:"jvm_args"`
}

// findJVMProcesses finds running JVM processes
func (jt *JVMTracer) findJVMProcesses() ([]*JVMProcess, error) {
	processes := make([]*JVMProcess, 0)

	// Read /proc to find Java processes
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
		if !jt.isJVMProcess(cmdline) {
			continue
		}

		// Parse JVM process information
		process, err := jt.parseJVMProcess(pid, cmdline)
		if err != nil {
			continue
		}

		processes = append(processes, process)
	}

	return processes, nil
}

// isJVMProcess checks if a command line represents a JVM process
func (jt *JVMTracer) isJVMProcess(cmdline string) bool {
	for _, target := range jt.config.TargetProcesses {
		if strings.Contains(cmdline, target) {
			return true
		}
	}
	return false
}

// parseJVMProcess parses JVM process information
func (jt *JVMTracer) parseJVMProcess(pidStr, cmdline string) (*JVMProcess, error) {
	// This is a simplified implementation
	// In practice, you would parse the full JVM command line
	process := &JVMProcess{
		CommandLine: cmdline,
	}

	// Parse PID
	if n, err := fmt.Sscanf(pidStr, "%d", &process.PID); n != 1 || err != nil {
		return nil, fmt.Errorf("invalid PID: %s", pidStr)
	}

	// Extract main class (simplified)
	parts := strings.Split(cmdline, "\x00")
	for i, part := range parts {
		if strings.Contains(part, "java") && i+1 < len(parts) {
			process.MainClass = parts[i+1]
			break
		}
	}

	return process, nil
}

// loadPrograms loads eBPF programs for JVM tracing
func (jt *JVMTracer) loadPrograms() error {
	// This would load actual eBPF programs for JVM tracing
	// For now, we'll create placeholder programs
	
	// Method entry/exit tracing program
	if jt.config.EnableMethodTracing {
		// Load method tracing eBPF program
		// This would be implemented with actual eBPF bytecode
	}

	// GC monitoring program
	if jt.config.EnableGCMonitoring {
		// Load GC monitoring eBPF program
		// This would hook into JVM GC events
	}

	// Thread tracking program
	if jt.config.EnableThreadTracking {
		// Load thread tracking eBPF program
		// This would monitor thread creation/destruction
	}

	return nil
}

// attachToProcess attaches eBPF programs to a JVM process
func (jt *JVMTracer) attachToProcess(process *JVMProcess) error {
	// Find JVM library
	jvmLib, err := jt.findJVMLibrary(process.PID)
	if err != nil {
		return fmt.Errorf("failed to find JVM library: %w", err)
	}

	// Attach uprobe to JVM functions
	if jt.config.EnableMethodTracing {
		if err := jt.attachMethodTracing(process.PID, jvmLib); err != nil {
			return fmt.Errorf("failed to attach method tracing: %w", err)
		}
	}

	if jt.config.EnableGCMonitoring {
		if err := jt.attachGCMonitoring(process.PID, jvmLib); err != nil {
			return fmt.Errorf("failed to attach GC monitoring: %w", err)
		}
	}

	return nil
}

// findJVMLibrary finds the JVM library for a process
func (jt *JVMTracer) findJVMLibrary(pid int) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(mapsData), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libjvm.so") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				return parts[5], nil
			}
		}
	}

	return "", fmt.Errorf("JVM library not found")
}

// attachMethodTracing attaches method tracing to JVM
func (jt *JVMTracer) attachMethodTracing(pid int, jvmLib string) error {
	// This would attach uprobe to JVM method entry/exit points
	// Implementation would depend on JVM internals and JVMTI
	return nil
}

// attachGCMonitoring attaches GC monitoring to JVM
func (jt *JVMTracer) attachGCMonitoring(pid int, jvmLib string) error {
	// This would attach uprobe to JVM GC functions
	// Implementation would hook into GC start/end events
	return nil
}

// processGCEvents processes garbage collection events
func (jt *JVMTracer) processGCEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-jt.stopChan:
			return
		case event := <-jt.gcEvents:
			jt.handleGCEvent(event)
		}
	}
}

// processMethodEvents processes method call events
func (jt *JVMTracer) processMethodEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-jt.stopChan:
			return
		case event := <-jt.methodEvents:
			jt.handleMethodEvent(event)
		}
	}
}

// monitorJVMHealth monitors JVM health and performance
func (jt *JVMTracer) monitorJVMHealth(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-jt.stopChan:
			return
		case <-ticker.C:
			jt.collectJVMMetrics()
		}
	}
}

// handleGCEvent handles a garbage collection event
func (jt *JVMTracer) handleGCEvent(event *GCEvent) {
	// Process GC event - update statistics, trigger alerts, etc.
	fmt.Printf("GC Event: %s %s took %v\n", event.GCType, event.Generation, event.Duration)
}

// handleMethodEvent handles a method call event
func (jt *JVMTracer) handleMethodEvent(event *MethodEvent) {
	// Process method event - update call counts, latency stats, etc.
	jt.mutex.Lock()
	defer jt.mutex.Unlock()

	methodKey := fmt.Sprintf("%s.%s", event.MethodInfo.ClassName, event.MethodInfo.MethodName)
	if method, exists := jt.methodMap[methodKey]; exists {
		method.CallCount++
		method.LastCalled = event.Timestamp
		if event.Duration > 0 {
			method.TotalTime += event.Duration
		}
	}
}

// collectJVMMetrics collects JVM performance metrics
func (jt *JVMTracer) collectJVMMetrics() {
	// Collect JVM metrics like heap usage, thread count, etc.
	// This would integrate with JVM monitoring APIs
}

// GetMethodStats returns method call statistics
func (jt *JVMTracer) GetMethodStats() map[string]*MethodInfo {
	jt.mutex.RLock()
	defer jt.mutex.RUnlock()

	stats := make(map[string]*MethodInfo)
	for k, v := range jt.methodMap {
		stats[k] = v
	}
	return stats
}

// GetClassInfo returns class information
func (jt *JVMTracer) GetClassInfo() map[string]*ClassInfo {
	jt.mutex.RLock()
	defer jt.mutex.RUnlock()

	info := make(map[string]*ClassInfo)
	for k, v := range jt.classMap {
		info[k] = v
	}
	return info
}

// GetThreadInfo returns thread information
func (jt *JVMTracer) GetThreadInfo() map[int]*ThreadInfo {
	jt.mutex.RLock()
	defer jt.mutex.RUnlock()

	info := make(map[int]*ThreadInfo)
	for k, v := range jt.threadMap {
		info[k] = v
	}
	return info
}

// IsRunning returns whether the tracer is running
func (jt *JVMTracer) IsRunning() bool {
	return jt.running
}
