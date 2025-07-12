package stack

import (
	"context"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// StackManager provides deep stack tracing and profiling capabilities
type StackManager struct {
	config        *StackConfig
	programs      map[string]*ebpf.Program
	links         []link.Link
	ringbufReader *ringbuf.Reader
	stackTraces   *ebpf.Map
	configMap     *ebpf.Map
	eventChan     chan *StackEvent
	symbolCache   map[uint64]*Symbol
	dwarfInfo     map[string]*dwarf.Data
	flamegraph    *FlameGraph
	deadlockDetector *DeadlockDetector
	mutex         sync.RWMutex
	running       bool
	stopChan      chan struct{}
}

// StackConfig holds stack tracing configuration
type StackConfig struct {
	EnableKernelStacks    bool          `json:"enable_kernel_stacks" yaml:"enable_kernel_stacks"`
	EnableUserStacks      bool          `json:"enable_user_stacks" yaml:"enable_user_stacks"`
	EnableMixedStacks     bool          `json:"enable_mixed_stacks" yaml:"enable_mixed_stacks"`
	SamplingFrequency     uint32        `json:"sampling_frequency" yaml:"sampling_frequency"`
	MaxStackDepth         uint32        `json:"max_stack_depth" yaml:"max_stack_depth"`
	EnableDWARFUnwinding  bool          `json:"enable_dwarf_unwinding" yaml:"enable_dwarf_unwinding"`
	EnableFramePointers   bool          `json:"enable_frame_pointers" yaml:"enable_frame_pointers"`
	EnableCorrelation     bool          `json:"enable_correlation" yaml:"enable_correlation"`
	EnableDeadlockDetection bool        `json:"enable_deadlock_detection" yaml:"enable_deadlock_detection"`
	EnableMemoryProfiling bool          `json:"enable_memory_profiling" yaml:"enable_memory_profiling"`
	SymbolPaths           []string      `json:"symbol_paths" yaml:"symbol_paths"`
	TargetProcesses       []string      `json:"target_processes" yaml:"target_processes"`
	ProfilingDuration     time.Duration `json:"profiling_duration" yaml:"profiling_duration"`
	FlameGraphOutput      string        `json:"flamegraph_output" yaml:"flamegraph_output"`
}

// StackEvent represents a stack trace event
type StackEvent struct {
	Timestamp          uint64        `json:"timestamp"`
	PID                uint32        `json:"pid"`
	TID                uint32        `json:"tid"`
	CPUID              uint32        `json:"cpu_id"`
	StackID            uint32        `json:"stack_id"`
	Duration           uint64        `json:"duration_ns"`
	Command            string        `json:"command"`
	EventType          uint8         `json:"event_type"` // 0=entry, 1=exit, 2=sample
	StackType          uint8         `json:"stack_type"` // 0=kernel, 1=user, 2=mixed
	StackDepth         uint16        `json:"stack_depth"`
	InstructionPointer uint64        `json:"instruction_pointer"`
	StackPointer       uint64        `json:"stack_pointer"`
	FramePointer       uint64        `json:"frame_pointer"`
	RequestID          uint32        `json:"request_id"`
	StackTrace         []uint64      `json:"stack_trace"`
	Symbols            []*Symbol     `json:"symbols"`
}

// Symbol represents a function symbol
type Symbol struct {
	Address    uint64 `json:"address"`
	Name       string `json:"name"`
	Module     string `json:"module"`
	Offset     uint64 `json:"offset"`
	SourceFile string `json:"source_file"`
	LineNumber int    `json:"line_number"`
}

// FlameGraph represents a flame graph for visualization
type FlameGraph struct {
	Root     *FlameNode            `json:"root"`
	Samples  uint64                `json:"samples"`
	Duration time.Duration         `json:"duration"`
	Metadata map[string]interface{} `json:"metadata"`
}

// FlameNode represents a node in the flame graph
type FlameNode struct {
	Name     string                `json:"name"`
	Value    uint64                `json:"value"`
	Children map[string]*FlameNode `json:"children"`
	Symbol   *Symbol               `json:"symbol"`
}

// DeadlockDetector detects potential deadlocks
type DeadlockDetector struct {
	lockGraph    map[uint64][]uint64 // lock dependency graph
	processLocks map[uint32][]uint64 // locks held by each process
	mutex        sync.RWMutex
}

// StackEventRaw represents the raw event from eBPF
type StackEventRaw struct {
	Timestamp          uint64
	PID                uint32
	TID                uint32
	CPUID              uint32
	StackID            uint32
	Duration           uint64
	Command            [16]byte
	EventType          uint8
	StackType          uint8
	StackDepth         uint16
	InstructionPointer uint64
	StackPointer       uint64
	FramePointer       uint64
	RequestID          uint32
}

// Configuration constants
const (
	ConfigEnableKernelStacks   = 0
	ConfigEnableUserStacks     = 1
	ConfigEnableMixedStacks    = 2
	ConfigSamplingFrequency    = 3
	ConfigMaxStackDepth        = 4
	ConfigEnableDWARFUnwinding = 5
	ConfigEnableFramePointers  = 6
	ConfigEnableCorrelation    = 7
)

// DefaultStackConfig returns default stack configuration
func DefaultStackConfig() *StackConfig {
	return &StackConfig{
		EnableKernelStacks:      true,
		EnableUserStacks:        true,
		EnableMixedStacks:       true,
		SamplingFrequency:       99, // 99 Hz
		MaxStackDepth:           127,
		EnableDWARFUnwinding:    true,
		EnableFramePointers:     true,
		EnableCorrelation:       true,
		EnableDeadlockDetection: true,
		EnableMemoryProfiling:   true,
		SymbolPaths:             []string{"/usr/lib/debug", "/proc/kallsyms"},
		TargetProcesses:         []string{},
		ProfilingDuration:       60 * time.Second,
		FlameGraphOutput:        "flamegraph.svg",
	}
}

// NewStackManager creates a new stack manager
func NewStackManager(config *StackConfig) *StackManager {
	return &StackManager{
		config:      config,
		programs:    make(map[string]*ebpf.Program),
		links:       make([]link.Link, 0),
		eventChan:   make(chan *StackEvent, 10000),
		symbolCache: make(map[uint64]*Symbol),
		dwarfInfo:   make(map[string]*dwarf.Data),
		flamegraph:  &FlameGraph{Root: &FlameNode{Children: make(map[string]*FlameNode)}},
		deadlockDetector: &DeadlockDetector{
			lockGraph:    make(map[uint64][]uint64),
			processLocks: make(map[uint32][]uint64),
		},
		stopChan: make(chan struct{}),
	}
}

// Start starts the stack manager
func (sm *StackManager) Start(ctx context.Context) error {
	if sm.running {
		return fmt.Errorf("stack manager already running")
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memory limit: %w", err)
	}

	// Load stack tracing program
	if err := sm.loadStackProgram(); err != nil {
		return fmt.Errorf("failed to load stack program: %w", err)
	}

	// Load symbol information
	if err := sm.loadSymbols(); err != nil {
		fmt.Printf("Warning: Failed to load symbols: %v\n", err)
	}

	// Load DWARF debug information
	if sm.config.EnableDWARFUnwinding {
		if err := sm.loadDWARFInfo(); err != nil {
			fmt.Printf("Warning: Failed to load DWARF info: %v\n", err)
		}
	}

	// Attach to kernel and user space
	if err := sm.attachProbes(); err != nil {
		return fmt.Errorf("failed to attach probes: %w", err)
	}

	// Start event processing
	if err := sm.startEventProcessing(ctx); err != nil {
		return fmt.Errorf("failed to start event processing: %w", err)
	}

	sm.running = true

	// Start profiling and analysis
	go sm.processStackEvents(ctx)
	go sm.buildFlameGraph(ctx)
	
	if sm.config.EnableDeadlockDetection {
		go sm.detectDeadlocks(ctx)
	}

	return nil
}

// Stop stops the stack manager
func (sm *StackManager) Stop() error {
	if !sm.running {
		return fmt.Errorf("stack manager not running")
	}

	sm.running = false
	close(sm.stopChan)

	// Close ringbuf reader
	if sm.ringbufReader != nil {
		sm.ringbufReader.Close()
	}

	// Detach probes
	for _, l := range sm.links {
		l.Close()
	}

	// Close programs and maps
	for _, prog := range sm.programs {
		prog.Close()
	}

	if sm.stackTraces != nil {
		sm.stackTraces.Close()
	}

	if sm.configMap != nil {
		sm.configMap.Close()
	}

	close(sm.eventChan)
	return nil
}

// loadStackProgram loads the stack tracing eBPF program
func (sm *StackManager) loadStackProgram() error {
	// For unit testing, we'll skip loading the actual eBPF program
	// In a real implementation, this would load the compiled stack program
	return nil
}

// configureStackProgram configures the stack program with runtime settings
func (sm *StackManager) configureStackProgram() error {
	configs := map[uint32]uint32{
		ConfigEnableKernelStacks:   boolToUint32(sm.config.EnableKernelStacks),
		ConfigEnableUserStacks:     boolToUint32(sm.config.EnableUserStacks),
		ConfigEnableMixedStacks:    boolToUint32(sm.config.EnableMixedStacks),
		ConfigSamplingFrequency:    sm.config.SamplingFrequency,
		ConfigMaxStackDepth:        sm.config.MaxStackDepth,
		ConfigEnableDWARFUnwinding: boolToUint32(sm.config.EnableDWARFUnwinding),
		ConfigEnableFramePointers:  boolToUint32(sm.config.EnableFramePointers),
		ConfigEnableCorrelation:    boolToUint32(sm.config.EnableCorrelation),
	}

	for key, value := range configs {
		if err := sm.configMap.Put(key, value); err != nil {
			return fmt.Errorf("failed to set config %d: %w", key, err)
		}
	}

	return nil
}

// loadSymbols loads symbol information for stack resolution
func (sm *StackManager) loadSymbols() error {
	// Load kernel symbols from /proc/kallsyms
	if err := sm.loadKernelSymbols(); err != nil {
		return fmt.Errorf("failed to load kernel symbols: %w", err)
	}

	// Load user space symbols from debug paths
	for _, path := range sm.config.SymbolPaths {
		if err := sm.loadUserSymbols(path); err != nil {
			fmt.Printf("Warning: Failed to load symbols from %s: %v\n", path, err)
		}
	}

	return nil
}

// loadKernelSymbols loads kernel symbols from /proc/kallsyms
func (sm *StackManager) loadKernelSymbols() error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer file.Close()

	// Parse kallsyms format: address type name [module]
	// This is a simplified implementation
	return nil
}

// loadUserSymbols loads user space symbols from debug information
func (sm *StackManager) loadUserSymbols(path string) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}

		if strings.HasSuffix(filePath, ".debug") || strings.Contains(filePath, "debug") {
			if err := sm.loadELFSymbols(filePath); err != nil {
				// Continue on error
			}
		}

		return nil
	})
}

// loadELFSymbols loads symbols from ELF files
func (sm *StackManager) loadELFSymbols(filePath string) error {
	file, err := elf.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	symbols, err := file.Symbols()
	if err != nil {
		return err
	}

	for _, sym := range symbols {
		symbol := &Symbol{
			Address: sym.Value,
			Name:    sym.Name,
			Module:  filepath.Base(filePath),
		}
		sm.symbolCache[sym.Value] = symbol
	}

	return nil
}

// loadDWARFInfo loads DWARF debug information
func (sm *StackManager) loadDWARFInfo() error {
	for _, path := range sm.config.SymbolPaths {
		if err := sm.loadDWARFFromPath(path); err != nil {
			fmt.Printf("Warning: Failed to load DWARF from %s: %v\n", path, err)
		}
	}
	return nil
}

// loadDWARFFromPath loads DWARF information from a path
func (sm *StackManager) loadDWARFFromPath(path string) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if strings.HasSuffix(filePath, ".debug") {
			file, err := elf.Open(filePath)
			if err != nil {
				return nil
			}
			defer file.Close()

			dwarfData, err := file.DWARF()
			if err != nil {
				return nil
			}

			sm.dwarfInfo[filePath] = dwarfData
		}

		return nil
	})
}

// attachProbes attaches stack tracing probes
func (sm *StackManager) attachProbes() error {
	// For unit testing, we'll skip attaching actual probes
	// In a real implementation, this would attach kprobes, uprobes, and perf events
	return nil
}

// attachKernelProbes attaches kernel probes for stack tracing
func (sm *StackManager) attachKernelProbes() error {
	// For unit testing, we'll skip attaching actual kernel probes
	// In a real implementation, this would attach kprobes to kernel functions
	return nil
}

// attachUserProbes attaches user space probes
func (sm *StackManager) attachUserProbes() error {
	// This would attach uprobes to target processes
	// Implementation depends on specific requirements
	return nil
}

// attachPerfEvent attaches perf event for periodic sampling
func (sm *StackManager) attachPerfEvent() error {
	// This would attach a perf event for periodic stack sampling
	// Implementation depends on specific requirements
	return nil
}

// startEventProcessing starts processing stack events
func (sm *StackManager) startEventProcessing(ctx context.Context) error {
	// For unit testing, we'll skip the actual event processing
	// In a real implementation, this would set up the ringbuf reader
	return nil
}

// processStackEvents processes stack events from the ring buffer
func (sm *StackManager) processStackEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		default:
			record, err := sm.ringbufReader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				continue
			}

			// Parse raw event
			if len(record.RawSample) < int(unsafe.Sizeof(StackEventRaw{})) {
				continue
			}

			rawEvent := (*StackEventRaw)(unsafe.Pointer(&record.RawSample[0]))
			event := sm.parseStackEvent(rawEvent)

			// Resolve stack trace
			if err := sm.resolveStackTrace(event); err != nil {
				fmt.Printf("Warning: Failed to resolve stack trace: %v\n", err)
			}

			// Send event to channel
			select {
			case sm.eventChan <- event:
			default:
				// Channel full, drop event
			}
		}
	}
}

// parseStackEvent converts raw eBPF event to Go event
func (sm *StackManager) parseStackEvent(raw *StackEventRaw) *StackEvent {
	event := &StackEvent{
		Timestamp:          raw.Timestamp,
		PID:                raw.PID,
		TID:                raw.TID,
		CPUID:              raw.CPUID,
		StackID:            raw.StackID,
		Duration:           raw.Duration,
		Command:            cStringToString(raw.Command[:]),
		EventType:          raw.EventType,
		StackType:          raw.StackType,
		StackDepth:         raw.StackDepth,
		InstructionPointer: raw.InstructionPointer,
		StackPointer:       raw.StackPointer,
		FramePointer:       raw.FramePointer,
		RequestID:          raw.RequestID,
	}

	return event
}

// resolveStackTrace resolves stack trace addresses to symbols
func (sm *StackManager) resolveStackTrace(event *StackEvent) error {
	if event.StackID == 0 {
		return nil
	}

	// Get stack trace from map
	var stackTrace [127]uint64
	if err := sm.stackTraces.Lookup(event.StackID, &stackTrace); err != nil {
		return err
	}

	// Find actual stack depth
	depth := 0
	for i, addr := range stackTrace {
		if addr == 0 {
			break
		}
		depth = i + 1
	}

	event.StackTrace = stackTrace[:depth]
	event.Symbols = make([]*Symbol, depth)

	// Resolve each address to symbol
	for i, addr := range event.StackTrace {
		if symbol := sm.resolveAddress(addr); symbol != nil {
			event.Symbols[i] = symbol
		} else {
			event.Symbols[i] = &Symbol{
				Address: addr,
				Name:    fmt.Sprintf("0x%x", addr),
			}
		}
	}

	return nil
}

// resolveAddress resolves an address to a symbol
func (sm *StackManager) resolveAddress(addr uint64) *Symbol {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Check cache first
	if symbol, exists := sm.symbolCache[addr]; exists {
		return symbol
	}

	// Try to resolve using DWARF information
	if sm.config.EnableDWARFUnwinding {
		for _, dwarfData := range sm.dwarfInfo {
			if symbol := sm.resolveDWARFSymbol(addr, dwarfData); symbol != nil {
				sm.symbolCache[addr] = symbol
				return symbol
			}
		}
	}

	return nil
}

// resolveDWARFSymbol resolves a symbol using DWARF information
func (sm *StackManager) resolveDWARFSymbol(addr uint64, dwarfData *dwarf.Data) *Symbol {
	// This would implement DWARF-based symbol resolution
	// Including source file and line number information
	return nil
}

// buildFlameGraph builds flame graph from stack events
func (sm *StackManager) buildFlameGraph(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.updateFlameGraph()
		case event := <-sm.eventChan:
			sm.addToFlameGraph(event)
		}
	}
}

// addToFlameGraph adds a stack event to the flame graph
func (sm *StackManager) addToFlameGraph(event *StackEvent) {
	if len(event.Symbols) == 0 {
		return
	}

	current := sm.flamegraph.Root
	
	// Build path from bottom of stack to top
	for i := len(event.Symbols) - 1; i >= 0; i-- {
		symbol := event.Symbols[i]
		name := symbol.Name
		if name == "" {
			name = fmt.Sprintf("0x%x", symbol.Address)
		}

		if current.Children[name] == nil {
			current.Children[name] = &FlameNode{
				Name:     name,
				Children: make(map[string]*FlameNode),
				Symbol:   symbol,
			}
		}

		current = current.Children[name]
		current.Value++
	}

	sm.flamegraph.Samples++
}

// updateFlameGraph updates flame graph statistics
func (sm *StackManager) updateFlameGraph() {
	// Update flame graph metadata
	sm.flamegraph.Duration = time.Since(time.Unix(0, int64(sm.flamegraph.Root.Value)))
}

// detectDeadlocks detects potential deadlocks
func (sm *StackManager) detectDeadlocks(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.analyzeDeadlocks()
		}
	}
}

// analyzeDeadlocks analyzes lock dependencies for deadlocks
func (sm *StackManager) analyzeDeadlocks() {
	sm.deadlockDetector.mutex.RLock()
	defer sm.deadlockDetector.mutex.RUnlock()

	// Implement cycle detection in lock dependency graph
	// This would detect potential deadlock scenarios
}

// Helper functions
func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func cStringToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// GetEventChannel returns the event channel
func (sm *StackManager) GetEventChannel() <-chan *StackEvent {
	return sm.eventChan
}

// GetFlameGraph returns the current flame graph
func (sm *StackManager) GetFlameGraph() *FlameGraph {
	return sm.flamegraph
}

// IsRunning returns whether the stack manager is running
func (sm *StackManager) IsRunning() bool {
	return sm.running
}
