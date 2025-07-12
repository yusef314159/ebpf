package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-tracing/config"
)

// TraceContext represents distributed tracing context
type TraceContext struct {
	TraceIDHigh   uint64   `json:"trace_id_high"`
	TraceIDLow    uint64   `json:"trace_id_low"`
	SpanID        uint64   `json:"span_id"`
	ParentSpanID  uint64   `json:"parent_span_id"`
	TraceFlags    uint8    `json:"trace_flags"`
	TraceStateLen uint8    `json:"trace_state_len"`
	TraceState    [64]byte `json:"-"`
}

// Event structure matching the HTTP tracer C struct
type Event struct {
	Timestamp       uint64       `json:"timestamp"`
	RequestID       uint64       `json:"request_id"`
	PID             uint32       `json:"pid"`
	TID             uint32       `json:"tid"`
	SrcIP           uint32       `json:"src_ip"`
	DstIP           uint32       `json:"dst_ip"`
	SrcPort         uint16       `json:"src_port"`
	DstPort         uint16       `json:"dst_port"`
	Comm            [16]byte     `json:"-"`
	Method          [8]byte      `json:"-"`
	Path            [128]byte    `json:"-"`
	PayloadLen      uint32       `json:"payload_len"`
	Payload         [256]byte    `json:"-"`
	EventType       uint8        `json:"event_type"`
	Protocol        uint8        `json:"protocol"`
	TraceCtx        TraceContext `json:"-"`
	ServiceID       uint32       `json:"service_id"`
	CorrelationType uint8        `json:"correlation_type"`
	HopCount        uint8        `json:"hop_count"`
	Reserved        uint16       `json:"-"`
}

// StackEventRaw represents the raw stack event from eBPF (matching C struct)
type StackEventRaw struct {
	Timestamp          uint64
	Duration           uint64
	PID                uint32
	TID                uint32
	CPUID              uint32
	Comm               [16]byte
	StackID            uint32
	StackDepth         uint16
	EventType          uint8
	StackType          uint8
	InstructionPointer uint64
	StackPointer       uint64
	FramePointer       uint64
	RequestID          uint32
}

// JSON-friendly trace context
type JSONTraceContext struct {
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id,omitempty"`
	TraceFlags   uint8  `json:"trace_flags"`
	TraceState   string `json:"trace_state,omitempty"`
}

// JSON-friendly event structure with distributed tracing
type JSONEvent struct {
	Timestamp       string            `json:"timestamp"`
	RequestID       uint64            `json:"request_id,omitempty"`
	PID             uint32            `json:"pid"`
	TID             uint32            `json:"tid"`
	SrcIP           string            `json:"src_ip"`
	DstIP           string            `json:"dst_ip"`
	SrcPort         uint16            `json:"src_port"`
	DstPort         uint16            `json:"dst_port"`
	Comm            string            `json:"comm"`
	Method          string            `json:"method,omitempty"`
	Path            string            `json:"path,omitempty"`
	PayloadLen      uint32            `json:"payload_len"`
	Payload         string            `json:"payload,omitempty"`
	EventType       string            `json:"event_type"`
	EventTypeID     uint8             `json:"event_type_id"`
	Protocol        string            `json:"protocol,omitempty"`

	// Distributed tracing fields
	TraceContext    JSONTraceContext  `json:"trace_context,omitempty"`
	ServiceID       uint32            `json:"service_id,omitempty"`
	ServiceName     string            `json:"service_name,omitempty"`
	CorrelationType string            `json:"correlation_type,omitempty"`
	HopCount        uint8             `json:"hop_count,omitempty"`

	// Stack tracer specific fields
	TracerType         string `json:"tracer_type,omitempty"`
	StackID            uint32 `json:"stack_id,omitempty"`
	StackDepth         uint16 `json:"stack_depth,omitempty"`
	StackType          uint8  `json:"stack_type,omitempty"`
	Duration           uint64 `json:"duration_ns,omitempty"`
	InstructionPointer uint64 `json:"instruction_pointer,omitempty"`
	StackPointer       uint64 `json:"stack_pointer,omitempty"`
	FramePointer       uint64 `json:"frame_pointer,omitempty"`
	CPUID              uint32 `json:"cpu_id,omitempty"`
}

// processStackEvent processes a stack tracer event
func processStackEvent(rawSample []byte) (JSONEvent, error) {
	if len(rawSample) < int(unsafe.Sizeof(StackEventRaw{})) {
		return JSONEvent{}, fmt.Errorf("insufficient data for stack event")
	}

	var stackEvent StackEventRaw
	err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &stackEvent)
	if err != nil {
		return JSONEvent{}, fmt.Errorf("failed to parse stack event: %w", err)
	}

	// Convert to JSON-friendly format
	jsonEvent := JSONEvent{
		Timestamp:   time.Unix(0, int64(stackEvent.Timestamp)).Format(time.RFC3339Nano),
		RequestID:   uint64(stackEvent.RequestID),
		PID:         stackEvent.PID,
		TID:         stackEvent.TID,
		Comm:        nullTerminatedString(stackEvent.Comm[:]),
		TracerType:  "stack",
		EventTypeID: stackEvent.EventType,
		// Stack-specific fields
		StackID:            stackEvent.StackID,
		StackDepth:         stackEvent.StackDepth,
		StackType:          stackEvent.StackType,
		Duration:           stackEvent.Duration,
		InstructionPointer: stackEvent.InstructionPointer,
		StackPointer:       stackEvent.StackPointer,
		FramePointer:       stackEvent.FramePointer,
		CPUID:              stackEvent.CPUID,
	}

	return jsonEvent, nil
}

// processHTTPEvent processes an HTTP tracer event
func processHTTPEvent(rawSample []byte) (JSONEvent, error) {
	if len(rawSample) < int(unsafe.Sizeof(Event{})) {
		return JSONEvent{}, fmt.Errorf("insufficient data for HTTP event")
	}

	var event Event
	err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &event)
	if err != nil {
		return JSONEvent{}, fmt.Errorf("failed to parse HTTP event: %w", err)
	}

	return convertToJSONEvent(event), nil
}

// processXDPEvent processes an XDP tracer event (placeholder)
func processXDPEvent(rawSample []byte) (JSONEvent, error) {
	// TODO: Implement XDP event processing when XDP tracer is ready
	return JSONEvent{}, fmt.Errorf("XDP event processing not yet implemented")
}

// attachTracerPrograms attaches the appropriate eBPF programs based on tracer type
func attachTracerPrograms(coll *ebpf.Collection, tracerType string) ([]link.Link, error) {
	switch tracerType {
	case "stack":
		return attachStackTracerPrograms(coll)
	case "http":
		return attachHTTPTracerPrograms(coll)
	case "xdp":
		return attachXDPTracerPrograms(coll)
	default:
		return nil, fmt.Errorf("unsupported tracer type: %s", tracerType)
	}
}

// attachStackTracerPrograms attaches stack tracer programs
func attachStackTracerPrograms(coll *ebpf.Collection) ([]link.Link, error) {
	log.Println("Attaching Stack Tracer programs...")
	
	programsFound := 0
	for name, prog := range coll.Programs {
		log.Printf("Found stack tracer program: %s", name)
		programsFound++

		// For stack tracer, we typically need manual attachment via perf tools
		// or specific kprobe/uprobe attachment which requires target functions
		log.Printf("Program %s loaded but requires manual attachment", name)
		_ = prog // Use the program variable to avoid unused warning
	}

	if programsFound == 0 {
		return nil, fmt.Errorf("no stack tracer programs found in collection")
	}

	log.Printf("Stack Tracer: %d programs loaded (manual attachment required)", programsFound)
	log.Println("Note: Stack tracing events will be captured through ring buffer")

	// Return empty links since stack tracer programs require manual attachment
	return []link.Link{}, nil
}

// attachHTTPTracerPrograms attaches HTTP tracer programs
func attachHTTPTracerPrograms(coll *ebpf.Collection) ([]link.Link, error) {
	log.Println("Attaching HTTP Tracer programs...")
	
	links := make([]link.Link, 0)
	
	// Accept enter
	if prog, exists := coll.Programs["trace_accept_enter"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_enter_accept", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach accept enter tracepoint: %w", err)
		}
		links = append(links, l)
		log.Println("Attached: trace_accept_enter")
	}

	// Accept exit
	if prog, exists := coll.Programs["trace_accept_exit"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_exit_accept", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach accept exit tracepoint: %w", err)
		}
		links = append(links, l)
		log.Println("Attached: trace_accept_exit")
	}

	// Read enter
	if prog, exists := coll.Programs["trace_read_enter"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_enter_read", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach read enter tracepoint: %w", err)
		}
		links = append(links, l)
		log.Println("Attached: trace_read_enter")
	}

	// Connect enter
	if prog, exists := coll.Programs["trace_connect_enter"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach connect enter tracepoint: %w", err)
		}
		links = append(links, l)
		log.Println("Attached: trace_connect_enter")
	}

	// Write enter
	if prog, exists := coll.Programs["trace_write_enter"]; exists {
		l, err := link.Tracepoint("syscalls", "sys_enter_write", prog, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach write enter tracepoint: %w", err)
		}
		links = append(links, l)
		log.Println("Attached: trace_write_enter")
	}

	log.Printf("HTTP Tracer: %d programs attached successfully", len(links))
	return links, nil
}

// attachXDPTracerPrograms attaches XDP tracer programs (placeholder)
func attachXDPTracerPrograms(coll *ebpf.Collection) ([]link.Link, error) {
	log.Println("Attaching XDP Tracer programs...")
	// TODO: Implement XDP program attachment when XDP tracer is ready
	return []link.Link{}, fmt.Errorf("XDP tracer attachment not yet implemented")
}

// Helper functions
func nullTerminatedString(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func convertToJSONEvent(event Event) JSONEvent {
	jsonEvent := JSONEvent{
		Timestamp:   time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339Nano),
		RequestID:   event.RequestID,
		PID:         event.PID,
		TID:         event.TID,
		SrcIP:       ipToString(event.SrcIP),
		DstIP:       ipToString(event.DstIP),
		SrcPort:     event.SrcPort,
		DstPort:     event.DstPort,
		Comm:        nullTerminatedString(event.Comm[:]),
		Method:      nullTerminatedString(event.Method[:]),
		Path:        nullTerminatedString(event.Path[:]),
		PayloadLen:  event.PayloadLen,
		EventTypeID: event.EventType,
		ServiceID:   event.ServiceID,
		HopCount:    event.HopCount,
		TracerType:  "http",
	}

	// Convert trace context if present
	if event.TraceCtx.TraceIDHigh != 0 || event.TraceCtx.TraceIDLow != 0 {
		jsonEvent.TraceContext = JSONTraceContext{
			TraceID:      fmt.Sprintf("%016x%016x", event.TraceCtx.TraceIDHigh, event.TraceCtx.TraceIDLow),
			SpanID:       fmt.Sprintf("%016x", event.TraceCtx.SpanID),
			TraceFlags:   event.TraceCtx.TraceFlags,
		}

		if event.TraceCtx.ParentSpanID != 0 {
			jsonEvent.TraceContext.ParentSpanID = fmt.Sprintf("%016x", event.TraceCtx.ParentSpanID)
		}

		if event.TraceCtx.TraceStateLen > 0 {
			jsonEvent.TraceContext.TraceState = nullTerminatedString(event.TraceCtx.TraceState[:event.TraceCtx.TraceStateLen])
		}
	}

	// Set correlation type string
	switch event.CorrelationType {
	case 0:
		jsonEvent.CorrelationType = "local"
	case 1:
		jsonEvent.CorrelationType = "incoming"
	case 2:
		jsonEvent.CorrelationType = "outgoing"
	default:
		jsonEvent.CorrelationType = "unknown"
	}

	// Set event type string
	switch event.EventType {
	case 0:
		jsonEvent.EventType = "accept"
	case 1:
		jsonEvent.EventType = "read"
	case 2:
		jsonEvent.EventType = "connect"
	case 3:
		jsonEvent.EventType = "write"
	default:
		jsonEvent.EventType = "unknown"
	}

	// Set protocol string
	switch event.Protocol {
	case 6:
		jsonEvent.Protocol = "TCP"
	case 17:
		jsonEvent.Protocol = "UDP"
	default:
		jsonEvent.Protocol = "unknown"
	}

	return jsonEvent
}

// generateSampleConfig generates a sample configuration file
func generateSampleConfig() {
	sampleConfig := map[string]interface{}{
		"general": map[string]interface{}{
			"config_path": "./universal-tracer.json",
			"log_level":   "info",
		},
		"ebpf": map[string]interface{}{
			"tracer_priority": []string{"stack", "http", "xdp"},
			"enable_stack_tracer": true,
			"enable_http_tracer":  true,
			"enable_xdp_tracer":   false,
			"stack_trace_depth":   50,
			"comment": "Priority: Stack Tracer (Primary) -> HTTP Tracer (Secondary) -> XDP Tracer (Tertiary)",
		},
		"service_discovery": map[string]interface{}{
			"enable_container_discovery":     true,
			"enable_kubernetes_integration":  false,
			"enable_service_mesh":            false,
			"discovery_interval":             "30s",
			"container_runtime":              "docker",
		},
		"performance": map[string]interface{}{
			"enable_cpu_profiling":     false,
			"enable_memory_profiling":  true,
			"enable_adaptive_sampling": true,
			"max_memory_usage":         "1GB",
			"sampling_rate":            1.0,
		},
		"runtime_tracers": map[string]interface{}{
			"enable_jvm_tracing":    false,
			"enable_python_tracing": false,
			"enable_nodejs_tracing": false,
			"enable_dotnet_tracing": false,
			"sampling_rate":         0.1,
			"max_stack_depth":       50,
		},
		"output": map[string]interface{}{
			"enable_batching":           true,
			"enable_compression":        false,
			"enable_rate_limiting":      false,
			"enable_distributed_tracing": true,
			"batch_size":                100,
			"batch_timeout":             "5s",
			"output_formats":            []string{"json"},
			"distributed_tracing": map[string]interface{}{
				"enable_opentelemetry": true,
				"enable_jaeger":        true,
				"service_name":         "universal-ebpf-tracer",
				"environment":          "production",
				"sampling_ratio":       0.1,
			},
		},
	}

	data, err := json.MarshalIndent(sampleConfig, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal sample config: %v", err)
	}

	fmt.Println(string(data))
}

func main() {
	// Parse command line flags
	var configPath = flag.String("config", "", "Path to configuration file")
	var generateConfig = flag.Bool("generate-config", false, "Generate sample configuration file")
	flag.Parse()

	// Generate config if requested
	if *generateConfig {
		generateSampleConfig()
		return
	}

	// Load configuration
	var err error
	if *configPath != "" {
		_, err = config.LoadConfig(*configPath)
		log.Printf("Using config file: %s", *configPath)
	} else {
		_, err = config.LoadConfig("universal-tracer.json")
		log.Printf("Using config file: ./universal-tracer.json")
	}
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize advanced output manager
	advancedOutputConfig := &AdvancedOutputConfig{
		EnableBatching:           true,
		EnableCompression:        false,
		EnableRateLimiting:       false,
		EnableDistributedTracing: true,
		BatchSize:                100,
		BatchTimeout:             5 * time.Second,
		OutputFormats:            []string{"json"},
		DistributedTracingConfig: &DistributedTracingConfig{
			EnableOpenTelemetry: true,
			EnableJaeger:        true,
			ServiceName:         "universal-ebpf-tracer",
			Environment:         "production",
			SamplingRatio:       0.1,
		},
	}

	advancedOutputManager, err := NewAdvancedOutputManager(advancedOutputConfig)
	if err != nil {
		log.Fatalf("Failed to create advanced output manager: %v", err)
	}
	defer advancedOutputManager.Stop()
	fmt.Println("Advanced output manager initialized")

	// Initialize service discovery
	serviceDiscoveryConfig := &ServiceDiscoveryConfig{
		EnableContainerDiscovery:    true,
		EnableKubernetesIntegration: false,
		EnableServiceMesh:           false,
		DiscoveryInterval:           30 * time.Second,
		ContainerRuntime:            "docker",
	}

	serviceDiscovery, err := NewServiceDiscovery(serviceDiscoveryConfig)
	if err != nil {
		log.Fatalf("Failed to create service discovery: %v", err)
	}
	defer serviceDiscovery.Stop()
	fmt.Println("Service discovery initialized")

	// Initialize performance optimizer
	performanceConfig := &PerformanceConfig{
		EnableCPUProfiling:      false,
		EnableMemoryProfiling:   true,
		EnableAdaptiveSampling:  true,
		MaxMemoryUsage:          1024 * 1024 * 1024, // 1GB
		SamplingRate:            1.0,
		AdaptiveSamplingWindow:  60 * time.Second,
		PerformanceMetricsPath:  "./metrics",
	}

	performanceOptimizer, err := NewPerformanceOptimizer(performanceConfig)
	if err != nil {
		log.Fatalf("Failed to create performance optimizer: %v", err)
	}
	defer performanceOptimizer.Stop()
	fmt.Println("Performance optimizer initialized")

	// Initialize runtime tracer manager
	runtimeTracerConfig := &RuntimeTracerConfig{
		EnableJVMTracing:    false,
		EnablePythonTracing: false,
		EnableNodeJSTracing: false,
		EnableDotNetTracing: false,
		SamplingRate:        0.1,
		MaxStackDepth:       50,
	}

	runtimeTracerManager, err := NewRuntimeTracerManager(runtimeTracerConfig)
	if err != nil {
		log.Fatalf("Failed to create runtime tracer manager: %v", err)
	}
	defer runtimeTracerManager.Stop()
	fmt.Println("Runtime tracer manager initialized")

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start all components
	if err := advancedOutputManager.Start(ctx); err != nil {
		log.Fatalf("Failed to start advanced output manager: %v", err)
	}

	if err := serviceDiscovery.Start(ctx); err != nil {
		log.Fatalf("Failed to start service discovery: %v", err)
	}

	if err := performanceOptimizer.Start(ctx); err != nil {
		log.Fatalf("Failed to start performance optimizer: %v", err)
	}

	if err := runtimeTracerManager.Start(ctx); err != nil {
		log.Fatalf("Failed to start runtime tracer manager: %v", err)
	}

	// Load pre-compiled eBPF programs in priority order
	// 1. Stack Tracer (Primary) - Deep profiling and stack unwinding
	stackSpec, err := ebpf.LoadCollectionSpec("stack_tracer.o")
	if err != nil {
		log.Printf("Warning: Failed to load stack tracer: %v", err)
		log.Printf("Continuing without stack tracing capabilities...")
	}

	// 2. HTTP Tracer (Secondary) - Application layer protocol tracing
	httpSpec, err := ebpf.LoadCollectionSpec("http_tracer.o")
	if err != nil {
		log.Printf("Warning: Failed to load HTTP tracer: %v", err)
		log.Printf("Continuing without HTTP tracing capabilities...")
	}

	// 3. XDP Tracer (Tertiary) - High-performance network processing
	xdpSpec, err := ebpf.LoadCollectionSpec("xdp_tracer.o")
	if err != nil {
		log.Printf("Warning: Failed to load XDP tracer: %v", err)
		log.Printf("Continuing without XDP tracing capabilities...")
	}

	// Use stack tracer as primary, fallback to HTTP tracer if stack tracer fails
	var spec *ebpf.CollectionSpec
	var tracerType string

	if stackSpec != nil {
		spec = stackSpec
		tracerType = "stack"
		log.Println("Using Stack Tracer as primary tracer")
	} else if httpSpec != nil {
		spec = httpSpec
		tracerType = "http"
		log.Println("Using HTTP Tracer as fallback (stack tracer unavailable)")
	} else if xdpSpec != nil {
		spec = xdpSpec
		tracerType = "xdp"
		log.Println("Using XDP Tracer as fallback (stack and HTTP tracers unavailable)")
	} else {
		log.Fatalf("No eBPF tracers available. Please ensure *.o files are compiled and present.")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Attach tracer-specific programs
	links, err := attachTracerPrograms(coll, tracerType)
	if err != nil {
		log.Fatalf("Failed to attach tracer programs: %v", err)
	}

	// Cleanup on exit
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Open ring buffer - use appropriate map name based on tracer type
	var ringBufMapName string
	switch tracerType {
	case "stack":
		ringBufMapName = "stack_events"
	case "http":
		ringBufMapName = "rb"
	case "xdp":
		ringBufMapName = "xdp_events"
	default:
		ringBufMapName = "rb"
	}

	// Debug: List all available maps
	log.Printf("Available maps in %s tracer:", tracerType)
	for mapName := range coll.Maps {
		log.Printf("  - %s", mapName)
	}

	ringBufMap := coll.Maps[ringBufMapName]
	if ringBufMap == nil {
		log.Fatalf("Ring buffer map '%s' not found in %s tracer", ringBufMapName, tracerType)
	}

	rd, err := ringbuf.NewReader(ringBufMap)
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	log.Printf("Universal eBPF Tracer started with %s tracer as primary. Press Ctrl+C to exit.", tracerType)

	// Handle signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Received signal, shutting down...")
		cancel()
	}()

	// Create a channel for ring buffer records
	recordChan := make(chan *ringbuf.Record, 100)
	errorChan := make(chan error, 1)

	// Start ring buffer reader in a separate goroutine
	go func() {
		defer close(recordChan)
		defer close(errorChan)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rd.Read()
				if err != nil {
					select {
					case errorChan <- err:
					case <-ctx.Done():
						return
					}
					return
				}

				select {
				case recordChan <- &record:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Process events with proper context handling
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, exiting...")
			return
		case err := <-errorChan:
			if err == ringbuf.ErrClosed {
				log.Println("Ring buffer closed, exiting...")
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			return
		case record := <-recordChan:
			if record == nil {
				log.Println("Ring buffer reader finished, exiting...")
				return
			}

			// Process event based on tracer type
			var jsonEvent JSONEvent
			switch tracerType {
			case "stack":
				jsonEvent, err = processStackEvent(record.RawSample)
			case "http":
				jsonEvent, err = processHTTPEvent(record.RawSample)
			case "xdp":
				jsonEvent, err = processXDPEvent(record.RawSample)
			default:
				log.Printf("Unknown tracer type: %s", tracerType)
				continue
			}

			if err != nil {
				log.Printf("Error processing %s event: %v", tracerType, err)
				performanceOptimizer.RecordEvent(false) // Record failed event
				continue
			}

			// Check if we should sample this event
			if !performanceOptimizer.ShouldSample() {
				performanceOptimizer.RecordEvent(false) // Record dropped event
				continue
			}

			// Correlate event with service information
			serviceDiscovery.CorrelateEvent(&jsonEvent)

			// Process runtime events if applicable
			if jsonEvent.TracerType == "runtime" {
				runtimeEvent := &RuntimeEvent{
					Timestamp:    time.Now(),
					Runtime:      jsonEvent.TracerType,
					ProcessID:    int(jsonEvent.PID),
					ThreadID:     int(jsonEvent.TID),
					FunctionName: jsonEvent.Method,
					ModuleName:   jsonEvent.Comm,
					Duration:     time.Duration(jsonEvent.Duration),
				}
				runtimeTracerManager.SendRuntimeEvent(runtimeEvent)
			}

			// Send to advanced output manager
			if err := advancedOutputManager.WriteEvent(&jsonEvent); err != nil {
				log.Printf("Error writing event to output: %v", err)
				performanceOptimizer.RecordEvent(false) // Record failed event
			} else {
				performanceOptimizer.RecordEvent(true) // Record successful event
			}
		}
	}
}
