package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-tracing/config"
	"ebpf-tracing/pkg/analytics"
	"ebpf-tracing/pkg/async"
	"ebpf-tracing/pkg/container"
	"ebpf-tracing/pkg/load"
	"ebpf-tracing/pkg/outputs"
	"ebpf-tracing/pkg/performance"
	"ebpf-tracing/pkg/protocols"
	"ebpf-tracing/pkg/runtimes"
	"ebpf-tracing/pkg/security"
	"ebpf-tracing/pkg/symbols"
	"ebpf-tracing/pkg/tracing"
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

// Event structure matching the enhanced C struct
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

	// Distributed tracing fields
	TraceCtx        TraceContext `json:"trace_context"`
	ServiceID       uint32       `json:"service_id"`
	CorrelationType uint8        `json:"correlation_type"`
	HopCount        uint8        `json:"hop_count"`
	Reserved        uint16       `json:"-"`
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
}

func main() {
	// Parse command line flags
	var configPath = flag.String("config", "", "Path to configuration file")
	var generateConfig = flag.Bool("generate-config", false, "Generate default configuration file")
	var validateConfig = flag.Bool("validate-config", false, "Validate configuration file")
	flag.Parse()

	// Generate default configuration if requested
	if *generateConfig {
		defaultConfig := config.DefaultConfig()
		if err := defaultConfig.SaveConfig("http-tracer.json"); err != nil {
			log.Fatalf("Failed to generate config: %v", err)
		}
		fmt.Println("Default configuration saved to http-tracer.json")
		return
	}

	// Load configuration
	var cfg *config.Config
	var err error

	if *configPath != "" {
		cfg, err = config.LoadConfig(*configPath)
	} else {
		// Try to find config file automatically
		foundConfigPath := config.FindConfigFile()
		if foundConfigPath != "" {
			fmt.Printf("Using config file: %s\n", foundConfigPath)
			cfg, err = config.LoadConfig(foundConfigPath)
		} else {
			fmt.Println("No config file found, using defaults")
			cfg = config.DefaultConfig()
		}
	}

	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate configuration if requested
	if *validateConfig {
		if err := cfg.Validate(); err != nil {
			log.Fatalf("Configuration validation failed: %v", err)
		}
		fmt.Println("Configuration is valid")
		return
	}

	// Check if tracer is enabled
	if !cfg.General.Enabled {
		fmt.Println("Tracer is disabled in configuration")
		return
	}

	// Initialize distributed tracing if enabled
	var spanManager *tracing.SpanManager
	if cfg.Output.EnableDistributedTracing {
		spanManager, err = initializeDistributedTracing(cfg)
		if err != nil {
			log.Fatalf("Failed to initialize distributed tracing: %v", err)
		}
		defer func() {
			if spanManager != nil {
				spanManager.Shutdown()
			}
		}()
		fmt.Println("Distributed tracing initialized")
	}

	// Initialize analytics engine if enabled
	var analyticsEngine *analytics.AnalyticsEngine
	if cfg.Output.EnableAnalytics {
		analyticsEngine, err = initializeAnalyticsEngine(cfg)
		if err != nil {
			log.Fatalf("Failed to initialize analytics engine: %v", err)
		}
		defer func() {
			if analyticsEngine != nil {
				analyticsEngine.Stop()
			}
		}()

		// Start analytics engine
		if err := analyticsEngine.Start(context.Background()); err != nil {
			log.Fatalf("Failed to start analytics engine: %v", err)
		}
		fmt.Printf("Analytics engine started on port %d\n", cfg.Output.Analytics.DashboardPort)
	}

	// Initialize output manager
	var outputManager *outputs.OutputManager
	outputManager, err = initializeOutputManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize output manager: %v", err)
	}
	defer func() {
		if outputManager != nil {
			outputManager.Close()
		}
	}()

	// Initialize output manager
	if err := outputManager.Initialize(context.Background()); err != nil {
		log.Fatalf("Failed to start output manager: %v", err)
	}
	fmt.Println("Output manager initialized")

	// Initialize security and compliance if enabled
	var complianceManager *security.ComplianceManager
	if cfg.ComplianceSecurity.EnableCompliance {
		complianceManager, err = initializeComplianceManager(cfg)
		if err != nil {
			log.Fatalf("Failed to initialize compliance manager: %v", err)
		}
		defer func() {
			if complianceManager != nil {
				// Compliance manager cleanup if needed
			}
		}()
		fmt.Println("Security and compliance system initialized")
	}

	// Initialize BTF/DWARF symbol resolution if enabled
	var btfManager *symbols.BTFManager
	var dwarfManager *symbols.DWARFManager
	if cfg.General.EnableSymbolResolution {
		btfManager, err = initializeBTFManager(cfg)
		if err != nil {
			log.Printf("Warning: Failed to initialize BTF manager: %v", err)
		} else {
			defer btfManager.Close()
			fmt.Println("BTF symbol resolution initialized")
		}

		dwarfManager = initializeDWARFManager(cfg)
		defer dwarfManager.Close()
		fmt.Println("DWARF symbol resolution initialized")
	}

	// Initialize async context tracking if enabled
	var contextTracker *async.ContextTracker
	if cfg.General.EnableAsyncTracking {
		contextTracker = initializeAsyncTracking(cfg)
		defer contextTracker.Close()
		fmt.Println("Async context tracking initialized")
	}

	// Initialize multi-protocol support if enabled
	var protocolManager *protocols.ProtocolManager
	if cfg.General.EnableMultiProtocol {
		protocolManager = initializeProtocolManager(cfg)
		defer protocolManager.Close()
		fmt.Println("Multi-protocol support initialized")
	}

	// Initialize performance optimizer if enabled
	var performanceOptimizer *performance.PerformanceOptimizer
	if cfg.General.EnablePerformanceOptimization {
		performanceOptimizer = initializePerformanceOptimizer(cfg)
		defer performanceOptimizer.Stop()

		// Start performance optimization
		if err := performanceOptimizer.Start(context.Background()); err != nil {
			log.Printf("Warning: Failed to start performance optimizer: %v", err)
		} else {
			fmt.Println("Performance optimization initialized")
		}
	}

	// Initialize runtime integration if enabled
	var runtimeManager *runtimes.RuntimeManager
	if cfg.General.EnableRuntimeIntegration {
		runtimeManager = initializeRuntimeManager(cfg)
		defer runtimeManager.Stop()

		// Start runtime integration
		if err := runtimeManager.Start(context.Background()); err != nil {
			log.Printf("Warning: Failed to start runtime manager: %v", err)
		} else {
			fmt.Println("Runtime integration initialized")
			activeRuntimes := runtimeManager.GetActiveRuntimes()
			if len(activeRuntimes) > 0 {
				fmt.Printf("Active runtimes: %v\n", activeRuntimes)
			}
		}
	}

	// Initialize container integration if enabled
	var containerManager *container.ContainerManager
	if cfg.General.EnableContainerIntegration {
		containerManager = initializeContainerManager(cfg)
		defer containerManager.Stop()

		// Start container integration
		if err := containerManager.Start(context.Background()); err != nil {
			log.Printf("Warning: Failed to start container manager: %v", err)
		} else {
			fmt.Println("Container integration initialized")
			stats := containerManager.GetStats()
			fmt.Printf("Container discovery: %d containers, %d pods, %d services\n",
				stats["containers_discovered"], stats["pods_discovered"], stats["services_discovered"])
		}
	}

	// Initialize load management if enabled
	var loadManager *load.LoadManager
	if cfg.General.EnableLoadManagement {
		loadManager = initializeLoadManager(cfg)
		defer loadManager.Stop()

		// Start load management
		if err := loadManager.Start(context.Background()); err != nil {
			log.Printf("Warning: Failed to start load manager: %v", err)
		} else {
			fmt.Println("Load management initialized")
			stats := loadManager.GetStats()
			fmt.Printf("Load management: sampling rate %.2f%%, %d events processed\n",
				stats.CurrentSamplingRate*100, stats.ProcessedEvents)
		}
	}

	// Initialize enhanced security if enabled
	var lsmManager *security.LSMManager
	if cfg.General.EnableEnhancedSecurity {
		lsmManager = initializeSecurityManager(cfg)
		defer lsmManager.Stop()

		// Start enhanced security
		if err := lsmManager.Start(context.Background()); err != nil {
			log.Printf("Warning: Failed to start LSM manager: %v", err)
		} else {
			fmt.Println("Enhanced security initialized")
			activeLSMs := lsmManager.GetActiveLSMs()
			if len(activeLSMs) > 0 {
				fmt.Printf("Active LSMs: %v\n", activeLSMs)
			}
		}
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("http_tracer.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Attach tracepoints
	links := make([]link.Link, 0)
	
	// Accept enter
	l1, err := link.Tracepoint("syscalls", "sys_enter_accept", coll.Programs["trace_accept_enter"], nil)
	if err != nil {
		log.Fatalf("Failed to attach accept enter tracepoint: %v", err)
	}
	links = append(links, l1)

	// Accept exit
	l2, err := link.Tracepoint("syscalls", "sys_exit_accept", coll.Programs["trace_accept_exit"], nil)
	if err != nil {
		log.Fatalf("Failed to attach accept exit tracepoint: %v", err)
	}
	links = append(links, l2)

	// Read enter
	l3, err := link.Tracepoint("syscalls", "sys_enter_read", coll.Programs["trace_read_enter"], nil)
	if err != nil {
		log.Fatalf("Failed to attach read enter tracepoint: %v", err)
	}
	links = append(links, l3)

	// Connect enter
	l4, err := link.Tracepoint("syscalls", "sys_enter_connect", coll.Programs["trace_connect_enter"], nil)
	if err != nil {
		log.Fatalf("Failed to attach connect enter tracepoint: %v", err)
	}
	links = append(links, l4)

	// Write enter
	l5, err := link.Tracepoint("syscalls", "sys_enter_write", coll.Programs["trace_write_enter"], nil)
	if err != nil {
		log.Fatalf("Failed to attach write enter tracepoint: %v", err)
	}
	links = append(links, l5)

	// Cleanup on exit
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Open ring buffer
	rd, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	log.Println("eBPF HTTP tracer started. Press Ctrl+C to exit.")

	// Handle signals
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Println("Received signal, shutting down...")
		cancel()
	}()

	// Process events
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
				continue
			}

			// Parse event
			var event Event
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			// Convert to JSON-friendly format
			jsonEvent := convertToJSONEvent(event)

				// Apply configuration-based filtering
				if shouldFilterEvent(cfg, jsonEvent) {
					continue
				}

				// Log different event types based on configuration
				shouldLog := false
				switch jsonEvent.EventTypeID {
				case 1: // read events - log if HTTP request detected and enabled
					shouldLog = cfg.Filtering.EventTypeFilters.EnableReadEvents && jsonEvent.Method != ""
				case 2: // connect events - log if correlated with HTTP request and enabled
					shouldLog = cfg.Filtering.EventTypeFilters.EnableConnectEvents && jsonEvent.RequestID != 0
				case 3: // write events - log if HTTP response detected or correlated with request and enabled
					shouldLog = cfg.Filtering.EventTypeFilters.EnableWriteEvents &&
						(jsonEvent.RequestID != 0 || isHTTPResponse(jsonEvent.Payload))
				default:
					shouldLog = false
				}

			// Process with distributed tracing if enabled
			if spanManager != nil {
				traceEvent := convertToTraceEvent(jsonEvent)
				if err := spanManager.ProcessEvent(context.Background(), traceEvent); err != nil {
					log.Printf("Error processing trace event: %v", err)
				}
			}

			// Process with analytics engine if enabled
			if analyticsEngine != nil {
				traceEvent := convertToTraceEvent(jsonEvent)
				if err := analyticsEngine.ProcessEvent(traceEvent); err != nil {
					log.Printf("Error processing analytics event: %v", err)
				}
			}

			// Process with compliance manager if enabled
			if complianceManager != nil {
				traceEvent := convertToTraceEvent(jsonEvent)
				processedEvent, err := complianceManager.ProcessEvent(context.Background(), traceEvent)
				if err != nil {
					log.Printf("Error processing compliance event: %v", err)
				} else {
					// Use the processed (filtered/encrypted) event for further processing
					_ = processedEvent
				}
			}

			if shouldLog {
				// Send event to output manager
				if err := outputManager.WriteEvent(jsonEvent); err != nil {
					log.Printf("Error writing event to outputs: %v", err)
				}
			}
		}
	}
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

	// Generate service name from comm and port
	if event.ServiceID != 0 {
		jsonEvent.ServiceName = fmt.Sprintf("%s:%d", jsonEvent.Comm, event.DstPort)
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
		jsonEvent.Protocol = ""
	}

	// Add payload if it contains printable data
	if event.PayloadLen > 0 {
		payload := event.Payload[:event.PayloadLen]
		if isPrintable(payload) {
			jsonEvent.Payload = string(payload)
		}
	}

	return jsonEvent
}

func nullTerminatedString(data []byte) string {
	n := bytes.IndexByte(data, 0)
	if n == -1 {
		return string(data)
	}
	return string(data[:n])
}

func ipToString(ip uint32) string {
	if ip == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// isHTTPResponse checks if the payload looks like an HTTP response
func isHTTPResponse(payload string) bool {
	if len(payload) < 12 {
		return false
	}

	// Check for HTTP response format
	return strings.HasPrefix(payload, "HTTP/1.") || strings.HasPrefix(payload, "HTTP/2.")
}

// shouldFilterEvent determines if an event should be filtered out based on configuration
func shouldFilterEvent(cfg *config.Config, event JSONEvent) bool {
	if !cfg.Filtering.Enabled {
		return false
	}

	// Filter by PID
	if cfg.ShouldFilterPID(event.PID) {
		return true
	}

	// Filter by process name
	if cfg.ShouldFilterProcess(event.Comm) {
		return true
	}

	// Filter by network (ports)
	if shouldFilterByPort(cfg, event.SrcPort, event.DstPort) {
		return true
	}

	// Filter by network (IPs)
	if shouldFilterByIP(cfg, event.SrcIP, event.DstIP) {
		return true
	}

	// Filter by HTTP method
	if event.Method != "" && shouldFilterByHTTPMethod(cfg, event.Method) {
		return true
	}

	// Filter by HTTP path
	if event.Path != "" && shouldFilterByHTTPPath(cfg, event.Path) {
		return true
	}

	// Filter by payload size
	if shouldFilterByPayloadSize(cfg, event.PayloadLen) {
		return true
	}

	return false
}

// shouldFilterByPort checks if event should be filtered by port
func shouldFilterByPort(cfg *config.Config, srcPort, dstPort uint16) bool {
	ports := []uint16{srcPort, dstPort}

	// Check include list (if specified, only include these ports)
	if len(cfg.Filtering.NetworkFilters.IncludePorts) > 0 {
		found := false
		for _, port := range ports {
			for _, includePort := range cfg.Filtering.NetworkFilters.IncludePorts {
				if port == includePort {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return true
		}
	}

	// Check exclude list
	for _, port := range ports {
		for _, excludePort := range cfg.Filtering.NetworkFilters.ExcludePorts {
			if port == excludePort {
				return true
			}
		}
	}

	return false
}

// shouldFilterByIP checks if event should be filtered by IP address
func shouldFilterByIP(cfg *config.Config, srcIP, dstIP string) bool {
	ips := []string{srcIP, dstIP}

	// Check localhost only filter
	if cfg.Filtering.NetworkFilters.LocalhostOnly {
		isLocalhost := false
		for _, ip := range ips {
			if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
				isLocalhost = true
				break
			}
		}
		if !isLocalhost {
			return true
		}
	}

	// Check include list (if specified, only include these IPs)
	if len(cfg.Filtering.NetworkFilters.IncludeIPs) > 0 {
		found := false
		for _, ip := range ips {
			for _, includeIP := range cfg.Filtering.NetworkFilters.IncludeIPs {
				if ip == includeIP {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return true
		}
	}

	// Check exclude list
	for _, ip := range ips {
		for _, excludeIP := range cfg.Filtering.NetworkFilters.ExcludeIPs {
			if ip == excludeIP {
				return true
			}
		}
	}

	return false
}

// shouldFilterByHTTPMethod checks if event should be filtered by HTTP method
func shouldFilterByHTTPMethod(cfg *config.Config, method string) bool {
	// Check include list (if specified, only include these methods)
	if len(cfg.Filtering.HTTPFilters.IncludeMethods) > 0 {
		found := false
		for _, includeMethod := range cfg.Filtering.HTTPFilters.IncludeMethods {
			if strings.EqualFold(method, includeMethod) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	// Check exclude list
	for _, excludeMethod := range cfg.Filtering.HTTPFilters.ExcludeMethods {
		if strings.EqualFold(method, excludeMethod) {
			return true
		}
	}

	return false
}

// shouldFilterByHTTPPath checks if event should be filtered by HTTP path
func shouldFilterByHTTPPath(cfg *config.Config, path string) bool {
	// Check include patterns (if specified, only include paths matching these patterns)
	if len(cfg.Filtering.HTTPFilters.IncludePathPatterns) > 0 {
		found := false
		for _, pattern := range cfg.Filtering.HTTPFilters.IncludePathPatterns {
			if strings.Contains(path, pattern) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	// Check exclude patterns
	for _, pattern := range cfg.Filtering.HTTPFilters.ExcludePathPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}

// shouldFilterByPayloadSize checks if event should be filtered by payload size
func shouldFilterByPayloadSize(cfg *config.Config, payloadLen uint32) bool {
	if payloadLen < cfg.Filtering.HTTPFilters.MinPayloadSize {
		return true
	}

	if cfg.Filtering.HTTPFilters.MaxPayloadSize > 0 && payloadLen > cfg.Filtering.HTTPFilters.MaxPayloadSize {
		return true
	}

	return false
}

// initializeDistributedTracing initializes the distributed tracing system
func initializeDistributedTracing(cfg *config.Config) (*tracing.SpanManager, error) {
	var otelProvider *tracing.TracingProvider
	var jaegerTracer *tracing.JaegerTracer
	var err error

	// Initialize OpenTelemetry if enabled
	if cfg.Output.DistributedTracing.EnableOpenTelemetry {
		otelConfig := &tracing.TracingConfig{
			ServiceName:    cfg.General.ProcessName,
			ServiceVersion: "1.0.0",
			Environment:    cfg.Output.DistributedTracing.Environment,
			ExporterType:   cfg.Output.DistributedTracing.OTLPExporter,
			OTLPEndpoint:   cfg.Output.DistributedTracing.OTLPEndpoint,
			SamplingRatio:  cfg.Output.DistributedTracing.SamplingRatio,
		}

		otelProvider, err = tracing.NewTracingProvider(otelConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create OpenTelemetry provider: %w", err)
		}
	}

	// Initialize Jaeger if enabled
	if cfg.Output.DistributedTracing.EnableJaeger {
		jaegerConfig := &tracing.JaegerConfig{
			ServiceName:   cfg.General.ProcessName,
			AgentEndpoint: cfg.Output.DistributedTracing.JaegerAgentEndpoint,
			CollectorURL:  cfg.Output.DistributedTracing.JaegerCollectorURL,
			SamplingType:  "const",
			SamplingParam: cfg.Output.DistributedTracing.SamplingRatio,
		}

		jaegerTracer, err = tracing.NewJaegerTracer(jaegerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Jaeger tracer: %w", err)
		}
	}

	// Create span manager
	spanManagerConfig := tracing.DefaultSpanManagerConfig()
	spanManagerConfig.EnableOtel = cfg.Output.DistributedTracing.EnableOpenTelemetry
	spanManagerConfig.EnableJaeger = cfg.Output.DistributedTracing.EnableJaeger

	spanManager := tracing.NewSpanManager(spanManagerConfig, otelProvider, jaegerTracer)

	return spanManager, nil
}

// initializeAnalyticsEngine initializes the real-time analytics engine
func initializeAnalyticsEngine(cfg *config.Config) (*analytics.AnalyticsEngine, error) {
	analyticsConfig := &analytics.AnalyticsConfig{
		BufferSize:      cfg.Output.Analytics.BufferSize,
		WorkerThreads:   cfg.Output.Analytics.WorkerThreads,
		FlushInterval:   time.Duration(cfg.Output.Analytics.FlushIntervalSeconds) * time.Second,
		WindowSizes:     parseWindowSizes(cfg.Output.Analytics.WindowSizes),
		RetentionPeriod: time.Duration(cfg.Output.Analytics.RetentionHours) * time.Hour,
		EnabledMetrics:  cfg.Output.Analytics.EnabledMetrics,
		EnableAlerting:  cfg.Output.Analytics.EnableAlerting,
		AlertRules:      convertAlertRules(cfg.Output.Analytics.AlertRules),
		EnableDashboard: cfg.Output.Analytics.EnableDashboard,
		DashboardPort:   cfg.Output.Analytics.DashboardPort,
		MetricsEndpoint: cfg.Output.Analytics.MetricsEndpoint,
	}

	engine, err := analytics.NewAnalyticsEngine(analyticsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create analytics engine: %w", err)
	}

	return engine, nil
}

// parseWindowSizes parses window size strings into durations
func parseWindowSizes(windowStrings []string) []time.Duration {
	var windows []time.Duration
	for _, windowStr := range windowStrings {
		if duration, err := time.ParseDuration(windowStr); err == nil {
			windows = append(windows, duration)
		}
	}

	// Default windows if none specified
	if len(windows) == 0 {
		windows = []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
		}
	}

	return windows
}

// convertAlertRules converts config alert rules to analytics alert rules
func convertAlertRules(configRules []config.AlertRuleConfig) []analytics.AlertRuleConfig {
	var analyticsRules []analytics.AlertRuleConfig

	for _, rule := range configRules {
		analyticsRules = append(analyticsRules, analytics.AlertRuleConfig{
			Name:        rule.Name,
			Metric:      rule.Metric,
			Condition:   rule.Condition,
			Threshold:   rule.Threshold,
			Duration:    time.Duration(rule.DurationSeconds) * time.Second,
			Labels:      rule.Labels,
			Annotations: rule.Annotations,
		})
	}

	return analyticsRules
}

// initializeComplianceManager initializes the security and compliance manager
func initializeComplianceManager(cfg *config.Config) (*security.ComplianceManager, error) {
	complianceConfig := &security.ComplianceConfig{
		EnableDataFiltering:    cfg.ComplianceSecurity.EnableDataFiltering,
		PIIDetection:          convertPIIDetectionConfig(cfg.ComplianceSecurity.PIIDetection),
		DataClassification:    convertDataClassificationConfig(cfg.ComplianceSecurity.DataClassification),
		EnableAuditLogging:    cfg.ComplianceSecurity.EnableAuditLogging,
		AuditConfig:          convertAuditConfig(cfg.ComplianceSecurity.AuditConfig),
		EnableEncryption:     cfg.ComplianceSecurity.EnableEncryption,
		EncryptionConfig:     convertEncryptionConfig(cfg.ComplianceSecurity.EncryptionConfig),
		EnableAccessControl:  cfg.ComplianceSecurity.EnableAccessControl,
		AccessControlConfig:  convertAccessControlConfig(cfg.ComplianceSecurity.AccessControlConfig),
		EnableRetentionPolicy: cfg.ComplianceSecurity.EnableRetentionPolicy,
		RetentionConfig:      convertRetentionConfig(cfg.ComplianceSecurity.RetentionConfig),
		ComplianceFrameworks: cfg.ComplianceSecurity.ComplianceFrameworks,
	}

	manager, err := security.NewComplianceManager(complianceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create compliance manager: %w", err)
	}

	return manager, nil
}

// Helper functions to convert config structures
func convertPIIDetectionConfig(cfg config.PIIDetectionConfig) security.PIIDetectionConfig {
	var customPatterns []security.PIIPattern
	for _, pattern := range cfg.CustomPatterns {
		customPatterns = append(customPatterns, security.PIIPattern{
			Name:        pattern.Name,
			Pattern:     pattern.Pattern,
			Type:        pattern.Type,
			Confidence:  pattern.Confidence,
			Description: pattern.Description,
		})
	}

	return security.PIIDetectionConfig{
		EnableDetection:  cfg.EnableDetection,
		RedactionMode:   cfg.RedactionMode,
		PIITypes:        cfg.PIITypes,
		CustomPatterns:  customPatterns,
		SensitivityLevel: cfg.SensitivityLevel,
	}
}

func convertDataClassificationConfig(cfg config.DataClassificationConfig) security.DataClassificationConfig {
	var levels []security.ClassificationLevel
	for _, level := range cfg.ClassificationLevels {
		levels = append(levels, security.ClassificationLevel{
			Level:       level.Level,
			Description: level.Description,
			Patterns:    level.Patterns,
			Actions:     level.Actions,
		})
	}

	return security.DataClassificationConfig{
		EnableClassification: cfg.EnableClassification,
		ClassificationLevels: levels,
		AutoClassification:   cfg.AutoClassification,
		DefaultLevel:        cfg.DefaultLevel,
	}
}

func convertAuditConfig(cfg config.AuditConfig) security.AuditConfig {
	return security.AuditConfig{
		AuditLevel:       cfg.AuditLevel,
		LogDestination:   cfg.LogDestination,
		LogFormat:       cfg.LogFormat,
		IncludePayloads: cfg.IncludePayloads,
		TamperProtection: cfg.TamperProtection,
		DigitalSigning:  cfg.DigitalSigning,
		RetentionPeriod: time.Duration(cfg.RetentionDays) * 24 * time.Hour,
		EncryptLogs:     cfg.EncryptLogs,
		RemoteEndpoints: cfg.RemoteEndpoints,
	}
}

func convertEncryptionConfig(cfg config.EncryptionConfig) security.EncryptionConfig {
	return security.EncryptionConfig{
		Algorithm:         cfg.Algorithm,
		KeyRotationPeriod: time.Duration(cfg.KeyRotationDays) * 24 * time.Hour,
		KeyDerivation:     cfg.KeyDerivation,
		EncryptInTransit:  cfg.EncryptInTransit,
		EncryptAtRest:     cfg.EncryptAtRest,
		KeyManagementURL:  cfg.KeyManagementURL,
	}
}

func convertAccessControlConfig(cfg config.AccessControlConfig) security.AccessControlConfig {
	var roles []security.Role
	for _, role := range cfg.Roles {
		roles = append(roles, security.Role{
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.Permissions,
			Resources:   role.Resources,
		})
	}

	var policies []security.AccessPolicy
	for _, policy := range cfg.Policies {
		policies = append(policies, security.AccessPolicy{
			Name:       policy.Name,
			Effect:     policy.Effect,
			Actions:    policy.Actions,
			Resources:  policy.Resources,
			Conditions: policy.Conditions,
			Principal:  policy.Principal,
		})
	}

	return security.AccessControlConfig{
		AuthenticationMode: cfg.AuthenticationMode,
		AuthorizationMode:  cfg.AuthorizationMode,
		Roles:             roles,
		Policies:          policies,
		SessionTimeout:    time.Duration(cfg.SessionTimeoutMinutes) * time.Minute,
		MaxSessions:       cfg.MaxSessions,
	}
}

func convertRetentionConfig(cfg config.RetentionConfig) security.RetentionConfig {
	dataTypeRetention := make(map[string]time.Duration)
	for dataType, days := range cfg.DataTypeRetentionDays {
		dataTypeRetention[dataType] = time.Duration(days) * 24 * time.Hour
	}

	return security.RetentionConfig{
		DefaultRetention:    time.Duration(cfg.DefaultRetentionDays) * 24 * time.Hour,
		DataTypeRetention:   dataTypeRetention,
		AutoPurge:          cfg.AutoPurge,
		PurgeSchedule:      cfg.PurgeSchedule,
		ArchiveBeforePurge: cfg.ArchiveBeforePurge,
		ArchiveLocation:    cfg.ArchiveLocation,
	}
}

// convertToTraceEvent converts JSONEvent to TraceEvent for distributed tracing
func convertToTraceEvent(jsonEvent JSONEvent) *tracing.TraceEvent {
	return &tracing.TraceEvent{
		Timestamp:       uint64(time.Now().UnixNano()), // Use current time for processing
		RequestID:       jsonEvent.RequestID,
		PID:             jsonEvent.PID,
		TID:             jsonEvent.TID,
		SrcIP:           jsonEvent.SrcIP,
		DstIP:           jsonEvent.DstIP,
		SrcPort:         jsonEvent.SrcPort,
		DstPort:         jsonEvent.DstPort,
		Comm:            jsonEvent.Comm,
		Method:          jsonEvent.Method,
		Path:            jsonEvent.Path,
		PayloadLen:      jsonEvent.PayloadLen,
		Payload:         jsonEvent.Payload,
		EventType:       jsonEvent.EventType,
		Protocol:        jsonEvent.Protocol,
		TraceContext: tracing.TraceContext{
			TraceID:      jsonEvent.TraceContext.TraceID,
			SpanID:       jsonEvent.TraceContext.SpanID,
			ParentSpanID: jsonEvent.TraceContext.ParentSpanID,
			TraceFlags:   jsonEvent.TraceContext.TraceFlags,
			TraceState:   jsonEvent.TraceContext.TraceState,
		},
		ServiceID:       jsonEvent.ServiceID,
		ServiceName:     jsonEvent.ServiceName,
		CorrelationType: jsonEvent.CorrelationType,
		HopCount:        jsonEvent.HopCount,
	}
}

// initializeBTFManager initializes BTF symbol resolution
func initializeBTFManager(cfg *config.Config) (*symbols.BTFManager, error) {
	btfConfig := symbols.DefaultBTFConfig()

	// Override with configuration if available
	if cfg.General.BTFPath != "" {
		btfConfig.KernelBTFPath = cfg.General.BTFPath
	}

	return symbols.NewBTFManager(btfConfig)
}

// initializeDWARFManager initializes DWARF symbol resolution
func initializeDWARFManager(cfg *config.Config) *symbols.DWARFManager {
	dwarfConfig := symbols.DefaultDWARFConfig()

	// Override with configuration if available
	if cfg.General.EnableDebugInfo {
		dwarfConfig.EnableInlineInfo = true
		dwarfConfig.EnableVariableInfo = true
		dwarfConfig.EnableCallFrame = true
	}

	return symbols.NewDWARFManager(dwarfConfig)
}

// initializeAsyncTracking initializes async context tracking
func initializeAsyncTracking(cfg *config.Config) *async.ContextTracker {
	asyncConfig := async.DefaultAsyncConfig()

	// Override with configuration if available
	if cfg.General.MaxAsyncContexts > 0 {
		asyncConfig.MaxContexts = cfg.General.MaxAsyncContexts
	}

	if cfg.General.AsyncContextTimeout > 0 {
		asyncConfig.ContextTimeout = time.Duration(cfg.General.AsyncContextTimeout) * time.Second
	}

	return async.NewContextTracker(asyncConfig)
}

// initializeProtocolManager initializes multi-protocol support
func initializeProtocolManager(cfg *config.Config) *protocols.ProtocolManager {
	protocolConfig := protocols.DefaultProtocolConfig()

	// Override with configuration if available
	if cfg.General.EnableGRPC {
		protocolConfig.EnableGRPC = true
	}

	if cfg.General.EnableWebSocket {
		protocolConfig.EnableWebSocket = true
	}

	if cfg.General.EnableTCP {
		protocolConfig.EnableTCP = true
	}

	return protocols.NewProtocolManager(protocolConfig)
}

// initializePerformanceOptimizer initializes performance optimization
func initializePerformanceOptimizer(cfg *config.Config) *performance.PerformanceOptimizer {
	optimizerConfig := performance.DefaultOptimizerConfig()

	// Override with configuration if available
	if cfg.General.EnableCPUProfiling {
		optimizerConfig.EnableCPUProfiling = true
	}

	if cfg.General.EnableMemoryProfiling {
		optimizerConfig.EnableMemoryProfiling = true
	}

	if cfg.General.EnableEventPooling {
		optimizerConfig.EnableEventPooling = true
	}

	if cfg.General.MaxEventPoolSize > 0 {
		optimizerConfig.MaxEventPoolSize = cfg.General.MaxEventPoolSize
	}

	return performance.NewPerformanceOptimizer(optimizerConfig)
}

// initializeRuntimeManager initializes runtime integration
func initializeRuntimeManager(cfg *config.Config) *runtimes.RuntimeManager {
	runtimeConfig := runtimes.DefaultRuntimeConfig()

	// Override with configuration if available
	if cfg.General.EnableJVMTracing {
		runtimeConfig.EnableJVMTracing = true
	}

	if cfg.General.EnablePythonTracing {
		runtimeConfig.EnablePythonTracing = true
	}

	if cfg.General.EnableV8Tracing {
		runtimeConfig.EnableV8Tracing = true
	}

	if cfg.General.RuntimeEventBufferSize > 0 {
		runtimeConfig.EventBufferSize = cfg.General.RuntimeEventBufferSize
	}

	return runtimes.NewRuntimeManager(runtimeConfig)
}

// initializeContainerManager initializes container integration
func initializeContainerManager(cfg *config.Config) *container.ContainerManager {
	containerConfig := container.DefaultContainerConfig()

	// Override with configuration if available
	if cfg.General.EnableContainerDiscovery {
		containerConfig.EnableContainerDiscovery = true
	}

	if cfg.General.EnableKubernetesIntegration {
		containerConfig.EnableKubernetesIntegration = true
	}

	if cfg.General.ContainerDiscoveryInterval > 0 {
		containerConfig.DiscoveryInterval = time.Duration(cfg.General.ContainerDiscoveryInterval) * time.Second
	}

	return container.NewContainerManager(containerConfig)
}

// initializeLoadManager initializes load management
func initializeLoadManager(cfg *config.Config) *load.LoadManager {
	loadConfig := load.DefaultLoadConfig()

	// Override with configuration if available
	if cfg.General.MaxEventsPerSecond > 0 {
		loadConfig.MaxEventsPerSecond = uint64(cfg.General.MaxEventsPerSecond)
	}

	if cfg.General.MinSamplingRate > 0 {
		loadConfig.MinSamplingRate = cfg.General.MinSamplingRate
	}

	if cfg.General.MaxSamplingRate > 0 {
		loadConfig.MaxSamplingRate = cfg.General.MaxSamplingRate
	}

	return load.NewLoadManager(loadConfig)
}

// initializeSecurityManager initializes enhanced security
func initializeSecurityManager(cfg *config.Config) *security.LSMManager {
	lsmConfig := security.DefaultLSMConfig()

	// Override with configuration if available
	if cfg.General.EnableSELinux {
		lsmConfig.EnableSELinux = true
	}

	if cfg.General.EnableAppArmor {
		lsmConfig.EnableAppArmor = true
	}

	if cfg.General.EnableSeccomp {
		lsmConfig.EnableSeccomp = true
	}

	return security.NewLSMManager(lsmConfig)
}

// initializeOutputManager initializes the output manager with configured outputs
func initializeOutputManager(cfg *config.Config) (*outputs.OutputManager, error) {
	manager := outputs.NewOutputManager()

	// Check if multiple outputs are enabled
	if cfg.Output.EnableMultipleOutputs && len(cfg.Output.Outputs) > 0 {
		// Use new multiple outputs system
		for _, outputConfig := range cfg.Output.Outputs {
			if !outputConfig.Enabled {
				continue
			}

			output, err := createOutput(outputConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to create output %s: %w", outputConfig.Name, err)
			}

			manager.AddOutput(output)
		}
	} else {
		// Use legacy single output system for backward compatibility
		output, err := createLegacyOutput(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create legacy output: %w", err)
		}

		manager.AddOutput(output)
	}

	return manager, nil
}

// createOutput creates a specific output adapter from configuration
func createOutput(config config.OutputAdapterConfig) (outputs.EventOutput, error) {
	switch config.Type {
	case "stdout":
		return createStdoutOutput(config)
	case "unix_socket":
		return createUnixSocketOutput(config)
	default:
		return nil, fmt.Errorf("unsupported output type: %s", config.Type)
	}
}

// createStdoutOutput creates a stdout output adapter
func createStdoutOutput(config config.OutputAdapterConfig) (outputs.EventOutput, error) {
	stdoutConfig := outputs.DefaultStdoutConfig()

	// Apply specific configuration
	if prettyPrint, ok := config.Config["pretty_print"].(bool); ok {
		stdoutConfig.PrettyPrint = prettyPrint
	}
	if addTimestamp, ok := config.Config["add_timestamp"].(bool); ok {
		stdoutConfig.AddTimestamp = addTimestamp
	}
	if timestampFormat, ok := config.Config["timestamp_format"].(string); ok {
		stdoutConfig.TimestampFormat = timestampFormat
	}

	return outputs.NewStdoutOutput(config.Name, stdoutConfig), nil
}

// createUnixSocketOutput creates a Unix socket output adapter
func createUnixSocketOutput(config config.OutputAdapterConfig) (outputs.EventOutput, error) {
	unixConfig := outputs.DefaultUnixSocketConfig()

	// Apply specific configuration
	if socketPath, ok := config.Config["socket_path"].(string); ok {
		unixConfig.SocketPath = socketPath
	}
	if removeExisting, ok := config.Config["remove_existing"].(bool); ok {
		unixConfig.RemoveExisting = removeExisting
	}
	if keepAlive, ok := config.Config["keep_alive"].(bool); ok {
		unixConfig.KeepAlive = keepAlive
	}
	if keepAliveInterval, ok := config.Config["keep_alive_interval"].(string); ok {
		if duration, err := time.ParseDuration(keepAliveInterval); err == nil {
			unixConfig.KeepAliveInterval = duration
		}
	}
	if connectTimeout, ok := config.Config["connect_timeout"].(string); ok {
		if duration, err := time.ParseDuration(connectTimeout); err == nil {
			unixConfig.ConnectTimeout = duration
		}
	}
	if writeTimeout, ok := config.Config["write_timeout"].(string); ok {
		if duration, err := time.ParseDuration(writeTimeout); err == nil {
			unixConfig.WriteTimeout = duration
		}
	}

	return outputs.NewUnixSocketOutput(config.Name, unixConfig), nil
}

// createLegacyOutput creates output adapter for backward compatibility
func createLegacyOutput(cfg *config.Config) (outputs.EventOutput, error) {
	// Default to stdout for backward compatibility
	stdoutConfig := outputs.DefaultStdoutConfig()

	// Apply legacy configuration
	if cfg.Output.Format == "json" {
		stdoutConfig.PrettyPrint = false
	}

	return outputs.NewStdoutOutput("legacy_stdout", stdoutConfig), nil
}
