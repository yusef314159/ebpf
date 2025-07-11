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
	"strings"
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

			if shouldLog {
				jsonData, err := json.Marshal(jsonEvent)
				if err != nil {
					log.Printf("Error marshaling JSON: %v", err)
					continue
				}
				fmt.Println(string(jsonData))
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
