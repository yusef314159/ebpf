package protocols

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// ProtocolManager manages multiple protocol parsers
type ProtocolManager struct {
	httpParser      *HTTPParser
	grpcParser      *GRPCParser
	websocketParser *WebSocketParser
	tcpParser       *TCPParser
	config          *ProtocolConfig
	stats           *ProtocolStats
	mutex           sync.RWMutex
}

// ProtocolConfig holds configuration for all protocol parsers
type ProtocolConfig struct {
	EnableHTTP      bool             `json:"enable_http" yaml:"enable_http"`
	EnableGRPC      bool             `json:"enable_grpc" yaml:"enable_grpc"`
	EnableWebSocket bool             `json:"enable_websocket" yaml:"enable_websocket"`
	EnableTCP       bool             `json:"enable_tcp" yaml:"enable_tcp"`
	AutoDetection   bool             `json:"auto_detection" yaml:"auto_detection"`
	HTTPConfig      *HTTPConfig      `json:"http_config" yaml:"http_config"`
	GRPCConfig      *GRPCConfig      `json:"grpc_config" yaml:"grpc_config"`
	WebSocketConfig *WebSocketConfig `json:"websocket_config" yaml:"websocket_config"`
	TCPConfig       *TCPConfig       `json:"tcp_config" yaml:"tcp_config"`
}

// ProtocolStats holds statistics for all protocol parsers
type ProtocolStats struct {
	HTTPMessages      uint64            `json:"http_messages"`
	GRPCMessages      uint64            `json:"grpc_messages"`
	WebSocketMessages uint64            `json:"websocket_messages"`
	TCPMessages       uint64            `json:"tcp_messages"`
	UnknownMessages   uint64            `json:"unknown_messages"`
	TotalMessages     uint64            `json:"total_messages"`
	DetectionErrors   uint64            `json:"detection_errors"`
	ParsingErrors     uint64            `json:"parsing_errors"`
	LastUpdate        time.Time         `json:"last_update"`
	ProtocolBreakdown map[string]uint64 `json:"protocol_breakdown"`
}

// ParsedMessage represents a message parsed by any protocol parser
type ParsedMessage struct {
	Protocol        string                 `json:"protocol"`
	Type            string                 `json:"type"`
	Timestamp       time.Time              `json:"timestamp"`
	SourceIP        string                 `json:"source_ip,omitempty"`
	DestIP          string                 `json:"dest_ip,omitempty"`
	SourcePort      uint16                 `json:"source_port,omitempty"`
	DestPort        uint16                 `json:"dest_port,omitempty"`
	Direction       string                 `json:"direction"`
	Size            uint64                 `json:"size"`
	
	// Protocol-specific data
	HTTPMessage      *HTTPMessage      `json:"http_message,omitempty"`
	GRPCMessage      *GRPCMessage      `json:"grpc_message,omitempty"`
	WebSocketMessage *WebSocketMessage `json:"websocket_message,omitempty"`
	TCPMessage       *TCPMessage       `json:"tcp_message,omitempty"`
	
	// Common fields
	TraceContext    *tracing.TraceContext  `json:"trace_context,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	RawData         []byte                 `json:"raw_data,omitempty"`
}

// HTTPConfig placeholder (would be defined in http.go)
type HTTPConfig struct {
	EnableMethodExtraction bool `json:"enable_method_extraction" yaml:"enable_method_extraction"`
	EnableHeaderExtraction bool `json:"enable_header_extraction" yaml:"enable_header_extraction"`
	MaxPayloadSize         int  `json:"max_payload_size" yaml:"max_payload_size"`
}

// TCPConfig placeholder for TCP protocol parsing
type TCPConfig struct {
	EnablePayloadInspection bool `json:"enable_payload_inspection" yaml:"enable_payload_inspection"`
	MaxPayloadSize          int  `json:"max_payload_size" yaml:"max_payload_size"`
	EnableConnectionTracking bool `json:"enable_connection_tracking" yaml:"enable_connection_tracking"`
}

// HTTPMessage placeholder (would be defined in http.go)
type HTTPMessage struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	StatusCode  int               `json:"status_code,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Version     string            `json:"version"`
}

// TCPMessage represents a parsed TCP message
type TCPMessage struct {
	Flags       uint8             `json:"flags"`
	SeqNumber   uint32            `json:"seq_number"`
	AckNumber   uint32            `json:"ack_number"`
	WindowSize  uint16            `json:"window_size"`
	Payload     []byte            `json:"payload,omitempty"`
	PayloadText string            `json:"payload_text,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// HTTPParser placeholder
type HTTPParser struct{}
func (hp *HTTPParser) ParseMessage(data []byte, isRequest bool) (*HTTPMessage, error) {
	return &HTTPMessage{}, nil
}
func (hp *HTTPParser) IsHTTPTraffic(data []byte) bool { return false }

// TCPParser placeholder
type TCPParser struct{}
func (tp *TCPParser) ParseMessage(data []byte) (*TCPMessage, error) {
	return &TCPMessage{}, nil
}
func (tp *TCPParser) IsTCPTraffic(data []byte) bool { return true }

// DefaultProtocolConfig returns default protocol configuration
func DefaultProtocolConfig() *ProtocolConfig {
	return &ProtocolConfig{
		EnableHTTP:      true,
		EnableGRPC:      true,
		EnableWebSocket: true,
		EnableTCP:       false, // Disabled by default as it's very verbose
		AutoDetection:   true,
		HTTPConfig:      &HTTPConfig{
			EnableMethodExtraction: true,
			EnableHeaderExtraction: true,
			MaxPayloadSize:         1024,
		},
		GRPCConfig:      DefaultGRPCConfig(),
		WebSocketConfig: DefaultWebSocketConfig(),
		TCPConfig:       &TCPConfig{
			EnablePayloadInspection:  false,
			MaxPayloadSize:           512,
			EnableConnectionTracking: true,
		},
	}
}

// NewProtocolManager creates a new protocol manager
func NewProtocolManager(config *ProtocolConfig) *ProtocolManager {
	pm := &ProtocolManager{
		config: config,
		stats: &ProtocolStats{
			ProtocolBreakdown: make(map[string]uint64),
		},
	}

	// Initialize parsers based on configuration
	if config.EnableHTTP {
		pm.httpParser = &HTTPParser{}
	}

	if config.EnableGRPC {
		pm.grpcParser = NewGRPCParser(config.GRPCConfig)
	}

	if config.EnableWebSocket {
		pm.websocketParser = NewWebSocketParser(config.WebSocketConfig)
	}

	if config.EnableTCP {
		pm.tcpParser = &TCPParser{}
	}

	return pm
}

// ParseMessage parses a message using the appropriate protocol parser
func (pm *ProtocolManager) ParseMessage(data []byte, sourceIP, destIP string, sourcePort, destPort uint16, isRequest bool) (*ParsedMessage, error) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	message := &ParsedMessage{
		Timestamp:  time.Now(),
		SourceIP:   sourceIP,
		DestIP:     destIP,
		SourcePort: sourcePort,
		DestPort:   destPort,
		Size:       uint64(len(data)),
		Metadata:   make(map[string]interface{}),
	}

	if isRequest {
		message.Direction = "request"
	} else {
		message.Direction = "response"
	}

	// Auto-detect protocol if enabled
	if pm.config.AutoDetection {
		protocol := pm.detectProtocol(data, destPort)
		message.Protocol = protocol
	}

	// Parse based on detected or configured protocol
	var err error
	switch message.Protocol {
	case "http":
		err = pm.parseHTTP(message, data, isRequest)
	case "grpc":
		err = pm.parseGRPC(message, data, isRequest)
	case "websocket":
		err = pm.parseWebSocket(message, data, isRequest)
	case "tcp":
		err = pm.parseTCP(message, data)
	default:
		// Try all parsers if auto-detection failed
		if pm.tryAllParsers(message, data, isRequest) {
			err = nil
		} else {
			message.Protocol = "unknown"
			pm.stats.UnknownMessages++
		}
	}

	if err != nil {
		pm.stats.ParsingErrors++
		return nil, fmt.Errorf("failed to parse %s message: %w", message.Protocol, err)
	}

	// Update statistics
	pm.updateStats(message.Protocol)

	return message, nil
}

// detectProtocol attempts to detect the protocol from the data
func (pm *ProtocolManager) detectProtocol(data []byte, destPort uint16) string {
	// Check common ports first
	switch destPort {
	case 80, 8080, 8000, 3000:
		if pm.config.EnableHTTP && pm.httpParser != nil && pm.httpParser.IsHTTPTraffic(data) {
			return "http"
		}
	case 443, 8443:
		// HTTPS - could be HTTP, gRPC, or WebSocket over TLS
		if pm.config.EnableGRPC && pm.grpcParser != nil && pm.grpcParser.IsGRPCTraffic(data) {
			return "grpc"
		}
		if pm.config.EnableWebSocket && pm.websocketParser != nil && pm.websocketParser.IsWebSocketTraffic(data) {
			return "websocket"
		}
		if pm.config.EnableHTTP && pm.httpParser != nil && pm.httpParser.IsHTTPTraffic(data) {
			return "http"
		}
	}

	// Content-based detection
	dataStr := strings.ToLower(string(data[:min(len(data), 100)]))

	// Check for HTTP
	if pm.config.EnableHTTP && pm.httpParser != nil {
		if strings.HasPrefix(dataStr, "get ") || strings.HasPrefix(dataStr, "post ") ||
			strings.HasPrefix(dataStr, "put ") || strings.HasPrefix(dataStr, "delete ") ||
			strings.HasPrefix(dataStr, "http/") {
			return "http"
		}
	}

	// Check for gRPC
	if pm.config.EnableGRPC && pm.grpcParser != nil && pm.grpcParser.IsGRPCTraffic(data) {
		return "grpc"
	}

	// Check for WebSocket
	if pm.config.EnableWebSocket && pm.websocketParser != nil && pm.websocketParser.IsWebSocketTraffic(data) {
		return "websocket"
	}

	// Default to TCP if enabled
	if pm.config.EnableTCP {
		return "tcp"
	}

	return "unknown"
}

// tryAllParsers tries all available parsers
func (pm *ProtocolManager) tryAllParsers(message *ParsedMessage, data []byte, isRequest bool) bool {
	// Try HTTP
	if pm.config.EnableHTTP && pm.httpParser != nil {
		if err := pm.parseHTTP(message, data, isRequest); err == nil {
			message.Protocol = "http"
			return true
		}
	}

	// Try gRPC
	if pm.config.EnableGRPC && pm.grpcParser != nil {
		if err := pm.parseGRPC(message, data, isRequest); err == nil {
			message.Protocol = "grpc"
			return true
		}
	}

	// Try WebSocket
	if pm.config.EnableWebSocket && pm.websocketParser != nil {
		if err := pm.parseWebSocket(message, data, isRequest); err == nil {
			message.Protocol = "websocket"
			return true
		}
	}

	// Try TCP
	if pm.config.EnableTCP && pm.tcpParser != nil {
		if err := pm.parseTCP(message, data); err == nil {
			message.Protocol = "tcp"
			return true
		}
	}

	return false
}

// parseHTTP parses HTTP message
func (pm *ProtocolManager) parseHTTP(message *ParsedMessage, data []byte, isRequest bool) error {
	httpMsg, err := pm.httpParser.ParseMessage(data, isRequest)
	if err != nil {
		return err
	}
	
	message.HTTPMessage = httpMsg
	message.Type = "http"
	return nil
}

// parseGRPC parses gRPC message
func (pm *ProtocolManager) parseGRPC(message *ParsedMessage, data []byte, isRequest bool) error {
	grpcMsg, err := pm.grpcParser.ParseMessage(data, isRequest)
	if err != nil {
		return err
	}
	
	message.GRPCMessage = grpcMsg
	message.Type = "grpc"
	
	// Extract trace context if available
	if grpcMsg.TraceContext != nil {
		message.TraceContext = grpcMsg.TraceContext
	}
	
	return nil
}

// parseWebSocket parses WebSocket message
func (pm *ProtocolManager) parseWebSocket(message *ParsedMessage, data []byte, isRequest bool) error {
	wsMsg, err := pm.websocketParser.ParseMessage(data, isRequest)
	if err != nil {
		return err
	}
	
	message.WebSocketMessage = wsMsg
	message.Type = "websocket"
	return nil
}

// parseTCP parses TCP message
func (pm *ProtocolManager) parseTCP(message *ParsedMessage, data []byte) error {
	tcpMsg, err := pm.tcpParser.ParseMessage(data)
	if err != nil {
		return err
	}
	
	message.TCPMessage = tcpMsg
	message.Type = "tcp"
	return nil
}

// updateStats updates protocol statistics
func (pm *ProtocolManager) updateStats(protocol string) {
	pm.stats.TotalMessages++
	pm.stats.LastUpdate = time.Now()
	pm.stats.ProtocolBreakdown[protocol]++

	switch protocol {
	case "http":
		pm.stats.HTTPMessages++
	case "grpc":
		pm.stats.GRPCMessages++
	case "websocket":
		pm.stats.WebSocketMessages++
	case "tcp":
		pm.stats.TCPMessages++
	default:
		pm.stats.UnknownMessages++
	}
}

// GetStats returns protocol parsing statistics
func (pm *ProtocolManager) GetStats() *ProtocolStats {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	// Create a copy to avoid race conditions
	stats := *pm.stats
	stats.ProtocolBreakdown = make(map[string]uint64)
	for k, v := range pm.stats.ProtocolBreakdown {
		stats.ProtocolBreakdown[k] = v
	}

	return &stats
}

// GetDetailedStats returns detailed statistics from all parsers
func (pm *ProtocolManager) GetDetailedStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if pm.grpcParser != nil {
		stats["grpc"] = pm.grpcParser.GetStats()
	}

	if pm.websocketParser != nil {
		stats["websocket"] = pm.websocketParser.GetStats()
	}

	stats["overall"] = pm.GetStats()

	return stats
}

// Reset resets all parser statistics
func (pm *ProtocolManager) Reset() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.stats = &ProtocolStats{
		ProtocolBreakdown: make(map[string]uint64),
	}

	if pm.grpcParser != nil {
		pm.grpcParser.Reset()
	}

	if pm.websocketParser != nil {
		pm.websocketParser.Reset()
	}
}

// Close shuts down the protocol manager
func (pm *ProtocolManager) Close() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.httpParser = nil
	pm.grpcParser = nil
	pm.websocketParser = nil
	pm.tcpParser = nil

	return nil
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
