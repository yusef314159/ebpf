package protocols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// GRPCParser handles parsing of gRPC protocol messages
type GRPCParser struct {
	config *GRPCConfig
	stats  *GRPCStats
}

// GRPCConfig holds configuration for gRPC parsing
type GRPCConfig struct {
	EnableMethodExtraction  bool     `json:"enable_method_extraction" yaml:"enable_method_extraction"`
	EnableMetadataExtraction bool    `json:"enable_metadata_extraction" yaml:"enable_metadata_extraction"`
	EnablePayloadInspection bool     `json:"enable_payload_inspection" yaml:"enable_payload_inspection"`
	MaxPayloadSize          int      `json:"max_payload_size" yaml:"max_payload_size"`
	TrackedServices         []string `json:"tracked_services" yaml:"tracked_services"`
	IgnoredMethods          []string `json:"ignored_methods" yaml:"ignored_methods"`
	EnableCompression       bool     `json:"enable_compression" yaml:"enable_compression"`
	EnableStreaming         bool     `json:"enable_streaming" yaml:"enable_streaming"`
}

// GRPCStats holds statistics for gRPC parsing
type GRPCStats struct {
	RequestsParsed     uint64 `json:"requests_parsed"`
	ResponsesParsed    uint64 `json:"responses_parsed"`
	StreamingRequests  uint64 `json:"streaming_requests"`
	CompressedMessages uint64 `json:"compressed_messages"`
	ParseErrors        uint64 `json:"parse_errors"`
	MethodsExtracted   uint64 `json:"methods_extracted"`
	MetadataExtracted  uint64 `json:"metadata_extracted"`
}

// GRPCMessage represents a parsed gRPC message
type GRPCMessage struct {
	Type            string                 `json:"type"` // request, response, stream
	Service         string                 `json:"service"`
	Method          string                 `json:"method"`
	FullMethod      string                 `json:"full_method"`
	MessageType     string                 `json:"message_type"`
	Compressed      bool                   `json:"compressed"`
	Length          uint32                 `json:"length"`
	Headers         map[string]string      `json:"headers,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
	Payload         []byte                 `json:"payload,omitempty"`
	PayloadText     string                 `json:"payload_text,omitempty"`
	StatusCode      int32                  `json:"status_code,omitempty"`
	StatusMessage   string                 `json:"status_message,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	StreamID        uint32                 `json:"stream_id,omitempty"`
	IsStreaming     bool                   `json:"is_streaming"`
	FrameType       string                 `json:"frame_type,omitempty"`
	TraceContext    *tracing.TraceContext  `json:"trace_context,omitempty"`
}

// HTTP2Frame represents an HTTP/2 frame (gRPC uses HTTP/2)
type HTTP2Frame struct {
	Length   uint32 `json:"length"`
	Type     uint8  `json:"type"`
	Flags    uint8  `json:"flags"`
	StreamID uint32 `json:"stream_id"`
	Payload  []byte `json:"payload"`
}

// gRPC frame types
const (
	HTTP2FrameData         = 0x0
	HTTP2FrameHeaders      = 0x1
	HTTP2FramePriority     = 0x2
	HTTP2FrameRSTStream    = 0x3
	HTTP2FrameSettings     = 0x4
	HTTP2FramePushPromise  = 0x5
	HTTP2FramePing         = 0x6
	HTTP2FrameGoAway       = 0x7
	HTTP2FrameWindowUpdate = 0x8
	HTTP2FrameContinuation = 0x9
)

// gRPC message compression flags
const (
	GRPCCompressionNone = 0x0
	GRPCCompressionGzip = 0x1
)

// DefaultGRPCConfig returns default gRPC configuration
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		EnableMethodExtraction:   true,
		EnableMetadataExtraction: true,
		EnablePayloadInspection:  false, // Disabled by default for performance
		MaxPayloadSize:           1024,  // 1KB limit for payload inspection
		TrackedServices:          []string{}, // Empty means track all
		IgnoredMethods:           []string{"grpc.health.v1.Health/Check"},
		EnableCompression:        true,
		EnableStreaming:          true,
	}
}

// NewGRPCParser creates a new gRPC parser
func NewGRPCParser(config *GRPCConfig) *GRPCParser {
	return &GRPCParser{
		config: config,
		stats:  &GRPCStats{},
	}
}

// ParseMessage parses a gRPC message from raw data
func (gp *GRPCParser) ParseMessage(data []byte, isRequest bool) (*GRPCMessage, error) {
	if len(data) < 9 { // Minimum HTTP/2 frame header size
		return nil, fmt.Errorf("data too short for HTTP/2 frame")
	}

	// Parse HTTP/2 frame
	frame, err := gp.parseHTTP2Frame(data)
	if err != nil {
		gp.stats.ParseErrors++
		return nil, fmt.Errorf("failed to parse HTTP/2 frame: %w", err)
	}

	message := &GRPCMessage{
		Timestamp:   time.Now(),
		StreamID:    frame.StreamID,
		FrameType:   gp.getFrameTypeName(frame.Type),
		IsStreaming: frame.StreamID > 0,
	}

	if isRequest {
		message.Type = "request"
		gp.stats.RequestsParsed++
	} else {
		message.Type = "response"
		gp.stats.ResponsesParsed++
	}

	// Parse based on frame type
	switch frame.Type {
	case HTTP2FrameHeaders:
		err = gp.parseHeadersFrame(message, frame)
	case HTTP2FrameData:
		err = gp.parseDataFrame(message, frame)
	default:
		// For other frame types, just record basic information
		message.MessageType = "control"
	}

	if err != nil {
		gp.stats.ParseErrors++
		return nil, err
	}

	// Extract trace context if available
	if gp.config.EnableMetadataExtraction {
		gp.extractTraceContext(message)
	}

	return message, nil
}

// parseHTTP2Frame parses an HTTP/2 frame header and payload
func (gp *GRPCParser) parseHTTP2Frame(data []byte) (*HTTP2Frame, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("insufficient data for HTTP/2 frame header")
	}

	frame := &HTTP2Frame{}
	
	// Parse frame header (9 bytes)
	frame.Length = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	frame.Type = data[3]
	frame.Flags = data[4]
	frame.StreamID = binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF // Clear reserved bit

	// Extract payload
	if len(data) >= 9+int(frame.Length) {
		frame.Payload = data[9 : 9+frame.Length]
	}

	return frame, nil
}

// parseHeadersFrame parses an HTTP/2 HEADERS frame containing gRPC metadata
func (gp *GRPCParser) parseHeadersFrame(message *GRPCMessage, frame *HTTP2Frame) error {
	message.MessageType = "headers"
	message.Headers = make(map[string]string)
	message.Metadata = make(map[string]string)

	// Simplified HPACK decoding - in practice, you'd need a full HPACK decoder
	payload := frame.Payload
	
	// Look for common gRPC headers in the payload
	if gp.config.EnableMethodExtraction {
		if method := gp.extractMethodFromHeaders(payload); method != "" {
			message.FullMethod = method
			parts := strings.Split(method, "/")
			if len(parts) >= 3 {
				message.Service = parts[1]
				message.Method = parts[2]
			}
			gp.stats.MethodsExtracted++
		}
	}

	if gp.config.EnableMetadataExtraction {
		gp.extractMetadataFromHeaders(message, payload)
		gp.stats.MetadataExtracted++
	}

	return nil
}

// parseDataFrame parses an HTTP/2 DATA frame containing gRPC message data
func (gp *GRPCParser) parseDataFrame(message *GRPCMessage, frame *HTTP2Frame) error {
	message.MessageType = "data"
	payload := frame.Payload

	if len(payload) < 5 {
		return fmt.Errorf("gRPC message too short")
	}

	// Parse gRPC message header (5 bytes)
	compressed := payload[0]
	length := binary.BigEndian.Uint32(payload[1:5])

	message.Compressed = compressed != GRPCCompressionNone
	message.Length = length

	if message.Compressed {
		gp.stats.CompressedMessages++
	}

	// Extract message payload if enabled and within size limit
	if gp.config.EnablePayloadInspection && len(payload) >= 5 {
		messageData := payload[5:]
		if len(messageData) > gp.config.MaxPayloadSize {
			messageData = messageData[:gp.config.MaxPayloadSize]
		}
		
		message.Payload = messageData
		
		// Try to extract readable text from protobuf (simplified)
		if text := gp.extractReadableText(messageData); text != "" {
			message.PayloadText = text
		}
	}

	return nil
}

// extractMethodFromHeaders extracts the gRPC method from HEADERS frame
func (gp *GRPCParser) extractMethodFromHeaders(payload []byte) string {
	// This is a simplified implementation
	// In practice, you'd need to properly decode HPACK headers
	
	// Look for :path header which contains the gRPC method
	payloadStr := string(payload)
	
	// Common patterns for gRPC method paths
	patterns := []string{
		":path",
		"/",
	}
	
	for _, pattern := range patterns {
		if idx := strings.Index(payloadStr, pattern); idx != -1 {
			// Extract method path (simplified)
			start := idx + len(pattern)
			if start < len(payloadStr) {
				end := start
				for end < len(payloadStr) && payloadStr[end] != '\x00' && payloadStr[end] != '\n' {
					end++
				}
				if end > start {
					method := payloadStr[start:end]
					if strings.HasPrefix(method, "/") && strings.Count(method, "/") >= 2 {
						return method
					}
				}
			}
		}
	}
	
	return ""
}

// extractMetadataFromHeaders extracts gRPC metadata from headers
func (gp *GRPCParser) extractMetadataFromHeaders(message *GRPCMessage, payload []byte) {
	// Simplified metadata extraction
	payloadStr := string(payload)
	
	// Look for common gRPC headers
	headers := map[string]string{
		"grpc-timeout":     "",
		"grpc-encoding":    "",
		"content-type":     "",
		"user-agent":       "",
		"authorization":    "",
		"grpc-trace-bin":   "",
		"grpc-tags-bin":    "",
	}
	
	for header := range headers {
		if idx := strings.Index(payloadStr, header); idx != -1 {
			// Extract header value (simplified)
			start := idx + len(header) + 1 // +1 for separator
			if start < len(payloadStr) {
				end := start
				for end < len(payloadStr) && payloadStr[end] != '\x00' && payloadStr[end] != '\n' {
					end++
				}
				if end > start {
					value := payloadStr[start:end]
					message.Metadata[header] = value
				}
			}
		}
	}
}

// extractTraceContext extracts distributed tracing context from gRPC metadata
func (gp *GRPCParser) extractTraceContext(message *GRPCMessage) {
	if message.Metadata == nil {
		return
	}

	// Look for trace context in various formats
	traceContext := &tracing.TraceContext{}
	
	// Check for grpc-trace-bin (binary format)
	if traceBin, exists := message.Metadata["grpc-trace-bin"]; exists && traceBin != "" {
		// Decode binary trace context (simplified)
		traceContext.TraceID = fmt.Sprintf("grpc-trace-%x", []byte(traceBin)[:16])
		traceContext.SpanID = fmt.Sprintf("grpc-span-%x", []byte(traceBin)[16:24])
	}
	
	// Check for text-based trace headers
	if traceID, exists := message.Metadata["x-trace-id"]; exists && traceID != "" {
		traceContext.TraceID = traceID
	}
	
	if spanID, exists := message.Metadata["x-span-id"]; exists && spanID != "" {
		traceContext.SpanID = spanID
	}
	
	if traceContext.TraceID != "" || traceContext.SpanID != "" {
		message.TraceContext = traceContext
	}
}

// extractReadableText extracts readable text from protobuf message (simplified)
func (gp *GRPCParser) extractReadableText(data []byte) string {
	var result strings.Builder
	
	// Simple heuristic to extract readable strings from protobuf
	for i := 0; i < len(data); i++ {
		if data[i] >= 32 && data[i] <= 126 { // Printable ASCII
			result.WriteByte(data[i])
		} else if data[i] == 0 {
			result.WriteString(" ")
		}
	}
	
	text := result.String()
	text = strings.TrimSpace(text)
	
	// Only return if we found meaningful text
	if len(text) > 3 && strings.ContainsAny(text, "abcdefghijklmnopqrstuvwxyz") {
		return text
	}
	
	return ""
}

// getFrameTypeName returns the name of an HTTP/2 frame type
func (gp *GRPCParser) getFrameTypeName(frameType uint8) string {
	switch frameType {
	case HTTP2FrameData:
		return "DATA"
	case HTTP2FrameHeaders:
		return "HEADERS"
	case HTTP2FramePriority:
		return "PRIORITY"
	case HTTP2FrameRSTStream:
		return "RST_STREAM"
	case HTTP2FrameSettings:
		return "SETTINGS"
	case HTTP2FramePushPromise:
		return "PUSH_PROMISE"
	case HTTP2FramePing:
		return "PING"
	case HTTP2FrameGoAway:
		return "GOAWAY"
	case HTTP2FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case HTTP2FrameContinuation:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("UNKNOWN_%d", frameType)
	}
}

// IsGRPCTraffic determines if the given data represents gRPC traffic
func (gp *GRPCParser) IsGRPCTraffic(data []byte) bool {
	if len(data) < 24 { // HTTP/2 connection preface is 24 bytes
		return false
	}

	// Check for HTTP/2 connection preface
	preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if bytes.HasPrefix(data, []byte(preface)) {
		return true
	}

	// Check for HTTP/2 frame with gRPC content-type
	if len(data) >= 9 {
		frame, err := gp.parseHTTP2Frame(data)
		if err == nil && frame.Type == HTTP2FrameHeaders {
			// Look for gRPC content-type in headers
			if strings.Contains(string(frame.Payload), "application/grpc") {
				return true
			}
		}
	}

	return false
}

// ShouldTrackService determines if a service should be tracked
func (gp *GRPCParser) ShouldTrackService(service string) bool {
	// If no specific services configured, track all
	if len(gp.config.TrackedServices) == 0 {
		return true
	}

	// Check if service is in tracked list
	for _, tracked := range gp.config.TrackedServices {
		if service == tracked {
			return true
		}
	}

	return false
}

// ShouldIgnoreMethod determines if a method should be ignored
func (gp *GRPCParser) ShouldIgnoreMethod(method string) bool {
	for _, ignored := range gp.config.IgnoredMethods {
		if method == ignored {
			return true
		}
	}
	return false
}

// GetStats returns gRPC parsing statistics
func (gp *GRPCParser) GetStats() *GRPCStats {
	return gp.stats
}

// Reset resets the parser statistics
func (gp *GRPCParser) Reset() {
	gp.stats = &GRPCStats{}
}
