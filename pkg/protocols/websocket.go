package protocols

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// WebSocketParser handles parsing of WebSocket protocol messages
type WebSocketParser struct {
	config *WebSocketConfig
	stats  *WebSocketStats
}

// WebSocketConfig holds configuration for WebSocket parsing
type WebSocketConfig struct {
	EnableHandshakeTracking bool     `json:"enable_handshake_tracking" yaml:"enable_handshake_tracking"`
	EnableFrameInspection   bool     `json:"enable_frame_inspection" yaml:"enable_frame_inspection"`
	EnablePayloadInspection bool     `json:"enable_payload_inspection" yaml:"enable_payload_inspection"`
	MaxPayloadSize          int      `json:"max_payload_size" yaml:"max_payload_size"`
	TrackedSubprotocols     []string `json:"tracked_subprotocols" yaml:"tracked_subprotocols"`
	EnableCompression       bool     `json:"enable_compression" yaml:"enable_compression"`
	EnableExtensions        bool     `json:"enable_extensions" yaml:"enable_extensions"`
	MaxFrameSize            uint64   `json:"max_frame_size" yaml:"max_frame_size"`
}

// WebSocketStats holds statistics for WebSocket parsing
type WebSocketStats struct {
	HandshakesTracked   uint64 `json:"handshakes_tracked"`
	FramesParsed        uint64 `json:"frames_parsed"`
	TextFrames          uint64 `json:"text_frames"`
	BinaryFrames        uint64 `json:"binary_frames"`
	ControlFrames       uint64 `json:"control_frames"`
	CompressedFrames    uint64 `json:"compressed_frames"`
	FragmentedMessages  uint64 `json:"fragmented_messages"`
	ParseErrors         uint64 `json:"parse_errors"`
	ConnectionsUpgraded uint64 `json:"connections_upgraded"`
	ConnectionsClosed   uint64 `json:"connections_closed"`
}

// WebSocketMessage represents a parsed WebSocket message
type WebSocketMessage struct {
	Type            string            `json:"type"` // handshake, frame, close
	Direction       string            `json:"direction"` // client_to_server, server_to_client
	Timestamp       time.Time         `json:"timestamp"`
	ConnectionID    string            `json:"connection_id,omitempty"`
	
	// Handshake fields
	IsHandshake     bool              `json:"is_handshake"`
	HandshakeType   string            `json:"handshake_type,omitempty"` // request, response
	HTTPVersion     string            `json:"http_version,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Subprotocols    []string          `json:"subprotocols,omitempty"`
	Extensions      []string          `json:"extensions,omitempty"`
	WebSocketKey    string            `json:"websocket_key,omitempty"`
	WebSocketAccept string            `json:"websocket_accept,omitempty"`
	
	// Frame fields
	IsFrame         bool              `json:"is_frame"`
	Frame           *WebSocketFrame   `json:"frame,omitempty"`
	
	// Message assembly (for fragmented messages)
	IsComplete      bool              `json:"is_complete"`
	FragmentCount   int               `json:"fragment_count,omitempty"`
	TotalLength     uint64            `json:"total_length,omitempty"`
	
	// Payload
	Payload         []byte            `json:"payload,omitempty"`
	PayloadText     string            `json:"payload_text,omitempty"`
	PayloadSize     uint64            `json:"payload_size"`
	
	// Metadata
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// WebSocketFrame represents a WebSocket frame
type WebSocketFrame struct {
	FIN             bool   `json:"fin"`
	RSV1            bool   `json:"rsv1"`
	RSV2            bool   `json:"rsv2"`
	RSV3            bool   `json:"rsv3"`
	Opcode          uint8  `json:"opcode"`
	OpcodeText      string `json:"opcode_text"`
	Masked          bool   `json:"masked"`
	PayloadLength   uint64 `json:"payload_length"`
	MaskingKey      []byte `json:"masking_key,omitempty"`
	PayloadData     []byte `json:"payload_data,omitempty"`
	IsControlFrame  bool   `json:"is_control_frame"`
	IsDataFrame     bool   `json:"is_data_frame"`
}

// WebSocket opcodes
const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

// WebSocket magic string for handshake
const WebSocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// DefaultWebSocketConfig returns default WebSocket configuration
func DefaultWebSocketConfig() *WebSocketConfig {
	return &WebSocketConfig{
		EnableHandshakeTracking: true,
		EnableFrameInspection:   true,
		EnablePayloadInspection: false, // Disabled by default for performance
		MaxPayloadSize:          1024,  // 1KB limit
		TrackedSubprotocols:     []string{}, // Empty means track all
		EnableCompression:       true,
		EnableExtensions:        true,
		MaxFrameSize:            1024 * 1024, // 1MB max frame size
	}
}

// NewWebSocketParser creates a new WebSocket parser
func NewWebSocketParser(config *WebSocketConfig) *WebSocketParser {
	return &WebSocketParser{
		config: config,
		stats:  &WebSocketStats{},
	}
}

// ParseMessage parses a WebSocket message from raw data
func (wsp *WebSocketParser) ParseMessage(data []byte, isClientToServer bool) (*WebSocketMessage, error) {
	message := &WebSocketMessage{
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	if isClientToServer {
		message.Direction = "client_to_server"
	} else {
		message.Direction = "server_to_client"
	}

	// Check if this is a WebSocket handshake
	if wsp.isHandshake(data) {
		return wsp.parseHandshake(message, data)
	}

	// Otherwise, parse as WebSocket frame
	return wsp.parseFrame(message, data)
}

// isHandshake determines if the data represents a WebSocket handshake
func (wsp *WebSocketParser) isHandshake(data []byte) bool {
	dataStr := string(data)
	
	// Check for HTTP request/response patterns
	if strings.HasPrefix(dataStr, "GET ") && strings.Contains(dataStr, "Upgrade: websocket") {
		return true
	}
	
	if strings.HasPrefix(dataStr, "HTTP/") && strings.Contains(dataStr, "Upgrade: websocket") {
		return true
	}
	
	return false
}

// parseHandshake parses a WebSocket handshake request or response
func (wsp *WebSocketParser) parseHandshake(message *WebSocketMessage, data []byte) (*WebSocketMessage, error) {
	message.Type = "handshake"
	message.IsHandshake = true
	message.Headers = make(map[string]string)
	
	dataStr := string(data)
	lines := strings.Split(dataStr, "\r\n")
	
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty handshake data")
	}
	
	// Parse first line
	firstLine := lines[0]
	if strings.HasPrefix(firstLine, "GET ") {
		// Client handshake request
		message.HandshakeType = "request"
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 3 {
			message.HTTPVersion = parts[2]
		}
	} else if strings.HasPrefix(firstLine, "HTTP/") {
		// Server handshake response
		message.HandshakeType = "response"
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 3 {
			message.HTTPVersion = parts[0]
			if len(parts[1]) > 0 {
				fmt.Sscanf(parts[1], "%d", &message.StatusCode)
			}
		}
	}
	
	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			message.Headers[key] = value
		}
	}
	
	// Extract WebSocket-specific headers
	if key, exists := message.Headers["sec-websocket-key"]; exists {
		message.WebSocketKey = key
	}
	
	if accept, exists := message.Headers["sec-websocket-accept"]; exists {
		message.WebSocketAccept = accept
	}
	
	if protocol, exists := message.Headers["sec-websocket-protocol"]; exists {
		message.Subprotocols = strings.Split(protocol, ",")
		for i := range message.Subprotocols {
			message.Subprotocols[i] = strings.TrimSpace(message.Subprotocols[i])
		}
	}
	
	if extensions, exists := message.Headers["sec-websocket-extensions"]; exists {
		message.Extensions = strings.Split(extensions, ",")
		for i := range message.Extensions {
			message.Extensions[i] = strings.TrimSpace(message.Extensions[i])
		}
	}
	
	// Validate handshake if it's a response
	if message.HandshakeType == "response" && message.WebSocketKey != "" {
		expectedAccept := wsp.calculateWebSocketAccept(message.WebSocketKey)
		if message.WebSocketAccept == expectedAccept {
			message.Metadata["handshake_valid"] = "true"
			wsp.stats.ConnectionsUpgraded++
		} else {
			message.Metadata["handshake_valid"] = "false"
		}
	}
	
	wsp.stats.HandshakesTracked++
	return message, nil
}

// parseFrame parses a WebSocket frame
func (wsp *WebSocketParser) parseFrame(message *WebSocketMessage, data []byte) (*WebSocketMessage, error) {
	message.Type = "frame"
	message.IsFrame = true
	
	if len(data) < 2 {
		wsp.stats.ParseErrors++
		return nil, fmt.Errorf("frame too short")
	}
	
	frame := &WebSocketFrame{}
	offset := 0
	
	// Parse first byte (FIN + RSV + Opcode)
	firstByte := data[offset]
	frame.FIN = (firstByte & 0x80) != 0
	frame.RSV1 = (firstByte & 0x40) != 0
	frame.RSV2 = (firstByte & 0x20) != 0
	frame.RSV3 = (firstByte & 0x10) != 0
	frame.Opcode = firstByte & 0x0F
	frame.OpcodeText = wsp.getOpcodeText(frame.Opcode)
	frame.IsControlFrame = frame.Opcode >= 0x8
	frame.IsDataFrame = frame.Opcode <= 0x2
	offset++
	
	// Parse second byte (MASK + Payload length)
	secondByte := data[offset]
	frame.Masked = (secondByte & 0x80) != 0
	payloadLen := uint64(secondByte & 0x7F)
	offset++
	
	// Parse extended payload length
	if payloadLen == 126 {
		if len(data) < offset+2 {
			wsp.stats.ParseErrors++
			return nil, fmt.Errorf("insufficient data for extended payload length")
		}
		payloadLen = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
	} else if payloadLen == 127 {
		if len(data) < offset+8 {
			wsp.stats.ParseErrors++
			return nil, fmt.Errorf("insufficient data for extended payload length")
		}
		payloadLen = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	
	frame.PayloadLength = payloadLen
	
	// Check frame size limit
	if payloadLen > wsp.config.MaxFrameSize {
		wsp.stats.ParseErrors++
		return nil, fmt.Errorf("frame size %d exceeds limit %d", payloadLen, wsp.config.MaxFrameSize)
	}
	
	// Parse masking key if present
	if frame.Masked {
		if len(data) < offset+4 {
			wsp.stats.ParseErrors++
			return nil, fmt.Errorf("insufficient data for masking key")
		}
		frame.MaskingKey = data[offset : offset+4]
		offset += 4
	}
	
	// Parse payload data
	if payloadLen > 0 {
		if len(data) < offset+int(payloadLen) {
			wsp.stats.ParseErrors++
			return nil, fmt.Errorf("insufficient data for payload")
		}
		
		frame.PayloadData = data[offset : offset+int(payloadLen)]
		
		// Unmask payload if masked
		if frame.Masked {
			for i := range frame.PayloadData {
				frame.PayloadData[i] ^= frame.MaskingKey[i%4]
			}
		}
	}
	
	message.Frame = frame
	message.PayloadSize = payloadLen
	
	// Extract payload for inspection if enabled
	if wsp.config.EnablePayloadInspection && payloadLen > 0 {
		maxSize := wsp.config.MaxPayloadSize
		if int(payloadLen) < maxSize {
			maxSize = int(payloadLen)
		}
		
		message.Payload = frame.PayloadData[:maxSize]
		
		// For text frames, try to extract readable text
		if frame.Opcode == OpcodeText {
			message.PayloadText = string(frame.PayloadData)
		}
	}
	
	// Handle different frame types
	switch frame.Opcode {
	case OpcodeText:
		wsp.stats.TextFrames++
	case OpcodeBinary:
		wsp.stats.BinaryFrames++
	case OpcodeClose:
		wsp.stats.ControlFrames++
		wsp.stats.ConnectionsClosed++
		wsp.parseCloseFrame(message, frame)
	case OpcodePing, OpcodePong:
		wsp.stats.ControlFrames++
	case OpcodeContinuation:
		wsp.stats.FragmentedMessages++
	}
	
	// Check for compression (RSV1 bit)
	if frame.RSV1 {
		wsp.stats.CompressedFrames++
		message.Metadata["compressed"] = "true"
	}
	
	// Mark message as complete if FIN bit is set
	message.IsComplete = frame.FIN
	
	wsp.stats.FramesParsed++
	return message, nil
}

// parseCloseFrame parses a WebSocket close frame
func (wsp *WebSocketParser) parseCloseFrame(message *WebSocketMessage, frame *WebSocketFrame) {
	if len(frame.PayloadData) >= 2 {
		closeCode := binary.BigEndian.Uint16(frame.PayloadData[:2])
		message.Metadata["close_code"] = fmt.Sprintf("%d", closeCode)
		
		if len(frame.PayloadData) > 2 {
			closeReason := string(frame.PayloadData[2:])
			message.Metadata["close_reason"] = closeReason
		}
	}
}

// getOpcodeText returns the text representation of an opcode
func (wsp *WebSocketParser) getOpcodeText(opcode uint8) string {
	switch opcode {
	case OpcodeContinuation:
		return "CONTINUATION"
	case OpcodeText:
		return "TEXT"
	case OpcodeBinary:
		return "BINARY"
	case OpcodeClose:
		return "CLOSE"
	case OpcodePing:
		return "PING"
	case OpcodePong:
		return "PONG"
	default:
		return fmt.Sprintf("UNKNOWN_%d", opcode)
	}
}

// calculateWebSocketAccept calculates the WebSocket accept value
func (wsp *WebSocketParser) calculateWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + WebSocketMagicString))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// IsWebSocketTraffic determines if the given data represents WebSocket traffic
func (wsp *WebSocketParser) IsWebSocketTraffic(data []byte) bool {
	dataStr := string(data)
	
	// Check for WebSocket handshake
	if strings.Contains(dataStr, "Upgrade: websocket") ||
		strings.Contains(dataStr, "Sec-WebSocket-Key") ||
		strings.Contains(dataStr, "Sec-WebSocket-Accept") {
		return true
	}
	
	// Check for WebSocket frame (basic heuristic)
	if len(data) >= 2 {
		firstByte := data[0]
		secondByte := data[1]
		
		// Check if opcode is valid
		opcode := firstByte & 0x0F
		if opcode <= 0x2 || (opcode >= 0x8 && opcode <= 0xA) {
			// Check if payload length is reasonable
			payloadLen := secondByte & 0x7F
			if payloadLen <= 125 || payloadLen == 126 || payloadLen == 127 {
				return true
			}
		}
	}
	
	return false
}

// ShouldTrackSubprotocol determines if a subprotocol should be tracked
func (wsp *WebSocketParser) ShouldTrackSubprotocol(subprotocol string) bool {
	// If no specific subprotocols configured, track all
	if len(wsp.config.TrackedSubprotocols) == 0 {
		return true
	}
	
	// Check if subprotocol is in tracked list
	for _, tracked := range wsp.config.TrackedSubprotocols {
		if subprotocol == tracked {
			return true
		}
	}
	
	return false
}

// GetStats returns WebSocket parsing statistics
func (wsp *WebSocketParser) GetStats() *WebSocketStats {
	return wsp.stats
}

// Reset resets the parser statistics
func (wsp *WebSocketParser) Reset() {
	wsp.stats = &WebSocketStats{}
}
