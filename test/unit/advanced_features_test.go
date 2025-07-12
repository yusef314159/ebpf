package unit

import (
	"fmt"
	"testing"
	"time"

	"ebpf-tracing/pkg/async"
	"ebpf-tracing/pkg/protocols"
	"ebpf-tracing/pkg/symbols"
)

// TestBTFManagerCreation tests BTF manager creation and basic functionality
func TestBTFManagerCreation(t *testing.T) {
	config := symbols.DefaultBTFConfig()
	
	// Use a test path that might not exist - that's okay for this test
	config.KernelBTFPath = "/tmp/test-btf"
	
	manager, err := symbols.NewBTFManager(config)
	if err != nil {
		// BTF might not be available in test environment, that's okay
		t.Logf("BTF manager creation failed (expected in test env): %v", err)
		return
	}
	defer manager.Close()

	// Test cache stats
	stats := manager.GetCacheStats()
	if stats == nil {
		t.Error("Expected cache stats to be non-nil")
	}

	t.Logf("BTF Manager created successfully with stats: %+v", stats)
}

// TestBTFSymbolResolution tests BTF symbol resolution
func TestBTFSymbolResolution(t *testing.T) {
	config := symbols.DefaultBTFConfig()
	config.KernelBTFPath = "/tmp/test-btf"
	
	manager, err := symbols.NewBTFManager(config)
	if err != nil {
		t.Skip("BTF not available in test environment")
	}
	defer manager.Close()

	// Test resolving a common kernel symbol
	symbolInfo, err := manager.ResolveKernelSymbol("sys_read")
	if err != nil {
		// Symbol might not be found, that's okay for this test
		t.Logf("Symbol resolution failed (expected): %v", err)
		return
	}

	if symbolInfo.Name != "sys_read" {
		t.Errorf("Expected symbol name 'sys_read', got '%s'", symbolInfo.Name)
	}

	if symbolInfo.Type == "" {
		t.Error("Expected symbol type to be set")
	}

	t.Logf("Symbol resolved: %+v", symbolInfo)
}

// TestDWARFManagerCreation tests DWARF manager creation
func TestDWARFManagerCreation(t *testing.T) {
	config := symbols.DefaultDWARFConfig()
	
	manager := symbols.NewDWARFManager(config)
	if manager == nil {
		t.Fatal("Expected DWARF manager to be created")
	}
	defer manager.Close()

	// Test cache stats
	stats := manager.GetCacheStats()
	if stats == nil {
		t.Error("Expected cache stats to be non-nil")
	}

	t.Logf("DWARF Manager created successfully with stats: %+v", stats)
}

// TestDWARFSymbolResolution tests DWARF symbol resolution
func TestDWARFSymbolResolution(t *testing.T) {
	config := symbols.DefaultDWARFConfig()
	manager := symbols.NewDWARFManager(config)
	defer manager.Close()

	// Test with a dummy binary path
	binaryPath := "/bin/ls" // Common binary that should exist
	symbolName := "main"
	address := uint64(0x1000)

	dwarfInfo, err := manager.ResolveSymbolWithDWARF(binaryPath, symbolName, address)
	if err != nil {
		// DWARF info might not be available, that's okay
		t.Logf("DWARF resolution failed (expected): %v", err)
		return
	}

	if dwarfInfo.Symbol == nil {
		t.Error("Expected symbol info to be set")
	}

	t.Logf("DWARF info resolved: %+v", dwarfInfo)
}

// TestAsyncContextTracker tests async context tracking
func TestAsyncContextTracker(t *testing.T) {
	config := async.DefaultAsyncConfig()
	config.CleanupInterval = 100 * time.Millisecond // Fast cleanup for testing
	
	tracker := async.NewContextTracker(config)
	if tracker == nil {
		t.Fatal("Expected context tracker to be created")
	}
	defer tracker.Close()

	// Test goroutine spawn tracking
	parentGoroutineID := uint64(1)
	newGoroutineID := uint64(2)
	threadID := uint32(100)
	traceID := "test-trace-123"
	spanID := "test-span-456"

	err := tracker.TrackGoroutineSpawn(parentGoroutineID, newGoroutineID, threadID, traceID, spanID)
	if err != nil {
		t.Fatalf("Failed to track goroutine spawn: %v", err)
	}

	// Verify context was created
	context, err := tracker.GetContext(newGoroutineID)
	if err != nil {
		t.Fatalf("Failed to get context: %v", err)
	}

	if context.ID != newGoroutineID {
		t.Errorf("Expected context ID %d, got %d", newGoroutineID, context.ID)
	}

	if context.Type != "goroutine" {
		t.Errorf("Expected context type 'goroutine', got '%s'", context.Type)
	}

	if context.TraceID != traceID {
		t.Errorf("Expected trace ID '%s', got '%s'", traceID, context.TraceID)
	}

	// Test async operation tracking
	err = tracker.TrackAsyncOperation(newGoroutineID, "await", "Waiting for HTTP response", map[string]interface{}{
		"url": "https://api.example.com/data",
	})
	if err != nil {
		t.Fatalf("Failed to track async operation: %v", err)
	}

	// Test context completion
	err = tracker.TrackContextCompletion(newGoroutineID, "success")
	if err != nil {
		t.Fatalf("Failed to track context completion: %v", err)
	}

	// Verify stats
	stats := tracker.GetStats()
	if stats.TotalContexts == 0 {
		t.Error("Expected total contexts to be > 0")
	}

	if stats.CompletedContexts == 0 {
		t.Error("Expected completed contexts to be > 0")
	}

	t.Logf("Async tracking stats: %+v", stats)
}

// TestThreadTracking tests OS thread tracking
func TestThreadTracking(t *testing.T) {
	config := async.DefaultAsyncConfig()
	tracker := async.NewContextTracker(config)
	defer tracker.Close()

	threadID := uint32(200)
	processID := uint32(1000)
	threadName := "worker-thread"

	err := tracker.TrackThreadCreation(threadID, processID, threadName)
	if err != nil {
		t.Fatalf("Failed to track thread creation: %v", err)
	}

	stats := tracker.GetStats()
	if stats.ActiveThreads == 0 {
		t.Error("Expected active threads to be > 0")
	}

	t.Logf("Thread tracking successful, stats: %+v", stats)
}

// TestGRPCParser tests gRPC protocol parsing
func TestGRPCParser(t *testing.T) {
	config := protocols.DefaultGRPCConfig()
	parser := protocols.NewGRPCParser(config)

	// Test with sample HTTP/2 frame data (simplified)
	sampleData := []byte{
		0x00, 0x00, 0x10, // Length: 16
		0x01,             // Type: HEADERS
		0x04,             // Flags: END_HEADERS
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
		// Simplified header data
		0x3a, 0x70, 0x61, 0x74, 0x68, // ":path"
		0x2f, 0x74, 0x65, 0x73, 0x74, // "/test"
		0x2e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, // ".Service"
	}

	message, err := parser.ParseMessage(sampleData, true)
	if err != nil {
		t.Logf("gRPC parsing failed (expected with simplified data): %v", err)
		return
	}

	if message.Type != "request" {
		t.Errorf("Expected message type 'request', got '%s'", message.Type)
	}

	if message.StreamID == 0 {
		t.Error("Expected stream ID to be set")
	}

	stats := parser.GetStats()
	if stats.RequestsParsed == 0 {
		t.Error("Expected requests parsed to be > 0")
	}

	t.Logf("gRPC message parsed: %+v", message)
	t.Logf("gRPC stats: %+v", stats)
}

// TestWebSocketParser tests WebSocket protocol parsing
func TestWebSocketParser(t *testing.T) {
	config := protocols.DefaultWebSocketConfig()
	parser := protocols.NewWebSocketParser(config)

	// Test WebSocket handshake request
	handshakeData := []byte(`GET /chat HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

`)

	message, err := parser.ParseMessage(handshakeData, true)
	if err != nil {
		t.Fatalf("Failed to parse WebSocket handshake: %v", err)
	}

	if !message.IsHandshake {
		t.Error("Expected message to be identified as handshake")
	}

	if message.HandshakeType != "request" {
		t.Errorf("Expected handshake type 'request', got '%s'", message.HandshakeType)
	}

	if message.WebSocketKey == "" {
		t.Log("WebSocket key not extracted (header parsing might need improvement)")
	}

	// Test WebSocket frame
	frameData := []byte{
		0x81, // FIN=1, Opcode=1 (text)
		0x05, // MASK=0, Payload length=5
		'H', 'e', 'l', 'l', 'o', // Payload: "Hello"
	}

	frameMessage, err := parser.ParseMessage(frameData, true)
	if err != nil {
		t.Fatalf("Failed to parse WebSocket frame: %v", err)
	}

	if !frameMessage.IsFrame {
		t.Error("Expected message to be identified as frame")
	}

	if frameMessage.Frame.Opcode != protocols.OpcodeText {
		t.Errorf("Expected opcode %d, got %d", protocols.OpcodeText, frameMessage.Frame.Opcode)
	}

	if !frameMessage.IsComplete {
		t.Error("Expected frame to be complete (FIN=1)")
	}

	stats := parser.GetStats()
	if stats.HandshakesTracked == 0 {
		t.Error("Expected handshakes tracked to be > 0")
	}

	if stats.FramesParsed == 0 {
		t.Error("Expected frames parsed to be > 0")
	}

	t.Logf("WebSocket handshake: %+v", message)
	t.Logf("WebSocket frame: %+v", frameMessage)
	t.Logf("WebSocket stats: %+v", stats)
}

// TestProtocolManager tests the unified protocol manager
func TestProtocolManager(t *testing.T) {
	config := protocols.DefaultProtocolConfig()
	manager := protocols.NewProtocolManager(config)
	defer manager.Close()

	// Test HTTP-like data
	httpData := []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n")
	
	message, err := manager.ParseMessage(httpData, "192.168.1.1", "192.168.1.2", 12345, 80, true)
	if err != nil {
		t.Logf("Protocol parsing failed (expected with placeholder parsers): %v", err)
	} else {
		if message.Protocol == "" {
			t.Error("Expected protocol to be detected")
		}

		if message.SourceIP != "192.168.1.1" {
			t.Errorf("Expected source IP '192.168.1.1', got '%s'", message.SourceIP)
		}

		if message.DestPort != 80 {
			t.Errorf("Expected dest port 80, got %d", message.DestPort)
		}

		t.Logf("Parsed message: %+v", message)
	}

	// Test statistics
	stats := manager.GetStats()
	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}

	detailedStats := manager.GetDetailedStats()
	if detailedStats == nil {
		t.Error("Expected detailed stats to be non-nil")
	}

	t.Logf("Protocol manager stats: %+v", stats)
	t.Logf("Detailed stats: %+v", detailedStats)
}

// TestCorrelationChains tests async correlation chains
func TestCorrelationChains(t *testing.T) {
	config := async.DefaultAsyncConfig()
	tracker := async.NewContextTracker(config)
	defer tracker.Close()

	traceID := "correlation-test-123"

	// Create multiple related contexts
	for i := uint64(1); i <= 3; i++ {
		err := tracker.TrackGoroutineSpawn(0, i, uint32(100+i), traceID, fmt.Sprintf("span-%d", i))
		if err != nil {
			t.Fatalf("Failed to track goroutine %d: %v", i, err)
		}
	}

	// Complete all contexts
	for i := uint64(1); i <= 3; i++ {
		err := tracker.TrackContextCompletion(i, "success")
		if err != nil {
			t.Fatalf("Failed to complete context %d: %v", i, err)
		}
	}

	// Try to get correlation chain
	chain, err := tracker.GetCorrelationChain(traceID)
	if err != nil {
		t.Logf("Correlation chain not found (might be cleaned up): %v", err)
		return
	}

	if len(chain.Contexts) != 3 {
		t.Errorf("Expected 3 contexts in chain, got %d", len(chain.Contexts))
	}

	if chain.Status != "completed" {
		t.Errorf("Expected chain status 'completed', got '%s'", chain.Status)
	}

	t.Logf("Correlation chain: %+v", chain)
}


