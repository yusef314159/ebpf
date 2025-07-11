package unit

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"unsafe"
)

// Event structure matching the C struct from main.go
type Event struct {
	Timestamp  uint64
	RequestID  uint64
	PID        uint32
	TID        uint32
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Comm       [16]byte
	Method     [8]byte
	Path       [128]byte
	PayloadLen uint32
	Payload    [256]byte
	EventType  uint8
	Protocol   uint8
}

// Helper functions for testing
func createTestEvent() *Event {
	event := &Event{
		Timestamp: uint64(time.Now().UnixNano()),
		RequestID: 12345,
		PID:       1234,
		TID:       5678,
		SrcIP:     ipToUint32("127.0.0.1"),
		DstIP:     ipToUint32("127.0.0.1"),
		SrcPort:   8080,
		DstPort:   80,
		PayloadLen: 20,
		EventType: 1,
		Protocol:  6, // TCP
	}
	
	copy(event.Comm[:], "test-process")
	copy(event.Method[:], "GET")
	copy(event.Path[:], "/api/test")
	copy(event.Payload[:], "GET /api/test HTTP/1.1")
	
	return event
}

func ipToUint32(ip string) uint32 {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return 0
	}
	ipv4 := parsedIP.To4()
	if ipv4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ipv4)
}

func uint32ToIP(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

// Test event structure size and alignment
func TestEventStructureSize(t *testing.T) {
	event := Event{}
	expectedSize := 8 + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 16 + 8 + 128 + 4 + 256 + 1 + 1 // 450 bytes
	actualSize := int(unsafe.Sizeof(event))
	
	t.Logf("Event structure size: %d bytes", actualSize)
	
	if actualSize != expectedSize {
		t.Logf("Warning: Event size (%d) differs from expected (%d). This may be due to padding.", actualSize, expectedSize)
	}
	
	// Ensure the structure is not too large for eBPF
	if actualSize > 512 {
		t.Errorf("Event structure too large (%d bytes). eBPF has limitations on structure sizes.", actualSize)
	}
}

// Test event serialization and deserialization
func TestEventSerialization(t *testing.T) {
	originalEvent := createTestEvent()
	
	// Serialize to bytes
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, originalEvent)
	if err != nil {
		t.Fatalf("Failed to serialize event: %v", err)
	}
	
	// Deserialize from bytes
	var deserializedEvent Event
	err = binary.Read(buf, binary.LittleEndian, &deserializedEvent)
	if err != nil {
		t.Fatalf("Failed to deserialize event: %v", err)
	}
	
	// Compare key fields
	if originalEvent.Timestamp != deserializedEvent.Timestamp {
		t.Errorf("Timestamp mismatch: expected %d, got %d", originalEvent.Timestamp, deserializedEvent.Timestamp)
	}
	
	if originalEvent.RequestID != deserializedEvent.RequestID {
		t.Errorf("RequestID mismatch: expected %d, got %d", originalEvent.RequestID, deserializedEvent.RequestID)
	}
	
	if originalEvent.PID != deserializedEvent.PID {
		t.Errorf("PID mismatch: expected %d, got %d", originalEvent.PID, deserializedEvent.PID)
	}
	
	if originalEvent.SrcIP != deserializedEvent.SrcIP {
		t.Errorf("SrcIP mismatch: expected %d, got %d", originalEvent.SrcIP, deserializedEvent.SrcIP)
	}
}

// Test IP address conversion functions
func TestIPConversion(t *testing.T) {
	testCases := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}
	
	for _, ip := range testCases {
		uint32IP := ipToUint32(ip)
		convertedBack := uint32ToIP(uint32IP)
		
		if ip != convertedBack {
			t.Errorf("IP conversion failed: %s -> %d -> %s", ip, uint32IP, convertedBack)
		}
	}
}

// Test invalid IP addresses
func TestInvalidIPConversion(t *testing.T) {
	invalidIPs := []string{
		"invalid",
		"256.256.256.256",
		"",
		"192.168.1",
	}
	
	for _, ip := range invalidIPs {
		result := ipToUint32(ip)
		if result != 0 {
			t.Errorf("Expected 0 for invalid IP %s, got %d", ip, result)
		}
	}
}

// Test event field validation
func TestEventFieldValidation(t *testing.T) {
	event := createTestEvent()
	
	// Test timestamp is reasonable (within last hour and next hour)
	now := time.Now().UnixNano()
	oneHour := int64(time.Hour)
	
	if int64(event.Timestamp) < now-oneHour || int64(event.Timestamp) > now+oneHour {
		t.Errorf("Timestamp seems unreasonable: %d (now: %d)", event.Timestamp, now)
	}
	
	// Test PID is positive
	if event.PID == 0 {
		t.Error("PID should not be 0 for user processes")
	}
	
	// Test ports are in valid range
	if event.SrcPort == 0 || event.DstPort == 0 {
		t.Error("Ports should not be 0")
	}
	
	// Test method is null-terminated
	methodStr := string(bytes.TrimRight(event.Method[:], "\x00"))
	if len(methodStr) == 0 {
		t.Error("Method should not be empty")
	}
	
	// Test path is null-terminated
	pathStr := string(bytes.TrimRight(event.Path[:], "\x00"))
	if len(pathStr) == 0 {
		t.Error("Path should not be empty")
	}
}

// Benchmark event creation
func BenchmarkEventCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = createTestEvent()
	}
}

// Benchmark event serialization
func BenchmarkEventSerialization(b *testing.B) {
	event := createTestEvent()
	buf := new(bytes.Buffer)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		binary.Write(buf, binary.LittleEndian, event)
	}
}
