package unit

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// TraceContext represents distributed tracing context for testing
type TraceContext struct {
	TraceIDHigh   uint64
	TraceIDLow    uint64
	SpanID        uint64
	ParentSpanID  uint64
	TraceFlags    uint8
	TraceStateLen uint8
	TraceState    [64]byte
}

// TestTraceIDGeneration tests trace ID generation
func TestTraceIDGeneration(t *testing.T) {
	// Simulate trace ID generation
	traceCtx1 := generateTestTraceID()
	traceCtx2 := generateTestTraceID()

	// Trace IDs should be different
	if traceCtx1.TraceIDHigh == traceCtx2.TraceIDHigh && traceCtx1.TraceIDLow == traceCtx2.TraceIDLow {
		t.Error("Generated trace IDs should be unique")
	}

	// Trace IDs should not be zero
	if traceCtx1.TraceIDHigh == 0 && traceCtx1.TraceIDLow == 0 {
		t.Error("Trace ID should not be zero")
	}

	// Test trace ID formatting
	traceIDStr := formatTraceID(traceCtx1.TraceIDHigh, traceCtx1.TraceIDLow)
	if len(traceIDStr) != 32 {
		t.Errorf("Trace ID string should be 32 characters, got %d", len(traceIDStr))
	}

	t.Logf("Generated trace ID: %s", traceIDStr)
}

// TestSpanIDGeneration tests span ID generation
func TestSpanIDGeneration(t *testing.T) {
	spanID1 := generateTestSpanID()
	spanID2 := generateTestSpanID()

	// Span IDs should be different
	if spanID1 == spanID2 {
		t.Error("Generated span IDs should be unique")
	}

	// Span IDs should not be zero
	if spanID1 == 0 {
		t.Error("Span ID should not be zero")
	}

	// Test span ID formatting
	spanIDStr := fmt.Sprintf("%016x", spanID1)
	if len(spanIDStr) != 16 {
		t.Errorf("Span ID string should be 16 characters, got %d", len(spanIDStr))
	}

	t.Logf("Generated span ID: %s", spanIDStr)
}

// TestServiceIDCalculation tests service ID calculation
func TestServiceIDCalculation(t *testing.T) {
	testCases := []struct {
		name     string
		comm     string
		port     uint16
		expected bool // Whether we expect a non-zero service ID
	}{
		{"nginx service", "nginx", 80, true},
		{"apache service", "apache", 8080, true},
		{"same service different port", "nginx", 443, true},
		{"empty comm", "", 80, false},
		{"zero port", "nginx", 0, true}, // Still generates ID from comm
	}

	serviceIDs := make(map[uint32]bool)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serviceID := calculateTestServiceID(tc.comm, tc.port)

			if tc.expected && serviceID == 0 {
				t.Errorf("Expected non-zero service ID for %s:%d", tc.comm, tc.port)
			}

			if !tc.expected && serviceID != 0 {
				t.Errorf("Expected zero service ID for %s:%d", tc.comm, tc.port)
			}

			// Check for uniqueness (different services should have different IDs)
			if serviceID != 0 {
				if serviceIDs[serviceID] {
					t.Logf("Warning: Service ID collision detected for %s:%d", tc.comm, tc.port)
				}
				serviceIDs[serviceID] = true
			}

			t.Logf("Service %s:%d -> ID: %d", tc.comm, tc.port, serviceID)
		})
	}
}

// TestTraceContextExtraction tests extracting trace context from HTTP headers
func TestTraceContextExtraction(t *testing.T) {
	testCases := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "W3C traceparent header",
			payload:  "GET /api HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n",
			expected: true,
		},
		{
			name:     "X-Trace-Id header",
			payload:  "POST /api HTTP/1.1\r\nX-Trace-Id: 4bf92f3577b34da6a3ce929d0e0e4736\r\n\r\n",
			expected: true,
		},
		{
			name:     "No trace headers",
			payload:  "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expected: false,
		},
		{
			name:     "Multiple headers with trace",
			payload:  "GET /api HTTP/1.1\r\nHost: example.com\r\nX-Trace-Id: abc123\r\nUser-Agent: test\r\n\r\n",
			expected: true,
		},
		{
			name:     "Case insensitive header",
			payload:  "GET /api HTTP/1.1\r\nTRACEPARENT: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n",
			expected: false, // Our simple implementation is case sensitive
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := extractTestTraceContext(tc.payload)

			if found != tc.expected {
				t.Errorf("Expected trace context found=%v, got found=%v", tc.expected, found)
			}

			if found {
				t.Logf("Successfully extracted trace context from: %s", tc.name)
			}
		})
	}
}

// TestCorrelationTypes tests different correlation types
func TestCorrelationTypes(t *testing.T) {
	testCases := []struct {
		correlationType uint8
		expectedString  string
	}{
		{0, "local"},
		{1, "incoming"},
		{2, "outgoing"},
		{99, "unknown"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("type_%d", tc.correlationType), func(t *testing.T) {
			result := correlationTypeToString(tc.correlationType)
			if result != tc.expectedString {
				t.Errorf("Expected correlation type string '%s', got '%s'", tc.expectedString, result)
			}
		})
	}
}

// TestDistributedTraceFlow tests a complete distributed trace flow
func TestDistributedTraceFlow(t *testing.T) {
	// Simulate a distributed trace across multiple services
	
	// Service A receives external request (root trace)
	serviceA := createTestService("service-a", 8080)
	traceA := serviceA.handleIncomingRequest("GET /api/users HTTP/1.1\r\n\r\n", false)
	
	if traceA.CorrelationType != "local" {
		t.Errorf("Root trace should be local, got %s", traceA.CorrelationType)
	}
	
	if traceA.HopCount != 0 {
		t.Errorf("Root trace should have hop count 0, got %d", traceA.HopCount)
	}

	// Service A makes outgoing request to Service B
	serviceB := createTestService("service-b", 8081)
	requestToB := serviceA.createOutgoingRequest("/api/orders", traceA.TraceContext)
	traceB := serviceB.handleIncomingRequest(requestToB, true)
	
	if traceB.CorrelationType != "incoming" {
		t.Errorf("Incoming trace should be incoming, got %s", traceB.CorrelationType)
	}
	
	if traceB.HopCount != 1 {
		t.Errorf("Incoming trace should have hop count 1, got %d", traceB.HopCount)
	}

	// Verify trace correlation
	if traceA.TraceContext.TraceID != traceB.TraceContext.TraceID {
		t.Error("Trace IDs should match across services")
	}

	if traceB.TraceContext.ParentSpanID != traceA.TraceContext.SpanID {
		t.Error("Parent span ID should match previous span ID")
	}

	t.Logf("Distributed trace flow:")
	t.Logf("  Service A: %s (trace: %s, span: %s)", traceA.ServiceName, traceA.TraceContext.TraceID, traceA.TraceContext.SpanID)
	t.Logf("  Service B: %s (trace: %s, span: %s, parent: %s)", traceB.ServiceName, traceB.TraceContext.TraceID, traceB.TraceContext.SpanID, traceB.TraceContext.ParentSpanID)
}

// Helper functions for testing

func generateTestTraceID() TraceContext {
	// Simulate trace ID generation with randomness
	rand.Seed(time.Now().UnixNano())
	return TraceContext{
		TraceIDHigh: uint64(rand.Int63()),
		TraceIDLow:  uint64(rand.Int63()),
	}
}

func generateTestSpanID() uint64 {
	// Simulate span ID generation with randomness
	rand.Seed(time.Now().UnixNano())
	return uint64(rand.Int63())
}

func calculateTestServiceID(comm string, port uint16) uint32 {
	if comm == "" {
		return 0
	}
	
	hash := uint32(0)
	for _, c := range comm {
		hash = hash*31 + uint32(c)
	}
	hash = hash*31 + uint32(port)
	return hash
}

func formatTraceID(high, low uint64) string {
	return fmt.Sprintf("%016x%016x", high, low)
}

func extractTestTraceContext(payload string) bool {
	// Simple implementation for testing
	return strings.Contains(payload, "traceparent:") || strings.Contains(payload, "X-Trace-Id:")
}

func correlationTypeToString(correlationType uint8) string {
	switch correlationType {
	case 0:
		return "local"
	case 1:
		return "incoming"
	case 2:
		return "outgoing"
	default:
		return "unknown"
	}
}

// Test service structure
type TestService struct {
	Name string
	Port uint16
	ID   uint32
}

type TestTrace struct {
	TraceContext    TestTraceContext
	ServiceName     string
	CorrelationType string
	HopCount        uint8
}

type TestTraceContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
}

func createTestService(name string, port uint16) *TestService {
	return &TestService{
		Name: name,
		Port: port,
		ID:   calculateTestServiceID(name, port),
	}
}

func (s *TestService) handleIncomingRequest(payload string, hasTraceContext bool) *TestTrace {
	trace := &TestTrace{
		ServiceName: fmt.Sprintf("%s:%d", s.Name, s.Port),
	}

	if hasTraceContext && extractTestTraceContext(payload) {
		// Extract trace ID from the payload (simplified)
		traceID := extractTraceIDFromPayload(payload)
		parentSpanID := extractSpanIDFromPayload(payload)

		// Incoming request with trace context
		trace.CorrelationType = "incoming"
		trace.HopCount = 1
		trace.TraceContext = TestTraceContext{
			TraceID:      traceID,
			SpanID:       fmt.Sprintf("%016x", generateTestSpanID()),
			ParentSpanID: parentSpanID,
		}
	} else {
		// New root trace
		trace.CorrelationType = "local"
		trace.HopCount = 0
		traceCtx := generateTestTraceID()
		trace.TraceContext = TestTraceContext{
			TraceID:      formatTraceID(traceCtx.TraceIDHigh, traceCtx.TraceIDLow),
			SpanID:       fmt.Sprintf("%016x", generateTestSpanID()),
			ParentSpanID: "",
		}
	}

	return trace
}

// Helper function to extract trace ID from payload
func extractTraceIDFromPayload(payload string) string {
	// Look for traceparent header and extract trace ID
	if strings.Contains(payload, "traceparent:") {
		// Find the traceparent line
		lines := strings.Split(payload, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "traceparent:") {
				// Format: traceparent: 00-<trace_id>-<span_id>-<flags>
				parts := strings.Split(line, "-")
				if len(parts) >= 2 {
					return parts[1]
				}
			}
		}
	}
	return "4bf92f3577b34da6a3ce929d0e0e4736" // Default for testing
}

// Helper function to extract span ID from payload
func extractSpanIDFromPayload(payload string) string {
	// Look for traceparent header and extract span ID
	if strings.Contains(payload, "traceparent:") {
		// Find the traceparent line
		lines := strings.Split(payload, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "traceparent:") {
				// Format: traceparent: 00-<trace_id>-<span_id>-<flags>
				parts := strings.Split(line, "-")
				if len(parts) >= 3 {
					return parts[2]
				}
			}
		}
	}
	return "00f067aa0ba902b7" // Default for testing
}

func (s *TestService) createOutgoingRequest(path string, parentTrace TestTraceContext) string {
	// Create HTTP request with trace headers
	return fmt.Sprintf("GET %s HTTP/1.1\r\ntraceparent: 00-%s-%s-01\r\n\r\n", 
		path, parentTrace.TraceID, parentTrace.SpanID)
}

// Benchmark advanced correlation operations
func BenchmarkTraceIDGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateTestTraceID()
	}
}

func BenchmarkServiceIDCalculation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateTestServiceID("nginx", 80)
	}
}

func BenchmarkTraceContextExtraction(b *testing.B) {
	payload := "GET /api HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractTestTraceContext(payload)
	}
}
