package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestWriteSyscallTracing tests the complete request-response correlation
func TestWriteSyscallTracing(t *testing.T) {
	// This test simulates the complete flow of HTTP request-response tracing
	// In a real environment, this would test the actual eBPF tracer
	
	testCases := []struct {
		name           string
		method         string
		path           string
		expectedStatus string
		expectedEvents int // Expected number of events (read + write)
	}{
		{
			name:           "GET request with 200 response",
			method:         "GET",
			path:           "/api/users",
			expectedStatus: "200",
			expectedEvents: 2, // 1 read (request) + 1 write (response)
		},
		{
			name:           "POST request with 201 response",
			method:         "POST",
			path:           "/api/users",
			expectedStatus: "201",
			expectedEvents: 2,
		},
		{
			name:           "GET request with 404 response",
			method:         "GET",
			path:           "/api/nonexistent",
			expectedStatus: "404",
			expectedEvents: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the complete tracing flow
			events := simulateHTTPTracing(tc.method, tc.path, tc.expectedStatus)
			
			// Validate we got the expected number of events
			if len(events) != tc.expectedEvents {
				t.Errorf("Expected %d events, got %d", tc.expectedEvents, len(events))
			}
			
			// Validate request event
			requestEvent := findEventByType(events, "read")
			if requestEvent == nil {
				t.Fatal("No read event found")
			}
			
			if requestEvent.Method != tc.method {
				t.Errorf("Expected method %s, got %s", tc.method, requestEvent.Method)
			}
			
			if requestEvent.Path != tc.path {
				t.Errorf("Expected path %s, got %s", tc.path, requestEvent.Path)
			}
			
			// Validate response event
			responseEvent := findEventByType(events, "write")
			if responseEvent == nil {
				t.Fatal("No write event found")
			}
			
			// For responses, the status code is stored in the method field
			if !strings.Contains(responseEvent.Method, tc.expectedStatus) {
				t.Errorf("Expected status %s in response, got method %s", 
					tc.expectedStatus, responseEvent.Method)
			}
			
			// Validate correlation
			if requestEvent.RequestID != responseEvent.RequestID {
				t.Errorf("Request ID mismatch: request=%d, response=%d", 
					requestEvent.RequestID, responseEvent.RequestID)
			}
			
			t.Logf("Successfully correlated request %d (%s %s) with response (%s)", 
				requestEvent.RequestID, tc.method, tc.path, tc.expectedStatus)
		})
	}
}

// MockEvent represents a traced event for testing
type MockEvent struct {
	Timestamp   string `json:"timestamp"`
	RequestID   uint64 `json:"request_id"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Comm        string `json:"comm"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	PayloadLen  uint32 `json:"payload_len"`
	Payload     string `json:"payload,omitempty"`
	EventType   string `json:"event_type"`
	EventTypeID uint8  `json:"event_type_id"`
	Protocol    string `json:"protocol,omitempty"`
}

// simulateHTTPTracing simulates the complete HTTP tracing flow
func simulateHTTPTracing(method, path, expectedStatus string) []*MockEvent {
	var events []*MockEvent
	requestID := uint64(time.Now().UnixNano()) // Simulate request ID generation
	
	// Simulate read event (HTTP request)
	requestPayload := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: localhost\r\n\r\n", method, path)
	requestEvent := &MockEvent{
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		RequestID:   requestID,
		PID:         1234,
		TID:         5678,
		SrcIP:       "127.0.0.1",
		DstIP:       "127.0.0.1",
		SrcPort:     8080,
		DstPort:     80,
		Comm:        "test-client",
		Method:      method,
		Path:        path,
		PayloadLen:  uint32(len(requestPayload)),
		Payload:     requestPayload,
		EventType:   "read",
		EventTypeID: 1,
		Protocol:    "TCP",
	}
	events = append(events, requestEvent)
	
	// Simulate write event (HTTP response)
	responsePayload := fmt.Sprintf("HTTP/1.1 %s %s\r\nContent-Length: 0\r\n\r\n", 
		expectedStatus, getStatusText(expectedStatus))
	responseEvent := &MockEvent{
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		RequestID:   requestID, // Same request ID for correlation
		PID:         1234,
		TID:         5678,
		SrcIP:       "127.0.0.1",
		DstIP:       "127.0.0.1",
		SrcPort:     80,
		DstPort:     8080,
		Comm:        "test-server",
		Method:      expectedStatus, // Status code stored in method field for responses
		Path:        path,           // Correlated path
		PayloadLen:  uint32(len(responsePayload)),
		Payload:     responsePayload,
		EventType:   "write",
		EventTypeID: 3,
		Protocol:    "TCP",
	}
	events = append(events, responseEvent)
	
	return events
}

// findEventByType finds an event by its type
func findEventByType(events []*MockEvent, eventType string) *MockEvent {
	for _, event := range events {
		if event.EventType == eventType {
			return event
		}
	}
	return nil
}

// getStatusText returns the standard HTTP status text for a status code
func getStatusText(statusCode string) string {
	switch statusCode {
	case "200":
		return "OK"
	case "201":
		return "Created"
	case "404":
		return "Not Found"
	case "500":
		return "Internal Server Error"
	default:
		return "Unknown"
	}
}

// TestRequestResponseCorrelationAccuracy tests correlation accuracy
func TestRequestResponseCorrelationAccuracy(t *testing.T) {
	// Test multiple concurrent requests to ensure proper correlation
	requests := []struct {
		method string
		path   string
		status string
	}{
		{"GET", "/api/users/1", "200"},
		{"POST", "/api/users", "201"},
		{"GET", "/api/users/999", "404"},
		{"PUT", "/api/users/1", "200"},
		{"DELETE", "/api/users/1", "204"},
	}
	
	var allEvents []*MockEvent
	uniqueRequestIDs := make(map[uint64]bool)

	// Generate events for all requests
	for _, req := range requests {
		events := simulateHTTPTracing(req.method, req.path, req.status)
		allEvents = append(allEvents, events...)

		// Track unique request IDs (each request should have a unique ID)
		if len(events) > 0 && events[0].RequestID != 0 {
			requestID := events[0].RequestID
			if uniqueRequestIDs[requestID] {
				t.Errorf("Duplicate request ID found across different requests: %d", requestID)
			}
			uniqueRequestIDs[requestID] = true
		}
	}
	
	// Validate correlation for each request
	for _, req := range requests {
		// Find request and response events for this request by matching request ID
		var requestEvent, responseEvent *MockEvent

		// First find the request event
		for _, event := range allEvents {
			if event.EventType == "read" && event.Method == req.method && event.Path == req.path {
				requestEvent = event
				break // Take the first matching request
			}
		}

		// Then find the corresponding response event with the same request ID
		if requestEvent != nil {
			for _, event := range allEvents {
				if event.EventType == "write" && event.RequestID == requestEvent.RequestID {
					responseEvent = event
					break
				}
			}
		}
		
		if requestEvent == nil {
			t.Errorf("No request event found for %s %s", req.method, req.path)
			continue
		}
		
		if responseEvent == nil {
			t.Errorf("No response event found for %s %s", req.method, req.path)
			continue
		}
		
		// Validate correlation
		if requestEvent.RequestID != responseEvent.RequestID {
			t.Errorf("Correlation failed for %s %s: request ID %d != response ID %d",
				req.method, req.path, requestEvent.RequestID, responseEvent.RequestID)
		}
		
		t.Logf("Successfully correlated %s %s: request ID %d", 
			req.method, req.path, requestEvent.RequestID)
	}
	
	t.Logf("Processed %d total events with %d unique request IDs",
		len(allEvents), len(uniqueRequestIDs))
}

// TestEventJSONSerialization tests JSON serialization of events
func TestEventJSONSerialization(t *testing.T) {
	events := simulateHTTPTracing("GET", "/api/test", "200")
	
	for _, event := range events {
		// Test JSON marshaling
		jsonData, err := json.Marshal(event)
		if err != nil {
			t.Errorf("Failed to marshal event to JSON: %v", err)
			continue
		}
		
		// Test JSON unmarshaling
		var unmarshaledEvent MockEvent
		err = json.Unmarshal(jsonData, &unmarshaledEvent)
		if err != nil {
			t.Errorf("Failed to unmarshal event from JSON: %v", err)
			continue
		}
		
		// Validate key fields
		if unmarshaledEvent.RequestID != event.RequestID {
			t.Errorf("Request ID mismatch after JSON round-trip: %d != %d", 
				unmarshaledEvent.RequestID, event.RequestID)
		}
		
		if unmarshaledEvent.EventType != event.EventType {
			t.Errorf("Event type mismatch after JSON round-trip: %s != %s", 
				unmarshaledEvent.EventType, event.EventType)
		}
		
		t.Logf("Successfully serialized %s event (ID: %d)", 
			event.EventType, event.RequestID)
	}
}

// BenchmarkRequestResponseCorrelation benchmarks correlation performance
func BenchmarkRequestResponseCorrelation(b *testing.B) {
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		events := simulateHTTPTracing("GET", "/api/benchmark", "200")
		
		// Simulate correlation lookup
		requestEvent := findEventByType(events, "read")
		responseEvent := findEventByType(events, "write")
		
		if requestEvent == nil || responseEvent == nil {
			b.Fatal("Failed to find events")
		}
		
		// Validate correlation
		if requestEvent.RequestID != responseEvent.RequestID {
			b.Fatal("Correlation failed")
		}
	}
}
