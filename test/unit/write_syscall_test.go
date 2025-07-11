package unit

import (
	"strings"
	"testing"
)

// Test HTTP response parsing logic that mirrors the eBPF implementation
func TestHTTPResponseParsing(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedStatus string
		expectedReason string
		expectedValid  bool
	}{
		{
			name:           "HTTP/1.1 200 OK",
			input:          "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			expectedStatus: "200",
			expectedReason: "OK",
			expectedValid:  true,
		},
		{
			name:           "HTTP/1.1 404 Not Found",
			input:          "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
			expectedStatus: "404",
			expectedReason: "Not Found",
			expectedValid:  true,
		},
		{
			name:           "HTTP/1.0 500 Internal Server Error",
			input:          "HTTP/1.0 500 Internal Server Error\r\n\r\n",
			expectedStatus: "500",
			expectedReason: "Internal Server Error",
			expectedValid:  true,
		},
		{
			name:           "HTTP/2.0 201 Created",
			input:          "HTTP/2.0 201 Created\r\nLocation: /api/resource/123\r\n\r\n",
			expectedStatus: "201",
			expectedReason: "Created",
			expectedValid:  true,
		},
		{
			name:           "Invalid - not HTTP response",
			input:          "GET /path HTTP/1.1\r\n\r\n",
			expectedStatus: "",
			expectedReason: "",
			expectedValid:  false,
		},
		{
			name:           "Invalid - too short",
			input:          "HTTP/1.1",
			expectedStatus: "",
			expectedReason: "",
			expectedValid:  false,
		},
		{
			name:           "Invalid - malformed status",
			input:          "HTTP/1.1 ABC Invalid\r\n\r\n",
			expectedStatus: "ABC",
			expectedReason: "Invalid",
			expectedValid:  true, // Still parses, but status is invalid
		},
		{
			name:           "No reason phrase",
			input:          "HTTP/1.1 204\r\n\r\n",
			expectedStatus: "204",
			expectedReason: "",
			expectedValid:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, reason, valid := parseHTTPResponse(tc.input)

			if valid != tc.expectedValid {
				t.Errorf("Expected valid=%v, got valid=%v", tc.expectedValid, valid)
			}

			if tc.expectedValid {
				if status != tc.expectedStatus {
					t.Errorf("Expected status='%s', got status='%s'", tc.expectedStatus, status)
				}

				if reason != tc.expectedReason {
					t.Errorf("Expected reason='%s', got reason='%s'", tc.expectedReason, reason)
				}
			}
		})
	}
}

// parseHTTPResponse simulates the HTTP response parsing logic from eBPF
func parseHTTPResponse(data string) (status, reason string, valid bool) {
	if len(data) < 12 { // "HTTP/1.1 200" minimum
		return "", "", false
	}

	// Check for HTTP response format
	if !strings.HasPrefix(data, "HTTP/") {
		return "", "", false
	}

	// Find the status code (after "HTTP/1.x ")
	spaceIndex := strings.Index(data, " ")
	if spaceIndex == -1 {
		return "", "", false
	}

	// Find second space (end of status code)
	statusStart := spaceIndex + 1
	if statusStart+3 > len(data) {
		return "", "", false
	}

	// Extract status code (3 characters)
	status = data[statusStart : statusStart+3]

	// Extract reason phrase if present
	reasonStart := statusStart + 4 // Skip "200 "
	if reasonStart < len(data) {
		// Find end of line
		endIndex := strings.Index(data[reasonStart:], "\r")
		if endIndex == -1 {
			endIndex = strings.Index(data[reasonStart:], "\n")
		}
		if endIndex != -1 {
			reason = strings.TrimSpace(data[reasonStart : reasonStart+endIndex])
		} else {
			reason = strings.TrimSpace(data[reasonStart:])
		}
	}

	return status, reason, true
}

// Test HTTP response detection
func TestIsHTTPResponse(t *testing.T) {
	testCases := []struct {
		name     string
		payload  string
		expected bool
	}{
		{"Valid HTTP/1.1 response", "HTTP/1.1 200 OK\r\n", true},
		{"Valid HTTP/1.0 response", "HTTP/1.0 404 Not Found\r\n", true},
		{"Valid HTTP/2.0 response", "HTTP/2.0 201 Created\r\n", true},
		{"Invalid - HTTP request", "GET /path HTTP/1.1\r\n", false},
		{"Invalid - too short", "HTTP/1.1", false},
		{"Invalid - not HTTP", "Content-Type: text/html\r\n", false},
		{"Invalid - empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isHTTPResponse(tc.payload)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v for payload: %q", tc.expected, result, tc.payload)
			}
		})
	}
}

// isHTTPResponse checks if the payload looks like an HTTP response
func isHTTPResponse(payload string) bool {
	if len(payload) < 12 {
		return false
	}

	// Check for HTTP response format
	return strings.HasPrefix(payload, "HTTP/1.") || strings.HasPrefix(payload, "HTTP/2.")
}

// Test request-response correlation logic
func TestRequestResponseCorrelation(t *testing.T) {
	// Simulate request context storage
	requestContexts := make(map[uint32]*RequestContext)

	// Test cases for correlation
	testCases := []struct {
		name        string
		pid         uint32
		requestID   uint64
		method      string
		path        string
		responseData string
		expectCorrelation bool
	}{
		{
			name:        "Successful correlation",
			pid:         1234,
			requestID:   12345,
			method:      "GET",
			path:        "/api/users",
			responseData: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n",
			expectCorrelation: true,
		},
		{
			name:        "No matching request context",
			pid:         5678,
			requestID:   0,
			method:      "",
			path:        "",
			responseData: "HTTP/1.1 404 Not Found\r\n\r\n",
			expectCorrelation: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup request context if expected
			if tc.expectCorrelation {
				requestContexts[tc.pid] = &RequestContext{
					RequestID: tc.requestID,
					Method:    tc.method,
					Path:      tc.path,
				}
			}

			// Simulate write event processing
			correlatedID, correlatedMethod, correlatedPath := processWriteEvent(
				tc.pid, tc.responseData, requestContexts)

			if tc.expectCorrelation {
				if correlatedID != tc.requestID {
					t.Errorf("Expected request ID %d, got %d", tc.requestID, correlatedID)
				}
				if correlatedMethod != tc.method {
					t.Errorf("Expected method '%s', got '%s'", tc.method, correlatedMethod)
				}
				if correlatedPath != tc.path {
					t.Errorf("Expected path '%s', got '%s'", tc.path, correlatedPath)
				}
			} else {
				if correlatedID == 0 && !isHTTPResponse(tc.responseData) {
					// Expected behavior for non-HTTP data without context
				} else if isHTTPResponse(tc.responseData) {
					// Should generate new ID for HTTP responses without context
					if correlatedID == 0 {
						t.Error("Expected new request ID for HTTP response without context")
					}
				}
			}
		})
	}
}

// RequestContext represents a stored request context
type RequestContext struct {
	RequestID uint64
	Method    string
	Path      string
}

// processWriteEvent simulates the write event processing logic
func processWriteEvent(pid uint32, responseData string, contexts map[uint32]*RequestContext) (uint64, string, string) {
	// Check if it's an HTTP response
	if isHTTPResponse(responseData) {
		// Try to correlate with existing request
		if ctx, exists := contexts[pid]; exists {
			return ctx.RequestID, ctx.Method, ctx.Path
		}
		// Generate new ID for uncorrelated HTTP response
		return generateNewRequestID(), "", ""
	}

	// Not an HTTP response, check for existing context
	if ctx, exists := contexts[pid]; exists {
		return ctx.RequestID, ctx.Method, ctx.Path
	}

	return 0, "", ""
}

// generateNewRequestID simulates request ID generation
func generateNewRequestID() uint64 {
	// In real implementation, this would use the same logic as eBPF
	return 99999 // Placeholder
}

// Test write event filtering logic
func TestWriteEventFiltering(t *testing.T) {
	testCases := []struct {
		name      string
		requestID uint64
		payload   string
		shouldLog bool
	}{
		{
			name:      "HTTP response with correlation",
			requestID: 12345,
			payload:   "HTTP/1.1 200 OK\r\n",
			shouldLog: true,
		},
		{
			name:      "HTTP response without correlation",
			requestID: 0,
			payload:   "HTTP/1.1 404 Not Found\r\n",
			shouldLog: true,
		},
		{
			name:      "Non-HTTP with correlation",
			requestID: 12345,
			payload:   "Some binary data",
			shouldLog: true,
		},
		{
			name:      "Non-HTTP without correlation",
			requestID: 0,
			payload:   "Some binary data",
			shouldLog: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldLog := tc.requestID != 0 || isHTTPResponse(tc.payload)
			if shouldLog != tc.shouldLog {
				t.Errorf("Expected shouldLog=%v, got shouldLog=%v", tc.shouldLog, shouldLog)
			}
		})
	}
}

// Benchmark write event processing
func BenchmarkHTTPResponseParsing(b *testing.B) {
	responseData := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseHTTPResponse(responseData)
	}
}

// Benchmark HTTP response detection
func BenchmarkIsHTTPResponse(b *testing.B) {
	responseData := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isHTTPResponse(responseData)
	}
}
