package ebpf

import (
	"strings"
	"testing"
)

// HTTP parsing test cases that mirror the eBPF program logic
type HTTPParseTestCase struct {
	name           string
	input          string
	expectedMethod string
	expectedPath   string
	expectedValid  bool
}

// Test cases for HTTP request parsing
func getHTTPParseTestCases() []HTTPParseTestCase {
	return []HTTPParseTestCase{
		{
			name:           "Simple GET request",
			input:          "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expectedMethod: "GET",
			expectedPath:   "/",
			expectedValid:  true,
		},
		{
			name:           "POST request with path",
			input:          "POST /api/users HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
			expectedMethod: "POST",
			expectedPath:   "/api/users",
			expectedValid:  true,
		},
		{
			name:           "PUT request",
			input:          "PUT /api/users/123 HTTP/1.1\r\n\r\n",
			expectedMethod: "PUT",
			expectedPath:   "/api/users/123",
			expectedValid:  true,
		},
		{
			name:           "DELETE request",
			input:          "DELETE /api/users/123 HTTP/1.1\r\n\r\n",
			expectedMethod: "DELETE",
			expectedPath:   "/api/users/123",
			expectedValid:  true,
		},
		{
			name:           "Complex path with query parameters",
			input:          "GET /api/search?q=test&limit=10 HTTP/1.1\r\n\r\n",
			expectedMethod: "GET",
			expectedPath:   "/api/search?q=test&limit=10",
			expectedValid:  true,
		},
		{
			name:           "HTTP/1.0 request",
			input:          "GET /index.html HTTP/1.0\r\n\r\n",
			expectedMethod: "GET",
			expectedPath:   "/index.html",
			expectedValid:  true,
		},
		{
			name:           "HTTP/2.0 request",
			input:          "GET /api/data HTTP/2.0\r\n\r\n",
			expectedMethod: "GET",
			expectedPath:   "/api/data",
			expectedValid:  true,
		},
		{
			name:           "Invalid method",
			input:          "INVALID /path HTTP/1.1\r\n\r\n",
			expectedMethod: "",
			expectedPath:   "",
			expectedValid:  false,
		},
		{
			name:           "Missing HTTP version",
			input:          "GET /path\r\n\r\n",
			expectedMethod: "",
			expectedPath:   "",
			expectedValid:  false,
		},
		{
			name:           "Malformed request line",
			input:          "GET\r\n\r\n",
			expectedMethod: "",
			expectedPath:   "",
			expectedValid:  false,
		},
		{
			name:           "Empty request",
			input:          "",
			expectedMethod: "",
			expectedPath:   "",
			expectedValid:  false,
		},
		{
			name:           "Too short request",
			input:          "GET",
			expectedMethod: "",
			expectedPath:   "",
			expectedValid:  false,
		},
	}
}

// Simulate the HTTP parsing logic from the eBPF program
func parseHTTPRequest(data string) (method, path string, valid bool) {
	if len(data) < 14 { // "GET / HTTP/1.1" minimum
		return "", "", false
	}

	// Find first space (end of method)
	methodEnd := strings.Index(data, " ")
	if methodEnd == -1 || methodEnd == 0 {
		return "", "", false
	}

	method = data[:methodEnd]
	
	// Validate method
	if !isValidHTTPMethod(method) {
		return "", "", false
	}

	// Find second space (end of path)
	remaining := data[methodEnd+1:]
	pathEnd := strings.Index(remaining, " ")
	if pathEnd == -1 {
		return "", "", false
	}

	path = remaining[:pathEnd]
	if len(path) == 0 {
		return "", "", false
	}

	// Check for HTTP version
	httpVersion := remaining[pathEnd+1:]
	if !strings.HasPrefix(httpVersion, "HTTP/") {
		return "", "", false
	}

	return method, path, true
}

// Validate HTTP method (mirrors eBPF logic)
func isValidHTTPMethod(method string) bool {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"}
	
	for _, validMethod := range validMethods {
		if method == validMethod {
			return true
		}
	}
	return false
}

// Test HTTP request parsing
func TestHTTPRequestParsing(t *testing.T) {
	testCases := getHTTPParseTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			method, path, valid := parseHTTPRequest(tc.input)

			if valid != tc.expectedValid {
				t.Errorf("Expected valid=%v, got valid=%v", tc.expectedValid, valid)
			}

			if tc.expectedValid {
				if method != tc.expectedMethod {
					t.Errorf("Expected method='%s', got method='%s'", tc.expectedMethod, method)
				}

				if path != tc.expectedPath {
					t.Errorf("Expected path='%s', got path='%s'", tc.expectedPath, path)
				}
			}
		})
	}
}

// Test HTTP method validation
func TestHTTPMethodValidation(t *testing.T) {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"}
	invalidMethods := []string{"INVALID", "get", "post", "CUSTOM", "", "G3T", "123"}

	for _, method := range validMethods {
		if !isValidHTTPMethod(method) {
			t.Errorf("Method '%s' should be valid", method)
		}
	}

	for _, method := range invalidMethods {
		if isValidHTTPMethod(method) {
			t.Errorf("Method '%s' should be invalid", method)
		}
	}
}

// Test edge cases for HTTP parsing
func TestHTTPParsingEdgeCases(t *testing.T) {
	edgeCases := []struct {
		name  string
		input string
	}{
		{"Very long method", strings.Repeat("A", 100) + " /path HTTP/1.1"},
		{"Very long path", "GET " + strings.Repeat("/a", 200) + " HTTP/1.1"},
		{"Binary data", "GET /path HTTP/1.1\x00\x01\x02"},
		{"Unicode characters", "GET /café HTTP/1.1"},
		{"Multiple spaces", "GET  /path  HTTP/1.1"},
		{"Tab characters", "GET\t/path\tHTTP/1.1"},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			method, path, valid := parseHTTPRequest(tc.input)
			t.Logf("Input: %q -> Method: %q, Path: %q, Valid: %v", tc.input, method, path, valid)
			// These are edge cases, so we just log the results for analysis
		})
	}
}

// Benchmark HTTP parsing performance
func BenchmarkHTTPParsing(b *testing.B) {
	testRequest := "GET /api/users/123?param=value HTTP/1.1\r\nHost: example.com\r\n\r\n"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseHTTPRequest(testRequest)
	}
}

// Test path validation for security
func TestPathSecurity(t *testing.T) {
	securityTestCases := []struct {
		path   string
		secure bool
	}{
		{"/normal/path", true},
		{"/api/users/123", true},
		{"/../../../etc/passwd", false}, // Path traversal
		{"/path\x00null", false},        // Null byte injection
		{"/path\r\ninjection", false},   // CRLF injection
		{"/very" + strings.Repeat("/long", 100), false}, // Extremely long path
	}

	for _, tc := range securityTestCases {
		t.Run("Path: "+tc.path, func(t *testing.T) {
			isSecure := isSecurePath(tc.path)
			if isSecure != tc.secure {
				t.Errorf("Path '%s' security check failed: expected %v, got %v", tc.path, tc.secure, isSecure)
			}
		})
	}
}

// Helper function to check path security
func isSecurePath(path string) bool {
	// Check for path traversal
	if strings.Contains(path, "..") {
		return false
	}
	
	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}
	
	// Check for CRLF injection
	if strings.Contains(path, "\r") || strings.Contains(path, "\n") {
		return false
	}
	
	// Check for reasonable length
	if len(path) > 1024 {
		return false
	}
	
	return true
}
