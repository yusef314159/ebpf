package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// JSONEvent represents the JSON output from the tracer
type JSONEvent struct {
	Timestamp   string `json:"timestamp"`
	RequestID   uint64 `json:"request_id,omitempty"`
	PID         uint32 `json:"pid"`
	TID         uint32 `json:"tid"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Comm        string `json:"comm"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	PayloadLen  uint32 `json:"payload_len"`
	Payload     string `json:"payload"`
	EventType   string `json:"event_type"`
	Protocol    string `json:"protocol"`
}

// TestServer represents a test HTTP server
type TestServer struct {
	cmd    *exec.Cmd
	port   string
	cancel context.CancelFunc
}

// StartTestServer starts the Flask test server
func StartTestServer(t *testing.T) *TestServer {
	ctx, cancel := context.WithCancel(context.Background())
	
	cmd := exec.CommandContext(ctx, "python3", "../flask_server.py")
	cmd.Dir = "../../test"
	
	// Start the server
	err := cmd.Start()
	if err != nil {
		cancel()
		t.Fatalf("Failed to start test server: %v", err)
	}
	
	// Wait for server to be ready
	time.Sleep(2 * time.Second)
	
	// Test if server is responding
	resp, err := http.Get("http://localhost:5000/health")
	if err != nil {
		cmd.Process.Kill()
		cancel()
		t.Fatalf("Test server not responding: %v", err)
	}
	resp.Body.Close()
	
	return &TestServer{
		cmd:    cmd,
		port:   "5000",
		cancel: cancel,
	}
}

// Stop stops the test server
func (ts *TestServer) Stop() {
	if ts.cmd != nil && ts.cmd.Process != nil {
		ts.cmd.Process.Signal(syscall.SIGTERM)
		ts.cmd.Wait()
	}
	if ts.cancel != nil {
		ts.cancel()
	}
}

// TracerProcess represents a running tracer process
type TracerProcess struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	cancel context.CancelFunc
	events chan JSONEvent
}

// StartTracer starts the HTTP tracer
func StartTracer(t *testing.T) *TracerProcess {
	// Check if running as root
	if os.Geteuid() != 0 {
		t.Skip("Integration tests require root privileges")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cmd := exec.CommandContext(ctx, "../../build/http-tracer")
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	
	err = cmd.Start()
	if err != nil {
		cancel()
		t.Fatalf("Failed to start tracer: %v", err)
	}
	
	events := make(chan JSONEvent, 100)
	
	// Start reading events
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			
			var event JSONEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Logf("Failed to parse JSON event: %v, line: %s", err, line)
				continue
			}
			
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	
	// Wait for tracer to initialize
	time.Sleep(3 * time.Second)
	
	return &TracerProcess{
		cmd:    cmd,
		stdout: stdout,
		cancel: cancel,
		events: events,
	}
}

// Stop stops the tracer process
func (tp *TracerProcess) Stop() {
	if tp.cmd != nil && tp.cmd.Process != nil {
		tp.cmd.Process.Signal(syscall.SIGTERM)
		tp.cmd.Wait()
	}
	if tp.cancel != nil {
		tp.cancel()
	}
	if tp.stdout != nil {
		tp.stdout.Close()
	}
}

// GetEvents returns events received within the timeout
func (tp *TracerProcess) GetEvents(timeout time.Duration) []JSONEvent {
	var events []JSONEvent
	deadline := time.After(timeout)
	
	for {
		select {
		case event, ok := <-tp.events:
			if !ok {
				return events
			}
			events = append(events, event)
		case <-deadline:
			return events
		}
	}
}

// Test basic HTTP request tracing
func TestBasicHTTPTracing(t *testing.T) {
	// Start test server
	server := StartTestServer(t)
	defer server.Stop()
	
	// Start tracer
	tracer := StartTracer(t)
	defer tracer.Stop()
	
	// Make HTTP requests
	testRequests := []struct {
		method string
		path   string
	}{
		{"GET", "/"},
		{"GET", "/api/users"},
		{"POST", "/api/users"},
		{"PUT", "/api/users/123"},
		{"DELETE", "/api/users/123"},
	}
	
	for _, req := range testRequests {
		t.Run(fmt.Sprintf("%s_%s", req.method, strings.ReplaceAll(req.path, "/", "_")), func(t *testing.T) {
			// Make HTTP request
			client := &http.Client{Timeout: 5 * time.Second}
			httpReq, err := http.NewRequest(req.method, "http://localhost:5000"+req.path, nil)
			if err != nil {
				t.Fatalf("Failed to create HTTP request: %v", err)
			}
			
			resp, err := client.Do(httpReq)
			if err != nil {
				t.Fatalf("Failed to make HTTP request: %v", err)
			}
			resp.Body.Close()
			
			// Wait for events
			events := tracer.GetEvents(5 * time.Second)
			
			// Verify we got events
			if len(events) == 0 {
				t.Fatal("No events received from tracer")
			}
			
			// Look for our request in the events
			found := false
			for _, event := range events {
				if event.Method == req.method && strings.Contains(event.Path, req.path) {
					found = true
					t.Logf("Found matching event: Method=%s, Path=%s, PID=%d", 
						event.Method, event.Path, event.PID)
					break
				}
			}
			
			if !found {
				t.Errorf("Did not find matching event for %s %s", req.method, req.path)
				t.Logf("Received %d events:", len(events))
				for i, event := range events {
					t.Logf("  Event %d: Method=%s, Path=%s, PID=%d", 
						i, event.Method, event.Path, event.PID)
				}
			}
		})
	}
}

// Test concurrent HTTP requests
func TestConcurrentHTTPTracing(t *testing.T) {
	// Start test server
	server := StartTestServer(t)
	defer server.Stop()
	
	// Start tracer
	tracer := StartTracer(t)
	defer tracer.Stop()
	
	// Make concurrent requests
	numRequests := 10
	done := make(chan bool, numRequests)
	
	for i := 0; i < numRequests; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			client := &http.Client{Timeout: 5 * time.Second}
			url := fmt.Sprintf("http://localhost:5000/api/test/%d", id)
			
			resp, err := client.Get(url)
			if err != nil {
				t.Errorf("Request %d failed: %v", id, err)
				return
			}
			resp.Body.Close()
		}(i)
	}
	
	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
	
	// Wait for events
	events := tracer.GetEvents(10 * time.Second)
	
	// Verify we got events
	if len(events) == 0 {
		t.Fatal("No events received from tracer")
	}
	
	// Count unique request IDs
	requestIDs := make(map[uint64]bool)
	for _, event := range events {
		if event.RequestID != 0 {
			requestIDs[event.RequestID] = true
		}
	}
	
	t.Logf("Received %d events with %d unique request IDs", len(events), len(requestIDs))
	
	// We should have at least some events (may not be exactly numRequests due to filtering)
	if len(events) < numRequests/2 {
		t.Errorf("Expected at least %d events, got %d", numRequests/2, len(events))
	}
}

// Test tracer performance under load
func TestTracerPerformance(t *testing.T) {
	// Start test server
	server := StartTestServer(t)
	defer server.Stop()
	
	// Start tracer
	tracer := StartTracer(t)
	defer tracer.Stop()
	
	// Performance test parameters
	numRequests := 100
	concurrency := 10
	
	start := time.Now()
	
	// Make requests with limited concurrency
	semaphore := make(chan struct{}, concurrency)
	done := make(chan bool, numRequests)
	
	for i := 0; i < numRequests; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			client := &http.Client{Timeout: 5 * time.Second}
			url := fmt.Sprintf("http://localhost:5000/api/perf/%d", id)
			
			resp, err := client.Get(url)
			if err != nil {
				t.Errorf("Request %d failed: %v", id, err)
				return
			}
			resp.Body.Close()
		}(i)
	}
	
	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}
	
	duration := time.Since(start)
	
	// Wait for events
	events := tracer.GetEvents(10 * time.Second)
	
	// Performance metrics
	requestsPerSecond := float64(numRequests) / duration.Seconds()
	eventsPerRequest := float64(len(events)) / float64(numRequests)
	
	t.Logf("Performance Results:")
	t.Logf("  Total requests: %d", numRequests)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Requests/second: %.2f", requestsPerSecond)
	t.Logf("  Total events: %d", len(events))
	t.Logf("  Events/request: %.2f", eventsPerRequest)
	
	// Basic performance assertions
	if requestsPerSecond < 10 {
		t.Errorf("Performance too low: %.2f requests/second", requestsPerSecond)
	}
	
	if len(events) == 0 {
		t.Error("No events captured during performance test")
	}
}
