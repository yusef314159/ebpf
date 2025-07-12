package analytics

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// HTTPMetricsProcessor processes HTTP-related metrics
type HTTPMetricsProcessor struct {
	aggregators map[string]Aggregator
	metrics     map[string]interface{}
	mutex       sync.RWMutex
}

// NewHTTPMetricsProcessor creates a new HTTP metrics processor
func NewHTTPMetricsProcessor(aggregators map[string]Aggregator) *HTTPMetricsProcessor {
	return &HTTPMetricsProcessor{
		aggregators: aggregators,
		metrics:     make(map[string]interface{}),
	}
}

// Name returns the processor name
func (hmp *HTTPMetricsProcessor) Name() string {
	return "http_metrics"
}

// Process processes an HTTP event
func (hmp *HTTPMetricsProcessor) Process(event *tracing.TraceEvent) error {
	if event.Method == "" && event.EventType != "write" {
		return nil // Not an HTTP event
	}

	timestamp := time.Unix(0, int64(event.Timestamp))
	labels := map[string]string{
		"method":      event.Method,
		"service":     event.ServiceName,
		"event_type":  event.EventType,
	}

	// Extract path pattern (remove query parameters and IDs)
	pathPattern := extractPathPattern(event.Path)
	if pathPattern != "" {
		labels["path"] = pathPattern
	}

	// HTTP request count
	if event.EventType == "read" && event.Method != "" {
		hmp.recordMetric("http_requests_total", 1, labels, timestamp)
	}

	// HTTP response metrics
	if event.EventType == "write" && strings.HasPrefix(event.Payload, "HTTP/") {
		statusCode := extractStatusCode(event.Payload)
		if statusCode > 0 {
			labels["status_code"] = strconv.Itoa(statusCode)
			labels["status_class"] = getStatusClass(statusCode)
			
			// Response count by status
			hmp.recordMetric("http_responses_total", 1, labels, timestamp)
			
			// Error rate
			if statusCode >= 400 {
				hmp.recordMetric("http_errors_total", 1, labels, timestamp)
			}
		}

		// Response size
		if event.PayloadLen > 0 {
			hmp.recordMetric("http_response_size_bytes", float64(event.PayloadLen), labels, timestamp)
		}
	}

	// Update processor metrics
	hmp.mutex.Lock()
	hmp.metrics["events_processed"] = getOrIncrement(hmp.metrics, "events_processed")
	hmp.metrics["last_processed"] = timestamp
	hmp.mutex.Unlock()

	return nil
}

// Metrics returns processor metrics
func (hmp *HTTPMetricsProcessor) Metrics() map[string]interface{} {
	hmp.mutex.RLock()
	defer hmp.mutex.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range hmp.metrics {
		result[k] = v
	}
	return result
}

// recordMetric records a metric through aggregators
func (hmp *HTTPMetricsProcessor) recordMetric(name string, value float64, labels map[string]string, timestamp time.Time) {
	for _, aggregator := range hmp.aggregators {
		aggregator.Aggregate(name, value, labels, timestamp)
	}
}

// NetworkMetricsProcessor processes network-related metrics
type NetworkMetricsProcessor struct {
	aggregators map[string]Aggregator
	metrics     map[string]interface{}
	mutex       sync.RWMutex
}

// NewNetworkMetricsProcessor creates a new network metrics processor
func NewNetworkMetricsProcessor(aggregators map[string]Aggregator) *NetworkMetricsProcessor {
	return &NetworkMetricsProcessor{
		aggregators: aggregators,
		metrics:     make(map[string]interface{}),
	}
}

// Name returns the processor name
func (nmp *NetworkMetricsProcessor) Name() string {
	return "network_metrics"
}

// Process processes a network event
func (nmp *NetworkMetricsProcessor) Process(event *tracing.TraceEvent) error {
	timestamp := time.Unix(0, int64(event.Timestamp))
	labels := map[string]string{
		"src_ip":      event.SrcIP,
		"dst_ip":      event.DstIP,
		"src_port":    strconv.Itoa(int(event.SrcPort)),
		"dst_port":    strconv.Itoa(int(event.DstPort)),
		"protocol":    event.Protocol,
		"event_type": event.EventType,
	}

	// Network bytes transferred
	if event.PayloadLen > 0 {
		nmp.recordMetric("network_bytes_total", float64(event.PayloadLen), labels, timestamp)
	}

	// Connection events
	if event.EventType == "connect" {
		nmp.recordMetric("network_connections_total", 1, labels, timestamp)
	}

	// Accept events
	if event.EventType == "accept" {
		nmp.recordMetric("network_accepts_total", 1, labels, timestamp)
	}

	// Update processor metrics
	nmp.mutex.Lock()
	nmp.metrics["events_processed"] = getOrIncrement(nmp.metrics, "events_processed")
	nmp.metrics["last_processed"] = timestamp
	nmp.mutex.Unlock()

	return nil
}

// Metrics returns processor metrics
func (nmp *NetworkMetricsProcessor) Metrics() map[string]interface{} {
	nmp.mutex.RLock()
	defer nmp.mutex.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range nmp.metrics {
		result[k] = v
	}
	return result
}

// recordMetric records a metric through aggregators
func (nmp *NetworkMetricsProcessor) recordMetric(name string, value float64, labels map[string]string, timestamp time.Time) {
	for _, aggregator := range nmp.aggregators {
		aggregator.Aggregate(name, value, labels, timestamp)
	}
}

// PerformanceMetricsProcessor processes performance-related metrics
type PerformanceMetricsProcessor struct {
	aggregators    map[string]Aggregator
	metrics        map[string]interface{}
	requestTimes   map[uint64]time.Time // Track request start times
	mutex          sync.RWMutex
}

// NewPerformanceMetricsProcessor creates a new performance metrics processor
func NewPerformanceMetricsProcessor(aggregators map[string]Aggregator) *PerformanceMetricsProcessor {
	return &PerformanceMetricsProcessor{
		aggregators:  aggregators,
		metrics:      make(map[string]interface{}),
		requestTimes: make(map[uint64]time.Time),
	}
}

// Name returns the processor name
func (pmp *PerformanceMetricsProcessor) Name() string {
	return "performance_metrics"
}

// Process processes a performance event
func (pmp *PerformanceMetricsProcessor) Process(event *tracing.TraceEvent) error {
	timestamp := time.Unix(0, int64(event.Timestamp))
	labels := map[string]string{
		"service":    event.ServiceName,
		"method":     event.Method,
		"event_type": event.EventType,
	}

	// Track request start times
	if event.EventType == "read" && event.Method != "" {
		pmp.mutex.Lock()
		pmp.requestTimes[event.RequestID] = timestamp
		pmp.mutex.Unlock()
	}

	// Calculate request duration when response is received
	if event.EventType == "write" && strings.HasPrefix(event.Payload, "HTTP/") {
		pmp.mutex.Lock()
		startTime, exists := pmp.requestTimes[event.RequestID]
		if exists {
			delete(pmp.requestTimes, event.RequestID)
		}
		pmp.mutex.Unlock()

		if exists {
			duration := timestamp.Sub(startTime)
			labels["path"] = extractPathPattern(event.Path)
			
			// Record request duration
			pmp.recordMetric("http_request_duration_seconds", duration.Seconds(), labels, timestamp)
			
			// Record latency percentiles
			pmp.recordMetric("http_request_duration_histogram", duration.Seconds(), labels, timestamp)
		}
	}

	// Process and thread metrics
	labels["pid"] = strconv.Itoa(int(event.PID))
	labels["comm"] = event.Comm
	pmp.recordMetric("process_events_total", 1, labels, timestamp)

	// Update processor metrics
	pmp.mutex.Lock()
	pmp.metrics["events_processed"] = getOrIncrement(pmp.metrics, "events_processed")
	pmp.metrics["active_requests"] = len(pmp.requestTimes)
	pmp.metrics["last_processed"] = timestamp
	pmp.mutex.Unlock()

	return nil
}

// Metrics returns processor metrics
func (pmp *PerformanceMetricsProcessor) Metrics() map[string]interface{} {
	pmp.mutex.RLock()
	defer pmp.mutex.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range pmp.metrics {
		result[k] = v
	}
	return result
}

// recordMetric records a metric through aggregators
func (pmp *PerformanceMetricsProcessor) recordMetric(name string, value float64, labels map[string]string, timestamp time.Time) {
	for _, aggregator := range pmp.aggregators {
		aggregator.Aggregate(name, value, labels, timestamp)
	}
}

// ErrorMetricsProcessor processes error-related metrics
type ErrorMetricsProcessor struct {
	aggregators map[string]Aggregator
	metrics     map[string]interface{}
	mutex       sync.RWMutex
}

// NewErrorMetricsProcessor creates a new error metrics processor
func NewErrorMetricsProcessor(aggregators map[string]Aggregator) *ErrorMetricsProcessor {
	return &ErrorMetricsProcessor{
		aggregators: aggregators,
		metrics:     make(map[string]interface{}),
	}
}

// Name returns the processor name
func (emp *ErrorMetricsProcessor) Name() string {
	return "error_metrics"
}

// Process processes an error event
func (emp *ErrorMetricsProcessor) Process(event *tracing.TraceEvent) error {
	timestamp := time.Unix(0, int64(event.Timestamp))
	labels := map[string]string{
		"service":    event.ServiceName,
		"event_type": event.EventType,
	}

	// HTTP error detection
	if event.EventType == "write" && strings.HasPrefix(event.Payload, "HTTP/") {
		statusCode := extractStatusCode(event.Payload)
		if statusCode >= 400 {
			labels["status_code"] = strconv.Itoa(statusCode)
			labels["error_type"] = getErrorType(statusCode)
			labels["method"] = event.Method
			labels["path"] = extractPathPattern(event.Path)
			
			emp.recordMetric("http_errors_total", 1, labels, timestamp)
			
			// Error rate calculation
			emp.recordMetric("error_events", 1, labels, timestamp)
		}
	}

	// Network error detection (connection failures, etc.)
	if event.EventType == "connect" && event.PayloadLen == 0 {
		labels["error_type"] = "connection_failed"
		emp.recordMetric("network_errors_total", 1, labels, timestamp)
	}

	// Update processor metrics
	emp.mutex.Lock()
	emp.metrics["events_processed"] = getOrIncrement(emp.metrics, "events_processed")
	emp.metrics["last_processed"] = timestamp
	emp.mutex.Unlock()

	return nil
}

// Metrics returns processor metrics
func (emp *ErrorMetricsProcessor) Metrics() map[string]interface{} {
	emp.mutex.RLock()
	defer emp.mutex.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range emp.metrics {
		result[k] = v
	}
	return result
}

// recordMetric records a metric through aggregators
func (emp *ErrorMetricsProcessor) recordMetric(name string, value float64, labels map[string]string, timestamp time.Time) {
	for _, aggregator := range emp.aggregators {
		aggregator.Aggregate(name, value, labels, timestamp)
	}
}

// Helper functions

// extractPathPattern extracts a path pattern by removing IDs and query parameters
func extractPathPattern(path string) string {
	if path == "" {
		return ""
	}

	// Remove query parameters
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Replace numeric IDs with placeholders
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if isNumeric(part) || isUUID(part) {
			parts[i] = "{id}"
		}
	}

	return strings.Join(parts, "/")
}

// extractStatusCode extracts HTTP status code from response
func extractStatusCode(payload string) int {
	if len(payload) < 12 || !strings.HasPrefix(payload, "HTTP/") {
		return 0
	}

	// Find first space
	spaceIndex := strings.Index(payload[5:], " ")
	if spaceIndex == -1 || spaceIndex+9 > len(payload) {
		return 0
	}

	statusStr := payload[spaceIndex+6 : spaceIndex+9]
	if statusCode, err := strconv.Atoi(statusStr); err == nil {
		return statusCode
	}

	return 0
}

// getStatusClass returns the HTTP status class (1xx, 2xx, etc.)
func getStatusClass(statusCode int) string {
	switch {
	case statusCode >= 100 && statusCode < 200:
		return "1xx"
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500 && statusCode < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

// getErrorType returns the error type based on status code
func getErrorType(statusCode int) string {
	switch {
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500 && statusCode < 600:
		return "server_error"
	default:
		return "unknown_error"
	}
}

// isNumeric checks if a string is numeric
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// isUUID checks if a string looks like a UUID
func isUUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

// getOrIncrement gets a value from map or increments it
func getOrIncrement(m map[string]interface{}, key string) interface{} {
	if val, exists := m[key]; exists {
		if count, ok := val.(int); ok {
			return count + 1
		}
	}
	return 1
}
