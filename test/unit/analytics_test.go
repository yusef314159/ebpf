package unit

import (
	"context"
	"testing"
	"time"

	"ebpf-tracing/pkg/analytics"
	"ebpf-tracing/pkg/tracing"
)

// TestAnalyticsEngineCreation tests analytics engine creation
func TestAnalyticsEngineCreation(t *testing.T) {
	config := analytics.DefaultAnalyticsConfig()
	config.EnableAlerting = false // Disable alerting for testing
	config.EnableDashboard = false // Disable dashboard for testing

	engine, err := analytics.NewAnalyticsEngine(config)
	if err != nil {
		t.Fatalf("Failed to create analytics engine: %v", err)
	}

	if engine == nil {
		t.Fatal("Analytics engine should not be nil")
	}

	// Test health status
	health := engine.GetHealthStatus()
	if health["status"] != "healthy" {
		t.Errorf("Expected healthy status, got %v", health["status"])
	}

	if health["processors"].(int) == 0 {
		t.Error("Expected processors to be registered")
	}

	if health["aggregators"].(int) == 0 {
		t.Error("Expected aggregators to be registered")
	}
}

// TestAnalyticsEngineStartStop tests starting and stopping the engine
func TestAnalyticsEngineStartStop(t *testing.T) {
	config := analytics.DefaultAnalyticsConfig()
	config.EnableAlerting = false
	config.EnableDashboard = false
	config.WorkerThreads = 2

	engine, err := analytics.NewAnalyticsEngine(config)
	if err != nil {
		t.Fatalf("Failed to create analytics engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start engine
	err = engine.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start analytics engine: %v", err)
	}

	// Let it run for a short time
	time.Sleep(100 * time.Millisecond)

	// Stop engine
	engine.Stop()
}

// TestEventProcessing tests event processing through the analytics engine
func TestEventProcessing(t *testing.T) {
	config := analytics.DefaultAnalyticsConfig()
	config.EnableAlerting = false
	config.EnableDashboard = false
	config.BufferSize = 100
	config.WorkerThreads = 1
	config.FlushInterval = 100 * time.Millisecond

	engine, err := analytics.NewAnalyticsEngine(config)
	if err != nil {
		t.Fatalf("Failed to create analytics engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start engine
	err = engine.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start analytics engine: %v", err)
	}
	defer engine.Stop()

	// Create test events
	events := []*tracing.TraceEvent{
		{
			Timestamp:   uint64(time.Now().UnixNano()),
			RequestID:   1,
			PID:         1234,
			TID:         5678,
			SrcIP:       "192.168.1.100",
			DstIP:       "192.168.1.200",
			SrcPort:     8080,
			DstPort:     80,
			Comm:        "nginx",
			Method:      "GET",
			Path:        "/api/users",
			EventType:   "read",
			ServiceName: "nginx:80",
			PayloadLen:  100,
		},
		{
			Timestamp:   uint64(time.Now().UnixNano()),
			RequestID:   1,
			PID:         1234,
			TID:         5678,
			SrcIP:       "192.168.1.200",
			DstIP:       "192.168.1.100",
			SrcPort:     80,
			DstPort:     8080,
			Comm:        "nginx",
			EventType:   "write",
			ServiceName: "nginx:80",
			Payload:     "HTTP/1.1 200 OK\r\n\r\n",
			PayloadLen:  18,
		},
	}

	// Process events
	for _, event := range events {
		err := engine.ProcessEvent(event)
		if err != nil {
			t.Errorf("Failed to process event: %v", err)
		}
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Check metrics
	metrics := engine.GetMetrics()
	if len(metrics) == 0 {
		t.Error("Expected metrics to be generated")
	}

	// Check processor metrics
	for processorName, processorMetrics := range metrics {
		if processorName == "aggregated" {
			continue
		}
		
		if pm, ok := processorMetrics.(map[string]interface{}); ok {
			if eventsProcessed, exists := pm["events_processed"]; exists {
				if count, ok := eventsProcessed.(int); ok && count == 0 {
					t.Errorf("Processor %s should have processed events", processorName)
				}
			}
		}
	}
}

// TestHTTPMetricsProcessor tests HTTP metrics processing
func TestHTTPMetricsProcessor(t *testing.T) {
	aggregators := make(map[string]analytics.Aggregator)
	processor := analytics.NewHTTPMetricsProcessor(aggregators)

	if processor.Name() != "http_metrics" {
		t.Errorf("Expected processor name 'http_metrics', got '%s'", processor.Name())
	}

	// Test HTTP request event
	requestEvent := &tracing.TraceEvent{
		Timestamp: uint64(time.Now().UnixNano()),
		RequestID: 1,
		Method:    "GET",
		Path:      "/api/users/123",
		EventType: "read",
	}

	err := processor.Process(requestEvent)
	if err != nil {
		t.Errorf("Failed to process HTTP request event: %v", err)
	}

	// Test HTTP response event
	responseEvent := &tracing.TraceEvent{
		Timestamp:  uint64(time.Now().UnixNano()),
		RequestID:  1,
		EventType:  "write",
		Payload:    "HTTP/1.1 200 OK\r\n\r\n",
		PayloadLen: 18,
	}

	err = processor.Process(responseEvent)
	if err != nil {
		t.Errorf("Failed to process HTTP response event: %v", err)
	}

	// Check processor metrics
	metrics := processor.Metrics()
	if eventsProcessed, exists := metrics["events_processed"]; exists {
		if count, ok := eventsProcessed.(int); ok && count != 2 {
			t.Errorf("Expected 2 events processed, got %d", count)
		}
	} else {
		t.Error("Expected events_processed metric")
	}
}

// TestTimeSeriesAggregator tests time series aggregation
func TestTimeSeriesAggregator(t *testing.T) {
	windowSizes := []time.Duration{1 * time.Minute, 5 * time.Minute}
	aggregator := analytics.NewTimeSeriesAggregator(windowSizes)

	if aggregator.Name() != "timeseries" {
		t.Errorf("Expected aggregator name 'timeseries', got '%s'", aggregator.Name())
	}

	// Add test data
	labels := map[string]string{"service": "test", "method": "GET"}
	timestamp := time.Now()

	err := aggregator.Aggregate("http_requests_total", 1.0, labels, timestamp)
	if err != nil {
		t.Errorf("Failed to aggregate metric: %v", err)
	}

	err = aggregator.Aggregate("http_requests_total", 2.0, labels, timestamp.Add(30*time.Second))
	if err != nil {
		t.Errorf("Failed to aggregate metric: %v", err)
	}

	// Get metrics for 1 minute window
	metrics, err := aggregator.GetMetrics(1 * time.Minute)
	if err != nil {
		t.Errorf("Failed to get metrics: %v", err)
	}

	if len(metrics) == 0 {
		t.Error("Expected aggregated metrics")
	}

	// Check aggregated value
	for _, metric := range metrics {
		if metric.Value != 3.0 { // 1.0 + 2.0
			t.Errorf("Expected aggregated value 3.0, got %f", metric.Value)
		}
		if metric.Type != "timeseries" {
			t.Errorf("Expected type 'timeseries', got '%s'", metric.Type)
		}
	}
}

// TestHistogramAggregator tests histogram aggregation
func TestHistogramAggregator(t *testing.T) {
	aggregator := analytics.NewHistogramAggregator()

	if aggregator.Name() != "histogram" {
		t.Errorf("Expected aggregator name 'histogram', got '%s'", aggregator.Name())
	}

	// Add test data
	labels := map[string]string{"service": "test", "method": "GET"}
	timestamp := time.Now()

	values := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}
	for _, value := range values {
		err := aggregator.Aggregate("http_request_duration_histogram", value, labels, timestamp)
		if err != nil {
			t.Errorf("Failed to aggregate metric: %v", err)
		}
	}

	// Get metrics
	metrics, err := aggregator.GetMetrics(1 * time.Minute)
	if err != nil {
		t.Errorf("Failed to get metrics: %v", err)
	}

	if len(metrics) == 0 {
		t.Error("Expected histogram metrics")
	}

	// Check for percentile metrics
	foundP50 := false
	foundP95 := false
	foundCount := false
	foundAvg := false

	for name, metric := range metrics {
		if name == "http_request_duration_histogram,service=test,method=GET_p50" {
			foundP50 = true
			if metric.Value < 0.4 || metric.Value > 0.6 {
				t.Errorf("Expected P50 to be around 0.4-0.6, got %f", metric.Value)
			}
		}
		if name == "http_request_duration_histogram,service=test,method=GET_p95" {
			foundP95 = true
			if metric.Value < 0.8 || metric.Value > 1.0 {
				t.Errorf("Expected P95 to be around 0.8-1.0, got %f", metric.Value)
			}
		}
		if name == "http_request_duration_histogram,service=test,method=GET_count" {
			foundCount = true
			if metric.Value < 8 || metric.Value > 10 {
				t.Errorf("Expected count to be around 8-10, got %f", metric.Value)
			}
		}
		if name == "http_request_duration_histogram,service=test,method=GET_avg" {
			foundAvg = true
			if metric.Value < 0.4 || metric.Value > 0.6 {
				t.Errorf("Expected average to be around 0.4-0.6, got %f", metric.Value)
			}
		}
	}

	if !foundP50 {
		t.Error("Expected P50 metric")
	}
	if !foundP95 {
		t.Error("Expected P95 metric")
	}
	if !foundCount {
		t.Error("Expected count metric")
	}
	if !foundAvg {
		t.Error("Expected average metric")
	}
}

// TestCounterAggregator tests counter aggregation
func TestCounterAggregator(t *testing.T) {
	aggregator := analytics.NewCounterAggregator()

	if aggregator.Name() != "counter" {
		t.Errorf("Expected aggregator name 'counter', got '%s'", aggregator.Name())
	}

	// Add test data
	labels := map[string]string{"service": "test", "status": "200"}
	timestamp := time.Now()

	err := aggregator.Aggregate("http_requests_total", 1.0, labels, timestamp)
	if err != nil {
		t.Errorf("Failed to aggregate metric: %v", err)
	}

	err = aggregator.Aggregate("http_requests_total", 2.0, labels, timestamp)
	if err != nil {
		t.Errorf("Failed to aggregate metric: %v", err)
	}

	// Get metrics
	metrics, err := aggregator.GetMetrics(1 * time.Minute)
	if err != nil {
		t.Errorf("Failed to get metrics: %v", err)
	}

	if len(metrics) == 0 {
		t.Error("Expected counter metrics")
	}

	// Check counter value and rate
	foundCounter := false
	foundRate := false

	for name, metric := range metrics {
		if name == "http_requests_total,service=test,status=200" {
			foundCounter = true
			if metric.Value != 3.0 {
				t.Errorf("Expected counter value 3.0, got %f", metric.Value)
			}
		}
		if name == "http_requests_total,service=test,status=200_rate" {
			foundRate = true
			if metric.Value <= 0 {
				t.Errorf("Expected positive rate, got %f", metric.Value)
			}
		}
	}

	if !foundCounter {
		t.Error("Expected counter metric")
	}
	if !foundRate {
		t.Error("Expected rate metric")
	}
}

// BenchmarkEventProcessing benchmarks event processing performance
func BenchmarkEventProcessing(b *testing.B) {
	config := analytics.DefaultAnalyticsConfig()
	config.EnableAlerting = false
	config.EnableDashboard = false
	config.BufferSize = 100000
	config.WorkerThreads = 1

	engine, err := analytics.NewAnalyticsEngine(config)
	if err != nil {
		b.Fatalf("Failed to create analytics engine: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = engine.Start(ctx)
	if err != nil {
		b.Fatalf("Failed to start analytics engine: %v", err)
	}
	defer engine.Stop()

	event := &tracing.TraceEvent{
		Timestamp:   uint64(time.Now().UnixNano()),
		RequestID:   1,
		Method:      "GET",
		Path:        "/api/test",
		EventType:   "read",
		ServiceName: "test:80",
		PayloadLen:  100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.RequestID = uint64(i)
		engine.ProcessEvent(event)
	}
}

// BenchmarkHTTPMetricsProcessor benchmarks HTTP metrics processor
func BenchmarkHTTPMetricsProcessor(b *testing.B) {
	aggregators := make(map[string]analytics.Aggregator)
	processor := analytics.NewHTTPMetricsProcessor(aggregators)

	event := &tracing.TraceEvent{
		Timestamp: uint64(time.Now().UnixNano()),
		RequestID: 1,
		Method:    "GET",
		Path:      "/api/test",
		EventType: "read",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.Process(event)
	}
}
