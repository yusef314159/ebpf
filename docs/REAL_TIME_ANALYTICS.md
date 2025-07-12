# Real-time Analytics Engine

The eBPF HTTP tracer now includes a comprehensive real-time analytics engine that provides stream processing, metrics aggregation, alerting, and visualization capabilities. This enables real-time monitoring and analysis of HTTP traffic patterns with configurable time windows and alerting rules.

## Overview

The real-time analytics engine provides:

- **Stream Processing**: Multi-threaded event processing with configurable workers
- **Time-Window Analytics**: Configurable time windows (1m, 5m, 15m, 1h, etc.)
- **Multiple Aggregation Types**: Time series, histograms, and counters
- **Real-time Alerting**: Configurable alert rules with threshold monitoring
- **Web Dashboard**: Interactive dashboard with real-time metrics visualization
- **Prometheus Integration**: Metrics export in Prometheus format
- **High Performance**: 727 ns/op processing with minimal memory overhead

## Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Events   │───▶│  Analytics       │───▶│   Processors    │
└─────────────────┘    │  Engine          │    └─────────────────┘
                       └──────────────────┘             │
                                │                       ▼
                                ▼              ┌─────────────────┐
                       ┌──────────────────┐    │   Aggregators   │
                       │  Alert Manager   │    └─────────────────┘
                       └──────────────────┘             │
                                │                       ▼
                                ▼              ┌─────────────────┐
                       ┌──────────────────┐    │  Metric Store   │
                       │  Web Dashboard   │    └─────────────────┘
                       └──────────────────┘             │
                                                        ▼
                                               ┌─────────────────┐
                                               │  Prometheus     │
                                               │  Endpoint       │
                                               └─────────────────┘
```

### Key Classes

1. **AnalyticsEngine**: Main orchestrator for stream processing and analytics
2. **Processors**: HTTP, Network, Performance, and Error metrics processors
3. **Aggregators**: Time series, histogram, and counter aggregation
4. **MetricStore**: Time-series data storage with configurable retention
5. **AlertManager**: Rule-based alerting with threshold monitoring
6. **Dashboard**: Web-based real-time visualization

## Configuration

### Basic Configuration

```json
{
  "output": {
    "enable_analytics": true,
    "analytics": {
      "buffer_size": 10000,
      "worker_threads": 4,
      "flush_interval_seconds": 10,
      "window_sizes": ["1m", "5m", "15m", "1h"],
      "retention_hours": 24,
      "enabled_metrics": [
        "http_requests_total",
        "http_request_duration",
        "http_response_size",
        "network_bytes_total",
        "error_rate"
      ],
      "enable_alerting": true,
      "alert_rules": [
        {
          "name": "high_error_rate",
          "metric": "http_errors_total_rate",
          "condition": "gt",
          "threshold": 10.0,
          "duration_seconds": 300,
          "labels": {"severity": "warning"},
          "annotations": {"description": "High HTTP error rate detected"}
        }
      ],
      "enable_dashboard": true,
      "dashboard_port": 8080,
      "metrics_endpoint": "/metrics"
    }
  }
}
```

### Environment Variables

```bash
# Enable analytics
HTTP_TRACER_ENABLE_ANALYTICS=true

# Processing settings
HTTP_TRACER_ANALYTICS_BUFFER_SIZE=10000
HTTP_TRACER_ANALYTICS_WORKER_THREADS=4
HTTP_TRACER_ANALYTICS_FLUSH_INTERVAL_SECONDS=10

# Dashboard settings
HTTP_TRACER_ANALYTICS_ENABLE_DASHBOARD=true
HTTP_TRACER_ANALYTICS_DASHBOARD_PORT=8080

# Alerting
HTTP_TRACER_ANALYTICS_ENABLE_ALERTING=true
```

## Stream Processing

### Multi-threaded Architecture

The analytics engine uses a multi-threaded architecture for high-performance stream processing:

```go
// Analytics engine with configurable workers
type AnalyticsEngine struct {
    config          *AnalyticsConfig
    processors      map[string]Processor
    aggregators     map[string]Aggregator
    eventChannel    chan *tracing.TraceEvent
    workerThreads   int
}

// Worker processes events from the event channel
func (ae *AnalyticsEngine) worker(ctx context.Context, workerID int) {
    for event := range ae.eventChannel {
        ae.processEvent(event)
    }
}
```

### Event Processing Pipeline

1. **Event Ingestion**: eBPF events are queued in a buffered channel
2. **Worker Distribution**: Multiple workers process events concurrently
3. **Processor Chain**: Events flow through HTTP, Network, Performance, and Error processors
4. **Aggregation**: Processed metrics are aggregated using time series, histograms, and counters
5. **Storage**: Aggregated metrics are stored with configurable retention

## Metrics and Processors

### HTTP Metrics Processor

Processes HTTP-specific metrics:

```go
// HTTP metrics generated
- http_requests_total (by method, path, service)
- http_responses_total (by status_code, status_class)
- http_errors_total (by error_type)
- http_response_size_bytes (response payload size)
```

### Network Metrics Processor

Processes network-level metrics:

```go
// Network metrics generated
- network_bytes_total (by protocol, direction)
- network_connections_total (connection events)
- network_accepts_total (accept events)
- network_errors_total (connection failures)
```

### Performance Metrics Processor

Processes performance and latency metrics:

```go
// Performance metrics generated
- http_request_duration_seconds (request-response latency)
- http_request_duration_histogram (latency percentiles)
- process_events_total (by PID, process name)
```

### Error Metrics Processor

Processes error detection and classification:

```go
// Error metrics generated
- http_errors_total (by status_code, error_type)
- error_events (error event counting)
- network_errors_total (network-level errors)
```

## Aggregation Types

### Time Series Aggregation

Aggregates metrics over configurable time windows:

```go
// Time windows: 1m, 5m, 15m, 1h, 24h
type TimeSeriesAggregator struct {
    windowSizes []time.Duration
    data        map[string]*TimeSeriesData
}

// Provides sum, average, rate calculations
```

### Histogram Aggregation

Calculates percentiles for latency metrics:

```go
// Percentiles: P50, P90, P95, P99
type HistogramAggregator struct {
    data map[string]*HistogramData
}

// Provides percentile, count, average calculations
```

### Counter Aggregation

Tracks cumulative counters and rates:

```go
// Counter metrics with rate calculation
type CounterAggregator struct {
    data map[string]*CounterData
}

// Provides total count and rate per second
```

## Real-time Alerting

### Alert Rules Configuration

```json
{
  "alert_rules": [
    {
      "name": "high_error_rate",
      "metric": "http_errors_total_rate",
      "condition": "gt",
      "threshold": 10.0,
      "duration_seconds": 300,
      "labels": {"severity": "warning", "team": "backend"},
      "annotations": {
        "description": "HTTP error rate exceeded 10 errors/sec",
        "runbook": "https://wiki.company.com/runbooks/high-error-rate"
      }
    },
    {
      "name": "high_latency",
      "metric": "http_request_duration_histogram_p95",
      "condition": "gt",
      "threshold": 1.0,
      "duration_seconds": 180,
      "labels": {"severity": "critical"},
      "annotations": {
        "description": "95th percentile latency exceeded 1 second"
      }
    }
  ]
}
```

### Alert Conditions

Supported alert conditions:
- **gt**: Greater than threshold
- **lt**: Less than threshold
- **eq**: Equal to threshold
- **ne**: Not equal to threshold
- **gte**: Greater than or equal to threshold
- **lte**: Less than or equal to threshold

### Alert States

- **Firing**: Condition is currently met
- **Resolved**: Condition is no longer met
- **Pending**: Condition met but duration not reached

## Web Dashboard

### Real-time Visualization

The web dashboard provides real-time visualization at `http://localhost:8080`:

- **System Health**: Engine status, buffer usage, worker threads
- **Real-time Metrics**: Current metric values with auto-refresh
- **Processor Statistics**: Events processed per processor
- **Active Alerts**: Current firing and resolved alerts
- **Historical Data**: Time-series charts and trends

### API Endpoints

```
GET /api/metrics?window=5m    - Get aggregated metrics
GET /api/health               - System health status
GET /api/alerts               - Active alerts and history
GET /api/processors           - Processor statistics
GET /api/stats                - Overall system statistics
GET /metrics                  - Prometheus metrics format
```

### Dashboard Features

- **Auto-refresh**: Updates every 30 seconds
- **Responsive Design**: Works on desktop and mobile
- **Real-time Status**: Live system health monitoring
- **Alert Visualization**: Color-coded alert status
- **Metric Filtering**: Filter by time windows

## Prometheus Integration

### Metrics Export

The analytics engine exports metrics in Prometheus format:

```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",service="nginx:80",path="/api/users"} 1234

# HELP http_request_duration_seconds HTTP request duration
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_p50{service="nginx:80"} 0.123
http_request_duration_seconds_p95{service="nginx:80"} 0.456
http_request_duration_seconds_p99{service="nginx:80"} 0.789
```

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ebpf-http-tracer'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

## Performance Characteristics

### Benchmarking Results

```
BenchmarkEventProcessing-8      4649877    251.9 ns/op    72 B/op    3 allocs/op
BenchmarkHTTPMetricsProcessor-8 1651954    727.0 ns/op   584 B/op   10 allocs/op
```

### Performance Optimizations

1. **Buffered Channels**: Configurable buffer sizes for event queuing
2. **Worker Pool**: Multiple worker threads for parallel processing
3. **Efficient Aggregation**: In-memory aggregation with periodic flushing
4. **Memory Management**: Configurable retention periods and cleanup
5. **Batch Processing**: Batched metric storage and export

## Usage Examples

### Basic Setup

```go
// Initialize analytics engine
analyticsConfig := &analytics.AnalyticsConfig{
    BufferSize:      10000,
    WorkerThreads:   4,
    FlushInterval:   10 * time.Second,
    WindowSizes:     []time.Duration{1*time.Minute, 5*time.Minute},
    EnableDashboard: true,
    DashboardPort:   8080,
}

engine, err := analytics.NewAnalyticsEngine(analyticsConfig)
if err != nil {
    log.Fatalf("Failed to create analytics engine: %v", err)
}

// Start engine
err = engine.Start(context.Background())
if err != nil {
    log.Fatalf("Failed to start analytics engine: %v", err)
}
defer engine.Stop()

// Process events
for event := range eventChannel {
    engine.ProcessEvent(event)
}
```

### Custom Processors

```go
// Register custom processor
type CustomProcessor struct {
    // Custom logic
}

func (cp *CustomProcessor) Process(event *tracing.TraceEvent) error {
    // Custom processing logic
    return nil
}

engine.RegisterProcessor(customProcessor)
```

### Custom Alert Rules

```go
// Add custom alert rule
alertRule := analytics.AlertRuleConfig{
    Name:      "custom_metric_alert",
    Metric:    "custom_metric_total",
    Condition: "gt",
    Threshold: 100.0,
    Duration:  5 * time.Minute,
}

// Configure in analytics config
config.AlertRules = append(config.AlertRules, alertRule)
```

## Deployment Scenarios

### Development Environment

```yaml
# docker-compose.yml
version: '3.8'
services:
  ebpf-tracer:
    build: .
    environment:
      - HTTP_TRACER_ENABLE_ANALYTICS=true
      - HTTP_TRACER_ANALYTICS_DASHBOARD_PORT=8080
    ports:
      - "8080:8080"  # Analytics dashboard
    privileged: true

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

### Production Environment

```yaml
# Kubernetes deployment
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-http-tracer
spec:
  template:
    spec:
      containers:
      - name: tracer
        env:
        - name: HTTP_TRACER_ENABLE_ANALYTICS
          value: "true"
        - name: HTTP_TRACER_ANALYTICS_BUFFER_SIZE
          value: "50000"
        - name: HTTP_TRACER_ANALYTICS_WORKER_THREADS
          value: "8"
        - name: HTTP_TRACER_ANALYTICS_DASHBOARD_PORT
          value: "8080"
        ports:
        - containerPort: 8080
          name: dashboard
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Monitoring and Observability

### Health Monitoring

```go
// Health check endpoint
GET /api/health

{
  "status": "healthy",
  "processors": 4,
  "aggregators": 3,
  "buffer_size": 150,
  "buffer_capacity": 10000,
  "worker_threads": 4
}
```

### Performance Metrics

- **Event Processing Rate**: Events processed per second
- **Buffer Utilization**: Current buffer usage percentage
- **Worker Efficiency**: Events processed per worker
- **Memory Usage**: Current memory consumption
- **Alert Response Time**: Time to detect and fire alerts

## Future Enhancements

1. **Machine Learning**: Anomaly detection using ML algorithms
2. **Advanced Visualizations**: Grafana dashboard integration
3. **Custom Exporters**: Support for additional monitoring systems
4. **Distributed Analytics**: Multi-node analytics processing
5. **Stream Analytics**: Complex event processing and pattern detection

The real-time analytics engine provides comprehensive monitoring and analysis capabilities while maintaining the high performance characteristics of the eBPF tracer, enabling production-ready observability for HTTP traffic in microservice environments.
