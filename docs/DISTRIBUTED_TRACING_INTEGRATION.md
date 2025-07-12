# Distributed Tracing Integration

The eBPF HTTP tracer now includes comprehensive distributed tracing integration with industry-standard OpenTelemetry and Jaeger support. This enables seamless integration with existing observability infrastructure and provides production-ready distributed tracing capabilities.

## Overview

The distributed tracing integration provides:

- **OpenTelemetry SDK Integration** for standard trace export
- **Jaeger Collector Support** for trace visualization
- **Automatic Span Lifecycle Management** with proper timing
- **Configurable Sampling Strategies** for production scalability
- **Multi-Exporter Support** (OTLP, Jaeger, Console)
- **Performance Optimized** span processing with batching

## Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Events   │───▶│   Span Manager   │───▶│  OpenTelemetry  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Request-Response │    │     Jaeger      │
                       │   Correlation    │    │   Collector     │
                       └──────────────────┘    └─────────────────┘
```

### Key Classes

1. **TracingProvider**: OpenTelemetry integration and span creation
2. **JaegerTracer**: Simplified Jaeger exporter wrapper
3. **SpanManager**: Lifecycle management and request-response correlation
4. **TraceEvent**: Enhanced event structure with distributed tracing context

## Configuration

### Basic Configuration

```json
{
  "output": {
    "enable_distributed_tracing": true,
    "distributed_tracing": {
      "enable_opentelemetry": true,
      "enable_jaeger": true,
      "service_name": "my-service",
      "environment": "production",
      "sampling_ratio": 0.1,
      "otlp_endpoint": "localhost:4317",
      "jaeger_collector_url": "http://localhost:14268/api/traces",
      "batch_size": 512,
      "batch_timeout_ms": 5000,
      "max_queue_size": 2048
    }
  }
}
```

### Environment Variables

```bash
# Enable distributed tracing
HTTP_TRACER_ENABLE_DISTRIBUTED_TRACING=true

# OpenTelemetry settings
HTTP_TRACER_ENABLE_OPENTELEMETRY=true
HTTP_TRACER_OTLP_ENDPOINT=localhost:4317

# Jaeger settings
HTTP_TRACER_ENABLE_JAEGER=true
HTTP_TRACER_JAEGER_COLLECTOR_URL=http://localhost:14268/api/traces

# Sampling
HTTP_TRACER_SAMPLING_RATIO=0.1
```

## OpenTelemetry Integration

### Span Creation

The system automatically creates OpenTelemetry spans from eBPF events:

```go
// Create span from eBPF event
span, err := tracingProvider.CreateSpanFromEvent(ctx, event)
if err != nil {
    return fmt.Errorf("failed to create span: %w", err)
}

// Span attributes are automatically added:
// - HTTP method, path, status code
// - Network information (IPs, ports)
// - Process information (PID, TID, comm)
// - Service identification
// - Distributed tracing context
```

### Supported Exporters

1. **OTLP gRPC**: Standard OpenTelemetry protocol
2. **Jaeger**: Direct Jaeger collector integration
3. **Console**: Development/debugging output

### Trace Context Propagation

The system supports W3C Trace Context standard:

```
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
```

## Jaeger Integration

### Simplified Architecture

The Jaeger integration uses OpenTelemetry's Jaeger exporter for simplicity and compatibility:

```go
// Create Jaeger exporter through OpenTelemetry
exp, err := jaeger.New(jaeger.WithCollectorEndpoint(
    jaeger.WithEndpoint(cfg.CollectorURL)))

// Create tracer provider with Jaeger exporter
tp := trace.NewTracerProvider(
    trace.WithBatcher(exp),
    trace.WithResource(res),
    trace.WithSampler(trace.TraceIDRatioBased(cfg.SamplingParam)),
)
```

### Jaeger UI Integration

Traces appear in Jaeger UI with rich metadata:

- **Service Map**: Automatic service topology discovery
- **Trace Timeline**: Request-response correlation with timing
- **Span Details**: HTTP methods, status codes, network information
- **Process Information**: PID, TID, process names
- **eBPF Metadata**: Event types, correlation types, hop counts

## Span Lifecycle Management

### Automatic Correlation

The SpanManager automatically correlates HTTP requests and responses:

```go
// Request event creates span
requestEvent := &TraceEvent{
    EventType: "read",
    Method:    "GET",
    Path:      "/api/users",
    RequestID: 12345,
}
spanManager.ProcessEvent(ctx, requestEvent)

// Response event completes span
responseEvent := &TraceEvent{
    EventType: "write",
    RequestID: 12345, // Same request ID
    Payload:   "HTTP/1.1 200 OK\r\n\r\n",
}
spanManager.ProcessEvent(ctx, responseEvent)
```

### Timeout Handling

Spans are automatically cleaned up if responses don't arrive:

```go
// Configurable span timeout
config := &SpanManagerConfig{
    SpanTimeout:     30 * time.Second,
    CleanupInterval: 10 * time.Second,
}

// Expired spans are marked with timeout status
span.SetStatus(codes.Error, "span timeout")
```

### Orphaned Response Handling

The system gracefully handles responses without matching requests:

```go
// Creates minimal span for orphaned response
func (sm *SpanManager) createOrphanedResponseSpan(ctx context.Context, event *TraceEvent) error {
    // Create span with "HTTP Response (orphaned)" operation name
    // Complete immediately with response data
}
```

## Performance Characteristics

### Benchmarking Results

```
BenchmarkSpanCreation-8         4649877    251.9 ns/op    72 B/op    3 allocs/op
BenchmarkStatusCodeExtraction-8 88943203   13.63 ns/op     0 B/op    0 allocs/op
BenchmarkTraceIDGeneration-8    136062     8260 ns/op      0 B/op    0 allocs/op
```

### Performance Optimizations

1. **Batched Export**: Configurable batch sizes and timeouts
2. **Efficient Correlation**: Hash-based request ID lookup
3. **Memory Pool**: Reused span structures
4. **Sampling**: Configurable sampling rates
5. **Async Processing**: Non-blocking span creation

## Usage Examples

### Basic Setup

```go
// Initialize distributed tracing
spanManager, err := initializeDistributedTracing(cfg)
if err != nil {
    log.Fatalf("Failed to initialize distributed tracing: %v", err)
}
defer spanManager.Shutdown()

// Process events
for event := range eventChannel {
    traceEvent := convertToTraceEvent(event)
    spanManager.ProcessEvent(context.Background(), traceEvent)
}
```

### Custom Span Attributes

```go
// Spans automatically include:
span.SetAttributes(
    semconv.HTTPMethod(event.Method),
    semconv.HTTPTarget(event.Path),
    attribute.String("net.peer.ip", event.SrcIP),
    attribute.Int("net.peer.port", int(event.SrcPort)),
    attribute.String("process.name", event.Comm),
    attribute.Int("process.pid", int(event.PID)),
    attribute.String("ebpf.event_type", event.EventType),
    attribute.String("ebpf.correlation_type", event.CorrelationType),
)
```

### Integration with Existing Systems

```go
// Extract trace context from HTTP headers
ctx := otel.GetTextMapPropagator().Extract(ctx, 
    propagation.HeaderCarrier(httpHeaders))

// Create child span
ctx, span := tracer.Start(ctx, "downstream-call")
defer span.End()

// Inject trace context for outgoing requests
otel.GetTextMapPropagator().Inject(ctx, 
    propagation.HeaderCarrier(outgoingHeaders))
```

## Deployment Scenarios

### Development Environment

```yaml
# docker-compose.yml
version: '3.8'
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  ebpf-tracer:
    build: .
    environment:
      - HTTP_TRACER_ENABLE_DISTRIBUTED_TRACING=true
      - HTTP_TRACER_JAEGER_COLLECTOR_URL=http://jaeger:14268/api/traces
    privileged: true
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
        image: ebpf-http-tracer:latest
        env:
        - name: HTTP_TRACER_ENABLE_DISTRIBUTED_TRACING
          value: "true"
        - name: HTTP_TRACER_OTLP_ENDPOINT
          value: "otel-collector:4317"
        - name: HTTP_TRACER_SAMPLING_RATIO
          value: "0.01"  # 1% sampling for production
        securityContext:
          privileged: true
```

## Monitoring and Observability

### Metrics

The system exposes metrics for monitoring:

- **Active Spans**: Current number of active spans
- **Span Creation Rate**: Spans created per second
- **Span Completion Rate**: Spans completed per second
- **Timeout Rate**: Spans timed out per second
- **Export Success Rate**: Successful trace exports

### Health Checks

```go
// Check span manager health
func (sm *SpanManager) HealthCheck() error {
    if sm.GetActiveSpanCount() > sm.maxActiveSpans {
        return fmt.Errorf("too many active spans: %d", sm.GetActiveSpanCount())
    }
    return nil
}
```

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Reduce batch size or increase flush interval
2. **Missing Traces**: Check sampling configuration and exporter endpoints
3. **Orphaned Spans**: Verify request-response correlation logic
4. **Export Failures**: Validate collector endpoints and network connectivity

### Debug Configuration

```json
{
  "distributed_tracing": {
    "enable_opentelemetry": true,
    "otlp_exporter": "console",
    "sampling_ratio": 1.0,
    "batch_size": 1,
    "batch_timeout_ms": 100
  }
}
```

## Future Enhancements

1. **Custom Samplers**: Adaptive and probabilistic sampling strategies
2. **Trace Analytics**: Real-time trace analysis and alerting
3. **Service Mesh Integration**: Automatic sidecar discovery
4. **Custom Exporters**: Support for additional tracing backends
5. **Trace Correlation**: Cross-service request correlation

The distributed tracing integration provides a production-ready foundation for observability in microservice environments while maintaining the high performance characteristics of the eBPF tracer.
