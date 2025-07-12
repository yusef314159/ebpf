package tracing

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// TracingConfig holds configuration for distributed tracing
type TracingConfig struct {
	// Service information
	ServiceName    string `json:"service_name"`
	ServiceVersion string `json:"service_version"`
	Environment    string `json:"environment"`
	
	// Exporter configuration
	ExporterType   string `json:"exporter_type"` // jaeger, otlp, console
	JaegerEndpoint string `json:"jaeger_endpoint"`
	OTLPEndpoint   string `json:"otlp_endpoint"`
	
	// Sampling configuration
	SamplingRatio float64 `json:"sampling_ratio"`
	
	// Batch configuration
	BatchTimeout   time.Duration `json:"batch_timeout"`
	BatchSize      int           `json:"batch_size"`
	MaxQueueSize   int           `json:"max_queue_size"`
}

// TracingProvider manages OpenTelemetry tracing
type TracingProvider struct {
	config   *TracingConfig
	provider *trace.TracerProvider
	tracer   oteltrace.Tracer
}

// NewTracingProvider creates a new tracing provider
func NewTracingProvider(config *TracingConfig) (*TracingProvider, error) {
	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
			semconv.DeploymentEnvironment(config.Environment),
			attribute.String("tracer.name", "ebpf-http-tracer"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on configuration
	exporter, err := createExporter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	// Create tracer provider
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter,
			trace.WithBatchTimeout(config.BatchTimeout),
			trace.WithMaxExportBatchSize(config.BatchSize),
			trace.WithMaxQueueSize(config.MaxQueueSize),
		),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(config.SamplingRatio)),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)
	
	// Set global propagator for trace context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer("ebpf-http-tracer")

	return &TracingProvider{
		config:   config,
		provider: tp,
		tracer:   tracer,
	}, nil
}

// createExporter creates the appropriate trace exporter
func createExporter(config *TracingConfig) (trace.SpanExporter, error) {
	switch config.ExporterType {
	case "jaeger":
		return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.JaegerEndpoint)))
	case "otlp":
		return otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(config.OTLPEndpoint),
			otlptracegrpc.WithInsecure(),
		)
	case "console":
		// For development/debugging - use stdout exporter
		return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint("http://localhost:14268/api/traces")))
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}
}

// Shutdown gracefully shuts down the tracing provider
func (tp *TracingProvider) Shutdown(ctx context.Context) error {
	return tp.provider.Shutdown(ctx)
}

// CreateSpanFromEvent creates an OpenTelemetry span from an eBPF event
func (tp *TracingProvider) CreateSpanFromEvent(ctx context.Context, event *TraceEvent) (oteltrace.Span, error) {
	// Parse trace context from event
	traceID, err := parseTraceID(event.TraceContext.TraceID)
	if err != nil {
		return nil, fmt.Errorf("invalid trace ID: %w", err)
	}

	spanID, err := parseSpanID(event.TraceContext.SpanID)
	if err != nil {
		return nil, fmt.Errorf("invalid span ID: %w", err)
	}

	var parentSpanID oteltrace.SpanID
	if event.TraceContext.ParentSpanID != "" {
		parentSpanID, err = parseSpanID(event.TraceContext.ParentSpanID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent span ID: %w", err)
		}
	}

	// Create span context
	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: oteltrace.TraceFlags(event.TraceContext.TraceFlags),
		Remote:     event.CorrelationType == "incoming",
	})

	// Create parent context if parent span exists
	if parentSpanID.IsValid() {
		parentSpanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     parentSpanID,
			TraceFlags: oteltrace.TraceFlags(event.TraceContext.TraceFlags),
			Remote:     true,
		})
		ctx = oteltrace.ContextWithSpanContext(ctx, parentSpanContext)
	} else {
		ctx = oteltrace.ContextWithSpanContext(ctx, spanContext)
	}

	// Determine operation name
	operationName := fmt.Sprintf("%s %s", event.Method, event.Path)
	if event.Method == "" {
		operationName = "HTTP Request"
	}

	// Start span with existing context
	ctx, span := tp.tracer.Start(ctx, operationName,
		oteltrace.WithSpanKind(getSpanKind(event.CorrelationType)),
		oteltrace.WithTimestamp(time.Unix(0, int64(event.Timestamp))),
	)

	// Add span attributes
	addSpanAttributes(span, event)

	return span, nil
}

// getSpanKind determines the OpenTelemetry span kind based on correlation type
func getSpanKind(correlationType string) oteltrace.SpanKind {
	switch correlationType {
	case "incoming":
		return oteltrace.SpanKindServer
	case "outgoing":
		return oteltrace.SpanKindClient
	case "local":
		return oteltrace.SpanKindInternal
	default:
		return oteltrace.SpanKindUnspecified
	}
}

// addSpanAttributes adds relevant attributes to the span
func addSpanAttributes(span oteltrace.Span, event *TraceEvent) {
	// HTTP attributes
	if event.Method != "" {
		span.SetAttributes(semconv.HTTPMethod(event.Method))
	}
	if event.Path != "" {
		span.SetAttributes(semconv.HTTPTarget(event.Path))
	}

	// Network attributes
	span.SetAttributes(
		attribute.String("net.peer.ip", event.SrcIP),
		attribute.Int("net.peer.port", int(event.SrcPort)),
		attribute.String("net.host.ip", event.DstIP),
		attribute.Int("net.host.port", int(event.DstPort)),
	)

	// Process attributes
	span.SetAttributes(
		attribute.Int("process.pid", int(event.PID)),
		attribute.Int("process.tid", int(event.TID)),
		attribute.String("process.name", event.Comm),
	)

	// Service attributes
	if event.ServiceName != "" {
		span.SetAttributes(semconv.ServiceName(event.ServiceName))
	}
	if event.ServiceID != 0 {
		span.SetAttributes(attribute.Int("service.id", int(event.ServiceID)))
	}

	// Tracing metadata
	span.SetAttributes(
		attribute.String("ebpf.event_type", event.EventType),
		attribute.String("ebpf.correlation_type", event.CorrelationType),
		attribute.Int("ebpf.hop_count", int(event.HopCount)),
		attribute.Int("ebpf.payload_len", int(event.PayloadLen)),
	)

	// Protocol attributes
	if event.Protocol != "" {
		span.SetAttributes(attribute.String("net.transport", event.Protocol))
	}
}

// parseTraceID parses a hex string into an OpenTelemetry trace ID
func parseTraceID(traceIDStr string) (oteltrace.TraceID, error) {
	if len(traceIDStr) != 32 {
		return oteltrace.TraceID{}, fmt.Errorf("trace ID must be 32 hex characters, got %d", len(traceIDStr))
	}

	bytes, err := hex.DecodeString(traceIDStr)
	if err != nil {
		return oteltrace.TraceID{}, fmt.Errorf("invalid hex in trace ID: %w", err)
	}

	var traceID oteltrace.TraceID
	copy(traceID[:], bytes)
	return traceID, nil
}

// parseSpanID parses a hex string into an OpenTelemetry span ID
func parseSpanID(spanIDStr string) (oteltrace.SpanID, error) {
	if len(spanIDStr) != 16 {
		return oteltrace.SpanID{}, fmt.Errorf("span ID must be 16 hex characters, got %d", len(spanIDStr))
	}

	bytes, err := hex.DecodeString(spanIDStr)
	if err != nil {
		return oteltrace.SpanID{}, fmt.Errorf("invalid hex in span ID: %w", err)
	}

	var spanID oteltrace.SpanID
	copy(spanID[:], bytes)
	return spanID, nil
}

// TraceEvent represents an event with tracing information
type TraceEvent struct {
	Timestamp       uint64            `json:"timestamp"`
	RequestID       uint64            `json:"request_id"`
	PID             uint32            `json:"pid"`
	TID             uint32            `json:"tid"`
	SrcIP           string            `json:"src_ip"`
	DstIP           string            `json:"dst_ip"`
	SrcPort         uint16            `json:"src_port"`
	DstPort         uint16            `json:"dst_port"`
	Comm            string            `json:"comm"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	PayloadLen      uint32            `json:"payload_len"`
	Payload         string            `json:"payload"`
	EventType       string            `json:"event_type"`
	Protocol        string            `json:"protocol"`
	TraceContext    TraceContext      `json:"trace_context"`
	ServiceID       uint32            `json:"service_id"`
	ServiceName     string            `json:"service_name"`
	CorrelationType string            `json:"correlation_type"`
	HopCount        uint8             `json:"hop_count"`
}

// TraceContext represents distributed tracing context
type TraceContext struct {
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id,omitempty"`
	TraceFlags   uint8  `json:"trace_flags"`
	TraceState   string `json:"trace_state,omitempty"`
}

// DefaultTracingConfig returns a default tracing configuration
func DefaultTracingConfig() *TracingConfig {
	return &TracingConfig{
		ServiceName:    "ebpf-http-tracer",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		ExporterType:   "jaeger",
		JaegerEndpoint: "http://localhost:14268/api/traces",
		OTLPEndpoint:   "localhost:4317",
		SamplingRatio:  1.0,
		BatchTimeout:   5 * time.Second,
		BatchSize:      512,
		MaxQueueSize:   2048,
	}
}
