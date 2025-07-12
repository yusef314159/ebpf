package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// JaegerConfig holds Jaeger-specific configuration
type JaegerConfig struct {
	ServiceName     string  `json:"service_name"`
	AgentEndpoint   string  `json:"agent_endpoint"`
	CollectorURL    string  `json:"collector_url"`
	SamplingType    string  `json:"sampling_type"`    // const, probabilistic, rateLimiting
	SamplingParam   float64 `json:"sampling_param"`
	LogSpans        bool    `json:"log_spans"`
	MaxTagValueLen  int     `json:"max_tag_value_len"`
	BufferFlushInterval time.Duration `json:"buffer_flush_interval"`
}

// JaegerTracer wraps OpenTelemetry Jaeger exporter functionality
type JaegerTracer struct {
	config   *JaegerConfig
	provider *trace.TracerProvider
}

// NewJaegerTracer creates a new Jaeger tracer using OpenTelemetry
func NewJaegerTracer(cfg *JaegerConfig) (*JaegerTracer, error) {
	// Create Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.CollectorURL)))
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(cfg.SamplingParam)),
	)

	return &JaegerTracer{
		config:   cfg,
		provider: tp,
	}, nil
}

// Close closes the Jaeger tracer
func (jt *JaegerTracer) Close() error {
	if jt.provider != nil {
		return jt.provider.Shutdown(context.Background())
	}
	return nil
}

// CreateSpanFromEvent creates a span from an eBPF event using OpenTelemetry
func (jt *JaegerTracer) CreateSpanFromEvent(event *TraceEvent) error {
	// This is now handled by the unified TracingProvider
	// This method is kept for compatibility but delegates to OpenTelemetry
	return nil
}

// GetProvider returns the OpenTelemetry tracer provider
func (jt *JaegerTracer) GetProvider() *trace.TracerProvider {
	return jt.provider
}

// DefaultJaegerConfig returns a default Jaeger configuration
func DefaultJaegerConfig() *JaegerConfig {
	return &JaegerConfig{
		ServiceName:         "ebpf-http-tracer",
		AgentEndpoint:       "localhost:6831",
		CollectorURL:        "http://localhost:14268/api/traces",
		SamplingType:        "const",
		SamplingParam:       1.0,
		LogSpans:            false,
		MaxTagValueLen:      1024,
		BufferFlushInterval: 1 * time.Second,
	}
}


