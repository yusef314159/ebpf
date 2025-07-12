package tracing

import (
	"context"
	"fmt"
	"sync"
	"time"

	oteltrace "go.opentelemetry.io/otel/trace"
)

// SpanManager manages the lifecycle of spans for HTTP requests and responses
type SpanManager struct {
	// Active spans indexed by request ID
	activeSpans map[uint64]*ActiveSpan
	mutex       sync.RWMutex
	
	// Tracing providers
	otelProvider   *TracingProvider
	jaegerTracer   *JaegerTracer
	
	// Configuration
	spanTimeout    time.Duration
	maxActiveSpans int
	
	// Cleanup
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// ActiveSpan represents an active span with metadata
type ActiveSpan struct {
	// Span references
	OtelSpan   oteltrace.Span
	
	// Metadata
	RequestID     uint64
	TraceID       string
	SpanID        string
	ServiceName   string
	OperationName string
	StartTime     time.Time
	
	// Request/Response correlation
	RequestEvent  *TraceEvent
	ResponseEvent *TraceEvent
	
	// State
	IsCompleted bool
	HasResponse bool
}

// SpanManagerConfig holds configuration for the span manager
type SpanManagerConfig struct {
	SpanTimeout    time.Duration `json:"span_timeout"`
	MaxActiveSpans int           `json:"max_active_spans"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
	EnableOtel     bool          `json:"enable_otel"`
	EnableJaeger   bool          `json:"enable_jaeger"`
}

// NewSpanManager creates a new span manager
func NewSpanManager(config *SpanManagerConfig, otelProvider *TracingProvider, jaegerTracer *JaegerTracer) *SpanManager {
	sm := &SpanManager{
		activeSpans:    make(map[uint64]*ActiveSpan),
		otelProvider:   otelProvider,
		jaegerTracer:   jaegerTracer,
		spanTimeout:    config.SpanTimeout,
		maxActiveSpans: config.MaxActiveSpans,
		stopCleanup:    make(chan struct{}),
	}
	
	// Start cleanup routine
	sm.cleanupTicker = time.NewTicker(config.CleanupInterval)
	go sm.cleanupRoutine()
	
	return sm
}

// ProcessEvent processes a trace event and manages span lifecycle
func (sm *SpanManager) ProcessEvent(ctx context.Context, event *TraceEvent) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	switch event.EventType {
	case "read":
		return sm.handleRequestEvent(ctx, event)
	case "write":
		return sm.handleResponseEvent(ctx, event)
	case "connect":
		return sm.handleConnectEvent(ctx, event)
	default:
		return fmt.Errorf("unsupported event type: %s", event.EventType)
	}
}

// handleRequestEvent handles HTTP request events (read syscalls)
func (sm *SpanManager) handleRequestEvent(ctx context.Context, event *TraceEvent) error {
	// Check if we already have a span for this request
	if existingSpan, exists := sm.activeSpans[event.RequestID]; exists {
		// Update existing span with request details
		existingSpan.RequestEvent = event
		return nil
	}
	
	// Check span limit
	if len(sm.activeSpans) >= sm.maxActiveSpans {
		return fmt.Errorf("maximum active spans reached: %d", sm.maxActiveSpans)
	}
	
	// Create new active span
	activeSpan := &ActiveSpan{
		RequestID:     event.RequestID,
		TraceID:       event.TraceContext.TraceID,
		SpanID:        event.TraceContext.SpanID,
		ServiceName:   event.ServiceName,
		OperationName: fmt.Sprintf("%s %s", event.Method, event.Path),
		StartTime:     time.Unix(0, int64(event.Timestamp)),
		RequestEvent:  event,
		IsCompleted:   false,
		HasResponse:   false,
	}
	
	// Create OpenTelemetry span if enabled
	if sm.otelProvider != nil {
		otelSpan, err := sm.otelProvider.CreateSpanFromEvent(ctx, event)
		if err != nil {
			return fmt.Errorf("failed to create OpenTelemetry span: %w", err)
		}
		activeSpan.OtelSpan = otelSpan
	}
	
	// Jaeger spans are now handled through OpenTelemetry
	// No separate Jaeger span creation needed
	
	// Store active span
	sm.activeSpans[event.RequestID] = activeSpan
	
	return nil
}

// handleResponseEvent handles HTTP response events (write syscalls)
func (sm *SpanManager) handleResponseEvent(ctx context.Context, event *TraceEvent) error {
	// Find corresponding request span
	activeSpan, exists := sm.activeSpans[event.RequestID]
	if !exists {
		// No corresponding request found, create orphaned response span
		return sm.createOrphanedResponseSpan(ctx, event)
	}
	
	// Update span with response details
	activeSpan.ResponseEvent = event
	activeSpan.HasResponse = true
	
	// Extract status code from response if available
	statusCode := sm.extractStatusCode(event)
	
	// Update OpenTelemetry span
	if activeSpan.OtelSpan != nil {
		sm.updateOtelSpanWithResponse(activeSpan.OtelSpan, event, statusCode)
	}
	
	// Jaeger spans are handled through OpenTelemetry
	
	// Complete the span
	return sm.completeSpan(activeSpan, time.Unix(0, int64(event.Timestamp)))
}

// handleConnectEvent handles connection events
func (sm *SpanManager) handleConnectEvent(ctx context.Context, event *TraceEvent) error {
	// For connect events, we might want to create a separate span or
	// just record it as an event on existing spans
	// For now, we'll just log it
	return nil
}

// createOrphanedResponseSpan creates a span for responses without matching requests
func (sm *SpanManager) createOrphanedResponseSpan(ctx context.Context, event *TraceEvent) error {
	// Create a minimal span for the orphaned response
	activeSpan := &ActiveSpan{
		RequestID:     event.RequestID,
		TraceID:       event.TraceContext.TraceID,
		SpanID:        event.TraceContext.SpanID,
		ServiceName:   event.ServiceName,
		OperationName: "HTTP Response (orphaned)",
		StartTime:     time.Unix(0, int64(event.Timestamp)),
		ResponseEvent: event,
		IsCompleted:   false,
		HasResponse:   true,
	}
	
	// Create OpenTelemetry span (Jaeger export handled automatically)
	if sm.otelProvider != nil {
		otelSpan, err := sm.otelProvider.CreateSpanFromEvent(ctx, event)
		if err == nil {
			activeSpan.OtelSpan = otelSpan
		}
	}
	
	// Complete immediately
	return sm.completeSpan(activeSpan, time.Unix(0, int64(event.Timestamp)))
}

// extractStatusCode extracts HTTP status code from response payload
func (sm *SpanManager) extractStatusCode(event *TraceEvent) int {
	if event.Payload == "" {
		return 0
	}

	// Simple extraction for "HTTP/1.1 200 OK" format
	if len(event.Payload) > 12 && event.Payload[:4] == "HTTP" {
		// Find first space
		spaceIndex := -1
		for i := 4; i < len(event.Payload) && i < 20; i++ {
			if event.Payload[i] == ' ' {
				spaceIndex = i
				break
			}
		}

		if spaceIndex != -1 && spaceIndex+4 < len(event.Payload) {
			statusStr := event.Payload[spaceIndex+1 : spaceIndex+4]
			if statusCode, err := parseStatusCode(statusStr); err == nil {
				return statusCode
			}
		}
	}

	return 0
}

// parseStatusCode parses a 3-digit status code string
func parseStatusCode(statusStr string) (int, error) {
	if len(statusStr) != 3 {
		return 0, fmt.Errorf("invalid status code length")
	}
	
	statusCode := 0
	for _, c := range statusStr {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid status code character")
		}
		statusCode = statusCode*10 + int(c-'0')
	}
	
	return statusCode, nil
}

// updateOtelSpanWithResponse updates OpenTelemetry span with response data
func (sm *SpanManager) updateOtelSpanWithResponse(span oteltrace.Span, event *TraceEvent, statusCode int) {
	if statusCode > 0 {
		span.SetAttributes(
			// semconv.HTTPStatusCode(statusCode), // Would need to import semconv
		)
		
		// Set status based on HTTP status code
		if statusCode >= 400 {
			span.SetStatus(2, fmt.Sprintf("HTTP %d", statusCode)) // Error status
		} else {
			span.SetStatus(1, "") // OK status
		}
	}
	
	// Add response size if available
	if event.PayloadLen > 0 {
		// span.SetAttributes(semconv.HTTPResponseSize(int(event.PayloadLen)))
	}
}

// updateJaegerSpanWithResponse is no longer needed as Jaeger is handled through OpenTelemetry

// completeSpan completes and removes a span
func (sm *SpanManager) completeSpan(activeSpan *ActiveSpan, endTime time.Time) error {
	// Finish OpenTelemetry span (Jaeger export handled automatically)
	if activeSpan.OtelSpan != nil {
		activeSpan.OtelSpan.End(oteltrace.WithTimestamp(endTime))
	}
	
	// Mark as completed
	activeSpan.IsCompleted = true
	
	// Remove from active spans
	delete(sm.activeSpans, activeSpan.RequestID)
	
	return nil
}

// cleanupRoutine periodically cleans up expired spans
func (sm *SpanManager) cleanupRoutine() {
	for {
		select {
		case <-sm.cleanupTicker.C:
			sm.cleanupExpiredSpans()
		case <-sm.stopCleanup:
			return
		}
	}
}

// cleanupExpiredSpans removes spans that have exceeded the timeout
func (sm *SpanManager) cleanupExpiredSpans() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	now := time.Now()
	expiredSpans := make([]*ActiveSpan, 0)
	
	// Find expired spans
	for requestID, activeSpan := range sm.activeSpans {
		if now.Sub(activeSpan.StartTime) > sm.spanTimeout {
			expiredSpans = append(expiredSpans, activeSpan)
			delete(sm.activeSpans, requestID)
		}
	}
	
	// Complete expired spans
	for _, span := range expiredSpans {
		if !span.IsCompleted {
			// Add timeout tag
			if span.OtelSpan != nil {
				span.OtelSpan.SetStatus(2, "span timeout") // Error status
			}
			
			sm.completeSpan(span, now)
		}
	}
}

// GetActiveSpanCount returns the number of active spans
func (sm *SpanManager) GetActiveSpanCount() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return len(sm.activeSpans)
}

// Shutdown gracefully shuts down the span manager
func (sm *SpanManager) Shutdown() {
	// Stop cleanup routine
	close(sm.stopCleanup)
	sm.cleanupTicker.Stop()
	
	// Complete all remaining spans
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	now := time.Now()
	for _, activeSpan := range sm.activeSpans {
		if !activeSpan.IsCompleted {
			sm.completeSpan(activeSpan, now)
		}
	}
}

// DefaultSpanManagerConfig returns default configuration
func DefaultSpanManagerConfig() *SpanManagerConfig {
	return &SpanManagerConfig{
		SpanTimeout:     30 * time.Second,
		MaxActiveSpans:  10000,
		CleanupInterval: 10 * time.Second,
		EnableOtel:      true,
		EnableJaeger:    true,
	}
}
