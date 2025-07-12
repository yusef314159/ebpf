// Package outputs provides interfaces and implementations for event output adapters
package outputs

import (
	"context"
	"time"
)

// EventOutput defines the interface for all output adapters
type EventOutput interface {
	// Initialize the output adapter
	Initialize(ctx context.Context) error
	
	// Write a single event
	WriteEvent(event interface{}) error
	
	// Write multiple events in batch
	WriteBatch(events []interface{}) error
	
	// Close the output adapter and cleanup resources
	Close() error
	
	// Get output adapter name
	Name() string
	
	// Get output adapter health status
	IsHealthy() bool
	
	// Get output adapter metrics
	GetMetrics() OutputMetrics
}

// OutputMetrics contains metrics for output adapters
type OutputMetrics struct {
	EventsWritten    uint64        `json:"events_written"`
	EventsDropped    uint64        `json:"events_dropped"`
	BytesWritten     uint64        `json:"bytes_written"`
	ErrorCount       uint64        `json:"error_count"`
	LastError        string        `json:"last_error,omitempty"`
	LastErrorTime    *time.Time    `json:"last_error_time,omitempty"`
	ConnectionUptime time.Duration `json:"connection_uptime"`
	IsConnected      bool          `json:"is_connected"`
}

// OutputConfig contains common configuration for output adapters
type OutputConfig struct {
	// Output adapter type (stdout, unix_socket, grpc_otlp, http_json)
	Type string `json:"type" yaml:"type"`
	
	// Enable/disable this output
	Enabled bool `json:"enabled" yaml:"enabled"`
	
	// Buffer size for batching events
	BufferSize int `json:"buffer_size" yaml:"buffer_size"`
	
	// Flush interval for batched events
	FlushInterval time.Duration `json:"flush_interval" yaml:"flush_interval"`
	
	// Connection timeout
	ConnectTimeout time.Duration `json:"connect_timeout" yaml:"connect_timeout"`
	
	// Write timeout
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`
	
	// Retry configuration
	MaxRetries    int           `json:"max_retries" yaml:"max_retries"`
	RetryInterval time.Duration `json:"retry_interval" yaml:"retry_interval"`
	
	// Enable compression
	EnableCompression bool `json:"enable_compression" yaml:"enable_compression"`
	
	// Output format (json, ndjson, text)
	Format string `json:"format" yaml:"format"`
}

// DefaultOutputConfig returns default configuration for output adapters
func DefaultOutputConfig() OutputConfig {
	return OutputConfig{
		Type:              "stdout",
		Enabled:           true,
		BufferSize:        1000,
		FlushInterval:     5 * time.Second,
		ConnectTimeout:    10 * time.Second,
		WriteTimeout:      5 * time.Second,
		MaxRetries:        3,
		RetryInterval:     1 * time.Second,
		EnableCompression: false,
		Format:            "json",
	}
}

// OutputManager manages multiple output adapters
type OutputManager struct {
	outputs []EventOutput
	metrics OutputManagerMetrics
}

// OutputManagerMetrics contains metrics for the output manager
type OutputManagerMetrics struct {
	TotalOutputs     int                    `json:"total_outputs"`
	ActiveOutputs    int                    `json:"active_outputs"`
	TotalEvents      uint64                 `json:"total_events"`
	TotalErrors      uint64                 `json:"total_errors"`
	OutputMetrics    map[string]OutputMetrics `json:"output_metrics"`
	LastUpdateTime   time.Time              `json:"last_update_time"`
}

// NewOutputManager creates a new output manager
func NewOutputManager() *OutputManager {
	return &OutputManager{
		outputs: make([]EventOutput, 0),
		metrics: OutputManagerMetrics{
			OutputMetrics: make(map[string]OutputMetrics),
		},
	}
}

// AddOutput adds an output adapter to the manager
func (om *OutputManager) AddOutput(output EventOutput) {
	om.outputs = append(om.outputs, output)
	om.updateMetrics()
}

// WriteEvent writes an event to all active outputs
func (om *OutputManager) WriteEvent(event interface{}) error {
	var lastError error
	successCount := 0
	
	for _, output := range om.outputs {
		if output.IsHealthy() {
			if err := output.WriteEvent(event); err != nil {
				lastError = err
			} else {
				successCount++
			}
		}
	}
	
	om.metrics.TotalEvents++
	if lastError != nil && successCount == 0 {
		om.metrics.TotalErrors++
		return lastError
	}
	
	return nil
}

// WriteBatch writes a batch of events to all active outputs
func (om *OutputManager) WriteBatch(events []interface{}) error {
	var lastError error
	successCount := 0
	
	for _, output := range om.outputs {
		if output.IsHealthy() {
			if err := output.WriteBatch(events); err != nil {
				lastError = err
			} else {
				successCount++
			}
		}
	}
	
	om.metrics.TotalEvents += uint64(len(events))
	if lastError != nil && successCount == 0 {
		om.metrics.TotalErrors++
		return lastError
	}
	
	return nil
}

// Initialize initializes all output adapters
func (om *OutputManager) Initialize(ctx context.Context) error {
	for _, output := range om.outputs {
		if err := output.Initialize(ctx); err != nil {
			return err
		}
	}
	om.updateMetrics()
	return nil
}

// Close closes all output adapters
func (om *OutputManager) Close() error {
	var lastError error
	for _, output := range om.outputs {
		if err := output.Close(); err != nil {
			lastError = err
		}
	}
	return lastError
}

// GetMetrics returns current metrics
func (om *OutputManager) GetMetrics() OutputManagerMetrics {
	om.updateMetrics()
	return om.metrics
}

// updateMetrics updates the manager metrics
func (om *OutputManager) updateMetrics() {
	om.metrics.TotalOutputs = len(om.outputs)
	om.metrics.ActiveOutputs = 0
	om.metrics.LastUpdateTime = time.Now()
	
	for _, output := range om.outputs {
		if output.IsHealthy() {
			om.metrics.ActiveOutputs++
		}
		om.metrics.OutputMetrics[output.Name()] = output.GetMetrics()
	}
}
