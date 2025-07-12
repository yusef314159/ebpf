package outputs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// StdoutConfig contains configuration for stdout output
type StdoutConfig struct {
	OutputConfig `yaml:",inline"`
	
	// Pretty print JSON output
	PrettyPrint bool `json:"pretty_print" yaml:"pretty_print"`
	
	// Add timestamp to each line
	AddTimestamp bool `json:"add_timestamp" yaml:"add_timestamp"`
	
	// Timestamp format (RFC3339, Unix, etc.)
	TimestampFormat string `json:"timestamp_format" yaml:"timestamp_format"`
}

// DefaultStdoutConfig returns default stdout configuration
func DefaultStdoutConfig() StdoutConfig {
	config := DefaultOutputConfig()
	config.Type = "stdout"
	
	return StdoutConfig{
		OutputConfig:    config,
		PrettyPrint:     false,
		AddTimestamp:    false,
		TimestampFormat: time.RFC3339,
	}
}

// StdoutOutput implements EventOutput for stdout
type StdoutOutput struct {
	name    string
	config  StdoutConfig
	metrics OutputMetrics
	mutex   sync.Mutex
	startTime time.Time
}

// NewStdoutOutput creates a new stdout output adapter
func NewStdoutOutput(name string, config StdoutConfig) *StdoutOutput {
	return &StdoutOutput{
		name:   name,
		config: config,
		metrics: OutputMetrics{
			IsConnected: true, // stdout is always "connected"
		},
	}
}

// Initialize implements EventOutput.Initialize
func (so *StdoutOutput) Initialize(ctx context.Context) error {
	so.startTime = time.Now()
	so.metrics.IsConnected = true
	so.metrics.ConnectionUptime = time.Since(so.startTime)
	return nil
}

// WriteEvent implements EventOutput.WriteEvent
func (so *StdoutOutput) WriteEvent(event interface{}) error {
	return so.WriteBatch([]interface{}{event})
}

// WriteBatch implements EventOutput.WriteBatch
func (so *StdoutOutput) WriteBatch(events []interface{}) error {
	if len(events) == 0 {
		return nil
	}
	
	so.mutex.Lock()
	defer so.mutex.Unlock()
	
	for _, event := range events {
		if err := so.writeEvent(event); err != nil {
			so.recordError(err)
			return err
		}
		so.metrics.EventsWritten++
	}
	
	return nil
}

// writeEvent writes a single event to stdout
func (so *StdoutOutput) writeEvent(event interface{}) error {
	var data []byte
	var err error
	
	// Serialize to JSON
	if so.config.PrettyPrint {
		data, err = json.MarshalIndent(event, "", "  ")
	} else {
		data, err = json.Marshal(event)
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	
	// Add timestamp if configured
	if so.config.AddTimestamp {
		timestamp := time.Now().Format(so.config.TimestampFormat)
		output := fmt.Sprintf("[%s] %s", timestamp, string(data))
		data = []byte(output)
	}
	
	// Write to stdout
	_, err = fmt.Println(string(data))
	if err != nil {
		return fmt.Errorf("failed to write to stdout: %w", err)
	}
	
	so.metrics.BytesWritten += uint64(len(data))
	return nil
}

// Close implements EventOutput.Close
func (so *StdoutOutput) Close() error {
	// Flush stdout
	if err := os.Stdout.Sync(); err != nil {
		return fmt.Errorf("failed to flush stdout: %w", err)
	}
	
	so.metrics.IsConnected = false
	return nil
}

// Name implements EventOutput.Name
func (so *StdoutOutput) Name() string {
	return so.name
}

// IsHealthy implements EventOutput.IsHealthy
func (so *StdoutOutput) IsHealthy() bool {
	return so.metrics.IsConnected
}

// GetMetrics implements EventOutput.GetMetrics
func (so *StdoutOutput) GetMetrics() OutputMetrics {
	so.metrics.ConnectionUptime = time.Since(so.startTime)
	return so.metrics
}

// recordError records an error in metrics
func (so *StdoutOutput) recordError(err error) {
	so.metrics.ErrorCount++
	so.metrics.LastError = err.Error()
	now := time.Now()
	so.metrics.LastErrorTime = &now
}
