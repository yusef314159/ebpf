package config

import (
	"fmt"
	"time"

	"ebpf-tracing/pkg/outputs"
)

// OutputsConfig contains configuration for all output adapters
type OutputsConfig struct {
	// List of output configurations
	Outputs []OutputAdapterConfig `json:"outputs" yaml:"outputs"`
	
	// Default output settings
	DefaultBufferSize    int           `json:"default_buffer_size" yaml:"default_buffer_size"`
	DefaultFlushInterval time.Duration `json:"default_flush_interval" yaml:"default_flush_interval"`
	DefaultFormat        string        `json:"default_format" yaml:"default_format"`
}

// OutputAdapterConfig contains configuration for a single output adapter
type OutputAdapterConfig struct {
	// Output adapter name (for identification)
	Name string `json:"name" yaml:"name"`
	
	// Output adapter type (stdout, unix_socket, grpc_otlp, http_json)
	Type string `json:"type" yaml:"type"`
	
	// Enable/disable this output
	Enabled bool `json:"enabled" yaml:"enabled"`
	
	// Output-specific configuration
	Config map[string]interface{} `json:"config" yaml:"config"`
}

// DefaultOutputsConfig returns default outputs configuration
func DefaultOutputsConfig() OutputsConfig {
	return OutputsConfig{
		Outputs: []OutputAdapterConfig{
			{
				Name:    "stdout",
				Type:    "stdout",
				Enabled: true,
				Config: map[string]interface{}{
					"pretty_print":     false,
					"add_timestamp":    false,
					"timestamp_format": time.RFC3339,
				},
			},
		},
		DefaultBufferSize:    1000,
		DefaultFlushInterval: 5 * time.Second,
		DefaultFormat:        "json",
	}
}

// CreateOutputManager creates an output manager from configuration
func (oc *OutputsConfig) CreateOutputManager() (*outputs.OutputManager, error) {
	manager := outputs.NewOutputManager()
	
	for _, outputConfig := range oc.Outputs {
		if !outputConfig.Enabled {
			continue
		}
		
		output, err := oc.createOutput(outputConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create output %s: %w", outputConfig.Name, err)
		}
		
		manager.AddOutput(output)
	}
	
	return manager, nil
}

// createOutput creates a specific output adapter
func (oc *OutputsConfig) createOutput(config OutputAdapterConfig) (outputs.EventOutput, error) {
	switch config.Type {
	case "stdout":
		return oc.createStdoutOutput(config)
	case "unix_socket":
		return oc.createUnixSocketOutput(config)
	default:
		return nil, fmt.Errorf("unsupported output type: %s", config.Type)
	}
}

// createStdoutOutput creates a stdout output adapter
func (oc *OutputsConfig) createStdoutOutput(config OutputAdapterConfig) (outputs.EventOutput, error) {
	stdoutConfig := outputs.DefaultStdoutConfig()
	
	// Apply default settings
	stdoutConfig.BufferSize = oc.DefaultBufferSize
	stdoutConfig.FlushInterval = oc.DefaultFlushInterval
	stdoutConfig.Format = oc.DefaultFormat
	
	// Apply specific configuration
	if prettyPrint, ok := config.Config["pretty_print"].(bool); ok {
		stdoutConfig.PrettyPrint = prettyPrint
	}
	if addTimestamp, ok := config.Config["add_timestamp"].(bool); ok {
		stdoutConfig.AddTimestamp = addTimestamp
	}
	if timestampFormat, ok := config.Config["timestamp_format"].(string); ok {
		stdoutConfig.TimestampFormat = timestampFormat
	}
	
	return outputs.NewStdoutOutput(config.Name, stdoutConfig), nil
}

// createUnixSocketOutput creates a Unix socket output adapter
func (oc *OutputsConfig) createUnixSocketOutput(config OutputAdapterConfig) (outputs.EventOutput, error) {
	unixConfig := outputs.DefaultUnixSocketConfig()
	
	// Apply default settings
	unixConfig.BufferSize = oc.DefaultBufferSize
	unixConfig.FlushInterval = oc.DefaultFlushInterval
	unixConfig.Format = oc.DefaultFormat
	
	// Apply specific configuration
	if socketPath, ok := config.Config["socket_path"].(string); ok {
		unixConfig.SocketPath = socketPath
	}
	if removeExisting, ok := config.Config["remove_existing"].(bool); ok {
		unixConfig.RemoveExisting = removeExisting
	}
	if keepAlive, ok := config.Config["keep_alive"].(bool); ok {
		unixConfig.KeepAlive = keepAlive
	}
	if keepAliveInterval, ok := config.Config["keep_alive_interval"].(string); ok {
		if duration, err := time.ParseDuration(keepAliveInterval); err == nil {
			unixConfig.KeepAliveInterval = duration
		}
	}
	if connectTimeout, ok := config.Config["connect_timeout"].(string); ok {
		if duration, err := time.ParseDuration(connectTimeout); err == nil {
			unixConfig.ConnectTimeout = duration
		}
	}
	if writeTimeout, ok := config.Config["write_timeout"].(string); ok {
		if duration, err := time.ParseDuration(writeTimeout); err == nil {
			unixConfig.WriteTimeout = duration
		}
	}
	
	return outputs.NewUnixSocketOutput(config.Name, unixConfig), nil
}

// ValidateOutputsConfig validates the outputs configuration
func (oc *OutputsConfig) ValidateOutputsConfig() error {
	if len(oc.Outputs) == 0 {
		return fmt.Errorf("no outputs configured")
	}
	
	enabledCount := 0
	names := make(map[string]bool)
	
	for i, output := range oc.Outputs {
		// Check for duplicate names
		if names[output.Name] {
			return fmt.Errorf("duplicate output name: %s", output.Name)
		}
		names[output.Name] = true
		
		// Check required fields
		if output.Name == "" {
			return fmt.Errorf("output %d: name is required", i)
		}
		if output.Type == "" {
			return fmt.Errorf("output %s: type is required", output.Name)
		}
		
		// Check supported types
		switch output.Type {
		case "stdout", "unix_socket":
			// Supported types
		default:
			return fmt.Errorf("output %s: unsupported type %s", output.Name, output.Type)
		}
		
		if output.Enabled {
			enabledCount++
		}
		
		// Validate type-specific configuration
		if err := oc.validateOutputConfig(output); err != nil {
			return fmt.Errorf("output %s: %w", output.Name, err)
		}
	}
	
	if enabledCount == 0 {
		return fmt.Errorf("no outputs enabled")
	}
	
	return nil
}

// validateOutputConfig validates type-specific output configuration
func (oc *OutputsConfig) validateOutputConfig(config OutputAdapterConfig) error {
	switch config.Type {
	case "unix_socket":
		if socketPath, ok := config.Config["socket_path"].(string); ok {
			if socketPath == "" {
				return fmt.Errorf("socket_path cannot be empty")
			}
		}
	}
	
	return nil
}
