package unit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ebpf-tracing/config"
)

// TestDefaultConfig tests the default configuration
func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test general settings
	if !cfg.General.Enabled {
		t.Error("Default config should be enabled")
	}

	if cfg.General.LogLevel != "info" {
		t.Errorf("Expected log level 'info', got '%s'", cfg.General.LogLevel)
	}

	if cfg.General.ProcessName != "http-tracer" {
		t.Errorf("Expected process name 'http-tracer', got '%s'", cfg.General.ProcessName)
	}

	// Test filtering settings
	if !cfg.Filtering.Enabled {
		t.Error("Default filtering should be enabled")
	}

	if !cfg.Filtering.EventTypeFilters.EnableReadEvents {
		t.Error("Read events should be enabled by default")
	}

	if !cfg.Filtering.EventTypeFilters.EnableWriteEvents {
		t.Error("Write events should be enabled by default")
	}

	// Test sampling settings
	if cfg.Sampling.Enabled {
		t.Error("Sampling should be disabled by default")
	}

	if cfg.Sampling.Rate != 1.0 {
		t.Errorf("Expected sampling rate 1.0, got %f", cfg.Sampling.Rate)
	}

	// Test output settings
	if cfg.Output.Format != "json" {
		t.Errorf("Expected output format 'json', got '%s'", cfg.Output.Format)
	}

	if cfg.Output.Destination != "stdout" {
		t.Errorf("Expected output destination 'stdout', got '%s'", cfg.Output.Destination)
	}

	// Test performance settings
	if cfg.Performance.RingBufferSize == 0 {
		t.Error("Ring buffer size should be greater than 0")
	}

	if cfg.Performance.WorkerThreads == 0 {
		t.Error("Worker threads should be greater than 0")
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	testCases := []struct {
		name        string
		modifyConfig func(*config.Config)
		expectError bool
	}{
		{
			name:        "Valid default config",
			modifyConfig: func(cfg *config.Config) {},
			expectError: false,
		},
		{
			name: "Invalid log level",
			modifyConfig: func(cfg *config.Config) {
				cfg.General.LogLevel = "invalid"
			},
			expectError: true,
		},
		{
			name: "Invalid sampling rate - too low",
			modifyConfig: func(cfg *config.Config) {
				cfg.Sampling.Enabled = true
				cfg.Sampling.Rate = -0.1
			},
			expectError: true,
		},
		{
			name: "Invalid sampling rate - too high",
			modifyConfig: func(cfg *config.Config) {
				cfg.Sampling.Enabled = true
				cfg.Sampling.Rate = 1.1
			},
			expectError: true,
		},
		{
			name: "Invalid sampling strategy",
			modifyConfig: func(cfg *config.Config) {
				cfg.Sampling.Enabled = true
				cfg.Sampling.Strategy = "invalid"
			},
			expectError: true,
		},
		{
			name: "Invalid output format",
			modifyConfig: func(cfg *config.Config) {
				cfg.Output.Format = "invalid"
			},
			expectError: true,
		},
		{
			name: "Invalid output destination",
			modifyConfig: func(cfg *config.Config) {
				cfg.Output.Destination = "invalid"
			},
			expectError: true,
		},
		{
			name: "File output without path",
			modifyConfig: func(cfg *config.Config) {
				cfg.Output.Destination = "file"
				cfg.Output.File.Path = ""
			},
			expectError: true,
		},
		{
			name: "Network output without address",
			modifyConfig: func(cfg *config.Config) {
				cfg.Output.Destination = "network"
				cfg.Output.Network.Address = ""
			},
			expectError: true,
		},
		{
			name: "Invalid network protocol",
			modifyConfig: func(cfg *config.Config) {
				cfg.Output.Destination = "network"
				cfg.Output.Network.Protocol = "invalid"
			},
			expectError: true,
		},
		{
			name: "Zero ring buffer size",
			modifyConfig: func(cfg *config.Config) {
				cfg.Performance.RingBufferSize = 0
			},
			expectError: true,
		},
		{
			name: "Zero worker threads",
			modifyConfig: func(cfg *config.Config) {
				cfg.Performance.WorkerThreads = 0
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			tc.modifyConfig(cfg)

			err := cfg.Validate()
			if tc.expectError && err == nil {
				t.Error("Expected validation error, but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no validation error, but got: %v", err)
			}
		})
	}
}

// TestConfigSaveLoad tests saving and loading configuration
func TestConfigSaveLoad(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "test-config.json")

	// Create test configuration
	originalConfig := config.DefaultConfig()
	originalConfig.General.LogLevel = "debug"
	originalConfig.Filtering.ProcessFilters.MinPID = 100
	originalConfig.Sampling.Enabled = true
	originalConfig.Sampling.Rate = 0.5

	// Save configuration
	err := originalConfig.SaveConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load configuration
	loadedConfig, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Compare configurations
	if loadedConfig.General.LogLevel != originalConfig.General.LogLevel {
		t.Errorf("Log level mismatch: expected %s, got %s",
			originalConfig.General.LogLevel, loadedConfig.General.LogLevel)
	}

	if loadedConfig.Filtering.ProcessFilters.MinPID != originalConfig.Filtering.ProcessFilters.MinPID {
		t.Errorf("MinPID mismatch: expected %d, got %d",
			originalConfig.Filtering.ProcessFilters.MinPID, loadedConfig.Filtering.ProcessFilters.MinPID)
	}

	if loadedConfig.Sampling.Enabled != originalConfig.Sampling.Enabled {
		t.Errorf("Sampling enabled mismatch: expected %v, got %v",
			originalConfig.Sampling.Enabled, loadedConfig.Sampling.Enabled)
	}

	if loadedConfig.Sampling.Rate != originalConfig.Sampling.Rate {
		t.Errorf("Sampling rate mismatch: expected %f, got %f",
			originalConfig.Sampling.Rate, loadedConfig.Sampling.Rate)
	}
}

// TestEnvironmentVariableOverrides tests environment variable overrides
func TestEnvironmentVariableOverrides(t *testing.T) {
	// Set environment variables
	envVars := map[string]string{
		"HTTP_TRACER_ENABLED":           "false",
		"HTTP_TRACER_LOG_LEVEL":         "debug",
		"HTTP_TRACER_PROCESS_NAME":      "test-tracer",
		"HTTP_TRACER_FILTERING_ENABLED": "false",
		"HTTP_TRACER_SAMPLING_ENABLED":  "true",
		"HTTP_TRACER_SAMPLING_RATE":     "0.8",
		"HTTP_TRACER_OUTPUT_FORMAT":     "text",
		"HTTP_TRACER_OUTPUT_DESTINATION": "file",
		"HTTP_TRACER_OUTPUT_FILE":       "/tmp/test.log",
		"HTTP_TRACER_RING_BUFFER_SIZE":  "2097152",
		"HTTP_TRACER_WORKER_THREADS":    "8",
	}

	// Set environment variables
	for key, value := range envVars {
		os.Setenv(key, value)
	}

	// Clean up environment variables after test
	defer func() {
		for key := range envVars {
			os.Unsetenv(key)
		}
	}()

	// Load configuration (should pick up environment variables)
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify environment variable overrides
	if cfg.General.Enabled {
		t.Error("Expected enabled=false from environment variable")
	}

	if cfg.General.LogLevel != "debug" {
		t.Errorf("Expected log level 'debug', got '%s'", cfg.General.LogLevel)
	}

	if cfg.General.ProcessName != "test-tracer" {
		t.Errorf("Expected process name 'test-tracer', got '%s'", cfg.General.ProcessName)
	}

	if cfg.Filtering.Enabled {
		t.Error("Expected filtering enabled=false from environment variable")
	}

	if !cfg.Sampling.Enabled {
		t.Error("Expected sampling enabled=true from environment variable")
	}

	if cfg.Sampling.Rate != 0.8 {
		t.Errorf("Expected sampling rate 0.8, got %f", cfg.Sampling.Rate)
	}

	if cfg.Output.Format != "text" {
		t.Errorf("Expected output format 'text', got '%s'", cfg.Output.Format)
	}

	if cfg.Output.Destination != "file" {
		t.Errorf("Expected output destination 'file', got '%s'", cfg.Output.Destination)
	}

	if cfg.Output.File.Path != "/tmp/test.log" {
		t.Errorf("Expected output file '/tmp/test.log', got '%s'", cfg.Output.File.Path)
	}

	if cfg.Performance.RingBufferSize != 2097152 {
		t.Errorf("Expected ring buffer size 2097152, got %d", cfg.Performance.RingBufferSize)
	}

	if cfg.Performance.WorkerThreads != 8 {
		t.Errorf("Expected worker threads 8, got %d", cfg.Performance.WorkerThreads)
	}
}

// TestPIDFiltering tests PID filtering functionality
func TestPIDFiltering(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test with no filters (should not filter anything)
	if cfg.ShouldFilterPID(1234) {
		t.Error("Should not filter PID when no filters are set")
	}

	// Test minimum PID filter
	cfg.Filtering.ProcessFilters.MinPID = 1000
	if !cfg.ShouldFilterPID(999) {
		t.Error("Should filter PID below minimum")
	}
	if cfg.ShouldFilterPID(1000) {
		t.Error("Should not filter PID at minimum")
	}

	// Test include PID filter
	cfg.Filtering.ProcessFilters.IncludePIDs = []uint32{1234, 5678}
	if cfg.ShouldFilterPID(1234) {
		t.Error("Should not filter included PID")
	}
	if !cfg.ShouldFilterPID(9999) {
		t.Error("Should filter PID not in include list")
	}

	// Test exclude PID filter
	cfg.Filtering.ProcessFilters.IncludePIDs = nil // Clear include list
	cfg.Filtering.ProcessFilters.ExcludePIDs = []uint32{1234, 5678}
	if !cfg.ShouldFilterPID(1234) {
		t.Error("Should filter excluded PID")
	}
	if cfg.ShouldFilterPID(9999) {
		t.Error("Should not filter PID not in exclude list")
	}
}

// TestProcessFiltering tests process name filtering functionality
func TestProcessFiltering(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test with no filters (should not filter anything)
	if cfg.ShouldFilterProcess("test-process") {
		t.Error("Should not filter process when no filters are set")
	}

	// Test include process filter
	cfg.Filtering.ProcessFilters.IncludeProcessNames = []string{"nginx", "apache"}
	if cfg.ShouldFilterProcess("nginx") {
		t.Error("Should not filter included process")
	}
	if !cfg.ShouldFilterProcess("unknown") {
		t.Error("Should filter process not in include list")
	}

	// Test exclude process filter
	cfg.Filtering.ProcessFilters.IncludeProcessNames = nil // Clear include list
	cfg.Filtering.ProcessFilters.ExcludeProcessNames = []string{"systemd", "kthreadd"}
	if !cfg.ShouldFilterProcess("systemd") {
		t.Error("Should filter excluded process")
	}
	if cfg.ShouldFilterProcess("nginx") {
		t.Error("Should not filter process not in exclude list")
	}
}

// TestConfigUtilityFunctions tests utility functions
func TestConfigUtilityFunctions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output.Buffer.FlushIntervalSeconds = 10
	cfg.Output.Network.TimeoutSeconds = 30

	// Test duration conversion
	flushInterval := cfg.GetFlushInterval()
	expectedFlushInterval := 10 * time.Second
	if flushInterval != expectedFlushInterval {
		t.Errorf("Expected flush interval %v, got %v", expectedFlushInterval, flushInterval)
	}

	networkTimeout := cfg.GetNetworkTimeout()
	expectedNetworkTimeout := 30 * time.Second
	if networkTimeout != expectedNetworkTimeout {
		t.Errorf("Expected network timeout %v, got %v", expectedNetworkTimeout, networkTimeout)
	}
}

// BenchmarkConfigLoad benchmarks configuration loading
func BenchmarkConfigLoad(b *testing.B) {
	// Create temporary config file
	tempDir := b.TempDir()
	configPath := filepath.Join(tempDir, "bench-config.json")

	cfg := config.DefaultConfig()
	if err := cfg.SaveConfig(configPath); err != nil {
		b.Fatalf("Failed to save config: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := config.LoadConfig(configPath)
		if err != nil {
			b.Fatalf("Failed to load config: %v", err)
		}
	}
}

// BenchmarkConfigValidation benchmarks configuration validation
func BenchmarkConfigValidation(b *testing.B) {
	cfg := config.DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := cfg.Validate()
		if err != nil {
			b.Fatalf("Config validation failed: %v", err)
		}
	}
}
