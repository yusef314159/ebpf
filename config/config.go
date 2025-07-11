package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config represents the complete configuration for the eBPF tracer
type Config struct {
	// General settings
	General GeneralConfig `json:"general" yaml:"general"`
	
	// Filtering settings
	Filtering FilteringConfig `json:"filtering" yaml:"filtering"`
	
	// Sampling settings
	Sampling SamplingConfig `json:"sampling" yaml:"sampling"`
	
	// Output settings
	Output OutputConfig `json:"output" yaml:"output"`
	
	// Performance settings
	Performance PerformanceConfig `json:"performance" yaml:"performance"`
	
	// Security settings
	Security SecurityConfig `json:"security" yaml:"security"`
}

// GeneralConfig contains general tracer settings
type GeneralConfig struct {
	// Enable/disable the tracer
	Enabled bool `json:"enabled" yaml:"enabled"`
	
	// Log level (debug, info, warn, error)
	LogLevel string `json:"log_level" yaml:"log_level"`
	
	// Process name for identification
	ProcessName string `json:"process_name" yaml:"process_name"`
	
	// PID file location
	PidFile string `json:"pid_file" yaml:"pid_file"`
	
	// Enable graceful shutdown
	GracefulShutdown bool `json:"graceful_shutdown" yaml:"graceful_shutdown"`
}

// FilteringConfig contains event filtering settings
type FilteringConfig struct {
	// Enable/disable filtering
	Enabled bool `json:"enabled" yaml:"enabled"`
	
	// Process filters
	ProcessFilters ProcessFilters `json:"process_filters" yaml:"process_filters"`
	
	// Network filters
	NetworkFilters NetworkFilters `json:"network_filters" yaml:"network_filters"`
	
	// HTTP filters
	HTTPFilters HTTPFilters `json:"http_filters" yaml:"http_filters"`
	
	// Event type filters
	EventTypeFilters EventTypeFilters `json:"event_type_filters" yaml:"event_type_filters"`
}

// ProcessFilters contains process-based filtering
type ProcessFilters struct {
	// Include only these PIDs (empty = all)
	IncludePIDs []uint32 `json:"include_pids" yaml:"include_pids"`
	
	// Exclude these PIDs
	ExcludePIDs []uint32 `json:"exclude_pids" yaml:"exclude_pids"`
	
	// Include only these process names (empty = all)
	IncludeProcessNames []string `json:"include_process_names" yaml:"include_process_names"`
	
	// Exclude these process names
	ExcludeProcessNames []string `json:"exclude_process_names" yaml:"exclude_process_names"`
	
	// Minimum PID to consider (filter out kernel threads)
	MinPID uint32 `json:"min_pid" yaml:"min_pid"`
}

// NetworkFilters contains network-based filtering
type NetworkFilters struct {
	// Include only these ports (empty = all)
	IncludePorts []uint16 `json:"include_ports" yaml:"include_ports"`
	
	// Exclude these ports
	ExcludePorts []uint16 `json:"exclude_ports" yaml:"exclude_ports"`
	
	// Include only these IP addresses (empty = all)
	IncludeIPs []string `json:"include_ips" yaml:"include_ips"`
	
	// Exclude these IP addresses
	ExcludeIPs []string `json:"exclude_ips" yaml:"exclude_ips"`
	
	// Include only localhost traffic
	LocalhostOnly bool `json:"localhost_only" yaml:"localhost_only"`
}

// HTTPFilters contains HTTP-specific filtering
type HTTPFilters struct {
	// Include only these HTTP methods (empty = all)
	IncludeMethods []string `json:"include_methods" yaml:"include_methods"`
	
	// Exclude these HTTP methods
	ExcludeMethods []string `json:"exclude_methods" yaml:"exclude_methods"`
	
	// Include only paths matching these patterns (empty = all)
	IncludePathPatterns []string `json:"include_path_patterns" yaml:"include_path_patterns"`
	
	// Exclude paths matching these patterns
	ExcludePathPatterns []string `json:"exclude_path_patterns" yaml:"exclude_path_patterns"`
	
	// Include only these status codes (empty = all)
	IncludeStatusCodes []int `json:"include_status_codes" yaml:"include_status_codes"`
	
	// Exclude these status codes
	ExcludeStatusCodes []int `json:"exclude_status_codes" yaml:"exclude_status_codes"`
	
	// Minimum payload size to capture
	MinPayloadSize uint32 `json:"min_payload_size" yaml:"min_payload_size"`
	
	// Maximum payload size to capture
	MaxPayloadSize uint32 `json:"max_payload_size" yaml:"max_payload_size"`
}

// EventTypeFilters contains event type filtering
type EventTypeFilters struct {
	// Enable read events (HTTP requests)
	EnableReadEvents bool `json:"enable_read_events" yaml:"enable_read_events"`
	
	// Enable write events (HTTP responses)
	EnableWriteEvents bool `json:"enable_write_events" yaml:"enable_write_events"`
	
	// Enable connect events
	EnableConnectEvents bool `json:"enable_connect_events" yaml:"enable_connect_events"`
	
	// Enable accept events
	EnableAcceptEvents bool `json:"enable_accept_events" yaml:"enable_accept_events"`
}

// SamplingConfig contains sampling settings
type SamplingConfig struct {
	// Enable/disable sampling
	Enabled bool `json:"enabled" yaml:"enabled"`
	
	// Sampling rate (0.0 to 1.0, where 1.0 = 100%)
	Rate float64 `json:"rate" yaml:"rate"`
	
	// Sampling strategy (random, deterministic, adaptive)
	Strategy string `json:"strategy" yaml:"strategy"`
	
	// Maximum events per second (rate limiting)
	MaxEventsPerSecond uint32 `json:"max_events_per_second" yaml:"max_events_per_second"`
	
	// Burst size for rate limiting
	BurstSize uint32 `json:"burst_size" yaml:"burst_size"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	// Output format (json, text, binary)
	Format string `json:"format" yaml:"format"`
	
	// Output destination (stdout, file, syslog, network)
	Destination string `json:"destination" yaml:"destination"`
	
	// File output settings
	File FileOutputConfig `json:"file" yaml:"file"`
	
	// Network output settings
	Network NetworkOutputConfig `json:"network" yaml:"network"`
	
	// Buffer settings
	Buffer BufferConfig `json:"buffer" yaml:"buffer"`
	
	// Include/exclude fields
	IncludeFields []string `json:"include_fields" yaml:"include_fields"`
	ExcludeFields []string `json:"exclude_fields" yaml:"exclude_fields"`
}

// FileOutputConfig contains file output settings
type FileOutputConfig struct {
	// Output file path
	Path string `json:"path" yaml:"path"`
	
	// Enable log rotation
	Rotation bool `json:"rotation" yaml:"rotation"`
	
	// Maximum file size before rotation (MB)
	MaxSizeMB uint32 `json:"max_size_mb" yaml:"max_size_mb"`
	
	// Maximum number of rotated files to keep
	MaxFiles uint32 `json:"max_files" yaml:"max_files"`
	
	// File permissions (octal)
	Permissions string `json:"permissions" yaml:"permissions"`
}

// NetworkOutputConfig contains network output settings
type NetworkOutputConfig struct {
	// Protocol (tcp, udp, unix)
	Protocol string `json:"protocol" yaml:"protocol"`
	
	// Address (host:port or socket path)
	Address string `json:"address" yaml:"address"`
	
	// Connection timeout
	TimeoutSeconds uint32 `json:"timeout_seconds" yaml:"timeout_seconds"`
	
	// Enable TLS
	TLS bool `json:"tls" yaml:"tls"`
	
	// TLS certificate file
	TLSCertFile string `json:"tls_cert_file" yaml:"tls_cert_file"`
	
	// TLS key file
	TLSKeyFile string `json:"tls_key_file" yaml:"tls_key_file"`
}

// BufferConfig contains buffering settings
type BufferConfig struct {
	// Buffer size (number of events)
	Size uint32 `json:"size" yaml:"size"`
	
	// Flush interval (seconds)
	FlushIntervalSeconds uint32 `json:"flush_interval_seconds" yaml:"flush_interval_seconds"`
	
	// Enable compression
	Compression bool `json:"compression" yaml:"compression"`
}

// PerformanceConfig contains performance tuning settings
type PerformanceConfig struct {
	// Ring buffer size (bytes)
	RingBufferSize uint32 `json:"ring_buffer_size" yaml:"ring_buffer_size"`
	
	// Number of worker threads
	WorkerThreads uint32 `json:"worker_threads" yaml:"worker_threads"`
	
	// Event processing batch size
	BatchSize uint32 `json:"batch_size" yaml:"batch_size"`
	
	// Enable CPU affinity
	CPUAffinity bool `json:"cpu_affinity" yaml:"cpu_affinity"`
	
	// CPU cores to use (empty = all)
	CPUCores []uint32 `json:"cpu_cores" yaml:"cpu_cores"`
	
	// Memory limits
	MaxMemoryMB uint32 `json:"max_memory_mb" yaml:"max_memory_mb"`
	
	// Enable memory profiling
	MemoryProfiling bool `json:"memory_profiling" yaml:"memory_profiling"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	// Enable privilege dropping
	DropPrivileges bool `json:"drop_privileges" yaml:"drop_privileges"`
	
	// User to drop to
	User string `json:"user" yaml:"user"`
	
	// Group to drop to
	Group string `json:"group" yaml:"group"`
	
	// Enable seccomp filtering
	Seccomp bool `json:"seccomp" yaml:"seccomp"`
	
	// Enable capability restrictions
	CapabilityRestrictions bool `json:"capability_restrictions" yaml:"capability_restrictions"`
	
	// Required capabilities
	RequiredCapabilities []string `json:"required_capabilities" yaml:"required_capabilities"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		General: GeneralConfig{
			Enabled:          true,
			LogLevel:         "info",
			ProcessName:      "http-tracer",
			PidFile:          "/var/run/http-tracer.pid",
			GracefulShutdown: true,
		},
		Filtering: FilteringConfig{
			Enabled: true,
			ProcessFilters: ProcessFilters{
				MinPID: 1,
			},
			NetworkFilters: NetworkFilters{
				LocalhostOnly: false,
			},
			HTTPFilters: HTTPFilters{
				MinPayloadSize: 1,
				MaxPayloadSize: 4096,
			},
			EventTypeFilters: EventTypeFilters{
				EnableReadEvents:    true,
				EnableWriteEvents:   true,
				EnableConnectEvents: true,
				EnableAcceptEvents:  true,
			},
		},
		Sampling: SamplingConfig{
			Enabled:            false,
			Rate:               1.0,
			Strategy:           "random",
			MaxEventsPerSecond: 10000,
			BurstSize:          100,
		},
		Output: OutputConfig{
			Format:      "json",
			Destination: "stdout",
			File: FileOutputConfig{
				Path:        "/var/log/http-tracer.log",
				Rotation:    true,
				MaxSizeMB:   100,
				MaxFiles:    10,
				Permissions: "0644",
			},
			Network: NetworkOutputConfig{
				Protocol:       "tcp",
				Address:        "localhost:9999",
				TimeoutSeconds: 30,
				TLS:            false,
			},
			Buffer: BufferConfig{
				Size:                 1000,
				FlushIntervalSeconds: 5,
				Compression:          false,
			},
		},
		Performance: PerformanceConfig{
			RingBufferSize:  1024 * 1024, // 1MB
			WorkerThreads:   4,
			BatchSize:       100,
			CPUAffinity:     false,
			MaxMemoryMB:     100,
			MemoryProfiling: false,
		},
		Security: SecurityConfig{
			DropPrivileges:          false,
			User:                    "nobody",
			Group:                   "nobody",
			Seccomp:                 false,
			CapabilityRestrictions:  false,
			RequiredCapabilities:    []string{"CAP_SYS_ADMIN", "CAP_BPF"},
		},
	}
}

// LoadConfig loads configuration from file with environment variable overrides
func LoadConfig(configPath string) (*Config, error) {
	// Start with default configuration
	config := DefaultConfig()

	// Load from file if it exists
	if configPath != "" {
		if err := loadConfigFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %v", err)
		}
	}

	// Override with environment variables
	loadConfigFromEnv(config)

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// loadConfigFromFile loads configuration from a JSON file
func loadConfigFromFile(config *Config, path string) error {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", path)
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse JSON
	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	return nil
}

// loadConfigFromEnv loads configuration from environment variables
func loadConfigFromEnv(config *Config) {
	// General settings
	if val := os.Getenv("HTTP_TRACER_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.General.Enabled = enabled
		}
	}

	if val := os.Getenv("HTTP_TRACER_LOG_LEVEL"); val != "" {
		config.General.LogLevel = val
	}

	if val := os.Getenv("HTTP_TRACER_PROCESS_NAME"); val != "" {
		config.General.ProcessName = val
	}

	if val := os.Getenv("HTTP_TRACER_PID_FILE"); val != "" {
		config.General.PidFile = val
	}

	// Filtering settings
	if val := os.Getenv("HTTP_TRACER_FILTERING_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Filtering.Enabled = enabled
		}
	}

	if val := os.Getenv("HTTP_TRACER_INCLUDE_PIDS"); val != "" {
		pids := parseUint32List(val)
		if len(pids) > 0 {
			config.Filtering.ProcessFilters.IncludePIDs = pids
		}
	}

	if val := os.Getenv("HTTP_TRACER_EXCLUDE_PIDS"); val != "" {
		pids := parseUint32List(val)
		if len(pids) > 0 {
			config.Filtering.ProcessFilters.ExcludePIDs = pids
		}
	}

	if val := os.Getenv("HTTP_TRACER_INCLUDE_PROCESSES"); val != "" {
		processes := strings.Split(val, ",")
		for i, proc := range processes {
			processes[i] = strings.TrimSpace(proc)
		}
		config.Filtering.ProcessFilters.IncludeProcessNames = processes
	}

	// Sampling settings
	if val := os.Getenv("HTTP_TRACER_SAMPLING_ENABLED"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			config.Sampling.Enabled = enabled
		}
	}

	if val := os.Getenv("HTTP_TRACER_SAMPLING_RATE"); val != "" {
		if rate, err := strconv.ParseFloat(val, 64); err == nil {
			config.Sampling.Rate = rate
		}
	}

	if val := os.Getenv("HTTP_TRACER_MAX_EVENTS_PER_SEC"); val != "" {
		if maxEvents, err := strconv.ParseUint(val, 10, 32); err == nil {
			config.Sampling.MaxEventsPerSecond = uint32(maxEvents)
		}
	}

	// Output settings
	if val := os.Getenv("HTTP_TRACER_OUTPUT_FORMAT"); val != "" {
		config.Output.Format = val
	}

	if val := os.Getenv("HTTP_TRACER_OUTPUT_DESTINATION"); val != "" {
		config.Output.Destination = val
	}

	if val := os.Getenv("HTTP_TRACER_OUTPUT_FILE"); val != "" {
		config.Output.File.Path = val
	}

	// Performance settings
	if val := os.Getenv("HTTP_TRACER_RING_BUFFER_SIZE"); val != "" {
		if size, err := strconv.ParseUint(val, 10, 32); err == nil {
			config.Performance.RingBufferSize = uint32(size)
		}
	}

	if val := os.Getenv("HTTP_TRACER_WORKER_THREADS"); val != "" {
		if threads, err := strconv.ParseUint(val, 10, 32); err == nil {
			config.Performance.WorkerThreads = uint32(threads)
		}
	}
}

// parseUint32List parses a comma-separated list of uint32 values
func parseUint32List(s string) []uint32 {
	parts := strings.Split(s, ",")
	var result []uint32

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if val, err := strconv.ParseUint(part, 10, 32); err == nil {
			result = append(result, uint32(val))
		}
	}

	return result
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate general settings
	if c.General.LogLevel != "" {
		validLevels := []string{"debug", "info", "warn", "error"}
		if !contains(validLevels, c.General.LogLevel) {
			return fmt.Errorf("invalid log level: %s", c.General.LogLevel)
		}
	}

	// Validate sampling settings
	if c.Sampling.Enabled {
		if c.Sampling.Rate < 0.0 || c.Sampling.Rate > 1.0 {
			return fmt.Errorf("sampling rate must be between 0.0 and 1.0, got: %f", c.Sampling.Rate)
		}

		validStrategies := []string{"random", "deterministic", "adaptive"}
		if !contains(validStrategies, c.Sampling.Strategy) {
			return fmt.Errorf("invalid sampling strategy: %s", c.Sampling.Strategy)
		}
	}

	// Validate output settings
	validFormats := []string{"json", "text", "binary"}
	if !contains(validFormats, c.Output.Format) {
		return fmt.Errorf("invalid output format: %s", c.Output.Format)
	}

	validDestinations := []string{"stdout", "stderr", "file", "syslog", "network"}
	if !contains(validDestinations, c.Output.Destination) {
		return fmt.Errorf("invalid output destination: %s", c.Output.Destination)
	}

	// Validate file output settings
	if c.Output.Destination == "file" {
		if c.Output.File.Path == "" {
			return fmt.Errorf("file path is required when output destination is file")
		}

		// Validate file permissions
		if c.Output.File.Permissions != "" {
			if _, err := strconv.ParseUint(c.Output.File.Permissions, 8, 32); err != nil {
				return fmt.Errorf("invalid file permissions: %s", c.Output.File.Permissions)
			}
		}
	}

	// Validate network output settings
	if c.Output.Destination == "network" {
		if c.Output.Network.Address == "" {
			return fmt.Errorf("network address is required when output destination is network")
		}

		validProtocols := []string{"tcp", "udp", "unix"}
		if !contains(validProtocols, c.Output.Network.Protocol) {
			return fmt.Errorf("invalid network protocol: %s", c.Output.Network.Protocol)
		}
	}

	// Validate performance settings
	if c.Performance.RingBufferSize == 0 {
		return fmt.Errorf("ring buffer size must be greater than 0")
	}

	if c.Performance.WorkerThreads == 0 {
		return fmt.Errorf("worker threads must be greater than 0")
	}

	return nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// GetConfigPaths returns possible configuration file paths
func GetConfigPaths() []string {
	return []string{
		"./http-tracer.json",
		"./config/http-tracer.json",
		"/etc/http-tracer/config.json",
		"/usr/local/etc/http-tracer/config.json",
		filepath.Join(os.Getenv("HOME"), ".config", "http-tracer", "config.json"),
	}
}

// FindConfigFile finds the first existing configuration file
func FindConfigFile() string {
	for _, path := range GetConfigPaths() {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetDuration converts seconds to time.Duration
func (c *Config) GetFlushInterval() time.Duration {
	return time.Duration(c.Output.Buffer.FlushIntervalSeconds) * time.Second
}

// GetNetworkTimeout converts seconds to time.Duration
func (c *Config) GetNetworkTimeout() time.Duration {
	return time.Duration(c.Output.Network.TimeoutSeconds) * time.Second
}

// ShouldFilterPID checks if a PID should be filtered out
func (c *Config) ShouldFilterPID(pid uint32) bool {
	if !c.Filtering.Enabled {
		return false
	}

	// Check minimum PID
	if pid < c.Filtering.ProcessFilters.MinPID {
		return true
	}

	// Check include list (if specified, only include these PIDs)
	if len(c.Filtering.ProcessFilters.IncludePIDs) > 0 {
		found := false
		for _, includePID := range c.Filtering.ProcessFilters.IncludePIDs {
			if pid == includePID {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	// Check exclude list
	for _, excludePID := range c.Filtering.ProcessFilters.ExcludePIDs {
		if pid == excludePID {
			return true
		}
	}

	return false
}

// ShouldFilterProcess checks if a process name should be filtered out
func (c *Config) ShouldFilterProcess(processName string) bool {
	if !c.Filtering.Enabled {
		return false
	}

	// Check include list (if specified, only include these processes)
	if len(c.Filtering.ProcessFilters.IncludeProcessNames) > 0 {
		found := false
		for _, includeProcess := range c.Filtering.ProcessFilters.IncludeProcessNames {
			if processName == includeProcess {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	// Check exclude list
	for _, excludeProcess := range c.Filtering.ProcessFilters.ExcludeProcessNames {
		if processName == excludeProcess {
			return true
		}
	}

	return false
}
