package outputs

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// UnixSocketConfig contains configuration for Unix socket output
type UnixSocketConfig struct {
	OutputConfig `yaml:",inline"`
	
	// Unix socket path
	SocketPath string `json:"socket_path" yaml:"socket_path"`
	
	// Socket permissions (octal, e.g., 0666)
	SocketPermissions os.FileMode `json:"socket_permissions" yaml:"socket_permissions"`
	
	// Remove existing socket file on startup
	RemoveExisting bool `json:"remove_existing" yaml:"remove_existing"`
	
	// Keep-alive settings
	KeepAlive         bool          `json:"keep_alive" yaml:"keep_alive"`
	KeepAliveInterval time.Duration `json:"keep_alive_interval" yaml:"keep_alive_interval"`
}

// DefaultUnixSocketConfig returns default Unix socket configuration
func DefaultUnixSocketConfig() UnixSocketConfig {
	config := DefaultOutputConfig()
	config.Type = "unix_socket"
	
	return UnixSocketConfig{
		OutputConfig:      config,
		SocketPath:        "/var/run/ebpf-tracer.sock",
		SocketPermissions: 0666,
		RemoveExisting:    true,
		KeepAlive:         true,
		KeepAliveInterval: 30 * time.Second,
	}
}

// UnixSocketOutput implements EventOutput for Unix domain sockets
type UnixSocketOutput struct {
	name     string
	config   UnixSocketConfig
	listener net.Listener
	clients  map[net.Conn]bool
	mutex    sync.RWMutex
	metrics  OutputMetrics
	ctx      context.Context
	cancel   context.CancelFunc
	startTime time.Time
}

// NewUnixSocketOutput creates a new Unix socket output adapter
func NewUnixSocketOutput(name string, config UnixSocketConfig) *UnixSocketOutput {
	return &UnixSocketOutput{
		name:    name,
		config:  config,
		clients: make(map[net.Conn]bool),
		metrics: OutputMetrics{
			IsConnected: false,
		},
	}
}

// Initialize implements EventOutput.Initialize
func (uso *UnixSocketOutput) Initialize(ctx context.Context) error {
	uso.ctx, uso.cancel = context.WithCancel(ctx)
	uso.startTime = time.Now()
	
	// Remove existing socket file if configured
	if uso.config.RemoveExisting {
		if err := os.Remove(uso.config.SocketPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing socket: %w", err)
		}
	}
	
	// Create Unix domain socket listener
	listener, err := net.Listen("unix", uso.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}
	
	uso.listener = listener
	
	// Set socket permissions
	if err := os.Chmod(uso.config.SocketPath, uso.config.SocketPermissions); err != nil {
		uso.listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}
	
	// Start accepting connections
	go uso.acceptConnections()
	
	uso.metrics.IsConnected = true
	uso.metrics.ConnectionUptime = time.Since(uso.startTime)
	
	return nil
}

// acceptConnections accepts incoming client connections
func (uso *UnixSocketOutput) acceptConnections() {
	for {
		select {
		case <-uso.ctx.Done():
			return
		default:
			conn, err := uso.listener.Accept()
			if err != nil {
				if uso.ctx.Err() != nil {
					return // Context cancelled
				}
				uso.recordError(fmt.Errorf("failed to accept connection: %w", err))
				continue
			}
			
			uso.mutex.Lock()
			uso.clients[conn] = true
			uso.mutex.Unlock()
			
			// Handle client connection
			go uso.handleClient(conn)
		}
	}
}

// handleClient handles a client connection
func (uso *UnixSocketOutput) handleClient(conn net.Conn) {
	defer func() {
		uso.mutex.Lock()
		delete(uso.clients, conn)
		uso.mutex.Unlock()
		conn.Close()
	}()
	
	// Set up keep-alive if enabled
	if uso.config.KeepAlive {
		if unixConn, ok := conn.(*net.UnixConn); ok {
			// Unix sockets don't support keep-alive, but we can set deadlines
			deadline := time.Now().Add(uso.config.KeepAliveInterval)
			unixConn.SetDeadline(deadline)
		}
	}
	
	// Keep connection alive until context is cancelled or client disconnects
	<-uso.ctx.Done()
}

// WriteEvent implements EventOutput.WriteEvent
func (uso *UnixSocketOutput) WriteEvent(event interface{}) error {
	return uso.WriteBatch([]interface{}{event})
}

// WriteBatch implements EventOutput.WriteBatch
func (uso *UnixSocketOutput) WriteBatch(events []interface{}) error {
	if len(events) == 0 {
		return nil
	}
	
	uso.mutex.RLock()
	clients := make([]net.Conn, 0, len(uso.clients))
	for client := range uso.clients {
		clients = append(clients, client)
	}
	uso.mutex.RUnlock()
	
	if len(clients) == 0 {
		// No clients connected, but don't consider this an error
		return nil
	}
	
	// Serialize events to JSON
	var data []byte
	var err error
	
	if len(events) == 1 {
		// Single event
		data, err = json.Marshal(events[0])
		if err != nil {
			uso.recordError(fmt.Errorf("failed to marshal event: %w", err))
			return err
		}
		data = append(data, '\n') // Add newline for line-based parsing
	} else {
		// Multiple events - send as NDJSON (newline-delimited JSON)
		for i, event := range events {
			eventData, err := json.Marshal(event)
			if err != nil {
				uso.recordError(fmt.Errorf("failed to marshal event %d: %w", i, err))
				continue
			}
			data = append(data, eventData...)
			data = append(data, '\n')
		}
	}
	
	// Write to all connected clients
	var lastError error
	successCount := 0
	
	for _, client := range clients {
		// Set write timeout
		if uso.config.WriteTimeout > 0 {
			client.SetWriteDeadline(time.Now().Add(uso.config.WriteTimeout))
		}
		
		_, err := client.Write(data)
		if err != nil {
			lastError = err
			uso.recordError(fmt.Errorf("failed to write to client: %w", err))
			
			// Remove failed client
			uso.mutex.Lock()
			delete(uso.clients, client)
			uso.mutex.Unlock()
			client.Close()
		} else {
			successCount++
			uso.metrics.EventsWritten += uint64(len(events))
			uso.metrics.BytesWritten += uint64(len(data))
		}
	}
	
	// Return error only if all clients failed
	if lastError != nil && successCount == 0 {
		return lastError
	}
	
	return nil
}

// Close implements EventOutput.Close
func (uso *UnixSocketOutput) Close() error {
	if uso.cancel != nil {
		uso.cancel()
	}
	
	// Close all client connections
	uso.mutex.Lock()
	for client := range uso.clients {
		client.Close()
	}
	uso.clients = make(map[net.Conn]bool)
	uso.mutex.Unlock()
	
	// Close listener
	if uso.listener != nil {
		uso.listener.Close()
	}
	
	// Remove socket file
	if uso.config.RemoveExisting {
		os.Remove(uso.config.SocketPath)
	}
	
	uso.metrics.IsConnected = false
	return nil
}

// Name implements EventOutput.Name
func (uso *UnixSocketOutput) Name() string {
	return uso.name
}

// IsHealthy implements EventOutput.IsHealthy
func (uso *UnixSocketOutput) IsHealthy() bool {
	return uso.metrics.IsConnected && uso.listener != nil
}

// GetMetrics implements EventOutput.GetMetrics
func (uso *UnixSocketOutput) GetMetrics() OutputMetrics {
	uso.metrics.ConnectionUptime = time.Since(uso.startTime)

	// Update connection status based on listener state
	if uso.listener != nil {
		uso.metrics.IsConnected = true
	}

	return uso.metrics
}

// GetClientCount returns the number of connected clients
func (uso *UnixSocketOutput) GetClientCount() int {
	uso.mutex.RLock()
	defer uso.mutex.RUnlock()
	return len(uso.clients)
}

// recordError records an error in metrics
func (uso *UnixSocketOutput) recordError(err error) {
	uso.metrics.ErrorCount++
	uso.metrics.LastError = err.Error()
	now := time.Now()
	uso.metrics.LastErrorTime = &now
}
