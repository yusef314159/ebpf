package async

import (
	"fmt"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// ContextTracker tracks asynchronous execution contexts across goroutines and threads
type ContextTracker struct {
	contexts       map[uint64]*AsyncContext
	goroutineMap   map[uint64]*GoroutineInfo
	threadMap      map[uint32]*ThreadInfo
	correlationMap map[string]*CorrelationChain
	mutex          sync.RWMutex
	config         *AsyncConfig
	stats          *AsyncStats
}

// AsyncContext represents an asynchronous execution context
type AsyncContext struct {
	ID              uint64                 `json:"id"`
	Type            string                 `json:"type"` // goroutine, thread, async_task
	ParentID        uint64                 `json:"parent_id,omitempty"`
	TraceID         string                 `json:"trace_id"`
	SpanID          string                 `json:"span_id"`
	CreatedAt       time.Time              `json:"created_at"`
	LastActivity    time.Time              `json:"last_activity"`
	State           string                 `json:"state"` // active, waiting, completed, cancelled
	Metadata        map[string]interface{} `json:"metadata"`
	Events          []*AsyncEvent          `json:"events,omitempty"`
	CorrelationKeys []string               `json:"correlation_keys,omitempty"`
}

// GoroutineInfo represents information about a Go goroutine
type GoroutineInfo struct {
	GoroutineID    uint64    `json:"goroutine_id"`
	ThreadID       uint32    `json:"thread_id"`
	StackTrace     []string  `json:"stack_trace,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeen       time.Time `json:"last_seen"`
	State          string    `json:"state"`
	WaitReason     string    `json:"wait_reason,omitempty"`
	ParentGoroutine uint64   `json:"parent_goroutine,omitempty"`
}

// ThreadInfo represents information about an OS thread
type ThreadInfo struct {
	ThreadID       uint32    `json:"thread_id"`
	ProcessID      uint32    `json:"process_id"`
	Name           string    `json:"name,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeen       time.Time `json:"last_seen"`
	State          string    `json:"state"`
	CPUTime        uint64    `json:"cpu_time"`
	ContextSwitches uint64   `json:"context_switches"`
}

// CorrelationChain represents a chain of correlated async operations
type CorrelationChain struct {
	ChainID     string           `json:"chain_id"`
	RootContext *AsyncContext    `json:"root_context"`
	Contexts    []*AsyncContext  `json:"contexts"`
	Events      []*AsyncEvent    `json:"events"`
	CreatedAt   time.Time        `json:"created_at"`
	CompletedAt *time.Time       `json:"completed_at,omitempty"`
	Status      string           `json:"status"` // active, completed, failed, timeout
}

// AsyncEvent represents an event in an async context
type AsyncEvent struct {
	ID          uint64                 `json:"id"`
	ContextID   uint64                 `json:"context_id"`
	Type        string                 `json:"type"` // spawn, await, complete, error, timeout
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	TraceEvent  *tracing.TraceEvent    `json:"trace_event,omitempty"`
}

// AsyncConfig holds configuration for async context tracking
type AsyncConfig struct {
	EnableGoroutineTracking bool          `json:"enable_goroutine_tracking" yaml:"enable_goroutine_tracking"`
	EnableThreadTracking    bool          `json:"enable_thread_tracking" yaml:"enable_thread_tracking"`
	EnableCorrelation       bool          `json:"enable_correlation" yaml:"enable_correlation"`
	MaxContexts             int           `json:"max_contexts" yaml:"max_contexts"`
	ContextTimeout          time.Duration `json:"context_timeout" yaml:"context_timeout"`
	CleanupInterval         time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	MaxEventsPerContext     int           `json:"max_events_per_context" yaml:"max_events_per_context"`
	EnableStackTraces       bool          `json:"enable_stack_traces" yaml:"enable_stack_traces"`
	MaxStackDepth           int           `json:"max_stack_depth" yaml:"max_stack_depth"`
	CorrelationTimeout      time.Duration `json:"correlation_timeout" yaml:"correlation_timeout"`
}

// AsyncStats holds statistics for async context tracking
type AsyncStats struct {
	ActiveContexts      uint64    `json:"active_contexts"`
	TotalContexts       uint64    `json:"total_contexts"`
	CompletedContexts   uint64    `json:"completed_contexts"`
	TimeoutContexts     uint64    `json:"timeout_contexts"`
	ActiveGoroutines    uint64    `json:"active_goroutines"`
	ActiveThreads       uint64    `json:"active_threads"`
	CorrelationChains   uint64    `json:"correlation_chains"`
	EventsProcessed     uint64    `json:"events_processed"`
	LastCleanup         time.Time `json:"last_cleanup"`
	mutex               sync.RWMutex
}

// DefaultAsyncConfig returns default async configuration
func DefaultAsyncConfig() *AsyncConfig {
	return &AsyncConfig{
		EnableGoroutineTracking: true,
		EnableThreadTracking:    true,
		EnableCorrelation:       true,
		MaxContexts:             10000,
		ContextTimeout:          5 * time.Minute,
		CleanupInterval:         1 * time.Minute,
		MaxEventsPerContext:     100,
		EnableStackTraces:       true,
		MaxStackDepth:           20,
		CorrelationTimeout:      10 * time.Minute,
	}
}

// NewContextTracker creates a new async context tracker
func NewContextTracker(config *AsyncConfig) *ContextTracker {
	tracker := &ContextTracker{
		contexts:       make(map[uint64]*AsyncContext),
		goroutineMap:   make(map[uint64]*GoroutineInfo),
		threadMap:      make(map[uint32]*ThreadInfo),
		correlationMap: make(map[string]*CorrelationChain),
		config:         config,
		stats:          &AsyncStats{},
	}

	// Start cleanup goroutine
	go tracker.cleanupLoop()

	return tracker
}

// TrackGoroutineSpawn tracks the spawning of a new goroutine
func (ct *ContextTracker) TrackGoroutineSpawn(parentGoroutineID, newGoroutineID uint64, threadID uint32, traceID, spanID string) error {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	now := time.Now()

	// Create goroutine info
	goroutineInfo := &GoroutineInfo{
		GoroutineID:     newGoroutineID,
		ThreadID:        threadID,
		CreatedAt:       now,
		LastSeen:        now,
		State:           "running",
		ParentGoroutine: parentGoroutineID,
	}

	if ct.config.EnableStackTraces {
		goroutineInfo.StackTrace = ct.captureStackTrace()
	}

	ct.goroutineMap[newGoroutineID] = goroutineInfo

	// Create async context
	context := &AsyncContext{
		ID:           newGoroutineID,
		Type:         "goroutine",
		ParentID:     parentGoroutineID,
		TraceID:      traceID,
		SpanID:       spanID,
		CreatedAt:    now,
		LastActivity: now,
		State:        "active",
		Metadata:     make(map[string]interface{}),
		Events:       make([]*AsyncEvent, 0),
	}

	context.Metadata["thread_id"] = threadID
	context.Metadata["parent_goroutine"] = parentGoroutineID

	ct.contexts[newGoroutineID] = context

	// Create spawn event
	event := &AsyncEvent{
		ID:          ct.generateEventID(),
		ContextID:   newGoroutineID,
		Type:        "spawn",
		Timestamp:   now,
		Description: fmt.Sprintf("Goroutine %d spawned from %d", newGoroutineID, parentGoroutineID),
		Metadata:    make(map[string]interface{}),
	}

	event.Metadata["parent_goroutine"] = parentGoroutineID
	event.Metadata["thread_id"] = threadID

	ct.addEventToContext(context, event)

	// Update correlation if enabled
	if ct.config.EnableCorrelation {
		ct.updateCorrelation(context, event)
	}

	// Update stats
	ct.stats.mutex.Lock()
	ct.stats.ActiveContexts++
	ct.stats.TotalContexts++
	ct.stats.ActiveGoroutines++
	ct.stats.EventsProcessed++
	ct.stats.mutex.Unlock()

	return nil
}

// TrackThreadCreation tracks the creation of a new OS thread
func (ct *ContextTracker) TrackThreadCreation(threadID, processID uint32, name string) error {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	now := time.Now()

	threadInfo := &ThreadInfo{
		ThreadID:  threadID,
		ProcessID: processID,
		Name:      name,
		CreatedAt: now,
		LastSeen:  now,
		State:     "running",
	}

	ct.threadMap[threadID] = threadInfo

	// Update stats
	ct.stats.mutex.Lock()
	ct.stats.ActiveThreads++
	ct.stats.mutex.Unlock()

	return nil
}

// TrackAsyncOperation tracks an async operation (await, promise, future, etc.)
func (ct *ContextTracker) TrackAsyncOperation(contextID uint64, operationType, description string, metadata map[string]interface{}) error {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	context, exists := ct.contexts[contextID]
	if !exists {
		return fmt.Errorf("context %d not found", contextID)
	}

	now := time.Now()
	context.LastActivity = now

	// Create async operation event
	event := &AsyncEvent{
		ID:          ct.generateEventID(),
		ContextID:   contextID,
		Type:        operationType,
		Timestamp:   now,
		Description: description,
		Metadata:    metadata,
	}

	ct.addEventToContext(context, event)

	// Update correlation
	if ct.config.EnableCorrelation {
		ct.updateCorrelation(context, event)
	}

	// Update stats
	ct.stats.mutex.Lock()
	ct.stats.EventsProcessed++
	ct.stats.mutex.Unlock()

	return nil
}

// TrackContextCompletion tracks the completion of an async context
func (ct *ContextTracker) TrackContextCompletion(contextID uint64, status string) error {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	context, exists := ct.contexts[contextID]
	if !exists {
		return fmt.Errorf("context %d not found", contextID)
	}

	now := time.Now()
	context.LastActivity = now
	context.State = "completed"

	// Create completion event
	event := &AsyncEvent{
		ID:          ct.generateEventID(),
		ContextID:   contextID,
		Type:        "complete",
		Timestamp:   now,
		Description: fmt.Sprintf("Context completed with status: %s", status),
		Metadata:    map[string]interface{}{"status": status},
	}

	ct.addEventToContext(context, event)

	// Update goroutine info if applicable
	if context.Type == "goroutine" {
		if goroutineInfo, exists := ct.goroutineMap[contextID]; exists {
			goroutineInfo.State = "completed"
			goroutineInfo.LastSeen = now
		}
	}

	// Update correlation
	if ct.config.EnableCorrelation {
		ct.updateCorrelation(context, event)
		ct.completeCorrelationChain(context)
	}

	// Update stats
	ct.stats.mutex.Lock()
	ct.stats.ActiveContexts--
	ct.stats.CompletedContexts++
	if context.Type == "goroutine" {
		ct.stats.ActiveGoroutines--
	}
	ct.stats.EventsProcessed++
	ct.stats.mutex.Unlock()

	return nil
}

// GetContext retrieves an async context by ID
func (ct *ContextTracker) GetContext(contextID uint64) (*AsyncContext, error) {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	context, exists := ct.contexts[contextID]
	if !exists {
		return nil, fmt.Errorf("context %d not found", contextID)
	}

	return context, nil
}

// GetCorrelationChain retrieves a correlation chain by ID
func (ct *ContextTracker) GetCorrelationChain(chainID string) (*CorrelationChain, error) {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	chain, exists := ct.correlationMap[chainID]
	if !exists {
		return nil, fmt.Errorf("correlation chain %s not found", chainID)
	}

	return chain, nil
}

// GetActiveContexts returns all active contexts
func (ct *ContextTracker) GetActiveContexts() []*AsyncContext {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	var active []*AsyncContext
	for _, context := range ct.contexts {
		if context.State == "active" {
			active = append(active, context)
		}
	}

	return active
}

// GetStats returns async tracking statistics
func (ct *ContextTracker) GetStats() *AsyncStats {
	ct.stats.mutex.RLock()
	defer ct.stats.mutex.RUnlock()

	// Create a copy to avoid race conditions
	stats := *ct.stats
	return &stats
}

// addEventToContext adds an event to a context
func (ct *ContextTracker) addEventToContext(context *AsyncContext, event *AsyncEvent) {
	context.Events = append(context.Events, event)

	// Limit events per context
	if len(context.Events) > ct.config.MaxEventsPerContext {
		context.Events = context.Events[1:] // Remove oldest event
	}
}

// updateCorrelation updates correlation chains
func (ct *ContextTracker) updateCorrelation(context *AsyncContext, event *AsyncEvent) {
	chainID := context.TraceID
	if chainID == "" {
		chainID = fmt.Sprintf("chain_%d", context.ID)
	}

	chain, exists := ct.correlationMap[chainID]
	if !exists {
		chain = &CorrelationChain{
			ChainID:   chainID,
			Contexts:  make([]*AsyncContext, 0),
			Events:    make([]*AsyncEvent, 0),
			CreatedAt: time.Now(),
			Status:    "active",
		}
		ct.correlationMap[chainID] = chain
		
		ct.stats.mutex.Lock()
		ct.stats.CorrelationChains++
		ct.stats.mutex.Unlock()
	}

	// Add context to chain if not already present
	found := false
	for _, ctx := range chain.Contexts {
		if ctx.ID == context.ID {
			found = true
			break
		}
	}
	if !found {
		chain.Contexts = append(chain.Contexts, context)
		if chain.RootContext == nil || context.ParentID == 0 {
			chain.RootContext = context
		}
	}

	// Add event to chain
	chain.Events = append(chain.Events, event)
}

// completeCorrelationChain marks a correlation chain as completed
func (ct *ContextTracker) completeCorrelationChain(context *AsyncContext) {
	chainID := context.TraceID
	if chainID == "" {
		chainID = fmt.Sprintf("chain_%d", context.ID)
	}

	if chain, exists := ct.correlationMap[chainID]; exists {
		// Check if all contexts in the chain are completed
		allCompleted := true
		for _, ctx := range chain.Contexts {
			if ctx.State != "completed" {
				allCompleted = false
				break
			}
		}

		if allCompleted {
			now := time.Now()
			chain.CompletedAt = &now
			chain.Status = "completed"
		}
	}
}

// captureStackTrace captures a stack trace (simplified implementation)
func (ct *ContextTracker) captureStackTrace() []string {
	// In a real implementation, this would capture the actual stack trace
	// using runtime.Stack() or similar mechanisms
	return []string{
		"goroutine_spawn_point",
		"caller_function",
		"main_function",
	}
}

// generateEventID generates a unique event ID
func (ct *ContextTracker) generateEventID() uint64 {
	// Simple implementation - in practice, use a proper ID generator
	return uint64(time.Now().UnixNano())
}

// cleanupLoop runs periodic cleanup of expired contexts
func (ct *ContextTracker) cleanupLoop() {
	ticker := time.NewTicker(ct.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		ct.cleanup()
	}
}

// cleanup removes expired contexts and correlation chains
func (ct *ContextTracker) cleanup() {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	now := time.Now()
	timeout := ct.config.ContextTimeout

	// Cleanup expired contexts
	for id, context := range ct.contexts {
		if context.State != "active" || now.Sub(context.LastActivity) > timeout {
			delete(ct.contexts, id)
			
			// Cleanup goroutine info
			if context.Type == "goroutine" {
				delete(ct.goroutineMap, id)
			}

			ct.stats.mutex.Lock()
			if context.State == "active" {
				ct.stats.TimeoutContexts++
				ct.stats.ActiveContexts--
				if context.Type == "goroutine" {
					ct.stats.ActiveGoroutines--
				}
			}
			ct.stats.mutex.Unlock()
		}
	}

	// Cleanup expired correlation chains
	correlationTimeout := ct.config.CorrelationTimeout
	for chainID, chain := range ct.correlationMap {
		if chain.Status == "completed" || now.Sub(chain.CreatedAt) > correlationTimeout {
			delete(ct.correlationMap, chainID)
			
			ct.stats.mutex.Lock()
			ct.stats.CorrelationChains--
			ct.stats.mutex.Unlock()
		}
	}

	ct.stats.mutex.Lock()
	ct.stats.LastCleanup = now
	ct.stats.mutex.Unlock()
}

// Close shuts down the context tracker
func (ct *ContextTracker) Close() error {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	ct.contexts = nil
	ct.goroutineMap = nil
	ct.threadMap = nil
	ct.correlationMap = nil

	return nil
}
