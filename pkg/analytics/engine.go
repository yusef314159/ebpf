package analytics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// AnalyticsEngine provides real-time stream processing and analytics
type AnalyticsEngine struct {
	config          *AnalyticsConfig
	processors      map[string]Processor
	aggregators     map[string]Aggregator
	alertManager    *AlertManager
	metricStore     *MetricStore
	eventChannel    chan *tracing.TraceEvent
	stopChannel     chan struct{}
	wg              sync.WaitGroup
	mutex           sync.RWMutex
}

// AnalyticsConfig holds configuration for the analytics engine
type AnalyticsConfig struct {
	// Processing configuration
	BufferSize       int           `json:"buffer_size"`
	WorkerThreads    int           `json:"worker_threads"`
	FlushInterval    time.Duration `json:"flush_interval"`
	
	// Time window configuration
	WindowSizes      []time.Duration `json:"window_sizes"`
	RetentionPeriod  time.Duration   `json:"retention_period"`
	
	// Aggregation configuration
	EnabledMetrics   []string `json:"enabled_metrics"`
	CustomMetrics    []CustomMetricConfig `json:"custom_metrics"`
	
	// Alerting configuration
	EnableAlerting   bool                 `json:"enable_alerting"`
	AlertRules       []AlertRuleConfig    `json:"alert_rules"`
	
	// Output configuration
	EnableDashboard  bool   `json:"enable_dashboard"`
	DashboardPort    int    `json:"dashboard_port"`
	MetricsEndpoint  string `json:"metrics_endpoint"`
}

// CustomMetricConfig defines a custom metric
type CustomMetricConfig struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`        // counter, gauge, histogram
	Description string            `json:"description"`
	Labels      []string          `json:"labels"`
	Filters     map[string]string `json:"filters"`
}

// AlertRuleConfig defines an alerting rule
type AlertRuleConfig struct {
	Name        string            `json:"name"`
	Metric      string            `json:"metric"`
	Condition   string            `json:"condition"`   // gt, lt, eq, ne
	Threshold   float64           `json:"threshold"`
	Duration    time.Duration     `json:"duration"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// Processor interface for stream processing
type Processor interface {
	Process(event *tracing.TraceEvent) error
	Name() string
	Metrics() map[string]interface{}
}

// Aggregator interface for metric aggregation
type Aggregator interface {
	Aggregate(metric string, value float64, labels map[string]string, timestamp time.Time) error
	GetMetrics(window time.Duration) (map[string]MetricValue, error)
	Name() string
}

// MetricValue represents an aggregated metric value
type MetricValue struct {
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels"`
	Timestamp time.Time         `json:"timestamp"`
	Type      string            `json:"type"`
}

// NewAnalyticsEngine creates a new analytics engine
func NewAnalyticsEngine(config *AnalyticsConfig) (*AnalyticsEngine, error) {
	engine := &AnalyticsEngine{
		config:       config,
		processors:   make(map[string]Processor),
		aggregators:  make(map[string]Aggregator),
		metricStore:  NewMetricStore(config.RetentionPeriod),
		eventChannel: make(chan *tracing.TraceEvent, config.BufferSize),
		stopChannel:  make(chan struct{}),
	}

	// Initialize alert manager if alerting is enabled
	if config.EnableAlerting {
		engine.alertManager = NewAlertManager(config.AlertRules)
	}

	// Register default processors
	if err := engine.registerDefaultProcessors(); err != nil {
		return nil, fmt.Errorf("failed to register default processors: %w", err)
	}

	// Register default aggregators
	if err := engine.registerDefaultAggregators(); err != nil {
		return nil, fmt.Errorf("failed to register default aggregators: %w", err)
	}

	return engine, nil
}

// Start starts the analytics engine
func (ae *AnalyticsEngine) Start(ctx context.Context) error {
	// Start worker threads
	for i := 0; i < ae.config.WorkerThreads; i++ {
		ae.wg.Add(1)
		go ae.worker(ctx, i)
	}

	// Start aggregation flush routine
	ae.wg.Add(1)
	go ae.flushRoutine(ctx)

	// Start alert evaluation routine if alerting is enabled
	if ae.alertManager != nil {
		ae.wg.Add(1)
		go ae.alertRoutine(ctx)
	}

	// Start dashboard if enabled
	if ae.config.EnableDashboard {
		ae.wg.Add(1)
		go ae.startDashboard(ctx)
	}

	return nil
}

// Stop stops the analytics engine
func (ae *AnalyticsEngine) Stop() {
	close(ae.stopChannel)
	ae.wg.Wait()
}

// ProcessEvent processes a trace event
func (ae *AnalyticsEngine) ProcessEvent(event *tracing.TraceEvent) error {
	select {
	case ae.eventChannel <- event:
		return nil
	default:
		// Channel full, drop event or implement backpressure
		return fmt.Errorf("analytics engine buffer full")
	}
}

// worker processes events from the event channel
func (ae *AnalyticsEngine) worker(ctx context.Context, workerID int) {
	defer ae.wg.Done()

	for {
		select {
		case event := <-ae.eventChannel:
			ae.processEvent(event)
		case <-ae.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

// processEvent processes a single event through all processors
func (ae *AnalyticsEngine) processEvent(event *tracing.TraceEvent) {
	ae.mutex.RLock()
	processors := make([]Processor, 0, len(ae.processors))
	for _, processor := range ae.processors {
		processors = append(processors, processor)
	}
	ae.mutex.RUnlock()

	// Process event through all processors
	for _, processor := range processors {
		if err := processor.Process(event); err != nil {
			// Log error but continue processing
			continue
		}
	}
}

// flushRoutine periodically flushes aggregated metrics
func (ae *AnalyticsEngine) flushRoutine(ctx context.Context) {
	defer ae.wg.Done()

	ticker := time.NewTicker(ae.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ae.flushMetrics()
		case <-ae.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

// flushMetrics flushes aggregated metrics to the metric store
func (ae *AnalyticsEngine) flushMetrics() {
	ae.mutex.RLock()
	aggregators := make([]Aggregator, 0, len(ae.aggregators))
	for _, aggregator := range ae.aggregators {
		aggregators = append(aggregators, aggregator)
	}
	ae.mutex.RUnlock()

	timestamp := time.Now()

	for _, aggregator := range aggregators {
		for _, window := range ae.config.WindowSizes {
			metrics, err := aggregator.GetMetrics(window)
			if err != nil {
				continue
			}

			for metricName, metricValue := range metrics {
				ae.metricStore.Store(metricName, metricValue, timestamp)
			}
		}
	}
}

// alertRoutine evaluates alert rules
func (ae *AnalyticsEngine) alertRoutine(ctx context.Context) {
	defer ae.wg.Done()

	ticker := time.NewTicker(10 * time.Second) // Evaluate alerts every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ae.evaluateAlerts()
		case <-ae.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

// evaluateAlerts evaluates all alert rules
func (ae *AnalyticsEngine) evaluateAlerts() {
	if ae.alertManager == nil {
		return
	}

	// Get current metrics for alert evaluation
	metrics := ae.metricStore.GetCurrentMetrics()
	ae.alertManager.Evaluate(metrics)
}

// RegisterProcessor registers a custom processor
func (ae *AnalyticsEngine) RegisterProcessor(processor Processor) error {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.processors[processor.Name()] = processor
	return nil
}

// RegisterAggregator registers a custom aggregator
func (ae *AnalyticsEngine) RegisterAggregator(aggregator Aggregator) error {
	ae.mutex.Lock()
	defer ae.mutex.Unlock()

	ae.aggregators[aggregator.Name()] = aggregator
	return nil
}

// GetMetrics returns current metrics
func (ae *AnalyticsEngine) GetMetrics() map[string]interface{} {
	result := make(map[string]interface{})

	// Get processor metrics
	ae.mutex.RLock()
	for name, processor := range ae.processors {
		result[name] = processor.Metrics()
	}
	ae.mutex.RUnlock()

	// Get aggregated metrics
	result["aggregated"] = ae.metricStore.GetCurrentMetrics()

	return result
}

// GetHealthStatus returns the health status of the analytics engine
func (ae *AnalyticsEngine) GetHealthStatus() map[string]interface{} {
	return map[string]interface{}{
		"status":           "healthy",
		"processors":       len(ae.processors),
		"aggregators":      len(ae.aggregators),
		"buffer_size":      len(ae.eventChannel),
		"buffer_capacity":  cap(ae.eventChannel),
		"worker_threads":   ae.config.WorkerThreads,
	}
}

// registerDefaultProcessors registers the default set of processors
func (ae *AnalyticsEngine) registerDefaultProcessors() error {
	// HTTP metrics processor
	httpProcessor := NewHTTPMetricsProcessor(ae.aggregators)
	if err := ae.RegisterProcessor(httpProcessor); err != nil {
		return err
	}

	// Network metrics processor
	networkProcessor := NewNetworkMetricsProcessor(ae.aggregators)
	if err := ae.RegisterProcessor(networkProcessor); err != nil {
		return err
	}

	// Performance metrics processor
	perfProcessor := NewPerformanceMetricsProcessor(ae.aggregators)
	if err := ae.RegisterProcessor(perfProcessor); err != nil {
		return err
	}

	// Error metrics processor
	errorProcessor := NewErrorMetricsProcessor(ae.aggregators)
	if err := ae.RegisterProcessor(errorProcessor); err != nil {
		return err
	}

	return nil
}

// registerDefaultAggregators registers the default set of aggregators
func (ae *AnalyticsEngine) registerDefaultAggregators() error {
	// Time series aggregator for time-based metrics
	timeSeriesAgg := NewTimeSeriesAggregator(ae.config.WindowSizes)
	if err := ae.RegisterAggregator(timeSeriesAgg); err != nil {
		return err
	}

	// Histogram aggregator for latency metrics
	histogramAgg := NewHistogramAggregator()
	if err := ae.RegisterAggregator(histogramAgg); err != nil {
		return err
	}

	// Counter aggregator for rate metrics
	counterAgg := NewCounterAggregator()
	if err := ae.RegisterAggregator(counterAgg); err != nil {
		return err
	}

	return nil
}

// DefaultAnalyticsConfig returns a default analytics configuration
func DefaultAnalyticsConfig() *AnalyticsConfig {
	return &AnalyticsConfig{
		BufferSize:    10000,
		WorkerThreads: 4,
		FlushInterval: 10 * time.Second,
		WindowSizes: []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
		},
		RetentionPeriod: 24 * time.Hour,
		EnabledMetrics: []string{
			"http_requests_total",
			"http_request_duration",
			"http_response_size",
			"network_bytes_total",
			"error_rate",
		},
		EnableAlerting:  false,
		EnableDashboard: true,
		DashboardPort:   8080,
		MetricsEndpoint: "/metrics",
	}
}
