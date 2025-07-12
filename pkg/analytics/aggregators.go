package analytics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// TimeSeriesAggregator aggregates metrics over time windows
type TimeSeriesAggregator struct {
	windowSizes []time.Duration
	data        map[string]*TimeSeriesData
	mutex       sync.RWMutex
}

// TimeSeriesData holds time series data for a metric
type TimeSeriesData struct {
	Points []TimePoint
	Labels map[string]string
}

// TimePoint represents a single data point
type TimePoint struct {
	Timestamp time.Time
	Value     float64
}

// NewTimeSeriesAggregator creates a new time series aggregator
func NewTimeSeriesAggregator(windowSizes []time.Duration) *TimeSeriesAggregator {
	return &TimeSeriesAggregator{
		windowSizes: windowSizes,
		data:        make(map[string]*TimeSeriesData),
	}
}

// Name returns the aggregator name
func (tsa *TimeSeriesAggregator) Name() string {
	return "timeseries"
}

// Aggregate aggregates a metric value
func (tsa *TimeSeriesAggregator) Aggregate(metric string, value float64, labels map[string]string, timestamp time.Time) error {
	key := tsa.buildKey(metric, labels)

	tsa.mutex.Lock()
	defer tsa.mutex.Unlock()

	if _, exists := tsa.data[key]; !exists {
		tsa.data[key] = &TimeSeriesData{
			Points: make([]TimePoint, 0),
			Labels: labels,
		}
	}

	// Add new data point
	tsa.data[key].Points = append(tsa.data[key].Points, TimePoint{
		Timestamp: timestamp,
		Value:     value,
	})

	// Clean old data points (keep only the largest window size + buffer)
	if len(tsa.windowSizes) > 0 {
		maxWindow := tsa.windowSizes[0]
		for _, window := range tsa.windowSizes {
			if window > maxWindow {
				maxWindow = window
			}
		}

		cutoff := timestamp.Add(-maxWindow - time.Hour) // Add 1 hour buffer
		tsa.cleanOldData(key, cutoff)
	}

	return nil
}

// GetMetrics returns aggregated metrics for a time window
func (tsa *TimeSeriesAggregator) GetMetrics(window time.Duration) (map[string]MetricValue, error) {
	tsa.mutex.RLock()
	defer tsa.mutex.RUnlock()

	result := make(map[string]MetricValue)
	now := time.Now()
	windowStart := now.Add(-window)

	for key, data := range tsa.data {
		// Filter points within the window
		var windowPoints []TimePoint
		for _, point := range data.Points {
			if point.Timestamp.After(windowStart) {
				windowPoints = append(windowPoints, point)
			}
		}

		if len(windowPoints) == 0 {
			continue
		}

		// Calculate aggregated value (sum for counters, average for gauges)
		var aggregatedValue float64
		for _, point := range windowPoints {
			aggregatedValue += point.Value
		}

		result[key] = MetricValue{
			Value:     aggregatedValue,
			Labels:    data.Labels,
			Timestamp: now,
			Type:      "timeseries",
		}
	}

	return result, nil
}

// cleanOldData removes data points older than the cutoff time
func (tsa *TimeSeriesAggregator) cleanOldData(key string, cutoff time.Time) {
	data := tsa.data[key]
	var newPoints []TimePoint

	for _, point := range data.Points {
		if point.Timestamp.After(cutoff) {
			newPoints = append(newPoints, point)
		}
	}

	data.Points = newPoints
}

// buildKey builds a unique key for a metric with labels
func (tsa *TimeSeriesAggregator) buildKey(metric string, labels map[string]string) string {
	key := metric
	for k, v := range labels {
		key += fmt.Sprintf(",%s=%s", k, v)
	}
	return key
}

// HistogramAggregator aggregates metrics into histograms for percentile calculation
type HistogramAggregator struct {
	data  map[string]*HistogramData
	mutex sync.RWMutex
}

// HistogramData holds histogram data for a metric
type HistogramData struct {
	Values    []float64
	Labels    map[string]string
	LastUpdate time.Time
}

// NewHistogramAggregator creates a new histogram aggregator
func NewHistogramAggregator() *HistogramAggregator {
	return &HistogramAggregator{
		data: make(map[string]*HistogramData),
	}
}

// Name returns the aggregator name
func (ha *HistogramAggregator) Name() string {
	return "histogram"
}

// Aggregate aggregates a metric value into a histogram
func (ha *HistogramAggregator) Aggregate(metric string, value float64, labels map[string]string, timestamp time.Time) error {
	// Only aggregate histogram metrics
	if metric != "http_request_duration_histogram" && metric != "http_request_duration_seconds" {
		return nil
	}

	key := ha.buildKey(metric, labels)

	ha.mutex.Lock()
	defer ha.mutex.Unlock()

	if _, exists := ha.data[key]; !exists {
		ha.data[key] = &HistogramData{
			Values: make([]float64, 0),
			Labels: labels,
		}
	}

	ha.data[key].Values = append(ha.data[key].Values, value)
	ha.data[key].LastUpdate = timestamp

	// Limit histogram size to prevent memory issues
	if len(ha.data[key].Values) > 10000 {
		// Keep only the most recent 10000 values
		ha.data[key].Values = ha.data[key].Values[len(ha.data[key].Values)-10000:]
	}

	return nil
}

// GetMetrics returns histogram metrics (percentiles)
func (ha *HistogramAggregator) GetMetrics(window time.Duration) (map[string]MetricValue, error) {
	ha.mutex.RLock()
	defer ha.mutex.RUnlock()

	result := make(map[string]MetricValue)
	now := time.Now()

	for key, data := range ha.data {
		// Only include recent data
		if now.Sub(data.LastUpdate) > window {
			continue
		}

		if len(data.Values) == 0 {
			continue
		}

		// Calculate percentiles
		values := make([]float64, len(data.Values))
		copy(values, data.Values)
		sort.Float64s(values)

		percentiles := []float64{50, 90, 95, 99}
		for _, p := range percentiles {
			percentileValue := calculatePercentile(values, p)
			percentileKey := fmt.Sprintf("%s_p%g", key, p)
			
			result[percentileKey] = MetricValue{
				Value:     percentileValue,
				Labels:    data.Labels,
				Timestamp: now,
				Type:      "histogram_percentile",
			}
		}

		// Add count and average
		result[key+"_count"] = MetricValue{
			Value:     float64(len(values)),
			Labels:    data.Labels,
			Timestamp: now,
			Type:      "histogram_count",
		}

		avg := calculateAverage(values)
		result[key+"_avg"] = MetricValue{
			Value:     avg,
			Labels:    data.Labels,
			Timestamp: now,
			Type:      "histogram_average",
		}
	}

	return result, nil
}

// buildKey builds a unique key for a metric with labels
func (ha *HistogramAggregator) buildKey(metric string, labels map[string]string) string {
	key := metric
	for k, v := range labels {
		key += fmt.Sprintf(",%s=%s", k, v)
	}
	return key
}

// CounterAggregator aggregates counter metrics
type CounterAggregator struct {
	data  map[string]*CounterData
	mutex sync.RWMutex
}

// CounterData holds counter data for a metric
type CounterData struct {
	Value      float64
	Labels     map[string]string
	LastUpdate time.Time
}

// NewCounterAggregator creates a new counter aggregator
func NewCounterAggregator() *CounterAggregator {
	return &CounterAggregator{
		data: make(map[string]*CounterData),
	}
}

// Name returns the aggregator name
func (ca *CounterAggregator) Name() string {
	return "counter"
}

// Aggregate aggregates a counter metric
func (ca *CounterAggregator) Aggregate(metric string, value float64, labels map[string]string, timestamp time.Time) error {
	// Only aggregate counter metrics
	if !isCounterMetric(metric) {
		return nil
	}

	key := ca.buildKey(metric, labels)

	ca.mutex.Lock()
	defer ca.mutex.Unlock()

	if _, exists := ca.data[key]; !exists {
		ca.data[key] = &CounterData{
			Value:  0,
			Labels: labels,
		}
	}

	ca.data[key].Value += value
	ca.data[key].LastUpdate = timestamp

	return nil
}

// GetMetrics returns counter metrics
func (ca *CounterAggregator) GetMetrics(window time.Duration) (map[string]MetricValue, error) {
	ca.mutex.RLock()
	defer ca.mutex.RUnlock()

	result := make(map[string]MetricValue)
	now := time.Now()

	for key, data := range ca.data {
		// Only include recent data
		if now.Sub(data.LastUpdate) > window {
			continue
		}

		result[key] = MetricValue{
			Value:     data.Value,
			Labels:    data.Labels,
			Timestamp: now,
			Type:      "counter",
		}

		// Calculate rate (per second)
		if window.Seconds() > 0 {
			rate := data.Value / window.Seconds()
			result[key+"_rate"] = MetricValue{
				Value:     rate,
				Labels:    data.Labels,
				Timestamp: now,
				Type:      "counter_rate",
			}
		}
	}

	return result, nil
}

// buildKey builds a unique key for a metric with labels
func (ca *CounterAggregator) buildKey(metric string, labels map[string]string) string {
	key := metric
	for k, v := range labels {
		key += fmt.Sprintf(",%s=%s", k, v)
	}
	return key
}

// Helper functions

// calculatePercentile calculates the percentile value from sorted data
func calculatePercentile(sortedValues []float64, percentile float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}

	if percentile <= 0 {
		return sortedValues[0]
	}
	if percentile >= 100 {
		return sortedValues[len(sortedValues)-1]
	}

	index := (percentile / 100.0) * float64(len(sortedValues)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sortedValues[lower]
	}

	// Linear interpolation
	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

// calculateAverage calculates the average of values
func calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// isCounterMetric checks if a metric is a counter type
func isCounterMetric(metric string) bool {
	counterMetrics := []string{
		"http_requests_total",
		"http_responses_total",
		"http_errors_total",
		"network_bytes_total",
		"network_connections_total",
		"network_accepts_total",
		"network_errors_total",
		"process_events_total",
		"error_events",
	}

	for _, counterMetric := range counterMetrics {
		if metric == counterMetric {
			return true
		}
	}
	return false
}
