package analytics

import (
	"sync"
	"time"
)

// MetricStore stores and manages metrics data
type MetricStore struct {
	data            map[string][]MetricValue
	retentionPeriod time.Duration
	mutex           sync.RWMutex
}

// NewMetricStore creates a new metric store
func NewMetricStore(retentionPeriod time.Duration) *MetricStore {
	return &MetricStore{
		data:            make(map[string][]MetricValue),
		retentionPeriod: retentionPeriod,
	}
}

// Store stores a metric value
func (ms *MetricStore) Store(name string, value MetricValue, timestamp time.Time) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if _, exists := ms.data[name]; !exists {
		ms.data[name] = make([]MetricValue, 0)
	}

	// Add timestamp to the metric value
	value.Timestamp = timestamp
	ms.data[name] = append(ms.data[name], value)

	// Clean old data
	ms.cleanOldData(name, timestamp.Add(-ms.retentionPeriod))
}

// GetCurrentMetrics returns the most recent metrics
func (ms *MetricStore) GetCurrentMetrics() map[string]MetricValue {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	result := make(map[string]MetricValue)
	for name, values := range ms.data {
		if len(values) > 0 {
			// Get the most recent value
			result[name] = values[len(values)-1]
		}
	}

	return result
}

// GetMetricHistory returns metric history for a time range
func (ms *MetricStore) GetMetricHistory(name string, start, end time.Time) []MetricValue {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	values, exists := ms.data[name]
	if !exists {
		return nil
	}

	var result []MetricValue
	for _, value := range values {
		if value.Timestamp.After(start) && value.Timestamp.Before(end) {
			result = append(result, value)
		}
	}

	return result
}

// GetMetricNames returns all metric names
func (ms *MetricStore) GetMetricNames() []string {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	names := make([]string, 0, len(ms.data))
	for name := range ms.data {
		names = append(names, name)
	}

	return names
}

// cleanOldData removes data older than the cutoff time
func (ms *MetricStore) cleanOldData(name string, cutoff time.Time) {
	values := ms.data[name]
	var newValues []MetricValue

	for _, value := range values {
		if value.Timestamp.After(cutoff) {
			newValues = append(newValues, value)
		}
	}

	ms.data[name] = newValues
}

// GetStats returns statistics about the metric store
func (ms *MetricStore) GetStats() map[string]interface{} {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	totalPoints := 0
	for _, values := range ms.data {
		totalPoints += len(values)
	}

	return map[string]interface{}{
		"total_metrics":     len(ms.data),
		"total_data_points": totalPoints,
		"retention_period":  ms.retentionPeriod.String(),
	}
}

// AlertManager manages alerting rules and notifications
type AlertManager struct {
	rules         []AlertRuleConfig
	activeAlerts  map[string]*ActiveAlert
	alertHistory  []AlertEvent
	mutex         sync.RWMutex
}

// ActiveAlert represents an active alert
type ActiveAlert struct {
	Rule        AlertRuleConfig
	StartTime   time.Time
	LastUpdate  time.Time
	Value       float64
	Status      string // firing, resolved
}

// AlertEvent represents an alert event
type AlertEvent struct {
	RuleName    string            `json:"rule_name"`
	Status      string            `json:"status"` // firing, resolved
	Timestamp   time.Time         `json:"timestamp"`
	Value       float64           `json:"value"`
	Threshold   float64           `json:"threshold"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(rules []AlertRuleConfig) *AlertManager {
	return &AlertManager{
		rules:        rules,
		activeAlerts: make(map[string]*ActiveAlert),
		alertHistory: make([]AlertEvent, 0),
	}
}

// Evaluate evaluates alert rules against current metrics
func (am *AlertManager) Evaluate(metrics map[string]MetricValue) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	now := time.Now()

	for _, rule := range am.rules {
		am.evaluateRule(rule, metrics, now)
	}
}

// evaluateRule evaluates a single alert rule
func (am *AlertManager) evaluateRule(rule AlertRuleConfig, metrics map[string]MetricValue, timestamp time.Time) {
	// Find the metric for this rule
	var metricValue *MetricValue
	for name, value := range metrics {
		if name == rule.Metric {
			metricValue = &value
			break
		}
	}

	if metricValue == nil {
		return // Metric not found
	}

	// Check if the condition is met
	conditionMet := am.checkCondition(rule.Condition, metricValue.Value, rule.Threshold)
	alertKey := rule.Name

	activeAlert, exists := am.activeAlerts[alertKey]

	if conditionMet {
		if !exists {
			// New alert
			am.activeAlerts[alertKey] = &ActiveAlert{
				Rule:       rule,
				StartTime:  timestamp,
				LastUpdate: timestamp,
				Value:      metricValue.Value,
				Status:     "firing",
			}

			// Create alert event
			event := AlertEvent{
				RuleName:    rule.Name,
				Status:      "firing",
				Timestamp:   timestamp,
				Value:       metricValue.Value,
				Threshold:   rule.Threshold,
				Labels:      rule.Labels,
				Annotations: rule.Annotations,
			}
			am.alertHistory = append(am.alertHistory, event)

		} else {
			// Update existing alert
			activeAlert.LastUpdate = timestamp
			activeAlert.Value = metricValue.Value
		}
	} else {
		if exists && activeAlert.Status == "firing" {
			// Resolve alert
			activeAlert.Status = "resolved"
			activeAlert.LastUpdate = timestamp

			// Create resolved event
			event := AlertEvent{
				RuleName:    rule.Name,
				Status:      "resolved",
				Timestamp:   timestamp,
				Value:       metricValue.Value,
				Threshold:   rule.Threshold,
				Labels:      rule.Labels,
				Annotations: rule.Annotations,
			}
			am.alertHistory = append(am.alertHistory, event)

			// Remove from active alerts
			delete(am.activeAlerts, alertKey)
		}
	}
}

// checkCondition checks if a condition is met
func (am *AlertManager) checkCondition(condition string, value, threshold float64) bool {
	switch condition {
	case "gt":
		return value > threshold
	case "lt":
		return value < threshold
	case "eq":
		return value == threshold
	case "ne":
		return value != threshold
	case "gte":
		return value >= threshold
	case "lte":
		return value <= threshold
	default:
		return false
	}
}

// GetActiveAlerts returns currently active alerts
func (am *AlertManager) GetActiveAlerts() map[string]*ActiveAlert {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	result := make(map[string]*ActiveAlert)
	for k, v := range am.activeAlerts {
		result[k] = v
	}
	return result
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []AlertEvent {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	// Return the most recent alerts
	start := len(am.alertHistory) - limit
	result := make([]AlertEvent, limit)
	copy(result, am.alertHistory[start:])

	return result
}

// GetAlertStats returns alert statistics
func (am *AlertManager) GetAlertStats() map[string]interface{} {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	firingCount := 0
	for _, alert := range am.activeAlerts {
		if alert.Status == "firing" {
			firingCount++
		}
	}

	return map[string]interface{}{
		"total_rules":     len(am.rules),
		"active_alerts":   len(am.activeAlerts),
		"firing_alerts":   firingCount,
		"total_events":    len(am.alertHistory),
	}
}
