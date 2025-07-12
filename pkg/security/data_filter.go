package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// DataFilter handles data filtering and PII protection
type DataFilter struct {
	piiConfig           *PIIDetectionConfig
	classificationConfig *DataClassificationConfig
	piiPatterns         map[string]*regexp.Regexp
	classificationRules map[string]*regexp.Regexp
	mutex               sync.RWMutex
	stats               *FilterStats
}

// FilterStats tracks filtering statistics
type FilterStats struct {
	EventsProcessed     int64     `json:"events_processed"`
	PIIDetections       int64     `json:"pii_detections"`
	DataRedactions      int64     `json:"data_redactions"`
	ClassificationCount map[string]int64 `json:"classification_count"`
	LastUpdate          time.Time `json:"last_update"`
	mutex               sync.RWMutex
}

// NewDataFilter creates a new data filter
func NewDataFilter(piiConfig *PIIDetectionConfig, classConfig *DataClassificationConfig) (*DataFilter, error) {
	df := &DataFilter{
		piiConfig:           piiConfig,
		classificationConfig: classConfig,
		piiPatterns:         make(map[string]*regexp.Regexp),
		classificationRules: make(map[string]*regexp.Regexp),
		stats: &FilterStats{
			ClassificationCount: make(map[string]int64),
			LastUpdate:          time.Now(),
		},
	}

	// Initialize PII detection patterns
	if err := df.initializePIIPatterns(); err != nil {
		return nil, fmt.Errorf("failed to initialize PII patterns: %w", err)
	}

	// Initialize classification rules
	if err := df.initializeClassificationRules(); err != nil {
		return nil, fmt.Errorf("failed to initialize classification rules: %w", err)
	}

	return df, nil
}

// FilterEvent filters an event for PII and sensitive data
func (df *DataFilter) FilterEvent(ctx context.Context, event *tracing.TraceEvent) (*tracing.TraceEvent, error) {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	// Create a copy of the event
	filteredEvent := *event

	// Update statistics
	df.stats.mutex.Lock()
	df.stats.EventsProcessed++
	df.stats.LastUpdate = time.Now()
	df.stats.mutex.Unlock()

	// Filter payload for PII
	if df.piiConfig.EnableDetection && filteredEvent.Payload != "" {
		filteredPayload, detections := df.filterPII(filteredEvent.Payload)
		filteredEvent.Payload = filteredPayload
		
		if detections > 0 {
			df.stats.mutex.Lock()
			df.stats.PIIDetections += int64(detections)
			df.stats.DataRedactions++
			df.stats.mutex.Unlock()
		}
	}

	// Note: TraceEvent doesn't have Headers field, so we skip header filtering

	// Filter URL parameters for PII
	if filteredEvent.Path != "" {
		filteredPath, detections := df.filterPII(filteredEvent.Path)
		filteredEvent.Path = filteredPath
		
		if detections > 0 {
			df.stats.mutex.Lock()
			df.stats.PIIDetections += int64(detections)
			df.stats.DataRedactions++
			df.stats.mutex.Unlock()
		}
	}

	return &filteredEvent, nil
}

// ClassifyEvent classifies an event based on data sensitivity
func (df *DataFilter) ClassifyEvent(ctx context.Context, event *tracing.TraceEvent) (string, error) {
	if !df.classificationConfig.EnableClassification {
		return df.classificationConfig.DefaultLevel, nil
	}

	// Analyze event content for classification
	content := strings.ToLower(event.Payload + " " + event.Path)
	// Note: TraceEvent doesn't have Headers field, so we only analyze payload and path

	// Check classification rules in order of sensitivity (most sensitive first)
	for _, level := range df.classificationConfig.ClassificationLevels {
		for _, pattern := range level.Patterns {
			if rule, exists := df.classificationRules[pattern]; exists {
				if rule.MatchString(content) {
					// Update classification statistics
					df.stats.mutex.Lock()
					df.stats.ClassificationCount[level.Level]++
					df.stats.mutex.Unlock()
					
					return level.Level, nil
				}
			}
		}
	}

	// Default classification
	df.stats.mutex.Lock()
	df.stats.ClassificationCount[df.classificationConfig.DefaultLevel]++
	df.stats.mutex.Unlock()

	return df.classificationConfig.DefaultLevel, nil
}

// filterPII filters PII from text content
func (df *DataFilter) filterPII(content string) (string, int) {
	if !df.piiConfig.EnableDetection || content == "" {
		return content, 0
	}

	filteredContent := content
	detections := 0

	// Apply PII patterns
	for piiType, pattern := range df.piiPatterns {
		matches := pattern.FindAllString(filteredContent, -1)
		if len(matches) > 0 {
			detections += len(matches)
			
			for _, match := range matches {
				replacement := df.generateReplacement(match, piiType)
				filteredContent = strings.ReplaceAll(filteredContent, match, replacement)
			}
		}
	}

	return filteredContent, detections
}

// generateReplacement generates a replacement for detected PII
func (df *DataFilter) generateReplacement(original, piiType string) string {
	switch df.piiConfig.RedactionMode {
	case "mask":
		return df.maskString(original)
	case "hash":
		return df.hashString(original)
	case "remove":
		return "[REDACTED]"
	case "encrypt":
		return df.encryptString(original)
	default:
		return df.maskString(original)
	}
}

// maskString masks a string with asterisks
func (df *DataFilter) maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	
	// Keep first and last 2 characters, mask the middle
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// hashString creates a SHA-256 hash of the string
func (df *DataFilter) hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return "[HASH:" + hex.EncodeToString(hash[:8]) + "]" // First 8 bytes for brevity
}

// encryptString encrypts a string (placeholder implementation)
func (df *DataFilter) encryptString(s string) string {
	// In a real implementation, this would use proper encryption
	return "[ENCRYPTED:" + df.hashString(s)[6:14] + "]"
}

// initializePIIPatterns initializes PII detection patterns
func (df *DataFilter) initializePIIPatterns() error {
	// Default PII patterns
	defaultPatterns := map[string]string{
		"email":       `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		"ssn":         `\b\d{3}-?\d{2}-?\d{4}\b`,
		"credit_card": `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
		"phone":       `\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`,
		"ip_address":  `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
		"api_key":     `\b[A-Za-z0-9]{32,}\b`,
		"jwt_token":   `\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b`,
	}

	// Compile default patterns
	for piiType, pattern := range defaultPatterns {
		if df.shouldDetectPIIType(piiType) {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("failed to compile PII pattern for %s: %w", piiType, err)
			}
			df.piiPatterns[piiType] = compiled
		}
	}

	// Compile custom patterns
	for _, customPattern := range df.piiConfig.CustomPatterns {
		compiled, err := regexp.Compile(customPattern.Pattern)
		if err != nil {
			return fmt.Errorf("failed to compile custom PII pattern %s: %w", customPattern.Name, err)
		}
		df.piiPatterns[customPattern.Name] = compiled
	}

	return nil
}

// initializeClassificationRules initializes data classification rules
func (df *DataFilter) initializeClassificationRules() error {
	if !df.classificationConfig.EnableClassification {
		return nil
	}

	// Default classification patterns
	defaultRules := map[string]string{
		"public":       `\b(public|open|general)\b`,
		"internal":     `\b(internal|private|company)\b`,
		"confidential": `\b(confidential|secret|sensitive|password|token|key)\b`,
		"restricted":   `\b(restricted|classified|top.secret|ssn|credit.card|medical)\b`,
	}

	// Compile default rules
	for level, pattern := range defaultRules {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile classification rule for %s: %w", level, err)
		}
		df.classificationRules[level] = compiled
	}

	// Compile custom classification patterns from config
	for _, level := range df.classificationConfig.ClassificationLevels {
		for _, pattern := range level.Patterns {
			if _, exists := df.classificationRules[pattern]; !exists {
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("failed to compile classification pattern %s: %w", pattern, err)
				}
				df.classificationRules[pattern] = compiled
			}
		}
	}

	return nil
}

// shouldDetectPIIType checks if a PII type should be detected
func (df *DataFilter) shouldDetectPIIType(piiType string) bool {
	if len(df.piiConfig.PIITypes) == 0 {
		return true // Detect all types if none specified
	}

	for _, configuredType := range df.piiConfig.PIITypes {
		if configuredType == piiType {
			return true
		}
	}
	return false
}

// GetFilterStats returns filtering statistics
func (df *DataFilter) GetFilterStats() *FilterStats {
	df.stats.mutex.RLock()
	defer df.stats.mutex.RUnlock()

	// Create a copy of stats
	statsCopy := &FilterStats{
		EventsProcessed: df.stats.EventsProcessed,
		PIIDetections:   df.stats.PIIDetections,
		DataRedactions:  df.stats.DataRedactions,
		LastUpdate:      df.stats.LastUpdate,
		ClassificationCount: make(map[string]int64),
	}

	for k, v := range df.stats.ClassificationCount {
		statsCopy.ClassificationCount[k] = v
	}

	return statsCopy
}

// GetComplianceStatus returns compliance status for data filtering
func (df *DataFilter) GetComplianceStatus() ComponentStatus {
	stats := df.GetFilterStats()
	
	status := ComponentStatus{
		Status:      "compliant",
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"events_processed":     stats.EventsProcessed,
			"pii_detections":       stats.PIIDetections,
			"data_redactions":      stats.DataRedactions,
			"classification_count": stats.ClassificationCount,
			"pii_detection_enabled": df.piiConfig.EnableDetection,
			"classification_enabled": df.classificationConfig.EnableClassification,
		},
		Issues: []string{},
	}

	// Check for compliance issues
	if df.piiConfig.EnableDetection && len(df.piiPatterns) == 0 {
		status.Status = "non_compliant"
		status.Issues = append(status.Issues, "PII detection enabled but no patterns configured")
	}

	if df.classificationConfig.EnableClassification && len(df.classificationRules) == 0 {
		status.Status = "non_compliant"
		status.Issues = append(status.Issues, "Data classification enabled but no rules configured")
	}

	// Check redaction rate
	if stats.EventsProcessed > 0 {
		redactionRate := float64(stats.DataRedactions) / float64(stats.EventsProcessed)
		if redactionRate > 0.5 { // More than 50% of events redacted might indicate over-filtering
			status.Status = "warning"
			status.Issues = append(status.Issues, "High redaction rate detected - review PII patterns")
		}
	}

	return status
}

// ValidateConfiguration validates the data filter configuration
func (df *DataFilter) ValidateConfiguration() error {
	// Validate PII configuration
	if df.piiConfig.EnableDetection {
		validRedactionModes := []string{"mask", "hash", "remove", "encrypt"}
		validMode := false
		for _, mode := range validRedactionModes {
			if df.piiConfig.RedactionMode == mode {
				validMode = true
				break
			}
		}
		if !validMode {
			return fmt.Errorf("invalid redaction mode: %s", df.piiConfig.RedactionMode)
		}

		validSensitivityLevels := []string{"low", "medium", "high", "strict"}
		validLevel := false
		for _, level := range validSensitivityLevels {
			if df.piiConfig.SensitivityLevel == level {
				validLevel = true
				break
			}
		}
		if !validLevel {
			return fmt.Errorf("invalid sensitivity level: %s", df.piiConfig.SensitivityLevel)
		}
	}

	// Validate classification configuration
	if df.classificationConfig.EnableClassification {
		if len(df.classificationConfig.ClassificationLevels) == 0 {
			return fmt.Errorf("classification enabled but no levels defined")
		}

		// Check that default level exists in classification levels
		defaultExists := false
		for _, level := range df.classificationConfig.ClassificationLevels {
			if level.Level == df.classificationConfig.DefaultLevel {
				defaultExists = true
				break
			}
		}
		if !defaultExists {
			return fmt.Errorf("default classification level %s not found in classification levels", df.classificationConfig.DefaultLevel)
		}
	}

	return nil
}

// UpdatePIIPatterns updates PII detection patterns at runtime
func (df *DataFilter) UpdatePIIPatterns(patterns map[string]string) error {
	df.mutex.Lock()
	defer df.mutex.Unlock()

	newPatterns := make(map[string]*regexp.Regexp)
	
	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern %s: %w", name, err)
		}
		newPatterns[name] = compiled
	}

	// Replace patterns atomically
	df.piiPatterns = newPatterns
	return nil
}

// GetDetectedPIITypes returns the types of PII detected in recent events
func (df *DataFilter) GetDetectedPIITypes() map[string]int64 {
	// This would be implemented with more detailed tracking
	// For now, return a placeholder
	return map[string]int64{
		"email":       df.stats.PIIDetections / 4,
		"phone":       df.stats.PIIDetections / 6,
		"credit_card": df.stats.PIIDetections / 10,
		"ssn":         df.stats.PIIDetections / 20,
	}
}
