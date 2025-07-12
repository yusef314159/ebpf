package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
	"github.com/robfig/cron/v3"
)

// RetentionManager manages data retention policies
type RetentionManager struct {
	config    *RetentionConfig
	scheduler *cron.Cron
	stats     *RetentionStats
	mutex     sync.RWMutex
}

// RetentionStats tracks retention management statistics
type RetentionStats struct {
	EventsProcessed    int64     `json:"events_processed"`
	EventsPurged       int64     `json:"events_purged"`
	EventsArchived     int64     `json:"events_archived"`
	LastPurgeRun       time.Time `json:"last_purge_run"`
	LastArchiveRun     time.Time `json:"last_archive_run"`
	StorageUsed        int64     `json:"storage_used"`
	StorageReclaimed   int64     `json:"storage_reclaimed"`
	PurgeErrors        int64     `json:"purge_errors"`
	ArchiveErrors      int64     `json:"archive_errors"`
	mutex              sync.RWMutex
}

// RetentionPolicy represents a data retention policy
type RetentionPolicy struct {
	DataType        string        `json:"data_type"`
	RetentionPeriod time.Duration `json:"retention_period"`
	ArchiveBeforePurge bool       `json:"archive_before_purge"`
	ArchiveLocation string        `json:"archive_location"`
	PurgeConditions []string      `json:"purge_conditions"`
}

// DataRecord represents a data record with retention metadata
type DataRecord struct {
	ID          string                 `json:"id"`
	DataType    string                 `json:"data_type"`
	CreatedAt   time.Time              `json:"created_at"`
	LastAccessed time.Time             `json:"last_accessed"`
	Size        int64                  `json:"size"`
	Metadata    map[string]interface{} `json:"metadata"`
	RetentionPolicy *RetentionPolicy   `json:"retention_policy"`
}

// PurgeResult represents the result of a purge operation
type PurgeResult struct {
	Timestamp       time.Time `json:"timestamp"`
	RecordsProcessed int64     `json:"records_processed"`
	RecordsPurged   int64     `json:"records_purged"`
	RecordsArchived int64     `json:"records_archived"`
	StorageReclaimed int64     `json:"storage_reclaimed"`
	Errors          []string  `json:"errors"`
	Duration        time.Duration `json:"duration"`
}

// NewRetentionManager creates a new retention manager
func NewRetentionManager(config *RetentionConfig) (*RetentionManager, error) {
	rm := &RetentionManager{
		config: config,
		stats: &RetentionStats{
			LastPurgeRun:   time.Now(),
			LastArchiveRun: time.Now(),
		},
	}

	// Initialize cron scheduler if auto-purge is enabled
	if config.AutoPurge && config.PurgeSchedule != "" {
		rm.scheduler = cron.New()
		
		_, err := rm.scheduler.AddFunc(config.PurgeSchedule, func() {
			if err := rm.RunPurge(context.Background()); err != nil {
				fmt.Printf("Scheduled purge failed: %v\n", err)
			}
		})
		if err != nil {
			return nil, fmt.Errorf("failed to schedule purge job: %w", err)
		}
		
		rm.scheduler.Start()
	}

	// Create archive directory if needed
	if config.ArchiveBeforePurge && config.ArchiveLocation != "" {
		if err := os.MkdirAll(config.ArchiveLocation, 0750); err != nil {
			return nil, fmt.Errorf("failed to create archive directory: %w", err)
		}
	}

	return rm, nil
}

// ApplyRetentionPolicy applies retention policy to an event
func (rm *RetentionManager) ApplyRetentionPolicy(ctx context.Context, event *tracing.TraceEvent) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// Update statistics
	rm.stats.mutex.Lock()
	rm.stats.EventsProcessed++
	rm.stats.mutex.Unlock()

	// Determine data type
	dataType := rm.determineDataType(event)
	
	// Get retention period for this data type
	retentionPeriod := rm.getRetentionPeriod(dataType)
	
	// Add retention information to payload as comment (since TraceEvent doesn't have Metadata field)
	if event.Payload != "" {
		purgeAfter := time.Now().Add(retentionPeriod).Format(time.RFC3339)
		event.Payload = fmt.Sprintf("%s [Retention: %s, PurgeAfter: %s]",
			event.Payload, dataType, purgeAfter)
	}
	
	return nil
}

// RunPurge runs the data purge process
func (rm *RetentionManager) RunPurge(ctx context.Context) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	startTime := time.Now()
	result := &PurgeResult{
		Timestamp: startTime,
		Errors:    []string{},
	}

	// Get all data records that need purging
	records, err := rm.getRecordsForPurge()
	if err != nil {
		return fmt.Errorf("failed to get records for purge: %w", err)
	}

	result.RecordsProcessed = int64(len(records))

	// Process each record
	for _, record := range records {
		if err := rm.processRecordForPurge(ctx, record, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to process record %s: %v", record.ID, err))
			rm.stats.mutex.Lock()
			rm.stats.PurgeErrors++
			rm.stats.mutex.Unlock()
		}
	}

	result.Duration = time.Since(startTime)

	// Update statistics
	rm.stats.mutex.Lock()
	rm.stats.EventsPurged += result.RecordsPurged
	rm.stats.EventsArchived += result.RecordsArchived
	rm.stats.StorageReclaimed += result.StorageReclaimed
	rm.stats.LastPurgeRun = startTime
	rm.stats.mutex.Unlock()

	return nil
}

// GetRetentionStats returns retention management statistics
func (rm *RetentionManager) GetRetentionStats() *RetentionStats {
	rm.stats.mutex.RLock()
	defer rm.stats.mutex.RUnlock()

	return &RetentionStats{
		EventsProcessed:  rm.stats.EventsProcessed,
		EventsPurged:     rm.stats.EventsPurged,
		EventsArchived:   rm.stats.EventsArchived,
		LastPurgeRun:     rm.stats.LastPurgeRun,
		LastArchiveRun:   rm.stats.LastArchiveRun,
		StorageUsed:      rm.stats.StorageUsed,
		StorageReclaimed: rm.stats.StorageReclaimed,
		PurgeErrors:      rm.stats.PurgeErrors,
		ArchiveErrors:    rm.stats.ArchiveErrors,
	}
}

// GetComplianceStatus returns compliance status for retention management
func (rm *RetentionManager) GetComplianceStatus() ComponentStatus {
	stats := rm.GetRetentionStats()
	
	status := ComponentStatus{
		Status:      "compliant",
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"events_processed":    stats.EventsProcessed,
			"events_purged":       stats.EventsPurged,
			"events_archived":     stats.EventsArchived,
			"storage_used":        stats.StorageUsed,
			"storage_reclaimed":   stats.StorageReclaimed,
			"auto_purge_enabled":  rm.config.AutoPurge,
			"archive_enabled":     rm.config.ArchiveBeforePurge,
			"default_retention":   rm.config.DefaultRetention.String(),
		},
		Issues: []string{},
	}

	// Check for compliance issues
	if stats.PurgeErrors > 0 {
		errorRate := float64(stats.PurgeErrors) / float64(stats.EventsProcessed)
		if errorRate > 0.01 { // More than 1% error rate
			status.Status = "warning"
			status.Issues = append(status.Issues, "High purge error rate detected")
		}
	}

	if stats.ArchiveErrors > 0 {
		errorRate := float64(stats.ArchiveErrors) / float64(stats.EventsArchived)
		if errorRate > 0.01 { // More than 1% error rate
			status.Status = "warning"
			status.Issues = append(status.Issues, "High archive error rate detected")
		}
	}

	// Check if purge is running on schedule
	if rm.config.AutoPurge {
		timeSinceLastPurge := time.Since(stats.LastPurgeRun)
		if timeSinceLastPurge > 48*time.Hour { // More than 48 hours since last purge
			status.Status = "warning"
			status.Issues = append(status.Issues, "Purge job may not be running on schedule")
		}
	}

	// Check storage usage
	if stats.StorageUsed > 0 {
		// If storage usage is growing without purging, it might indicate a problem
		if stats.EventsPurged == 0 && stats.EventsProcessed > 1000 {
			status.Status = "warning"
			status.Issues = append(status.Issues, "No data has been purged despite processing many events")
		}
	}

	return status
}

// GetRetentionPolicies returns all configured retention policies
func (rm *RetentionManager) GetRetentionPolicies() map[string]RetentionPolicy {
	policies := make(map[string]RetentionPolicy)
	
	// Add default policy
	policies["default"] = RetentionPolicy{
		DataType:           "default",
		RetentionPeriod:    rm.config.DefaultRetention,
		ArchiveBeforePurge: rm.config.ArchiveBeforePurge,
		ArchiveLocation:    rm.config.ArchiveLocation,
	}
	
	// Add specific data type policies
	for dataType, retention := range rm.config.DataTypeRetention {
		policies[dataType] = RetentionPolicy{
			DataType:           dataType,
			RetentionPeriod:    retention,
			ArchiveBeforePurge: rm.config.ArchiveBeforePurge,
			ArchiveLocation:    rm.config.ArchiveLocation,
		}
	}
	
	return policies
}

// UpdateRetentionPolicy updates a retention policy
func (rm *RetentionManager) UpdateRetentionPolicy(dataType string, retention time.Duration) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.config.DataTypeRetention == nil {
		rm.config.DataTypeRetention = make(map[string]time.Duration)
	}
	
	rm.config.DataTypeRetention[dataType] = retention
	return nil
}

// Helper methods

func (rm *RetentionManager) determineDataType(event *tracing.TraceEvent) string {
	// Determine data type based on event characteristics
	if event.EventType == "read" || event.EventType == "write" {
		if event.Method != "" {
			return "http_request"
		}
		return "network_event"
	}
	
	if event.EventType == "error" {
		return "error_event"
	}
	
	if event.EventType == "accept" || event.EventType == "connect" {
		return "connection_event"
	}
	
	return "general_event"
}

func (rm *RetentionManager) getRetentionPeriod(dataType string) time.Duration {
	if retention, exists := rm.config.DataTypeRetention[dataType]; exists {
		return retention
	}
	return rm.config.DefaultRetention
}

func (rm *RetentionManager) getRecordsForPurge() ([]*DataRecord, error) {
	// This is a placeholder implementation
	// In a real system, this would query the data store for records
	// that have exceeded their retention period
	
	var records []*DataRecord
	
	// For demonstration, create some sample records that need purging
	cutoffTime := time.Now().Add(-rm.config.DefaultRetention)
	
	// In practice, this would query actual data storage
	for i := 0; i < 10; i++ {
		if time.Now().Add(-time.Duration(i)*24*time.Hour).Before(cutoffTime) {
			record := &DataRecord{
				ID:           fmt.Sprintf("record_%d", i),
				DataType:     "http_request",
				CreatedAt:    time.Now().Add(-time.Duration(i) * 24 * time.Hour),
				LastAccessed: time.Now().Add(-time.Duration(i) * 12 * time.Hour),
				Size:         1024 * int64(i+1),
				Metadata:     make(map[string]interface{}),
			}
			records = append(records, record)
		}
	}
	
	return records, nil
}

func (rm *RetentionManager) processRecordForPurge(ctx context.Context, record *DataRecord, result *PurgeResult) error {
	// Archive before purge if configured
	if rm.config.ArchiveBeforePurge {
		if err := rm.archiveRecord(ctx, record); err != nil {
			rm.stats.mutex.Lock()
			rm.stats.ArchiveErrors++
			rm.stats.mutex.Unlock()
			return fmt.Errorf("failed to archive record: %w", err)
		}
		result.RecordsArchived++
	}
	
	// Purge the record
	if err := rm.purgeRecord(ctx, record); err != nil {
		return fmt.Errorf("failed to purge record: %w", err)
	}
	
	result.RecordsPurged++
	result.StorageReclaimed += record.Size
	
	return nil
}

func (rm *RetentionManager) archiveRecord(ctx context.Context, record *DataRecord) error {
	if rm.config.ArchiveLocation == "" {
		return fmt.Errorf("archive location not configured")
	}
	
	// Create archive file path
	archiveDir := filepath.Join(rm.config.ArchiveLocation, record.DataType)
	if err := os.MkdirAll(archiveDir, 0750); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}
	
	archiveFile := filepath.Join(archiveDir, fmt.Sprintf("%s_%s.json", 
		record.ID, record.CreatedAt.Format("20060102")))
	
	// In a real implementation, this would serialize and write the record
	// For now, just create an empty file to simulate archiving
	file, err := os.Create(archiveFile)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	defer file.Close()
	
	// Write record metadata (simplified)
	fmt.Fprintf(file, "Record ID: %s\nData Type: %s\nCreated: %s\nSize: %d bytes\n",
		record.ID, record.DataType, record.CreatedAt.Format(time.RFC3339), record.Size)
	
	return nil
}

func (rm *RetentionManager) purgeRecord(ctx context.Context, record *DataRecord) error {
	// In a real implementation, this would delete the record from the data store
	// For now, just simulate the purge operation
	
	// Simulate some processing time
	time.Sleep(1 * time.Millisecond)
	
	return nil
}

// Stop stops the retention manager
func (rm *RetentionManager) Stop() {
	if rm.scheduler != nil {
		rm.scheduler.Stop()
	}
}

// ValidateConfiguration validates the retention configuration
func (rm *RetentionManager) ValidateConfiguration() error {
	if rm.config.DefaultRetention <= 0 {
		return fmt.Errorf("default retention period must be positive")
	}
	
	for dataType, retention := range rm.config.DataTypeRetention {
		if retention <= 0 {
			return fmt.Errorf("retention period for data type %s must be positive", dataType)
		}
	}
	
	if rm.config.AutoPurge && rm.config.PurgeSchedule == "" {
		return fmt.Errorf("purge schedule must be specified when auto-purge is enabled")
	}
	
	if rm.config.ArchiveBeforePurge && rm.config.ArchiveLocation == "" {
		return fmt.Errorf("archive location must be specified when archive-before-purge is enabled")
	}
	
	return nil
}

// GetDataTypeRetention returns retention period for a specific data type
func (rm *RetentionManager) GetDataTypeRetention(dataType string) time.Duration {
	if retention, exists := rm.config.DataTypeRetention[dataType]; exists {
		return retention
	}
	return rm.config.DefaultRetention
}

// GetStorageUsage returns current storage usage information
func (rm *RetentionManager) GetStorageUsage() map[string]interface{} {
	stats := rm.GetRetentionStats()
	
	return map[string]interface{}{
		"total_storage_used":    stats.StorageUsed,
		"storage_reclaimed":     stats.StorageReclaimed,
		"events_processed":      stats.EventsProcessed,
		"events_purged":         stats.EventsPurged,
		"events_archived":       stats.EventsArchived,
		"purge_efficiency":      rm.calculatePurgeEfficiency(),
		"archive_location":      rm.config.ArchiveLocation,
		"auto_purge_enabled":    rm.config.AutoPurge,
	}
}

func (rm *RetentionManager) calculatePurgeEfficiency() float64 {
	stats := rm.GetRetentionStats()
	if stats.EventsProcessed == 0 {
		return 0.0
	}
	return float64(stats.EventsPurged) / float64(stats.EventsProcessed)
}
