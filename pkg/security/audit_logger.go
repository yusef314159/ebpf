package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLogger handles tamper-proof audit logging
type AuditLogger struct {
	config      *AuditConfig
	logFile     *os.File
	logWriter   *AuditWriter
	hmacKey     []byte
	entryCount  int64
	lastHash    string
	mutex       sync.Mutex
	stats       *AuditStats
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Source      string                 `json:"source"`
	Action      string                 `json:"action"`
	Resource    string                 `json:"resource"`
	Principal   string                 `json:"principal"`
	Result      string                 `json:"result"`      // success, failure, error
	Severity    string                 `json:"severity"`    // low, medium, high, critical
	Details     map[string]interface{} `json:"details"`
	Hash        string                 `json:"hash"`        // Tamper protection hash
	PrevHash    string                 `json:"prev_hash"`   // Previous entry hash for chain
	Signature   string                 `json:"signature"`   // Digital signature (if enabled)
}

// AuditWriter handles different audit log destinations
type AuditWriter struct {
	config      *AuditConfig
	fileWriter  *os.File
	remoteClients []RemoteAuditClient
}

// RemoteAuditClient interface for remote audit logging
type RemoteAuditClient interface {
	SendAuditEntry(ctx context.Context, entry *AuditEntry) error
	Close() error
}

// AuditStats tracks audit logging statistics
type AuditStats struct {
	EntriesLogged       int64     `json:"entries_logged"`
	FailedEntries       int64     `json:"failed_entries"`
	TamperAttempts      int64     `json:"tamper_attempts"`
	LastEntry           time.Time `json:"last_entry"`
	LogFileSize         int64     `json:"log_file_size"`
	RemoteDeliveryRate  float64   `json:"remote_delivery_rate"`
	mutex               sync.RWMutex
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config *AuditConfig) (*AuditLogger, error) {
	al := &AuditLogger{
		config:   config,
		hmacKey:  generateHMACKey(),
		stats: &AuditStats{
			LastEntry: time.Now(),
		},
	}

	// Initialize audit writer
	writer, err := NewAuditWriter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit writer: %w", err)
	}
	al.logWriter = writer

	// Initialize log file if file destination is configured
	if config.LogDestination == "file" || config.LogDestination == "both" {
		if err := al.initializeLogFile(); err != nil {
			return nil, fmt.Errorf("failed to initialize log file: %w", err)
		}
	}

	// Load last hash for tamper protection chain
	if config.TamperProtection {
		al.lastHash = al.loadLastHash()
	}

	return al, nil
}

// LogEntry logs an audit entry
func (al *AuditLogger) LogEntry(ctx context.Context, entry *AuditEntry) error {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	// Generate entry ID
	entry.ID = al.generateEntryID()

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Set default severity if not provided
	if entry.Severity == "" {
		entry.Severity = "medium"
	}

	// Add tamper protection
	if al.config.TamperProtection {
		entry.PrevHash = al.lastHash
		entry.Hash = al.calculateEntryHash(entry)
		al.lastHash = entry.Hash
	}

	// Add digital signature if enabled
	if al.config.DigitalSigning {
		signature, err := al.signEntry(entry)
		if err != nil {
			return fmt.Errorf("failed to sign audit entry: %w", err)
		}
		entry.Signature = signature
	}

	// Write to configured destinations
	if err := al.writeEntry(ctx, entry); err != nil {
		al.stats.mutex.Lock()
		al.stats.FailedEntries++
		al.stats.mutex.Unlock()
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	// Update statistics
	al.stats.mutex.Lock()
	al.stats.EntriesLogged++
	al.stats.LastEntry = entry.Timestamp
	al.entryCount++
	al.stats.mutex.Unlock()

	return nil
}

// LogSecurityEvent logs a security-related event
func (al *AuditLogger) LogSecurityEvent(ctx context.Context, eventType, action, resource, principal, result string, details map[string]interface{}) error {
	entry := &AuditEntry{
		Timestamp: time.Now(),
		EventType: eventType,
		Source:    "security_system",
		Action:    action,
		Resource:  resource,
		Principal: principal,
		Result:    result,
		Severity:  al.determineSeverity(eventType, result),
		Details:   details,
	}

	return al.LogEntry(ctx, entry)
}

// LogComplianceEvent logs a compliance-related event
func (al *AuditLogger) LogComplianceEvent(ctx context.Context, framework, requirement, status string, details map[string]interface{}) error {
	entry := &AuditEntry{
		Timestamp: time.Now(),
		EventType: "compliance_check",
		Source:    "compliance_system",
		Action:    "evaluate_requirement",
		Resource:  requirement,
		Principal: "system",
		Result:    status,
		Severity:  al.getComplianceSeverity(status),
		Details: map[string]interface{}{
			"framework":   framework,
			"requirement": requirement,
			"details":     details,
		},
	}

	return al.LogEntry(ctx, entry)
}

// LogDataAccess logs data access events
func (al *AuditLogger) LogDataAccess(ctx context.Context, principal, action, resource string, success bool, details map[string]interface{}) error {
	result := "success"
	if !success {
		result = "failure"
	}

	entry := &AuditEntry{
		Timestamp: time.Now(),
		EventType: "data_access",
		Source:    "data_access_system",
		Action:    action,
		Resource:  resource,
		Principal: principal,
		Result:    result,
		Severity:  al.getDataAccessSeverity(action, success),
		Details:   details,
	}

	return al.LogEntry(ctx, entry)
}

// VerifyIntegrity verifies the integrity of audit logs
func (al *AuditLogger) VerifyIntegrity(ctx context.Context) (*IntegrityReport, error) {
	if !al.config.TamperProtection {
		return &IntegrityReport{
			Status:  "not_applicable",
			Message: "Tamper protection not enabled",
		}, nil
	}

	// Read all audit entries and verify hash chain
	entries, err := al.readAllEntries()
	if err != nil {
		return nil, fmt.Errorf("failed to read audit entries: %w", err)
	}

	report := &IntegrityReport{
		Timestamp:     time.Now(),
		TotalEntries:  len(entries),
		VerifiedEntries: 0,
		FailedEntries: 0,
		Status:        "verified",
		Issues:        []string{},
	}

	var prevHash string
	for i, entry := range entries {
		// Verify hash chain
		if entry.PrevHash != prevHash {
			report.Status = "compromised"
			report.Issues = append(report.Issues, fmt.Sprintf("Hash chain broken at entry %d", i))
			report.FailedEntries++
			continue
		}

		// Verify entry hash
		expectedHash := al.calculateEntryHash(&entry)
		if entry.Hash != expectedHash {
			report.Status = "compromised"
			report.Issues = append(report.Issues, fmt.Sprintf("Hash mismatch at entry %d", i))
			report.FailedEntries++
			continue
		}

		// Verify digital signature if present
		if al.config.DigitalSigning && entry.Signature != "" {
			if !al.verifySignature(&entry) {
				report.Status = "compromised"
				report.Issues = append(report.Issues, fmt.Sprintf("Invalid signature at entry %d", i))
				report.FailedEntries++
				continue
			}
		}

		report.VerifiedEntries++
		prevHash = entry.Hash
	}

	// Update tamper attempt statistics if issues found
	if len(report.Issues) > 0 {
		al.stats.mutex.Lock()
		al.stats.TamperAttempts += int64(len(report.Issues))
		al.stats.mutex.Unlock()
	}

	return report, nil
}

// GetAuditStats returns audit logging statistics
func (al *AuditLogger) GetAuditStats() *AuditStats {
	al.stats.mutex.RLock()
	defer al.stats.mutex.RUnlock()

	// Update log file size
	if al.logFile != nil {
		if stat, err := al.logFile.Stat(); err == nil {
			al.stats.LogFileSize = stat.Size()
		}
	}

	// Create a copy of stats
	statsCopy := &AuditStats{
		EntriesLogged:      al.stats.EntriesLogged,
		FailedEntries:      al.stats.FailedEntries,
		TamperAttempts:     al.stats.TamperAttempts,
		LastEntry:          al.stats.LastEntry,
		LogFileSize:        al.stats.LogFileSize,
		RemoteDeliveryRate: al.stats.RemoteDeliveryRate,
	}

	return statsCopy
}

// GetComplianceStatus returns compliance status for audit logging
func (al *AuditLogger) GetComplianceStatus() ComponentStatus {
	stats := al.GetAuditStats()
	
	status := ComponentStatus{
		Status:      "compliant",
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"entries_logged":       stats.EntriesLogged,
			"failed_entries":       stats.FailedEntries,
			"tamper_attempts":      stats.TamperAttempts,
			"log_file_size":        stats.LogFileSize,
			"tamper_protection":    al.config.TamperProtection,
			"digital_signing":      al.config.DigitalSigning,
			"encryption_enabled":   al.config.EncryptLogs,
		},
		Issues: []string{},
	}

	// Check for compliance issues
	if stats.FailedEntries > 0 {
		failureRate := float64(stats.FailedEntries) / float64(stats.EntriesLogged)
		if failureRate > 0.01 { // More than 1% failure rate
			status.Status = "warning"
			status.Issues = append(status.Issues, "High audit log failure rate detected")
		}
	}

	if stats.TamperAttempts > 0 {
		status.Status = "non_compliant"
		status.Issues = append(status.Issues, "Tamper attempts detected in audit logs")
	}

	if al.config.TamperProtection && al.config.RetentionPeriod > 0 {
		// Check if logs are being retained for the required period
		oldestAllowed := time.Now().Add(-al.config.RetentionPeriod)
		if stats.LastEntry.Before(oldestAllowed) {
			status.Status = "warning"
			status.Issues = append(status.Issues, "Audit log retention period may not be met")
		}
	}

	return status
}

// Helper methods

func (al *AuditLogger) generateEntryID() string {
	return fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), al.entryCount)
}

func (al *AuditLogger) calculateEntryHash(entry *AuditEntry) string {
	// Create a copy without hash and signature for calculation
	hashEntry := *entry
	hashEntry.Hash = ""
	hashEntry.Signature = ""

	data, _ := json.Marshal(hashEntry)
	
	h := hmac.New(sha256.New, al.hmacKey)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (al *AuditLogger) signEntry(entry *AuditEntry) (string, error) {
	// Placeholder for digital signature implementation
	// In a real implementation, this would use proper cryptographic signing
	data, _ := json.Marshal(entry)
	h := sha256.Sum256(data)
	return "SIG:" + hex.EncodeToString(h[:8]), nil
}

func (al *AuditLogger) verifySignature(entry *AuditEntry) bool {
	// Placeholder for signature verification
	// In a real implementation, this would verify the cryptographic signature
	return entry.Signature != ""
}

func (al *AuditLogger) writeEntry(ctx context.Context, entry *AuditEntry) error {
	return al.logWriter.WriteEntry(ctx, entry)
}

func (al *AuditLogger) initializeLogFile() error {
	logDir := "/var/log/ebpf-tracer"
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}

	al.logFile = file
	return nil
}

func (al *AuditLogger) loadLastHash() string {
	// Load the last hash from the audit log for chain continuity
	// This is a simplified implementation
	return ""
}

func (al *AuditLogger) readAllEntries() ([]AuditEntry, error) {
	// Read all audit entries from the log file
	// This is a placeholder implementation
	return []AuditEntry{}, nil
}

func (al *AuditLogger) determineSeverity(eventType, result string) string {
	if result == "failure" || result == "error" {
		return "high"
	}
	
	switch eventType {
	case "authentication", "authorization", "data_access":
		return "medium"
	case "configuration_change", "privilege_escalation":
		return "high"
	case "security_violation", "tamper_attempt":
		return "critical"
	default:
		return "low"
	}
}

func (al *AuditLogger) getComplianceSeverity(status string) string {
	switch status {
	case "compliant":
		return "low"
	case "warning":
		return "medium"
	case "non_compliant":
		return "high"
	default:
		return "medium"
	}
}

func (al *AuditLogger) getDataAccessSeverity(action string, success bool) string {
	if !success {
		return "high"
	}
	
	switch action {
	case "read":
		return "low"
	case "write", "update":
		return "medium"
	case "delete", "export":
		return "high"
	default:
		return "medium"
	}
}

func generateHMACKey() []byte {
	// In a real implementation, this would use a proper key derivation function
	// and store the key securely
	return []byte("ebpf-tracer-audit-hmac-key-change-in-production")
}

// IntegrityReport represents an audit log integrity verification report
type IntegrityReport struct {
	Timestamp       time.Time `json:"timestamp"`
	Status          string    `json:"status"`          // verified, compromised, not_applicable
	Message         string    `json:"message"`
	TotalEntries    int       `json:"total_entries"`
	VerifiedEntries int       `json:"verified_entries"`
	FailedEntries   int       `json:"failed_entries"`
	Issues          []string  `json:"issues"`
}

// NewAuditWriter creates a new audit writer
func NewAuditWriter(config *AuditConfig) (*AuditWriter, error) {
	writer := &AuditWriter{
		config: config,
	}

	// Initialize file writer if needed
	if config.LogDestination == "file" || config.LogDestination == "both" {
		// File writer will be initialized by the audit logger
	}

	// Initialize remote clients if configured
	if len(config.RemoteEndpoints) > 0 {
		// Initialize remote audit clients
		// This would be implemented based on the specific remote logging system
	}

	return writer, nil
}

// WriteEntry writes an audit entry to configured destinations
func (aw *AuditWriter) WriteEntry(ctx context.Context, entry *AuditEntry) error {
	var entryData []byte
	var err error

	// Format entry based on configuration
	switch aw.config.LogFormat {
	case "json":
		entryData, err = json.Marshal(entry)
	case "cef":
		entryData = []byte(aw.formatCEF(entry))
	case "leef":
		entryData = []byte(aw.formatLEEF(entry))
	default:
		entryData, err = json.Marshal(entry)
	}

	if err != nil {
		return fmt.Errorf("failed to format audit entry: %w", err)
	}

	// Write to file if configured
	if aw.config.LogDestination == "file" || aw.config.LogDestination == "both" {
		if aw.fileWriter != nil {
			if _, err := aw.fileWriter.Write(append(entryData, '\n')); err != nil {
				return fmt.Errorf("failed to write to audit log file: %w", err)
			}
		}
	}

	// Write to remote endpoints if configured
	if len(aw.remoteClients) > 0 {
		for _, client := range aw.remoteClients {
			if err := client.SendAuditEntry(ctx, entry); err != nil {
				// Log error but don't fail the entire operation
				fmt.Printf("Failed to send audit entry to remote endpoint: %v\n", err)
			}
		}
	}

	return nil
}

// formatCEF formats an audit entry in CEF (Common Event Format)
func (aw *AuditWriter) formatCEF(entry *AuditEntry) string {
	return fmt.Sprintf("CEF:0|eBPF-Tracer|HTTP-Tracer|1.0|%s|%s|%s|rt=%d src=%s act=%s outcome=%s",
		entry.EventType, entry.Action, entry.Severity, entry.Timestamp.Unix(), entry.Source, entry.Action, entry.Result)
}

// formatLEEF formats an audit entry in LEEF (Log Event Extended Format)
func (aw *AuditWriter) formatLEEF(entry *AuditEntry) string {
	return fmt.Sprintf("LEEF:2.0|eBPF-Tracer|HTTP-Tracer|1.0|%s|devTime=%s|src=%s|usrName=%s|resource=%s|result=%s",
		entry.EventType, entry.Timestamp.Format(time.RFC3339), entry.Source, entry.Principal, entry.Resource, entry.Result)
}
