package security

import (
	"context"

	"fmt"
	"strings"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
)

// ComplianceManager manages security and compliance features
type ComplianceManager struct {
	config          *ComplianceConfig
	dataFilter      *DataFilter
	auditLogger     *AuditLogger
	encryptionMgr   *EncryptionManager
	accessControl   *AccessControl
	retentionMgr    *RetentionManager
	mutex           sync.RWMutex
}

// ComplianceConfig holds compliance configuration
type ComplianceConfig struct {
	// Data filtering and PII protection
	EnableDataFiltering    bool                    `json:"enable_data_filtering"`
	PIIDetection          PIIDetectionConfig      `json:"pii_detection"`
	DataClassification    DataClassificationConfig `json:"data_classification"`
	
	// Audit logging
	EnableAuditLogging    bool                    `json:"enable_audit_logging"`
	AuditConfig          AuditConfig             `json:"audit_config"`
	
	// Encryption
	EnableEncryption     bool                    `json:"enable_encryption"`
	EncryptionConfig     EncryptionConfig        `json:"encryption_config"`
	
	// Access control
	EnableAccessControl  bool                    `json:"enable_access_control"`
	AccessControlConfig  AccessControlConfig     `json:"access_control_config"`
	
	// Data retention
	EnableRetentionPolicy bool                   `json:"enable_retention_policy"`
	RetentionConfig      RetentionConfig         `json:"retention_config"`
	
	// Compliance frameworks
	ComplianceFrameworks []string                `json:"compliance_frameworks"` // GDPR, HIPAA, SOX, PCI-DSS
}

// PIIDetectionConfig configures PII detection and redaction
type PIIDetectionConfig struct {
	EnableDetection      bool     `json:"enable_detection"`
	RedactionMode       string   `json:"redaction_mode"`        // mask, hash, remove, encrypt
	PIITypes            []string `json:"pii_types"`             // email, ssn, credit_card, phone, etc.
	CustomPatterns      []PIIPattern `json:"custom_patterns"`
	SensitivityLevel    string   `json:"sensitivity_level"`     // low, medium, high, strict
}

// PIIPattern defines a custom PII detection pattern
type PIIPattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Type        string `json:"type"`
	Confidence  float64 `json:"confidence"`
	Description string `json:"description"`
}

// DataClassificationConfig configures data classification
type DataClassificationConfig struct {
	EnableClassification bool                    `json:"enable_classification"`
	ClassificationLevels []ClassificationLevel   `json:"classification_levels"`
	AutoClassification   bool                    `json:"auto_classification"`
	DefaultLevel        string                  `json:"default_level"`
}

// ClassificationLevel defines a data classification level
type ClassificationLevel struct {
	Level       string   `json:"level"`        // public, internal, confidential, restricted
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
	Actions     []string `json:"actions"`      // log, encrypt, restrict, audit
}

// AuditConfig configures audit logging
type AuditConfig struct {
	AuditLevel          string            `json:"audit_level"`           // basic, detailed, comprehensive
	LogDestination      string            `json:"log_destination"`       // file, syslog, database, remote
	LogFormat          string            `json:"log_format"`            // json, cef, leef
	IncludePayloads    bool              `json:"include_payloads"`
	TamperProtection   bool              `json:"tamper_protection"`
	DigitalSigning     bool              `json:"digital_signing"`
	RetentionPeriod    time.Duration     `json:"retention_period"`
	EncryptLogs        bool              `json:"encrypt_logs"`
	RemoteEndpoints    []string          `json:"remote_endpoints"`
}

// EncryptionConfig configures encryption settings
type EncryptionConfig struct {
	Algorithm          string `json:"algorithm"`           // AES-256-GCM, ChaCha20-Poly1305
	KeyRotationPeriod  time.Duration `json:"key_rotation_period"`
	KeyDerivation      string `json:"key_derivation"`      // PBKDF2, Argon2, scrypt
	EncryptInTransit   bool   `json:"encrypt_in_transit"`
	EncryptAtRest      bool   `json:"encrypt_at_rest"`
	KeyManagementURL   string `json:"key_management_url"`  // External KMS
}

// AccessControlConfig configures access control
type AccessControlConfig struct {
	AuthenticationMode string              `json:"authentication_mode"` // none, basic, oauth, mtls
	AuthorizationMode  string              `json:"authorization_mode"`  // rbac, abac, acl
	Roles             []Role              `json:"roles"`
	Policies          []AccessPolicy      `json:"policies"`
	SessionTimeout    time.Duration       `json:"session_timeout"`
	MaxSessions       int                 `json:"max_sessions"`
}

// Role defines an access control role
type Role struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Resources   []string `json:"resources"`
}

// AccessPolicy defines an access control policy
type AccessPolicy struct {
	Name        string            `json:"name"`
	Effect      string            `json:"effect"`      // allow, deny
	Actions     []string          `json:"actions"`
	Resources   []string          `json:"resources"`
	Conditions  map[string]string `json:"conditions"`
	Principal   string            `json:"principal"`
}

// RetentionConfig configures data retention policies
type RetentionConfig struct {
	DefaultRetention    time.Duration              `json:"default_retention"`
	DataTypeRetention   map[string]time.Duration   `json:"data_type_retention"`
	AutoPurge          bool                       `json:"auto_purge"`
	PurgeSchedule      string                     `json:"purge_schedule"`    // cron expression
	ArchiveBeforePurge bool                       `json:"archive_before_purge"`
	ArchiveLocation    string                     `json:"archive_location"`
}

// NewComplianceManager creates a new compliance manager
func NewComplianceManager(config *ComplianceConfig) (*ComplianceManager, error) {
	cm := &ComplianceManager{
		config: config,
	}

	// Initialize data filter
	if config.EnableDataFiltering {
		dataFilter, err := NewDataFilter(&config.PIIDetection, &config.DataClassification)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize data filter: %w", err)
		}
		cm.dataFilter = dataFilter
	}

	// Initialize audit logger
	if config.EnableAuditLogging {
		auditLogger, err := NewAuditLogger(&config.AuditConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
		}
		cm.auditLogger = auditLogger
	}

	// Initialize encryption manager
	if config.EnableEncryption {
		encryptionMgr, err := NewEncryptionManager(&config.EncryptionConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize encryption manager: %w", err)
		}
		cm.encryptionMgr = encryptionMgr
	}

	// Initialize access control
	if config.EnableAccessControl {
		accessControl, err := NewAccessControl(&config.AccessControlConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize access control: %w", err)
		}
		cm.accessControl = accessControl
	}

	// Initialize retention manager
	if config.EnableRetentionPolicy {
		retentionMgr, err := NewRetentionManager(&config.RetentionConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize retention manager: %w", err)
		}
		cm.retentionMgr = retentionMgr
	}

	return cm, nil
}

// ProcessEvent processes an event through the compliance pipeline
func (cm *ComplianceManager) ProcessEvent(ctx context.Context, event *tracing.TraceEvent) (*tracing.TraceEvent, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	// Create a copy of the event for processing
	processedEvent := *event

	// Step 1: Data filtering and PII protection
	if cm.dataFilter != nil {
		filteredEvent, err := cm.dataFilter.FilterEvent(ctx, &processedEvent)
		if err != nil {
			return nil, fmt.Errorf("data filtering failed: %w", err)
		}
		processedEvent = *filteredEvent
	}

	// Step 2: Data classification
	if cm.dataFilter != nil {
		classification, err := cm.dataFilter.ClassifyEvent(ctx, &processedEvent)
		if err != nil {
			return nil, fmt.Errorf("data classification failed: %w", err)
		}
		// Add classification to payload as comment (since TraceEvent doesn't have Metadata field)
		if processedEvent.Payload != "" {
			processedEvent.Payload = fmt.Sprintf("%s [Classification: %s]", processedEvent.Payload, classification)
		}
	}

	// Step 3: Encryption (if required by classification)
	if cm.encryptionMgr != nil && cm.shouldEncrypt(&processedEvent) {
		encryptedEvent, err := cm.encryptionMgr.EncryptEvent(ctx, &processedEvent)
		if err != nil {
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
		processedEvent = *encryptedEvent
	}

	// Step 4: Audit logging
	if cm.auditLogger != nil {
		auditEntry := &AuditEntry{
			Timestamp:    time.Now(),
			EventType:    "trace_event_processed",
			Source:       "compliance_manager",
			Action:       "process_event",
			Resource:     fmt.Sprintf("event_%d", event.RequestID),
			Principal:    "system",
			Result:       "success",
			Details:      map[string]interface{}{
				"original_size":  len(event.Payload),
				"processed_size": len(processedEvent.Payload),
				"classification": "processed", // Classification info is embedded in payload
			},
		}
		
		if err := cm.auditLogger.LogEntry(ctx, auditEntry); err != nil {
			// Log audit failure but don't fail the event processing
			fmt.Printf("Audit logging failed: %v\n", err)
		}
	}

	// Step 5: Apply retention policy
	if cm.retentionMgr != nil {
		if err := cm.retentionMgr.ApplyRetentionPolicy(ctx, &processedEvent); err != nil {
			return nil, fmt.Errorf("retention policy application failed: %w", err)
		}
	}

	return &processedEvent, nil
}

// ValidateAccess validates access to resources
func (cm *ComplianceManager) ValidateAccess(ctx context.Context, principal, action, resource string) error {
	if cm.accessControl == nil {
		return nil // Access control disabled
	}

	return cm.accessControl.ValidateAccess(ctx, principal, action, resource)
}

// GetComplianceReport generates a compliance report
func (cm *ComplianceManager) GetComplianceReport(ctx context.Context) (*ComplianceReport, error) {
	report := &ComplianceReport{
		Timestamp:           time.Now(),
		ComplianceFrameworks: cm.config.ComplianceFrameworks,
		Status:              "compliant",
		Components:          make(map[string]ComponentStatus),
	}

	// Check data filtering compliance
	if cm.dataFilter != nil {
		status := cm.dataFilter.GetComplianceStatus()
		report.Components["data_filtering"] = status
	}

	// Check audit logging compliance
	if cm.auditLogger != nil {
		status := cm.auditLogger.GetComplianceStatus()
		report.Components["audit_logging"] = status
	}

	// Check encryption compliance
	if cm.encryptionMgr != nil {
		status := cm.encryptionMgr.GetComplianceStatus()
		report.Components["encryption"] = status
	}

	// Check access control compliance
	if cm.accessControl != nil {
		status := cm.accessControl.GetComplianceStatus()
		report.Components["access_control"] = status
	}

	// Check retention policy compliance
	if cm.retentionMgr != nil {
		status := cm.retentionMgr.GetComplianceStatus()
		report.Components["retention"] = status
	}

	// Determine overall compliance status
	for _, componentStatus := range report.Components {
		if componentStatus.Status != "compliant" {
			report.Status = "non_compliant"
			break
		}
	}

	return report, nil
}

// shouldEncrypt determines if an event should be encrypted based on classification
func (cm *ComplianceManager) shouldEncrypt(event *tracing.TraceEvent) bool {
	// Check if payload contains classification markers that require encryption
	payload := event.Payload

	// Look for confidential classification in payload
	if strings.Contains(payload, "[Classification: confidential]") ||
		strings.Contains(payload, "[Classification: secret]") {
		return true
	}

	// Default encryption based on config
	return cm.config.EnableEncryption
}

// ComplianceReport represents a compliance status report
type ComplianceReport struct {
	Timestamp           time.Time                    `json:"timestamp"`
	ComplianceFrameworks []string                     `json:"compliance_frameworks"`
	Status              string                       `json:"status"` // compliant, non_compliant, partial
	Components          map[string]ComponentStatus   `json:"components"`
	Recommendations     []string                     `json:"recommendations"`
	Issues              []ComplianceIssue            `json:"issues"`
}

// ComponentStatus represents the compliance status of a component
type ComponentStatus struct {
	Status      string                 `json:"status"`      // compliant, non_compliant, warning
	LastChecked time.Time              `json:"last_checked"`
	Details     map[string]interface{} `json:"details"`
	Issues      []string               `json:"issues"`
}

// ComplianceIssue represents a compliance issue
type ComplianceIssue struct {
	Severity    string    `json:"severity"`    // critical, high, medium, low
	Component   string    `json:"component"`
	Description string    `json:"description"`
	Remediation string    `json:"remediation"`
	Timestamp   time.Time `json:"timestamp"`
}

// DefaultComplianceConfig returns a default compliance configuration
func DefaultComplianceConfig() *ComplianceConfig {
	return &ComplianceConfig{
		EnableDataFiltering: true,
		PIIDetection: PIIDetectionConfig{
			EnableDetection:  true,
			RedactionMode:   "mask",
			PIITypes:        []string{"email", "ssn", "credit_card", "phone", "ip_address"},
			SensitivityLevel: "medium",
		},
		DataClassification: DataClassificationConfig{
			EnableClassification: true,
			AutoClassification:   true,
			DefaultLevel:        "internal",
			ClassificationLevels: []ClassificationLevel{
				{
					Level:       "public",
					Description: "Public information",
					Actions:     []string{"log"},
				},
				{
					Level:       "internal",
					Description: "Internal use only",
					Actions:     []string{"log", "audit"},
				},
				{
					Level:       "confidential",
					Description: "Confidential information",
					Actions:     []string{"log", "audit", "encrypt"},
				},
				{
					Level:       "restricted",
					Description: "Restricted access",
					Actions:     []string{"log", "audit", "encrypt", "restrict"},
				},
			},
		},
		EnableAuditLogging: true,
		AuditConfig: AuditConfig{
			AuditLevel:       "detailed",
			LogDestination:   "file",
			LogFormat:       "json",
			IncludePayloads: false,
			TamperProtection: true,
			DigitalSigning:  false,
			RetentionPeriod: 90 * 24 * time.Hour, // 90 days
			EncryptLogs:     true,
		},
		EnableEncryption: true,
		EncryptionConfig: EncryptionConfig{
			Algorithm:         "AES-256-GCM",
			KeyRotationPeriod: 30 * 24 * time.Hour, // 30 days
			KeyDerivation:     "PBKDF2",
			EncryptInTransit:  true,
			EncryptAtRest:     true,
		},
		EnableAccessControl: false, // Disabled by default
		AccessControlConfig: AccessControlConfig{
			AuthenticationMode: "none",
			AuthorizationMode:  "rbac",
			SessionTimeout:     8 * time.Hour,
			MaxSessions:       10,
		},
		EnableRetentionPolicy: true,
		RetentionConfig: RetentionConfig{
			DefaultRetention: 30 * 24 * time.Hour, // 30 days
			DataTypeRetention: map[string]time.Duration{
				"http_request":  7 * 24 * time.Hour,   // 7 days
				"http_response": 7 * 24 * time.Hour,   // 7 days
				"error_event":   90 * 24 * time.Hour,  // 90 days
				"audit_log":     365 * 24 * time.Hour, // 1 year
			},
			AutoPurge:          true,
			PurgeSchedule:      "0 2 * * *", // Daily at 2 AM
			ArchiveBeforePurge: true,
			ArchiveLocation:    "/var/lib/ebpf-tracer/archive",
		},
		ComplianceFrameworks: []string{"GDPR", "SOX"},
	}
}
