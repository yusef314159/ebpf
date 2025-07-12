# Enhanced Security & Compliance System

The eBPF HTTP Tracer includes a comprehensive security and compliance system designed to meet enterprise security requirements and regulatory compliance standards.

## Overview

The security system provides:

- **Data Filtering & PII Protection**: Automatic detection and redaction of personally identifiable information
- **Data Classification**: Automatic classification of data based on sensitivity levels
- **Audit Logging**: Comprehensive audit trails for security and compliance monitoring
- **Encryption**: End-to-end encryption of sensitive data
- **Access Control**: Role-based access control with authentication and authorization
- **Data Retention**: Automated data retention policies with purging and archiving
- **Compliance Frameworks**: Support for GDPR, HIPAA, SOX, PCI-DSS, and other standards

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   eBPF Events   │───▶│ Compliance       │───▶│  Processed      │
│                 │    │ Manager          │    │  Events         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ Security         │
                    │ Components       │
                    └──────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Data Filter │    │ Audit Logger    │    │ Encryption      │
│ & PII       │    │                 │    │ Manager         │
│ Detection   │    │                 │    │                 │
└─────────────┘    └─────────────────┘    └─────────────────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Access      │    │ Retention       │    │ Compliance      │
│ Control     │    │ Manager         │    │ Reporting       │
└─────────────┘    └─────────────────┘    └─────────────────┘
```

## Configuration

### Basic Security Configuration

```yaml
compliance_security:
  enable_compliance: true
  compliance_frameworks: ["GDPR", "HIPAA", "SOX"]
  
  # Data filtering and PII protection
  enable_data_filtering: true
  pii_detection:
    enable_detection: true
    redaction_mode: "mask"  # mask, hash, remove
    pii_types: ["email", "ssn", "credit_card", "phone"]
    sensitivity_level: "medium"
    custom_patterns:
      - name: "custom_id"
        pattern: "ID-\\d{8}"
        type: "identifier"
        confidence: 0.9
  
  # Data classification
  data_classification:
    enable_classification: true
    auto_classification: true
    default_level: "internal"
    classification_levels:
      - level: "public"
        description: "Public information"
        patterns: ["public"]
        actions: ["log"]
      - level: "internal"
        description: "Internal use only"
        patterns: ["internal"]
        actions: ["log", "audit"]
      - level: "confidential"
        description: "Confidential information"
        patterns: ["confidential", "secret"]
        actions: ["log", "audit", "encrypt"]
  
  # Audit logging
  enable_audit_logging: true
  audit_config:
    audit_level: "detailed"  # basic, detailed, comprehensive
    log_destination: "/var/log/ebpf-tracer/audit.log"
    log_format: "json"
    include_payloads: false
    tamper_protection: true
    digital_signing: false
    retention_days: 365
    encrypt_logs: true
  
  # Encryption
  enable_encryption: true
  encryption_config:
    algorithm: "AES-256-GCM"
    key_rotation_days: 30
    key_derivation: "PBKDF2"
    encrypt_in_transit: true
    encrypt_at_rest: true
    key_management_url: "https://kms.example.com"
  
  # Access control
  enable_access_control: true
  access_control_config:
    authentication_mode: "oauth2"  # basic, oauth2, saml
    authorization_mode: "rbac"     # rbac, abac
    session_timeout_minutes: 480
    max_sessions: 10
    roles:
      - name: "admin"
        description: "Administrator role"
        permissions: ["read", "write", "delete", "admin"]
        resources: ["*"]
      - name: "analyst"
        description: "Security analyst role"
        permissions: ["read", "analyze"]
        resources: ["events/*", "reports/*"]
      - name: "viewer"
        description: "Read-only access"
        permissions: ["read"]
        resources: ["events/public/*"]
  
  # Data retention
  enable_retention_policy: true
  retention_config:
    default_retention_days: 90
    data_type_retention_days:
      http_request: 30
      http_response: 30
      error_event: 365
      audit_log: 2555  # 7 years
      security_event: 1095  # 3 years
    auto_purge: true
    purge_schedule: "0 2 * * *"  # Daily at 2 AM
    archive_before_purge: true
    archive_location: "/var/lib/ebpf-tracer/archive"
```

## Security Components

### 1. Data Filter & PII Protection

The data filter automatically detects and redacts PII from HTTP payloads:

```go
// Create data filter
piiConfig := &security.PIIDetectionConfig{
    EnableDetection:  true,
    RedactionMode:   "mask",
    PIITypes:        []string{"email", "ssn", "credit_card"},
    SensitivityLevel: "high",
}

dataFilter, err := security.NewDataFilter(piiConfig, classConfig)
if err != nil {
    log.Fatal(err)
}

// Filter event
filteredEvent, err := dataFilter.FilterEvent(ctx, event)
```

**Supported PII Types:**
- Email addresses
- Social Security Numbers (SSN)
- Credit card numbers
- Phone numbers
- IP addresses
- Custom patterns via regex

**Redaction Modes:**
- `mask`: Replace with asterisks (e.g., `***@***.com`)
- `hash`: Replace with SHA-256 hash
- `remove`: Remove entirely from payload

### 2. Data Classification

Automatic classification of data based on content analysis:

```go
classification, err := dataFilter.ClassifyEvent(ctx, event)
// Returns: "public", "internal", "confidential", "restricted"
```

**Classification Levels:**
- **Public**: No restrictions
- **Internal**: Internal use only
- **Confidential**: Restricted access, encryption required
- **Restricted**: Highest security, special handling required

### 3. Audit Logging

Comprehensive audit trails for security monitoring:

```go
auditLogger, err := security.NewAuditLogger(auditConfig)

// Log security event
err = auditLogger.LogSecurityEvent(ctx, "authentication", "login", 
    "user_account", "john.doe", "success", metadata)

// Log compliance event
err = auditLogger.LogComplianceEvent(ctx, "GDPR", "data_processing", 
    "compliant", metadata)

// Log data access
err = auditLogger.LogDataAccess(ctx, "john.doe", "read", 
    "user_profile", true, metadata)
```

**Audit Event Types:**
- Authentication events
- Authorization events
- Data access events
- Configuration changes
- Security violations
- Compliance events

### 4. Encryption

End-to-end encryption for sensitive data:

```go
encryptionMgr, err := security.NewEncryptionManager(encryptionConfig)

// Encrypt event
encryptedEvent, err := encryptionMgr.EncryptEvent(ctx, event)

// Decrypt event
decryptedEvent, err := encryptionMgr.DecryptEvent(ctx, encryptedEvent)
```

**Encryption Features:**
- AES-256-GCM encryption
- Automatic key rotation
- Key derivation with PBKDF2
- In-transit and at-rest encryption
- Integration with external key management systems

### 5. Access Control

Role-based access control with authentication:

```go
accessControl, err := security.NewAccessControl(accessConfig)

// Authenticate user
session, err := accessControl.Authenticate(ctx, username, password, metadata)

// Validate access
err = accessControl.ValidateAccess(ctx, username, "read", "events/sensitive")

// Revoke session
err = accessControl.RevokeSession(ctx, sessionID)
```

**Access Control Features:**
- Multiple authentication methods (Basic, OAuth2, SAML)
- Role-based authorization (RBAC)
- Attribute-based authorization (ABAC)
- Session management
- Multi-factor authentication support

### 6. Data Retention

Automated data retention and purging:

```go
retentionMgr, err := security.NewRetentionManager(retentionConfig)

// Apply retention policy
err = retentionMgr.ApplyRetentionPolicy(ctx, event)

// Manual purge
err = retentionMgr.PurgeExpiredData(ctx)
```

**Retention Features:**
- Configurable retention periods by data type
- Automatic purging based on schedules
- Archive before purge option
- Compliance with legal hold requirements
- Audit trail of retention actions

## Compliance Frameworks

### GDPR (General Data Protection Regulation)

- **Data Minimization**: Only collect necessary data
- **Purpose Limitation**: Use data only for specified purposes
- **Right to Erasure**: Automatic data deletion after retention period
- **Data Protection by Design**: Built-in privacy protection
- **Audit Trails**: Comprehensive logging for compliance reporting

### HIPAA (Health Insurance Portability and Accountability Act)

- **PHI Protection**: Automatic detection and encryption of health information
- **Access Controls**: Role-based access to sensitive data
- **Audit Logs**: Detailed logging of all data access
- **Data Integrity**: Tamper-proof audit trails
- **Breach Notification**: Automated alerts for security incidents

### SOX (Sarbanes-Oxley Act)

- **Data Integrity**: Immutable audit trails
- **Access Controls**: Segregation of duties
- **Change Management**: Audit trail of all configuration changes
- **Retention**: Long-term retention of financial data
- **Reporting**: Automated compliance reporting

### PCI-DSS (Payment Card Industry Data Security Standard)

- **Cardholder Data Protection**: Automatic detection and encryption
- **Access Controls**: Restricted access to payment data
- **Network Security**: Secure transmission of payment information
- **Monitoring**: Real-time monitoring of payment transactions
- **Incident Response**: Automated incident detection and response

## Usage Examples

### Basic Compliance Setup

```go
// Create compliance manager
config := security.DefaultComplianceConfig()
config.EnableDataFiltering = true
config.EnableAuditLogging = true
config.EnableEncryption = true
config.ComplianceFrameworks = []string{"GDPR", "HIPAA"}

manager, err := security.NewComplianceManager(config)
if err != nil {
    log.Fatal(err)
}

// Process event through compliance pipeline
processedEvent, err := manager.ProcessEvent(ctx, event)
if err != nil {
    log.Printf("Compliance processing failed: %v", err)
}

// Generate compliance report
report, err := manager.GetComplianceReport(ctx)
if err != nil {
    log.Printf("Failed to generate compliance report: %v", err)
}

fmt.Printf("Compliance Status: %s\n", report.Status)
for component, status := range report.Components {
    fmt.Printf("  %s: %s\n", component, status.Status)
}
```

### Custom PII Detection

```go
// Define custom PII patterns
customPatterns := []security.PIIPattern{
    {
        Name:        "employee_id",
        Pattern:     "EMP-\\d{6}",
        Type:        "identifier",
        Confidence:  0.95,
        Description: "Employee ID pattern",
    },
    {
        Name:        "customer_id",
        Pattern:     "CUST-[A-Z]{2}\\d{8}",
        Type:        "identifier",
        Confidence:  0.90,
        Description: "Customer ID pattern",
    },
}

piiConfig := &security.PIIDetectionConfig{
    EnableDetection:  true,
    RedactionMode:   "hash",
    CustomPatterns:  customPatterns,
    SensitivityLevel: "high",
}
```

## Monitoring and Alerting

The security system provides comprehensive monitoring capabilities:

### Security Metrics

- PII detection rate
- Classification accuracy
- Encryption/decryption performance
- Access control violations
- Audit log integrity
- Compliance score

### Alerts

- PII exposure detected
- Unauthorized access attempts
- Encryption failures
- Audit log tampering
- Compliance violations
- Data retention policy violations

### Dashboards

- Real-time security status
- Compliance posture
- Data classification distribution
- Access patterns
- Retention policy effectiveness

## Best Practices

1. **Regular Security Reviews**: Conduct periodic reviews of security configurations
2. **Key Rotation**: Implement regular encryption key rotation
3. **Access Audits**: Regular review of user access and permissions
4. **Compliance Testing**: Regular testing of compliance controls
5. **Incident Response**: Maintain incident response procedures
6. **Data Minimization**: Collect only necessary data
7. **Encryption**: Encrypt sensitive data at rest and in transit
8. **Monitoring**: Implement continuous security monitoring
9. **Training**: Regular security awareness training
10. **Documentation**: Maintain up-to-date security documentation

## Troubleshooting

### Common Issues

1. **PII Detection False Positives**: Adjust sensitivity levels and patterns
2. **Performance Impact**: Optimize filtering rules and encryption settings
3. **Compliance Failures**: Review configuration and audit logs
4. **Access Denied**: Check user roles and permissions
5. **Encryption Errors**: Verify key management configuration

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
general:
  log_level: "debug"
  
compliance_security:
  audit_config:
    audit_level: "comprehensive"
```

### Log Analysis

Monitor security logs for:
- Authentication failures
- Authorization violations
- PII exposure incidents
- Encryption failures
- Compliance violations

## Performance Considerations

- **Filtering Impact**: PII detection adds ~5-10ms per event
- **Encryption Overhead**: Encryption adds ~2-5ms per event
- **Audit Logging**: Minimal impact with async logging
- **Memory Usage**: ~50MB additional memory for security components
- **Storage**: Audit logs require additional storage capacity

## Security Hardening

1. **Secure Configuration**: Use secure defaults
2. **Network Security**: Implement network segmentation
3. **Access Controls**: Principle of least privilege
4. **Monitoring**: Comprehensive security monitoring
5. **Updates**: Regular security updates
6. **Backup**: Secure backup of configuration and keys
7. **Testing**: Regular security testing
8. **Documentation**: Maintain security documentation

## Conclusion

The Enhanced Security & Compliance system provides enterprise-grade security features for the eBPF HTTP Tracer, ensuring data protection, regulatory compliance, and comprehensive audit capabilities. The modular design allows for flexible configuration based on specific security requirements and compliance frameworks.
