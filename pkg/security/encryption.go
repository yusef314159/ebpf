package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"ebpf-tracing/pkg/tracing"
	"golang.org/x/crypto/pbkdf2"
)

// EncryptionManager handles encryption and key management
type EncryptionManager struct {
	config       *EncryptionConfig
	currentKey   []byte
	keyVersion   int
	gcm          cipher.AEAD
	keyHistory   map[int][]byte
	mutex        sync.RWMutex
	stats        *EncryptionStats
}

// EncryptionStats tracks encryption statistics
type EncryptionStats struct {
	EventsEncrypted   int64     `json:"events_encrypted"`
	EventsDecrypted   int64     `json:"events_decrypted"`
	KeyRotations      int64     `json:"key_rotations"`
	EncryptionErrors  int64     `json:"encryption_errors"`
	LastKeyRotation   time.Time `json:"last_key_rotation"`
	CurrentKeyVersion int       `json:"current_key_version"`
	mutex             sync.RWMutex
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Data       string `json:"data"`        // Base64 encoded encrypted data
	Nonce      string `json:"nonce"`       // Base64 encoded nonce
	KeyVersion int    `json:"key_version"` // Key version used for encryption
	Algorithm  string `json:"algorithm"`   // Encryption algorithm used
	Timestamp  int64  `json:"timestamp"`   // Encryption timestamp
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager(config *EncryptionConfig) (*EncryptionManager, error) {
	em := &EncryptionManager{
		config:     config,
		keyHistory: make(map[int][]byte),
		stats: &EncryptionStats{
			LastKeyRotation:   time.Now(),
			CurrentKeyVersion: 1,
		},
	}

	// Initialize encryption key
	if err := em.initializeKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption key: %w", err)
	}

	// Start key rotation routine if configured
	if config.KeyRotationPeriod > 0 {
		go em.keyRotationRoutine()
	}

	return em, nil
}

// EncryptEvent encrypts sensitive fields in a trace event
func (em *EncryptionManager) EncryptEvent(ctx context.Context, event *tracing.TraceEvent) (*tracing.TraceEvent, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	encryptedEvent := *event

	// Encrypt payload if present
	if event.Payload != "" {
		encryptedPayload, err := em.encryptString(event.Payload)
		if err != nil {
			em.updateStats(false, true, false)
			return nil, fmt.Errorf("failed to encrypt payload: %w", err)
		}
		encryptedEvent.Payload = encryptedPayload
	}

	// Note: TraceEvent doesn't have Headers field, so we skip header encryption

	// Add encryption marker to payload
	if encryptedEvent.Payload != "" {
		encryptedEvent.Payload = fmt.Sprintf("%s [Encrypted with %s at %s]",
			encryptedEvent.Payload, em.config.Algorithm, time.Now().Format(time.RFC3339))
	}

	em.updateStats(true, false, false)
	return &encryptedEvent, nil
}

// DecryptEvent decrypts encrypted fields in a trace event
func (em *EncryptionManager) DecryptEvent(ctx context.Context, event *tracing.TraceEvent) (*tracing.TraceEvent, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	// Check if event is encrypted (look for encryption marker in payload)
	if !strings.Contains(event.Payload, "[Encrypted") {
		return event, nil // Not encrypted
	}

	decryptedEvent := *event

	// Decrypt payload if present
	if event.Payload != "" {
		decryptedPayload, err := em.decryptString(event.Payload)
		if err != nil {
			em.updateStats(false, true, false)
			return nil, fmt.Errorf("failed to decrypt payload: %w", err)
		}
		decryptedEvent.Payload = decryptedPayload
	}

	// Note: TraceEvent doesn't have Headers field, so we skip header decryption

	// Remove encryption marker from payload
	if strings.Contains(decryptedEvent.Payload, "[Encrypted") {
		// Remove the encryption marker from the payload
		re := regexp.MustCompile(`\s*\[Encrypted[^\]]*\]`)
		decryptedEvent.Payload = re.ReplaceAllString(decryptedEvent.Payload, "")
	}

	em.updateStats(false, false, true)
	return &decryptedEvent, nil
}

// EncryptString encrypts a string value
func (em *EncryptionManager) EncryptString(plaintext string) (string, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.encryptString(plaintext)
}

// DecryptString decrypts a string value
func (em *EncryptionManager) DecryptString(ciphertext string) (string, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.decryptString(ciphertext)
}

// encryptString encrypts a string using AES-GCM
func (em *EncryptionManager) encryptString(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	// Generate a random nonce
	nonce := make([]byte, em.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := em.gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Create encrypted data structure
	encData := EncryptedData{
		Data:       base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		KeyVersion: em.keyVersion,
		Algorithm:  em.config.Algorithm,
		Timestamp:  time.Now().Unix(),
	}

	// Encode as base64 JSON
	jsonData, err := json.Marshal(encData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal encrypted data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(jsonData), nil
}

// decryptString decrypts a string using AES-GCM
func (em *EncryptionManager) decryptString(encryptedText string) (string, error) {
	if encryptedText == "" {
		return "", nil
	}

	// Decode base64 JSON
	jsonData, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	var encData EncryptedData
	if err := json.Unmarshal(jsonData, &encData); err != nil {
		return "", fmt.Errorf("failed to unmarshal encrypted data: %w", err)
	}

	// Get the appropriate key for decryption
	key, exists := em.keyHistory[encData.KeyVersion]
	if !exists {
		return "", fmt.Errorf("encryption key version %d not found", encData.KeyVersion)
	}

	// Create cipher for this key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decode ciphertext and nonce
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encData.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// RotateKey rotates the encryption key
func (em *EncryptionManager) RotateKey() error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	// Store current key in history
	em.keyHistory[em.keyVersion] = em.currentKey

	// Generate new key
	em.keyVersion++
	newKey, err := em.generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	em.currentKey = newKey
	em.keyHistory[em.keyVersion] = newKey

	// Update cipher
	block, err := aes.NewCipher(em.currentKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher with new key: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM with new key: %w", err)
	}

	em.gcm = gcm

	// Update statistics
	em.updateStats(false, false, false)
	em.stats.mutex.Lock()
	em.stats.KeyRotations++
	em.stats.LastKeyRotation = time.Now()
	em.stats.CurrentKeyVersion = em.keyVersion
	em.stats.mutex.Unlock()

	return nil
}

// GetEncryptionStats returns encryption statistics
func (em *EncryptionManager) GetEncryptionStats() *EncryptionStats {
	em.stats.mutex.RLock()
	defer em.stats.mutex.RUnlock()

	return &EncryptionStats{
		EventsEncrypted:   em.stats.EventsEncrypted,
		EventsDecrypted:   em.stats.EventsDecrypted,
		KeyRotations:      em.stats.KeyRotations,
		EncryptionErrors:  em.stats.EncryptionErrors,
		LastKeyRotation:   em.stats.LastKeyRotation,
		CurrentKeyVersion: em.stats.CurrentKeyVersion,
	}
}

// GetComplianceStatus returns compliance status for encryption
func (em *EncryptionManager) GetComplianceStatus() ComponentStatus {
	stats := em.GetEncryptionStats()
	
	status := ComponentStatus{
		Status:      "compliant",
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"events_encrypted":    stats.EventsEncrypted,
			"events_decrypted":    stats.EventsDecrypted,
			"key_rotations":       stats.KeyRotations,
			"encryption_errors":   stats.EncryptionErrors,
			"current_key_version": stats.CurrentKeyVersion,
			"algorithm":           em.config.Algorithm,
			"key_rotation_period": em.config.KeyRotationPeriod.String(),
		},
		Issues: []string{},
	}

	// Check for compliance issues
	if stats.EncryptionErrors > 0 {
		errorRate := float64(stats.EncryptionErrors) / float64(stats.EventsEncrypted+stats.EventsDecrypted)
		if errorRate > 0.01 { // More than 1% error rate
			status.Status = "warning"
			status.Issues = append(status.Issues, "High encryption error rate detected")
		}
	}

	// Check key rotation compliance
	if em.config.KeyRotationPeriod > 0 {
		timeSinceRotation := time.Since(stats.LastKeyRotation)
		if timeSinceRotation > em.config.KeyRotationPeriod*2 {
			status.Status = "non_compliant"
			status.Issues = append(status.Issues, "Key rotation overdue")
		} else if timeSinceRotation > em.config.KeyRotationPeriod {
			status.Status = "warning"
			status.Issues = append(status.Issues, "Key rotation due soon")
		}
	}

	return status
}

// Helper methods

func (em *EncryptionManager) initializeKey() error {
	key, err := em.generateKey()
	if err != nil {
		return fmt.Errorf("failed to generate initial key: %w", err)
	}

	em.currentKey = key
	em.keyVersion = 1
	em.keyHistory[em.keyVersion] = key

	// Initialize AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	em.gcm = gcm
	return nil
}

func (em *EncryptionManager) generateKey() ([]byte, error) {
	// In a production environment, this should use a proper key derivation function
	// and potentially integrate with a key management service
	
	switch em.config.KeyDerivation {
	case "PBKDF2":
		return em.generatePBKDF2Key()
	case "random":
		return em.generateRandomKey()
	default:
		return em.generateRandomKey()
	}
}

func (em *EncryptionManager) generatePBKDF2Key() ([]byte, error) {
	// Use a master password and salt for key derivation
	// In production, these should be securely managed
	password := []byte("ebpf-tracer-master-key-change-in-production")
	salt := []byte("ebpf-tracer-salt")
	
	return pbkdf2.Key(password, salt, 100000, 32, sha256.New), nil
}

func (em *EncryptionManager) generateRandomKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key for AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

func (em *EncryptionManager) shouldEncryptHeader(headerName string) bool {
	sensitiveHeaders := []string{
		"authorization",
		"cookie",
		"x-api-key",
		"x-auth-token",
		"x-session-id",
	}

	headerLower := strings.ToLower(headerName)
	for _, sensitive := range sensitiveHeaders {
		if headerLower == sensitive {
			return true
		}
	}
	return false
}

func (em *EncryptionManager) keyRotationRoutine() {
	ticker := time.NewTicker(em.config.KeyRotationPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := em.RotateKey(); err != nil {
				fmt.Printf("Key rotation failed: %v\n", err)
			}
		}
	}
}

func (em *EncryptionManager) updateStats(encrypted, error, decrypted bool) {
	em.stats.mutex.Lock()
	defer em.stats.mutex.Unlock()

	if encrypted {
		em.stats.EventsEncrypted++
	}
	if decrypted {
		em.stats.EventsDecrypted++
	}
	if error {
		em.stats.EncryptionErrors++
	}
}

// ValidateConfiguration validates the encryption configuration
func (em *EncryptionManager) ValidateConfiguration() error {
	validAlgorithms := []string{"AES-256-GCM", "ChaCha20-Poly1305"}
	validAlgorithm := false
	for _, alg := range validAlgorithms {
		if em.config.Algorithm == alg {
			validAlgorithm = true
			break
		}
	}
	if !validAlgorithm {
		return fmt.Errorf("invalid encryption algorithm: %s", em.config.Algorithm)
	}

	validKeyDerivations := []string{"PBKDF2", "Argon2", "scrypt", "random"}
	validKeyDerivation := false
	for _, kd := range validKeyDerivations {
		if em.config.KeyDerivation == kd {
			validKeyDerivation = true
			break
		}
	}
	if !validKeyDerivation {
		return fmt.Errorf("invalid key derivation method: %s", em.config.KeyDerivation)
	}

	if em.config.KeyRotationPeriod < 0 {
		return fmt.Errorf("key rotation period cannot be negative")
	}

	return nil
}
