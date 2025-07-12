package security

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// LSMManager provides Linux Security Module integration
type LSMManager struct {
	config         *LSMConfig
	activeModules  []string
	seccompProfile *SeccompProfile
	selinuxContext *SELinuxContext
	apparmorProfile *ApparmorProfile
	capabilities   *CapabilitySet
	sandboxManager *SandboxManager
	mutex          sync.RWMutex
	running        bool
	stopChan       chan struct{}
}

// LSMConfig holds LSM configuration
type LSMConfig struct {
	EnableSELinux         bool     `json:"enable_selinux" yaml:"enable_selinux"`
	EnableAppArmor        bool     `json:"enable_apparmor" yaml:"enable_apparmor"`
	EnableSeccomp         bool     `json:"enable_seccomp" yaml:"enable_seccomp"`
	EnableCapabilities    bool     `json:"enable_capabilities" yaml:"enable_capabilities"`
	EnableSandboxing      bool     `json:"enable_sandboxing" yaml:"enable_sandboxing"`
	SELinuxPolicy         string   `json:"selinux_policy" yaml:"selinux_policy"`
	ApparmorProfile       string   `json:"apparmor_profile" yaml:"apparmor_profile"`
	SeccompProfile        string   `json:"seccomp_profile" yaml:"seccomp_profile"`
	AllowedCapabilities   []string `json:"allowed_capabilities" yaml:"allowed_capabilities"`
	DeniedCapabilities    []string `json:"denied_capabilities" yaml:"denied_capabilities"`
	SandboxType           string   `json:"sandbox_type" yaml:"sandbox_type"`
	RestrictedSyscalls    []string `json:"restricted_syscalls" yaml:"restricted_syscalls"`
	AllowedPaths          []string `json:"allowed_paths" yaml:"allowed_paths"`
	DeniedPaths           []string `json:"denied_paths" yaml:"denied_paths"`
	NetworkRestrictions   bool     `json:"network_restrictions" yaml:"network_restrictions"`
	FileSystemRestrictions bool    `json:"filesystem_restrictions" yaml:"filesystem_restrictions"`
}

// SeccompProfile represents a seccomp security profile
type SeccompProfile struct {
	Name            string              `json:"name"`
	DefaultAction   string              `json:"default_action"`
	Architectures   []string            `json:"architectures"`
	SyscallRules    []SeccompSyscallRule `json:"syscall_rules"`
	Flags           []string            `json:"flags"`
	CreatedAt       time.Time           `json:"created_at"`
	LastModified    time.Time           `json:"last_modified"`
}

// SeccompSyscallRule represents a seccomp syscall rule
type SeccompSyscallRule struct {
	Names  []string           `json:"names"`
	Action string             `json:"action"`
	Args   []SeccompArgument  `json:"args"`
}

// SeccompArgument represents a seccomp syscall argument filter
type SeccompArgument struct {
	Index    int    `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"value_two"`
	Op       string `json:"op"`
}

// SELinuxContext represents SELinux security context
type SELinuxContext struct {
	User     string    `json:"user"`
	Role     string    `json:"role"`
	Type     string    `json:"type"`
	Level    string    `json:"level"`
	Policy   string    `json:"policy"`
	Enforcing bool     `json:"enforcing"`
	CreatedAt time.Time `json:"created_at"`
}

// ApparmorProfile represents AppArmor security profile
type ApparmorProfile struct {
	Name         string            `json:"name"`
	Mode         string            `json:"mode"` // "enforce", "complain", "disable"
	Rules        []ApparmorRule    `json:"rules"`
	Capabilities []string          `json:"capabilities"`
	NetworkRules []NetworkRule     `json:"network_rules"`
	FileRules    []FileRule        `json:"file_rules"`
	Flags        map[string]string `json:"flags"`
	CreatedAt    time.Time         `json:"created_at"`
	LastModified time.Time         `json:"last_modified"`
}

// ApparmorRule represents an AppArmor rule
type ApparmorRule struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Permissions string `json:"permissions"`
	Target      string `json:"target"`
}

// NetworkRule represents a network access rule
type NetworkRule struct {
	Family   string `json:"family"`   // "inet", "inet6", "unix"
	Type     string `json:"type"`     // "stream", "dgram"
	Protocol string `json:"protocol"` // "tcp", "udp"
	Address  string `json:"address"`
	Port     string `json:"port"`
	Action   string `json:"action"`   // "allow", "deny"
}

// FileRule represents a file access rule
type FileRule struct {
	Path        string `json:"path"`
	Permissions string `json:"permissions"` // "r", "w", "x", "m", "k", "l"
	Owner       string `json:"owner"`
	Action      string `json:"action"` // "allow", "deny"
}

// CapabilitySet represents Linux capabilities
type CapabilitySet struct {
	Effective   []string  `json:"effective"`
	Permitted   []string  `json:"permitted"`
	Inheritable []string  `json:"inheritable"`
	Bounding    []string  `json:"bounding"`
	Ambient     []string  `json:"ambient"`
	CreatedAt   time.Time `json:"created_at"`
}

// SandboxManager provides hardware-assisted sandboxing
type SandboxManager struct {
	config       *SandboxConfig
	sandboxes    map[string]*Sandbox
	mpkSupport   bool
	sfiSupport   bool
	mutex        sync.RWMutex
}

// SandboxConfig holds sandbox configuration
type SandboxConfig struct {
	EnableMPK         bool     `json:"enable_mpk" yaml:"enable_mpk"`           // Memory Protection Keys
	EnableSFI         bool     `json:"enable_sfi" yaml:"enable_sfi"`           // Software Fault Isolation
	EnableCET         bool     `json:"enable_cet" yaml:"enable_cet"`           // Control-flow Enforcement Technology
	MemoryDomains     []string `json:"memory_domains" yaml:"memory_domains"`
	IsolationLevel    string   `json:"isolation_level" yaml:"isolation_level"`
	MaxSandboxes      int      `json:"max_sandboxes" yaml:"max_sandboxes"`
	SandboxTimeout    time.Duration `json:"sandbox_timeout" yaml:"sandbox_timeout"`
}

// Sandbox represents an isolated execution environment
type Sandbox struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	PID           int               `json:"pid"`
	MemoryDomain  int               `json:"memory_domain"`
	Permissions   []string          `json:"permissions"`
	Resources     SandboxResources  `json:"resources"`
	State         string            `json:"state"`
	CreatedAt     time.Time         `json:"created_at"`
	LastAccessed  time.Time         `json:"last_accessed"`
	Violations    []SecurityViolation `json:"violations"`
}

// SandboxResources represents sandbox resource limits
type SandboxResources struct {
	MaxMemory     uint64        `json:"max_memory"`
	MaxCPUTime    time.Duration `json:"max_cpu_time"`
	MaxFileSize   uint64        `json:"max_file_size"`
	MaxOpenFiles  int           `json:"max_open_files"`
	MaxProcesses  int           `json:"max_processes"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	PID         int               `json:"pid"`
	UID         int               `json:"uid"`
	GID         int               `json:"gid"`
	Command     string            `json:"command"`
	Path        string            `json:"path"`
	Syscall     string            `json:"syscall"`
	Context     map[string]string `json:"context"`
	Timestamp   time.Time         `json:"timestamp"`
	Blocked     bool              `json:"blocked"`
}

// ThreatProtection provides advanced threat protection
type ThreatProtection struct {
	config           *ThreatConfig
	anomalyDetector  *AnomalyDetector
	behaviorAnalyzer *BehaviorAnalyzer
	threatIntel      *ThreatIntelligence
	responseEngine   *ResponseEngine
	mutex            sync.RWMutex
}

// ThreatConfig holds threat protection configuration
type ThreatConfig struct {
	EnableAnomalyDetection   bool          `json:"enable_anomaly_detection" yaml:"enable_anomaly_detection"`
	EnableBehaviorAnalysis   bool          `json:"enable_behavior_analysis" yaml:"enable_behavior_analysis"`
	EnableThreatIntelligence bool          `json:"enable_threat_intelligence" yaml:"enable_threat_intelligence"`
	EnableAutoResponse       bool          `json:"enable_auto_response" yaml:"enable_auto_response"`
	AnomalyThreshold         float64       `json:"anomaly_threshold" yaml:"anomaly_threshold"`
	BehaviorWindow           time.Duration `json:"behavior_window" yaml:"behavior_window"`
	ThreatFeeds              []string      `json:"threat_feeds" yaml:"threat_feeds"`
	ResponseActions          []string      `json:"response_actions" yaml:"response_actions"`
}

// AnomalyDetector detects anomalous behavior
type AnomalyDetector struct {
	baselines    map[string]*Baseline
	currentStats map[string]*Statistics
	mutex        sync.RWMutex
}

// Baseline represents normal behavior baseline
type Baseline struct {
	ProcessName   string            `json:"process_name"`
	SyscallCounts map[string]uint64 `json:"syscall_counts"`
	NetworkConns  uint64            `json:"network_conns"`
	FileAccesses  uint64            `json:"file_accesses"`
	CPUUsage      float64           `json:"cpu_usage"`
	MemoryUsage   uint64            `json:"memory_usage"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Statistics represents current behavior statistics
type Statistics struct {
	SyscallCounts map[string]uint64 `json:"syscall_counts"`
	NetworkConns  uint64            `json:"network_conns"`
	FileAccesses  uint64            `json:"file_accesses"`
	CPUUsage      float64           `json:"cpu_usage"`
	MemoryUsage   uint64            `json:"memory_usage"`
	Timestamp     time.Time         `json:"timestamp"`
}

// BehaviorAnalyzer analyzes process behavior patterns
type BehaviorAnalyzer struct {
	patterns      map[string]*BehaviorPattern
	currentBehavior map[string]*ProcessBehavior
	mutex         sync.RWMutex
}

// BehaviorPattern represents a behavior pattern
type BehaviorPattern struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Indicators  []string          `json:"indicators"`
	Threshold   float64           `json:"threshold"`
	Severity    string            `json:"severity"`
	Actions     []string          `json:"actions"`
	Metadata    map[string]string `json:"metadata"`
}

// ProcessBehavior represents current process behavior
type ProcessBehavior struct {
	PID           int               `json:"pid"`
	ProcessName   string            `json:"process_name"`
	StartTime     time.Time         `json:"start_time"`
	SyscallPattern []string         `json:"syscall_pattern"`
	NetworkPattern []string         `json:"network_pattern"`
	FilePattern   []string          `json:"file_pattern"`
	RiskScore     float64           `json:"risk_score"`
	Flags         []string          `json:"flags"`
}

// ThreatIntelligence provides threat intelligence integration
type ThreatIntelligence struct {
	feeds         map[string]*ThreatFeed
	indicators    map[string]*ThreatIndicator
	mutex         sync.RWMutex
}

// ThreatFeed represents a threat intelligence feed
type ThreatFeed struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"`
	LastUpdated time.Time `json:"last_updated"`
	Indicators  int       `json:"indicators"`
	Active      bool      `json:"active"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	Tags        []string          `json:"tags"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
}

// ResponseEngine provides automated threat response
type ResponseEngine struct {
	actions       map[string]*ResponseAction
	activeResponses map[string]*ActiveResponse
	mutex         sync.RWMutex
}

// ResponseAction represents a threat response action
type ResponseAction struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Command     string            `json:"command"`
	Parameters  map[string]string `json:"parameters"`
	Timeout     time.Duration     `json:"timeout"`
	Retries     int               `json:"retries"`
}

// ActiveResponse represents an active threat response
type ActiveResponse struct {
	ID          string            `json:"id"`
	Action      string            `json:"action"`
	Target      string            `json:"target"`
	Status      string            `json:"status"`
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt time.Time         `json:"completed_at"`
	Result      map[string]string `json:"result"`
}

// DefaultLSMConfig returns default LSM configuration
func DefaultLSMConfig() *LSMConfig {
	return &LSMConfig{
		EnableSELinux:      true,
		EnableAppArmor:     true,
		EnableSeccomp:      true,
		EnableCapabilities: true,
		EnableSandboxing:   true,
		SELinuxPolicy:      "targeted",
		ApparmorProfile:    "ebpf-tracer",
		SeccompProfile:     "default",
		AllowedCapabilities: []string{
			"CAP_SYS_ADMIN", "CAP_BPF", "CAP_PERFMON",
			"CAP_NET_ADMIN", "CAP_SYS_PTRACE",
		},
		DeniedCapabilities: []string{
			"CAP_SYS_MODULE", "CAP_SYS_RAWIO",
		},
		SandboxType: "mpk",
		RestrictedSyscalls: []string{
			"ptrace", "process_vm_readv", "process_vm_writev",
		},
		AllowedPaths: []string{
			"/proc", "/sys/fs/bpf", "/sys/kernel/debug",
		},
		DeniedPaths: []string{
			"/etc/shadow", "/etc/passwd", "/root",
		},
		NetworkRestrictions:    true,
		FileSystemRestrictions: true,
	}
}

// NewLSMManager creates a new LSM manager
func NewLSMManager(config *LSMConfig) *LSMManager {
	lsm := &LSMManager{
		config:       config,
		activeModules: make([]string, 0),
		stopChan:     make(chan struct{}),
	}

	// Initialize components
	if config.EnableSeccomp {
		lsm.seccompProfile = &SeccompProfile{
			Name:          config.SeccompProfile,
			DefaultAction: "SCMP_ACT_ALLOW",
			CreatedAt:     time.Now(),
		}
	}

	if config.EnableSELinux {
		lsm.selinuxContext = &SELinuxContext{
			Policy:    config.SELinuxPolicy,
			Enforcing: true,
			CreatedAt: time.Now(),
		}
	}

	if config.EnableAppArmor {
		lsm.apparmorProfile = &ApparmorProfile{
			Name:      config.ApparmorProfile,
			Mode:      "enforce",
			CreatedAt: time.Now(),
		}
	}

	if config.EnableCapabilities {
		lsm.capabilities = &CapabilitySet{
			Effective:   config.AllowedCapabilities,
			Permitted:   config.AllowedCapabilities,
			Inheritable: []string{},
			Bounding:    config.AllowedCapabilities,
			Ambient:     []string{},
			CreatedAt:   time.Now(),
		}
	}

	if config.EnableSandboxing {
		lsm.sandboxManager = NewSandboxManager(&SandboxConfig{
			EnableMPK:      true,
			EnableSFI:      true,
			EnableCET:      true,
			IsolationLevel: "strict",
			MaxSandboxes:   100,
			SandboxTimeout: 30 * time.Second,
		})
	}

	return lsm
}

// Start starts the LSM manager
func (lsm *LSMManager) Start(ctx context.Context) error {
	if lsm.running {
		return fmt.Errorf("LSM manager already running")
	}

	// Detect active LSM modules
	if err := lsm.detectActiveLSMs(); err != nil {
		return fmt.Errorf("failed to detect LSMs: %w", err)
	}

	// Apply security policies
	if err := lsm.applySecurityPolicies(); err != nil {
		return fmt.Errorf("failed to apply security policies: %w", err)
	}

	// Start sandbox manager if enabled
	if lsm.sandboxManager != nil {
		if err := lsm.sandboxManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start sandbox manager: %w", err)
		}
	}

	lsm.running = true

	// Start monitoring
	go lsm.monitorSecurityEvents(ctx)

	return nil
}

// Stop stops the LSM manager
func (lsm *LSMManager) Stop() error {
	if !lsm.running {
		return fmt.Errorf("LSM manager not running")
	}

	lsm.running = false
	close(lsm.stopChan)

	// Stop sandbox manager
	if lsm.sandboxManager != nil {
		lsm.sandboxManager.Stop()
	}

	return nil
}

// detectActiveLSMs detects active LSM modules
func (lsm *LSMManager) detectActiveLSMs() error {
	// Check /sys/kernel/security/lsm
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		// If the file doesn't exist, assume no LSMs are active (for testing)
		lsm.activeModules = []string{}
		return nil
	}

	lsm.activeModules = strings.Split(strings.TrimSpace(string(data)), ",")
	return nil
}

// applySecurityPolicies applies security policies
func (lsm *LSMManager) applySecurityPolicies() error {
	// Apply SELinux policy
	if lsm.config.EnableSELinux && lsm.hasSELinux() {
		if err := lsm.applySELinuxPolicy(); err != nil {
			return fmt.Errorf("failed to apply SELinux policy: %w", err)
		}
	}

	// Apply AppArmor profile
	if lsm.config.EnableAppArmor && lsm.hasAppArmor() {
		if err := lsm.applyApparmorProfile(); err != nil {
			return fmt.Errorf("failed to apply AppArmor profile: %w", err)
		}
	}

	// Apply seccomp profile
	if lsm.config.EnableSeccomp {
		if err := lsm.applySeccompProfile(); err != nil {
			return fmt.Errorf("failed to apply seccomp profile: %w", err)
		}
	}

	// Apply capability restrictions
	if lsm.config.EnableCapabilities {
		if err := lsm.applyCapabilityRestrictions(); err != nil {
			return fmt.Errorf("failed to apply capability restrictions: %w", err)
		}
	}

	return nil
}

// monitorSecurityEvents monitors security events
func (lsm *LSMManager) monitorSecurityEvents(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-lsm.stopChan:
			return
		case <-ticker.C:
			lsm.checkSecurityViolations()
		}
	}
}

// Helper methods (simplified implementations)
func (lsm *LSMManager) hasSELinux() bool {
	for _, module := range lsm.activeModules {
		if module == "selinux" {
			return true
		}
	}
	return false
}

func (lsm *LSMManager) hasAppArmor() bool {
	for _, module := range lsm.activeModules {
		if module == "apparmor" {
			return true
		}
	}
	return false
}

func (lsm *LSMManager) applySELinuxPolicy() error {
	// Simplified implementation
	return nil
}

func (lsm *LSMManager) applyApparmorProfile() error {
	// Simplified implementation
	return nil
}

func (lsm *LSMManager) applySeccompProfile() error {
	// Simplified implementation - skip actual seccomp for testing
	// In production, this would use proper seccomp-bpf filters
	return nil
}

func (lsm *LSMManager) applyCapabilityRestrictions() error {
	// Simplified implementation
	return nil
}

func (lsm *LSMManager) checkSecurityViolations() {
	// Simplified implementation
}

// GetActiveLSMs returns active LSM modules
func (lsm *LSMManager) GetActiveLSMs() []string {
	return lsm.activeModules
}

// IsRunning returns whether the LSM manager is running
func (lsm *LSMManager) IsRunning() bool {
	return lsm.running
}

// GetStats returns LSM statistics
func (lsm *LSMManager) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"active_lsms":     lsm.activeModules,
		"selinux_enabled": lsm.config.EnableSELinux && lsm.hasSELinux(),
		"apparmor_enabled": lsm.config.EnableAppArmor && lsm.hasAppArmor(),
		"seccomp_enabled": lsm.config.EnableSeccomp,
		"sandboxing_enabled": lsm.config.EnableSandboxing,
	}
}

// Simplified sandbox manager implementation
func NewSandboxManager(config *SandboxConfig) *SandboxManager {
	return &SandboxManager{
		config:    config,
		sandboxes: make(map[string]*Sandbox),
	}
}

func (sm *SandboxManager) Start(ctx context.Context) error {
	// Check for hardware support
	sm.mpkSupport = sm.checkMPKSupport()
	sm.sfiSupport = sm.checkSFISupport()
	return nil
}

func (sm *SandboxManager) Stop() error {
	return nil
}

func (sm *SandboxManager) checkMPKSupport() bool {
	// Check for Memory Protection Keys support
	return false // Simplified
}

func (sm *SandboxManager) checkSFISupport() bool {
	// Check for Software Fault Isolation support
	return false // Simplified
}
