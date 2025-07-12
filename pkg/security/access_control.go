package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AccessControl manages authentication and authorization
type AccessControl struct {
	config    *AccessControlConfig
	roles     map[string]*Role
	policies  map[string]*AccessPolicy
	sessions  map[string]*Session
	mutex     sync.RWMutex
	stats     *AccessStats
}

// Session represents an authenticated session
type Session struct {
	ID          string            `json:"id"`
	Principal   string            `json:"principal"`
	Roles       []string          `json:"roles"`
	CreatedAt   time.Time         `json:"created_at"`
	LastAccess  time.Time         `json:"last_access"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Attributes  map[string]string `json:"attributes"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
}

// AccessStats tracks access control statistics
type AccessStats struct {
	AuthenticationAttempts int64     `json:"authentication_attempts"`
	SuccessfulLogins      int64     `json:"successful_logins"`
	FailedLogins          int64     `json:"failed_logins"`
	AuthorizationChecks   int64     `json:"authorization_checks"`
	AccessDenied          int64     `json:"access_denied"`
	ActiveSessions        int64     `json:"active_sessions"`
	LastActivity          time.Time `json:"last_activity"`
	mutex                 sync.RWMutex
}

// AccessRequest represents an access request
type AccessRequest struct {
	Principal string            `json:"principal"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Context   map[string]string `json:"context"`
	Timestamp time.Time         `json:"timestamp"`
}

// AccessDecision represents an access control decision
type AccessDecision struct {
	Request     *AccessRequest `json:"request"`
	Decision    string         `json:"decision"`    // allow, deny
	Reason      string         `json:"reason"`
	PolicyUsed  string         `json:"policy_used"`
	Timestamp   time.Time      `json:"timestamp"`
}

// NewAccessControl creates a new access control manager
func NewAccessControl(config *AccessControlConfig) (*AccessControl, error) {
	ac := &AccessControl{
		config:   config,
		roles:    make(map[string]*Role),
		policies: make(map[string]*AccessPolicy),
		sessions: make(map[string]*Session),
		stats: &AccessStats{
			LastActivity: time.Now(),
		},
	}

	// Initialize roles
	for _, role := range config.Roles {
		ac.roles[role.Name] = &role
	}

	// Initialize policies
	for _, policy := range config.Policies {
		ac.policies[policy.Name] = &policy
	}

	// Start session cleanup routine
	go ac.sessionCleanupRoutine()

	return ac, nil
}

// Authenticate authenticates a principal
func (ac *AccessControl) Authenticate(ctx context.Context, principal, credentials string, clientInfo map[string]string) (*Session, error) {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	ac.updateStats(true, false, false, false)

	// Validate authentication based on mode
	switch ac.config.AuthenticationMode {
	case "none":
		// No authentication required
		break
	case "basic":
		if !ac.validateBasicAuth(principal, credentials) {
			ac.updateStats(false, true, false, false)
			return nil, fmt.Errorf("authentication failed")
		}
	case "oauth":
		if !ac.validateOAuthToken(credentials) {
			ac.updateStats(false, true, false, false)
			return nil, fmt.Errorf("invalid OAuth token")
		}
	case "mtls":
		if !ac.validateMTLS(clientInfo) {
			ac.updateStats(false, true, false, false)
			return nil, fmt.Errorf("mTLS authentication failed")
		}
	default:
		ac.updateStats(false, true, false, false)
		return nil, fmt.Errorf("unsupported authentication mode: %s", ac.config.AuthenticationMode)
	}

	// Check session limits
	if ac.countUserSessions(principal) >= ac.config.MaxSessions {
		ac.updateStats(false, true, false, false)
		return nil, fmt.Errorf("maximum sessions exceeded for user %s", principal)
	}

	// Create session
	session := &Session{
		ID:         ac.generateSessionID(),
		Principal:  principal,
		Roles:      ac.getUserRoles(principal),
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		ExpiresAt:  time.Now().Add(ac.config.SessionTimeout),
		Attributes: make(map[string]string),
		IPAddress:  clientInfo["ip_address"],
		UserAgent:  clientInfo["user_agent"],
	}

	ac.sessions[session.ID] = session
	ac.updateStats(false, false, true, false)

	return session, nil
}

// ValidateAccess validates access to a resource
func (ac *AccessControl) ValidateAccess(ctx context.Context, principal, action, resource string) error {
	ac.mutex.RLock()
	defer ac.mutex.RUnlock()

	ac.updateStats(false, false, false, true)

	// Create access request
	request := &AccessRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   make(map[string]string),
		Timestamp: time.Now(),
	}

	// Make access decision
	decision := ac.makeAccessDecision(request)

	if decision.Decision == "deny" {
		ac.updateStats(false, false, false, false)
		ac.stats.mutex.Lock()
		ac.stats.AccessDenied++
		ac.stats.mutex.Unlock()
		return fmt.Errorf("access denied: %s", decision.Reason)
	}

	return nil
}

// ValidateSession validates a session
func (ac *AccessControl) ValidateSession(ctx context.Context, sessionID string) (*Session, error) {
	ac.mutex.RLock()
	defer ac.mutex.RUnlock()

	session, exists := ac.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		ac.mutex.RUnlock()
		ac.mutex.Lock()
		delete(ac.sessions, sessionID)
		ac.mutex.Unlock()
		ac.mutex.RLock()
		return nil, fmt.Errorf("session expired")
	}

	// Update last access time
	ac.mutex.RUnlock()
	ac.mutex.Lock()
	session.LastAccess = time.Now()
	ac.mutex.Unlock()
	ac.mutex.RLock()

	return session, nil
}

// RevokeSession revokes a session
func (ac *AccessControl) RevokeSession(ctx context.Context, sessionID string) error {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	if _, exists := ac.sessions[sessionID]; !exists {
		return fmt.Errorf("session not found")
	}

	delete(ac.sessions, sessionID)
	return nil
}

// GetAccessStats returns access control statistics
func (ac *AccessControl) GetAccessStats() *AccessStats {
	ac.stats.mutex.RLock()
	defer ac.stats.mutex.RUnlock()

	// Update active sessions count
	ac.mutex.RLock()
	activeCount := int64(len(ac.sessions))
	ac.mutex.RUnlock()

	return &AccessStats{
		AuthenticationAttempts: ac.stats.AuthenticationAttempts,
		SuccessfulLogins:      ac.stats.SuccessfulLogins,
		FailedLogins:          ac.stats.FailedLogins,
		AuthorizationChecks:   ac.stats.AuthorizationChecks,
		AccessDenied:          ac.stats.AccessDenied,
		ActiveSessions:        activeCount,
		LastActivity:          ac.stats.LastActivity,
	}
}

// GetComplianceStatus returns compliance status for access control
func (ac *AccessControl) GetComplianceStatus() ComponentStatus {
	stats := ac.GetAccessStats()
	
	status := ComponentStatus{
		Status:      "compliant",
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"authentication_attempts": stats.AuthenticationAttempts,
			"successful_logins":      stats.SuccessfulLogins,
			"failed_logins":          stats.FailedLogins,
			"authorization_checks":   stats.AuthorizationChecks,
			"access_denied":          stats.AccessDenied,
			"active_sessions":        stats.ActiveSessions,
			"authentication_mode":    ac.config.AuthenticationMode,
			"authorization_mode":     ac.config.AuthorizationMode,
		},
		Issues: []string{},
	}

	// Check for compliance issues
	if stats.AuthenticationAttempts > 0 {
		failureRate := float64(stats.FailedLogins) / float64(stats.AuthenticationAttempts)
		if failureRate > 0.1 { // More than 10% failure rate
			status.Status = "warning"
			status.Issues = append(status.Issues, "High authentication failure rate detected")
		}
	}

	if stats.AuthorizationChecks > 0 {
		denialRate := float64(stats.AccessDenied) / float64(stats.AuthorizationChecks)
		if denialRate > 0.2 { // More than 20% denial rate
			status.Status = "warning"
			status.Issues = append(status.Issues, "High access denial rate detected")
		}
	}

	// Check session management
	if stats.ActiveSessions > int64(ac.config.MaxSessions*len(ac.roles)) {
		status.Status = "warning"
		status.Issues = append(status.Issues, "High number of active sessions")
	}

	return status
}

// Helper methods

func (ac *AccessControl) makeAccessDecision(request *AccessRequest) *AccessDecision {
	decision := &AccessDecision{
		Request:   request,
		Decision:  "deny",
		Reason:    "no matching policy",
		Timestamp: time.Now(),
	}

	// Check authorization based on mode
	switch ac.config.AuthorizationMode {
	case "rbac":
		return ac.evaluateRBAC(request)
	case "abac":
		return ac.evaluateABAC(request)
	case "acl":
		return ac.evaluateACL(request)
	default:
		decision.Reason = "unsupported authorization mode"
		return decision
	}
}

func (ac *AccessControl) evaluateRBAC(request *AccessRequest) *AccessDecision {
	decision := &AccessDecision{
		Request:   request,
		Decision:  "deny",
		Reason:    "no role permissions",
		Timestamp: time.Now(),
	}

	userRoles := ac.getUserRoles(request.Principal)
	
	for _, roleName := range userRoles {
		role, exists := ac.roles[roleName]
		if !exists {
			continue
		}

		// Check if role has permission for this action
		for _, permission := range role.Permissions {
			if ac.matchesPermission(permission, request.Action) {
				// Check if role has access to this resource
				for _, resource := range role.Resources {
					if ac.matchesResource(resource, request.Resource) {
						decision.Decision = "allow"
						decision.Reason = fmt.Sprintf("role %s has permission", roleName)
						decision.PolicyUsed = roleName
						return decision
					}
				}
			}
		}
	}

	return decision
}

func (ac *AccessControl) evaluateABAC(request *AccessRequest) *AccessDecision {
	decision := &AccessDecision{
		Request:   request,
		Decision:  "deny",
		Reason:    "no matching attribute policy",
		Timestamp: time.Now(),
	}

	// Evaluate policies in order
	for _, policy := range ac.policies {
		if ac.evaluatePolicy(policy, request) {
			decision.Decision = policy.Effect
			decision.Reason = fmt.Sprintf("policy %s matched", policy.Name)
			decision.PolicyUsed = policy.Name
			return decision
		}
	}

	return decision
}

func (ac *AccessControl) evaluateACL(request *AccessRequest) *AccessDecision {
	decision := &AccessDecision{
		Request:   request,
		Decision:  "deny",
		Reason:    "not in ACL",
		Timestamp: time.Now(),
	}

	// Simple ACL evaluation - check if principal has direct access
	for _, policy := range ac.policies {
		if policy.Principal == request.Principal || policy.Principal == "*" {
			if ac.matchesAction(policy.Actions, request.Action) && 
			   ac.matchesResource(policy.Resources[0], request.Resource) {
				decision.Decision = policy.Effect
				decision.Reason = fmt.Sprintf("ACL policy %s matched", policy.Name)
				decision.PolicyUsed = policy.Name
				return decision
			}
		}
	}

	return decision
}

func (ac *AccessControl) evaluatePolicy(policy *AccessPolicy, request *AccessRequest) bool {
	// Check principal
	if policy.Principal != "*" && policy.Principal != request.Principal {
		return false
	}

	// Check actions
	if !ac.matchesAction(policy.Actions, request.Action) {
		return false
	}

	// Check resources
	resourceMatched := false
	for _, resource := range policy.Resources {
		if ac.matchesResource(resource, request.Resource) {
			resourceMatched = true
			break
		}
	}
	if !resourceMatched {
		return false
	}

	// Check conditions
	for key, expectedValue := range policy.Conditions {
		if actualValue, exists := request.Context[key]; !exists || actualValue != expectedValue {
			return false
		}
	}

	return true
}

func (ac *AccessControl) matchesPermission(permission, action string) bool {
	return permission == "*" || permission == action || strings.HasPrefix(action, permission+":")
}

func (ac *AccessControl) matchesAction(actions []string, action string) bool {
	for _, policyAction := range actions {
		if policyAction == "*" || policyAction == action {
			return true
		}
	}
	return false
}

func (ac *AccessControl) matchesResource(pattern, resource string) bool {
	if pattern == "*" {
		return true
	}
	
	// Simple wildcard matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}
	
	return pattern == resource
}

func (ac *AccessControl) getUserRoles(principal string) []string {
	// In a real implementation, this would query a user directory
	// For now, return default roles based on principal
	if strings.HasPrefix(principal, "admin") {
		return []string{"admin"}
	}
	if strings.HasPrefix(principal, "operator") {
		return []string{"operator"}
	}
	return []string{"viewer"}
}

func (ac *AccessControl) validateBasicAuth(principal, credentials string) bool {
	// Placeholder for basic authentication validation
	// In production, this would validate against a secure credential store
	return credentials != ""
}

func (ac *AccessControl) validateOAuthToken(token string) bool {
	// Placeholder for OAuth token validation
	// In production, this would validate the token with the OAuth provider
	return strings.HasPrefix(token, "Bearer ")
}

func (ac *AccessControl) validateMTLS(clientInfo map[string]string) bool {
	// Placeholder for mTLS validation
	// In production, this would validate the client certificate
	return clientInfo["client_cert"] != ""
}

func (ac *AccessControl) generateSessionID() string {
	return fmt.Sprintf("session_%d_%d", time.Now().UnixNano(), len(ac.sessions))
}

func (ac *AccessControl) countUserSessions(principal string) int {
	count := 0
	for _, session := range ac.sessions {
		if session.Principal == principal {
			count++
		}
	}
	return count
}

func (ac *AccessControl) sessionCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ac.cleanupExpiredSessions()
		}
	}
}

func (ac *AccessControl) cleanupExpiredSessions() {
	ac.mutex.Lock()
	defer ac.mutex.Unlock()

	now := time.Now()
	for sessionID, session := range ac.sessions {
		if now.After(session.ExpiresAt) {
			delete(ac.sessions, sessionID)
		}
	}
}

func (ac *AccessControl) updateStats(auth, authFail, login, authz bool) {
	ac.stats.mutex.Lock()
	defer ac.stats.mutex.Unlock()

	if auth {
		ac.stats.AuthenticationAttempts++
	}
	if authFail {
		ac.stats.FailedLogins++
	}
	if login {
		ac.stats.SuccessfulLogins++
	}
	if authz {
		ac.stats.AuthorizationChecks++
	}
	
	ac.stats.LastActivity = time.Now()
}
