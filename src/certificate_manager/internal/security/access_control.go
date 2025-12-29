package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Errors
// ============================================================================

var (
	ErrAccessDenied          = errors.New("access denied")
	ErrUserNotFound          = errors.New("user not found")
	ErrInvalidRole           = errors.New("invalid role")
	ErrInactiveUser          = errors.New("user is inactive")
	ErrInvalidAPIKey         = errors.New("invalid API key")
	ErrUnauthorizedOperation = errors.New("unauthorized operation")
)

// ============================================================================
// Roles and Operations
// ============================================================================

// Role represents a user role.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access
	RoleOperator Role = "operator" // Can issue/renew certificates
	RoleViewer   Role = "viewer"   // Read-only access
	RoleService  Role = "service"  // Automated service access
)

// Operation represents a controlled operation.
// Note: Uses Op* constants from audit_logger.go for shared operations
// These are access-control specific operations.
const (
	ACOpModifyConfig  = "modify_config"
	ACOpViewAuditLog  = "view_audit_log"
	ACOpCreateBackup  = "create_backup"
	ACOpRestoreBackup = "restore_backup"
	ACOpViewStats     = "view_stats"
)

// ============================================================================
// Permissions
// ============================================================================

// Permissions defines allowed operations for a role.
type Permissions struct {
	CanIssueCertificate  bool `json:"can_issue_certificate"`
	CanRevokeCertificate bool `json:"can_revoke_certificate"`
	CanAccessCAKey       bool `json:"can_access_ca_key"`
	CanModifyConfig      bool `json:"can_modify_config"`
	CanViewAuditLog      bool `json:"can_view_audit_log"`
	CanCreateBackup      bool `json:"can_create_backup"`
	CanRestoreBackup     bool `json:"can_restore_backup"`
	CanRotatePassphrase  bool `json:"can_rotate_passphrase"`
	CanViewStats         bool `json:"can_view_stats"`
}

// DefaultPermissions defines default permissions for each role.
var DefaultPermissions = map[Role]Permissions{
	RoleAdmin: {
		CanIssueCertificate:  true,
		CanRevokeCertificate: true,
		CanAccessCAKey:       true,
		CanModifyConfig:      true,
		CanViewAuditLog:      true,
		CanCreateBackup:      true,
		CanRestoreBackup:     true,
		CanRotatePassphrase:  true,
		CanViewStats:         true,
	},
	RoleOperator: {
		CanIssueCertificate:  true,
		CanRevokeCertificate: false,
		CanAccessCAKey:       false,
		CanModifyConfig:      false,
		CanViewAuditLog:      true,
		CanCreateBackup:      false,
		CanRestoreBackup:     false,
		CanRotatePassphrase:  false,
		CanViewStats:         true,
	},
	RoleViewer: {
		CanIssueCertificate:  false,
		CanRevokeCertificate: false,
		CanAccessCAKey:       false,
		CanModifyConfig:      false,
		CanViewAuditLog:      true,
		CanCreateBackup:      false,
		CanRestoreBackup:     false,
		CanRotatePassphrase:  false,
		CanViewStats:         true,
	},
	RoleService: {
		CanIssueCertificate:  true,
		CanRevokeCertificate: false,
		CanAccessCAKey:       true,
		CanModifyConfig:      false,
		CanViewAuditLog:      false,
		CanCreateBackup:      false,
		CanRestoreBackup:     false,
		CanRotatePassphrase:  false,
		CanViewStats:         true,
	},
}

// ============================================================================
// User
// ============================================================================

// User represents a user with role-based permissions.
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastLogin time.Time `json:"last_login,omitempty"`
	Active    bool      `json:"active"`
}

// ============================================================================
// Service Account
// ============================================================================

// ServiceAccount represents an automated service account.
type ServiceAccount struct {
	Name              string    `json:"name"`
	APIKeyHash        string    `json:"api_key_hash"`
	Role              Role      `json:"role"`
	AllowedOperations []string  `json:"allowed_operations,omitempty"`
	AllowedIPRanges   []string  `json:"allowed_ip_ranges,omitempty"`
	Active            bool      `json:"active"`
	CreatedAt         time.Time `json:"created_at"`
}

// ============================================================================
// Access Controller
// ============================================================================

// AccessController manages role-based access control.
type AccessController struct {
	mu sync.RWMutex

	// User storage
	users map[string]*User // Key: username

	// Service accounts
	serviceAccounts map[string]*ServiceAccount // Key: name

	// API key to service account mapping
	apiKeyIndex map[string]string // Key: hash, Value: account name

	// Custom permissions
	customPermissions map[Role]Permissions

	// Audit logger (optional)
	auditLogger *AuditLogger

	// Statistics
	accessGrants   int64
	accessDenials  int64
	violationCount int64
}

// NewAccessController creates a new access controller.
func NewAccessController() *AccessController {
	return &AccessController{
		users:             make(map[string]*User),
		serviceAccounts:   make(map[string]*ServiceAccount),
		apiKeyIndex:       make(map[string]string),
		customPermissions: make(map[Role]Permissions),
	}
}

// SetAuditLogger sets the audit logger.
func (ac *AccessController) SetAuditLogger(logger *AuditLogger) {
	ac.auditLogger = logger
}

// ============================================================================
// User Management
// ============================================================================

// CreateUser creates a new user.
func (ac *AccessController) CreateUser(username string, role Role, email string) (*User, error) {
	if !isValidRole(role) {
		return nil, ErrInvalidRole
	}

	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := ac.users[username]; exists {
		return nil, fmt.Errorf("user already exists: %s", username)
	}

	user := &User{
		ID:        generateID(),
		Username:  username,
		Role:      role,
		Email:     email,
		CreatedAt: time.Now(),
		Active:    true,
	}

	ac.users[username] = user
	return user, nil
}

// GetUser retrieves a user by username.
func (ac *AccessController) GetUser(username string) (*User, error) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	user, exists := ac.users[username]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// UpdateUserRole changes a user's role.
func (ac *AccessController) UpdateUserRole(username string, newRole Role) error {
	if !isValidRole(newRole) {
		return ErrInvalidRole
	}

	ac.mu.Lock()
	defer ac.mu.Unlock()

	user, exists := ac.users[username]
	if !exists {
		return ErrUserNotFound
	}

	oldRole := user.Role
	user.Role = newRole

	// Log role change
	if ac.auditLogger != nil {
		ac.auditLogger.LogOperation("role_change", username, "system", true, map[string]interface{}{
			"old_role": string(oldRole),
			"new_role": string(newRole),
		})
	}

	return nil
}

// DeactivateUser deactivates a user.
func (ac *AccessController) DeactivateUser(username string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	user, exists := ac.users[username]
	if !exists {
		return ErrUserNotFound
	}

	user.Active = false
	return nil
}

// ============================================================================
// Permission Checking
// ============================================================================

// CheckPermission checks if a user has permission for an operation.
func (ac *AccessController) CheckPermission(username, operation string) (bool, error) {
	ac.mu.RLock()
	user, exists := ac.users[username]
	ac.mu.RUnlock()

	if !exists {
		atomic.AddInt64(&ac.accessDenials, 1)
		return false, ErrUserNotFound
	}

	if !user.Active {
		atomic.AddInt64(&ac.accessDenials, 1)
		atomic.AddInt64(&ac.violationCount, 1)
		ac.logViolation(username, operation, "inactive user")
		return false, ErrInactiveUser
	}

	allowed := ac.hasPermission(user.Role, operation)
	if !allowed {
		atomic.AddInt64(&ac.accessDenials, 1)
		atomic.AddInt64(&ac.violationCount, 1)
		ac.logViolation(username, operation, "insufficient permissions")
		return false, nil
	}

	atomic.AddInt64(&ac.accessGrants, 1)
	return true, nil
}

// hasPermission checks if a role has permission for an operation.
func (ac *AccessController) hasPermission(role Role, operation string) bool {
	// Check custom permissions first
	if perms, ok := ac.customPermissions[role]; ok {
		return checkPermissionFlag(perms, operation)
	}

	// Fall back to default permissions
	if perms, ok := DefaultPermissions[role]; ok {
		return checkPermissionFlag(perms, operation)
	}

	return false
}

// checkPermissionFlag checks a specific permission flag.
func checkPermissionFlag(perms Permissions, operation string) bool {
	switch operation {
	case OpIssueCertificate:
		return perms.CanIssueCertificate
	case OpRevokeCertificate:
		return perms.CanRevokeCertificate
	case OpAccessCAKey:
		return perms.CanAccessCAKey
	case ACOpModifyConfig:
		return perms.CanModifyConfig
	case ACOpViewAuditLog:
		return perms.CanViewAuditLog
	case ACOpCreateBackup:
		return perms.CanCreateBackup
	case ACOpRestoreBackup:
		return perms.CanRestoreBackup
	case OpRotatePassphrase:
		return perms.CanRotatePassphrase
	case ACOpViewStats:
		return perms.CanViewStats
	default:
		return false
	}
}

// ============================================================================
// Service Account Management
// ============================================================================

// CreateServiceAccount creates a new service account.
func (ac *AccessController) CreateServiceAccount(name string, apiKey string, allowedIPs []string) (*ServiceAccount, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if _, exists := ac.serviceAccounts[name]; exists {
		return nil, fmt.Errorf("service account already exists: %s", name)
	}

	apiKeyHash := hashAPIKey(apiKey)

	account := &ServiceAccount{
		Name:            name,
		APIKeyHash:      apiKeyHash,
		Role:            RoleService,
		AllowedIPRanges: allowedIPs,
		Active:          true,
		CreatedAt:       time.Now(),
	}

	ac.serviceAccounts[name] = account
	ac.apiKeyIndex[apiKeyHash] = name

	return account, nil
}

// AuthenticateServiceAccount authenticates a service account by API key.
func (ac *AccessController) AuthenticateServiceAccount(apiKey, sourceIP string) (*ServiceAccount, error) {
	apiKeyHash := hashAPIKey(apiKey)

	ac.mu.RLock()
	accountName, exists := ac.apiKeyIndex[apiKeyHash]
	if !exists {
		ac.mu.RUnlock()
		atomic.AddInt64(&ac.accessDenials, 1)
		return nil, ErrInvalidAPIKey
	}

	account := ac.serviceAccounts[accountName]
	ac.mu.RUnlock()

	if account == nil || !account.Active {
		atomic.AddInt64(&ac.accessDenials, 1)
		return nil, ErrInvalidAPIKey
	}

	// Check IP restrictions
	if len(account.AllowedIPRanges) > 0 {
		if !ac.isIPAllowed(sourceIP, account.AllowedIPRanges) {
			atomic.AddInt64(&ac.accessDenials, 1)
			ac.logViolation(account.Name, "authenticate", "IP not allowed: "+sourceIP)
			return nil, ErrAccessDenied
		}
	}

	atomic.AddInt64(&ac.accessGrants, 1)
	return account, nil
}

// isIPAllowed checks if an IP is in the allowed ranges.
func (ac *AccessController) isIPAllowed(sourceIP string, allowedRanges []string) bool {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		// Try parsing IP:port format
		host, _, err := net.SplitHostPort(sourceIP)
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}

	for _, rangeStr := range allowedRanges {
		// Check if it's a single IP or CIDR
		if !containsSlash(rangeStr) {
			if rangeStr == ip.String() {
				return true
			}
			continue
		}

		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// ============================================================================
// Violation Logging
// ============================================================================

// logViolation logs an access violation.
func (ac *AccessController) logViolation(subject, operation, reason string) {
	if ac.auditLogger != nil {
		ac.auditLogger.LogAccessDenied(operation, subject, reason)
	}
}

// ============================================================================
// Statistics
// ============================================================================

// AccessControlStats contains access control statistics.
type AccessControlStats struct {
	UserCount           int   `json:"user_count"`
	ServiceAccountCount int   `json:"service_account_count"`
	AccessGrants        int64 `json:"access_grants"`
	AccessDenials       int64 `json:"access_denials"`
	ViolationCount      int64 `json:"violation_count"`
}

// GetStats returns access control statistics.
func (ac *AccessController) GetStats() *AccessControlStats {
	ac.mu.RLock()
	userCount := len(ac.users)
	serviceCount := len(ac.serviceAccounts)
	ac.mu.RUnlock()

	return &AccessControlStats{
		UserCount:           userCount,
		ServiceAccountCount: serviceCount,
		AccessGrants:        atomic.LoadInt64(&ac.accessGrants),
		AccessDenials:       atomic.LoadInt64(&ac.accessDenials),
		ViolationCount:      atomic.LoadInt64(&ac.violationCount),
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// isValidRole checks if a role is valid.
func isValidRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleOperator, RoleViewer, RoleService:
		return true
	default:
		return false
	}
}

// hashAPIKey creates a SHA-256 hash of an API key.
func hashAPIKey(apiKey string) string {
	hash := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(hash[:])
}

// generateID generates a unique ID.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// containsSlash checks if a string contains a slash.
func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

// ============================================================================
// Role Information
// ============================================================================

// GetRolePermissions returns the permissions for a role.
func GetRolePermissions(role Role) (Permissions, bool) {
	perms, ok := DefaultPermissions[role]
	return perms, ok
}

// GetAllRoles returns all defined roles.
func GetAllRoles() []Role {
	return []Role{RoleAdmin, RoleOperator, RoleViewer, RoleService}
}

// GetAllOperations returns all defined operations.
func GetAllOperations() []string {
	return []string{
		OpIssueCertificate,
		OpRevokeCertificate,
		OpAccessCAKey,
		ACOpModifyConfig,
		ACOpViewAuditLog,
		ACOpCreateBackup,
		ACOpRestoreBackup,
		OpRotatePassphrase,
		ACOpViewStats,
	}
}
