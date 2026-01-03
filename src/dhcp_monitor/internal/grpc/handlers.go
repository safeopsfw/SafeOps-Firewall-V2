// Package grpc provides gRPC handler utilities and validation helpers
package grpc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"dhcp_monitor/internal/database"
	"dhcp_monitor/internal/manager"
	gen "dhcp_monitor/proto/gen"
)

// =============================================================================
// DHCP MONITOR SERVICE HANDLER
// =============================================================================

// DHCPMonitorServiceHandler provides validation and utility functions for gRPC handlers
type DHCPMonitorServiceHandler struct {
	manager *manager.DeviceManager
}

// NewDHCPMonitorServiceHandler creates a new service handler
func NewDHCPMonitorServiceHandler(mgr *manager.DeviceManager) *DHCPMonitorServiceHandler {
	return &DHCPMonitorServiceHandler{
		manager: mgr,
	}
}

// GetManager returns the device manager
func (h *DHCPMonitorServiceHandler) GetManager() *manager.DeviceManager {
	return h.manager
}

// =============================================================================
// REQUEST VALIDATION HELPERS
// =============================================================================

// ValidateIPAddress validates IP address format
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return status.Error(codes.InvalidArgument, "IP address is required")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid IP address format: %s", ip))
	}

	return nil
}

// ValidateMACAddress validates MAC address format
func ValidateMACAddress(mac string) error {
	if mac == "" {
		return status.Error(codes.InvalidArgument, "MAC address is required")
	}

	// MAC format: AA:BB:CC:DD:EE:FF (case-insensitive)
	macRegex := regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	if !macRegex.MatchString(mac) {
		return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid MAC address format: %s", mac))
	}

	return nil
}

// ValidateDeviceID validates and parses device UUID
func ValidateDeviceID(id string) (uuid.UUID, error) {
	if id == "" {
		return uuid.Nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	deviceID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid device ID format: %s", id))
	}

	return deviceID, nil
}

// ValidateTrustStatus validates trust status value
func ValidateTrustStatus(trustStatus string) error {
	switch strings.ToUpper(trustStatus) {
	case "UNTRUSTED", "TRUSTED", "BLOCKED":
		return nil
	default:
		return status.Error(codes.InvalidArgument, fmt.Sprintf("invalid trust status: %s", trustStatus))
	}
}

// NormalizeMACAddress normalizes MAC address to uppercase with colons
func NormalizeMACAddress(mac string) string {
	// Remove any existing separators
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, ".", "")

	// Convert to uppercase
	mac = strings.ToUpper(mac)

	// Add colons
	if len(mac) != 12 {
		return mac // Return as-is if invalid length
	}

	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])
}

// =============================================================================
// ERROR MAPPING HELPERS
// =============================================================================

// MapError converts internal errors to gRPC status errors
func MapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if errors.Is(err, sql.ErrNoRows) {
		return status.Error(codes.NotFound, "device not found")
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request timeout")
	}

	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "request cancelled")
	}

	// Check if already a gRPC status error
	if _, ok := status.FromError(err); ok {
		return err
	}

	// Log the actual error internally
	log.Printf("[GRPC_HANDLER] Internal error: %v", err)

	// Return sanitized error
	return status.Error(codes.Internal, "internal server error")
}

// MapNotFoundError creates a NotFound status error
func MapNotFoundError(resourceType, identifier string) error {
	return status.Error(codes.NotFound, fmt.Sprintf("%s not found: %s", resourceType, identifier))
}

// MapValidationError creates an InvalidArgument status error
func MapValidationError(message string) error {
	return status.Error(codes.InvalidArgument, message)
}

// =============================================================================
// TRUST STATUS CONVERSION
// =============================================================================

// TrustStatusToString converts protobuf trust status string to database format
func TrustStatusToString(protoStatus string) string {
	return strings.ToUpper(protoStatus)
}

// TrustStatusToProto converts database trust status to protobuf format
func TrustStatusToProto(dbStatus database.TrustStatus) string {
	return string(dbStatus)
}

// =============================================================================
// FILTER CONVERSION
// =============================================================================

// ConvertListDevicesFilter converts protobuf request to database filter
func ConvertListDevicesFilter(req *gen.ListDevicesRequest) *database.DeviceFilter {
	filter := &database.DeviceFilter{
		TrustStatus:   req.GetFilterByTrust(),
		OnlineOnly:    req.GetOnlineOnly(),
		InterfaceName: req.GetInterfaceName(),
		Limit:         req.GetLimit(),
		Offset:        req.GetOffset(),
	}

	// Apply defaults
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000 // Cap at 1000
	}

	return filter
}

// =============================================================================
// RESPONSE CONVERSION
// =============================================================================

// DevicesToProto converts slice of database devices to protobuf
func DevicesToProto(devices []*database.Device) []*gen.Device {
	protoDevices := make([]*gen.Device, len(devices))
	for i, d := range devices {
		protoDevices[i] = d.ToProto()
	}
	return protoDevices
}

// DeviceStatsToProto converts database stats to protobuf
func DeviceStatsToProto(stats *database.DeviceStats) *gen.DeviceStats {
	return &gen.DeviceStats{
		TotalDevices:     stats.TotalDevices,
		OnlineDevices:    stats.OnlineDevices,
		TrustedDevices:   stats.TrustedDevices,
		UntrustedDevices: stats.UntrustedDevices,
		BlockedDevices:   stats.BlockedDevices,
	}
}

// =============================================================================
// LOGGING HELPERS
// =============================================================================

// LogRPC logs an RPC call with method, request summary, latency, and error status
func LogRPC(method string, requestSummary string, latency time.Duration, err error) {
	statusStr := "OK"
	if err != nil {
		if st, ok := status.FromError(err); ok {
			statusStr = st.Code().String()
		} else {
			statusStr = "ERROR"
		}
	}

	log.Printf("[GRPC_HANDLER] %s %s latency=%v status=%s",
		method, requestSummary, latency, statusStr)
}

// LogRPCStart logs the start of an RPC call and returns the start time
func LogRPCStart(method string) time.Time {
	return time.Now()
}

// LogRPCEnd logs the completion of an RPC call
func LogRPCEnd(method string, startTime time.Time, requestSummary string, err error) {
	LogRPC(method, requestSummary, time.Since(startTime), err)
}

// =============================================================================
// CONTEXT HELPERS
// =============================================================================

// ExtractClientInfo extracts client information from context (for logging/audit)
func ExtractClientInfo(ctx context.Context) string {
	// TODO: Extract from gRPC peer info when TLS is enabled
	return "unknown"
}

// CreateTimeoutContext creates a context with timeout for database operations
func CreateTimeoutContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// =============================================================================
// AUDIT LOGGING
// =============================================================================

// LogTrustStatusChange logs a trust status change for audit purposes
func LogTrustStatusChange(deviceID uuid.UUID, mac string, oldStatus, newStatus string, clientInfo string) {
	log.Printf("[AUDIT] Trust status changed: device_id=%s mac=%s old_status=%s new_status=%s client=%s",
		deviceID.String(), mac, oldStatus, newStatus, clientInfo)
}

// LogDeviceCreated logs a new device creation for audit purposes
func LogDeviceCreated(deviceID uuid.UUID, mac string, ip string, interfaceName string) {
	log.Printf("[AUDIT] Device created: device_id=%s mac=%s ip=%s interface=%s",
		deviceID.String(), mac, ip, interfaceName)
}

// LogDeviceDeleted logs a device deletion for audit purposes
func LogDeviceDeleted(deviceID uuid.UUID, mac string, reason string) {
	log.Printf("[AUDIT] Device deleted: device_id=%s mac=%s reason=%s",
		deviceID.String(), mac, reason)
}
