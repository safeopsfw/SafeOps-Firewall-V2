// Package distribution provides installation reporting API.
// This handles callbacks from devices after CA certificate installation.
package distribution

import (
	"encoding/json"
	"net/http"
	"time"
)

// ============================================================================
// Installation Report Structure
// ============================================================================

// InstallationReport contains device installation status.
type InstallationReport struct {
	MACAddress            string    `json:"mac_address"`
	IPAddress             string    `json:"ip_address"`
	Hostname              string    `json:"hostname"`
	OS                    string    `json:"os"`
	CertificateThumbprint string    `json:"certificate_thumbprint"`
	InstallationStatus    string    `json:"installation_status"` // success, failed, already_installed
	InstallationMethod    string    `json:"installation_method"` // auto-powershell, auto-bash, manual, mdm
	Timestamp             time.Time `json:"timestamp"`
	Message               string    `json:"message"`
}

// ============================================================================
// Installation Report Handler
// ============================================================================

// HandleInstallationReport handles POST /api/report from devices.
func (h *Handlers) HandleInstallationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var report InstallationReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate report
	if report.MACAddress == "" || report.IPAddress == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Get client IP from request
	clientIP := h.getClientIP(r)

	// Log installation report
	h.logInstallationReport(&report, clientIP)

	// Store in database (if storage is available)
	if err := h.storeInstallationReport(&report); err != nil {
		// Log error but don't fail the request
		h.logError("Failed to store installation report", err)
	}

	// Send success response
	response := map[string]interface{}{
		"status":  "success",
		"message": "Installation report received",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ============================================================================
// Device Status Query Handler
// ============================================================================

// HandleDeviceStatus handles GET /api/device-status?mac=XX:XX:XX:XX:XX:XX
func (h *Handlers) HandleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	macAddr := r.URL.Query().Get("mac")
	if macAddr == "" {
		http.Error(w, "Missing MAC address parameter", http.StatusBadRequest)
		return
	}

	// Query device status from database
	status, err := h.getDeviceStatus(macAddr)
	if err != nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// ============================================================================
// Helper Methods
// ============================================================================

func (h *Handlers) logInstallationReport(report *InstallationReport, clientIP string) {
	// Log to console/file
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	status := "SUCCESS"
	if report.InstallationStatus != "success" && report.InstallationStatus != "already_installed" {
		status = "FAILED"
	}

	logMessage := "[" + timestamp + "] [INSTALLATION] [" + status + "] " +
		"MAC=" + report.MACAddress +
		" IP=" + report.IPAddress +
		" Host=" + report.Hostname +
		" OS=" + report.OS +
		" Method=" + report.InstallationMethod +
		" Status=" + report.InstallationStatus +
		" Message=" + report.Message

	// Would use proper logger in production
	println(logMessage)
}

func (h *Handlers) storeInstallationReport(report *InstallationReport) error {
	// In production, this would:
	// 1. Insert into device_ca_status table
	// 2. Update device compliance status
	// 3. Notify other services (firewall, TLS proxy)
	// 4. Update metrics/statistics

	// Track installation via download tracker metrics
	if h.tracker != nil {
		// Create a download event for tracking
		event := &DownloadEvent{
			Timestamp:  time.Now(),
			DeviceIP:   report.IPAddress,
			MACAddress: report.MACAddress,
			Format:     "installation",
			UserAgent:  report.OS,
			StatusCode: 200,
		}
		h.tracker.TrackDownload(event)
	}

	return nil
}

func (h *Handlers) getDeviceStatus(macAddr string) (interface{}, error) {
	// In production, query from database
	// For now, return mock data

	return map[string]interface{}{
		"mac_address":   macAddr,
		"ca_installed":  true,
		"trust_status":  "trusted",
		"last_verified": time.Now().Format(time.RFC3339),
	}, nil
}

// Note: getClientIP is defined in handlers.go, reuse that implementation

func (h *Handlers) logError(message string, err error) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	println("[" + timestamp + "] [ERROR] " + message + ": " + err.Error())
}

// ============================================================================
// Registration (called from http_server.go)
// ============================================================================

// RegisterAPIRoutes registers API routes to the mux.
func (h *Handlers) RegisterAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/report", h.HandleInstallationReport)
	mux.HandleFunc("/api/device-status", h.HandleDeviceStatus)
}
