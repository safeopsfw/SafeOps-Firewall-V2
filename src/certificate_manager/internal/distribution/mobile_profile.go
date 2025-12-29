package distribution

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// Configuration Types
// ============================================================================

// MobileProfileConfig contains configuration for mobile profile generation.
type MobileProfileConfig struct {
	OrganizationName string // Organization name displayed in profile
	DisplayName      string // User-friendly display name
	Description      string // Profile description
	CertificateName  string // Certificate filename
	BaseURL          string // Base URL for HTTP server
	SignProfile      bool   // Whether to sign the profile (iOS)
	ConsentText      string // Legal/informational text shown before installation
}

// ProfileMetadata contains metadata about a generated profile.
type ProfileMetadata struct {
	ProfileUUID     string    `json:"profile_uuid"`
	PayloadUUID     string    `json:"payload_uuid"`
	Version         int       `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	CertFingerprint string    `json:"cert_fingerprint"`
	Platform        string    `json:"platform"`
	CompatibleOS    string    `json:"compatible_os"`
	IsSigned        bool      `json:"is_signed"`
}

// ============================================================================
// Error Types
// ============================================================================

var (
	ErrEmptyOrganization  = errors.New("organization name cannot be empty")
	ErrEmptyDisplayName   = errors.New("display name cannot be empty")
	ErrNoCertificateData  = errors.New("certificate data cannot be empty")
	ErrCertificateExpired = errors.New("certificate has expired")
	ErrProfileGeneration  = errors.New("profile generation failed")
)

// ============================================================================
// iOS Configuration Profile Template
// ============================================================================

const iosMobileconfigTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>{{.CertificateFileName}}</string>
            <key>PayloadContent</key>
            <data>{{.CertificateDataBase64}}</data>
            <key>PayloadDescription</key>
            <string>{{.PayloadDescription}}</string>
            <key>PayloadDisplayName</key>
            <string>{{.CertificateDisplayName}}</string>
            <key>PayloadIdentifier</key>
            <string>{{.PayloadIdentifier}}</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{{.PayloadUUID}}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>{{.ProfileDescription}}</string>
    <key>PayloadDisplayName</key>
    <string>{{.ProfileDisplayName}}</string>
    <key>PayloadIdentifier</key>
    <string>{{.ProfileIdentifier}}</string>
    <key>PayloadOrganization</key>
    <string>{{.OrganizationName}}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{{.ProfileUUID}}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    {{if .ConsentText}}
    <key>ConsentText</key>
    <dict>
        <key>default</key>
        <string>{{.ConsentText}}</string>
    </dict>
    {{end}}
</dict>
</plist>
`

// ============================================================================
// iOS Profile Generation
// ============================================================================

// iOSProfileData contains data for iOS mobileconfig template rendering.
type iOSProfileData struct {
	CertificateFileName    string
	CertificateDataBase64  string
	CertificateDisplayName string
	PayloadDescription     string
	PayloadIdentifier      string
	PayloadUUID            string
	ProfileDescription     string
	ProfileDisplayName     string
	ProfileIdentifier      string
	ProfileUUID            string
	OrganizationName       string
	ConsentText            string
}

// GenerateiOSProfile generates an iOS/iPadOS .mobileconfig configuration profile.
// The profile embeds the root CA certificate in Base64 DER format.
func GenerateiOSProfile(certPEM []byte, config *MobileProfileConfig) ([]byte, *ProfileMetadata, error) {
	if err := validateMobileProfileConfig(config); err != nil {
		return nil, nil, fmt.Errorf("GenerateiOSProfile: %w", err)
	}

	if len(certPEM) == 0 {
		return nil, nil, ErrNoCertificateData
	}

	// Convert PEM to DER
	derBytes, err := PEMToDER(certPEM)
	if err != nil {
		// Maybe it's already DER format
		derBytes = certPEM
		if _, parseErr := x509.ParseCertificate(derBytes); parseErr != nil {
			return nil, nil, fmt.Errorf("GenerateiOSProfile: invalid certificate: %w", err)
		}
	}

	// Parse certificate to validate and extract info
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateiOSProfile: %w", err)
	}

	// Check certificate validity
	if time.Now().After(cert.NotAfter) {
		return nil, nil, ErrCertificateExpired
	}

	// Generate UUIDs
	profileUUID := uuid.New().String()
	payloadUUID := uuid.New().String()

	// Calculate fingerprint
	fingerprint := calculateFingerprint(derBytes)

	// Prepare template data
	data := &iOSProfileData{
		CertificateFileName:    sanitizeFilename(config.CertificateName) + ".crt",
		CertificateDataBase64:  base64.StdEncoding.EncodeToString(derBytes),
		CertificateDisplayName: config.DisplayName,
		PayloadDescription:     fmt.Sprintf("Root CA certificate for %s", config.OrganizationName),
		PayloadIdentifier:      fmt.Sprintf("com.safeops.ca-cert.%s", strings.ToLower(payloadUUID[:8])),
		PayloadUUID:            payloadUUID,
		ProfileDescription:     config.Description,
		ProfileDisplayName:     config.DisplayName,
		ProfileIdentifier:      fmt.Sprintf("com.safeops.profile.%s", strings.ToLower(profileUUID[:8])),
		ProfileUUID:            profileUUID,
		OrganizationName:       config.OrganizationName,
		ConsentText:            config.ConsentText,
	}

	// Render template
	tmpl, err := template.New("mobileconfig").Parse(iosMobileconfigTemplate)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateiOSProfile: template parse: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, nil, fmt.Errorf("GenerateiOSProfile: template execute: %w", err)
	}

	// Create metadata
	metadata := &ProfileMetadata{
		ProfileUUID:     profileUUID,
		PayloadUUID:     payloadUUID,
		Version:         1,
		CreatedAt:       time.Now(),
		ExpiresAt:       cert.NotAfter,
		CertFingerprint: fingerprint,
		Platform:        "iOS",
		CompatibleOS:    "iOS 12.0+, iPadOS 13.0+",
		IsSigned:        false, // Signing would require PKCS#7 implementation
	}

	return buf.Bytes(), metadata, nil
}

// ============================================================================
// Android Profile Generation
// ============================================================================

// AndroidProfileType represents the type of Android profile to generate.
type AndroidProfileType string

const (
	AndroidProfileSimple     AndroidProfileType = "simple"     // Direct .crt download
	AndroidProfileEnterprise AndroidProfileType = "enterprise" // Android Enterprise/Work Profile
)

// GenerateAndroidProfile generates an Android-compatible certificate file.
// For simple mode, returns the certificate in DER format ready for installation.
// For enterprise mode, returns a JSON configuration for MDM deployment.
func GenerateAndroidProfile(certPEM []byte, config *MobileProfileConfig, profileType AndroidProfileType) ([]byte, *ProfileMetadata, error) {
	if err := validateMobileProfileConfig(config); err != nil {
		return nil, nil, fmt.Errorf("GenerateAndroidProfile: %w", err)
	}

	if len(certPEM) == 0 {
		return nil, nil, ErrNoCertificateData
	}

	// Convert PEM to DER
	derBytes, err := PEMToDER(certPEM)
	if err != nil {
		// Maybe it's already DER format
		derBytes = certPEM
		if _, parseErr := x509.ParseCertificate(derBytes); parseErr != nil {
			return nil, nil, fmt.Errorf("GenerateAndroidProfile: invalid certificate: %w", err)
		}
	}

	// Parse certificate to validate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("GenerateAndroidProfile: %w", err)
	}

	// Check certificate validity
	if time.Now().After(cert.NotAfter) {
		return nil, nil, ErrCertificateExpired
	}

	// Calculate fingerprint
	fingerprint := calculateFingerprint(derBytes)
	profileUUID := uuid.New().String()

	// Create metadata
	metadata := &ProfileMetadata{
		ProfileUUID:     profileUUID,
		PayloadUUID:     profileUUID,
		Version:         1,
		CreatedAt:       time.Now(),
		ExpiresAt:       cert.NotAfter,
		CertFingerprint: fingerprint,
		Platform:        "Android",
		CompatibleOS:    "Android 8.0+",
		IsSigned:        false,
	}

	switch profileType {
	case AndroidProfileSimple:
		// Return DER certificate directly
		return derBytes, metadata, nil

	case AndroidProfileEnterprise:
		// Generate Android Enterprise configuration JSON
		enterpriseConfig := generateAndroidEnterpriseConfig(derBytes, config, fingerprint)
		return []byte(enterpriseConfig), metadata, nil

	default:
		// Default to simple mode
		return derBytes, metadata, nil
	}
}

// generateAndroidEnterpriseConfig generates a JSON configuration for Android Enterprise.
func generateAndroidEnterpriseConfig(derBytes []byte, config *MobileProfileConfig, fingerprint string) string {
	certBase64 := base64.StdEncoding.EncodeToString(derBytes)

	return fmt.Sprintf(`{
    "kind": "Configuration",
    "name": "%s",
    "description": "%s",
    "organization": "%s",
    "certificatePolicy": {
        "trustedRootCertificates": [
            {
                "displayName": "%s",
                "certificateData": "%s",
                "fingerprint": "%s",
                "format": "DER"
            }
        ]
    },
    "metadata": {
        "version": 1,
        "compatibleAndroidVersion": "8.0+",
        "createdAt": "%s"
    }
}`, config.DisplayName, config.Description, config.OrganizationName,
		config.CertificateName, certBase64, fingerprint, time.Now().Format(time.RFC3339))
}

// ============================================================================
// Android Installation Instructions
// ============================================================================

const androidInstructionsTemplate = `SafeOps Root CA Installation Instructions for Android
======================================================
Organization: {{.Organization}}

Step 1: Download the Certificate
--------------------------------
Download the CA certificate from:
{{.DownloadURL}}

Step 2: Install Certificate
---------------------------
1. Open Settings
2. Navigate to: Security > Encryption & credentials
   (Location varies by Android version and manufacturer)
3. Tap "Install a certificate" or "Install from storage"
4. Select "CA certificate"
5. Locate and select the downloaded file

Step 3: Verify Installation
---------------------------
1. Go to Settings > Security > Encryption & credentials
2. Tap "Trusted credentials" or "User credentials"
3. You should see "{{.CertificateName}}" in the list

{{if .Fingerprint}}
Certificate Fingerprint (SHA-256):
{{.Fingerprint}}
{{end}}

Note for Enterprise Devices:
If your device is managed by your organization, the CA certificate
may be automatically installed via MDM policy.

For assistance, contact your IT administrator.
`

// GenerateAndroidInstructions generates installation instructions for Android.
func GenerateAndroidInstructions(config *MobileProfileConfig, fingerprint string) (string, error) {
	if err := validateMobileProfileConfig(config); err != nil {
		return "", fmt.Errorf("GenerateAndroidInstructions: %w", err)
	}

	data := struct {
		Organization    string
		DownloadURL     string
		CertificateName string
		Fingerprint     string
	}{
		Organization:    config.OrganizationName,
		DownloadURL:     config.BaseURL + "/ca.crt",
		CertificateName: config.DisplayName,
		Fingerprint:     fingerprint,
	}

	tmpl, err := template.New("android-instructions").Parse(androidInstructionsTemplate)
	if err != nil {
		return "", fmt.Errorf("GenerateAndroidInstructions: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("GenerateAndroidInstructions: %w", err)
	}

	return buf.String(), nil
}

// ============================================================================
// iOS Installation Instructions
// ============================================================================

const iosInstructionsTemplate = `SafeOps Root CA Installation Instructions for iOS/iPadOS
========================================================
Organization: {{.Organization}}

Step 1: Download the Configuration Profile
------------------------------------------
Open Safari and navigate to:
{{.DownloadURL}}

(Note: Must use Safari - other browsers won't trigger profile installation)

Step 2: Review and Install Profile
----------------------------------
1. A popup will appear: "This website is trying to download a configuration profile"
2. Tap "Allow"
3. Go to Settings > General > VPN & Device Management
4. Tap the downloaded profile "{{.ProfileName}}"
5. Tap "Install" in the top right
6. Enter your device passcode if prompted
7. Tap "Install" again to confirm

Step 3: Enable Full Trust (Required)
-----------------------------------
1. Go to Settings > General > About
2. Scroll down and tap "Certificate Trust Settings"
3. Find "{{.CertificateName}}" under "Enable Full Trust"
4. Toggle the switch ON
5. Tap "Continue" in the warning dialog

{{if .Fingerprint}}
Certificate Fingerprint (SHA-256):
{{.Fingerprint}}
{{end}}

Important Notes:
- You MUST complete Step 3 for HTTPS inspection to work
- The profile can be removed from:
  Settings > General > VPN & Device Management

For assistance, contact your IT administrator.
`

// GenerateiOSInstructions generates installation instructions for iOS.
func GenerateiOSInstructions(config *MobileProfileConfig, fingerprint string) (string, error) {
	if err := validateMobileProfileConfig(config); err != nil {
		return "", fmt.Errorf("GenerateiOSInstructions: %w", err)
	}

	data := struct {
		Organization    string
		DownloadURL     string
		ProfileName     string
		CertificateName string
		Fingerprint     string
	}{
		Organization:    config.OrganizationName,
		DownloadURL:     config.BaseURL + "/ca.mobileconfig",
		ProfileName:     config.DisplayName,
		CertificateName: config.CertificateName,
		Fingerprint:     fingerprint,
	}

	tmpl, err := template.New("ios-instructions").Parse(iosInstructionsTemplate)
	if err != nil {
		return "", fmt.Errorf("GenerateiOSInstructions: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("GenerateiOSInstructions: %w", err)
	}

	return buf.String(), nil
}

// ============================================================================
// Content Types and File Extensions
// ============================================================================

// MobileProfileContentTypes returns MIME content types for mobile profiles.
func MobileProfileContentTypes() map[string]string {
	return map[string]string{
		"ios":                  "application/x-apple-aspen-config",
		"android":              "application/x-x509-ca-cert",
		"android-enterprise":   "application/json",
		"ios-instructions":     "text/plain",
		"android-instructions": "text/plain",
	}
}

// MobileProfileFileExtensions returns file extensions for mobile profiles.
func MobileProfileFileExtensions() map[string]string {
	return map[string]string{
		"ios":                  ".mobileconfig",
		"android":              ".crt",
		"android-enterprise":   ".json",
		"ios-instructions":     ".txt",
		"android-instructions": ".txt",
	}
}

// ============================================================================
// User-Agent Detection
// ============================================================================

// MobileDeviceType represents detected mobile device type.
type MobileDeviceType string

const (
	DeviceTypeUnknown MobileDeviceType = "unknown"
	DeviceTypeiOS     MobileDeviceType = "ios"
	DeviceTypeiPadOS  MobileDeviceType = "ipados"
	DeviceTypeAndroid MobileDeviceType = "android"
	DeviceTypeDesktop MobileDeviceType = "desktop"
)

// DetectMobileDevice detects the mobile device type from User-Agent string.
func DetectMobileDevice(userAgent string) MobileDeviceType {
	ua := strings.ToLower(userAgent)

	// Check for iOS devices
	if strings.Contains(ua, "iphone") {
		return DeviceTypeiOS
	}
	if strings.Contains(ua, "ipad") {
		return DeviceTypeiPadOS
	}
	// iPod touch
	if strings.Contains(ua, "ipod") {
		return DeviceTypeiOS
	}

	// Check for Android devices
	if strings.Contains(ua, "android") {
		return DeviceTypeAndroid
	}

	// Check for macOS/Windows/Linux desktops
	if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		return DeviceTypeDesktop
	}
	if strings.Contains(ua, "windows") {
		return DeviceTypeDesktop
	}
	if strings.Contains(ua, "linux") && !strings.Contains(ua, "android") {
		return DeviceTypeDesktop
	}

	return DeviceTypeUnknown
}

// IsAppleDevice returns true if the device is an Apple mobile device.
func IsAppleDevice(deviceType MobileDeviceType) bool {
	return deviceType == DeviceTypeiOS || deviceType == DeviceTypeiPadOS
}

// ============================================================================
// Validation and Utilities
// ============================================================================

// validateMobileProfileConfig validates the profile configuration.
func validateMobileProfileConfig(config *MobileProfileConfig) error {
	if config == nil {
		return errors.New("config cannot be nil")
	}
	if strings.TrimSpace(config.OrganizationName) == "" {
		return ErrEmptyOrganization
	}
	if strings.TrimSpace(config.DisplayName) == "" {
		return ErrEmptyDisplayName
	}
	return nil
}

// calculateFingerprint calculates SHA-256 fingerprint of certificate.
func calculateFingerprint(derBytes []byte) string {
	hash := sha256.Sum256(derBytes)
	hexStr := hex.EncodeToString(hash[:])

	// Format as colon-separated hex
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		end := i + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, strings.ToUpper(hexStr[i:end]))
	}

	return strings.Join(parts, ":")
}

// sanitizeFilename removes unsafe characters from filename.
func sanitizeFilename(name string) string {
	// Replace spaces and special characters
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, "\\", "-")
	name = strings.ReplaceAll(name, ":", "-")
	name = strings.ReplaceAll(name, "*", "")
	name = strings.ReplaceAll(name, "?", "")
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "<", "")
	name = strings.ReplaceAll(name, ">", "")
	name = strings.ReplaceAll(name, "|", "")
	return strings.ToLower(name)
}

// ============================================================================
// Profile Configuration Builder
// ============================================================================

// NewMobileProfileConfig creates a new MobileProfileConfig with default values.
func NewMobileProfileConfig(baseURL string) *MobileProfileConfig {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &MobileProfileConfig{
		OrganizationName: "SafeOps",
		DisplayName:      "SafeOps Root CA",
		Description:      "Installs the SafeOps Root CA certificate to enable secure network access.",
		CertificateName:  "SafeOps Root CA",
		BaseURL:          baseURL,
		SignProfile:      false,
		ConsentText:      "",
	}
}

// WithOrganization sets the organization name.
func (c *MobileProfileConfig) WithOrganization(org string) *MobileProfileConfig {
	c.OrganizationName = org
	return c
}

// WithDisplayName sets the display name.
func (c *MobileProfileConfig) WithDisplayName(name string) *MobileProfileConfig {
	c.DisplayName = name
	return c
}

// WithDescription sets the profile description.
func (c *MobileProfileConfig) WithDescription(desc string) *MobileProfileConfig {
	c.Description = desc
	return c
}

// WithConsentText sets the consent text shown before installation.
func (c *MobileProfileConfig) WithConsentText(text string) *MobileProfileConfig {
	c.ConsentText = text
	return c
}

// WithSigning enables profile signing (iOS only).
func (c *MobileProfileConfig) WithSigning(sign bool) *MobileProfileConfig {
	c.SignProfile = sign
	return c
}

// ============================================================================
// Profile Generation Helper
// ============================================================================

// GenerateMobileProfile generates the appropriate profile based on device type.
func GenerateMobileProfile(certPEM []byte, config *MobileProfileConfig, deviceType MobileDeviceType) ([]byte, string, *ProfileMetadata, error) {
	switch deviceType {
	case DeviceTypeiOS, DeviceTypeiPadOS:
		profile, metadata, err := GenerateiOSProfile(certPEM, config)
		if err != nil {
			return nil, "", nil, err
		}
		return profile, "application/x-apple-aspen-config", metadata, nil

	case DeviceTypeAndroid:
		profile, metadata, err := GenerateAndroidProfile(certPEM, config, AndroidProfileSimple)
		if err != nil {
			return nil, "", nil, err
		}
		return profile, "application/x-x509-ca-cert", metadata, nil

	default:
		// For unknown/desktop devices, return iOS profile as default mobile format
		profile, metadata, err := GenerateiOSProfile(certPEM, config)
		if err != nil {
			return nil, "", nil, err
		}
		return profile, "application/x-apple-aspen-config", metadata, nil
	}
}
