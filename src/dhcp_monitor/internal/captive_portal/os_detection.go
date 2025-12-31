package captive_portal

import (
	"strings"
)

// OSType represents detected operating system
type OSType string

const (
	OSiOS     OSType = "ios"
	OSAndroid OSType = "android"
	OSWindows OSType = "windows"
	OSMacOS   OSType = "macos"
	OSLinux   OSType = "linux"
	OSUnknown OSType = "unknown"
)

// DetectOS detects the operating system from User-Agent header
func DetectOS(userAgent string) OSType {
	ua := strings.ToLower(userAgent)

	// iOS (iPhone, iPad, iPod)
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") {
		return OSiOS
	}

	// Android
	if strings.Contains(ua, "android") {
		return OSAndroid
	}

	// Windows
	if strings.Contains(ua, "windows") {
		return OSWindows
	}

	// macOS (Mac OS X, Macintosh)
	if strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh") {
		// Exclude iOS devices that report Mac OS X
		if !strings.Contains(ua, "mobile") {
			return OSMacOS
		}
	}

	// Linux
	if strings.Contains(ua, "linux") && !strings.Contains(ua, "android") {
		return OSLinux
	}

	return OSUnknown
}

// GetOSDisplayName returns user-friendly OS name
func GetOSDisplayName(os OSType) string {
	switch os {
	case OSiOS:
		return "iOS (iPhone/iPad)"
	case OSAndroid:
		return "Android"
	case OSWindows:
		return "Windows"
	case OSMacOS:
		return "macOS"
	case OSLinux:
		return "Linux"
	default:
		return "Unknown"
	}
}

// GetInstallationInstructions returns OS-specific installation instructions
func GetInstallationInstructions(os OSType) string {
	switch os {
	case OSiOS:
		return `
<h3>iOS Installation Steps</h3>
<ol>
	<li>Tap the download button below</li>
	<li>A prompt will appear - tap <strong>"Allow"</strong></li>
	<li>Go to <strong>Settings > General > VPN & Device Management</strong></li>
	<li>Tap on the downloaded profile</li>
	<li>Tap <strong>"Install"</strong> (enter your passcode if prompted)</li>
	<li>Tap <strong>"Install"</strong> again to confirm</li>
	<li>Go to <strong>Settings > General > About > Certificate Trust Settings</strong></li>
	<li>Enable full trust for the root certificate</li>
	<li>Return to this page - you'll be connected automatically!</li>
</ol>
`
	case OSAndroid:
		return `
<h3>Android Installation Steps</h3>
<ol>
	<li>Tap the download button below to download the certificate</li>
	<li>Open <strong>Settings > Security > Encryption & credentials</strong></li>
	<li>Tap <strong>"Install from storage"</strong> or <strong>"Install a certificate"</strong></li>
	<li>Select <strong>"CA certificate"</strong></li>
	<li>Tap <strong>"Install anyway"</strong> when warned</li>
	<li>Browse to your Downloads folder and select the downloaded certificate</li>
	<li>Enter a name for the certificate (e.g., "Network CA")</li>
	<li>Return to this page - you'll be connected automatically!</li>
</ol>
`
	case OSWindows:
		return `
<h3>Windows Installation Steps</h3>
<ol>
	<li>Click the download button below to save the certificate</li>
	<li>Double-click the downloaded certificate file</li>
	<li>Click <strong>"Install Certificate..."</strong></li>
	<li>Select <strong>"Current User"</strong> and click <strong>"Next"</strong></li>
	<li>Select <strong>"Place all certificates in the following store"</strong></li>
	<li>Click <strong>"Browse"</strong> and select <strong>"Trusted Root Certification Authorities"</strong></li>
	<li>Click <strong>"Next"</strong> then <strong>"Finish"</strong></li>
	<li>Click <strong>"Yes"</strong> to the security warning</li>
	<li>Return to this page - you'll be connected automatically!</li>
</ol>
`
	case OSMacOS:
		return `
<h3>macOS Installation Steps</h3>
<ol>
	<li>Click the download button below to save the certificate</li>
	<li>Double-click the downloaded certificate to open Keychain Access</li>
	<li>Enter your password if prompted</li>
	<li>In Keychain Access, find the certificate in <strong>"login"</strong> keychain</li>
	<li>Double-click the certificate to open it</li>
	<li>Expand <strong>"Trust"</strong> section</li>
	<li>Set <strong>"When using this certificate"</strong> to <strong>"Always Trust"</strong></li>
	<li>Close the window and enter your password to save changes</li>
	<li>Return to this page - you'll be connected automatically!</li>
</ol>
`
	case OSLinux:
		return `
<h3>Linux Installation Steps</h3>
<ol>
	<li>Download the certificate using the button below</li>
	<li>Open a terminal</li>
	<li>Copy the certificate to the CA directory:<br>
		<code>sudo cp ~/Downloads/ca.crt /usr/local/share/ca-certificates/network-ca.crt</code>
	</li>
	<li>Update CA certificates:<br>
		<code>sudo update-ca-certificates</code>
	</li>
	<li>For browsers (Firefox):<br>
		Settings > Privacy & Security > Certificates > View Certificates > Import
	</li>
	<li>Return to this page - you'll be connected automatically!</li>
</ol>
`
	default:
		return `
<h3>Installation Steps</h3>
<ol>
	<li>Download the certificate using the button below</li>
	<li>Install it in your device's trusted root certificate store</li>
	<li>Consult your device's documentation for specific steps</li>
	<li>Return to this page after installation</li>
</ol>
`
	}
}

// GetDownloadURL returns the appropriate download URL for the OS
func GetDownloadURL(os OSType) string {
	switch os {
	case OSiOS:
		return "/download?type=ios" // iOS Configuration Profile
	case OSAndroid:
		return "/download?type=android" // .crt file
	case OSWindows:
		return "/download?type=windows" // .crt file
	case OSMacOS:
		return "/download?type=macos" // .crt file
	case OSLinux:
		return "/download?type=linux" // .crt file
	default:
		return "/download?type=generic" // .crt file
	}
}

// GetDownloadFilename returns the appropriate filename for the OS
func GetDownloadFilename(os OSType) string {
	switch os {
	case OSiOS:
		return "network-ca.mobileconfig"
	default:
		return "network-ca.crt"
	}
}
