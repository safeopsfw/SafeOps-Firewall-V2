// Package protocol defines DHCP option codes from RFC 2132 and custom CA options.
// This CRITICAL file enables zero-touch CA certificate distribution via DHCP.
package protocol

// ============================================================================
// Option Value Types
// ============================================================================

// OptionType defines the data type for DHCP option values
type OptionType int

const (
	OptionTypeUnknown OptionType = iota
	OptionTypeIP                 // 4-byte IP address
	OptionTypeIPList             // Multiple 4-byte IP addresses
	OptionTypeString             // ASCII string
	OptionTypeUint32             // 4-byte unsigned integer
	OptionTypeUint16             // 2-byte unsigned integer
	OptionTypeUint8              // 1-byte unsigned integer
	OptionTypeBinary             // Raw binary data
	OptionTypeBool               // Boolean (1 byte)
)

// ============================================================================
// Option Length Constraints
// ============================================================================

const (
	// MaxHostnameLength is the maximum hostname string length
	MaxHostnameLength = 255
	// MaxDomainNameLength is the maximum domain name length
	MaxDomainNameLength = 255
	// FixedIPLength is the IPv4 address size
	FixedIPLength = 4
	// FixedLeaseTimeLength is the lease time size (32-bit)
	FixedLeaseTimeLength = 4
	// MaxOptionLength is the maximum single option data length per RFC
	MaxOptionLength = 255
	// MaxURLLength is the maximum CA certificate URL length
	MaxURLLength = 255
)

// ============================================================================
// Standard RFC 2132 Options (1-81)
// ============================================================================

const (
	// OptionPad is padding (no operation)
	OptionPad uint8 = 0

	// Network Configuration Options
	OptionSubnetMask       uint8 = 1  // Subnet mask for assigned IP
	OptionTimeOffset       uint8 = 2  // UTC time offset in seconds
	OptionRouter           uint8 = 3  // Default gateway IP address (critical)
	OptionTimeServer       uint8 = 4  // Time server addresses
	OptionNameServer       uint8 = 5  // IEN-116 name servers (obsolete)
	OptionDomainNameServer uint8 = 6  // DNS server addresses (critical)
	OptionLogServer        uint8 = 7  // Logging server addresses
	OptionQuotesServer     uint8 = 8  // Quote server addresses
	OptionLPRServer        uint8 = 9  // Line printer server addresses
	OptionImpressServer    uint8 = 10 // Impress server addresses
	OptionRLPServer        uint8 = 11 // Resource location server

	// Host Configuration Options
	OptionHostname       uint8 = 12 // Client hostname
	OptionBootFileSize   uint8 = 13 // Boot file size in 512-byte blocks
	OptionMeritDumpFile  uint8 = 14 // Path to crash dump file
	OptionDomainName     uint8 = 15 // DNS domain name (e.g., "local.lan")
	OptionSwapServer     uint8 = 16 // Swap server address
	OptionRootPath       uint8 = 17 // Path to root disk
	OptionExtensionsPath uint8 = 18 // Path to extensions file

	// IP Layer Parameters
	OptionIPForwarding       uint8 = 19 // Enable/disable IP forwarding
	OptionNonLocalSrcRouting uint8 = 20 // Non-local source routing
	OptionPolicyFilter       uint8 = 21 // Policy filter for non-local routing
	OptionMaxDGReassembly    uint8 = 22 // Maximum datagram reassembly size
	OptionDefaultIPTTL       uint8 = 23 // Default IP time-to-live
	OptionMTUTimeout         uint8 = 24 // Path MTU aging timeout
	OptionMTUPlateau         uint8 = 25 // Path MTU plateau table
	OptionMTUInterface       uint8 = 26 // Interface MTU
	OptionMTUSubnet          uint8 = 27 // All subnets are local

	// Interface Parameters
	OptionBroadcastAddress   uint8 = 28 // Broadcast address for subnet
	OptionMaskDiscovery      uint8 = 29 // Perform mask discovery
	OptionMaskSupplier       uint8 = 30 // Respond to mask discovery
	OptionRouterDiscovery    uint8 = 31 // Perform router discovery
	OptionRouterSolicitation uint8 = 32 // Router solicitation address
	OptionStaticRoute        uint8 = 33 // Static route option

	// Link Layer Parameters
	OptionTrailerEncap  uint8 = 34 // Trailer encapsulation
	OptionARPTimeout    uint8 = 35 // ARP cache timeout
	OptionEthernetEncap uint8 = 36 // Ethernet encapsulation

	// TCP Parameters
	OptionTCPDefaultTTL       uint8 = 37 // Default TCP time-to-live
	OptionTCPKeepalive        uint8 = 38 // TCP keepalive interval
	OptionTCPKeepaliveGarbage uint8 = 39 // TCP keepalive garbage

	// Application and Service Parameters
	OptionNISDomain       uint8 = 40 // NIS domain name
	OptionNISServers      uint8 = 41 // NIS server addresses
	OptionNTPServers      uint8 = 42 // Network Time Protocol servers (important)
	OptionVendorSpecific  uint8 = 43 // Vendor-specific information
	OptionNetBIOSNameSrv  uint8 = 44 // NetBIOS name servers (Windows)
	OptionNetBIOSDGSrv    uint8 = 45 // NetBIOS datagram distribution
	OptionNetBIOSNodeType uint8 = 46 // NetBIOS node type
	OptionNetBIOSScope    uint8 = 47 // NetBIOS scope
	OptionXFontServer     uint8 = 48 // X Window font server
	OptionXDisplayManager uint8 = 49 // X Window display manager

	// DHCP Protocol Options (Critical)
	OptionRequestedIP      uint8 = 50 // Client requests specific IP
	OptionLeaseTime        uint8 = 51 // IP address lease time in seconds
	OptionOverload         uint8 = 52 // Option overload (sname/file fields)
	OptionMessageType      uint8 = 53 // DHCP message type (DISCOVER, OFFER, etc.) - REQUIRED
	OptionServerID         uint8 = 54 // Server identifier (server IP) - REQUIRED in OFFER/ACK
	OptionParamRequestList uint8 = 55 // Client requests specific options
	OptionMessage          uint8 = 56 // Error message string
	OptionMaxMessageSize   uint8 = 57 // Maximum DHCP message size
	OptionRenewalTime      uint8 = 58 // T1 renewal time
	OptionRebindingTime    uint8 = 59 // T2 rebinding time
	OptionVendorClassID    uint8 = 60 // Vendor class identifier
	OptionClientID         uint8 = 61 // Client identifier (unique ID)

	// Additional Options
	OptionNetWareIPDomain   uint8 = 62 // NetWare/IP domain name
	OptionNetWareIPInfo     uint8 = 63 // NetWare/IP information
	OptionNISDomainName     uint8 = 64 // NIS+ domain name
	OptionNISServerAddr     uint8 = 65 // NIS+ server addresses
	OptionTFTPServerName    uint8 = 66 // TFTP server name
	OptionBootFileName      uint8 = 67 // Boot file name
	OptionMobileIPHomeAgent uint8 = 68 // Mobile IP home agent
	OptionSMTPServer        uint8 = 69 // SMTP server
	OptionPOP3Server        uint8 = 70 // POP3 server
	OptionNNTPServer        uint8 = 71 // NNTP server
	OptionWWWServer         uint8 = 72 // WWW server
	OptionFingerServer      uint8 = 73 // Finger server
	OptionIRCServer         uint8 = 74 // IRC server
	OptionStreetTalkServer  uint8 = 75 // StreetTalk server
	OptionSTDAServer        uint8 = 76 // StreetTalk directory assistance

	// User and FQDN Options
	OptionUserClass       uint8 = 77 // User class information
	OptionSLPDirAgent     uint8 = 78 // SLP directory agent
	OptionSLPServiceScope uint8 = 79 // SLP service scope
	OptionRapidCommit     uint8 = 80 // Rapid commit (DHCPv4 fast-track)
	OptionClientFQDN      uint8 = 81 // Client Fully Qualified Domain Name

	// Domain Search Option
	OptionDomainSearch uint8 = 119 // Domain search list

	// Classless Static Routes
	OptionClasslessStaticRoute uint8 = 121 // Classless static routes

	// OptionEnd marks the end of options
	OptionEnd uint8 = 255
)

// ============================================================================
// ⭐ CUSTOM CA CERTIFICATE OPTIONS (224, 225, 252) - CRITICAL
// ============================================================================
// These custom options enable zero-touch CA certificate distribution via DHCP.
// When a device receives an IP address, it also receives URLs to download
// the CA certificate for TLS proxy trust configuration.

const (
	// OptionCACertURL (224) - CA certificate download URL
	// ⭐ CA INTEGRATION - Zero-touch TLS proxy setup
	// Format: "http://192.168.1.1/ca.crt"
	// Purpose: Client downloads CA certificate from this URL
	// Used by: Windows, macOS, Linux clients with custom DHCP client handlers
	// Integration: Populated by calling cert_integration/ca_provider.go → GetCACertificate()
	OptionCACertURL uint8 = 224

	// OptionInstallScriptURLs (225) - CA installation script URLs
	// ⭐ CA INTEGRATION - Automated CA deployment
	// Format: "http://192.168.1.1/install-ca.sh,http://192.168.1.1/install-ca.ps1"
	// Purpose: Platform-specific CA installation scripts
	// Used by: Enterprise deployment tools
	// Integration: Retrieved from Certificate Manager's GetCertificateInfo() response
	OptionInstallScriptURLs uint8 = 225

	// OptionWPADURL (252) - Web Proxy Auto-Discovery URL
	// ⭐ CA INTEGRATION - Proxy auto-configuration for TLS interception
	// Format: "http://192.168.1.1/wpad.dat"
	// Purpose: Automatic proxy configuration for browsers
	// Standard: RFC 2131 allows 252 for vendor-specific use
	// Integration: Generated by Certificate Manager for automatic proxy configuration
	OptionWPADURL uint8 = 252
)

// IsCustomCAOption returns true if the option code is a custom CA option
func IsCustomCAOption(code uint8) bool {
	return code == OptionCACertURL || code == OptionInstallScriptURLs || code == OptionWPADURL
}

// ============================================================================
// Option Type Mapping
// ============================================================================

// optionTypes maps option codes to their value types
var optionTypes = map[uint8]OptionType{
	// Network config (IP)
	OptionSubnetMask:       OptionTypeIP,
	OptionRouter:           OptionTypeIPList,
	OptionDomainNameServer: OptionTypeIPList,
	OptionBroadcastAddress: OptionTypeIP,
	OptionNTPServers:       OptionTypeIPList,
	OptionRequestedIP:      OptionTypeIP,
	OptionServerID:         OptionTypeIP,
	OptionTimeServer:       OptionTypeIPList,
	OptionNameServer:       OptionTypeIPList,
	OptionLogServer:        OptionTypeIPList,
	OptionNetBIOSNameSrv:   OptionTypeIPList,

	// Strings
	OptionHostname:       OptionTypeString,
	OptionDomainName:     OptionTypeString,
	OptionMessage:        OptionTypeString,
	OptionVendorClassID:  OptionTypeString,
	OptionTFTPServerName: OptionTypeString,
	OptionBootFileName:   OptionTypeString,
	OptionDomainSearch:   OptionTypeString,

	// Uint32
	OptionTimeOffset:    OptionTypeUint32,
	OptionLeaseTime:     OptionTypeUint32,
	OptionRenewalTime:   OptionTypeUint32,
	OptionRebindingTime: OptionTypeUint32,

	// Uint16
	OptionMaxMessageSize: OptionTypeUint16,
	OptionBootFileSize:   OptionTypeUint16,

	// Uint8
	OptionMessageType:     OptionTypeUint8,
	OptionOverload:        OptionTypeUint8,
	OptionNetBIOSNodeType: OptionTypeUint8,

	// Binary
	OptionClientID:         OptionTypeBinary,
	OptionParamRequestList: OptionTypeBinary,
	OptionVendorSpecific:   OptionTypeBinary,
	OptionUserClass:        OptionTypeBinary,
	OptionClientFQDN:       OptionTypeBinary,

	// ⭐ Custom CA Options (all strings/URLs)
	OptionCACertURL:         OptionTypeString,
	OptionInstallScriptURLs: OptionTypeString,
	OptionWPADURL:           OptionTypeString,
}

// GetOptionType returns the data type for a DHCP option code.
// Returns OptionTypeUnknown for undefined options.
func GetOptionType(code uint8) OptionType {
	if t, ok := optionTypes[code]; ok {
		return t
	}
	return OptionTypeUnknown
}

// ============================================================================
// Option Description Mapping
// ============================================================================

// optionDescriptions maps option codes to human-readable descriptions
var optionDescriptions = map[uint8]string{
	OptionPad:                  "Pad",
	OptionSubnetMask:           "Subnet Mask",
	OptionTimeOffset:           "Time Offset",
	OptionRouter:               "Router (Default Gateway)",
	OptionTimeServer:           "Time Server",
	OptionNameServer:           "Name Server",
	OptionDomainNameServer:     "Domain Name Server (DNS)",
	OptionLogServer:            "Log Server",
	OptionHostname:             "Hostname",
	OptionDomainName:           "Domain Name",
	OptionBroadcastAddress:     "Broadcast Address",
	OptionNTPServers:           "NTP Servers",
	OptionNetBIOSNameSrv:       "NetBIOS Name Server",
	OptionNetBIOSScope:         "NetBIOS Scope",
	OptionRequestedIP:          "Requested IP Address",
	OptionLeaseTime:            "IP Address Lease Time",
	OptionOverload:             "Option Overload",
	OptionMessageType:          "DHCP Message Type",
	OptionServerID:             "Server Identifier",
	OptionParamRequestList:     "Parameter Request List",
	OptionMessage:              "Message",
	OptionMaxMessageSize:       "Maximum DHCP Message Size",
	OptionRenewalTime:          "Renewal (T1) Time",
	OptionRebindingTime:        "Rebinding (T2) Time",
	OptionVendorClassID:        "Vendor Class Identifier",
	OptionClientID:             "Client Identifier",
	OptionTFTPServerName:       "TFTP Server Name",
	OptionBootFileName:         "Bootfile Name",
	OptionUserClass:            "User Class",
	OptionClientFQDN:           "Client FQDN",
	OptionDomainSearch:         "Domain Search List",
	OptionClasslessStaticRoute: "Classless Static Route",
	OptionEnd:                  "End",

	// ⭐ Custom CA Options
	OptionCACertURL:         "CA Certificate URL (Custom - Zero-Touch CA Distribution)",
	OptionInstallScriptURLs: "CA Install Script URLs (Custom - Enterprise Deployment)",
	OptionWPADURL:           "WPAD URL (Custom - Proxy Auto-Config for TLS Interception)",
}

// GetOptionDescription returns a human-readable description for an option code.
// Returns "Unknown Option (N)" for undefined options.
func GetOptionDescription(code uint8) string {
	if desc, ok := optionDescriptions[code]; ok {
		return desc
	}
	return "Unknown Option"
}

// ============================================================================
// Common Option Lists
// ============================================================================

// StandardClientRequestList is a common set of options clients typically request
var StandardClientRequestList = []uint8{
	OptionSubnetMask,
	OptionRouter,
	OptionDomainNameServer,
	OptionDomainName,
	OptionBroadcastAddress,
	OptionNTPServers,
	OptionHostname,
	OptionLeaseTime,
	OptionRenewalTime,
	OptionRebindingTime,
}

// CADistributionOptions are the custom options for CA certificate distribution
var CADistributionOptions = []uint8{
	OptionCACertURL,
	OptionInstallScriptURLs,
	OptionWPADURL,
}

// RequiredServerOptions are options that MUST be included in OFFER/ACK
var RequiredServerOptions = []uint8{
	OptionMessageType,
	OptionServerID,
	OptionLeaseTime,
}
