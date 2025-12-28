// Package protocol defines DHCP message type constants from RFC 2131 section 3.1.
// These types are transmitted in DHCP option 53 and determine state machine transitions.
package protocol

// ============================================================================
// DHCP Message Type Constants (RFC 2131 Table 1)
// ============================================================================

const (
	// DHCPDISCOVER - Client broadcast to locate available DHCP servers
	// Sent when client has no IP address and needs one
	DHCPDISCOVER uint8 = 1

	// DHCPOFFER - Server unicast offering IP address to client
	// Contains offered IP and configuration options
	DHCPOFFER uint8 = 2

	// DHCPREQUEST - Client message accepting offered address or renewing lease
	// Can occur in SELECTING, INIT-REBOOT, RENEWING, or REBINDING states
	DHCPREQUEST uint8 = 3

	// DHCPDECLINE - Client declines offered address (conflict detected)
	// Server should mark IP as unavailable
	DHCPDECLINE uint8 = 4

	// DHCPACK - Server confirms lease assignment
	// Contains final configuration parameters
	DHCPACK uint8 = 5

	// DHCPNAK - Server rejects lease request
	// Forces client back to INIT state (wrong subnet, expired offer)
	DHCPNAK uint8 = 6

	// DHCPRELEASE - Client relinquishes IP address lease
	// Server frees IP for reassignment
	DHCPRELEASE uint8 = 7

	// DHCPINFORM - Client requests local configuration (already has IP)
	// Server responds with DHCPACK containing only options
	DHCPINFORM uint8 = 8
)

// ============================================================================
// Message Type String Mapping
// ============================================================================

// messageTypeStrings maps message type codes to human-readable names
var messageTypeStrings = map[uint8]string{
	DHCPDISCOVER: "DISCOVER",
	DHCPOFFER:    "OFFER",
	DHCPREQUEST:  "REQUEST",
	DHCPDECLINE:  "DECLINE",
	DHCPACK:      "ACK",
	DHCPNAK:      "NAK",
	DHCPRELEASE:  "RELEASE",
	DHCPINFORM:   "INFORM",
}

// MessageTypeToString returns a human-readable name for the message type.
// Returns "UNKNOWN" for invalid or unrecognized message types.
// Use case: Log messages like "Received DHCPDISCOVER from MAC AA:BB:CC:DD:EE:FF"
func MessageTypeToString(msgType uint8) string {
	if s, ok := messageTypeStrings[msgType]; ok {
		return s
	}
	return "UNKNOWN"
}

// MessageTypeFromString parses a string to message type constant.
// Returns 0 if the string is not recognized.
func MessageTypeFromString(s string) uint8 {
	for code, name := range messageTypeStrings {
		if name == s {
			return code
		}
	}
	return 0
}

// ============================================================================
// Validation Function
// ============================================================================

// IsValidMessageType validates that the message type is within legal range (1-8).
// Returns true if msgType is a valid DHCP message type per RFC 2131.
// Use case: Prevents processing malformed packets with invalid message types.
func IsValidMessageType(msgType uint8) bool {
	return msgType >= DHCPDISCOVER && msgType <= DHCPINFORM
}

// ============================================================================
// State Machine Helpers
// ============================================================================

// GetExpectedResponse determines the expected server response for a client message type.
// Returns 0 if no response is expected (DECLINE, RELEASE).
// Use case: State machine validation and logging.
func GetExpectedResponse(clientMsg uint8) uint8 {
	switch clientMsg {
	case DHCPDISCOVER:
		return DHCPOFFER
	case DHCPREQUEST:
		// Can return ACK or NAK depending on validation
		return DHCPACK
	case DHCPINFORM:
		return DHCPACK
	case DHCPDECLINE, DHCPRELEASE:
		// No response required
		return 0
	default:
		return 0
	}
}

// IsClientMessage returns true if the message type is sent by clients.
func IsClientMessage(msgType uint8) bool {
	switch msgType {
	case DHCPDISCOVER, DHCPREQUEST, DHCPDECLINE, DHCPRELEASE, DHCPINFORM:
		return true
	default:
		return false
	}
}

// IsServerMessage returns true if the message type is sent by servers.
func IsServerMessage(msgType uint8) bool {
	switch msgType {
	case DHCPOFFER, DHCPACK, DHCPNAK:
		return true
	default:
		return false
	}
}

// RequiresResponse returns true if the client message expects a server response.
func RequiresResponse(msgType uint8) bool {
	switch msgType {
	case DHCPDISCOVER, DHCPREQUEST, DHCPINFORM:
		return true
	default:
		return false
	}
}

// ============================================================================
// DHCP Client States (RFC 2131 Section 4.4)
// ============================================================================

// ClientState represents the DHCP client state machine states
type ClientState int

const (
	// StateInit - Client begins here, sends DISCOVER
	StateInit ClientState = iota
	// StateSelecting - Client waits for OFFER after DISCOVER
	StateSelecting
	// StateRequesting - Client sent REQUEST, waiting for ACK/NAK
	StateRequesting
	// StateBound - Client has valid lease
	StateBound
	// StateRenewing - T1 expired, client unicasts REQUEST to server
	StateRenewing
	// StateRebinding - T2 expired, client broadcasts REQUEST
	StateRebinding
	// StateInitReboot - Client reboots with valid lease, verifies address
	StateInitReboot
)

// ClientStateStrings provides human-readable state names
var ClientStateStrings = map[ClientState]string{
	StateInit:       "INIT",
	StateSelecting:  "SELECTING",
	StateRequesting: "REQUESTING",
	StateBound:      "BOUND",
	StateRenewing:   "RENEWING",
	StateRebinding:  "REBINDING",
	StateInitReboot: "INIT-REBOOT",
}

// String returns the string representation of the client state
func (s ClientState) String() string {
	if str, ok := ClientStateStrings[s]; ok {
		return str
	}
	return "UNKNOWN"
}
