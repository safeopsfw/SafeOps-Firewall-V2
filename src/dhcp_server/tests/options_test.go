// Package tests contains tests for DHCP option handling.
// This file implements comprehensive option parsing, encoding, and validation tests.
package tests

import (
	"encoding/binary"
	"strings"
	"testing"
)

// ============================================================================
// Option Constants
// ============================================================================

const (
	// Standard DHCP Options
	optSubnetMask    = 1
	optRouter        = 3
	optDNS           = 6
	optDomainName    = 15
	optLeaseTime     = 51
	optMessageType   = 53
	optServerID      = 54
	optRenewalTime   = 58
	optRebindingTime = 59
	optEnd           = 255

	// Custom CA Options
	optCACertURL      = 224
	optInstallScripts = 225
	optWPADURL        = 252

	// Message Types
	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgDecline  = 4
	msgAck      = 5
	msgNak      = 6
	msgRelease  = 7
	msgInform   = 8
)

// Ensure all message types are used
var _ = msgDecline

// ============================================================================
// Option Structure
// ============================================================================

type dhcpOption struct {
	Code   uint8
	Length uint8
	Data   []byte
}

func newOption(code uint8, data []byte) dhcpOption {
	return dhcpOption{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
	}
}

func (o dhcpOption) serialize() []byte {
	if o.Code == optEnd {
		return []byte{optEnd}
	}
	result := make([]byte, 2+len(o.Data))
	result[0] = o.Code
	result[1] = o.Length
	copy(result[2:], o.Data)
	return result
}

// ============================================================================
// Standard DHCP Options Tests
// ============================================================================

func TestOption1_SubnetMask(t *testing.T) {
	t.Run("EncodeSubnetMask", func(t *testing.T) {
		mask := []byte{255, 255, 255, 0}
		opt := newOption(optSubnetMask, mask)

		if opt.Code != 1 {
			t.Errorf("expected code 1, got %d", opt.Code)
		}
		if opt.Length != 4 {
			t.Errorf("expected length 4, got %d", opt.Length)
		}
		for i, b := range mask {
			if opt.Data[i] != b {
				t.Errorf("byte %d mismatch: expected %d, got %d", i, b, opt.Data[i])
			}
		}
	})

	t.Run("DecodeSubnetMask", func(t *testing.T) {
		data := []byte{255, 255, 255, 0}
		decoded := decodeIPAddress(data)
		expected := "255.255.255.0"
		if decoded != expected {
			t.Errorf("expected %s, got %s", expected, decoded)
		}
	})
}

func TestOption3_Router(t *testing.T) {
	t.Run("EncodeRouter", func(t *testing.T) {
		gateway := []byte{192, 168, 1, 1}
		opt := newOption(optRouter, gateway)

		if opt.Code != 3 {
			t.Errorf("expected code 3, got %d", opt.Code)
		}
		if opt.Length != 4 {
			t.Errorf("expected length 4, got %d", opt.Length)
		}

		serialized := opt.serialize()
		expected := []byte{3, 4, 192, 168, 1, 1}
		for i, b := range expected {
			if serialized[i] != b {
				t.Errorf("byte %d: expected %d, got %d", i, b, serialized[i])
			}
		}
	})
}

func TestOption6_DNSServers(t *testing.T) {
	t.Run("MultipleServers", func(t *testing.T) {
		// 3 DNS servers: 192.168.1.1, 8.8.8.8, 8.8.4.4
		dnsData := []byte{
			192, 168, 1, 1,
			8, 8, 8, 8,
			8, 8, 4, 4,
		}
		opt := newOption(optDNS, dnsData)

		if opt.Code != 6 {
			t.Errorf("expected code 6, got %d", opt.Code)
		}
		if opt.Length != 12 {
			t.Errorf("expected length 12, got %d", opt.Length)
		}

		// Decode servers
		servers := decodeDNSServers(opt.Data)
		if len(servers) != 3 {
			t.Errorf("expected 3 servers, got %d", len(servers))
		}
		if servers[0] != "192.168.1.1" {
			t.Errorf("first server wrong: %s", servers[0])
		}
		if servers[1] != "8.8.8.8" {
			t.Errorf("second server wrong: %s", servers[1])
		}
		if servers[2] != "8.8.4.4" {
			t.Errorf("third server wrong: %s", servers[2])
		}
	})
}

func TestOption15_DomainName(t *testing.T) {
	t.Run("EncodeDomainName", func(t *testing.T) {
		domain := "example.local"
		data := []byte(domain)
		opt := newOption(optDomainName, data)

		if opt.Code != 15 {
			t.Errorf("expected code 15, got %d", opt.Code)
		}
		if opt.Length != uint8(len(domain)) {
			t.Errorf("expected length %d, got %d", len(domain), opt.Length)
		}

		decoded := string(opt.Data)
		if decoded != domain {
			t.Errorf("expected %s, got %s", domain, decoded)
		}
	})
}

func TestOption51_LeaseTime(t *testing.T) {
	t.Run("EncodeLeaseTime", func(t *testing.T) {
		leaseTime := uint32(86400) // 24 hours
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, leaseTime)
		opt := newOption(optLeaseTime, data)

		if opt.Code != 51 {
			t.Errorf("expected code 51, got %d", opt.Code)
		}
		if opt.Length != 4 {
			t.Errorf("expected length 4, got %d", opt.Length)
		}

		// Verify network byte order
		expected := []byte{0x00, 0x01, 0x51, 0x80}
		for i, b := range expected {
			if opt.Data[i] != b {
				t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, b, opt.Data[i])
			}
		}

		// Decode
		decoded := binary.BigEndian.Uint32(opt.Data)
		if decoded != 86400 {
			t.Errorf("expected 86400, got %d", decoded)
		}
	})
}

func TestOption53_MessageType(t *testing.T) {
	testCases := []struct {
		name     string
		msgType  uint8
		expected uint8
	}{
		{"DISCOVER", msgDiscover, 1},
		{"OFFER", msgOffer, 2},
		{"REQUEST", msgRequest, 3},
		{"ACK", msgAck, 5},
		{"NAK", msgNak, 6},
		{"RELEASE", msgRelease, 7},
		{"INFORM", msgInform, 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opt := newOption(optMessageType, []byte{tc.msgType})

			if opt.Code != 53 {
				t.Errorf("expected code 53, got %d", opt.Code)
			}
			if opt.Length != 1 {
				t.Errorf("expected length 1, got %d", opt.Length)
			}
			if opt.Data[0] != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, opt.Data[0])
			}
		})
	}
}

func TestOption54_ServerIdentifier(t *testing.T) {
	t.Run("EncodeServerID", func(t *testing.T) {
		serverIP := []byte{192, 168, 1, 1}
		opt := newOption(optServerID, serverIP)

		if opt.Code != 54 {
			t.Errorf("expected code 54, got %d", opt.Code)
		}
		if opt.Length != 4 {
			t.Errorf("expected length 4, got %d", opt.Length)
		}
	})
}

func TestOption58_RenewalTime(t *testing.T) {
	t.Run("T1Timer", func(t *testing.T) {
		// T1 = 50% of 24 hours = 43200 seconds
		t1 := uint32(43200)
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, t1)
		opt := newOption(optRenewalTime, data)

		if opt.Code != 58 {
			t.Errorf("expected code 58, got %d", opt.Code)
		}

		decoded := binary.BigEndian.Uint32(opt.Data)
		if decoded != 43200 {
			t.Errorf("expected 43200, got %d", decoded)
		}
	})
}

func TestOption59_RebindingTime(t *testing.T) {
	t.Run("T2Timer", func(t *testing.T) {
		// T2 = 87.5% of 24 hours = 75600 seconds
		t2 := uint32(75600)
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, t2)
		opt := newOption(optRebindingTime, data)

		if opt.Code != 59 {
			t.Errorf("expected code 59, got %d", opt.Code)
		}

		decoded := binary.BigEndian.Uint32(opt.Data)
		if decoded != 75600 {
			t.Errorf("expected 75600, got %d", decoded)
		}
	})
}

// ============================================================================
// Custom CA Certificate Options Tests
// ============================================================================

func TestOption224_CACertURL(t *testing.T) {
	t.Run("EncodeCAURL", func(t *testing.T) {
		url := "http://192.168.1.1/ca.crt"
		data := []byte(url)
		opt := newOption(optCACertURL, data)

		if opt.Code != 224 {
			t.Errorf("expected code 224, got %d", opt.Code)
		}
		if opt.Length != uint8(len(url)) {
			t.Errorf("expected length %d, got %d", len(url), opt.Length)
		}

		decoded := string(opt.Data)
		if decoded != url {
			t.Errorf("expected %s, got %s", url, decoded)
		}
	})
}

func TestOption225_InstallScriptURLs(t *testing.T) {
	t.Run("MultipleScripts", func(t *testing.T) {
		scripts := []string{
			"http://192.168.1.1/install-ca.sh",
			"http://192.168.1.1/install-ca.ps1",
		}
		data := []byte(strings.Join(scripts, ","))
		opt := newOption(optInstallScripts, data)

		if opt.Code != 225 {
			t.Errorf("expected code 225, got %d", opt.Code)
		}

		// Decode
		decoded := strings.Split(string(opt.Data), ",")
		if len(decoded) != 2 {
			t.Errorf("expected 2 URLs, got %d", len(decoded))
		}
		if decoded[0] != scripts[0] {
			t.Errorf("first URL wrong: %s", decoded[0])
		}
		if decoded[1] != scripts[1] {
			t.Errorf("second URL wrong: %s", decoded[1])
		}
	})
}

func TestOption252_WPADURL(t *testing.T) {
	t.Run("EncodeWPAD", func(t *testing.T) {
		url := "http://192.168.1.1/wpad.dat"
		data := []byte(url)
		opt := newOption(optWPADURL, data)

		if opt.Code != 252 {
			t.Errorf("expected code 252, got %d", opt.Code)
		}
		if opt.Length != uint8(len(url)) {
			t.Errorf("expected length %d, got %d", len(url), opt.Length)
		}

		decoded := string(opt.Data)
		if decoded != url {
			t.Errorf("expected %s, got %s", url, decoded)
		}
	})
}

func TestCustomOptionsInACK(t *testing.T) {
	t.Run("CAOptionsPresent", func(t *testing.T) {
		// Build ACK options with CA enabled
		options := buildTestACKOptions(true)

		// Parse and verify
		parsed := parseOptions(options)

		foundCA := false
		foundScripts := false
		foundWPAD := false

		for _, opt := range parsed {
			switch opt.Code {
			case optCACertURL:
				foundCA = true
			case optInstallScripts:
				foundScripts = true
			case optWPADURL:
				foundWPAD = true
			}
		}

		if !foundCA {
			t.Error("Option 224 (CA Cert URL) not found in ACK")
		}
		if !foundScripts {
			t.Error("Option 225 (Install Scripts) not found in ACK")
		}
		if !foundWPAD {
			t.Error("Option 252 (WPAD URL) not found in ACK")
		}
	})
}

func TestCustomOptionsNotInOFFER(t *testing.T) {
	t.Run("CAOptionsAbsent", func(t *testing.T) {
		// Build OFFER options (no CA options)
		options := buildTestOfferOptions()

		// Parse and verify
		parsed := parseOptions(options)

		for _, opt := range parsed {
			switch opt.Code {
			case optCACertURL:
				t.Error("Option 224 should not be in OFFER")
			case optInstallScripts:
				t.Error("Option 225 should not be in OFFER")
			case optWPADURL:
				t.Error("Option 252 should not be in OFFER")
			}
		}
	})
}

// ============================================================================
// Option Parsing Tests
// ============================================================================

func TestParseOptions(t *testing.T) {
	t.Run("ParseMultipleOptions", func(t *testing.T) {
		// Build options: 53, 54, 1, 3, 6, 51, 255
		options := buildTestACKOptions(false)
		parsed := parseOptions(options)

		if len(parsed) < 6 {
			t.Errorf("expected at least 6 options, got %d", len(parsed))
		}
	})
}

func TestParseOptionsEndMarker(t *testing.T) {
	t.Run("StopsAtEnd", func(t *testing.T) {
		// Options with End in middle: 53, 54, 255, 1 (after end)
		data := []byte{
			53, 1, msgAck, // Message type
			54, 4, 192, 168, 1, 1, // Server ID
			255,                    // End
			1, 4, 255, 255, 255, 0, // Subnet (should be ignored)
		}

		parsed := parseOptions(data)

		// Should only have 2 options (53, 54), not 3
		if len(parsed) != 2 {
			t.Errorf("expected 2 options before End, got %d", len(parsed))
		}
	})
}

func TestParseOptionsUnknownCode(t *testing.T) {
	t.Run("SkipsUnknown", func(t *testing.T) {
		// Options with unknown code 200
		data := []byte{
			53, 1, msgAck, // Message type
			200, 2, 0x00, 0x00, // Unknown option
			54, 4, 192, 168, 1, 1, // Server ID
			255, // End
		}

		parsed := parseOptions(data)

		// Should have 3 options (53, 200, 54)
		if len(parsed) != 3 {
			t.Errorf("expected 3 options, got %d", len(parsed))
		}
	})
}

// ============================================================================
// Option Building Tests
// ============================================================================

func TestBuildOptionsOrder(t *testing.T) {
	t.Run("MessageTypeFirst", func(t *testing.T) {
		options := buildTestACKOptions(false)
		parsed := parseOptions(options)

		if len(parsed) == 0 {
			t.Fatal("no options parsed")
		}

		if parsed[0].Code != optMessageType {
			t.Errorf("expected Option 53 first, got %d", parsed[0].Code)
		}
	})
}

func TestBuildOptionsEndMarker(t *testing.T) {
	t.Run("EndsWithEnd", func(t *testing.T) {
		options := buildTestACKOptions(false)

		if options[len(options)-1] != optEnd {
			t.Errorf("expected last byte to be 255 (End), got %d", options[len(options)-1])
		}
	})
}

// ============================================================================
// Option Serialization Tests
// ============================================================================

func TestSerializeOption(t *testing.T) {
	t.Run("RouterOption", func(t *testing.T) {
		opt := newOption(optRouter, []byte{192, 168, 1, 1})
		serialized := opt.serialize()

		expected := []byte{3, 4, 192, 168, 1, 1}
		if len(serialized) != len(expected) {
			t.Fatalf("length mismatch: expected %d, got %d", len(expected), len(serialized))
		}

		for i, b := range expected {
			if serialized[i] != b {
				t.Errorf("byte %d: expected %d, got %d", i, b, serialized[i])
			}
		}
	})
}

func TestSerializeEndOption(t *testing.T) {
	t.Run("EndNoLength", func(t *testing.T) {
		opt := dhcpOption{Code: optEnd}
		serialized := opt.serialize()

		if len(serialized) != 1 {
			t.Errorf("End option should be 1 byte, got %d", len(serialized))
		}
		if serialized[0] != 255 {
			t.Errorf("expected 255, got %d", serialized[0])
		}
	})
}

func TestSerializeNetworkByteOrder(t *testing.T) {
	t.Run("BigEndian", func(t *testing.T) {
		leaseTime := uint32(86400) // 0x00015180
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, leaseTime)

		opt := newOption(optLeaseTime, data)
		serialized := opt.serialize()

		// [51, 4, 0x00, 0x01, 0x51, 0x80]
		expected := []byte{51, 4, 0x00, 0x01, 0x51, 0x80}
		for i, b := range expected {
			if serialized[i] != b {
				t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, b, serialized[i])
			}
		}
	})
}

// ============================================================================
// Option Validation Tests
// ============================================================================

func TestValidateLeaseTime(t *testing.T) {
	testCases := []struct {
		name        string
		leaseTime   uint32
		expectValid bool
	}{
		{"Zero", 0, false},
		{"TooShort", 30, false},
		{"Minimum", 60, true},
		{"OneDay", 86400, true},
		{"OneWeek", 604800, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid := validateLeaseTime(tc.leaseTime)
			if valid != tc.expectValid {
				t.Errorf("lease time %d: expected valid=%v, got %v", tc.leaseTime, tc.expectValid, valid)
			}
		})
	}
}

func TestValidateURLFormat(t *testing.T) {
	testCases := []struct {
		name        string
		url         string
		expectValid bool
	}{
		{"ValidHTTP", "http://192.168.1.1/ca.crt", true},
		{"ValidHTTPS", "https://ca.example.com/ca.crt", true},
		{"NoScheme", "192.168.1.1/ca.crt", false},
		{"Invalid", "not-a-url", false},
		{"Empty", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid := validateURL(tc.url)
			if valid != tc.expectValid {
				t.Errorf("URL %s: expected valid=%v, got %v", tc.url, tc.expectValid, valid)
			}
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func decodeIPAddress(data []byte) string {
	if len(data) != 4 {
		return ""
	}
	return strings.Join([]string{
		itoa(int(data[0])),
		itoa(int(data[1])),
		itoa(int(data[2])),
		itoa(int(data[3])),
	}, ".")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

func decodeDNSServers(data []byte) []string {
	servers := make([]string, 0)
	for i := 0; i+3 < len(data); i += 4 {
		server := itoa(int(data[i])) + "." +
			itoa(int(data[i+1])) + "." +
			itoa(int(data[i+2])) + "." +
			itoa(int(data[i+3]))
		servers = append(servers, server)
	}
	return servers
}

func parseOptions(data []byte) []dhcpOption {
	options := make([]dhcpOption, 0)
	offset := 0

	for offset < len(data) {
		code := data[offset]
		if code == optEnd {
			break
		}
		if code == 0 { // Padding
			offset++
			continue
		}

		if offset+1 >= len(data) {
			break
		}
		length := int(data[offset+1])

		if offset+2+length > len(data) {
			break
		}

		opt := dhcpOption{
			Code:   code,
			Length: uint8(length),
			Data:   data[offset+2 : offset+2+length],
		}
		options = append(options, opt)
		offset += 2 + length
	}

	return options
}

func buildTestACKOptions(includeCA bool) []byte {
	var result []byte

	// Option 53: Message Type = ACK
	result = append(result, 53, 1, msgAck)

	// Option 54: Server ID
	result = append(result, 54, 4, 192, 168, 1, 1)

	// Option 1: Subnet Mask
	result = append(result, 1, 4, 255, 255, 255, 0)

	// Option 3: Router
	result = append(result, 3, 4, 192, 168, 1, 1)

	// Option 6: DNS
	result = append(result, 6, 4, 192, 168, 1, 1)

	// Option 51: Lease Time (86400 seconds)
	result = append(result, 51, 4, 0x00, 0x01, 0x51, 0x80)

	// CA options if enabled
	if includeCA {
		caURL := "http://192.168.1.1/ca.crt"
		result = append(result, optCACertURL, uint8(len(caURL)))
		result = append(result, []byte(caURL)...)

		scripts := "http://192.168.1.1/install.sh"
		result = append(result, optInstallScripts, uint8(len(scripts)))
		result = append(result, []byte(scripts)...)

		wpad := "http://192.168.1.1/wpad.dat"
		result = append(result, optWPADURL, uint8(len(wpad)))
		result = append(result, []byte(wpad)...)
	}

	// Option 255: End
	result = append(result, optEnd)

	return result
}

func buildTestOfferOptions() []byte {
	var result []byte

	// Option 53: Message Type = OFFER
	result = append(result, 53, 1, msgOffer)

	// Option 54: Server ID
	result = append(result, 54, 4, 192, 168, 1, 1)

	// Option 1: Subnet Mask
	result = append(result, 1, 4, 255, 255, 255, 0)

	// Option 3: Router
	result = append(result, 3, 4, 192, 168, 1, 1)

	// Option 6: DNS
	result = append(result, 6, 4, 192, 168, 1, 1)

	// Option 51: Lease Time
	result = append(result, 51, 4, 0x00, 0x01, 0x51, 0x80)

	// Option 255: End (no CA options in OFFER)
	result = append(result, optEnd)

	return result
}

func validateLeaseTime(seconds uint32) bool {
	return seconds >= 60
}

func validateURL(url string) bool {
	if url == "" {
		return false
	}
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}
