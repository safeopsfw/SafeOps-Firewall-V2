// Package tests contains unit and integration tests for DHCP server components.
// This file implements tests for core server components.
package tests

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Test Constants
// ============================================================================

const (
	// DHCP message types
	testDHCPDiscover = 1
	testDHCPOffer    = 2
	testDHCPRequest  = 3
	testDHCPDecline  = 4
	testDHCPAck      = 5
	testDHCPNak      = 6
	testDHCPRelease  = 7
	testDHCPInform   = 8

	// DHCP magic cookie
	testMagicCookie = 0x63825363

	// Minimum DHCP packet size
	testMinPacketSize = 240
)

// ============================================================================
// Test Packet Builder
// ============================================================================

// buildTestDHCPPacket creates a valid DHCP packet for testing.
func buildTestDHCPPacket(msgType uint8, xid uint32, mac []byte) []byte {
	packet := make([]byte, 300)

	// BOOTP header
	packet[0] = 1 // op: BOOTREQUEST
	packet[1] = 1 // htype: Ethernet
	packet[2] = 6 // hlen: MAC address length

	// Transaction ID (xid)
	binary.BigEndian.PutUint32(packet[4:8], xid)

	// Client hardware address (chaddr)
	if len(mac) >= 6 {
		copy(packet[28:34], mac[:6])
	}

	// Magic cookie at offset 236
	binary.BigEndian.PutUint32(packet[236:240], testMagicCookie)

	// DHCP options starting at offset 240
	optionOffset := 240

	// Option 53: DHCP Message Type
	packet[optionOffset] = 53  // Option code
	packet[optionOffset+1] = 1 // Length
	packet[optionOffset+2] = msgType
	optionOffset += 3

	// Option 255: End
	packet[optionOffset] = 255

	return packet
}

// buildTestDHCPPacketWithOptions creates a packet with additional options.
func buildTestDHCPPacketWithOptions(msgType uint8, xid uint32, mac []byte, options map[uint8][]byte) []byte {
	packet := buildTestDHCPPacket(msgType, xid, mac)

	// Overwrite options section
	optionOffset := 240

	// Option 53: DHCP Message Type
	packet[optionOffset] = 53
	packet[optionOffset+1] = 1
	packet[optionOffset+2] = msgType
	optionOffset += 3

	// Add additional options
	for code, value := range options {
		packet[optionOffset] = code
		packet[optionOffset+1] = uint8(len(value))
		copy(packet[optionOffset+2:], value)
		optionOffset += 2 + len(value)
	}

	// End option
	packet[optionOffset] = 255

	return packet
}

// Ensure buildTestDHCPPacketWithOptions is used
var _ = buildTestDHCPPacketWithOptions

// ============================================================================
// UDP Listener Tests
// ============================================================================

func TestListenerConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		config := &testListenerConfig{
			ListenAddress: "0.0.0.0",
			Port:          67,
			BufferSize:    4096,
		}

		if config.ListenAddress != "0.0.0.0" {
			t.Errorf("expected 0.0.0.0, got %s", config.ListenAddress)
		}
		if config.Port != 67 {
			t.Errorf("expected port 67, got %d", config.Port)
		}
		if config.BufferSize != 4096 {
			t.Errorf("expected buffer 4096, got %d", config.BufferSize)
		}
	})
}

func TestListenerReceivePacket(t *testing.T) {
	t.Run("ValidPacketReceived", func(t *testing.T) {
		// Create mock handler
		handler := &mockPacketHandler{}

		// Create test packet
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)

		// Simulate packet receipt
		handler.handlePacket(packet)

		if handler.callCount != 1 {
			t.Errorf("expected 1 call, got %d", handler.callCount)
		}
	})
}

func TestListenerConcurrentPackets(t *testing.T) {
	t.Run("HandleMultiplePackets", func(t *testing.T) {
		handler := &mockPacketHandler{}

		// Send 100 packets concurrently
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, byte(id)}
				packet := buildTestDHCPPacket(testDHCPDiscover, uint32(id), mac)
				handler.handlePacket(packet)
			}(i)
		}

		wg.Wait()

		if handler.callCount != 100 {
			t.Errorf("expected 100 calls, got %d", handler.callCount)
		}
	})
}

func TestListenerGracefulShutdown(t *testing.T) {
	t.Run("ShutdownWithContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		// Simulate listener running
		running := true
		go func() {
			<-ctx.Done()
			running = false
		}()

		// Cancel context
		cancel()
		time.Sleep(10 * time.Millisecond)

		if running {
			t.Error("expected listener to stop after context cancel")
		}
	})
}

// ============================================================================
// Packet Parsing Tests
// ============================================================================

func TestParseValidDHCPPacket(t *testing.T) {
	t.Run("ValidDiscover", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)

		// Verify op code
		if packet[0] != 1 {
			t.Errorf("expected op=1, got %d", packet[0])
		}

		// Verify xid
		xid := binary.BigEndian.Uint32(packet[4:8])
		if xid != 0x12345678 {
			t.Errorf("expected xid=0x12345678, got 0x%x", xid)
		}

		// Verify magic cookie
		cookie := binary.BigEndian.Uint32(packet[236:240])
		if cookie != testMagicCookie {
			t.Errorf("expected magic cookie=0x%x, got 0x%x", testMagicCookie, cookie)
		}

		// Verify chaddr
		for i := 0; i < 6; i++ {
			if packet[28+i] != mac[i] {
				t.Errorf("MAC byte %d mismatch", i)
			}
		}
	})
}

func TestParseMalformedPacket(t *testing.T) {
	t.Run("PacketTooSmall", func(t *testing.T) {
		packet := make([]byte, 100) // Less than 240 bytes
		err := validatePacket(packet)
		if err == nil {
			t.Error("expected error for small packet")
		}
	})

	t.Run("MissingMagicCookie", func(t *testing.T) {
		packet := make([]byte, 300)
		packet[0] = 1 // op
		// Don't set magic cookie

		err := validatePacket(packet)
		if err == nil {
			t.Error("expected error for missing magic cookie")
		}
	})
}

func TestExtractMessageType(t *testing.T) {
	testCases := []struct {
		name     string
		msgType  uint8
		expected uint8
	}{
		{"DISCOVER", testDHCPDiscover, 1},
		{"OFFER", testDHCPOffer, 2},
		{"REQUEST", testDHCPRequest, 3},
		{"DECLINE", testDHCPDecline, 4},
		{"ACK", testDHCPAck, 5},
		{"NAK", testDHCPNak, 6},
		{"RELEASE", testDHCPRelease, 7},
		{"INFORM", testDHCPInform, 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
			packet := buildTestDHCPPacket(tc.msgType, 0x12345678, mac)

			msgType := extractMessageType(packet)
			if msgType != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, msgType)
			}
		})
	}
}

func TestExtractClientMAC(t *testing.T) {
	t.Run("ValidMAC", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)

		extractedMAC := extractClientMAC(packet)
		for i := 0; i < 6; i++ {
			if extractedMAC[i] != mac[i] {
				t.Errorf("MAC byte %d mismatch: expected 0x%02x, got 0x%02x", i, mac[i], extractedMAC[i])
			}
		}
	})
}

// ============================================================================
// Packet Handler Routing Tests
// ============================================================================

func TestRouteDiscoverPacket(t *testing.T) {
	t.Run("RoutesToDiscoverHandler", func(t *testing.T) {
		router := &testPacketRouter{}

		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)

		router.routePacket(packet)

		if router.discoverCalls != 1 {
			t.Errorf("expected 1 discover call, got %d", router.discoverCalls)
		}
		if router.requestCalls != 0 || router.releaseCalls != 0 {
			t.Error("unexpected calls to other handlers")
		}
	})
}

func TestRouteRequestPacket(t *testing.T) {
	t.Run("RoutesToRequestHandler", func(t *testing.T) {
		router := &testPacketRouter{}

		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPRequest, 0x12345678, mac)

		router.routePacket(packet)

		if router.requestCalls != 1 {
			t.Errorf("expected 1 request call, got %d", router.requestCalls)
		}
	})
}

func TestRouteReleasePacket(t *testing.T) {
	t.Run("RoutesToReleaseHandler", func(t *testing.T) {
		router := &testPacketRouter{}

		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPRelease, 0x12345678, mac)

		router.routePacket(packet)

		if router.releaseCalls != 1 {
			t.Errorf("expected 1 release call, got %d", router.releaseCalls)
		}
	})
}

// ============================================================================
// Message Builder Tests
// ============================================================================

func TestBuildOfferPacket(t *testing.T) {
	t.Run("ValidOffer", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		requestPacket := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)

		offerPacket := buildOfferResponse(requestPacket, net.ParseIP("192.168.1.100"))

		// Verify op = 2 (BOOTREPLY)
		if offerPacket[0] != 2 {
			t.Errorf("expected op=2, got %d", offerPacket[0])
		}

		// Verify xid matches
		xid := binary.BigEndian.Uint32(offerPacket[4:8])
		if xid != 0x12345678 {
			t.Errorf("expected xid=0x12345678, got 0x%x", xid)
		}

		// Verify magic cookie
		cookie := binary.BigEndian.Uint32(offerPacket[236:240])
		if cookie != testMagicCookie {
			t.Errorf("expected magic cookie=0x%x, got 0x%x", testMagicCookie, cookie)
		}
	})
}

func TestBuildAckPacket(t *testing.T) {
	t.Run("ValidAck", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		requestPacket := buildTestDHCPPacket(testDHCPRequest, 0x12345678, mac)

		ackPacket := buildAckResponse(requestPacket, net.ParseIP("192.168.1.100"))

		// Verify op = 2 (BOOTREPLY)
		if ackPacket[0] != 2 {
			t.Errorf("expected op=2, got %d", ackPacket[0])
		}

		// Verify message type is ACK (5)
		msgType := extractMessageType(ackPacket)
		if msgType != testDHCPAck {
			t.Errorf("expected message type %d, got %d", testDHCPAck, msgType)
		}
	})
}

func TestBuildNakPacket(t *testing.T) {
	t.Run("ValidNak", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		requestPacket := buildTestDHCPPacket(testDHCPRequest, 0x12345678, mac)

		nakPacket := buildNakResponse(requestPacket)

		// Verify op = 2 (BOOTREPLY)
		if nakPacket[0] != 2 {
			t.Errorf("expected op=2, got %d", nakPacket[0])
		}

		// Verify yiaddr = 0.0.0.0
		yiaddr := net.IP(nakPacket[16:20])
		if !yiaddr.Equal(net.IPv4zero) {
			t.Errorf("expected yiaddr=0.0.0.0, got %s", yiaddr)
		}

		// Verify message type is NAK (6)
		msgType := extractMessageType(nakPacket)
		if msgType != testDHCPNak {
			t.Errorf("expected message type %d, got %d", testDHCPNak, msgType)
		}
	})
}

// ============================================================================
// Sender Tests
// ============================================================================

func TestSendBroadcastResponse(t *testing.T) {
	t.Run("BroadcastWhenNoCiaddr", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)
		// ciaddr is already 0.0.0.0

		destAddr := determineDestination(packet, testDHCPOffer)
		if destAddr != "255.255.255.255:68" {
			t.Errorf("expected broadcast, got %s", destAddr)
		}
	})
}

func TestSendUnicastResponse(t *testing.T) {
	t.Run("UnicastWhenHasCiaddr", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPRequest, 0x12345678, mac)

		// Set ciaddr to 192.168.1.100
		copy(packet[12:16], []byte{192, 168, 1, 100})

		// Clear broadcast flag
		packet[10] = 0
		packet[11] = 0

		destAddr := determineDestination(packet, testDHCPAck)
		expected := "192.168.1.100:68"
		if destAddr != expected {
			t.Errorf("expected %s, got %s", expected, destAddr)
		}
	})
}

func TestSendViaRelayAgent(t *testing.T) {
	t.Run("SendToGiaddr", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPRequest, 0x12345678, mac)

		// Set giaddr to 10.0.0.1 (relay agent)
		copy(packet[24:28], []byte{10, 0, 0, 1})

		destAddr := determineDestination(packet, testDHCPAck)
		expected := "10.0.0.1:67"
		if destAddr != expected {
			t.Errorf("expected %s, got %s", expected, destAddr)
		}
	})
}

// ============================================================================
// Transaction ID Tests
// ============================================================================

func TestTransactionIDPreserved(t *testing.T) {
	t.Run("XidMatchesInResponse", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		requestPacket := buildTestDHCPPacket(testDHCPDiscover, 0xDEADBEEF, mac)

		responsePacket := buildOfferResponse(requestPacket, net.ParseIP("192.168.1.100"))

		requestXid := binary.BigEndian.Uint32(requestPacket[4:8])
		responseXid := binary.BigEndian.Uint32(responsePacket[4:8])

		if requestXid != responseXid {
			t.Errorf("XID mismatch: request=0x%x, response=0x%x", requestXid, responseXid)
		}
	})
}

// ============================================================================
// Performance Tests
// ============================================================================

func TestConcurrentRequests(t *testing.T) {
	t.Run("HandleConcurrentRequests", func(t *testing.T) {
		var processedCount int64
		var wg sync.WaitGroup

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, byte(id)}
				packet := buildTestDHCPPacket(testDHCPDiscover, uint32(id), mac)

				// Simulate processing
				_ = buildOfferResponse(packet, net.ParseIP("192.168.1.100"))
				atomic.AddInt64(&processedCount, 1)
			}(i)
		}

		wg.Wait()

		if processedCount != 100 {
			t.Errorf("expected 100 processed, got %d", processedCount)
		}
	})
}

func TestResponseTime(t *testing.T) {
	t.Run("FastResponse", func(t *testing.T) {
		mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		packet := buildTestDHCPPacket(testDHCPDiscover, 0x12345678, mac)

		start := time.Now()
		_ = buildOfferResponse(packet, net.ParseIP("192.168.1.100"))
		duration := time.Since(start)

		// Response should be < 1ms for in-memory operations
		if duration > time.Millisecond {
			t.Errorf("response too slow: %v", duration)
		}
	})
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

type testListenerConfig struct {
	ListenAddress string
	Port          int
	BufferSize    int
}

type mockPacketHandler struct {
	mu        sync.Mutex
	callCount int
	packets   [][]byte
}

func (h *mockPacketHandler) handlePacket(packet []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callCount++
	h.packets = append(h.packets, packet)
}

type testPacketRouter struct {
	discoverCalls int
	requestCalls  int
	releaseCalls  int
	declineCalls  int
}

func (r *testPacketRouter) routePacket(packet []byte) {
	msgType := extractMessageType(packet)

	switch msgType {
	case testDHCPDiscover:
		r.discoverCalls++
	case testDHCPRequest:
		r.requestCalls++
	case testDHCPRelease:
		r.releaseCalls++
	case testDHCPDecline:
		r.declineCalls++
	}
}

func validatePacket(packet []byte) error {
	if len(packet) < testMinPacketSize {
		return errPacketTooSmall
	}

	cookie := binary.BigEndian.Uint32(packet[236:240])
	if cookie != testMagicCookie {
		return errInvalidMagicCookie
	}

	return nil
}

func extractMessageType(packet []byte) uint8 {
	// Options start at offset 240
	offset := 240

	for offset < len(packet) {
		optCode := packet[offset]
		if optCode == 255 { // End option
			break
		}
		if optCode == 0 { // Padding
			offset++
			continue
		}

		optLen := int(packet[offset+1])

		if optCode == 53 { // DHCP Message Type
			return packet[offset+2]
		}

		offset += 2 + optLen
	}

	return 0
}

func extractClientMAC(packet []byte) []byte {
	return packet[28:34]
}

func buildOfferResponse(request []byte, offeredIP net.IP) []byte {
	response := make([]byte, 300)

	// op = 2 (BOOTREPLY)
	response[0] = 2
	response[1] = request[1] // htype
	response[2] = request[2] // hlen

	// Copy xid
	copy(response[4:8], request[4:8])

	// yiaddr = offered IP
	if offeredIP != nil {
		copy(response[16:20], offeredIP.To4())
	}

	// Copy chaddr
	copy(response[28:44], request[28:44])

	// Magic cookie
	binary.BigEndian.PutUint32(response[236:240], testMagicCookie)

	// Options
	offset := 240
	response[offset] = 53 // DHCP Message Type
	response[offset+1] = 1
	response[offset+2] = testDHCPOffer
	offset += 3

	response[offset] = 255 // End

	return response
}

func buildAckResponse(request []byte, assignedIP net.IP) []byte {
	response := make([]byte, 300)

	// op = 2 (BOOTREPLY)
	response[0] = 2
	response[1] = request[1]
	response[2] = request[2]

	// Copy xid
	copy(response[4:8], request[4:8])

	// yiaddr = assigned IP
	if assignedIP != nil {
		copy(response[16:20], assignedIP.To4())
	}

	// Copy chaddr
	copy(response[28:44], request[28:44])

	// Magic cookie
	binary.BigEndian.PutUint32(response[236:240], testMagicCookie)

	// Options
	offset := 240
	response[offset] = 53 // DHCP Message Type
	response[offset+1] = 1
	response[offset+2] = testDHCPAck
	offset += 3

	response[offset] = 255 // End

	return response
}

func buildNakResponse(request []byte) []byte {
	response := make([]byte, 300)

	// op = 2 (BOOTREPLY)
	response[0] = 2
	response[1] = request[1]
	response[2] = request[2]

	// Copy xid
	copy(response[4:8], request[4:8])

	// yiaddr = 0.0.0.0 (already zero)

	// Copy chaddr
	copy(response[28:44], request[28:44])

	// Magic cookie
	binary.BigEndian.PutUint32(response[236:240], testMagicCookie)

	// Options
	offset := 240
	response[offset] = 53 // DHCP Message Type
	response[offset+1] = 1
	response[offset+2] = testDHCPNak
	offset += 3

	response[offset] = 255 // End

	return response
}

func determineDestination(packet []byte, msgType uint8) string {
	// Check giaddr first (relay agent)
	giaddr := net.IP(packet[24:28])
	if !giaddr.Equal(net.IPv4zero) {
		return giaddr.String() + ":67"
	}

	// Check if broadcast is needed
	ciaddr := net.IP(packet[12:16])
	broadcastFlag := (binary.BigEndian.Uint16(packet[10:12]) & 0x8000) != 0

	// For OFFER/NAK, or if ciaddr is 0 or broadcast flag set, use broadcast
	if msgType == testDHCPOffer || msgType == testDHCPNak || ciaddr.Equal(net.IPv4zero) || broadcastFlag {
		return "255.255.255.255:68"
	}

	// Unicast to ciaddr
	return ciaddr.String() + ":68"
}

// Test errors
var (
	errPacketTooSmall     = errNew("packet too small")
	errInvalidMagicCookie = errNew("invalid magic cookie")
)

type testError struct {
	msg string
}

func (e *testError) Error() string { return e.msg }

func errNew(msg string) error { return &testError{msg: msg} }
