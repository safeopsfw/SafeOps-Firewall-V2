package verdict

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/wiresock/ndisapi-go"
)

// InjectHTMLBlockPage injects a custom HTML page for HTTP requests
// This responds to the client with a "blocked" page instead of RST
func (e *Engine) InjectHTMLBlockPage(
	adapterHandle ndisapi.Handle,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	srcMAC, dstMAC [6]byte,
	reason string,
	ruleID string,
) error {
	// Build custom HTML response
	htmlBody := e.buildBlockPageHTML(reason, ruleID)

	// Build HTTP response
	httpResponse := fmt.Sprintf(
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"Server: SafeOps-Engine\r\n"+
			"Cache-Control: no-store, no-cache, must-revalidate\r\n"+
			"\r\n"+
			"%s",
		len(htmlBody),
		htmlBody,
	)

	// Build full packet: Ethernet + IP + TCP + HTTP
	packet := e.buildHTTPResponsePacket(
		dstMAC, srcMAC,
		dstIP, srcIP,
		dstPort, srcPort,
		[]byte(httpResponse),
	)

	// Send response packet
	if err := e.sendPacket(adapterHandle, packet); err != nil {
		return fmt.Errorf("failed to inject HTML block page: %w", err)
	}

	// Send TCP FIN to close connection gracefully
	finPacket := e.buildTCPFinPacket(dstMAC, srcMAC, dstIP, srcIP, dstPort, srcPort)
	if err := e.sendPacket(adapterHandle, finPacket); err != nil {
		return fmt.Errorf("failed to send FIN: %w", err)
	}

	return nil
}

// buildBlockPageHTML generates the HTML block page
func (e *Engine) buildBlockPageHTML(reason, ruleID string) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05 MST")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - SafeOps Firewall</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 600px;
            width: 100%%;
            padding: 40px;
            text-align: center;
        }
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #e53e3e;
            font-size: 32px;
            margin-bottom: 16px;
            font-weight: 700;
        }
        .subtitle {
            color: #4a5568;
            font-size: 18px;
            margin-bottom: 32px;
        }
        .reason-box {
            background: #f7fafc;
            border-left: 4px solid #e53e3e;
            padding: 20px;
            margin: 24px 0;
            text-align: left;
            border-radius: 4px;
        }
        .reason-box .label {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 8px;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .reason-box .value {
            color: #4a5568;
            font-size: 16px;
            word-break: break-word;
        }
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-top: 24px;
        }
        .info-item {
            background: #f7fafc;
            padding: 16px;
            border-radius: 8px;
            text-align: left;
        }
        .info-item .label {
            font-size: 12px;
            color: #718096;
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-item .value {
            font-size: 14px;
            color: #2d3748;
            font-family: "Courier New", monospace;
        }
        .footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e2e8f0;
            color: #718096;
            font-size: 14px;
        }
        .footer-logo {
            color: #667eea;
            font-weight: 700;
            font-size: 16px;
            margin-bottom: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>Access Blocked</h1>
        <p class="subtitle">This website has been blocked by your firewall policy</p>

        <div class="reason-box">
            <div class="label">Block Reason</div>
            <div class="value">%s</div>
        </div>

        <div class="info-grid">
            <div class="info-item">
                <div class="label">Rule ID</div>
                <div class="value">%s</div>
            </div>
            <div class="info-item">
                <div class="label">Timestamp</div>
                <div class="value">%s</div>
            </div>
        </div>

        <div class="footer">
            <div class="footer-logo">🔒 SafeOps Firewall</div>
            <div>If you believe this is a mistake, please contact your network administrator.</div>
        </div>
    </div>
</body>
</html>`, reason, ruleID, timestamp)

	return html
}

// buildHTTPResponsePacket builds a complete HTTP response packet
func (e *Engine) buildHTTPResponsePacket(
	srcMAC, dstMAC [6]byte,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	httpPayload []byte,
) []byte {
	// Calculate sizes
	ethHeaderSize := 14
	ipHeaderSize := 20
	tcpHeaderSize := 20
	totalSize := ethHeaderSize + ipHeaderSize + tcpHeaderSize + len(httpPayload)

	packet := make([]byte, totalSize)

	// === Ethernet Header ===
	copy(packet[0:6], dstMAC[:])
	copy(packet[6:12], srcMAC[:])
	packet[12] = 0x08 // IPv4
	packet[13] = 0x00

	// === IP Header ===
	ipStart := ethHeaderSize
	packet[ipStart] = 0x45                                                    // Version 4, Header length 5
	packet[ipStart+1] = 0x00                                                  // DSCP/ECN
	binary.BigEndian.PutUint16(packet[ipStart+2:ipStart+4], uint16(totalSize-ethHeaderSize)) // Total length
	binary.BigEndian.PutUint16(packet[ipStart+4:ipStart+6], 0)               // ID
	binary.BigEndian.PutUint16(packet[ipStart+6:ipStart+8], 0)               // Flags/Fragment
	packet[ipStart+8] = 64                                                    // TTL
	packet[ipStart+9] = 6                                                     // Protocol: TCP
	binary.BigEndian.PutUint16(packet[ipStart+10:ipStart+12], 0)             // Checksum (will calculate)
	copy(packet[ipStart+12:ipStart+16], srcIP.To4())                          // Source IP
	copy(packet[ipStart+16:ipStart+20], dstIP.To4())                          // Destination IP

	// Calculate IP checksum
	ipChecksum := e.calculateChecksum(packet[ipStart : ipStart+ipHeaderSize])
	binary.BigEndian.PutUint16(packet[ipStart+10:ipStart+12], ipChecksum)

	// === TCP Header ===
	tcpStart := ipStart + ipHeaderSize
	binary.BigEndian.PutUint16(packet[tcpStart:tcpStart+2], srcPort)     // Source port
	binary.BigEndian.PutUint16(packet[tcpStart+2:tcpStart+4], dstPort)   // Destination port
	binary.BigEndian.PutUint32(packet[tcpStart+4:tcpStart+8], 1)         // Sequence number
	binary.BigEndian.PutUint32(packet[tcpStart+8:tcpStart+12], 1)        // Acknowledgment number
	packet[tcpStart+12] = 0x50                                            // Data offset (5 * 4 = 20 bytes)
	packet[tcpStart+13] = 0x18                                            // Flags: PSH + ACK
	binary.BigEndian.PutUint16(packet[tcpStart+14:tcpStart+16], 65535)   // Window size
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], 0)       // Checksum (will calculate)
	binary.BigEndian.PutUint16(packet[tcpStart+18:tcpStart+20], 0)       // Urgent pointer

	// Copy HTTP payload
	payloadStart := tcpStart + tcpHeaderSize
	copy(packet[payloadStart:], httpPayload)

	// Calculate TCP checksum
	tcpSegment := packet[tcpStart:]
	tcpChecksum := e.calculateTCPChecksum(packet[ipStart+12:ipStart+20], tcpSegment)
	binary.BigEndian.PutUint16(packet[tcpStart+16:tcpStart+18], tcpChecksum)

	return packet
}

// buildTCPFinPacket builds a TCP FIN packet to close the connection
func (e *Engine) buildTCPFinPacket(srcMAC, dstMAC [6]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 54) // Ethernet(14) + IP(20) + TCP(20)

	// === Ethernet Header ===
	copy(packet[0:6], dstMAC[:])
	copy(packet[6:12], srcMAC[:])
	packet[12] = 0x08
	packet[13] = 0x00

	// === IP Header ===
	packet[14] = 0x45
	packet[15] = 0x00
	binary.BigEndian.PutUint16(packet[16:18], 40) // Total length (IP + TCP)
	binary.BigEndian.PutUint16(packet[18:20], 0)
	binary.BigEndian.PutUint16(packet[20:22], 0)
	packet[22] = 64  // TTL
	packet[23] = 6   // TCP
	binary.BigEndian.PutUint16(packet[24:26], 0)
	copy(packet[26:30], srcIP.To4())
	copy(packet[30:34], dstIP.To4())

	ipChecksum := e.calculateChecksum(packet[14:34])
	binary.BigEndian.PutUint16(packet[24:26], ipChecksum)

	// === TCP Header ===
	binary.BigEndian.PutUint16(packet[34:36], srcPort)
	binary.BigEndian.PutUint16(packet[36:38], dstPort)
	binary.BigEndian.PutUint32(packet[38:42], 2)  // Sequence number
	binary.BigEndian.PutUint32(packet[42:46], 2)  // Acknowledgment number
	packet[46] = 0x50                             // Data offset
	packet[47] = 0x11                             // Flags: FIN + ACK
	binary.BigEndian.PutUint16(packet[48:50], 0)
	binary.BigEndian.PutUint16(packet[50:52], 0)
	binary.BigEndian.PutUint16(packet[52:54], 0)

	tcpChecksum := e.calculateTCPChecksum(packet[26:34], packet[34:54])
	binary.BigEndian.PutUint16(packet[50:52], tcpChecksum)

	return packet
}
