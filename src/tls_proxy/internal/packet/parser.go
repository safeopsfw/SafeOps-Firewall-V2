package packet

// PacketInfo contains parsed packet information
type PacketInfo struct {
	IsHTTP        bool
	IsHTTPS       bool
	IsTCP         bool
	IsUDP         bool
	SourceIP      string
	DestIP        string
	SourcePort    uint16
	DestPort      uint16
	Protocol      string
	HTTPMethod    string
	HTTPHost      string
	HTTPPath      string
	RawPayload    []byte
}

// ParsePacket parses raw packet bytes (stub for Phase 3A)
func ParsePacket(rawPacket []byte, sourceIP, destIP string, sourcePort, destPort uint32, protocol string) (*PacketInfo, error) {
	info := &PacketInfo{
		SourceIP:   sourceIP,
		DestIP:     destIP,
		SourcePort: uint16(sourcePort),
		DestPort:   uint16(destPort),
		Protocol:   protocol,
		RawPayload: rawPacket,
	}

	// Simple HTTP detection on port 80
	if protocol == "TCP" && (destPort == 80 || sourcePort == 80) {
		info.IsHTTP = true
		info.HTTPMethod = "GET" // Stub
	}

	if protocol == "TCP" && (destPort == 443 || sourcePort == 443) {
		info.IsHTTPS = true
	}

	return info, nil
}

// ClassifyPacket determines packet type
func ClassifyPacket(info *PacketInfo) string {
	if info.IsHTTP {
		return "HTTP"
	}
	if info.IsHTTPS {
		return "TLS"
	}
	return "TCP"
}

// ShouldIntercept determines if packet should be intercepted
func ShouldIntercept(info *PacketInfo) bool {
	// Only intercept HTTP for Phase 3A
	return info.IsHTTP && info.HTTPMethod == "GET"
}

// GetDestinationDomain returns destination domain
func GetDestinationDomain(info *PacketInfo) string {
	if info.HTTPHost != "" {
		return info.HTTPHost
	}
	return info.DestIP
}
