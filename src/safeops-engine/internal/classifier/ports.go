package classifier

// ===============================================
// CENTRALIZED PORT DEFINITIONS FOR SAFEOPS ENGINE
// ===============================================
// All port assignments in one place to avoid conflicts

// SafeOps Internal Service Ports
const (
	// dnsproxy listens here (WinpkFilter redirects port 53 → this)
	PortDNSProxy = 15353

	// mitmproxy SOCKS5 listens here (we tunnel HTTP/HTTPS through this)
	PortMITMProxy = 18080

	// SafeOps API server
	PortAPI = 9002
)

// Traffic Classification Ports
const (
	// DNS - always redirect to dnsproxy
	PortDNS = 53

	// HTTP/HTTPS - redirect to mitmproxy
	PortHTTP  = 80
	PortHTTPS = 443

	// DHCP - CRITICAL: Always bypass (network operations)
	PortDHCPServer = 67 // DHCP Server (UDP)
	PortDHCPClient = 68 // DHCP Client (UDP)
)

// Gaming Ports - BYPASS (zero latency, no inspection)
var GamingPorts = map[uint16]bool{
	// Steam
	27000: true, 27015: true, 27016: true, 27030: true, 27031: true, 27036: true,
	// Epic Games
	9000: true, 9001: true, 9003: true,
	// Battle.net
	1119: true, 6113: true,
	// Xbox Live
	3074: true,
	// PlayStation
	3478: true, 3479: true, 3658: true,
}

// VoIP Ports - BYPASS (low latency required)
var VoIPPorts = map[uint16]bool{
	// Discord
	50000: true, 50001: true, 50002: true,
	// Teams
	50010: true, 50019: true,
	// Zoom
	8801: true, 8802: true, 8810: true,
}

// Streaming Ports - BYPASS
var StreamingPorts = map[uint16]bool{
	// RTMP
	1935: true,
	// RTSP
	554: true,
}

// Bypass Domains (checked via SNI) - BYPASS
var BypassDomains = []string{
	"steampowered.com",
	"steamcommunity.com",
	"epicgames.com",
	"discord.gg",
	"discord.com",
	"discordapp.com",
	"twitch.tv",
	"youtube.com",
	"googlevideo.com",
	"netflix.com",
	"nflxvideo.net",
}
