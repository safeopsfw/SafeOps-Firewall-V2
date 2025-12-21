package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/safeops/threat-intel/pkg/types"
	"github.com/safeops/threat-intel/pkg/utils"
)

// NetsetParser handles parsing of network range and CIDR block datasets
type NetsetParser struct {
	config           *NetsetParserConfig
	maxExpansionSize int
	preserveRanges   bool
	allowIPv6        bool
	logger           Logger

	// Statistics
	totalParsed       int
	cidrCount         int
	rangeCount        int
	netmaskCount      int
	expandedNetworks  int
	preservedNetworks int
	filteredPrivate   int
	filteredReserved  int
}

// NetsetParserConfig defines network parsing rules and limits
type NetsetParserConfig struct {
	MaxExpansionSize    int
	PreserveRanges      bool
	AllowIPv6           bool
	StrictCIDR          bool
	ConvertNetmasks     bool
	ExpandSmallRanges   bool
	SmallRangeThreshold int
	SkipPrivateRanges   bool
	SkipReservedRanges  bool
	ValidateBoundaries  bool
}

// NewNetsetParser creates a new network range parser
func NewNetsetParser(config *NetsetParserConfig, logger Logger) (*NetsetParser, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	if config == nil {
		config = &NetsetParserConfig{
			MaxExpansionSize:    65536,
			PreserveRanges:      true,
			AllowIPv6:           true,
			StrictCIDR:          false,
			ConvertNetmasks:     true,
			ExpandSmallRanges:   false,
			SmallRangeThreshold: 256,
			SkipPrivateRanges:   false,
			SkipReservedRanges:  false,
			ValidateBoundaries:  true,
		}
	}

	// Set defaults
	if config.MaxExpansionSize == 0 {
		config.MaxExpansionSize = 65536
	}
	if config.SmallRangeThreshold == 0 {
		config.SmallRangeThreshold = 256
	}

	return &NetsetParser{
		config:           config,
		maxExpansionSize: config.MaxExpansionSize,
		preserveRanges:   config.PreserveRanges,
		allowIPv6:        config.AllowIPv6,
		logger:           logger,
	}, nil
}

// Parse processes network range data
func (p *NetsetParser) Parse(reader io.Reader, feedID string) ([]types.IOC, error) {
	scanner := bufio.NewScanner(reader)
	iocs := make([]types.IOC, 0)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		p.totalParsed++

		// Detect format and parse
		var lineIOCs []types.IOC
		var err error

		if strings.Contains(line, "/") {
			// Either CIDR or netmask notation
			if p.isNetmaskNotation(line) && p.config.ConvertNetmasks {
				lineIOCs, err = p.parseNetmask(line, feedID)
				p.netmaskCount++
			} else {
				lineIOCs, err = p.parseCIDR(line, feedID)
				p.cidrCount++
			}
		} else if strings.Contains(line, "-") {
			// IP range notation
			lineIOCs, err = p.parseIPRange(line, feedID)
			p.rangeCount++
		} else {
			// Single IP address
			lineIOCs, err = p.parseSingleIP(line, feedID)
		}

		if err != nil {
			p.logger.Warnf("Line %d: %v", lineNumber, err)
			continue
		}

		iocs = append(iocs, lineIOCs...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading data: %w", err)
	}

	// Apply filters
	if p.config.SkipPrivateRanges {
		iocs, p.filteredPrivate = p.filterPrivateRanges(iocs)
	}
	if p.config.SkipReservedRanges {
		iocs, p.filteredReserved = p.filterReservedRanges(iocs)
	}

	p.logger.Infof("Netset parsing complete: %d total, %d CIDR, %d ranges, %d netmasks, %d expanded, %d preserved, %d private filtered, %d reserved filtered",
		p.totalParsed, p.cidrCount, p.rangeCount, p.netmaskCount, p.expandedNetworks, p.preservedNetworks,
		p.filteredPrivate, p.filteredReserved)

	return iocs, nil
}

// isNetmaskNotation checks if string uses netmask notation
func (p *NetsetParser) isNetmaskNotation(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	// Check if second part looks like a netmask (contains dots or colons)
	return strings.Contains(parts[1], ".") || strings.Contains(parts[1], ":")
}

// parseCIDR processes CIDR notation
func (p *NetsetParser) parseCIDR(cidrString, feedID string) ([]types.IOC, error) {
	// Parse CIDR
	_, network, err := net.ParseCIDR(cidrString)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Check IPv6 allowance
	if !p.allowIPv6 && network.IP.To4() == nil {
		return nil, fmt.Errorf("IPv6 not allowed")
	}

	// Normalize network address if strict mode
	if p.config.StrictCIDR {
		normalized := p.normalizeNetworkAddress(network)
		if !normalized.IP.Equal(network.IP) {
			return nil, fmt.Errorf("host bits set in network address: %s", cidrString)
		}
	}

	// Determine expansion
	shouldExpand, reason := p.shouldExpandNetwork(network)
	p.logger.Debugf("Network %s expansion decision: %v (%s)", cidrString, shouldExpand, reason)

	if shouldExpand {
		p.expandedNetworks++
		return p.expandNetwork(network, feedID)
	}

	// Preserve as network
	p.preservedNetworks++
	return []types.IOC{p.createNetworkIOC(network, feedID)}, nil
}

// parseIPRange processes IP range notation
func (p *NetsetParser) parseIPRange(rangeString, feedID string) ([]types.IOC, error) {
	parts := strings.Split(rangeString, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", rangeString)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP addresses in range")
	}

	// Validate boundaries
	if p.config.ValidateBoundaries {
		if err := p.validateNetworkBoundaries(startIP, endIP); err != nil {
			return nil, err
		}
	}

	// Convert range to CIDRs
	cidrs, err := p.rangeToCIDRs(startIP, endIP)
	if err != nil {
		return nil, err
	}

	// Process each CIDR
	iocs := make([]types.IOC, 0)
	for _, cidr := range cidrs {
		cidrIOCs, err := p.parseCIDR(cidr, feedID)
		if err != nil {
			p.logger.Warnf("Failed to parse generated CIDR %s: %v", cidr, err)
			continue
		}
		iocs = append(iocs, cidrIOCs...)
	}

	return iocs, nil
}

// parseNetmask processes netmask notation
func (p *NetsetParser) parseNetmask(netmaskString, feedID string) ([]types.IOC, error) {
	parts := strings.Split(netmaskString, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid netmask notation")
	}

	networkAddr := net.ParseIP(strings.TrimSpace(parts[0]))
	netmask := net.ParseIP(strings.TrimSpace(parts[1]))

	if networkAddr == nil || netmask == nil {
		return nil, fmt.Errorf("invalid IP or netmask")
	}

	// Convert netmask to prefix length
	prefixLen := p.netmaskToPrefixLen(netmask)
	if prefixLen == -1 {
		return nil, fmt.Errorf("invalid netmask (non-contiguous bits)")
	}

	// Create CIDR notation
	var cidr string
	if networkAddr.To4() != nil {
		cidr = fmt.Sprintf("%s/%d", networkAddr.String(), prefixLen)
	} else {
		cidr = fmt.Sprintf("%s/%d", networkAddr.String(), prefixLen)
	}

	return p.parseCIDR(cidr, feedID)
}

// parseSingleIP processes single IP address
func (p *NetsetParser) parseSingleIP(ipString, feedID string) ([]types.IOC, error) {
	ip := net.ParseIP(strings.TrimSpace(ipString))
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipString)
	}

	if !p.allowIPv6 && ip.To4() == nil {
		return nil, fmt.Errorf("IPv6 not allowed")
	}

	now := time.Now()
	iocType := types.IOCTypeIPv4
	if ip.To4() == nil {
		iocType = types.IOCTypeIPv6
	}

	ioc := types.IOC{
		IOCType:         iocType,
		Value:           ip.String(),
		NormalizedValue: ip.String(),
		ThreatType:      types.ThreatSuspicious,
		Confidence:      60.0,
		Severity:        types.SeverityMedium,
		Sources:         []string{feedID},
		SourceCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
		Tags:            []string{"netset"},
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	return []types.IOC{ioc}, nil
}

// expandNetwork expands network to individual IPs
func (p *NetsetParser) expandNetwork(network *net.IPNet, feedID string) ([]types.IOC, error) {
	size, overflow := p.calculateNetworkSize(network)
	if overflow {
		return nil, fmt.Errorf("network too large to calculate size")
	}

	if size > uint64(p.maxExpansionSize) {
		return nil, fmt.Errorf("network size %d exceeds expansion limit %d", size, p.maxExpansionSize)
	}

	iocs := make([]types.IOC, 0, size)
	now := time.Now()

	// Get network bounds
	ip := network.IP.Mask(network.Mask)
	isIPv4 := ip.To4() != nil

	// Iterate through range
	for current := duplicate(ip); network.Contains(current); current = increment(current) {
		// Skip network and broadcast for IPv4
		if isIPv4 && (current.Equal(network.IP) || current.Equal(broadcast(network))) {
			continue
		}

		iocType := types.IOCTypeIPv4
		if !isIPv4 {
			iocType = types.IOCTypeIPv6
		}

		ioc := types.IOC{
			IOCType:         iocType,
			Value:           current.String(),
			NormalizedValue: current.String(),
			ThreatType:      types.ThreatSuspicious,
			Confidence:      60.0,
			Severity:        types.SeverityMedium,
			Sources:         []string{feedID},
			SourceCount:     1,
			FirstSeen:       now,
			LastSeen:        now,
			Tags:            []string{"netset", "expanded"},
			Metadata:        map[string]interface{}{"source_network": network.String()},
			IsActive:        true,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		iocs = append(iocs, ioc)

		if len(iocs) >= p.maxExpansionSize {
			break
		}
	}

	return iocs, nil
}

// createNetworkIOC creates IOC for network block
func (p *NetsetParser) createNetworkIOC(network *net.IPNet, feedID string) types.IOC {
	now := time.Now()

	// Determine IOC type based on IP version
	iocType := types.IOCTypeIPv4
	if network.IP.To4() == nil {
		iocType = types.IOCTypeIPv6
	}

	return types.IOC{
		IOCType:         iocType,
		Value:           network.String(),
		NormalizedValue: network.String(),
		ThreatType:      types.ThreatSuspicious,
		Confidence:      60.0,
		Severity:        types.SeverityMedium,
		Sources:         []string{feedID},
		SourceCount:     1,
		FirstSeen:       now,
		LastSeen:        now,
		Tags:            []string{"netset", "cidr"},
		Metadata:        make(map[string]interface{}),
		IsActive:        true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// shouldExpandNetwork determines expansion decision
func (p *NetsetParser) shouldExpandNetwork(network *net.IPNet) (bool, string) {
	if p.preserveRanges {
		return false, "preserve ranges enabled"
	}

	size, overflow := p.calculateNetworkSize(network)
	if overflow {
		return false, "network too large"
	}

	if size > uint64(p.maxExpansionSize) {
		return false, fmt.Sprintf("size %d exceeds limit %d", size, p.maxExpansionSize)
	}

	// Single host
	ones, bits := network.Mask.Size()
	if ones == bits {
		return true, "single host network"
	}

	if p.config.ExpandSmallRanges && int(size) <= p.config.SmallRangeThreshold {
		return true, fmt.Sprintf("small range (%d IPs)", size)
	}

	return false, "default preserve"
}

// rangeToCIDRs converts IP range to CIDR blocks
func (p *NetsetParser) rangeToCIDRs(startIP, endIP net.IP) ([]string, error) {
	cidrs := make([]string, 0)

	// Ensure same IP version
	if (startIP.To4() == nil) != (endIP.To4() == nil) {
		return nil, fmt.Errorf("mixed IPv4/IPv6 range")
	}

	isIPv4 := startIP.To4() != nil

	// Convert to big.Int for arithmetic
	start := ipToInt(startIP)
	end := ipToInt(endIP)

	current := new(big.Int).Set(start)
	one := big.NewInt(1)

	for current.Cmp(end) <= 0 {
		// Find largest CIDR that fits
		maxSize := new(big.Int).Sub(end, current)
		maxSize.Add(maxSize, one)

		// Find highest bit set for max CIDR size
		prefixLen := p.findPrefixLength(current, maxSize, isIPv4)

		// Create CIDR
		ip := intToIP(current, isIPv4)
		cidr := fmt.Sprintf("%s/%d", ip.String(), prefixLen)
		cidrs = append(cidrs, cidr)

		// Calculate CIDR size and advance
		var bits int
		if isIPv4 {
			bits = 32
		} else {
			bits = 128
		}
		cidrSize := new(big.Int).Lsh(one, uint(bits-prefixLen))
		current.Add(current, cidrSize)
	}

	return cidrs, nil
}

// findPrefixLength finds optimal CIDR prefix for range
func (p *NetsetParser) findPrefixLength(start, maxSize *big.Int, isIPv4 bool) int {
	bits := 128
	if isIPv4 {
		bits = 32
	}

	// Start with smallest prefix (largest network)
	for prefixLen := 0; prefixLen <= bits; prefixLen++ {
		networkSize := new(big.Int).Lsh(big.NewInt(1), uint(bits-prefixLen))

		// Check if network aligns with start
		mask := new(big.Int).Sub(networkSize, big.NewInt(1))
		mask.Not(mask)
		aligned := new(big.Int).And(start, mask)

		if aligned.Cmp(start) == 0 && networkSize.Cmp(maxSize) <= 0 {
			return prefixLen
		}
	}

	return bits // /32 or /128
}

// calculateNetworkSize calculates usable IPs
func (p *NetsetParser) calculateNetworkSize(network *net.IPNet) (uint64, bool) {
	ones, bits := network.Mask.Size()
	hostBits := bits - ones

	if hostBits > 63 {
		return 0, true // Overflow
	}

	size := uint64(1) << uint(hostBits)

	// Subtract network and broadcast for IPv4
	if network.IP.To4() != nil && hostBits > 0 {
		size -= 2
	}

	return size, false
}

// normalizeNetworkAddress clears host bits
func (p *NetsetParser) normalizeNetworkAddress(network *net.IPNet) *net.IPNet {
	return &net.IPNet{
		IP:   network.IP.Mask(network.Mask),
		Mask: network.Mask,
	}
}

// validateNetworkBoundaries validates range boundaries
func (p *NetsetParser) validateNetworkBoundaries(startIP, endIP net.IP) error {
	if startIP == nil || endIP == nil {
		return fmt.Errorf("nil IP address")
	}

	// Check same version
	if (startIP.To4() == nil) != (endIP.To4() == nil) {
		return fmt.Errorf("mixed IPv4/IPv6 in range")
	}

	// Check order
	if bytes.Compare(startIP, endIP) > 0 {
		return fmt.Errorf("start IP greater than end IP")
	}

	return nil
}

// filterPrivateRanges removes private IP ranges
func (p *NetsetParser) filterPrivateRanges(iocs []types.IOC) ([]types.IOC, int) {
	filtered := make([]types.IOC, 0, len(iocs))
	filteredCount := 0

	for _, ioc := range iocs {
		if utils.IsPublicIP(ioc.Value) {
			filtered = append(filtered, ioc)
		} else {
			filteredCount++
		}
	}

	return filtered, filteredCount
}

// filterReservedRanges removes reserved ranges
func (p *NetsetParser) filterReservedRanges(iocs []types.IOC) ([]types.IOC, int) {
	filtered := make([]types.IOC, 0, len(iocs))
	filteredCount := 0

	for _, ioc := range iocs {
		ip := net.ParseIP(ioc.Value)
		if ip != nil && !p.isReservedIP(ip) {
			filtered = append(filtered, ioc)
		} else {
			filteredCount++
		}
	}

	return filtered, filteredCount
}

// isReservedIP checks for reserved ranges
func (p *NetsetParser) isReservedIP(ip net.IP) bool {
	// Loopback
	if ip.IsLoopback() {
		return true
	}

	// Multicast
	if ip.IsMulticast() {
		return true
	}

	// Link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// netmaskToPrefixLen converts netmask to prefix length
func (p *NetsetParser) netmaskToPrefixLen(netmask net.IP) int {
	var mask []byte
	if netmask.To4() != nil {
		mask = netmask.To4()
	} else {
		mask = netmask.To16()
	}

	prefixLen := 0
	inOnes := true

	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			bit := (b >> uint(i)) & 1
			if inOnes {
				if bit == 1 {
					prefixLen++
				} else {
					inOnes = false
				}
			} else {
				if bit == 1 {
					return -1 // Non-contiguous
				}
			}
		}
	}

	return prefixLen
}

// Helper functions

func duplicate(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func increment(ip net.IP) net.IP {
	incremented := duplicate(ip)
	for i := len(incremented) - 1; i >= 0; i-- {
		incremented[i]++
		if incremented[i] > 0 {
			break
		}
	}
	return incremented
}

func broadcast(network *net.IPNet) net.IP {
	ip := duplicate(network.IP)
	for i := range network.Mask {
		ip[i] |= ^network.Mask[i]
	}
	return ip
}

func ipToInt(ip net.IP) *big.Int {
	if ip.To4() != nil {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}
	return new(big.Int).SetBytes(ip)
}

func intToIP(i *big.Int, isIPv4 bool) net.IP {
	bytes := i.Bytes()

	if isIPv4 {
		// Pad to 4 bytes
		padded := make([]byte, 4)
		copy(padded[4-len(bytes):], bytes)
		return net.IP(padded)
	}

	// Pad to 16 bytes for IPv6
	padded := make([]byte, 16)
	copy(padded[16-len(bytes):], bytes)
	return net.IP(padded)
}

// Close performs cleanup
func (p *NetsetParser) Close() error {
	p.logger.Debugf("Netset parser closed. Stats: %d total, %d CIDR, %d ranges, %d netmasks, %d expanded, %d preserved",
		p.totalParsed, p.cidrCount, p.rangeCount, p.netmaskCount, p.expandedNetworks, p.preservedNetworks)
	return nil
}
