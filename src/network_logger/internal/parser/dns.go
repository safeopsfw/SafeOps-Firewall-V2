package parser

import (
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/safeops/network_logger/pkg/models"
)

// DNSParser parses DNS packets
type DNSParser struct{}

// NewDNSParser creates a new DNS parser
func NewDNSParser() *DNSParser {
	return &DNSParser{}
}

// Parse extracts DNS information
func (p *DNSParser) Parse(dns *layers.DNS) *models.DNSData {
	if dns == nil {
		return nil
	}

	dnsData := &models.DNSData{
		TransactionID: dns.ID,
		Flags:         uint16(dns.OpCode)<<11 | boolToUint16(dns.QR)<<15 | boolToUint16(dns.AA)<<10 | boolToUint16(dns.TC)<<9 | boolToUint16(dns.RD)<<8 | boolToUint16(dns.RA)<<7,
		QR:            boolToUint8(dns.QR),
		Opcode:        uint8(dns.OpCode),
		AA:            boolToUint8(dns.AA),
		TC:            boolToUint8(dns.TC),
		RD:            boolToUint8(dns.RD),
		RA:            boolToUint8(dns.RA),
		Z:             0,
		Rcode:         uint8(dns.ResponseCode),
	}

	// Parse queries
	if len(dns.Questions) > 0 {
		dnsData.Queries = make([]models.DNSQuery, 0, len(dns.Questions))
		for _, q := range dns.Questions {
			query := models.DNSQuery{
				Name:  string(q.Name),
				Type:  getDNSTypeName(q.Type),
				Class: getDNSClassName(q.Class),
			}
			dnsData.Queries = append(dnsData.Queries, query)
		}
	}

	// Parse answers
	if len(dns.Answers) > 0 {
		dnsData.Answers = make([]models.DNSAnswer, 0, len(dns.Answers))
		for _, a := range dns.Answers {
			answer := models.DNSAnswer{
				Name:  string(a.Name),
				Type:  getDNSTypeName(a.Type),
				Class: getDNSClassName(a.Class),
				TTL:   a.TTL,
				Data:  formatDNSAnswerData(a),
			}
			dnsData.Answers = append(dnsData.Answers, answer)
		}
	}

	return dnsData
}

// formatDNSAnswerData formats DNS answer data based on type
func formatDNSAnswerData(answer layers.DNSResourceRecord) string {
	switch answer.Type {
	case layers.DNSTypeA:
		return answer.IP.String()
	case layers.DNSTypeAAAA:
		return answer.IP.String()
	case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
		return string(answer.CNAME)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s", answer.MX.Preference, string(answer.MX.Name))
	case layers.DNSTypeTXT:
		if len(answer.TXTs) > 0 {
			return string(answer.TXTs[0])
		}
	case layers.DNSTypeSOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			string(answer.SOA.MName),
			string(answer.SOA.RName),
			answer.SOA.Serial,
			answer.SOA.Refresh,
			answer.SOA.Retry,
			answer.SOA.Expire,
			answer.SOA.Minimum)
	}

	return fmt.Sprintf("%x", answer.Data)
}

// getDNSTypeName returns human-readable DNS type
func getDNSTypeName(dnsType layers.DNSType) string {
	switch dnsType {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", dnsType)
	}
}

// getDNSClassName returns human-readable DNS class
func getDNSClassName(dnsClass layers.DNSClass) string {
	switch dnsClass {
	case layers.DNSClassIN:
		return "IN"
	case layers.DNSClassCS:
		return "CS"
	case layers.DNSClassCH:
		return "CH"
	case layers.DNSClassHS:
		return "HS"
	default:
		return fmt.Sprintf("CLASS%d", dnsClass)
	}
}

// Helper functions
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func boolToUint16(b bool) uint16 {
	if b {
		return 1
	}
	return 0
}
