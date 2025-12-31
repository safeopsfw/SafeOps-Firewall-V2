// Package authoritative implements authoritative DNS server functionality.
package authoritative

import (
	"context"
	"log"
	"strings"

	"safeops/dns_server/internal/protocol"
	"safeops/dns_server/internal/storage"
)

// ============================================================================
// Authoritative Server
// ============================================================================

// Server handles authoritative DNS queries for local zones
type Server struct {
	zoneStore *storage.ZoneStore
	zones     []string // List of authoritative zone names
}

// NewServer creates a new authoritative DNS server
func NewServer(zoneStore *storage.ZoneStore) *Server {
	return &Server{
		zoneStore: zoneStore,
		zones:     make([]string, 0),
	}
}

// ============================================================================
// Zone Management
// ============================================================================

// AddZone adds a zone to the authoritative server
func (s *Server) AddZone(zoneName string) {
	zoneName = strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for _, z := range s.zones {
		if z == zoneName {
			return // Already exists
		}
	}
	s.zones = append(s.zones, zoneName)
	log.Printf("Authoritative zone added: %s", zoneName)
}

// RemoveZone removes a zone from the authoritative server
func (s *Server) RemoveZone(zoneName string) {
	zoneName = strings.ToLower(strings.TrimSuffix(zoneName, "."))
	for i, z := range s.zones {
		if z == zoneName {
			s.zones = append(s.zones[:i], s.zones[i+1:]...)
			log.Printf("Authoritative zone removed: %s", zoneName)
			return
		}
	}
}

// IsAuthoritative checks if server is authoritative for domain
func (s *Server) IsAuthoritative(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, zone := range s.zones {
		if domain == zone || strings.HasSuffix(domain, "."+zone) {
			return true
		}
	}
	return false
}

// GetZoneForDomain returns the zone name for a domain
func (s *Server) GetZoneForDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, zone := range s.zones {
		if domain == zone || strings.HasSuffix(domain, "."+zone) {
			return zone
		}
	}
	return ""
}

// ============================================================================
// Query Handling
// ============================================================================

// Query handles an authoritative DNS query
func (s *Server) Query(ctx context.Context, q protocol.Question) ([]protocol.ResourceRecord, error) {
	zoneName := s.GetZoneForDomain(q.Name)
	if zoneName == "" {
		return nil, nil // Not authoritative
	}

	recordType := recordTypeToString(q.Type)
	records, err := s.zoneStore.GetRecordsByName(ctx, zoneName, q.Name, recordType)
	if err != nil {
		return nil, err
	}

	// Convert storage records to protocol records
	var results []protocol.ResourceRecord
	for _, r := range records {
		rr := storageToProtocol(r)
		if rr != nil {
			results = append(results, *rr)
		}
	}

	return results, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func recordTypeToString(rt protocol.RecordType) string {
	switch rt {
	case protocol.TypeA:
		return "A"
	case protocol.TypeAAAA:
		return "AAAA"
	case protocol.TypeCNAME:
		return "CNAME"
	case protocol.TypeMX:
		return "MX"
	case protocol.TypeTXT:
		return "TXT"
	case protocol.TypeNS:
		return "NS"
	case protocol.TypePTR:
		return "PTR"
	case protocol.TypeSRV:
		return "SRV"
	case protocol.TypeSOA:
		return "SOA"
	default:
		return "A"
	}
}

func storageToProtocol(r *storage.Record) *protocol.ResourceRecord {
	rt := stringToRecordType(r.Type)
	return &protocol.ResourceRecord{
		Name:       r.Name,
		Type:       rt,
		Class:      protocol.ClassIN,
		TTL:        r.TTL,
		ParsedData: r.Value,
	}
}

func stringToRecordType(s string) protocol.RecordType {
	switch strings.ToUpper(s) {
	case "A":
		return protocol.TypeA
	case "AAAA":
		return protocol.TypeAAAA
	case "CNAME":
		return protocol.TypeCNAME
	case "MX":
		return protocol.TypeMX
	case "TXT":
		return protocol.TypeTXT
	case "NS":
		return protocol.TypeNS
	case "PTR":
		return protocol.TypePTR
	case "SRV":
		return protocol.TypeSRV
	case "SOA":
		return protocol.TypeSOA
	default:
		return protocol.TypeA
	}
}
