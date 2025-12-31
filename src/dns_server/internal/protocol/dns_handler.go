// Package protocol implements the DNS query processing pipeline.
package protocol

import (
	"context"
	"log"
	"net"
	"strings"
	"time"
)

// ============================================================================
// DNS Handler - Central Query Processing
// ============================================================================

// Handler processes DNS queries and generates responses
type Handler struct {
	// Resolver for upstream queries
	resolver Resolver

	// Zone store for authoritative data
	zoneStore ZoneStore

	// Cache for response caching
	cache Cache

	// Filter for domain blocking
	filter Filter

	// Captive portal handler
	captive CaptiveHandler

	// Configuration
	config *HandlerConfig
}

// HandlerConfig holds handler configuration
type HandlerConfig struct {
	AuthoritativeZones []string
	RecursionEnabled   bool
	CacheEnabled       bool
	FilterEnabled      bool
	CaptiveEnabled     bool
}

// Resolver interface for upstream DNS resolution
type Resolver interface {
	Resolve(ctx context.Context, q Question) ([]ResourceRecord, error)
}

// ZoneStore interface for authoritative zone data
type ZoneStore interface {
	GetRecords(ctx context.Context, zoneName, name, recordType string) ([]ResourceRecord, error)
	IsAuthoritative(zoneName string) bool
}

// Cache interface for DNS response caching
type Cache interface {
	Get(key string) ([]ResourceRecord, bool)
	Set(key string, records []ResourceRecord, ttl time.Duration)
}

// Filter interface for domain filtering
type Filter interface {
	IsBlocked(domain string) (bool, string)
	IsAllowed(domain string) bool
}

// CaptiveHandler interface for captive portal
type CaptiveHandler interface {
	ShouldRedirect(ctx context.Context, clientIP net.IP, domain string) bool
	GetRedirectIP() net.IP
}

// NewHandler creates a new DNS handler
func NewHandler(config *HandlerConfig) *Handler {
	return &Handler{
		config: config,
	}
}

// SetResolver sets the upstream resolver
func (h *Handler) SetResolver(r Resolver) {
	h.resolver = r
}

// SetZoneStore sets the authoritative zone store
func (h *Handler) SetZoneStore(zs ZoneStore) {
	h.zoneStore = zs
}

// SetCache sets the response cache
func (h *Handler) SetCache(c Cache) {
	h.cache = c
}

// SetFilter sets the domain filter
func (h *Handler) SetFilter(f Filter) {
	h.filter = f
}

// SetCaptive sets the captive portal handler
func (h *Handler) SetCaptive(c CaptiveHandler) {
	h.captive = c
}

// ============================================================================
// Query Processing
// ============================================================================

// HandleQuery processes a DNS query and returns a response
func (h *Handler) HandleQuery(ctx context.Context, query *Message, clientIP net.IP) *Message {
	startTime := time.Now()

	// Create response from query
	response := h.createResponse(query)

	// Ensure at least one question
	if len(query.Questions) == 0 {
		response.Flags.RCODE = RCodeFormError
		return response
	}

	// Process each question (usually just one)
	for _, q := range query.Questions {
		answers := h.processQuestion(ctx, q, clientIP)
		response.Answers = append(response.Answers, answers...)
	}

	// Set response code based on results
	if len(response.Answers) == 0 && response.Flags.RCODE == RCodeNoError {
		response.Flags.RCODE = RCodeNXDomain
	}

	// Log query
	elapsed := time.Since(startTime)
	log.Printf("DNS: %s %s -> %d answers (%v)",
		query.Questions[0].Name,
		recordTypeString(query.Questions[0].Type),
		len(response.Answers),
		elapsed)

	return response
}

func (h *Handler) processQuestion(ctx context.Context, q Question, clientIP net.IP) []ResourceRecord {
	domain := strings.ToLower(q.Name)

	// 1. Check captive portal redirect
	if h.config.CaptiveEnabled && h.captive != nil {
		if h.captive.ShouldRedirect(ctx, clientIP, domain) {
			return h.createCaptiveRedirect(q)
		}
	}

	// 2. Check allowlist (bypasses blocking)
	if h.config.FilterEnabled && h.filter != nil {
		if !h.filter.IsAllowed(domain) {
			// Check blocklist
			if blocked, reason := h.filter.IsBlocked(domain); blocked {
				log.Printf("Blocked: %s (%s)", domain, reason)
				return nil // Returns NXDOMAIN
			}
		}
	}

	// 3. Check cache
	if h.config.CacheEnabled && h.cache != nil {
		cacheKey := cacheKey(q)
		if records, ok := h.cache.Get(cacheKey); ok {
			return records
		}
	}

	// 4. Check authoritative zones
	records := h.queryAuthoritative(ctx, q)
	if records != nil {
		h.cacheRecords(q, records)
		return records
	}

	// 5. Forward to upstream resolver
	if h.config.RecursionEnabled && h.resolver != nil {
		records, err := h.resolver.Resolve(ctx, q)
		if err != nil {
			log.Printf("Resolver error for %s: %v", domain, err)
			return nil
		}
		h.cacheRecords(q, records)
		return records
	}

	return nil
}

// ============================================================================
// Response Building
// ============================================================================

func (h *Handler) createResponse(query *Message) *Message {
	response := NewMessage(query.ID)
	response.Flags.QR = true // This is a response
	response.Flags.Opcode = query.Flags.Opcode
	response.Flags.RD = query.Flags.RD
	response.Flags.RA = h.config.RecursionEnabled
	response.Flags.RCODE = RCodeNoError

	// Copy questions to response
	response.Questions = make([]Question, len(query.Questions))
	copy(response.Questions, query.Questions)

	return response
}

func (h *Handler) createCaptiveRedirect(q Question) []ResourceRecord {
	if h.captive == nil {
		return nil
	}

	redirectIP := h.captive.GetRedirectIP()
	if redirectIP == nil {
		return nil
	}

	switch q.Type {
	case TypeA:
		ip4 := redirectIP.To4()
		if ip4 != nil {
			return []ResourceRecord{{
				Name:       q.Name,
				Type:       TypeA,
				Class:      ClassIN,
				TTL:        60, // Short TTL for redirect
				RData:      ip4,
				ParsedData: redirectIP,
			}}
		}
	case TypeAAAA:
		ip6 := redirectIP.To16()
		if ip6 != nil {
			return []ResourceRecord{{
				Name:       q.Name,
				Type:       TypeAAAA,
				Class:      ClassIN,
				TTL:        60,
				RData:      ip6,
				ParsedData: redirectIP,
			}}
		}
	}

	return nil
}

func (h *Handler) queryAuthoritative(ctx context.Context, q Question) []ResourceRecord {
	if h.zoneStore == nil {
		return nil
	}

	// Extract zone from domain name
	zoneName := h.findZone(q.Name)
	if zoneName == "" {
		return nil
	}

	// Query zone store
	records, err := h.zoneStore.GetRecords(ctx, zoneName, q.Name, recordTypeString(q.Type))
	if err != nil {
		log.Printf("Zone query error: %v", err)
		return nil
	}

	return records
}

func (h *Handler) findZone(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	for _, zone := range h.config.AuthoritativeZones {
		zone = strings.TrimSuffix(strings.ToLower(zone), ".")
		if domain == zone || strings.HasSuffix(domain, "."+zone) {
			return zone
		}
	}

	return ""
}

func (h *Handler) cacheRecords(q Question, records []ResourceRecord) {
	if !h.config.CacheEnabled || h.cache == nil || len(records) == 0 {
		return
	}

	// Use minimum TTL from records
	minTTL := uint32(3600)
	for _, r := range records {
		if r.TTL < minTTL {
			minTTL = r.TTL
		}
	}

	h.cache.Set(cacheKey(q), records, time.Duration(minTTL)*time.Second)
}

// ============================================================================
// Helper Functions
// ============================================================================

func cacheKey(q Question) string {
	return strings.ToLower(q.Name) + ":" + recordTypeString(q.Type)
}

func recordTypeString(rt RecordType) string {
	switch rt {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeNS:
		return "NS"
	case TypePTR:
		return "PTR"
	case TypeSRV:
		return "SRV"
	case TypeSOA:
		return "SOA"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// Error Response Builders
// ============================================================================

// CreateErrorResponse creates an error response for the given query
func CreateErrorResponse(query *Message, rcode ResponseCode) *Message {
	response := NewMessage(query.ID)
	response.Flags.QR = true
	response.Flags.Opcode = query.Flags.Opcode
	response.Flags.RD = query.Flags.RD
	response.Flags.RCODE = rcode
	response.Questions = query.Questions
	return response
}

// CreateServFailResponse creates a server failure response
func CreateServFailResponse(query *Message) *Message {
	return CreateErrorResponse(query, RCodeServFail)
}

// CreateNXDomainResponse creates a non-existent domain response
func CreateNXDomainResponse(query *Message) *Message {
	return CreateErrorResponse(query, RCodeNXDomain)
}

// CreateRefusedResponse creates a refused response
func CreateRefusedResponse(query *Message) *Message {
	return CreateErrorResponse(query, RCodeRefused)
}
