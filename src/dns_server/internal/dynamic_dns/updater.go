// Package dynamic_dns implements DHCP-integrated dynamic DNS updates.
package dynamic_dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"safeops/dns_server/internal/storage"
)

// ============================================================================
// Dynamic DNS Updater
// ============================================================================

// Updater manages dynamic DNS updates from DHCP
type Updater struct {
	zoneStore   *storage.ZoneStore
	defaultZone string
	defaultTTL  uint32
}

// NewUpdater creates a new dynamic DNS updater
func NewUpdater(zoneStore *storage.ZoneStore, defaultZone string) *Updater {
	return &Updater{
		zoneStore:   zoneStore,
		defaultZone: defaultZone,
		defaultTTL:  300, // 5 minutes for dynamic records
	}
}

// ============================================================================
// DHCP Integration
// ============================================================================

// UpdateRequest represents a DNS update from DHCP
type UpdateRequest struct {
	Hostname   string
	IPAddress  net.IP
	MACAddress string
	LeaseTime  time.Duration
}

// AddHost adds or updates a host record from DHCP
func (u *Updater) AddHost(ctx context.Context, req *UpdateRequest) error {
	hostname := strings.ToLower(req.Hostname)
	if !strings.Contains(hostname, ".") {
		hostname = hostname + "." + u.defaultZone
	}

	// Add A record
	aRecord := &storage.Record{
		Name:      hostname,
		Type:      "A",
		TTL:       uint32(req.LeaseTime.Seconds()),
		Value:     req.IPAddress.String(),
		IsDynamic: true,
	}

	recordID, err := u.zoneStore.AddRecord(ctx, u.defaultZone, aRecord)
	if err != nil {
		return fmt.Errorf("failed to add A record: %w", err)
	}

	// Add PTR record for reverse DNS
	ptrName := reverseIP(req.IPAddress)
	ptrRecord := &storage.Record{
		Name:      ptrName,
		Type:      "PTR",
		TTL:       uint32(req.LeaseTime.Seconds()),
		Value:     hostname,
		IsDynamic: true,
	}

	// Get reverse zone
	reverseZone := getReverseZone(req.IPAddress)
	if reverseZone != "" {
		_, err = u.zoneStore.AddRecord(ctx, reverseZone, ptrRecord)
		if err != nil {
			log.Printf("Failed to add PTR record: %v", err)
		}
	}

	log.Printf("Dynamic DNS: %s -> %s (lease: %s, id: %s)",
		hostname, req.IPAddress, req.LeaseTime, recordID)
	return nil
}

// RemoveHost removes a host record
func (u *Updater) RemoveHost(ctx context.Context, hostname string) error {
	hostname = strings.ToLower(hostname)
	if !strings.Contains(hostname, ".") {
		hostname = hostname + "." + u.defaultZone
	}

	// Find and remove the record
	record, err := u.zoneStore.GetRecord(ctx, u.defaultZone, hostname, "A")
	if err != nil {
		return err
	}
	if record == nil {
		return nil // Already removed
	}

	return u.zoneStore.DeleteRecord(ctx, record.ID)
}

// ============================================================================
// Lease Cleanup
// ============================================================================

// CleanupExpired removes expired dynamic records
func (u *Updater) CleanupExpired(ctx context.Context) (int, error) {
	// Get all dynamic records
	recordType := "A"
	records, err := u.zoneStore.ListRecords(ctx, u.defaultZone, &recordType)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, r := range records {
		if r.IsDynamic {
			// Check if expired (based on creation time + TTL)
			expiresAt := r.CreatedAt.Add(time.Duration(r.TTL) * time.Second)
			if time.Now().After(expiresAt) {
				if err := u.zoneStore.DeleteRecord(ctx, r.ID); err == nil {
					removed++
				}
			}
		}
	}

	if removed > 0 {
		log.Printf("Dynamic DNS cleanup: removed %d expired records", removed)
	}
	return removed, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func reverseIP(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
		ip4[3], ip4[2], ip4[1], ip4[0])
}

func getReverseZone(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.in-addr.arpa",
		ip4[2], ip4[1], ip4[0])
}

// SetDefaultTTL sets the default TTL for dynamic records
func (u *Updater) SetDefaultTTL(ttl uint32) {
	u.defaultTTL = ttl
}

// SetDefaultZone sets the default zone for hostnames without domain
func (u *Updater) SetDefaultZone(zone string) {
	u.defaultZone = zone
}
