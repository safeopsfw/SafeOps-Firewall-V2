// Package stream provides metadata broadcasting for external consumers
package stream

import (
	"sync"
	"time"

	"safeops-engine/internal/driver"
)

// PacketMetadata contains packet information for firewall/IDS/IPS engines
type PacketMetadata struct {
	Timestamp    time.Time
	Direction    string // "INBOUND" or "OUTBOUND"
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	Protocol     uint8
	PacketSize   int
	AdapterName  string
	Domain       string // Extracted domain (DNS/SNI/HTTP)
	DomainSource string // "DNS", "SNI", "HTTP", or empty

	// Protocol detection
	IsDNSQuery    bool
	IsDNSResponse bool
	IsHTTP        bool
	HTTPMethod    string

	// TCP flags
	TCPFlags uint8
	IsSYN    bool
	IsACK    bool
	IsRST    bool
	IsFIN    bool
}

// Subscriber represents a consumer of the metadata stream
type Subscriber struct {
	ID   string
	Chan chan *PacketMetadata
}

// Broadcaster distributes packet metadata to multiple subscribers
type Broadcaster struct {
	subscribers map[string]*Subscriber
	mu          sync.RWMutex
	bufferSize  int
}

// NewBroadcaster creates a new metadata broadcaster
func NewBroadcaster(bufferSize int) *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[string]*Subscriber),
		bufferSize:  bufferSize,
	}
}

// Subscribe creates a new subscription to the metadata stream
func (b *Broadcaster) Subscribe(id string) *Subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()

	sub := &Subscriber{
		ID:   id,
		Chan: make(chan *PacketMetadata, b.bufferSize),
	}
	b.subscribers[id] = sub
	return sub
}

// Unsubscribe removes a subscriber
func (b *Broadcaster) Unsubscribe(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if sub, exists := b.subscribers[id]; exists {
		close(sub.Chan)
		delete(b.subscribers, id)
	}
}

// Broadcast sends packet metadata to all subscribers
func (b *Broadcaster) Broadcast(meta *PacketMetadata) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, sub := range b.subscribers {
		select {
		case sub.Chan <- meta:
			// Sent successfully
		default:
			// Channel full, skip (prevents blocking)
		}
	}
}

// SubscriberCount returns the number of active subscribers
func (b *Broadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// ConvertPacket converts internal driver packet to public metadata
func ConvertPacket(pkt *driver.ParsedPacket) *PacketMetadata {
	meta := &PacketMetadata{
		Timestamp:    time.Now(),
		SrcIP:        pkt.SrcIP.String(),
		DstIP:        pkt.DstIP.String(),
		SrcPort:      pkt.SrcPort,
		DstPort:      pkt.DstPort,
		Protocol:     pkt.Protocol,
		PacketSize:   len(pkt.Payload),
		AdapterName:  pkt.AdapterName,
		Domain:       pkt.Domain,
		DomainSource: pkt.DomainSource,
	}

	// Set direction
	if pkt.Direction == driver.DirectionInbound {
		meta.Direction = "INBOUND"
	} else {
		meta.Direction = "OUTBOUND"
	}

	// Parse TCP flags if TCP packet
	if pkt.Protocol == 6 && len(pkt.Payload) >= 20 {
		if len(pkt.Payload) > 13 {
			flags := pkt.Payload[13]
			meta.TCPFlags = flags
			meta.IsSYN = (flags & 0x02) != 0
			meta.IsACK = (flags & 0x10) != 0
			meta.IsRST = (flags & 0x04) != 0
			meta.IsFIN = (flags & 0x01) != 0
		}
	}

	// Check for DNS
	if pkt.Protocol == 17 && (pkt.SrcPort == 53 || pkt.DstPort == 53) {
		if pkt.DstPort == 53 {
			meta.IsDNSQuery = true
		} else {
			meta.IsDNSResponse = true
		}
	}

	// Check for HTTP
	if pkt.Protocol == 6 && len(pkt.Payload) > 4 {
		payload := string(pkt.Payload[:min(100, len(pkt.Payload))])
		if len(payload) > 0 {
			if payload[0] == 'G' || payload[0] == 'P' || payload[0] == 'H' {
				meta.IsHTTP = true
				if len(payload) >= 3 {
					if payload[:3] == "GET" {
						meta.HTTPMethod = "GET"
					} else if len(payload) >= 4 && payload[:4] == "POST" {
						meta.HTTPMethod = "POST"
					}
				}
			}
		}
	}

	return meta
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
