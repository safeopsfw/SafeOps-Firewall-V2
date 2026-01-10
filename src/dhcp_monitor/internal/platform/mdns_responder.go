package platform

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// MDNSResponder handles responding to mDNS queries for specific hostnames
type MDNSResponder struct {
	hostname string // e.g., "safeops-portal.local."
	conn     *net.UDPConn
}

// NewMDNSResponder creates a responder for the given hostname
// It dynamically determines the response IP based on the querying client's subnet
func NewMDNSResponder(hostname string) (*MDNSResponder, error) {
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	return &MDNSResponder{
		hostname: hostname,
	}, nil
}

// Start listens for mDNS queries and responds
func (r *MDNSResponder) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return fmt.Errorf("resolve addr failed: %w", err)
	}

	// Listen on Multicast UDP
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("listen multicast failed: %w", err)
	}
	r.conn = conn

	log.Printf("[MDNS_RESPONDER] Listening for %s (Auto-IP selection)", r.hostname)

	go func() {
		defer conn.Close()
		buf := make([]byte, 1500) // Standard MTU

		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, src, err := conn.ReadFromUDP(buf)
				if err != nil {
					log.Printf("[MDNS_RESPONDER] Read error: %v", err)
					continue
				}

				r.handlePacket(buf[:n], src)
			}
		}
	}()

	return nil
}

func (r *MDNSResponder) handlePacket(data []byte, src *net.UDPAddr) {
	var msg dnsmessage.Message
	if err := msg.Unpack(data); err != nil {
		return // Ignore invalid packets
	}

	// Only interested in Queries
	if msg.Header.Response {
		return
	}

	// Check questions
	for _, q := range msg.Questions {
		qName := q.Name.String()
		// Case-insensitive comparison
		if strings.EqualFold(qName, r.hostname) {
			// Find the correct local IP for this client
			localIP := r.findLocalIPForClient(src.IP)
			if localIP == nil {
				// Fallback: Pick first non-loopback IP? Or ignore?
				// Ignore for now to avoid sending unreachable IPs
				continue
			}

			// It matches! Send Response
			r.sendResponse(msg.ID, q.Name, src, localIP)
			return
		}
	}
}

// findLocalIPForClient iterates local interfaces to find one that shares a subnet with clientIP
func (r *MDNSResponder) findLocalIPForClient(clientIP net.IP) net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				// Check if clientIP is in this subnet
				if ipNet.Contains(clientIP) {
					return ipNet.IP
				}
			}
		}
	}
	return nil
}

func (r *MDNSResponder) sendResponse(id uint16, name dnsmessage.Name, dst *net.UDPAddr, ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}

	// Construct Response
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120, // 2 minutes
				},
				Body: &dnsmessage.AResource{
					A: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]},
				},
			},
		},
	}

	packed, err := resp.Pack()
	if err != nil {
		log.Printf("[MDNS_RESPONDER] Pack error: %v", err)
		return
	}

	if _, err := r.conn.WriteToUDP(packed, dst); err != nil {
		log.Printf("[MDNS_RESPONDER] Write error: %v", err)
	}
}
