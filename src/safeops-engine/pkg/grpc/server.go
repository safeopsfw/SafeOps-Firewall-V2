// Package grpc provides gRPC server for metadata streaming
package grpc

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
	"safeops-engine/internal/parser"
	"safeops-engine/pkg/grpc/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the gRPC metadata streaming service
type Server struct {
	pb.UnimplementedMetadataStreamServiceServer

	log        *logger.Logger
	driver     *driver.Driver
	grpcServer *grpc.Server
	listener   net.Listener

	// Subscribers
	subscribers map[string]*Subscriber
	subMutex    sync.RWMutex
	nextPktID   uint64

	// Verdict system
	verdictCache   map[string]*CachedVerdict // key: src_ip:src_port:dst_ip:dst_port:proto
	verdictMutex   sync.RWMutex
	verdictsApplied uint64

	// Stats
	subscriberCount uint64

	// Protocol parsers (created once, reused)
	dnsParser  *parser.DNSParser
	httpParser *parser.HTTPParser
	tlsParser  *parser.TLSParser
}

// Subscriber represents a client subscribed to metadata stream
type Subscriber struct {
	ID      string
	Channel chan *pb.PacketMetadata
	Cancel  context.CancelFunc
	Filters []string // Optional protocol filters
}

// CachedVerdict stores a verdict decision with TTL
type CachedVerdict struct {
	Verdict     pb.VerdictType
	Reason      string
	RuleID      string
	ExpiresAt   time.Time
	HitCount    uint64
}

// NewServer creates a new gRPC metadata stream server
func NewServer(log *logger.Logger, drv *driver.Driver, listenAddr string) (*Server, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(1024*1024),   // 1MB
		grpc.MaxSendMsgSize(10*1024*1024), // 10MB
	)

	s := &Server{
		log:          log,
		driver:       drv,
		grpcServer:   grpcServer,
		listener:     listener,
		subscribers:  make(map[string]*Subscriber),
		verdictCache: make(map[string]*CachedVerdict),
		dnsParser:    parser.NewDNSParser(),
		httpParser:   parser.NewHTTPParser(),
		tlsParser:    parser.NewTLSParser(),
	}

	pb.RegisterMetadataStreamServiceServer(grpcServer, s)

	log.Info("gRPC server created", map[string]interface{}{
		"address": listenAddr,
	})

	return s, nil
}

// Start starts the gRPC server
func (s *Server) Start() error {
	s.log.Info("Starting gRPC server", map[string]interface{}{
		"address": s.listener.Addr().String(),
	})

	// Start gRPC server goroutine
	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			s.log.Error("gRPC server error", map[string]interface{}{"error": err.Error()})
		}
	}()

	// Start cache cleanup goroutine (every 60 seconds)
	go s.cacheCleanupLoop()

	return nil
}

// cacheCleanupLoop periodically removes expired verdict cache entries
func (s *Server) cacheCleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanExpiredVerdicts()
	}
}

// cleanExpiredVerdicts removes expired entries from verdict cache
func (s *Server) cleanExpiredVerdicts() {
	now := time.Now()
	s.verdictMutex.Lock()
	defer s.verdictMutex.Unlock()

	removed := 0
	for key, verdict := range s.verdictCache {
		if now.After(verdict.ExpiresAt) {
			delete(s.verdictCache, key)
			removed++
		}
	}

	if removed > 0 {
		s.log.Debug("Cleaned expired verdicts", map[string]interface{}{
			"removed":   removed,
			"remaining": len(s.verdictCache),
		})
	}
}

// Stop stops the gRPC server gracefully
func (s *Server) Stop() {
	s.log.Info("Stopping gRPC server", nil)

	// Close all subscriber channels
	s.subMutex.Lock()
	for _, sub := range s.subscribers {
		sub.Cancel()
		close(sub.Channel)
	}
	s.subscribers = make(map[string]*Subscriber)
	s.subMutex.Unlock()

	// Stop gRPC server
	s.grpcServer.GracefulStop()
	s.listener.Close()

	s.log.Info("gRPC server stopped", nil)
}

// BroadcastPacket broadcasts packet metadata to all subscribers
func (s *Server) BroadcastPacket(pkt *driver.ParsedPacket) bool {
	// FAST PATH: No subscribers = instant pass-through
	s.subMutex.RLock()
	hasSubscribers := len(s.subscribers) > 0
	s.subMutex.RUnlock()

	if !hasSubscribers {
		return true // No subscribers, allow immediately
	}

	// FAST PATH: Check verdict cache for established connections
	cacheKey := s.getCacheKey(pkt)
	if verdict := s.getCachedVerdict(cacheKey); verdict != nil {
		atomic.AddUint64(&verdict.HitCount, 1)
		return verdict.Verdict == pb.VerdictType_ALLOW
	}

	// SLOW PATH: Need to broadcast and get verdict
	s.subMutex.RLock()
	defer s.subMutex.RUnlock()

	// Generate unique packet ID
	pktID := atomic.AddUint64(&s.nextPktID, 1)

	// Extract domain if this is web traffic (DNS/HTTP/HTTPS)
	s.extractDomain(pkt)

	// Convert to protobuf message
	pbPkt := convertToProtobuf(pkt, pktID)

	// Broadcast to all subscribers
	for _, sub := range s.subscribers {
		// Check filters
		if !s.matchesFilters(pbPkt, sub.Filters) {
			continue
		}

		select {
		case sub.Channel <- pbPkt:
			// Sent successfully
		default:
			// Channel full, skip (non-blocking)
			s.log.Warn("Subscriber channel full, dropping packet", map[string]interface{}{
				"subscriber_id": sub.ID,
			})
		}
	}

	// Default: allow packet (no explicit verdict yet)
	return true
}

// StreamMetadata implements the gRPC streaming method
func (s *Server) StreamMetadata(req *pb.SubscribeRequest, stream pb.MetadataStreamService_StreamMetadataServer) error {
	ctx := stream.Context()

	// Validate subscriber ID
	if req.SubscriberId == "" {
		return status.Error(codes.InvalidArgument, "subscriber_id cannot be empty")
	}

	s.log.Info("New metadata subscriber", map[string]interface{}{
		"subscriber_id": req.SubscriberId,
		"filters":       req.Filters,
	})

	// Create subscriber
	subCtx, cancel := context.WithCancel(ctx)
	sub := &Subscriber{
		ID:      req.SubscriberId,
		Channel: make(chan *pb.PacketMetadata, 10000), // Large buffer
		Cancel:  cancel,
		Filters: req.Filters,
	}

	// Register subscriber
	s.subMutex.Lock()
	s.subscribers[req.SubscriberId] = sub
	atomic.AddUint64(&s.subscriberCount, 1)
	s.subMutex.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.subMutex.Lock()
		delete(s.subscribers, req.SubscriberId)
		atomic.AddUint64(&s.subscriberCount, ^uint64(0)) // Decrement
		s.subMutex.Unlock()

		cancel()
		close(sub.Channel)

		s.log.Info("Metadata subscriber disconnected", map[string]interface{}{
			"subscriber_id": req.SubscriberId,
		})
	}()

	// Stream packets to client
	for {
		select {
		case <-subCtx.Done():
			return status.Error(codes.Canceled, "stream canceled")
		case pkt, ok := <-sub.Channel:
			if !ok {
				return status.Error(codes.Aborted, "channel closed")
			}

			if err := stream.Send(pkt); err != nil {
				s.log.Error("Failed to send packet to subscriber", map[string]interface{}{
					"subscriber_id": req.SubscriberId,
					"error":         err.Error(),
				})
				return status.Error(codes.Internal, fmt.Sprintf("send error: %v", err))
			}
		}
	}
}

// ApplyVerdict implements the verdict enforcement method
func (s *Server) ApplyVerdict(ctx context.Context, req *pb.VerdictRequest) (*pb.VerdictResponse, error) {
	// Cache verdict if TTL > 0 (for established connections)
	if req.TtlSeconds > 0 && req.CacheKey != "" {
		s.verdictMutex.Lock()
		s.verdictCache[req.CacheKey] = &CachedVerdict{
			Verdict:   req.Verdict,
			Reason:    req.Reason,
			RuleID:    req.RuleId,
			ExpiresAt: time.Now().Add(time.Duration(req.TtlSeconds) * time.Second),
			HitCount:  0,
		}
		s.verdictMutex.Unlock()

		s.log.Debug("Verdict cached", map[string]interface{}{
			"cache_key": req.CacheKey,
			"verdict":   req.Verdict.String(),
			"ttl":       req.TtlSeconds,
		})
	}

	// Log non-allow verdicts
	if req.Verdict != pb.VerdictType_ALLOW {
		s.log.Info("Verdict received", map[string]interface{}{
			"packet_id": req.PacketId,
			"verdict":   req.Verdict.String(),
			"reason":    req.Reason,
			"rule_id":   req.RuleId,
			"cached":    req.TtlSeconds > 0,
		})
	}

	atomic.AddUint64(&s.verdictsApplied, 1)

	return &pb.VerdictResponse{
		Success:         true,
		Message:         "Verdict applied successfully",
		PacketsAffected: 1,
	}, nil
}

// GetStats implements the stats retrieval method
func (s *Server) GetStats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsResponse, error) {
	read, written, dropped := s.driver.GetStats()

	return &pb.StatsResponse{
		PacketsRead:       read,
		PacketsWritten:    written,
		PacketsDropped:    dropped,
		ActiveSubscribers: atomic.LoadUint64(&s.subscriberCount),
		VerdictsApplied:   atomic.LoadUint64(&s.verdictsApplied),
		CachedVerdicts:    uint64(len(s.verdictCache)),
	}, nil
}

// Helper methods

func (s *Server) getCacheKey(pkt *driver.ParsedPacket) string {
	return fmt.Sprintf("%s:%d:%s:%d:%d",
		pkt.SrcIP.String(),
		pkt.SrcPort,
		pkt.DstIP.String(),
		pkt.DstPort,
		pkt.Protocol,
	)
}

func (s *Server) getCachedVerdict(key string) *CachedVerdict {
	s.verdictMutex.RLock()
	defer s.verdictMutex.RUnlock()

	verdict, exists := s.verdictCache[key]
	if !exists {
		return nil
	}

	// Check if expired
	if time.Now().After(verdict.ExpiresAt) {
		// Expired, will be cleaned up later
		return nil
	}

	return verdict
}

func (s *Server) applyVerdictToPacket(pkt *driver.ParsedPacket, verdict pb.VerdictType) {
	// This will be implemented in Phase 2 with actual packet manipulation
	// For now, just log
	s.log.Debug("Applying cached verdict", map[string]interface{}{
		"verdict": verdict.String(),
		"src_ip":  pkt.SrcIP.String(),
		"dst_ip":  pkt.DstIP.String(),
	})
}

func (s *Server) matchesFilters(pkt *pb.PacketMetadata, filters []string) bool {
	if len(filters) == 0 {
		return true // No filters, accept all
	}

	// Check protocol filters
	for _, filter := range filters {
		switch filter {
		case "tcp":
			if pkt.Protocol == 6 {
				return true
			}
		case "udp":
			if pkt.Protocol == 17 {
				return true
			}
		case "dns":
			if pkt.IsDnsQuery || pkt.IsDnsResponse {
				return true
			}
		case "http":
			if pkt.IsHttp {
				return true
			}
		}
	}

	return false
}

func convertToProtobuf(pkt *driver.ParsedPacket, pktID uint64) *pb.PacketMetadata {
	// Pre-compute cache key for verdict caching (5-tuple)
	cacheKey := fmt.Sprintf("%s:%d:%s:%d:%d",
		pkt.SrcIP.String(),
		pkt.SrcPort,
		pkt.DstIP.String(),
		pkt.DstPort,
		pkt.Protocol,
	)

	pbPkt := &pb.PacketMetadata{
		PacketId:     pktID,
		Timestamp:    time.Now().UnixNano(),
		SrcIp:        pkt.SrcIP.String(),
		DstIp:        pkt.DstIP.String(),
		SrcPort:      uint32(pkt.SrcPort),
		DstPort:      uint32(pkt.DstPort),
		Protocol:     uint32(pkt.Protocol),
		PacketSize:   uint32(len(pkt.Payload)),
		AdapterName:  pkt.AdapterName,
		Domain:       pkt.Domain,
		DomainSource: pkt.DomainSource,
		CacheKey:     cacheKey, // Include pre-computed cache key
	}

	// Set direction
	if pkt.Direction == driver.DirectionInbound {
		pbPkt.Direction = "INBOUND"
	} else {
		pbPkt.Direction = "OUTBOUND"
	}

	// Parse TCP flags if TCP
	if pkt.Protocol == 6 && len(pkt.Payload) > 13 {
		flags := pkt.Payload[13]
		pbPkt.TcpFlags = uint32(flags)
		pbPkt.IsSyn = (flags & 0x02) != 0
		pbPkt.IsAck = (flags & 0x10) != 0
		pbPkt.IsRst = (flags & 0x04) != 0
		pbPkt.IsFin = (flags & 0x01) != 0
	}

	// Protocol detection
	if pkt.Protocol == 17 && (pkt.SrcPort == 53 || pkt.DstPort == 53) {
		if pkt.DstPort == 53 {
			pbPkt.IsDnsQuery = true
		} else {
			pbPkt.IsDnsResponse = true
		}
	}

	if pkt.Protocol == 6 && len(pkt.Payload) > 4 {
		payload := string(pkt.Payload[:min(100, len(pkt.Payload))])
		if len(payload) > 0 {
			if payload[0] == 'G' || payload[0] == 'P' || payload[0] == 'H' {
				pbPkt.IsHttp = true
				if len(payload) >= 3 {
					if payload[:3] == "GET" {
						pbPkt.HttpMethod = "GET"
					} else if len(payload) >= 4 && payload[:4] == "POST" {
						pbPkt.HttpMethod = "POST"
					}
				}
			}
		}
	}

	return pbPkt
}

// extractDomain extracts domain from DNS/HTTP/HTTPS packets
// Only called for new connections (not cached), so minimal performance impact
func (s *Server) extractDomain(pkt *driver.ParsedPacket) {
	// DNS query (UDP port 53)
	if pkt.Protocol == 17 && pkt.DstPort == 53 {
		if domain := s.dnsParser.ExtractDomain(pkt.Payload); domain != "" {
			pkt.Domain = domain
			pkt.DomainSource = "DNS"
			return
		}
	}

	// HTTPS (TCP port 443) - Extract SNI
	if pkt.Protocol == 6 && pkt.DstPort == 443 {
		if sni := s.tlsParser.ExtractSNI(pkt.Payload); sni != "" {
			pkt.Domain = sni
			pkt.DomainSource = "SNI"
			return
		}
	}

	// HTTP (TCP port 80) - Extract Host header
	if pkt.Protocol == 6 && pkt.DstPort == 80 {
		if host := s.httpParser.ExtractHost(pkt.Payload); host != "" {
			pkt.Domain = host
			pkt.DomainSource = "HTTP"
			return
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
