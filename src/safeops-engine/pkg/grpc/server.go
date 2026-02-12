// Package grpc provides gRPC server for metadata streaming
package grpc

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
	"safeops-engine/internal/parser"
	"safeops-engine/internal/verdict"
	"safeops-engine/pkg/grpc/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the gRPC metadata streaming service
type Server struct {
	pb.UnimplementedMetadataStreamServiceServer

	log           *logger.Logger
	driver        *driver.Driver
	verdictEngine *verdict.Engine
	grpcServer    *grpc.Server
	listener      net.Listener

	// Subscribers - atomic snapshot for lock-free broadcast
	subscribers     atomic.Value // stores []*Subscriber (slice snapshot)
	subscriberMap   map[string]*Subscriber
	subMutex        sync.Mutex // only held during add/remove, NOT during broadcast
	nextPktID       uint64
	subscriberCount uint64
	droppedPackets  uint64 // atomic counter for packets dropped due to full channel

	// Verdict cache - sync.Map for lock-free reads on hot path
	verdictCache    sync.Map // key: string -> *CachedVerdict
	verdictsApplied uint64
	cacheSize       int64 // atomic counter for cache size

	// Protocol parsers (created once, reused)
	dnsParser  *parser.DNSParser
	httpParser *parser.HTTPParser
	tlsParser  *parser.TLSParser

	// Reusable buffer pool for cache key generation
	keyBufPool sync.Pool
}

// Subscriber represents a client subscribed to metadata stream
type Subscriber struct {
	ID      string
	Channel chan *pb.PacketMetadata
	Cancel  context.CancelFunc
	Filters []string // Optional protocol filters
	// Pre-computed filter flags for fast matching
	acceptTCP  bool
	acceptUDP  bool
	acceptDNS  bool
	acceptHTTP bool
	acceptAll  bool
	closed     atomic.Bool // prevents double-close panic on shutdown
}

// CloseChannel safely closes the subscriber's channel exactly once
func (sub *Subscriber) CloseChannel() {
	if sub.closed.CompareAndSwap(false, true) {
		close(sub.Channel)
	}
}

// CachedVerdict stores a verdict decision with TTL
type CachedVerdict struct {
	Verdict   pb.VerdictType
	Reason    string
	RuleID    string
	ExpiresAt int64  // Unix nano for fast comparison (no time.Time allocation)
	HitCount  uint64
}

// NewServer creates a new gRPC metadata stream server
func NewServer(log *logger.Logger, drv *driver.Driver, ve *verdict.Engine, listenAddr string) (*Server, error) {
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
		log:           log,
		driver:        drv,
		verdictEngine: ve,
		grpcServer:    grpcServer,
		listener:      listener,
		subscriberMap: make(map[string]*Subscriber),
		dnsParser:     parser.NewDNSParser(),
		httpParser:    parser.NewHTTPParser(),
		tlsParser:     parser.NewTLSParser(),
		keyBufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0, 64) // Pre-allocate 64 bytes for cache key
				return &buf
			},
		},
	}

	// Initialize empty subscriber snapshot
	s.subscribers.Store(make([]*Subscriber, 0))

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
	now := time.Now().UnixNano()
	removed := 0

	s.verdictCache.Range(func(key, value interface{}) bool {
		cv := value.(*CachedVerdict)
		if now > cv.ExpiresAt {
			s.verdictCache.Delete(key)
			atomic.AddInt64(&s.cacheSize, -1)
			removed++
		}
		return true
	})

	if removed > 0 {
		s.log.Debug("Cleaned expired verdicts", map[string]interface{}{
			"removed":   removed,
			"remaining": atomic.LoadInt64(&s.cacheSize),
		})
	}
}

// Stop stops the gRPC server gracefully
func (s *Server) Stop() {
	s.log.Info("Stopping gRPC server", nil)

	// Close all subscriber channels (safe: CloseChannel is idempotent)
	s.subMutex.Lock()
	for _, sub := range s.subscriberMap {
		sub.Cancel()
		sub.CloseChannel()
	}
	s.subscriberMap = make(map[string]*Subscriber)
	s.subscribers.Store(make([]*Subscriber, 0))
	s.subMutex.Unlock()

	// Stop gRPC server
	s.grpcServer.GracefulStop()
	s.listener.Close()

	s.log.Info("gRPC server stopped", nil)
}

// SubscriberCount returns the number of active gRPC subscribers
func (s *Server) SubscriberCount() uint64 {
	return atomic.LoadUint64(&s.subscriberCount)
}

// buildCacheKey builds a 5-tuple cache key without fmt.Sprintf allocations
func (s *Server) buildCacheKey(pkt *driver.ParsedPacket) string {
	bufPtr := s.keyBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]

	buf = append(buf, pkt.SrcIP.String()...)
	buf = append(buf, ':')
	buf = strconv.AppendUint(buf, uint64(pkt.SrcPort), 10)
	buf = append(buf, ':')
	buf = append(buf, pkt.DstIP.String()...)
	buf = append(buf, ':')
	buf = strconv.AppendUint(buf, uint64(pkt.DstPort), 10)
	buf = append(buf, ':')
	buf = strconv.AppendUint(buf, uint64(pkt.Protocol), 10)

	key := string(buf) // single allocation for the final string
	*bufPtr = buf
	s.keyBufPool.Put(bufPtr)

	return key
}

// CheckVerdictCache checks the verdict cache for a packet WITHOUT broadcasting.
// Used on the fast path where we don't want to send packets over gRPC
// but still want to enforce cached verdicts from the Firewall Engine.
func (s *Server) CheckVerdictCache(pkt *driver.ParsedPacket) bool {
	cacheKey := s.buildCacheKey(pkt)
	if val, ok := s.verdictCache.Load(cacheKey); ok {
		cv := val.(*CachedVerdict)
		if time.Now().UnixNano() <= cv.ExpiresAt {
			atomic.AddUint64(&cv.HitCount, 1)
			if cv.Verdict != pb.VerdictType_ALLOW {
				s.applyVerdictToPacket(pkt, cv)
				return false
			}
			return true
		}
		s.verdictCache.Delete(cacheKey)
		atomic.AddInt64(&s.cacheSize, -1)
	}
	return true
}

// BroadcastPacket broadcasts packet metadata to all subscribers.
// Checks the verdict cache first — if a cached verdict exists, it's applied
// without re-broadcasting. Use BroadcastPacketNoCache for forced broadcast.
func (s *Server) BroadcastPacket(pkt *driver.ParsedPacket) bool {
	// FAST PATH: No subscribers = instant pass-through (atomic load, no mutex)
	if atomic.LoadUint64(&s.subscriberCount) == 0 {
		return true
	}

	// FAST PATH: Check verdict cache (sync.Map = lock-free read)
	cacheKey := s.buildCacheKey(pkt)
	if val, ok := s.verdictCache.Load(cacheKey); ok {
		cv := val.(*CachedVerdict)
		// Check expiry with fast int64 comparison (no time.Time)
		if time.Now().UnixNano() <= cv.ExpiresAt {
			atomic.AddUint64(&cv.HitCount, 1)
			if cv.Verdict != pb.VerdictType_ALLOW {
				s.applyVerdictToPacket(pkt, cv)
				return false
			}
			return true
		}
		// Expired - delete lazily
		s.verdictCache.Delete(cacheKey)
		atomic.AddInt64(&s.cacheSize, -1)
	}

	return s.broadcastToSubscribers(pkt, cacheKey)
}

// BroadcastPacketNoCache broadcasts packet metadata to all subscribers
// WITHOUT checking the verdict cache. Used for fast-path security monitoring
// where DDoS/flood counters must always be incremented regardless of cached verdicts.
func (s *Server) BroadcastPacketNoCache(pkt *driver.ParsedPacket) {
	if atomic.LoadUint64(&s.subscriberCount) == 0 {
		return
	}
	cacheKey := s.buildCacheKey(pkt)
	s.broadcastToSubscribers(pkt, cacheKey)
}

// broadcastToSubscribers sends packet to all matching subscribers.
func (s *Server) broadcastToSubscribers(pkt *driver.ParsedPacket, cacheKey string) bool {
	// SLOW PATH: Broadcast to subscribers
	// Load atomic snapshot of subscribers (no mutex needed for reads)
	subs := s.subscribers.Load().([]*Subscriber)
	if len(subs) == 0 {
		return true
	}

	// Generate unique packet ID
	pktID := atomic.AddUint64(&s.nextPktID, 1)

	// Extract domain if this is web traffic (DNS/HTTP/HTTPS)
	s.extractDomain(pkt)

	// Convert to protobuf message
	pbPkt := s.convertToProtobuf(pkt, pktID, cacheKey)

	// Broadcast to all subscribers using snapshot (no lock)
	for _, sub := range subs {
		if sub.closed.Load() {
			continue
		}
		if !sub.matchesPacket(pbPkt) {
			continue
		}

		select {
		case sub.Channel <- pbPkt:
			// Sent successfully
		default:
			// Channel full — count the drop
			dropped := atomic.AddUint64(&s.droppedPackets, 1)
			// Log every 10K drops so operator sees the problem
			if dropped%10000 == 0 {
				s.log.Warn("Subscriber channel overflow", map[string]interface{}{
					"subscriber_id":  sub.ID,
					"total_dropped":  dropped,
					"channel_cap":    cap(sub.Channel),
				})
			}
		}
	}

	// Default: allow packet (no explicit verdict yet)
	return true
}

// matchesPacket uses pre-computed filter flags for O(1) matching
func (sub *Subscriber) matchesPacket(pkt *pb.PacketMetadata) bool {
	if sub.acceptAll {
		return true
	}
	if sub.acceptTCP && pkt.Protocol == 6 {
		return true
	}
	if sub.acceptUDP && pkt.Protocol == 17 {
		return true
	}
	if sub.acceptDNS && (pkt.IsDnsQuery || pkt.IsDnsResponse) {
		return true
	}
	if sub.acceptHTTP && pkt.IsHttp {
		return true
	}
	return false
}

// updateSubscriberSnapshot rebuilds the atomic subscriber slice (called under lock)
func (s *Server) updateSubscriberSnapshot() {
	subs := make([]*Subscriber, 0, len(s.subscriberMap))
	for _, sub := range s.subscriberMap {
		subs = append(subs, sub)
	}
	s.subscribers.Store(subs)
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

	// Create subscriber with pre-computed filter flags
	subCtx, cancel := context.WithCancel(ctx)
	sub := &Subscriber{
		ID:      req.SubscriberId,
		Channel: make(chan *pb.PacketMetadata, 500000), // 500K buffer for high throughput
		Cancel:  cancel,
		Filters: req.Filters,
	}

	// Pre-compute filter flags
	if len(req.Filters) == 0 {
		sub.acceptAll = true
	} else {
		for _, f := range req.Filters {
			switch f {
			case "tcp":
				sub.acceptTCP = true
			case "udp":
				sub.acceptUDP = true
			case "dns":
				sub.acceptDNS = true
			case "http":
				sub.acceptHTTP = true
			}
		}
	}

	// Register subscriber (mutex only held briefly during add)
	s.subMutex.Lock()
	s.subscriberMap[req.SubscriberId] = sub
	atomic.AddUint64(&s.subscriberCount, 1)
	s.updateSubscriberSnapshot()
	s.subMutex.Unlock()

	// Cleanup on disconnect
	defer func() {
		s.subMutex.Lock()
		delete(s.subscriberMap, req.SubscriberId)
		atomic.AddUint64(&s.subscriberCount, ^uint64(0)) // Decrement
		s.updateSubscriberSnapshot()
		s.subMutex.Unlock()

		cancel()
		sub.CloseChannel()

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
	// Cache verdict if TTL > 0 (sync.Map Store = lock-free for readers)
	if req.TtlSeconds > 0 && req.CacheKey != "" {
		s.verdictCache.Store(req.CacheKey, &CachedVerdict{
			Verdict:   req.Verdict,
			Reason:    req.Reason,
			RuleID:    req.RuleId,
			ExpiresAt: time.Now().Add(time.Duration(req.TtlSeconds) * time.Second).UnixNano(),
			HitCount:  0,
		})
		atomic.AddInt64(&s.cacheSize, 1)

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
		PacketsDropped:    dropped + atomic.LoadUint64(&s.droppedPackets),
		ActiveSubscribers: atomic.LoadUint64(&s.subscriberCount),
		VerdictsApplied:   atomic.LoadUint64(&s.verdictsApplied),
		CachedVerdicts:    uint64(atomic.LoadInt64(&s.cacheSize)),
	}, nil
}

// applyVerdictToPacket enforces a cached verdict by sending RST/DNS inject/HTML block page
func (s *Server) applyVerdictToPacket(pkt *driver.ParsedPacket, cv *CachedVerdict) {
	// Extract MAC addresses from raw Ethernet header
	var srcMAC, dstMAC [6]byte
	data := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]
	if len(data) >= 14 {
		copy(dstMAC[:], data[0:6])
		copy(srcMAC[:], data[6:12])
	}

	switch cv.Verdict {
	case pb.VerdictType_BLOCK:
		if pkt.Protocol == driver.ProtoTCP {
			// For HTTP: inject block page before RST
			if pkt.DstPort == 80 && s.verdictEngine != nil {
				s.verdictEngine.InjectHTMLBlockPage(
					pkt.AdapterHandle,
					pkt.SrcIP, pkt.DstIP,
					pkt.SrcPort, pkt.DstPort,
					srcMAC, dstMAC,
					cv.Reason, cv.RuleID,
				)
			}
			// Send TCP RST to kill connection
			if s.verdictEngine != nil {
				s.verdictEngine.SendTCPReset(
					pkt.AdapterHandle,
					pkt.SrcIP, pkt.DstIP,
					pkt.SrcPort, pkt.DstPort,
					srcMAC, dstMAC,
				)
			}
		}

	case pb.VerdictType_REDIRECT:
		if pkt.DstPort == 53 && pkt.Protocol == driver.ProtoUDP && s.verdictEngine != nil {
			redirectIP := net.ParseIP("127.0.0.1")
			s.verdictEngine.InjectDNSResponse(
				pkt.AdapterHandle,
				data,
				pkt.Domain,
				redirectIP,
				srcMAC, dstMAC,
			)
		}

	case pb.VerdictType_DROP:
		// Silent drop - no action needed, packet just won't be reinjected
	}

	s.log.Debug("Verdict enforced", map[string]interface{}{
		"verdict": cv.Verdict.String(),
		"reason":  cv.Reason,
		"src_ip":  pkt.SrcIP.String(),
		"dst_ip":  pkt.DstIP.String(),
	})
}

// convertToProtobuf converts driver packet to protobuf (method to avoid extra cache key alloc)
func (s *Server) convertToProtobuf(pkt *driver.ParsedPacket, pktID uint64, cacheKey string) *pb.PacketMetadata {
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
		CacheKey:     cacheKey, // Reuse already-computed cache key
	}

	// Set direction
	if pkt.Direction == driver.DirectionInbound {
		pbPkt.Direction = "INBOUND"
	} else {
		pbPkt.Direction = "OUTBOUND"
	}

	// Parse TCP flags from raw packet buffer (NOT pkt.Payload which is application data)
	// TCP flags byte is at offset 47: Ethernet(14) + IP(20) + TCP offset 13
	if pkt.Protocol == 6 && pkt.RawBuffer != nil && pkt.RawBuffer.Length >= 48 {
		flags := pkt.RawBuffer.Buffer[47]
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
		// Check first byte directly without string conversion
		first := pkt.Payload[0]
		if first == 'G' || first == 'P' || first == 'H' {
			pbPkt.IsHttp = true
			if len(pkt.Payload) >= 4 {
				if pkt.Payload[0] == 'G' && pkt.Payload[1] == 'E' && pkt.Payload[2] == 'T' {
					pbPkt.HttpMethod = "GET"
				} else if pkt.Payload[0] == 'P' && pkt.Payload[1] == 'O' && pkt.Payload[2] == 'S' && pkt.Payload[3] == 'T' {
					pbPkt.HttpMethod = "POST"
				}
			}
		}
	}

	return pbPkt
}

// extractDomain extracts domain from DNS/HTTP/HTTPS packets
// Only called for new connections (not cached), so minimal performance impact.
// Skips extraction if domain was already set by the engine's slow path.
func (s *Server) extractDomain(pkt *driver.ParsedPacket) {
	// If domain was already extracted by engine.go slow path, skip re-extraction
	if pkt.Domain != "" {
		return
	}

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
