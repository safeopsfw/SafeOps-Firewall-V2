// Package server implements the DHCP server core components.
// This file implements the DHCP packet handler and message router.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Packet Handler Configuration
// ============================================================================

// PacketHandlerConfig holds packet handler settings.
type PacketHandlerConfig struct {
	ProcessingTimeout time.Duration
	MaxConcurrent     int
}

// DefaultPacketHandlerConfig returns sensible defaults.
func DefaultPacketHandlerConfig() *PacketHandlerConfig {
	return &PacketHandlerConfig{
		ProcessingTimeout: 5 * time.Second,
		MaxConcurrent:     1000,
	}
}

// ============================================================================
// Request Context
// ============================================================================

// RequestContext contains parsed information from DHCP request.
type RequestContext struct {
	TransactionID uint32
	ClientMAC     net.HardwareAddr
	ClientIP      net.IP
	YourIP        net.IP
	ServerIP      net.IP
	GatewayIP     net.IP
	RequestedIP   net.IP
	Hostname      string
	ClientID      []byte
	VendorClass   string
	ParamList     []byte
	MessageType   uint8
	Flags         uint16
	Hops          uint8
	BroadcastFlag bool
	RawPacket     []byte
	ClientAddr    *net.UDPAddr
	ReceivedAt    time.Time
}

// ============================================================================
// Message Handlers Interface
// ============================================================================

// DiscoverHandler handles DHCP DISCOVER messages.
type DiscoverHandler interface {
	HandleDiscover(ctx context.Context, req *RequestContext) (*ResponseContext, error)
}

// RequestHandler handles DHCP REQUEST messages.
type RequestHandler interface {
	HandleRequest(ctx context.Context, req *RequestContext) (*ResponseContext, error)
}

// DeclineHandler handles DHCP DECLINE messages.
type DeclineHandler interface {
	HandleDecline(ctx context.Context, req *RequestContext) error
}

// ReleaseHandler handles DHCP RELEASE messages.
type ReleaseHandler interface {
	HandleRelease(ctx context.Context, req *RequestContext) error
}

// InformHandler handles DHCP INFORM messages.
type InformHandler interface {
	HandleInform(ctx context.Context, req *RequestContext) (*ResponseContext, error)
}

// ============================================================================
// Response Context
// ============================================================================

// ResponseContext contains information for building DHCP response.
type ResponseContext struct {
	MessageType    uint8
	YourIP         net.IP
	ServerIP       net.IP
	LeaseTime      uint32
	SubnetMask     net.IP
	Router         net.IP
	DNSServers     []net.IP
	DomainName     string
	Hostname       string
	CACertURL      string
	InstallScripts []string
	WPADURL        string
	CRLURL         string
	OCSPURL        string
	NAKMessage     string
	ShouldRespond  bool
}

// ============================================================================
// DHCP Packet Handler
// ============================================================================

// DHCPPacketHandler handles incoming DHCP packets.
type DHCPPacketHandler struct {
	mu     sync.RWMutex
	config *PacketHandlerConfig

	// Message handlers
	discoverHandler DiscoverHandler
	requestHandler  RequestHandler
	declineHandler  DeclineHandler
	releaseHandler  ReleaseHandler
	informHandler   InformHandler

	// Response components
	messageBuilder *MessageBuilder
	sender         *UDPSender

	// Concurrency control
	concurrent int64

	// Statistics
	stats PacketHandlerStats
}

// PacketHandlerStats tracks packet handler metrics.
type PacketHandlerStats struct {
	DiscoverReceived int64
	RequestReceived  int64
	DeclineReceived  int64
	ReleaseReceived  int64
	InformReceived   int64
	OfferSent        int64
	AckSent          int64
	NakSent          int64
	ParseErrors      int64
	HandlerErrors    int64
	ResponseErrors   int64
	TotalProcessed   int64
	TotalDropped     int64
	AvgProcessingMs  int64
}

// ============================================================================
// Handler Creation
// ============================================================================

// NewDHCPPacketHandler creates a new packet handler.
func NewDHCPPacketHandler(config *PacketHandlerConfig) *DHCPPacketHandler {
	if config == nil {
		config = DefaultPacketHandlerConfig()
	}

	return &DHCPPacketHandler{
		config: config,
	}
}

// ============================================================================
// Handler Setters
// ============================================================================

// SetDiscoverHandler sets the DISCOVER handler.
func (h *DHCPPacketHandler) SetDiscoverHandler(handler DiscoverHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.discoverHandler = handler
}

// SetRequestHandler sets the REQUEST handler.
func (h *DHCPPacketHandler) SetRequestHandler(handler RequestHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requestHandler = handler
}

// SetDeclineHandler sets the DECLINE handler.
func (h *DHCPPacketHandler) SetDeclineHandler(handler DeclineHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.declineHandler = handler
}

// SetReleaseHandler sets the RELEASE handler.
func (h *DHCPPacketHandler) SetReleaseHandler(handler ReleaseHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.releaseHandler = handler
}

// SetInformHandler sets the INFORM handler.
func (h *DHCPPacketHandler) SetInformHandler(handler InformHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.informHandler = handler
}

// SetMessageBuilder sets the message builder.
func (h *DHCPPacketHandler) SetMessageBuilder(builder *MessageBuilder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messageBuilder = builder
}

// SetSender sets the UDP sender.
func (h *DHCPPacketHandler) SetSender(sender *UDPSender) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sender = sender
}

// ============================================================================
// Main Packet Handler (implements PacketHandler interface)
// ============================================================================

// HandleDHCPPacket processes an incoming DHCP packet.
func (h *DHCPPacketHandler) HandleDHCPPacket(ctx context.Context, data []byte, clientAddr *net.UDPAddr) error {
	startTime := time.Now()

	// Check concurrency limit
	if atomic.LoadInt64(&h.concurrent) >= int64(h.config.MaxConcurrent) {
		atomic.AddInt64(&h.stats.TotalDropped, 1)
		return ErrTooManyRequests
	}
	atomic.AddInt64(&h.concurrent, 1)
	defer atomic.AddInt64(&h.concurrent, -1)

	// Parse packet into request context
	reqCtx, err := h.parsePacket(data, clientAddr)
	if err != nil {
		atomic.AddInt64(&h.stats.ParseErrors, 1)
		return err
	}
	reqCtx.ReceivedAt = startTime

	// Create processing context with timeout
	processCtx, cancel := context.WithTimeout(ctx, h.config.ProcessingTimeout)
	defer cancel()

	// Route to appropriate handler based on message type
	err = h.routeMessage(processCtx, reqCtx)

	// Update statistics
	processingTime := time.Since(startTime).Milliseconds()
	h.updateProcessingStats(reqCtx.MessageType, processingTime, err)

	return err
}

// ============================================================================
// Message Routing
// ============================================================================

func (h *DHCPPacketHandler) routeMessage(ctx context.Context, req *RequestContext) error {
	switch req.MessageType {
	case DHCPDiscover:
		atomic.AddInt64(&h.stats.DiscoverReceived, 1)
		return h.handleDiscover(ctx, req)

	case DHCPRequest:
		atomic.AddInt64(&h.stats.RequestReceived, 1)
		return h.handleRequest(ctx, req)

	case DHCPDecline:
		atomic.AddInt64(&h.stats.DeclineReceived, 1)
		return h.handleDecline(ctx, req)

	case DHCPRelease:
		atomic.AddInt64(&h.stats.ReleaseReceived, 1)
		return h.handleRelease(ctx, req)

	case DHCPInform:
		atomic.AddInt64(&h.stats.InformReceived, 1)
		return h.handleInform(ctx, req)

	default:
		atomic.AddInt64(&h.stats.TotalDropped, 1)
		return ErrUnknownMessageType
	}
}

// ============================================================================
// Message Type Handlers
// ============================================================================

func (h *DHCPPacketHandler) handleDiscover(ctx context.Context, req *RequestContext) error {
	h.mu.RLock()
	handler := h.discoverHandler
	h.mu.RUnlock()

	if handler == nil {
		return ErrNoDiscoverHandler
	}

	resp, err := handler.HandleDiscover(ctx, req)
	if err != nil {
		atomic.AddInt64(&h.stats.HandlerErrors, 1)
		return err
	}

	if resp != nil && resp.ShouldRespond {
		return h.sendResponse(req, resp, DHCPOffer)
	}

	return nil
}

func (h *DHCPPacketHandler) handleRequest(ctx context.Context, req *RequestContext) error {
	h.mu.RLock()
	handler := h.requestHandler
	h.mu.RUnlock()

	if handler == nil {
		return ErrNoRequestHandler
	}

	resp, err := handler.HandleRequest(ctx, req)
	if err != nil {
		atomic.AddInt64(&h.stats.HandlerErrors, 1)
		// Send NAK for certain errors
		if shouldNak(err) {
			return h.sendNak(req, err.Error())
		}
		return err
	}

	if resp != nil && resp.ShouldRespond {
		if resp.MessageType == DHCPNak {
			return h.sendNak(req, resp.NAKMessage)
		}
		return h.sendResponse(req, resp, DHCPAck)
	}

	return nil
}

func (h *DHCPPacketHandler) handleDecline(ctx context.Context, req *RequestContext) error {
	h.mu.RLock()
	handler := h.declineHandler
	h.mu.RUnlock()

	if handler == nil {
		return ErrNoDeclineHandler
	}

	// DECLINE: No response sent per RFC 2131
	err := handler.HandleDecline(ctx, req)
	if err != nil {
		atomic.AddInt64(&h.stats.HandlerErrors, 1)
	}

	return err
}

func (h *DHCPPacketHandler) handleRelease(ctx context.Context, req *RequestContext) error {
	h.mu.RLock()
	handler := h.releaseHandler
	h.mu.RUnlock()

	if handler == nil {
		return ErrNoReleaseHandler
	}

	// RELEASE: No response sent per RFC 2131
	err := handler.HandleRelease(ctx, req)
	if err != nil {
		atomic.AddInt64(&h.stats.HandlerErrors, 1)
	}

	return err
}

func (h *DHCPPacketHandler) handleInform(ctx context.Context, req *RequestContext) error {
	h.mu.RLock()
	handler := h.informHandler
	h.mu.RUnlock()

	if handler == nil {
		// INFORM is optional, skip if no handler
		return nil
	}

	resp, err := handler.HandleInform(ctx, req)
	if err != nil {
		atomic.AddInt64(&h.stats.HandlerErrors, 1)
		return err
	}

	if resp != nil && resp.ShouldRespond {
		return h.sendResponse(req, resp, DHCPAck)
	}

	return nil
}

// ============================================================================
// Response Sending
// ============================================================================

func (h *DHCPPacketHandler) sendResponse(req *RequestContext, resp *ResponseContext, msgType uint8) error {
	h.mu.RLock()
	builder := h.messageBuilder
	sender := h.sender
	h.mu.RUnlock()

	if builder == nil || sender == nil {
		return ErrNoResponseComponents
	}

	// Build response packet
	buildReq := &BuildRequest{
		TransactionID:  req.TransactionID,
		ClientMAC:      req.ClientMAC,
		ClientIP:       req.ClientIP,
		YourIP:         resp.YourIP,
		ServerIP:       resp.ServerIP,
		GatewayIP:      req.GatewayIP,
		Flags:          req.Flags,
		Hops:           req.Hops,
		MessageType:    msgType,
		LeaseTime:      resp.LeaseTime,
		SubnetMask:     resp.SubnetMask,
		Router:         resp.Router,
		DNSServers:     resp.DNSServers,
		DomainName:     resp.DomainName,
		Hostname:       resp.Hostname,
		CACertURL:      resp.CACertURL,
		InstallScripts: resp.InstallScripts,
		WPADURL:        resp.WPADURL,
		CRLURL:         resp.CRLURL,
		OCSPURL:        resp.OCSPURL,
	}

	var packet []byte
	var err error

	switch msgType {
	case DHCPOffer:
		packet, err = builder.BuildOffer(buildReq)
		if err == nil {
			atomic.AddInt64(&h.stats.OfferSent, 1)
		}
	case DHCPAck:
		packet, err = builder.BuildAck(buildReq)
		if err == nil {
			atomic.AddInt64(&h.stats.AckSent, 1)
		}
	default:
		return ErrInvalidResponseType
	}

	if err != nil {
		atomic.AddInt64(&h.stats.ResponseErrors, 1)
		return err
	}

	// Send response
	sendReq := &SendRequest{
		Data:          packet,
		ClientAddr:    req.ClientAddr,
		ClientMAC:     req.ClientMAC,
		ClientIP:      resp.YourIP,
		GatewayIP:     req.GatewayIP,
		BroadcastFlag: req.BroadcastFlag,
		MessageType:   messageTypeName(msgType),
		TransactionID: req.TransactionID,
	}

	_, err = sender.SendResponse(sendReq)
	if err != nil {
		atomic.AddInt64(&h.stats.ResponseErrors, 1)
	}

	return err
}

func (h *DHCPPacketHandler) sendNak(req *RequestContext, message string) error {
	h.mu.RLock()
	builder := h.messageBuilder
	sender := h.sender
	h.mu.RUnlock()

	if builder == nil || sender == nil {
		return ErrNoResponseComponents
	}

	buildReq := &BuildRequest{
		TransactionID: req.TransactionID,
		ClientMAC:     req.ClientMAC,
		GatewayIP:     req.GatewayIP,
		Flags:         req.Flags,
		Hops:          req.Hops,
		NAKMessage:    message,
	}

	packet, err := builder.BuildNak(buildReq)
	if err != nil {
		atomic.AddInt64(&h.stats.ResponseErrors, 1)
		return err
	}

	atomic.AddInt64(&h.stats.NakSent, 1)

	// NAK always broadcast
	sendReq := &SendRequest{
		Data:          packet,
		ClientAddr:    req.ClientAddr,
		ClientMAC:     req.ClientMAC,
		GatewayIP:     req.GatewayIP,
		BroadcastFlag: true,
		MessageType:   "NAK",
		TransactionID: req.TransactionID,
	}

	_, err = sender.SendResponse(sendReq)
	return err
}

// ============================================================================
// Packet Parsing
// ============================================================================

func (h *DHCPPacketHandler) parsePacket(data []byte, clientAddr *net.UDPAddr) (*RequestContext, error) {
	if len(data) < MinDHCPPacketSize {
		return nil, ErrPacketTooSmall
	}

	// Verify magic cookie
	if len(data) >= 240 {
		cookie := uint32(data[236])<<24 | uint32(data[237])<<16 | uint32(data[238])<<8 | uint32(data[239])
		if cookie != DHCPMagicCookie {
			return nil, ErrInvalidMagicCookie
		}
	}

	req := &RequestContext{
		RawPacket:  data,
		ClientAddr: clientAddr,
	}

	// Parse BOOTP header
	req.Hops = data[3]
	req.TransactionID = binary.BigEndian.Uint32(data[4:8])
	req.Flags = binary.BigEndian.Uint16(data[10:12])
	req.BroadcastFlag = (req.Flags & 0x8000) != 0

	// Extract IPs
	req.ClientIP = net.IP(data[12:16])
	req.YourIP = net.IP(data[16:20])
	req.ServerIP = net.IP(data[20:24])
	req.GatewayIP = net.IP(data[24:28])

	// Extract client MAC (first 6 bytes of chaddr)
	req.ClientMAC = net.HardwareAddr(data[28:34])

	// Parse options
	if err := h.parseOptions(data[240:], req); err != nil {
		return nil, err
	}

	// Validate message type was found
	if req.MessageType == 0 {
		return nil, ErrNoMessageType
	}

	return req, nil
}

func (h *DHCPPacketHandler) parseOptions(options []byte, req *RequestContext) error {
	offset := 0

	for offset < len(options) {
		optCode := options[offset]

		// End option
		if optCode == OptEnd {
			break
		}

		// Pad option (no length)
		if optCode == 0 {
			offset++
			continue
		}

		// Check we have length byte
		if offset+1 >= len(options) {
			break
		}

		optLen := int(options[offset+1])
		optData := options[offset+2 : offset+2+optLen]

		// Process option
		switch optCode {
		case OptMessageType:
			if optLen >= 1 {
				req.MessageType = optData[0]
			}
		case OptRequestedIP:
			if optLen >= 4 {
				req.RequestedIP = net.IP(optData[:4])
			}
		case OptHostname:
			req.Hostname = string(optData)
		case OptClientID:
			req.ClientID = optData
		case OptParamRequest:
			req.ParamList = optData
		}

		offset += 2 + optLen
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func shouldNak(_ error) bool {
	// Determine if error should result in NAK
	// Add specific error types that warrant NAK response
	return false
}

func messageTypeName(msgType uint8) string {
	switch msgType {
	case DHCPOffer:
		return "OFFER"
	case DHCPAck:
		return "ACK"
	case DHCPNak:
		return "NAK"
	default:
		return "UNKNOWN"
	}
}

func (h *DHCPPacketHandler) updateProcessingStats(_ uint8, processingMs int64, _ error) {
	atomic.AddInt64(&h.stats.TotalProcessed, 1)

	// Update average processing time (simple moving average)
	current := atomic.LoadInt64(&h.stats.AvgProcessingMs)
	if current == 0 {
		atomic.StoreInt64(&h.stats.AvgProcessingMs, processingMs)
	} else {
		avg := (current + processingMs) / 2
		atomic.StoreInt64(&h.stats.AvgProcessingMs, avg)
	}
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns packet handler statistics.
func (h *DHCPPacketHandler) GetStats() PacketHandlerStats {
	return PacketHandlerStats{
		DiscoverReceived: atomic.LoadInt64(&h.stats.DiscoverReceived),
		RequestReceived:  atomic.LoadInt64(&h.stats.RequestReceived),
		DeclineReceived:  atomic.LoadInt64(&h.stats.DeclineReceived),
		ReleaseReceived:  atomic.LoadInt64(&h.stats.ReleaseReceived),
		InformReceived:   atomic.LoadInt64(&h.stats.InformReceived),
		OfferSent:        atomic.LoadInt64(&h.stats.OfferSent),
		AckSent:          atomic.LoadInt64(&h.stats.AckSent),
		NakSent:          atomic.LoadInt64(&h.stats.NakSent),
		ParseErrors:      atomic.LoadInt64(&h.stats.ParseErrors),
		HandlerErrors:    atomic.LoadInt64(&h.stats.HandlerErrors),
		ResponseErrors:   atomic.LoadInt64(&h.stats.ResponseErrors),
		TotalProcessed:   atomic.LoadInt64(&h.stats.TotalProcessed),
		TotalDropped:     atomic.LoadInt64(&h.stats.TotalDropped),
		AvgProcessingMs:  atomic.LoadInt64(&h.stats.AvgProcessingMs),
	}
}

// GetConcurrent returns current concurrent request count.
func (h *DHCPPacketHandler) GetConcurrent() int64 {
	return atomic.LoadInt64(&h.concurrent)
}

// ============================================================================
// Errors
// ============================================================================

var (
	// ErrUnknownMessageType is returned for unknown DHCP message types
	ErrUnknownMessageType = errors.New("unknown DHCP message type")

	// ErrNoMessageType is returned when Option 53 not found
	ErrNoMessageType = errors.New("no DHCP message type option found")

	// ErrNoDiscoverHandler is returned when DISCOVER handler not set
	ErrNoDiscoverHandler = errors.New("no DISCOVER handler configured")

	// ErrNoRequestHandler is returned when REQUEST handler not set
	ErrNoRequestHandler = errors.New("no REQUEST handler configured")

	// ErrNoDeclineHandler is returned when DECLINE handler not set
	ErrNoDeclineHandler = errors.New("no DECLINE handler configured")

	// ErrNoReleaseHandler is returned when RELEASE handler not set
	ErrNoReleaseHandler = errors.New("no RELEASE handler configured")

	// ErrNoResponseComponents is returned when builder or sender not set
	ErrNoResponseComponents = errors.New("response components not configured")

	// ErrInvalidResponseType is returned for invalid response message type
	ErrInvalidResponseType = errors.New("invalid response message type")

	// ErrTooManyRequests is returned when concurrent limit exceeded
	ErrTooManyRequests = errors.New("too many concurrent requests")
)
