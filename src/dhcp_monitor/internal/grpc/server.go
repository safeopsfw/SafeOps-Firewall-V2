// Package grpc provides the gRPC server implementation for DHCP Monitor
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"dhcp_monitor/internal/database"
	"dhcp_monitor/internal/manager"
	"dhcp_monitor/internal/watcher"
	gen "dhcp_monitor/proto/gen"
)

// =============================================================================
// SERVER CONFIGURATION CONSTANTS
// =============================================================================

const (
	DefaultPort                 = 50055
	DefaultMaxConnectionIdle    = 15 * time.Minute
	DefaultMaxConnectionAge     = 30 * time.Minute
	DefaultMaxConcurrentStreams = 100
	DefaultMaxRecvMsgSize       = 4 * 1024 * 1024 // 4 MB
	DefaultMaxSendMsgSize       = 4 * 1024 * 1024 // 4 MB
	DefaultKeepaliveInterval    = 2 * time.Hour
	DefaultKeepaliveTimeout     = 20 * time.Second
	DefaultShutdownTimeout      = 30 * time.Second
)

// =============================================================================
// SERVER STATISTICS
// =============================================================================

// ServerStatistics contains server runtime metrics
type ServerStatistics struct {
	TotalRPCs     int64     `json:"total_rpcs"`
	ErrorCount    int64     `json:"error_count"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	StartTime     time.Time `json:"start_time"`
}

// =============================================================================
// GRPC SERVER STRUCT
// =============================================================================

// Server manages the gRPC server lifecycle and implements DHCPMonitorServer
type Server struct {
	gen.UnimplementedDHCPMonitorServer

	grpcServer    *grpc.Server
	listener      net.Listener
	deviceManager *manager.DeviceManager
	db            *database.DatabaseClient

	// Lifecycle
	isRunning       bool
	mutex           sync.Mutex
	startTime       time.Time
	shutdownTimeout time.Duration

	// TLS config
	tlsEnabled  bool
	tlsCertPath string
	tlsKeyPath  string
	tlsCAPath   string

	// Statistics
	totalRPCs  int64
	errorCount int64
}

// NewServer creates a new gRPC server with device management
func NewServer(db *database.DatabaseClient) *Server {
	// Create event channel for watcher -> manager communication
	eventChannel := watcher.NewEventChannel(100)

	// Create device manager
	deviceMgr, _ := manager.NewDeviceManager(db, eventChannel, 5*time.Minute, 10*time.Minute)

	return &Server{
		db:              db,
		deviceManager:   deviceMgr,
		isRunning:       false,
		shutdownTimeout: DefaultShutdownTimeout,
	}
}

// =============================================================================
// LIFECYCLE METHODS
// =============================================================================

// Start begins accepting gRPC connections
func (s *Server) Start(host string, port int) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isRunning {
		return fmt.Errorf("gRPC server already running")
	}

	// Validate port
	if port <= 0 || port > 65535 {
		port = DefaultPort
	}

	// Create TCP listener
	address := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}
	s.listener = listener

	// Build server options
	options, err := s.buildServerOptions()
	if err != nil {
		s.listener.Close()
		return fmt.Errorf("failed to build server options: %w", err)
	}

	// Create gRPC server
	s.grpcServer = grpc.NewServer(options...)

	// Register DHCP Monitor service
	gen.RegisterDHCPMonitorServer(s.grpcServer, s)

	// Start device manager
	if s.deviceManager != nil {
		ctx := context.Background()
		if err := s.deviceManager.Start(ctx); err != nil {
			log.Printf("[GRPC_SERVER] Warning: device manager start failed: %v", err)
		}
	}

	s.isRunning = true
	s.startTime = time.Now()

	log.Printf("[GRPC_SERVER] Listening on %s", address)

	// Start serving (blocking)
	if err := s.grpcServer.Serve(s.listener); err != nil {
		return fmt.Errorf("serve error: %w", err)
	}

	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isRunning {
		return
	}

	log.Println("[GRPC_SERVER] Shutting down...")

	// Stop device manager first
	if s.deviceManager != nil {
		s.deviceManager.Stop()
	}

	// Graceful stop with timeout
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[GRPC_SERVER] Graceful shutdown complete (%d RPCs processed)",
			atomic.LoadInt64(&s.totalRPCs))
	case <-time.After(s.shutdownTimeout):
		log.Println("[GRPC_SERVER] Shutdown timeout, forcing stop")
		s.grpcServer.Stop()
	}

	s.isRunning = false
}

// IsRunning returns server status
func (s *Server) IsRunning() bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.isRunning
}

// =============================================================================
// SERVER OPTIONS
// =============================================================================

// buildServerOptions creates gRPC server options
func (s *Server) buildServerOptions() ([]grpc.ServerOption, error) {
	var options []grpc.ServerOption

	// TLS configuration
	if s.tlsEnabled {
		creds, err := s.loadTLSCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		options = append(options, grpc.Creds(creds))
	}

	// Keepalive parameters
	kaParams := keepalive.ServerParameters{
		MaxConnectionIdle: DefaultMaxConnectionIdle,
		MaxConnectionAge:  DefaultMaxConnectionAge,
		Time:              DefaultKeepaliveInterval,
		Timeout:           DefaultKeepaliveTimeout,
	}
	options = append(options, grpc.KeepaliveParams(kaParams))

	// Enforcement policy
	kaPolicy := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}
	options = append(options, grpc.KeepaliveEnforcementPolicy(kaPolicy))

	// Connection limits
	options = append(options, grpc.MaxConcurrentStreams(uint32(DefaultMaxConcurrentStreams)))
	options = append(options, grpc.MaxRecvMsgSize(DefaultMaxRecvMsgSize))
	options = append(options, grpc.MaxSendMsgSize(DefaultMaxSendMsgSize))

	// Interceptors
	options = append(options, grpc.UnaryInterceptor(s.loggingInterceptor()))

	return options, nil
}

// loggingInterceptor creates a logging interceptor
func (s *Server) loggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Call handler
		resp, err := handler(ctx, req)

		// Update statistics
		atomic.AddInt64(&s.totalRPCs, 1)
		if err != nil {
			atomic.AddInt64(&s.errorCount, 1)
		}

		// Log RPC
		latency := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code()
			} else {
				statusCode = codes.Unknown
			}
		}

		log.Printf("[GRPC_SERVER] %s status=%s latency=%v",
			info.FullMethod, statusCode.String(), latency)

		return resp, err
	}
}

// loadTLSCredentials loads TLS certificates
func (s *Server) loadTLSCredentials() (credentials.TransportCredentials, error) {
	serverCert, err := tls.LoadX509KeyPair(s.tlsCertPath, s.tlsKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if s.tlsCAPath != "" {
		caCert, err := os.ReadFile(s.tlsCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return credentials.NewTLS(tlsConfig), nil
}

// GetStatistics returns server runtime metrics
func (s *Server) GetStatistics() *ServerStatistics {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var uptimeSeconds int64
	if s.isRunning {
		uptimeSeconds = int64(time.Since(s.startTime).Seconds())
	}

	return &ServerStatistics{
		TotalRPCs:     atomic.LoadInt64(&s.totalRPCs),
		ErrorCount:    atomic.LoadInt64(&s.errorCount),
		UptimeSeconds: uptimeSeconds,
		StartTime:     s.startTime,
	}
}

// =============================================================================
// GRPC SERVICE IMPLEMENTATION
// =============================================================================

// GetDeviceByIP implements DHCPMonitorServer
func (s *Server) GetDeviceByIP(ctx context.Context, req *gen.IPRequest) (*gen.Device, error) {
	if req.GetIpAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "IP address is required")
	}

	device, err := s.deviceManager.GetDeviceByIP(ctx, req.GetIpAddress())
	if err != nil {
		return nil, status.Error(codes.NotFound, "device not found")
	}

	return device.ToProto(), nil
}

// GetDeviceByMAC implements DHCPMonitorServer
func (s *Server) GetDeviceByMAC(ctx context.Context, req *gen.MACRequest) (*gen.Device, error) {
	if req.GetMacAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "MAC address is required")
	}

	device, err := s.deviceManager.GetDeviceByMAC(ctx, req.GetMacAddress())
	if err != nil {
		return nil, status.Error(codes.NotFound, "device not found")
	}

	return device.ToProto(), nil
}

// GetDeviceByID implements DHCPMonitorServer
func (s *Server) GetDeviceByID(ctx context.Context, req *gen.DeviceIDRequest) (*gen.Device, error) {
	if req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	deviceID, err := parseUUID(req.GetDeviceId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid device ID format")
	}

	device, err := s.deviceManager.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "device not found")
	}

	return device.ToProto(), nil
}

// UpdateTrustStatus implements DHCPMonitorServer
func (s *Server) UpdateTrustStatus(ctx context.Context, req *gen.TrustUpdateRequest) (*gen.Device, error) {
	if req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	deviceID, err := parseUUID(req.GetDeviceId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid device ID format")
	}

	device, err := s.deviceManager.UpdateTrustStatus(ctx, deviceID, req.GetTrustStatus())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return device.ToProto(), nil
}

// MarkPortalShown implements DHCPMonitorServer
// Phase 3A: Called by Captive Portal when welcome page is loaded
// Used by TLS Proxy to skip redirect for ALLOW_ONCE policy
func (s *Server) MarkPortalShown(ctx context.Context, req *gen.MarkPortalShownRequest) (*gen.Device, error) {
	// Allow lookup by device_id or ip_address
	deviceID := req.GetDeviceId()
	ipAddress := req.GetIpAddress()

	if deviceID == "" && ipAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id or ip_address is required")
	}

	var device *database.Device
	var err error

	if deviceID != "" {
		uid, parseErr := parseUUID(deviceID)
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid device ID format")
		}
		device, err = s.db.MarkPortalShown(ctx, uid)
	} else {
		device, err = s.db.MarkPortalShownByIP(ctx, ipAddress)
	}

	if err != nil {
		log.Printf("[GRPC_SERVER] MarkPortalShown error: %v", err)
		return nil, status.Error(codes.NotFound, "device not found")
	}

	log.Printf("[GRPC_SERVER] MarkPortalShown: device=%s IP=%s portal_shown=true",
		device.DeviceID, device.CurrentIP)

	return device.ToProto(), nil
}

// MarkCACertInstalled implements DHCPMonitorServer - Phase 3B CA cert tracking
func (s *Server) MarkCACertInstalled(ctx context.Context, req *gen.MarkCACertInstalledRequest) (*gen.Device, error) {
	// Allow lookup by device_id, ip_address, or mac_address
	deviceID := req.GetDeviceId()
	ipAddress := req.GetIpAddress()
	macAddress := req.GetMacAddress()

	if deviceID == "" && ipAddress == "" && macAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id, ip_address, or mac_address is required")
	}

	var device *database.Device
	var err error

	if deviceID != "" {
		uid, parseErr := parseUUID(deviceID)
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid device ID format")
		}
		device, err = s.db.MarkCACertInstalled(ctx, uid)
	} else if ipAddress != "" {
		device, err = s.db.MarkCACertInstalledByIP(ctx, ipAddress)
	} else {
		device, err = s.db.MarkCACertInstalledByMAC(ctx, macAddress)
	}

	if err != nil {
		log.Printf("[GRPC_SERVER] MarkCACertInstalled error: %v", err)
		return nil, status.Error(codes.NotFound, "device not found")
	}

	log.Printf("[GRPC_SERVER] ✅ MarkCACertInstalled: device=%s IP=%s MAC=%s ca_cert=true",
		device.DeviceID, device.CurrentIP, device.MACAddress)

	return device.ToProto(), nil
}

// ListDevices implements DHCPMonitorServer
func (s *Server) ListDevices(ctx context.Context, req *gen.ListDevicesRequest) (*gen.DeviceList, error) {
	filter := &database.DeviceFilter{
		TrustStatus: req.GetFilterByTrust(),
		OnlineOnly:  req.GetOnlineOnly(),
		Limit:       req.GetLimit(),
		Offset:      req.GetOffset(),
	}

	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	devices, total, err := s.deviceManager.ListDevices(ctx, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	protoDevices := make([]*gen.Device, len(devices))
	for i, d := range devices {
		protoDevices[i] = d.ToProto()
	}

	return &gen.DeviceList{
		Devices:    protoDevices,
		TotalCount: total,
	}, nil
}

// GetDeviceStats implements DHCPMonitorServer
func (s *Server) GetDeviceStats(ctx context.Context, req *gen.Empty) (*gen.DeviceStats, error) {
	stats, err := s.deviceManager.GetDeviceStats(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &gen.DeviceStats{
		TotalDevices:     stats.TotalDevices,
		OnlineDevices:    stats.OnlineDevices,
		TrustedDevices:   stats.TrustedDevices,
		UntrustedDevices: stats.UntrustedDevices,
		BlockedDevices:   stats.BlockedDevices,
	}, nil
}

// HealthCheck implements DHCPMonitorServer
func (s *Server) HealthCheck(ctx context.Context, req *gen.Empty) (*gen.HealthStatus, error) {
	return &gen.HealthStatus{
		Healthy:        true,
		DatabaseStatus: "connected",
		Uptime:         time.Since(s.startTime).String(),
		TotalQueries:   atomic.LoadInt64(&s.totalRPCs),
	}, nil
}

// =============================================================================
// DHCP EVENT REPORTING FROM PACKET ENGINE
// =============================================================================

// ReportDhcpEvent implements DHCPMonitorServer - receives DHCP packets from Packet Engine
// This is the NEW method that enables Packet Engine to report captured DHCP traffic
// for device detection and enrichment
func (s *Server) ReportDhcpEvent(ctx context.Context, req *gen.DhcpEvent) (*gen.DhcpEventResponse, error) {
	// Validate MAC address
	if req.GetMacAddress() == "" {
		return &gen.DhcpEventResponse{
			Success: false,
			Message: "MAC address is required",
		}, nil
	}

	// Normalize MAC address
	mac := NormalizeMACAddress(req.GetMacAddress())

	log.Printf("[GRPC_SERVER] 📡 DHCP Event: type=%s MAC=%s IP=%s hostname=%s vendor=%s",
		req.GetMessageType(), mac, req.GetClientIp(), req.GetHostname(), req.GetVendorClass())

	// Create or update device in database
	device, isNew, err := s.processDeviceFromDhcpEvent(ctx, req, mac)
	if err != nil {
		log.Printf("[GRPC_SERVER] ❌ DHCP Event failed: %v", err)
		return &gen.DhcpEventResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	if isNew {
		log.Printf("[GRPC_SERVER] ✅ New device created from DHCP: device_id=%s MAC=%s hostname=%s",
			device.DeviceID, mac, req.GetHostname())
	} else {
		log.Printf("[GRPC_SERVER] ✅ Device updated from DHCP: device_id=%s MAC=%s hostname=%s",
			device.DeviceID, mac, req.GetHostname())
	}

	return &gen.DhcpEventResponse{
		Success:     true,
		DeviceId:    device.DeviceID.String(),
		Message:     "Device processed successfully",
		IsNewDevice: isNew,
	}, nil
}

// processDeviceFromDhcpEvent creates or updates a device from DHCP event data
func (s *Server) processDeviceFromDhcpEvent(ctx context.Context, req *gen.DhcpEvent, mac string) (*database.Device, bool, error) {
	// Try to find existing device by MAC
	existingDevice, err := s.db.GetDeviceByMAC(ctx, mac)

	if err == nil && existingDevice != nil {
		// Device exists - update with new DHCP info
		if req.GetClientIp() != "" && req.GetClientIp() != "0.0.0.0" {
			existingDevice.CurrentIP = net.ParseIP(req.GetClientIp())
		}
		if req.GetHostname() != "" {
			existingDevice.Hostname = sql.NullString{String: req.GetHostname(), Valid: true}
		}
		if req.GetVendorClass() != "" {
			existingDevice.Vendor = sql.NullString{String: req.GetVendorClass(), Valid: true}
		}
		if req.GetInterfaceName() != "" {
			existingDevice.InterfaceName = req.GetInterfaceName()
		}

		// Always update last_seen and detection method
		existingDevice.LastSeen = time.Now()
		existingDevice.IsOnline = true
		existingDevice.DetectionMethod = database.DetectionMethod("PACKET_ENGINE_DHCP")

		err := s.db.UpdateDevice(ctx, existingDevice)
		if err != nil {
			return nil, false, fmt.Errorf("failed to update device: %w", err)
		}
		return existingDevice, false, nil
	}

	// Device doesn't exist - create new device
	newDevice := &database.Device{
		DeviceID:        uuid.New(),
		MACAddress:      mac,
		CurrentIP:       net.ParseIP(req.GetClientIp()),
		Hostname:        sql.NullString{String: req.GetHostname(), Valid: req.GetHostname() != ""},
		DeviceType:      "Unknown",
		Vendor:          sql.NullString{String: req.GetVendorClass(), Valid: req.GetVendorClass() != ""},
		TrustStatus:     database.TrustStatusUntrusted,
		InterfaceName:   req.GetInterfaceName(),
		Status:          database.DeviceStatusActive,
		DetectionMethod: database.DetectionMethod("PACKET_ENGINE_DHCP"),
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		IsOnline:        true,
	}

	// Insert into database
	err = s.db.CreateDevice(ctx, newDevice)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create device: %w", err)
	}

	// Audit log
	LogDeviceCreated(newDevice.DeviceID, mac, req.GetClientIp(), req.GetInterfaceName())

	return newDevice, true, nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
