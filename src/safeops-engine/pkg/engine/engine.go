// Package engine provides public API for SafeOps Engine integration
package engine

import (
	"context"
	"fmt"
	"sync"

	"safeops-engine/internal/config"
	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
	"safeops-engine/internal/parser"
	grpcserver "safeops-engine/pkg/grpc"
	"safeops-engine/pkg/stream"
)

var (
	globalEngine *Engine
	once         sync.Once
	mu           sync.RWMutex
)

// Engine represents the SafeOps Engine instance
type Engine struct {
	log         *logger.Logger
	driver      *driver.Driver
	broadcaster *stream.Broadcaster
	grpcServer  *grpcserver.Server
	ctx         context.Context
	cancel      context.CancelFunc

	// Parsers for domain extraction
	dnsParser  *parser.DNSParser
	tlsParser  *parser.TLSParser
	httpParser *parser.HTTPParser
}

// GetEngine returns the global SafeOps Engine instance
func GetEngine() *Engine {
	mu.RLock()
	defer mu.RUnlock()
	return globalEngine
}

// Initialize creates and starts the SafeOps Engine
func Initialize() (*Engine, error) {
	var err error
	once.Do(func() {
		logCfg := config.LoggingConfig{
			Level:  "info",
			Format: "json",
			File:   "D:/SafeOpsFV2/data/logs/engine.log",
		}

		log := logger.New(logCfg)
		log.StartRotation()

		ctx, cancel := context.WithCancel(context.Background())

		// Open driver
		drv, drvErr := driver.Open(log)
		if drvErr != nil {
			err = fmt.Errorf("failed to open driver: %w", drvErr)
			cancel()
			return
		}

		// Set tunnel mode
		if tunnelErr := drv.SetTunnelModeAll(); tunnelErr != nil {
			err = fmt.Errorf("failed to set tunnel mode: %w", tunnelErr)
			drv.Close()
			cancel()
			return
		}

		// Create broadcaster with 10k buffer
		broadcaster := stream.NewBroadcaster(10000)

		// Create gRPC server
		grpcSrv, grpcErr := grpcserver.NewServer(log, drv, "127.0.0.1:50051")
		if grpcErr != nil {
			err = fmt.Errorf("failed to create gRPC server: %w", grpcErr)
			drv.Close()
			cancel()
			return
		}

		engine := &Engine{
			log:         log,
			driver:      drv,
			broadcaster: broadcaster,
			grpcServer:  grpcSrv,
			ctx:         ctx,
			cancel:      cancel,
			dnsParser:   parser.NewDNSParser(),
			tlsParser:   parser.NewTLSParser(),
			httpParser:  parser.NewHTTPParser(),
		}

		// Set packet handler
		drv.SetHandler(func(pkt *driver.ParsedPacket) bool {
			// FAST PATH: Broadcast to gRPC (includes verdict cache check)
			// This returns immediately if no subscribers or verdict is cached
			shouldAllow := engine.grpcServer.BroadcastPacket(pkt)
			if !shouldAllow {
				return false // Firewall blocked this packet
			}

			// OPTIMIZATION: Only extract domain if subscribers need it
			// For gaming, this is rarely needed and adds latency
			// Domain extraction now happens in gRPC layer only if needed

			// Convert to public metadata (for in-process subscribers if any)
			meta := stream.ConvertPacket(pkt)

			// Broadcast to in-process subscribers (if any exist)
			engine.broadcaster.Broadcast(meta)

			// Allow packet through
			return true
		})

		// Start gRPC server
		if startErr := grpcSrv.Start(); startErr != nil {
			err = fmt.Errorf("failed to start gRPC server: %w", startErr)
			drv.Close()
			cancel()
			return
		}

		// Start packet processing
		go drv.ProcessPacketsAll(ctx)

		log.Info("SafeOps Engine initialized", map[string]interface{}{
			"version":     "3.0.0",
			"mode":        "grpc-stream",
			"grpc_listen": "127.0.0.1:50051",
		})

		mu.Lock()
		globalEngine = engine
		mu.Unlock()
	})

	return globalEngine, err
}

// SubscribeToMetadata creates a subscription to the packet metadata stream
func (e *Engine) SubscribeToMetadata(subscriberID string) *stream.Subscriber {
	e.log.Info("New metadata subscriber", map[string]interface{}{
		"subscriber_id": subscriberID,
		"total_subs":    e.broadcaster.SubscriberCount() + 1,
	})
	return e.broadcaster.Subscribe(subscriberID)
}

// UnsubscribeFromMetadata removes a metadata subscription
func (e *Engine) UnsubscribeFromMetadata(subscriberID string) {
	e.broadcaster.Unsubscribe(subscriberID)
	e.log.Info("Metadata subscriber removed", map[string]interface{}{
		"subscriber_id": subscriberID,
		"total_subs":    e.broadcaster.SubscriberCount(),
	})
}

// GetStats returns packet statistics
func (e *Engine) GetStats() (read, written, dropped uint64) {
	return e.driver.GetStats()
}

// Shutdown stops the engine
func (e *Engine) Shutdown() {
	e.log.Info("Shutting down SafeOps Engine", nil)
	e.cancel()

	// Stop gRPC server
	if e.grpcServer != nil {
		e.grpcServer.Stop()
	}

	e.driver.Close()
	e.log.Close()
}
