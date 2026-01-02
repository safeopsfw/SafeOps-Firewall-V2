// Package main is the TLS Proxy service entry point.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tls_proxy/internal/buffer"
	"tls_proxy/internal/config"
	"tls_proxy/internal/dns"
	"tls_proxy/internal/forwarder"
	tlsgrpc "tls_proxy/internal/grpc"
	"tls_proxy/internal/processor"
)

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

func main() {
	fmt.Println("Starting TLS Proxy...")

	// Step 1: Load Configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	cfg.Print()

	// Step 2: Initialize DNS Resolver
	resolver := dns.NewSNIResolver(cfg)
	fmt.Printf("Initialized DNS resolver (target: %s)\n", cfg.DNSServerAddress)

	// Step 3: Initialize Packet Buffer
	buf := buffer.NewPacketBuffer(cfg)
	fmt.Printf("Initialized packet buffer (capacity: %d, TTL: %v)\n", cfg.PacketBufferSize, cfg.BufferTTL)

	// Step 4: Initialize Packet Processor
	proc := processor.NewPacketProcessor(cfg, resolver, buf)
	fmt.Println("Initialized packet processor")

	// Step 5: Initialize Packet Forwarder
	fwd := forwarder.NewPacketForwarder(cfg, buf)
	fmt.Println("Initialized packet forwarder")

	// Step 6: Initialize gRPC Service
	service := tlsgrpc.NewTLSProxyService(cfg, proc, fwd)
	fmt.Println("Initialized gRPC service")

	// Step 7: Start gRPC Server
	if err := service.Start(cfg.GRPCPort); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start gRPC server: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("TLS Proxy running on :%d\n", cfg.GRPCPort)
	fmt.Println("Press Ctrl+C to stop")

	// Step 8: Setup Signal Handlers
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Step 9: Wait for Termination Signal
	sig := <-signalChan
	fmt.Printf("\nReceived signal: %v\n", sig)

	// Step 10: Graceful Shutdown
	shutdown(service, buf, resolver, proc)
}

// =============================================================================
// SHUTDOWN SEQUENCE
// =============================================================================

// shutdown performs graceful cleanup of all components.
func shutdown(
	service *tlsgrpc.TLSProxyService,
	buf *buffer.PacketBuffer,
	resolver *dns.SNIResolver,
	proc *processor.PacketProcessor,
) {
	fmt.Println("Shutting down TLS Proxy...")

	// Stop accepting new requests
	fmt.Println("Stopping gRPC server...")
	service.Stop()
	fmt.Println("gRPC server stopped")

	// Display final statistics
	displayStats(service, buf, resolver, proc)

	// Cleanup buffer
	removed := buf.Cleanup()
	fmt.Printf("Buffer cleanup: removed %d expired entries\n", removed)

	// Clear processor connection cache
	proc.ClearConnectionCache()
	fmt.Println("Cleared processor cache")

	fmt.Println("TLS Proxy stopped")
}

// =============================================================================
// STATISTICS DISPLAY
// =============================================================================

// displayStats prints final service statistics.
func displayStats(
	service *tlsgrpc.TLSProxyService,
	buf *buffer.PacketBuffer,
	resolver *dns.SNIResolver,
	proc *processor.PacketProcessor,
) {
	fmt.Println("\n=== Final Statistics ===")

	// gRPC Service Stats
	svcStats := service.GetStats()
	fmt.Printf("gRPC Requests:     %d total, %d successful, %d errors\n",
		svcStats.TotalRequests, svcStats.SuccessfulResponses, svcStats.ErrorResponses)
	fmt.Printf("Peak Active:       %d concurrent requests\n", svcStats.PeakActiveRequests)
	fmt.Printf("Average Latency:   %v\n", svcStats.AverageLatency())

	// Processor Stats
	procStats := proc.GetStats()
	fmt.Printf("Packets Processed: %d total, %d HTTPS\n",
		procStats.TotalPacketsProcessed, procStats.HTTPSPacketsDetected)
	fmt.Printf("SNI Extractions:   %d attempted, %d succeeded (%.1f%%)\n",
		procStats.SNIExtractionsAttempted, procStats.SNIExtractionsSucceeded, procStats.SNISuccessRate())
	fmt.Printf("DNS Queries:       %d attempted, %d succeeded (%.1f%%)\n",
		procStats.DNSQueriesPerformed, procStats.DNSQueriesSucceeded, procStats.DNSSuccessRate())

	// Buffer Stats
	bufStats := buf.GetStats()
	fmt.Printf("Buffer Operations: %d stored, %d evicted, %d expired\n",
		bufStats.TotalStored, bufStats.EvictionCount, bufStats.ExpirationCount)
	fmt.Printf("Buffer Size:       %d current / %d max\n", bufStats.CurrentCount, buf.Capacity())

	// Resolver Stats
	resStats := resolver.GetStats()
	fmt.Printf("Resolver Queries:  %d total, %d succeeded, %d NXDOMAIN, %d timeouts\n",
		resStats.TotalQueries, resStats.SuccessfulResolutions, resStats.NXDomainCount, resStats.TimeoutCount)
	fmt.Printf("Average DNS RTT:   %v\n", resStats.AverageResponseTime())

	fmt.Println("========================")
}
