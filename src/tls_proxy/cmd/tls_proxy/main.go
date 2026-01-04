// Package main is the TLS Proxy Phase 3 (3A + 3B) application entry point.
// Phase 3A: DNS Decision Service + HTTP Packet Interception & Redirection
// Phase 3B: TLS MITM Inspection with SNI Parser + Certificate Cache + Dual TLS
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"tls_proxy/internal/brain"
	"tls_proxy/internal/certcache"
	"tls_proxy/internal/grpc"
	"tls_proxy/internal/integration"
	"tls_proxy/internal/transparent"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Check if MITM is enabled (Phase 3B)
	enableMITM := getEnvBool("TLS_PROXY_ENABLE_MITM", false)

	if enableMITM {
		log.Println("==========================================================")
		log.Println("  SafeOps TLS Proxy - Phase 3B (3A + MITM)")
		log.Println("  HTTPS MITM Inspection + HTTP Redirection")
		log.Println("==========================================================")
	} else {
		log.Println("==========================================================")
		log.Println("  SafeOps TLS Proxy - Phase 3A")
		log.Println("  DNS Decisions + HTTP Packet Interception + Redirection")
		log.Println("==========================================================")
	}

	// Configuration from environment
	dhcpMonitorAddr := getEnv("TLS_PROXY_DHCP_MONITOR", "localhost:50055")
	stepCAAddr := getEnv("TLS_PROXY_STEP_CA", "https://localhost:9000")
	stepCAToken := getEnv("TLS_PROXY_STEP_CA_TOKEN", "")
	dnsDecisionPort := getEnvInt("TLS_PROXY_DNS_PORT", 50052)
	packetProcessingPort := getEnvInt("TLS_PROXY_PACKET_PORT", 50051)
	gatewayIP := getEnv("TLS_PROXY_GATEWAY_IP", "192.168.137.1")
	policyMode := getEnv("TLS_PROXY_POLICY", "ALLOW_ONCE") // STRICT, PERMISSIVE, ALLOW_ONCE
	captiveURL := getEnv("TLS_PROXY_CAPTIVE_URL", "https://captive.safeops.local:8444/welcome")
	showOnce := getEnvBool("TLS_PROXY_SHOW_ONCE", true)

	logConfig(dhcpMonitorAddr, stepCAAddr, dnsDecisionPort, packetProcessingPort, gatewayIP, policyMode, captiveURL, showOnce, enableMITM)

	// Initialize DHCP Monitor client
	dhcpMonitor, err := integration.NewDHCPMonitorClient(dhcpMonitorAddr, 5000000000)
	if err != nil {
		log.Printf("WARNING: DHCP Monitor connection failed: %v", err)
		log.Println("Using stub client (all devices UNTRUSTED)")
	} else {
		log.Printf("✓ Connected to DHCP Monitor")
	}

	// Initialize Step-CA client and generate Root CA
	// Root CA is always needed for captive portal certificate download
	var stepCA *integration.StepCAClient
	stepCA = integration.NewStepCAClient(stepCAAddr, stepCAToken)

	// Generate Root CA certificate for MITM and captive portal
	if err := stepCA.GenerateRootCA(); err != nil {
		log.Fatalf("CRITICAL: Failed to generate Root CA: %v", err)
	}

	// Save Root CA to file for captive portal to serve
	rootCAPath := "D:/SafeOpsFV2/src/tls_proxy/certs/safeops-root-ca.crt"
	if err := stepCA.SaveRootCAToFile(rootCAPath); err != nil {
		log.Fatalf("CRITICAL: Failed to save Root CA: %v", err)
	}
	log.Printf("✓ Root CA ready at: %s", rootCAPath)

	// Create certificate cache for MITM (if enabled)
	var certCache *certcache.CertificateCache
	if enableMITM {
		log.Printf("✓ Step-CA client initialized for MITM: %s", stepCAAddr)
		certCache = certcache.NewCertificateCache(stepCA, 24*3600000000000, 1000) // 24h TTL, 1000 certs max
	}

	// Create decision engine
	decisionConfig := &brain.DecisionConfig{
		InternalDomains: []string{"captive.safeops.local", "safeops.local"},
		GatewayIP:       gatewayIP,
		PolicyMode:      policyMode,
		DefaultTTL:      300,
	}
	engine := brain.NewDecisionEngine(dhcpMonitor, decisionConfig)
	log.Println("✓ Decision engine initialized")

	// Create DNS decision gRPC server
	dnsAddr := fmt.Sprintf(":%d", dnsDecisionPort)
	dnsServer, err := grpc.NewDNSDecisionGRPCServer(dnsAddr, engine)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	// Create packet processing gRPC server
	packetAddr := fmt.Sprintf(":%d", packetProcessingPort)
	var packetServer *grpc.PacketProcessingGRPCServer
	if enableMITM {
		// With MITM inspection
		packetServer, err = grpc.NewPacketProcessingGRPCServerWithMITM(
			packetAddr,
			dhcpMonitor,
			stepCA,
			captiveURL,
			policyMode,
			showOnce,
			true, // enableMITM
		)
	} else {
		// HTTP only
		packetServer, err = grpc.NewPacketProcessingGRPCServer(packetAddr, dhcpMonitor, captiveURL, policyMode, showOnce)
	}
	if err != nil {
		log.Fatalf("Failed to create packet server: %v", err)
	}

	// Start transparent HTTPS proxy if MITM is enabled
	if enableMITM && certCache != nil {
		transparentProxyAddr := gatewayIP + ":443"
		transparentProxy := transparent.NewTransparentProxy(
			transparentProxyAddr,
			certCache,
			dhcpMonitor,
			true, // Log HTTP traffic to console
		)

		go func() {
			log.Printf("✓ Transparent HTTPS Proxy: %s (MITM Inspection)", transparentProxyAddr)
			if err := transparentProxy.Start(); err != nil {
				log.Fatalf("Transparent proxy error: %v", err)
			}
		}()
	}

	// Start servers
	go func() {
		log.Printf("✓ DNS Decision Service: %s", dnsAddr)
		if err := dnsServer.Start(); err != nil {
			log.Fatalf("DNS server error: %v", err)
		}
	}()

	go func() {
		log.Printf("✓ Packet Processing Service: %s", packetAddr)
		if err := packetServer.Start(); err != nil {
			log.Fatalf("Packet server error: %v", err)
		}
	}()

	log.Println("==========================================================")
	if enableMITM {
		log.Println("  TLS Proxy Phase 3B RUNNING (MITM Enabled)")
	} else {
		log.Println("  TLS Proxy Phase 3A RUNNING (HTTP Only)")
	}
	log.Println("==========================================================")
	log.Println("Press Ctrl+C to stop")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\nShutting down...")
	dnsServer.Stop()
	packetServer.Stop()
	if dhcpMonitor != nil {
		dhcpMonitor.Close()
	}
	log.Println("Stopped")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}
	return def
}

func logConfig(dhcp, stepCA string, dnsPort, packetPort int, gw, policy, captive string, once, mitm bool) {
	log.Println("\nConfiguration:")
	log.Printf("  DHCP Monitor:     %s", dhcp)
	if mitm {
		log.Printf("  Step-CA:          %s", stepCA)
	}
	log.Printf("  DNS Port:         %d", dnsPort)
	log.Printf("  Packet Port:      %d", packetPort)
	log.Printf("  Gateway IP:       %s", gw)
	log.Printf("  Policy Mode:      %s", policy)
	log.Printf("  Captive URL:      %s", captive)
	log.Printf("  Show Once:        %v", once)
	log.Printf("  MITM Enabled:     %v", mitm)
	log.Println()
}
