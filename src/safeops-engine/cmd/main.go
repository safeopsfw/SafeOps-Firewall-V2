package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"safeops-engine/internal/api"
	"safeops-engine/internal/classifier"
	"safeops-engine/internal/config"
	"safeops-engine/internal/dns"
	"safeops-engine/internal/driver"
	"safeops-engine/internal/logger"
	"safeops-engine/internal/proxy"
	"safeops-engine/internal/spawner"
)

func main() {
	fmt.Println("=== SafeOps Network Pipeline ===")
	fmt.Println("Version: 2.0.0 (Go-based proxy)")
	fmt.Println("Starting...")

	// Load configuration
	cfg, err := config.Load("configs/engine.yaml")
	if err != nil {
		cfg, err = config.Load("src/safeops-engine/configs/engine.yaml")
		if err != nil {
			fmt.Printf("Failed to load config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Loaded config from: src/safeops-engine/configs/engine.yaml")
	}

	// Initialize logger
	log := logger.New(cfg.Logging)
	log.Info("SafeOps Engine starting", map[string]interface{}{
		"version": "2.0.0",
		"mode":    "go-proxy",
	})

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize process spawner (for dnsproxy only now)
	spawnerMgr := spawner.New(log)

	// Spawn dnsproxy (port 15353)
	log.Info("Spawning dnsproxy...", nil)
	if err := spawnerMgr.SpawnDNSProxy(ctx, cfg.DNSProxy); err != nil {
		log.Warn("dnsproxy failed", map[string]interface{}{"error": err.Error()})
	}
	time.Sleep(1 * time.Second)

	// Start Go-based inline proxy (replaces mitmproxy)
	inlineProxy := proxy.New(cfg.MITM.ListenPort)
	go func() {
		log.Info("Starting Go-based inline proxy", map[string]interface{}{"port": cfg.MITM.ListenPort})
		if err := inlineProxy.Start(); err != nil {
			log.Error("Inline proxy failed", map[string]interface{}{"error": err.Error()})
		}
	}()
	time.Sleep(1 * time.Second)

	// Configure Windows system proxy to use our proxy
	if err := proxy.ConfigureSystemProxy(cfg.MITM.ListenPort); err != nil {
		log.Warn("Failed to configure system proxy", map[string]interface{}{"error": err.Error()})
	} else {
		log.Info("System proxy configured", map[string]interface{}{"proxy": fmt.Sprintf("127.0.0.1:%d", cfg.MITM.ListenPort)})
	}
	// Cleanup proxy on exit
	defer proxy.DisableSystemProxy()

	// Start API server
	log.Info("Starting API server", map[string]interface{}{"port": cfg.API.Port})
	apiServer := api.NewServer(cfg.API, log)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Error("API server failed", map[string]interface{}{"error": err.Error()})
		}
	}()

	// Initialize WinpkFilter driver
	log.Info("Initializing WinpkFilter driver...", nil)
	drv, err := driver.Open(log)
	if err != nil {
		log.Error("Failed to open WinpkFilter driver", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	defer drv.Close()

	// List adapters
	adapters, _ := drv.GetAdapters()
	log.Info("Found adapters", map[string]interface{}{"count": len(adapters)})

	// Set tunnel mode on all physical adapters
	if err := drv.SetTunnelModeAll(); err != nil {
		log.Error("Failed to set tunnel mode", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	// Initialize classifier
	cls := classifier.New()
	log.Info("Classifier initialized", nil)

	// Initialize DNS redirector
	dnsRedirector := dns.NewRedirector()
	log.Info("DNS redirector initialized", map[string]interface{}{"target": "127.0.0.1:15353"})

	log.Info("Pipeline ready - Go proxy handles HTTP/HTTPS inline", nil)

	// Packet counter
	var packetCount uint64

	// Packet handler: DNS redirect only, HTTP/HTTPS pass-through (goproxy via routing)
	drv.SetHandler(func(pkt *driver.ParsedPacket) bool {
		atomic.AddUint64(&packetCount, 1)

		action := cls.Classify(pkt)
		rawData := pkt.RawBuffer.Buffer[:pkt.RawBuffer.Length]

		// DNS: redirect at packet level
		if action == classifier.ActionRedirectDNS && pkt.Protocol == driver.ProtoUDP {
			if pkt.Direction == driver.DirectionOutbound {
				dnsRedirector.RedirectDNS(rawData, pkt.SrcPort, pkt.DstPort, pkt.DstIP)
			} else {
				dnsRedirector.HandleResponse(rawData, pkt.SrcPort, pkt.DstPort)
			}
		}

		// HTTP/HTTPS: pass through - goproxy handles via Windows routing

		return true // Always forward
	})

	// Start packet processing
	log.Info("Starting packet processing...", nil)
	go drv.ProcessPacketsAll(ctx)

	// Stats logging every 30 seconds (less frequent)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				bypass, dnsCount, httpCount, drop := cls.GetStats()
				dnsRedir, _ := dnsRedirector.GetStats()
				proxyReqs, proxyBlocked := inlineProxy.GetStats()
				read, written, dropped := drv.GetStats()

				log.Info("Stats", map[string]interface{}{
					"packets": read, "written": written, "dropped": dropped,
					"dns": dnsCount, "http": httpCount, "bypass": bypass, "drop": drop,
					"dns_redir":  dnsRedir,
					"proxy_reqs": proxyReqs, "proxy_blocked": proxyBlocked,
				})
			}
		}
	}()

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down...", nil)
	cancel()
	time.Sleep(2 * time.Second)

	// Final stats
	bypass, dnsCount, httpCount, drop := cls.GetStats()
	dnsRedir, _ := dnsRedirector.GetStats()
	proxyReqs, proxyBlocked := inlineProxy.GetStats()
	log.Info("Final stats", map[string]interface{}{
		"total":  atomic.LoadUint64(&packetCount),
		"bypass": bypass, "dns": dnsCount, "http": httpCount, "drop": drop,
		"dns_redir":  dnsRedir,
		"proxy_reqs": proxyReqs, "proxy_blocked": proxyBlocked,
	})

	log.Info("SafeOps Engine stopped", nil)
}
