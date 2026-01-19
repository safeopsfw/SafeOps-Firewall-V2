package spawner

import (
	"context"
	"fmt"
	"os/exec"

	"safeops-engine/internal/config"
	"safeops-engine/internal/logger"
)

// Spawner manages external processes
type Spawner struct {
	log       *logger.Logger
	processes map[string]*exec.Cmd
}

// New creates a new spawner
func New(log *logger.Logger) *Spawner {
	return &Spawner{
		log:       log,
		processes: make(map[string]*exec.Cmd),
	}
}

// SpawnDNSProxy spawns the dnsproxy process
func (s *Spawner) SpawnDNSProxy(ctx context.Context, cfg config.DNSProxyConfig) error {
	if !cfg.Enabled {
		s.log.Info("dnsproxy disabled in config", nil)
		return nil
	}

	// Try primary port first, then fallbacks
	port := cfg.ListenPort
	allPorts := append([]int{port}, cfg.FallbackPorts...)

	var cmd *exec.Cmd
	var lastErr error

	for _, tryPort := range allPorts {
		// Use CLI args instead of config file (more reliable)
		// IMPORTANT: Use only plain DNS (no DoH) to avoid bootstrap issues
		args := []string{
			"-l", "127.0.0.1",
			"-p", fmt.Sprintf("%d", tryPort),
			"-u", "8.8.8.8",      // Google Public DNS
			"-u", "1.1.1.1",      // Cloudflare DNS
			"-u", "208.67.222.222", // OpenDNS
			"--cache",
			"--cache-size", "10000",
			"-v", // Verbose logging for debugging
		}

		cmd = exec.CommandContext(ctx, cfg.BinaryPath, args...)

		s.log.Info("Attempting to start dnsproxy", map[string]interface{}{
			"binary": cfg.BinaryPath,
			"port":   tryPort,
		})

		if err := cmd.Start(); err != nil {
			s.log.Warn("Failed to start on port, trying next", map[string]interface{}{
				"port":  tryPort,
				"error": err.Error(),
			})
			lastErr = err
			continue
		}

		// Success!
		s.log.Info("dnsproxy started successfully", map[string]interface{}{
			"port": tryPort,
		})
		s.processes["dnsproxy"] = cmd

		// Monitor process
		go s.monitorProcess(ctx, "dnsproxy", cmd)

		return nil
	}

	// All ports failed
	return fmt.Errorf("failed to start dnsproxy on any port (tried %v): %w", allPorts, lastErr)
}

// SpawnMITM spawns the mitmproxy process
func (s *Spawner) SpawnMITM(ctx context.Context, cfg config.MITMConfig) error {
	if !cfg.Enabled {
		s.log.Info("mitmproxy disabled in config", nil)
		return nil
	}

	// Use transparent proxy mode - intercepts via Windows routing
	args := []string{
		"--mode", "transparent",
		"--showhost",
		"--ssl-insecure",
		"--set", "block_global=false",
	}

	// Add addon if configured (for passive logger later)
	if cfg.AddonPath != "" {
		args = append(args, "-s", cfg.AddonPath)
	}

	cmd := exec.CommandContext(ctx, cfg.BinaryPath, args...)

	s.log.Info("Starting mitmproxy", map[string]interface{}{
		"binary": cfg.BinaryPath,
		"mode":   "regular",
		"port":   cfg.ListenPort,
	})

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start mitmproxy: %w", err)
	}

	s.processes["mitmproxy"] = cmd

	// Monitor process
	go s.monitorProcess(ctx, "mitmproxy", cmd)

	return nil
}

// monitorProcess monitors a child process and logs if it exits
func (s *Spawner) monitorProcess(ctx context.Context, name string, cmd *exec.Cmd) {
	err := cmd.Wait()

	select {
	case <-ctx.Done():
		s.log.Info("Process stopped (context cancelled)", map[string]interface{}{
			"process": name,
		})
	default:
		if err != nil {
			s.log.Error("Process exited with error", map[string]interface{}{
				"process": name,
				"error":   err.Error(),
			})
		} else {
			s.log.Warn("Process exited unexpectedly", map[string]interface{}{
				"process": name,
			})
		}
	}
}

// StopAll stops all spawned processes
func (s *Spawner) StopAll() {
	for name, cmd := range s.processes {
		s.log.Info("Stopping process", map[string]interface{}{"process": name})
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}
}
