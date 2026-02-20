//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// ============================================================================
// Windows Service Integration
// ============================================================================

const serviceName = "SafeOpsFirewall"
const serviceDisplayName = "SafeOps Firewall Engine"
const serviceDescription = "SafeOps Firewall Engine — packet inspection and threat detection"

// windowsService implements the svc.Handler interface.
// It receives Windows service control signals and maps them to our shutdown path.
type windowsService struct {
	stopFn func() // called when service receives STOP/SHUTDOWN signal
}

// Execute is the entry point called by the Windows SCM.
func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for cr := range r {
		switch cr.Cmd {
		case svc.Interrogate:
			status <- cr.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			if s.stopFn != nil {
				s.stopFn()
			}
			return
		default:
			// Ignore other commands
		}
	}
	return
}

// isWindowsService returns true if the process is running as a Windows service.
// It checks using svc.IsWindowsService() (available in golang.org/x/sys).
func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

// runAsService runs the firewall engine as a Windows service.
// stopFn is called when the SCM sends a stop signal.
func runAsService(stopFn func()) error {
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		// Fallback: run via debug log when event log is unavailable (e.g. not installed yet)
		return debug.Run(serviceName, &windowsService{stopFn: stopFn})
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("%s starting", serviceDisplayName))
	if err := svc.Run(serviceName, &windowsService{stopFn: stopFn}); err != nil {
		elog.Error(1, fmt.Sprintf("%s failed: %v", serviceDisplayName, err))
		return err
	}
	elog.Info(1, fmt.Sprintf("%s stopped", serviceDisplayName))
	return nil
}

// ============================================================================
// Service Management Commands — called via CLI flags
// ============================================================================

// installService registers the firewall engine as a Windows service.
func installService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Register event log source
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	fmt.Printf("Service %q installed successfully.\n", serviceName)
	fmt.Println("Start with: sc start SafeOpsFirewall")
	return nil
}

// removeService stops and deletes the Windows service.
func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", serviceName, err)
	}
	defer s.Close()

	// Stop if running
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		_, err = s.Control(svc.Stop)
		if err != nil {
			return fmt.Errorf("could not stop service: %w", err)
		}
		// Wait up to 10s for service to stop
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	_ = eventlog.Remove(serviceName)
	fmt.Printf("Service %q removed successfully.\n", serviceName)
	return nil
}

// handleServiceCLI processes Windows service CLI flags (-install, -remove, -service).
// Returns true if a service command was handled (caller should exit).
func handleServiceCLI(args []string, stopFn func()) (handled bool) {
	for _, arg := range args {
		switch arg {
		case "-install", "--install":
			exePath, _ := os.Executable()
			if err := installService(exePath); err != nil {
				fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
				os.Exit(1)
			}
			return true

		case "-remove", "--remove":
			if err := removeService(); err != nil {
				fmt.Fprintf(os.Stderr, "Remove failed: %v\n", err)
				os.Exit(1)
			}
			return true

		case "-service", "--service":
			if err := runAsService(stopFn); err != nil {
				fmt.Fprintf(os.Stderr, "Service run failed: %v\n", err)
				os.Exit(1)
			}
			return true
		}
	}
	return false
}
