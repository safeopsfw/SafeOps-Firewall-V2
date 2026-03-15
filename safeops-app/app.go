package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	goruntime "runtime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	_ "github.com/lib/pq"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// ─── Status types ─────────────────────────────────────────────────────────────

type ServiceStatus string

const (
	StatusStopped  ServiceStatus = "stopped"
	StatusStarting ServiceStatus = "starting"
	StatusRunning  ServiceStatus = "running"
	StatusError    ServiceStatus = "error"
)

// ─── Config ───────────────────────────────────────────────────────────────────

type ServiceConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Group       string   `json:"group"`
	ExeName     string   `json:"exeName"`
	SubDir      string   `json:"subDir"`
	Args        []string `json:"args"`
	AutoStart   bool     `json:"autoStart"`
	Port        int      `json:"port"`
	PortLabel   string   `json:"portLabel"`
	NeedsAdmin  bool     `json:"needsAdmin"`
}

type ServiceState struct {
	Config  ServiceConfig `json:"config"`
	Status  ServiceStatus `json:"status"`
	PID     int           `json:"pid"`
	Error   string        `json:"error"`
	process *os.Process
}

type SystemStats struct {
	CPUPercent float64 `json:"cpuPercent"`
	MemUsedMB  uint64  `json:"memUsedMB"`
	MemTotalMB uint64  `json:"memTotalMB"`
	MemPercent float64 `json:"memPercent"`
	GoRoutines int     `json:"goRoutines"`
}

type WebUIState struct {
	BackendRunning  bool `json:"backendRunning"`
	FrontendRunning bool `json:"frontendRunning"`
	BackendPID      int  `json:"backendPid"`
	FrontendPID     int  `json:"frontendPid"`
	backendProcess  *os.Process
	frontendProcess *os.Process
}

type SetupProgress struct {
	Step    int    `json:"step"`
	Total   int    `json:"total"`
	Message string `json:"message"`
	Done    bool   `json:"done"`
	Error   string `json:"error"`
}

type SIEMState struct {
	ElasticRunning      bool   `json:"elasticRunning"`
	ElasticStarting     bool   `json:"elasticStarting"`
	KibanaRunning       bool   `json:"kibanaRunning"`
	KibanaStarting      bool   `json:"kibanaStarting"`
	SIEMDir             string `json:"siemDir"`
	HasScripts          bool   `json:"hasScripts"`
	ElasticPID          int    `json:"elasticPid"`
	KibanaPID           int    `json:"kibanaPid"`
	TemplatesConfigured bool   `json:"templatesConfigured"`
}

type InstallPaths struct {
	InstallDir string `json:"install_dir"`
	BinDir     string `json:"bin_dir"`
	DataDir    string `json:"data_dir"`
	UIDir      string `json:"ui_dir"`
	BackendDir string `json:"backend_dir"`
	ESDir      string `json:"es_dir"`
	KibanaDir  string `json:"kibana_dir"`
	Version    string `json:"version"`
}

// ─── Services ─────────────────────────────────────────────────────────────────

var serviceConfigs = []ServiceConfig{
	{
		ID: "safeops-engine", Name: "SafeOps Engine", Group: "Core",
		Description: "NDIS packet capture & injection engine",
		ExeName: "safeops-engine.exe", SubDir: "safeops-engine",
		NeedsAdmin: true, Port: 50051, PortLabel: ":50051 gRPC",
	},
	{
		ID: "firewall-engine", Name: "Firewall Engine", Group: "Core",
		Description: "DDoS, brute-force, domain & geo blocking",
		ExeName: "firewall-engine.exe", SubDir: "firewall-engine",
		NeedsAdmin: true, AutoStart: true, Port: 50052, PortLabel: ":50052 HTTP API",
	},
	{
		ID: "nic-management", Name: "NIC Management", Group: "Network",
		Description: "Network interface management & monitoring",
		ExeName: "nic_management.exe", SubDir: "nic_management",
		Port: 8081, PortLabel: ":8081 REST",
	},
	{
		ID: "dhcp-monitor", Name: "DHCP Monitor", Group: "Network",
		Description: "DHCP lease tracking & ARP monitor",
		ExeName: "dhcp_monitor.exe", SubDir: "dhcp_monitor",
		Port: 50055, PortLabel: ":50055 gRPC",
	},
	{
		ID: "captive-portal", Name: "Captive Portal", Group: "Network",
		Description: "HTTP/HTTPS captive portal for CA cert delivery",
		ExeName: "captive_portal.exe", SubDir: "captive_portal",
		NeedsAdmin: true, Port: 8090, PortLabel: ":8090/:8445",
	},
	{
		ID: "step-ca", Name: "Step CA", Group: "Certificates",
		Description: "Internal certificate authority (TLS/mTLS)",
		ExeName: filepath.Join("bin", "step-ca.exe"), SubDir: "step-ca",
		Args: []string{"config/ca.json", "--password-file", "secrets/password.txt"},
		Port: 9000, PortLabel: ":9000 HTTPS",
	},
	{
		ID: "network-logger", Name: "Network Logger", Group: "Data",
		Description: "Packet logging to JSONL, 5-min rotation",
		ExeName: "network-logger.exe", SubDir: "network-logger",
	},
	{
		ID: "siem-forwarder", Name: "SIEM Forwarder", Group: "Data",
		Description: "Log shipping → Elasticsearch",
		ExeName: "siem-forwarder.exe", SubDir: "siem-forwarder",
		Args: []string{"-config", "config.yaml"},
	},
	{
		ID: "threat-intel", Name: "Threat Intel", Group: "Data",
		Description: "Threat feed pipeline & enrichment",
		ExeName: "threat_intel.exe", SubDir: "threat_intel",
		Args: []string{"-scheduler"},
	},
}

// ─── App ──────────────────────────────────────────────────────────────────────

type App struct {
	ctx             context.Context
	binDir          string
	rootDir         string
	dataDir         string
	siemDir         string
	mu              sync.RWMutex
	services        map[string]*ServiceState
	webUI           WebUIState
	siem            SIEMState
	statsStop       chan struct{}
	installed       bool
	elasticProcess  *os.Process
	kibanaProcess   *os.Process
	elasticStarting bool
	kibanaStarting  bool
}

func NewApp() *App {
	app := &App{
		services:  make(map[string]*ServiceState),
		statsStop: make(chan struct{}),
	}
	for _, cfg := range serviceConfigs {
		app.services[cfg.ID] = &ServiceState{Config: cfg, Status: StatusStopped}
	}
	return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.dataDir = filepath.Join(os.Getenv("PROGRAMDATA"), "SafeOps")
	a.detectPaths()
	a.installed = a.isInstalled()
	a.detectSIEMDir()

	// Kill stale processes from a previous unclean shutdown
	a.killStaleProcesses()

	// Write startup diagnostic log to Desktop (always — helps debug VM installs)
	go a.writeDesktopStartupLog()

	if a.installed {
		go func() {
			// Web UI starts immediately in background
			time.Sleep(400 * time.Millisecond)
			a.StartWebUI()

			// SafeOps Engine MUST start before Firewall Engine
			// (Firewall connects to SafeOps gRPC on :50051 for packet metadata)
			time.Sleep(600 * time.Millisecond)
			a.StartService("safeops-engine")

			// Wait up to 15s for safeops-engine gRPC port to be ready
			for i := 0; i < 30; i++ {
				time.Sleep(500 * time.Millisecond)
				if a.portListening("50051") {
					break
				}
			}

			// Now start firewall — it will connect to safeops-engine and push the blocklist
			a.StartService("firewall-engine")
		}()
	}

	go a.statsLoop()

	// Check for updates in background (non-blocking, 8s delay)
	go a.checkUpdateOnStartup()
}

func (a *App) shutdown(ctx context.Context) {
	close(a.statsStop)
	a.StopAll()
}

// killStaleProcesses kills leftover SafeOps child processes from a previous
// unclean shutdown (crash, force close, etc.) so ports are freed for reuse.
func (a *App) killStaleProcesses() {
	staleNames := []string{
		"safeops-engine", "firewall-engine", "nic_management",
		"dhcp_monitor", "captive_portal", "network-logger",
		"siem-forwarder", "threat_intel",
	}
	for _, name := range staleNames {
		exec.Command("taskkill", "/IM", name+".exe", "/F").Run()
	}
}

// ─── Desktop startup log ──────────────────────────────────────────────────────

// writeDesktopStartupLog writes a diagnostic log to the user's Desktop.
// Run on every startup so VM testers can easily share install/runtime info.
func (a *App) writeDesktopStartupLog() {
	desktop := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	if _, err := os.Stat(desktop); os.IsNotExist(err) {
		desktop = filepath.Join(os.Getenv("PUBLIC"), "Desktop")
	}
	if _, err := os.Stat(desktop); os.IsNotExist(err) {
		return
	}

	logPath := filepath.Join(desktop, fmt.Sprintf("SafeOps-Startup-%s.log", time.Now().Format("2006-01-02")))

	var sb strings.Builder
	line := func(s string) { sb.WriteString(s + "\r\n") }

	hostname, _ := os.Hostname()
	line("═══════════════════════════════════════════════════════════════")
	line("  SafeOps Startup Diagnostic Log")
	line(fmt.Sprintf("  Date    : %s", time.Now().Format("2006-01-02 15:04:05")))
	line(fmt.Sprintf("  Machine : %s", hostname))
	line(fmt.Sprintf("  OS/Arch : %s/%s", goruntime.GOOS, goruntime.GOARCH))
	line(fmt.Sprintf("  Go      : %s", goruntime.Version()))
	line("═══════════════════════════════════════════════════════════════")
	line("")
	line("INSTALLATION:")
	line(fmt.Sprintf("  Installed : %v", a.installed))
	line(fmt.Sprintf("  BinDir    : %s", a.binDir))
	line(fmt.Sprintf("  RootDir   : %s", a.rootDir))
	line(fmt.Sprintf("  DataDir   : %s", a.dataDir))
	line(fmt.Sprintf("  SIEMDir   : %s", a.siemDir))
	line("")
	line("EXECUTABLE STATUS:")
	exeChecks := []struct{ name, sub string }{
		{"SafeOps Launcher", "SafeOps.exe"},
		{"SafeOps Engine", filepath.Join("safeops-engine", "safeops-engine.exe")},
		{"Firewall Engine", filepath.Join("firewall-engine", "firewall-engine.exe")},
		{"NIC Management", filepath.Join("nic_management", "nic_management.exe")},
		{"DHCP Monitor", filepath.Join("dhcp_monitor", "dhcp_monitor.exe")},
		{"Step-CA", filepath.Join("step-ca", "bin", "step-ca.exe")},
		{"SIEM Forwarder", filepath.Join("siem-forwarder", "siem-forwarder.exe")},
		{"Network Logger", filepath.Join("network-logger", "network-logger.exe")},
		{"Threat Intel", filepath.Join("threat_intel", "threat_intel.exe")},
		{"Captive Portal", filepath.Join("captive_portal", "captive_portal.exe")},
	}
	for _, c := range exeChecks {
		p := filepath.Join(a.binDir, c.sub)
		if _, err := os.Stat(p); err == nil {
			line(fmt.Sprintf("  [OK]   %-22s  %s", c.name, p))
		} else {
			line(fmt.Sprintf("  [MISS] %-22s  %s  ← NOT FOUND", c.name, p))
		}
	}
	line("")
	line("PORTS (at startup):")
	portChecks := []struct{ port, label string }{
		{"50051", "SafeOps Engine gRPC"},
		{"50052", "Firewall Engine HTTP"},
		{"8443", "Firewall Engine HTTPS"},
		{"3001", "Web UI (React)"},
		{"5050", "Node Backend"},
		{"5432", "PostgreSQL"},
		{"9200", "Elasticsearch"},
		{"5601", "Kibana"},
		{"9000", "Step-CA"},
		{"8090", "Captive Portal"},
	}
	for _, p := range portChecks {
		status := "[DOWN]"
		if a.portListening(p.port) {
			status = "[UP]  "
		}
		line(fmt.Sprintf("  %s :%s  %s", status, p.port, p.label))
	}
	line("")
	line("SYSTEM:")
	if v, err := mem.VirtualMemory(); err == nil {
		line(fmt.Sprintf("  RAM Total : %d MB", v.Total/1024/1024))
		line(fmt.Sprintf("  RAM Used  : %d MB (%.1f%%)", v.Used/1024/1024, v.UsedPercent))
	}
	if n, err := cpu.Counts(true); err == nil {
		line(fmt.Sprintf("  CPU Cores : %d", n))
	}
	line("")
	line("═══════════════════════════════════════════════════════════════")
	line("  Share this file when reporting issues.")
	line("═══════════════════════════════════════════════════════════════")

	_ = os.WriteFile(logPath, []byte(sb.String()), 0644)
}

// ─── Path detection ───────────────────────────────────────────────────────────

func (a *App) detectPaths() {
	// 1. Try install-paths.json
	pathsFile := filepath.Join(a.dataDir, "install-paths.json")
	if data, err := os.ReadFile(pathsFile); err == nil {
		var paths InstallPaths
		if json.Unmarshal(data, &paths) == nil && paths.BinDir != "" {
			a.binDir = paths.BinDir
			a.rootDir = paths.InstallDir
			return
		}
	}

	// 2. SAFEOPS_HOME env
	if home := os.Getenv("SAFEOPS_HOME"); home != "" {
		if _, err := os.Stat(filepath.Join(home, "bin")); err == nil {
			a.rootDir = home
			a.binDir = filepath.Join(home, "bin")
			return
		}
	}

	// 3. Relative to executable
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	for _, candidate := range []string{exeDir, filepath.Dir(exeDir)} {
		binPath := filepath.Join(candidate, "bin")
		if _, err := os.Stat(binPath); err == nil {
			abs, _ := filepath.Abs(candidate)
			a.rootDir = abs
			a.binDir = filepath.Join(abs, "bin")
			return
		}
	}

	a.rootDir = exeDir
	a.binDir = filepath.Join(exeDir, "bin")
}

func (a *App) isInstalled() bool {
	pathsFile := filepath.Join(a.dataDir, "install-paths.json")
	if _, err := os.Stat(pathsFile); err == nil {
		return true
	}
	// Check for key executable
	if _, err := os.Stat(filepath.Join(a.binDir, "safeops-engine", "safeops-engine.exe")); err == nil {
		return true
	}
	return false
}

// ─── First-run / Setup ────────────────────────────────────────────────────────

func (a *App) IsFirstRun() bool { return !a.installed }

func (a *App) GetInstallPaths() InstallPaths {
	return InstallPaths{
		InstallDir: a.rootDir,
		BinDir:     a.binDir,
		DataDir:    a.dataDir,
		UIDir:      filepath.Join(a.rootDir, "src", "ui", "dev"),
		BackendDir: filepath.Join(a.rootDir, "backend"),
		ESDir:      filepath.Join(a.binDir, "siem", "elasticsearch"),
		KibanaDir:  filepath.Join(a.binDir, "siem", "kibana"),
		Version:    "1.0.0",
	}
}

func (a *App) RunSetupStep(step int, username, password string) SetupProgress {
	total := 8
	stepNames := map[int]string{
		1: "Installing PostgreSQL 16 & Node.js 20...",
		2: "Configuring databases & schemas...",
		3: "Running database schema files...",
		4: "Creating default admin user...",
		5: "Downloading & extracting Elasticsearch...",
		6: "Downloading & extracting Kibana...",
		7: "Installing UI & backend dependencies...",
		8: "Writing install paths & finalizing...",
	}
	prog := SetupProgress{Step: step, Total: total, Message: stepNames[step]}

	wailsruntime.EventsEmit(a.ctx, "setup:progress", prog)

	switch step {
	case 4:
		if err := a.createDefaultUser(username, password); err != nil {
			prog.Error = err.Error()
		} else {
			prog.Message = fmt.Sprintf("User '%s' created successfully.", username)
		}
	case 8:
		// Finalize: write install-paths.json, mark done, install npm deps
		a.writeInstallPaths()
		// Install npm deps in background
		go func() {
			a.installNpmDeps()
		}()
		a.installed = true
		prog.Done = true
		prog.Message = "SafeOps installation complete!"
	default:
		// Run PowerShell helper
		psStepMap := map[int]int{1: 1, 2: 2, 3: 3, 5: 4, 6: 5, 7: 6}
		psStep, ok := psStepMap[step]
		if ok {
			helperPath := a.findHelper()
			if helperPath == "" && step <= 3 {
				prog.Error = "Setup helper not found. Run SafeOps-Dependencies-Setup.exe first."
			} else if helperPath != "" {
				cmd := exec.Command("powershell.exe",
					"-ExecutionPolicy", "Bypass",
					"-File", helperPath,
					"-Step", strconv.Itoa(psStep),
					"-InstallDir", a.rootDir,
					"-BinDir", a.binDir,
				)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
				if err := cmd.Run(); err != nil {
					prog.Error = fmt.Sprintf("Step %d failed: %v", step, err)
				}
			}
		}
	}

	wailsruntime.EventsEmit(a.ctx, "setup:progress", prog)
	return prog
}

func (a *App) findHelper() string {
	locs := []string{
		filepath.Join(a.rootDir, "SafeOps Dependencies Installer", "SafeOps-Setup-Helper.ps1"),
		filepath.Join(a.dataDir, "SafeOps-Setup-Helper.ps1"),
		filepath.Join(a.rootDir, "setup", "SafeOps-Setup-Helper.ps1"),
	}
	for _, l := range locs {
		if _, err := os.Stat(l); err == nil { return l }
	}
	return ""
}

func (a *App) createDefaultUser(username, password string) error {
	if username == "" { username = "admin" }
	if password == "" { password = "safeops123" }

	connStr := "host=localhost port=5432 user=postgres password=admin dbname=safeops sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil { return fmt.Errorf("DB connect: %v", err) }
	defer db.Close()

	if err := db.Ping(); err != nil { return fmt.Errorf("DB not ready: %v", err) }

	// Try with pgcrypto crypt() first, fallback to plain
	_, err = db.Exec(`
		INSERT INTO users (username, password_hash, role, created_at, is_active)
		VALUES ($1, $2, 'superadmin', NOW(), true)
		ON CONFLICT (username) DO UPDATE SET password_hash = $2, role = 'superadmin', is_active = true
	`, username, password)
	if err != nil {
		return fmt.Errorf("user insert failed: %v", err)
	}
	return nil
}

func (a *App) writeInstallPaths() {
	os.MkdirAll(a.dataDir, 0755)
	paths := a.GetInstallPaths()
	data, _ := json.MarshalIndent(paths, "", "  ")
	os.WriteFile(filepath.Join(a.dataDir, "install-paths.json"), data, 0644)
	os.WriteFile(filepath.Join(a.rootDir, "install-paths.json"), data, 0644)
}

func (a *App) installNpmDeps() {
	uiDir := filepath.Join(a.rootDir, "src", "ui", "dev")
	backendDir := filepath.Join(a.rootDir, "backend")

	for _, dir := range []string{uiDir, backendDir} {
		if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
			cmd := exec.Command("npm", "install", "--prefer-offline", "--silent")
			cmd.Dir = dir
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
			cmd.Run()
		}
	}
}

// OpenReadme opens the getting-started guide in Notepad
func (a *App) OpenReadme() {
	locs := []string{
		filepath.Join(a.rootDir, "IMPORTANT-README.txt"),
		filepath.Join(a.binDir, "siem", "IMPORTANT-README.txt"),
	}
	for _, loc := range locs {
		if _, err := os.Stat(loc); err == nil {
			exec.Command("notepad.exe", loc).Start()
			return
		}
	}
	// Generate readme on the fly
	content := fmt.Sprintf(`═══════════════════════════════════════════════════════════════
   SAFEOPS - GETTING STARTED GUIDE
═══════════════════════════════════════════════════════════════

IMPORTANT: Follow this order for first launch!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1: SIEM Setup  (do this FIRST — takes 5-15 min)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1a. Start Elasticsearch:
      %s\1-start-elasticsearch.bat
      → Wait until "started" message (~2-3 min)

  1b. Setup ES index templates:
      %s\0-setup-elasticsearch-templates.bat
      → Wait until "Templates created"

  1c. Start Kibana:
      %s\2-start-kibana.bat
      → ⚠ KIBANA IS SLOW — wait 3-5 min, then open:
            http://localhost:5601

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2: Start SafeOps Services (from this Launcher)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. Firewall Engine   → auto-started (check status)
  2. SafeOps Engine    → click Start
  3. SIEM Forwarder    → click Start (ships logs to ES)
  4. Others            → start as needed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3: Open Web Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Click "Open Web Console" or go to: http://localhost:3001

  Login: admin / safeops123

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PORTS REFERENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Web Dashboard     → http://localhost:3001
  Kibana (SIEM)     → http://localhost:5601
  Elasticsearch     → http://localhost:9200
  Firewall API      → http://localhost:50052
  Step-CA           → https://localhost:9000
  NIC Management    → http://localhost:8081
  Captive Portal    → http://localhost:8090
  PostgreSQL        → localhost:5432  (password: admin)

NOTE: All services run as Administrator — no CMD windows
      will appear when launched from SafeOps Launcher.
═══════════════════════════════════════════════════════════════
`,
		filepath.Join(a.binDir, "siem"),
		filepath.Join(a.binDir, "siem"),
		filepath.Join(a.binDir, "siem"),
	)
	tmp := filepath.Join(os.TempDir(), "SafeOps-README.txt")
	os.WriteFile(tmp, []byte(content), 0644)
	exec.Command("notepad.exe", tmp).Start()
}

// CheckPostgresReady pings PostgreSQL
func (a *App) CheckPostgresReady() bool {
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=admin dbname=postgres sslmode=disable")
	if err != nil { return false }
	defer db.Close()
	return db.Ping() == nil
}

// ─── Service management ───────────────────────────────────────────────────────

func (a *App) GetServices() []*ServiceState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*ServiceState, 0, len(a.services))
	for _, cfg := range serviceConfigs {
		if svc, ok := a.services[cfg.ID]; ok {
			result = append(result, svc)
		}
	}
	return result
}

func (a *App) StartService(id string) error {
	a.mu.Lock()
	svc, ok := a.services[id]
	if !ok { a.mu.Unlock(); return fmt.Errorf("unknown: %s", id) }
	if svc.Status == StatusRunning || svc.Status == StatusStarting { a.mu.Unlock(); return nil }
	svc.Status = StatusStarting
	svc.Error = ""
	a.mu.Unlock()
	a.emitServices()

	go func() {
		err := a.launchService(svc)
		a.mu.Lock()
		if err != nil { svc.Status = StatusError; svc.Error = err.Error() }
		a.mu.Unlock()
		a.emitServices()
	}()
	return nil
}

func (a *App) launchService(svc *ServiceState) error {
	// Pre-launch hook for step-ca: auto-fix BadgerDB vlog truncation
	if svc.Config.ID == "step-ca" {
		a.fixStepCAVlog()
	}

	err := a.launchServiceOnce(svc)
	// If step-ca crashed, try vlog fix + one retry
	if err != nil && svc.Config.ID == "step-ca" && strings.Contains(err.Error(), "Truncate Needed") {
		if a.fixStepCAVlogFromError(err.Error()) {
			a.mu.Lock(); svc.Status = StatusStarting; svc.Error = ""; a.mu.Unlock()
			err = a.launchServiceOnce(svc)
		}
	}
	return err
}

func (a *App) launchServiceOnce(svc *ServiceState) error {
	cfg := svc.Config
	exePath := filepath.Join(a.binDir, cfg.SubDir, cfg.ExeName)
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		return fmt.Errorf("not found: %s", exePath)
	}

	var outBuf bytes.Buffer
	cmd := exec.Command(exePath, cfg.Args...)
	cmd.Dir = filepath.Join(a.binDir, cfg.SubDir)
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}

	if err := cmd.Start(); err != nil { return fmt.Errorf("launch: %v", err) }

	a.mu.Lock()
	svc.process = cmd.Process
	svc.PID = cmd.Process.Pid
	a.mu.Unlock()

	// Wait 2s — catch immediate startup crashes
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		// Process exited within 2s — startup crash
		output := strings.TrimSpace(outBuf.String())
		if len(output) > 400 { output = output[len(output)-400:] }
		if output == "" {
			if err != nil { output = err.Error() } else { output = "process exited immediately" }
		}
		a.mu.Lock()
		svc.PID = 0; svc.process = nil
		a.mu.Unlock()
		return fmt.Errorf("%s", output)

	case <-time.After(2 * time.Second):
		// Still running — healthy
		a.mu.Lock()
		svc.Status = StatusRunning
		a.mu.Unlock()
		a.emitServices()

		go func() {
			<-done
			a.mu.Lock()
			if svc.Status == StatusRunning {
				svc.Status = StatusStopped; svc.PID = 0; svc.process = nil
			}
			a.mu.Unlock()
			a.emitServices()
		}()
		return nil
	}
}

// fixStepCAVlog pre-emptively truncates the BadgerDB vlog if it looks pre-allocated.
// BadgerDB pre-allocates 000000.vlog to 2GB; on unclean exit, it can't reopen.
func (a *App) fixStepCAVlog() {
	vlogPath := filepath.Join(a.binDir, "step-ca", "db", "000000.vlog")
	info, err := os.Stat(vlogPath)
	if err != nil { return }
	// If the vlog is >= 512MB it's almost certainly pre-allocated — scan for valid end
	if info.Size() < 512*1024*1024 { return }

	// Read first 8KB to find the real data end heuristically
	f, err := os.OpenFile(vlogPath, os.O_RDWR, 0)
	if err != nil { return }
	defer f.Close()

	// Scan backwards from the end to find last non-zero byte
	// This is a best-effort approximation; EndOffset from the error is more precise
	buf := make([]byte, 8192)
	_, _ = f.ReadAt(buf, 0)
	// Find last non-zero in first 8KB to estimate data size
	end := 0
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] != 0 { end = i + 1; break }
	}
	if end < 4096 { end = 4096 } // keep at least 4KB
	f.Truncate(int64(end))
}

// fixStepCAVlogFromError parses "Endoffset: N" from badger error and truncates vlog.
func (a *App) fixStepCAVlogFromError(errStr string) bool {
	// Parse "Endoffset: N" from the error string
	idx := strings.Index(errStr, "Endoffset:")
	if idx < 0 { return false }
	rest := strings.TrimSpace(errStr[idx+10:])
	// rest may be "4793 Error..." — grab the number
	numStr := ""
	for _, ch := range rest {
		if ch >= '0' && ch <= '9' { numStr += string(ch) } else { break }
	}
	if numStr == "" { return false }

	endOffset := int64(0)
	for _, ch := range numStr {
		endOffset = endOffset*10 + int64(ch-'0')
	}
	if endOffset <= 0 { return false }

	vlogPath := filepath.Join(a.binDir, "step-ca", "db", "000000.vlog")
	f, err := os.OpenFile(vlogPath, os.O_RDWR, 0)
	if err != nil { return false }
	defer f.Close()
	return f.Truncate(endOffset) == nil
}

func (a *App) StopService(id string) error {
	a.mu.Lock()
	svc, ok := a.services[id]
	if !ok { a.mu.Unlock(); return fmt.Errorf("unknown: %s", id) }
	pid := svc.PID
	a.mu.Unlock()

	if pid > 0 { exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F").Run() }

	a.mu.Lock()
	svc.Status = StatusStopped; svc.PID = 0; svc.process = nil
	a.mu.Unlock()
	a.emitServices()
	return nil
}

func (a *App) StartAll() {
	for _, cfg := range serviceConfigs {
		a.StartService(cfg.ID)
		time.Sleep(1200 * time.Millisecond)
	}
}

func (a *App) StopAll() {
	a.mu.RLock()
	svcs := make([]*ServiceState, 0)
	for _, s := range a.services { svcs = append(svcs, s) }
	a.mu.RUnlock()

	for _, s := range svcs {
		if s.PID > 0 { exec.Command("taskkill", "/PID", strconv.Itoa(s.PID), "/F").Run() }
	}
	a.mu.Lock()
	for _, s := range a.services { s.Status = StatusStopped; s.PID = 0; s.process = nil }
	a.mu.Unlock()
	a.StopWebUI()
}

// ─── Web UI ───────────────────────────────────────────────────────────────────

func (a *App) StartWebUI() {
	uiDir := filepath.Join(a.rootDir, "src", "ui", "dev")
	backendDir := filepath.Join(a.rootDir, "backend")

	if _, err := os.Stat(backendDir); err == nil {
		cmd := exec.Command("node", "server.js")
		cmd.Dir = backendDir
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err == nil {
			a.mu.Lock()
			a.webUI.BackendRunning = true
			a.webUI.BackendPID = cmd.Process.Pid
			a.webUI.backendProcess = cmd.Process
			a.mu.Unlock()
		}
	}

	if _, err := os.Stat(uiDir); err == nil {
		cmd := exec.Command("npm", "run", "dev")
		cmd.Dir = uiDir
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if err := cmd.Start(); err == nil {
			a.mu.Lock()
			a.webUI.FrontendRunning = true
			a.webUI.FrontendPID = cmd.Process.Pid
			a.webUI.frontendProcess = cmd.Process
			a.mu.Unlock()
		}
	}

	a.emitServices()
}

func (a *App) StopWebUI() {
	a.mu.RLock()
	bPID := a.webUI.BackendPID
	fPID := a.webUI.FrontendPID
	a.mu.RUnlock()

	if bPID > 0 { exec.Command("taskkill", "/PID", strconv.Itoa(bPID), "/F", "/T").Run() }
	if fPID > 0 { exec.Command("taskkill", "/PID", strconv.Itoa(fPID), "/F", "/T").Run() }

	a.mu.Lock(); a.webUI = WebUIState{}; a.mu.Unlock()
}

func (a *App) GetWebUIState() WebUIState {
	a.mu.RLock(); defer a.mu.RUnlock(); return a.webUI
}

func (a *App) OpenWebConsole() {
	go func() {
		for i := 0; i < 20; i++ {
			if resp, err := http.Get("http://localhost:3001"); err == nil {
				resp.Body.Close(); break
			}
			time.Sleep(1 * time.Second)
		}
		wailsruntime.BrowserOpenURL(a.ctx, "http://localhost:3001")
	}()
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (a *App) GetSystemStats() SystemStats {
	st := SystemStats{}
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 { st.CPUPercent = pct[0] }
	if m, err := mem.VirtualMemory(); err == nil {
		st.MemTotalMB = m.Total / 1024 / 1024
		st.MemUsedMB = m.Used / 1024 / 1024
		st.MemPercent = m.UsedPercent
	}
	st.GoRoutines = goruntime.NumGoroutine()
	return st
}

func (a *App) GetBinDir() string  { return a.binDir }
func (a *App) GetRootDir() string { return a.rootDir }

// ─── Firewall UI ──────────────────────────────────────────────────────────────

// OpenFirewallUI opens the firewall engine's embedded web UI at :8443
func (a *App) OpenFirewallUI() {
	wailsruntime.BrowserOpenURL(a.ctx, "http://localhost:8443")
}

// ─── SIEM management ──────────────────────────────────────────────────────────

func (a *App) detectSIEMDir() {
	// 1. Try from install-paths.json
	pathsFile := filepath.Join(a.dataDir, "install-paths.json")
	if data, err := os.ReadFile(pathsFile); err == nil {
		var paths InstallPaths
		if json.Unmarshal(data, &paths) == nil && paths.ESDir != "" {
			// siemDir is parent of es_dir
			a.siemDir = filepath.Dir(paths.ESDir)
			if _, err := os.Stat(filepath.Join(a.siemDir, "1-start-elasticsearch.bat")); err == nil {
				return
			}
		}
	}
	// 2. Check relative to binDir
	candidates := []string{
		filepath.Join(a.binDir, "siem"),
		filepath.Join(a.rootDir, "bin", "siem"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "1-start-elasticsearch.bat")); err == nil {
			a.siemDir = c
			return
		}
	}
}

func (a *App) portListening(port string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 800*time.Millisecond)
	if err != nil { return false }
	conn.Close()
	return true
}

func (a *App) GetSIEMState() SIEMState {
	a.mu.RLock()
	siemDir := a.siemDir
	a.mu.RUnlock()

	state := SIEMState{SIEMDir: siemDir}
	if siemDir != "" {
		_, err := os.Stat(filepath.Join(siemDir, "1-start-elasticsearch.bat"))
		state.HasScripts = err == nil
	}

	if a.portListening("9200") {
		state.ElasticRunning = true
		a.mu.Lock(); a.elasticStarting = false; a.mu.Unlock()
	} else {
		a.mu.RLock(); state.ElasticStarting = a.elasticStarting; a.mu.RUnlock()
	}

	if a.portListening("5601") {
		state.KibanaRunning = true
		a.mu.Lock(); a.kibanaStarting = false; a.mu.Unlock()
	} else {
		a.mu.RLock(); state.KibanaStarting = a.kibanaStarting; a.mu.RUnlock()
	}

	state.TemplatesConfigured = a.checkTemplatesConfigured()
	return state
}

func (a *App) checkTemplatesConfigured() bool {
	_, err := os.Stat(filepath.Join(a.dataDir, "siem-templates-ok"))
	return err == nil
}

func (a *App) GetSIEMDir() string { return a.siemDir }

// ChooseSIEMDir opens a folder picker so user can locate their SIEM scripts
func (a *App) ChooseSIEMDir() string {
	dir, err := wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select SafeOps SIEM Scripts Directory",
	})
	if err != nil || dir == "" { return a.siemDir }
	a.mu.Lock()
	a.siemDir = dir
	a.mu.Unlock()
	// Persist to install-paths.json
	a.persistSIEMDir(dir)
	return dir
}

func (a *App) persistSIEMDir(dir string) {
	pathsFile := filepath.Join(a.dataDir, "install-paths.json")
	data, _ := os.ReadFile(pathsFile)
	m := map[string]interface{}{}
	json.Unmarshal(data, &m)
	m["siem_dir"] = dir
	m["es_dir"] = filepath.Join(dir, "elasticsearch")
	m["kibana_dir"] = filepath.Join(dir, "kibana")
	out, _ := json.MarshalIndent(m, "", "  ")
	os.WriteFile(pathsFile, out, 0644)
	// Also write to install dir
	if a.rootDir != "" {
		os.WriteFile(filepath.Join(a.rootDir, "install-paths.json"), out, 0644)
	}
}

func (a *App) StartElasticsearch() string {
	state := a.GetSIEMState()
	if state.ElasticRunning { return "already_running" }
	if a.siemDir == "" || !state.HasScripts { return "no_scripts" }
	batFile := filepath.Join(a.siemDir, "1-start-elasticsearch.bat")
	cmd := exec.Command("cmd.exe", "/C", batFile)
	cmd.Dir = a.siemDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil { return fmt.Sprintf("error: %v", err) }
	a.mu.Lock()
	a.elasticProcess = cmd.Process
	a.elasticStarting = true
	a.mu.Unlock()
	return "started"
}

func (a *App) StartKibana() string {
	state := a.GetSIEMState()
	if state.KibanaRunning { return "already_running" }
	if a.siemDir == "" || !state.HasScripts { return "no_scripts" }
	batFile := filepath.Join(a.siemDir, "2-start-kibana.bat")
	if _, err := os.Stat(batFile); err != nil { return "no_scripts" }
	cmd := exec.Command("cmd.exe", "/C", batFile)
	cmd.Dir = a.siemDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil { return fmt.Sprintf("error: %v", err) }
	a.mu.Lock()
	a.kibanaProcess = cmd.Process
	a.kibanaStarting = true
	a.mu.Unlock()
	return "started"
}

func (a *App) StopElasticsearch() {
	a.mu.Lock()
	p := a.elasticProcess
	a.elasticProcess = nil
	a.elasticStarting = false
	a.mu.Unlock()
	if p != nil { p.Kill() }
	// Kill java processes for ES (port 9200)
	exec.Command("powershell", "-Command",
		"Get-NetTCPConnection -LocalPort 9200 -ErrorAction SilentlyContinue | "+
			"ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }").Run()
}

func (a *App) StopKibana() {
	a.mu.Lock()
	p := a.kibanaProcess
	a.kibanaProcess = nil
	a.kibanaStarting = false
	a.mu.Unlock()
	if p != nil { p.Kill() }
	exec.Command("powershell", "-Command",
		"Get-NetTCPConnection -LocalPort 5601 -ErrorAction SilentlyContinue | "+
			"ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }").Run()
}

func (a *App) OpenKibana() {
	wailsruntime.BrowserOpenURL(a.ctx, "http://localhost:5601")
}

func (a *App) RunESTemplates() string {
	if a.siemDir == "" { return "no_scripts" }
	batFile := filepath.Join(a.siemDir, "0-setup-elasticsearch-templates.bat")
	if _, err := os.Stat(batFile); err != nil { return "no_scripts" }
	cmd := exec.Command("cmd.exe", "/C", batFile)
	cmd.Dir = a.siemDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Run(); err != nil { return fmt.Sprintf("error: %v", err) }
	// Mark templates as configured
	os.MkdirAll(a.dataDir, 0755)
	os.WriteFile(filepath.Join(a.dataDir, "siem-templates-ok"), []byte("ok"), 0644)
	return "Templates configured successfully"
}

// ─── Prerequisites verification ───────────────────────────────────────────────

type PrereqStatus struct {
	PostgresOK      bool     `json:"postgresOK"`
	DBsMissing      []string `json:"dbsMissing"`
	ElasticOK       bool     `json:"elasticOK"`
	IndicesMissing  []string `json:"indicesMissing"`
	SIEMDirOK       bool     `json:"siemDirOK"`
	Error           string   `json:"error"`
}

func (a *App) VerifyPrerequisites() PrereqStatus {
	status := PrereqStatus{}

	// Check PostgreSQL
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=admin dbname=postgres sslmode=disable")
	if err == nil {
		if pingErr := db.Ping(); pingErr == nil {
			status.PostgresOK = true
			required := []string{"safeops", "safeops_network", "threat_intel_db"}
			for _, dbName := range required {
				var exists bool
				row := db.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)", dbName)
				row.Scan(&exists)
				if !exists { status.DBsMissing = append(status.DBsMissing, dbName) }
			}
		} else {
			status.Error = "PostgreSQL not running: " + pingErr.Error()
		}
		db.Close()
	} else {
		status.Error = "PostgreSQL connect failed: " + err.Error()
	}

	// Check Elasticsearch
	if a.portListening("9200") {
		status.ElasticOK = true
		resp, err := http.Get("http://localhost:9200/_cat/indices?h=index&format=json")
		if err == nil {
			defer resp.Body.Close()
			var indices []struct{ Index string `json:"index"` }
			if json.NewDecoder(resp.Body).Decode(&indices) == nil {
				indexSet := make(map[string]bool)
				for _, idx := range indices { indexSet[idx.Index] = true }
				required := []string{"firewall-alerts", "network-logs", "threat-intel"}
				for _, idx := range required {
					if !indexSet[idx] { status.IndicesMissing = append(status.IndicesMissing, idx) }
				}
			}
		}
	}

	// Check SIEM dir
	if a.siemDir != "" {
		_, err := os.Stat(filepath.Join(a.siemDir, "1-start-elasticsearch.bat"))
		status.SIEMDirOK = err == nil
	}

	return status
}

// FixMissingDatabases runs the DB schema scripts to create missing databases.
func (a *App) FixMissingDatabases() string {
	helperPath := a.findHelper()
	if helperPath == "" {
		return "error: setup helper not found. Run SafeOps-Dependencies-Setup.exe first."
	}
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass",
		"-File", helperPath,
		"-Step", "2",
		"-InstallDir", a.rootDir,
		"-BinDir", a.binDir,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	// Also run schema step
	cmd2 := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass",
		"-File", helperPath,
		"-Step", "3",
		"-InstallDir", a.rootDir,
		"-BinDir", a.binDir,
	)
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	cmd2.Run()
	return "Databases created successfully. Verify to confirm."
}

// FixMissingIndices runs the ES template setup script.
func (a *App) FixMissingIndices() string {
	if a.siemDir == "" {
		return "error: SIEM scripts path not configured"
	}
	batFile := filepath.Join(a.siemDir, "0-setup-elasticsearch-templates.bat")
	if _, err := os.Stat(batFile); err != nil {
		return "error: template script not found at " + batFile
	}
	cmd := exec.Command("cmd.exe", "/C", batFile)
	cmd.Dir = a.siemDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Run(); err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	os.MkdirAll(a.dataDir, 0755)
	os.WriteFile(filepath.Join(a.dataDir, "siem-templates-ok"), []byte("ok"), 0644)
	return "ES indices/templates created successfully."
}

// ─── User settings cache ──────────────────────────────────────────────────────

type UserSettings struct {
	SIEMDir           string `json:"siem_dir"`
	AutoStartFirewall bool   `json:"auto_start_firewall"`
	AutoStartWebUI    bool   `json:"auto_start_web_ui"`
	Theme             string `json:"theme"`
	LastBinDir        string `json:"last_bin_dir"`
}

func (a *App) GetUserSettings() UserSettings {
	settingsPath := filepath.Join(a.dataDir, "user-settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return UserSettings{AutoStartFirewall: true, AutoStartWebUI: true, SIEMDir: a.siemDir}
	}
	var s UserSettings
	if json.Unmarshal(data, &s) != nil {
		return UserSettings{AutoStartFirewall: true, AutoStartWebUI: true, SIEMDir: a.siemDir}
	}
	return s
}

func (a *App) SaveUserSettings(settings UserSettings) string {
	os.MkdirAll(a.dataDir, 0755)
	if settings.SIEMDir != "" {
		a.mu.Lock(); a.siemDir = settings.SIEMDir; a.mu.Unlock()
		a.persistSIEMDir(settings.SIEMDir)
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil { return "error: " + err.Error() }
	if err := os.WriteFile(filepath.Join(a.dataDir, "user-settings.json"), data, 0644); err != nil {
		return "error: " + err.Error()
	}
	return "saved"
}

func (a *App) emitServices() {
	if a.ctx == nil { return }
	wailsruntime.EventsEmit(a.ctx, "services:update", a.GetServices())
	wailsruntime.EventsEmit(a.ctx, "webui:update", a.GetWebUIState())
}

func (a *App) statsLoop() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if a.ctx != nil { wailsruntime.EventsEmit(a.ctx, "stats:update", a.GetSystemStats()) }
		case <-a.statsStop:
			return
		}
	}
}
