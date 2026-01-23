# PHASE 12: PRODUCTION HARDENING & DEPLOYMENT

**Status:** 🔜 Future Phase (After Phase 11 Complete)
**Duration:** 2-3 weeks
**Goal:** Deploy to production safely with graceful shutdown, error recovery, and Windows service
**Deliverable:** Production-ready Windows service with auto-start, monitoring, and recovery

---

## 📋 Phase Overview

**What Changes in Phase 12:**
- **Phase 11 Reality:** Firewall works perfectly in development/testing, but not production-hardened
- **Phase 12 Goal:** Production-ready deployment with graceful shutdown, error recovery, resource limits, and Windows service
- **Focus Areas:** Reliability, maintainability, monitoring, deployment automation

**Current State (Development):**
```
Development Deployment:
├─ Start: ./firewall-engine (command line)
├─ Stop: Ctrl+C (immediate termination, no cleanup)
├─ Crashes: Process dies, no restart
├─ Updates: Stop service, replace binary, start service (manual)
├─ Monitoring: Logs only (no health checks)
└─ Issues: Data loss, connection drops, manual intervention
```

**Target State (Production):**
```
Production Deployment:
├─ Start: Windows Service (auto-start on boot)
├─ Stop: Graceful shutdown (flush logs, close connections)
├─ Crashes: Auto-restart (3 attempts, exponential backoff)
├─ Updates: In-place binary update (zero downtime)
├─ Monitoring: Health checks, metrics, alerting
└─ Result: 99.9% uptime, no data loss, automated recovery
```

**Dependencies:**
- ✅ Phase 1-11: All firewall functionality complete
- ✅ External: PostgreSQL database running as Windows service
- ✅ External: SafeOps Engine running as Windows service
- ✅ External: Step CA server (optional, for Phase 9)

---

## 🎯 Phase 12 Outcomes (What You Should See)

### After Compilation & Execution:

**Initial Startup (Windows Service):**
```
[INFO] Firewall Engine v12.0.0 Starting...
[INFO] Running as Windows Service: SafeOps-Firewall
[INFO] Service Control Manager: CONNECTED
[INFO] Graceful Shutdown: ENABLED (SIGTERM/SIGINT handler)
[INFO] Error Recovery: ENABLED (auto-reconnect, fallback)
[INFO] Resource Limits: ENABLED
[INFO] ├─ Max Memory: 2GB (soft limit: 1.5GB)
[INFO] ├─ Max Goroutines: 10,000
[INFO] ├─ Max Open Files: 10,000
[INFO] ├─ Max DB Connections: 100
[INFO] └─ Panic Recovery: ENABLED (3 restart attempts)
[INFO] Health Check: ENABLED (HTTP :8080/health)
[INFO] Dependencies:
[INFO] ├─ PostgreSQL: ✅ RUNNING (127.0.0.1:5432)
[INFO] ├─ SafeOps Engine: ✅ RUNNING (127.0.0.1:50053)
[INFO] └─ Step CA: ✅ RUNNING (ca.internal.com:9000)
[INFO] Auto-Start: ENABLED (boot order: DB → SafeOps → Firewall)
[INFO] Firewall Ready (Production Mode)
```

**Graceful Shutdown (SIGTERM received):**
```
[INFO] Shutdown signal received (SIGTERM)
[INFO] Initiating graceful shutdown...
[INFO] ├─ [1/6] Stopping packet processing (no new packets)
[INFO] │  └─ Packet queue: 247 packets remaining
[INFO] ├─ [2/6] Waiting for in-flight packets (timeout: 30s)
[INFO] │  └─ Processing remaining packets... (247 → 156 → 78 → 12 → 0)
[INFO] │  └─ All packets processed (elapsed: 3.2s)
[INFO] ├─ [3/6] Flushing logs to disk
[INFO] │  └─ Log buffer: 1,543 entries → flushed to firewall.log
[INFO] │  └─ Database buffer: 487 entries → bulk insert complete
[INFO] ├─ [4/6] Closing gRPC connections
[INFO] │  └─ SafeOps Engine: Connection closed gracefully
[INFO] ├─ [5/6] Saving state to disk
[INFO] │  └─ Connection table: 4,521 entries → saved to state.db
[INFO] │  └─ Rule cache: 150 rules → saved to rules.cache
[INFO] └─ [6/6] Releasing resources
[INFO]    ├─ Memory pools: Released (300MB freed)
[INFO]    ├─ Database: Connections closed (pool drained)
[INFO]    └─ File handles: All closed (0 leaks)
[INFO] Graceful shutdown complete (total time: 5.8s)
[INFO] Firewall stopped cleanly ✅
```

**Error Recovery (SafeOps Engine crashed):**
```
[ERROR] gRPC connection lost: rpc error: connection refused
[WARN] SafeOps Engine unavailable, initiating recovery...
[INFO] Recovery Strategy: Auto-reconnect with exponential backoff
[INFO] Attempt 1/10: Reconnecting to SafeOps Engine...
[ERROR] Connection failed: dial tcp 127.0.0.1:50053: connection refused
[INFO] Backoff: 1s (exponential backoff)
[INFO] Attempt 2/10: Reconnecting to SafeOps Engine...
[ERROR] Connection failed: dial tcp 127.0.0.1:50053: connection refused
[INFO] Backoff: 2s (exponential backoff)
[INFO] Attempt 3/10: Reconnecting to SafeOps Engine...
[SUCCESS] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Resuming packet processing...
[INFO] Recovery complete (elapsed: 5.3s, packets dropped: 0)
```

**Fallback Mode (SafeOps Engine permanently unavailable):**
```
[ERROR] SafeOps Engine unavailable after 10 reconnect attempts (3 minutes)
[WARN] Activating fallback mode: Direct WFP control
[INFO] Fallback Strategy: Apply cached rules directly to WFP
[INFO] ├─ Loading cached rules from state.db
[INFO] ├─ Applying 150 rules to WFP filters
[INFO] └─ Firewall operational (limited functionality, no gRPC)
[INFO] Monitoring SafeOps Engine for recovery...
[SUCCESS] SafeOps Engine recovered (127.0.0.1:50053)
[INFO] Exiting fallback mode, resuming normal operation
```

**Resource Limit Triggered:**
```
[WARN] Memory usage: 1.52GB (soft limit: 1.5GB, hard limit: 2GB)
[INFO] Triggering garbage collection (forced GC)
[INFO] Memory after GC: 987MB (recovered 533MB)
[INFO] Memory usage: ✅ Normal

[WARN] Goroutines: 9,847 (limit: 10,000)
[INFO] Goroutine leak detected, investigating...
[INFO] ├─ Stuck goroutines: 3,241 (waiting on closed channel)
[INFO] └─ Terminating stuck goroutines...
[INFO] Goroutines: 6,606 (leak resolved)
```

**Windows Service Control:**
```powershell
# Install service
PS> .\firewall-engine.exe --install-service
[INFO] Installing Windows Service: SafeOps-Firewall
[INFO] ├─ Service Name: SafeOps-Firewall
[INFO] ├─ Display Name: SafeOps Firewall Engine
[INFO] ├─ Description: SafeOps next-generation firewall engine
[INFO] ├─ Startup Type: Automatic (Delayed Start)
[INFO] ├─ Dependencies: PostgreSQL, SafeOps-Engine
[INFO] ├─ Recovery: Restart on failure (3 attempts)
[INFO] └─ Account: LocalSystem (restricted)
[SUCCESS] Service installed successfully ✅

# Start service
PS> Start-Service SafeOps-Firewall
[INFO] Starting SafeOps-Firewall service...
[INFO] Service started successfully

# Stop service (graceful shutdown)
PS> Stop-Service SafeOps-Firewall
[INFO] Stopping SafeOps-Firewall service...
[INFO] Graceful shutdown initiated (timeout: 30s)
[INFO] Service stopped successfully

# Check status
PS> Get-Service SafeOps-Firewall

Status   Name               DisplayName
------   ----               -----------
Running  SafeOps-Firewall   SafeOps Firewall Engine

# View service details
PS> sc.exe qc SafeOps-Firewall
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SafeOps-Firewall
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\SafeOps\firewall-engine.exe" --service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : SafeOps Firewall Engine
        DEPENDENCIES       : PostgreSQL
                           : SafeOps-Engine
        SERVICE_START_NAME : LocalSystem
```

**Health Check Endpoint:**
```bash
# Health check (HTTP endpoint)
$ curl http://localhost:8080/health
{
  "status": "healthy",
  "version": "12.0.0",
  "uptime": "2h 15m 43s",
  "components": {
    "packet_processing": "healthy",
    "safeops_engine": "healthy",
    "database": "healthy",
    "memory": "healthy",
    "disk": "healthy"
  },
  "metrics": {
    "packets_per_second": 102847,
    "latency_ms": 0.62,
    "memory_mb": 347,
    "goroutines": 6432,
    "connections": 4521
  },
  "last_check": "2026-01-22T15:30:45Z"
}

# Health check (unhealthy)
$ curl http://localhost:8080/health
{
  "status": "unhealthy",
  "version": "12.0.0",
  "uptime": "3h 42m 12s",
  "components": {
    "packet_processing": "healthy",
    "safeops_engine": "unhealthy",  # ⚠️ Issue detected
    "database": "healthy",
    "memory": "degraded",           # ⚠️ High memory
    "disk": "healthy"
  },
  "errors": [
    "SafeOps Engine connection lost (retrying...)",
    "Memory usage 1.8GB (90% of limit)"
  ],
  "metrics": {
    "packets_per_second": 0,        # Processing stopped
    "latency_ms": null,
    "memory_mb": 1843,
    "goroutines": 9241,
    "connections": 0
  },
  "last_check": "2026-01-22T16:45:23Z"
}
```

---

## 🔧 Sub-Task Breakdown

### **1. Graceful Shutdown** (`internal/lifecycle/shutdown.go`)

**Purpose:**
- Prevent data loss (flush logs, save state)
- Close connections gracefully (no abrupt termination)
- Wait for in-flight packets to complete
- Signal-aware shutdown (SIGTERM, SIGINT, Windows service stop)

**Implementation:**
```go
// internal/lifecycle/shutdown.go

package lifecycle

import (
    "context"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"
)

// ShutdownManager - Manages graceful shutdown
type ShutdownManager struct {
    config         ShutdownConfig
    shutdownFuncs  []ShutdownFunc  // Ordered shutdown functions
    shutdownChan   chan os.Signal
    shutdownMutex  sync.Mutex
    isShuttingDown bool
}

// ShutdownConfig - Configuration for graceful shutdown
type ShutdownConfig struct {
    GracePeriod      time.Duration  // Max time to wait (default: 30s)
    FlushLogs        bool           // Flush logs before exit
    SaveState        bool           // Save state to disk
    WaitForPackets   bool           // Wait for in-flight packets
    ForceKillTimeout time.Duration  // Force kill after timeout (default: 60s)
}

// ShutdownFunc - Function called during shutdown
type ShutdownFunc func(ctx context.Context) error

func NewShutdownManager(config ShutdownConfig) *ShutdownManager {
    return &ShutdownManager{
        config:        config,
        shutdownFuncs: make([]ShutdownFunc, 0),
        shutdownChan:  make(chan os.Signal, 1),
    }
}

// RegisterShutdownFunc - Register function to call on shutdown
func (sm *ShutdownManager) RegisterShutdownFunc(name string, fn ShutdownFunc) {
    sm.shutdownFuncs = append(sm.shutdownFuncs, fn)
    log.Debugf("Registered shutdown function: %s", name)
}

// SetupSignalHandlers - Setup OS signal handlers
func (sm *ShutdownManager) SetupSignalHandlers() {
    signal.Notify(sm.shutdownChan,
        os.Interrupt,           // SIGINT (Ctrl+C)
        syscall.SIGTERM,        // SIGTERM (systemd, docker)
        syscall.SIGHUP,         // SIGHUP (reload config)
    )

    go sm.waitForShutdownSignal()
}

// waitForShutdownSignal - Wait for shutdown signal
func (sm *ShutdownManager) waitForShutdownSignal() {
    sig := <-sm.shutdownChan
    log.Infof("Shutdown signal received: %v", sig)

    if sig == syscall.SIGHUP {
        // SIGHUP: Reload configuration (don't shutdown)
        log.Info("Reloading configuration...")
        sm.reloadConfig()
        return
    }

    // SIGTERM/SIGINT: Graceful shutdown
    sm.GracefulShutdown()
}

// GracefulShutdown - Perform graceful shutdown
func (sm *ShutdownManager) GracefulShutdown() {
    sm.shutdownMutex.Lock()
    if sm.isShuttingDown {
        log.Warn("Shutdown already in progress, ignoring duplicate signal")
        sm.shutdownMutex.Unlock()
        return
    }
    sm.isShuttingDown = true
    sm.shutdownMutex.Unlock()

    log.Info("Initiating graceful shutdown...")

    // Create shutdown context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), sm.config.GracePeriod)
    defer cancel()

    // Execute shutdown functions in order
    for i, fn := range sm.shutdownFuncs {
        log.Infof("├─ [%d/%d] Executing shutdown function...",
            i+1, len(sm.shutdownFuncs))

        if err := fn(ctx); err != nil {
            log.Errorf("│  └─ Shutdown function %d failed: %v", i+1, err)
        } else {
            log.Infof("│  └─ Shutdown function %d complete", i+1)
        }

        // Check timeout
        if ctx.Err() != nil {
            log.Errorf("Shutdown timeout exceeded (%v), forcing shutdown",
                sm.config.GracePeriod)
            break
        }
    }

    log.Info("Graceful shutdown complete ✅")
    os.Exit(0)
}

// ForceShutdown - Force immediate shutdown (no cleanup)
func (sm *ShutdownManager) ForceShutdown() {
    log.Warn("Force shutdown initiated (no cleanup)")
    os.Exit(1)
}

// Example: Register shutdown functions
func setupShutdown(fw *Firewall) *ShutdownManager {
    config := ShutdownConfig{
        GracePeriod:      30 * time.Second,
        FlushLogs:        true,
        SaveState:        true,
        WaitForPackets:   true,
        ForceKillTimeout: 60 * time.Second,
    }

    sm := NewShutdownManager(config)

    // Step 1: Stop packet processing
    sm.RegisterShutdownFunc("stop_packet_processing", func(ctx context.Context) error {
        log.Info("Stopping packet processing (no new packets)")
        fw.StopProcessing()
        return nil
    })

    // Step 2: Wait for in-flight packets
    sm.RegisterShutdownFunc("wait_for_packets", func(ctx context.Context) error {
        log.Info("Waiting for in-flight packets (timeout: 30s)")
        return fw.WaitForPackets(ctx)
    })

    // Step 3: Flush logs
    sm.RegisterShutdownFunc("flush_logs", func(ctx context.Context) error {
        log.Info("Flushing logs to disk")
        return fw.FlushLogs(ctx)
    })

    // Step 4: Close gRPC connections
    sm.RegisterShutdownFunc("close_grpc", func(ctx context.Context) error {
        log.Info("Closing gRPC connections")
        return fw.CloseGRPCConnection(ctx)
    })

    // Step 5: Save state
    sm.RegisterShutdownFunc("save_state", func(ctx context.Context) error {
        log.Info("Saving state to disk")
        return fw.SaveState(ctx)
    })

    // Step 6: Release resources
    sm.RegisterShutdownFunc("release_resources", func(ctx context.Context) error {
        log.Info("Releasing resources")
        return fw.ReleaseResources(ctx)
    })

    // Setup signal handlers
    sm.SetupSignalHandlers()

    return sm
}
```

**Shutdown Implementation in Firewall:**
```go
// cmd/main.go

package main

import (
    "github.com/safeops/firewall/internal/lifecycle"
)

func main() {
    // Initialize firewall
    fw := initializeFirewall()

    // Setup graceful shutdown
    shutdownManager := lifecycle.NewShutdownManager(lifecycle.ShutdownConfig{
        GracePeriod:      30 * time.Second,
        FlushLogs:        true,
        SaveState:        true,
        WaitForPackets:   true,
        ForceKillTimeout: 60 * time.Second,
    })

    // Register shutdown steps
    shutdownManager.RegisterShutdownFunc("stop_processing", fw.StopProcessing)
    shutdownManager.RegisterShutdownFunc("wait_packets", fw.WaitForPackets)
    shutdownManager.RegisterShutdownFunc("flush_logs", fw.FlushLogs)
    shutdownManager.RegisterShutdownFunc("close_grpc", fw.CloseGRPCConnection)
    shutdownManager.RegisterShutdownFunc("save_state", fw.SaveState)
    shutdownManager.RegisterShutdownFunc("release_resources", fw.ReleaseResources)

    // Setup signal handlers
    shutdownManager.SetupSignalHandlers()

    // Start firewall (blocks until shutdown)
    fw.Start()
}

// StopProcessing - Stop accepting new packets
func (fw *Firewall) StopProcessing() error {
    fw.isShuttingDown = true
    close(fw.packetChan)  // Close packet channel (no new packets)
    log.Info("Packet processing stopped")
    return nil
}

// WaitForPackets - Wait for in-flight packets to complete
func (fw *Firewall) WaitForPackets(ctx context.Context) error {
    remaining := atomic.LoadInt64(&fw.inFlightPackets)
    log.Infof("Waiting for %d in-flight packets...", remaining)

    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            remaining = atomic.LoadInt64(&fw.inFlightPackets)
            if remaining == 0 {
                log.Info("All packets processed")
                return nil
            }
            log.Debugf("In-flight packets: %d", remaining)

        case <-ctx.Done():
            remaining = atomic.LoadInt64(&fw.inFlightPackets)
            log.Warnf("Timeout waiting for packets (%d remaining)", remaining)
            return ctx.Err()
        }
    }
}

// FlushLogs - Flush log buffers to disk
func (fw *Firewall) FlushLogs(ctx context.Context) error {
    // Flush application logs
    log.Sync()

    // Flush packet logs
    if fw.packetLogger != nil {
        if err := fw.packetLogger.Flush(); err != nil {
            return fmt.Errorf("failed to flush packet logs: %w", err)
        }
    }

    // Flush database log buffer
    if fw.dbLogger != nil {
        if err := fw.dbLogger.FlushBuffer(); err != nil {
            return fmt.Errorf("failed to flush database logs: %w", err)
        }
    }

    log.Info("Logs flushed successfully")
    return nil
}

// CloseGRPCConnection - Close gRPC connection gracefully
func (fw *Firewall) CloseGRPCConnection(ctx context.Context) error {
    if fw.grpcConn != nil {
        return fw.grpcConn.Close()
    }
    return nil
}

// SaveState - Save connection table and cache to disk
func (fw *Firewall) SaveState(ctx context.Context) error {
    // Save connection table
    if err := fw.connTracker.SaveToFile("state.db"); err != nil {
        return fmt.Errorf("failed to save connection table: %w", err)
    }

    // Save rule cache
    if err := fw.ruleManager.SaveCache("rules.cache"); err != nil {
        return fmt.Errorf("failed to save rule cache: %w", err)
    }

    log.Info("State saved to disk")
    return nil
}

// ReleaseResources - Release memory pools, close files
func (fw *Firewall) ReleaseResources(ctx context.Context) error {
    // Release memory pools
    if fw.memoryPool != nil {
        fw.memoryPool.Drain()
    }

    // Close database connections
    if fw.db != nil {
        fw.db.Close()
    }

    // Close file handles
    // ...

    log.Info("Resources released")
    return nil
}
```

---

### **2. Error Recovery** (`internal/recovery/error_recovery.go`)

**Purpose:**
- Automatic reconnection to SafeOps Engine (exponential backoff)
- Fallback to direct WFP control if SafeOps unavailable
- Database error recovery (retry queries)
- Panic recovery (restart process, max 3 attempts)

**Implementation:**
```go
// internal/recovery/error_recovery.go

package recovery

import (
    "context"
    "fmt"
    "time"
)

// RecoveryConfig - Configuration for error recovery
type RecoveryConfig struct {
    // gRPC reconnection
    MaxReconnectAttempts  int           // Max reconnect attempts (default: 10)
    InitialBackoff        time.Duration // Initial backoff (default: 1s)
    MaxBackoff            time.Duration // Max backoff (default: 60s)
    BackoffMultiplier     float64       // Backoff multiplier (default: 2.0)

    // Fallback mode
    EnableFallback        bool          // Enable fallback to WFP (default: true)
    FallbackTimeout       time.Duration // Time before fallback (default: 3min)

    // Database retry
    MaxDBRetries          int           // Max DB retry attempts (default: 3)
    DBRetryDelay          time.Duration // Delay between retries (default: 1s)

    // Panic recovery
    MaxPanicRestarts      int           // Max panic restarts (default: 3)
    PanicRestartDelay     time.Duration // Delay before restart (default: 5s)
}

// ErrorRecoveryManager - Manages error recovery
type ErrorRecoveryManager struct {
    config        RecoveryConfig
    panicCount    int
    lastPanicTime time.Time
    inFallback    bool
}

func NewErrorRecoveryManager(config RecoveryConfig) *ErrorRecoveryManager {
    return &ErrorRecoveryManager{
        config: config,
    }
}

// RecoverFromGRPCDisconnect - Reconnect to SafeOps Engine
func (erm *ErrorRecoveryManager) RecoverFromGRPCDisconnect(
    ctx context.Context,
    reconnectFn func() error,
) error {
    log.Warn("SafeOps Engine unavailable, initiating recovery...")
    log.Info("Recovery Strategy: Auto-reconnect with exponential backoff")

    backoff := erm.config.InitialBackoff
    attempt := 1

    for attempt <= erm.config.MaxReconnectAttempts {
        log.Infof("Attempt %d/%d: Reconnecting to SafeOps Engine...",
            attempt, erm.config.MaxReconnectAttempts)

        if err := reconnectFn(); err != nil {
            log.Errorf("Connection failed: %v", err)

            // Exponential backoff
            log.Infof("Backoff: %v (exponential backoff)", backoff)
            time.Sleep(backoff)

            backoff = time.Duration(float64(backoff) * erm.config.BackoffMultiplier)
            if backoff > erm.config.MaxBackoff {
                backoff = erm.config.MaxBackoff
            }

            attempt++
            continue
        }

        // Reconnection successful
        log.Success("Connected to SafeOps Engine")
        return nil
    }

    // Max attempts exceeded
    log.Errorf("SafeOps Engine unavailable after %d attempts", erm.config.MaxReconnectAttempts)

    // Activate fallback mode if enabled
    if erm.config.EnableFallback {
        return erm.ActivateFallbackMode()
    }

    return fmt.Errorf("failed to reconnect to SafeOps Engine")
}

// ActivateFallbackMode - Fallback to direct WFP control
func (erm *ErrorRecoveryManager) ActivateFallbackMode() error {
    log.Warn("Activating fallback mode: Direct WFP control")
    log.Info("Fallback Strategy: Apply cached rules directly to WFP")

    erm.inFallback = true

    // Load cached rules from disk
    rules, err := loadCachedRules("rules.cache")
    if err != nil {
        return fmt.Errorf("failed to load cached rules: %w", err)
    }

    log.Infof("├─ Loading cached rules from state.db")
    log.Infof("├─ Applying %d rules to WFP filters", len(rules))

    // Apply rules directly to WFP (bypass SafeOps Engine)
    if err := applyRulesToWFP(rules); err != nil {
        return fmt.Errorf("failed to apply rules to WFP: %w", err)
    }

    log.Info("└─ Firewall operational (limited functionality, no gRPC)")
    log.Info("Monitoring SafeOps Engine for recovery...")

    // Start background recovery monitoring
    go erm.monitorForRecovery()

    return nil
}

// monitorForRecovery - Monitor SafeOps Engine for recovery
func (erm *ErrorRecoveryManager) monitorForRecovery() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        if !erm.inFallback {
            return  // Already recovered
        }

        // Try to reconnect
        if err := reconnectToSafeOps(); err == nil {
            log.Success("SafeOps Engine recovered")
            log.Info("Exiting fallback mode, resuming normal operation")
            erm.inFallback = false
            return
        }
    }
}

// RecoverFromDatabaseError - Retry database queries
func (erm *ErrorRecoveryManager) RecoverFromDatabaseError(
    operation func() error,
) error {
    for attempt := 1; attempt <= erm.config.MaxDBRetries; attempt++ {
        if err := operation(); err != nil {
            log.Warnf("Database operation failed (attempt %d/%d): %v",
                attempt, erm.config.MaxDBRetries, err)

            if attempt < erm.config.MaxDBRetries {
                time.Sleep(erm.config.DBRetryDelay)
                continue
            }

            // Max retries exceeded
            return fmt.Errorf("database operation failed after %d attempts: %w",
                erm.config.MaxDBRetries, err)
        }

        // Success
        if attempt > 1 {
            log.Infof("Database operation succeeded on attempt %d", attempt)
        }
        return nil
    }

    return fmt.Errorf("unreachable")
}

// RecoverFromPanic - Recover from panic and restart
func (erm *ErrorRecoveryManager) RecoverFromPanic() {
    if r := recover(); r != nil {
        erm.panicCount++

        log.Errorf("PANIC RECOVERED: %v", r)
        log.Errorf("Stack trace:\n%s", debug.Stack())

        // Check restart limit
        if erm.panicCount > erm.config.MaxPanicRestarts {
            log.Fatalf("Too many panics (%d), giving up", erm.panicCount)
        }

        // Reset panic count if last panic was >1 hour ago
        if time.Since(erm.lastPanicTime) > 1*time.Hour {
            erm.panicCount = 1
        }

        erm.lastPanicTime = time.Now()

        log.Warnf("Restarting process (attempt %d/%d)",
            erm.panicCount, erm.config.MaxPanicRestarts)

        time.Sleep(erm.config.PanicRestartDelay)

        // Restart process (exec.Command or os.Exit + supervisor restart)
        restartProcess()
    }
}

// SetupPanicRecovery - Setup panic recovery for goroutines
func (erm *ErrorRecoveryManager) SetupPanicRecovery(fn func()) {
    defer erm.RecoverFromPanic()
    fn()
}

// Example: Use panic recovery
func worker() {
    recovery := NewErrorRecoveryManager(RecoveryConfig{
        MaxPanicRestarts: 3,
        PanicRestartDelay: 5 * time.Second,
    })

    // Wrap worker function with panic recovery
    recovery.SetupPanicRecovery(func() {
        // Worker logic here...
        for {
            processPacket()
        }
    })
}
```

---

### **3. Resource Limits** (`internal/resources/limits.go`)

**Purpose:**
- Prevent OOM (out-of-memory) crashes
- Limit goroutines (prevent goroutine leaks)
- Limit open files (prevent file descriptor exhaustion)
- Limit database connections (prevent connection pool exhaustion)

**Implementation:**
```go
// internal/resources/limits.go

package resources

import (
    "fmt"
    "runtime"
    "runtime/debug"
    "sync/atomic"
)

// ResourceLimits - Resource usage limits
type ResourceLimits struct {
    MaxMemoryMB          int64  // Max memory (MB, default: 2048)
    SoftMemoryMB         int64  // Soft memory limit (MB, default: 1536)
    MaxGoroutines        int64  // Max goroutines (default: 10000)
    MaxOpenFiles         int64  // Max open files (default: 10000)
    MaxDBConnections     int    // Max DB connections (default: 100)
    EnableMemoryMonitor  bool   // Monitor memory usage
    EnableGoroutineCheck bool   // Monitor goroutine count
}

// ResourceMonitor - Monitors resource usage
type ResourceMonitor struct {
    limits           ResourceLimits
    currentGoroutines int64
    currentOpenFiles int64
    memoryWarnings   int64
    goroutineWarnings int64
}

func NewResourceMonitor(limits ResourceLimits) *ResourceMonitor {
    return &ResourceMonitor{
        limits: limits,
    }
}

// Start - Start resource monitoring
func (rm *ResourceMonitor) Start(ctx context.Context) {
    if rm.limits.EnableMemoryMonitor {
        go rm.monitorMemory(ctx)
    }

    if rm.limits.EnableGoroutineCheck {
        go rm.monitorGoroutines(ctx)
    }
}

// monitorMemory - Monitor memory usage
func (rm *ResourceMonitor) monitorMemory(ctx context.Context) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            var memStats runtime.MemStats
            runtime.ReadMemStats(&memStats)

            memoryMB := int64(memStats.HeapAlloc / 1024 / 1024)

            // Soft limit exceeded
            if memoryMB > rm.limits.SoftMemoryMB {
                atomic.AddInt64(&rm.memoryWarnings, 1)
                log.Warnf("Memory usage: %dMB (soft limit: %dMB, hard limit: %dMB)",
                    memoryMB, rm.limits.SoftMemoryMB, rm.limits.MaxMemoryMB)

                // Force garbage collection
                log.Info("Triggering garbage collection (forced GC)")
                runtime.GC()

                // Re-check memory after GC
                runtime.ReadMemStats(&memStats)
                memoryAfterGC := int64(memStats.HeapAlloc / 1024 / 1024)
                log.Infof("Memory after GC: %dMB (recovered %dMB)",
                    memoryAfterGC, memoryMB-memoryAfterGC)

                // Hard limit exceeded (even after GC)
                if memoryAfterGC > rm.limits.MaxMemoryMB {
                    log.Fatalf("CRITICAL: Memory limit exceeded: %dMB (limit: %dMB)",
                        memoryAfterGC, rm.limits.MaxMemoryMB)
                }
            }

        case <-ctx.Done():
            return
        }
    }
}

// monitorGoroutines - Monitor goroutine count
func (rm *ResourceMonitor) monitorGoroutines(ctx context.Context) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            numGoroutines := int64(runtime.NumGoroutine())

            if numGoroutines > rm.limits.MaxGoroutines {
                atomic.AddInt64(&rm.goroutineWarnings, 1)
                log.Warnf("Goroutines: %d (limit: %d)",
                    numGoroutines, rm.limits.MaxGoroutines)

                // Goroutine leak detected
                log.Warn("Goroutine leak suspected, investigating...")
                rm.dumpGoroutineStacks()

                // Try to identify stuck goroutines
                rm.identifyLeakedGoroutines()
            }

        case <-ctx.Done():
            return
        }
    }
}

// dumpGoroutineStacks - Dump goroutine stacks (debug)
func (rm *ResourceMonitor) dumpGoroutineStacks() {
    buf := make([]byte, 1<<20)  // 1MB buffer
    stackSize := runtime.Stack(buf, true)

    log.Debugf("Goroutine stacks:\n%s", buf[:stackSize])

    // Save to file
    os.WriteFile("goroutine_stacks.txt", buf[:stackSize], 0644)
    log.Info("Goroutine stacks saved to goroutine_stacks.txt")
}

// identifyLeakedGoroutines - Identify stuck goroutines
func (rm *ResourceMonitor) identifyLeakedGoroutines() {
    // Parse goroutine stacks, identify common patterns:
    // - Goroutines waiting on closed channels
    // - Goroutines blocked on mutex
    // - Goroutines in infinite loops
    //
    // Example detection:
    stacks := string(debug.Stack())
    stuckCount := strings.Count(stacks, "chan receive")

    if stuckCount > 1000 {
        log.Warnf("├─ Stuck goroutines: %d (waiting on closed channel)", stuckCount)
        log.Warn("└─ Terminating stuck goroutines... (restart required)")
    }
}

// SetMemoryLimit - Set GOMEMLIMIT (Go 1.19+)
func (rm *ResourceMonitor) SetMemoryLimit() {
    // Go 1.19+ supports GOMEMLIMIT environment variable
    memLimitBytes := rm.limits.MaxMemoryMB * 1024 * 1024
    debug.SetMemoryLimit(memLimitBytes)
    log.Infof("Memory limit set: %dMB", rm.limits.MaxMemoryMB)
}

// GetResourceStats - Get current resource usage
func (rm *ResourceMonitor) GetResourceStats() ResourceStats {
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)

    return ResourceStats{
        MemoryMB:         int64(memStats.HeapAlloc / 1024 / 1024),
        MemoryLimitMB:    rm.limits.MaxMemoryMB,
        Goroutines:       int64(runtime.NumGoroutine()),
        GoroutineLimit:   rm.limits.MaxGoroutines,
        MemoryWarnings:   atomic.LoadInt64(&rm.memoryWarnings),
        GoroutineWarnings: atomic.LoadInt64(&rm.goroutineWarnings),
    }
}

// ResourceStats - Current resource usage
type ResourceStats struct {
    MemoryMB          int64
    MemoryLimitMB     int64
    Goroutines        int64
    GoroutineLimit    int64
    MemoryWarnings    int64
    GoroutineWarnings int64
}
```

---

### **4. Windows Service Installation** (`internal/service/windows_service.go`)

**Purpose:**
- Install as Windows service (auto-start on boot)
- Service dependencies (PostgreSQL, SafeOps Engine must start first)
- Service recovery options (restart on failure)
- Service control (start, stop, restart, status)

**Implementation:**
```go
// internal/service/windows_service.go
// +build windows

package service

import (
    "fmt"
    "golang.org/x/sys/windows/svc"
    "golang.org/x/sys/windows/svc/mgr"
    "time"
)

// WindowsService - Windows service wrapper
type WindowsService struct {
    name        string
    displayName string
    description string
    firewall    *Firewall
}

func NewWindowsService(name, displayName, description string, fw *Firewall) *WindowsService {
    return &WindowsService{
        name:        name,
        displayName: displayName,
        description: description,
        firewall:    fw,
    }
}

// Execute - Service control handler (Windows SCM callback)
func (ws *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
    const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

    // Service started
    changes <- svc.Status{State: svc.StartPending}
    log.Info("Windows service starting...")

    // Start firewall
    go ws.firewall.Start()

    changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
    log.Info("Windows service running")

    // Wait for control commands
    for {
        select {
        case c := <-r:
            switch c.Cmd {
            case svc.Interrogate:
                changes <- c.CurrentStatus

            case svc.Stop, svc.Shutdown:
                // Graceful shutdown
                log.Info("Windows service stopping...")
                changes <- svc.Status{State: svc.StopPending}

                ws.firewall.GracefulShutdown()

                changes <- svc.Status{State: svc.Stopped}
                return false, 0

            default:
                log.Errorf("Unexpected control request: %v", c)
            }
        }
    }
}

// InstallService - Install Windows service
func InstallService(name, displayName, description string, dependencies []string) error {
    exePath, err := os.Executable()
    if err != nil {
        return fmt.Errorf("failed to get executable path: %w", err)
    }

    // Connect to Windows Service Control Manager
    m, err := mgr.Connect()
    if err != nil {
        return fmt.Errorf("failed to connect to SCM: %w", err)
    }
    defer m.Disconnect()

    // Check if service already exists
    s, err := m.OpenService(name)
    if err == nil {
        s.Close()
        return fmt.Errorf("service %s already exists", name)
    }

    // Create service
    s, err = m.CreateService(name, exePath,
        mgr.Config{
            DisplayName:      displayName,
            Description:      description,
            StartType:        mgr.StartAutomatic,
            DelayedAutoStart: true,  // Delayed auto-start (after boot)
            Dependencies:     dependencies,
        },
        "--service",  // Args passed to service
    )
    if err != nil {
        return fmt.Errorf("failed to create service: %w", err)
    }
    defer s.Close()

    // Configure service recovery (restart on failure)
    err = s.SetRecoveryActions([]mgr.RecoveryAction{
        {Type: mgr.ServiceRestart, Delay: 10 * time.Second},   // 1st failure: restart after 10s
        {Type: mgr.ServiceRestart, Delay: 30 * time.Second},   // 2nd failure: restart after 30s
        {Type: mgr.ServiceRestart, Delay: 60 * time.Second},   // 3rd failure: restart after 60s
    }, 300)  // Reset failure count after 300 seconds
    if err != nil {
        return fmt.Errorf("failed to set recovery actions: %w", err)
    }

    log.Infof("Service %s installed successfully", name)
    return nil
}

// UninstallService - Uninstall Windows service
func UninstallService(name string) error {
    m, err := mgr.Connect()
    if err != nil {
        return fmt.Errorf("failed to connect to SCM: %w", err)
    }
    defer m.Disconnect()

    s, err := m.OpenService(name)
    if err != nil {
        return fmt.Errorf("service %s not found: %w", name, err)
    }
    defer s.Close()

    // Stop service if running
    status, err := s.Query()
    if err != nil {
        return fmt.Errorf("failed to query service: %w", err)
    }

    if status.State != svc.Stopped {
        _, err = s.Control(svc.Stop)
        if err != nil {
            return fmt.Errorf("failed to stop service: %w", err)
        }

        // Wait for service to stop
        timeout := time.Now().Add(30 * time.Second)
        for status.State != svc.Stopped {
            if time.Now().After(timeout) {
                return fmt.Errorf("service did not stop within 30 seconds")
            }
            time.Sleep(500 * time.Millisecond)
            status, err = s.Query()
            if err != nil {
                return fmt.Errorf("failed to query service: %w", err)
            }
        }
    }

    // Delete service
    err = s.Delete()
    if err != nil {
        return fmt.Errorf("failed to delete service: %w", err)
    }

    log.Infof("Service %s uninstalled successfully", name)
    return nil
}

// StartService - Start Windows service
func StartService(name string) error {
    m, err := mgr.Connect()
    if err != nil {
        return fmt.Errorf("failed to connect to SCM: %w", err)
    }
    defer m.Disconnect()

    s, err := m.OpenService(name)
    if err != nil {
        return fmt.Errorf("service %s not found: %w", name, err)
    }
    defer s.Close()

    err = s.Start()
    if err != nil {
        return fmt.Errorf("failed to start service: %w", err)
    }

    log.Infof("Service %s started", name)
    return nil
}

// StopService - Stop Windows service
func StopService(name string) error {
    m, err := mgr.Connect()
    if err != nil {
        return fmt.Errorf("failed to connect to SCM: %w", err)
    }
    defer m.Disconnect()

    s, err := m.OpenService(name)
    if err != nil {
        return fmt.Errorf("service %s not found: %w", name, err)
    }
    defer s.Close()

    status, err := s.Control(svc.Stop)
    if err != nil {
        return fmt.Errorf("failed to stop service: %w", err)
    }

    log.Infof("Service %s stopped (status: %v)", name, status)
    return nil
}

// ServiceStatus - Get service status
func ServiceStatus(name string) (svc.State, error) {
    m, err := mgr.Connect()
    if err != nil {
        return 0, fmt.Errorf("failed to connect to SCM: %w", err)
    }
    defer m.Disconnect()

    s, err := m.OpenService(name)
    if err != nil {
        return 0, fmt.Errorf("service %s not found: %w", name, err)
    }
    defer s.Close()

    status, err := s.Query()
    if err != nil {
        return 0, fmt.Errorf("failed to query service: %w", err)
    }

    return status.State, nil
}
```

**CLI Commands:**
```go
// cmd/main.go

package main

import (
    "flag"
    "golang.org/x/sys/windows/svc"
)

func main() {
    installFlag := flag.Bool("install-service", false, "Install Windows service")
    uninstallFlag := flag.Bool("uninstall-service", false, "Uninstall Windows service")
    serviceFlag := flag.Bool("service", false, "Run as Windows service")
    flag.Parse()

    serviceName := "SafeOps-Firewall"
    displayName := "SafeOps Firewall Engine"
    description := "SafeOps next-generation firewall engine"

    // Install service
    if *installFlag {
        err := service.InstallService(serviceName, displayName, description,
            []string{"PostgreSQL", "SafeOps-Engine"})
        if err != nil {
            log.Fatalf("Failed to install service: %v", err)
        }
        log.Info("Service installed successfully ✅")
        return
    }

    // Uninstall service
    if *uninstallFlag {
        err := service.UninstallService(serviceName)
        if err != nil {
            log.Fatalf("Failed to uninstall service: %v", err)
        }
        log.Info("Service uninstalled successfully ✅")
        return
    }

    // Run as service
    if *serviceFlag {
        isService, err := svc.IsWindowsService()
        if err != nil {
            log.Fatalf("Failed to determine if running as service: %v", err)
        }

        if isService {
            fw := initializeFirewall()
            ws := service.NewWindowsService(serviceName, displayName, description, fw)
            err = svc.Run(serviceName, ws)
            if err != nil {
                log.Fatalf("Service failed: %v", err)
            }
            return
        }
    }

    // Run as console application (development mode)
    fw := initializeFirewall()
    fw.Start()
}
```

---

### **5. Update & Maintenance** (`internal/update/updater.go`)

**Purpose:**
- In-place binary updates (zero downtime)
- Configuration migration (preserve settings across versions)
- Backup and restore (rollback on failure)
- Health monitoring (detect issues early)

**Implementation:**
```go
// internal/update/updater.go

package update

import (
    "crypto/sha256"
    "fmt"
    "io"
    "os"
)

// Updater - Handles in-place binary updates
type Updater struct {
    currentVersion string
    currentBinary  string
    backupBinary   string
}

func NewUpdater(currentVersion string) *Updater {
    exePath, _ := os.Executable()
    return &Updater{
        currentVersion: currentVersion,
        currentBinary:  exePath,
        backupBinary:   exePath + ".backup",
    }
}

// Update - Perform in-place binary update
func (u *Updater) Update(newBinaryPath string) error {
    log.Infof("Starting update: %s → %s", u.currentVersion, "NEW")

    // Step 1: Verify new binary integrity
    log.Info("├─ [1/6] Verifying new binary integrity...")
    if err := u.verifyBinary(newBinaryPath); err != nil {
        return fmt.Errorf("binary verification failed: %w", err)
    }

    // Step 2: Backup current binary
    log.Info("├─ [2/6] Backing up current binary...")
    if err := u.backupCurrentBinary(); err != nil {
        return fmt.Errorf("backup failed: %w", err)
    }

    // Step 3: Stop service gracefully
    log.Info("├─ [3/6] Stopping service gracefully...")
    if err := service.StopService("SafeOps-Firewall"); err != nil {
        return fmt.Errorf("failed to stop service: %w", err)
    }

    // Step 4: Replace binary
    log.Info("├─ [4/6] Replacing binary...")
    if err := u.replaceBinary(newBinaryPath); err != nil {
        log.Error("Binary replacement failed, rolling back...")
        u.rollback()
        return fmt.Errorf("binary replacement failed: %w", err)
    }

    // Step 5: Start service
    log.Info("├─ [5/6] Starting service with new binary...")
    if err := service.StartService("SafeOps-Firewall"); err != nil {
        log.Error("Failed to start service, rolling back...")
        u.rollback()
        return fmt.Errorf("failed to start service: %w", err)
    }

    // Step 6: Health check
    log.Info("└─ [6/6] Performing health check...")
    if err := u.healthCheck(); err != nil {
        log.Error("Health check failed, rolling back...")
        u.rollback()
        return fmt.Errorf("health check failed: %w", err)
    }

    log.Info("Update successful ✅")
    return nil
}

// verifyBinary - Verify binary integrity (checksum)
func (u *Updater) verifyBinary(binaryPath string) error {
    // Compute SHA256 checksum
    file, err := os.Open(binaryPath)
    if err != nil {
        return err
    }
    defer file.Close()

    hash := sha256.New()
    if _, err := io.Copy(hash, file); err != nil {
        return err
    }

    checksum := fmt.Sprintf("%x", hash.Sum(nil))
    log.Infof("│  └─ Binary checksum: %s", checksum)

    // Verify against expected checksum (from update manifest)
    // expectedChecksum := fetchExpectedChecksum()
    // if checksum != expectedChecksum {
    //     return fmt.Errorf("checksum mismatch")
    // }

    return nil
}

// backupCurrentBinary - Backup current binary
func (u *Updater) backupCurrentBinary() error {
    src, err := os.Open(u.currentBinary)
    if err != nil {
        return err
    }
    defer src.Close()

    dst, err := os.Create(u.backupBinary)
    if err != nil {
        return err
    }
    defer dst.Close()

    if _, err := io.Copy(dst, src); err != nil {
        return err
    }

    log.Infof("│  └─ Backup saved: %s", u.backupBinary)
    return nil
}

// replaceBinary - Replace current binary with new version
func (u *Updater) replaceBinary(newBinaryPath string) error {
    // Windows: Cannot replace running executable
    // Solution: Rename current, copy new, delete old on next boot

    // Rename current binary
    oldBinary := u.currentBinary + ".old"
    if err := os.Rename(u.currentBinary, oldBinary); err != nil {
        return err
    }

    // Copy new binary
    src, err := os.Open(newBinaryPath)
    if err != nil {
        return err
    }
    defer src.Close()

    dst, err := os.Create(u.currentBinary)
    if err != nil {
        return err
    }
    defer dst.Close()

    if _, err := io.Copy(dst, src); err != nil {
        return err
    }

    // Schedule deletion of old binary on next boot
    // (Windows: MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT)

    log.Infof("│  └─ Binary replaced: %s", u.currentBinary)
    return nil
}

// rollback - Rollback to previous version
func (u *Updater) rollback() error {
    log.Warn("Rolling back to previous version...")

    // Stop service
    service.StopService("SafeOps-Firewall")

    // Restore backup binary
    src, err := os.Open(u.backupBinary)
    if err != nil {
        return err
    }
    defer src.Close()

    dst, err := os.Create(u.currentBinary)
    if err != nil {
        return err
    }
    defer dst.Close()

    if _, err := io.Copy(dst, src); err != nil {
        return err
    }

    // Start service
    service.StartService("SafeOps-Firewall")

    log.Info("Rollback complete")
    return nil
}

// healthCheck - Verify service is healthy after update
func (u *Updater) healthCheck() error {
    // Wait for service to start
    time.Sleep(5 * time.Second)

    // Check health endpoint
    resp, err := http.Get("http://localhost:8080/health")
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("health check failed: status %d", resp.StatusCode)
    }

    log.Info("│  └─ Health check passed ✅")
    return nil
}
```

---

## 📊 Production Checklist

### **Pre-Deployment Checklist:**
```
┌─────────────────────────────────────────────────────────────┐
│                  PRE-DEPLOYMENT CHECKLIST                   │
├─────────────────────────────────────────────────────────────┤
│  □ Graceful shutdown implemented and tested                 │
│  □ Error recovery (gRPC, DB, panic) implemented             │
│  □ Resource limits configured (memory, goroutines)          │
│  □ Windows service installed and tested                     │
│  □ Service dependencies configured (PostgreSQL, SafeOps)    │
│  □ Service recovery options configured (restart on failure) │
│  □ Health check endpoint implemented (/health)              │
│  □ Monitoring enabled (Prometheus metrics)                  │
│  □ Logging configured (file rotation, syslog)               │
│  □ Configuration backup (firewall.toml, state.db)           │
│  □ Update mechanism tested (in-place update, rollback)      │
│  □ Load testing completed (100K pps sustained)              │
│  □ Security audit completed (no vulnerabilities)            │
│  □ Documentation complete (deployment, troubleshooting)     │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ Acceptance Criteria

**Phase 12 is complete when:**

1. **Graceful Shutdown:**
   - ✅ SIGTERM/SIGINT handler implemented
   - ✅ Logs flushed before exit (no data loss)
   - ✅ gRPC connections closed gracefully
   - ✅ State saved to disk (connection table, cache)
   - ✅ In-flight packets complete before shutdown

2. **Error Recovery:**
   - ✅ Auto-reconnect to SafeOps Engine (exponential backoff)
   - ✅ Fallback to WFP if SafeOps unavailable
   - ✅ Database retry logic (3 attempts)
   - ✅ Panic recovery (restart process, max 3 attempts)

3. **Resource Limits:**
   - ✅ Memory limit enforced (2GB hard limit, 1.5GB soft limit)
   - ✅ Goroutine limit monitored (10K limit)
   - ✅ Open file limit enforced (10K limit)
   - ✅ Database connection pool limited (100 connections)

4. **Windows Service:**
   - ✅ Service installs successfully
   - ✅ Service auto-starts on boot (delayed start)
   - ✅ Service dependencies configured (PostgreSQL first)
   - ✅ Service recovery configured (restart on failure, 3 attempts)
   - ✅ Service control works (start, stop, restart, status)

5. **Update & Maintenance:**
   - ✅ In-place binary update works (zero downtime)
   - ✅ Configuration migration works (preserve settings)
   - ✅ Backup and restore works (rollback on failure)
   - ✅ Health monitoring works (detect issues early)

6. **Production Validation:**
   - ✅ 24-hour uptime test (no crashes, no memory leaks)
   - ✅ Load test (100K pps sustained for 1 hour)
   - ✅ Fault injection test (kill SafeOps, kill DB, network loss)
   - ✅ Update test (update binary, rollback, verify)

---

## 📈 Expected Timeline

```
Week 1: Graceful Shutdown & Error Recovery
├─ Day 1-2: Graceful shutdown implementation
├─ Day 3-4: Error recovery (gRPC, DB, panic)
└─ Day 5: Testing & validation

Week 2: Resource Limits & Windows Service
├─ Day 1-2: Resource monitoring (memory, goroutines)
├─ Day 3-4: Windows service implementation
└─ Day 5: Service installation & testing

Week 3: Update & Maintenance
├─ Day 1-2: In-place update mechanism
├─ Day 3-4: Health monitoring & alerting
└─ Day 5: Production validation (24h test)

Total: 2-3 weeks
```

---

## 🎯 Deliverables

### **Code Deliverables:**
```
src/firewall_engine/
├─ internal/lifecycle/
│  ├─ shutdown.go               # Graceful shutdown
│  └─ health.go                 # Health check endpoint
├─ internal/recovery/
│  ├─ error_recovery.go         # Error recovery (gRPC, DB, panic)
│  └─ fallback.go               # Fallback mode (direct WFP)
├─ internal/resources/
│  └─ limits.go                 # Resource monitoring & limits
├─ internal/service/
│  └─ windows_service.go        # Windows service wrapper
└─ internal/update/
   ├─ updater.go                # In-place binary updater
   └─ migrator.go               # Configuration migration
```

### **Documentation Deliverables:**
```
docs/
├─ deployment/
│  ├─ INSTALLATION.md           # Installation guide
│  ├─ CONFIGURATION.md          # Configuration guide
│  ├─ SERVICE-SETUP.md          # Windows service setup
│  └─ TROUBLESHOOTING.md        # Common issues & fixes
└─ operations/
   ├─ MONITORING.md             # Monitoring guide
   ├─ UPDATES.md                # Update procedure
   └─ BACKUP-RESTORE.md         # Backup & restore guide
```

---

**END OF PHASE 12 DOCUMENT**
