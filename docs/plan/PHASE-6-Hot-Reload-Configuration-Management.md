# PHASE 6: HOT-RELOAD & CONFIGURATION MANAGEMENT

**Status:** 🔜 Future Phase (After Phase 5 Complete)
**Duration:** 1.5 weeks
**Goal:** Zero-downtime rule updates - edit config file, rules update instantly without restart
**Deliverable:** Production-ready hot-reload system with rollback, validation, and atomic swaps

---

## 📋 Phase Overview

**What Changes in Phase 6:**
- **Phase 5 Reality:** Changing rules requires restarting firewall (downtime, packet loss)
- **Phase 6 Goal:** Edit firewall.toml, save, rules update instantly with zero packet loss
- **Integration Point:** File watcher detects changes, validates, and atomically swaps rules

**Dependencies:**
- ✅ Phase 1: gRPC metadata stream working
- ✅ Phase 2: Rule matching engine functional
- ✅ Phase 3: SafeOps verdict enforcement working
- ✅ Phase 4: WFP dual-engine active
- ✅ Phase 5: Logging, metrics, health monitoring

---

## 🎯 Phase 6 Outcomes (What You Should See)

### After Compilation & Execution:

**Initial Startup:**
```
[INFO] Firewall Engine v6.0.0 Starting...
[INFO] Connected to SafeOps Engine (127.0.0.1:50053)
[INFO] Loaded 150 firewall rules from firewall.toml
[INFO] Hot-Reload: Watching /etc/safeops/firewall.toml for changes
[INFO] Dual Engine Mode: ENABLED (SafeOps + WFP)
[INFO] Firewall ready - processing traffic
```

**User Edits Config (Add New Rule):**
```bash
# Terminal 1: Edit config file
$ vim /etc/safeops/firewall.toml

# Add new rule at end of file:
[[rule]]
name = "Block_TikTok"
action = "DENY"
protocol = "TCP"
dst_domain = "*.tiktok.com"
dst_port = 443
priority = 100

# Save file (:wq)
```

**Firewall Detects Change (Automatic):**
```
[INFO] Hot-Reload: File change detected: /etc/safeops/firewall.toml
[INFO] Hot-Reload: Debouncing... (waiting 1 second for additional changes)
[INFO] Hot-Reload: Starting reload process
[INFO] Hot-Reload: Creating backup: /etc/safeops/firewall.toml.20260122_101530
[INFO] Hot-Reload: Validating new configuration...
[INFO] Hot-Reload: ✓ TOML syntax valid
[INFO] Hot-Reload: ✓ 151 rules parsed successfully
[INFO] Hot-Reload: ✓ All rules validated (no conflicts, valid syntax)
[INFO] Hot-Reload: Building new rule tree...
[INFO] Hot-Reload: ✓ Rule tree built (151 rules, 3ms)
[INFO] Hot-Reload: Preparing atomic swap...
[INFO] Hot-Reload: ├─ Flushing verdict cache (50,000 entries invalidated)
[INFO] Hot-Reload: ├─ Updating WFP filters (151 filters, batched)
[INFO] Hot-Reload: ├─ WFP transaction started
[INFO] Hot-Reload: ├─ Deleting old WFP filters (150 filters)
[INFO] Hot-Reload: ├─ Installing new WFP filters (151 filters)
[INFO] Hot-Reload: ├─ WFP transaction committed (500ms)
[INFO] Hot-Reload: ├─ Swapping rule engine (atomic pointer swap)
[INFO] Hot-Reload: └─ Atomic swap complete (0 packets dropped)
[INFO] Hot-Reload: ✅ Reload successful (151 rules active, total time: 1.234s)
[INFO] Hot-Reload: New rule active: Block_TikTok

# Metrics updated:
[INFO] firewall_reload_total: 1
[INFO] firewall_reload_success_total: 1
[INFO] firewall_reload_duration_seconds: 1.234
```

**Testing New Rule (Immediate Effect):**
```bash
# Terminal 2: Test TikTok blocking (immediately after reload)
$ curl -I https://www.tiktok.com

# Firewall logs:
[INFO] [DENY] TCP 192.168.1.100:54321 -> 104.244.42.1:443 HTTPS [Rule: Block_TikTok] [Latency: 18μs] [Engine: Dual]

# curl receives:
curl: (7) Failed to connect to www.tiktok.com port 443: Connection refused
# ✅ New rule working instantly!
```

**User Edits Config (Invalid Rule - Triggers Rollback):**
```bash
# Terminal 1: Edit config with error
$ vim /etc/safeops/firewall.toml

# Add invalid rule (bad syntax):
[[rule]]
name = "Block_Invalid"
action = "INVALID_ACTION"  # ❌ Invalid action (should be ALLOW/DENY/DROP)
protocol = "TCP"
dst_port = "not_a_number"  # ❌ Invalid port (should be integer)
priority = 9999999         # ❌ Priority too high (max 1000)

# Save file (:wq)
```

**Firewall Detects Change (Validation Fails):**
```
[INFO] Hot-Reload: File change detected: /etc/safeops/firewall.toml
[INFO] Hot-Reload: Debouncing... (waiting 1 second)
[INFO] Hot-Reload: Starting reload process
[INFO] Hot-Reload: Creating backup: /etc/safeops/firewall.toml.20260122_101545
[INFO] Hot-Reload: Validating new configuration...
[ERROR] Hot-Reload: ❌ Validation failed (3 errors):
[ERROR]   1. Rule 'Block_Invalid': Invalid action 'INVALID_ACTION' (must be ALLOW, DENY, or DROP)
[ERROR]   2. Rule 'Block_Invalid': Invalid port 'not_a_number' (must be integer 1-65535)
[ERROR]   3. Rule 'Block_Invalid': Priority 9999999 exceeds maximum (1000)
[ERROR] Hot-Reload: Aborting reload - keeping current rules active
[ERROR] Hot-Reload: ⚠️  CONFIG REJECTED - Fix errors and save again
[ERROR] Hot-Reload: Backup available at: /etc/safeops/firewall.toml.20260122_101530

# Metrics updated:
[INFO] firewall_reload_total: 2
[INFO] firewall_reload_success_total: 1
[INFO] firewall_reload_failure_total: 1
[INFO] firewall_reload_last_error: "Invalid action 'INVALID_ACTION'"

# Original 151 rules still active (no downtime)
```

**User Fixes Config:**
```bash
# Terminal 1: Fix errors
$ vim /etc/safeops/firewall.toml

# Fix rule:
[[rule]]
name = "Block_Invalid"
action = "DENY"            # ✅ Fixed
protocol = "TCP"
dst_port = 443             # ✅ Fixed
priority = 100             # ✅ Fixed

# Save file (:wq)
```

**Firewall Accepts Fixed Config:**
```
[INFO] Hot-Reload: File change detected: /etc/safeops/firewall.toml
[INFO] Hot-Reload: Debouncing... (waiting 1 second)
[INFO] Hot-Reload: Starting reload process
[INFO] Hot-Reload: Creating backup: /etc/safeops/firewall.toml.20260122_101600
[INFO] Hot-Reload: Validating new configuration...
[INFO] Hot-Reload: ✓ TOML syntax valid
[INFO] Hot-Reload: ✓ 152 rules parsed successfully
[INFO] Hot-Reload: ✓ All rules validated
[INFO] Hot-Reload: Building new rule tree...
[INFO] Hot-Reload: ✓ Rule tree built (152 rules, 3ms)
[INFO] Hot-Reload: Performing atomic swap...
[INFO] Hot-Reload: ✅ Reload successful (152 rules active, total time: 1.156s)

# Metrics updated:
[INFO] firewall_reload_total: 3
[INFO] firewall_reload_success_total: 2
[INFO] firewall_reload_failure_total: 1
```

**Zero Packet Loss During Reload:**
```
# Performance test during reload:
$ iperf3 -c target_server -t 60 -i 1

# Output (reload happens at 30s mark):
[  5] 28.00-29.00 sec  115 MBytes  965 Mbits/sec
[  5] 29.00-30.00 sec  115 MBytes  965 Mbits/sec
[  5] 30.00-31.00 sec  115 MBytes  965 Mbits/sec  ← Reload happens here
[  5] 31.00-32.00 sec  115 MBytes  965 Mbits/sec  ← No packet loss!
[  5] 32.00-33.00 sec  115 MBytes  965 Mbits/sec

# ✅ No throughput drop, no packet loss, no latency spike
```

**Manual Reload via API:**
```bash
# Trigger reload without file change
$ safeops-firewall-cli rules reload

Reloading rules...
Creating backup: /etc/safeops/firewall.toml.20260122_101700
Validating configuration... ✓
Building rule tree... ✓
Performing atomic swap... ✓
Success! Loaded 152 rules in 1.234s

# Same atomic swap process, triggered manually
```

---

## 🏗️ Phase 6 Architecture

### Hot-Reload Flow:

```
User Edits File                    Firewall Process
────────────────                   ─────────────────

vim firewall.toml
:wq (save)
   │
   │ (file modified)
   ↓
                                   ┌─────────────────────┐
                                   │  File Watcher       │
                                   │  (fsnotify)         │
                                   └──────────┬──────────┘
                                              │
                                   (event: WRITE)
                                              ↓
                                   ┌─────────────────────┐
                                   │  Debouncer          │
                                   │  (wait 1 second)    │
                                   └──────────┬──────────┘
                                              │
                                   (debounced event)
                                              ↓
                                   ┌─────────────────────┐
                                   │  Reload Manager     │
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────┴─────────┐
                                   ↓                    ↓
                        ┌──────────────────┐  ┌──────────────────┐
                        │  1. Backup       │  │  2. Validate     │
                        │  Create snapshot │  │  Parse + Check   │
                        └──────────────────┘  └──────────┬───────┘
                                                          │
                                              (if invalid) │ (if valid)
                                              ↓           ↓
                                   ┌──────────────────┐  ┌──────────────────┐
                                   │  Rollback        │  │  3. Build Tree   │
                                   │  Keep old rules  │  │  New rule engine │
                                   └──────────────────┘  └──────────┬───────┘
                                                                     │
                                                                     ↓
                                                          ┌──────────────────┐
                                                          │  4. Atomic Swap  │
                                                          ├──────────────────┤
                                                          │ a. Flush cache   │
                                                          │ b. Update WFP    │
                                                          │ c. Swap pointer  │
                                                          └──────────┬───────┘
                                                                     │
                                                                     ↓
                                   ┌─────────────────────────────────────┐
                                   │  5. New Rules Active                │
                                   │  (packets processed with new rules)  │
                                   └─────────────────────────────────────┘
```

### Atomic Swap Mechanism:

```
Current State (Before Reload):
┌──────────────────────────────────────────────────────────┐
│  Rule Engine Pointer (atomic.Value)                      │
│  ├─> RuleEngine V1 (150 rules)                          │
│                                                           │
│  Packet Processing Thread 1 ──> Reads pointer ──> V1     │
│  Packet Processing Thread 2 ──> Reads pointer ──> V1     │
│  Packet Processing Thread 3 ──> Reads pointer ──> V1     │
│  Packet Processing Thread 4 ──> Reads pointer ──> V1     │
└──────────────────────────────────────────────────────────┘

Reload Process (Preparation):
┌──────────────────────────────────────────────────────────┐
│  Rule Engine Pointer (atomic.Value)                      │
│  ├─> RuleEngine V1 (150 rules)  ← Still active          │
│                                                           │
│  Background goroutine:                                    │
│  ├─ Build RuleEngine V2 (151 rules)                     │
│  ├─ Validate all rules                                   │
│  └─ Prepare WFP filters                                  │
│                                                           │
│  Packet Processing (continues normally):                 │
│  Packet Processing Thread 1 ──> Reads pointer ──> V1     │
│  Packet Processing Thread 2 ──> Reads pointer ──> V1     │
└──────────────────────────────────────────────────────────┘

Atomic Swap (Single Instruction):
┌──────────────────────────────────────────────────────────┐
│  Rule Engine Pointer (atomic.Value)                      │
│  ├─X RuleEngine V1 (150 rules)  ← Old (no longer used)  │
│  └─> RuleEngine V2 (151 rules)  ← New (now active)      │
│                                                           │
│  atomic.StorePointer(&ruleEnginePtr, &v2)  ← 1 CPU cycle│
│                                                           │
│  Packet Processing (instantly switches):                 │
│  Packet Processing Thread 1 ──> Reads pointer ──> V2     │
│  Packet Processing Thread 2 ──> Reads pointer ──> V2     │
│  Packet Processing Thread 3 ──> Reads pointer ──> V1 (old packet in flight)
│  Packet Processing Thread 4 ──> Reads pointer ──> V2     │
└──────────────────────────────────────────────────────────┘

Post-Swap Cleanup:
┌──────────────────────────────────────────────────────────┐
│  Rule Engine Pointer (atomic.Value)                      │
│  └─> RuleEngine V2 (151 rules)  ← Active                │
│                                                           │
│  All threads now using V2:                               │
│  Packet Processing Thread 1 ──> Reads pointer ──> V2     │
│  Packet Processing Thread 2 ──> Reads pointer ──> V2     │
│  Packet Processing Thread 3 ──> Reads pointer ──> V2     │
│  Packet Processing Thread 4 ──> Reads pointer ──> V2     │
│                                                           │
│  Background cleanup:                                      │
│  ├─ Wait for old packets to finish (grace period 100ms) │
│  ├─ Free RuleEngine V1 memory (GC collects)             │
│  └─ Delete old WFP filters                               │
└──────────────────────────────────────────────────────────┘
```

**Why Atomic Swap Works:**
- CPU atomic instruction (cannot be interrupted)
- Pointer swap takes 1 CPU cycle (~0.3 nanoseconds)
- No locks required (lock-free, wait-free)
- No packet loss (in-flight packets finish with old rules)
- No latency spike (instant switch)

---

## 📦 Phase 6 Components (4 Sub-Tasks)

### Sub-Task 6.1: File Watcher (`internal/hotreload/watcher.go`)

**Purpose:** Monitor configuration file for changes and trigger reload

**Core Concept:**
File watcher uses operating system events to detect file modifications:
- Linux: inotify (kernel notifications)
- Windows: ReadDirectoryChangesW (Win32 API)
- macOS: FSEvents (kernel notifications)

---

#### What to Create:

**1. File Watcher Implementation**

**Purpose:** Use fsnotify library to watch config file

**fsnotify Library:**
```
Go library: github.com/fsnotify/fsnotify
Cross-platform file system notifications:
├─ Linux: inotify
├─ Windows: ReadDirectoryChangesW
├─ macOS: FSEvents/kqueue
└─ BSD: kqueue

Events:
├─ CREATE: File created
├─ WRITE: File modified (this is what we care about)
├─ REMOVE: File deleted
├─ RENAME: File renamed
└─ CHMOD: File permissions changed
```

**Watcher Setup:**
```
1. Initialize fsnotify:
   watcher, err := fsnotify.NewWatcher()
   if err != nil {
     return fmt.Errorf("failed to create file watcher: %w", err)
   }

2. Add config file to watch list:
   err = watcher.Add("/etc/safeops/firewall.toml")
   if err != nil {
     return fmt.Errorf("failed to watch config file: %w", err)
   }

3. Start event loop (goroutine):
   go func() {
     for {
       select {
       case event := <-watcher.Events:
         handleEvent(event)
       case err := <-watcher.Errors:
         log.Error().Err(err).Msg("File watcher error")
       }
     }
   }()

4. Watch indefinitely (until firewall stops)
```

**Event Handling:**
```
func handleEvent(event fsnotify.Event) {
  // Filter event type
  if event.Op&fsnotify.Write != fsnotify.Write {
    return  // Ignore non-WRITE events (CREATE, REMOVE, etc.)
  }

  // Check if it's our config file
  if event.Name != configFilePath {
    return  // Ignore other files in same directory
  }

  log.Info().
    Str("file", event.Name).
    Str("operation", event.Op.String()).
    Msg("Config file modified")

  // Trigger reload (with debouncing)
  triggerReload()
}
```

---

**2. Debouncing**

**Purpose:** Wait for rapid successive edits to complete before reloading

**Why Debounce:**
```
Problem: Text editors save files multiple times
Example (vim):
├─ 10:00:00.000 - User types character → vim auto-saves (WRITE event)
├─ 10:00:00.100 - User types character → vim auto-saves (WRITE event)
├─ 10:00:00.200 - User types character → vim auto-saves (WRITE event)
├─ 10:00:00.300 - User saves file (:w) → vim saves (WRITE event)
└─ Result: 4 WRITE events in 300ms

Without debouncing:
├─ Reload triggered 4 times (expensive!)
├─ 4 × 1.2s = 4.8 seconds total reload time
├─ Cache flushed 4 times (lost cached verdicts)
└─ WFP filters updated 4 times (unnecessary work)

With debouncing (1 second):
├─ First event (10:00:00.000): Start timer (1 second)
├─ Second event (10:00:00.100): Reset timer (1 second from now)
├─ Third event (10:00:00.200): Reset timer (1 second from now)
├─ Fourth event (10:00:00.300): Reset timer (1 second from now)
├─ Timer expires (10:00:01.300): Trigger reload ONCE
└─ Result: 1 reload (1.2 seconds total)
```

**Debounce Implementation:**
```
Debouncer state:
├─ timer: *time.Timer (countdown timer)
├─ mutex: sync.Mutex (protect timer access)
└─ delay: time.Duration (1 second default)

Algorithm:
1. File change event received
2. Lock mutex
3. If timer exists: Stop timer (cancel previous reload)
4. Create new timer: time.AfterFunc(1 * time.Second, reloadFunc)
5. Unlock mutex
6. Wait for timer to expire (1 second of no changes)
7. Timer expires → trigger reload

Code structure:
type Debouncer struct {
  timer *time.Timer
  mutex sync.Mutex
  delay time.Duration
}

func (d *Debouncer) Trigger(fn func()) {
  d.mutex.Lock()
  defer d.mutex.Unlock()

  // Cancel previous timer
  if d.timer != nil {
    d.timer.Stop()
  }

  // Create new timer
  d.timer = time.AfterFunc(d.delay, fn)
}

Usage:
debouncer := NewDebouncer(1 * time.Second)

func handleFileChange() {
  debouncer.Trigger(func() {
    log.Info().Msg("Debounce period ended, triggering reload")
    reloadManager.Reload()
  })
}
```

**Debounce Duration Tuning:**
```
Duration | User Experience             | Risk
---------+------------------------------+---------------------------
100ms    | Very fast (reactive)         | May reload mid-edit
500ms    | Fast (responsive)            | Might reload mid-edit
1000ms   | Normal (1 second delay) ✓    | Good balance
2000ms   | Slow (noticeable delay)      | User wonders if it worked
5000ms   | Very slow (frustrating)      | User may edit again

Recommendation: 1 second (1000ms)
- Long enough to capture rapid edits
- Short enough to feel instant
- Standard duration in industry
```

---

**3. Watch Multiple Files**

**Purpose:** Watch rule includes, domain lists, GeoIP databases

**Why Multiple Files:**
```
Config file structure:
firewall.toml (main config)
├─ [[rule]] definitions (inline rules)
└─ include_rules = "/etc/safeops/rules.d/*.toml"  # External rule files

rules.d/
├─ 01-system.toml      # System rules
├─ 02-security.toml    # Security rules
└─ 03-custom.toml      # Custom rules

domains/
├─ malware-domains.txt  # Malware domain list
└─ blocked-sites.txt    # Corporate blocked sites

geoip/
└─ GeoLite2-Country.mmdb  # GeoIP database

All these files need watching:
- Change malware-domains.txt → reload
- Change 02-security.toml → reload
- Change GeoLite2-Country.mmdb → reload
```

**Multi-File Watcher:**
```
Watch list:
1. Add main config:
   watcher.Add("/etc/safeops/firewall.toml")

2. Add included rule files (glob pattern):
   includes, _ := filepath.Glob("/etc/safeops/rules.d/*.toml")
   for _, path := range includes {
     watcher.Add(path)
   }

3. Add domain lists:
   watcher.Add("/etc/safeops/domains/malware-domains.txt")
   watcher.Add("/etc/safeops/domains/blocked-sites.txt")

4. Add GeoIP database:
   watcher.Add("/etc/safeops/geoip/GeoLite2-Country.mmdb")

Event handling (any file changes):
- Single debouncer for all files (don't reload 4 times if 4 files change)
- Reload loads ALL files (main + includes)
```

---

**4. Watch Directory (Handle New Files)**

**Purpose:** Detect new files added to rules.d/ directory

**Why Watch Directory:**
```
Problem: User adds new file to rules.d/
Example:
$ cp 04-temp-rules.toml /etc/safeops/rules.d/

File watcher only watches existing files at startup:
├─ 01-system.toml (watched)
├─ 02-security.toml (watched)
├─ 03-custom.toml (watched)
└─ 04-temp-rules.toml (NOT watched - didn't exist at startup)

Solution: Watch directory instead of individual files
watcher.Add("/etc/safeops/rules.d/")

Events:
├─ CREATE: New file added (04-temp-rules.toml) → Trigger reload
├─ WRITE: Existing file modified → Trigger reload
├─ REMOVE: File deleted → Trigger reload
└─ RENAME: File renamed → Trigger reload
```

**Directory Watcher:**
```
Watch directories:
1. Watch rules directory:
   watcher.Add("/etc/safeops/rules.d/")

2. On CREATE event (new file):
   ├─ Reload (will pick up new file)
   └─ New file automatically included (glob pattern matches)

3. On REMOVE event (file deleted):
   ├─ Reload (will exclude deleted file)
   └─ Rules from deleted file removed

4. On RENAME event (file renamed):
   ├─ If old name matches glob (*.toml): Reload (file removed)
   └─ If new name matches glob (*.toml): Reload (file added)

Filter events:
- Only trigger on *.toml files (ignore .swp, .bak, ~, etc.)
- Ignore temporary editor files (vim: .swp, emacs: ~, nano: .save)
```

**Editor Temporary File Handling:**
```
Text editors create temporary files:
vim: firewall.toml.swp, firewall.toml~
emacs: #firewall.toml#, firewall.toml~
nano: firewall.toml.save

Filter these out:
func shouldIgnoreFile(filename string) bool {
  // Ignore vim swap files
  if strings.HasSuffix(filename, ".swp") {
    return true
  }

  // Ignore backup files
  if strings.HasSuffix(filename, "~") {
    return true
  }

  // Ignore emacs lock files
  if strings.HasPrefix(filepath.Base(filename), "#") {
    return true
  }

  // Ignore nano backup files
  if strings.HasSuffix(filename, ".save") {
    return true
  }

  // Only process .toml files
  if !strings.HasSuffix(filename, ".toml") {
    return true
  }

  return false
}
```

---

**5. Watcher Health Monitoring**

**Purpose:** Detect if file watcher stops working

**Why Monitor:**
```
File watcher can fail:
├─ inotify limit exceeded (Linux: /proc/sys/fs/inotify/max_user_watches)
├─ File system unmounted (network drive disconnected)
├─ Permissions changed (can't read file)
└─ OS bug (kernel panic, driver crash)

If watcher fails:
- User edits config → No reload happens
- Firewall uses stale rules (security risk)
- No error message (silent failure)

Solution: Health check
- Every 30 seconds: Verify watcher still alive
- Test: Write to file, verify event received
- If no event: Log error, alert admin, restart watcher
```

**Health Check Implementation:**
```
Heartbeat mechanism:
1. Create test file in watched directory:
   /etc/safeops/.hotreload_test

2. Every 30 seconds:
   ├─ Write current timestamp to test file
   ├─ Wait for WRITE event (max 5 seconds)
   ├─ If event received: Watcher healthy
   └─ If no event: Watcher dead

3. If watcher dead:
   ├─ Log error: "File watcher unresponsive"
   ├─ Update metric: firewall_hotreload_health = 0
   ├─ Attempt restart: watcher.Close() + NewWatcher()
   └─ If restart fails: Alert admin (PagerDuty/Slack)

Health check goroutine:
go func() {
  ticker := time.NewTicker(30 * time.Second)
  for range ticker.C {
    healthy := testWatcher()
    if !healthy {
      log.Error().Msg("File watcher unhealthy, attempting restart")
      restartWatcher()
    }
  }
}()
```

---

#### Files to Create:
```
internal/hotreload/
├── watcher.go           # File watcher (fsnotify integration)
├── debouncer.go         # Debounce rapid changes
├── multi_watch.go       # Watch multiple files/directories
└── watcher_health.go    # Watcher health monitoring
```

---

### Sub-Task 6.2: Reload Logic (`internal/hotreload/reloader.go`)

**Purpose:** Orchestrate reload process (backup, validate, build, swap)

**Core Concept:**
Reload manager coordinates all reload steps in correct order, handles errors, and ensures atomicity (all-or-nothing reload).

---

#### What to Create:

**1. Reload Manager**

**Purpose:** Coordinate reload process from start to finish

**Reload State Machine:**
```
States:
├─ IDLE: No reload in progress, watching for changes
├─ DEBOUNCING: File changed, waiting for more changes
├─ RELOADING: Reload in progress (backup, validate, build, swap)
├─ ROLLING_BACK: Reload failed, restoring previous state
└─ FAILED: Reload failed, error state

State transitions:
IDLE → DEBOUNCING (file changed)
DEBOUNCING → RELOADING (debounce period ended)
RELOADING → IDLE (reload successful)
RELOADING → ROLLING_BACK (reload failed)
ROLLING_BACK → IDLE (rollback complete)
ROLLING_BACK → FAILED (rollback failed - critical)

Mutex protection:
- Only one reload at a time (mutex ensures no concurrent reloads)
- If reload in progress, queue next reload (don't start second reload)
```

**Reload Manager Structure:**
```
type ReloadManager struct {
  // State
  state       ReloadState
  stateMutex  sync.RWMutex
  reloadMutex sync.Mutex  // Prevent concurrent reloads

  // Dependencies
  configPath  string
  ruleManager *rules.Manager
  wfpEngine   *wfp.Engine
  cache       *cache.Manager
  logger      *logging.Logger
  metrics     *metrics.Collector

  // Backup management
  backupPath  string
  backupTime  time.Time

  // Statistics
  reloadCount uint64
  successCount uint64
  failureCount uint64
  lastReloadTime time.Time
  lastReloadDuration time.Duration
  lastError string
}
```

---

**2. Reload Process (Step-by-Step)**

**Purpose:** Execute reload in correct order with error handling

**Reload Steps:**
```
Step 1: Acquire Reload Lock
├─ Try to acquire reloadMutex (non-blocking)
├─ If already locked: Log "Reload already in progress, skipping"
├─ If acquired: Proceed to Step 2
└─ Update state: IDLE → RELOADING

Step 2: Create Backup
├─ Generate backup filename: firewall.toml.YYYYMMDD_HHMMSS
├─ Copy current config: cp firewall.toml firewall.toml.20260122_101530
├─ Verify backup created successfully
├─ Store backup path (for rollback)
└─ If backup fails: Abort reload (cannot rollback without backup)

Step 3: Parse New Configuration
├─ Read file: ioutil.ReadFile(configPath)
├─ Parse TOML: toml.Unmarshal(data, &config)
├─ If parse error: Log syntax error, goto Rollback
└─ If success: config struct contains new rules

Step 4: Validate Rules
├─ For each rule: Validate syntax, constraints, conflicts
├─ Check for:
│  ├─ Valid action (ALLOW/DENY/DROP)
│  ├─ Valid protocol (TCP/UDP/ICMP)
│  ├─ Valid port range (1-65535)
│  ├─ Valid IP address/CIDR
│  ├─ Valid priority (1-1000)
│  └─ No duplicate rule names
├─ If validation error: Log detailed errors, goto Rollback
└─ If success: Rules are valid

Step 5: Build New Rule Engine
├─ Create new rule.Manager instance
├─ Load validated rules into manager
├─ Build rule tree (decision tree for fast matching)
├─ Measure build time (should be <10ms for 1000 rules)
├─ If build error: Log error, goto Rollback
└─ If success: New rule engine ready

Step 6: Prepare WFP Filters (If Enabled)
├─ Translate rules to WFP filters
├─ Start WFP transaction (batch operation)
├─ Delete old WFP filters (current rules)
├─ Install new WFP filters (new rules)
├─ Commit transaction (atomic)
├─ If WFP error: Rollback transaction, goto Rollback
└─ If success: WFP filters updated

Step 7: Atomic Swap
├─ Flush verdict cache (invalidate cached verdicts)
├─ Atomic pointer swap: atomic.StorePointer(&ruleEngine, &newEngine)
├─ Wait grace period (100ms for in-flight packets to finish)
├─ Update metrics (firewall_rules_loaded)
└─ Success: New rules active

Step 8: Cleanup
├─ Wait for old packets to finish (100ms grace period)
├─ Mark old rule engine for garbage collection
├─ Update reload statistics (count, duration, timestamp)
├─ Update metrics (firewall_reload_success_total)
├─ Release reload lock
└─ Update state: RELOADING → IDLE
```

**Error Handling:**
```
If error at any step:
1. Log detailed error (step, reason, details)
2. Update metrics (firewall_reload_failure_total)
3. Goto Rollback (Sub-Task 6.4)
4. Keep old rules active (no downtime)
5. Alert administrator (optional)

Critical errors (cannot recover):
├─ Backup creation failed (can't rollback)
├─ Old rule engine corrupted (memory corruption)
└─ WFP rollback failed (Windows API error)

For critical errors:
├─ Log FATAL error
├─ Update health status: CRITICAL
├─ Do NOT exit (keep old rules running)
└─ Alert administrator immediately (PagerDuty)
```

---

**3. Concurrency Control**

**Purpose:** Prevent multiple simultaneous reloads

**Why Mutex:**
```
Problem: Two events trigger reload simultaneously
Example:
├─ Thread 1: File change → Start reload
├─ Thread 2: API call (ReloadRules) → Start reload
└─ Result: Two reloads running concurrently

Without mutex:
├─ Both threads read old config
├─ Both threads build new rule engine
├─ Thread 1 swaps pointer → New rules active
├─ Thread 2 swaps pointer → Overwrites Thread 1 (data race)
└─ Result: Undefined behavior, potential crash

With mutex:
├─ Thread 1: Acquire mutex → Start reload
├─ Thread 2: Try acquire mutex → Blocked (wait for Thread 1)
├─ Thread 1: Complete reload → Release mutex
├─ Thread 2: Acquire mutex → Start reload (picks up latest config)
└─ Result: Sequential reloads, no data race
```

**Mutex Implementation:**
```
type ReloadManager struct {
  reloadMutex sync.Mutex
}

func (rm *ReloadManager) Reload() error {
  // Non-blocking try lock
  if !rm.reloadMutex.TryLock() {
    log.Warn().Msg("Reload already in progress, skipping")
    return ErrReloadInProgress
  }
  defer rm.reloadMutex.Unlock()

  // Only one thread executes this code at a time
  log.Info().Msg("Starting reload")

  // ... reload logic ...

  log.Info().Msg("Reload complete")
  return nil
}
```

**Queue Next Reload:**
```
Problem: Multiple file changes during reload
├─ 10:00:00: Reload starts (takes 1.2 seconds)
├─ 10:00:00.5: User saves file again (reload in progress)
├─ 10:00:01.2: First reload completes
└─ Second change not reloaded (missed)

Solution: Queue pending reload
├─ If reload in progress: Set flag "reloadPending = true"
├─ When reload completes: Check flag
├─ If flag set: Start new reload immediately
└─ Result: No changes missed

Implementation:
var reloadPending atomic.Bool

func (rm *ReloadManager) Reload() error {
  if !rm.reloadMutex.TryLock() {
    reloadPending.Store(true)  // Queue next reload
    return ErrReloadInProgress
  }
  defer rm.reloadMutex.Unlock()

  // Reload loop (process queued reloads)
  for {
    reloadPending.Store(false)  // Clear flag before reload

    // Perform reload
    err := rm.performReload()
    if err != nil {
      return err
    }

    // Check if another reload queued during this reload
    if !reloadPending.Load() {
      break  // No pending reload, done
    }

    log.Info().Msg("Processing queued reload")
    // Loop again to process queued reload
  }

  return nil
}
```

---

**4. Progress Tracking**

**Purpose:** Report reload progress to users (API, logs)

**Progress Events:**
```
Reload stages:
1. BACKUP_CREATED (10% complete)
2. CONFIG_PARSED (20% complete)
3. RULES_VALIDATED (40% complete)
4. TREE_BUILT (60% complete)
5. WFP_UPDATED (80% complete)
6. SWAPPED (90% complete)
7. CLEANUP (100% complete)

Progress reporting:
- Update progress counter: atomic.StoreUint32(&progress, 40)
- Emit progress event: progressChan <- ProgressEvent{Stage: RULES_VALIDATED, Percent: 40}
- Log progress: log.Info().Str("stage", "RULES_VALIDATED").Msg("Reload progress")
```

**Progress API (gRPC):**
```
RPC method:
rpc GetReloadStatus(GetReloadStatusRequest) returns (stream ReloadStatusResponse);

Client subscribes:
client.GetReloadStatus() → stream of progress events

Server sends progress:
1. BACKUP_CREATED (10%)
2. CONFIG_PARSED (20%)
3. RULES_VALIDATED (40%)
4. TREE_BUILT (60%)
5. WFP_UPDATED (80%)
6. SWAPPED (90%)
7. CLEANUP (100%)

Example:
$ safeops-firewall-cli rules reload --watch

Reloading rules...
[█░░░░░░░░░] 10% - Creating backup
[██░░░░░░░░] 20% - Parsing configuration
[████░░░░░░] 40% - Validating rules
[██████░░░░] 60% - Building rule tree
[████████░░] 80% - Updating WFP filters
[█████████░] 90% - Swapping rule engine
[██████████] 100% - Cleanup complete
Success! Loaded 152 rules in 1.234s
```

---

**5. Reload Statistics**

**Purpose:** Track reload performance and success rate

**Statistics Collected:**
```
Counters:
├─ reload_count: Total reloads attempted
├─ success_count: Successful reloads
├─ failure_count: Failed reloads
└─ rollback_count: Rollbacks performed

Timing:
├─ last_reload_time: Timestamp of last reload
├─ last_reload_duration: How long last reload took
├─ avg_reload_duration: Average reload time
├─ max_reload_duration: Slowest reload
└─ min_reload_duration: Fastest reload

Stage timing (breakdown):
├─ backup_duration: Time to create backup
├─ parse_duration: Time to parse TOML
├─ validate_duration: Time to validate rules
├─ build_duration: Time to build rule tree
├─ wfp_duration: Time to update WFP filters
└─ swap_duration: Time for atomic swap
```

**Metrics Export (Prometheus):**
```
# Total reloads
firewall_reload_total{status="success|failure"} counter

# Reload duration
firewall_reload_duration_seconds histogram

# Last reload time
firewall_reload_last_timestamp gauge

# Reload errors
firewall_reload_last_error{stage="backup|parse|validate|build|wfp|swap"} gauge
```

---

#### Files to Create:
```
internal/hotreload/
├── reloader.go          # Reload manager (orchestrates process)
├── progress.go          # Progress tracking and reporting
├── statistics.go        # Reload statistics collection
└── concurrency.go       # Mutex management, queuing
```

---

### Sub-Task 6.3: Atomic Rule Swap (`internal/hotreload/atomic_swap.go`)

**Purpose:** Swap rule engines with zero packet loss using atomic operations

**Core Concept:**
Atomic pointer swap allows changing rule engine in a single CPU instruction, ensuring no packet sees partial state or experiences delay.

---

#### What to Create:

**1. Atomic Pointer Implementation**

**Purpose:** Use Go's atomic.Value for lock-free rule engine swapping

**Why Atomic Operations:**
```
Traditional approach (mutex):
├─ Lock mutex
├─ ruleEngine = newRuleEngine
├─ Unlock mutex
└─ Problem: Packet threads block on mutex (latency spike)

Atomic approach:
├─ atomic.StorePointer(&ruleEngine, &newRuleEngine)
└─ No blocking (lock-free, wait-free)

Atomic guarantees:
1. Atomicity: Operation completes fully or not at all (no partial writes)
2. Visibility: All threads immediately see new value (no stale reads)
3. Ordering: Operations before/after atomic op are properly ordered
4. Performance: Single CPU instruction (LOCK CMPXCHG on x86)
```

**Implementation:**
```
Rule engine container:
type RuleEngineContainer struct {
  engine atomic.Value  // Holds *rules.Manager
}

Initialization:
container := &RuleEngineContainer{}
container.engine.Store(initialEngine)  // Store initial engine

Read (packet processing):
func (c *RuleEngineContainer) Get() *rules.Manager {
  return c.engine.Load().(*rules.Manager)
}

Write (reload):
func (c *RuleEngineContainer) Set(newEngine *rules.Manager) {
  c.engine.Store(newEngine)  // Atomic swap
}

Usage in packet processing:
func processPacket(pkt *Packet) Verdict {
  engine := ruleEngineContainer.Get()  // Atomic load (lock-free)
  verdict := engine.Match(pkt)         // Match rules
  return verdict
}

Usage in reload:
func reloadRules(newEngine *rules.Manager) {
  ruleEngineContainer.Set(newEngine)  // Atomic store (lock-free)
  log.Info().Msg("Rule engine swapped")
}
```

---

**2. Swap Preparation**

**Purpose:** Prepare new rule engine before swap (validate, test, warm up)

**Pre-Swap Steps:**
```
Step 1: Build New Engine (Background)
├─ Load rules from config file
├─ Build decision tree
├─ Allocate data structures
├─ Time: ~5ms for 1000 rules
└─ Old engine still active (no impact on traffic)

Step 2: Validate New Engine
├─ Sanity checks:
│  ├─ Rule count > 0 (not empty)
│  ├─ All rules parseable
│  ├─ No null pointers
│  └─ Data structures initialized
├─ Test matching:
│  ├─ Create test packet (192.168.1.1 → 8.8.8.8:53)
│  ├─ Match against new engine
│  ├─ Verify verdict returned (ALLOW/DENY)
│  └─ Verify no crash
└─ If validation fails: Abort swap, keep old engine

Step 3: Warm Up New Engine (Optional)
├─ Pre-populate caches (DNS cache, rule cache)
├─ JIT compile rules (if using JIT)
├─ Allocate memory pools (prevent allocation during swap)
└─ Goal: New engine ready for production immediately

Step 4: Checkpoint Old Engine
├─ Store pointer to old engine (for rollback)
├─ oldEngine := ruleEngineContainer.Get()
├─ Keep reference (prevent GC until swap complete)
└─ Rollback: ruleEngineContainer.Set(oldEngine)
```

---

**3. Cache Invalidation**

**Purpose:** Flush verdict cache after rule change (old cached verdicts may be wrong)

**Why Invalidate:**
```
Problem: Cached verdicts based on old rules
Example:
├─ Old rule: "Allow 192.168.1.100 → 8.8.8.8:53" (DNS allowed)
├─ Verdict cached: {"192.168.1.100:8.8.8.8:53" → ALLOW}
├─ New rule: "Deny 192.168.1.100 → 8.8.8.8:53" (DNS blocked)
├─ Cache not flushed: {"192.168.1.100:8.8.8.8:53" → ALLOW} (stale!)
└─ Result: DNS still allowed despite rule change (security bug!)

Solution: Flush cache after rule swap
├─ Old rules active → Cache has verdicts for old rules
├─ Swap to new rules → Flush cache
├─ New rules active → Cache empty (will repopulate with new verdicts)
└─ Result: All verdicts correct
```

**Cache Invalidation Strategies:**
```
Strategy 1: Flush All (Simple, Effective)
├─ cache.FlushAll()
├─ Pros: Simple, guarantees correctness
├─ Cons: Temporary performance drop (cache cold)
└─ Impact: 5-10 seconds for cache to warm up

Strategy 2: Selective Invalidation (Complex, Optimal)
├─ Compare old rules vs new rules
├─ For each changed rule:
│  ├─ Find cached verdicts affected by this rule
│  ├─ Invalidate only those verdicts
│  └─ Keep unaffected verdicts
├─ Pros: Minimal performance impact
├─ Cons: Complex logic, risk of missing cached verdicts
└─ Impact: 1-2 seconds for partial cache warm up

Strategy 3: Lazy Invalidation (TTL-Based)
├─ Don't flush cache immediately
├─ Add TTL to cached verdicts (5 minutes)
├─ After swap: Wait for cache entries to expire naturally
├─ Pros: No performance impact
├─ Cons: Stale verdicts for up to 5 minutes (security risk!)
└─ Not recommended for security-critical firewall

Recommendation: Strategy 1 (Flush All)
- Simple, reliable, correct
- Performance impact acceptable (5-10 seconds)
- No risk of stale verdicts
```

**Flush Implementation:**
```
func (c *cache.Manager) FlushAll() (int, error) {
  c.mutex.Lock()
  defer c.mutex.Unlock()

  // Count entries before flush
  entryCount := len(c.verdicts)

  // Clear map
  c.verdicts = make(map[string]Verdict)

  // Reset statistics
  c.hitRate = 0.0
  c.hits = 0
  c.misses = 0

  log.Info().
    Int("entries_flushed", entryCount).
    Msg("Verdict cache flushed")

  return entryCount, nil
}

Timing:
├─ Before swap: Flush cache (10ms for 100K entries)
├─ During swap: Atomic pointer swap (<1μs)
├─ After swap: Cache empty, will repopulate
└─ Total swap time: ~10ms (99.999% is cache flush, not swap)
```

---

**4. WFP Filter Update**

**Purpose:** Synchronize WFP filters with new rules (dual-engine mode)

**Why Update WFP:**
```
Dual-engine architecture:
├─ SafeOps engine: Uses rule engine (just swapped)
└─ WFP engine: Uses WFP filters (need to update)

If WFP not updated:
├─ SafeOps uses new rules (facebook.com blocked)
├─ WFP uses old rules (facebook.com allowed)
└─ Result: Inconsistent enforcement (WFP allows, SafeOps blocks)

Solution: Update WFP filters during swap
├─ Build new WFP filters from new rules
├─ Delete old WFP filters
├─ Install new WFP filters
├─ Commit transaction (atomic)
└─ Result: Both engines synchronized
```

**WFP Update Process:**
```
Step 1: Start WFP Transaction
├─ FwpmTransactionBegin0(session)
├─ All operations buffered (not committed yet)
└─ Atomic: All succeed or all fail

Step 2: Delete Old Filters
├─ Enumerate current filters (by provider GUID)
├─ For each filter: FwpmFilterDeleteByKey0(session, filterGUID)
├─ Time: ~500ms for 1000 filters
└─ Not committed yet (transaction)

Step 3: Install New Filters
├─ Translate new rules to WFP filters
├─ For each filter: FwpmFilterAdd0(session, &filter, ...)
├─ Time: ~500ms for 1000 filters
└─ Not committed yet (transaction)

Step 4: Commit Transaction
├─ FwpmTransactionCommit0(session)
├─ All changes applied atomically
├─ Time: ~10ms (commit overhead)
└─ Result: New WFP filters active

Step 5: Error Handling
├─ If commit fails: FwpmTransactionAbort0(session)
├─ Old filters remain active (no downtime)
├─ Log error, trigger rollback
└─ Result: WFP unchanged, SafeOps not swapped

Total time: ~1 second for 1000 rules
```

**Optimization (Differential Update):**
```
Problem: Deleting + adding 1000 filters = 1 second (slow)

Optimization: Only update changed filters
├─ Compare old rules vs new rules
├─ Identify:
│  ├─ Added rules (need new WFP filters)
│  ├─ Removed rules (need to delete WFP filters)
│  └─ Unchanged rules (keep WFP filters)
└─ Only update added/removed (faster)

Example:
├─ Old rules: 1000
├─ New rules: 1001 (one added)
├─ Traditional: Delete 1000 + Add 1001 = 2001 operations
├─ Differential: Add 1 = 1 operation (2000× faster!)
└─ Time: ~1ms instead of 1 second

Implementation:
1. Calculate diff:
   ├─ added = new rules - old rules
   ├─ removed = old rules - new rules
   └─ unchanged = old rules ∩ new rules

2. Update only changed:
   ├─ For each added: FwpmFilterAdd0()
   ├─ For each removed: FwpmFilterDeleteByKey0()
   └─ For unchanged: Skip (keep existing filter)

3. Commit transaction

Trade-off:
├─ Pros: 10-100× faster for small changes
├─ Cons: Complex diff algorithm, risk of bugs
└─ Recommendation: Implement for Phase 7 (optimization phase)
```

---

**5. Grace Period**

**Purpose:** Wait for in-flight packets to finish processing before cleanup

**Why Grace Period:**
```
Packet processing timeline:
├─ T+0ms: Packet arrives
├─ T+5ms: Load rule engine (via atomic load)
├─ T+10ms: Match rules (using old engine)
├─ T+15ms: Rule swap happens (new engine active)
├─ T+20ms: Verdict returned (from old engine)
└─ T+25ms: Packet sent

Problem:
├─ T+15ms: New engine active
├─ T+15ms: Old engine freed (GC cleanup)
├─ T+20ms: Old packet tries to access old engine (freed!)
└─ Result: Crash (use-after-free)

Solution: Grace period
├─ T+15ms: New engine active
├─ T+15ms: Start grace period (100ms)
├─ T+20ms: Old packet finishes (using old engine)
├─ T+115ms: Grace period ends
├─ T+115ms: Free old engine (safe now)
└─ Result: No crash (all old packets finished)
```

**Grace Period Implementation:**
```
func (rm *ReloadManager) atomicSwap(newEngine *rules.Manager) error {
  // Store pointer to old engine
  oldEngine := rm.ruleEngineContainer.Get()

  // Atomic swap (instant)
  rm.ruleEngineContainer.Set(newEngine)
  log.Info().Msg("Rule engine swapped (atomic)")

  // Grace period (wait for in-flight packets)
  gracePeriod := 100 * time.Millisecond
  log.Debug().
    Dur("grace_period", gracePeriod).
    Msg("Waiting for in-flight packets to finish")
  time.Sleep(gracePeriod)

  // Now safe to cleanup old engine
  log.Debug().Msg("Grace period ended, old engine can be freed")
  // oldEngine will be garbage collected (no more references)

  return nil
}

Grace period duration:
├─ 10ms: Too short (some packets still in flight)
├─ 50ms: Conservative (most packets finished)
├─ 100ms: Safe (all packets finished) ✓
├─ 1000ms: Overkill (wasted time)
└─ Recommendation: 100ms (balance safety vs speed)
```

---

#### Files to Create:
```
internal/hotreload/
├── atomic_swap.go       # Atomic pointer swap implementation
├── cache_flush.go       # Verdict cache invalidation
├── wfp_sync.go          # WFP filter synchronization
└── grace_period.go      # Grace period management
```

---

### Sub-Task 6.4: Rollback on Error (`internal/hotreload/rollback.go`)

**Purpose:** Restore previous configuration if reload fails

**Core Concept:**
Rollback ensures firewall continues running with old rules if new rules are invalid, preventing downtime and maintaining security.

---

#### What to Create:

**1. Backup Management**

**Purpose:** Create and manage configuration backups for rollback

**Backup Strategy:**
```
Backup naming:
├─ Format: firewall.toml.YYYYMMDD_HHMMSS
├─ Example: firewall.toml.20260122_101530
└─ Timestamp: ISO 8601 (sortable)

Backup location:
├─ Same directory as config file:
│  ├─ /etc/safeops/firewall.toml (current)
│  ├─ /etc/safeops/firewall.toml.20260122_101530 (backup 1)
│  ├─ /etc/safeops/firewall.toml.20260122_095000 (backup 2)
│  └─ /etc/safeops/firewall.toml.20260121_153000 (backup 3)
└─ Alternative: Separate backup directory:
   ├─ /etc/safeops/backups/firewall.toml.20260122_101530
   └─ Keeps main directory clean

Backup retention:
├─ Keep last 10 backups (rotating window)
├─ Delete backups older than 7 days
└─ Compress old backups (gzip) to save space

Backup verification:
├─ After creating backup: Read back and compare checksum
├─ If checksum mismatch: Backup corrupted, abort reload
└─ Ensures backup is actually usable for rollback
```

**Backup Implementation:**
```
func (rm *ReloadManager) createBackup() (string, error) {
  // Generate backup filename
  timestamp := time.Now().Format("20060102_150405")
  backupPath := fmt.Sprintf("%s.%s", rm.configPath, timestamp)

  // Read current config
  data, err := os.ReadFile(rm.configPath)
  if err != nil {
    return "", fmt.Errorf("failed to read config: %w", err)
  }

  // Write backup
  err = os.WriteFile(backupPath, data, 0644)
  if err != nil {
    return "", fmt.Errorf("failed to write backup: %w", err)
  }

  // Verify backup (read back)
  backupData, err := os.ReadFile(backupPath)
  if err != nil {
    return "", fmt.Errorf("failed to verify backup: %w", err)
  }

  // Compare checksums
  originalHash := sha256.Sum256(data)
  backupHash := sha256.Sum256(backupData)
  if originalHash != backupHash {
    return "", fmt.Errorf("backup corrupted (checksum mismatch)")
  }

  log.Info().
    Str("backup_path", backupPath).
    Msg("Backup created successfully")

  return backupPath, nil
}
```

---

**2. Rollback Process**

**Purpose:** Restore previous configuration and rule engine state

**Rollback Steps:**
```
Step 1: Detect Failure
├─ Validation error (invalid rule syntax)
├─ Build error (rule tree construction failed)
├─ WFP error (filter installation failed)
└─ Trigger rollback

Step 2: Log Error Details
├─ Log what failed (validation, build, WFP)
├─ Log error message (detailed)
├─ Log config file path
├─ Log backup path
└─ Update metrics (firewall_reload_failure_total)

Step 3: Restore Config File (Optional)
├─ Copy backup → current config
├─ cp firewall.toml.20260122_101530 firewall.toml
├─ Purpose: Revert file to known-good state
└─ User can re-edit from good state

Step 4: Keep Old Engine Active
├─ DO NOT swap rule engines
├─ Old engine still active (no swap happened)
├─ No action needed (old rules never replaced)
└─ Result: Firewall continues with old rules (no downtime)

Step 5: Alert Administrator
├─ Log ERROR-level message
├─ Update health status: DEGRADED
├─ Emit alert (PagerDuty, Slack, email)
├─ Alert message: "Config reload failed: <error>"
└─ Admin notified to fix config

Step 6: Clean Up
├─ Release reload lock (allow future reloads)
├─ Update state: ROLLING_BACK → IDLE
├─ Update metrics
└─ Wait for user to fix config and save
```

**Rollback Implementation:**
```
func (rm *ReloadManager) rollback(backupPath string, err error) error {
  log.Error().
    Err(err).
    Str("backup_path", backupPath).
    Msg("Reload failed, rolling back")

  // Update metrics
  rm.metrics.IncrementCounter("firewall_reload_failure_total")
  rm.metrics.SetGauge("firewall_reload_last_error", 1)
  rm.lastError = err.Error()

  // Restore config file from backup (optional)
  if rm.config.RestoreOnFailure {
    err := rm.restoreFromBackup(backupPath)
    if err != nil {
      log.Error().
        Err(err).
        Msg("Failed to restore config from backup")
      // Continue (not critical - old engine still active)
    } else {
      log.Info().Msg("Config file restored from backup")
    }
  }

  // Old engine still active (no swap happened, nothing to roll back)
  log.Info().Msg("Old rules still active (no downtime)")

  // Alert administrator
  if rm.alerter != nil {
    rm.alerter.SendAlert(AlertLevelWarning, fmt.Sprintf("Config reload failed: %v", err))
  }

  // Update health status
  rm.health.SetComponentHealth("reload", HealthDegraded, err.Error())

  return nil
}
```

---

**3. Partial Rollback (WFP)**

**Purpose:** If WFP update fails after SafeOps swap, rollback WFP only

**Scenario:**
```
Reload sequence:
1. Build new rule engine ✓ Success
2. Swap SafeOps rule engine ✓ Success (atomic)
3. Update WFP filters ❌ Failed (Windows API error)

Problem:
├─ SafeOps using new rules (swapped)
├─ WFP using old rules (not swapped)
└─ Result: Inconsistent state (engines diverged)

Solution: Partial rollback
├─ Rollback SafeOps: Swap back to old engine (atomic)
├─ Keep WFP: Old filters still active
└─ Result: Both engines using old rules (consistent)
```

**Partial Rollback Implementation:**
```
func (rm *ReloadManager) performReload() error {
  // ... backup, validate, build ...

  // Store old engine (for rollback)
  oldEngine := rm.ruleEngineContainer.Get()

  // Swap SafeOps engine
  rm.ruleEngineContainer.Set(newEngine)
  log.Info().Msg("SafeOps engine swapped")

  // Update WFP filters
  err := rm.wfpEngine.UpdateFilters(newRules)
  if err != nil {
    // WFP update failed!
    log.Error().Err(err).Msg("WFP update failed, rolling back SafeOps")

    // Rollback: Swap back to old engine
    rm.ruleEngineContainer.Set(oldEngine)
    log.Info().Msg("SafeOps engine rolled back")

    // Both engines now using old rules (consistent)
    return fmt.Errorf("WFP update failed: %w", err)
  }

  log.Info().Msg("WFP filters updated successfully")
  return nil
}
```

---

**4. Validation Before Swap**

**Purpose:** Detect errors early (before swap) to avoid rollback

**Validation Checks:**
```
Pre-swap validation (catch errors early):
1. TOML syntax check:
   ├─ Parse TOML file
   ├─ If parse error: Reject config (before any changes)
   └─ Example: Missing quote, trailing comma

2. Rule syntax validation:
   ├─ For each rule: Check all required fields present
   ├─ Check field types (port = int, action = string)
   ├─ Check field values (port 1-65535, action in ALLOW/DENY/DROP)
   └─ Example: dst_port = "abc" (should be integer)

3. Rule semantic validation:
   ├─ Check for conflicts (two rules with same name)
   ├─ Check for impossible rules (dst_port = 0, invalid CIDR)
   ├─ Check for circular dependencies (if using rule groups)
   └─ Example: src_address = "256.1.1.1" (invalid IP)

4. Test matching:
   ├─ Create test packet
   ├─ Match against new engine
   ├─ Verify verdict returned (not crash)
   └─ Example: Malformed rule causes panic (caught here)

5. Resource checks:
   ├─ Estimate memory usage (new engine)
   ├─ Check if sufficient memory available
   ├─ If memory low: Reject config (prevent OOM)
   └─ Example: 10,000 rules = 500MB (have 1GB free, OK)

If any validation fails:
├─ Reject config immediately (no swap)
├─ Log detailed error
├─ Keep old engine active
└─ No rollback needed (nothing changed yet)
```

**Validation Implementation:**
```
func (rm *ReloadManager) validateConfig(config *Config) error {
  // 1. Syntax validation
  if err := config.Validate(); err != nil {
    return fmt.Errorf("config validation failed: %w", err)
  }

  // 2. Build rule engine (test)
  testEngine, err := rules.NewManager(config.Rules)
  if err != nil {
    return fmt.Errorf("failed to build rule engine: %w", err)
  }

  // 3. Test matching (sanity check)
  testPacket := &Packet{
    SrcIP: "192.168.1.1",
    DstIP: "8.8.8.8",
    DstPort: 53,
    Protocol: "UDP",
  }

  _, err = testEngine.Match(testPacket)
  if err != nil {
    return fmt.Errorf("rule matching test failed: %w", err)
  }

  // 4. Resource check
  estimatedMemory := testEngine.EstimateMemoryUsage()
  if estimatedMemory > rm.maxMemoryUsage {
    return fmt.Errorf("config exceeds memory limit: %d bytes", estimatedMemory)
  }

  // All validations passed
  return nil
}
```

---

**5. Emergency Rollback**

**Purpose:** Manual rollback command for disaster recovery

**Use Case:**
```
Scenario: Rules reloaded, but causing issues
├─ New rules deployed (syntax valid)
├─ Unexpected behavior (blocking legitimate traffic)
├─ Need to rollback immediately (emergency)
└─ Admin triggers manual rollback

CLI command:
$ safeops-firewall-cli rules rollback --to=20260122_101530

Rollback process:
1. Find backup: firewall.toml.20260122_101530
2. Copy backup → current config
3. Trigger reload (load old rules)
4. Log rollback action
5. Alert: "Manual rollback to 20260122_101530"
```

**Emergency Rollback Implementation:**
```
CLI command handler:
func rollbackCommand(timestamp string) error {
  // Find backup file
  backupPath := fmt.Sprintf("/etc/safeops/firewall.toml.%s", timestamp)
  if !fileExists(backupPath) {
    return fmt.Errorf("backup not found: %s", backupPath)
  }

  // Call gRPC API
  client := firewall.NewManagementClient(conn)
  req := &pb.RollbackRequest{
    BackupTimestamp: timestamp,
  }

  resp, err := client.RollbackConfig(ctx, req)
  if err != nil {
    return fmt.Errorf("rollback failed: %w", err)
  }

  fmt.Printf("Rollback successful!\n")
  fmt.Printf("Rules loaded: %d\n", resp.RulesLoaded)
  fmt.Printf("Rollback time: %s\n", resp.RollbackTime)
  return nil
}

Server implementation:
func (s *managementServer) RollbackConfig(ctx context.Context, req *pb.RollbackRequest) (*pb.RollbackResponse, error) {
  // Find backup
  backupPath := fmt.Sprintf("%s.%s", s.configPath, req.BackupTimestamp)

  // Restore config from backup
  err := copyFile(backupPath, s.configPath)
  if err != nil {
    return nil, status.Errorf(codes.Internal, "failed to restore backup: %v", err)
  }

  // Trigger reload
  err = s.reloadManager.Reload()
  if err != nil {
    return nil, status.Errorf(codes.Internal, "reload failed: %v", err)
  }

  // Success
  return &pb.RollbackResponse{
    Success: true,
    RulesLoaded: int32(s.ruleManager.GetRuleCount()),
    RollbackTime: time.Now().Format(time.RFC3339),
  }, nil
}
```

---

#### Files to Create:
```
internal/hotreload/
├── rollback.go          # Rollback orchestration
├── backup.go            # Backup creation and management
├── restore.go           # Config file restoration
└── validation.go        # Pre-swap validation checks
```

---

## 📊 Phase 6 Success Criteria

**By end of Phase 6, the firewall must demonstrate:**

1. ✅ **File Watcher Working:**
   - Detects config file changes within 1 second
   - Debouncing prevents multiple reloads (1 second debounce)
   - Multi-file watching (main config + includes)
   - Watcher health monitoring (detects failures)

2. ✅ **Zero-Downtime Reload:**
   - Edit firewall.toml, rules update without restart
   - No packet loss during reload (iperf3 test)
   - No latency spike (p99 latency unchanged)
   - Atomic swap completes in <10ms

3. ✅ **Validation & Rollback:**
   - Invalid config rejected (keeps old rules)
   - Detailed error messages (tells user what's wrong)
   - Backup created before every reload
   - Manual rollback command working

4. ✅ **Performance:**
   - Reload time <2 seconds (1000 rules)
   - Cache flush <100ms (100K entries)
   - WFP update <1 second (1000 filters)
   - Grace period 100ms (no crashes)

5. ✅ **Integration:**
   - gRPC API: ReloadRules() working
   - CLI tool: `safeops-firewall-cli rules reload`
   - Metrics: firewall_reload_total, firewall_reload_duration_seconds
   - Logging: Detailed reload progress logs

---

## 🚀 Next Steps After Phase 6

After Phase 6 completion, proceed to:
- **Phase 7:** Security Features (DDoS protection, rate limiting, GeoIP blocking)
- **Phase 8:** Testing & Benchmarking (stress tests, integration tests, performance tuning)
- **Phase 9:** Production Deployment (Kubernetes, Docker, systemd service)

**Estimated Total Time for Phase 6:** 1.5 weeks

---

**END OF PHASE 6 DOCUMENTATION**
