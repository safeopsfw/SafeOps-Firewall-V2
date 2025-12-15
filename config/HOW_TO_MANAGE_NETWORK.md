# Managing Network Infrastructure via SafeOps Windows Application

## Overview
This guide explains how to manage network infrastructure (switches, VLANs, ISPs, etc.) using the **SafeOps Windows Desktop Application** - a native Windows app built with Wails (Go + React).

## ============================================================================
## SafeOps Windows Application
## ============================================================================

### Installation

```powershell
# Download from releases
Invoke-WebRequest -Uri https://releases.safeops.io/windows/latest/SafeOps-Setup.exe -OutFile SafeOps-Setup.exe

# Run installer
.\SafeOps-Setup.exe

# Or use winget
winget install SafeOps.SafeOps
```

### First Launch

1. **Open SafeOps** from Start Menu or Desktop
2. **Connect to Backend**
   - Server: `localhost:50051` (local)
   - Or: `safeops-server.local:50051` (remote)
3. **Authenticate**
   - Username: `admin`
   - Password: (set during installation)
   - Optional: Enable Windows Hello biometric auth

### Application Features

- ✅ **Native Windows UI** (not browser-based)
- ✅ **Offline Mode** (view-only when disconnected)
- ✅ **Real-time Updates** (via gRPC streaming)
- ✅ **Dark/Light Theme**
- ✅ **Keyboard Shortcuts** (Ctrl+N for new, Ctrl+E for edit, etc.)
- ✅ **Network Topology Visualization**
- ✅ **Configuration Validation** (before saving)
- ✅ **Auto-backup** (before changes)

## ============================================================================
## Managing Switches
## ============================================================================

### Adding a New Switch

1. **Navigate**: Click `Network` → `Switches` in sidebar
2. **Click**: `Add Switch` button (or press `Ctrl+N`)
3. **Fill Form**:
   ```
   ╔══════════════════════════════════════════╗
   ║   Add Network Switch                     ║
   ╠══════════════════════════════════════════╣
   ║ Name: *          [office-sw-04        ]  ║
   ║ Type:            [Access ▼]              ║
   ║ Model:           [HP Aruba 2930F      ]  ║
   ║ Management IP: * [192.168.100.14      ]  ║
   ║ Location:        [Office Floor 4      ]  ║
   ║ Port Count:      [24                  ]  ║
   ║ VLANs:           [10, 100            ]↕  ║
   ║ Connected To:    [core-sw-01         ]↕  ║
   ║ ☑ PoE Enabled                            ║
   ║ ☐ Link Aggregation                       ║
   ║                                          ║
   ║    [Validate]  [Cancel]  [Save & Apply]  ║
   ╚══════════════════════════════════════════╝
   ```

4. **Validation**: App validates in real-time:
   - ✅ IP uniqueness check
   - ✅ VLAN existence check
   - ✅ Name format validation
   - ❌ Shows errors inline

5. **Save**: Click `Save & Apply`
   - Auto-generates configuration
   - Updates network topology
   - Refreshes IDS/IPS variables
   - Adds to monitoring

### Editing an Existing Switch

1. **Navigate**: `Network` → `Switches`
2. **Find Switch**: Use search box or browse list
3. **Double-click** switch or click `Edit` button
4. **Edit Dialog Opens**:
   ```
   ╔══════════════════════════════════════════╗
   ║   Edit Switch: office-sw-01              ║
   ╠══════════════════════════════════════════╣
   ║ Name:            [office-sw-01        ]  ║ (read-only)
   ║ Type:            [Access ▼]              ║
   ║ Model:           [HP Aruba 2930F      ]  ║
   ║ Management IP:   [192.168.100.11___   ]  ║ ← Edit here
   ║ Location:        [Office Floor 1      ]  ║
   ║ Port Count:      [24                  ]  ║
   ║ VLANs:           [10, 100            ]↕  ║ ← Modify
   ║                  [+ Add VLAN]            ║
   ║ Connected To:    [core-sw-01         ]↕  ║
   ║ ☑ PoE Enabled                            ║
   ║ ☑ Link Aggregation                       ║ ← Changed
   ║                                          ║
   ║ Status: ● Online  Uptime: 45d 12h       ║
   ║                                          ║
   ║  [Validate]  [Cancel]  [Save Changes]    ║
   ╚══════════════════════════════════════════╝
   ```

5. **Make Changes**: Modify any field
6. **Preview Impact**: Click `Preview` to see what will change
7. **Save**: Click `Save Changes`
   - Creates backup of old config
   - Applies new configuration
   - Verifies switch is still reachable
   - Shows success notification

### Bulk Edit Switches

1. **Select Multiple**: Hold `Ctrl` and click switches
2. **Right-click** → `Bulk Edit`
3. **Bulk Edit Dialog**:
   ```
   ╔══════════════════════════════════════════╗
   ║   Bulk Edit (3 switches selected)        ║
   ╠══════════════════════════════════════════╣
   ║ Change:                                  ║
   ║ ○ Add VLAN                               ║
   ║ ● Remove VLAN                            ║
   ║ ○ Update Location                        ║
   ║ ○ Enable/Disable Feature                 ║
   ║                                          ║
   ║ VLAN to Remove: [30 ▼]                   ║
   ║                                          ║
   ║ Will affect:                             ║
   ║   • office-sw-01                         ║
   ║   • office-sw-02                         ║
   ║   • office-sw-03                         ║
   ║                                          ║
   ║     [Preview]  [Cancel]  [Apply to All]  ║
   ╚══════════════════════════════════════════╝
   ```

### Visual Network Topology

Click `Network` → `Topology View` to see:
- ✅ Interactive network diagram
- ✅ Drag-and-drop to rearrange
- ✅ Color-coded by status (green=up, red=down)
- ✅ Click any device to edit
- ✅ Right-click for quick actions

```
        ┌─────────┐
        │  WAN 1  │ (Green)
        └────┬────┘
             │
        ┌────┴────┐
        │ Core    │ (Green)
        │ SW-01   │
        └──┬───┬──┘
     ┌─────┘   └─────┐
 ┌───┴───┐       ┌───┴───┐
 │Office │       │Server │
 │ SW-01 │(Red)  │ SW-01 │(Green)
 └───────┘       └───────┘
```

## ============================================================================
## Managing Network Segments (VLANs)
## ============================================================================

### Adding a VLAN

1. **Navigate**: `Network` → `VLANs`
2. **Click**: `Add VLAN` (or press `Ctrl+N`)
3. **Wizard Opens**:

**Step 1: Basic Info**
```
╔══════════════════════════════════════════╗
║   Add VLAN (Step 1 of 3)                 ║
╠══════════════════════════════════════════╣
║ VLAN ID: *       [60     ]   (1-4094)    ║
║ Name: *          [Development          ] ║
║ Description:     [Dev team network     ] ║
║ Zone:            [Trusted ▼]             ║
║ Security Level:  [Medium ▼]              ║
║                                          ║
║              [Cancel]  [Next >]          ║
╚══════════════════════════════════════════╝
```

**Step 2: IP Configuration**
```
╔══════════════════════════════════════════╗
║   Add VLAN (Step 2 of 3)                 ║
╠══════════════════════════════════════════╣
║ Subnet: *        [192.168.60.0/24     ]  ║
║ Gateway:         [192.168.60.1        ]  ║
║                                          ║
║ DHCP Settings:                           ║
║ ☑ Enable DHCP                            ║
║   Range Start:   [192.168.60.100      ]  ║
║   Range End:     [192.168.60.200      ]  ║
║   Lease Time:    [24 ▼] hours            ║
║   DNS Servers:   [192.168.60.1        ]  ║
║                  [+ Add DNS]             ║
║                                          ║
║         [< Back]  [Cancel]  [Next >]     ║
╚══════════════════════════════════════════╝
```

**Step 3: Access Control**
```
╔══════════════════════════════════════════╗
║   Add VLAN (Step 3 of 3)                 ║
╠══════════════════════════════════════════╣
║ Access Permissions:                      ║
║ ☑ Allow Internet Access                 ║
║ ☑ Allow Server Network (VLAN 20)        ║
║ ☐ Allow Management Network (VLAN 100)   ║
║ ☐ Isolated (No inter-VLAN routing)      ║
║                                          ║
║ Bandwidth Limit:                         ║
║ ☐ Enable   [_____] Mbps                 ║
║                                          ║
║ Firewall Rules:                          ║
║   Auto-generate zone-based rules         ║
║                                          ║
║    [< Back]  [Cancel]  [Finish & Apply]  ║
╚══════════════════════════════════════════╝
```

4. **Review**: Shows summary of changes
5. **Apply**: Creates VLAN, DNS zone, DHCP scope, firewall rules

### Editing a VLAN

1. **Navigate**: `Network` → `VLANs`
2. **Select VLAN** from list
3. **Click Edit** or press `F2`
4. **Tabbed Edit Dialog**:
   ```
   ╔══════════════════════════════════════════╗
   ║   Edit VLAN: Development (60)            ║
   ╠══════════════════════════════════════════╣
   ║ [General] [IP Config] [DHCP] [Firewall]  ║
   ╠══════════════════════════════════════════╣
   ║ VLAN ID:         60 (read-only)          ║
   ║ Name:            [Development          ] ║
   ║ Description:     [Dev team network     ] ║
   ║ Zone:            [Trusted ▼]             ║
   ║ Security Level:  [High ▼]     ← Changed  ║
   ║                                          ║
   ║ Active Devices:  12                      ║
   ║ DHCP Leases:     8 / 100                 ║
   ║ Traffic (24h):   ▓▓▓▓░░░░ 45 GB         ║
   ║                                          ║
   ║     [Cancel]  [Save Changes]             ║
   ╚══════════════════════════════════════════╝
   ```

5. **Switch Tabs** to edit different aspects
6. **Save** when done

### VLAN Dashboard

View real-time stats:
```
╔═══════════════════════════════════════════════════════╗
║ VLAN 10 - Office Main                                 ║
╠═══════════════════════════════════════════════════════╣
║ Status: ● Active    Devices: 145 / 200               ║
║                                                       ║
║ Traffic:                                              ║
║   Inbound:  ▓▓▓▓▓▓▓▓░░  85 Mbps                      ║
║   Outbound: ▓▓▓▓░░░░░░  42 Mbps                      ║
║                                                       ║
║ Top Talkers:                                          ║
║   1. 192.168.10.105   15 GB  (workstation-42)        ║
║   2. 192.168.10.087   12 GB  (laptop-finance)        ║
║   3. 192.168.10.143    8 GB  (desktop-marketing)     ║
║                                                       ║
║ [View Details]  [Edit]  [Block Device]               ║
╚═══════════════════════════════════════════════════════╝
```

## ============================================================================
## Managing WAN Connections (ISPs)
## ============================================================================

### Adding ISP Connection

1. **Navigate**: `Network` → `WAN Connections`
2. **Click**: `Add ISP`
3. **Form**:
   ```
   ╔══════════════════════════════════════════╗
   ║   Add WAN Connection                     ║
   ╠══════════════════════════════════════════╣
   ║ Name: *          [ISP-Backup-2        ]  ║
   ║ Provider:        [Verizon             ]  ║
   ║ Interface:       [eth3 ▼]               ║
   ║ Type:            [Fiber ▼]              ║
   ║ Bandwidth:       [500    ] Mbps         ║
   ║                                          ║
   ║ IP Configuration:                        ║
   ║ ○ Static IP      ● DHCP    ○ PPPoE      ║
   ║                                          ║
   ║ Priority:        [4      ] (1=highest)   ║
   ║ Failover Group:  [Backup ▼]             ║
   ║ Load Balance:    [20     ] % weight     ║
   ║                                          ║
   ║ Monitoring:                              ║
   ║ ☑ Enable Health Checks                   ║
   ║   Ping Target:   [8.8.8.8             ]  ║
   ║   Check Every:   [30     ] seconds       ║
   ║                                          ║
   ║      [Test Connection]                   ║
   ║      [Cancel]  [Save & Activate]         ║
   ╚══════════════════════════════════════════╝
   ```

4. **Test**: Click `Test Connection` to verify
5. **Save**: Adds to load balancing pool

### Editing ISP Settings

1. **Navigate**: `Network` → `WAN Connections`
2. **Select ISP**, click `Edit`
3. **Live Monitoring While Editing**:
   ```
   ╔══════════════════════════════════════════╗
   ║   Edit WAN: ISP-Primary                  ║
   ╠══════════════════════════════════════════╣
   ║ Status: ● UP     Latency: 12ms           ║
   ║ Uptime: 45d 12h  Packet Loss: 0.1%       ║
   ║                                          ║
   ║ [General] [IP Config] [Monitoring]       ║
   ╠══════════════════════════════════════════╣
   ║ Name:            [ISP-Primary          ] ║
   ║ Priority:        [1      ] ← Change to 2 ║
   ║ Load Balance:    [50     ] %             ║
   ║                                          ║
   ║ Traffic (24h):                           ║
   ║   ▓▓▓▓▓▓▓▓▓▓ 450 GB sent                ║
   ║   ▓▓▓▓▓▓░░░░ 280 GB received             ║
   ║                                          ║
   ║     [Test Now]  [Cancel]  [Save]         ║
   ╚══════════════════════════════════════════╝
   ```

## ============================================================================
## Configuration Management Features
## ============================================================================

### Configuration Backup

**Automatic Backups:**
- Before any change
- Daily at 2 AM
- Before updates

**View Backups:**
1. `File` → `Configuration Backups`
2. See list of backups with timestamps
3. Click to preview differences
4. Click `Restore` to rollback

```
╔══════════════════════════════════════════════════════╗
║ Configuration Backups                                ║
╠══════════════════════════════════════════════════════╣
║ Date/Time           Type        Size    Description  ║
║ 2025-12-13 14:30    Auto        2.5 MB  ✓ Verified  ║
║ 2025-12-13 02:00    Scheduled   2.5 MB  ✓ Verified  ║
║ 2025-12-12 16:45    Manual      2.4 MB  ✓ Verified  ║
║ 2025-12-12 02:00    Scheduled   2.4 MB  ✓ Verified  ║
║                                                      ║
║ Selected: 2025-12-13 14:30 (Before switch edit)     ║
║                                                      ║
║  [View Diff]  [Restore]  [Export]  [Delete]         ║
╚══════════════════════════════════════════════════════╝
```

### Configuration Import/Export

**Export Current Config:**
```
File → Export Configuration
Choose format:
  ○ YAML (Human-readable)
  ● TOML (SafeOps native)
  ○ JSON (API compatible)

☑ Include credentials (encrypted)
☐ Include secrets
☑ Include network topology
☑ Include firewall rules

[Export to File...]
```

**Import Config:**
```
File → Import Configuration
[Browse...] → Select file
Preview changes:
  + 5 switches to be added
  ~ 2 VLANs to be modified
  - 1 ISP to be removed
  
☑ Create backup before import
☑ Validate before applying
○ Merge with existing
● Replace existing

[Cancel]  [Import & Apply]
```

### Bulk Operations

**CSV Import:**
```powershell
# Prepare CSV
Name,Type,ManagementIP,Location,VLANs
library-sw-03,ACCESS,192.168.100.33,Library Floor 3,"10,100"
lab-sw-01,ACCESS,192.168.100.51,Computer Lab,"10,100"
```

**In App:**
1. `Tools` → `Import from CSV`
2. Select file
3. Map columns
4. Preview
5. Import

## ============================================================================
## Application Settings
## ============================================================================

### Preferences

`Edit` → `Preferences` or `Ctrl+,`

```
╔══════════════════════════════════════════╗
║   SafeOps Preferences                    ║
╠══════════════════════════════════════════╣
║ [General] [Network] [Security] [Updates] ║
╠══════════════════════════════════════════╣
║ Appearance:                              ║
║   Theme: ● Dark  ○ Light  ○ System       ║
║   Font Size: [Medium ▼]                  ║
║                                          ║
║ Behavior:                                ║
║   ☑ Confirm before deleting              ║
║   ☑ Auto-save changes                    ║
║   ☑ Show notifications                   ║
║   ☐ Minimize to system tray              ║
║                                          ║
║ Auto-Backup:                             ║
║   ☑ Before changes                       ║
║   ☑ Daily at [02:00]                     ║
║   Retention: [90] days                   ║
║                                          ║
║       [Cancel]  [Apply]  [OK]            ║
╚══════════════════════════════════════════╝
```

## ============================================================================
## Keyboard Shortcuts
## ============================================================================

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New (switch/VLAN/etc.) |
| `Ctrl+E` or `F2` | Edit selected item |
| `Ctrl+D` or `Delete` | Delete selected item |
| `Ctrl+F` | Search/Filter |
| `Ctrl+R` | Refresh view |
| `Ctrl+S` | Save current changes |
| `Ctrl+Z` | Undo last change |
| `Ctrl+,` | Open Preferences |
| `F5` | Refresh data from server |
| `F11` | Toggle fullscreen |

## ============================================================================
## Integration with Backend
## ============================================================================

The Windows app communicates with backend via:

**gRPC Streaming:**
- Real-time updates pushed to app
- No polling needed
- Low latency (<10ms locally)

**Configuration Files:**
- App can read/write to `config/network_topology.yaml` directly
- Or use gRPC API for managed access
- Changes auto-sync to database

**Offline Mode:**
- View cached data when disconnected
- Edit mode disabled
- Auto-reconnect when available

## ============================================================================
## Troubleshooting
## ============================================================================

### App Won't Connect to Backend

1. Check `Settings` → `Connection`
2. Verify server address: `localhost:50051`
3. Test connection: Click `Test Connection`
4. Check firewall: Allow port 50051
5. View logs: `Help` → `View Logs`

### Changes Not Saving

1. Check permissions: Run as Administrator
2. Verify config file writable
3. Check disk space
4. View error log in status bar

### Performance Issues

1. Reduce polling frequency: `Preferences` → `Network` → `Update interval`
2. Clear cache: `Tools` → `Clear Cache`
3. Check system resources in Task Manager
4. Disable real-time topology if network is large (>100 devices)

## ============================================================================
## References
## ============================================================================

- User Manual: `Help` → `User Manual` in app
- API Documentation: `/docs/api/network_manager.md`
- gRPC Proto: `/proto/network_manager.proto`
- Configuration Examples: `/config/examples/`
- Video Tutorials: `Help` → `Video Tutorials`
