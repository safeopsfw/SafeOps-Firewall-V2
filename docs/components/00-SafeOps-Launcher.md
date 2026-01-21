# SafeOps Launcher Documentation

## Overview
The SafeOps Launcher is the unified service orchestrator that starts and manages all SafeOps components with a single command. It provides graceful startup, monitoring, and shutdown of all services.

## Component Information

**Component Type:** Service Orchestrator
**Language:** Go 1.24.0
**Executable:** `bin/SafeOps-Launcher.exe`
**Version:** 1.0.0

## Files and Locations

### Source Files
```
D:\SafeOpsFV2\cmd\safeops_launcher\
└── main.go                    # Main launcher application
```

### Binary/Executable Files
```
D:\SafeOpsFV2\bin\
└── SafeOps-Launcher.exe       # Main executable
```

## Functionality

### Purpose
The launcher provides a single entry point to start all SafeOps services in the correct order with proper error handling and graceful shutdown.

### Managed Services

The launcher starts the following services in order:

1. **PostgreSQL Database**
   - Port: 5432
   - Command: `pg_ctl start -D "C:/Program Files/PostgreSQL/16/data"`
   - Purpose: Data persistence layer

2. **NIC Management API**
   - Port: 8081
   - Command: `go run ./cmd/...` in `src/nic_management`
   - Purpose: Network interface management

3. **DHCP Server**
   - Port: 67
   - Command: `go run ./cmd/main.go` in `src/dhcp_server`
   - Purpose: DHCP services

4. **Threat Intel API**
   - Port: 8080
   - Command: `go run ./cmd/server/main.go` in `src/threat_intel`
   - Purpose: Threat intelligence feeds

5. **Frontend Dev Server**
   - Port: 3003
   - Command: `npm run dev` in `src/ui/dev`
   - Purpose: Web UI development server

## Starting Services

### Quick Start
```cmd
cd D:\SafeOpsFV2
.\bin\SafeOps-Launcher.exe
```

### What Happens
1. Banner displays with SafeOps branding
2. Services start sequentially with 500ms stagger
3. Status display shows all running services
4. Launcher waits for shutdown signal (Ctrl+C)

### Service Startup Output
```
🚀 Starting SafeOps services...
▶️  Starting PostgreSQL Database on port 5432...
✅ PostgreSQL Database started (PID: 1234)
▶️  Starting NIC Management API on port 8081...
✅ NIC Management API started (PID: 2345)
▶️  Starting DHCP Server on port 67...
✅ DHCP Server started (PID: 3456)
▶️  Starting Threat Intel API on port 8080...
✅ Threat Intel API started (PID: 4567)
▶️  Starting Frontend Dev Server on port 3003...
✅ Frontend Dev Server started (PID: 5678)
```

## Stopping Services

### Graceful Shutdown
Press **Ctrl+C** to initiate graceful shutdown:

```
^C
🛑 Shutting down SafeOps services...
⏹️  Stopping Frontend Dev Server...
⏹️  Stopping Threat Intel API...
⏹️  Stopping DHCP Server...
⏹️  Stopping NIC Management API...
⏹️  Stopping PostgreSQL Database...
✅ All services stopped. Goodbye!
```

## Access Points

After startup, services are available at:

- **NIC Management API:** http://localhost:8081/api/nics
- **Frontend Dev UI:** http://localhost:3003
- **Threat Intel API:** http://localhost:8080
- **DHCP Server:** UDP port 67 (internal)
- **PostgreSQL:** localhost:5432

## Features

### Service Management
- **Sequential Startup:** Services start in dependency order
- **Staggered Start:** 500ms delay between services
- **Process Monitoring:** Tracks PIDs and status
- **Graceful Shutdown:** Properly terminates all services
- **Error Handling:** Reports failed starts

### Banner Display
Shows ASCII art SafeOps logo and version information on startup.

### Status Display
After startup, shows:
- Service names
- Running status (🟢/🔴)
- Port numbers
- Access URLs

## Technical Details

### Implementation
- **Language:** Go
- **Concurrency:** Goroutines for each service
- **Signal Handling:** SIGINT, SIGTERM for shutdown
- **Context Management:** Graceful cancellation
- **Wait Groups:** Ensures all services complete

### Process Management
Each service:
- Runs in separate goroutine
- Has dedicated exec.Cmd process
- Outputs to stdout/stderr
- Tracked by PID
- Monitored for termination

## Configuration

### Project Root Detection
The launcher automatically finds the project root by:
1. Checking current directory for "SafeOpsFV2"
2. Looking for `go.work` file
3. Walking up parent directories
4. Falling back to `D:\SafeOpsFV2`

### Service Definitions
Services are defined in the `services` array with:
- **Name:** Display name
- **Dir:** Working directory (relative to project root)
- **Command:** Executable to run
- **Args:** Command-line arguments
- **Port:** Service port number
- **Env:** Environment variables (optional)

## Important Notes

### Prerequisites
- PostgreSQL installed at `C:/Program Files/PostgreSQL/16/`
- Go 1.24.0+ installed
- Node.js and npm installed
- All source directories present

### Limitations
- Development mode only (runs `go run` and `npm run dev`)
- No production build support
- No service restart on failure
- No log file rotation
- Services must be manually configured

### Troubleshooting

**Service Fails to Start:**
- Check if port is already in use
- Verify source directory exists
- Check command is correct
- View error output in console

**Launcher Won't Stop:**
- Press Ctrl+C again
- Kill process manually if needed
- Check for hung child processes

## Connection to Other Components

The launcher orchestrates:
- **NIC Management:** Network interface control
- **DHCP Server:** IP address assignment
- **Threat Intel:** Security feed aggregation
- **Frontend UI:** User interface
- **PostgreSQL:** Data storage for all components

## Future Enhancements

- Production build support
- Service health monitoring
- Automatic restart on failure
- Log file management
- Configuration file support
- Windows service installation
- Systemd integration for Linux

---

**Status:** Development/Testing
**Auto-Start:** Manual execution
**Dependencies:** PostgreSQL, Go, Node.js
**Managed By:** Direct execution
