#!/bin/bash
#############################################################################
# NIC Management Service - Linux Installation Script
#
# Description:
#   Automated installation script for NIC Management service on Linux
#   - Checks prerequisites (root, systemd, kernel version)
#   - Creates service user
#   - Installs binary with capabilities
#   - Creates systemd service unit
#   - Configures security hardening
#
# Usage:
#   sudo ./install_linux.sh [OPTIONS]
#
# Options:
#   --config-path PATH      Configuration file path (default: /etc/safeops/nic_management.yaml)
#   --binary-path PATH      Service binary path (default: ./nic_management)
#   --start-service         Start service after installation (default: yes)
#   --no-start-service      Do not start service after installation
#   --service-user USER     Service user account (default: safeops)
#   --help                  Show this help message
#
# Examples:
#   sudo ./install_linux.sh
#   sudo ./install_linux.sh --config-path /opt/config.yaml --start-service
#
#############################################################################

set -e

# =============================================================================
# Configuration Variables
# =============================================================================

CONFIG_PATH="${CONFIG_PATH:-/etc/safeops/nic_management.yaml}"
BINARY_PATH="${BINARY_PATH:-./nic_management}"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="nic-management"
SERVICE_USER="${SERVICE_USER:-safeops}"
LOG_DIR="/var/log/safeops"
START_SERVICE=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}→${NC} $1"
}

print_step() {
    echo -e "\n${CYAN}$1${NC}"
}

die() {
    print_error "$1"
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# =============================================================================
# Parse Command-Line Arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --config-path)
            CONFIG_PATH="$2"
            shift 2
            ;;
        --binary-path)
            BINARY_PATH="$2"
            shift 2
            ;;
        --start-service)
            START_SERVICE=true
            shift
            ;;
        --no-start-service)
            START_SERVICE=false
            shift
            ;;
        --service-user)
            SERVICE_USER="$2"
            shift 2
            ;;
        --help)
            grep "^#" "$0" | grep -v "^#!/" | sed 's/^# //' | head -30
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# =============================================================================
# Header
# =============================================================================

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "  SafeOps NIC Management Service - Linux Installer"
echo -e "${CYAN}============================================================${NC}"

# =============================================================================
# Step 1: Check Root Privileges
# =============================================================================

print_step "[1/10] Checking privileges..."

if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root. Use: sudo $0"
fi

print_success "Running as root"

# =============================================================================
# Step 2: Check Linux Distribution and Version
# =============================================================================

print_step "[2/10] Checking Linux distribution..."

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_NAME="$NAME"
    DISTRO_VERSION="$VERSION_ID"
    
    print_success "Detected: $DISTRO_NAME $DISTRO_VERSION"
    
    # Check kernel version (minimum 3.10 for required features)
    KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 3 ]] || [[ $KERNEL_MAJOR -eq 3 && $KERNEL_MINOR -lt 10 ]]; then
        die "Kernel version 3.10+ required. Current: $(uname -r)"
    fi
    
    print_success "Kernel version check passed: $(uname -r)"
else
    print_warning "Could not detect Linux distribution"
fi

# =============================================================================
# Step 3: Check Required Tools
# =============================================================================

print_step "[3/10] Checking required tools..."

REQUIRED_TOOLS=("systemctl" "useradd" "setcap" "getcap" "chown" "chmod")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command_exists "$tool"; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    print_error "Missing required tools: ${MISSING_TOOLS[*]}"
    echo "Install with:"
    echo "  Ubuntu/Debian: apt-get install libcap2-bin systemd"
    echo "  RHEL/CentOS:   yum install libcap systemd"
    exit 1
fi

print_success "All required tools present"

# =============================================================================
# Step 4: Check Systemd Available
# =============================================================================

print_step "[4/10] Checking systemd..."

if ! command_exists systemctl; then
    die "systemd is required but not found. This script only supports systemd-based distributions."
fi

if ! systemctl --version >/dev/null 2>&1; then
    die "systemd is not running or not functional"
fi

print_success "systemd is available"

# =============================================================================
# Step 5: Check Binary Exists
# =============================================================================

print_step "[5/10] Checking service binary..."

if [[ ! -f "$BINARY_PATH" ]]; then
    die "Binary not found at: $BINARY_PATH"
fi

if [[ ! -x "$BINARY_PATH" ]]; then
    print_warning "Binary is not executable, setting execute permission..."
    chmod +x "$BINARY_PATH"
fi

# Resolve to absolute path
BINARY_PATH=$(realpath "$BINARY_PATH")

print_success "Binary found: $BINARY_PATH"

# =============================================================================
# Step 6: Create Service User
# =============================================================================

print_step "[6/10] Creating service user: $SERVICE_USER..."

if id "$SERVICE_USER" >/dev/null 2>&1; then
    print_warning "User $SERVICE_USER already exists, skipping creation"
else
    useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
    
    if [[ $? -eq 0 ]]; then
        print_success "User $SERVICE_USER created"
    else
        die "Failed to create user $SERVICE_USER"
    fi
fi

# =============================================================================
# Step 7: Create Directories and Install Binary
# =============================================================================

print_step "[7/10] Installing binary and creating directories..."

# Configuration directory
CONFIG_DIR=$(dirname "$CONFIG_PATH")
if [[ ! -d "$CONFIG_DIR" ]]; then
    mkdir -p "$CONFIG_DIR"
    print_success "Created config directory: $CONFIG_DIR"
fi

# Log directory
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chmod 755 "$LOG_DIR"
    print_success "Created log directory: $LOG_DIR"
fi

# Install binary
INSTALLED_BINARY="$INSTALL_DIR/nic_management"

cp "$BINARY_PATH" "$INSTALLED_BINARY"
chown root:root "$INSTALLED_BINARY"
chmod 755 "$INSTALLED_BINARY"

print_success "Binary installed to: $INSTALLED_BINARY"

# =============================================================================
# Step 8: Set Linux Capabilities
# =============================================================================

print_step "[8/10] Setting Linux capabilities..."

setcap cap_net_raw,cap_net_admin=+eip "$INSTALLED_BINARY"

if [[ $? -eq 0 ]]; then
    # Verify capabilities
    CAPS=$(getcap "$INSTALLED_BINARY")
    if [[ "$CAPS" == *"cap_net_raw"* ]] && [[ "$CAPS" == *"cap_net_admin"* ]]; then
        print_success "Capabilities set: cap_net_raw,cap_net_admin"
    else
        print_warning "Capability verification: $CAPS"
    fi
else
    die "Failed to set capabilities (required for packet capture)"
fi

# =============================================================================
# Step 9: Install Configuration and Create Systemd Unit
# =============================================================================

print_step "[9/10] Creating systemd service..."

# Configuration file
DEFAULT_CONFIG=$(dirname "$BINARY_PATH")/nic_management.yaml

if [[ -f "$CONFIG_PATH" ]]; then
    BACKUP_PATH="$CONFIG_PATH.backup.$(date +%Y%m%d%H%M%S)"
    cp "$CONFIG_PATH" "$BACKUP_PATH"
    print_warning "Existing config backed up to: $BACKUP_PATH"
elif [[ -f "$DEFAULT_CONFIG" ]]; then
    cp "$DEFAULT_CONFIG" "$CONFIG_PATH"
    chown root:"$SERVICE_USER" "$CONFIG_PATH"
    chmod 640 "$CONFIG_PATH"
    print_success "Configuration installed to: $CONFIG_PATH"
else
    print_warning "No default configuration found, you need to create $CONFIG_PATH"
fi

# Create systemd service unit
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=SafeOps NIC Management Service
Documentation=https://docs.safeops.io/nic-management
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALLED_BINARY --config $CONFIG_PATH
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nic-management

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

if [[ $? -eq 0 ]]; then
    print_success "Service unit created: $UNIT_FILE"
else
    die "Failed to create service unit file"
fi

# Reload systemd daemon
systemctl daemon-reload
print_success "Systemd daemon reloaded"

# Enable service
systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1
print_success "Service enabled (will start on boot)"

# =============================================================================
# Step 10: Start Service and Verify
# =============================================================================

print_step "[10/10] Starting and verifying service..."

if [[ "$START_SERVICE" == true ]]; then
    systemctl start "$SERVICE_NAME.service"
    
    if [[ $? -eq 0 ]]; then
        sleep 3
        
        if systemctl is-active --quiet "$SERVICE_NAME.service"; then
            print_success "Service started successfully"
            
            # Test connectivity
            sleep 2
            if command_exists nc; then
                if nc -z localhost 50054 2>/dev/null; then
                    print_success "gRPC endpoint accessible on port 50054"
                else
                    print_warning "gRPC port 50054 not accessible (service may still be initializing)"
                fi
            fi
        else
            print_error "Service failed to start"
            echo "Check logs with: journalctl -u $SERVICE_NAME -n 50"
        fi
    else
        print_error "Failed to start service"
        echo "Check logs with: journalctl -u $SERVICE_NAME -n 50"
    fi
else
    print_info "Service not started (use --start-service to start)"
fi

# Verify installation
SERVICE_STATUS=$(systemctl is-active "$SERVICE_NAME.service" 2>/dev/null || echo "inactive")
SERVICE_ENABLED=$(systemctl is-enabled "$SERVICE_NAME.service" 2>/dev/null || echo "disabled")

# =============================================================================
# Installation Summary
# =============================================================================

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  NIC Management Service - Installation Complete${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo "Installation Details:"
echo "  Service:      $SERVICE_NAME.service"
echo "  Binary:       $INSTALLED_BINARY"
echo "  Config:       $CONFIG_PATH"
echo "  Logs:         $LOG_DIR"
echo "  User:         $SERVICE_USER"
echo "  gRPC Port:    50054"
echo ""
echo "Service Status:"
echo "  Active:       $SERVICE_STATUS"
echo "  Enabled:      $SERVICE_ENABLED"
echo ""
echo "Service Management Commands:"
echo "  Start:    sudo systemctl start $SERVICE_NAME"
echo "  Stop:     sudo systemctl stop $SERVICE_NAME"
echo "  Restart:  sudo systemctl restart $SERVICE_NAME"
echo "  Status:   sudo systemctl status $SERVICE_NAME"
echo ""
echo "View Logs:"
echo "  Live:     sudo journalctl -u $SERVICE_NAME -f"
echo "  Last 50:  sudo journalctl -u $SERVICE_NAME -n 50"
echo "  Today:    sudo journalctl -u $SERVICE_NAME --since today"
echo ""
echo "Configuration:"
echo "  Edit:     sudo nano $CONFIG_PATH"
echo "  Reload:   sudo systemctl restart $SERVICE_NAME"
echo ""
echo -e "${CYAN}============================================================${NC}"
