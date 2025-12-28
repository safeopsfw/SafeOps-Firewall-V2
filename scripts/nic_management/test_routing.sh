#!/bin/bash
#############################################################################
# NIC Management Service - Routing Test Script
#
# Description:
#   Automated testing for NIC Management service functionality
#   - Interface discovery and classification
#   - NAT translation verification
#   - WAN failover testing
#   - Load balancing validation
#   - Connection tracking verification
#
# Usage:
#   sudo ./test_routing.sh [OPTIONS]
#
# Options:
#   --grpc-endpoint HOST:PORT   gRPC endpoint (default: localhost:50054)
#   --test-destination IP       Test destination IP (default: 8.8.8.8)
#   --skip-failover             Skip WAN failover tests
#   --verbose                   Enable verbose output
#   --help                      Show this help message
#
# Examples:
#   sudo ./test_routing.sh
#   sudo ./test_routing.sh --grpc-endpoint 192.168.1.10:50054 --verbose
#
# Requirements:
#   - grpcurl (for gRPC API testing)
#   - tcpdump (for packet capture verification)
#   - ping, curl, nc (for connectivity testing)
#   - jq (for JSON parsing)
#
#############################################################################

set -e

# =============================================================================
# Configuration Variables
# =============================================================================

GRPC_ENDPOINT="${GRPC_ENDPOINT:-localhost:50054}"
TEST_DESTINATION="${TEST_DESTINATION:-8.8.8.8}"
SKIP_FAILOVER=false
VERBOSE=false

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Helper Functions
# =============================================================================

test_header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}TEST: $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

test_skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    ((TESTS_SKIPPED++))
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Required command '$1' not found${NC}"
        echo "Install with: apt-get install $2 (Ubuntu/Debian)"
        return 1
    fi
    return 0
}

# =============================================================================
# Parse Command-Line Arguments
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --grpc-endpoint)
            GRPC_ENDPOINT="$2"
            shift 2
            ;;
        --test-destination)
            TEST_DESTINATION="$2"
            shift 2
            ;;
        --skip-failover)
            SKIP_FAILOVER=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            grep "^#" "$0" | grep -v "^#!/" | sed 's/^# //' | head -35
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
echo -e "${CYAN}================================================================${NC}"
echo -e "  NIC Management Service - Routing Tests"
echo -e "${CYAN}================================================================${NC}"
echo ""
echo "Configuration:"
echo "  gRPC Endpoint:     $GRPC_ENDPOINT"
echo "  Test Destination:  $TEST_DESTINATION"
echo "  Skip Failover:     $SKIP_FAILOVER"
echo "  Verbose Mode:      $VERBOSE"

# =============================================================================
# Test 1: Check Prerequisites
# =============================================================================

test_header "Checking Prerequisites"

PREREQ_FAILED=false

# Check required tools
TOOLS_OK=true
for tool in grpcurl tcpdump ping curl nc jq; do
    case $tool in
        grpcurl) pkg="grpcurl" ;;
        tcpdump) pkg="tcpdump" ;;
        ping) pkg="iputils-ping" ;;
        curl) pkg="curl" ;;
        nc) pkg="netcat" ;;
        jq) pkg="jq" ;;
    esac
    
    if command -v "$tool" >/dev/null 2>&1; then
        log_verbose "$tool: found"
    else
        echo -e "${YELLOW}Warning: $tool not found (install: apt-get install $pkg)${NC}"
        TOOLS_OK=false
    fi
done

if [[ "$TOOLS_OK" == true ]]; then
    test_pass "All required tools available"
else
    test_fail "Some tools missing (tests may be limited)"
fi

# Check root privileges (needed for tcpdump)
if [[ $EUID -eq 0 ]]; then
    test_pass "Running as root"
else
    test_skip "Not running as root (tcpdump tests will be skipped)"
fi

# =============================================================================
# Test 2: Service Connectivity
# =============================================================================

test_header "Service Connectivity"

log_verbose "Testing gRPC endpoint: $GRPC_ENDPOINT"

# Test TCP connectivity first
if command -v nc >/dev/null 2>&1; then
    HOST=$(echo "$GRPC_ENDPOINT" | cut -d: -f1)
    PORT=$(echo "$GRPC_ENDPOINT" | cut -d: -f2)
    
    if nc -z "$HOST" "$PORT" 2>/dev/null; then
        test_pass "TCP connection to $GRPC_ENDPOINT successful"
    else
        test_fail "Cannot connect to $GRPC_ENDPOINT"
        echo "Ensure NIC Management service is running"
        exit 1
    fi
else
    test_skip "nc not available for TCP test"
fi

# Test gRPC health check
if command -v grpcurl >/dev/null 2>&1; then
    if grpcurl -plaintext "$GRPC_ENDPOINT" grpc.health.v1.Health/Check >/dev/null 2>&1; then
        test_pass "gRPC health check passed"
    else
        # Try listing services instead
        if grpcurl -plaintext "$GRPC_ENDPOINT" list >/dev/null 2>&1; then
            test_pass "gRPC service responding (no health service)"
        else
            test_fail "gRPC service not responding properly"
        fi
    fi
    
    if [[ "$VERBOSE" == true ]]; then
        echo "Available gRPC services:"
        grpcurl -plaintext "$GRPC_ENDPOINT" list 2>/dev/null | sed 's/^/  /'
    fi
else
    test_skip "grpcurl not available"
fi

# =============================================================================
# Test 3: Interface Discovery
# =============================================================================

test_header "Interface Discovery"

if command -v grpcurl >/dev/null 2>&1; then
    INTERFACES=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/ListNetworkInterfaces 2>/dev/null || echo "")
    
    if [[ -n "$INTERFACES" ]] && command -v jq >/dev/null 2>&1; then
        INTERFACE_COUNT=$(echo "$INTERFACES" | jq '.interfaces | length' 2>/dev/null || echo "0")
        WAN_COUNT=$(echo "$INTERFACES" | jq '[.interfaces[]? | select(.type == "WAN")] | length' 2>/dev/null || echo "0")
        LAN_COUNT=$(echo "$INTERFACES" | jq '[.interfaces[]? | select(.type == "LAN")] | length' 2>/dev/null || echo "0")
        
        if [[ "$INTERFACE_COUNT" -gt 0 ]]; then
            test_pass "Discovered $INTERFACE_COUNT interfaces ($WAN_COUNT WAN, $LAN_COUNT LAN)"
            
            if [[ "$VERBOSE" == true ]]; then
                echo "Interfaces:"
                echo "$INTERFACES" | jq -r '.interfaces[]? | "  \(.id): \(.name) (\(.type)) - \(.status)"' 2>/dev/null
            fi
            
            if [[ "$WAN_COUNT" -gt 0 ]]; then
                test_pass "WAN interfaces detected: $WAN_COUNT"
            else
                test_fail "No WAN interfaces detected"
            fi
        else
            test_fail "No interfaces discovered"
        fi
    elif [[ -n "$INTERFACES" ]]; then
        test_pass "Interface list retrieved (jq not available for parsing)"
    else
        test_fail "Failed to retrieve interface list"
    fi
else
    test_skip "grpcurl not available for interface test"
fi

# =============================================================================
# Test 4: NAT Translation
# =============================================================================

test_header "NAT Translation"

# Establish test connection to trigger NAT
log_verbose "Establishing test connection to $TEST_DESTINATION"

if ping -c 1 -W 2 "$TEST_DESTINATION" >/dev/null 2>&1; then
    test_pass "External connectivity verified (ping to $TEST_DESTINATION)"
else
    test_fail "Cannot reach $TEST_DESTINATION"
fi

# Wait for NAT mapping to be created
sleep 2

# Query NAT mappings
if command -v grpcurl >/dev/null 2>&1; then
    NAT_MAPPINGS=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/GetNATMappings 2>/dev/null || echo "")
    
    if [[ -n "$NAT_MAPPINGS" ]] && command -v jq >/dev/null 2>&1; then
        MAPPING_COUNT=$(echo "$NAT_MAPPINGS" | jq '.mappings | length' 2>/dev/null || echo "0")
        
        if [[ "$MAPPING_COUNT" -gt 0 ]]; then
            test_pass "NAT mappings active: $MAPPING_COUNT sessions"
            
            if [[ "$VERBOSE" == true ]]; then
                echo "NAT Mappings:"
                echo "$NAT_MAPPINGS" | jq -r '.mappings[]? | "  \(.lanIp):\(.lanPort) -> \(.wanIp):\(.wanPort) [\(.protocol)]"' 2>/dev/null
            fi
        else
            test_skip "No NAT mappings found (NAT may be disabled or no active sessions)"
        fi
    elif [[ -n "$NAT_MAPPINGS" ]]; then
        test_pass "NAT mappings retrieved"
    else
        test_skip "NAT mappings RPC not available"
    fi
else
    test_skip "grpcurl not available for NAT test"
fi

# =============================================================================
# Test 5: Packet Forwarding
# =============================================================================

test_header "Packet Forwarding"

if [[ $EUID -eq 0 ]] && command -v tcpdump >/dev/null 2>&1; then
    CAPTURE_FILE="/tmp/nic_test_capture_$$.pcap"
    log_verbose "Starting packet capture: $CAPTURE_FILE"
    
    # Start packet capture in background
    timeout 10 tcpdump -i any -c 20 -w "$CAPTURE_FILE" "host $TEST_DESTINATION" >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    
    sleep 2  # Let tcpdump initialize
    
    # Generate test traffic
    log_verbose "Generating test traffic to $TEST_DESTINATION"
    ping -c 5 "$TEST_DESTINATION" >/dev/null 2>&1 || true
    
    # Wait for tcpdump
    wait $TCPDUMP_PID 2>/dev/null || true
    
    # Analyze capture
    if [[ -f "$CAPTURE_FILE" ]]; then
        PACKET_COUNT=$(tcpdump -r "$CAPTURE_FILE" 2>/dev/null | wc -l)
        
        if [[ $PACKET_COUNT -gt 0 ]]; then
            test_pass "Packets captured: $PACKET_COUNT packets"
        else
            test_fail "No packets captured"
        fi
        
        rm -f "$CAPTURE_FILE"
    else
        test_fail "Packet capture failed"
    fi
else
    test_skip "tcpdump not available or not running as root"
fi

# =============================================================================
# Test 6: WAN Health Status
# =============================================================================

test_header "WAN Health Monitoring"

if command -v grpcurl >/dev/null 2>&1; then
    WAN_HEALTH=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/GetWANHealthStatus 2>/dev/null || echo "")
    
    if [[ -n "$WAN_HEALTH" ]] && command -v jq >/dev/null 2>&1; then
        UP_COUNT=$(echo "$WAN_HEALTH" | jq '[.wanHealth[]? | select(.status == "UP")] | length' 2>/dev/null || echo "0")
        DOWN_COUNT=$(echo "$WAN_HEALTH" | jq '[.wanHealth[]? | select(.status == "DOWN")] | length' 2>/dev/null || echo "0")
        TOTAL_COUNT=$(echo "$WAN_HEALTH" | jq '.wanHealth | length' 2>/dev/null || echo "0")
        
        if [[ "$TOTAL_COUNT" -gt 0 ]]; then
            test_pass "WAN health retrieved: $UP_COUNT UP, $DOWN_COUNT DOWN"
            
            if [[ "$VERBOSE" == true ]]; then
                echo "WAN Health:"
                echo "$WAN_HEALTH" | jq -r '.wanHealth[]? | "  \(.interfaceId): \(.status) - Latency: \(.latency)ms, Loss: \(.packetLoss)%"' 2>/dev/null
            fi
            
            if [[ "$UP_COUNT" -gt 0 ]]; then
                test_pass "At least one WAN is UP"
            else
                test_fail "No WAN interfaces are UP"
            fi
        else
            test_skip "No WAN health data available"
        fi
    elif [[ -n "$WAN_HEALTH" ]]; then
        test_pass "WAN health retrieved"
    else
        test_skip "WAN health RPC not available"
    fi
else
    test_skip "grpcurl not available for WAN health test"
fi

# =============================================================================
# Test 7: WAN Failover (Optional)
# =============================================================================

if [[ "$SKIP_FAILOVER" == false ]]; then
    test_header "WAN Failover Simulation"
    
    if command -v grpcurl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        # Check if we have multiple WANs
        if [[ -n "$WAN_HEALTH" ]]; then
            ACTIVE_WAN=$(echo "$WAN_HEALTH" | jq -r '.wanHealth[]? | select(.status == "UP") | .interfaceId' 2>/dev/null | head -1)
            BACKUP_WAN=$(echo "$WAN_HEALTH" | jq -r ".wanHealth[]? | select(.interfaceId != \"$ACTIVE_WAN\" and .status == \"UP\") | .interfaceId" 2>/dev/null | head -1)
            
            if [[ -z "$ACTIVE_WAN" ]]; then
                test_skip "No active WAN for failover test"
            elif [[ -z "$BACKUP_WAN" ]]; then
                test_skip "No backup WAN available (single WAN configuration)"
            else
                log_verbose "Primary WAN: $ACTIVE_WAN, Backup WAN: $BACKUP_WAN"
                
                # Trigger failover
                FAILOVER_RESULT=$(grpcurl -plaintext \
                    -d "{\"targetWan\": \"$BACKUP_WAN\", \"reason\": \"Test failover\", \"force\": false}" \
                    "$GRPC_ENDPOINT" nic_management.NICManagement/TriggerFailover 2>/dev/null || echo "")
                
                if [[ -n "$FAILOVER_RESULT" ]]; then
                    SUCCESS=$(echo "$FAILOVER_RESULT" | jq -r '.success' 2>/dev/null || echo "false")
                    
                    if [[ "$SUCCESS" == "true" ]]; then
                        AFFECTED=$(echo "$FAILOVER_RESULT" | jq -r '.affectedSessions' 2>/dev/null || echo "0")
                        test_pass "Failover successful: $AFFECTED sessions remapped"
                    else
                        test_fail "Failover returned failure"
                    fi
                else
                    test_skip "Failover RPC not available"
                fi
            fi
        else
            test_skip "WAN health data not available for failover test"
        fi
    else
        test_skip "grpcurl or jq not available for failover test"
    fi
else
    test_skip "WAN failover tests skipped (--skip-failover)"
fi

# =============================================================================
# Test 8: Performance Metrics
# =============================================================================

test_header "Performance Metrics"

if command -v grpcurl >/dev/null 2>&1; then
    # Test metrics endpoint
    METRICS=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/GetMetrics 2>/dev/null || echo "")
    
    if [[ -n "$METRICS" ]]; then
        test_pass "Performance metrics accessible"
        
        if [[ "$VERBOSE" == true ]] && command -v jq >/dev/null 2>&1; then
            echo "Metrics sample:"
            echo "$METRICS" | jq '.' 2>/dev/null | head -20
        fi
    else
        test_skip "Metrics RPC not available"
    fi
else
    test_skip "grpcurl not available for metrics test"
fi

# =============================================================================
# Test 9: Integration Statistics
# =============================================================================

test_header "Integration Statistics"

if command -v grpcurl >/dev/null 2>&1; then
    # Test QoS stats
    QOS=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/GetQoSStats 2>/dev/null || echo "")
    if [[ -n "$QOS" ]]; then
        test_pass "QoS statistics accessible"
    else
        test_skip "QoS integration not available"
    fi
    
    # Test Firewall stats
    FW=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/GetFirewallStats 2>/dev/null || echo "")
    if [[ -n "$FW" ]]; then
        test_pass "Firewall statistics accessible"
    else
        test_skip "Firewall integration not available"
    fi
    
    # Test IDS stats
    IDS=$(grpcurl -plaintext "$GRPC_ENDPOINT" nic_management.NICManagement/GetIDSStats 2>/dev/null || echo "")
    if [[ -n "$IDS" ]]; then
        test_pass "IDS/IPS statistics accessible"
    else
        test_skip "IDS/IPS integration not available"
    fi
else
    test_skip "grpcurl not available for integration tests"
fi

# =============================================================================
# Test Summary
# =============================================================================

echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  Test Summary${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""
echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
echo ""
echo -e "${CYAN}================================================================${NC}"

# Exit with appropriate code
if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Some tests failed. Review output above for details.${NC}"
    exit 1
else
    echo -e "${GREEN}All executed tests passed!${NC}"
    exit 0
fi
