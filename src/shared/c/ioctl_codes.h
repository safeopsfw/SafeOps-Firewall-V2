/*
 * SafeOps Firewall v2.0 - IOCTL Codes Header
 *
 * Purpose: Defines I/O Control (IOCTL) command codes enabling bidirectional
 *          communication between userspace service and Windows kernel driver.
 *
 * Author: SafeOps Development Team
 * Created: 2025-12-20
 *
 * CRITICAL: IOCTL codes are part of the driver ABI. Once defined, codes CANNOT
 *           change values without breaking compatibility. New IOCTLs must use
 *           unused function codes. Existing IOCTLs must maintain same code
 * value.
 *
 * Control Plane: IOCTLs enable userspace to orchestrate kernel driver behavior
 *                including statistics retrieval, firewall rules, packet
 * capture, NIC management, and ring buffer operations.
 */

#ifndef SAFEOPS_IOCTL_CODES_H
#define SAFEOPS_IOCTL_CODES_H

/*
 * =============================================================================
 * REQUIRED INCLUDES
 * =============================================================================
 */

#ifdef _KERNEL_MODE
/* Kernel mode: Use WDK headers */
#include <ntddk.h>
#include <wdf.h>
#else
/* User mode: Use Windows SDK headers */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h> /* CTL_CODE macro, METHOD_* constants */
#include <winsock2.h>

#endif

/* SafeOps internal headers */
#include "shared_constants.h"

/*
 * =============================================================================
 * CTL_CODE MACRO EXPLANATION
 * =============================================================================
 *
 * Windows CTL_CODE macro packs device type, function code, transfer method,
 * and access rights into a single 32-bit IOCTL code:
 *
 * CTL_CODE(DeviceType, Function, Method, Access)
 *
 * Bit Layout (32-bit value):
 *   Bits 31-16: Device Type (0x8000 for SafeOps custom device)
 *   Bits 15-14: Access Rights (FILE_ANY_ACCESS, FILE_READ_DATA,
 * FILE_WRITE_DATA) Bits 13-2:  Function Code (0x800-0xFFF for custom functions)
 *   Bits 1-0:   Transfer Method (METHOD_BUFFERED, METHOD_IN_DIRECT, etc.)
 *
 * Transfer Methods:
 *   METHOD_BUFFERED (0) - Kernel copies data to/from system buffer (≤4KB)
 *   METHOD_IN_DIRECT (1) - Direct memory access for input buffer (DMA)
 *   METHOD_OUT_DIRECT (2) - Direct memory access for output buffer (DMA)
 *   METHOD_NEITHER (3) - Neither buffered nor direct (rare, unsafe)
 *
 * Access Rights:
 *   FILE_ANY_ACCESS (0x00) - No specific access required
 *   FILE_READ_DATA (0x01) - Read access required
 *   FILE_WRITE_DATA (0x02) - Write access required
 */

/*
 * =============================================================================
 * GENERAL DRIVER COMMANDS (0x00 - 0x0F)
 * =============================================================================
 * Purpose: Basic driver management operations including version queries,
 *          capability detection, initialization, and shutdown.
 */

/*
 * IOCTL_SAFEOPS_GET_VERSION
 *
 * Query driver version and ABI compatibility.
 *
 * Input: None
 * Output: SAFEOPS_VERSION_INFO structure
 *   - major: Major version number
 *   - minor: Minor version number
 *   - patch: Patch version number
 *   - build: Build number
 *   - abiVersion: ABI version for compatibility checking
 *
 * Purpose: Userspace service validates compatibility at initialization.
 *          Service compares driver version against compiled version and
 *          aborts if ABI versions mismatch.
 *
 * Usage: First IOCTL called after opening driver device handle.
 */
#define IOCTL_SAFEOPS_GET_VERSION                                              \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x00, METHOD_BUFFERED,    \
           FILE_ANY_ACCESS)

/*
 * IOCTL_SAFEOPS_GET_CAPABILITIES
 *
 * Query driver feature support flags.
 *
 * Input: None
 * Output: DWORD capability flags bitmask
 *   - CAP_PACKET_INSPECTION: Deep packet inspection support
 *   - CAP_STATEFUL_FIREWALL: Connection tracking support
 *   - CAP_NAT_SUPPORT: Network address translation
 *   - CAP_VLAN_SUPPORT: VLAN tagging support
 *   - CAP_JUMBO_FRAMES: Jumbo frame support
 *   - CAP_IPV6_SUPPORT: IPv6 protocol support
 *
 * Purpose: Determines which features are available on this system.
 *          Hardware limitations or configuration may disable certain features.
 *
 * Usage: Service enables/disables features based on driver capabilities.
 */
#define IOCTL_SAFEOPS_GET_CAPABILITIES                                         \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x01, METHOD_BUFFERED,    \
           FILE_ANY_ACCESS)

/*
 * IOCTL_SAFEOPS_INITIALIZE_DRIVER
 *
 * Initialize driver subsystems and allocate resources.
 *
 * Input: DRIVER_INIT_PARAMS structure (optional config overrides)
 * Output: NTSTATUS result code
 *
 * Purpose: Allocates 2GB ring buffer, initializes filter engine,
 *          registers WFP callouts, sets up connection tracking.
 *
 * Usage: Called once after service starts, before any other IOCTLs.
 *        Must succeed before driver can process packets.
 */
#define IOCTL_SAFEOPS_INITIALIZE_DRIVER                                        \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x02, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_SHUTDOWN_DRIVER
 *
 * Graceful driver shutdown and resource cleanup.
 *
 * Input: None
 * Output: NTSTATUS result code
 *
 * Purpose: Flushes ring buffer, unregisters WFP callouts, releases
 *          connection tracking table, frees memory pools.
 *
 * Usage: Called during service shutdown or before driver unload.
 */
#define IOCTL_SAFEOPS_SHUTDOWN_DRIVER                                          \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x03, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * =============================================================================
 * STATISTICS RETRIEVAL (0x10 - 0x1F)
 * =============================================================================
 * Purpose: Query various driver statistics for monitoring and diagnostics.
 */

/*
 * IOCTL_SAFEOPS_GET_GLOBAL_STATS
 *
 * Query global driver statistics.
 *
 * Input: None
 * Output: GLOBAL_STATS structure
 *   - totalPacketsCaptured: Total packets processed
 *   - totalPacketsDropped: Packets dropped (buffer full)
 *   - totalPacketsFiltered: Packets blocked by firewall
 *   - totalBytesProcessed: Total bytes processed
 *   - uptimeSeconds: Driver uptime in seconds
 *
 * Purpose: Monitoring dashboard displays throughput and drop rates.
 *
 * Usage: Polled every 5 seconds for real-time metrics.
 */
#define IOCTL_SAFEOPS_GET_GLOBAL_STATS                                         \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x10, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_GET_INTERFACE_STATS
 *
 * Query per-interface statistics.
 *
 * Input: ULONG interfaceIndex
 * Output: INTERFACE_STATS structure
 *   - packetsIn: Packets received on this interface
 *   - packetsOut: Packets sent on this interface
 *   - bytesIn: Bytes received
 *   - bytesOut: Bytes sent
 *   - errors: Error count
 *
 * Purpose: Identify which NIC has high traffic or errors.
 *
 * Usage: Iterate all interfaces to build per-NIC statistics table.
 */
#define IOCTL_SAFEOPS_GET_INTERFACE_STATS                                      \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x11, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_GET_PROTOCOL_STATS
 *
 * Query protocol breakdown statistics.
 *
 * Input: None
 * Output: PROTOCOL_STATS structure
 *   - tcpCount: TCP packet count
 *   - udpCount: UDP packet count
 *   - icmpCount: ICMP packet count
 *   - otherCount: Other protocol count
 *
 * Purpose: Understanding traffic composition for capacity planning.
 *
 * Usage: Dashboard pie chart showing protocol distribution.
 */
#define IOCTL_SAFEOPS_GET_PROTOCOL_STATS                                       \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x12, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_GET_CONNECTION_COUNT
 *
 * Query active connection count.
 *
 * Input: None
 * Output: ULONG activeConnections
 *
 * Purpose: Monitoring connection tracking table utilization.
 *
 * Usage: Alert if approaching MAX_CONNECTIONS limit (1M).
 */
#define IOCTL_SAFEOPS_GET_CONNECTION_COUNT                                     \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x13, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * =============================================================================
 * FIREWALL FILTER RULES (0x20 - 0x2F)
 * =============================================================================
 * Purpose: Dynamic firewall rule management without driver restart.
 */

/*
 * IOCTL_SAFEOPS_ADD_FILTER_RULE
 *
 * Add new firewall rule to filter engine.
 *
 * Input: FILTER_RULE structure
 *   - priority: Rule priority (higher value = higher priority)
 *   - action: ACTION_ALLOW, ACTION_DENY, ACTION_REJECT, ACTION_LOG
 *   - protocol: IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)
 *   - srcIP: Source IP address (0.0.0.0 = any)
 *   - dstIP: Destination IP address
 *   - srcPort: Source port (0 = any)
 *   - dstPort: Destination port
 *   - nicTag: Interface tag (NIC_TAG_WAN, NIC_TAG_LAN, etc.)
 *
 * Output: ULONG ruleId (unique identifier assigned by driver)
 *
 * Purpose: Dynamically add firewall rule without driver restart.
 *
 * Usage: Threat intelligence service adds block rule for malicious IP.
 */
#define IOCTL_SAFEOPS_ADD_FILTER_RULE                                          \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x20, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_REMOVE_FILTER_RULE
 *
 * Delete existing firewall rule.
 *
 * Input: ULONG ruleId
 * Output: NTSTATUS result
 *
 * Purpose: Remove rule no longer needed.
 *
 * Usage: IP reputation expiration removes temporary block rules.
 */
#define IOCTL_SAFEOPS_REMOVE_FILTER_RULE                                       \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x21, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_UPDATE_FILTER_RULE
 *
 * Modify existing firewall rule.
 *
 * Input: FILTER_RULE_UPDATE structure
 *   - ruleId: Rule to update
 *   - updates: Fields to modify
 *
 * Output: NTSTATUS result
 *
 * Purpose: Change rule action (ALLOW → BLOCK) or priority without
 *          removing and re-adding rule.
 *
 * Usage: Firewall configuration changes applied live.
 */
#define IOCTL_SAFEOPS_UPDATE_FILTER_RULE                                       \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x22, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_GET_FILTER_RULES
 *
 * Retrieve all firewall rules.
 *
 * Input: ULONG bufferSize
 * Output: Array of FILTER_RULE structures
 *
 * Purpose: Backup current ruleset or display in UI.
 *          Uses METHOD_OUT_DIRECT for efficient large data transfer.
 *
 * Usage: Orchestrator periodically backs up firewall rules.
 */
#define IOCTL_SAFEOPS_GET_FILTER_RULES                                         \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x23, METHOD_OUT_DIRECT,  \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_CLEAR_ALL_RULES
 *
 * Delete all firewall rules.
 *
 * Input: ULONG confirmationToken (safety check to prevent accidents)
 * Output: NTSTATUS result
 *
 * Purpose: Reset firewall to default state.
 *
 * Usage: Emergency clear during troubleshooting.
 */
#define IOCTL_SAFEOPS_CLEAR_ALL_RULES                                          \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x24, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * =============================================================================
 * PACKET CAPTURE CONTROL (0x30 - 0x3F)
 * =============================================================================
 * Purpose: Control packet capture engine and filtering.
 */

/*
 * IOCTL_SAFEOPS_START_CAPTURE
 *
 * Begin packet capture.
 *
 * Input: CAPTURE_PARAMS structure (optional)
 *   - snaplen: Maximum bytes to capture per packet
 *   - filterExpression: BPF-style filter (optional)
 *
 * Output: NTSTATUS result
 *
 * Purpose: Activate NDIS filter to start writing packets to ring buffer.
 *
 * Usage: Service starts capture during initialization.
 */
#define IOCTL_SAFEOPS_START_CAPTURE                                            \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x30, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_STOP_CAPTURE
 *
 * Stop packet capture.
 *
 * Input: None
 * Output: NTSTATUS result
 *
 * Purpose: Pause packet capture (ring buffer stops receiving packets).
 *
 * Usage: Service stops capture during shutdown or maintenance.
 */
#define IOCTL_SAFEOPS_STOP_CAPTURE                                             \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x31, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_SET_CAPTURE_FILTER
 *
 * Configure capture filter to reduce captured packets.
 *
 * Input: CAPTURE_FILTER structure
 *   - protocol: Protocol filter (0 = all)
 *   - portRanges: Port ranges to capture
 *   - ipRanges: IP ranges to capture
 *   - nicTag: Interface tag filter
 *
 * Output: NTSTATUS result
 *
 * Purpose: Performance optimization by filtering at kernel level.
 *          Example: Only capture TCP port 80, or only WAN interface.
 *
 * Usage: Reduce ring buffer load for targeted monitoring.
 */
#define IOCTL_SAFEOPS_SET_CAPTURE_FILTER                                       \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x32, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_GET_CAPTURE_STATUS
 *
 * Query capture state.
 *
 * Input: None
 * Output: CAPTURE_STATUS structure
 *   - isRunning: TRUE if capture active
 *   - packetsCaptured: Total packets captured
 *   - durationSeconds: Capture duration
 *
 * Purpose: Health monitoring and diagnostics.
 *
 * Usage: Orchestrator verifies capture is active.
 */
#define IOCTL_SAFEOPS_GET_CAPTURE_STATUS                                       \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x33, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * =============================================================================
 * NETWORK INTERFACE MANAGEMENT (0x40 - 0x4F)
 * =============================================================================
 * Purpose: Discover and configure network interfaces.
 */

/*
 * IOCTL_SAFEOPS_ENUMERATE_INTERFACES
 *
 * List all network interfaces.
 *
 * Input: ULONG bufferSize
 * Output: Array of INTERFACE_INFO structures
 *   - interfaceIndex: Windows interface index
 *   - name: Interface name
 *   - macAddress: MAC address
 *   - ipAddress: IPv4 address
 *   - nicTag: Current tag (NIC_TAG_WAN, NIC_TAG_LAN, etc.)
 *   - status: Up/Down status
 *
 * Purpose: Discover available NICs for configuration.
 *
 * Usage: UI displays interface list for user selection.
 */
#define IOCTL_SAFEOPS_ENUMERATE_INTERFACES                                     \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x40, METHOD_OUT_DIRECT,  \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_SET_NIC_TAG
 *
 * Classify interface (WAN/LAN/WiFi/VPN/etc).
 *
 * Input: NIC_TAG_PARAMS structure
 *   - interfaceIndex: Interface to tag
 *   - nicTag: Tag to apply (NIC_TAG_WAN, NIC_TAG_LAN, etc.)
 *
 * Output: NTSTATUS result
 *
 * Purpose: Tags interface for security policy application.
 *          WAN interfaces receive stricter filtering than LAN.
 *
 * Usage: Administrator marks interface as WAN (untrusted) vs LAN (trusted).
 */
#define IOCTL_SAFEOPS_SET_NIC_TAG                                              \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x41, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_GET_NIC_TAG
 *
 * Query interface classification.
 *
 * Input: ULONG interfaceIndex
 * Output: UCHAR nicTag
 *
 * Purpose: Retrieve current tag for interface.
 *
 * Usage: Firewall engine queries tag to apply appropriate rules.
 */
#define IOCTL_SAFEOPS_GET_NIC_TAG                                              \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x42, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_ENABLE_INTERFACE
 *
 * Enable packet capture on interface.
 *
 * Input: ULONG interfaceIndex
 * Output: NTSTATUS result
 *
 * Purpose: Activate capture on specific NIC.
 *
 * Usage: Selective monitoring (e.g., only WAN interface).
 */
#define IOCTL_SAFEOPS_ENABLE_INTERFACE                                         \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x43, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_DISABLE_INTERFACE
 *
 * Disable packet capture on interface.
 *
 * Input: ULONG interfaceIndex
 * Output: NTSTATUS result
 *
 * Purpose: Stop capturing on specific NIC.
 *
 * Usage: Exclude internal-only interfaces from monitoring.
 */
#define IOCTL_SAFEOPS_DISABLE_INTERFACE                                        \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x44, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * =============================================================================
 * RING BUFFER OPERATIONS (0x50 - 0x5F)
 * =============================================================================
 * Purpose: Monitor and manage 2GB shared memory ring buffer.
 */

/*
 * IOCTL_SAFEOPS_GET_RING_BUFFER_STATS
 *
 * Query ring buffer statistics.
 *
 * Input: None
 * Output: RING_BUFFER_STATS structure
 *   - totalPackets: Total packets written
 *   - droppedPackets: Packets dropped (buffer full)
 *   - currentUsage: Current entries in buffer
 *   - peakUsage: Peak usage (high watermark)
 *   - percentFull: Current utilization (0-100%)
 *
 * Purpose: Monitor ring buffer health.
 *
 * Usage: Alert if droppedPackets > 0 or usage > 90%.
 */
#define IOCTL_SAFEOPS_GET_RING_BUFFER_STATS                                    \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x50, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_FLUSH_RING_BUFFER
 *
 * Clear all packets from ring buffer.
 *
 * Input: ULONG confirmationToken (safety check)
 * Output: NTSTATUS result
 *
 * Purpose: Emergency clear during buffer overflow or corruption.
 *          Resets readIndex to writeIndex.
 *
 * Usage: Admin triggers manual flush via UI.
 */
#define IOCTL_SAFEOPS_FLUSH_RING_BUFFER                                        \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x51, METHOD_BUFFERED,    \
           FILE_WRITE_DATA)

/*
 * IOCTL_SAFEOPS_GET_RING_BUFFER_STATUS
 *
 * Query ring buffer header snapshot.
 *
 * Input: None
 * Output: RING_BUFFER_HEADER snapshot
 *   - writeIndex: Current producer position
 *   - readIndex: Current consumer position
 *   - totalSize: Buffer size (2GB)
 *   - droppedPackets: Drop counter
 *
 * Purpose: Detailed diagnostics and debugging.
 *
 * Usage: Troubleshooting ring buffer synchronization issues.
 */
#define IOCTL_SAFEOPS_GET_RING_BUFFER_STATUS                                   \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x52, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * IOCTL_SAFEOPS_MAP_RING_BUFFER
 *
 * Retrieve memory mapping information for ring buffer.
 *
 * Input: None
 * Output: RING_BUFFER_MAPPING_INFO structure
 *   - sectionName: Global section name for OpenFileMapping()
 *   - size: Buffer size (2GB)
 *
 * Purpose: Userspace maps ring buffer into process address space.
 *
 * Usage: Called once at service startup to establish shared memory connection.
 */
#define IOCTL_SAFEOPS_MAP_RING_BUFFER                                          \
  CTL_CODE(IOCTL_SAFEOPS_BASE, IOCTL_FUNCTION_BASE + 0x53, METHOD_BUFFERED,    \
           FILE_READ_DATA)

/*
 * =============================================================================
 * IOCTL CODE VALUE VERIFICATION
 * =============================================================================
 * Purpose: Compile-time verification that IOCTL codes have expected values.
 *          Prevents accidental changes to existing IOCTL codes.
 */

#ifdef _KERNEL_MODE
/* Kernel mode - use C_ASSERT */
#define IOCTL_STATIC_ASSERT(expr, msg) C_ASSERT(expr)
#elif defined(__cplusplus)
#define IOCTL_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#elif defined(_MSC_VER)
/* MSVC C mode - use typedef trick since _Static_assert not supported */
#define IOCTL_STATIC_ASSERT_JOIN(a, b) a##b
#define IOCTL_STATIC_ASSERT_NAME(line)                                         \
  IOCTL_STATIC_ASSERT_JOIN(ioctl_static_assertion_, line)
#define IOCTL_STATIC_ASSERT(expr, msg)                                         \
  typedef char IOCTL_STATIC_ASSERT_NAME(__LINE__)[(expr) ? 1 : -1]
#else
/* C11 compilers - use _Static_assert */
#define IOCTL_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)
#endif

/* Verify IOCTL codes are unique (no duplicates) */
IOCTL_STATIC_ASSERT(IOCTL_SAFEOPS_GET_VERSION != IOCTL_SAFEOPS_GET_CAPABILITIES,
                    "IOCTL codes must be unique");
IOCTL_STATIC_ASSERT(IOCTL_SAFEOPS_ADD_FILTER_RULE !=
                        IOCTL_SAFEOPS_REMOVE_FILTER_RULE,
                    "IOCTL codes must be unique");

/*
 * =============================================================================
 * END OF HEADER
 * =============================================================================
 */

#endif /* SAFEOPS_IOCTL_CODES_H */

/*
 * INTEGRATION NOTES:
 *
 * ABI Stability:
 * - IOCTL codes are part of driver ABI and must remain stable
 * - Once defined, IOCTL codes CANNOT change values
 * - New IOCTLs must use unused function codes
 * - Removing IOCTLs requires deprecation period
 *
 * Data Structure Versioning:
 * - Input/output structures passed via IOCTLs must be versioned
 * - Add version field to all IOCTL data structures
 * - Driver checks version and handles multiple versions gracefully
 * - Example: FILTER_RULE_V1, FILTER_RULE_V2 with version discriminator
 *
 * Error Handling:
 * - Driver validates all input buffers for size and content
 * - Returns appropriate NTSTATUS codes (STATUS_SUCCESS,
 * STATUS_INVALID_PARAMETER, etc.)
 * - Userspace checks return values and handles errors gracefully
 *
 * Security:
 * - Destructive IOCTLs (CLEAR_ALL_RULES, FLUSH_RING_BUFFER) require
 * confirmation tokens
 * - Driver validates caller has appropriate access rights
 * - FILE_WRITE_DATA access required for modification IOCTLs
 *
 * Testing:
 * - Every IOCTL must have handler in kernel driver
 * - Unrecognized IOCTLs return STATUS_INVALID_DEVICE_REQUEST
 * - Buffer size validation prevents buffer overruns
 * - Concurrent IOCTL calls must be thread-safe
 */
