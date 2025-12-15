/*
 * ioctl_codes.h
 * IOCTL command codes for SafeOps kernel driver control and communication
 *
 * Categories: Driver Control, Rule Management, Statistics, Configuration
 * Uses Windows CTL_CODE macro for standardized IOCTL code generation
 */

#ifndef SAFEOPS_IOCTL_CODES_H
#define SAFEOPS_IOCTL_CODES_H

#include <windows.h>

// Device and symbolic link names
#define SAFEOPS_DEVICE_NAME L"\\Device\\SafeOps"
#define SAFEOPS_SYMLINK_NAME L"\\DosDevices\\SafeOps"
#define SAFEOPS_USERMODE_PATH L"\\\\.\\SafeOps"

// Device type for SafeOps driver
#define FILE_DEVICE_SAFEOPS 0x8000

// ============================================================================
// DRIVER CONTROL COMMANDS (0x800-0x81F)
// ============================================================================

// Start packet capture
#define IOCTL_SAFEOPS_START_CAPTURE                                            \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x800, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Stop packet capture
#define IOCTL_SAFEOPS_STOP_CAPTURE                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Enable packet filtering
#define IOCTL_SAFEOPS_ENABLE_FILTERING                                         \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Disable packet filtering
#define IOCTL_SAFEOPS_DISABLE_FILTERING                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Set capture mode (promiscuous, selective, etc.)
#define IOCTL_SAFEOPS_SET_CAPTURE_MODE                                         \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Query driver status
#define IOCTL_SAFEOPS_GET_STATUS                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS)

// Query driver version
#define IOCTL_SAFEOPS_GET_VERSION                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS)

// Reset driver to initial state
#define IOCTL_SAFEOPS_RESET_DRIVER                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Pause packet capture (temporary stop)
#define IOCTL_SAFEOPS_PAUSE_CAPTURE                                            \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Resume packet capture
#define IOCTL_SAFEOPS_RESUME_CAPTURE                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// ============================================================================
// RING BUFFER MANAGEMENT (0x820-0x82F)
// ============================================================================

// Map ring buffer to userspace
#define IOCTL_SAFEOPS_MAP_RING_BUFFER                                          \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x820, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

// Unmap ring buffer
#define IOCTL_SAFEOPS_UNMAP_RING_BUFFER                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x821, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get ring buffer info (size, addresses, etc.)
#define IOCTL_SAFEOPS_GET_RING_BUFFER_INFO                                     \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x822, METHOD_BUFFERED, FILE_READ_ACCESS)

// Reset ring buffer indices
#define IOCTL_SAFEOPS_RESET_RING_BUFFER                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x823, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// ============================================================================
// FIREWALL RULE MANAGEMENT (0x830-0x84F)
// ============================================================================

// Add firewall rule
#define IOCTL_SAFEOPS_ADD_RULE                                                 \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x830, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Delete firewall rule by ID
#define IOCTL_SAFEOPS_DELETE_RULE                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x831, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Update existing firewall rule
#define IOCTL_SAFEOPS_UPDATE_RULE                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x832, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get firewall rule by ID
#define IOCTL_SAFEOPS_GET_RULE                                                 \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x833, METHOD_BUFFERED, FILE_READ_ACCESS)

// List all firewall rules
#define IOCTL_SAFEOPS_LIST_RULES                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x834, METHOD_BUFFERED, FILE_READ_ACCESS)

// Clear all firewall rules
#define IOCTL_SAFEOPS_CLEAR_RULES                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x835, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Enable specific rule
#define IOCTL_SAFEOPS_ENABLE_RULE                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x836, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Disable specific rule
#define IOCTL_SAFEOPS_DISABLE_RULE                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x837, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get rule count
#define IOCTL_SAFEOPS_GET_RULE_COUNT                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x838, METHOD_BUFFERED, FILE_READ_ACCESS)

// Import rules (bulk add)
#define IOCTL_SAFEOPS_IMPORT_RULES                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x839, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Export rules (bulk get)
#define IOCTL_SAFEOPS_EXPORT_RULES                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x83A, METHOD_BUFFERED, FILE_READ_ACCESS)

// ============================================================================
// STATISTICS AND MONITORING (0x850-0x86F)
// ============================================================================

// Get packet statistics
#define IOCTL_SAFEOPS_GET_PACKET_STATS                                         \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x850, METHOD_BUFFERED, FILE_READ_ACCESS)

// Get connection statistics
#define IOCTL_SAFEOPS_GET_CONNECTION_STATS                                     \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x851, METHOD_BUFFERED, FILE_READ_ACCESS)

// Get performance metrics
#define IOCTL_SAFEOPS_GET_PERFORMANCE_METRICS                                  \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x852, METHOD_BUFFERED, FILE_READ_ACCESS)

// Get detailed statistics (all counters)
#define IOCTL_SAFEOPS_GET_STATS                                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x853, METHOD_BUFFERED, FILE_READ_ACCESS)

// Reset all counters
#define IOCTL_SAFEOPS_RESET_COUNTERS                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x854, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Reset packet counters
#define IOCTL_SAFEOPS_RESET_PACKET_COUNTERS                                    \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x855, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Reset connection counters
#define IOCTL_SAFEOPS_RESET_CONNECTION_COUNTERS                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x856, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get interface statistics (per-NIC)
#define IOCTL_SAFEOPS_GET_INTERFACE_STATS                                      \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x857, METHOD_BUFFERED, FILE_READ_ACCESS)

// Get protocol distribution statistics
#define IOCTL_SAFEOPS_GET_PROTOCOL_STATS                                       \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x858, METHOD_BUFFERED, FILE_READ_ACCESS)

// Get blocked packets statistics
#define IOCTL_SAFEOPS_GET_BLOCKED_STATS                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x859, METHOD_BUFFERED, FILE_READ_ACCESS)

// ============================================================================
// CONFIGURATION (0x870-0x8FF)
// ============================================================================

// Set NIC tagging configuration
#define IOCTL_SAFEOPS_SET_NIC_TAG                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x870, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get NIC tagging configuration
#define IOCTL_SAFEOPS_GET_NIC_TAG                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x871, METHOD_BUFFERED, FILE_READ_ACCESS)

// Configure RSS (Receive Side Scaling) queues
#define IOCTL_SAFEOPS_SET_RSS_CONFIG                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x872, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get RSS configuration
#define IOCTL_SAFEOPS_GET_RSS_CONFIG                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x873, METHOD_BUFFERED, FILE_READ_ACCESS)

// Set buffer parameters (size, count, etc.)
#define IOCTL_SAFEOPS_SET_BUFFER_PARAMS                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x874, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get buffer parameters
#define IOCTL_SAFEOPS_GET_BUFFER_PARAMS                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x875, METHOD_BUFFERED, FILE_READ_ACCESS)

// Enable hardware offload features
#define IOCTL_SAFEOPS_ENABLE_OFFLOAD                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x876, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Disable hardware offload features
#define IOCTL_SAFEOPS_DISABLE_OFFLOAD                                          \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x877, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Set logging level
#define IOCTL_SAFEOPS_SET_LOG_LEVEL                                            \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x878, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get logging level
#define IOCTL_SAFEOPS_GET_LOG_LEVEL                                            \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x879, METHOD_BUFFERED, FILE_READ_ACCESS)

// Set packet truncation size
#define IOCTL_SAFEOPS_SET_TRUNCATE_SIZE                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x87A, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get packet truncation size
#define IOCTL_SAFEOPS_GET_TRUNCATE_SIZE                                        \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x87B, METHOD_BUFFERED, FILE_READ_ACCESS)

// Set filter optimization level
#define IOCTL_SAFEOPS_SET_FILTER_OPTIMIZATION                                  \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x87C, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Enable/disable debug mode
#define IOCTL_SAFEOPS_SET_DEBUG_MODE                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x87D, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// ============================================================================
// FILTER MANAGEMENT (0x900-0x91F)
// ============================================================================

// Set packet filter (BPF-like)
#define IOCTL_SAFEOPS_SET_FILTER                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x900, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get current filter
#define IOCTL_SAFEOPS_GET_FILTER                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x901, METHOD_BUFFERED, FILE_READ_ACCESS)

// Clear filter (pass all)
#define IOCTL_SAFEOPS_CLEAR_FILTER                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x902, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Add filter expression
#define IOCTL_SAFEOPS_ADD_FILTER_EXPR                                          \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x903, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Remove filter expression
#define IOCTL_SAFEOPS_REMOVE_FILTER_EXPR                                       \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x904, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// ============================================================================
// PACKET READING (0x920-0x92F)
// ============================================================================

// Get packets (direct read, alternative to ring buffer)
#define IOCTL_SAFEOPS_GET_PACKETS                                              \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x920, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

// Peek packets (read without consuming)
#define IOCTL_SAFEOPS_PEEK_PACKETS                                             \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x921, METHOD_OUT_DIRECT, FILE_READ_ACCESS)

// Get packet count in buffer
#define IOCTL_SAFEOPS_GET_PACKET_COUNT                                         \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x922, METHOD_BUFFERED, FILE_READ_ACCESS)

// ============================================================================
// DIAGNOSTIC AND DEBUG (0x930-0x94F)
// ============================================================================

// Run self-test
#define IOCTL_SAFEOPS_SELF_TEST                                                \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x930, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get last error
#define IOCTL_SAFEOPS_GET_LAST_ERROR                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x931, METHOD_BUFFERED, FILE_READ_ACCESS)

// Clear error log
#define IOCTL_SAFEOPS_CLEAR_ERROR_LOG                                          \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x932, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Get debug info
#define IOCTL_SAFEOPS_GET_DEBUG_INFO                                           \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x933, METHOD_BUFFERED, FILE_READ_ACCESS)

// Dump driver state
#define IOCTL_SAFEOPS_DUMP_STATE                                               \
  CTL_CODE(FILE_DEVICE_SAFEOPS, 0x934, METHOD_BUFFERED, FILE_READ_ACCESS)

// ============================================================================
// HELPER MACROS
// ============================================================================

// Extract components from IOCTL code
#define IOCTL_FUNCTION_CODE(code) (((code) >> 2) & 0xFFF)
#define IOCTL_DEVICE_TYPE(code) (((code) >> 16) & 0xFFFF)
#define IOCTL_ACCESS_TYPE(code) ((code) & 0x3)
#define IOCTL_METHOD(code) ((code) & 0x3)

// Check if IOCTL requires write access
#define IOCTL_REQUIRES_WRITE(code)                                             \
  ((IOCTL_ACCESS_TYPE(code) & FILE_WRITE_ACCESS) != 0)

// Check if IOCTL requires read access
#define IOCTL_REQUIRES_READ(code)                                              \
  ((IOCTL_ACCESS_TYPE(code) & FILE_READ_ACCESS) != 0)

#endif // SAFEOPS_IOCTL_CODES_H
