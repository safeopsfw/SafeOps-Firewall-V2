/**
 * @file error_codes.h
 * @brief Standardized 32-bit error codes shared between kernel driver and
 * userspace service
 *
 * This header defines a comprehensive set of hierarchically organized error
 * codes (0x00000000-0x9FFFFFFF) covering success conditions, memory failures,
 * ring buffer operations, packet processing, network errors, NDIS driver
 * operations, WFP callout failures, IOCTL communication issues, and userspace
 * service errors.
 *
 * BINARY STABILITY GUARANTEE: Error code numeric values are immutable once
 * defined. Never change an existing error code value - this ensures ABI
 * compatibility.
 *
 * ERROR CODE STRUCTURE (32-bit):
 *   Bits 31-16: Category identifier (0x0000 through 0x9000 in increments of
 * 0x1000) Bits 15-0:  Specific error within category (0x0001 through 0xFFFF)
 *
 * Example: 0x30000001 decodes as:
 *   Category: 0x3000 (Ring Buffer)
 *   Code:     0x0001 (Ring Buffer Full)
 *
 * CATEGORY RANGES:
 *   0x0000xxxx - Success and informational codes
 *   0x1000xxxx - General errors (invalid parameters, timeouts, cancellations)
 *   0x2000xxxx - Memory errors (allocation failures, buffer overflows)
 *   0x3000xxxx - Ring buffer errors (full/empty, corruption, index errors)
 *   0x4000xxxx - Packet processing errors (malformed, checksums, fragmentation)
 *   0x5000xxxx - Network errors (connection failures, protocol errors)
 *   0x6000xxxx - NDIS driver errors (filter operations, send/receive)
 *   0x7000xxxx - WFP callout errors (registration, filter management)
 *   0x8000xxxx - IOCTL errors (invalid codes, buffer sizes, access denied)
 *   0x9000xxxx - Userspace service errors (lifecycle, config, database)
 *   0xA000-0xFFFF - Reserved for future expansion
 *
 * @version 2.0.0
 * @date 2025-12-23
 * @author SafeOps Security Team
 */

#ifndef SAFEOPS_ERROR_CODES_H
#define SAFEOPS_ERROR_CODES_H

/* ============================================================================
 * COMPATIBILITY LAYER
 * ============================================================================
 */

#ifdef _KERNEL_MODE
/* Kernel-mode compilation (Windows Driver Kit) */
#include <ntddk.h>

/* Use ULONG (32-bit unsigned) for error codes in kernel mode */
typedef ULONG SAFEOPS_ERROR;

#else
/* User-mode compilation (Windows SDK) */
/* Only need stdint.h for uint32_t - windows.h should be included by caller */
#include <stdint.h>

/* Use uint32_t for error codes in user mode */
typedef uint32_t SAFEOPS_ERROR;

#endif /* _KERNEL_MODE */

/* ============================================================================
 * SUCCESS CODES (0x0000xxxx Range)
 * Indicates successful operations or informational states without errors.
 * ============================================================================
 */

/**
 * Operation completed successfully without any issues.
 * Standard success return; function accomplished its task.
 */
#define SAFEOPS_SUCCESS 0x00000000

/**
 * Operation initiated successfully but will complete asynchronously later.
 * Kernel driver returns this when operation is queued (e.g., async I/O).
 */
#define SAFEOPS_SUCCESS_PENDING 0x00000001

/**
 * Operation successful but no data available to return.
 * Ring buffer read when buffer is empty (not an error condition).
 */
#define SAFEOPS_SUCCESS_NO_DATA 0x00000002

/* ============================================================================
 * GENERAL ERROR CODES (0x1000xxxx Range)
 * Common errors that don't fit specific categories; system-wide failures.
 * ============================================================================
 */

/**
 * Unspecified general error; catch-all for unexpected failures.
 * Should be rare - prefer specific error codes when possible.
 */
#define SAFEOPS_ERROR_GENERAL 0x10000001

/**
 * Function received null pointer, out-of-range value, or invalid input.
 * Input validation failures.
 */
#define SAFEOPS_ERROR_INVALID_PARAMETER 0x10000002

/**
 * Component not initialized before use.
 * Calling functions before driver/service initialization.
 */
#define SAFEOPS_ERROR_NOT_INITIALIZED 0x10000003

/**
 * Component already initialized; cannot initialize twice.
 * Prevents double-initialization bugs.
 */
#define SAFEOPS_ERROR_ALREADY_INITIALIZED 0x10000004

/**
 * Feature or operation not supported on this system.
 * Hardware doesn't support required features.
 */
#define SAFEOPS_ERROR_NOT_SUPPORTED 0x10000005

/**
 * Operation exceeded time limit and was aborted.
 * Waiting for resources or responses. RETRYABLE.
 */
#define SAFEOPS_ERROR_TIMEOUT 0x10000006

/**
 * Operation was explicitly cancelled by user or system.
 * User interrupts long-running operation.
 */
#define SAFEOPS_ERROR_CANCELLED 0x10000007

/**
 * Resource temporarily unavailable; try again later.
 * Transient failures due to contention. RETRYABLE.
 */
#define SAFEOPS_ERROR_BUSY 0x10000008

/* ============================================================================
 * MEMORY ERROR CODES (0x2000xxxx Range)
 * All memory-related failures including allocation, buffer management,
 * and pointer validation.
 * ============================================================================
 */

/**
 * System out of memory; allocation request failed.
 * Kernel pool allocation (ExAllocatePoolWithTag) returns NULL. CRITICAL.
 */
#define SAFEOPS_ERROR_NO_MEMORY 0x20000001

/**
 * Memory allocation failed for reasons other than out-of-memory.
 * Allocation denied by quota, permissions, or policy. CRITICAL.
 */
#define SAFEOPS_ERROR_ALLOCATION_FAILED 0x20000002

/**
 * Provided buffer insufficient for operation.
 * IOCTL output buffer smaller than required.
 */
#define SAFEOPS_ERROR_BUFFER_TOO_SMALL 0x20000003

/**
 * Writing beyond buffer bounds detected.
 * Security; prevents buffer overflow vulnerabilities.
 */
#define SAFEOPS_ERROR_BUFFER_OVERFLOW 0x20000004

/**
 * Required pointer parameter is NULL.
 * Input validation for pointer arguments.
 */
#define SAFEOPS_ERROR_NULL_POINTER 0x20000005

/**
 * Memory address not valid or not accessible.
 * Attempting to access unmapped memory.
 */
#define SAFEOPS_ERROR_INVALID_ADDRESS 0x20000006

/**
 * Detected memory leak; resource not freed.
 * Debug builds; leak detection instrumentation.
 */
#define SAFEOPS_ERROR_MEMORY_LEAK 0x20000007

/* ============================================================================
 * RING BUFFER ERROR CODES (0x3000xxxx Range)
 * Errors specific to lock-free ring buffer operations between kernel
 * and userspace.
 * ============================================================================
 */

/**
 * Ring buffer has no free slots; cannot write packet.
 * Producer (kernel) faster than consumer (userspace).
 * Action: Packet dropped; increment metrics counter.
 */
#define SAFEOPS_ERROR_RING_BUFFER_FULL 0x30000001

/**
 * Ring buffer has no entries to read.
 * Consumer tries to read but no packets captured yet.
 * Action: Return SAFEOPS_SUCCESS_NO_DATA (not fatal).
 */
#define SAFEOPS_ERROR_RING_BUFFER_EMPTY 0x30000002

/**
 * Ring buffer data structure corrupted; invalid pointers or counts.
 * Detected via signature validation or index checks. CRITICAL.
 * Action: Requires ring buffer reset or system restart.
 */
#define SAFEOPS_ERROR_RING_BUFFER_CORRUPT 0x30000003

/**
 * Write operation would exceed buffer capacity.
 * Attempting to write when buffer full.
 */
#define SAFEOPS_ERROR_RING_BUFFER_OVERFLOW 0x30000004

/**
 * Read operation when buffer empty.
 * Consumer attempts read with no entries.
 */
#define SAFEOPS_ERROR_RING_BUFFER_UNDERFLOW 0x30000005

/**
 * Calculated index outside valid buffer range.
 * Modulo arithmetic error or corruption.
 */
#define SAFEOPS_ERROR_INDEX_OUT_OF_RANGE 0x30000006

/**
 * Entry size doesn't match expected size.
 * Version mismatch between driver and service.
 */
#define SAFEOPS_ERROR_SIZE_MISMATCH 0x30000007

/* ============================================================================
 * PACKET PROCESSING ERROR CODES (0x4000xxxx Range)
 * Errors during packet capture, parsing, validation, and filtering.
 * ============================================================================
 */

/**
 * Packet smaller than minimum valid size for protocol.
 * Truncated or malformed packets.
 */
#define SAFEOPS_ERROR_PACKET_TOO_SMALL 0x40000001

/**
 * Packet exceeds maximum size (MTU or MAX_PACKET_SIZE).
 * Jumbo frames or malicious packets.
 */
#define SAFEOPS_ERROR_PACKET_TOO_LARGE 0x40000002

/**
 * Packet format doesn't match protocol specifications.
 * Invalid field values or structure.
 */
#define SAFEOPS_ERROR_INVALID_PACKET 0x40000003

/**
 * Packet structure is incorrect or corrupted.
 * Header lengths don't match actual data.
 */
#define SAFEOPS_ERROR_MALFORMED_PACKET 0x40000004

/**
 * Packet checksum validation failed.
 * Corrupted packets or transmission errors.
 */
#define SAFEOPS_ERROR_CHECKSUM_FAILED 0x40000005

/**
 * Packet intentionally dropped (firewall rule or policy).
 * Firewall blocked packet.
 */
#define SAFEOPS_ERROR_PACKET_DROPPED 0x40000006

/**
 * Packet is fragmented and cannot be processed.
 * IDS requires complete packets for inspection.
 */
#define SAFEOPS_ERROR_FRAGMENTATION 0x40000007

/**
 * Cannot reassemble fragmented packet.
 * Missing fragments or timeout.
 */
#define SAFEOPS_ERROR_REASSEMBLY_FAILED 0x40000008

/* ============================================================================
 * NETWORK ERROR CODES (0x5000xxxx Range)
 * General network connectivity and protocol errors.
 * ============================================================================
 */

/**
 * Network interface is down or disabled.
 * NIC not operational.
 */
#define SAFEOPS_ERROR_NETWORK_DOWN 0x50000001

/**
 * Destination network not reachable.
 * Routing failures.
 */
#define SAFEOPS_ERROR_NETWORK_UNREACHABLE 0x50000002

/**
 * Remote host refused connection (TCP RST received).
 * Service not listening on port.
 */
#define SAFEOPS_ERROR_CONNECTION_REFUSED 0x50000003

/**
 * Connection attempt timed out.
 * No response from remote host. RETRYABLE.
 */
#define SAFEOPS_ERROR_CONNECTION_TIMEOUT 0x50000004

/**
 * Connection forcibly closed (TCP RST).
 * Abrupt connection termination.
 */
#define SAFEOPS_ERROR_CONNECTION_RESET 0x50000005

/**
 * Protocol violation or unexpected sequence.
 * Invalid state transitions.
 */
#define SAFEOPS_ERROR_PROTOCOL_ERROR 0x50000006

/**
 * IP address or port already bound.
 * Socket binding failures.
 */
#define SAFEOPS_ERROR_ADDRESS_IN_USE 0x50000007

/* ============================================================================
 * NDIS ERROR CODES (0x6000xxxx Range)
 * Windows NDIS filter driver specific errors.
 * ============================================================================
 */

/**
 * Unspecified NDIS driver error.
 * Catch-all for NDIS failures.
 */
#define SAFEOPS_ERROR_NDIS_GENERAL 0x60000001

/**
 * Filter failed to attach to network adapter.
 * Driver initialization failure.
 */
#define SAFEOPS_ERROR_NDIS_ATTACH_FAILED 0x60000002

/**
 * Filter failed to detach from adapter.
 * Driver unload issues.
 */
#define SAFEOPS_ERROR_NDIS_DETACH_FAILED 0x60000003

/**
 * Filter operation failed (packet inspection error).
 * Packet processing failures.
 */
#define SAFEOPS_ERROR_NDIS_FILTER_FAILED 0x60000004

/**
 * Packet send operation failed.
 * Outbound packet injection errors.
 */
#define SAFEOPS_ERROR_NDIS_SEND_FAILED 0x60000005

/**
 * Packet receive operation failed.
 * Inbound packet processing errors.
 */
#define SAFEOPS_ERROR_NDIS_RECEIVE_FAILED 0x60000006

/**
 * Filter failed to pause.
 * Power management or reconfiguration issues.
 */
#define SAFEOPS_ERROR_NDIS_PAUSE_FAILED 0x60000007

/**
 * Filter failed to restart after pause.
 * Resume from suspend failures.
 */
#define SAFEOPS_ERROR_NDIS_RESTART_FAILED 0x60000008

/* ============================================================================
 * WFP ERROR CODES (0x7000xxxx Range)
 * Windows Filtering Platform callout errors.
 * ============================================================================
 */

/**
 * Unspecified WFP error.
 * Catch-all for WFP failures.
 */
#define SAFEOPS_ERROR_WFP_GENERAL 0x70000001

/**
 * Failed to register WFP callout.
 * Callout registration during driver initialization.
 */
#define SAFEOPS_ERROR_WFP_CALLOUT_REGISTER 0x70000002

/**
 * Failed to unregister WFP callout.
 * Driver unload cleanup.
 */
#define SAFEOPS_ERROR_WFP_CALLOUT_UNREGISTER 0x70000003

/**
 * Failed to add WFP filter.
 * Filter rule installation.
 */
#define SAFEOPS_ERROR_WFP_FILTER_ADD 0x70000004

/**
 * Failed to remove WFP filter.
 * Filter rule deletion.
 */
#define SAFEOPS_ERROR_WFP_FILTER_REMOVE 0x70000005

/**
 * Failed to open WFP engine handle.
 * Engine initialization.
 */
#define SAFEOPS_ERROR_WFP_ENGINE_OPEN 0x70000006

/**
 * Failed to close WFP engine handle.
 * Engine cleanup.
 */
#define SAFEOPS_ERROR_WFP_ENGINE_CLOSE 0x70000007

/**
 * WFP classify callback failed to process packet.
 * Packet classification errors.
 */
#define SAFEOPS_ERROR_WFP_CLASSIFY_FAILED 0x70000008

/* ============================================================================
 * IOCTL ERROR CODES (0x8000xxxx Range)
 * Errors in IOCTL communication channel between userspace and kernel.
 * ============================================================================
 */

/**
 * IOCTL control code not recognized.
 * Userspace sends unsupported IOCTL.
 */
#define SAFEOPS_ERROR_IOCTL_INVALID_CODE 0x80000001

/**
 * Input/output buffer size incorrect.
 * Buffer size validation.
 */
#define SAFEOPS_ERROR_IOCTL_BUFFER_SIZE 0x80000002

/**
 * Insufficient permissions for IOCTL operation.
 * Security checks.
 */
#define SAFEOPS_ERROR_IOCTL_ACCESS_DENIED 0x80000003

/**
 * Device busy processing another IOCTL.
 * Serialization of conflicting operations. RETRYABLE.
 */
#define SAFEOPS_ERROR_IOCTL_DEVICE_BUSY 0x80000004

/**
 * Device not ready to process IOCTL.
 * Driver initialization incomplete.
 */
#define SAFEOPS_ERROR_IOCTL_NOT_READY 0x80000005

/**
 * IOCTL operation failed for unspecified reason.
 * General IOCTL failure.
 */
#define SAFEOPS_ERROR_IOCTL_FAILED 0x80000006

/* ============================================================================
 * USERSPACE SERVICE ERROR CODES (0x9000xxxx Range)
 * Errors in userspace service component.
 * ============================================================================
 */

/**
 * Service not started or stopped.
 * Operations requiring running service.
 */
#define SAFEOPS_ERROR_SERVICE_NOT_RUNNING 0x90000001

/**
 * Service failed to start.
 * Service initialization errors.
 */
#define SAFEOPS_ERROR_SERVICE_START_FAILED 0x90000002

/**
 * Service failed to stop gracefully.
 * Shutdown issues.
 */
#define SAFEOPS_ERROR_SERVICE_STOP_FAILED 0x90000003

/**
 * Configuration file load failed.
 * Config parsing errors.
 */
#define SAFEOPS_ERROR_CONFIG_LOAD_FAILED 0x90000004

/**
 * Cannot write to log file.
 * Logging failures.
 */
#define SAFEOPS_ERROR_LOG_WRITE_FAILED 0x90000005

/**
 * Database operation failed.
 * PostgreSQL connection or query errors.
 */
#define SAFEOPS_ERROR_DATABASE_ERROR 0x90000006

/**
 * File I/O operation failed.
 * Reading/writing files.
 */
#define SAFEOPS_ERROR_FILE_IO_ERROR 0x90000007

/* ============================================================================
 * ERROR CODE UTILITY MACROS
 * Helper macros for working with error codes programmatically.
 * ============================================================================
 */

/**
 * Check if error code indicates success.
 * Returns non-zero (TRUE) if code is in success range (0x0000xxxx).
 * @param code The error code to check
 */
#define SAFEOPS_SUCCEEDED(code) (((code) & 0xFFFF0000) == 0x00000000)

/**
 * Check if error code indicates failure.
 * Returns non-zero (TRUE) if code is NOT in success range.
 * @param code The error code to check
 */
#define SAFEOPS_FAILED(code) (((code) & 0xFFFF0000) != 0x00000000)

/**
 * Extract category from error code (upper 16 bits).
 * Returns the category portion of the error code.
 * @param code The error code
 * @return Category value (0x10000000, 0x20000000, etc.)
 */
#define SAFEOPS_ERROR_CATEGORY(code) ((code) & 0xFFFF0000)

/**
 * Extract specific error code within category (lower 16 bits).
 * Returns the specific error number within its category.
 * @param code The error code
 * @return Specific code value (0x0001, 0x0002, etc.)
 */
#define SAFEOPS_ERROR_CODE(code) ((code) & 0x0000FFFF)

/**
 * Check if error is memory-related.
 * @param code The error code to check
 * @return Non-zero if error is in memory category (0x2000xxxx)
 */
#define SAFEOPS_IS_MEMORY_ERROR(code)                                          \
  (SAFEOPS_ERROR_CATEGORY(code) == 0x20000000)

/**
 * Check if error is network-related.
 * @param code The error code to check
 * @return Non-zero if error is in network category (0x5000xxxx)
 */
#define SAFEOPS_IS_NETWORK_ERROR(code)                                         \
  (SAFEOPS_ERROR_CATEGORY(code) == 0x50000000)

/**
 * Check if error is ring buffer-related.
 * @param code The error code to check
 * @return Non-zero if error is in ring buffer category (0x3000xxxx)
 */
#define SAFEOPS_IS_RING_BUFFER_ERROR(code)                                     \
  (SAFEOPS_ERROR_CATEGORY(code) == 0x30000000)

/**
 * Check if error is IOCTL-related.
 * @param code The error code to check
 * @return Non-zero if error is in IOCTL category (0x8000xxxx)
 */
#define SAFEOPS_IS_IOCTL_ERROR(code)                                           \
  (SAFEOPS_ERROR_CATEGORY(code) == 0x80000000)

/**
 * Determine if error is critical (system cannot continue).
 * Critical errors include: RING_BUFFER_CORRUPT, NO_MEMORY, ALLOCATION_FAILED
 * @param code The error code to check
 * @return Non-zero if error is critical
 */
#define SAFEOPS_IS_CRITICAL(code)                                              \
  ((code) == SAFEOPS_ERROR_RING_BUFFER_CORRUPT ||                              \
   (code) == SAFEOPS_ERROR_NO_MEMORY ||                                        \
   (code) == SAFEOPS_ERROR_ALLOCATION_FAILED)

/**
 * Determine if error is transient and can be retried.
 * Retryable errors include: TIMEOUT, BUSY, DEVICE_BUSY, CONNECTION_TIMEOUT
 * @param code The error code to check
 * @return Non-zero if error is retryable
 */
#define SAFEOPS_IS_RETRYABLE(code)                                             \
  ((code) == SAFEOPS_ERROR_TIMEOUT || (code) == SAFEOPS_ERROR_BUSY ||          \
   (code) == SAFEOPS_ERROR_IOCTL_DEVICE_BUSY ||                                \
   (code) == SAFEOPS_ERROR_CONNECTION_TIMEOUT)

/* ============================================================================
 * ERROR-TO-STRING CONVERSION (User-Mode Only)
 * Provides human-readable error messages for logging and debugging.
 * ============================================================================
 */

#ifndef _KERNEL_MODE

/**
 * Convert error code to human-readable string.
 * Returns descriptive string for known error codes.
 * Returns "Unknown Error (0xXXXXXXXX)" for unrecognized codes.
 *
 * NOTE: Implementation in error_strings.c, not in header.
 *
 * @param errorCode The error code to convert
 * @return Pointer to static string describing the error
 */
const char *SafeOpsErrorToString(SAFEOPS_ERROR errorCode);

#endif /* !_KERNEL_MODE */

/* ============================================================================
 * STATIC ASSERTIONS (Compile-Time Validation)
 * Verifies error code definitions at compile time to catch mistakes.
 * ============================================================================
 */

/* C11 _Static_assert or MSVC static_assert - guard against redefinition */
#ifndef SAFEOPS_STATIC_ASSERT
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
/* C11 or later: use _Static_assert */
#define SAFEOPS_STATIC_ASSERT(expr, msg) _Static_assert(expr, msg)
#elif defined(_MSC_VER)
/* MSVC: use static_assert */
#define SAFEOPS_STATIC_ASSERT(expr, msg) static_assert(expr, msg)
#else
/* Fallback: typedef trick for older compilers */
#define SAFEOPS_STATIC_ASSERT_IMPL(expr, line)                                 \
  typedef char safeops_static_assert_##line[(expr) ? 1 : -1]
#define SAFEOPS_STATIC_ASSERT(expr, msg)                                       \
  SAFEOPS_STATIC_ASSERT_IMPL(expr, __LINE__)
#endif
#endif /* SAFEOPS_STATIC_ASSERT */

/* Verify error code sizes are 32-bit */
SAFEOPS_STATIC_ASSERT(sizeof(SAFEOPS_ERROR) == 4,
                      "Error codes must be exactly 32 bits");

/* Verify success codes are in 0x0000xxxx range */
SAFEOPS_STATIC_ASSERT((SAFEOPS_SUCCESS & 0xFFFF0000) == 0,
                      "SAFEOPS_SUCCESS must be in 0x0000xxxx range");
SAFEOPS_STATIC_ASSERT((SAFEOPS_SUCCESS_PENDING & 0xFFFF0000) == 0,
                      "SAFEOPS_SUCCESS_PENDING must be in 0x0000xxxx range");
SAFEOPS_STATIC_ASSERT((SAFEOPS_SUCCESS_NO_DATA & 0xFFFF0000) == 0,
                      "SAFEOPS_SUCCESS_NO_DATA must be in 0x0000xxxx range");

/* Verify categories are correct */
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_GENERAL) ==
                          0x10000000,
                      "General errors must be in 0x1000xxxx range");
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_NO_MEMORY) ==
                          0x20000000,
                      "Memory errors must be in 0x2000xxxx range");
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_RING_BUFFER_FULL) ==
                          0x30000000,
                      "Ring buffer errors must be in 0x3000xxxx range");
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_PACKET_TOO_SMALL) ==
                          0x40000000,
                      "Packet errors must be in 0x4000xxxx range");
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_NETWORK_DOWN) ==
                          0x50000000,
                      "Network errors must be in 0x5000xxxx range");
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_NDIS_GENERAL) ==
                          0x60000000,
                      "NDIS errors must be in 0x6000xxxx range");
SAFEOPS_STATIC_ASSERT(SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_WFP_GENERAL) ==
                          0x70000000,
                      "WFP errors must be in 0x7000xxxx range");
SAFEOPS_STATIC_ASSERT(
    SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_IOCTL_INVALID_CODE) == 0x80000000,
    "IOCTL errors must be in 0x8000xxxx range");
SAFEOPS_STATIC_ASSERT(
    SAFEOPS_ERROR_CATEGORY(SAFEOPS_ERROR_SERVICE_NOT_RUNNING) == 0x90000000,
    "Service errors must be in 0x9000xxxx range");

#endif /* SAFEOPS_ERROR_CODES_H */
