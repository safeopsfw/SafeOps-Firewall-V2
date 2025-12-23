/**
 * @file error_strings.c
 * @brief User-mode implementation of SafeOpsErrorToString()
 *
 * Provides human-readable error messages for logging and debugging.
 * This file is only compiled for userspace service, NOT for kernel driver.
 *
 * @version 2.0.0
 * @date 2025-12-23
 * @author SafeOps Security Team
 */

#include "error_codes.h"
#include <stdio.h>

/* Only compile for user-mode */
#ifndef _KERNEL_MODE

/**
 * Convert error code to human-readable string.
 *
 * @param errorCode The error code to convert
 * @return Pointer to static string describing the error
 */
const char *SafeOpsErrorToString(SAFEOPS_ERROR errorCode) {
  switch (errorCode) {
  /* Success Codes */
  case SAFEOPS_SUCCESS:
    return "Success";
  case SAFEOPS_SUCCESS_PENDING:
    return "Operation Pending";
  case SAFEOPS_SUCCESS_NO_DATA:
    return "Success (No Data)";

  /* General Errors */
  case SAFEOPS_ERROR_GENERAL:
    return "General Error";
  case SAFEOPS_ERROR_INVALID_PARAMETER:
    return "Invalid Parameter";
  case SAFEOPS_ERROR_NOT_INITIALIZED:
    return "Not Initialized";
  case SAFEOPS_ERROR_ALREADY_INITIALIZED:
    return "Already Initialized";
  case SAFEOPS_ERROR_NOT_SUPPORTED:
    return "Not Supported";
  case SAFEOPS_ERROR_TIMEOUT:
    return "Timeout";
  case SAFEOPS_ERROR_CANCELLED:
    return "Cancelled";
  case SAFEOPS_ERROR_BUSY:
    return "Resource Busy";

  /* Memory Errors */
  case SAFEOPS_ERROR_NO_MEMORY:
    return "Out of Memory";
  case SAFEOPS_ERROR_ALLOCATION_FAILED:
    return "Allocation Failed";
  case SAFEOPS_ERROR_BUFFER_TOO_SMALL:
    return "Buffer Too Small";
  case SAFEOPS_ERROR_BUFFER_OVERFLOW:
    return "Buffer Overflow";
  case SAFEOPS_ERROR_NULL_POINTER:
    return "Null Pointer";
  case SAFEOPS_ERROR_INVALID_ADDRESS:
    return "Invalid Address";
  case SAFEOPS_ERROR_MEMORY_LEAK:
    return "Memory Leak Detected";

  /* Ring Buffer Errors */
  case SAFEOPS_ERROR_RING_BUFFER_FULL:
    return "Ring Buffer Full";
  case SAFEOPS_ERROR_RING_BUFFER_EMPTY:
    return "Ring Buffer Empty";
  case SAFEOPS_ERROR_RING_BUFFER_CORRUPT:
    return "Ring Buffer Corrupt (CRITICAL)";
  case SAFEOPS_ERROR_RING_BUFFER_OVERFLOW:
    return "Ring Buffer Overflow";
  case SAFEOPS_ERROR_RING_BUFFER_UNDERFLOW:
    return "Ring Buffer Underflow";
  case SAFEOPS_ERROR_INDEX_OUT_OF_RANGE:
    return "Index Out of Range";
  case SAFEOPS_ERROR_SIZE_MISMATCH:
    return "Size Mismatch";

  /* Packet Processing Errors */
  case SAFEOPS_ERROR_PACKET_TOO_SMALL:
    return "Packet Too Small";
  case SAFEOPS_ERROR_PACKET_TOO_LARGE:
    return "Packet Too Large";
  case SAFEOPS_ERROR_INVALID_PACKET:
    return "Invalid Packet";
  case SAFEOPS_ERROR_MALFORMED_PACKET:
    return "Malformed Packet";
  case SAFEOPS_ERROR_CHECKSUM_FAILED:
    return "Checksum Failed";
  case SAFEOPS_ERROR_PACKET_DROPPED:
    return "Packet Dropped";
  case SAFEOPS_ERROR_FRAGMENTATION:
    return "Packet Fragmented";
  case SAFEOPS_ERROR_REASSEMBLY_FAILED:
    return "Fragment Reassembly Failed";

  /* Network Errors */
  case SAFEOPS_ERROR_NETWORK_DOWN:
    return "Network Down";
  case SAFEOPS_ERROR_NETWORK_UNREACHABLE:
    return "Network Unreachable";
  case SAFEOPS_ERROR_CONNECTION_REFUSED:
    return "Connection Refused";
  case SAFEOPS_ERROR_CONNECTION_TIMEOUT:
    return "Connection Timeout";
  case SAFEOPS_ERROR_CONNECTION_RESET:
    return "Connection Reset";
  case SAFEOPS_ERROR_PROTOCOL_ERROR:
    return "Protocol Error";
  case SAFEOPS_ERROR_ADDRESS_IN_USE:
    return "Address In Use";

  /* NDIS Errors */
  case SAFEOPS_ERROR_NDIS_GENERAL:
    return "NDIS Error";
  case SAFEOPS_ERROR_NDIS_ATTACH_FAILED:
    return "NDIS Attach Failed";
  case SAFEOPS_ERROR_NDIS_DETACH_FAILED:
    return "NDIS Detach Failed";
  case SAFEOPS_ERROR_NDIS_FILTER_FAILED:
    return "NDIS Filter Failed";
  case SAFEOPS_ERROR_NDIS_SEND_FAILED:
    return "NDIS Send Failed";
  case SAFEOPS_ERROR_NDIS_RECEIVE_FAILED:
    return "NDIS Receive Failed";
  case SAFEOPS_ERROR_NDIS_PAUSE_FAILED:
    return "NDIS Pause Failed";
  case SAFEOPS_ERROR_NDIS_RESTART_FAILED:
    return "NDIS Restart Failed";

  /* WFP Errors */
  case SAFEOPS_ERROR_WFP_GENERAL:
    return "WFP Error";
  case SAFEOPS_ERROR_WFP_CALLOUT_REGISTER:
    return "WFP Callout Register Failed";
  case SAFEOPS_ERROR_WFP_CALLOUT_UNREGISTER:
    return "WFP Callout Unregister Failed";
  case SAFEOPS_ERROR_WFP_FILTER_ADD:
    return "WFP Filter Add Failed";
  case SAFEOPS_ERROR_WFP_FILTER_REMOVE:
    return "WFP Filter Remove Failed";
  case SAFEOPS_ERROR_WFP_ENGINE_OPEN:
    return "WFP Engine Open Failed";
  case SAFEOPS_ERROR_WFP_ENGINE_CLOSE:
    return "WFP Engine Close Failed";
  case SAFEOPS_ERROR_WFP_CLASSIFY_FAILED:
    return "WFP Classify Failed";

  /* IOCTL Errors */
  case SAFEOPS_ERROR_IOCTL_INVALID_CODE:
    return "Invalid IOCTL Code";
  case SAFEOPS_ERROR_IOCTL_BUFFER_SIZE:
    return "IOCTL Buffer Size Error";
  case SAFEOPS_ERROR_IOCTL_ACCESS_DENIED:
    return "IOCTL Access Denied";
  case SAFEOPS_ERROR_IOCTL_DEVICE_BUSY:
    return "IOCTL Device Busy";
  case SAFEOPS_ERROR_IOCTL_NOT_READY:
    return "IOCTL Device Not Ready";
  case SAFEOPS_ERROR_IOCTL_FAILED:
    return "IOCTL Failed";

  /* Userspace Service Errors */
  case SAFEOPS_ERROR_SERVICE_NOT_RUNNING:
    return "Service Not Running";
  case SAFEOPS_ERROR_SERVICE_START_FAILED:
    return "Service Start Failed";
  case SAFEOPS_ERROR_SERVICE_STOP_FAILED:
    return "Service Stop Failed";
  case SAFEOPS_ERROR_CONFIG_LOAD_FAILED:
    return "Config Load Failed";
  case SAFEOPS_ERROR_LOG_WRITE_FAILED:
    return "Log Write Failed";
  case SAFEOPS_ERROR_DATABASE_ERROR:
    return "Database Error";
  case SAFEOPS_ERROR_FILE_IO_ERROR:
    return "File I/O Error";

  default: {
    /* Return hex code for unknown errors */
    static char unknownBuffer[64];
    snprintf(unknownBuffer, sizeof(unknownBuffer), "Unknown Error (0x%08X)",
             errorCode);
    return unknownBuffer;
  }
  }
}

/**
 * Get error category name as string.
 *
 * @param errorCode The error code to get category for
 * @return Pointer to static string describing the category
 */
const char *SafeOpsErrorCategoryToString(SAFEOPS_ERROR errorCode) {
  switch (SAFEOPS_ERROR_CATEGORY(errorCode)) {
  case 0x00000000:
    return "Success";
  case 0x10000000:
    return "General";
  case 0x20000000:
    return "Memory";
  case 0x30000000:
    return "Ring Buffer";
  case 0x40000000:
    return "Packet Processing";
  case 0x50000000:
    return "Network";
  case 0x60000000:
    return "NDIS Driver";
  case 0x70000000:
    return "WFP Callout";
  case 0x80000000:
    return "IOCTL";
  case 0x90000000:
    return "Userspace Service";
  default:
    return "Unknown Category";
  }
}

#endif /* !_KERNEL_MODE */
