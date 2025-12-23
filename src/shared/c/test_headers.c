/**
 * @file test_headers.c
 * @brief Test file to verify all C headers compile correctly
 */

/* Test user-mode compilation */
#define _WIN32_WINNT 0x0601

/* Include all SafeOps headers in correct order */
#include "error_codes.h"
#include "ioctl_codes.h"
#include "packet_structs.h"
#include "ring_buffer.h"
#include "shared_constants.h"

#include <stdio.h>

int main(void) {
  printf("=== SafeOps C Headers Compilation Test ===\n\n");

  /* Test shared_constants.h */
  printf("shared_constants.h:\n");
  printf("  SAFEOPS_VERSION: %d.%d.%d\n", SAFEOPS_DRIVER_VERSION_MAJOR,
         SAFEOPS_DRIVER_VERSION_MINOR, SAFEOPS_DRIVER_VERSION_PATCH);
  printf("  MAX_PACKET_SIZE: %u\n", MAX_PACKET_SIZE);
  printf("  RING_BUFFER_MAX_ENTRIES: %llu\n",
         (unsigned long long)RING_BUFFER_MAX_ENTRIES);
  printf("  RING_BUFFER_SIGNATURE: 0x%08X\n", RING_BUFFER_SIGNATURE);

  /* Test error_codes.h */
  printf("\nerror_codes.h:\n");
  printf("  SAFEOPS_SUCCESS: 0x%08X\n", SAFEOPS_SUCCESS);
  printf("  SAFEOPS_ERROR_RING_BUFFER_FULL: 0x%08X\n",
         SAFEOPS_ERROR_RING_BUFFER_FULL);
  printf("  SAFEOPS_ERROR_GENERAL: 0x%08X\n", SAFEOPS_ERROR_GENERAL);
  printf("  SAFEOPS_SUCCEEDED(0x00000000): %s\n",
         SAFEOPS_SUCCEEDED(0x00000000) ? "TRUE" : "FALSE");
  printf("  SAFEOPS_FAILED(0x30000001): %s\n",
         SAFEOPS_FAILED(0x30000001) ? "TRUE" : "FALSE");
  printf("  SAFEOPS_IS_CRITICAL(RING_BUFFER_CORRUPT): %s\n",
         SAFEOPS_IS_CRITICAL(SAFEOPS_ERROR_RING_BUFFER_CORRUPT) ? "TRUE"
                                                                : "FALSE");
  printf("  SAFEOPS_ERROR_CATEGORY(0x30000001): 0x%08X\n",
         SAFEOPS_ERROR_CATEGORY(0x30000001));

  /* Test ring_buffer.h */
  printf("\nring_buffer.h:\n");
  printf("  sizeof(RING_BUFFER_HEADER): %zu bytes\n",
         sizeof(RING_BUFFER_HEADER));
  printf("  sizeof(RING_BUFFER_ENTRY): %zu bytes\n", sizeof(RING_BUFFER_ENTRY));

  /* Test packet_structs.h */
  printf("\npacket_structs.h:\n");
  printf("  sizeof(ETHERNET_HEADER): %zu bytes\n", sizeof(ETHERNET_HEADER));
  printf("  sizeof(IPV4_HEADER): %zu bytes\n", sizeof(IPV4_HEADER));
  printf("  sizeof(IPV6_HEADER): %zu bytes\n", sizeof(IPV6_HEADER));
  printf("  sizeof(TCP_HEADER): %zu bytes\n", sizeof(TCP_HEADER));
  printf("  sizeof(UDP_HEADER): %zu bytes\n", sizeof(UDP_HEADER));
  printf("  sizeof(SAFEOPS_PACKET): %zu bytes\n", sizeof(SAFEOPS_PACKET));

  /* Test ioctl_codes.h */
  printf("\nioctl_codes.h:\n");
  printf("  IOCTL_SAFEOPS_GET_VERSION: 0x%08lX\n",
         (unsigned long)IOCTL_SAFEOPS_GET_VERSION);
  printf("  IOCTL_SAFEOPS_GET_GLOBAL_STATS: 0x%08lX\n",
         (unsigned long)IOCTL_SAFEOPS_GET_GLOBAL_STATS);
  printf("  IOCTL_SAFEOPS_ADD_FILTER_RULE: 0x%08lX\n",
         (unsigned long)IOCTL_SAFEOPS_ADD_FILTER_RULE);

  printf("\n=== ALL 5 HEADERS COMPILED SUCCESSFULLY ===\n");

  return 0;
}
