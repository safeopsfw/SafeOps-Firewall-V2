//==============================================================================
// FILE: src/userspace_service/log_writer.h
//
// SafeOps Log Writer - Header File
//
// PURPOSE:
//   Header file for log writer component
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
//==============================================================================

#ifndef SAFEOPS_LOG_WRITER_H
#define SAFEOPS_LOG_WRITER_H

#include <windows.h>
#include "service_main.h"

//==============================================================================
// PUBLIC FUNCTION PROTOTYPES
//==============================================================================

// Initialization
BOOL LogWriter_Initialize(PLOG_WRITER_CONTEXT ctx, const char *log_directory,
                          BOOL json_format);

// Writing operations
BOOL LogWriter_WritePacket(PLOG_WRITER_CONTEXT ctx, PPACKET_ENTRY packet);

// Flushing
VOID LogWriter_Flush(PLOG_WRITER_CONTEXT ctx);

// Cleanup
VOID LogWriter_Cleanup(PLOG_WRITER_CONTEXT ctx);

#endif // SAFEOPS_LOG_WRITER_H
