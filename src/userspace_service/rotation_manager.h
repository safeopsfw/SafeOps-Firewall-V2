//==============================================================================
// FILE: src/userspace_service/rotation_manager.h
//
// SafeOps Rotation Manager - Header File
//
// PURPOSE:
//   Header file for rotation manager component
//
// AUTHOR: SafeOps Security
// VERSION: 2.0.0
//==============================================================================

#ifndef SAFEOPS_ROTATION_MANAGER_H
#define SAFEOPS_ROTATION_MANAGER_H

#include <windows.h>
#include "service_main.h"

//==============================================================================
// PUBLIC FUNCTION PROTOTYPES
//==============================================================================

// Initialization
BOOL RotationManager_Initialize(PROTATION_CONTEXT ctx,
                                PLOG_WRITER_CONTEXT log_writer,
                                DWORD interval_ms);

// Rotation operations
BOOL RotationManager_Rotate(PROTATION_CONTEXT ctx);

// Cleanup
VOID RotationManager_Cleanup(PROTATION_CONTEXT ctx);

#endif // SAFEOPS_ROTATION_MANAGER_H
