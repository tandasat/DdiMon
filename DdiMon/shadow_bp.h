// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to shadow breakpoint functions.

#ifndef DDIMON_SHADOW_BP_H_
#define DDIMON_SHADOW_BP_H_

#include "../HyperPlatform/HyperPlatform/ia32_type.h"

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct EptData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS SbpInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS SbpStart();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void SbpTermination();

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpVmCallDisablePageShadowing(
    EptData* ept_data, void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) NTSTATUS
    SbpVmCallEnablePageShadowing(EptData* ept_data, void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) bool SbpHandleBreakpoint(
    _In_ EptData* ept_data, _In_ void* guest_ip, _In_ GpRegisters* gp_regs);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpHandleMonitorTrapFlag(
    _In_ EptData* ept_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpHandleEptViolation(
    _In_ EptData* ept_data, _In_ void* fault_va);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // DDIMON_SHADOW_BP_H_
