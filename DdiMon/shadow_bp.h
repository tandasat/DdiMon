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
struct SbpData;
struct SharedSbpData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C _In_
    SharedSbpData* SbpAllocateSharedData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void SbpFreeSharedData(_In_ SharedSbpData* shared_sbp_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C SbpData* SbpInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void SbpTermination(_In_ SbpData* sbp_data);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS SbpStart();

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS SbpStop();

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpVmCallDisablePageShadowing(
    _In_ EptData* ept_data, _In_ void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) NTSTATUS
    SbpVmCallEnablePageShadowing(_In_ EptData* ept_data, _In_ void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) void* SbpHandleBreakpoint(
    SbpData* sbp_data, SharedSbpData* shared_sbp_data, void* guest_ip);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpHandleMonitorTrapFlag(
    _In_ SbpData* sbp_data, _In_ SharedSbpData* shared_sbp_data,
    _In_ EptData* ept_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpHandleEptViolation(
    _In_ SbpData* sbp_data, _In_ SharedSbpData* shared_sbp_data,
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
