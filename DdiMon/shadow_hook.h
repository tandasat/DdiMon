// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to shadow hook functions.

#ifndef DDIMON_SHADOW_HOOK_H_
#define DDIMON_SHADOW_HOOK_H_

#include <fltKernel.h>

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

// Expresses where to set a breakpoint by a function name and its handlers
struct BreakpointTarget {
  UNICODE_STRING target_name;
  void* handler;
  void* original_call;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C SbpData* SbpInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void SbpTermination(_In_ SbpData* sbp_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C 
    SharedSbpData* SbpAllocateSharedData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void SbpFreeSharedData(_In_ SharedSbpData* shared_sbp_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS SbpStart();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS SbpStop();

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpVmCallDisablePageShadowing(
    _In_ EptData* ept_data, _In_ void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) NTSTATUS
    SbpVmCallEnablePageShadowing(_In_ EptData* ept_data, _In_ void* context);

_IRQL_requires_min_(DISPATCH_LEVEL) void* SbpHandleBreakpoint(
  _In_ SbpData* sbp_data, _In_  SharedSbpData* shared_sbp_data, 
  _In_ void* guest_ip);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpHandleMonitorTrapFlag(
    _In_ SbpData* sbp_data, _In_ SharedSbpData* shared_sbp_data,
    _In_ EptData* ept_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpHandleEptViolation(
    _In_ SbpData* sbp_data, _In_ SharedSbpData* shared_sbp_data,
    _In_ EptData* ept_data, _In_ void* fault_va);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C bool SbpCreatePreBreakpoint(
    _In_ SharedSbpData* shared_sbp_data, _In_ void* address,
    _In_ BreakpointTarget* target, _In_ const char* name);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // DDIMON_SHADOW_HOOK_H_
