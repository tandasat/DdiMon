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
struct ShadowHookData;
struct SharedShadowHookData;

// Expresses where to install hooks by a function name, and its handlers
struct ShadowHookTarget {
  UNICODE_STRING target_name;  // An export name to hook
  void* handler;               // An address of a hook handler

  // An address of a trampoline code to call original function. Initialized by
  // a successful call of ShInstallHook().
  void* original_call;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    ShadowHookData* ShAllocateShadowHookData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void ShFreeShadowHookData(_In_ ShadowHookData* sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    SharedShadowHookData* ShAllocateSharedShaowHookData();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    void ShFreeSharedShadowHookData(_In_ SharedShadowHookData* shared_sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS ShEnableHooks();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS ShDisableHooks();

_IRQL_requires_min_(DISPATCH_LEVEL) NTSTATUS
    ShEnablePageShadowing(_In_ EptData* ept_data,
                          _In_ const SharedShadowHookData* shared_sh_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void ShVmCallDisablePageShadowing(
    _In_ EptData* ept_data, _In_ const SharedShadowHookData* shared_sh_data);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    bool ShInstallHook(_In_ SharedShadowHookData* shared_sh_data,
                       _In_ void* address, _In_ ShadowHookTarget* target);

_IRQL_requires_min_(DISPATCH_LEVEL) bool ShHandleBreakpoint(
    _In_ ShadowHookData* sh_data,
    _In_ const SharedShadowHookData* shared_sh_data, _In_ void* guest_ip);

_IRQL_requires_min_(DISPATCH_LEVEL) void ShHandleMonitorTrapFlag(
    _In_ ShadowHookData* sh_data,
    _In_ const SharedShadowHookData* shared_sh_data, _In_ EptData* ept_data);

_IRQL_requires_min_(DISPATCH_LEVEL) void ShHandleEptViolation(
    _In_ ShadowHookData* sh_data,
    _In_ const SharedShadowHookData* shared_sh_data, _In_ EptData* ept_data,
    _In_ void* fault_va);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // DDIMON_SHADOW_HOOK_H_
