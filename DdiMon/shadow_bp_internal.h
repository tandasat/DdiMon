// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// @brief Declares interfaces to shadow breakpoint internal functions.

#ifndef DDIMON_SHADOW_BP_INTERNAL_H_
#define DDIMON_SHADOW_BP_INTERNAL_H_

#include "../HyperPlatform/HyperPlatform/ia32_type.h"
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <array>

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
struct Page;
struct PatchInformation;

// Breakpoint handler type
using BreakpointHandlerType = void (*)(const PatchInformation& info,
                                       EptData* ept_data, GpRegisters* gp_reg,
                                       ULONG_PTR guest_sp);

// Expresses where to set a breakpoint by a function name and its handlers
struct BreakpointTarget {
  UNICODE_STRING target_name;
  BreakpointHandlerType pre_handler;
  BreakpointHandlerType post_handler;
};

// A type of breakpoint
enum class BreakpointType {
  kPre,   // pre_handler is called
  kPost,  // post_handler is called
};

// Holds at most 16 function paramaters
using CapturedParameters = std::array<ULONG_PTR, 16>;

// Represents shadow breakpoint
struct PatchInformation {
  BreakpointType type;
  void* patch_address;  // An address of breakpoint

  // A copy of a pages where patch_address belongs to. shadow_page_base_for_rw
  // is exposed to a guest for read and write operation against the page of
  // patch_address, and shadow_page_base_for_exec is exposed for execution.
  std::shared_ptr<Page> shadow_page_base_for_rw;
  std::shared_ptr<Page> shadow_page_base_for_exec;

  // Phyisical address of the above two copied pages
  ULONG64 pa_base_for_rw;
  ULONG64 pa_base_for_exec;

  // Hanlder to be called
  BreakpointHandlerType handler;

  // If type is kPre, this is used to create kPost breakpoint on hit of the
  // breakpoint as needed. If type is kPost, it is always nullptr because
  // a handler is saved to and called via handler.
  BreakpointHandlerType post_handler;

  // If type is kPre, it is ignored. If type is kPost, it is used to determine
  // a thread hitting the breakpoint is the same thread as one hit a
  // corresponding kPre breakpoint.
  HANDLE target_tid;

  // If type is kPre, it is ignored. If type is kPost, it can hold function
  // parameters inspected in a pre-handler.
  CapturedParameters parameters;

  // A name of breakpont (a DDI name)
  std::array<char, 64> name;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

void SbpCreatePreBreakpoint(_In_ void* address,
                            _In_ const BreakpointTarget& target,
                            _In_ const char* name);

_IRQL_requires_min_(DISPATCH_LEVEL) void SbpCreateAndEnablePostBreakpoint(
    _In_ void* address, _In_ const PatchInformation& info,
    _In_ const CapturedParameters& parameters, _In_ EptData* ept_data);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // DDIMON_SHADOW_BP_INTERNAL_H_
