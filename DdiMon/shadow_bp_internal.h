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

// Expresses where to set a breakpoint by a function name and its handlers
struct BreakpointTarget {
  UNICODE_STRING target_name;
  void* handler;
  void* original_call;
};

struct PatchInfoDetails {
  SIZE_T patch_size;
};

// Represents shadow breakpoint
struct PatchInformation {
  void* patch_address;  // An address of breakpoint

  // A copy of a pages where patch_address belongs to. shadow_page_base_for_rw
  // is exposed to a guest for read and write operation against the page of
  // patch_address, and shadow_page_base_for_exec is exposed for execution.
  std::shared_ptr<Page> shadow_page_base_for_rw;
  std::shared_ptr<Page> shadow_page_base_for_exec;

  // Phyisical address of the above two copied pages
  ULONG64 pa_base_for_rw;
  ULONG64 pa_base_for_exec;

  // A name of breakpont (a DDI name)
  std::array<char, 64> name;

  void* handler;
  PatchInfoDetails details;
};

struct SharedSbpData {
  // Holds all currently installed breakpoints
  std::vector<std::unique_ptr<PatchInformation>> breakpoints;

  // Spin lock for breakpoints
  KSPIN_LOCK breakpoints_skinlock;
};

struct SbpData {
  // Remember a breakpoint hit last
  const PatchInformation* last_breakpoint;

  // Remember a value of guests eflags.IT
  bool previouse_interrupt_flag;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

void SbpCreatePreBreakpoint(_In_ SharedSbpData* shared_sbp_data,
                            _In_ void* address, _In_ BreakpointTarget* target,
                            _In_ const char* name);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // DDIMON_SHADOW_BP_INTERNAL_H_
