// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements DdiMon functions.

#include "ddi_mon.h"
#include <ntimage.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include "shadow_bp.h"
#include "shadow_bp_internal.h"

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

// A helper type for parsing a PoolTag value
union PoolTag {
  ULONG value;
  UCHAR chars[4];
};

// A callback type for EnumExportedSymbols()
using EnumExportedSymbolsCallbackType = bool (*)(
    ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base, ULONG_PTR directory_end, void* context);

// dt nt!_LDR_DATA_TABLE_ENTRY
struct LdrDataTableEntry {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  LIST_ENTRY in_initialization_order_links;
  void* dll_base;
  void* entry_point;
  ULONG size_of_image;
  UNICODE_STRING full_dll_name;
  // ...
};

// For SystemProcessInformation
enum SystemInformationClass {
  kSystemProcessInformation = 5,
};

// For NtQuerySystemInformation
struct SystemProcessInformation {
  ULONG next_entry_offset;
  ULONG number_of_threads;
  LARGE_INTEGER working_set_private_size;
  ULONG hard_fault_count;
  ULONG number_of_threads_high_watermark;
  ULONG64 cycle_time;
  LARGE_INTEGER create_time;
  LARGE_INTEGER user_time;
  LARGE_INTEGER kernel_time;
  UNICODE_STRING image_name;
  // omitted. see ole32!_SYSTEM_PROCESS_INFORMATION
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

static void DdimonpFreeAllocatedTrampolineRegions();

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static NTSTATUS
    DdimonpInitializePcToFileHeader(_In_ PDRIVER_OBJECT driver_object);

static void* DdimonpPcToFileHeader(_In_ void* address);

static PVOID NTAPI DdimonpUnsafePcToFileHeader(_In_ PVOID pc_value,
                                               _In_ PVOID* base_of_image);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C static NTSTATUS
    DdimonpEnumExportedSymbols(_In_ ULONG_PTR base_address,
                               _In_ EnumExportedSymbolsCallbackType callback,
                               _In_opt_ void* context);

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    static bool DdimonpEnumExportedSymbolsCallback(
        _In_ ULONG index, _In_ ULONG_PTR base_address,
        _In_ PIMAGE_EXPORT_DIRECTORY directory, _In_ ULONG_PTR directory_base,
        _In_ ULONG_PTR directory_end, _In_opt_ void* context);

static std::array<char, 5> DdimonpTagToString(_In_ ULONG tag_value);

static VOID DdimonpHandleExQueueWorkItem(_Inout_ PWORK_QUEUE_ITEM work_item,
                                         _In_ WORK_QUEUE_TYPE queue_type);

static PVOID DdimonpHandleExAllocatePoolWithTag(_In_ POOL_TYPE pool_type,
                                                _In_ SIZE_T number_of_bytes,
                                                _In_ ULONG tag);

static VOID DdimonpHandleExFreePoolWithTag(_Pre_notnull_ PVOID p,
                                           _In_ ULONG tag);
static NTSTATUS DdimonpHandleNtQuerySystemInformation(
    _In_ SystemInformationClass SystemInformationClass,
    _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DdimonInitialization)
#pragma alloc_text(INIT, DdimonpInitializePcToFileHeader)
#pragma alloc_text(INIT, DdimonpEnumExportedSymbols)
#pragma alloc_text(INIT, DdimonpEnumExportedSymbolsCallback)
#pragma alloc_text(PAGE, DdimonTermination)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// An address of PsLoadedModuleList
static LIST_ENTRY* g_ddimonp_PsLoadedModuleList;

// Defines where to set breakpoints and their handlers
//
// Because of simplified imlementation of DdiMon, it is unable to handle any
// of following exports properly:
//  - already unmapped exports (eg, ones on the INIT section) because it no
//    longer exists on memory
//  - exported data because setting 0xcc does not make any sense in this case
//  - functions can be called at IRQL higher than DISPATCH_LEVEL because
//    DdiMon call DDI that cannot be called that IRQL when it handles
//    breakpoints. Using DDI in a VMM is actually violation of VMM coding best
//    practice described in HyperPlatform User's Document, but is done to
//    simplify implementation sine DdiMon is more like demonstration of use of
//    EPT.
//  - functions does not comply x64 calling conventions, for example Zw*
//    functions, because contents of stack do not hold expected values leading
//    handlers to failure of parameter analysis that may result in bug check.
//
// Also the following care should be taken:
//  - Function parameters may be an user-address space pointer and not
//    trusted. Even a kernel-address space pointer should not be trusted for
//    production level security. Vefity and capture all contents from user
//    surpplied address to VMM, then use them.

static BreakpointTarget g_ddimonp_breakpoint_targets[] = {
    {
        RTL_CONSTANT_STRING(L"EXQUEUEWORKITEM"), DdimonpHandleExQueueWorkItem,
        nullptr,
    },
    {
        RTL_CONSTANT_STRING(L"EXALLOCATEPOOLWITHTAG"),
        DdimonpHandleExAllocatePoolWithTag, nullptr,
    },
    {
        RTL_CONSTANT_STRING(L"EXFREEPOOLWITHTAG"),
        DdimonpHandleExFreePoolWithTag, nullptr,
    },
    {
        RTL_CONSTANT_STRING(L"NTQUERYSYSTEMINFORMATION"),
        DdimonpHandleNtQuerySystemInformation, nullptr,
    },
};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes DdiMon
_Use_decl_annotations_ EXTERN_C NTSTATUS DdimonInitialization(
    SharedSbpData* shared_sbp_data, PDRIVER_OBJECT driver_object) {
  HYPERPLATFORM_COMMON_DBG_BREAK();

  // Make DdimonpPcToFileHeader() avaialable for use
  auto status = DdimonpInitializePcToFileHeader(driver_object);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Get a base address of ntoskrnl
  auto nt_base = DdimonpPcToFileHeader(KdDebuggerEnabled);
  if (!nt_base) {
    return STATUS_UNSUCCESSFUL;
  }

  // Initialize a container of breakpoint objects and create them by enumerating
  // exported symbols by ntoskrnl
  status = DdimonpEnumExportedSymbols(reinterpret_cast<ULONG_PTR>(nt_base),
                                      DdimonpEnumExportedSymbolsCallback,
                                      shared_sbp_data);
  if (!NT_SUCCESS(status)) {
    DdimonpFreeAllocatedTrampolineRegions();
    return status;
  }

  status = SbpStart();
  if (!NT_SUCCESS(status)) {
    DdimonpFreeAllocatedTrampolineRegions();
    return status;
  }

  HYPERPLATFORM_LOG_INFO("DdiMon has been initialized.");
  return status;
}

// Terminates DdiMon
_Use_decl_annotations_ EXTERN_C void DdimonTermination() {
  PAGED_CODE();
  HYPERPLATFORM_COMMON_DBG_BREAK();
  SbpStop();
  UtilSleep(500);
  DdimonpFreeAllocatedTrampolineRegions();
  HYPERPLATFORM_LOG_INFO("DdiMon has been terminated.");
}

// Frees trampoline code allocated and stored in g_ddimonp_breakpoint_targets by
// DdimonpEnumExportedSymbolsCallback()
/*_Use_decl_annotations_*/ static void DdimonpFreeAllocatedTrampolineRegions() {
  for (auto& target : g_ddimonp_breakpoint_targets) {
    if (target.original_call) {
      ExFreePoolWithTag(target.original_call, kHyperPlatformCommonPoolTag);
      target.original_call = nullptr;
    }
  }
}

// Saves PsLoadedModuleList that is referenced by DdimonpUnsafePcToFileHeader().
_Use_decl_annotations_ static NTSTATUS DdimonpInitializePcToFileHeader(
    PDRIVER_OBJECT driver_object) {
  PAGED_CODE();

#pragma warning(push)
#pragma warning(disable : 28175)
  auto module =
      reinterpret_cast<LdrDataTableEntry*>(driver_object->DriverSection);
#pragma warning(pop)

  g_ddimonp_PsLoadedModuleList = module->in_load_order_links.Flink;
  return STATUS_SUCCESS;
}

// A wrapper of DdimonpUnsafePcToFileHeader
_Use_decl_annotations_ static void* DdimonpPcToFileHeader(void* address) {
  void* base = nullptr;
  return DdimonpUnsafePcToFileHeader(address, &base);
}

// A fake RtlPcToFileHeader without accquireing PsLoadedModuleSpinLock. Thus, it
// is unsafe and should be updated if we can locate PsLoadedModuleSpinLock.
_Use_decl_annotations_ static PVOID NTAPI
DdimonpUnsafePcToFileHeader(PVOID pc_value, PVOID* base_of_image) {
  if (pc_value < MmSystemRangeStart) {
    return nullptr;
  }

  const auto head = g_ddimonp_PsLoadedModuleList;
  for (auto current = head->Flink; current != head; current = current->Flink) {
    const auto module =
        CONTAINING_RECORD(current, LdrDataTableEntry, in_load_order_links);
    const auto driver_end = reinterpret_cast<void*>(
        reinterpret_cast<ULONG_PTR>(module->dll_base) + module->size_of_image);
    if (UtilIsInBounds(pc_value, module->dll_base, driver_end)) {
      *base_of_image = module->dll_base;
      return module->dll_base;
    }
  }
  return nullptr;
}

// Enumerates all exports in a module specified by base_address.
_Use_decl_annotations_ EXTERN_C static NTSTATUS DdimonpEnumExportedSymbols(
    ULONG_PTR base_address, EnumExportedSymbolsCallbackType callback,
    void* context) {
  PAGED_CODE();

  auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
  auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base_address + dos->e_lfanew);
  auto dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
      &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
  if (!dir->Size || !dir->VirtualAddress) {
    return STATUS_SUCCESS;
  }

  auto dir_base = base_address + dir->VirtualAddress;
  auto dir_end = base_address + dir->VirtualAddress + dir->Size - 1;
  auto exp_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base_address +
                                                           dir->VirtualAddress);
  for (auto i = 0ul; i < exp_dir->NumberOfNames; i++) {
    if (!callback(i, base_address, exp_dir, dir_base, dir_end, context)) {
      return STATUS_SUCCESS;
    }
  }
  return STATUS_SUCCESS;
}

// Determines if the export is listed as a breakpoint target and creates a
// breakpoint object if so,.
_Use_decl_annotations_ EXTERN_C static bool DdimonpEnumExportedSymbolsCallback(
    ULONG index, ULONG_PTR base_address, PIMAGE_EXPORT_DIRECTORY directory,
    ULONG_PTR directory_base, ULONG_PTR directory_end, void* context) {
  PAGED_CODE();

  if (!context) {
    return false;
  }

  auto functions =
      reinterpret_cast<ULONG*>(base_address + directory->AddressOfFunctions);
  auto ordinals = reinterpret_cast<USHORT*>(base_address +
                                            directory->AddressOfNameOrdinals);
  auto names =
      reinterpret_cast<ULONG*>(base_address + directory->AddressOfNames);

  auto ord = ordinals[index];
  auto export_address = base_address + functions[ord];
  auto export_name = reinterpret_cast<const char*>(base_address + names[index]);

  // Check if an export is forwared one? If so, ignore it.
  if (UtilIsInBounds(export_address, directory_base, directory_end)) {
    return true;
  }

  // convert the name to UNICODE_STRING
  wchar_t name[100];
  auto status =
      RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"%S", export_name);
  if (!NT_SUCCESS(status)) {
    return true;
  }
  UNICODE_STRING name_u = {};
  RtlInitUnicodeString(&name_u, name);

  for (auto& target : g_ddimonp_breakpoint_targets) {
    if (!FsRtlIsNameInExpression(&target.target_name, &name_u, TRUE, nullptr)) {
      continue;
    }

    // Yes, create a new breakpoint
    SbpCreatePreBreakpoint(reinterpret_cast<SharedSbpData*>(context),
                           reinterpret_cast<void*>(export_address), &target,
                           export_name);
    HYPERPLATFORM_LOG_INFO("Breakpoint has been set to %p %s.", export_address,
                           export_name);
  }
  return true;
}

// Converts a pool tag in integer to a printable string
_Use_decl_annotations_ static std::array<char, 5> DdimonpTagToString(
    ULONG tag_value) {
  PoolTag tag = {tag_value};
  for (auto& c : tag.chars) {
    if (!c && isspace(c)) {
      c = ' ';
    }
    if (!isprint(c)) {
      c = '.';
    }
  }

  std::array<char, 5> str;
  auto status =
      RtlStringCchPrintfA(str.data(), str.size(), "%c%c%c%c", tag.chars[0],
                          tag.chars[1], tag.chars[2], tag.chars[3]);
  NT_VERIFY(NT_SUCCESS(status));
  return str;
}

template <typename T>
static T DdimonpFindOrignal(T handler) {
  for (const auto& target : g_ddimonp_breakpoint_targets) {
    if (target.handler == handler) {
      NT_ASSERT(target.original_call);
      return reinterpret_cast<T>(target.original_call);
    }
  }
  NT_ASSERT(false);
  return nullptr;
}

// Pre-ExFreePoolWithTag. Logs if the DDI is called from where not backed by
// any image
_Use_decl_annotations_ static VOID DdimonpHandleExFreePoolWithTag(PVOID p, ULONG tag) {
  // HYPERPLATFORM_COMMON_DBG_BREAK();
  const auto original = DdimonpFindOrignal(DdimonpHandleExFreePoolWithTag);
  original(p, tag);
  auto return_addr = _ReturnAddress();
  if (DdimonpPcToFileHeader(return_addr)) {
    return;
  }
  HYPERPLATFORM_LOG_INFO_SAFE(
      "%ExFreePoolWithTag(P= %p, Tag= %s) returning to %p", p,
      DdimonpTagToString(tag).data(), return_addr);
}

// Pre-ExQueueWorkItem. Logs if a WorkerRoutine points to where not backed by
// any image.
_Use_decl_annotations_ static VOID DdimonpHandleExQueueWorkItem(PWORK_QUEUE_ITEM work_item,
                                         WORK_QUEUE_TYPE queue_type) {
  // HYPERPLATFORM_COMMON_DBG_BREAK();
  const auto original = DdimonpFindOrignal(DdimonpHandleExQueueWorkItem);

  // Is inside image?
  if (DdimonpPcToFileHeader(work_item->WorkerRoutine)) {
    original(work_item, queue_type);
    return;
  }

  auto return_addr = _ReturnAddress();
  HYPERPLATFORM_LOG_INFO_SAFE(
      "ExQueueWorkItem({Routine= %p, Parameter= %p}, %d) returning to %p",
      work_item->WorkerRoutine, work_item->Parameter, queue_type, return_addr);
  // DO log
  // call original
  // do log
  original(work_item, queue_type);
}

// Pre-ExAllocatePoolWithTag. Logs if the DDI is called from where not backed by
// any image and sets post breakpoint if so.
_Use_decl_annotations_ static PVOID DdimonpHandleExAllocatePoolWithTag(POOL_TYPE pool_type,
                                                SIZE_T number_of_bytes,
                                                ULONG tag) {
  // HYPERPLATFORM_COMMON_DBG_BREAK();
  const auto original = DdimonpFindOrignal(DdimonpHandleExAllocatePoolWithTag);
  const auto result = original(pool_type, number_of_bytes, tag);
  auto return_addr = _ReturnAddress();
  if (DdimonpPcToFileHeader(return_addr)) {
    return result;
  }

  HYPERPLATFORM_LOG_INFO_SAFE(
      "ExAllocatePoolWithTag(POOL_TYPE= %08x, NumberOfBytes= %08X, Tag= %s) => "
      "%p returning to %p",
      pool_type, number_of_bytes, DdimonpTagToString(tag).data(), result,
      return_addr);
  return result;
}

// Pre-NtQuerySystemInformation. Sets post breakpoint if it is quering a list
// of processes.
_Use_decl_annotations_ static NTSTATUS DdimonpHandleNtQuerySystemInformation(
    SystemInformationClass system_information_class, PVOID system_information,
    ULONG system_information_length, PULONG return_length) {
  // HYPERPLATFORM_COMMON_DBG_BREAK();
  const auto original =
      DdimonpFindOrignal(DdimonpHandleNtQuerySystemInformation);
  const auto result = original(system_information_class, system_information,
                               system_information_length, return_length);
  if (!NT_SUCCESS(result)) {
    return result;
  }
  if (system_information_class != kSystemProcessInformation) {
    return result;
  }

  auto next = reinterpret_cast<SystemProcessInformation*>(system_information);
  while (next->next_entry_offset) {
    auto curr = next;
    next = reinterpret_cast<SystemProcessInformation*>(
        reinterpret_cast<UCHAR*>(curr) + curr->next_entry_offset);

    if (_wcsnicmp(next->image_name.Buffer, L"cmd.exe", 7) == 0) {
      if (next->next_entry_offset) {
        curr->next_entry_offset += next->next_entry_offset;
      } else {
        curr->next_entry_offset = 0;
      }
      next = curr;
    }
  }

  return result;
}
