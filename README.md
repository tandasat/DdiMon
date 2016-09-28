DdiMon
=======

Introduction
-------------
DdiMon is a hypervisor performing inline hooking that is invisible to a guest
(ie, any code other than DdiMon) by using extended page table (EPT).

DdiMon is meant to be an educational tool for understanding how to use EPT from
a programming perspective for research. To demonstrate it, DdiMon installs the
invisible inline hooks on the following device driver interfaces (DDIs) to
monitor activities of the Windows built-in kernel patch protection, a.k.a.
PatchGuard, and hide certain processes without being detected by PatchGuard.
- ExQueueWorkItem
- ExAllocatePoolWithTag
- ExFreePool
- ExFreePoolWithTag
- NtQuerySystemInformation

Those stealth shadow hooks are hidden from guest's read and write memory
operations and exposed only on execution of the memory. Therefore, they are
neither visible nor overwritable from a guest, while they function as ordinal
hooks. It is accomplished by making use of EPT enforcing a guest to see
different memory contents from what it would see if EPT is not in use. This
technique is often called memory shadowing. For more details, see the Design
section below.

Here is a movie demonstrating that shadow hooks allow you to monitor and
control DDI calls without being notified by PatchGuard.
- https://www.youtube.com/watch?v=UflyX3GeYkw

DdiMon is implemented on the top of HyperPlatform. See a project page for
more details of HyperPlatform:
- https://github.com/tandasat/HyperPlatform


Installation and Uninstallation
--------------------------------
Clone full source code from Github with a below command and compile it on Visual
Studio.

    $ git clone --recursive https://github.com/tandasat/DdiMon.git

On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    >bcdedit /set testsigning on

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create DdiMon type= kernel binPath= C:\Users\user\Desktop\DdiMon.sys
    >sc start DdiMon

And for uninstallation:

    >sc stop DdiMon
    >sc delete DdiMon
    >bcdedit /deletevalue testsigning

Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver.

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User Document.
- http://tandasat.github.io/HyperPlatform/userdocument/


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\DdiMon.log.


Motivation
-----------
Despite existence of plenty of academic research projects[1,2,3] and production
software[4,5], EPT (a.k.a. SLAT; second-level-address translation) is still
underused technology among reverse engineers due to lack of information on how
it works and how to control it through programming.

MoRE[6] by Jacob Torrey is a one of very few open source projects demonstrating
use of EPT with small amount of code. While we recommend to look into the
project for basic comprehension of how EPT can be initialized and used to set up
more than 1:1 guest to machine physical memory mapping, MoRE lacks flexibility
to extend its code for supporting broader platforms and implementing your own
analysis tools.

DdiMon provides a similar sample use of EPT as what MoRE does with a greater
range of platform support such as x64 and/or Windows 10. DdiMon, also, can be
seen as example extension of HyperPlatform for memory virtualization.

- [1] SecVisor: A Tiny Hypervisor to Provide Lifetime Kernel Code Integrity for
      Commodity OSes
      - https://www.cs.cmu.edu/~arvinds/pubs/secvisor.pdf
- [2] SPIDER: Stealthy Binary Program Instrumentation and Debugging via Hardware
      Virtualization
      - https://www.cerias.purdue.edu/assets/pdf/bibtex_archive/2013-5.pdf
- [3] Dynamic VM Dependability Monitoring Using Hypervisor Probes
      - http://assured-cloud-computing.illinois.edu/files/2014/03/Dynamic-VM-Dependability-Monitoring-Using-Hypervisor-Probes.pdf
- [4] Windows 10 Virtualization-based Security (Device Guard)
      - https://technet.microsoft.com/en-us/library/mt463091(v=vs.85).aspx
- [5] VMRay
      - https://www.vmray.com/features/
- [6] MoRE
      - https://github.com/ainfosec/MoRE


Design
-------
In order to install a shadow hook, DdiMon creates a couple of copies of a page
where the address to install a hook belongs to. After DdiMon is initialized,
those two pages are accessed when a guest, namely all but ones by the hypervisor
(ie, DdiMon), attempts to access to the original page instead. For example, when
DdiMon installs a hook onto 0x1234, two copied pages are created: 0xa000 for
execution access and 0xb000 for read or write access, and memory access is
performed as below after the hook is activated:

                   Requested    Accessed
    By Hypervisor: 0x1234    -> 0x1234 on all access
    By Guest:      0x1234    -> 0xa234 on execution access
                             -> 0xb234 on read or write access

The following explains how it is accomplished.

**Default state**

DdiMon first configures an EPT entry corresponds to 0x1000-0x1fff to refer to
the contents of 0xa000 and to disallow read and write access to the page.

**Scenario: Read or Write**

1. With this configuration, any read and write access triggers EPT violation
VM-exit. Up on the VM-exit, the EPT entry for 0x1000-0x1fff is modified to refer
to the contents of 0xb000, which is copy of 0x1000, and to allow read and write
to the page. And then, sets the Monitor Trap Flag (MTF), which works like the
Trap Flag of the flag register but not visible to a guest, so that a guest can
perform the read or write operation and then interrupted by the hypervisor with
MTF VM-exit.

2. After executing a single instruction, a guest is interrupted by MTF VM-exit.
On this VM-exit, the hypervisor clears the MTF and resets the EPT entry to the
default state so that subsequent execution is done with the contents of 0xa000.

As a result of this sequence of operations, a guest executed a single
instruction reading from or writing to 0xb234.

**Scenario: Execute**

At this time, execution is done against contents of 0xa000 without triggering
any events unless no other settings is made. In order to monitor execution of
0xa234 (0x1234 from guest's perspective), DdiMon sets a break point (0xcc) to
0xa234 and handles #BP in the hypervisor. Following steps are how DdiMon
hooks execution of 0xa234.

1. On #BP VM-exit, the hypervisor checks if guest's EIP/RIP is 0x1234 first. If
so, the hypervisor changes the contents of the register to point to a
corresponding hook handler for instrumenting the DDI call.

2. On VM-enter, a guest executes the hook handler. The hook handler calls an
original function, examines parameters, return values and/or a return address,
and takes action accordingly.

This is just like a typical inline hooking. Only differences are that it sets
0xcc and changes EIP/RIP from a hypervisor instead of overwriting original code
with JMP instructions and that installed hooks are not visible from a guest. An
advantage of using 0xcc is that it does not require a target function to have a
length to install JMP instructions.


Implementation
---------------
The following are a call hierarchy with regard to sequences explained above.

**On DriverEntry**

    DdimonInitialization()
      DdimonpEnumExportedSymbolsCallback()  // Enumerates exports of ntoskrnl
        ShInstallHook()                     // Installs a stealth hook
      ShEnableHooks()                       // Activates installed hooks
        ShEnablePageShadowing()
          ShpEnablePageShadowingForExec()   // Configures an EPT entry as
                                            // explained in "Default state"

**On EPT violation VM-exit with read or write**

    VmmpHandleEptViolation()
      EptHandleEptViolation()
        ShHandleEptViolation()  // Performs actions as explained in the 1 of
                                // "Scenario: Read or Write"

**On MTF VM-exit**

    VmmpHandleMonitorTrap()
      ShHandleMonitorTrapFlag() // Performs actions as explained in the 2 of
                                // "Scenario: Read or Write"

**On #BP VM-exit**

    VmmpHandleException()
      ShHandleBreakpoint()      // Performs actions as explained in the 1 of
                                // "Scenario: Execute"



Implemented Hook Handlers
--------------------------
- ExQueueWorkItem
      - The hook handler prints out given parameters when a specified work 
        item routine is not inside any images.

- ExAllocatePoolWithTag
      - The hook handler prints out given parameters and a return value of
        ExAllocatePoolWithTag() when it is called from an address where is
        not backed by any images.

- ExFreePool and ExFreePoolWithTag
      - The hook handlers print out given parameters when they are called
        from addresses where are not backed by any images.

- NtQuerySystemInformation
      - The hook handler takes out an entry for "cmd.exe" from returned 
        process information so that cmd.exe is not listed by process 
        enumeration.

The easiest way to see those logs is installing NoImage.sys.
- https://github.com/tandasat/MemoryMon/tree/master/MemoryMonTest

Logs for activities of NoImage are look like this:

    17:59:23.014	INF	#0	    4	   48	System         	84660265: ExFreePoolWithTag(P= 84665000, Tag= nigm)
    17:59:23.014	INF	#0	    4	   48	System         	84660283: ExAllocatePoolWithTag(POOL_TYPE= 00000000, NumberOfBytes= 00001000, Tag= nigm) => 8517B000
    17:59:23.014	INF	#0	    4	   48	System         	8517B1C3: ExQueueWorkItem({Routine= 8517B1D4, Parameter= 8517B000}, 1)


Caveats
--------
DdiMon is meant to be an educational tool and not robust, production quality
software which is able to handle various edge cases. For example, DdiMon
does not handle self-modification code since any memory writes on a shadowed
page is not reflected to a view for execution. For this reason, researchers are
encouraged to use this project as sample code to get familiar with EPT and
develop their own tools as needed.


Supported Platforms
----------------------
- x86 and x64 Windows 7, 8.1 and 10
- The system must support the Intel VT-x and EPT technology


License
--------
This software is released under the MIT License, see LICENSE.
