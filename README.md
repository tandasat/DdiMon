DdiMon
=======

Introduction
-------------
DdiMon is a hypervisor providing a breakpoint that is invisible to a guest using
extended page table (EPT) for monitoring and controlling calls to the device
driver interfaces (DDIs, ie, the Windows kernel APIs).

DdiMon is meant to be an educational tool for understanding how to use EPT from
a programming perspective for reverse engineering. To demonstrate it, DdiMon
sets the invisible breakpoints on the following DDIs to monitor activities of
the Windows built-in kernel patch protection, a.k.a. PatchGuard, and hide
certain processes without being detected by PatchGuard.
- ExQueueWorkItem
- ExAllocatePoolWithTag
- ExFreePool
- ExFreePoolWithTag
- NtQuerySystemInformation

Those stealth breakpoints are hidden from guest's read and write memory
operations and exposed only on execution of the memory. Therefore, they are
neither visible nor overwritable from a guest, while they function as breakpoint.
It is accomplished by making use of EPT allowing you to enforce a guest to
see a different memory contents from what it would see if EPT is not in use.
This technique is called memory shadowing. For more details, see the Design
section below.

Here is a movie demonstrating that stealth breakpoints allow you to monitor and
control DDI calls without being notified by PatchGuard.
- https://www.youtube.com/watch?v=UflyX3GeYkw

DdiMon is implemented on the top of HyperPlatform. See a project page for
more details of HyperPlatform:
- https://github.com/tandasat/HyperPlatform


Installation and Uninstallation
--------------------------------
On the x64 platform, you have to enable test signing to install the driver.
To do that, open the command prompt with the administrator privilege and type
the following command, and then restart the system to activate the change:

    bcdedit /set testsigning on

Since DdiMon supports only uni-processor systems currently (#1), a system
with more than one processors must change a number of active processors
with below command, and then restart the system to activate the change:

    bcdedit /set numproc 1

To install and uninstall the driver, use the 'sc' command. For installation:

    >sc create DdiMon type= kernel binPath= C:\Users\user\Desktop\DdiMon.sys
    >sc start DdiMon

And for uninstallation:

    >sc stop DdiMon
    >sc delete DdiMon
    >bcdedit /deletevalue numproc
    >bcdedit /deletevalue testsigning

Note that the system must support the Intel VT-x and EPT technology to
successfully install the driver.

To install the driver on a virtual machine on VMware Workstation, see an "Using
VMware Workstation" section in the HyperPlatform User's Documents found in its
project page.
- https://github.com/tandasat/HyperPlatform/tree/master/Documents


Output
-------
All logs are printed out to DbgView and saved in C:\Windows\DdiMon.log.


Motivation
-----------

Despite existence of plenty of academic research projects[1,2,3] and production
software[4,5], EPT (a.k.a. SLAT; second-level-address translation) is still
underused technology among reverse engineers due to lack of information on how
it works and can be controlled through programming.

MoRE[6] by Jacob Torrey is a one of very few open source projects demonstrating
use of EPT with small amount of code. While we recommend to look into the
project for basic comprehension of how EPT can be initialized and used for
providing more than 1:1 mapping, MoRE lacks flexibility to extend its code for
supporting broader platforms and implementing your own analysis tools.

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

In order to set a stealth breakpoint, DdiMon creates a couple of copies of a
page where the address to set breakpoint belongs to. After DdiMon is initialized,
those two pages are accessed when a guest, which is any execution but ones by
hypervisor, attempts to access to the original page instead. For example, when
DdiMon sets a stealth breakpoint on 0x1234, actual access is performed as below:

                   Requested    Accessed
    By Hypervisor: 0x1234    -> 0x1234 on all access
    By Guest:      0x1234    -> 0xa234 on execution access
                             -> 0xb234 on read or write access

The following explains how it is accomplished.

**Default state**

This is done by configuring an EPT entry corresponds to 0x1000-0x1fff to
refer to contents of 0xa000 and to disallow read and write access to the page.

**Scenario: Read or Write**

1. With this configuration, any read and write access triggers EPT violation
VM-exit. Up on the VM-exit, the EPT entry for 0x1000-0x1fff is modified to refer
to contents of 0xb000 and to allow read and write to the page. And then, sets
the Monitor Trap Flag (MTF), which works as if the Trap Flag of the flag but not
visible to a guest so that guest can perform the read or write operation and
then interrupted by the VMM with MTF VM-exit.

2. After executing a single instruction, guest is interrupted by MTF VM-exit. on
this VM-exit, the VMM clear the MTF and set the EPT entry to the default state
so that subsequent execution is done with the contents 0xa000.

As a result of this sequence of operations, a guest executed a single
instruction reading from or writing to 0xb234.

**Scenario: Execute**

Execution is done against contents of 0xa000 without triggering any events at
this time. It is fine, and how to monitor execution of 0xa234 (0x1234 from
guest's perspective) is left to developers. One option is installing inline hook
and transfer to instrumentation code without triggering VM-exit. DdiMon sets
0xcc to 0xa234 and handles #BP in the VMM instead, as it does not require a
disassembler. The following steps are how DdiMon monitors execution of 0xa234.

1. On #BP VM-exit, the VMM checks if guest IP is 0x1234 first. If so, next, it
checks if a contents of 0xb234 is 0xcc. If so, that is a breakpoint set by a
guest and the #BP should be delivered to a guest instead. If not the case, the
VMM runs a specified handler to instrument the DDI call and sets a new
breakpoint at a return address if a post handler is given. After that, just 
like the case of the read and write access, the VMM changes an EPT entry
corresponds to 0x1000-0x1fff to refer to contents of 0xb000 and sets MTF so 
that a guest can run an original instruction and be interrupted then.

2. On MTF VM-exit, the exact same operations are done as the case of the read and
write access.

As a result of this sequence of operations, a guest executed a single
instruction at 0xa234 with being instrumented.


Implementation
---------------
The following are a call hierarchy with regard to sequences explained above.

**On DriverEntry**

    DdimonInitialization()
      // Enumerates exports of ntoskrnl
      DdimonpEnumExportedSymbolsCallback()
        // Creates stealth breakpoint without activating it
        SbpCreatePreBreakpoint()
      SbpStart()
        // Activates all stealth breakpoints
        SbpVmCallEnablePageShadowing()
          // Configure an EPT entry as explained in "Default state"
          SbppEnablePageShadowingForExec()

**On EPT violation VM-exit with read or write**

    VmmpHandleEptViolation()
      EptHandleEptViolation()
        // Perform actions as explained in "EPT violation VM-exit"
        SbpHandleEptViolation()

**On MTF VM-exit**

    VmmpHandleMonitorTrap()
      // Perform actions as explained in "MTF VM-exit"
      SbpHandleMonitorTrapFlag()

**On #BP VM-exit**

    VmmpHandleException()
      // Perform actions as explained in "#BP VM-exit"
      SbpHandleBreakpoint()


Implemented Breakpoint Handlers
--------------------------------
- ExQueueWorkItem (Pre)
A pre-handler prints out given parameters when a specified work item routine is
not inside any images.

- ExAllocatePoolWithTag (Pre and Post)
A pre-handler prints out given parameters when it is called from an address
where is not backed by any images. A post-handler prints out a return value of
the DDI.

- ExFreePool and ExFreePoolWithTag (Pre)
Pre-handlers print out given parameters when they are called from addresses
where are not backed by any images.

- NtQuerySystemInformation (Post)
A post-handler takes out an entry for "cmd.exe" from returned process
information so that cmd.exe can be hidden from process enumeration.

The easiest way to see those logs is installing NoImage.sys.
- https://github.com/tandasat/MemoryMon/tree/master/MemoryMonTest

Logs for activities of NoImage are look like this:

    17:59:23.014	INF	#0	    4	   48	System         	ExFreePoolWithTag(P= 84665000, Tag= nigm) returning to 84660265
    17:59:23.014	INF	#0	    4	   48	System         	ExAllocatePoolWithTag(POOL_TYPE= 00000000, NumberOfBytes= 00001000, Tag= nigm) returning to 84660283
    17:59:23.014	INF	#0	    4	   48	System         	ExAllocatePoolWithTag(...) => 8517B000
    17:59:23.014	INF	#0	    4	   48	System         	ExQueueWorkItem({Routine= 8517B1D4, Parameter= 8517B000}, 1) returning to 8517B1C3


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
- Uni-processor systems (the author is working for taking off this limitation #1)


License
--------
This software is released under the MIT License, see LICENSE.
