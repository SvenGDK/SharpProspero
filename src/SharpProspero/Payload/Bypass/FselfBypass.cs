// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Kernel;
using System;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// FSELF (Fake-Signed ELF) bypass. Installs debug register watchpoints on the kernel's
/// SELF verification path to intercept the <c>verifyHeader</c> and
/// <c>sceSblAuthMgrIsLoadable2</c> checks, allowing unsigned SELF modules to load.
/// </summary>
public static unsafe class PayloadFselfBypass
{
    /// <summary>
    /// Installs the FSELF bypass by arming three execution watchpoints and configuring
    /// DR7. Three breakpoints are required: DR0 intercepts the loadable check, DR1
    /// intercepts the header verification return, and DR2 intercepts the ASLR randomizer
    /// so segment addresses remain deterministic for the block-copy path.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="isLoadable2Addr">Kernel address of <c>sceSblAuthMgrIsLoadable2</c>.</param>
    /// <param name="verifyHeaderLr">Return address within <c>verifyHeader</c>.</param>
    /// <param name="aslrFixAddr">Kernel address of the SELF-loader mmap ASLR site to disarm.</param>
    /// <returns><see langword="true"/> if all three debug register writes were accepted.</returns>
    public static bool Install(PayloadKernelIo io, ulong isLoadable2Addr, ulong verifyHeaderLr,
        ulong aslrFixAddr)
    {
        // KernelDebugRegs uses a compact six-element buffer: indices 0..3 hold
        // DR0..DR3, index 4 is DR6, index 5 is DR7. Writing DR7 to index 7 (the
        // hardware-numbered position) would land outside the slots the kekcall
        // read/write pair actually transfers.
        Span<ulong> dbregs = stackalloc ulong[6];
        KernelDebugRegs.Read(dbregs);

        dbregs[0] = isLoadable2Addr;  // DR0 = break on IsLoadable2
        dbregs[1] = verifyHeaderLr;   // DR1 = break on verifyHeader return
        dbregs[2] = aslrFixAddr;      // DR2 = break on SELF loader ASLR site
        // DR7: L0|L1|L2 + fixed reserved bit (bit 10 = 0x400) so the kernel
        // accepts the write; R/W and LEN fields stay zero (execute-only, 1 byte)
        // for each breakpoint. Total = 0x415. Slot 5 is the compact-buffer DR7.
        dbregs[5] = 0x400UL |
                    KernelDebugRegs.Dr7L0 | KernelDebugRegs.Dr7L1 | KernelDebugRegs.Dr7L2 |
                    (KernelDebugRegs.Dr7CondExec << 16) | (KernelDebugRegs.Dr7Len1 << 18) |
                    (KernelDebugRegs.Dr7CondExec << 20) | (KernelDebugRegs.Dr7Len1 << 22) |
                    (KernelDebugRegs.Dr7CondExec << 24) | (KernelDebugRegs.Dr7Len1 << 26);

        KernelDebugRegs.Write(dbregs);

        // Verify by reading back. A failed write leaves the debug regs in an
        // undefined state; downstream trap handlers would fire on stale/wrong
        // addresses. Report failure so the caller can abort cleanly.
        Span<ulong> readback = stackalloc ulong[6];
        KernelDebugRegs.Read(readback);
        return readback[0] == isLoadable2Addr
            && readback[1] == verifyHeaderLr
            && readback[2] == aslrFixAddr
            && readback[5] == dbregs[5];
    }

    /// <summary>
    /// Removes the FSELF bypass by clearing the debug registers.
    /// </summary>
    public static void Remove()
    {
        Span<ulong> dbregs = stackalloc ulong[6];
        dbregs.Clear();
        KernelDebugRegs.Write(dbregs);
    }
}
