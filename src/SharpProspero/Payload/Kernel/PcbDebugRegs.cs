// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Installs debug register values into the PCB save area of every thread in a process.
/// When the <c>PCB_DBREGS</c> flag is set in the PCB, <c>cpu_switch</c> restores DR0-DR3,
/// DR6, and DR7 from the save area each time the thread is scheduled onto a CPU, ensuring
/// the hardware breakpoint configuration persists across context switches.
/// </summary>
/// <remarks>
/// <para>
/// The PCB save area stores six contiguous <c>register_t</c> values starting at
/// <c>pcb_dr0</c>: DR0, DR1, DR2, DR3, DR6, DR7. On firmware 10.00 and later, all PCB
/// fields from <c>pcb_fsbase</c> onward shift by 16 bytes; <see cref="KernelOffsets.PcbShift"/>
/// computes the adjustment.
/// </para>
/// <para>
/// The <c>pcb_flags</c> word is a 32-bit field. Setting bit 1 (<c>PCB_DBREGS</c>, value
/// <c>0x02</c>) tells the kernel's <c>cpu_switch</c> to reload the debug registers from
/// the PCB when this thread is next scheduled in.
/// </para>
/// </remarks>
public static unsafe class PcbDebugRegs
{
    private const int MaxThreadsPerProcess = 4096;

    /// <summary>
    /// Walks all threads in the given process and writes the debug register values from
    /// <paramref name="dbregs"/> into each thread's PCB save area. Sets the <c>PCB_DBREGS</c>
    /// flag so that <c>cpu_switch</c> restores the registers on every context switch.
    /// </summary>
    /// <param name="io">Kernel read/write primitive.</param>
    /// <param name="procAddr">Kernel address of the target <c>proc</c> structure.</param>
    /// <param name="dbregs">
    /// Eight-element span indexed by hardware register number: [0]=DR0, [1]=DR1, [2]=DR2,
    /// [3]=DR3, [4]=DR4 (unused), [5]=DR5 (unused), [6]=DR6, [7]=DR7.
    /// </param>
    /// <returns>The number of threads armed, or zero if no threads were found or the span
    /// has fewer than eight elements.</returns>
    public static int InstallOnProcess(PayloadKernelIo io, ulong procAddr, ReadOnlySpan<ulong> dbregs)
    {
        if (dbregs.Length < 8)
            return 0;

        uint fw = PayloadKernel.GetFirmwareVersion(io);
        int shift = KernelOffsets.PcbShift(fw);
        int dr0Offset = KernelOffsets.PcbDr0Base + shift;
        int flagsOffset = KernelOffsets.PcbFlagsBase + shift;

        int armed = 0;
        if (!io.TryReadU64(procAddr + (ulong)KernelOffsets.ProcThreads, out ulong td))
            return 0;

        int safety = 0;
        while (td != 0 && safety < MaxThreadsPerProcess)
        {
            if (io.TryReadU64(td + (ulong)KernelOffsets.ThreadPcb, out ulong pcb) && pcb != 0)
            {
                ulong drBase = pcb + (ulong)dr0Offset;

                // Write DR0, DR1, DR2, DR3 (contiguous in the PCB save area).
                io.WriteU64(drBase, dbregs[0]);
                io.WriteU64(drBase + 8, dbregs[1]);
                io.WriteU64(drBase + 16, dbregs[2]);
                io.WriteU64(drBase + 24, dbregs[3]);

                // DR4/DR5 have no PCB save slot (they are aliases on x86-64).
                // Write DR6 and DR7 into the remaining two slots.
                io.WriteU64(drBase + 32, dbregs[6]);
                io.WriteU64(drBase + 40, dbregs[7]);

                // Set PCB_DBREGS (bit 1) in pcb_flags. The field is u_long (64-bit)
                // on amd64; a 32-bit write here would truncate the upper half and lose
                // PCB_FPUINITDONE (bit 8) and other flags the kernel expects to persist.
                if (io.TryReadU64(pcb + (ulong)flagsOffset, out ulong flags))
                {
                    io.WriteU64(pcb + (ulong)flagsOffset, flags | KernelOffsets.PcbDbregsFlag);
                    armed++;
                }
            }

            if (!io.TryReadU64(td + (ulong)KernelOffsets.ThreadListNext, out td))
                break;

            safety++;
        }

        return armed;
    }

    /// <summary>
    /// Locates the <c>SceShellCore</c> process by name in the kernel's <c>allproc</c> list
    /// and installs debug register values into every thread's PCB save area.
    /// </summary>
    /// <param name="io">Kernel read/write primitive.</param>
    /// <param name="dbregs">
    /// Eight-element span indexed by hardware register number: [0]=DR0, [1]=DR1, [2]=DR2,
    /// [3]=DR3, [4]=DR4 (unused), [5]=DR5 (unused), [6]=DR6, [7]=DR7.
    /// </param>
    /// <returns>The number of threads armed, or -1 if <c>SceShellCore</c> was not found.</returns>
    public static int InstallOnShellCore(PayloadKernelIo io, ReadOnlySpan<ulong> dbregs)
    {
        ReadOnlySpan<byte> name = "SceShellCore"u8;
        ulong proc;
        fixed (byte* p = name)
            proc = PayloadKernel.FindProcessByName(io, p, name.Length);

        if (proc == 0)
            return -1;

        return InstallOnProcess(io, proc, dbregs);
    }
}
