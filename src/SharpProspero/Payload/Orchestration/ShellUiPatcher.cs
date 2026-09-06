// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Debug;
using SharpProspero.Payload.Elf;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Process;

namespace SharpProspero.Payload.Orchestration;

/// <summary>
/// ShellUI trophy availability patcher. Finds the SceShellUI process, locates the
/// trophy-server-availability check functions, and patches them to always return
/// "unavailable" so the trophy list loads without a network connection.
/// </summary>
public static unsafe class PayloadShellUiPatcher
{
    /// <summary>NID for <c>sceNpTrophySystemIsServerAvailable</c>.</summary>
    public static readonly ulong NidTrophyServerAvail =
        PayloadNid.ComputeRaw("sceNpTrophySystemIsServerAvailable"u8);

    /// <summary>NID for <c>sceNpTrophy2SystemIsServerAvailable</c>.</summary>
    public static readonly ulong NidTrophy2ServerAvail =
        PayloadNid.ComputeRaw("sceNpTrophy2SystemIsServerAvailable"u8);

    private const int RetryCount = 60;
    private const int RetryDelayUs = 500_000;

    /// <summary>
    /// Patches the trophy server availability checks in SceShellUI to always return
    /// false (unavailable). Retries library resolution up to 30 seconds (60 x 500ms)
    /// to handle the case where SceShellUI was just launched and libraries aren't loaded yet.
    /// Uses page-table-walk memory writes for compatibility with all firmware versions.
    /// </summary>
    /// <param name="io">Kernel I/O for reading process structures.</param>
    /// <param name="shellUiPid">PID of SceShellUI.</param>
    /// <param name="dmapBase">DMAP base for physical memory access.</param>
    /// <param name="fwMajorMinor">Firmware major.minor for vmspace offset lookup.</param>
    /// <returns><see langword="true"/> if the patches were applied.</returns>
    public static bool PatchTrophyChecks(PayloadKernelIo io, int shellUiPid,
        ulong dmapBase, uint fwMajorMinor)
    {
        ulong proc = PayloadKernel.WalkAllprocForPid(io, shellUiPid);
        if (proc == 0) return false;

        ulong fn1 = 0;
        for (int i = 0; i < RetryCount; i++)
        {
            ulong trophy1Base = PayloadHijacker.FindModuleBase(io, proc,
                "libSceNpTrophy.sprx\0"u8, 0x3A8);
            if (trophy1Base != 0)
            {
                fn1 = PayloadHijacker.ResolveByNid(io, trophy1Base, NidTrophyServerAvail, shellUiPid);
                if (fn1 != 0) break;
            }
            PayloadThread.usleep(RetryDelayUs);
        }

        ulong fn2 = 0;
        for (int i = 0; i < RetryCount; i++)
        {
            ulong trophy2Base = PayloadHijacker.FindModuleBase(io, proc,
                "libSceNpTrophy2.sprx\0"u8, 0x3A8);
            if (trophy2Base != 0)
            {
                fn2 = PayloadHijacker.ResolveByNid(io, trophy2Base, NidTrophy2ServerAvail, shellUiPid);
                if (fn2 != 0) break;
            }
            PayloadThread.usleep(RetryDelayUs);
        }

        if (fn1 == 0 && fn2 == 0) return false;

        // Patch: mov byte ptr [rdi], 0; xor eax, eax; ret
        byte* patch = stackalloc byte[] { 0xC6, 0x07, 0x00, 0x31, 0xC0, 0xC3 };
        bool ok = true;

        ulong cr3 = KernelPaging.GetProcessCr3(io, shellUiPid, fwMajorMinor);
        if (cr3 == 0) return false;

        if (fn1 != 0)
        {
            byte* tmp1 = stackalloc byte[6];
            PayloadDebug.mdbg_copyout(shellUiPid, (nint)fn1, tmp1, 6);
            ok &= KernelPaging.PhysCopyin(io, cr3, dmapBase, fn1, patch, 6);
        }
        if (fn2 != 0)
        {
            byte* tmp2 = stackalloc byte[6];
            PayloadDebug.mdbg_copyout(shellUiPid, (nint)fn2, tmp2, 6);
            ok &= KernelPaging.PhysCopyin(io, cr3, dmapBase, fn2, patch, 6);
        }

        return ok;
    }
}
