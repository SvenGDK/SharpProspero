// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Debug;
using SharpProspero.Payload.IO;
using SharpProspero.Payload.Kernel;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// One binary patch to apply to the SceShellCore process.
/// </summary>
public readonly struct ShellCorePatch
{
    /// <summary>Offset from the SceShellCore module base address.</summary>
    public readonly ulong Offset;

    /// <summary>The bytes to write at the offset.</summary>
    public readonly byte[] Data;

    /// <summary>
    /// Creates a new patch entry.
    /// </summary>
    /// <param name="offset">Offset from module base.</param>
    /// <param name="data">Bytes to write.</param>
    public ShellCorePatch(ulong offset, byte[] data)
    {
        Offset = offset;
        Data = data;
    }
}

/// <summary>
/// Console kit type for selecting the correct ShellCore patch set.
/// </summary>
public enum ConsoleKitType
{
    /// <summary>Retail console.</summary>
    Retail = 0,

    /// <summary>Testing kit.</summary>
    Testkit = 1,

    /// <summary>Development kit.</summary>
    Devkit = 2,
}

/// <summary>
/// ShellCore binary patcher. Applies firmware-specific binary patches to the
/// SceShellCore process to bypass signature verification, enable fake-signed
/// content loading, and disable license checks.
/// </summary>
/// <remarks>
/// <para>
/// The patcher locates SceShellCore in the process list, reads its base address
/// from kernel memory, and applies the patch set matching the running firmware
/// and console type. Patches are applied through the physical copy mechanism
/// (<see cref="KernelPaging.PhysCopyin"/>) to bypass the kernel's write protection
/// on the SceShellCore text section.
/// </para>
/// <para>
/// Each firmware version has up to three patch sets (retail, testkit, devkit) with
/// 25-35 entries each. The patch data is firmware-specific and must be populated
/// for each supported version.
/// </para>
/// </remarks>
public static unsafe class PayloadShellCorePatcher
{
    /// <summary>
    /// Applies the ShellCore patches for the given firmware and console type.
    /// </summary>
    /// <param name="io">Kernel I/O for reading process structures.</param>
    /// <param name="cr3">The SceShellCore process CR3 for physical address translation.</param>
    /// <param name="dmapBase">Direct physical memory map base.</param>
    /// <param name="firmwareVersion">The running firmware version (BCD-encoded).</param>
    /// <param name="kitType">The console type.</param>
    /// <returns>The number of patches applied, or -1 on failure.</returns>
    public static int Apply(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        uint firmwareVersion, ConsoleKitType kitType)
    {
        // Find SceShellCore in the process list.
        byte* shellCoreName = stackalloc byte[] {
            (byte)'S', (byte)'c', (byte)'e', (byte)'S', (byte)'h', (byte)'e', (byte)'l',
            (byte)'l', (byte)'C', (byte)'o', (byte)'r', (byte)'e', 0 };
        ulong proc = PayloadKernel.FindProcessByName(io, shellCoreName, 12);
        if (proc == 0) return -1;

        // Read the base address from the process's dynlib list.
        ulong moduleBase = PayloadHijacker.FindModuleBase(io, proc,
            "SceShellCore\0"u8, KernelOffsets.ProcSysent(firmwareVersion) - 0x260);
        if (moduleBase == 0) return -1;

        // Get the patch set for this firmware.
        ShellCorePatch[]? patches = GetPatches(firmwareVersion, kitType);
        if (patches == null || patches.Length == 0) return 0;

        // Read the SceShellCore PID for mdbg_copyout page prefetch.
        int shellCorePid = (int)io.ReadU32(proc + (ulong)KernelOffsets.ProcPid);

        // Prefetch buffer sized to one page so mdbg_copyout can pull each 4 KB
        // page containing the patch into physical memory. mdbg_copyout is the
        // demand-page fault trigger: reading a byte inside the page causes the
        // kernel to resolve the mapping and back it with a real physical frame.
        // Without a resident page, the subsequent phys_copyin (which walks the
        // process page tables and writes through the DMAP) has nowhere to land
        // the bytes and the patch silently fails.
        const int PageSize = 4096;
        const ulong PageMask = ~(ulong)(PageSize - 1);
        byte* prefetchBuf = stackalloc byte[PageSize];

        int applied = 0;
        for (int i = 0; i < patches.Length; i++)
        {
            ulong targetAddr = moduleBase + patches[i].Offset;
            int patchLen = patches[i].Data.Length;

            // Fault in every 4 KB page the patch touches, including the case
            // where the patch straddles a page boundary. One mdbg_copyout per
            // page is enough — reading any byte inside a page faults the whole
            // page into physical memory.
            ulong firstPage = targetAddr & PageMask;
            ulong lastPage = (targetAddr + (ulong)(patchLen - 1)) & PageMask;
            for (ulong page = firstPage; page <= lastPage; page += PageSize)
                PayloadDebug.mdbg_copyout(shellCorePid, (nint)page, prefetchBuf, 1);

            fixed (byte* data = patches[i].Data)
            {
                if (KernelPaging.PhysCopyin(io, cr3, dmapBase, targetAddr, data, patchLen))
                    applied++;
            }
        }

        return applied;
    }

    /// <summary>
    /// Returns the patch set for the given firmware and console type, or null if no
    /// patches are available for that combination.
    /// </summary>
    public static ShellCorePatch[]? GetPatches(uint firmwareVersion, ConsoleKitType kitType)
    {
        uint masked = firmwareVersion & KernelOffsets.VersionMask;
        return kitType switch
        {
            ConsoleKitType.Retail => GetRetailPatches(masked),
            ConsoleKitType.Testkit => GetTestkitPatches(masked),
            ConsoleKitType.Devkit => GetDevkitPatches(masked),
            _ => null,
        };
    }

    /// <summary>
    /// Detects the console kit type by checking for the presence of the debug library.
    /// </summary>
    public static ConsoleKitType DetectKitType()
    {
        byte* devkitPath = stackalloc byte[] {
            (byte)'/', (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m',
            (byte)'/', (byte)'p', (byte)'r', (byte)'i', (byte)'v',
            (byte)'/', (byte)'l', (byte)'i', (byte)'b', (byte)'/', (byte)'l', (byte)'i',
            (byte)'b', (byte)'S', (byte)'c', (byte)'e', (byte)'D', (byte)'e', (byte)'c',
            (byte)'i', (byte)'5', (byte)'D', (byte)'t', (byte)'r', (byte)'a', (byte)'c',
            (byte)'e', (byte)'p', (byte)'.', (byte)'s', (byte)'p', (byte)'r', (byte)'x', 0 };

        if (PayloadFileSystem.access(devkitPath, PayloadFileSystem.F_OK) == 0)
            return ConsoleKitType.Devkit;

        byte* testkitPath = stackalloc byte[] {
            (byte)'/', (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m',
            (byte)'/', (byte)'p', (byte)'r', (byte)'i', (byte)'v',
            (byte)'/', (byte)'l', (byte)'i', (byte)'b', (byte)'/', (byte)'l', (byte)'i',
            (byte)'b', (byte)'S', (byte)'c', (byte)'e', (byte)'D', (byte)'e', (byte)'c',
            (byte)'i', (byte)'5', (byte)'T', (byte)'t', (byte)'y', (byte)'p', (byte)'.',
            (byte)'s', (byte)'p', (byte)'r', (byte)'x', 0 };

        if (PayloadFileSystem.access(testkitPath, PayloadFileSystem.F_OK) == 0)
            return ConsoleKitType.Testkit;

        return ConsoleKitType.Retail;
    }

    // Per-firmware retail patch tables covering the supported firmware range.
    private static ShellCorePatch[]? GetRetailPatches(uint fw) =>
        ShellCorePatchData.GetRetail(fw);

    private static ShellCorePatch[]? GetTestkitPatches(uint fw) => fw switch
    {
        _ => null,
    };

    private static ShellCorePatch[]? GetDevkitPatches(uint fw) => fw switch
    {
        _ => null,
    };
}
