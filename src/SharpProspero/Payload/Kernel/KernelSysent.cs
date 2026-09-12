// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Kernel sysent table manipulation. Reads and patches individual system call entries
/// by their (sy_narg, pad, sy_call, ...) layout in the sysents table.
/// </summary>
/// <remarks>
/// A FreeBSD-derived <c>struct sysent</c> is 48 bytes on amd64:
/// <c>int sy_narg</c> at +0x00, pad at +0x04, <c>sy_call_t *sy_call</c> at +0x08,
/// and remaining audit / thread-count / entry / return / flags fields filling the
/// rest of the 48 bytes. Callers manipulating <c>sy_call</c> must add
/// <see cref="SyCallOffset"/> to the entry base.
/// </remarks>
public static unsafe class KernelSysent
{
    /// <summary>Size of one <c>struct sysent</c> entry on amd64 in bytes.</summary>
    public const int SysentSize = 48;

    /// <summary>Byte offset of the <c>sy_call</c> function pointer inside a sysent entry.</summary>
    public const int SyCallOffset = 8;

    /// <summary>
    /// Reads the <c>sy_call</c> function pointer for the given syscall number.
    /// </summary>
    public static ulong ReadSysentFunction(PayloadKernelIo io, ulong sysentsBase, int syscallNr)
    {
        return io.ReadU64(sysentsBase + (ulong)(syscallNr * SysentSize) + SyCallOffset);
    }

    /// <summary>
    /// Writes a new <c>sy_call</c> function pointer for the given syscall number.
    /// </summary>
    public static void WriteSysentFunction(PayloadKernelIo io, ulong sysentsBase,
        int syscallNr, ulong funcAddr)
    {
        io.WriteU64(sysentsBase + (ulong)(syscallNr * SysentSize) + SyCallOffset, funcAddr);
    }
}
