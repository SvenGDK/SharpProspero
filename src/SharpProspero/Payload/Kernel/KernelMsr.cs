// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// MSR (Model-Specific Register) access through the kernel trace mechanism.
/// Reads route via the read-MSR kekcall; writes route via a single-step
/// <c>wrmsr</c> instruction inside <see cref="PayloadKfncall"/>'s dispatch chain.
/// </summary>
public static class KernelMsr
{
    /// <summary>
    /// Reads a model-specific register by its address.
    /// </summary>
    /// <param name="msrAddr">The MSR address (e.g., 0xC0000080 for EFER).</param>
    /// <returns>The 64-bit MSR value.</returns>
    public static ulong Read(uint msrAddr)
    {
        return (ulong)PayloadKekcall.Invoke(PayloadKekcall.ReadMsr, msrAddr);
    }

    /// <summary>
    /// Writes a model-specific register. Delegates to <see cref="PayloadKfncall.WriteMsr(PayloadKernelIo, uint, ulong)"/>,
    /// which requires the trace setup to be resident.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="msrAddr">MSR number (e.g. <c>0xC0000084</c> for SFMASK).</param>
    /// <param name="value">64-bit value to write.</param>
    /// <returns><see langword="true"/> on success.</returns>
    public static bool Write(PayloadKernelIo io, uint msrAddr, ulong value)
    {
        return PayloadKfncall.WriteMsr(io, msrAddr, value);
    }

    /// <summary>IA32_EFER — Extended Feature Enable Register.</summary>
    public const uint Efer = 0xC0000080;

    /// <summary>IA32_LSTAR — Long-mode SYSCALL target.</summary>
    public const uint Lstar = 0xC0000082;

    /// <summary>SFMASK — bits cleared from RFLAGS on SYSCALL entry.</summary>
    public const uint Sfmask = 0xC0000084;

    /// <summary>IA32_GS_BASE — GS base.</summary>
    public const uint GsBase = 0xC0000101;

    /// <summary>IA32_KERNEL_GS_BASE — Kernel GS base.</summary>
    public const uint KernelGsBase = 0xC0000102;
}
