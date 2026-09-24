// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Memory;

/// <summary>
/// CPU data-cache maintenance for buffers that a DMA reader outside the CPU coherency domain will
/// consume next: the display scan-out engine, the video decoder, or any device that reads DRAM
/// through the memory controller rather than through the L2/L3 fabric.
/// <para>
/// The only kind of direct memory an application can allocate is cached
/// (<see cref="Interop.Kernel.KernelMemory.MemoryTypeCached"/> or
/// <see cref="Interop.Kernel.KernelMemory.MemoryTypeCachedShared"/>). Every store the CPU issues to
/// such memory lands in the L1 line first and only reaches DRAM once the line is evicted or
/// explicitly written back. A CPU renderer that hands a scan-out buffer to <c>sceVideoOutSubmitFlip</c>
/// without a writeback shows the display a mixture of the previous frame's bytes and only the lines
/// natural eviction happened to retire, which reads as granular noise concentrated in the region the
/// CPU wrote last.
/// </para>
/// <para>
/// <see cref="WriteBack"/> is the primitive callers use between the last store to a buffer and the
/// point of hand-off. It walks the buffer one 64-byte cache line at a time issuing
/// <c>CLFLUSHOPT</c> for each line, then <c>SFENCE</c> to order the (weakly-ordered) writebacks
/// ahead of anything the caller does afterwards. The base pointer must be 64-byte aligned; direct
/// memory allocated through <see cref="DirectMemoryRegion.Allocate"/> is 2 MB aligned and satisfies
/// that trivially.
/// </para>
/// </summary>
public static unsafe partial class CpuCache
{
    /// <summary>
    /// The placeholder library name the link step resolves to the compat object that carries
    /// <see cref="WriteBack"/>. Declared as a <c>DirectPInvoke</c> item in
    /// <c>build/Prospero.App.props</c>, so the ahead-of-time compiler emits a direct call to the
    /// entry-point symbol rather than a runtime module lookup: the name never reaches the loader.
    /// </summary>
    private const string Lib = "libSharpProsperoCompat";

    /// <summary>
    /// Writes every dirty CPU cache line covering <c>[address, address + length)</c> back to DRAM and
    /// orders the writebacks ahead of any subsequent store or call. Safe to call with
    /// <paramref name="length"/> equal to zero; the <c>SFENCE</c> still runs.
    /// </summary>
    /// <param name="address">The first byte of the range to write back. Must be 64-byte aligned.</param>
    /// <param name="length">The number of bytes to cover, walked in 64-byte cache-line steps.</param>
    /// <remarks>
    /// The call is a handful of x86 instructions with no kernel transition, so it carries
    /// <see cref="SuppressGCTransitionAttribute"/> and takes no garbage-collection safepoint.
    /// </remarks>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_write_back_cache_lines")]
    public static partial void WriteBack(void* address, nuint length);
}
