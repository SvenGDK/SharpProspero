// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// Direct-memory bindings. A module reserves a region of physical memory, then maps it into its
/// address space with a chosen CPU/GPU protection. Framebuffers and GPU-visible buffers come from
/// this path. All lengths and alignments are byte counts; addresses returned by the reserve step
/// are physical offsets, not pointers.
/// </summary>
public static unsafe partial class KernelMemory
{
    private const string Lib = "libkernel";

    /// <summary>General-purpose cached memory.</summary>
    public const int MemoryTypeCached = 11;

    /// <summary>Cached memory shared between the CPU and the GPU. The common choice for framebuffers.</summary>
    public const int MemoryTypeCachedShared = 12;

    /// <summary>CPU may read the mapping.</summary>
    public const int ProtCpuRead = 0x01;

    /// <summary>CPU write bit.</summary>
    public const int ProtCpuWrite = 0x02;

    /// <summary>CPU may read and write the mapping: the read and write bits combined (0x03).</summary>
    public const int ProtCpuReadWrite = ProtCpuRead | ProtCpuWrite;

    /// <summary>CPU may execute from the mapping.</summary>
    public const int ProtCpuExecute = 0x04;

    /// <summary>CPU may read, write and execute.</summary>
    public const int ProtCpuAll = 0x07;

    /// <summary>GPU may read the mapping.</summary>
    public const int ProtGpuRead = 0x10;

    /// <summary>GPU may write the mapping.</summary>
    public const int ProtGpuWrite = 0x20;

    /// <summary>GPU may read and write the mapping.</summary>
    public const int ProtGpuReadWrite = 0x30;

    /// <summary>Alias of <see cref="ProtGpuReadWrite"/>.</summary>
    public const int ProtGpuAll = 0x30;

    /// <summary>
    /// Mapping flag: keep this mapping to itself rather than joining it to a neighbouring one. A
    /// service that is handed a region and checks what backs it needs the mapping left as it was made.
    /// </summary>
    public const int MapNoCoalesce = 0x400000;

    /// <summary>The size of a memory page, and the alignment a direct mapping is made on.</summary>
    public const nuint PageSize = 16384;

    /// <summary>Size, in bytes, of the direct-memory pool available to the module.</summary>
    [LibraryImport(Lib)]
    public static partial nuint sceKernelGetDirectMemorySize();

    /// <summary>
    /// Reserves <paramref name="length"/> bytes of direct memory of <paramref name="memoryType"/>
    /// within [<paramref name="searchStart"/>, <paramref name="searchEnd"/>), aligned to
    /// <paramref name="alignment"/>. On success writes the physical offset to
    /// <paramref name="physicalAddressOut"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAllocateDirectMemory(
        long searchStart, long searchEnd, nuint length, nuint alignment, int memoryType, long* physicalAddressOut);

    /// <summary>
    /// Maps a reserved region starting at <paramref name="directMemoryStart"/> into the address
    /// space with <paramref name="protection"/>, writing the mapped pointer to
    /// <paramref name="address"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelMapDirectMemory(
        void** address, nuint length, int protection, int flags, long directMemoryStart, nuint alignment);

    /// <summary>Releases a reserved region previously obtained from the allocate call.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelReleaseDirectMemory(long start, nuint length);

    /// <summary>
    /// Maps <paramref name="length"/> bytes of flexible memory into the address space with
    /// <paramref name="protection"/>, writing the mapped pointer to <paramref name="address"/>. Flexible
    /// memory is drawn from a pool the system may move, so it needs no reserve step; it suits general
    /// working buffers rather than the GPU-visible framebuffers that direct memory backs.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelMapFlexibleMemory(void** address, nuint length, int protection, int flags);

    /// <summary>
    /// Maps flexible memory as <see cref="sceKernelMapFlexibleMemory"/> does, tagging the mapping with
    /// <paramref name="name"/> so a memory report can name it. The name is at most 31 characters.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelMapNamedFlexibleMemory(void** address, nuint length, int protection, int flags, byte* name);

    /// <summary>Releases a flexible mapping starting at <paramref name="start"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelReleaseFlexibleMemory(void* start, nuint length);

    /// <summary>
    /// Takes the addresses back. Releasing memory gives up what is behind an address; this gives up the
    /// address itself, and the two are separate - releasing alone leaves the range occupied for the
    /// life of the process, so a run that maps and releases repeatedly runs out of address space
    /// rather than out of memory.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelMunmap(void* address, nuint length);

    /// <summary>Changes the protection of an existing mapping to <paramref name="protection"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelMprotect(void* address, nuint length, int protection);

    /// <summary>On success writes the flexible memory still available to the module, in bytes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAvailableFlexibleMemorySize(nuint* outSize);

    /// <summary>
    /// Finds the largest free run of direct memory within [<paramref name="searchStart"/>,
    /// <paramref name="searchEnd"/>) aligned to <paramref name="alignment"/>, writing its physical offset
    /// to <paramref name="physicalAddressOut"/> and its size to <paramref name="sizeOut"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAvailableDirectMemorySize(
        long searchStart, long searchEnd, nuint alignment, long* physicalAddressOut, nuint* sizeOut);

    /// <summary>
    /// Describes the mapping that covers <paramref name="address"/>, writing a query-info record to
    /// <paramref name="info"/> (a buffer of <paramref name="infoSize"/> bytes). Use it to learn a region's
    /// bounds and protection.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelVirtualQuery(void* address, int flags, void* info, nuint infoSize);

    /// <summary>
    /// Extended direct-memory allocator: like <see cref="sceKernelAllocateDirectMemory"/> but with a
    /// caller-chosen <paramref name="flags"/> value for the reservation.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAllocateDirectMemory2(
        long searchStart, long searchEnd, nuint length, nuint alignment,
        int memoryType, int flags, long* physicalAddressOut);

    /// <summary>Reads the address and length of a PRT aperture window by <paramref name="index"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetPrtAperture(int index, void** address, nuint* length);

    /// <summary>
    /// Applies a run of mapping operations at once. Each entry names a range, its protection, its
    /// memory type, and one of the <see cref="SceKernelMapEntryOperation"/> operations.
    /// <paramref name="numberOfEntriesOut"/> receives how many entries had been consumed when the
    /// call returned, so a caller can retry from the first unfinished one on failure.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelBatchMap(
        SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut);

    /// <summary>
    /// Applies a run of mapping operations at once with <paramref name="flags"/> chosen by the caller.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelBatchMap2(
        SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut, int flags);
}

/// <summary>One entry of a batched mapping call: the address range, the protection, the memory type,
/// and one of the <see cref="SceKernelMapEntryOperation"/> operations to apply.</summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceKernelBatchMapEntry
{
    /// <summary>The first address of the range.</summary>
    public void* Start;

    /// <summary>The physical offset the range is backed from, for a mapping operation.</summary>
    public long Offset;

    /// <summary>The byte count of the range.</summary>
    public nuint Length;

    /// <summary>The protection bits, low byte of the <c>Prot*</c> flags on <see cref="KernelMemory"/>.</summary>
    public byte Protection;

    /// <summary>The memory type, low byte of the <c>MemoryType*</c> values on <see cref="KernelMemory"/>.</summary>
    public byte Type;

    private short _pad1;

    /// <summary>One of the <see cref="SceKernelMapEntryOperation"/> values.</summary>
    public int Operation;
}

/// <summary>Which operation one <see cref="SceKernelBatchMapEntry"/> asks for.</summary>
public enum SceKernelMapEntryOperation
{
    /// <summary>Map the range from a direct-memory reservation.</summary>
    MapDirect = 0,

    /// <summary>Unmap the range, whatever backed it.</summary>
    Unmap = 1,

    /// <summary>Change the range's protection.</summary>
    Protect = 2,

    /// <summary>Map the range from flexible memory.</summary>
    MapFlexible = 3,

    /// <summary>Change both the range's memory type and its protection.</summary>
    TypeProtect = 4,
}
