// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Debug;

/// <summary>
/// The CPU profiler bindings. Push and pop labelled markers, plot named values against time, insert
/// timestamped bookmarks, tag buffers for the data sampler, delimit logical file accesses, and query
/// whether a capture is active.
/// </summary>
public static unsafe partial class RazorCpu
{
    private const string Lib = "libSceRazorCpu";

    /// <summary>Marker flag: enable the marker on the head-up display.</summary>
    public const uint MarkerEnableHud = 1;

    /// <summary>Marker flag: promise that the marker is popped inside the same function that pushed it.</summary>
    public const uint MarkerPromiseScoped = 2;

    /// <summary>Return value from <see cref="sceRazorCpuIsCapturing"/>: no capture is active.</summary>
    public const uint NotCapturing = 0;

    /// <summary>Return value from <see cref="sceRazorCpuIsCapturing"/>: a capture is active.</summary>
    public const uint Capturing = 1;

    /// <summary>ABGR color word for a red marker.</summary>
    public const uint ColorRed = 0x800000FFu;

    /// <summary>ABGR color word for a green marker.</summary>
    public const uint ColorGreen = 0x8000FF00u;

    /// <summary>ABGR color word for a blue marker.</summary>
    public const uint ColorBlue = 0x80FF0000u;

    /// <summary>ABGR color word for a yellow marker.</summary>
    public const uint ColorYellow = 0x8000FFFFu;

    /// <summary>ABGR color word for a magenta marker.</summary>
    public const uint ColorMagenta = 0x80FF00FFu;

    /// <summary>ABGR color word for a cyan marker.</summary>
    public const uint ColorCyan = 0x80FFFF00u;

    /// <summary>ABGR color word for a white marker.</summary>
    public const uint ColorWhite = 0x80FFFFFFu;

    /// <summary>ABGR color word for a black marker.</summary>
    public const uint ColorBlack = 0x80000000u;

    /// <summary>Return value from <see cref="sceRazorCpuFlushOccurred"/>: a flush occurred since the last call.</summary>
    public const uint FlushOccurredFlag = 1;

    /// <summary>Return value from <see cref="sceRazorCpuFlushOccurred"/>: no flush occurred since the last call.</summary>
    public const uint NoFlushOccurred = 0;

    /// <summary>Operation value for <see cref="sceRazorCpuBeginLogicalFileAccess"/>: a read.</summary>
    public const byte LogicalFileRead = 0;

    /// <summary>Operation value for <see cref="sceRazorCpuBeginLogicalFileAccess"/>: a write.</summary>
    public const byte LogicalFileWrite = 1;

    /// <summary>
    /// Reports whether a flush occurred since the last call, and optionally the cycles spent flushing.
    /// </summary>
    /// <param name="pTimeSpentInFlush">Optional pointer that receives the cycles spent flushing; pass null to skip.</param>
    /// <returns><see cref="FlushOccurredFlag"/> or <see cref="NoFlushOccurred"/>.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuFlushOccurred(ulong* pTimeSpentInFlush);

    /// <summary>
    /// Switches the user-marker context tag from the running fiber to the thread. Every subsequent marker
    /// carries the thread identifier; matched push/pop within the same thread across fibers is the caller's
    /// responsibility.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial void sceRazorCpuDisableFiberUserMarkers();

    /// <summary>Pushes a marker with a UTF-8 label; the label is copied into the trace buffer.</summary>
    /// <param name="label">Marker label as a NUL-terminated UTF-8 string. Up to 16,384 bytes including the terminator.</param>
    /// <param name="color">ABGR color word; use one of the <c>Color*</c> constants or a caller-supplied value.</param>
    /// <param name="flags">Zero, or <see cref="MarkerPromiseScoped"/> to enable backtrace capture for the marker.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuPushMarker(byte* label, uint color, uint flags);

    /// <summary>
    /// Pushes a marker whose label pointer is stored verbatim; the label must remain valid for the whole
    /// capture. When live streaming is on the label is copied.
    /// </summary>
    /// <param name="label">Static NUL-terminated UTF-8 label.</param>
    /// <param name="color">ABGR color word.</param>
    /// <param name="flags">Zero, or <see cref="MarkerPromiseScoped"/>.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuPushMarkerStatic(byte* label, uint color, uint flags);

    /// <summary>Pops the marker most recently pushed on this fiber or thread.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuPopMarker();

    /// <summary>Writes a timestamped point to a named plot series.</summary>
    /// <param name="series">Series name as NUL-terminated UTF-8. Up to 16,384 bytes including the terminator.</param>
    /// <param name="value">Value to record.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuPlotValue(byte* series, float value);

    /// <summary>Writes a timestamped bookmark into the trace.</summary>
    /// <param name="label">NUL-terminated UTF-8 label.</param>
    /// <param name="description">Optional NUL-terminated UTF-8 description; pass null when unused.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuWriteBookmark(byte* label, byte* description);

    /// <summary>Emits an unnamed frame-boundary event.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuSync();

    /// <summary>Emits a named frame-boundary event.</summary>
    /// <param name="label">NUL-terminated UTF-8 label. Up to 16,384 bytes including the terminator.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuNamedSync(byte* label);

    /// <summary>Assigns backing storage for the data-sampling buffer-tag table.</summary>
    /// <param name="pBuffer">Caller-allocated buffer. Alignment as required by the module.</param>
    /// <param name="uSize">Byte size of <paramref name="pBuffer"/>; use <see cref="sceRazorCpuGetDataTagStorageSize"/> to compute it.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuInitDataTags(void* pBuffer, nuint uSize);

    /// <summary>Releases the data-sampling buffer-tag table set by <see cref="sceRazorCpuInitDataTags"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuShutdownDataTags();

    /// <summary>Returns the byte size a data-sampling buffer-tag table needs for <paramref name="uTagCount"/> entries.</summary>
    [LibraryImport(Lib)]
    public static partial nuint sceRazorCpuGetDataTagStorageSize(uint uTagCount);

    /// <summary>Tags an array of fixed-size elements for the data sampler.</summary>
    /// <param name="label">NUL-terminated UTF-8 tag-type name.</param>
    /// <param name="uCategory">Caller-defined 16-bit category identifier.</param>
    /// <param name="pArray">Address of the tagged array.</param>
    /// <param name="uBufferSize">Total byte size of the tagged array.</param>
    /// <param name="uElementSize">Byte size of one element.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuTagArray(
        byte* label,
        uint uCategory,
        void* pArray,
        nuint uBufferSize,
        nuint uElementSize);

    /// <summary>Tags an untyped buffer for the data sampler.</summary>
    /// <param name="label">NUL-terminated UTF-8 tag-type name.</param>
    /// <param name="uCategory">Caller-defined 16-bit category identifier.</param>
    /// <param name="pBuffer">Address of the tagged buffer.</param>
    /// <param name="uBufferSize">Byte size of the tagged buffer.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuTagBuffer(
        byte* label,
        uint uCategory,
        void* pBuffer,
        nuint uBufferSize);

    /// <summary>Changes the size recorded for a previously tagged buffer.</summary>
    /// <param name="uCategory">Category the tag was registered under.</param>
    /// <param name="pBuffer">Address the tag was registered against.</param>
    /// <param name="uNewBufferSize">New byte size to record.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuResizeTaggedBuffer(uint uCategory, void* pBuffer, nuint uNewBufferSize);

    /// <summary>Closes a data-sampling tag for a buffer or array.</summary>
    /// <param name="uCategory">Category the tag was registered under.</param>
    /// <param name="pBuffer">Address the tag was registered against.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuUnTagBuffer(uint uCategory, void* pBuffer);

    /// <summary>
    /// Marks the beginning of a logical file access on the current thread. Subsequent read or write
    /// syscalls on this thread are attributed to the named logical file until
    /// <see cref="sceRazorCpuEndLogicalFileAccess"/> closes the region.
    /// </summary>
    /// <param name="pFilename">NUL-terminated UTF-8 logical filename.</param>
    /// <param name="uTag">Eight caller-defined metadata bytes.</param>
    /// <param name="uSize">Expected byte count for the operation.</param>
    /// <param name="operation"><see cref="LogicalFileRead"/> or <see cref="LogicalFileWrite"/>.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuBeginLogicalFileAccess(
        byte* pFilename,
        ulong uTag,
        ulong uSize,
        byte operation);

    /// <summary>Marks the end of the current thread's logical file access.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuEndLogicalFileAccess();

    /// <summary>Reports whether a host capture is currently active.</summary>
    /// <returns><see cref="Capturing"/> or <see cref="NotCapturing"/>.</returns>
    [LibraryImport(Lib)]
    public static partial uint sceRazorCpuIsCapturing();
}
