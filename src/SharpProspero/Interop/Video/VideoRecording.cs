// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Video;

/// <summary>The container the recorder writes.</summary>
public enum VideoRecordingFormat
{
    /// <summary>MP4 with AVC video and AAC audio.</summary>
    Mp4AvcAac = 0,

    /// <summary>WebM with VP9 video and Opus audio.</summary>
    WebmVp9Opus = 1,
}

/// <summary>Where the recorder is in its lifecycle.</summary>
public enum VideoRecordingStatus
{
    /// <summary>The recorder is not open.</summary>
    None = 0,

    /// <summary>The recorder is capturing.</summary>
    Running = 1,

    /// <summary>The recorder is open but paused.</summary>
    Paused = 2,
}

/// <summary>
/// How the recorder is opened: the ring-buffer duration in seconds and the container format the
/// service writes. Fill it through <see cref="VideoRecording.Init"/> before every open so the
/// service's own defaults land in <see cref="Size"/> and stay untouched by the caller.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideoRecordingParam
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint Size;

    /// <summary>How many seconds of recorded video the ring buffer retains.</summary>
    public int RingSec;

    /// <summary>Which container to write, from <see cref="VideoRecordingFormat"/>.</summary>
    public int Format;
}

/// <summary>
/// Gameplay video recording bindings. The recorder writes a ring buffer whose most recent
/// <see cref="SceVideoRecordingParam.RingSec"/> seconds are kept, opens onto a target file, and
/// starts and stops the encoder against that file.
/// </summary>
public static unsafe partial class VideoRecording
{
    private const string Lib = "libSceVideoRecording";

    /// <summary>The largest file path the recorder accepts, excluding the terminator.</summary>
    public const int MaxPathLen = 1023;

    /// <summary>The longest recording, in seconds, the service supports.</summary>
    public const int MaxTimeLen = 60 * 60;

    /// <summary>The largest heap the recorder needs, in bytes.</summary>
    public const int MaxMemSize = 4 * 1024;

    /// <summary>Fills <paramref name="param"/> with the service's own defaults. Not called directly; use <see cref="Init"/>.</summary>
    [LibraryImport(Lib, EntryPoint = "_sceVideoRecordingQueryParam")]
    public static partial void _sceVideoRecordingQueryParam(SceVideoRecordingParam* param);

    /// <summary>Reports the recorder's current lifecycle state, from <see cref="VideoRecordingStatus"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideoRecordingGetStatus();

    /// <summary>Reports how many bytes of heap the recorder needs for the settings in <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideoRecordingQueryMemSize(SceVideoRecordingParam* param);

    /// <summary>
    /// Opens the recorder against <paramref name="path"/> (NUL-terminated UTF-8, up to
    /// <see cref="MaxPathLen"/> bytes plus a terminator) using the settings in
    /// <paramref name="param"/> and the heap that <paramref name="heap"/> and
    /// <paramref name="heapSize"/> describe.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceVideoRecordingOpen(byte* path, SceVideoRecordingParam* param, void* heap, int heapSize);

    /// <summary>Starts the encoder on the open recorder.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideoRecordingStart();

    /// <summary>Stops the encoder on the open recorder.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideoRecordingStop();

    /// <summary>
    /// Closes the open recorder. When <paramref name="discard"/> is non-zero the ring buffer is dropped
    /// rather than written to the target file.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceVideoRecordingClose(int discard);

    /// <summary>
    /// Fills <paramref name="param"/>: sets <see cref="SceVideoRecordingParam.Size"/> to the structure's
    /// byte size, asks the service to write its own defaults, then sets the ring-buffer duration to
    /// fifteen minutes.
    /// </summary>
    public static void Init(SceVideoRecordingParam* param)
    {
        param->Size = (nuint)sizeof(SceVideoRecordingParam);
        _sceVideoRecordingQueryParam(param);
        param->RingSec = 60 * 15;
    }
}
