// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Media;

/// <summary>How much the player reports about what it is doing.</summary>
public enum AvPlayerDebugLevel
{
    /// <summary>Report nothing.</summary>
    None = 0,

    /// <summary>Report errors.</summary>
    Info = 1,

    /// <summary>Report errors and warnings.</summary>
    Warnings = 2,

    /// <summary>Report everything.</summary>
    All = 3,
}

/// <summary>The allocators the player calls. It has none of its own, so all four must be supplied.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct AvPlayerMemAllocator
{
    /// <summary>Passed back to each callback. Offset 0.</summary>
    public void* ObjectPointer;

    /// <summary>General allocation: (object, alignment, size) returning the block. Offset 8.</summary>
    public delegate* unmanaged<void*, uint, uint, void*> Allocate;

    /// <summary>General release: (object, block). Offset 16.</summary>
    public delegate* unmanaged<void*, void*, void> Deallocate;

    /// <summary>Frame-memory allocation: (object, alignment, size) returning the block. Offset 24.</summary>
    public delegate* unmanaged<void*, uint, uint, void*> AllocateTexture;

    /// <summary>Frame-memory release: (object, block). Offset 32.</summary>
    public delegate* unmanaged<void*, void*, void> DeallocateTexture;
}

/// <summary>
/// Optional file callbacks. Leave the whole block zero to let the player read the file itself, which
/// is what a plain path needs.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct AvPlayerFileReplacement
{
    /// <summary>Passed back to each callback. Offset 0.</summary>
    public void* ObjectPointer;

    /// <summary>Open: (object, path) returning zero on success. Offset 8.</summary>
    public delegate* unmanaged<void*, byte*, int> Open;

    /// <summary>Close: (object) returning zero on success. Offset 16.</summary>
    public delegate* unmanaged<void*, int> Close;

    /// <summary>Read: (object, buffer, position, length) returning the bytes read. Offset 24.</summary>
    public delegate* unmanaged<void*, byte*, ulong, uint, int> ReadOffset;

    /// <summary>Size: (object) returning the file length. Offset 32.</summary>
    public delegate* unmanaged<void*, ulong> Size;
}

/// <summary>Optional event callback. Leave zero to poll instead.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct AvPlayerEventReplacement
{
    /// <summary>Passed back to the callback. Offset 0.</summary>
    public void* ObjectPointer;

    /// <summary>Event: (object, eventId, sourceId, eventData). Offset 8.</summary>
    public delegate* unmanaged<void*, int, int, void*, void> EventCallback;
}

/// <summary>What the player starts with. Build one with <see cref="AvPlayer.InitializeData"/>.</summary>
[StructLayout(LayoutKind.Sequential, Size = 120)]
public unsafe struct AvPlayerInitData
{
    /// <summary>The allocators. Required. Offset 0.</summary>
    public AvPlayerMemAllocator MemoryReplacement;

    /// <summary>Optional file callbacks. Offset 40.</summary>
    public AvPlayerFileReplacement FileReplacement;

    /// <summary>Optional event callback. Offset 80.</summary>
    public AvPlayerEventReplacement EventReplacement;

    /// <summary>How much the player reports. Offset 96.</summary>
    public AvPlayerDebugLevel DebugLevel;

    /// <summary>Thread priority; zero takes the default of 700, otherwise 637 to 764. Offset 100.</summary>
    public uint BasePriority;

    /// <summary>Frame buffers to hold, 2 to 16; anything else takes 2. Offset 104.</summary>
    public int NumOutputVideoFrameBuffers;

    /// <summary>Whether playback begins without waiting for the callback. Offset 108.</summary>
    public byte AutoStart;

    private byte _reserved0;
    private byte _reserved1;
    private byte _reserved2;

    /// <summary>Optional default language for stream selection. Offset 112.</summary>
    public byte* DefaultLanguage;
}

/// <summary>The details of an audio frame.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct AvPlayerAudioDetails
{
    /// <summary>How many channels the frame carries. Offset 0.</summary>
    public ushort ChannelCount;

    private ushort _reserved;

    /// <summary>Samples per second. Offset 4.</summary>
    public uint SampleRate;

    /// <summary>The payload size in bytes. Offset 8.</summary>
    public uint Size;

    /// <summary>The language code. Offset 12.</summary>
    public uint LanguageCode;
}

/// <summary>The details of a video stream.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct AvPlayerVideoDetails
{
    /// <summary>Width in pixels. Offset 0.</summary>
    public uint Width;

    /// <summary>Height in pixels. Offset 4.</summary>
    public uint Height;

    /// <summary>Aspect ratio. Offset 8.</summary>
    public float AspectRatio;

    /// <summary>The language code. Offset 12.</summary>
    public uint LanguageCode;
}

/// <summary>The details of a frame; which member applies depends on the stream it came from.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
public struct AvPlayerStreamDetails
{
    /// <summary>Read when the frame is audio.</summary>
    [FieldOffset(0)] public AvPlayerAudioDetails Audio;

    /// <summary>Read when the stream is video.</summary>
    [FieldOffset(0)] public AvPlayerVideoDetails Video;
}

/// <summary>What one of a source's streams carries.</summary>
public enum AvPlayerStreamType
{
    /// <summary>Nothing the player recognises.</summary>
    Unknown = 0,

    /// <summary>Pictures.</summary>
    Video = 1,

    /// <summary>Sound.</summary>
    Audio = 2,

    /// <summary>Subtitles.</summary>
    TimedText = 3,
}

/// <summary>How the player decides when to hand back audio and video frames.</summary>
public enum AvPlayerAvSyncMode
{
    /// <summary>
    /// Audio drives the clock when audio is on; otherwise the player runs an internal one. Video frames
    /// arrive at that clock.
    /// </summary>
    Default = 0,

    /// <summary>Frames arrive as soon as they decode; the caller decides when to draw them.</summary>
    None = 1,
}

/// <summary>What kind of content a source URI carries.</summary>
public enum AvPlayerSourceType
{
    /// <summary>Not specified; the player infers the type from the file extension.</summary>
    Unknown = 0,

    /// <summary>Local or remote MP4 file.</summary>
    FileMp4 = 1,

    /// <summary>Local or remote WebM file.</summary>
    FileWebm = 2,

    /// <summary>HTTP live-streaming source.</summary>
    Hls = 8,
}

/// <summary>What a <see cref="AvPlayerSourceDetails"/> URI addresses.</summary>
public enum AvPlayerUriType
{
    /// <summary>The source itself: a file path or an HLS playlist URL.</summary>
    Source = 0,
}

/// <summary>Which colour primaries a video stream identifies itself with.</summary>
public enum AvPlayerColourPrimaries
{
    /// <summary>Reserved for future standards.</summary>
    Reserved = 0,

    /// <summary>Rec. ITU-R BT.709-6, BT.1361-0, IEC 61966-2-1 sRGB/sYCC, IEC 61966-2-4.</summary>
    Bt709 = 1,

    /// <summary>Not specified; the application decides.</summary>
    Unspecified = 2,

    /// <summary>Rec. ITU-R BT.470-6 System M.</summary>
    Bt470SystemM = 4,

    /// <summary>Rec. ITU-R BT.601-6 625, BT.470-6 System B/G, BT.1358-1 625, 625 PAL/SECAM.</summary>
    Bt601_625 = 5,

    /// <summary>Rec. ITU-R BT.601-6 525, BT.1358-1 525, BT.1700-0 NTSC, SMPTE 170M (2004).</summary>
    Bt601_525 = 6,

    /// <summary>SMPTE 240M (1999).</summary>
    Smpte240M = 7,

    /// <summary>Generic film with colour filters using Illuminant C.</summary>
    GenericFilm = 8,

    /// <summary>Rec. ITU-R BT.2020-2, BT.2100-0.</summary>
    Bt2020 = 9,

    /// <summary>SMPTE ST 428-1 (CIE 1931 XYZ).</summary>
    SmpteSt428 = 10,

    /// <summary>SMPTE RP 431-2 (2011).</summary>
    SmpteRp431 = 11,

    /// <summary>SMPTE EG 432-1 (2010).</summary>
    SmpteEg432 = 12,

    /// <summary>EBU Tech. 3213-E (1975).</summary>
    EbuTech3213E = 22,
}

/// <summary>The opto-electronic transfer characteristics a video stream identifies itself with.</summary>
public enum AvPlayerTransferCharacteristics
{
    /// <summary>Reserved for future standards.</summary>
    Reserved = 0,

    /// <summary>Rec. ITU-R BT.709-6, BT.1361-0.</summary>
    Bt709 = 1,

    /// <summary>Not specified; the application decides.</summary>
    Unspecified = 2,

    /// <summary>Assumed display gamma 2.2. Rec. ITU-R BT.470-6 System M, BT.1700-0 625 PAL/SECAM.</summary>
    Bt470SystemM = 4,

    /// <summary>Assumed display gamma 2.8. Rec. ITU-R BT.470-6 System B/G.</summary>
    Bt470SystemBg = 5,

    /// <summary>Rec. ITU-R BT.601-6 525 or 625, BT.1358-1 525 or 625, BT.1700-0 NTSC, SMPTE 170M (2004).</summary>
    Bt601 = 6,

    /// <summary>SMPTE 240M (1999).</summary>
    Smpte240M = 7,

    /// <summary>Linear transfer.</summary>
    Linear = 8,

    /// <summary>Logarithmic transfer (100:1 range).</summary>
    Logarithmic = 9,

    /// <summary>Logarithmic transfer (100 * sqrt(10) : 1 range).</summary>
    LogarithmicSqrt = 10,

    /// <summary>IEC 61966-2-4.</summary>
    Iec61966 = 11,

    /// <summary>Rec. ITU-R BT.1361-0 extended colour gamut system.</summary>
    Bt1361 = 12,

    /// <summary>IEC 61966-2-1 sRGB or sYCC.</summary>
    Srgb = 13,

    /// <summary>Rec. ITU-R BT.2020-2.</summary>
    Bt2020 = 14,

    /// <summary>Rec. ITU-R BT.2100-0 perceptual quantization (PQ), SMPTE ST 2084 for 10/12/14/16-bit systems.</summary>
    Pq = 16,

    /// <summary>SMPTE ST 428-1.</summary>
    SmpteSt428 = 17,

    /// <summary>Rec. ITU-R BT.2100-0 hybrid log-gamma (HLG), ARIB STD-B67.</summary>
    Hlg = 18,
}

/// <summary>Which video decoder the player uses.</summary>
public enum AvPlayerVideoDecoderType
{
    /// <summary>The platform's default video decoder.</summary>
    Default = 0,

    /// <summary>The compute-based software decoder that does not depend on sliced encoding.</summary>
    Software2 = 1,
}

/// <summary>Which audio decoder the player uses.</summary>
public enum AvPlayerAudioDecoderType
{
    /// <summary>The platform's default audio decoder.</summary>
    Default = 0,
}

/// <summary>Which channel ordering the audio decoder writes for 7- and 7.1-channel AAC output.</summary>
public enum AvPlayerAudioChannelOrder
{
    /// <summary>Default ordering: C, L, R, Ls, Rs, ExtL, ExtR, LFE.</summary>
    Default = 0,

    /// <summary>Variant A: L, R, C, LFE, Lext, Rext, Ls, Rs.</summary>
    ExtLExtRLsRs = 1,

    /// <summary>Variant B: L, R, C, LFE, Ls, Rs, Lext, Rext.</summary>
    LsRsExtLExtR = 2,
}

/// <summary>One of a source's streams: what it carries, its details, and how long it runs.</summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public struct AvPlayerStreamInfo
{
    /// <summary>What the stream carries. Offset 0.</summary>
    public AvPlayerStreamType Type;

    private uint _reserved;

    /// <summary>The details, read according to <see cref="Type"/>. Offset 8.</summary>
    public AvPlayerStreamDetails Details;

    /// <summary>How long the stream runs, in milliseconds. Offset 24.</summary>
    public ulong Duration;
}

/// <summary>One decoded frame: where the payload is, when it plays, and what it holds.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct AvPlayerFrameInfo
{
    /// <summary>The payload. Offset 0.</summary>
    public byte* Data;

    private uint _reserved;
    private uint _padding;

    /// <summary>When the frame plays, in milliseconds. Offset 16.</summary>
    public ulong TimeStamp;

    /// <summary>What the frame holds. Offset 24.</summary>
    public AvPlayerStreamDetails Details;
}

/// <summary>
/// One decoded video frame in extended form. The extended frame carries the pitch, which is needed to
/// address the NV12 planes the decoder writes. Only the fields the SDK reads are named; the rest of the
/// 80-byte details union is reserved.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 104)]
public unsafe struct AvPlayerFrameInfoEx
{
    /// <summary>The frame payload (NV12 planes). Offset 0.</summary>
    [FieldOffset(0)] public void* Data;

    /// <summary>When the frame plays, in milliseconds. Offset 16.</summary>
    [FieldOffset(16)] public ulong TimeStamp;

    /// <summary>Video width in pixels. Offset 24 (details.video.width).</summary>
    [FieldOffset(24)] public uint VideoWidth;

    /// <summary>Video height in pixels. Offset 28 (details.video.height).</summary>
    [FieldOffset(28)] public uint VideoHeight;

    /// <summary>
    /// How many columns at the left of the framebuffer are not part of the picture. Offset 44
    /// (details.video.cropLeftOffset).
    /// </summary>
    [FieldOffset(44)] public uint CropLeft;

    /// <summary>
    /// How many columns at the right of the framebuffer are not part of the picture, measured from the
    /// pitch rather than the width - the padding that makes up the pitch is counted here too. Offset 48.
    /// </summary>
    [FieldOffset(48)] public uint CropRight;

    /// <summary>How many rows at the top are not part of the picture. Offset 52.</summary>
    [FieldOffset(52)] public uint CropTop;

    /// <summary>How many rows at the bottom are not part of the picture. Offset 56.</summary>
    [FieldOffset(56)] public uint CropBottom;

    /// <summary>Row pitch of the luma and chroma planes in bytes. Offset 60 (details.video.pitch).</summary>
    [FieldOffset(60)] public uint VideoPitch;
}

/// <summary>The bounding rectangle a timed-text run draws into, in pixels from the framebuffer edges.</summary>
[StructLayout(LayoutKind.Sequential, Size = 8)]
public struct AvPlayerTextPosition
{
    /// <summary>The top edge in pixels from the topmost row. Offset 0.</summary>
    public short Top;

    /// <summary>The left edge in pixels from the leftmost column. Offset 2.</summary>
    public short Left;

    /// <summary>The bottom edge in pixels from the topmost row. Offset 4.</summary>
    public short Bottom;

    /// <summary>The right edge in pixels from the leftmost column. Offset 6.</summary>
    public short Right;
}

/// <summary>Extended audio-stream details, 80 bytes with reserved tail.</summary>
[StructLayout(LayoutKind.Sequential, Size = 80)]
public struct AvPlayerAudioDetailsEx
{
    /// <summary>How many channels the frame carries. Offset 0.</summary>
    public ushort ChannelCount;

    private ushort _reserved0;

    /// <summary>Samples per second. Offset 4.</summary>
    public uint SampleRate;

    /// <summary>The payload size in bytes. Offset 8.</summary>
    public uint Size;

    /// <summary>The language code. Offset 12.</summary>
    public uint LanguageCode;
}

/// <summary>
/// Extended video-stream details, 80 bytes with reserved tail. Adds the frame's crop insets, the row
/// pitch, the sample bit depths, the framerate, and the colour-space identifiers.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 80)]
public struct AvPlayerVideoDetailsEx
{
    /// <summary>The picture width in pixels. Offset 0.</summary>
    public uint Width;

    /// <summary>The picture height in pixels. Offset 4.</summary>
    public uint Height;

    /// <summary>Aspect ratio. Offset 8.</summary>
    public float AspectRatio;

    /// <summary>The language code. Offset 12.</summary>
    public uint LanguageCode;

    private uint _reserved0;

    /// <summary>Columns at the left of the framebuffer that are not part of the picture. Offset 20.</summary>
    public uint CropLeftOffset;

    /// <summary>
    /// Columns at the right of the framebuffer that are not part of the picture, measured from the
    /// pitch rather than the width; the pitch padding is counted here. Offset 24.
    /// </summary>
    public uint CropRightOffset;

    /// <summary>Rows at the top of the framebuffer that are not part of the picture. Offset 28.</summary>
    public uint CropTopOffset;

    /// <summary>Rows at the bottom of the framebuffer that are not part of the picture. Offset 32.</summary>
    public uint CropBottomOffset;

    /// <summary>The framebuffer row pitch in bytes. Offset 36.</summary>
    public uint Pitch;

    /// <summary>Bit depth of the luma samples. Only 8 for AVC. Offset 40.</summary>
    public byte LumaBitDepth;

    /// <summary>Bit depth of the chroma samples. Only 8 for AVC. Offset 41.</summary>
    public byte ChromaBitDepth;

    /// <summary>
    /// True when luma and chroma span the full 0-255 range instead of the studio range. Almost always
    /// false. Offset 42.
    /// </summary>
    public byte VideoFullRangeFlag;

    private byte _reserved1a;
    private byte _reserved1b;
    private byte _reserved1c;
    private byte _reserved1d;
    private byte _reserved1e;

    /// <summary>Frames per second. Offset 48.</summary>
    public double Framerate;

    /// <summary>Which colour primaries the stream identifies itself with. Offset 56.</summary>
    public AvPlayerColourPrimaries ColourPrimaries;

    /// <summary>The opto-electronic transfer characteristic the stream identifies itself with. Offset 60.</summary>
    public AvPlayerTransferCharacteristics TransferCharacteristics;
}

/// <summary>Extended timed-text stream details, 80 bytes with reserved tail.</summary>
[StructLayout(LayoutKind.Sequential, Size = 80)]
public struct AvPlayerTimedTextDetailsEx
{
    /// <summary>The language code. Offset 0.</summary>
    public uint LanguageCode;

    /// <summary>How many bytes of timed text the frame carries. Offset 4.</summary>
    public ushort TextSize;

    /// <summary>The font size; ignored for HLS sources. Offset 6.</summary>
    public ushort FontSize;

    /// <summary>The rectangle to draw the text into; ignored for HLS sources. Offset 8.</summary>
    public AvPlayerTextPosition Position;
}

/// <summary>
/// The extended-form details of a stream, read according to <see cref="AvPlayerStreamInfoEx.Type"/>.
/// The three views share the same 80 bytes.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct AvPlayerStreamDetailsEx
{
    /// <summary>Read when the stream is audio.</summary>
    [FieldOffset(0)] public AvPlayerAudioDetailsEx Audio;

    /// <summary>Read when the stream is video.</summary>
    [FieldOffset(0)] public AvPlayerVideoDetailsEx Video;

    /// <summary>Read when the stream is timed text.</summary>
    [FieldOffset(0)] public AvPlayerTimedTextDetailsEx TimedText;
}

/// <summary>
/// The extended-form description of one stream. Set <see cref="ThisSize"/> to
/// <c>sizeof(AvPlayerStreamInfoEx)</c> before the call so the library can accept future extensions.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 104)]
public struct AvPlayerStreamInfoEx
{
    /// <summary>How many bytes the caller thinks this struct is. Offset 0.</summary>
    public nuint ThisSize;

    /// <summary>What the stream carries. Offset 8.</summary>
    public AvPlayerStreamType Type;

    private uint _reserved;

    /// <summary>The details, read according to <see cref="Type"/>. Offset 16.</summary>
    public AvPlayerStreamDetailsEx Details;

    /// <summary>How long the stream runs, in milliseconds. Offset 96.</summary>
    public ulong Duration;
}

/// <summary>A URI the player consumes: a pointer to the string and its length.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct AvPlayerUri
{
    /// <summary>The URI text as a UTF-8 byte string. Offset 0.</summary>
    public byte* Name;

    /// <summary>How many bytes the URI has, not counting a trailing NUL if present. Offset 8.</summary>
    public uint Length;
}

/// <summary>
/// The details of a source: its URI and an optional explicit type. When
/// <see cref="SourceType"/> is <see cref="AvPlayerSourceType.Unknown"/> the player guesses from the file
/// extension in the URI.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 128)]
public struct AvPlayerSourceDetails
{
    /// <summary>The URI to play. Offset 0.</summary>
    [FieldOffset(0)] public AvPlayerUri Uri;

    /// <summary>The kind of content the URI points at. Offset 80.</summary>
    [FieldOffset(80)] public AvPlayerSourceType SourceType;
}

/// <summary>
/// The thread parameters for one of the player's internal threads. A zero <see cref="Priority"/>
/// inherits the priority of the thread that calls the extended init; a zero <see cref="StackSize"/>
/// takes the default.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 48)]
public struct AvPlayerThreadInfo
{
    /// <summary>The absolute thread priority. Offset 0.</summary>
    public uint Priority;

    /// <summary>The stack size in bytes. Offset 4.</summary>
    public uint StackSize;

    /// <summary>The processor mask the thread runs on. Offset 8.</summary>
    public ulong Affinity;
}

/// <summary>
/// The extended initialization parameters. Set <see cref="ThisSize"/> to
/// <c>sizeof(AvPlayerInitDataEx)</c> and clear the whole struct before filling any field.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 560)]
public unsafe struct AvPlayerInitDataEx
{
    /// <summary>How many bytes the caller thinks this struct is. Offset 0.</summary>
    public nuint ThisSize;

    /// <summary>The allocators. Required. Offset 8.</summary>
    public AvPlayerMemAllocator MemoryReplacement;

    /// <summary>Optional file callbacks. Offset 48.</summary>
    public AvPlayerFileReplacement FileReplacement;

    /// <summary>Optional event callback. Offset 88.</summary>
    public AvPlayerEventReplacement EventReplacement;

    /// <summary>Optional default language for stream selection. Offset 104.</summary>
    public byte* DefaultLanguage;

    /// <summary>How much the player reports. Offset 112.</summary>
    public AvPlayerDebugLevel DebugLevel;

    /// <summary>Whether playback begins without waiting for the callback. Offset 116.</summary>
    public byte AutoStart;

    private byte _reserved0;
    private byte _reserved1;
    private byte _reserved2;

    /// <summary>Audio-decoder thread parameters. Offset 120.</summary>
    public AvPlayerThreadInfo AudioDecoder;

    /// <summary>Video-decoder thread parameters. Offset 168.</summary>
    public AvPlayerThreadInfo VideoDecoder;

    /// <summary>Demuxer thread parameters. Offset 216.</summary>
    public AvPlayerThreadInfo Demuxer;

    /// <summary>Event thread parameters. Offset 264.</summary>
    public AvPlayerThreadInfo Event;

    /// <summary>Call-queue thread parameters. Offset 312.</summary>
    public AvPlayerThreadInfo CallQueue;

    /// <summary>HTTP command-processor thread parameters. Offset 360.</summary>
    public AvPlayerThreadInfo HttpCommandProcessor;

    /// <summary>HTTP segment-manager thread parameters. Offset 408.</summary>
    public AvPlayerThreadInfo HttpSegmentManager;

    /// <summary>HTTP stream-list thread parameters. Offset 456.</summary>
    public AvPlayerThreadInfo HttpStreamlist;

    /// <summary>File-streaming thread parameters. Offset 504.</summary>
    public AvPlayerThreadInfo FileStreaming;

    /// <summary>Frame buffers to hold, 2 to 16; anything else takes 2. Offset 552.</summary>
    public int NumOutputVideoFrameBuffers;
}

/// <summary>
/// The parameters that start playback. Set <see cref="ThisSize"/> to <c>sizeof(AvPlayerStartInfoEx)</c>
/// before the call.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct AvPlayerStartInfoEx
{
    /// <summary>How many bytes the caller thinks this struct is. Offset 0.</summary>
    public nuint ThisSize;

    /// <summary>Where playback starts, in milliseconds. Offset 8.</summary>
    public ulong StartTimeMilliseconds;
}

/// <summary>The HTTP context and optional SSL context an HLS source draws from.</summary>
[StructLayout(LayoutKind.Sequential, Size = 8)]
public struct AvPlayerHttpContext
{
    /// <summary>The HTTP context id returned by <c>sceHttpInit</c>. Offset 0.</summary>
    public uint HttpContextId;

    /// <summary>The SSL context id returned by <c>sceSslInit</c>; required for HTTPS sources. Offset 4.</summary>
    public uint SslContextId;
}

/// <summary>The parameters the software video decoder takes when the client picks it.</summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public struct AvPlayerVideoSoftware2Params
{
    /// <summary>The CPU affinity mask; zero inherits the caller's. Offset 0.</summary>
    public ulong CpuAffinityMask;

    /// <summary>The CPU thread priority; zero inherits the caller's. Offset 8.</summary>
    public int CpuThreadPriority;

    /// <summary>The decoder input-queue depth, 1 to 8; zero takes the default of 4. Offset 12.</summary>
    public byte DecodeInputQueueDepth;

    /// <summary>The compute pipe id, 0 to 4. Offset 13.</summary>
    public byte ComputePipeId;

    /// <summary>The compute queue id, 0 to 7. Offset 14.</summary>
    public byte ComputeQueueId;
}

/// <summary>The parameters the audio decoder takes.</summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public struct AvPlayerAudioDecoderParams
{
    /// <summary>The channel ordering for 7- and 7.1-channel AAC output. Offset 0.</summary>
    public AvPlayerAudioChannelOrder AudioChannelOrder;
}

/// <summary>The decoder-initialization parameters for one audio or video decoder.</summary>
[StructLayout(LayoutKind.Explicit, Size = 40)]
public struct AvPlayerDecoderInit
{
    /// <summary>The video decoder to use. Offset 0.</summary>
    [FieldOffset(0)] public AvPlayerVideoDecoderType VideoType;

    /// <summary>The audio decoder to use. Offset 0.</summary>
    [FieldOffset(0)] public AvPlayerAudioDecoderType AudioType;

    /// <summary>The software video-decoder parameters. Offset 8.</summary>
    [FieldOffset(8)] public AvPlayerVideoSoftware2Params VideoSw2;

    /// <summary>The audio-decoder parameters. Offset 8.</summary>
    [FieldOffset(8)] public AvPlayerAudioDecoderParams Audio;
}

/// <summary>
/// The advanced initialization parameters. Fill with zeros before setting any field so the reserved
/// bytes do not collide with future ones.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 152)]
public struct AvPlayerPostInitData
{
    /// <summary>
    /// The demux video buffer size in bytes. Zero picks 4 MiB for MP4, WebM and HLS. The valid range is
    /// 128 KiB to 32 MiB. Offset 0.
    /// </summary>
    public uint DemuxVideoBufferSize;

    private uint _reserved;

    /// <summary>The video-decoder parameters. Offset 8.</summary>
    public AvPlayerDecoderInit VideoDecoderInit;

    /// <summary>The audio-decoder parameters. Offset 48.</summary>
    public AvPlayerDecoderInit AudioDecoderInit;

    /// <summary>The HTTP context ids for HLS sources. Offset 88.</summary>
    public AvPlayerHttpContext HttpContext;
}

/// <summary>
/// Media-playback bindings. Start the player with allocators it can call, add a source, start it, and
/// pull decoded audio and video frames while it stays active.
/// </summary>
public static unsafe partial class AvPlayer
{
    private const string Lib = "libSceAvPlayer";

    /// <summary>The default thread priority the player takes when none is given.</summary>
    public const uint DefaultBasePriority = 700;

    /// <summary>Zeroes <paramref name="data"/> so only the fields a caller sets are non-zero.</summary>
    public static void InitializeData(AvPlayerInitData* data)
        => new System.Span<byte>(data, sizeof(AvPlayerInitData)).Clear();

    /// <summary>Starts a player. Returns the handle, or null when it could not start.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceAvPlayerInit(AvPlayerInitData* data);

    /// <summary>Adds the file at <paramref name="path"/> as the source to play.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerAddSource(void* handle, byte* path);

    /// <summary>Begins playback.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerStart(void* handle);

    /// <summary>Stops playback.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerStop(void* handle);

    /// <summary>Pauses playback.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerPause(void* handle);

    /// <summary>Resumes paused playback.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerResume(void* handle);

    /// <summary>Whether the player still has something to play.</summary>
    [LibraryImport(Lib)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool sceAvPlayerIsActive(void* handle);

    /// <summary>Sets whether the source repeats.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerSetLooping(void* handle, [MarshalAs(UnmanagedType.U1)] bool loop);

    /// <summary>
    /// Takes the next decoded audio frame into <paramref name="frame"/>. Returns false when none is
    /// ready.
    /// </summary>
    [LibraryImport(Lib)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool sceAvPlayerGetAudioData(void* handle, AvPlayerFrameInfo* frame);

    /// <summary>
    /// Takes the next decoded video frame into <paramref name="frame"/>, in NV12 with the pitch filled.
    /// Returns false when none is ready.
    /// </summary>
    [LibraryImport(Lib)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static partial bool sceAvPlayerGetVideoDataEx(void* handle, AvPlayerFrameInfoEx* frame);

    /// <summary>The playback position in milliseconds.</summary>
    [LibraryImport(Lib)]
    public static partial ulong sceAvPlayerCurrentTime(void* handle);

    /// <summary>Moves playback to <paramref name="milliseconds"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerJumpToTime(void* handle, ulong milliseconds);

    /// <summary>
    /// How many streams the source carries. A source is read on the player's own thread, so this
    /// answers zero until that finishes, and again once playback has been stopped.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerStreamCount(void* handle);

    /// <summary>Describes one of the source's streams.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerGetStreamInfo(void* handle, uint streamId, AvPlayerStreamInfo* info);

    /// <summary>
    /// Turns a stream on. Playback carries the streams that were turned on and no others, so a player
    /// whose streams were all left off refuses to start rather than playing everything.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerEnableStream(void* handle, uint streamId);

    /// <summary>Shuts the player down and releases it.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerClose(void* handle);

    /// <summary>
    /// Starts a player with the extended parameters. Writes the handle to <paramref name="handleOut"/>
    /// and returns zero on success. The caller must set
    /// <see cref="AvPlayerInitDataEx.ThisSize"/> to <c>sizeof(AvPlayerInitDataEx)</c>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerInitEx(AvPlayerInitDataEx* initDataEx, void** handleOut);

    /// <summary>
    /// Applies the advanced initialization parameters. Call with caution and only when the defaults
    /// are not enough.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerPostInit(void* handle, AvPlayerPostInitData* postInit);

    /// <summary>
    /// Adds the source described by <paramref name="sourceDetails"/>. The source type may be omitted
    /// to let the player guess from the URI extension.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerAddSourceEx(void* handle, AvPlayerUriType uriType, AvPlayerSourceDetails* sourceDetails);

    /// <summary>
    /// Describes one of the source's streams in the extended form, which carries the crop insets,
    /// pitch, framerate, and colour identifiers alongside the basics.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerGetStreamInfoEx(void* handle, uint streamId, AvPlayerStreamInfoEx* info);

    /// <summary>Turns a stream off.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerDisableStream(void* handle, uint streamId);

    /// <summary>
    /// Swaps the active audio stream for another once playback has started, for example to change
    /// language. Use this instead of disable/enable so the swap is seamless.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerChangeStream(void* handle, uint oldStreamId, uint newStreamId);

    /// <summary>
    /// Starts playback with the extended parameters, which include the initial position in
    /// milliseconds. The caller must set
    /// <see cref="AvPlayerStartInfoEx.ThisSize"/> to <c>sizeof(AvPlayerStartInfoEx)</c>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerStartEx(void* handle, AvPlayerStartInfoEx* startInfoEx);

    /// <summary>
    /// Sets the trick-play speed as hundredths of normal. 100 is normal, 400 to 3200 fast-forwards,
    /// -400 to -3200 rewinds; anything smaller than the 4x threshold refuses.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerSetTrickSpeed(void* handle, int trickSpeed);

    /// <summary>
    /// Chooses how the player times its audio and video output. Call before
    /// <see cref="sceAvPlayerStart(void*)"/>; changing the mode once playback runs is undefined.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerSetAvSyncMode(void* handle, AvPlayerAvSyncMode syncMode);

    /// <summary>
    /// Sets the network bandwidth bounds an HLS session picks quality levels within. Call before
    /// adding the source; a zero value drops that bound. Bandwidths are bits per second.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerSetAvailableBandwidth(void* handle, uint startBandwidth, uint minimumBandwidth, uint maximumBandwidth);

    /// <summary>
    /// Registers a callback the player calls with each log line. Passing <c>null</c> for
    /// <paramref name="logCallback"/> restores output to standard out. The callback receives the
    /// caller-supplied user data, the format string, and the <c>va_list</c> the caller must decode
    /// itself; it should copy anything it needs and return quickly.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerSetLogCallback(delegate* unmanaged<void*, byte*, void*, int> logCallback, void* userData);

    // The player also publishes a variadic message entry point alongside the two below. A variadic
    // call needs the caller to set the vector-register count in AL, which a fixed-shape declaration
    // never does, so binding it with a fixed argument list would hand the callee a register save
    // area it cannot read correctly. The list-taking form below is the same entry point with an
    // argument list the caller lays out, and it is the one an application can call correctly.

    /// <summary>
    /// Writes a message through the player's log channel. <paramref name="args"/> is a caller-built
    /// argument list laid out to match the platform calling convention. Pass <c>null</c> when the
    /// format carries no substitutions.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAvPlayerVprintf(byte* format, void* args);
}
