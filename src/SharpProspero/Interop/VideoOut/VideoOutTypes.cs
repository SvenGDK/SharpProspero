// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.VideoOut;

/// <summary>Limits and sentinel indices that apply to a display handle.</summary>
public static class VideoOutLimits
{
    /// <summary>Success return value for the display service.</summary>
    public const int Ok = 0;

    /// <summary>Boolean true, as the service uses it.</summary>
    public const int True = 1;

    /// <summary>Boolean false, as the service uses it.</summary>
    public const int False = 0;

    /// <summary>The largest number of buffers a display handle may register.</summary>
    public const int BufferNumMax = 16;

    /// <summary>The largest number of buffer-attribute sets a display handle may keep.</summary>
    public const int BufferAttributeNumMax = 4;

    /// <summary>The largest flip rate the display accepts.</summary>
    public const int BufferFlipRateMax = 2;

    /// <summary>Buffer index that shows a transparent blank frame instead of a registered buffer.</summary>
    public const int BufferIndexBlank = -1;

    /// <summary>Buffer index that shows an opaque black frame instead of a registered buffer.</summary>
    public const int BufferIndexBlack = -2;

    /// <summary>The initial <c>flipArg</c> value a fresh handle reports before any flip is submitted.</summary>
    public const int BufferInitialFlipArg = -1;

    /// <summary>Element count of the alpha-2 lookup table passed to <see cref="VideoOut.sceVideoOutSetAlphaControl"/>.</summary>
    public const int A2LutNum = 4;

    /// <summary>Buffer-count limit for the flat-panel-display parameter block.</summary>
    public const int BufferNumMaxFpd = 16;

    /// <summary>Attribute-set-count limit for the flat-panel-display parameter block.</summary>
    public const int BufferAttributeNumMaxFpd = 1;

    /// <summary>Flip-rate limit for the flat-panel-display parameter block.</summary>
    public const int BufferFlipRateMaxFpd = 2;

    /// <summary>Version constant expected in the primary (main) parameter block.</summary>
    public const uint ParamPrimaryVersion = 1u << 4;

    /// <summary>Alias for <see cref="ParamPrimaryVersion"/> retained for callers that use the main-parameter naming.</summary>
    public const uint ParamMainVersion = ParamPrimaryVersion;

    /// <summary>Version constant expected in the flat-panel-display parameter block.</summary>
    public const uint ParamFpdVersion = (1u << 4) | 5u;
}

/// <summary>Output bus a display handle attaches to.</summary>
public enum VideoOutBusType
{
    /// <summary>The main output.</summary>
    Main = 0,

    /// <summary>The overlay output.</summary>
    Overlay = 1,

    /// <summary>The secondary output.</summary>
    Sub = 2,
}

/// <summary>How a submitted flip is timed.</summary>
public enum VideoOutFlipMode : uint
{
    /// <summary>Flip on the next vertical blank.</summary>
    VSync = 1,

    /// <summary>Flip as soon as possible.</summary>
    Asap = 2,

    /// <summary>Vertical-blank timing that may flip within a top or bottom window.</summary>
    Window = 3,

    /// <summary>Vertical-blank timing that allows several flips per blank.</summary>
    VSyncMulti = 4,

    /// <summary>The slave side of a master/slave atomic flip pair.</summary>
    Slave = 8,

    /// <summary>The master side of a master/slave atomic flip pair.</summary>
    Master = 9,
}

/// <summary>Framebuffer memory layout.</summary>
public enum VideoOutTilingMode
{
    /// <summary>GPU-tiled layout.</summary>
    Tiled = 0,

    /// <summary>Row-major linear layout. Required for CPU-written framebuffers.</summary>
    Linear = 1,
}

/// <summary>Whether the registered buffers carry compression metadata.</summary>
public enum VideoOutBufferCategory
{
    /// <summary>Plain framebuffers with no compression metadata.</summary>
    Uncompressed = 0,

    /// <summary>Framebuffers with compression metadata.</summary>
    Compressed = 1,
}

/// <summary>Identifies which kind of event a display equeue entry carries.</summary>
public enum VideoOutEventId
{
    /// <summary>A submitted flip has retired.</summary>
    Flip = 0,

    /// <summary>A vertical blank has occurred.</summary>
    Vblank = 1,

    /// <summary>The interval before a vertical blank has begun.</summary>
    PreVblankStart = 2,
}

/// <summary>How the per-output alpha value is combined with per-pixel alpha.</summary>
public enum VideoOutGlobalAlphaMode
{
    /// <summary>Blend the global alpha with the per-pixel alpha.</summary>
    Normal = 0,

    /// <summary>Use the global alpha only and ignore the per-pixel alpha.</summary>
    GlobalAlphaOnly = 1,
}

/// <summary>Color space the alpha blend is performed in.</summary>
public enum VideoOutGlobalBlendSpace : uint
{
    /// <summary>Gamma space.</summary>
    Gamma = 0,

    /// <summary>Linear space.</summary>
    Linear = 1,
}

/// <summary>Output resolution reported through <see cref="SceVideoOutOutputStatus.Resolution"/>.</summary>
public enum VideoOutOutputResolution : uint
{
    /// <summary>Resolution not yet determined.</summary>
    Unknown = 0,

    /// <summary>High-definition output (1080p and similar).</summary>
    Hd = 1,

    /// <summary>Ultra-high-definition (4K) output.</summary>
    UltraHd4K = 2,
}

/// <summary>Dynamic range reported through <see cref="SceVideoOutOutputStatus.DynamicRange"/>.</summary>
public enum VideoOutOutputDynamicRange : uint
{
    /// <summary>Dynamic range not yet determined.</summary>
    Unknown = 0,

    /// <summary>Standard dynamic range.</summary>
    Sdr = 1,

    /// <summary>High dynamic range.</summary>
    Hdr = 2,
}

/// <summary>Bit flags reported through <see cref="SceVideoOutOutputStatus.Flags"/>.</summary>
[System.Flags]
public enum VideoOutOutputStatusFlags : ulong
{
    /// <summary>No flags set.</summary>
    None = 0,

    /// <summary>The output is in HDR.</summary>
    Hdr = 1UL << 0,
}

/// <summary>Bit flags reported through <see cref="SceVideoOutVblankStatus.Flags"/>.</summary>
[System.Flags]
public enum VideoOutVblankStatusFlags : byte
{
    /// <summary>No flags set.</summary>
    None = 0,
}

/// <summary>Delta color-compression modes accepted by <see cref="SceVideoOutBufferAttribute2.DccControl"/>.</summary>
public enum VideoOutDccControl : uint
{
    /// <summary>No delta color compression.</summary>
    None = 0,

    /// <summary>256/256/0 compression ratios.</summary>
    Dcc256_256_0 = 0x8u | 0x40u | 0u,

    /// <summary>128/128/0 compression ratios.</summary>
    Dcc128_128_0 = 0x4u | 0x20u | 0u,

    /// <summary>128/128/128 compression ratios.</summary>
    Dcc128_128_128 = 0x4u | 0x20u | 0x00100000u,

    /// <summary>256/64/64 compression ratios.</summary>
    Dcc256_64_64 = 0x8u | 0u | 0x200u,
}

/// <summary>Refresh-rate tokens carried by an output mode.</summary>
public enum VideoOutRefreshRate
{
    /// <summary>Refresh rate not determined.</summary>
    Unknown = 0,

    /// <summary>59.94 Hz.</summary>
    Rate59_94Hz = 3,

    /// <summary>119.88 Hz.</summary>
    Rate119_88Hz = 13,
}

/// <summary>Output mode tokens accepted by <see cref="VideoOut.sceVideoOutConfigureOutput"/>.</summary>
public static class VideoOutOutputMode
{
    /// <summary>Output mode not determined.</summary>
    public const ulong Unknown = 0x0000000000000000UL;

    /// <summary>The default output mode.</summary>
    public const ulong Default = 0x0000000000000001UL;

    /// <summary>The 119.88 Hz output mode.</summary>
    public const ulong Mode119_88Hz = 0x000000000000000FUL;
}

/// <summary>Pixel formats accepted by the buffer attribute setter. Values are opaque tokens.</summary>
public static class VideoOutPixelFormat
{
    /// <summary>32-bit RGBA, sRGB transfer.</summary>
    public const ulong Rgba8Srgb = 0x8000000022000000UL;

    /// <summary>32-bit BGRA, sRGB transfer. The layout used by the CPU renderer in this SDK.</summary>
    public const ulong Bgra8Srgb = 0x8000000000000000UL;

    /// <summary>10-bit-per-channel RGB with 2-bit alpha.</summary>
    public const ulong Rgb10A2 = 0x8100000622000000UL;

    /// <summary>10-bit-per-channel BGR with 2-bit alpha.</summary>
    public const ulong Bgr10A2 = 0x8100000600000000UL;

    /// <summary>10-bit-per-channel RGB with 2-bit alpha, sRGB transfer.</summary>
    public const ulong Rgb10A2Srgb = 0x8100000022000000UL;

    /// <summary>10-bit-per-channel BGR with 2-bit alpha, sRGB transfer.</summary>
    public const ulong Bgr10A2Srgb = 0x8100000000000000UL;

    /// <summary>10-bit-per-channel RGB with 2-bit alpha, BT.2100 PQ transfer.</summary>
    public const ulong Rgb10A2Bt2100Pq = 0x8100070422000000UL;

    /// <summary>10-bit-per-channel BGR with 2-bit alpha, BT.2100 PQ transfer.</summary>
    public const ulong Bgr10A2Bt2100Pq = 0x8100070400000000UL;

    /// <summary>16-bit-per-channel RGBA float.</summary>
    public const ulong Rgba16Float = 0xC001000622000000UL;

    /// <summary>16-bit-per-channel BGRA float.</summary>
    public const ulong Bgra16Float = 0xC001000600000000UL;

    /// <summary>16-bit-per-channel RGBA float in the BT.2100 PQ working space.</summary>
    public const ulong Rgba16FloatForBt2100Pq = 0xC001070722000000UL;

    /// <summary>16-bit-per-channel BGRA float in the BT.2100 PQ working space.</summary>
    public const ulong Bgra16FloatForBt2100Pq = 0xC001070700000000UL;
}

/// <summary>Options for the buffer attribute setter.</summary>
public static class VideoOutBufferAttributeOption
{
    /// <summary>No options.</summary>
    public const ulong None = 0;

    /// <summary>Ask for strict colorimetry on the registered buffers.</summary>
    public const ulong StrictColorimetry = 1UL << 3;

    /// <summary>The buffer's pixels carry alpha that is not premultiplied.</summary>
    public const ulong AlphaNonPremultiplied = 0UL << 5;

    /// <summary>The buffer's pixels carry alpha that is premultiplied into the color.</summary>
    public const ulong AlphaPremultiplied = 1UL << 5;

    /// <summary>Mask for the alpha-premultiplied bit inside an option value.</summary>
    public const ulong AlphaPremultipliedMask = 1UL << 5;

    /// <summary>Mask that covers every option this SDK exposes.</summary>
    public const ulong Mask = StrictColorimetry | AlphaPremultiplied;
}

/// <summary>
/// One entry in the array registered with the display. <see cref="Data"/> points at a mapped,
/// GPU-visible framebuffer; the remaining fields stay null for uncompressed buffers.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideoOutBuffers
{
    /// <summary>Pointer to the framebuffer pixels.</summary>
    public void* Data;

    /// <summary>Pointer to compression metadata, or null.</summary>
    public void* Metadata;

    /// <summary>Reserved. Leave zero.</summary>
    public void* Reserved0;

    /// <summary>Reserved. Leave zero.</summary>
    public void* Reserved1;
}

/// <summary>
/// Describes the geometry and format of the buffers registered with a display. Fill it through
/// <see cref="VideoOut.sceVideoOutSetBufferAttribute2"/> rather than by hand.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVideoOutBufferAttribute2
{
    private int _reserved0;

    /// <summary><see cref="VideoOutTilingMode"/>.</summary>
    public int TilingMode;

    /// <summary>Aspect ratio selector. Zero for the default.</summary>
    public int AspectRatio;

    /// <summary>Width in pixels.</summary>
    public uint Width;

    /// <summary>Height in pixels.</summary>
    public uint Height;

    /// <summary>Row pitch in pixels. Zero lets the service derive it.</summary>
    public uint PitchInPixel;

    /// <summary>Attribute options.</summary>
    public ulong Option;

    /// <summary>Pixel format token.</summary>
    public ulong PixelFormat;

    /// <summary>Clear color used with compression control.</summary>
    public ulong DccCbRegisterClearColor;

    /// <summary>Compression control.</summary>
    public uint DccControl;

    private uint _pad0;
    private ulong _reserved1_0;
    private ulong _reserved1_1;
    private ulong _reserved1_2;
}

/// <summary>
/// The output options for a mode change, an opaque 64-byte block. Fill it with
/// <see cref="VideoOut.sceVideoOutInitializeOutputOptions"/> before passing it to
/// <see cref="VideoOut.sceVideoOutConfigureOutput"/> or <see cref="VideoOut.sceVideoOutIsOutputSupported"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceVideoOutOutputOptions
{
    private fixed uint _internalData[16];
}

/// <summary>
/// The current state of a display output, from <see cref="VideoOut.sceVideoOutGetOutputStatus"/>: the
/// resolution and refresh rate in effect and whether the display is in HDR.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 48)]
public unsafe struct SceVideoOutOutputStatus
{
    /// <summary>The resolution token in effect.</summary>
    public uint Resolution;

    /// <summary>The dynamic range in effect: 0 unknown, 1 SDR, 2 HDR.</summary>
    public uint DynamicRange;

    /// <summary>The refresh rate in effect.</summary>
    public ulong RefreshRate;

    /// <summary>Status flags; bit 0 set means the output is in HDR.</summary>
    public ulong Flags;

    private fixed ulong _reserved[3];
}

/// <summary>
/// A gamma color-adjustment block for an output. Set the gamma with
/// <see cref="VideoOut.ColorSettingsSetGamma"/>, then apply it with <see cref="VideoOut.AdjustColor"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceVideoOutColorSettings
{
    /// <summary>The gamma for the red, green and blue channels.</summary>
    public fixed float Gamma[3];

    /// <summary>Option flags.</summary>
    public uint Option;
}

/// <summary>
/// An SDR-to-HDR color-space conversion block for an output. Configure it with the conversion setters,
/// then apply it with <see cref="VideoOut.AdjustColorSpaceConversion"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceVideoOutColorSpaceConversionSettings
{
    private fixed uint _param[8];
}

/// <summary>
/// The parameter block <see cref="VideoOut.sceVideoOutOpen"/> accepts when a caller opens the primary
/// (main) output. It sets the service thread's priority and CPU affinity for that handle; zeroing the
/// two "set" flags leaves the service defaults in place.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 88)]
public unsafe struct SceVideoOutParamPrimary
{
    /// <summary>Must be <see cref="VideoOutLimits.ParamPrimaryVersion"/>. First field per the block's contract.</summary>
    public uint ParamVersion;

    /// <summary>Nonzero applies <see cref="ServiceThreadPriority"/>; zero leaves the default in place.</summary>
    public int SetServiceThreadPriority;

    /// <summary>The service thread's scheduling priority.</summary>
    public int ServiceThreadPriority;

    /// <summary>Nonzero applies <see cref="ServiceThreadAffinityMask"/>; zero leaves the default in place.</summary>
    public int SetServiceThreadAffinityMask;

    /// <summary>The service thread's CPU affinity mask, as passed to <see cref="Kernel.SceKernelCpumask"/>.</summary>
    public ulong ServiceThreadAffinityMask;

    private fixed ulong _reserved[8];
}

/// <summary>
/// The parameter block <see cref="VideoOut.sceVideoOutOpen"/> accepts when a caller opens the
/// flat-panel-display output. It sets the service thread's priority and CPU affinity for that handle.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceVideoOutParamFpd
{
    /// <summary>Must be <see cref="VideoOutLimits.ParamFpdVersion"/>. First field per the block's contract.</summary>
    public uint ParamVersion;

    /// <summary>The service thread's scheduling priority.</summary>
    public int ThreadPriority;

    /// <summary>The service thread's CPU affinity mask, as passed to <see cref="Kernel.SceKernelCpumask"/>.</summary>
    public ulong ThreadAffinityMask;

    private fixed int _reserved[4];
}
