// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.VideoOut;

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

/// <summary>Pixel formats accepted by the buffer attribute setter. Values are opaque tokens.</summary>
public static class VideoOutPixelFormat
{
    /// <summary>32-bit RGBA, sRGB transfer.</summary>
    public const ulong Rgba8Srgb = 0x8000000022000000UL;

    /// <summary>32-bit BGRA, sRGB transfer. The layout used by the CPU renderer in this SDK.</summary>
    public const ulong Bgra8Srgb = 0x8000000000000000UL;

    /// <summary>10-bit RGB with 2-bit alpha.</summary>
    public const ulong Rgb10A2 = 0x8100000622000000UL;

    /// <summary>16-bit-per-channel float RGBA.</summary>
    public const ulong Rgba16Float = 0xC001000622000000UL;
}

/// <summary>Options for the buffer attribute setter.</summary>
public static class VideoOutBufferAttributeOption
{
    /// <summary>No options.</summary>
    public const ulong None = 0;
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
