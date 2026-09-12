// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics.Agc;

/// <summary>The shape a texture presents to a shader, from <see cref="AgcTextureDescriptor.SetType"/>.</summary>
public enum AgcImageType : uint
{
    /// <summary>A one-dimensional texture.</summary>
    Texture1D = 8,
    /// <summary>A two-dimensional texture.</summary>
    Texture2D = 9,
    /// <summary>A three-dimensional (volume) texture.</summary>
    Texture3D = 10,
    /// <summary>A cube map (six faces).</summary>
    Cubemap = 11,
    /// <summary>An array of one-dimensional textures.</summary>
    Texture1DArray = 12,
    /// <summary>An array of two-dimensional textures.</summary>
    Texture2DArray = 13,
    /// <summary>A multisampled two-dimensional texture.</summary>
    Texture2DMultisample = 14,
    /// <summary>An array of multisampled two-dimensional textures.</summary>
    Texture2DArrayMultisample = 15,
}

/// <summary>Which source channel feeds an output channel, from <see cref="AgcTextureDescriptor.SetChannelOrder"/>.</summary>
public enum AgcChannelSource : uint
{
    /// <summary>A constant zero.</summary>
    Zero = 0,
    /// <summary>A constant one.</summary>
    One = 1,
    /// <summary>The red (first) channel.</summary>
    Red = 4,
    /// <summary>The green (second) channel.</summary>
    Green = 5,
    /// <summary>The blue (third) channel.</summary>
    Blue = 6,
    /// <summary>The alpha (fourth) channel.</summary>
    Alpha = 7,
}

/// <summary>
/// The eight-word hardware descriptor a shader reads to sample a texture (a "T#"): where the pixels are,
/// how big the surface is, its format, how its channels map to red-green-blue-alpha, and the mip and
/// array ranges. Build one for an image already laid out in tiled memory (by the host texture tool or by
/// <see cref="AgcTiler"/>), write its words with <see cref="WriteTo"/> into GPU-readable memory, and point
/// a shader resource slot at it. The bit layout is the graphics-processor image-resource format; the
/// setters pack each field into the exact bits the hardware reads.
/// </summary>
/// <remarks>
/// A descriptor addresses memory in 256-byte units, so the base address and the metadata address are the
/// byte address shifted right by eight. This is a value type; copy it where the shader can reach it.
/// </remarks>
public struct AgcTextureDescriptor
{
    private uint _w0, _w1, _w2, _w3, _w4, _w5, _w6, _w7;

    /// <summary>The number of 32-bit words in the descriptor.</summary>
    public const int WordCount = 8;

    private static void Set(ref uint word, int offset, int width, uint value)
    {
        uint mask = width == 32 ? 0xFFFFFFFFu : ((1u << width) - 1) << offset;
        word = (word & ~mask) | ((value << offset) & mask);
    }

    /// <summary>The word at <paramref name="index"/> (0 to 7).</summary>
    public readonly uint this[int index] => index switch
    {
        0 => _w0,
        1 => _w1,
        2 => _w2,
        3 => _w3,
        4 => _w4,
        5 => _w5,
        6 => _w6,
        7 => _w7,
        _ => throw new ArgumentOutOfRangeException(nameof(index)),
    };

    /// <summary>Writes the eight words into <paramref name="destination"/>, which must hold at least eight.</summary>
    public readonly void WriteTo(Span<uint> destination)
    {
        if (destination.Length < WordCount)
            throw new ArgumentException($"A texture descriptor needs {WordCount} words.", nameof(destination));
        destination[0] = _w0; destination[1] = _w1; destination[2] = _w2; destination[3] = _w3;
        destination[4] = _w4; destination[5] = _w5; destination[6] = _w6; destination[7] = _w7;
    }

    /// <summary>The base GPU byte address of the pixels. Stored as the address in 256-byte units.</summary>
    public void SetBaseAddress(ulong gpuByteAddress)
    {
        ulong units = gpuByteAddress >> 8;
        _w0 = (uint)units;
        Set(ref _w1, 0, 8, (uint)(units >> 32) & 0xFFu); // the eight high address bits
    }

    /// <summary>
    /// The pixel format: a nine-bit typed-format value that names the element size, channel layout, and
    /// how the channels are read (for example 56 for four 8-bit unsigned-normalized channels, 130 for the
    /// sRGB variant; see <see cref="AgcFormats.TypedFormat"/>).
    /// </summary>
    public void SetFormat(uint typedFormat) => Set(ref _w1, 20, 9, typedFormat & 0x1FFu);

    /// <summary>The surface width and height in texels (each at most 16384).</summary>
    public void SetDimensions(int width, int height)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(width, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(height, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(width, 16384);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(height, 16384);
        // Width less one is split: the low two bits sit at the top of the first word, the high twelve at
        // the start of the second. Height less one is the fourteen bits above the reserved pair.
        uint widthMinusOne = (uint)(width - 1);
        Set(ref _w1, 30, 2, widthMinusOne & 0x3u);
        Set(ref _w2, 0, 12, widthMinusOne >> 2);
        Set(ref _w2, 14, 14, (uint)(height - 1));
    }

    /// <summary>The depth of a volume texture, or the slice count of an array (at most 8192).</summary>
    public void SetDepthOrSlices(int depthOrSlices)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(depthOrSlices, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(depthOrSlices, 8192);
        Set(ref _w4, 0, 13, (uint)(depthOrSlices - 1));
    }

    /// <summary>Which source channel feeds each of the four output channels.</summary>
    public void SetChannelOrder(AgcChannelSource x, AgcChannelSource y, AgcChannelSource z, AgcChannelSource w)
    {
        Set(ref _w3, 0, 3, (uint)x);
        Set(ref _w3, 3, 3, (uint)y);
        Set(ref _w3, 6, 3, (uint)z);
        Set(ref _w3, 9, 3, (uint)w);
    }

    /// <summary>The lowest and highest mip level the shader may sample.</summary>
    public void SetMipRange(int baseLevel, int lastLevel)
    {
        Set(ref _w3, 12, 4, (uint)baseLevel);
        Set(ref _w3, 16, 4, (uint)lastLevel);
    }

    /// <summary>
    /// How many mip levels the surface holds, from one to fifteen. This is what tells the processor how
    /// far the chain runs; the range above only narrows which of them a shader may sample. Left unset
    /// the surface reads as holding one level, so the address of every level below the first is wrong.
    /// Not for a multi-sampled surface, which uses <see cref="SetFragmentCount"/> instead.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="levelCount"/> is outside one to fifteen.</exception>
    public void SetMipLevelCount(int levelCount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(levelCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(levelCount, 15);
        Set(ref _w5, 4, 4, (uint)(levelCount - 1));
    }

    /// <summary>
    /// How many samples each texel of a multi-sampled surface holds, as the power of two: one for two
    /// samples, two for four, three for eight. The count goes in the place the chain length occupies
    /// for an ordinary surface and in the last-level field as well, which is what a multi-sampled
    /// surface reads instead of a mip chain.
    /// </summary>
    public void SetFragmentCount(int log2Samples)
    {
        Set(ref _w3, 16, 4, (uint)log2Samples);
        Set(ref _w5, 4, 4, (uint)log2Samples);
    }

    /// <summary>The first and last array slice the shader may sample.</summary>
    public void SetArrayRange(int baseSlice, int lastSlice)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(baseSlice);
        ArgumentOutOfRangeException.ThrowIfNegative(lastSlice);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(baseSlice, 8191);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(lastSlice, 8191);
        // The base slice sits in the upper half of the depth word; the last slice shares the depth field.
        Set(ref _w4, 16, 13, (uint)baseSlice);
        Set(ref _w4, 0, 13, (uint)lastSlice);
    }

    /// <summary>The tiling (swizzle) mode index the surface was laid out with.</summary>
    public void SetTilingIndex(int tilingIndex) => Set(ref _w3, 20, 5, (uint)tilingIndex);

    /// <summary>The texture's dimensionality.</summary>
    public void SetType(AgcImageType type) => Set(ref _w3, 28, 4, (uint)type);

    /// <summary>
    /// The base address of the compression surface, which has to be a multiple of 256 bytes. The
    /// address is split: its lowest byte above those 256 goes in the top byte of word six and the rest
    /// in word seven. Putting the whole thing in word seven made the address 256 times too large.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="gpuByteAddress"/> is not a multiple of 256.</exception>
    public void SetMetadataAddress(ulong gpuByteAddress)
    {
        if ((gpuByteAddress & 0xFF) != 0)
            throw new ArgumentException("The compression surface starts on a 256-byte boundary.", nameof(gpuByteAddress));
        Set(ref _w6, 24, 8, (uint)((gpuByteAddress >> 8) & 0xFF));
        _w7 = (uint)(gpuByteAddress >> 16);
    }

    /// <summary>The base address of the compression surface, as written.</summary>
    public readonly ulong MetadataAddress => (((ulong)(_w6 >> 24) & 0xFF) << 8) | ((ulong)_w7 << 16);

    /// <summary>Whether the surface carries compression metadata.</summary>
    public void SetMetadataEnabled(bool enabled) => Set(ref _w6, 21, 1, enabled ? 1u : 0u);

    /// <summary>
    /// The minimum level-of-detail clamp, applied after the sampler's own clamp, as unsigned 4.8
    /// fixed-point (0 to just under 16). It stops the shader from sampling below this level.
    /// </summary>
    public void SetMinLodClamp(float minLod) => Set(ref _w1, 8, 12, ToUFixed4_8(minLod));

    /// <summary>Which source channels feed the border-color lookup, as a raw three-bit swizzle value (0 to 7).</summary>
    public void SetBorderColorTableSwizzle(int swizzle) => Set(ref _w3, 25, 3, (uint)swizzle & 0x7u);

    /// <summary>Whether this is the depth plane of a multi-sampled depth texture, so it aliases correctly.</summary>
    public void SetMsaaDepthTexture(bool enabled) => Set(ref _w6, 10, 1, enabled ? 1u : 0u);

    /// <summary>The largest block the compressor may leave uncompressed, as a raw two-bit value (0 to 3).</summary>
    public void SetDccMaxUncompressedBlockSize(int size) => Set(ref _w6, 15, 2, (uint)size & 0x3u);

    /// <summary>The largest block the compressor may produce, as a raw two-bit value (0 to 3).</summary>
    public void SetDccMaxCompressedBlockSize(int size) => Set(ref _w6, 17, 2, (uint)size & 0x3u);

    /// <summary>Whether the compression metadata is aligned to the memory pipes.</summary>
    public void SetMetadataPipeAlignment(bool enabled) => Set(ref _w6, 19, 1, enabled ? 1u : 0u);

    /// <summary>Whether the compressor re-compresses on write.</summary>
    public void SetDccWriteRecompress(bool enabled) => Set(ref _w6, 20, 1, enabled ? 1u : 0u);

    /// <summary>Whether the alpha channel is placed at the most-significant position for compression.</summary>
    public void SetDccAlphaPosition(bool alphaOnMsb) => Set(ref _w6, 22, 1, alphaOnMsb ? 1u : 0u);

    /// <summary>Whether the compressor applies its color transform. The field is inverted: the value
    /// 0 applies the transform and 1 disables it, so the enabled flag maps to 0.</summary>
    public void SetDccColorTransform(bool enabled) => Set(ref _w6, 23, 1, enabled ? 0u : 1u);

    // Converts a level of detail to unsigned 4.8 fixed-point, clamped to the 12-bit range. The scaled
    // value is truncated toward zero, matching the fixed-point conversion the hardware layer performs.
    private static uint ToUFixed4_8(float value)
    {
        float clamped = Math.Clamp(value, 0f, 4095f / 256f);
        return (uint)(clamped * 256f) & 0xFFFu;
    }
}

