// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics.Agc;

/// <summary>How a texture coordinate outside 0..1 is handled, from <see cref="AgcSamplerDescriptor.SetAddressModes"/>.</summary>
public enum AgcAddressMode : uint
{
    /// <summary>Repeat the texture (the fractional part of the coordinate).</summary>
    Wrap = 0,
    /// <summary>Repeat, mirroring every other tile.</summary>
    Mirror = 1,
    /// <summary>Clamp to the edge texel.</summary>
    ClampToEdge = 2,
    /// <summary>Mirror once, then clamp to the edge texel.</summary>
    MirrorOnceToEdge = 3,
    /// <summary>Clamp to halfway into the border.</summary>
    ClampHalfBorder = 4,
    /// <summary>Mirror once, then clamp halfway into the border.</summary>
    MirrorOnceHalfBorder = 5,
    /// <summary>Clamp to the border color.</summary>
    ClampToBorder = 6,
    /// <summary>Mirror once, then clamp to the border color.</summary>
    MirrorOnceToBorder = 7,
}

/// <summary>The minification or magnification filter, from <see cref="AgcSamplerDescriptor.SetFilter"/>.</summary>
public enum AgcFilter : uint
{
    /// <summary>Nearest texel.</summary>
    Point = 0,
    /// <summary>Linear blend of the four nearest texels.</summary>
    Bilinear = 1,
    /// <summary>Nearest, with anisotropy.</summary>
    AnisotropicPoint = 2,
    /// <summary>Linear, with anisotropy.</summary>
    AnisotropicBilinear = 3,
}

/// <summary>How mip levels are blended, from <see cref="AgcSamplerDescriptor.SetFilter"/>.</summary>
public enum AgcMipFilter : uint
{
    /// <summary>Sample only the base level.</summary>
    None = 0,
    /// <summary>Pick the nearest mip level.</summary>
    Point = 1,
    /// <summary>Blend the two nearest mip levels.</summary>
    Linear = 2,
}

/// <summary>How the slices of a volume texture are blended, from <see cref="AgcSamplerDescriptor.SetZFilter"/>.</summary>
public enum AgcZFilter : uint
{
    /// <summary>Do not sample across slices.</summary>
    None = 0,
    /// <summary>Sample the nearest slice.</summary>
    Point = 1,
    /// <summary>Blend the two nearest slices.</summary>
    Linear = 2,
}

/// <summary>How the sampled texels are reduced to one value, from <see cref="AgcSamplerDescriptor.SetFilterReductionMode"/>.</summary>
public enum AgcFilterReductionMode : uint
{
    /// <summary>The weighted average of the texels (the usual filtering).</summary>
    WeightedAverage = 0,
    /// <summary>The minimum texel value per channel.</summary>
    Min = 1,
    /// <summary>The maximum texel value per channel.</summary>
    Max = 2,
}

/// <summary>The comparison a shadow (depth-compare) sampler applies, from <see cref="AgcSamplerDescriptor.SetDepthCompare"/>.</summary>
public enum AgcDepthCompare : uint
{
    /// <summary>Never passes.</summary>
    Never = 0,
    /// <summary>Passes when the reference is less than the texel.</summary>
    Less = 1,
    /// <summary>Passes when equal.</summary>
    Equal = 2,
    /// <summary>Passes when less than or equal.</summary>
    LessEqual = 3,
    /// <summary>Passes when greater than.</summary>
    Greater = 4,
    /// <summary>Passes when not equal.</summary>
    NotEqual = 5,
    /// <summary>Passes when greater than or equal.</summary>
    GreaterEqual = 6,
    /// <summary>Always passes.</summary>
    Always = 7,
}

/// <summary>The color used outside a texture when the address mode clamps to a border.</summary>
public enum AgcBorderColor : uint
{
    /// <summary>Transparent black (0, 0, 0, 0).</summary>
    TransparentBlack = 0,
    /// <summary>Opaque black (0, 0, 0, 1).</summary>
    OpaqueBlack = 1,
    /// <summary>Opaque white (1, 1, 1, 1).</summary>
    OpaqueWhite = 2,
    /// <summary>A color from the border-color table, selected by an index and a table pointer set separately.</summary>
    FromTable = 3,
}

/// <summary>
/// The four-word hardware descriptor a shader reads to filter a texture (an "S#"): how coordinates wrap,
/// which filters apply for magnification, minification, mip levels and volume slices, the level-of-detail
/// range and bias, anisotropy, an optional depth comparison for shadows, and the border color. Build one
/// with <see cref="Create"/>, set what differs from the defaults, write its words with <see cref="WriteTo"/>
/// into GPU-readable memory, and point a shader sampler slot at it. Every setter packs its field into the
/// exact bits the graphics processor reads.
/// </summary>
/// <remarks>
/// The level-of-detail values are fixed-point: the range clamps are unsigned 4.8, the bias is signed 6.8,
/// and the secondary bias is signed 2.4, which the float setters convert for you. This is a value type;
/// copy it where the shader can reach it. Prefer <see cref="Create"/> over <c>default</c>: the created
/// descriptor uses the same starting state the hardware layer does (full mip range, point mip and slice
/// filtering), whereas an all-zero descriptor clamps to the base mip and never samples slices.
/// </remarks>
public struct AgcSamplerDescriptor
{
    private uint _w0, _w1, _w2, _w3;

    /// <summary>The number of 32-bit words in the descriptor.</summary>
    public const int WordCount = 4;

    /// <summary>
    /// A descriptor in the standard starting state: coordinates wrap, magnification and minification
    /// point-sample, the full mip range is available, and mip and slice sampling are point. Adjust from
    /// here with the setters.
    /// </summary>
    public static AgcSamplerDescriptor Create()
    {
        var s = default(AgcSamplerDescriptor);
        Set(ref s._w1, 12, 12, 4095);              // maxLod = 4095 (the top of the 4.8 range)
        Set(ref s._w2, 24, 2, (uint)AgcZFilter.Point);
        Set(ref s._w2, 26, 2, (uint)AgcMipFilter.Point);
        return s;
    }

    private static void Set(ref uint word, int offset, int width, uint value)
    {
        uint mask = width == 32 ? 0xFFFFFFFFu : ((1u << width) - 1) << offset;
        word = (word & ~mask) | ((value << offset) & mask);
    }

    /// <summary>The word at <paramref name="index"/> (0 to 3).</summary>
    public readonly uint this[int index] => index switch
    {
        0 => _w0,
        1 => _w1,
        2 => _w2,
        3 => _w3,
        _ => throw new ArgumentOutOfRangeException(nameof(index)),
    };

    /// <summary>Writes the four words into <paramref name="destination"/>, which must hold at least four.</summary>
    public readonly void WriteTo(Span<uint> destination)
    {
        if (destination.Length < WordCount)
            throw new ArgumentException($"A sampler descriptor needs {WordCount} words.", nameof(destination));
        destination[0] = _w0; destination[1] = _w1; destination[2] = _w2; destination[3] = _w3;
    }

    /// <summary>How coordinates outside 0..1 wrap on each of the three axes.</summary>
    public void SetAddressModes(AgcAddressMode x, AgcAddressMode y, AgcAddressMode z)
    {
        Set(ref _w0, 0, 3, (uint)x);
        Set(ref _w0, 3, 3, (uint)y);
        Set(ref _w0, 6, 3, (uint)z);
    }

    /// <summary>The magnification, minification and mip filters.</summary>
    public void SetFilter(AgcFilter magnification, AgcFilter minification, AgcMipFilter mip)
    {
        Set(ref _w2, 20, 2, (uint)magnification);
        Set(ref _w2, 22, 2, (uint)minification);
        Set(ref _w2, 26, 2, (uint)mip);
    }

    /// <summary>How the slices of a volume (3D) texture are blended.</summary>
    public void SetZFilter(AgcZFilter filter) => Set(ref _w2, 24, 2, (uint)filter);

    /// <summary>How the sampled texels are reduced to one value (average, minimum or maximum).</summary>
    public void SetFilterReductionMode(AgcFilterReductionMode mode) => Set(ref _w0, 29, 2, (uint)mode);

    /// <summary>
    /// The maximum anisotropy ratio: 0 = 1x, 1 = 2x, 2 = 4x, 3 = 8x, 4 = 16x. Higher values are invalid.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="ratio"/> is outside 0 to 4.</exception>
    public void SetMaxAnisotropy(int ratio)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(ratio);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(ratio, 4);
        Set(ref _w0, 9, 3, (uint)ratio);
    }

    /// <summary>The anisotropy threshold, a raw 3-bit tuning value (0 to 7).</summary>
    public void SetAnisotropyThreshold(int threshold) => Set(ref _w0, 16, 3, (uint)threshold & 0x7u);

    /// <summary>The anisotropy bias, as unsigned 1.5 fixed-point (0 to just under 2).</summary>
    public void SetAnisotropyBias(float bias) => Set(ref _w0, 21, 6, ToUFixed1_5(bias));

    /// <summary>Whether to override the automatic anisotropy decision and always apply it.</summary>
    public void SetAnisotropyOverride(bool enable) => Set(ref _w2, 29, 1, enable ? 1u : 0u);

    /// <summary>The depth-compare function for a shadow sampler.</summary>
    public void SetDepthCompare(AgcDepthCompare compare) => Set(ref _w0, 12, 3, (uint)compare);

    /// <summary>The lowest and highest mip level the sampler reads, as unsigned 4.8 fixed-point.</summary>
    public void SetLodRange(float minLod, float maxLod)
    {
        Set(ref _w1, 0, 12, ToUFixed4_8(minLod));
        Set(ref _w1, 12, 12, ToUFixed4_8(maxLod));
    }

    /// <summary>The level-of-detail bias, as signed 6.8 fixed-point (range -32 to just under 32).</summary>
    public void SetLodBias(float bias) => Set(ref _w2, 0, 14, ToSFixed6_8(bias));

    /// <summary>The secondary level-of-detail bias, as signed 2.4 fixed-point (range -2 to just under 2).</summary>
    public void SetLodBiasSecondary(float bias) => Set(ref _w2, 14, 6, ToSFixed2_4(bias));

    /// <summary>The size of the mip clamp region, a raw 4-bit value (0 to 15).</summary>
    public void SetMipClampRegionSize(int size) => Set(ref _w1, 24, 4, (uint)size & 0xFu);

    /// <summary>The size of the slice clamp region, a raw 4-bit value (0 to 15).</summary>
    public void SetZClampRegionSize(int size) => Set(ref _w1, 28, 4, (uint)size & 0xFu);

    /// <summary>Whether to force unnormalized texture coordinates (texel-space rather than 0..1).</summary>
    public void SetForceUnnormalizedCoordinates(bool force) => Set(ref _w0, 15, 1, force ? 1u : 0u);

    /// <summary>Whether to apply sRGB-to-linear conversion before filtering, when the format allows it.</summary>
    public void SetForceSrgb(bool enable) => Set(ref _w0, 20, 1, enable ? 1u : 0u);

    /// <summary>Whether to disable the sRGB-to-linear conversion the texture descriptor would otherwise apply.</summary>
    public void SetDisableDegamma(bool disable) => Set(ref _w0, 31, 1, disable ? 1u : 0u);

    /// <summary>Whether point sampling truncates rather than rounding to nearest-even.</summary>
    public void SetCoordinateRoundingTruncate(bool truncate) => Set(ref _w0, 27, 1, truncate ? 1u : 0u);

    /// <summary>Whether to disable seamless cubemap filtering so the wrap modes apply to cubemaps.</summary>
    public void SetDisableSeamlessCube(bool disable) => Set(ref _w0, 28, 1, disable ? 1u : 0u);

    /// <summary>Whether the mip-point filter pre-clamps the level of detail.</summary>
    public void SetMipPointFilterPreclamp(bool enable) => Set(ref _w2, 28, 1, enable ? 1u : 0u);

    /// <summary>The border color used when an address mode clamps to a border.</summary>
    public void SetBorderColor(AgcBorderColor color) => Set(ref _w3, 30, 2, (uint)color);

    /// <summary>The index into the border-color table, used with <see cref="AgcBorderColor.FromTable"/>.</summary>
    public void SetBorderColorTableIndex(int index) => Set(ref _w3, 0, 12, (uint)index & 0xFFFu);

    // Converts a level of detail to unsigned 4.8 fixed-point, clamped to the 12-bit range. The scaled
    // value is truncated toward zero, matching the fixed-point conversion the hardware layer performs.
    private static uint ToUFixed4_8(float value)
    {
        float clamped = Math.Clamp(value, 0f, 4095f / 256f);
        return (uint)(clamped * 256f) & 0xFFFu;
    }

    // Converts an anisotropy bias to unsigned 1.5 fixed-point, clamped to the 6-bit range.
    private static uint ToUFixed1_5(float value)
    {
        float clamped = Math.Clamp(value, 0f, 63f / 32f);
        return (uint)(clamped * 32f) & 0x3Fu;
    }

    // Converts a bias to signed 6.8 fixed-point, clamped to the 14-bit two's-complement range.
    private static uint ToSFixed6_8(float value)
    {
        float clamped = Math.Clamp(value, -32f, 8191f / 256f);
        return (uint)(int)(clamped * 256f) & 0x3FFFu;
    }

    // Converts a secondary bias to signed 2.4 fixed-point, clamped to the 6-bit two's-complement range.
    private static uint ToSFixed2_4(float value)
    {
        float clamped = Math.Clamp(value, -2f, 31f / 16f);
        return (uint)(int)(clamped * 16f) & 0x3Fu;
    }
}
