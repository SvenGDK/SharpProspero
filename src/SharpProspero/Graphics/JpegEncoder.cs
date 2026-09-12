// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Image;
using SharpProspero.Storage;
using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// How a JPEG stores color. A color image keeps luminance at full resolution and stores the two chroma
/// channels at a chosen resolution: dropping chroma resolution shrinks the file with little visible loss
/// on photographs, which is why cameras favor it. Grayscale keeps only the luminance channel. The color
/// modes name the sampling ratio the way the format writes it in the frame header, luminance to chroma
/// horizontally to chroma vertically. The encoder subsamples chroma either two-to-one horizontally
/// (4:2:2) or in both directions (4:2:0); it has no full-chroma color mode.
/// </summary>
public enum JpegSampling
{
    /// <summary>Chroma at half the horizontal resolution (4:2:2).</summary>
    Ycc422,

    /// <summary>Chroma at half the horizontal and vertical resolution (4:2:0): the smallest color file, and the default.</summary>
    Ycc420,

    /// <summary>A single luminance channel with no color, computed from the surface pixels.</summary>
    Grayscale,
}

/// <summary>
/// Encodes a drawing surface to JPEG bytes, for a screenshot or a photo export. JPEG is far smaller
/// than PNG for photographic content, which makes it the format for capture and thumbnails. The surface
/// is the display's B8-G8-R8-A8 format, so a framebuffer encodes directly. Load the JPEG-encode module
/// (<c>SystemModule.Load(SystemModuleId.JpegEnc)</c>) before encoding.
/// </summary>
public static unsafe class JpegEncoder
{
    /// <summary>
    /// Encodes <paramref name="surface"/> to the bytes of a JPEG file.
    /// </summary>
    /// <param name="surface">The pixels to encode, in the display's B8-G8-R8-A8 format.</param>
    /// <param name="quality">Picture quality, 1 (smallest) to 100 (best). Default 90.</param>
    /// <param name="sampling">
    /// How color is stored: full, half, or quarter chroma resolution, or a single grayscale channel.
    /// Defaults to 4:2:0, the smallest color output.
    /// </param>
    /// <exception cref="ProsperoException">Sizing, creating the encoder, or encoding failed.</exception>
    public static byte[] Encode(Surface surface, int quality = 90, JpegSampling sampling = JpegSampling.Ycc420)
    {
        if (surface.Width <= 0 || surface.Height <= 0)
            throw new ArgumentException("The surface has no pixels to encode.", nameof(surface));

        // Map the friendly 1..100 quality to the encoder's inverted 0..255 ratio, where zero is best.
        int level = Math.Clamp(quality, 1, 100);
        byte compressionRatio = (byte)((100 - level) * 255 / 100);

        (JpegEncColorSpace colorSpace, JpegEncSamplingType samplingType, JpegEncPixelFormat pixelFormat) = ResolveFormat(sampling);
        bool grayscale = colorSpace == JpegEncColorSpace.Grayscale;

        var create = new SceJpegEncCreateParam { ThisSize = (uint)sizeof(SceJpegEncCreateParam), Attribute = 0 };
        int workSize = JpegEnc.sceJpegEncQueryMemorySize(&create);
        SceResult.ThrowIfFailed(workSize, nameof(JpegEnc.sceJpegEncQueryMemorySize));

        // The source rows step by the row pitch in bytes: one byte per pixel for a grayscale channel,
        // or the surface stride in four-byte pixels for color. The buffer spans every row. Compute in
        // 64-bit so the products are exact and cannot wrap the size check.
        ulong pitch = grayscale ? (ulong)surface.Width : (ulong)surface.Stride * 4;
        ulong imageBytes = pitch * (ulong)surface.Height;
        // A generous upper bound for the output: at the highest quality a JPEG can approach its source
        // size, so the buffer is sized above it with room for the container.
        ulong jpegCapacity = imageBytes + (imageBytes >> 1) + 0x10000;
        if (imageBytes > uint.MaxValue || jpegCapacity > uint.MaxValue)
            throw new ProsperoException("The image is too large to encode.", unchecked((int)0x80650102));

        void* work = NativeMemory.Alloc((nuint)workSize);
        void* handle = null;
        void* jpegBuffer = null;
        // A grayscale encode needs a single-channel source, so the luminance of each surface pixel is
        // gathered into a packed buffer the encoder reads; a color encode reads the surface directly.
        void* grayBuffer = null;
        try
        {
            SceResult.ThrowIfFailed(JpegEnc.sceJpegEncCreate(&create, work, (uint)workSize, &handle), nameof(JpegEnc.sceJpegEncCreate));

            void* source;
            if (grayscale)
            {
                grayBuffer = NativeMemory.Alloc((nuint)imageBytes);
                WriteLuminance(surface, (byte*)grayBuffer);
                source = grayBuffer;
            }
            else
            {
                source = surface.Pixels;
            }

            jpegBuffer = NativeMemory.Alloc((nuint)jpegCapacity);
            var encode = new SceJpegEncEncodeParam
            {
                ImageMemAddr = source,
                JpegMemAddr = jpegBuffer,
                ImageMemSize = (uint)imageBytes,
                JpegMemSize = (uint)jpegCapacity,
                ImageWidth = (uint)surface.Width,
                ImageHeight = (uint)surface.Height,
                ImagePitch = (uint)pitch,
                PixelFormat = (ushort)pixelFormat,
                EncodeMode = (ushort)JpegEncMode.Normal,
                ColorSpace = (ushort)colorSpace,
                SamplingType = (byte)samplingType,
                CompressionRatio = compressionRatio,
                RestartInterval = 0,
            };
            SceJpegEncOutputInfo info = default;
            SceResult.ThrowIfFailed(JpegEnc.sceJpegEncEncode(handle, &encode, &info), nameof(JpegEnc.sceJpegEncEncode));

            var output = new byte[info.DataSize];
            new ReadOnlySpan<byte>(jpegBuffer, (int)info.DataSize).CopyTo(output);
            return output;
        }
        finally
        {
            if (grayBuffer != null)
                NativeMemory.Free(grayBuffer);
            if (jpegBuffer != null)
                NativeMemory.Free(jpegBuffer);
            if (handle != null)
                JpegEnc.sceJpegEncDelete(handle);
            NativeMemory.Free(work);
        }
    }

    /// <summary>
    /// Encodes <paramref name="surface"/> and writes it to the file at <paramref name="path"/>, for
    /// saving a screenshot (for example <c>/data/screenshot.jpg</c>).
    /// </summary>
    /// <exception cref="ProsperoException">Encoding or writing the file failed.</exception>
    public static void Save(Surface surface, string path, int quality = 90, JpegSampling sampling = JpegSampling.Ycc420)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        FileSystem.WriteAllBytes(path, Encode(surface, quality, sampling));
    }

    /// <summary>
    /// Resolves a <see cref="JpegSampling"/> mode to the encoder's color space, chroma sampling factor,
    /// and source pixel layout. The color modes keep the surface's B8-G8-R8-A8 layout and set the
    /// sampling factor; grayscale writes a single luminance channel and always uses full sampling, since
    /// a lone channel has no chroma to reduce.
    /// </summary>
    internal static (JpegEncColorSpace ColorSpace, JpegEncSamplingType Sampling, JpegEncPixelFormat PixelFormat) ResolveFormat(JpegSampling sampling)
        => sampling switch
        {
            JpegSampling.Ycc422 => (JpegEncColorSpace.Ycc, JpegEncSamplingType.Sub422, JpegEncPixelFormat.Bgra8),
            JpegSampling.Ycc420 => (JpegEncColorSpace.Ycc, JpegEncSamplingType.Sub420, JpegEncPixelFormat.Bgra8),
            JpegSampling.Grayscale => (JpegEncColorSpace.Grayscale, JpegEncSamplingType.Full, JpegEncPixelFormat.Gray8),
            _ => (JpegEncColorSpace.Ycc, JpegEncSamplingType.Sub420, JpegEncPixelFormat.Bgra8),
        };

    /// <summary>
    /// The luminance of a B8-G8-R8-A8 pixel, the standard weighted sum of its red, green and blue that
    /// forms the luminance channel of a color JPEG. Fixed-point weights sum to exactly one, so pure
    /// white maps to 255 and pure black to 0.
    /// </summary>
    internal static byte Luminance(uint bgra)
    {
        uint r = (bgra >> 16) & 0xFF;
        uint g = (bgra >> 8) & 0xFF;
        uint b = bgra & 0xFF;
        return (byte)((19595 * r + 38470 * g + 7471 * b + 32768) >> 16);
    }

    /// <summary>
    /// Writes the luminance of each surface pixel into <paramref name="destination"/>, a packed buffer
    /// of one byte per pixel with rows the surface width apart and no padding.
    /// </summary>
    private static void WriteLuminance(Surface surface, byte* destination)
    {
        uint* pixels = surface.Pixels;
        int width = surface.Width;
        int height = surface.Height;
        int stride = surface.Stride;
        for (int y = 0; y < height; y++)
        {
            uint* sourceRow = pixels + (long)y * stride;
            byte* destinationRow = destination + (long)y * width;
            for (int x = 0; x < width; x++)
                destinationRow[x] = Luminance(sourceRow[x]);
        }
    }
}
