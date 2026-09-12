// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Storage;
using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// A decoded TGA (Targa) image held as B8-G8-R8-A8 pixels, the layout the display uses, so it blits
/// straight onto a framebuffer. TGA is a simple lossless format that tools and asset pipelines commonly
/// export, and unlike BMP it carries a proper alpha channel and an optional run-length compression.
/// Decode once, draw its <see cref="AsSurface"/> as often as needed, and dispose it to release the
/// pixels. It needs no system module.
/// </summary>
public sealed unsafe class TgaImage : IDisposable
{
    // Image families, taken from the low three bits of the image-type byte.
    private const int ColorMapped = 1;
    private const int TrueColor = 2;
    private const int Grayscale = 3;

    private void* _pixels;
    private bool _disposed;

    private TgaImage(void* pixels, int width, int height)
    {
        _pixels = pixels;
        Width = width;
        Height = height;
    }

    /// <summary>Width in pixels.</summary>
    public int Width { get; }

    /// <summary>Height in pixels.</summary>
    public int Height { get; }

    /// <summary>Views the decoded pixels as a drawing surface.</summary>
    public Surface AsSurface() => new((uint*)_pixels, Width, Height);

    /// <summary>Loads and decodes the TGA file at <paramref name="path"/>.</summary>
    /// <exception cref="ProsperoException">The file could not be read or is not a supported TGA.</exception>
    public static TgaImage Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return Decode(FileSystem.ReadAllBytes(path));
    }

    /// <summary>
    /// Decodes a TGA into a B8-G8-R8-A8 image. True-colour (15-, 16-, 24- or 32-bit), colour-mapped
    /// (indexed through the file's palette) and grayscale forms are all read, each either uncompressed
    /// or run-length encoded, with the origin in any corner.
    /// </summary>
    /// <exception cref="ProsperoException">The data is not a supported TGA.</exception>
    public static TgaImage Decode(ReadOnlySpan<byte> tga)
    {
        if (tga.Length < 18)
            throw new ProsperoException("Not a TGA file.", -1);

        int idLength = tga[0];
        int colorMapType = tga[1];
        int imageType = tga[2];
        // Colour-map specification (bytes 3-7): the index the first stored entry maps to, the number of
        // entries, and the bit width of one entry.
        int firstEntryIndex = tga[3] | (tga[4] << 8);
        int colorMapLength = tga[5] | (tga[6] << 8);
        int colorMapEntrySize = tga[7];
        int width = tga[12] | (tga[13] << 8);
        int height = tga[14] | (tga[15] << 8);
        int depth = tga[16];
        // Image-descriptor byte: bits 0-3 count the attribute (alpha) bits, bit 5 (0x20) puts the origin
        // at the top, bit 4 (0x10) at the right.
        int attributeBits = tga[17] & 0x0F;
        bool topToBottom = (tga[17] & 0x20) != 0;
        bool rightToLeft = (tga[17] & 0x10) != 0;

        // The image type names the family in its low three bits; adding 8 to a type marks it run-length
        // encoded. 1 is colour-mapped, 2 true-colour, 3 grayscale.
        bool rle;
        int kind;
        switch (imageType)
        {
            case 1: kind = ColorMapped; rle = false; break;
            case 2: kind = TrueColor; rle = false; break;
            case 3: kind = Grayscale; rle = false; break;
            case 9: kind = ColorMapped; rle = true; break;
            case 10: kind = TrueColor; rle = true; break;
            case 11: kind = Grayscale; rle = true; break;
            default:
                throw new ProsperoException("Unsupported TGA image type.", -1);
        }

        if (colorMapType != 0 && colorMapType != 1)
            throw new ProsperoException("Unsupported TGA colour-map type.", -1);
        if (kind == ColorMapped && colorMapType != 1)
            throw new ProsperoException("A colour-mapped TGA needs a colour map.", -1);
        if (width <= 0 || height <= 0)
            throw new ProsperoException("The TGA has no image.", -1);

        // The stream carries one sample per pixel; its width depends on the family. Colour-mapped samples
        // are the 8- or 16-bit palette index, grayscale samples are an 8-bit intensity (or 16-bit
        // intensity-plus-alpha), and true-colour samples are 15/16-, 24- or 32-bit colour.
        if (kind == ColorMapped && depth is not (8 or 16))
            throw new ProsperoException("Only 8- or 16-bit colour-mapped TGA is supported.", -1);
        if (kind == TrueColor && depth is not (15 or 16 or 24 or 32))
            throw new ProsperoException("Only 15-, 16-, 24- or 32-bit true-colour TGA is supported.", -1);
        if (kind == Grayscale && depth is not (8 or 16))
            throw new ProsperoException("Only 8- or 16-bit grayscale TGA is supported.", -1);

        int bytesPerPixel = (depth + 7) / 8;
        // The output is always four bytes per pixel; the pixel count is bounded by two 16-bit fields, so
        // the total fits comfortably in 64 bits. Keep it within a signed int so the pixel-count and
        // offset math in the decoders cannot overflow.
        ulong imageBytes = (ulong)width * 4 * (ulong)height;
        if (imageBytes > int.MaxValue)
            throw new ProsperoException("The TGA image is too large.", -1);
        if (18 + idLength > tga.Length)
            throw new ProsperoException("The TGA data is truncated.", -1);
        int offset = 18 + idLength;

        // A colour map, when present, follows the image-id field and precedes the pixel data. It is read
        // into a palette when the image indexes it, and skipped past otherwise.
        uint[]? palette = null;
        if (colorMapType == 1)
        {
            if (colorMapEntrySize is not (15 or 16 or 24 or 32))
                throw new ProsperoException("Unsupported TGA colour-map entry size.", -1);
            int entryBytes = (colorMapEntrySize + 7) / 8;
            // A 64-bit product so a crafted length cannot overflow the map-size check.
            long mapBytes = (long)colorMapLength * entryBytes;
            if (mapBytes > tga.Length - offset)
                throw new ProsperoException("The TGA colour map is truncated.", -1);
            if (kind == ColorMapped)
            {
                if (colorMapLength <= 0)
                    throw new ProsperoException("The TGA colour map is empty.", -1);
                ReadOnlySpan<byte> map = tga.Slice(offset, (int)mapBytes);
                bool entryAlpha = colorMapEntrySize == 16 && attributeBits > 0;
                palette = new uint[colorMapLength];
                for (int e = 0; e < colorMapLength; e++)
                {
                    int at = e * entryBytes;
                    palette[e] = colorMapEntrySize switch
                    {
                        24 => TrueColorSample(map, at, 3),
                        32 => TrueColorSample(map, at, 4),
                        _ => Unpack16(map[at] | (map[at + 1] << 8), entryAlpha),
                    };
                }
            }
            offset += (int)mapBytes;
        }

        var format = new Format(kind, bytesPerPixel, palette, firstEntryIndex, depth == 16 && attributeBits > 0);
        ReadOnlySpan<byte> data = tga[offset..];

        void* image = NativeMemory.Alloc((nuint)imageBytes);
        try
        {
            uint* pixels = (uint*)image;
            if (rle)
                DecodeRle(data, pixels, width, height, in format, topToBottom, rightToLeft);
            else
                DecodeRaw(data, pixels, width, height, in format, topToBottom, rightToLeft);
        }
        catch
        {
            NativeMemory.Free(image);
            throw;
        }

        return new TgaImage(image, width, height);
    }

    private static void DecodeRaw(ReadOnlySpan<byte> data, uint* pixels, int width, int height, in Format format, bool topToBottom, bool rightToLeft)
    {
        int count = width * height;
        if ((long)count * format.BytesPerPixel > data.Length)
            throw new ProsperoException("The TGA pixel data is truncated.", -1);
        for (int i = 0; i < count; i++)
            Store(pixels, i, Sample(data, i * format.BytesPerPixel, in format), width, height, topToBottom, rightToLeft);
    }

    private static void DecodeRle(ReadOnlySpan<byte> data, uint* pixels, int width, int height, in Format format, bool topToBottom, bool rightToLeft)
    {
        int bytesPerPixel = format.BytesPerPixel;
        int total = width * height;
        int produced = 0, position = 0;
        while (produced < total)
        {
            if (position >= data.Length)
                throw new ProsperoException("The TGA pixel data is truncated.", -1);
            byte packet = data[position++];
            int runLength = (packet & 0x7F) + 1;

            if ((packet & 0x80) != 0)
            {
                // A run packet: one sample repeated.
                if (data.Length - position < bytesPerPixel)
                    throw new ProsperoException("The TGA pixel data is truncated.", -1);
                uint value = Sample(data, position, in format);
                position += bytesPerPixel;
                for (int k = 0; k < runLength && produced < total; k++)
                    Store(pixels, produced++, value, width, height, topToBottom, rightToLeft);
            }
            else
            {
                // A raw packet: literal samples.
                for (int k = 0; k < runLength && produced < total; k++)
                {
                    if (data.Length - position < bytesPerPixel)
                        throw new ProsperoException("The TGA pixel data is truncated.", -1);
                    Store(pixels, produced++, Sample(data, position, in format), width, height, topToBottom, rightToLeft);
                    position += bytesPerPixel;
                }
            }
        }
    }

    // Turns one stream sample at <paramref name="offset"/> into a B8-G8-R8-A8 pixel.
    private static uint Sample(ReadOnlySpan<byte> data, int offset, in Format format)
    {
        switch (format.Kind)
        {
            case TrueColor:
                return format.BytesPerPixel switch
                {
                    2 => Unpack16(data[offset] | (data[offset + 1] << 8), format.Alpha16),
                    3 => TrueColorSample(data, offset, 3),
                    _ => TrueColorSample(data, offset, 4),
                };
            case Grayscale:
                {
                    // A single intensity fills all three colour channels; a 16-bit grayscale sample carries
                    // that intensity in its first byte and an alpha value in its second.
                    byte gray = data[offset];
                    byte a = format.BytesPerPixel == 2 ? data[offset + 1] : (byte)255;
                    return ((uint)a << 24) | ((uint)gray << 16) | ((uint)gray << 8) | gray;
                }
            default: // ColorMapped
                {
                    int index = format.BytesPerPixel == 2 ? (data[offset] | (data[offset + 1] << 8)) : data[offset];
                    uint[]? palette = format.Palette;
                    int entry = index - format.FirstEntryIndex;
                    if (palette is null || (uint)entry >= (uint)palette.Length)
                        throw new ProsperoException("The TGA colour index is out of range.", -1);
                    return palette[entry];
                }
        }
    }

    // A 24- or 32-bit true-colour sample stored blue, green, red, then an optional alpha byte; a 24-bit
    // sample is read fully opaque.
    private static uint TrueColorSample(ReadOnlySpan<byte> data, int offset, int bytesPerPixel)
    {
        byte b = data[offset];
        byte g = data[offset + 1];
        byte r = data[offset + 2];
        byte a = bytesPerPixel == 4 ? data[offset + 3] : (byte)255;
        return ((uint)a << 24) | ((uint)r << 16) | ((uint)g << 8) | b;
    }

    // Unpacks a 15/16-bit little-endian sample: bits 0-4 blue, 5-9 green, 10-14 red, each expanded from
    // five to eight bits by replicating the high bits into the low ones. The top bit is an attribute bit,
    // read as alpha only when the descriptor declares one; otherwise the sample is opaque.
    private static uint Unpack16(int packed, bool hasAlpha)
    {
        uint r = (uint)((packed >> 10) & 0x1F);
        uint g = (uint)((packed >> 5) & 0x1F);
        uint b = (uint)(packed & 0x1F);
        r = (r << 3) | (r >> 2);
        g = (g << 3) | (g >> 2);
        b = (b << 3) | (b >> 2);
        uint a = hasAlpha ? ((packed & 0x8000) != 0 ? 255u : 0u) : 255u;
        return (a << 24) | (r << 16) | (g << 8) | b;
    }

    // TGA rows and columns run from the origin corner. When the origin is at the bottom the file's
    // first row is the image's last, so the row is flipped unless the top-to-bottom flag is set; when
    // the origin is at the right the pixels run leftward, so the column is flipped too.
    private static void Store(uint* pixels, int index, uint value, int width, int height, bool topToBottom, bool rightToLeft)
    {
        int sourceRow = index / width;
        int sourceColumn = index % width;
        int destinationRow = topToBottom ? sourceRow : height - 1 - sourceRow;
        int destinationColumn = rightToLeft ? width - 1 - sourceColumn : sourceColumn;
        pixels[(destinationRow * width) + destinationColumn] = value;
    }

    // The decoded shape of the pixel stream: which family a sample belongs to, how many bytes it spans,
    // the palette a colour-mapped sample indexes (with the index its first entry maps to), and whether a
    // 16-bit true-colour sample carries alpha in its top bit.
    private readonly struct Format(int kind, int bytesPerPixel, uint[]? palette, int firstEntryIndex, bool alpha16)
    {
        public readonly int Kind = kind;
        public readonly int BytesPerPixel = bytesPerPixel;
        public readonly uint[]? Palette = palette;
        public readonly int FirstEntryIndex = firstEntryIndex;
        public readonly bool Alpha16 = alpha16;
    }

    /// <summary>Releases the decoded pixels.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_pixels != null)
        {
            NativeMemory.Free(_pixels);
            _pixels = null;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases the pixels if the image was dropped without a <see cref="Dispose"/> call.</summary>
    ~TgaImage() => Dispose();
}

/// <summary>
/// Encodes a drawing surface to the bytes of an uncompressed TGA file, keeping the alpha channel by
/// default. Use it to save a drawing, a screenshot, or a generated texture in a format editors read.
/// </summary>
public static unsafe class TgaEncoder
{
    /// <summary>
    /// Encodes <paramref name="surface"/> to TGA bytes. With <paramref name="includeAlpha"/> set (the
    /// default) it writes 32-bit BGRA; otherwise 24-bit BGR.
    /// </summary>
    /// <exception cref="ArgumentException">The surface has no pixels.</exception>
    /// <exception cref="ProsperoException">The encoded image would exceed the maximum file size.</exception>
    public static byte[] Encode(Surface surface, bool includeAlpha = true)
    {
        int width = surface.Width, height = surface.Height;
        if (width <= 0 || height <= 0)
            throw new ArgumentException("The surface has no pixels to encode.", nameof(surface));
        int bytesPerPixel = includeAlpha ? 4 : 3;

        // Size the file in 64-bit so the pixel-region product cannot wrap on a very large surface, then
        // keep it within a signed int for the output array.
        long size = 18L + (long)width * height * bytesPerPixel;
        if (size > int.MaxValue)
            throw new ProsperoException("The TGA image is too large.", -1);
        byte[] output = new byte[(int)size];

        output[2] = 2; // uncompressed true-colour
        output[12] = (byte)(width & 0xFF);
        output[13] = (byte)(width >> 8);
        output[14] = (byte)(height & 0xFF);
        output[15] = (byte)(height >> 8);
        output[16] = (byte)(bytesPerPixel * 8);
        // Alpha-channel depth in the low bits, and the top-to-bottom flag so the rows are written in order.
        output[17] = (byte)((includeAlpha ? 0x08 : 0x00) | 0x20);

        int offset = 18;
        for (int y = 0; y < height; y++)
        {
            uint* row = surface.Pixels + ((long)y * surface.Stride);
            for (int x = 0; x < width; x++)
            {
                uint pixel = row[x];
                output[offset++] = (byte)pixel;         // B
                output[offset++] = (byte)(pixel >> 8);  // G
                output[offset++] = (byte)(pixel >> 16); // R
                if (includeAlpha)
                    output[offset++] = (byte)(pixel >> 24); // A
            }
        }
        return output;
    }

    /// <summary>Encodes <paramref name="surface"/> and writes it to the file at <paramref name="path"/>.</summary>
    public static void Save(Surface surface, string path, bool includeAlpha = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        FileSystem.WriteAllBytes(path, Encode(surface, includeAlpha));
    }
}
