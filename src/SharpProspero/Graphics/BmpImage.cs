// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Storage;
using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// A decoded BMP image held as B8-G8-R8-A8 pixels, the same layout the display surface uses, so it
/// blits straight onto a framebuffer. BMP is a widely produced interchange format the SDK reads and
/// writes on its own, with no system module, which makes it a dependable choice for a file browser or an
/// editor. Decode once, draw its <see cref="AsSurface"/> as often as needed, dispose it to release the
/// pixels.
/// </summary>
public sealed unsafe class BmpImage : IDisposable
{
    // Compression identifiers from the BITMAPINFOHEADER biCompression field.
    private const int BiRgb = 0;
    private const int BiRle8 = 1;
    private const int BiRle4 = 2;
    private const int BiBitfields = 3;
    private const int BiAlphaBitfields = 6;

    private void* _pixels;
    private bool _disposed;

    private BmpImage(void* pixels, int width, int height)
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

    /// <summary>Loads and decodes the BMP file at <paramref name="path"/>.</summary>
    /// <exception cref="ProsperoException">The file could not be read or is not a supported BMP.</exception>
    public static BmpImage Load(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        return Decode(FileSystem.ReadAllBytes(path));
    }

    /// <summary>
    /// Decodes a BMP into a B8-G8-R8-A8 image. Supported forms are 1-, 4- and 8-bit palettized images
    /// (including the run-length encodings), 16-bit RGB555 and the bit-field variants, 24-bit and 32-bit
    /// true colour, and the bit-field masked layouts used by 16- and 32-bit files. A source without an
    /// alpha channel is read fully opaque. Top-down and bottom-up row orders are both handled, and rows
    /// are read with the format's four-byte row padding.
    /// </summary>
    /// <exception cref="ProsperoException">The data is not a BMP this reader supports, or it is truncated.</exception>
    public static BmpImage Decode(ReadOnlySpan<byte> bmp)
    {
        // File header (14) + at least the core BITMAPINFOHEADER (40).
        if (bmp.Length < 54 || bmp[0] != (byte)'B' || bmp[1] != (byte)'M')
            throw new ProsperoException("Not a BMP file.", -1);

        int pixelOffset = BinaryPrimitives.ReadInt32LittleEndian(bmp[10..]);
        int dibSize = BinaryPrimitives.ReadInt32LittleEndian(bmp[14..]);
        // The information header cannot be smaller than the 40-byte BITMAPINFOHEADER nor larger than the
        // file; bounding it here keeps the later 14 + dibSize offset math from overflowing on crafted input.
        if (dibSize < 40 || dibSize > bmp.Length)
            throw new ProsperoException("Unsupported BMP header.", -1);

        int width = BinaryPrimitives.ReadInt32LittleEndian(bmp[18..]);
        int rawHeight = BinaryPrimitives.ReadInt32LittleEndian(bmp[22..]);
        ushort bitCount = BinaryPrimitives.ReadUInt16LittleEndian(bmp[28..]);
        int compression = BinaryPrimitives.ReadInt32LittleEndian(bmp[30..]);
        uint paletteEntries = BinaryPrimitives.ReadUInt32LittleEndian(bmp[46..]);

        // A negative height stores the rows top-down; int.MinValue cannot be negated, so reject it.
        bool topDown = rawHeight < 0;
        if (rawHeight == int.MinValue)
            throw new ProsperoException("Invalid BMP dimensions.", -1);
        int height = topDown ? -rawHeight : rawHeight;

        if (width <= 0 || height <= 0)
            throw new ProsperoException("Invalid BMP dimensions.", -1);

        // The output is always four bytes per pixel; keep it inside a signed int so every later
        // offset computation stays well within range before anything is allocated.
        ulong outputBytes = (ulong)width * 4 * (ulong)height;
        if (outputBytes > int.MaxValue)
            throw new ProsperoException("The BMP image is too large.", -1);

        // Pixel data must begin at or after the end of the header and lie within the file.
        if (pixelOffset < 14 + dibSize || pixelOffset > bmp.Length)
            throw new ProsperoException("BMP pixel data is truncated.", -1);

        void* image = NativeMemory.Alloc((nuint)outputBytes);
        try
        {
            uint* pixels = (uint*)image;
            switch (compression)
            {
                case BiRgb:
                    switch (bitCount)
                    {
                        case 1:
                        case 4:
                        case 8:
                            DecodeIndexed(bmp, pixels, width, height, bitCount, dibSize, pixelOffset, paletteEntries, topDown);
                            break;
                        case 16:
                            // Uncompressed 16-bit stores 5-5-5 colour with the top bit unused.
                            DecodeMasked(bmp, pixels, width, height, 16, pixelOffset, 0x7C00u, 0x03E0u, 0x001Fu, 0u, topDown);
                            break;
                        case 24:
                            DecodeBgr24(bmp, pixels, width, height, pixelOffset, topDown);
                            break;
                        case 32:
                            DecodeBgrx32(bmp, pixels, width, height, pixelOffset, topDown);
                            break;
                        default:
                            throw new ProsperoException("Unsupported BMP pixel format.", -1);
                    }
                    break;
                case BiBitfields:
                case BiAlphaBitfields:
                    if (bitCount is 16 or 24 or 32)
                        DecodeBitfields(bmp, pixels, width, height, bitCount, compression, dibSize, pixelOffset, topDown);
                    else
                        throw new ProsperoException("Unsupported BMP pixel format.", -1);
                    break;
                case BiRle8:
                    if (bitCount == 8)
                        DecodeRle8(bmp, pixels, width, height, dibSize, pixelOffset, paletteEntries, topDown);
                    else
                        throw new ProsperoException("Unsupported BMP pixel format.", -1);
                    break;
                case BiRle4:
                    if (bitCount == 4)
                        DecodeRle4(bmp, pixels, width, height, dibSize, pixelOffset, paletteEntries, topDown);
                    else
                        throw new ProsperoException("Unsupported BMP pixel format.", -1);
                    break;
                default:
                    throw new ProsperoException("Unsupported BMP pixel format.", -1);
            }
        }
        catch
        {
            NativeMemory.Free(image);
            throw;
        }
        return new BmpImage(image, width, height);
    }

    // Bytes from the start of one stored row to the next: a row of packed samples padded up to a
    // four-byte boundary.
    private static long RowStride(int width, int bitCount) => ((long)width * bitCount + 31) / 32 * 4;

    // Confirms the stored rows fit inside the file and hands back the stride and the number of bytes a
    // single row actually occupies (the padding on the final row may be absent).
    private static void ValidateRows(ReadOnlySpan<byte> bmp, int pixelOffset, int width, int height, int bitCount, out long stride, out int rowBytes)
    {
        stride = RowStride(width, bitCount);
        rowBytes = (int)(((long)width * bitCount + 7) / 8);
        long lastRowStart = (long)(height - 1) * stride;
        if (pixelOffset + lastRowStart + rowBytes > bmp.Length)
            throw new ProsperoException("BMP pixel data is truncated.", -1);
    }

    // The colour table follows the DIB header. Each entry is blue, green, red and one unused byte. A
    // full 2^bitCount table is returned so every index a row can hold maps to a defined colour; entries
    // the file does not supply stay opaque black.
    private static uint[] ReadPalette(ReadOnlySpan<byte> bmp, int dibSize, uint paletteEntries, int bitCount)
    {
        int maxEntries = 1 << bitCount;
        int stated = paletteEntries == 0 ? maxEntries : (int)Math.Min(paletteEntries, (uint)maxEntries);

        int paletteStart = 14 + dibSize;
        if ((long)paletteStart + (long)stated * 4 > bmp.Length)
            throw new ProsperoException("BMP palette is truncated.", -1);

        uint[] palette = new uint[maxEntries];
        for (int i = 0; i < maxEntries; i++)
            palette[i] = 0xFF000000u;
        for (int i = 0; i < stated; i++)
        {
            int o = paletteStart + i * 4;
            palette[i] = 0xFF000000u | ((uint)bmp[o + 2] << 16) | ((uint)bmp[o + 1] << 8) | bmp[o];
        }
        return palette;
    }

    private static void DecodeIndexed(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int bitCount, int dibSize, int pixelOffset, uint paletteEntries, bool topDown)
    {
        uint[] palette = ReadPalette(bmp, dibSize, paletteEntries, bitCount);
        ValidateRows(bmp, pixelOffset, width, height, bitCount, out long stride, out int rowBytes);

        for (int y = 0; y < height; y++)
        {
            int srcRow = topDown ? y : height - 1 - y;
            ReadOnlySpan<byte> row = bmp.Slice(pixelOffset + (int)(srcRow * stride), rowBytes);
            uint* dst = pixels + (long)y * width;
            switch (bitCount)
            {
                case 8:
                    for (int x = 0; x < width; x++)
                        dst[x] = palette[row[x]];
                    break;
                case 4:
                    for (int x = 0; x < width; x++)
                    {
                        int packed = row[x >> 1];
                        int index = (x & 1) == 0 ? packed >> 4 : packed & 0x0F;
                        dst[x] = palette[index];
                    }
                    break;
                default: // 1-bit, most-significant bit first.
                    for (int x = 0; x < width; x++)
                    {
                        int index = (row[x >> 3] >> (7 - (x & 7))) & 1;
                        dst[x] = palette[index];
                    }
                    break;
            }
        }
    }

    private static void DecodeBgr24(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int pixelOffset, bool topDown)
    {
        ValidateRows(bmp, pixelOffset, width, height, 24, out long stride, out int rowBytes);
        for (int y = 0; y < height; y++)
        {
            int srcRow = topDown ? y : height - 1 - y;
            ReadOnlySpan<byte> row = bmp.Slice(pixelOffset + (int)(srcRow * stride), rowBytes);
            uint* dst = pixels + (long)y * width;
            for (int x = 0; x < width; x++)
            {
                int i = x * 3;
                dst[x] = 0xFF000000u | ((uint)row[i + 2] << 16) | ((uint)row[i + 1] << 8) | row[i];
            }
        }
    }

    private static void DecodeBgrx32(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int pixelOffset, bool topDown)
    {
        ValidateRows(bmp, pixelOffset, width, height, 32, out long stride, out int rowBytes);
        for (int y = 0; y < height; y++)
        {
            int srcRow = topDown ? y : height - 1 - y;
            ReadOnlySpan<byte> row = bmp.Slice(pixelOffset + (int)(srcRow * stride), rowBytes);
            uint* dst = pixels + (long)y * width;
            for (int x = 0; x < width; x++)
            {
                int i = x * 4;
                // Stored blue, green, red, then a reserved byte: an uncompressed BMP carries no alpha,
                // so the fourth byte is dropped and the pixel is read fully opaque.
                dst[x] = 0xFF000000u | ((uint)row[i + 2] << 16) | ((uint)row[i + 1] << 8) | row[i];
            }
        }
    }

    // Reads the channel masks that follow the header (or live inside a version-4/5 header, at the same
    // file position) and decodes each pixel by extracting and scaling every channel to eight bits.
    private static void DecodeBitfields(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int bitCount, int compression, int dibSize, int pixelOffset, bool topDown)
    {
        // The three colour masks sit immediately after the 40-byte core header; a fourth alpha mask is
        // present for the alpha bit-field mode and for the extended headers that carry one.
        if (bmp.Length < 66)
            throw new ProsperoException("BMP colour masks are truncated.", -1);
        uint rMask = BinaryPrimitives.ReadUInt32LittleEndian(bmp[54..]);
        uint gMask = BinaryPrimitives.ReadUInt32LittleEndian(bmp[58..]);
        uint bMask = BinaryPrimitives.ReadUInt32LittleEndian(bmp[62..]);
        uint aMask = 0;
        if (compression == BiAlphaBitfields || dibSize >= 56)
        {
            if (bmp.Length < 70)
                throw new ProsperoException("BMP colour masks are truncated.", -1);
            aMask = BinaryPrimitives.ReadUInt32LittleEndian(bmp[66..]);
        }

        // A file that names bit fields but supplies no masks falls back to the depth's usual layout.
        if ((rMask | gMask | bMask) == 0)
        {
            if (bitCount == 16)
            {
                rMask = 0x7C00u; gMask = 0x03E0u; bMask = 0x001Fu;
            }
            else
            {
                rMask = 0x00FF0000u; gMask = 0x0000FF00u; bMask = 0x000000FFu;
            }
        }

        DecodeMasked(bmp, pixels, width, height, bitCount, pixelOffset, rMask, gMask, bMask, aMask, topDown);
    }

    private static void DecodeMasked(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int bitCount, int pixelOffset, uint rMask, uint gMask, uint bMask, uint aMask, bool topDown)
    {
        ValidateRows(bmp, pixelOffset, width, height, bitCount, out long stride, out int rowBytes);
        int bytesPerPixel = bitCount / 8;

        int rShift = Shift(rMask), rBits = Bits(rMask);
        int gShift = Shift(gMask), gBits = Bits(gMask);
        int bShift = Shift(bMask), bBits = Bits(bMask);
        int aShift = Shift(aMask), aBits = Bits(aMask);

        for (int y = 0; y < height; y++)
        {
            int srcRow = topDown ? y : height - 1 - y;
            ReadOnlySpan<byte> row = bmp.Slice(pixelOffset + (int)(srcRow * stride), rowBytes);
            uint* dst = pixels + (long)y * width;
            for (int x = 0; x < width; x++)
            {
                int i = x * bytesPerPixel;
                uint sample = bytesPerPixel switch
                {
                    2 => (uint)(row[i] | (row[i + 1] << 8)),
                    3 => (uint)(row[i] | (row[i + 1] << 8) | (row[i + 2] << 16)),
                    _ => (uint)(row[i] | (row[i + 1] << 8) | (row[i + 2] << 16) | (row[i + 3] << 24)),
                };
                uint r = Scale(sample, rMask, rShift, rBits);
                uint g = Scale(sample, gMask, gShift, gBits);
                uint b = Scale(sample, bMask, bShift, bBits);
                uint a = aMask == 0 ? 255u : Scale(sample, aMask, aShift, aBits);
                dst[x] = (a << 24) | (r << 16) | (g << 8) | b;
            }
        }
    }

    private static int Shift(uint mask) => mask == 0 ? 0 : BitOperations.TrailingZeroCount(mask);

    private static int Bits(uint mask) => BitOperations.PopCount(mask);

    // Isolates one channel and rescales its stored value to the full 0..255 range. A channel narrower
    // than eight bits is scaled up with rounding so its widest value maps exactly to 255; a wider one
    // keeps its most significant eight bits. The width is non-zero here (the mask is non-zero), so no
    // division by zero is possible.
    private static uint Scale(uint sample, uint mask, int shift, int bits)
    {
        if (mask == 0)
            return 0;
        uint value = (sample & mask) >> shift;
        if (bits == 8)
            return value;
        if (bits > 8)
            return value >> (bits - 8);
        int max = (1 << bits) - 1;
        return (value * 255u + (uint)(max / 2)) / (uint)max;
    }

    // Run-length rows are decoded from the bottom up (the format's positive-height convention); each
    // scanline the encoding advances corresponds to the next row toward the top of the image. Pixels a
    // delta or an early end-of-line skips keep the first palette colour.
    private static void DecodeRle8(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int dibSize, int pixelOffset, uint paletteEntries, bool topDown)
    {
        uint[] palette = ReadPalette(bmp, dibSize, paletteEntries, 8);
        ReadOnlySpan<byte> data = bmp[pixelOffset..];
        FillBackground(pixels, width, height, palette[0]);

        int x = 0, row = 0, pos = 0;
        while (pos + 2 <= data.Length)
        {
            byte count = data[pos++];
            byte value = data[pos++];
            if (count > 0)
            {
                for (int k = 0; k < count; k++)
                    Put(pixels, palette, value, x++, row, width, height, topDown);
                continue;
            }
            switch (value)
            {
                case 0: // End of line.
                    x = 0;
                    row++;
                    break;
                case 1: // End of bitmap.
                    return;
                case 2: // Delta: skip right and up by the next two bytes.
                    if (pos + 2 > data.Length)
                        throw new ProsperoException("BMP run-length data is truncated.", -1);
                    x += data[pos++];
                    row += data[pos++];
                    break;
                default: // Absolute run of literal indices, padded to a two-byte boundary.
                    if (pos + value > data.Length)
                        throw new ProsperoException("BMP run-length data is truncated.", -1);
                    for (int k = 0; k < value; k++)
                        Put(pixels, palette, data[pos++], x++, row, width, height, topDown);
                    if ((value & 1) != 0 && pos < data.Length)
                        pos++;
                    break;
            }
        }
    }

    private static void DecodeRle4(ReadOnlySpan<byte> bmp, uint* pixels, int width, int height, int dibSize, int pixelOffset, uint paletteEntries, bool topDown)
    {
        uint[] palette = ReadPalette(bmp, dibSize, paletteEntries, 4);
        ReadOnlySpan<byte> data = bmp[pixelOffset..];
        FillBackground(pixels, width, height, palette[0]);

        int x = 0, row = 0, pos = 0;
        while (pos + 2 <= data.Length)
        {
            byte count = data[pos++];
            byte value = data[pos++];
            if (count > 0)
            {
                // The run alternates between the high and low nibble, high nibble first.
                int high = value >> 4, low = value & 0x0F;
                for (int k = 0; k < count; k++)
                    Put(pixels, palette, (byte)((k & 1) == 0 ? high : low), x++, row, width, height, topDown);
                continue;
            }
            switch (value)
            {
                case 0: // End of line.
                    x = 0;
                    row++;
                    break;
                case 1: // End of bitmap.
                    return;
                case 2: // Delta: skip right and up by the next two bytes.
                    if (pos + 2 > data.Length)
                        throw new ProsperoException("BMP run-length data is truncated.", -1);
                    x += data[pos++];
                    row += data[pos++];
                    break;
                default: // Absolute run of literal nibbles, packed two per byte and padded to a two-byte boundary.
                    int bytesToRead = (value + 1) / 2;
                    if (pos + bytesToRead > data.Length)
                        throw new ProsperoException("BMP run-length data is truncated.", -1);
                    int produced = 0;
                    for (int b = 0; b < bytesToRead; b++)
                    {
                        int packed = data[pos++];
                        if (produced++ < value)
                            Put(pixels, palette, (byte)(packed >> 4), x++, row, width, height, topDown);
                        if (produced++ < value)
                            Put(pixels, palette, (byte)(packed & 0x0F), x++, row, width, height, topDown);
                    }
                    if ((bytesToRead & 1) != 0 && pos < data.Length)
                        pos++;
                    break;
            }
        }
    }

    private static void FillBackground(uint* pixels, int width, int height, uint color)
        => new Span<uint>(pixels, (int)((long)width * height)).Fill(color);

    // Places one run-length pixel. The stored rows run bottom-up unless the header marks the image
    // top-down; positions outside the image (a run or delta that overshoots) are ignored rather than
    // written out of bounds.
    private static void Put(uint* pixels, uint[] palette, byte index, int x, int row, int width, int height, bool topDown)
    {
        int dstRow = topDown ? row : height - 1 - row;
        if ((uint)x < (uint)width && (uint)dstRow < (uint)height)
            pixels[(long)dstRow * width + x] = palette[index];
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
    ~BmpImage() => Dispose();
}

/// <summary>
/// Writes a drawing surface to an uncompressed BMP, a dependable interchange format that needs no system
/// module. It writes a 24-bit opaque image, which every image tool reads. Use it to export a screenshot
/// or a picture without loading an encoder.
/// </summary>
public static unsafe class BmpEncoder
{
    private const int FileHeaderSize = 14;
    private const int InfoHeaderSize = 40;

    /// <summary>Encodes <paramref name="surface"/> to the bytes of a 24-bit BMP file.</summary>
    /// <exception cref="ArgumentException">The surface has no pixels.</exception>
    /// <exception cref="ProsperoException">The encoded file would exceed the maximum size.</exception>
    public static byte[] Encode(Surface surface)
    {
        int width = surface.Width, height = surface.Height;
        if (width <= 0 || height <= 0)
            throw new ArgumentException("The surface is empty.", nameof(surface));

        // Size the file in 64-bit arithmetic so a very large surface cannot wrap the byte total to a
        // negative or under-sized value before the buffer is allocated.
        long rowStride = ((long)width * 3 + 3) & ~3L;
        long pixelBytes = rowStride * height;
        long fileSize = FileHeaderSize + InfoHeaderSize + pixelBytes;
        if (fileSize > int.MaxValue)
            throw new ProsperoException("The BMP image is too large.", -1);

        int pixelOffset = FileHeaderSize + InfoHeaderSize;
        byte[] output = new byte[fileSize];
        Span<byte> span = output;

        // File header.
        span[0] = (byte)'B';
        span[1] = (byte)'M';
        BinaryPrimitives.WriteInt32LittleEndian(span[2..], (int)fileSize);
        BinaryPrimitives.WriteInt32LittleEndian(span[10..], pixelOffset);

        // BITMAPINFOHEADER: 24-bit, bottom-up (positive height), uncompressed.
        BinaryPrimitives.WriteInt32LittleEndian(span[14..], InfoHeaderSize);
        BinaryPrimitives.WriteInt32LittleEndian(span[18..], width);
        BinaryPrimitives.WriteInt32LittleEndian(span[22..], height);
        BinaryPrimitives.WriteUInt16LittleEndian(span[26..], 1);   // planes
        BinaryPrimitives.WriteUInt16LittleEndian(span[28..], 24);  // bit count
        BinaryPrimitives.WriteInt32LittleEndian(span[34..], (int)pixelBytes);

        uint* pixels = surface.Pixels;
        int stride = surface.Stride;
        for (int y = 0; y < height; y++)
        {
            // BMP rows run bottom-up.
            uint* srcRow = pixels + (long)(height - 1 - y) * stride;
            long rowStart = pixelOffset + (long)y * rowStride;
            for (int x = 0; x < width; x++)
            {
                uint p = srcRow[x];
                long o = rowStart + (long)x * 3;
                span[(int)o] = (byte)p;            // blue
                span[(int)o + 1] = (byte)(p >> 8); // green
                span[(int)o + 2] = (byte)(p >> 16);// red
            }
        }
        return output;
    }

    /// <summary>Encodes <paramref name="surface"/> and writes it to the file at <paramref name="path"/>.</summary>
    public static void Save(Surface surface, string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        FileSystem.WriteAllBytes(path, Encode(surface));
    }
}
