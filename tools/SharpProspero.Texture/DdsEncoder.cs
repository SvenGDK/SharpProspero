// SharpProspero.Texture - builds GNF texture containers for the console from common image files.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Texture;

/// <summary>
/// Encodes a decoded image to the DirectDraw Surface form the system browser reads for a title's
/// <c>icon0</c>, <c>pic0</c>, <c>pic1</c> and <c>pic2</c> media. The output is a DX10-header DDS that
/// carries a single, full-resolution, no-mipmap 2D surface, with the pixels compressed as
/// <c>DXGI_FORMAT_BC7_UNORM</c>.
/// </summary>
/// <remarks>
/// The container is one hundred and forty-eight bytes of header - the four-byte magic, the
/// hundred-and-twenty-four-byte DDS_HEADER, and the twenty-byte DDS_HEADER_DXT10 extension - followed
/// by one byte per texel of block-compressed data (a four-by-four block is sixteen bytes, so a single
/// block covers sixteen texels). The block encoder settles on mode six, which is the simplest block
/// that covers all four channels: one endpoint pair, seven-bit endpoint components with a shared
/// low-order bit per endpoint, and one index of four bits for each texel. The first index has its
/// most-significant bit tied to zero and is packed in three bits; the encoder swaps the endpoints and
/// inverts every index when the closest one it found had that bit set.
/// </remarks>
public static class DdsEncoder
{
    /// <summary>The container header size: four-byte magic, DDS_HEADER, and DDS_HEADER_DXT10.</summary>
    public const int HeaderSize = 148;

    // DXGI_FORMAT_BC7_UNORM. What the system browser reads for the icon and picture media.
    private const uint DxgiFormatBc7Unorm = 98;

    // Interpolation weights used to reconstruct a texel from the endpoint pair (aWeight4 in the block
    // format specification): reconstructed[c] = (e0[c] * (64 - w) + e1[c] * w + 32) >> 6, where w comes
    // from this table indexed by the four-bit texel index.
    private static readonly int[] Weights4 =
        [0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64];

    /// <summary>
    /// Encodes <paramref name="image"/>'s pixels to the bytes of a DDS file.
    /// </summary>
    /// <param name="image">The image to encode.</param>
    /// <exception cref="ArgumentNullException"><paramref name="image"/> is null.</exception>
    public static byte[] Encode(DecodedImage image)
    {
        ArgumentNullException.ThrowIfNull(image);
        return Encode(image.Rgba, image.Width, image.Height);
    }

    /// <summary>
    /// Encodes a tightly packed top-down red-green-blue-alpha pixel run of
    /// <paramref name="width"/> * <paramref name="height"/> pixels to the bytes of a DDS file.
    /// The image is measured in whole texels; the block plane rounds each dimension up to a multiple
    /// of four, with edge pixels held over to fill the partial blocks at the far edges.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">A dimension is zero or negative.</exception>
    /// <exception cref="ArgumentException">The pixel run is shorter than the declared image size.</exception>
    public static byte[] Encode(byte[] rgba, int width, int height)
    {
        ArgumentNullException.ThrowIfNull(rgba);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(width);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(height);
        if (rgba.Length < (long)width * height * 4)
            throw new ArgumentException("Pixel buffer is shorter than the declared image size.", nameof(rgba));

        int blocksX = (width + 3) >> 2;
        int blocksY = (height + 3) >> 2;
        int blockedWidth = blocksX * 4;
        int blockedHeight = blocksY * 4;
        long payloadLong = (long)blockedWidth * blockedHeight;
        if (HeaderSize + payloadLong > int.MaxValue)
            throw new ArgumentException("The image is too large for a DDS file.", nameof(width));

        byte[] file = new byte[HeaderSize + (int)payloadLong];
        WriteHeader(file, width, height, (uint)payloadLong);

        Span<byte> texels = stackalloc byte[16 * 4];
        int cursor = HeaderSize;
        for (int by = 0; by < blocksY; by++)
        {
            for (int bx = 0; bx < blocksX; bx++)
            {
                GatherBlock(rgba, width, height, bx * 4, by * 4, texels);
                EncodeBlockMode6(texels, file.AsSpan(cursor, 16));
                cursor += 16;
            }
        }

        return file;
    }

    // Writes the fixed part of the DDS: magic, DDS_HEADER, DDS_HEADER_DXT10. Every field the system
    // reader has an opinion on is spelled out; the fields it does not are left zero, so re-reading the
    // same header with a stricter decoder still passes.
    private static void WriteHeader(byte[] dst, int width, int height, uint linearSize)
    {
        // "DDS " magic.
        dst[0] = (byte)'D';
        dst[1] = (byte)'D';
        dst[2] = (byte)'S';
        dst[3] = (byte)' ';

        WriteU32(dst, 0x04, 124);                    // dwSize (DDS_HEADER)
        WriteU32(dst, 0x08, 0x000A1007);             // CAPS | HEIGHT | WIDTH | PIXELFORMAT | MIPMAPCOUNT | LINEARSIZE
        WriteU32(dst, 0x0C, (uint)height);           // dwHeight
        WriteU32(dst, 0x10, (uint)width);            // dwWidth
        WriteU32(dst, 0x14, linearSize);             // dwPitchOrLinearSize
        WriteU32(dst, 0x18, 0);                      // dwDepth
        WriteU32(dst, 0x1C, 1);                      // dwMipMapCount
        // 0x20..0x4B: dwReserved1[11] — kept zero.
        WriteU32(dst, 0x4C, 32);                     // ddspf.dwSize
        WriteU32(dst, 0x50, 0x04);                   // ddspf.dwFlags = DDPF_FOURCC

        dst[0x54] = (byte)'D';                       // ddspf.dwFourCC = "DX10"
        dst[0x55] = (byte)'X';
        dst[0x56] = (byte)'1';
        dst[0x57] = (byte)'0';
        // 0x58..0x6B: pixel-format masks (unused with FOURCC).
        WriteU32(dst, 0x6C, 0x1000);                 // dwCaps = DDSCAPS_TEXTURE
        // 0x70..0x7F: dwCaps2, dwCaps3, dwCaps4, dwReserved2 — kept zero.

        // DDS_HEADER_DXT10 extension.
        WriteU32(dst, 0x80, DxgiFormatBc7Unorm);     // dxgiFormat
        WriteU32(dst, 0x84, 3);                      // resourceDimension = D3D10_RESOURCE_DIMENSION_TEXTURE2D
        WriteU32(dst, 0x88, 0);                      // miscFlag
        WriteU32(dst, 0x8C, 1);                      // arraySize
        WriteU32(dst, 0x90, 0);                      // miscFlags2
    }

    private static void WriteU32(byte[] dst, int offset, uint value)
    {
        dst[offset] = (byte)value;
        dst[offset + 1] = (byte)(value >> 8);
        dst[offset + 2] = (byte)(value >> 16);
        dst[offset + 3] = (byte)(value >> 24);
    }

    // Copies one four-by-four RGBA block starting at (x0, y0). Pixels past the image edge repeat the
    // last valid pixel along that axis, which is what a block plane rounded up in each dimension needs
    // when the image itself is not a multiple of four texels wide or tall.
    private static void GatherBlock(byte[] rgba, int width, int height, int x0, int y0, Span<byte> block)
    {
        for (int y = 0; y < 4; y++)
        {
            int sy = y0 + y;
            if (sy >= height) sy = height - 1;
            int rowStart = sy * width * 4;
            for (int x = 0; x < 4; x++)
            {
                int sx = x0 + x;
                if (sx >= width) sx = width - 1;
                int src = rowStart + sx * 4;
                int dst = (y * 4 + x) * 4;
                block[dst] = rgba[src];
                block[dst + 1] = rgba[src + 1];
                block[dst + 2] = rgba[src + 2];
                block[dst + 3] = rgba[src + 3];
            }
        }
    }

    // Encodes one block into sixteen bytes at <paramref name="dst"/>.
    //
    // Layout (little-endian, bits packed LSB-first):
    //     bits 0..6    mode token — six zero bits followed by a one
    //     bits 7..62   endpoint components — R0 R1 G0 G1 B0 B1 A0 A1, each seven bits
    //     bits 63..64  the per-endpoint p-bit — P0 then P1
    //     bits 65..67  the first texel's index — three bits, high bit assumed zero
    //     bits 68..127 the remaining fifteen texel indices — four bits each
    private static void EncodeBlockMode6(ReadOnlySpan<byte> block, Span<byte> dst)
    {
        // Endpoint pair: the bounding box of the block in each channel.
        Span<int> min = stackalloc int[4] { 255, 255, 255, 255 };
        Span<int> max = stackalloc int[4] { 0, 0, 0, 0 };
        for (int i = 0; i < 16; i++)
        {
            int p = i * 4;
            for (int c = 0; c < 4; c++)
            {
                int v = block[p + c];
                if (v < min[c]) min[c] = v;
                if (v > max[c]) max[c] = v;
            }
        }

        // Quantize each endpoint to a seven-bit base plus a shared low-order bit, keeping the pair that
        // reconstructs closest to the original in the sum of squared differences over the four channels.
        Span<int> base0 = stackalloc int[4];
        Span<int> base1 = stackalloc int[4];
        Span<int> recon0 = stackalloc int[4];
        Span<int> recon1 = stackalloc int[4];
        int p0 = QuantizeEndpoint(min, base0, recon0);
        int p1 = QuantizeEndpoint(max, base1, recon1);

        // Pick the closest four-bit index for each texel against the reconstructed endpoint line.
        Span<int> indices = stackalloc int[16];
        for (int i = 0; i < 16; i++)
            indices[i] = BestIndex(recon0, recon1, block, i * 4);

        // Anchor: index[0] must fit in three bits. When the best pick sits above seven, swap the pair
        // and invert every index; the decoded result is identical.
        if (indices[0] >= 8)
        {
            Swap(base0, base1);
            Swap(recon0, recon1);
            (p0, p1) = (p1, p0);
            for (int i = 0; i < 16; i++)
                indices[i] = 15 - indices[i];
        }

        ulong lo = 0;
        ulong hi = 0;
        int pos = 0;
        Put(ref lo, ref hi, ref pos, 1u << 6, 7);                  // mode 6 token
        Put(ref lo, ref hi, ref pos, (uint)base0[0], 7);           // R0
        Put(ref lo, ref hi, ref pos, (uint)base1[0], 7);           // R1
        Put(ref lo, ref hi, ref pos, (uint)base0[1], 7);           // G0
        Put(ref lo, ref hi, ref pos, (uint)base1[1], 7);           // G1
        Put(ref lo, ref hi, ref pos, (uint)base0[2], 7);           // B0
        Put(ref lo, ref hi, ref pos, (uint)base1[2], 7);           // B1
        Put(ref lo, ref hi, ref pos, (uint)base0[3], 7);           // A0
        Put(ref lo, ref hi, ref pos, (uint)base1[3], 7);           // A1
        Put(ref lo, ref hi, ref pos, (uint)p0, 1);                 // P0
        Put(ref lo, ref hi, ref pos, (uint)p1, 1);                 // P1
        Put(ref lo, ref hi, ref pos, (uint)indices[0], 3);         // anchor index
        for (int i = 1; i < 16; i++)
            Put(ref lo, ref hi, ref pos, (uint)indices[i], 4);

        for (int i = 0; i < 8; i++)
            dst[i] = (byte)(lo >> (i * 8));
        for (int i = 0; i < 8; i++)
            dst[8 + i] = (byte)(hi >> (i * 8));
    }

    // Picks the p-bit and seven-bit base per channel whose reconstructed endpoint is closest to the
    // source value across the four channels, in the sum of squared differences.
    private static int QuantizeEndpoint(ReadOnlySpan<int> value, Span<int> bestBase, Span<int> bestRecon)
    {
        int chosenP = 0;
        long bestErr = long.MaxValue;
        Span<int> b = stackalloc int[4];
        Span<int> r = stackalloc int[4];
        for (int p = 0; p <= 1; p++)
        {
            long err = 0;
            for (int c = 0; c < 4; c++)
            {
                int q = (value[c] - p + 1) >> 1;
                if (q < 0) q = 0;
                else if (q > 127) q = 127;
                int rec = (q << 1) | p;
                int diff = rec - value[c];
                err += (long)diff * diff;
                b[c] = q;
                r[c] = rec;
            }
            if (err < bestErr)
            {
                bestErr = err;
                chosenP = p;
                b.CopyTo(bestBase);
                r.CopyTo(bestRecon);
            }
        }
        return chosenP;
    }

    // Returns the four-bit index whose interpolated colour is closest, in the sum of squared
    // differences, to the pixel at block[po..po+4).
    private static int BestIndex(ReadOnlySpan<int> e0, ReadOnlySpan<int> e1, ReadOnlySpan<byte> block, int po)
    {
        int best = 0;
        long bestErr = long.MaxValue;
        for (int i = 0; i < 16; i++)
        {
            int w = Weights4[i];
            long err = 0;
            for (int c = 0; c < 4; c++)
            {
                int rec = (e0[c] * (64 - w) + e1[c] * w + 32) >> 6;
                int diff = rec - block[po + c];
                err += (long)diff * diff;
            }
            if (err < bestErr)
            {
                bestErr = err;
                best = i;
            }
        }
        return best;
    }

    private static void Put(ref ulong lo, ref ulong hi, ref int pos, uint value, int count)
    {
        for (int i = 0; i < count; i++)
        {
            if (((value >> i) & 1u) != 0)
            {
                int bit = pos + i;
                if (bit < 64) lo |= 1UL << bit;
                else hi |= 1UL << (bit - 64);
            }
        }
        pos += count;
    }

    private static void Swap(Span<int> a, Span<int> b)
    {
        for (int i = 0; i < a.Length; i++)
            (a[i], b[i]) = (b[i], a[i]);
    }
}
