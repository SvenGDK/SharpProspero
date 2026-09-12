// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Security;
using System;
using System.Collections.Generic;

namespace SharpProspero.Compression;

/// <summary>Thrown when a compressed stream is malformed or truncated.</summary>
public sealed class CompressionException(string message) : Exception(message);

/// <summary>
/// Decompresses DEFLATE data entirely in managed code - the compression behind gzip, the zlib format, ZIP
/// entries, PNG image data and countless network and file formats. It runs anywhere, with no service and
/// no size cap, so it works the same on the console, in a tool, and in a test. Use <see cref="Raw"/> for a
/// bare DEFLATE stream, <see cref="Zlib"/> for a zlib-wrapped one, and <see cref="Gzip"/> for a gzip file.
/// </summary>
public static class Inflate
{
    private const int MaxBits = 15;

    private static readonly ushort[] LengthBase =
    [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
        67, 83, 99, 115, 131, 163, 195, 227, 258,
    ];

    private static readonly byte[] LengthExtra =
    [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];

    private static readonly ushort[] DistanceBase =
    [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];

    private static readonly byte[] DistanceExtra =
    [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    ];

    // The order the code-length code lengths appear in a dynamic block header.
    private static readonly byte[] CodeLengthOrder =
        [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    /// <summary>
    /// Decompresses a bare DEFLATE stream. <paramref name="sizeHint"/> presizes the output buffer;
    /// <paramref name="maxOutput"/>, when positive, is the most bytes the result may reach before the
    /// decode is refused, which bounds a decompression bomb.
    /// </summary>
    public static byte[] Raw(ReadOnlySpan<byte> data, int sizeHint = 0, int maxOutput = 0) => RunToArray(data, sizeHint, maxOutput);

    // Runs the block loop over a DEFLATE payload. Empty input is empty output (some encoders emit no bytes
    // for empty content); a non-empty but truncated stream still errors inside the loop.
    private static byte[] RunToArray(ReadOnlySpan<byte> deflate, int sizeHint, int maxOutput = 0)
    {
        if (deflate.IsEmpty)
            return [];
        var output = new GrowBuffer(sizeHint > 0 ? sizeHint : Math.Max(64, deflate.Length * 4), maxOutput);
        var reader = new BitReader(deflate);
        Run(ref reader, output);
        return output.ToArray();
    }

    /// <summary>
    /// Decompresses a zlib-wrapped (RFC 1950) stream and verifies its Adler-32 checksum.
    /// <paramref name="maxOutput"/>, when positive, caps the decompressed size to bound a bomb.
    /// </summary>
    public static byte[] Zlib(ReadOnlySpan<byte> data, int maxOutput = 0)
    {
        if (data.Length < 6)
            throw new CompressionException("The zlib stream is too short.");
        int cmf = data[0], flg = data[1];
        if ((cmf & 0x0F) != 8)
            throw new CompressionException("The zlib stream is not DEFLATE-compressed.");
        if (((cmf << 8) | flg) % 31 != 0)
            throw new CompressionException("The zlib header check failed.");
        int start = 2;
        if ((flg & 0x20) != 0) // a preset dictionary is present but not supported here
            throw new CompressionException("The zlib stream uses a preset dictionary, which is not supported.");

        // The DEFLATE payload sits between the 2-byte header and the 4-byte Adler-32 trailer.
        byte[] result = RunToArray(data[start..(data.Length - 4)], data.Length * 4, maxOutput);
        int trailer = data.Length - 4;
        uint stored = ((uint)data[trailer] << 24) | ((uint)data[trailer + 1] << 16) | ((uint)data[trailer + 2] << 8) | data[trailer + 3];
        if (Adler32(result) != stored)
            throw new CompressionException("The zlib Adler-32 checksum did not match.");
        return result;
    }

    /// <summary>
    /// Decompresses a gzip (RFC 1952) file, verifying the CRC-32 and length trailer of every member.
    /// </summary>
    /// <remarks>
    /// A gzip file is one or more members laid end to end and its content is theirs joined, which is
    /// what appending one compressed log or chunk to another produces. Reading only the first member
    /// would return a prefix, and where the members happen to be identical it would return that prefix
    /// with both trailer checks passing, so every member is read.
    /// </remarks>
    public static byte[] Gzip(ReadOnlySpan<byte> data, int maxOutput = 0)
    {
        byte[] first = ReadGzipMember(data, 0, out int pos, maxOutput);
        if (pos == data.Length)
            return first;

        var members = new List<byte[]> { first };
        int total = first.Length;
        while (pos < data.Length)
        {
            // The cap is on the whole file's content, so each member gets what is left of the budget;
            // a run of members cannot together decode past the ceiling.
            int remaining = maxOutput > 0 ? Math.Max(0, maxOutput - total) : 0;
            byte[] member = ReadGzipMember(data, pos, out pos, remaining);
            members.Add(member);
            total += member.Length;
        }

        var joined = new byte[total];
        int written = 0;
        foreach (byte[] member in members)
        {
            member.CopyTo(joined, written);
            written += member.Length;
        }
        return joined;
    }

    // Decodes the member starting at `start`, checks its own trailer against its own output, and
    // reports the offset just past it. The member's compressed data has no declared length, so where it
    // ends is only known once the block loop has stopped: the trailer begins at the next byte boundary.
    private static byte[] ReadGzipMember(ReadOnlySpan<byte> data, int start, out int next, int maxOutput = 0)
    {
        ReadOnlySpan<byte> member = data[start..];
        if (member.Length < 18 || member[0] != 0x1F || member[1] != 0x8B)
            throw new CompressionException("The data is not a gzip member.");
        if (member[2] != 8)
            throw new CompressionException("The gzip member is not DEFLATE-compressed.");
        int flags = member[3];
        int pos = 10; // fixed header: magic(2), method(1), flags(1), mtime(4), xfl(1), os(1)

        if ((flags & 0x04) != 0) // FEXTRA
        {
            if (pos + 2 > member.Length)
                throw new CompressionException("The gzip extra field is truncated.");
            int xlen = member[pos] | (member[pos + 1] << 8);
            pos += 2 + xlen;
        }
        if ((flags & 0x08) != 0) // FNAME
            pos = SkipZeroTerminated(member, pos);
        if ((flags & 0x10) != 0) // FCOMMENT
            pos = SkipZeroTerminated(member, pos);
        if ((flags & 0x02) != 0) // FHCRC
            pos += 2;
        if (pos > member.Length - 8)
            throw new CompressionException("The gzip header is truncated.");

        var output = new GrowBuffer(Math.Max(64, (member.Length - pos) * 4), maxOutput);
        var reader = new BitReader(member[pos..]);
        Run(ref reader, output);
        byte[] result = output.ToArray();

        int trailer = pos + reader.BytePosition;
        if (trailer > member.Length - 8)
            throw new CompressionException("The gzip trailer is truncated.");
        uint crc = ReadLittle(member, trailer);
        uint size = ReadLittle(member, trailer + 4);
        if ((uint)result.Length != size)
            throw new CompressionException("The gzip length trailer did not match.");
        if (Crc32.Compute(result) != crc)
            throw new CompressionException("The gzip CRC-32 checksum did not match.");

        next = start + trailer + 8;
        return result;
    }

    // The core DEFLATE loop: read blocks until the final one, appending to the output.
    private static void Run(ref BitReader reader, GrowBuffer output)
    {
        bool final;
        do
        {
            final = reader.Bit() == 1;
            int type = reader.Bits(2);
            switch (type)
            {
                case 0:
                    Stored(ref reader, output);
                    break;
                case 1:
                    Compressed(ref reader, output, FixedLiterals.Value, FixedDistances.Value);
                    break;
                case 2:
                    (HuffmanTable lit, HuffmanTable dist) = ReadDynamicTables(ref reader);
                    Compressed(ref reader, output, lit, dist);
                    break;
                default:
                    throw new CompressionException("The DEFLATE block type is invalid.");
            }
        }
        while (!final);
    }

    private static void Stored(ref BitReader reader, GrowBuffer output)
    {
        reader.AlignToByte();
        int len = reader.Bits(16);
        int nlen = reader.Bits(16);
        if ((len ^ 0xFFFF) != nlen)
            throw new CompressionException("The stored block length check failed.");
        for (int i = 0; i < len; i++)
            output.Add((byte)reader.Bits(8));
    }

    private static void Compressed(ref BitReader reader, GrowBuffer output, HuffmanTable literals, HuffmanTable distances)
    {
        while (true)
        {
            int symbol = Decode(ref reader, literals);
            if (symbol < 256)
            {
                output.Add((byte)symbol);
            }
            else if (symbol == 256)
            {
                return;
            }
            else
            {
                symbol -= 257;
                if (symbol >= LengthBase.Length)
                    throw new CompressionException("The DEFLATE length symbol is invalid.");
                int length = LengthBase[symbol] + reader.Bits(LengthExtra[symbol]);

                int distSymbol = Decode(ref reader, distances);
                if (distSymbol >= DistanceBase.Length)
                    throw new CompressionException("The DEFLATE distance symbol is invalid.");
                int distance = DistanceBase[distSymbol] + reader.Bits(DistanceExtra[distSymbol]);
                if (distance > output.Count)
                    throw new CompressionException("The DEFLATE back reference points before the output.");
                output.CopyBack(distance, length);
            }
        }
    }

    private static (HuffmanTable Literals, HuffmanTable Distances) ReadDynamicTables(ref BitReader reader)
    {
        int hlit = reader.Bits(5) + 257;
        int hdist = reader.Bits(5) + 1;
        int hclen = reader.Bits(4) + 4;

        var codeLengthLengths = new byte[19];
        for (int i = 0; i < hclen; i++)
            codeLengthLengths[CodeLengthOrder[i]] = (byte)reader.Bits(3);
        var codeLengthTable = new HuffmanTable(codeLengthLengths);

        var lengths = new byte[hlit + hdist];
        int index = 0;
        while (index < lengths.Length)
        {
            int symbol = Decode(ref reader, codeLengthTable);
            if (symbol < 16)
            {
                lengths[index++] = (byte)symbol;
            }
            else if (symbol == 16)
            {
                if (index == 0)
                    throw new CompressionException("A DEFLATE repeat had no previous length.");
                byte previous = lengths[index - 1];
                int repeat = 3 + reader.Bits(2);
                while (repeat-- > 0 && index < lengths.Length)
                    lengths[index++] = previous;
            }
            else if (symbol == 17)
            {
                int repeat = 3 + reader.Bits(3);
                while (repeat-- > 0 && index < lengths.Length)
                    lengths[index++] = 0;
            }
            else // 18
            {
                int repeat = 11 + reader.Bits(7);
                while (repeat-- > 0 && index < lengths.Length)
                    lengths[index++] = 0;
            }
        }

        return (new HuffmanTable(lengths.AsSpan(0, hlit)), new HuffmanTable(lengths.AsSpan(hlit)));
    }

    // Reads one Huffman symbol, one bit at a time, over the canonical code table (the puff.c method).
    private static int Decode(ref BitReader reader, HuffmanTable table)
    {
        int code = 0, first = 0, index = 0;
        for (int len = 1; len <= MaxBits; len++)
        {
            code |= reader.Bit();
            int count = table.Count[len];
            if (code - first < count)
                return table.Symbols[index + (code - first)];
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        throw new CompressionException("The DEFLATE code is invalid.");
    }

    private static readonly Lazy<HuffmanTable> FixedLiterals = new(() =>
    {
        var lengths = new byte[288];
        for (int i = 0; i < 144; i++) lengths[i] = 8;
        for (int i = 144; i < 256; i++) lengths[i] = 9;
        for (int i = 256; i < 280; i++) lengths[i] = 7;
        for (int i = 280; i < 288; i++) lengths[i] = 8;
        return new HuffmanTable(lengths);
    });

    private static readonly Lazy<HuffmanTable> FixedDistances = new(() =>
    {
        var lengths = new byte[30];
        Array.Fill(lengths, (byte)5);
        return new HuffmanTable(lengths);
    });

    private static int SkipZeroTerminated(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && data[pos] != 0)
            pos++;
        return pos + 1;
    }

    private static uint ReadLittle(ReadOnlySpan<byte> data, int offset)
        => data[offset] | ((uint)data[offset + 1] << 8) | ((uint)data[offset + 2] << 16) | ((uint)data[offset + 3] << 24);

    /// <summary>The Adler-32 checksum zlib streams carry, exposed for verifying one yourself.</summary>
    public static uint Adler32(ReadOnlySpan<byte> data)
    {
        const uint mod = 65521;
        uint a = 1, b = 0;
        foreach (byte value in data)
        {
            a = (a + value) % mod;
            b = (b + a) % mod;
        }
        return (b << 16) | a;
    }

    // A canonical Huffman decode table: a count of codes per bit length and the symbols in canonical order.
    private sealed class HuffmanTable
    {
        public readonly int[] Count = new int[MaxBits + 1];
        public readonly int[] Symbols;

        public HuffmanTable(ReadOnlySpan<byte> lengths)
        {
            Symbols = new int[lengths.Length];
            foreach (byte length in lengths)
                Count[length]++;
            Count[0] = 0;

            Span<int> offsets = stackalloc int[MaxBits + 2];
            for (int len = 1; len <= MaxBits; len++)
                offsets[len + 1] = offsets[len] + Count[len];
            for (int symbol = 0; symbol < lengths.Length; symbol++)
                if (lengths[symbol] != 0)
                    Symbols[offsets[lengths[symbol]]++] = symbol;
        }
    }

    // A DEFLATE bit reader: bits run least-significant first within each byte.
    private ref struct BitReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _pos;
        private int _bitBuffer;
        private int _bitCount;

        public int Bit()
        {
            if (_bitCount == 0)
            {
                if (_pos >= _data.Length)
                    throw new CompressionException("The DEFLATE stream ended unexpectedly.");
                _bitBuffer = _data[_pos++];
                _bitCount = 8;
            }
            int bit = _bitBuffer & 1;
            _bitBuffer >>= 1;
            _bitCount--;
            return bit;
        }

        public int Bits(int count)
        {
            int value = 0;
            for (int i = 0; i < count; i++)
                value |= Bit() << i;
            return value;
        }

        public void AlignToByte() => _bitCount = 0;

        // How many bytes the reader has taken. Any bits still buffered came out of the byte before
        // this one, so this is where whatever follows a DEFLATE payload begins.
        public readonly int BytePosition => _pos;
    }

    // A growable output buffer with a back-copy for DEFLATE back references (which may overlap).
    private sealed class GrowBuffer(int capacity, int max = 0)
    {
        // When positive, the most bytes the output may hold; a further byte is refused, which stops a
        // stream that expands far past its compressed size from exhausting memory.
        private readonly int _max = max;
        private byte[] _buffer = new byte[Math.Min(Math.Max(16, capacity), max > 0 ? max : int.MaxValue)];
        public int Count { get; private set; }

        public void Add(byte value)
        {
            if (_max > 0 && Count >= _max)
                throw new CompressionException("The decompressed data exceeds the maximum allowed size.");
            if (Count == _buffer.Length)
            {
                int target = _buffer.Length * 2;
                if (_max > 0 && (target > _max || target < _buffer.Length))
                    target = _max;
                Array.Resize(ref _buffer, target);
            }
            _buffer[Count++] = value;
        }

        public void CopyBack(int distance, int length)
        {
            int from = Count - distance;
            for (int i = 0; i < length; i++)
                Add(_buffer[from + i]); // reads bytes this same loop may have just written, so overlap works
        }

        public byte[] ToArray() => _buffer.AsSpan(0, Count).ToArray();
    }
}
