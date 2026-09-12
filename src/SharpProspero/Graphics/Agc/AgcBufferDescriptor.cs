// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics.Agc;

/// <summary>
/// A buffer resource descriptor: the four 32-bit words that tell a shader where a buffer is, how its
/// records are sized, and how to read them. A vertex program reads its vertices through one of these,
/// and its transform matrices through a constant-buffer one. Build the descriptor, then write its four
/// words into the shader's user data so the program can reach the buffer.
/// </summary>
public readonly struct AgcBufferDescriptor
{
    /// <summary>The four descriptor words, in order.</summary>
    public readonly uint Word0, Word1, Word2, Word3;

    private AgcBufferDescriptor(uint w0, uint w1, uint w2, uint w3)
    {
        Word0 = w0; Word1 = w1; Word2 = w2; Word3 = w3;
    }

    /// <summary>Writes the four words into <paramref name="dest"/> (length at least 4).</summary>
    public void WriteTo(Span<uint> dest)
    {
        dest[0] = Word0; dest[1] = Word1; dest[2] = Word2; dest[3] = Word3;
    }

    // The address occupies 48 bits: the low 32 in word0, the high 16 in the low half of word1. The stride
    // is 14 bits in word1; the record count is all of word2. Word3 selects the channels and the element
    // format and marks the descriptor a buffer (type 0).
    private const uint RegularSwizzle = 0x204;   // channels X,0,0,1
    private const uint RegularFormat = 5;        // one 8-bit unsigned element; the shader reads by stride
    private const uint ConstantSwizzle = 0xfac;  // channels X,Y,Z,W
    private const uint ConstantFormat = 77;      // four 32-bit floats

    /// <summary>
    /// A structured buffer of <paramref name="elementCount"/> records, each <paramref name="strideInBytes"/>
    /// bytes, at <paramref name="address"/>. A vertex program reads a vertex from one of these by index.
    /// </summary>
    public static AgcBufferDescriptor Structured(ulong address, uint strideInBytes, uint elementCount)
    {
        if (strideInBytes >= 1u << 14) throw new ArgumentOutOfRangeException(nameof(strideInBytes), "The stride must be less than 16384 bytes.");
        uint word0 = (uint)(address & 0xFFFFFFFF);
        uint word1 = (uint)((address >> 32) & 0xFFFF) | ((strideInBytes & 0x3FFF) << 16);
        // The out-of-bounds behaviour sits in word3 bits 28-29. With a real stride a read is out of
        // bounds when the index reaches the record count or the offset reaches the stride
        // (kIndexAndOffset, 0). With a zero stride the record count instead holds the byte size and the
        // one element repeats, so the bound is an offset check (kOffsetOrSwizzle, 3).
        uint outOfBounds = strideInBytes == 0 ? 3u : 0u;
        uint word3 = RegularSwizzle | (RegularFormat << 12) | (outOfBounds << 28); // buffer type 0
        return new AgcBufferDescriptor(word0, word1, elementCount, word3);
    }

    /// <summary>
    /// A constant buffer of <paramref name="sizeInBytes"/> bytes at <paramref name="address"/>. A vertex
    /// program reads its transform matrices from one of these.
    /// </summary>
    public static AgcBufferDescriptor Constant(ulong address, uint sizeInBytes)
    {
        const uint recordSize = 16; // constant buffers are addressed in 16-byte records
        uint records = (sizeInBytes + recordSize - 1) / recordSize;
        uint word0 = (uint)(address & 0xFFFFFFFF);
        uint word1 = (uint)((address >> 32) & 0xFFFF) | (recordSize << 16);
        uint word3 = ConstantSwizzle | (ConstantFormat << 12);
        return new AgcBufferDescriptor(word0, word1, records, word3);
    }
}
