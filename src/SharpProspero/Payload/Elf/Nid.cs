// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Security;
using System;

namespace SharpProspero.Payload.Elf;

/// <summary>
/// Computes and compares symbol identifiers (NIDs). An NID is a compact 11-character
/// base64 encoding of the first 8 bytes (reversed) of the SHA-1 hash of a symbol name.
/// </summary>
public static class PayloadNid
{
    private const string Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

    /// <summary>
    /// Computes the 11-character NID string for a symbol name.
    /// </summary>
    public static unsafe string Compute(ReadOnlySpan<byte> symbolName)
    {
        byte[] hash = Sha1.Hash(symbolName);

        Span<byte> reversed = stackalloc byte[8];
        for (int i = 0; i < 8; i++)
            reversed[i] = hash[7 - i];

        return EncodeBase64(reversed);
    }

    /// <summary>
    /// Computes the 8-byte raw NID value for a symbol name (first 8 bytes of SHA-1,
    /// byte-reversed).
    /// </summary>
    public static unsafe ulong ComputeRaw(ReadOnlySpan<byte> symbolName)
    {
        byte[] hash = Sha1.Hash(symbolName);

        ulong value = 0;
        for (int i = 0; i < 8; i++)
            value |= (ulong)hash[i] << (i * 8);

        return value;
    }

    /// <summary>
    /// Compares two NID values for equality.
    /// </summary>
    public static bool Match(ulong a, ulong b) => a == b;

    /// <summary>
    /// Writes the 11-byte base64 NID encoding of a raw NID value into the destination span.
    /// Used for direct byte comparison against NID strings stored in symbol tables.
    /// </summary>
    /// <returns>Number of bytes written (always 11 for a valid NID).</returns>
    public static int EncodeRawToBytes(ulong raw, Span<byte> dest)
    {
        Span<byte> data = stackalloc byte[8];
        for (int i = 0; i < 8; i++)
            data[i] = (byte)(raw >> ((7 - i) * 8));

        int bits = 0, accumulator = 0, idx = 0;
        for (int i = 0; i < 8 && idx < 11; i++)
        {
            accumulator = (accumulator << 8) | data[i];
            bits += 8;
            while (bits >= 6 && idx < 11)
            {
                bits -= 6;
                dest[idx++] = (byte)Base64Chars[(accumulator >> bits) & 0x3F];
            }
        }
        if (bits > 0 && idx < 11)
            dest[idx++] = (byte)Base64Chars[(accumulator << (6 - bits)) & 0x3F];

        return idx;
    }

    /// <summary>
    /// Encodes 8 bytes into an 11-character base64 NID string using the variant base64
    /// alphabet (with <c>+</c> and <c>-</c> instead of <c>/</c> and <c>=</c>).
    /// </summary>
    private static string EncodeBase64(ReadOnlySpan<byte> data)
    {
        Span<char> result = stackalloc char[11];
        int bits = 0;
        int accumulator = 0;
        int idx = 0;

        for (int i = 0; i < 8 && idx < 11; i++)
        {
            accumulator = (accumulator << 8) | data[i];
            bits += 8;
            while (bits >= 6 && idx < 11)
            {
                bits -= 6;
                result[idx++] = Base64Chars[(accumulator >> bits) & 0x3F];
            }
        }

        if (bits > 0 && idx < 11)
            result[idx++] = Base64Chars[(accumulator << (6 - bits)) & 0x3F];

        return new string(result.Slice(0, idx));
    }
}
