// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// A byte pattern with per-byte wildcard support. Each entry holds two parallel arrays: the
/// fixed bytes and a mask where <c>0xFF</c> means the corresponding byte must match and any
/// other value means the byte is a wildcard.
/// </summary>
/// <remarks>
/// The pattern uses a mask array instead of encoding wildcards as a magic value (for example
/// <c>0xFF</c>) so a pattern that legitimately contains a <c>0xFF</c> byte still matches. Both
/// arrays are the same length and are typically produced from the human-readable spec
/// <c>"e8 ?? ?? ?? 01 85 c0"</c> via <see cref="Parse"/>.
/// </remarks>
public readonly struct Pattern
{
    /// <summary>The pattern bytes. Wildcard positions carry an arbitrary value (usually zero).</summary>
    public readonly byte[] Bytes;

    /// <summary>The pattern mask. <c>0xFF</c> = fixed byte, any other value = wildcard.</summary>
    public readonly byte[] Mask;

    /// <summary>Total pattern length in bytes.</summary>
    public int Length => Bytes.Length;

    /// <summary>Creates a pattern from a fixed byte array and its mask (both same length).</summary>
    public Pattern(byte[] bytes, byte[] mask)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(mask);
        if (bytes.Length != mask.Length)
            throw new ArgumentException("Pattern bytes and mask must have the same length.", nameof(mask));
        Bytes = bytes;
        Mask = mask;
    }

    /// <summary>
    /// Parses a human-readable pattern spec into fixed bytes plus mask. The spec is a
    /// whitespace-separated sequence of two-hex-digit bytes and <c>??</c> wildcard tokens.
    /// A wildcard byte reads as <c>0</c> in <see cref="Bytes"/> and <c>0</c> in <see cref="Mask"/>;
    /// a fixed byte reads as its value in <see cref="Bytes"/> and <c>0xFF</c> in <see cref="Mask"/>.
    /// </summary>
    /// <example>
    ///   <c>Pattern.Parse("e8 ?? ?? ?? 01 85 c0")</c>
    /// </example>
    /// <exception cref="ArgumentException">The spec contains an unparseable token.</exception>
    public static Pattern Parse(string spec)
    {
        ArgumentException.ThrowIfNullOrEmpty(spec);
        string[] tokens = spec.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        byte[] bytes = new byte[tokens.Length];
        byte[] mask = new byte[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            string tok = tokens[i];
            if (tok is "??" or "?")
            {
                bytes[i] = 0;
                mask[i] = 0;
            }
            else if (tok.Length == 2 && IsHex(tok[0]) && IsHex(tok[1]))
            {
                bytes[i] = (byte)((HexNibble(tok[0]) << 4) | HexNibble(tok[1]));
                mask[i] = 0xFF;
            }
            else
            {
                throw new ArgumentException($"'{tok}' is not a byte or wildcard.", nameof(spec));
            }
        }
        return new Pattern(bytes, mask);
    }

    private static bool IsHex(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    private static int HexNibble(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => 10 + (c - 'a'),
        >= 'A' and <= 'F' => 10 + (c - 'A'),
        _ => throw new ArgumentException($"'{c}' is not a hex digit.", nameof(c)),
    };
}

/// <summary>
/// Byte pattern matcher. Walks a buffer looking for the first occurrence of a masked pattern
/// and returns the offset, or <c>-1</c> when the pattern is not present.
/// </summary>
public static unsafe class PatternScan
{
    /// <summary>
    /// Returns the offset of the first match of <paramref name="pattern"/> inside the buffer
    /// pointed at by <paramref name="buffer"/> (with length <paramref name="length"/>), or
    /// <c>-1</c> when the pattern is not present. Matching starts at <paramref name="startOffset"/>.
    /// </summary>
    public static long Find(byte* buffer, long length, Pattern pattern, long startOffset = 0)
    {
        if (buffer == null || length <= 0)
            return -1;
        byte[] bytes = pattern.Bytes;
        byte[] mask = pattern.Mask;
        int patLen = bytes.Length;
        if (patLen == 0 || (long)patLen > length)
            return -1;

        long limit = length - patLen;
        for (long i = startOffset; i <= limit; i++)
        {
            int j = 0;
            while (j < patLen)
            {
                byte m = mask[j];
                if (m != 0 && (byte)(buffer[i + j] ^ bytes[j]) != 0)
                    break;
                j++;
            }
            if (j == patLen)
                return i;
        }
        return -1;
    }

    /// <summary>
    /// Returns the offset of the first match of the human-readable pattern <paramref name="spec"/>,
    /// or <c>-1</c> when no match is present. Convenience wrapper over <see cref="Find(byte*, long, Pattern, long)"/>.
    /// </summary>
    public static long Find(byte* buffer, long length, string spec, long startOffset = 0)
        => Find(buffer, length, Pattern.Parse(spec), startOffset);

    /// <summary>Counts every match of <paramref name="pattern"/> in the buffer.</summary>
    public static int CountMatches(byte* buffer, long length, Pattern pattern)
    {
        int count = 0;
        long offset = 0;
        while (true)
        {
            long hit = Find(buffer, length, pattern, offset);
            if (hit < 0)
                return count;
            count++;
            offset = hit + 1;
        }
    }
}
