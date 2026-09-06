// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.IO;
using SharpProspero.Payload.Kernel;
using System;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// Content identifier handling for the package mount path. The content ID is a 36-byte ASCII
/// string that identifies a package (<c>"UP9000-XXXX00000_00-PROSPERO00000000"</c>). The EKPFS
/// key derivation requires the content ID padded to 48 bytes with trailing zeros.
/// </summary>
/// <remarks>
/// <para>
/// The content ID for an installed title is stored in <c>/user/appmeta/TITLEID/param.json</c>
/// as the <c>"content_id"</c> JSON field. The system itself uses this path during install and
/// launch (visible in device logs as the <c>[ScePatchCache]</c> <c>contentId</c> value).
/// </para>
/// <para>
/// A payload that knows the title ID (compiled in from the package it was built for, or
/// received from the unjail daemon's request) can read this file to recover the full content
/// identifier without intercepting any kernel-side pointer (<c>ppkg_opt+0x48</c> is userland
/// but not reachable from a payload context).
/// </para>
/// </remarks>
public static unsafe class ContentIdCapture
{
    /// <summary>Length of a content identifier in bytes (ASCII, no null terminator).</summary>
    public const int ContentIdLength = 36;

    /// <summary>Padded length required by the EKPFS derivation. The SHA3-256 step hashes the
    /// content ID zero-padded to this length.</summary>
    public const int ContentIdPaddedLength = 48;

    /// <summary>Maximum number of bytes read from <c>param.json</c>. The file is typically a
    /// few hundred bytes; 4096 is well above any realistic size.</summary>
    private const int MaxParamJsonBytes = 4096;

    /// <summary>
    /// The JSON key whose value is the content identifier:
    /// <c>"content_id"</c>.
    /// </summary>
    private static ReadOnlySpan<byte> ContentIdKey => "\"content_id\""u8;

    /// <summary>
    /// Pads a 36-byte content identifier to 48 bytes by zeroing the remainder. The EKPFS
    /// derivation computes <c>SHA3-256(cid48)</c> over this padded form.
    /// </summary>
    /// <param name="contentId">The content identifier, at least
    /// <see cref="ContentIdLength"/> bytes.</param>
    /// <param name="padded">Destination span of at least
    /// <see cref="ContentIdPaddedLength"/> bytes. Bytes 0..35 receive the content
    /// identifier; bytes 36..47 are zeroed.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="contentId"/> has fewer than <see cref="ContentIdLength"/> bytes, or
    /// <paramref name="padded"/> has fewer than <see cref="ContentIdPaddedLength"/>
    /// bytes.
    /// </exception>
    public static void PadContentId(ReadOnlySpan<byte> contentId, Span<byte> padded)
    {
        if (contentId.Length < ContentIdLength)
            throw new ArgumentException(
                $"Content ID must be at least {ContentIdLength} bytes.", nameof(contentId));
        if (padded.Length < ContentIdPaddedLength)
            throw new ArgumentException(
                $"Padded buffer must be at least {ContentIdPaddedLength} bytes.", nameof(padded));

        padded[..ContentIdPaddedLength].Clear();
        contentId[..ContentIdLength].CopyTo(padded);
    }

    /// <summary>
    /// The debug/fpkg passcode: 32 ASCII <c>'0'</c> characters (<c>0x30</c>). All fake-signed
    /// packages use this fixed passcode for the EKPFS derivation.
    /// </summary>
    public static ReadOnlySpan<byte> DebugPasscode =>
    [
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    ];

    /// <summary>
    /// The default fpkg passcode: 32 ASCII <c>'0'</c> characters (<c>0x30</c>). Identical to
    /// <see cref="DebugPasscode"/>; this alias matches the naming used by the key derivation
    /// convenience methods.
    /// </summary>
    public static ReadOnlySpan<byte> DefaultPasscode => DebugPasscode;

    /// <summary>
    /// Reads the content identifier from <c>/user/appmeta/&lt;titleId&gt;/param.json</c>. The
    /// file is opened via <see cref="PayloadIo"/>, read in full (up to 4 KB), and scanned for
    /// the <c>"content_id"</c> JSON field. The 36-byte ASCII value is copied verbatim into
    /// <paramref name="contentId"/>.
    /// </summary>
    /// <param name="titleId">The nine-character title identifier (e.g. <c>PPSA99103</c>),
    /// encoded as UTF-8 bytes with no null terminator.</param>
    /// <param name="contentId">Destination span receiving the 36-byte content identifier on
    /// success. Must have at least <see cref="ContentIdLength"/> bytes of capacity.</param>
    /// <returns><see langword="true"/> when the file was read and the content identifier was
    /// extracted; <see langword="false"/> on any I/O failure, missing file, or if the JSON
    /// field is absent or shorter than 36 bytes.</returns>
    public static bool ReadFromParamJson(ReadOnlySpan<byte> titleId, Span<byte> contentId)
    {
        if (titleId.IsEmpty || contentId.Length < ContentIdLength)
            return false;

        // Build: /user/appmeta/<titleId>/param.json\0
        // Maximum path length: 15 + titleId.Length + 11 + 1 = 27 + titleId.Length
        byte* pathBuf = stackalloc byte[256];
        int pathLen = 0;

        pathLen = CopyTo(pathBuf, "/user/appmeta/"u8, pathLen);
        pathLen = CopyTo(pathBuf, titleId, pathLen);
        pathLen = CopyTo(pathBuf, "/param.json"u8, pathLen);
        pathBuf[pathLen] = 0;

        // Read the entire file into a stack buffer.
        byte* fileBuf = stackalloc byte[MaxParamJsonBytes];
        int fileLen = ReadFile(pathBuf, fileBuf, MaxParamJsonBytes);
        if (fileLen <= 0)
            return false;

        // Extract the content_id value from the JSON.
        return ExtractContentId(fileBuf, fileLen, contentId);
    }

    /// <summary>
    /// Reads the content identifier from <c>param.json</c> for <paramref name="titleId"/>,
    /// then derives the full PFS key set (AES-XTS tweak key, AES-XTS data key, and HMAC
    /// signing key) through the SHA3-256 + HMAC-SHA256 keyed-crypto ladder.
    /// </summary>
    /// <param name="titleId">The title identifier (e.g. <c>PPSA99103</c>).</param>
    /// <param name="passcode">The 32-byte passcode. Use <see cref="DefaultPasscode"/> for
    /// fake-signed packages.</param>
    /// <param name="cryptSeed">The 16-byte PFS superblock crypt seed.</param>
    /// <param name="tweakKey">Receives the 16-byte AES-XTS tweak key.</param>
    /// <param name="dataKey">Receives the 16-byte AES-XTS data key.</param>
    /// <param name="signKey">Receives the HMAC signing key (up to 32 bytes).</param>
    /// <returns><see langword="true"/> when the content identifier was read and keys were
    /// derived; <see langword="false"/> when <c>param.json</c> could not be read or the
    /// content identifier field is missing.</returns>
    public static bool ReadAndDeriveKeys(
        ReadOnlySpan<byte> titleId,
        ReadOnlySpan<byte> passcode,
        ReadOnlySpan<byte> cryptSeed,
        Span<byte> tweakKey,
        Span<byte> dataKey,
        Span<byte> signKey)
    {
        Span<byte> cid = stackalloc byte[ContentIdLength];
        if (!ReadFromParamJson(titleId, cid))
            return false;

        PayloadPfsCryptoPs5.DeriveKeysFromContentId(cid, passcode, cryptSeed,
            tweakKey, dataKey, signKey);
        return true;
    }

    // ---- Private helpers ----

    /// <summary>
    /// Opens and reads an entire file into <paramref name="buffer"/>, up to
    /// <paramref name="maxBytes"/> bytes.
    /// </summary>
    /// <returns>The number of bytes read, or 0 on any failure.</returns>
    private static int ReadFile(byte* pathZ, byte* buffer, int maxBytes)
    {
        int fd = PayloadIo.open(pathZ, PayloadFileSystem.O_RDONLY);
        if (fd < 0)
            return 0;

        int total = 0;
        while (total < maxBytes)
        {
            long n = PayloadIo.read(fd, buffer + total, (nuint)(maxBytes - total));
            if (n <= 0)
                break;
            total += (int)n;
        }

        PayloadIo.close(fd);
        return total;
    }

    /// <summary>
    /// Scans a JSON buffer for <c>"content_id":"VALUE"</c> and copies up to
    /// <see cref="ContentIdLength"/> bytes of VALUE into <paramref name="contentId"/>.
    /// </summary>
    /// <remarks>
    /// The parser is intentionally minimal: it searches for the byte sequence
    /// <c>"content_id"</c>, skips any whitespace and the <c>:</c> separator, then reads the
    /// quoted string value. No full JSON grammar is needed because <c>param.json</c> is a
    /// small, well-formed file produced by the system install pipeline.
    /// </remarks>
    private static bool ExtractContentId(byte* buf, int len, Span<byte> contentId)
    {
        ReadOnlySpan<byte> key = ContentIdKey;
        int keyLen = key.Length;

        // Find the key in the buffer.
        int pos = FindSequence(buf, len, key);
        if (pos < 0)
            return false;

        // Advance past the key.
        pos += keyLen;

        // Skip whitespace.
        while (pos < len && IsJsonWhitespace(buf[pos]))
            pos++;

        // Expect ':'.
        if (pos >= len || buf[pos] != (byte)':')
            return false;
        pos++;

        // Skip whitespace after ':'.
        while (pos < len && IsJsonWhitespace(buf[pos]))
            pos++;

        // Expect opening '"'.
        if (pos >= len || buf[pos] != (byte)'"')
            return false;
        pos++;

        // Read the value until the closing '"'.
        int valueStart = pos;
        while (pos < len && buf[pos] != (byte)'"')
            pos++;

        int valueLen = pos - valueStart;
        if (valueLen < ContentIdLength)
            return false;

        // Copy exactly ContentIdLength bytes of the value.
        for (int i = 0; i < ContentIdLength; i++)
            contentId[i] = buf[valueStart + i];

        return true;
    }

    /// <summary>
    /// Finds the first occurrence of <paramref name="needle"/> in the byte buffer.
    /// </summary>
    /// <returns>The zero-based index of the first match, or -1 if not found.</returns>
    private static int FindSequence(byte* haystack, int haystackLen, ReadOnlySpan<byte> needle)
    {
        int needleLen = needle.Length;
        if (needleLen == 0 || needleLen > haystackLen)
            return -1;

        int limit = haystackLen - needleLen;
        for (int i = 0; i <= limit; i++)
        {
            bool match = true;
            for (int j = 0; j < needleLen; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return i;
        }

        return -1;
    }

    /// <summary>
    /// Returns <see langword="true"/> for JSON insignificant whitespace characters:
    /// space, horizontal tab, newline, and carriage return.
    /// </summary>
    private static bool IsJsonWhitespace(byte b)
        => b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D;

    /// <summary>
    /// Copies <paramref name="src"/> into <paramref name="dst"/> starting at
    /// <paramref name="offset"/>. Returns the new offset past the copied bytes.
    /// </summary>
    private static int CopyTo(byte* dst, ReadOnlySpan<byte> src, int offset)
    {
        for (int i = 0; i < src.Length; i++)
            dst[offset + i] = src[i];
        return offset + src.Length;
    }
}
