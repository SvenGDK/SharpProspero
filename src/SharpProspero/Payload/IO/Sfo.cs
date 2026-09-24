// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Payload.IO;

/// <summary>
/// SFO file header. The magic bytes are <c>\0PSF</c> (read as little-endian <c>0x46535000</c>).
/// </summary>
/// <remarks>
/// For a managed reader/writer that supports round-trip editing, see
/// <see cref="Storage.Sfo.SfoFile"/>.
/// </remarks>
[StructLayout(LayoutKind.Sequential, Size = 20)]
public struct SfoHeader
{
    /// <summary>Magic value: <c>0x46535000</c> (bytes <c>\0PSF</c> in little-endian).</summary>
    public uint Magic;

    /// <summary>Format version (typically <c>0x00000101</c>).</summary>
    public uint Version;

    /// <summary>Absolute offset to the key table.</summary>
    public uint KeyTableOffset;

    /// <summary>Absolute offset to the data table.</summary>
    public uint DataTableOffset;

    /// <summary>Number of entries in the index table.</summary>
    public uint EntryCount;
}

/// <summary>
/// One entry in the SFO index table, describing a key-value pair.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SfoEntry
{
    /// <summary>Offset of the key string relative to the key table.</summary>
    public ushort KeyOffset;

    /// <summary>Data format: <c>0x0004</c> (special string), <c>0x0204</c> (UTF-8 string),
    /// <c>0x0404</c> (signed 32-bit integer).</summary>
    public ushort ParamFormat;

    /// <summary>Actual length of the data (including NUL for strings).</summary>
    public uint ParamLength;

    /// <summary>Maximum length of the data field.</summary>
    public uint ParamMaxLength;

    /// <summary>Offset of the data relative to the data table.</summary>
    public uint DataOffset;
}

/// <summary>Parameter data formats used in <see cref="SfoEntry.ParamFormat"/>.</summary>
public static class SfoParamFormat
{
    /// <summary>Special mode string.</summary>
    public const ushort SpecialString = 0x0004;

    /// <summary>UTF-8 NUL-terminated string.</summary>
    public const ushort Utf8String = 0x0204;

    /// <summary>Signed 32-bit integer.</summary>
    public const ushort Int32 = 0x0404;
}

/// <summary>
/// Reads a <c>param.sfo</c> binary file in place from a byte buffer. The reader does not
/// allocate or copy; it returns pointers and spans into the original buffer.
/// </summary>
/// <remarks>
/// The SFO format stores application metadata (title id, title name, application version, etc.)
/// as a flat key-value table. The file begins with a 20-byte <see cref="SfoHeader"/>, followed by
/// an array of 16-byte <see cref="SfoEntry"/> records, then the key string table and the data
/// table. For a managed reader/writer that supports round-trip editing, see
/// <see cref="Storage.Sfo.SfoFile"/>.
/// </remarks>
public readonly unsafe ref struct SfoReader
{
    /// <summary>SFO magic value: bytes <c>\0PSF</c> read as little-endian <see cref="uint"/>.</summary>
    public const uint Magic = 0x46535000;

    private readonly byte* _data;
    private readonly int _length;
    private readonly SfoHeader* _header;

    /// <summary>
    /// Wraps a buffer containing a complete SFO file.
    /// </summary>
    /// <param name="data">Pointer to the start of the SFO data.</param>
    /// <param name="length">Total length of the buffer in bytes.</param>
    public SfoReader(byte* data, int length)
    {
        _data = data;
        _length = length;
        _header = (SfoHeader*)data;
    }

    /// <summary>Returns <c>true</c> when the buffer begins with the SFO magic.</summary>
    public bool IsValid => _length >= sizeof(SfoHeader) && _header->Magic == Magic;

    /// <summary>Number of entries in the file.</summary>
    public int EntryCount => IsValid ? (int)_header->EntryCount : 0;

    /// <summary>Returns a pointer to the entry at <paramref name="index"/>.</summary>
    public SfoEntry* GetEntry(int index)
    {
        if ((uint)index >= _header->EntryCount)
            return null;
        return (SfoEntry*)(_data + sizeof(SfoHeader) + index * sizeof(SfoEntry));
    }

    /// <summary>
    /// Returns a read-only span over the NUL-terminated key string for the given entry.
    /// The span does not include the terminating NUL.
    /// </summary>
    public ReadOnlySpan<byte> GetKey(SfoEntry* entry)
    {
        byte* start = _data + _header->KeyTableOffset + entry->KeyOffset;
        int len = 0;
        while (start[len] != 0 && (_header->KeyTableOffset + entry->KeyOffset + len) < (uint)_length)
            len++;
        return new ReadOnlySpan<byte>(start, len);
    }

    /// <summary>
    /// Returns a read-only span over the raw data for the given entry.
    /// </summary>
    public ReadOnlySpan<byte> GetData(SfoEntry* entry)
    {
        byte* start = _data + _header->DataTableOffset + entry->DataOffset;
        return new ReadOnlySpan<byte>(start, (int)entry->ParamLength);
    }

    /// <summary>
    /// Reads the data as a UTF-8 string (strips the trailing NUL if present).
    /// </summary>
    public ReadOnlySpan<byte> GetString(SfoEntry* entry)
    {
        ReadOnlySpan<byte> raw = GetData(entry);
        if (raw.Length > 0 && raw[raw.Length - 1] == 0)
            raw = raw.Slice(0, raw.Length - 1);
        return raw;
    }

    /// <summary>
    /// Reads the data as a signed 32-bit integer.
    /// </summary>
    public int GetInt32(SfoEntry* entry)
    {
        byte* start = _data + _header->DataTableOffset + entry->DataOffset;
        return *(int*)start;
    }

    /// <summary>
    /// Finds the first entry whose key matches <paramref name="key"/> (byte-exact comparison).
    /// Returns null when no match is found.
    /// </summary>
    public SfoEntry* FindEntry(ReadOnlySpan<byte> key)
    {
        for (int i = 0; i < EntryCount; i++)
        {
            SfoEntry* entry = GetEntry(i);
            if (GetKey(entry).SequenceEqual(key))
                return entry;
        }
        return null;
    }

    /// <summary>
    /// Reads the value of the entry whose key matches <paramref name="key"/> as a UTF-8 string.
    /// Returns an empty span when the key is not found.
    /// </summary>
    public ReadOnlySpan<byte> GetStringByKey(ReadOnlySpan<byte> key)
    {
        SfoEntry* entry = FindEntry(key);
        if (entry == null)
            return ReadOnlySpan<byte>.Empty;
        return GetString(entry);
    }

    /// <summary>
    /// Reads the value of the entry whose key matches <paramref name="key"/> as a 32-bit integer.
    /// Returns <paramref name="defaultValue"/> when the key is not found.
    /// </summary>
    public int GetInt32ByKey(ReadOnlySpan<byte> key, int defaultValue = 0)
    {
        SfoEntry* entry = FindEntry(key);
        if (entry == null)
            return defaultValue;
        return GetInt32(entry);
    }
}
