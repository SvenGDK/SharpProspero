// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;
using System.Text;

namespace SharpProspero.Storage.Sfo;

/// <summary>
/// Reads, modifies, and writes SFO (<c>param.sfo</c>) parameter files.
/// The SFO format stores application metadata as a flat key-value table with a 20-byte header,
/// an array of 16-byte index entries, a NUL-terminated key string table, and a data table.
/// </summary>
/// <remarks>
/// For a zero-allocation in-place reader suitable for payload contexts, see
/// <see cref="Payload.IO.SfoReader"/>.
/// </remarks>
public sealed class SfoFile
{
    /// <summary>SFO magic: bytes <c>\0PSF</c> read as a little-endian <see cref="uint"/>.</summary>
    public const uint Magic = 0x46535000;

    /// <summary>Format version: bytes <c>0x01 0x01 0x00 0x00</c> read as little-endian.</summary>
    public const uint Version = 0x00000101;

    /// <summary>Maximum number of entries accepted when reading (sanity guard).</summary>
    private const uint MaxEntryCount = 1024;

    /// <summary>The parameter entries in this SFO file, in index-table order.</summary>
    public List<SfoEntry> Entries { get; } = [];

    /// <summary>
    /// Returns the string value of the first entry whose key matches <paramref name="key"/>,
    /// or <c>null</c> when no matching string entry exists.
    /// </summary>
    /// <param name="key">The parameter key to look up.</param>
    /// <returns>The string value, or <c>null</c>.</returns>
    public string? GetString(string key)
    {
        foreach (SfoEntry entry in Entries)
        {
            if (entry.Key == key && entry.ValueType == SfoValueType.String)
                return entry.StringValue;
        }
        return null;
    }

    /// <summary>
    /// Returns the integer value of the first entry whose key matches <paramref name="key"/>,
    /// or <paramref name="defaultValue"/> when no matching integer entry exists.
    /// </summary>
    /// <param name="key">The parameter key to look up.</param>
    /// <param name="defaultValue">Value returned when the key is absent.</param>
    /// <returns>The integer value, or <paramref name="defaultValue"/>.</returns>
    public int GetInt32(string key, int defaultValue = 0)
    {
        foreach (SfoEntry entry in Entries)
        {
            if (entry.Key == key && entry.ValueType == SfoValueType.Int32)
                return entry.Int32Value;
        }
        return defaultValue;
    }

    /// <summary>
    /// Returns the raw byte value of the first entry whose key matches <paramref name="key"/>,
    /// or <c>null</c> when no matching byte-type entry exists.
    /// </summary>
    /// <param name="key">The parameter key to look up.</param>
    /// <returns>The raw bytes, or <c>null</c>.</returns>
    public byte[]? GetBytes(string key)
    {
        foreach (SfoEntry entry in Entries)
        {
            if (entry.Key == key && entry.ValueType == SfoValueType.Bytes)
                return entry.RawValue;
        }
        return null;
    }

    /// <summary>
    /// Sets or adds a UTF-8 string parameter. Entries are kept in ascending key order.
    /// When <paramref name="maxLength"/> is zero the maximum length is derived from the
    /// encoded value (or the current maximum, whichever is larger).
    /// </summary>
    /// <param name="key">The parameter key.</param>
    /// <param name="value">The string value to store.</param>
    /// <param name="maxLength">Explicit maximum data length, or zero to auto-size.</param>
    public void SetString(string key, string value, uint maxLength = 0)
    {
        foreach (SfoEntry entry in Entries)
        {
            if (entry.Key == key)
            {
                entry.ValueType = SfoValueType.String;
                entry.StringValue = value;
                if (maxLength > 0)
                    entry.MaxLength = maxLength;
                return;
            }
        }
        byte[] encoded = Encoding.UTF8.GetBytes(value);
        uint ml = maxLength > 0 ? maxLength : (uint)(encoded.Length + 1);
        var newEntry = new SfoEntry
        {
            Key = key,
            ValueType = SfoValueType.String,
            MaxLength = ml,
        };
        newEntry.StringValue = value;
        InsertSorted(newEntry);
    }

    /// <summary>
    /// Sets or adds a 32-bit integer parameter. Entries are kept in ascending key order.
    /// </summary>
    /// <param name="key">The parameter key.</param>
    /// <param name="value">The integer value to store.</param>
    public void SetInt32(string key, int value)
    {
        foreach (SfoEntry entry in Entries)
        {
            if (entry.Key == key)
            {
                entry.ValueType = SfoValueType.Int32;
                entry.Int32Value = value;
                return;
            }
        }
        var newEntry = new SfoEntry
        {
            Key = key,
            ValueType = SfoValueType.Int32,
            MaxLength = 4,
        };
        newEntry.Int32Value = value;
        InsertSorted(newEntry);
    }

    /// <summary>
    /// Inserts an entry in ascending key order (ordinal comparison).
    /// </summary>
    private void InsertSorted(SfoEntry newEntry)
    {
        for (int i = 0; i < Entries.Count; i++)
        {
            if (string.Compare(Entries[i].Key, newEntry.Key, StringComparison.Ordinal) > 0)
            {
                Entries.Insert(i, newEntry);
                return;
            }
        }
        Entries.Add(newEntry);
    }

    /// <summary>
    /// Parses an SFO file from a byte buffer. Returns <c>null</c> when the buffer is
    /// too small, the magic does not match, or any entry offset falls outside the buffer.
    /// Unknown parameter formats are preserved as raw bytes.
    /// </summary>
    /// <param name="data">The complete SFO file contents.</param>
    /// <returns>The parsed <see cref="SfoFile"/>, or <c>null</c> on failure.</returns>
    public static SfoFile? Read(byte[] data)
    {
        if (data.Length < 20)
            return null;

        uint magic = ReadUInt32(data, 0);
        if (magic != Magic)
            return null;

        uint keyTableOffset = ReadUInt32(data, 8);
        uint dataTableOffset = ReadUInt32(data, 12);
        uint entryCount = ReadUInt32(data, 16);

        if (entryCount > MaxEntryCount)
            return null;

        var sfo = new SfoFile();

        for (uint i = 0; i < entryCount; i++)
        {
            int indexOffset = 20 + (int)(i * 16);
            if (indexOffset + 16 > data.Length)
                return null;

            ushort keyOffset = ReadUInt16(data, indexOffset);
            ushort paramFormat = ReadUInt16(data, indexOffset + 2);
            uint paramLength = ReadUInt32(data, indexOffset + 4);
            uint paramMaxLength = ReadUInt32(data, indexOffset + 8);
            uint dataOffset = ReadUInt32(data, indexOffset + 12);

            // Validate that the key offset falls within the buffer.
            long keyStartLong = (long)keyTableOffset + keyOffset;
            if (keyStartLong < 0 || keyStartLong >= data.Length)
                return null;
            int keyStart = (int)keyStartLong;

            int keyEnd = keyStart;
            while (keyEnd < data.Length && data[keyEnd] != 0)
                keyEnd++;
            string key = Encoding.UTF8.GetString(data, keyStart, keyEnd - keyStart);

            // Validate that the data offset falls within the buffer.
            long dataStartLong = (long)dataTableOffset + dataOffset;
            if (dataStartLong < 0 || dataStartLong > data.Length)
                return null;
            int dataStart = (int)dataStartLong;

            int dataLen = (int)Math.Min(paramLength, (uint)(data.Length - dataStart));
            if (dataLen < 0)
                dataLen = 0;

            byte[] rawValue = new byte[dataLen];
            if (dataLen > 0)
                Array.Copy(data, dataStart, rawValue, 0, dataLen);

            sfo.Entries.Add(new SfoEntry
            {
                Key = key,
                ValueType = (SfoValueType)paramFormat,
                RawValue = rawValue,
                MaxLength = paramMaxLength,
            });
        }

        return sfo;
    }

    /// <summary>
    /// Reads an SFO file from the filesystem. Returns <c>null</c> when the file does not exist
    /// or cannot be parsed.
    /// </summary>
    /// <param name="path">Absolute filesystem path to the SFO file.</param>
    /// <returns>The parsed <see cref="SfoFile"/>, or <c>null</c>.</returns>
    public static SfoFile? ReadFromFile(string path)
    {
        if (!FileSystem.Exists(path))
            return null;
        byte[] data = FileSystem.ReadAllBytes(path);
        return Read(data);
    }

    /// <summary>
    /// Serializes this SFO to a byte array. The output contains a valid SFO header, index table,
    /// key table, and data table. The <c>paramLength</c> field is clamped to
    /// <c>min(RawValue.Length, MaxLength)</c> so data never overflows its slot.
    /// </summary>
    /// <returns>The serialized SFO bytes.</returns>
    public byte[] Write()
    {
        int indexTableSize = Entries.Count * 16;
        int keyTableSize = 0;
        foreach (SfoEntry entry in Entries)
        {
            keyTableSize += Encoding.UTF8.GetByteCount(entry.Key) + 1;
        }
        int keyTablePadded = Align4(keyTableSize);

        int dataTableSize = 0;
        foreach (SfoEntry entry in Entries)
        {
            dataTableSize += (int)entry.MaxLength;
        }

        uint keyTableOffset = (uint)(20 + indexTableSize);
        uint dataTableOffset = (uint)(20 + indexTableSize + keyTablePadded);
        int totalSize = (int)(dataTableOffset + dataTableSize);

        byte[] output = new byte[totalSize];

        WriteUInt32(output, 0, Magic);
        WriteUInt32(output, 4, Version);
        WriteUInt32(output, 8, keyTableOffset);
        WriteUInt32(output, 12, dataTableOffset);
        WriteUInt32(output, 16, (uint)Entries.Count);

        int keyPos = 0;
        int dataPos = 0;

        for (int i = 0; i < Entries.Count; i++)
        {
            SfoEntry entry = Entries[i];
            int indexOffset = 20 + (i * 16);

            WriteUInt16(output, indexOffset, (ushort)keyPos);
            WriteUInt16(output, indexOffset + 2, (ushort)entry.ValueType);

            // Clamp paramLength so it never exceeds MaxLength.
            uint paramLength = Math.Min((uint)entry.RawValue.Length, entry.MaxLength);
            WriteUInt32(output, indexOffset + 4, paramLength);
            WriteUInt32(output, indexOffset + 8, entry.MaxLength);
            WriteUInt32(output, indexOffset + 12, (uint)dataPos);

            byte[] keyBytes = Encoding.UTF8.GetBytes(entry.Key);
            Array.Copy(keyBytes, 0, output, (int)keyTableOffset + keyPos, keyBytes.Length);
            output[(int)keyTableOffset + keyPos + keyBytes.Length] = 0;
            keyPos += keyBytes.Length + 1;

            int copyLen = (int)Math.Min((uint)entry.RawValue.Length, entry.MaxLength);
            if (copyLen > 0)
                Array.Copy(entry.RawValue, 0, output, (int)dataTableOffset + dataPos, copyLen);
            dataPos += (int)entry.MaxLength;
        }

        return output;
    }

    /// <summary>
    /// Writes this SFO to a file on the filesystem.
    /// </summary>
    /// <param name="path">Absolute filesystem path for the output file.</param>
    public void WriteToFile(string path) => FileSystem.WriteAllBytes(path, Write());

    private static uint ReadUInt32(byte[] data, int offset) =>
        (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));

    private static ushort ReadUInt16(byte[] data, int offset) =>
        (ushort)(data[offset] | (data[offset + 1] << 8));

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
        data[offset + 2] = (byte)(value >> 16);
        data[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
    }

    private static int Align4(int value) => (value + 3) & ~3;
}
