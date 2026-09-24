// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Text;

namespace SharpProspero.Storage.Sfo;

/// <summary>
/// Represents one key-value parameter in an SFO file. Each entry has a string key,
/// a typed value (string, integer, or raw bytes), and a maximum length for the data slot.
/// </summary>
public sealed class SfoEntry
{
    /// <summary>The parameter key (ASCII identifier such as "TITLE_ID" or "APP_VER").</summary>
    public string Key { get; set; } = "";

    /// <summary>The data format of this entry.</summary>
    public SfoValueType ValueType { get; set; }

    /// <summary>The raw parameter bytes as stored in the data table.</summary>
    public byte[] RawValue { get; set; } = [];

    /// <summary>The maximum length of the data field in the SFO table.</summary>
    public uint MaxLength { get; set; }

    /// <summary>
    /// Gets or sets the parameter value as a UTF-8 string. Reading strips the trailing
    /// NUL terminator. Writing appends a NUL terminator and grows <see cref="MaxLength"/>
    /// when the encoded value exceeds it.
    /// </summary>
    public string StringValue
    {
        get
        {
            if (ValueType != SfoValueType.String || RawValue.Length == 0)
                return "";
            int len = RawValue.Length;
            if (len > 0 && RawValue[len - 1] == 0)
                len--;
            return Encoding.UTF8.GetString(RawValue, 0, len);
        }
        set
        {
            byte[] encoded = Encoding.UTF8.GetBytes(value);
            RawValue = new byte[encoded.Length + 1];
            Array.Copy(encoded, RawValue, encoded.Length);
            RawValue[encoded.Length] = 0;
            if ((uint)RawValue.Length > MaxLength)
                MaxLength = (uint)RawValue.Length;
        }
    }

    /// <summary>
    /// Gets or sets the parameter value as a signed 32-bit integer (little-endian).
    /// Returns <c>0</c> when the entry is not of type <see cref="SfoValueType.Int32"/>
    /// or the raw data is shorter than four bytes.
    /// </summary>
    public int Int32Value
    {
        get
        {
            if (ValueType != SfoValueType.Int32 || RawValue.Length < 4)
                return 0;
            return RawValue[0] | (RawValue[1] << 8) | (RawValue[2] << 16) | (RawValue[3] << 24);
        }
        set
        {
            RawValue = [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];
        }
    }
}
