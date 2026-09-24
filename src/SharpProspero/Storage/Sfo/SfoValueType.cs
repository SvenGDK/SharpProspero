// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Storage.Sfo;

/// <summary>
/// Identifies the data format of an SFO parameter entry.
/// </summary>
public enum SfoValueType : ushort
{
    /// <summary>Raw byte array.</summary>
    Bytes = 0x0004,

    /// <summary>UTF-8 NUL-terminated string.</summary>
    String = 0x0204,

    /// <summary>Signed 32-bit integer (little-endian).</summary>
    Int32 = 0x0404,
}
