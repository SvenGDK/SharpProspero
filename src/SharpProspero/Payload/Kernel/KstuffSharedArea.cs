// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Maximum number of fake key slots in the shared area.
/// </summary>
public static class KstuffSharedAreaConstants
{
    /// <summary>Number of fake key slots.</summary>
    public const int FakeKeySlots = 63;

    /// <summary>Size of each fake key (bytes).</summary>
    public const int FakeKeySize = 32;

    /// <summary>Total shared area size (non-observability build).</summary>
    public const int SharedAreaSize = 2048;
}

/// <summary>
/// Shared area structure for communication between the kernel payload and userspace.
/// Layout:
/// <list type="bullet">
///   <item><c>bitmask</c> (8 bytes) - allocation bitmask for fake key slots.</item>
///   <item><c>ready_mask</c> (8 bytes) - readiness bitmask (slot data is valid).</item>
///   <item><c>pad[16]</c> (16 bytes) - reserved padding.</item>
///   <item><c>key_data[63][32]</c> (2016 bytes) - 63 fake key slots, 32 bytes each.</item>
/// </list>
/// Total: 2048 bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct KstuffSharedArea
{
    /// <summary>Allocation bitmask for fake key slots. Each bit represents one slot;
    /// a set bit means the slot index is claimed (may or may not be ready).</summary>
    public ulong Bitmask;

    /// <summary>Readiness bitmask. A set bit means the corresponding slot in
    /// <see cref="KeyData"/> contains valid key material and can be read.</summary>
    public ulong ReadyMask;

    /// <summary>Reserved padding (16 bytes).</summary>
    public fixed byte Pad[16];

    /// <summary>Fake key data: 63 slots of 32 bytes each (2016 bytes total).
    /// Indexed as <c>KeyData[slotIndex * 32 .. (slotIndex + 1) * 32]</c>.</summary>
    public fixed byte KeyData[KstuffSharedAreaConstants.FakeKeySlots * KstuffSharedAreaConstants.FakeKeySize];
}
