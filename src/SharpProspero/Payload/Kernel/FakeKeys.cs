// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Manages the fake-key registry within the kernel shared area. Each slot holds
/// 32 bytes of key material. Allocation uses the bitmask/ready_mask fields:
/// a bit set in <c>Bitmask</c> means the slot is claimed; a bit set in
/// <c>ReadyMask</c> means the slot contains valid data.
/// </summary>
public static unsafe class PayloadFakeKeys
{
    /// <summary>Byte offset of the <c>key_data</c> array from the start of the shared area
    /// (bitmask[8] + ready_mask[8] + pad[16] = 32).</summary>
    private const int KeyDataOffset = 32;

    /// <summary>Size of each key slot in bytes.</summary>
    private const int KeySize = KstuffSharedAreaConstants.FakeKeySize;

    /// <summary>Maximum number of key slots.</summary>
    private const int MaxSlots = KstuffSharedAreaConstants.FakeKeySlots;

    /// <summary>
    /// Reads the shared area header from the given kernel address.
    /// </summary>
    public static KstuffSharedArea ReadSharedArea(PayloadKernelIo io, ulong sharedAreaAddr)
    {
        KstuffSharedArea area;
        io.Read(sharedAreaAddr, (byte*)&area, sizeof(KstuffSharedArea));
        return area;
    }

    /// <summary>
    /// Returns the number of registered (ready) fake keys.
    /// </summary>
    public static int GetKeyCount(KstuffSharedArea area)
    {
        return BitCount(area.ReadyMask);
    }

    /// <summary>
    /// Checks whether a key slot contains valid data.
    /// </summary>
    public static bool HasFakeKey(KstuffSharedArea area, int index)
    {
        if (index < 0 || index >= MaxSlots) return false;
        return (area.ReadyMask & (1UL << index)) != 0;
    }

    /// <summary>
    /// Registers a 32-byte fake key in the shared area by finding a free slot,
    /// writing the key data, and setting the ready bit. Returns the slot index
    /// or -1 if no free slot is available.
    /// </summary>
    public static int RegisterFakeKey(PayloadKernelIo io, ulong sharedAreaAddr,
        ReadOnlySpan<byte> keyData)
    {
        if (keyData.Length < KeySize) return -1;

        // Read current bitmask to find a free slot
        ulong bitmask = io.ReadU64(sharedAreaAddr);
        int slot = FindFreeSlot(bitmask);
        if (slot < 0) return -1;

        ulong bit = 1UL << slot;

        // Claim the slot in bitmask
        io.WriteU64(sharedAreaAddr, bitmask | bit);

        // Write key data
        ulong keyAddr = sharedAreaAddr + KeyDataOffset + (ulong)(slot * KeySize);
        fixed (byte* p = keyData)
            io.Write(keyAddr, p, KeySize);

        // Set the ready bit
        ulong readyMask = io.ReadU64(sharedAreaAddr + 8);
        io.WriteU64(sharedAreaAddr + 8, readyMask | bit);

        return slot;
    }

    /// <summary>
    /// Unregisters a fake key by clearing its ready and bitmask bits.
    /// </summary>
    public static void UnregisterFakeKey(PayloadKernelIo io, ulong sharedAreaAddr, int index)
    {
        if (index < 0 || index >= MaxSlots) return;
        ulong bit = 1UL << index;

        // Clear ready_mask first
        ulong readyMask = io.ReadU64(sharedAreaAddr + 8);
        io.WriteU64(sharedAreaAddr + 8, readyMask & ~bit);

        // Clear bitmask
        ulong bitmask = io.ReadU64(sharedAreaAddr);
        io.WriteU64(sharedAreaAddr, bitmask & ~bit);
    }

    /// <summary>
    /// Reads a 32-byte fake key from the given slot.
    /// </summary>
    public static void GetFakeKey(PayloadKernelIo io, ulong sharedAreaAddr,
        int index, Span<byte> keyData)
    {
        if (index < 0 || index >= MaxSlots) return;
        ulong keyAddr = sharedAreaAddr + KeyDataOffset + (ulong)(index * KeySize);
        fixed (byte* p = keyData)
            io.Read(keyAddr, p, KeySize);
    }

    /// <summary>
    /// Writes a 32-byte fake key into a slot that is already allocated.
    /// </summary>
    public static void WriteFakeKey(PayloadKernelIo io, ulong sharedAreaAddr,
        int index, ReadOnlySpan<byte> keyData)
    {
        if (index < 0 || index >= MaxSlots) return;
        ulong keyAddr = sharedAreaAddr + KeyDataOffset + (ulong)(index * KeySize);
        fixed (byte* p = keyData)
            io.Write(keyAddr, p, Math.Min(keyData.Length, KeySize));
    }

    /// <summary>
    /// Finds the first free slot index in the bitmask, or -1 if all 63 slots are taken.
    /// </summary>
    private static int FindFreeSlot(ulong bitmask)
    {
        // The bitmask uses bits 0..62 (63 slots). Find the lowest clear bit.
        ulong available = ~bitmask & ((1UL << MaxSlots) - 1);
        if (available == 0) return -1;
        return TrailingZeroCount(available);
    }

    private static int BitCount(ulong v)
    {
        int c = 0;
        while (v != 0) { v &= v - 1; c++; }
        return c;
    }

    private static int TrailingZeroCount(ulong v)
    {
        if (v == 0) return 64;
        int c = 0;
        while ((v & 1) == 0) { v >>= 1; c++; }
        return c;
    }
}
