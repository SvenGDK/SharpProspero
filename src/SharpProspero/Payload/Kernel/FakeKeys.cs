// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Numerics;

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

    /// <summary>User-mode registration lock. The pipe-based kernel I/O offers no
    /// atomic compare-and-swap primitive, so a write-then-verify pattern cannot
    /// distinguish two concurrent callers claiming the same free slot from a
    /// single caller writing twice — both readbacks succeed identically. This
    /// lock serialises every user-mode <see cref="RegisterFakeKey"/> and
    /// <see cref="UnregisterFakeKey"/> so a single caller owns the bitmask +
    /// ready_mask + key-data write for the duration of the transaction. Kernel-
    /// side handlers only read these fields, so the lock is sufficient.
    /// </summary>
    private static readonly object s_registrationLock = new();

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
    /// <remarks>
    /// All writes happen under <see cref="s_registrationLock"/> so two
    /// concurrent callers cannot claim the same free slot: without the lock a
    /// write-then-verify pattern would let both writers compute the same
    /// desired bitmask, both see their own bit land, both write different key
    /// bytes to the same slot, and one caller's key would silently overwrite
    /// the other's. The pipe primitive offers no atomic compare-and-swap, so
    /// serialisation is the only correct answer.
    /// </remarks>
    public static int RegisterFakeKey(PayloadKernelIo io, ulong sharedAreaAddr,
        ReadOnlySpan<byte> keyData)
    {
        if (keyData.Length < KeySize) return -1;

        lock (s_registrationLock)
        {
            ulong bitmask = io.ReadU64(sharedAreaAddr);
            int slot = FindFreeSlot(bitmask);
            if (slot < 0) return -1;

            ulong bit = 1UL << slot;

            // Claim the slot in the bitmask before we touch the key data so a
            // concurrent unregister on a different slot cannot fight our write.
            io.WriteU64(sharedAreaAddr, bitmask | bit);

            // Write key data before publishing the ready bit so any consumer
            // that sees the ready bit set is guaranteed to observe fully-
            // written key material through the pipe-copyin ordering.
            ulong keyAddr = sharedAreaAddr + KeyDataOffset + (ulong)(slot * KeySize);
            fixed (byte* p = keyData)
                io.Write(keyAddr, p, KeySize);

            // Publish readiness last.
            ulong readyMask = io.ReadU64(sharedAreaAddr + 8);
            io.WriteU64(sharedAreaAddr + 8, readyMask | bit);
            return slot;
        }
    }

    /// <summary>
    /// Unregisters a fake key by clearing its ready and bitmask bits.
    /// </summary>
    /// <remarks>
    /// Serialised under <see cref="s_registrationLock"/> to match the
    /// invariant established by <see cref="RegisterFakeKey"/>.
    /// </remarks>
    public static void UnregisterFakeKey(PayloadKernelIo io, ulong sharedAreaAddr, int index)
    {
        if (index < 0 || index >= MaxSlots) return;
        ulong bit = 1UL << index;

        lock (s_registrationLock)
        {
            // Clear ready_mask first so consumers stop selecting this slot
            // before the underlying storage becomes reusable.
            ulong readyMask = io.ReadU64(sharedAreaAddr + 8);
            if ((readyMask & bit) != 0)
                io.WriteU64(sharedAreaAddr + 8, readyMask & ~bit);

            ulong bitmask = io.ReadU64(sharedAreaAddr);
            if ((bitmask & bit) != 0)
                io.WriteU64(sharedAreaAddr, bitmask & ~bit);
        }
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

    private static int BitCount(ulong v) => BitOperations.PopCount(v);

    private static int TrailingZeroCount(ulong v) => v == 0 ? 64 : BitOperations.TrailingZeroCount(v);
}
