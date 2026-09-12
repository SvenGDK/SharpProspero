// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Kernel;
using System;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// Layout constants for the <c>verifyImage</c> SP mailbox command (opcode 1). The kernel's
/// PFS mount worker (<c>verify_ppr_sblock_100</c>) builds an 0x80-byte request buffer at
/// <c>regs[RDX]</c>, submits it through <c>sceSblServiceMailbox</c>, and reads response
/// fields from the same buffer.
/// </summary>
/// <remarks>
/// <para>
/// The buffer serves dual purpose: the kernel fills request fields before the mailbox call,
/// and the secure processor (or an emulator) overwrites specific offsets with response data.
/// After the mailbox returns, the kernel reads back <c>+0x04</c> (status), <c>+0x08</c>
/// (encryption key handle), <c>+0x0C</c> (signing key handle), <c>+0x4C</c> (echo value
/// returned to the caller), and <c>+0x54</c> (byte-swap trip count).
/// </para>
/// <para>
/// The byte-swap field at <c>+0x54</c> is the most dangerous: a non-zero value causes the
/// kernel to iterate <c>value &gt;&gt; 3</c> times over the caller's <c>param_3</c> buffer
/// doing 8-byte endian swaps. On the ppr path, <c>param_3</c> is a kernel pointer and
/// <c>+0x54</c> inherits the high dword of that pointer (e.g. <c>0xffffdfa6</c>), producing
/// a 0x1FFFFFFF-iteration loop that dereferences address zero. Any emulation must zero the
/// entire 0x80-byte buffer before writing response fields.
/// </para>
/// </remarks>
public static class VerifyImageMailbox
{
    /// <summary>Total size of the mailbox request/response buffer in bytes.</summary>
    public const int RequestSize = 0x80;

    /// <summary>Offset of the mailbox opcode (uint32). Value 1 selects
    /// <c>verifyImage</c>.</summary>
    public const int OffsetOpcode = 0x00;

    /// <summary>Offset of the status word (uint32). The secure processor writes zero for
    /// success; the kernel logs <c>ERROR: verifyImage(966) ret &lt;n&gt;</c> on any non-zero
    /// value and maps it to EICV.</summary>
    public const int OffsetStatus = 0x04;

    /// <summary>Offset of the encryption key handle (uint32). After the mailbox, the kernel
    /// reads this as the <c>ekey</c> handle for <c>kms_register</c>. Must differ from
    /// <see cref="OffsetSkeyHandle"/> to avoid a duplicate-handle <c>-17</c> error.</summary>
    public const int OffsetEkeyHandle = 0x08;

    /// <summary>Offset of the signing key handle (uint32). After the mailbox, the kernel
    /// reads this as the <c>skey</c> handle for <c>kms_register</c>. Must differ from
    /// <see cref="OffsetEkeyHandle"/>.</summary>
    public const int OffsetSkeyHandle = 0x0C;

    /// <summary>Offset of the key-output buffer virtual address (uint64). Written by the
    /// kernel before the mailbox call; points to a <c>0x20000</c>-byte region at a kernel
    /// data address. Shares the same offset as <see cref="OffsetEkeyHandle"/> because the
    /// secure processor overwrites the request field with the response handle.</summary>
    public const int OffsetKeyOutputVa = 0x08;

    /// <summary>Offset of the key-output buffer physical address (uint64). Written by the
    /// kernel as <c>vtophys</c> of the key-output VA.</summary>
    public const int OffsetKeyOutputPhys = 0x10;

    /// <summary>Offset of the key-output buffer size (uint64). The kernel writes
    /// <c>0x20000</c>.</summary>
    public const int OffsetKeyOutputSize = 0x18;

    /// <summary>Offset of the mapped-input descriptor (uint64). On the ppr path, this holds
    /// <c>vtophys(param_3)</c> — the outer superblock mapped <c>0x10000</c> bytes into
    /// DMEM.</summary>
    public const int OffsetMappedInput = 0x20;

    /// <summary>Offset of the flag pair (uint64). Contains <c>param_5</c> and <c>param_7</c>
    /// region sizes packed as two uint32 values: low dword = <c>param_5</c> size
    /// (<c>0x1000</c>), high dword = <c>param_7</c> size (<c>0x3000</c>).</summary>
    public const int OffsetFlagPair = 0x48;

    /// <summary>Offset of the echo field (uint32). Read back by the kernel after the mailbox
    /// and returned to the caller through its output parameter. The mount worker compares
    /// this against <c>0x1000</c> (the <c>param_5</c> buffer size); a mismatch logs
    /// <c>unexpected fih_read_size</c> and aborts.</summary>
    public const int OffsetEchoField = 0x4C;

    /// <summary>Offset of the byte-swap length field (uint32). Read back by the kernel as
    /// the trip count (<c>value &gt;&gt; 3</c>) for an 8-byte endian-swap loop over
    /// <c>param_3</c>. Must be zero on the ppr path to prevent a destructive
    /// loop.</summary>
    public const int OffsetByteSwapLen = 0x54;

    /// <summary>Opcode for the <c>verifyImage</c> command.</summary>
    public const uint OpcodeVerifyImage = 1;

    /// <summary>Opcode for the <c>verifySuperBlock</c> command. Uses the same
    /// <c>+0x04</c>/<c>+0x08</c>/<c>+0x0C</c> response layout as
    /// <c>verifyImage</c>.</summary>
    public const uint OpcodeVerifySuperBlock = 0x11;
}

/// <summary>
/// Builds <c>verifyImage</c> mailbox responses and combines key derivation with response
/// construction. The <c>verifyImage</c> command is issued by the kernel's PFS mount worker
/// during package launch; a correct response provides two distinct key handles and an echo
/// value the kernel cross-checks.
/// </summary>
/// <remarks>
/// This class provides the building blocks a trap handler needs. It does not implement the
/// trap handler itself (that requires kernel-side integration via debug register breakpoints
/// on <c>sceSblServiceMailbox</c>).
/// </remarks>
public static unsafe class VerifyImageEmulator
{
    /// <summary>
    /// Handle base for fake key identifiers. Each fake key slot in the shared area
    /// carries a handle formed as <c>HandleBase | (uint8)(slotIndex + 1)</c>. The
    /// kernel-side XTS/HMAC handler recovers the slot index from the low byte
    /// (<c>(handle &amp; 0xFF) - 1</c>); the encoding must match on both sides.
    /// </summary>
    public const uint HandleBase = 0x13374100;

    /// <summary>
    /// Computes the encryption key handle for a given registration slot.
    /// </summary>
    /// <param name="index">Zero-based slot index from the fake key registration.</param>
    /// <returns>The encryption key handle.</returns>
    public static uint EkeyHandleFromIndex(int index) => HandleBase | ((uint)(index + 1) & 0xFF);

    /// <summary>
    /// Computes the signing key handle for a given registration slot.
    /// </summary>
    /// <param name="index">Zero-based slot index from the fake key registration.</param>
    /// <returns>The signing key handle.</returns>
    public static uint SkeyHandleFromIndex(int index) => HandleBase | ((uint)(index + 1) & 0xFF);

    /// <summary>
    /// Writes a <c>verifyImage</c> success response into the 0x80-byte kernel buffer at
    /// <paramref name="requestAddr"/>. The entire buffer is zeroed first, then specific
    /// response fields are written in a single bulk operation.
    /// </summary>
    /// <param name="io">Kernel read/write primitive.</param>
    /// <param name="requestAddr">
    /// Kernel address of the 0x80-byte mailbox buffer (<c>regs[RDX]</c>).
    /// </param>
    /// <param name="ekeyHandle">
    /// Distinct handle for the encryption key, written to <c>+0x08</c>. Must differ from
    /// <paramref name="skeyHandle"/> to avoid a <c>-17</c> duplicate-handle collision in
    /// <c>kms_register</c>.
    /// </param>
    /// <param name="skeyHandle">
    /// Distinct handle for the signing key, written to <c>+0x0C</c>. Must differ from
    /// <paramref name="ekeyHandle"/>.
    /// </param>
    /// <param name="echoValue">
    /// Value written to <c>+0x4C</c>. The kernel expects this to equal the <c>param_5</c>
    /// buffer size (typically <c>0x1000</c>).
    /// </param>
    public static void BuildVerifyImageResponse(
        PayloadKernelIo io,
        ulong requestAddr,
        uint ekeyHandle,
        uint skeyHandle,
        uint echoValue)
    {
        // Build the full response locally, then write as a single bulk operation.
        // Zeroing the entire buffer is critical: +0x54 inherits a kernel pointer's high
        // dword from the request, which would trigger the destructive byte-swap loop.
        byte* resp = stackalloc byte[VerifyImageMailbox.RequestSize];
        new Span<byte>(resp, VerifyImageMailbox.RequestSize).Clear();

        // +0x04: status = 0 (success).
        *(uint*)(resp + VerifyImageMailbox.OffsetStatus) = 0;

        // +0x08: encryption key handle.
        *(uint*)(resp + VerifyImageMailbox.OffsetEkeyHandle) = ekeyHandle;

        // +0x0C: signing key handle.
        *(uint*)(resp + VerifyImageMailbox.OffsetSkeyHandle) = skeyHandle;

        // +0x4C: echo value (param_5 buffer size returned to the caller).
        *(uint*)(resp + VerifyImageMailbox.OffsetEchoField) = echoValue;

        // +0x54: byte-swap length = 0. Already zero from the clear, but the assignment
        // is explicit to document the invariant.
        *(uint*)(resp + VerifyImageMailbox.OffsetByteSwapLen) = 0;

        io.Write(requestAddr, resp, VerifyImageMailbox.RequestSize);
    }

    /// <summary>
    /// Derives PS5 PFS keys from the given content identity and PFS superblock crypt seed,
    /// registers them in the shared area, then builds the <c>verifyImage</c> response with
    /// the registered handles.
    /// </summary>
    /// <param name="io">Kernel read/write primitive.</param>
    /// <param name="requestAddr">
    /// Kernel address of the 0x80-byte mailbox buffer (<c>regs[RDX]</c>).
    /// </param>
    /// <param name="sharedAreaAddr">Address of the kernel shared area.</param>
    /// <param name="contentId">The 36-byte content identifier (ASCII).</param>
    /// <param name="passcode">The 32-byte passcode (ASCII).</param>
    /// <param name="cryptSeed">The 16-byte PFS superblock crypt seed.</param>
    /// <returns>
    /// <see langword="true"/> when key derivation and registration succeeded and the response
    /// was written; <see langword="false"/> when the shared area has no capacity for a new
    /// key entry.
    /// </returns>
    public static bool HandleVerifyImage(
        PayloadKernelIo io,
        ulong requestAddr,
        ulong sharedAreaAddr,
        ReadOnlySpan<byte> contentId,
        ReadOnlySpan<byte> passcode,
        ReadOnlySpan<byte> cryptSeed)
    {
        // Derive EKPFS from contentId + passcode, then tweak/data/sign keys from
        // EKPFS + cryptSeed through the SHA3-256 + HMAC-SHA256 keyed-crypto ladder.
        Span<byte> tweakKey = stackalloc byte[16];
        Span<byte> dataKey = stackalloc byte[16];
        Span<byte> signKey = stackalloc byte[32];
        PayloadPfsCryptoPs5.DeriveKeysFromContentId(contentId, passcode, cryptSeed,
            tweakKey, dataKey, signKey);

        // Combine tweakKey + dataKey into the 32-byte XTS encryption key.
        Span<byte> encKey = stackalloc byte[32];
        tweakKey.CopyTo(encKey);
        dataKey.CopyTo(encKey[16..]);

        // Register the key pair in the shared area (one slot per key).
        if (!PayloadFpkgBypass.RegisterKeys(io, sharedAreaAddr, encKey, signKey,
                out int encSlot, out int sigSlot))
            return false;

        // Compute two distinct handles from the slot indices.
        uint ekeyHandle = EkeyHandleFromIndex(encSlot);
        uint skeyHandle = SkeyHandleFromIndex(sigSlot);

        // Read the echo value from the low 32 bits of the flag pair at +0x48. This is the
        // param_5 buffer size (0x1000) that the kernel will compare against +0x4C after
        // the mailbox returns.
        uint echoValue = io.ReadU32(requestAddr + VerifyImageMailbox.OffsetFlagPair);

        // Build and write the response.
        BuildVerifyImageResponse(io, requestAddr, ekeyHandle, skeyHandle, echoValue);

        return true;
    }
}
