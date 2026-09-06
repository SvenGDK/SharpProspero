// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Kernel;
using System;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// FPKG (Fake Package) crypto bypass. Intercepts PFS key derivation to substitute
/// custom encryption and signing keys, allowing fake-signed packages to be mounted
/// and read.
/// </summary>
public static unsafe class PayloadFpkgBypass
{
    /// <summary>
    /// Registers a set of fake PFS keys for FPKG bypass. Allocates two shared-area
    /// slots: one for the 32-byte XTS encryption key and one for the 32-byte HMAC
    /// signing key.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="sharedAreaAddr">Address of the shared area.</param>
    /// <param name="encKey">The 32-byte XTS encryption key.</param>
    /// <param name="sigKey">The 32-byte HMAC signing key.</param>
    /// <param name="encSlot">Receives the encryption key slot index.</param>
    /// <param name="sigSlot">Receives the signing key slot index.</param>
    /// <returns><see langword="true"/> if both keys were registered.</returns>
    public static bool RegisterKeys(PayloadKernelIo io, ulong sharedAreaAddr,
        ReadOnlySpan<byte> encKey, ReadOnlySpan<byte> sigKey,
        out int encSlot, out int sigSlot)
    {
        encSlot = PayloadFakeKeys.RegisterFakeKey(io, sharedAreaAddr, encKey);
        if (encSlot < 0)
        {
            sigSlot = -1;
            return false;
        }

        sigSlot = PayloadFakeKeys.RegisterFakeKey(io, sharedAreaAddr, sigKey);
        if (sigSlot < 0)
        {
            PayloadFakeKeys.UnregisterFakeKey(io, sharedAreaAddr, encSlot);
            encSlot = -1;
            return false;
        }

        return true;
    }

    /// <summary>
    /// Derives and registers PFS keys from an EKPFS seed.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="sharedAreaAddr">Address of the shared area.</param>
    /// <param name="contentId">The content identifier (48 bytes).</param>
    /// <param name="ekpfs">The 32-byte EKPFS seed.</param>
    /// <param name="seed">The 16-byte PFS superblock crypt seed.</param>
    /// <param name="encSlot">Receives the encryption key slot index.</param>
    /// <param name="sigSlot">Receives the signing key slot index.</param>
    /// <returns><see langword="true"/> if both keys were registered.</returns>
    public static bool DeriveAndRegister(PayloadKernelIo io, ulong sharedAreaAddr,
        ReadOnlySpan<byte> contentId, ReadOnlySpan<byte> ekpfs, ReadOnlySpan<byte> seed,
        out int encSlot, out int sigSlot)
    {
        Span<byte> xtsKey = stackalloc byte[32];
        Span<byte> hmacKey = stackalloc byte[32];
        PayloadPfsCrypto.DeriveKeys(ekpfs, seed, xtsKey, hmacKey);
        return RegisterKeys(io, sharedAreaAddr, xtsKey, hmacKey, out encSlot, out sigSlot);
    }

    /// <summary>
    /// PS5-era key derivation and registration. Derives the EKPFS from
    /// <paramref name="contentId"/> and <paramref name="passcode"/> using SHA3-256,
    /// then derives the AES-XTS and signing keys through the keyed-crypto ladder with the
    /// PFS superblock <paramref name="seed"/>, and registers them for the fake-key bypass.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="sharedAreaAddr">Address of the shared area.</param>
    /// <param name="contentId">The 36-byte content identifier (ASCII, padded to 48 internally).</param>
    /// <param name="passcode">The 32-byte passcode (ASCII).</param>
    /// <param name="seed">The 16-byte PFS superblock crypt seed.</param>
    /// <param name="encSlot">Receives the encryption key slot index.</param>
    /// <param name="sigSlot">Receives the signing key slot index.</param>
    /// <returns><see langword="true"/> if both keys were registered.</returns>
    public static bool DeriveAndRegisterPs5(PayloadKernelIo io, ulong sharedAreaAddr,
        ReadOnlySpan<byte> contentId, ReadOnlySpan<byte> passcode, ReadOnlySpan<byte> seed,
        out int encSlot, out int sigSlot)
    {
        Span<byte> tweakKey = stackalloc byte[16];
        Span<byte> dataKey = stackalloc byte[16];
        Span<byte> signKey = stackalloc byte[32];
        PayloadPfsCryptoPs5.DeriveKeysFromContentId(contentId, passcode, seed,
            tweakKey, dataKey, signKey);

        // Combine tweakKey + dataKey into the 32-byte XTS key.
        Span<byte> xtsKey = stackalloc byte[32];
        tweakKey.CopyTo(xtsKey);
        dataKey.CopyTo(xtsKey[16..]);

        return RegisterKeys(io, sharedAreaAddr, xtsKey, signKey, out encSlot, out sigSlot);
    }
}
