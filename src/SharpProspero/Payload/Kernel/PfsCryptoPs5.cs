// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Security;
using System;
using System.Buffers.Binary;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// PS5-era PFS cryptographic key derivation. Derives the EKPFS from a content identifier
/// and passcode using SHA3-256, then produces AES-XTS encryption keys and the HMAC signing
/// key through the keyed-crypto ladder with a PFS superblock seed.
/// </summary>
public static class PayloadPfsCryptoPs5
{
    /// <summary>Key-ladder index that yields the EKPFS from the content-id and passcode.</summary>
    private const uint EkpfsIndex = 1;

    /// <summary>Key-generation index for the AES-XTS encryption key pair.</summary>
    private const uint EncKeyIndex = 1;

    /// <summary>Key-generation index for the HMAC signing key.</summary>
    private const uint SignKeyIndex = 2;

    /// <summary>
    /// Derives the 32-byte EKPFS from <paramref name="contentId"/> (36 bytes) and
    /// <paramref name="passcode"/> (32 bytes) using SHA3-256:
    /// <c>EKPFS = SHA3-256( SHA3-256(BE32(1)) || SHA3-256(contentId padded to 48) || passcode )</c>.
    /// </summary>
    /// <param name="contentId">The 36-byte content identifier (ASCII).</param>
    /// <param name="passcode">The 32-byte passcode (ASCII).</param>
    /// <param name="ekpfs">Receives the 32-byte EKPFS seed value.</param>
    public static void DeriveEkpfs(ReadOnlySpan<byte> contentId, ReadOnlySpan<byte> passcode, Span<byte> ekpfs)
    {
        if (contentId.Length != 36)
            throw new ArgumentException("Content ID must be exactly 36 bytes.", nameof(contentId));
        if (passcode.Length != 32)
            throw new ArgumentException("Passcode must be exactly 32 bytes.", nameof(passcode));
        if (ekpfs.Length < 32)
            throw new ArgumentException("EKPFS buffer must be at least 32 bytes.", nameof(ekpfs));

        // SHA3-256( BE32(EkpfsIndex) )
        Span<byte> indexBe = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(indexBe, EkpfsIndex);
        Span<byte> indexHash = stackalloc byte[32];
        Sha3.Hash(indexBe, indexHash);

        // SHA3-256( contentId padded to 48 bytes with nulls )
        Span<byte> cidPadded = stackalloc byte[48];
        cidPadded.Clear();
        contentId.CopyTo(cidPadded);
        Span<byte> cidHash = stackalloc byte[32];
        Sha3.Hash(cidPadded, cidHash);

        // Concatenate: indexHash[32] || cidHash[32] || passcode[32] = 96 bytes
        Span<byte> combined = stackalloc byte[96];
        indexHash.CopyTo(combined);
        cidHash.CopyTo(combined[32..]);
        passcode.CopyTo(combined[64..]);

        // EKPFS = SHA3-256( combined )
        Sha3.Hash(combined, ekpfs);
    }

    /// <summary>
    /// Derives the AES-XTS key pair (tweak key + data key, 16 bytes each) and the HMAC
    /// signing key from <paramref name="ekpfs"/> and the 16-byte PFS superblock
    /// <paramref name="seed"/>. The keyed-crypto ladder is:
    /// <list type="bullet">
    ///   <item><c>derivedKey = HMAC-SHA256(ekpfs, seed)</c></item>
    ///   <item><c>encKey = HMAC-SHA256(derivedKey, LE32(1) || seed)</c> — tweakKey = [0:16], dataKey = [16:32]</item>
    ///   <item><c>signKey = HMAC-SHA256(derivedKey, LE32(2) || seed)</c></item>
    /// </list>
    /// </summary>
    /// <param name="ekpfs">The 32-byte EKPFS seed.</param>
    /// <param name="seed">The 16-byte PFS superblock crypt seed.</param>
    /// <param name="tweakKey">Receives the 16-byte AES-XTS tweak key.</param>
    /// <param name="dataKey">Receives the 16-byte AES-XTS data key.</param>
    /// <param name="signKey">Receives the HMAC signing key (up to 32 bytes).</param>
    public static void DeriveKeys(ReadOnlySpan<byte> ekpfs, ReadOnlySpan<byte> seed,
        Span<byte> tweakKey, Span<byte> dataKey, Span<byte> signKey)
    {
        if (ekpfs.Length < 32)
            throw new ArgumentException("EKPFS must be at least 32 bytes.", nameof(ekpfs));
        if (seed.Length != 16)
            throw new ArgumentException("Seed must be exactly 16 bytes.", nameof(seed));

        // Intermediate key: derivedKey = HMAC-SHA256(ekpfs, seed)
        byte[] derivedKey = Hmac.Sha256(ekpfs, seed);

        // Encryption key: HMAC-SHA256(derivedKey, LE32(1) || seed)
        Span<byte> hmacData = stackalloc byte[20]; // 4 bytes index + 16 bytes seed
        BinaryPrimitives.WriteUInt32LittleEndian(hmacData, EncKeyIndex);
        seed.CopyTo(hmacData[4..]);
        byte[] encResult = Hmac.Sha256(derivedKey, hmacData);
        encResult.AsSpan(0, Math.Min(16, tweakKey.Length)).CopyTo(tweakKey);
        encResult.AsSpan(16, Math.Min(16, dataKey.Length)).CopyTo(dataKey);

        // Signing key: HMAC-SHA256(derivedKey, LE32(2) || seed)
        BinaryPrimitives.WriteUInt32LittleEndian(hmacData, SignKeyIndex);
        byte[] sigResult = Hmac.Sha256(derivedKey, hmacData);
        sigResult.AsSpan(0, Math.Min(sigResult.Length, signKey.Length)).CopyTo(signKey);
    }

    /// <summary>
    /// Derives the AES-XTS key pair and HMAC signing key from <paramref name="contentId"/>,
    /// <paramref name="passcode"/>, and PFS superblock <paramref name="seed"/> in one step.
    /// </summary>
    /// <param name="contentId">The 36-byte content identifier (ASCII).</param>
    /// <param name="passcode">The 32-byte passcode (ASCII).</param>
    /// <param name="seed">The 16-byte PFS superblock crypt seed.</param>
    /// <param name="tweakKey">Receives the 16-byte AES-XTS tweak key.</param>
    /// <param name="dataKey">Receives the 16-byte AES-XTS data key.</param>
    /// <param name="signKey">Receives the HMAC signing key (up to 32 bytes).</param>
    public static void DeriveKeysFromContentId(ReadOnlySpan<byte> contentId, ReadOnlySpan<byte> passcode,
        ReadOnlySpan<byte> seed, Span<byte> tweakKey, Span<byte> dataKey, Span<byte> signKey)
    {
        Span<byte> ekpfs = stackalloc byte[32];
        DeriveEkpfs(contentId, passcode, ekpfs);
        DeriveKeys(ekpfs, seed, tweakKey, dataKey, signKey);
    }
}
