// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Buffers.Binary;
using System.Numerics;

namespace SharpProspero.Security;

/// <summary>Which SHA-3 digest to compute, by output size in bits.</summary>
public enum Sha3Variant
{
    /// <summary>SHA3-256, a 32-byte digest.</summary>
    Bits256 = 256,

    /// <summary>SHA3-384, a 48-byte digest.</summary>
    Bits384 = 384,

    /// <summary>SHA3-512, a 64-byte digest.</summary>
    Bits512 = 512,
}

/// <summary>
/// The SHA-3 digest (Keccak sponge, FIPS 202), a modern alternative to the SHA-2 family for verifying data
/// against a published checksum. Choose the width with <see cref="Sha3Variant"/>. Use the static
/// <see cref="Hash(ReadOnlySpan{byte}, Sha3Variant)"/> for a block of bytes, <see cref="HashFile"/> for a
/// file, or construct one and call <see cref="HashAlgorithm.Update"/> to hash a stream. Like the other
/// digests it is a self-contained calculation that needs no system module.
/// </summary>
public sealed class Sha3 : HashAlgorithm
{
    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    private static readonly int[] RhoOffsets =
    [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

    private readonly ulong[] _state = new ulong[25];
    private readonly byte[] _block;
    private readonly int _rate;      // bytes absorbed per permutation
    private readonly int _hashSize;
    private int _blockLength;

    /// <summary>Creates a hasher for the given SHA-3 <paramref name="variant"/> (SHA3-256 by default).</summary>
    public Sha3(Sha3Variant variant = Sha3Variant.Bits256)
    {
        int bits = (int)variant;
        _hashSize = bits / 8;
        _rate = (1600 - (2 * bits)) / 8; // 136 for 256, 104 for 384, 72 for 512
        _block = new byte[_rate];
    }

    /// <inheritdoc/>
    public override int HashSize => _hashSize;

    /// <inheritdoc/>
    public override void Update(ReadOnlySpan<byte> data)
    {
        int offset = 0;

        // Top up a partial block first, absorbing it once it fills.
        if (_blockLength > 0)
        {
            int take = Math.Min(_rate - _blockLength, data.Length);
            data[..take].CopyTo(_block.AsSpan(_blockLength));
            _blockLength += take;
            offset = take;
            if (_blockLength == _rate)
            {
                AbsorbBlock(_block);
                _blockLength = 0;
            }
        }

        while (data.Length - offset >= _rate)
        {
            AbsorbBlock(data.Slice(offset, _rate));
            offset += _rate;
        }

        int remaining = data.Length - offset;
        if (remaining > 0)
        {
            data.Slice(offset, remaining).CopyTo(_block);
            _blockLength = remaining;
        }
    }

    /// <inheritdoc/>
    protected override void FinishCore(Span<byte> destination)
    {
        // Pad the trailing partial block: the SHA-3 domain suffix 0x06, then the final bit at the top.
        Span<byte> pad = stackalloc byte[_rate];
        _block.AsSpan(0, _blockLength).CopyTo(pad);
        pad[_blockLength..].Clear();
        pad[_blockLength] = 0x06;
        pad[_rate - 1] |= 0x80;
        AbsorbBlock(pad);

        // Squeeze the digest out of the state; for every SHA-3 width it fits in one rate block.
        Span<byte> lane = stackalloc byte[8];
        int produced = 0;
        while (produced < destination.Length)
        {
            for (int i = 0; i < _rate / 8 && produced < destination.Length; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(lane, _state[i]);
                int take = Math.Min(8, destination.Length - produced);
                lane[..take].CopyTo(destination[produced..]);
                produced += take;
            }

            if (produced < destination.Length)
                KeccakF1600(_state);
        }
    }

    /// <summary>Computes the SHA-3 digest of <paramref name="data"/> in one call.</summary>
    public static byte[] Hash(ReadOnlySpan<byte> data, Sha3Variant variant = Sha3Variant.Bits256)
    {
        var hash = new Sha3(variant);
        hash.Update(data);
        return hash.Finish();
    }

    /// <summary>Computes the SHA-3 digest of <paramref name="data"/> as a lowercase hexadecimal string.</summary>
    public static string HashHex(ReadOnlySpan<byte> data, Sha3Variant variant = Sha3Variant.Bits256)
        => Convert.ToHexStringLower(Hash(data, variant));

    /// <summary>Streams the file at <paramref name="path"/> through a SHA-3 digest.</summary>
    /// <exception cref="Interop.ProsperoException">Opening or reading the file failed.</exception>
    public static byte[] HashFile(string path, Sha3Variant variant = Sha3Variant.Bits256)
        => new Sha3(variant).ComputeFile(path);

    /// <summary>Streams the file at <paramref name="path"/> through a SHA-3 digest and returns hexadecimal.</summary>
    public static string HashFileHex(string path, Sha3Variant variant = Sha3Variant.Bits256)
        => Convert.ToHexStringLower(HashFile(path, variant));

    /// <summary>
    /// Computes the SHA3-256 digest of <paramref name="input"/> into <paramref name="output"/>
    /// without any heap allocation. Suitable for kernel-context payloads where the GC is
    /// unavailable. The output span must hold at least 32 bytes.
    /// </summary>
    /// <param name="input">The message to hash.</param>
    /// <param name="output">Destination buffer, at least 32 bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="output"/> is shorter than 32 bytes.</exception>
    public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length < 32)
            throw new ArgumentException("Output buffer must be at least 32 bytes.", nameof(output));

        const int rate = 136; // SHA3-256: (1600 - 2*256) / 8

        Span<ulong> state = stackalloc ulong[25];
        state.Clear();

        int offset = 0;
        int remaining = input.Length;

        // Absorb full rate-sized blocks.
        while (remaining >= rate)
        {
            AbsorbInto(state, input.Slice(offset, rate), rate);
            offset += rate;
            remaining -= rate;
        }

        // Pad and absorb the final partial block.
        Span<byte> pad = stackalloc byte[rate];
        pad.Clear();
        input.Slice(offset, remaining).CopyTo(pad);
        pad[remaining] = 0x06;
        pad[rate - 1] |= 0x80;
        AbsorbInto(state, pad, rate);

        // Squeeze: 32 bytes = 4 lanes, always fits in one rate block.
        BinaryPrimitives.WriteUInt64LittleEndian(output, state[0]);
        BinaryPrimitives.WriteUInt64LittleEndian(output[8..], state[1]);
        BinaryPrimitives.WriteUInt64LittleEndian(output[16..], state[2]);
        BinaryPrimitives.WriteUInt64LittleEndian(output[24..], state[3]);
    }

    // XOR a block into the state and permute; used by the zero-allocation path.
    private static void AbsorbInto(Span<ulong> state, ReadOnlySpan<byte> block, int rate)
    {
        for (int i = 0; i < rate / 8; i++)
            state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));
        KeccakF1600(state);
    }

    private void AbsorbBlock(ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < _rate / 8; i++)
            _state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));
        KeccakF1600(_state);
    }

    private static void KeccakF1600(Span<ulong> a)
    {
        Span<ulong> c = stackalloc ulong[5];
        Span<ulong> d = stackalloc ulong[5];
        Span<ulong> b = stackalloc ulong[25];

        for (int round = 0; round < 24; round++)
        {
            // Theta
            for (int x = 0; x < 5; x++)
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++)
                d[x] = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
            for (int i = 0; i < 25; i++)
                a[i] ^= d[i % 5];

            // Rho and Pi
            for (int i = 0; i < 25; i++)
            {
                int x = i % 5;
                int y = i / 5;
                int destination = y + (5 * (((2 * x) + (3 * y)) % 5));
                b[destination] = BitOperations.RotateLeft(a[i], RhoOffsets[i]);
            }

            // Chi
            for (int y = 0; y < 25; y += 5)
            {
                for (int x = 0; x < 5; x++)
                    a[y + x] = b[y + x] ^ (~b[y + ((x + 1) % 5)] & b[y + ((x + 2) % 5)]);
            }

            // Iota
            a[0] ^= RoundConstants[round];
        }
    }

    // Verification against NIST test vectors (SHA3-256):
    //
    //   Input: "" (empty)
    //   Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
    //
    //   Input: "abc" (0x61 0x62 0x63)
    //   Expected: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
    //
    //   Span<byte> digest = stackalloc byte[32];
    //   Sha3.Hash(ReadOnlySpan<byte>.Empty, digest);
    //   // digest == a7ffc6f8...
    //
    //   Sha3.Hash("abc"u8, digest);
    //   // digest == 3a985da7...
}
