// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace SharpProspero.Security;

/// <summary>
/// The SHA-1 digest, a 20-byte hash. It is offered for checking data against the many manifests and
/// tools that still publish SHA-1 sums; prefer <see cref="Sha256"/> when a choice is available.
/// </summary>
/// <remarks>
/// Two shapes of API cover the two ways the digest is used in this codebase. The
/// <see cref="BlockHashAlgorithm"/>-derived instance API — <see cref="HashAlgorithm.Update"/> and
/// <see cref="HashAlgorithm.Finish()"/> — is what <see cref="Hmac"/> and the general callers reach for.
/// The nested <see cref="Context"/> plus <see cref="Init"/>/<see cref="Update(Context, ReadOnlySpan{byte})"/>/<see cref="Final"/>
/// mirror the <c>SHA_CTX</c> / <c>SHAInit</c>/<c>SHAUpdate</c>/<c>SHAFinal</c> shape that libkirk-style
/// crypto ports carry around; the KIRK dispatch layer keeps one <see cref="Context"/> across the
/// several buffer chunks a decryption feeds it.
/// </remarks>
public sealed class Sha1 : BlockHashAlgorithm
{
    private const int ShsDataSize = 64;
    private const int ShsDigestSize = 20;

    private const uint H0Init = 0x67452301u;
    private const uint H1Init = 0xEFCDAB89u;
    private const uint H2Init = 0x98BADCFEu;
    private const uint H3Init = 0x10325476u;
    private const uint H4Init = 0xC3D2E1F0u;

    private const uint K1 = 0x5A827999u;
    private const uint K2 = 0x6ED9EBA1u;
    private const uint K3 = 0x8F1BBCDCu;
    private const uint K4 = 0xCA62C1D6u;

    // libkirk's endianTest sets the flag once at Init; we resolve it at class load. TRUE (1) on
    // big-endian silicon means LongReverse skips the byte swap; the PS5 and every test rig here is
    // little-endian, so this evaluates to 0 in practice and the byte-swap path runs.
    private static readonly int PlatformEndianness = BitConverter.IsLittleEndian ? 0 : 1;

    // The running state for the instance API. The array is mutated in place, so `readonly` locks the
    // reference but not the contents.
    private readonly uint[] _digest = [H0Init, H1Init, H2Init, H3Init, H4Init];

    /// <inheritdoc/>
    public override int HashSize => ShsDigestSize;

    /// <inheritdoc/>
    protected override bool LengthIsBigEndian => true;

    /// <inheritdoc/>
    protected override void ProcessBlock(ReadOnlySpan<byte> block)
    {
        // The instance path arrives with a 64-byte block already normalised by BlockHashAlgorithm.
        // The 16 message-schedule words are the block read as big-endian uint32s; that is the same
        // sequence libkirk's LongReverse leaves in memory on a little-endian machine.
        Span<uint> eData = stackalloc uint[16];
        for (int i = 0; i < 16; i++)
            eData[i] = BinaryPrimitives.ReadUInt32BigEndian(block[(i * 4)..]);
        RunEightyRounds(_digest, eData);
    }

    /// <inheritdoc/>
    protected override void WriteDigest(Span<byte> destination)
    {
        for (int i = 0; i < 5; i++)
            BinaryPrimitives.WriteUInt32BigEndian(destination[(i * 4)..], _digest[i]);
    }

    /// <summary>Computes the SHA-1 digest of <paramref name="data"/>.</summary>
    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        var sha = new Sha1();
        sha.Update(data);
        return sha.Finish();
    }

    /// <summary>Computes the SHA-1 digest of <paramref name="data"/> as a lowercase hexadecimal string.</summary>
    public static string HashHex(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(Hash(data));

    /// <summary>Computes the SHA-1 digest of the file at <paramref name="path"/>.</summary>
    public static byte[] HashFile(string path) => new Sha1().ComputeFile(path);

    /// <summary>Computes the SHA-1 digest of the file at <paramref name="path"/> as a lowercase hexadecimal string.</summary>
    public static string HashFileHex(string path) => Convert.ToHexStringLower(HashFile(path));

    /// <summary>Computes the SHA-1 digest of <paramref name="data"/> through the <see cref="Context"/> API.</summary>
    public static byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        var ctx = new Context();
        Init(ctx);
        Update(ctx, data);
        byte[] output = new byte[ShsDigestSize];
        Final(output, ctx);
        return output;
    }

    /// <summary>
    /// The SHA-1 running state. Field names match libkirk's <c>SHA_CTX</c> layout — digest, low and
    /// high 32-bit halves of the bit count, a 64-byte data buffer, and the endianness flag — so ported
    /// C code that keeps a live <c>SHA_CTX *</c> across several update calls maps onto one of these.
    /// </summary>
    internal sealed class Context
    {
        internal readonly uint[] Digest = new uint[5];
        internal uint CountLo;
        internal uint CountHi;
        internal readonly uint[] Data = new uint[16];
        internal int Endianness;
    }

    private static void EndianTest(ref int endianness) => endianness = PlatformEndianness;

    /// <summary>Resets the state, matching libkirk's <c>SHAInit</c>.</summary>
    internal static void Init(Context shsInfo)
    {
        EndianTest(ref shsInfo.Endianness);
        shsInfo.Digest[0] = H0Init;
        shsInfo.Digest[1] = H1Init;
        shsInfo.Digest[2] = H2Init;
        shsInfo.Digest[3] = H3Init;
        shsInfo.Digest[4] = H4Init;
        shsInfo.CountLo = shsInfo.CountHi = 0;
    }

    /// <summary>Feeds <paramref name="buffer"/> into the running digest, matching libkirk's <c>SHAUpdate</c>.</summary>
    internal static void Update(Context shsInfo, ReadOnlySpan<byte> buffer)
    {
        int count = buffer.Length;

        // Update the 64-bit bit count. The low half carries into the high half on wrap; the extra
        // add of `count >> 29` folds in the top bits of `count * 8` that never fit into `countLo`.
        uint tmp = shsInfo.CountLo;
        if ((shsInfo.CountLo = tmp + ((uint)count << 3)) < tmp)
            shsInfo.CountHi++;
        shsInfo.CountHi += (uint)(count >> 29);

        // The byte offset of the next write into the block buffer. libkirk reads it from the bit
        // count so no separate `_blockLength` field is needed.
        int dataCount = (int)(tmp >> 3) & 0x3F;

        Span<byte> dataBytes = MemoryMarshal.AsBytes(shsInfo.Data.AsSpan());

        // Leading odd-sized chunk: top up a partial block first, and if that fills it, transform.
        if (dataCount != 0)
        {
            int p = dataCount;
            dataCount = ShsDataSize - dataCount;
            if (count < dataCount)
            {
                buffer.CopyTo(dataBytes[p..]);
                return;
            }
            buffer[..dataCount].CopyTo(dataBytes[p..]);
            LongReverse(shsInfo.Data, ShsDataSize, shsInfo.Endianness);
            SHSTransform(shsInfo.Digest, shsInfo.Data);
            buffer = buffer[dataCount..];
            count -= dataCount;
        }

        // Whole blocks straight through.
        while (count >= ShsDataSize)
        {
            buffer[..ShsDataSize].CopyTo(dataBytes);
            LongReverse(shsInfo.Data, ShsDataSize, shsInfo.Endianness);
            SHSTransform(shsInfo.Digest, shsInfo.Data);
            buffer = buffer[ShsDataSize..];
            count -= ShsDataSize;
        }

        // Trailing bytes wait in the buffer for the next call, or for Final.
        buffer.CopyTo(dataBytes);
    }

    /// <summary>Appends the length pad, transforms the last block(s) and writes the digest, matching libkirk's <c>SHAFinal</c>.</summary>
    internal static void Final(Span<byte> output, Context shsInfo)
    {
        // Bytes already in the block buffer.
        int count = (int)shsInfo.CountLo;
        count = (count >> 3) & 0x3F;

        Span<byte> dataBytes = MemoryMarshal.AsBytes(shsInfo.Data.AsSpan());

        // The single 0x80 terminator, always safe because the buffer has at least one free byte here.
        int dataPtr = count;
        dataBytes[dataPtr++] = 0x80;

        // Bytes still free after the terminator.
        count = ShsDataSize - 1 - count;

        if (count < 8)
        {
            // Not enough room for the length in the current block: pad, transform, then zero the next
            // block up to byte 56 so only the trailing length remains to write.
            dataBytes.Slice(dataPtr, count).Clear();
            LongReverse(shsInfo.Data, ShsDataSize, shsInfo.Endianness);
            SHSTransform(shsInfo.Digest, shsInfo.Data);
            dataBytes[..(ShsDataSize - 8)].Clear();
        }
        else
        {
            // Zero everything between the terminator and the length slot.
            dataBytes.Slice(dataPtr, count - 8).Clear();
        }

        // The 64-bit length lands in the last two message-schedule slots. libkirk writes it as native
        // uint32s and skips the byte swap on those two words: the transform reads the same numeric
        // value regardless of endianness, which is exactly the big-endian bit count.
        shsInfo.Data[14] = shsInfo.CountHi;
        shsInfo.Data[15] = shsInfo.CountLo;

        LongReverse(shsInfo.Data, ShsDataSize - 8, shsInfo.Endianness);
        SHSTransform(shsInfo.Digest, shsInfo.Data);

        SHAtoByte(output, shsInfo.Digest, ShsDigestSize);

        // Zeroise sensitive stuff — libkirk memsets the whole SHA_CTX, so every field goes.
        Array.Clear(shsInfo.Digest);
        shsInfo.CountLo = 0;
        shsInfo.CountHi = 0;
        Array.Clear(shsInfo.Data);
        shsInfo.Endianness = 0;
    }

    // Copies libkirk's SHSTransform: pull the block into an expandable window, run the 80 rounds,
    // fold the round state back into digest[]. `data` is a live 16-word buffer whose byte order has
    // already been normalised by LongReverse.
    private static void SHSTransform(uint[] digest, uint[] data)
    {
        Span<uint> eData = stackalloc uint[16];
        data.AsSpan().CopyTo(eData);
        RunEightyRounds(digest, eData);
    }

    // Byte-swaps each of the first `byteCount / 4` uint32 words in place. Uses the same two-mask
    // rotate-then-swap-halves decomposition libkirk does, so this stays a byte-for-byte match.
    private static void LongReverse(uint[] buffer, int byteCount, int endianness)
    {
        if (endianness == 1) return;
        byteCount /= 4;
        for (int i = 0; i < byteCount; i++)
        {
            uint value = buffer[i];
            value = ((value & 0xFF00FF00u) >> 8) | ((value & 0x00FF00FFu) << 8);
            buffer[i] = (value << 16) | (value >> 16);
        }
    }

    // Writes the five state words as big-endian bytes: input[i] high byte first, low byte last.
    private static void SHAtoByte(Span<byte> output, uint[] input, int len)
    {
        int i = 0;
        for (int j = 0; j < len; i++, j += 4)
        {
            output[j + 3] = (byte)(input[i] & 0xFF);
            output[j + 2] = (byte)((input[i] >> 8) & 0xFF);
            output[j + 1] = (byte)((input[i] >> 16) & 0xFF);
            output[j] = (byte)((input[i] >> 24) & 0xFF);
        }
    }

    // libkirk's expand() macro: rotate-left-1 of the XOR of four earlier window words, writing the
    // result back into the same slot. `i & 15` implements the 16-entry circular schedule.
    private static uint Expand(Span<uint> W, int i) =>
        W[i & 15] = BitOperations.RotateLeft(W[i & 15] ^ W[(i - 14) & 15] ^ W[(i - 8) & 15] ^ W[(i - 3) & 15], 1);

    // The four round functions from libkirk's f1..f4 macros, in the same reduced forms.
    private static uint F1(uint x, uint y, uint z) => z ^ (x & (y ^ z));
    private static uint F2(uint x, uint y, uint z) => x ^ y ^ z;
    private static uint F3(uint x, uint y, uint z) => (x & y) | (z & (x | y));
    private static uint F4(uint x, uint y, uint z) => x ^ y ^ z;

    private static uint RotL(int n, uint x) => BitOperations.RotateLeft(x, n);

    // The 80-round SHA-1 core, unrolled the way libkirk's SHSTransform lays it out with subRound and
    // expand. The five state words cycle through the accumulator slot every 5 rounds, and eData is
    // the 16-entry circular window into the 80-word message schedule.
    private static void RunEightyRounds(uint[] digest, Span<uint> eData)
    {
        uint A = digest[0];
        uint B = digest[1];
        uint C = digest[2];
        uint D = digest[3];
        uint E = digest[4];

        E += RotL(5, A) + F1(B, C, D) + K1 + eData[0]; B = RotL(30, B);
        D += RotL(5, E) + F1(A, B, C) + K1 + eData[1]; A = RotL(30, A);
        C += RotL(5, D) + F1(E, A, B) + K1 + eData[2]; E = RotL(30, E);
        B += RotL(5, C) + F1(D, E, A) + K1 + eData[3]; D = RotL(30, D);
        A += RotL(5, B) + F1(C, D, E) + K1 + eData[4]; C = RotL(30, C);
        E += RotL(5, A) + F1(B, C, D) + K1 + eData[5]; B = RotL(30, B);
        D += RotL(5, E) + F1(A, B, C) + K1 + eData[6]; A = RotL(30, A);
        C += RotL(5, D) + F1(E, A, B) + K1 + eData[7]; E = RotL(30, E);
        B += RotL(5, C) + F1(D, E, A) + K1 + eData[8]; D = RotL(30, D);
        A += RotL(5, B) + F1(C, D, E) + K1 + eData[9]; C = RotL(30, C);
        E += RotL(5, A) + F1(B, C, D) + K1 + eData[10]; B = RotL(30, B);
        D += RotL(5, E) + F1(A, B, C) + K1 + eData[11]; A = RotL(30, A);
        C += RotL(5, D) + F1(E, A, B) + K1 + eData[12]; E = RotL(30, E);
        B += RotL(5, C) + F1(D, E, A) + K1 + eData[13]; D = RotL(30, D);
        A += RotL(5, B) + F1(C, D, E) + K1 + eData[14]; C = RotL(30, C);
        E += RotL(5, A) + F1(B, C, D) + K1 + eData[15]; B = RotL(30, B);
        D += RotL(5, E) + F1(A, B, C) + K1 + Expand(eData, 16); A = RotL(30, A);
        C += RotL(5, D) + F1(E, A, B) + K1 + Expand(eData, 17); E = RotL(30, E);
        B += RotL(5, C) + F1(D, E, A) + K1 + Expand(eData, 18); D = RotL(30, D);
        A += RotL(5, B) + F1(C, D, E) + K1 + Expand(eData, 19); C = RotL(30, C);

        E += RotL(5, A) + F2(B, C, D) + K2 + Expand(eData, 20); B = RotL(30, B);
        D += RotL(5, E) + F2(A, B, C) + K2 + Expand(eData, 21); A = RotL(30, A);
        C += RotL(5, D) + F2(E, A, B) + K2 + Expand(eData, 22); E = RotL(30, E);
        B += RotL(5, C) + F2(D, E, A) + K2 + Expand(eData, 23); D = RotL(30, D);
        A += RotL(5, B) + F2(C, D, E) + K2 + Expand(eData, 24); C = RotL(30, C);
        E += RotL(5, A) + F2(B, C, D) + K2 + Expand(eData, 25); B = RotL(30, B);
        D += RotL(5, E) + F2(A, B, C) + K2 + Expand(eData, 26); A = RotL(30, A);
        C += RotL(5, D) + F2(E, A, B) + K2 + Expand(eData, 27); E = RotL(30, E);
        B += RotL(5, C) + F2(D, E, A) + K2 + Expand(eData, 28); D = RotL(30, D);
        A += RotL(5, B) + F2(C, D, E) + K2 + Expand(eData, 29); C = RotL(30, C);
        E += RotL(5, A) + F2(B, C, D) + K2 + Expand(eData, 30); B = RotL(30, B);
        D += RotL(5, E) + F2(A, B, C) + K2 + Expand(eData, 31); A = RotL(30, A);
        C += RotL(5, D) + F2(E, A, B) + K2 + Expand(eData, 32); E = RotL(30, E);
        B += RotL(5, C) + F2(D, E, A) + K2 + Expand(eData, 33); D = RotL(30, D);
        A += RotL(5, B) + F2(C, D, E) + K2 + Expand(eData, 34); C = RotL(30, C);
        E += RotL(5, A) + F2(B, C, D) + K2 + Expand(eData, 35); B = RotL(30, B);
        D += RotL(5, E) + F2(A, B, C) + K2 + Expand(eData, 36); A = RotL(30, A);
        C += RotL(5, D) + F2(E, A, B) + K2 + Expand(eData, 37); E = RotL(30, E);
        B += RotL(5, C) + F2(D, E, A) + K2 + Expand(eData, 38); D = RotL(30, D);
        A += RotL(5, B) + F2(C, D, E) + K2 + Expand(eData, 39); C = RotL(30, C);

        E += RotL(5, A) + F3(B, C, D) + K3 + Expand(eData, 40); B = RotL(30, B);
        D += RotL(5, E) + F3(A, B, C) + K3 + Expand(eData, 41); A = RotL(30, A);
        C += RotL(5, D) + F3(E, A, B) + K3 + Expand(eData, 42); E = RotL(30, E);
        B += RotL(5, C) + F3(D, E, A) + K3 + Expand(eData, 43); D = RotL(30, D);
        A += RotL(5, B) + F3(C, D, E) + K3 + Expand(eData, 44); C = RotL(30, C);
        E += RotL(5, A) + F3(B, C, D) + K3 + Expand(eData, 45); B = RotL(30, B);
        D += RotL(5, E) + F3(A, B, C) + K3 + Expand(eData, 46); A = RotL(30, A);
        C += RotL(5, D) + F3(E, A, B) + K3 + Expand(eData, 47); E = RotL(30, E);
        B += RotL(5, C) + F3(D, E, A) + K3 + Expand(eData, 48); D = RotL(30, D);
        A += RotL(5, B) + F3(C, D, E) + K3 + Expand(eData, 49); C = RotL(30, C);
        E += RotL(5, A) + F3(B, C, D) + K3 + Expand(eData, 50); B = RotL(30, B);
        D += RotL(5, E) + F3(A, B, C) + K3 + Expand(eData, 51); A = RotL(30, A);
        C += RotL(5, D) + F3(E, A, B) + K3 + Expand(eData, 52); E = RotL(30, E);
        B += RotL(5, C) + F3(D, E, A) + K3 + Expand(eData, 53); D = RotL(30, D);
        A += RotL(5, B) + F3(C, D, E) + K3 + Expand(eData, 54); C = RotL(30, C);
        E += RotL(5, A) + F3(B, C, D) + K3 + Expand(eData, 55); B = RotL(30, B);
        D += RotL(5, E) + F3(A, B, C) + K3 + Expand(eData, 56); A = RotL(30, A);
        C += RotL(5, D) + F3(E, A, B) + K3 + Expand(eData, 57); E = RotL(30, E);
        B += RotL(5, C) + F3(D, E, A) + K3 + Expand(eData, 58); D = RotL(30, D);
        A += RotL(5, B) + F3(C, D, E) + K3 + Expand(eData, 59); C = RotL(30, C);

        E += RotL(5, A) + F4(B, C, D) + K4 + Expand(eData, 60); B = RotL(30, B);
        D += RotL(5, E) + F4(A, B, C) + K4 + Expand(eData, 61); A = RotL(30, A);
        C += RotL(5, D) + F4(E, A, B) + K4 + Expand(eData, 62); E = RotL(30, E);
        B += RotL(5, C) + F4(D, E, A) + K4 + Expand(eData, 63); D = RotL(30, D);
        A += RotL(5, B) + F4(C, D, E) + K4 + Expand(eData, 64); C = RotL(30, C);
        E += RotL(5, A) + F4(B, C, D) + K4 + Expand(eData, 65); B = RotL(30, B);
        D += RotL(5, E) + F4(A, B, C) + K4 + Expand(eData, 66); A = RotL(30, A);
        C += RotL(5, D) + F4(E, A, B) + K4 + Expand(eData, 67); E = RotL(30, E);
        B += RotL(5, C) + F4(D, E, A) + K4 + Expand(eData, 68); D = RotL(30, D);
        A += RotL(5, B) + F4(C, D, E) + K4 + Expand(eData, 69); C = RotL(30, C);
        E += RotL(5, A) + F4(B, C, D) + K4 + Expand(eData, 70); B = RotL(30, B);
        D += RotL(5, E) + F4(A, B, C) + K4 + Expand(eData, 71); A = RotL(30, A);
        C += RotL(5, D) + F4(E, A, B) + K4 + Expand(eData, 72); E = RotL(30, E);
        B += RotL(5, C) + F4(D, E, A) + K4 + Expand(eData, 73); D = RotL(30, D);
        A += RotL(5, B) + F4(C, D, E) + K4 + Expand(eData, 74); C = RotL(30, C);
        E += RotL(5, A) + F4(B, C, D) + K4 + Expand(eData, 75); B = RotL(30, B);
        D += RotL(5, E) + F4(A, B, C) + K4 + Expand(eData, 76); A = RotL(30, A);
        C += RotL(5, D) + F4(E, A, B) + K4 + Expand(eData, 77); E = RotL(30, E);
        B += RotL(5, C) + F4(D, E, A) + K4 + Expand(eData, 78); D = RotL(30, D);
        A += RotL(5, B) + F4(C, D, E) + K4 + Expand(eData, 79); C = RotL(30, C);

        digest[0] += A;
        digest[1] += B;
        digest[2] += C;
        digest[3] += D;
        digest[4] += E;
    }
}
