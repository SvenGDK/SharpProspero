// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Security;

/// <summary>
/// RSA-2048 private key operation using the Chinese Remainder Theorem (CRT). Computes
/// <c>message^d mod n</c> for a 2048-bit modulus using precomputed CRT parameters.
/// </summary>
/// <remarks>
/// This is a minimal RSA implementation for PFS EKPFS key derivation, not a general-purpose
/// RSA library. It handles only the private key operation (decryption/signing) with
/// fixed 2048-bit keys.
/// </remarks>
public sealed class Rsa2048
{
    private readonly BigUint _p, _q, _dp, _dq, _qinv, _n;

    /// <summary>
    /// Initialises the RSA private key with CRT parameters.
    /// </summary>
    /// <param name="n">The 256-byte modulus (n = p * q).</param>
    /// <param name="p">The 128-byte first prime factor.</param>
    /// <param name="q">The 128-byte second prime factor.</param>
    /// <param name="dp">The 128-byte CRT exponent for p (d mod (p-1)).</param>
    /// <param name="dq">The 128-byte CRT exponent for q (d mod (q-1)).</param>
    /// <param name="qinv">The 128-byte CRT coefficient (q^-1 mod p).</param>
    public Rsa2048(ReadOnlySpan<byte> n, ReadOnlySpan<byte> p, ReadOnlySpan<byte> q,
        ReadOnlySpan<byte> dp, ReadOnlySpan<byte> dq, ReadOnlySpan<byte> qinv)
    {
        _n = new BigUint(n);
        _p = new BigUint(p);
        _q = new BigUint(q);
        _dp = new BigUint(dp);
        _dq = new BigUint(dq);
        _qinv = new BigUint(qinv);
    }

    /// <summary>
    /// Performs a raw RSA modular exponentiation: <c>message^exponent mod modulus</c>.
    /// All three inputs and the output are 256-byte big-endian buffers.
    /// </summary>
    /// <param name="message">The 256-byte input block.</param>
    /// <param name="modulus">The 256-byte RSA modulus (n).</param>
    /// <param name="exponent">The 256-byte exponent (e or d).</param>
    /// <param name="result">The 256-byte output buffer.</param>
    public static void RawOp(ReadOnlySpan<byte> message, ReadOnlySpan<byte> modulus,
        ReadOnlySpan<byte> exponent, Span<byte> result)
    {
        var m = new BigUint(message);
        var n = new BigUint(modulus);
        var e = new BigUint(exponent);
        var r = BigUint.ModPow(BigUint.Clone(m), e, n);
        r.ToBytes(result);
    }

    /// <summary>
    /// Performs the RSA private key operation on a 256-byte message block.
    /// </summary>
    /// <param name="message">The 256-byte input (ciphertext or hash to sign).</param>
    /// <param name="result">The 256-byte output buffer.</param>
    public void PrivateOp(ReadOnlySpan<byte> message, Span<byte> result)
    {
        var m = new BigUint(message);

        // CRT: m1 = m^dp mod p, m2 = m^dq mod q
        // Clone m for each ModPow since ModReduce mutates the base's Words array.
        var m1 = BigUint.ModPow(BigUint.Clone(m), _dp, _p);
        var m2 = BigUint.ModPow(BigUint.Clone(m), _dq, _q);

        // h = qinv * (m1 - m2) mod p
        var diff = BigUint.ModSub(m1, m2, _p);
        var h = BigUint.ModMul(diff, _qinv, _p);

        // result = m2 + h * q
        var hq = BigUint.Mul(h, _q);
        var res = BigUint.Add(m2, hq);

        res.ToBytes(result);
    }

    /// <summary>
    /// A minimal big-unsigned-integer type for RSA operations. Stores values as
    /// arrays of 32-bit words in little-endian order.
    /// </summary>
    internal struct BigUint
    {
        internal uint[] Words;

        internal BigUint(int wordCount)
        {
            Words = new uint[wordCount];
        }

        internal BigUint(ReadOnlySpan<byte> bigEndianBytes)
        {
            int wordCount = (bigEndianBytes.Length + 3) / 4;
            Words = new uint[wordCount];
            for (int i = 0; i < bigEndianBytes.Length; i++)
            {
                int wordIdx = (bigEndianBytes.Length - 1 - i) / 4;
                int byteIdx = (bigEndianBytes.Length - 1 - i) % 4;
                Words[wordIdx] |= (uint)bigEndianBytes[i] << (byteIdx * 8);
            }
        }

        internal void ToBytes(Span<byte> bigEndianBytes)
        {
            bigEndianBytes.Clear();
            for (int i = 0; i < bigEndianBytes.Length && i / 4 < Words.Length; i++)
            {
                int wordIdx = (bigEndianBytes.Length - 1 - i) / 4;
                int byteIdx = (bigEndianBytes.Length - 1 - i) % 4;
                if (wordIdx < Words.Length)
                    bigEndianBytes[i] = (byte)(Words[wordIdx] >> (byteIdx * 8));
            }
        }

        internal static BigUint Clone(BigUint v)
        {
            var c = new BigUint(v.Words.Length);
            Array.Copy(v.Words, c.Words, v.Words.Length);
            return c;
        }

        internal static BigUint ModPow(BigUint baseVal, BigUint exp, BigUint mod)
        {
            var result = new BigUint(mod.Words.Length);
            result.Words[0] = 1;

            var b = ModReduce(baseVal, mod);

            for (int i = 0; i < exp.Words.Length * 32; i++)
            {
                if ((exp.Words[i / 32] & (1u << (i % 32))) != 0)
                    result = ModMul(result, b, mod);
                b = ModMul(b, b, mod);
            }
            return result;
        }

        internal static BigUint ModMul(BigUint a, BigUint b, BigUint mod)
        {
            int n = mod.Words.Length;
            var product = new BigUint(n * 2 + 1);

            for (int i = 0; i < a.Words.Length && i < n; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < b.Words.Length && j < n; j++)
                {
                    ulong p = (ulong)a.Words[i] * b.Words[j] + product.Words[i + j] + carry;
                    product.Words[i + j] = (uint)p;
                    carry = p >> 32;
                }
                if (i + n < product.Words.Length)
                    product.Words[i + n] += (uint)carry;
            }

            return ModReduce(product, mod);
        }

        internal static BigUint ModSub(BigUint a, BigUint b, BigUint mod)
        {
            int n = Math.Max(a.Words.Length, Math.Max(b.Words.Length, mod.Words.Length));
            var result = new BigUint(n + 1);

            long borrow = 0;
            for (int i = 0; i < n; i++)
            {
                long av = i < a.Words.Length ? a.Words[i] : 0;
                long bv = i < b.Words.Length ? b.Words[i] : 0;
                long diff = av - bv - borrow;
                if (diff < 0) { diff += 0x100000000L; borrow = 1; }
                else borrow = 0;
                result.Words[i] = (uint)diff;
            }

            if (borrow != 0)
            {
                // result is negative, add mod
                long carry = 0;
                for (int i = 0; i < n; i++)
                {
                    long sum = (long)result.Words[i] + (i < mod.Words.Length ? mod.Words[i] : 0) + carry;
                    result.Words[i] = (uint)sum;
                    carry = sum >> 32;
                }
            }

            return result;
        }

        internal static BigUint Add(BigUint a, BigUint b)
        {
            int n = Math.Max(a.Words.Length, b.Words.Length) + 1;
            var result = new BigUint(n);
            ulong carry = 0;
            for (int i = 0; i < n; i++)
            {
                ulong sum = carry;
                if (i < a.Words.Length) sum += a.Words[i];
                if (i < b.Words.Length) sum += b.Words[i];
                result.Words[i] = (uint)sum;
                carry = sum >> 32;
            }
            return result;
        }

        internal static BigUint Mul(BigUint a, BigUint b)
        {
            int n = a.Words.Length + b.Words.Length;
            var result = new BigUint(n);
            for (int i = 0; i < a.Words.Length; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < b.Words.Length; j++)
                {
                    ulong p = (ulong)a.Words[i] * b.Words[j] + result.Words[i + j] + carry;
                    result.Words[i + j] = (uint)p;
                    carry = p >> 32;
                }
                if (i + b.Words.Length < n)
                    result.Words[i + b.Words.Length] += (uint)carry;
            }
            return result;
        }

        private static BigUint ModReduce(BigUint a, BigUint mod)
        {
            // Schoolbook long division: shift mod left until it's just larger than a,
            // then subtract in a loop, shifting right each iteration.
            int aBits = BitLength(a);
            int mBits = BitLength(mod);
            if (mBits == 0 || aBits < mBits) return a;

            int shift = aBits - mBits;
            var shifted = ShiftLeft(mod, shift);

            for (int s = shift; s >= 0; s--)
            {
                if (Compare(a, shifted) >= 0)
                {
                    long borrow = 0;
                    for (int i = 0; i < a.Words.Length; i++)
                    {
                        long diff = (long)a.Words[i] - (i < shifted.Words.Length ? shifted.Words[i] : 0) - borrow;
                        if (diff < 0) { diff += 0x100000000L; borrow = 1; }
                        else borrow = 0;
                        a.Words[i] = (uint)diff;
                    }
                }
                shifted = ShiftRight1(shifted);
            }
            return a;
        }

        private static int BitLength(BigUint v)
        {
            for (int i = v.Words.Length - 1; i >= 0; i--)
            {
                if (v.Words[i] != 0)
                {
                    int bits = i * 32;
                    uint w = v.Words[i];
                    while (w != 0) { bits++; w >>= 1; }
                    return bits;
                }
            }
            return 0;
        }

        private static BigUint ShiftLeft(BigUint v, int bits)
        {
            int wordShift = bits / 32;
            int bitShift = bits % 32;
            var result = new BigUint(v.Words.Length + wordShift + 1);
            for (int i = 0; i < v.Words.Length; i++)
            {
                ulong w = (ulong)v.Words[i] << bitShift;
                result.Words[i + wordShift] |= (uint)w;
                if (i + wordShift + 1 < result.Words.Length)
                    result.Words[i + wordShift + 1] |= (uint)(w >> 32);
            }
            return result;
        }

        private static BigUint ShiftRight1(BigUint v)
        {
            var result = new BigUint(v.Words.Length);
            for (int i = 0; i < v.Words.Length; i++)
            {
                result.Words[i] = v.Words[i] >> 1;
                if (i + 1 < v.Words.Length)
                    result.Words[i] |= v.Words[i + 1] << 31;
            }
            return result;
        }

        private static int Compare(BigUint a, BigUint b)
        {
            int n = Math.Max(a.Words.Length, b.Words.Length);
            for (int i = n - 1; i >= 0; i--)
            {
                uint av = i < a.Words.Length ? a.Words[i] : 0;
                uint bv = i < b.Words.Length ? b.Words[i] : 0;
                if (av > bv) return 1;
                if (av < bv) return -1;
            }
            return 0;
        }
    }
}
