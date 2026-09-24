// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Buffers.Binary;

namespace SharpProspero.Security;

/// <summary>
/// State for a BBMac session: the running key, the pending pad tail, and the finalisation kind.
/// </summary>
public struct BBMacContext
{
    /// <summary>Finalisation kind: 1 uses the fixed AES key, 2 the fuse id, 3 the fixed key with an extra encrypt pass.</summary>
    public int Type;
    /// <summary>The 16-byte running CBC-MAC key updated block-by-block.</summary>
    public byte[] Key;
    /// <summary>Up to 16 bytes of trailing data that did not yet make up a full block.</summary>
    public byte[] Pad;
    /// <summary>Byte count currently held in <see cref="Pad"/>.</summary>
    public int PadSize;
}

/// <summary>
/// State for a BBCipher session: the working key, the seed counter, and the finalisation kind.
/// </summary>
public struct BBCipherContext
{
    /// <summary>Finalisation kind: 1 uses the fixed AES key, 2 the fuse id.</summary>
    public uint Type;
    /// <summary>Sixteen-byte block counter used to build per-block whitening data.</summary>
    public uint Seed;
    /// <summary>The 16-byte working key held across update calls.</summary>
    public byte[] Key;
}

/// <summary>
/// The PGD container descriptor: keys, geometry and the scratch block used while decrypting.
/// </summary>
public sealed class PgdDescriptor
{
    /// <summary>Key that unwraps the PGD header itself.</summary>
    public byte[] VKey = new byte[16];
    /// <summary>Key that unwraps the PGD payload blocks.</summary>
    public byte[] DKey = new byte[16];

    public uint OpenFlag;
    public uint KeyIndex;
    public uint DrmType;
    public uint MacType;
    public uint CipherType;

    public uint DataSize;
    public uint AlignSize;
    public uint BlockSize;
    public uint BlockNr;
    public uint DataOffset;
    public uint TableOffset;

    /// <summary>Scratch buffer sized for two encrypted blocks.</summary>
    public byte[]? BlockBuf;
    public uint CurrentBlock;
    public uint FileOffset;
}

/// <summary>
/// Managed translation of the amctrl BBMac / BBCipher / NPDRM key derivation and PGD open
/// primitives. KIRK calls are dispatched through
/// <see cref="KirkEngine.sceUtilsBufferCopyWithRange(KirkState, byte[], int, byte[], int, int)"/>; this class wraps the CBC-MAC
/// construction, the counter-based whitening cipher, and the NPDRM fixed-key mixer. Each API
/// entry point allocates its own 0x814-byte scratch buffer that plays the role of libamctrl's
/// per-caller <c>kirk-&gt;kirk_buf</c> and gives the underlying KIRK dispatcher a single
/// contiguous region for headers and data.
/// </summary>
public static class Amctrl
{
    // Header (0x14) plus 0x800 of payload data - the same working size libamctrl reserves.
    private const int KirkBufSize = 0x814;

    private static ReadOnlySpan<byte> Loc1CD4 => [0xE3, 0x50, 0xED, 0x1D, 0x91, 0x0A, 0x1F, 0xD0, 0x29, 0xBB, 0x1C, 0x3E, 0xF3, 0x40, 0x77, 0xFB];
    private static ReadOnlySpan<byte> Loc1CE4 => [0x13, 0x5F, 0xA4, 0x7C, 0xAB, 0x39, 0x5B, 0xA4, 0x76, 0xB8, 0xCC, 0xA9, 0x8F, 0x3A, 0x04, 0x45];
    private static ReadOnlySpan<byte> Loc1CF4 => [0x67, 0x8D, 0x7F, 0xA3, 0x2A, 0x9C, 0xA0, 0xD1, 0x50, 0x8A, 0xD8, 0x38, 0x5E, 0x4B, 0x01, 0x7E];

    private static ReadOnlySpan<byte> Key357C =>
    [
        0x07, 0x3D, 0x9E, 0x9D, 0xA8, 0xFD, 0x3B, 0x2F, 0x63, 0x18, 0x93, 0x2E, 0xF8, 0x57, 0xA6, 0x64,
        0x37, 0x49, 0xB7, 0x01, 0xCA, 0xE2, 0xE0, 0xC5, 0x44, 0x2E, 0x06, 0xB6, 0x1E, 0xFF, 0x84, 0xF2,
        0x9D, 0x31, 0xB8, 0x5A, 0xC8, 0xFA, 0x16, 0x80, 0x73, 0x60, 0x18, 0x82, 0x18, 0x77, 0x91, 0x9D,
    ];

    private static ReadOnlySpan<byte> Key363C =>
        [0x38, 0x20, 0xD0, 0x11, 0x07, 0xA3, 0xFF, 0x3E, 0x0A, 0x4C, 0x20, 0x85, 0x39, 0x10, 0xB5, 0x54];

    private static ReadOnlySpan<byte> DnasKey1A90 =>
        [0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43];

    private static ReadOnlySpan<byte> DnasKey1AA0 =>
        [0x27, 0x74, 0xFB, 0xEB, 0xA4, 0xA0, 0x01, 0xD7, 0x02, 0x56, 0x9E, 0x33, 0x8C, 0x19, 0x57, 0x83];

    private static int DoKirk4(KirkState kirk, byte[] buf, int size, int type)
    {
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0, 4), 4);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12, 4), type);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(16, 4), size);

        int retv = KirkEngine.sceUtilsBufferCopyWithRange(kirk, buf, size + 0x14, buf, size, 4);
        if (retv != 0)
            return unchecked((int)0x80510311);
        return 0;
    }

    private static int DoKirk7(KirkState kirk, byte[] buf, int size, int type)
    {
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0, 4), 5);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12, 4), type);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(16, 4), size);

        int retv = KirkEngine.sceUtilsBufferCopyWithRange(kirk, buf, size + 0x14, buf, size, 7);
        if (retv != 0)
            return unchecked((int)0x80510311);
        return 0;
    }

    private static int Kirk5(KirkState kirk, byte[] buf, int size)
    {
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0, 4), 4);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12, 4), 0x0100);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(16, 4), size);

        int retv = KirkEngine.sceUtilsBufferCopyWithRange(kirk, buf, size + 0x14, buf, size, 5);
        if (retv != 0)
            return unchecked((int)0x80510312);
        return 0;
    }

    private static int Kirk8(KirkState kirk, byte[] buf, int size)
    {
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(0, 4), 5);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(4, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(8, 4), 0);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(12, 4), 0x0100);
        BinaryPrimitives.WriteInt32LittleEndian(buf.AsSpan(16, 4), size);

        int retv = KirkEngine.sceUtilsBufferCopyWithRange(kirk, buf, size + 0x14, buf, size, 8);
        if (retv != 0)
            return unchecked((int)0x80510312);
        return 0;
    }

    private static int Kirk14(KirkState kirk, byte[] buf)
    {
        int retv = KirkEngine.sceUtilsBufferCopyWithRange(kirk, buf, 0x14, null, 0, 14);
        if (retv != 0)
            return unchecked((int)0x80510315);
        return 0;
    }

    private static int Sub158(KirkState kirk, byte[] buf, int size, byte[] key, int keyType)
    {
        for (int i = 0; i < 16; i++)
            buf[0x14 + i] ^= key[i];

        int retv = DoKirk4(kirk, buf, size, keyType);
        if (retv != 0)
            return retv;

        // The last encrypted block becomes the new running key.
        Buffer.BlockCopy(buf, size + 4, key, 0, 16);
        return 0;
    }

    /// <summary>
    /// Resets a BBMac context. <paramref name="type"/> selects the finalisation kind: 1 (fixed
    /// key), 2 (fuse id) or 3 (fixed key with extra encryption of the final tag).
    /// </summary>
    public static int sceDrmBBMacInit(ref BBMacContext mkey, int type)
    {
        mkey.Type = type;
        mkey.PadSize = 0;
        mkey.Key = new byte[16];
        mkey.Pad = new byte[16];
        return 0;
    }

    /// <summary>
    /// Feeds <paramref name="size"/> bytes of <paramref name="buf"/> into the running BBMac. Any
    /// tail shorter than a block is held in the context's pad and picked up on the next call or
    /// at finalisation.
    /// </summary>
    public static int sceDrmBBMacUpdate(KirkState kirk, ref BBMacContext mkey, byte[] buf, int size)
    {
        if (mkey.PadSize > 16)
            return unchecked((int)0x80510302);

        if (mkey.PadSize + size <= 16)
        {
            Buffer.BlockCopy(buf, 0, mkey.Pad, mkey.PadSize, size);
            mkey.PadSize += size;
            return 0;
        }

        byte[] kirkBuf = new byte[KirkBufSize];
        // Prime kbuf (kirk_buf+0x14) with the pending pad tail from the previous call.
        Buffer.BlockCopy(mkey.Pad, 0, kirkBuf, 0x14, mkey.PadSize);
        int p = mkey.PadSize;

        mkey.PadSize += size;
        mkey.PadSize &= 0x0f;
        if (mkey.PadSize == 0)
            mkey.PadSize = 16;

        size -= mkey.PadSize;
        // Save the new tail bytes for next call / finalisation.
        Buffer.BlockCopy(buf, size, mkey.Pad, 0, mkey.PadSize);

        int type = (mkey.Type == 2) ? 0x3A : 0x38;
        int bufOffset = 0;

        while (size > 0)
        {
            int ksize = (size + p >= 0x0800) ? 0x0800 : size + p;
            Buffer.BlockCopy(buf, bufOffset, kirkBuf, 0x14 + p, ksize - p);
            int retv = Sub158(kirk, kirkBuf, ksize, mkey.Key, type);
            if (retv != 0)
                return retv;
            size -= (ksize - p);
            bufOffset += ksize - p;
            p = 0;
        }

        return 0;
    }

    /// <summary>
    /// Closes a BBMac session and writes the 16-byte tag into <paramref name="buf"/>. When
    /// <paramref name="vkey"/> is non-null the tag is XORed with it, encrypted through a KIRK
    /// pass that uses <paramref name="mkey"/>'s finalisation code, and stored back.
    /// </summary>
    public static int sceDrmBBMacFinal(KirkState kirk, ref BBMacContext mkey, byte[] buf, byte[]? vkey)
    {
        if (mkey.PadSize > 16)
            return unchecked((int)0x80510302);

        int code = (mkey.Type == 2) ? 0x3A : 0x38;
        byte[] kirkBuf = new byte[KirkBufSize];
        Span<byte> kbuf = kirkBuf.AsSpan(0x14);

        kbuf[..16].Clear();
        int retv = DoKirk4(kirk, kirkBuf, 16, code);
        if (retv != 0)
            return retv;

        Span<byte> tmp = stackalloc byte[16];
        kbuf[..16].CopyTo(tmp);

        // Shift tmp left one bit, then XOR the low byte with 0x87 if the top bit was set.
        int t0 = ((tmp[0] & 0x80) != 0) ? 0x87 : 0;
        for (int i = 0; i < 15; i++)
        {
            uint v1 = tmp[i];
            uint v0 = tmp[i + 1];
            v1 <<= 1;
            v0 >>= 7;
            v0 |= v1;
            tmp[i] = (byte)v0;
        }
        {
            uint v0 = tmp[15];
            v0 <<= 1;
            v0 ^= (uint)t0;
            tmp[15] = (byte)v0;
        }

        if (mkey.PadSize < 16)
        {
            // Second shift, matched to the pad-with-0x80 branch of the CBC-MAC construction.
            t0 = ((tmp[0] & 0x80) != 0) ? 0x87 : 0;
            for (int i = 0; i < 15; i++)
            {
                uint v1 = tmp[i];
                uint v0 = tmp[i + 1];
                v1 <<= 1;
                v0 >>= 7;
                v0 |= v1;
                tmp[i] = (byte)v0;
            }
            {
                uint v0 = tmp[15];
                v0 <<= 1;
                v0 ^= (uint)t0;
                tmp[15] = (byte)v0;
            }

            mkey.Pad[mkey.PadSize] = 0x80;
            if (mkey.PadSize + 1 < 16)
                Array.Clear(mkey.Pad, mkey.PadSize + 1, 16 - mkey.PadSize - 1);
        }

        for (int i = 0; i < 16; i++)
            mkey.Pad[i] ^= tmp[i];

        Buffer.BlockCopy(mkey.Pad, 0, kirkBuf, 0x14, 16);
        Span<byte> tmp1 = stackalloc byte[16];
        mkey.Key.AsSpan(0, 16).CopyTo(tmp1);

        byte[] tmp1Array = tmp1.ToArray();
        retv = Sub158(kirk, kirkBuf, 0x10, tmp1Array, code);
        if (retv != 0)
            return retv;
        tmp1Array.CopyTo(tmp1);

        for (int i = 0; i < 16; i++)
            tmp1[i] ^= Loc1CD4[i];

        if (mkey.Type == 2)
        {
            tmp1.CopyTo(kirkBuf.AsSpan(0x14, 16));

            retv = Kirk5(kirk, kirkBuf, 0x10);
            if (retv != 0)
                return retv;

            retv = DoKirk4(kirk, kirkBuf, 0x10, code);
            if (retv != 0)
                return retv;

            kirkBuf.AsSpan(0x14, 16).CopyTo(tmp1);
        }

        if (vkey != null)
        {
            for (int i = 0; i < 16; i++)
                tmp1[i] ^= vkey[i];
            tmp1.CopyTo(kirkBuf.AsSpan(0x14, 16));

            retv = DoKirk4(kirk, kirkBuf, 0x10, code);
            if (retv != 0)
                return retv;

            kirkBuf.AsSpan(0x14, 16).CopyTo(tmp1);
        }

        tmp1.CopyTo(buf.AsSpan(0, 16));

        Array.Clear(mkey.Key, 0, 16);
        Array.Clear(mkey.Pad, 0, 16);
        mkey.PadSize = 0;
        mkey.Type = 0;
        return 0;
    }

    /// <summary>
    /// Compares the tag Amctrl would emit against <paramref name="outBuf"/>; on type 3 the
    /// candidate tag is first passed through a KIRK 7 decrypt with seed 0x63.
    /// </summary>
    public static int sceDrmBBMacFinal2(KirkState kirk, ref BBMacContext mkey, byte[] outBuf, byte[]? vkey)
    {
        int type = mkey.Type;
        byte[] tmp = new byte[16];
        int retv = sceDrmBBMacFinal(kirk, ref mkey, tmp, vkey);
        if (retv != 0)
            return retv;

        byte[] kirkBuf = new byte[KirkBufSize];
        if (type == 3)
        {
            Buffer.BlockCopy(outBuf, 0, kirkBuf, 0x14, 0x10);
            DoKirk7(kirk, kirkBuf, 0x10, 0x63);
        }
        else
        {
            Buffer.BlockCopy(outBuf, 0, kirkBuf, 0, 0x10);
        }

        for (int i = 0; i < 0x10; i++)
        {
            if (kirkBuf[i] != tmp[i])
                return unchecked((int)0x80510300);
        }
        return 0;
    }

    /// <summary>
    /// Recovers the vkey a stored BBMac tag was XORed against, given the running mac context and
    /// the tag itself.
    /// </summary>
    public static int bbmac_getkey(KirkState kirk, ref BBMacContext mkey, byte[] bbmac, byte[] vkey)
    {
        int type = mkey.Type;
        byte[] tmp = new byte[16];
        int retv = sceDrmBBMacFinal(kirk, ref mkey, tmp, null);
        if (retv != 0)
            return retv;

        byte[] kirkBuf = new byte[KirkBufSize];

        if (type == 3)
        {
            Buffer.BlockCopy(bbmac, 0, kirkBuf, 0x14, 0x10);
            DoKirk7(kirk, kirkBuf, 0x10, 0x63);
        }
        else
        {
            Buffer.BlockCopy(bbmac, 0, kirkBuf, 0, 0x10);
        }

        byte[] tmp1 = new byte[16];
        Buffer.BlockCopy(kirkBuf, 0, tmp1, 0, 16);
        Buffer.BlockCopy(tmp1, 0, kirkBuf, 0x14, 16);

        int code = (type == 2) ? 0x3A : 0x38;
        DoKirk7(kirk, kirkBuf, 0x10, code);

        for (int i = 0; i < 0x10; i++)
            vkey[i] = (byte)(tmp[i] ^ kirkBuf[i]);

        return 0;
    }

    private static int Sub1F8(KirkState kirk, byte[] buf, int size, byte[] key, int keyType)
    {
        byte[] tmp = new byte[16];
        Buffer.BlockCopy(buf, size + 0x14 - 16, tmp, 0, 16);

        int retv = DoKirk7(kirk, buf, size, keyType);
        if (retv != 0)
            return retv;

        for (int i = 0; i < 16; i++)
            buf[i] ^= key[i];

        Buffer.BlockCopy(tmp, 0, key, 0, 16);
        return 0;
    }

    private static int Sub428(KirkState kirk, byte[] kbuf, byte[] dbuf, int dbufOffset, int size, ref BBCipherContext ckey)
    {
        Buffer.BlockCopy(ckey.Key, 0, kbuf, 0x14, 16);

        for (int i = 0; i < 16; i++)
            kbuf[0x14 + i] ^= Loc1CF4[i];

        int retv;
        if (ckey.Type == 2)
            retv = Kirk8(kirk, kbuf, 16);
        else
            retv = DoKirk7(kirk, kbuf, 16, 0x39);
        if (retv != 0)
            return retv;

        for (int i = 0; i < 16; i++)
            kbuf[i] ^= Loc1CE4[i];

        byte[] tmp2 = new byte[16];
        Buffer.BlockCopy(kbuf, 0, tmp2, 0, 0x10);

        byte[] tmp1 = new byte[16];
        if (ckey.Seed == 1)
        {
            // tmp1 already zero
        }
        else
        {
            Buffer.BlockCopy(tmp2, 0, tmp1, 0, 0x10);
            BinaryPrimitives.WriteUInt32LittleEndian(tmp1.AsSpan(0x0c, 4), ckey.Seed - 1);
        }

        for (int i = 0; i < size; i += 16)
        {
            Buffer.BlockCopy(tmp2, 0, kbuf, 0x14 + i, 12);
            BinaryPrimitives.WriteUInt32LittleEndian(kbuf.AsSpan(0x14 + i + 12, 4), ckey.Seed);
            ckey.Seed += 1;
        }

        retv = Sub1F8(kirk, kbuf, size, tmp1, 0x63);
        if (retv != 0)
            return retv;

        for (int i = 0; i < size; i++)
            dbuf[dbufOffset + i] ^= kbuf[i];

        return 0;
    }

    /// <summary>
    /// Sets up a BBCipher context. <paramref name="mode"/> is 1 to encrypt or 2 to decrypt;
    /// <paramref name="type"/> is 1 for the fixed key or 2 for the fuse-id key. In decrypt mode
    /// the context's key is derived from <paramref name="headerKey"/> and, when supplied,
    /// XORed with <paramref name="versionKey"/>. In encrypt mode the header key is generated
    /// through KIRK 14 and written back into <paramref name="headerKey"/>.
    /// </summary>
    public static int sceDrmBBCipherInit(KirkState kirk, ref BBCipherContext ckey, int type, int mode, byte[] headerKey, byte[]? versionKey, uint seed)
    {
        ckey.Type = (uint)type;
        if (ckey.Key == null)
            ckey.Key = new byte[16];

        int retv;
        if (mode == 2)
        {
            ckey.Seed = seed + 1;
            for (int i = 0; i < 16; i++)
                ckey.Key[i] = headerKey[i];
            if (versionKey != null)
            {
                for (int i = 0; i < 16; i++)
                    ckey.Key[i] ^= versionKey[i];
            }
            retv = 0;
        }
        else if (mode == 1)
        {
            byte[] kirkBuf = new byte[KirkBufSize];
            ckey.Seed = 1;
            retv = Kirk14(kirk, kirkBuf);
            if (retv != 0)
                return retv;

            Buffer.BlockCopy(kirkBuf, 0, kirkBuf, 0x14, 0x10);
            Array.Clear(kirkBuf, 0x14 + 0x0c, 4);

            if (ckey.Type == 2)
            {
                for (int i = 0; i < 16; i++)
                    kirkBuf[0x14 + i] ^= Loc1CE4[i];
                retv = Kirk5(kirk, kirkBuf, 0x10);
                for (int i = 0; i < 16; i++)
                    kirkBuf[0x14 + i] ^= Loc1CF4[i];
            }
            else
            {
                for (int i = 0; i < 16; i++)
                    kirkBuf[0x14 + i] ^= Loc1CE4[i];
                retv = DoKirk4(kirk, kirkBuf, 0x10, 0x39);
                for (int i = 0; i < 16; i++)
                    kirkBuf[0x14 + i] ^= Loc1CF4[i];
            }
            if (retv != 0)
                return retv;

            Buffer.BlockCopy(kirkBuf, 0x14, ckey.Key, 0, 0x10);
            Buffer.BlockCopy(kirkBuf, 0x14, headerKey, 0, 0x10);

            if (versionKey != null)
            {
                for (int i = 0; i < 16; i++)
                    ckey.Key[i] ^= versionKey[i];
            }
        }
        else
        {
            retv = 0;
        }

        return retv;
    }

    /// <summary>
    /// Runs <paramref name="size"/> bytes of <paramref name="data"/> through a BBCipher block
    /// pass, whitening them in place. The context advances its seed and can be called again
    /// to consume the next region.
    /// </summary>
    public static int sceDrmBBCipherUpdate(KirkState kirk, ref BBCipherContext ckey, byte[] data, int size)
    {
        byte[] kirkBuf = new byte[KirkBufSize];
        int retv = 0;
        int p = 0;

        while (size > 0)
        {
            int dsize = (size >= 0x0800) ? 0x0800 : size;
            retv = Sub428(kirk, kirkBuf, data, p, dsize, ref ckey);
            if (retv != 0)
                break;
            size -= dsize;
            p += dsize;
        }

        return retv;
    }

    /// <summary>Wipes a BBCipher context's key, kind and seed.</summary>
    public static int sceDrmBBCipherFinal(ref BBCipherContext ckey)
    {
        if (ckey.Key != null)
            Array.Clear(ckey.Key, 0, 16);
        ckey.Type = 0;
        ckey.Seed = 0;
        return 0;
    }

    /// <summary>
    /// Derives an NPDRM fixed key. <paramref name="type"/> must carry the 0x01000000 flag; the
    /// low byte then picks one of four post-MAC AES passes. The 48-byte pass-key table (three
    /// AES-128 keys) is bundled in <see cref="Key357C"/>; the base BBMac vkey is bundled in
    /// <see cref="Key363C"/>.
    /// </summary>
    public static int sceNpDrmGetFixedKey(KirkState kirk, byte[] key, string npstr, int type)
    {
        if ((type & 0x01000000) == 0)
            return unchecked((int)0x80550901);
        type &= 0x000000ff;

        byte[] strbuf = new byte[0x30];
        // strncpy(strbuf, npstr, 0x30) - copies up to 0x30 bytes; strbuf was zeroed on allocation.
        int copyLen = Math.Min(npstr.Length, 0x30);
        for (int i = 0; i < copyLen; i++)
        {
            char c = npstr[i];
            if (c > 0xFF)
                c = (char)0;
            strbuf[i] = (byte)c;
        }

        BBMacContext mkey = default;
        int retv = sceDrmBBMacInit(ref mkey, 1);
        if (retv != 0)
            return retv;

        retv = sceDrmBBMacUpdate(kirk, ref mkey, strbuf, 0x30);
        if (retv != 0)
            return retv;

        retv = sceDrmBBMacFinal(kirk, ref mkey, key, Key363C.ToArray());
        if (retv != 0)
            return unchecked((int)0x80550902);

        if (type == 0)
            return 0;
        if (type > 3)
            return unchecked((int)0x80550901);
        type = (type - 1) * 16;

        var aes = new Aes128(Key357C.Slice(type, 16));
        aes.EncryptBlock(key.AsSpan(0, 16));
        return 0;
    }

    /// <summary>
    /// Opens a PGD-wrapped buffer: verifies the header MAC, recovers the version key from the
    /// second MAC, unwraps the block-key metadata region, and lays out the block table. The
    /// returned descriptor owns a scratch buffer sized for two encrypted blocks.
    /// </summary>
    public static PgdDescriptor? PgdOpen(KirkState kirk, byte[] pgdBuf, int pgdFlag, byte[]? pgdVkey)
    {
        var pgd = new PgdDescriptor
        {
            KeyIndex = BinaryPrimitives.ReadUInt32LittleEndian(pgdBuf.AsSpan(4, 4)),
            DrmType = BinaryPrimitives.ReadUInt32LittleEndian(pgdBuf.AsSpan(8, 4)),
        };

        if (pgd.DrmType == 1)
        {
            pgd.MacType = 1;
            pgdFlag |= 4;
            if (pgd.KeyIndex > 1)
            {
                pgd.MacType = 3;
                pgdFlag |= 8;
            }
            pgd.CipherType = 1;
        }
        else
        {
            pgd.MacType = 2;
            pgd.CipherType = 2;
        }
        pgd.OpenFlag = (uint)pgdFlag;

        byte[]? fkey = null;
        if ((pgdFlag & 2) != 0)
            fkey = DnasKey1A90.ToArray();
        if ((pgdFlag & 1) != 0)
            fkey = DnasKey1AA0.ToArray();
        if (fkey == null)
            return null;

        BBMacContext mkey = default;
        sceDrmBBMacInit(ref mkey, (int)pgd.MacType);
        sceDrmBBMacUpdate(kirk, ref mkey, pgdBuf, 0x80);
        byte[] tag80 = new byte[16];
        Buffer.BlockCopy(pgdBuf, 0x80, tag80, 0, 16);
        int retv = sceDrmBBMacFinal2(kirk, ref mkey, tag80, fkey);
        if (retv != 0)
            return null;

        mkey = default;
        sceDrmBBMacInit(ref mkey, (int)pgd.MacType);
        sceDrmBBMacUpdate(kirk, ref mkey, pgdBuf, 0x70);
        byte[] tag70 = new byte[16];
        Buffer.BlockCopy(pgdBuf, 0x70, tag70, 0, 16);
        if (pgdVkey != null)
        {
            retv = sceDrmBBMacFinal2(kirk, ref mkey, tag70, pgdVkey);
            if (retv != 0)
                return null;
            Buffer.BlockCopy(pgdVkey, 0, pgd.VKey, 0, 16);
        }
        else
        {
            bbmac_getkey(kirk, ref mkey, tag70, pgd.VKey);
        }

        BBCipherContext ckey = default;
        byte[] headerKey = new byte[16];
        Buffer.BlockCopy(pgdBuf, 0x10, headerKey, 0, 16);
        sceDrmBBCipherInit(kirk, ref ckey, (int)pgd.CipherType, 2, headerKey, pgd.VKey, 0);
        byte[] descRegion = new byte[0x30];
        Buffer.BlockCopy(pgdBuf, 0x30, descRegion, 0, 0x30);
        sceDrmBBCipherUpdate(kirk, ref ckey, descRegion, 0x30);
        sceDrmBBCipherFinal(ref ckey);
        Buffer.BlockCopy(descRegion, 0, pgdBuf, 0x30, 0x30);

        pgd.DataSize = BinaryPrimitives.ReadUInt32LittleEndian(pgdBuf.AsSpan(0x44, 4));
        pgd.BlockSize = BinaryPrimitives.ReadUInt32LittleEndian(pgdBuf.AsSpan(0x48, 4));
        pgd.DataOffset = BinaryPrimitives.ReadUInt32LittleEndian(pgdBuf.AsSpan(0x4c, 4));
        Buffer.BlockCopy(pgdBuf, 0x30, pgd.DKey, 0, 16);

        pgd.AlignSize = (pgd.DataSize + 15) & ~15u;
        pgd.TableOffset = pgd.DataOffset + pgd.AlignSize;
        pgd.BlockNr = (pgd.AlignSize + pgd.BlockSize - 1) & ~(pgd.BlockSize - 1);
        pgd.BlockNr = pgd.BlockNr / pgd.BlockSize;

        pgd.FileOffset = 0;
        pgd.CurrentBlock = 0xFFFFFFFFu;
        pgd.BlockBuf = new byte[pgd.BlockSize * 2];

        return pgd;
    }

    /// <summary>
    /// Decrypts one PGD block from <see cref="PgdDescriptor.BlockBuf"/> in place using the
    /// descriptor's data key and the block index as the whitening seed.
    /// </summary>
    public static int PgdDecryptBlock(KirkState kirk, PgdDescriptor pgd, int block)
    {
        BBCipherContext ckey = default;
        uint blockOffset = (uint)block * pgd.BlockSize;
        sceDrmBBCipherInit(kirk, ref ckey, (int)pgd.CipherType, 2, pgd.DKey, pgd.VKey, blockOffset >> 4);
        sceDrmBBCipherUpdate(kirk, ref ckey, pgd.BlockBuf!, (int)pgd.BlockSize);
        sceDrmBBCipherFinal(ref ckey);
        return (int)pgd.BlockSize;
    }

    /// <summary>Releases a PGD descriptor's scratch buffer.</summary>
    public static int PgdClose(PgdDescriptor? pgd)
    {
        if (pgd != null)
            pgd.BlockBuf = null;
        return 0;
    }
}
