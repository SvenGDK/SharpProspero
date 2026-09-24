// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Buffers.Binary;

namespace SharpProspero.Security;

/// <summary>
/// The per-caller state carried by every KIRK engine call: the PRNG state, the fuse-ID mirror
/// registers, the initialization flag, and the fixed KIRK-1 AES context. Callers hold one of
/// these and pass it to <see cref="KirkEngine"/> dispatch methods, or use the process-wide
/// <see cref="Default"/> instance through <see cref="KirkEngine.sceUtilsBufferCopyWithRange(byte[], int, byte[], int, int)"/>.
/// </summary>
/// <remarks>
/// ECDSA commands (12, 13, 16, 17) are not implemented; each returns
/// <see cref="KIRK_SIG_CHECK_INVALID"/>. Command 1 with <c>ecdsa_hash == 1</c> skips signature
/// verification and proceeds straight to the body decrypt; callers are responsible for
/// establishing signature trust before dispatching that path.
/// </remarks>
public sealed class KirkState
{
    // ------------------------- Return codes -------------------------

    /// <summary>Operation succeeded.</summary>
    public const int KIRK_OPERATION_SUCCESS = 0;
    /// <summary>KIRK is disabled.</summary>
    public const int KIRK_NOT_ENABLED = 1;
    /// <summary>Header carries a mode this command does not accept.</summary>
    public const int KIRK_INVALID_MODE = 2;
    /// <summary>CMAC over header bytes did not match the stored value.</summary>
    public const int KIRK_HEADER_HASH_INVALID = 3;
    /// <summary>CMAC over data bytes did not match the stored value.</summary>
    public const int KIRK_DATA_HASH_INVALID = 4;
    /// <summary>ECDSA signature check failed, or this build cannot check it.</summary>
    public const int KIRK_SIG_CHECK_INVALID = 5;
    /// <summary>Reserved KIRK error slot.</summary>
    public const int KIRK_UNK_1 = 6;
    /// <summary>Reserved KIRK error slot.</summary>
    public const int KIRK_UNK_2 = 7;
    /// <summary>Reserved KIRK error slot.</summary>
    public const int KIRK_UNK_3 = 8;
    /// <summary>Reserved KIRK error slot.</summary>
    public const int KIRK_UNK_4 = 9;
    /// <summary>Reserved KIRK error slot.</summary>
    public const int KIRK_UNK_5 = 0xA;
    /// <summary>Reserved KIRK error slot.</summary>
    public const int KIRK_UNK_6 = 0xB;
    /// <summary>The engine has not been initialised.</summary>
    public const int KIRK_NOT_INITIALIZED = 0xC;
    /// <summary>The requested operation is not valid in this state.</summary>
    public const int KIRK_INVALID_OPERATION = 0xD;
    /// <summary>The header carries an unrecognised seed code.</summary>
    public const int KIRK_INVALID_SEED_CODE = 0xE;
    /// <summary>The passed buffer is smaller than the command needs.</summary>
    public const int KIRK_INVALID_SIZE = 0xF;
    /// <summary>The header data size is zero.</summary>
    public const int KIRK_DATA_SIZE_ZERO = 0x10;

    // ------------------------- Command IDs (mode passed to sceUtilsBufferCopyWithRange) -------------------------

    /// <summary>Command 1: super-decrypt with CMAC header verification.</summary>
    public const int KIRK_CMD_DECRYPT_PRIVATE = 1;
    /// <summary>Command 2 (encrypt-with-private-sig; not implemented).</summary>
    public const int KIRK_CMD_2 = 2;
    /// <summary>Command 3 (decrypt-with-private-sig; not implemented).</summary>
    public const int KIRK_CMD_3 = 3;
    /// <summary>Command 4: AES-128-CBC encrypt with IV = 0 and a seed-selected key.</summary>
    public const int KIRK_CMD_ENCRYPT_IV_0 = 4;
    /// <summary>Command 5 (encrypt with IV = fuse ID; not implemented).</summary>
    public const int KIRK_CMD_ENCRYPT_IV_FUSE = 5;
    /// <summary>Command 6 (encrypt with IV = user; not implemented).</summary>
    public const int KIRK_CMD_ENCRYPT_IV_USER = 6;
    /// <summary>Command 7: AES-128-CBC decrypt with IV = 0 and a seed-selected key.</summary>
    public const int KIRK_CMD_DECRYPT_IV_0 = 7;
    /// <summary>Command 8 (decrypt with IV = fuse ID; not implemented).</summary>
    public const int KIRK_CMD_DECRYPT_IV_FUSE = 8;
    /// <summary>Command 9 (decrypt with IV = user; not implemented).</summary>
    public const int KIRK_CMD_DECRYPT_IV_USER = 9;
    /// <summary>Command 10: verify a command-1 header's CMAC hashes in place.</summary>
    public const int KIRK_CMD_PRIV_SIGN_CHECK = 10;
    /// <summary>Command 11: SHA-1 hash of a length-prefixed buffer.</summary>
    public const int KIRK_CMD_SHA1_HASH = 11;
    /// <summary>Command 12: ECDSA key-pair generation (not implemented).</summary>
    public const int KIRK_CMD_ECDSA_GEN_KEYS = 12;
    /// <summary>Command 13: ECDSA point multiplication (not implemented).</summary>
    public const int KIRK_CMD_ECDSA_MULTIPLY_POINT = 13;
    /// <summary>Command 14: pseudo-random number generation.</summary>
    public const int KIRK_CMD_PRNG = 14;
    /// <summary>Command 15 (reserved).</summary>
    public const int KIRK_CMD_15 = 15;
    /// <summary>Command 16: ECDSA sign (not implemented).</summary>
    public const int KIRK_CMD_ECDSA_SIGN = 16;
    /// <summary>Command 17: ECDSA verify (not implemented).</summary>
    public const int KIRK_CMD_ECDSA_VERIFY = 17;

    // ------------------------- Header "mode" values -------------------------

    /// <summary>Header mode 1: KIRK command-1 payload.</summary>
    public const int KIRK_MODE_CMD1 = 1;
    /// <summary>Header mode 2: KIRK command-2 payload.</summary>
    public const int KIRK_MODE_CMD2 = 2;
    /// <summary>Header mode 3: KIRK command-3 payload.</summary>
    public const int KIRK_MODE_CMD3 = 3;
    /// <summary>Header mode 4: KIRK command-4/5/6 (encrypt) payload.</summary>
    public const int KIRK_MODE_ENCRYPT_CBC = 4;
    /// <summary>Header mode 5: KIRK command-7/8/9 (decrypt) payload.</summary>
    public const int KIRK_MODE_DECRYPT_CBC = 5;

    // ------------------------- sceUtilsBufferCopyWithRange errors -------------------------

    /// <summary>Input buffer is not aligned to 16 bytes. Name mirrors the libkirk typo.</summary>
    public const int SUBCWR_NOT_16_ALGINED = 0x90A;
    /// <summary>Header CMAC did not verify.</summary>
    public const int SUBCWR_HEADER_HASH_INVALID = 0x920;
    /// <summary>Caller's output buffer is smaller than the command needs.</summary>
    public const int SUBCWR_BUFFER_TOO_SMALL = 0x1000;

    // ------------------------- Header layouts -------------------------

    /// <summary>Byte layout of a KIRK command-1 header (0x90 bytes total).</summary>
    /// <remarks>
    /// Offsets, from <c>kirk_engine.h</c>'s <c>KIRK_CMD1_HEADER</c>:
    /// <list type="table">
    /// <item><term>0x00</term><description>AES_key[16]</description></item>
    /// <item><term>0x10</term><description>CMAC_key[16]</description></item>
    /// <item><term>0x20</term><description>CMAC_header_hash[16]</description></item>
    /// <item><term>0x30</term><description>CMAC_data_hash[16]</description></item>
    /// <item><term>0x40</term><description>unused[32]</description></item>
    /// <item><term>0x60</term><description>mode (u32 little-endian)</description></item>
    /// <item><term>0x64</term><description>ecdsa_hash (u8)</description></item>
    /// <item><term>0x65</term><description>unk3[11]</description></item>
    /// <item><term>0x70</term><description>data_size (u32 little-endian)</description></item>
    /// <item><term>0x74</term><description>data_offset (u32 little-endian)</description></item>
    /// <item><term>0x78</term><description>unk4[8]</description></item>
    /// <item><term>0x80</term><description>unk5[16]</description></item>
    /// </list>
    /// </remarks>
    public readonly ref struct Cmd1Header
    {
        /// <summary>Total header size in bytes.</summary>
        public const int Size = 0x90;

        private readonly Span<byte> _bytes;

        /// <summary>Wraps the first <see cref="Size"/> bytes of <paramref name="bytes"/>.</summary>
        public Cmd1Header(Span<byte> bytes)
        {
            if (bytes.Length < Size)
                throw new ArgumentException($"KIRK command-1 header needs {Size} bytes.", nameof(bytes));
            _bytes = bytes[..Size];
        }

        /// <summary>AES-128 encryption key, offset 0x00 (16 bytes).</summary>
        public Span<byte> AesKey => _bytes.Slice(0x00, 16);
        /// <summary>AES-CMAC key, offset 0x10 (16 bytes).</summary>
        public Span<byte> CmacKey => _bytes.Slice(0x10, 16);
        /// <summary>CMAC over the 0x30 body-header bytes starting at 0x60, at offset 0x20 (16 bytes).</summary>
        public Span<byte> CmacHeaderHash => _bytes.Slice(0x20, 16);
        /// <summary>CMAC over the body-header and payload, at offset 0x30 (16 bytes).</summary>
        public Span<byte> CmacDataHash => _bytes.Slice(0x30, 16);

        /// <summary>Mode field (u32 little-endian, offset 0x60).</summary>
        public uint Mode
        {
            get => BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x60, 4));
            set => BinaryPrimitives.WriteUInt32LittleEndian(_bytes.Slice(0x60, 4), value);
        }

        /// <summary>ECDSA hash flag (u8, offset 0x64).</summary>
        public byte EcdsaHash => _bytes[0x64];

        /// <summary>Data size (u32 little-endian, offset 0x70).</summary>
        public int DataSize => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x70, 4));

        /// <summary>Data offset (u32 little-endian, offset 0x74).</summary>
        public int DataOffset => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x74, 4));
    }

    /// <summary>Byte layout of a KIRK command-1 ECDSA header (0x90 bytes total).</summary>
    /// <remarks>
    /// Offsets, from <c>kirk_engine.h</c>'s <c>KIRK_CMD1_ECDSA_HEADER</c>:
    /// <list type="table">
    /// <item><term>0x00</term><description>AES_key[16]</description></item>
    /// <item><term>0x10</term><description>header_sig_r[20]</description></item>
    /// <item><term>0x24</term><description>header_sig_s[20]</description></item>
    /// <item><term>0x38</term><description>data_sig_r[20]</description></item>
    /// <item><term>0x4C</term><description>data_sig_s[20]</description></item>
    /// <item><term>0x60</term><description>mode (u32 little-endian)</description></item>
    /// <item><term>0x64</term><description>ecdsa_hash (u8)</description></item>
    /// <item><term>0x70</term><description>data_size (u32 little-endian)</description></item>
    /// <item><term>0x74</term><description>data_offset (u32 little-endian)</description></item>
    /// </list>
    /// </remarks>
    public readonly ref struct Cmd1EcdsaHeader
    {
        /// <summary>Total header size in bytes.</summary>
        public const int Size = 0x90;

        private readonly ReadOnlySpan<byte> _bytes;

        /// <summary>Wraps the first <see cref="Size"/> bytes of <paramref name="bytes"/>.</summary>
        public Cmd1EcdsaHeader(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < Size)
                throw new ArgumentException($"KIRK command-1 ECDSA header needs {Size} bytes.", nameof(bytes));
            _bytes = bytes[..Size];
        }

        /// <summary>AES-128 encryption key, offset 0x00 (16 bytes).</summary>
        public ReadOnlySpan<byte> AesKey => _bytes.Slice(0x00, 16);
        /// <summary>ECDSA header signature R, offset 0x10 (20 bytes).</summary>
        public ReadOnlySpan<byte> HeaderSigR => _bytes.Slice(0x10, 20);
        /// <summary>ECDSA header signature S, offset 0x24 (20 bytes).</summary>
        public ReadOnlySpan<byte> HeaderSigS => _bytes.Slice(0x24, 20);
        /// <summary>ECDSA data signature R, offset 0x38 (20 bytes).</summary>
        public ReadOnlySpan<byte> DataSigR => _bytes.Slice(0x38, 20);
        /// <summary>ECDSA data signature S, offset 0x4C (20 bytes).</summary>
        public ReadOnlySpan<byte> DataSigS => _bytes.Slice(0x4C, 20);
        /// <summary>Mode (u32 little-endian, offset 0x60).</summary>
        public uint Mode => BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x60, 4));
        /// <summary>ECDSA hash flag (u8, offset 0x64).</summary>
        public byte EcdsaHash => _bytes[0x64];
        /// <summary>Data size (u32 little-endian, offset 0x70).</summary>
        public int DataSize => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x70, 4));
        /// <summary>Data offset (u32 little-endian, offset 0x74).</summary>
        public int DataOffset => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x74, 4));
    }

    /// <summary>Byte layout of a KIRK AES-128-CBC header (0x14 bytes total).</summary>
    /// <remarks>
    /// Offsets, from <c>kirk_engine.h</c>'s <c>KIRK_AES128CBC_HEADER</c>:
    /// <list type="table">
    /// <item><term>0x00</term><description>mode (u32 little-endian)</description></item>
    /// <item><term>0x04</term><description>unk_4 (u32)</description></item>
    /// <item><term>0x08</term><description>unk_8 (u32)</description></item>
    /// <item><term>0x0C</term><description>keyseed (u32 little-endian)</description></item>
    /// <item><term>0x10</term><description>data_size (u32 little-endian)</description></item>
    /// </list>
    /// </remarks>
    public readonly ref struct Aes128CbcHeader
    {
        /// <summary>Total header size in bytes.</summary>
        public const int Size = 0x14;

        private readonly ReadOnlySpan<byte> _bytes;

        /// <summary>Wraps the first <see cref="Size"/> bytes of <paramref name="bytes"/>.</summary>
        public Aes128CbcHeader(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < Size)
                throw new ArgumentException($"KIRK AES-128-CBC header needs {Size} bytes.", nameof(bytes));
            _bytes = bytes[..Size];
        }

        /// <summary>Mode (u32 little-endian, offset 0x00).</summary>
        public uint Mode => BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x00, 4));
        /// <summary>Key seed (u32 little-endian, offset 0x0C).</summary>
        public int KeySeed => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x0C, 4));
        /// <summary>Data size (u32 little-endian, offset 0x10).</summary>
        public int DataSize => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x10, 4));
    }

    /// <summary>Byte layout of a KIRK SHA-1 header (4 bytes total: the u32 data size).</summary>
    /// <remarks>
    /// Offsets, from <c>kirk_engine.h</c>'s <c>KIRK_SHA1_HEADER</c>:
    /// <list type="table">
    /// <item><term>0x00</term><description>data_size (u32 little-endian)</description></item>
    /// </list>
    /// </remarks>
    public readonly ref struct Sha1Header
    {
        /// <summary>Total header size in bytes.</summary>
        public const int Size = 0x04;

        private readonly Span<byte> _bytes;

        /// <summary>Wraps the first <see cref="Size"/> bytes of <paramref name="bytes"/>.</summary>
        public Sha1Header(Span<byte> bytes)
        {
            if (bytes.Length < Size)
                throw new ArgumentException($"KIRK SHA-1 header needs {Size} bytes.", nameof(bytes));
            _bytes = bytes[..Size];
        }

        /// <summary>Data size (u32 little-endian, offset 0x00).</summary>
        public int DataSize
        {
            get => (int)BinaryPrimitives.ReadUInt32LittleEndian(_bytes.Slice(0x00, 4));
            set => BinaryPrimitives.WriteUInt32LittleEndian(_bytes.Slice(0x00, 4), (uint)value);
        }
    }

    // ------------------------- Instance state -------------------------

    private uint _g_fuse90;
    private uint _g_fuse94;
    private Aes128? _aes_kirk1;
    private readonly byte[] _prng_data = new byte[0x14];
    private bool _is_kirk_initialized;

    /// <summary>Fuse-ID low 32 bits (mirror of BC100090).</summary>
    public uint FuseId90 => _g_fuse90;
    /// <summary>Fuse-ID high 32 bits (mirror of BC100094).</summary>
    public uint FuseId94 => _g_fuse94;
    /// <summary>Whether <see cref="Init"/> / <see cref="Init2"/> has run.</summary>
    public bool IsInitialized => _is_kirk_initialized;

    /// <summary>The 0x0814-byte scratch buffer libkirk carries per state (from the C struct's <c>kirk_buf</c> field).</summary>
    public byte[] KirkBuf { get; } = new byte[0x0814];

    // A default instance for the static shim. Its Init() runs on first access.
    private static readonly KirkState s_default = CreateDefaultInitialized();

    private static KirkState CreateDefaultInitialized()
    {
        var k = new KirkState();
        k.Init();
        return k;
    }

    /// <summary>The lazily-created default state used by the process-wide static shim.</summary>
    public static KirkState Default => s_default;

    /// <summary>
    /// Instance dispatch for <see cref="KirkEngine.sceUtilsBufferCopyWithRange(byte[], int, byte[], int, int)"/>.
    /// Argument order and semantics match libkirk's <c>kirk_sceUtilsBufferCopyWithRange</c>;
    /// unimplemented commands return <see cref="KIRK_SIG_CHECK_INVALID"/> so callers see a
    /// hard error rather than a silent success.
    /// </summary>
    /// <param name="outbuff">Output buffer. Ignored by commands that write only to <paramref name="inbuff"/>.</param>
    /// <param name="outSize">Length of <paramref name="outbuff"/>.</param>
    /// <param name="inbuff">Input buffer. Some commands (CMD1, CMD10) also write into it.</param>
    /// <param name="inSize">Length of <paramref name="inbuff"/>.</param>
    /// <param name="cmd">One of the <c>KIRK_CMD_*</c> constants.</param>
    /// <returns>A <c>KIRK_*</c> return code.</returns>
    public int SceUtilsBufferCopyWithRange(byte[]? outbuff, int outSize, byte[]? inbuff, int inSize, int cmd)
    {
        Span<byte> outSpan = outbuff is null ? Span<byte>.Empty : outbuff.AsSpan(0, outSize);
        Span<byte> inSpan = inbuff is null ? Span<byte>.Empty : inbuff.AsSpan(0, inSize);

        return cmd switch
        {
            KIRK_CMD_DECRYPT_PRIVATE => Cmd1(outSpan, inSpan, inSize),
            KIRK_CMD_ENCRYPT_IV_0 => Cmd4(outSpan, inSpan, inSize),
            KIRK_CMD_DECRYPT_IV_0 => Cmd7(outSpan, inSpan, inSize),
            KIRK_CMD_PRIV_SIGN_CHECK => Cmd10(inSpan, inSize),
            KIRK_CMD_SHA1_HASH => Cmd11(outSpan, inSpan, inSize),
            KIRK_CMD_ECDSA_GEN_KEYS => KIRK_SIG_CHECK_INVALID,
            KIRK_CMD_ECDSA_MULTIPLY_POINT => KIRK_SIG_CHECK_INVALID,
            KIRK_CMD_PRNG => Cmd14(outSpan, outSize),
            KIRK_CMD_ECDSA_SIGN => KIRK_SIG_CHECK_INVALID,
            KIRK_CMD_ECDSA_VERIFY => KIRK_SIG_CHECK_INVALID,
            _ => -1,
        };
    }

    // ------------------------- Init -------------------------

    /// <summary>
    /// Runs <see cref="Init2"/> with the libkirk defaults: a 33-byte placeholder seed, fuse-ID
    /// 90 = 0xBABEF00D, fuse-ID 94 = 0xDEADBEEF. The seed's contents are not consumed - libkirk
    /// zero-fills its own seed buffer and only hashes the seed length.
    /// </summary>
    public int Init()
        => Init2("Lazy Dev should have initialized!"u8, 0xBABEF00Du, 0xDEADBEEFu);

    /// <summary>
    /// Seeds the internal PRNG, sets the fuse-ID mirrors and installs the fixed KIRK-1 AES key.
    /// Faithful port of libkirk's <c>kirk_init2</c>, including its long-standing quirk of never
    /// mixing the caller's seed bytes into <see cref="_prng_data"/> - the seed buffer is
    /// zero-filled internally before hashing, so only <paramref name="rndSeed"/>'s length has any
    /// effect on the resulting PRNG state.
    /// </summary>
    /// <param name="rndSeed">Placeholder seed. Only its length is used.</param>
    /// <param name="fuseId90">Fuse-ID low 32 bits.</param>
    /// <param name="fuseId94">Fuse-ID high 32 bits.</param>
    /// <returns>Always <see cref="KIRK_OPERATION_SUCCESS"/>.</returns>
    public int Init2(ReadOnlySpan<byte> rndSeed, uint fuseId90, uint fuseId94)
    {
        Span<byte> temp = stackalloc byte[0x104];
        temp.Fill(0xAA);

        if (rndSeed.Length > 0)
        {
            // libkirk allocates seed_size + 4 bytes, memsets to zero, writes seed_size into the
            // header field, and only then hashes. The seed bytes themselves never reach the hash.
            int seedSize = rndSeed.Length;
            byte[] seedBuf = new byte[seedSize + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(seedBuf.AsSpan(0, 4), (uint)seedSize);
            Cmd11(_prng_data.AsSpan(0, 20), seedBuf.AsSpan(0, seedSize + 4), seedSize + 4);
        }

        _prng_data.AsSpan().CopyTo(temp.Slice(4, 0x14));
        uint curTime = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        temp[0x18] = (byte)(curTime & 0xFF);
        temp[0x19] = (byte)((curTime >> 8) & 0xFF);
        temp[0x1A] = (byte)((curTime >> 16) & 0xFF);
        temp[0x1B] = (byte)((curTime >> 24) & 0xFF);
        RandomKey.CopyTo(temp.Slice(0x1C, 0x10));

        // Header data_size at offset 0 = 0x100; SHA-1 covers the 256 bytes at offset 4.
        BinaryPrimitives.WriteUInt32LittleEndian(temp[..4], 0x100);
        Cmd11(_prng_data.AsSpan(0, 20), temp, 0x104);

        _g_fuse90 = fuseId90;
        _g_fuse94 = fuseId94;

        _aes_kirk1 = new Aes128(Kirk1Key);
        _is_kirk_initialized = true;
        return KIRK_OPERATION_SUCCESS;
    }

    // ------------------------- KIRK commands -------------------------

    /// <summary>
    /// Command 0: encrypt a KIRK command-1 payload. Copies <paramref name="inbuff"/> into
    /// <paramref name="outbuff"/>, encrypts the body with the caller-supplied AES key, computes
    /// CMAC hashes with the caller-supplied CMAC key, writes them back into the header, then
    /// wraps the AES + CMAC keys with the fixed KIRK-1 key.
    /// </summary>
    /// <param name="outbuff">Output buffer. Receives the wrapped, encrypted payload.</param>
    /// <param name="inbuff">Input buffer. The unencrypted command-1 payload.</param>
    /// <param name="size">Length of both buffers.</param>
    /// <param name="generateTrash">When true, fills the pre-body gap with PRNG bytes via <see cref="Cmd14"/>.</param>
    /// <returns>A <c>KIRK_*</c> return code.</returns>
    public int Cmd0(Span<byte> outbuff, ReadOnlySpan<byte> inbuff, int size, bool generateTrash)
    {
        if (!_is_kirk_initialized || _aes_kirk1 is null) return KIRK_NOT_INITIALIZED;

        inbuff[..size].CopyTo(outbuff[..size]);
        var header = new Cmd1Header(outbuff);

        if (header.Mode != KIRK_MODE_CMD1) return KIRK_INVALID_MODE;

        if (generateTrash)
            Cmd14(outbuff[Cmd1Header.Size..], header.DataOffset);

        int chkSize = header.DataSize;
        if ((chkSize % 16) != 0) chkSize += 16 - (chkSize % 16);

        var k1 = new Aes128(header.AesKey);
        int bodyStart = Cmd1Header.Size + header.DataOffset;
        // libkirk reads plaintext body from inbuff and writes ciphertext to outbuff; the source
        // buffer is untouched by the CMD0 body encryption pass.
        CbcEncrypt(k1, inbuff.Slice(bodyStart, chkSize), outbuff.Slice(bodyStart, chkSize));

        var cmacKey = new Aes128(header.CmacKey);
        Span<byte> cmacHeaderHash = stackalloc byte[16];
        Span<byte> cmacDataHash = stackalloc byte[16];
        Cmac(cmacKey, outbuff.Slice(0x60, 0x30), cmacHeaderHash);
        Cmac(cmacKey, outbuff.Slice(0x60, 0x30 + chkSize + header.DataOffset), cmacDataHash);

        cmacHeaderHash.CopyTo(header.CmacHeaderHash);
        cmacDataHash.CopyTo(header.CmacDataHash);

        // Wrap the AES and CMAC keys at offsets 0x00 and 0x10 with the fixed KIRK-1 key.
        CbcEncrypt(_aes_kirk1, inbuff[..32], outbuff[..32]);
        return KIRK_OPERATION_SUCCESS;
    }

    /// <summary>
    /// Command 1: decrypt a wrapped KIRK command-1 payload. Unwraps the AES + CMAC keys with
    /// the fixed KIRK-1 key, verifies the CMAC hashes (via <see cref="Cmd10"/>) unless the
    /// header requests ECDSA verification, then decrypts the payload body.
    /// </summary>
    /// <param name="outbuff">Output buffer. Receives the decrypted body.</param>
    /// <param name="inbuff">Input buffer. Also written to (in-place unwrap).</param>
    /// <param name="size">Length of <paramref name="inbuff"/>.</param>
    /// <returns>A <c>KIRK_*</c> return code.</returns>
    public int Cmd1(Span<byte> outbuff, Span<byte> inbuff, int size)
    {
        if (size < Cmd1Header.Size) return KIRK_INVALID_SIZE;
        if (!_is_kirk_initialized || _aes_kirk1 is null) return KIRK_NOT_INITIALIZED;

        var header = new Cmd1Header(inbuff);
        if (header.Mode != KIRK_MODE_CMD1) return KIRK_INVALID_MODE;

        // Unwrap AES + CMAC keys into a temporary buffer.
        Span<byte> keys = stackalloc byte[32];
        CbcDecrypt(_aes_kirk1, inbuff[..32], keys);

        if (header.EcdsaHash != 1)
        {
            int r = Cmd10(inbuff, size);
            if (r != KIRK_OPERATION_SUCCESS) return r;
        }
        // When header.EcdsaHash == 1 the header/data ECDSA signatures cover the payload
        // instead of the CMAC hashes verified by Cmd10. The signature check is skipped and
        // decryption continues so tag classes that set ecdsa_hash=1 can still be unwrapped.

        var k1 = new Aes128(keys[..16]);
        int bodyStart = Cmd1Header.Size + header.DataOffset;
        int chkSize = header.DataSize;
        if ((chkSize % 16) != 0) chkSize += 16 - (chkSize % 16);
        CbcDecrypt(k1, inbuff.Slice(bodyStart, chkSize), outbuff[..chkSize]);
        return KIRK_OPERATION_SUCCESS;
    }

    /// <summary>
    /// Command 4: AES-128-CBC encrypt with IV = 0 and a seed-selected key. The header at the
    /// start of <paramref name="inbuff"/> selects both the mode and the key seed.
    /// </summary>
    public int Cmd4(Span<byte> outbuff, ReadOnlySpan<byte> inbuff, int size)
    {
        if (!_is_kirk_initialized) return KIRK_NOT_INITIALIZED;

        var header = new Aes128CbcHeader(inbuff);
        if (header.Mode != KIRK_MODE_ENCRYPT_CBC) return KIRK_INVALID_MODE;
        if (header.DataSize == 0) return KIRK_DATA_SIZE_ZERO;

        ReadOnlySpan<byte> key = GetKey47(header.KeySeed);
        if (key.IsEmpty) return KIRK_INVALID_SIZE;

        var cipher = new Aes128(key);
        CbcEncrypt(
            cipher,
            inbuff.Slice(Aes128CbcHeader.Size, header.DataSize),
            outbuff.Slice(Aes128CbcHeader.Size, header.DataSize));
        return KIRK_OPERATION_SUCCESS;
    }

    /// <summary>
    /// Command 7: AES-128-CBC decrypt with IV = 0 and a seed-selected key. Mirror of
    /// <see cref="Cmd4"/>.
    /// </summary>
    public int Cmd7(Span<byte> outbuff, ReadOnlySpan<byte> inbuff, int size)
    {
        if (!_is_kirk_initialized) return KIRK_NOT_INITIALIZED;

        var header = new Aes128CbcHeader(inbuff);
        if (header.Mode != KIRK_MODE_DECRYPT_CBC) return KIRK_INVALID_MODE;
        if (header.DataSize == 0) return KIRK_DATA_SIZE_ZERO;

        ReadOnlySpan<byte> key = GetKey47(header.KeySeed);
        if (key.IsEmpty) return KIRK_INVALID_SIZE;

        var cipher = new Aes128(key);
        CbcDecrypt(
            cipher,
            inbuff.Slice(Aes128CbcHeader.Size, header.DataSize),
            outbuff[..header.DataSize]);
        return KIRK_OPERATION_SUCCESS;
    }

    /// <summary>
    /// Command 10: verify the CMAC header + data hashes on a KIRK command-1 payload, in place.
    /// </summary>
    public int Cmd10(Span<byte> inbuff, int inSize)
    {
        if (!_is_kirk_initialized || _aes_kirk1 is null) return KIRK_NOT_INITIALIZED;

        var header = new Cmd1Header(inbuff);
        if (header.Mode != KIRK_MODE_CMD1
            && header.Mode != KIRK_MODE_CMD2
            && header.Mode != KIRK_MODE_CMD3)
            return KIRK_INVALID_MODE;

        if (header.DataSize == 0) return KIRK_DATA_SIZE_ZERO;

        if (header.Mode == KIRK_MODE_CMD1)
        {
            Span<byte> keys = stackalloc byte[32];
            CbcDecrypt(_aes_kirk1, inbuff[..32], keys);

            var cmacKey = new Aes128(keys.Slice(16, 16));
            Span<byte> cmacHeaderHash = stackalloc byte[16];
            Cmac(cmacKey, inbuff.Slice(0x60, 0x30), cmacHeaderHash);

            int chkSize = header.DataSize;
            if ((chkSize % 16) != 0) chkSize += 16 - (chkSize % 16);

            Span<byte> cmacDataHash = stackalloc byte[16];
            Cmac(cmacKey, inbuff.Slice(0x60, 0x30 + chkSize + header.DataOffset), cmacDataHash);

            if (!cmacHeaderHash.SequenceEqual(header.CmacHeaderHash)) return KIRK_HEADER_HASH_INVALID;
            if (!cmacDataHash.SequenceEqual(header.CmacDataHash)) return KIRK_DATA_HASH_INVALID;
            return KIRK_OPERATION_SUCCESS;
        }

        // Modes 2 and 3 use ECDSA signatures that are not implemented in this port.
        return KIRK_SIG_CHECK_INVALID;
    }

    /// <summary>
    /// Command 11: SHA-1 hash of a length-prefixed buffer. The first 4 bytes of
    /// <paramref name="inbuff"/> are a little-endian u32 giving the number of bytes past the
    /// header to hash.
    /// </summary>
    public int Cmd11(Span<byte> outbuff, ReadOnlySpan<byte> inbuff, int size)
    {
        if (!_is_kirk_initialized) return KIRK_NOT_INITIALIZED;

        int dataSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(inbuff[..4]);
        if (dataSize == 0 || size == 0) return KIRK_DATA_SIZE_ZERO;

        var sha = new Sha1();
        sha.Update(inbuff.Slice(Sha1Header.Size, dataSize));
        Span<byte> digest = stackalloc byte[20];
        sha.Finish(digest);
        digest.CopyTo(outbuff[..20]);
        return KIRK_OPERATION_SUCCESS;
    }

    /// <summary>
    /// Command 14: fill <paramref name="outbuff"/> with pseudo-random bytes. Repeatedly re-hashes
    /// <see cref="_prng_data"/> mixed with the current time and copies out 20-byte chunks. The
    /// recursion mirrors libkirk's own implementation for a byte-for-byte match.
    /// </summary>
    public int Cmd14(Span<byte> outbuff, int outSize)
    {
        Span<byte> temp = stackalloc byte[0x104];
        temp.Fill(0xAA);

        if (outSize <= 0) return KIRK_OPERATION_SUCCESS;

        _prng_data.AsSpan().CopyTo(temp.Slice(4, 0x14));
        uint curTime = unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        temp[0x18] = (byte)(curTime & 0xFF);
        temp[0x19] = (byte)((curTime >> 8) & 0xFF);
        temp[0x1A] = (byte)((curTime >> 16) & 0xFF);
        temp[0x1B] = (byte)((curTime >> 24) & 0xFF);
        RandomData.CopyTo(temp.Slice(0x1C, 0x10));

        BinaryPrimitives.WriteUInt32LittleEndian(temp[..4], 0x100);
        Cmd11(_prng_data.AsSpan(0, 20), temp, 0x104);

        int cursor = 0;
        while (outSize > 0)
        {
            int blockRem = outSize % 0x14;
            int block = outSize / 0x14;
            if (block != 0)
            {
                _prng_data.AsSpan().CopyTo(outbuff.Slice(cursor, 0x14));
                cursor += 0x14;
                outSize -= 0x14;
                // Recursive call re-hashes the PRNG for the next 20-byte chunk.
                Cmd14(outbuff[cursor..], outSize);
            }
            else
            {
                if (blockRem != 0)
                {
                    _prng_data.AsSpan(0, blockRem).CopyTo(outbuff.Slice(cursor, blockRem));
                    outSize -= blockRem;
                }
            }
        }
        return KIRK_OPERATION_SUCCESS;
    }

    /// <summary>
    /// Overhead-free CBC encrypt with a key from the keyvault. Mirrors libkirk's <c>kirk4()</c>.
    /// </summary>
    public static void Kirk4(Span<byte> outbuff, ReadOnlySpan<byte> inbuff, int size, int keyId)
    {
        ReadOnlySpan<byte> key = GetKey47(keyId);
        if (key.IsEmpty)
            throw new ArgumentOutOfRangeException(nameof(keyId), $"Key ID 0x{keyId:X} is outside the 0x00..0x7F keyvault range.");
        var cipher = new Aes128(key);
        CbcEncrypt(cipher, inbuff[..size], outbuff[..size]);
    }

    /// <summary>
    /// Overhead-free CBC decrypt with a key from the keyvault. Mirrors libkirk's <c>kirk7()</c>.
    /// </summary>
    public static void Kirk7(Span<byte> outbuff, ReadOnlySpan<byte> inbuff, int size, int keyId)
    {
        ReadOnlySpan<byte> key = GetKey47(keyId);
        if (key.IsEmpty)
            throw new ArgumentOutOfRangeException(nameof(keyId), $"Key ID 0x{keyId:X} is outside the 0x00..0x7F keyvault range.");
        var cipher = new Aes128(key);
        CbcDecrypt(cipher, inbuff[..size], outbuff[..size]);
    }

    /// <summary>Returns the 16-byte keyvault entry for <paramref name="keyType"/>, or empty when out of range.</summary>
    public static ReadOnlySpan<byte> GetKey47(int keyType)
    {
        if (keyType < 0 || keyType >= 0x80) return ReadOnlySpan<byte>.Empty;
        return KeyVault.Slice(keyType * 16, 16);
    }

    // ------------------------- AES helpers (IV = 0, matching libkirk byte for byte) -------------------------

    /// <summary>
    /// CBC-encrypts <paramref name="src"/> into <paramref name="dst"/> with IV = 0.
    /// <paramref name="src"/> and <paramref name="dst"/> may alias.
    /// </summary>
    internal static void CbcEncrypt(Aes128 cipher, ReadOnlySpan<byte> src, Span<byte> dst)
    {
        Span<byte> blockBuff = stackalloc byte[16];
        int size = src.Length;
        for (int i = 0; i < size; i += 16)
        {
            src.Slice(i, 16).CopyTo(dst.Slice(i, 16));
            if (i != 0)
            {
                for (int j = 0; j < 16; j++) dst[i + j] ^= blockBuff[j];
            }
            dst.Slice(i, 16).CopyTo(blockBuff);
            cipher.EncryptBlock(blockBuff);
            blockBuff.CopyTo(dst.Slice(i, 16));
        }
    }

    /// <summary>
    /// CBC-decrypts <paramref name="src"/> into <paramref name="dst"/> with IV = 0.
    /// <paramref name="src"/> and <paramref name="dst"/> may alias.
    /// </summary>
    internal static void CbcDecrypt(Aes128 cipher, ReadOnlySpan<byte> src, Span<byte> dst)
    {
        int size = src.Length;
        if (size < 16) return;

        Span<byte> blockBuffPrevious = stackalloc byte[16];
        src.Slice(0, 16).CopyTo(blockBuffPrevious);
        src.Slice(0, 16).CopyTo(dst.Slice(0, 16));
        cipher.DecryptBlock(dst.Slice(0, 16));

        Span<byte> blockBuff = stackalloc byte[16];
        for (int i = 16; i < size; i += 16)
        {
            src.Slice(i, 16).CopyTo(blockBuff);
            src.Slice(i, 16).CopyTo(dst.Slice(i, 16));
            cipher.DecryptBlock(dst.Slice(i, 16));
            for (int j = 0; j < 16; j++) dst[i + j] ^= blockBuffPrevious[j];
            blockBuff.CopyTo(blockBuffPrevious);
        }
    }

    /// <summary>
    /// AES-CMAC over <paramref name="input"/>. Writes a 16-byte MAC to <paramref name="mac"/>.
    /// Follows the RFC 4493 subkey derivation used by libkirk.
    /// </summary>
    internal static void Cmac(Aes128 cipher, ReadOnlySpan<byte> input, Span<byte> mac)
    {
        Span<byte> k1 = stackalloc byte[16];
        Span<byte> k2 = stackalloc byte[16];
        Span<byte> x = stackalloc byte[16];
        Span<byte> y = stackalloc byte[16];
        Span<byte> mLast = stackalloc byte[16];
        Span<byte> padded = stackalloc byte[16];

        GenerateSubkey(cipher, k1, k2);

        int length = input.Length;
        int n = (length + 15) / 16;
        bool flag;
        if (n == 0)
        {
            n = 1;
            flag = false;
        }
        else
        {
            flag = (length % 16) == 0;
        }

        if (flag)
        {
            Xor128(input.Slice(16 * (n - 1), 16), k1, mLast);
        }
        else
        {
            int rem = length % 16;
            Padding(input[(16 * (n - 1))..], padded, rem);
            Xor128(padded, k2, mLast);
        }

        x.Clear();
        for (int i = 0; i < n - 1; i++)
        {
            Xor128(x, input.Slice(16 * i, 16), y);
            y.CopyTo(x);
            cipher.EncryptBlock(x);
        }
        Xor128(x, mLast, y);
        y.CopyTo(x);
        cipher.EncryptBlock(x);
        x.CopyTo(mac[..16]);
    }

    private static void GenerateSubkey(Aes128 cipher, Span<byte> k1, Span<byte> k2)
    {
        Span<byte> l = stackalloc byte[16];
        Span<byte> tmp = stackalloc byte[16];
        l.Clear();
        cipher.EncryptBlock(l);

        if ((l[0] & 0x80) == 0)
        {
            LeftShiftOneBit(l, k1);
        }
        else
        {
            LeftShiftOneBit(l, tmp);
            Xor128(tmp, ConstRb, k1);
        }

        if ((k1[0] & 0x80) == 0)
        {
            LeftShiftOneBit(k1, k2);
        }
        else
        {
            LeftShiftOneBit(k1, tmp);
            Xor128(tmp, ConstRb, k2);
        }
    }

    private static void LeftShiftOneBit(ReadOnlySpan<byte> input, Span<byte> output)
    {
        byte overflow = 0;
        for (int i = 15; i >= 0; i--)
        {
            output[i] = (byte)((input[i] << 1) | overflow);
            overflow = (byte)(((input[i] & 0x80) != 0) ? 1 : 0);
        }
    }

    private static void Padding(ReadOnlySpan<byte> lastb, Span<byte> pad, int length)
    {
        for (int j = 0; j < 16; j++)
        {
            if (j < length) pad[j] = lastb[j];
            else if (j == length) pad[j] = 0x80;
            else pad[j] = 0;
        }
    }

    private static void Xor128(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> outSpan)
    {
        for (int i = 0; i < 16; i++) outSpan[i] = (byte)(a[i] ^ b[i]);
    }

    private static ReadOnlySpan<byte> ConstRb =>
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
    ];

    // ------------------------- Key material -------------------------

    /// <summary>The fixed 16-byte KIRK-1 AES key used to wrap / unwrap the header keys.</summary>
    private static ReadOnlySpan<byte> Kirk1Key =>
    [
        0x98, 0xC9, 0x40, 0x97, 0x5C, 0x1D, 0x10, 0xE8,
        0x7F, 0xE6, 0x0E, 0xA3, 0xFD, 0x03, 0xA8, 0xBA,
    ];

    /// <summary>The 16-byte "random data" mixed into every PRNG draw.</summary>
    private static ReadOnlySpan<byte> RandomData =>
    [
        0xA7, 0x2E, 0x4C, 0xB6, 0xC3, 0x34, 0xDF, 0x85,
        0x70, 0x01, 0x49, 0xFC, 0xC0, 0x87, 0xC4, 0x77,
    ];

    /// <summary>The 16-byte "random key" mixed into <see cref="Init2"/>'s first PRNG hash.</summary>
    private static ReadOnlySpan<byte> RandomKey =>
    [
        0x07, 0xAB, 0xEF, 0xF8, 0x96, 0x8C, 0xF3, 0xD6,
        0x14, 0xE0, 0xEB, 0xB2, 0x9D, 0x8B, 0x4E, 0x74,
    ];

    /// <summary>
    /// The 128-entry keyvault, 16 bytes per entry (2048 bytes total). Layout matches
    /// libkirk's <c>keyvault[0x80][0x10]</c>: entry <c>N</c> starts at offset <c>N * 16</c>.
    /// </summary>
    private static ReadOnlySpan<byte> KeyVault =>
    [
        0x2C, 0x92, 0xE5, 0x90, 0x2B, 0x86, 0xC1, 0x06, 0xB7, 0x2E, 0xEA, 0x6C, 0xD4, 0xEC, 0x72, 0x48, // 0x00
        0x05, 0x8D, 0xC8, 0x0B, 0x33, 0xA5, 0xBF, 0x9D, 0x56, 0x98, 0xFA, 0xE0, 0xD3, 0x71, 0x5E, 0x1F, // 0x01
        0xB8, 0x13, 0xC3, 0x5E, 0xC6, 0x44, 0x41, 0xE3, 0xDC, 0x3C, 0x16, 0xF5, 0xB4, 0x5E, 0x64, 0x84, // 0x02
        0x98, 0x02, 0xC4, 0xE6, 0xEC, 0x9E, 0x9E, 0x2F, 0xFC, 0x63, 0x4C, 0xE4, 0x2F, 0xBB, 0x46, 0x68, // 0x03
        0x99, 0x24, 0x4C, 0xD2, 0x58, 0xF5, 0x1B, 0xCB, 0xB0, 0x61, 0x9C, 0xA7, 0x38, 0x30, 0x07, 0x5F, // 0x04
        0x02, 0x25, 0xD7, 0xBA, 0x63, 0xEC, 0xB9, 0x4A, 0x9D, 0x23, 0x76, 0x01, 0xB3, 0xF6, 0xAC, 0x17, // 0x05
        0x60, 0x99, 0xF2, 0x81, 0x70, 0x56, 0x0E, 0x5F, 0x74, 0x7C, 0xB5, 0x20, 0xC0, 0xCD, 0xC2, 0x3C, // 0x06
        0x76, 0x36, 0x8B, 0x43, 0x8F, 0x77, 0xD8, 0x7E, 0xFE, 0x5F, 0xB6, 0x11, 0x59, 0x39, 0x88, 0x5C, // 0x07
        0x14, 0xA1, 0x15, 0xEB, 0x43, 0x4A, 0x1B, 0xA4, 0x90, 0x5E, 0x03, 0xB6, 0x17, 0xA1, 0x5C, 0x04, // 0x08
        0xE6, 0x58, 0x03, 0xD9, 0xA7, 0x1A, 0xA8, 0x7F, 0x05, 0x9D, 0x22, 0x9D, 0xAF, 0x54, 0x53, 0xD0, // 0x09
        0xBA, 0x34, 0x80, 0xB4, 0x28, 0xA7, 0xCA, 0x5F, 0x21, 0x64, 0x12, 0xF7, 0x0F, 0xBB, 0x73, 0x23, // 0x0A
        0x72, 0xAD, 0x35, 0xAC, 0x9A, 0xC3, 0x13, 0x0A, 0x77, 0x8C, 0xB1, 0x9D, 0x88, 0x55, 0x0B, 0x0C, // 0x0B
        0x84, 0x85, 0xC8, 0x48, 0x75, 0x08, 0x43, 0xBC, 0x9B, 0x9A, 0xEC, 0xA7, 0x9C, 0x7F, 0x60, 0x18, // 0x0C
        0xB5, 0xB1, 0x6E, 0xDE, 0x23, 0xA9, 0x7B, 0x0E, 0xA1, 0x7C, 0xDB, 0xA2, 0xDC, 0xDE, 0xC4, 0x6E, // 0x0D
        0xC8, 0x71, 0xFD, 0xB3, 0xBC, 0xC5, 0xD2, 0xF2, 0xE2, 0xD7, 0x72, 0x9D, 0xDF, 0x82, 0x68, 0x82, // 0x0E
        0x0A, 0xBB, 0x33, 0x6C, 0x96, 0xD4, 0xCD, 0xD8, 0xCB, 0x5F, 0x4B, 0xE0, 0xBA, 0xDB, 0x9E, 0x03, // 0x0F
        0x32, 0x29, 0x5B, 0xD5, 0xEA, 0xF7, 0xA3, 0x42, 0x16, 0xC8, 0x8E, 0x48, 0xFF, 0x50, 0xD3, 0x71, // 0x10
        0x46, 0xF2, 0x5E, 0x8E, 0x4D, 0x2A, 0xA5, 0x40, 0x73, 0x0B, 0xC4, 0x6E, 0x47, 0xEE, 0x6F, 0x0A, // 0x11
        0x5D, 0xC7, 0x11, 0x39, 0xD0, 0x19, 0x38, 0xBC, 0x02, 0x7F, 0xDD, 0xDC, 0xB0, 0x83, 0x7D, 0x9D, // 0x12
        0x51, 0xDD, 0x65, 0xF0, 0x71, 0xA4, 0xE5, 0xEA, 0x6A, 0xAF, 0x12, 0x19, 0x41, 0x29, 0xB8, 0xF4, // 0x13
        0x03, 0x76, 0x3C, 0x68, 0x65, 0xC6, 0x9B, 0x0F, 0xFE, 0x8F, 0xD8, 0xEE, 0xA4, 0x36, 0x16, 0xA0, // 0x14
        0x7D, 0x50, 0xB8, 0x5C, 0xAF, 0x67, 0x69, 0xF0, 0xE5, 0x4A, 0xA8, 0x09, 0x8B, 0x0E, 0xBE, 0x1C, // 0x15
        0x72, 0x68, 0x4B, 0x32, 0xAC, 0x3B, 0x33, 0x2F, 0x2A, 0x7A, 0xFC, 0x9E, 0x14, 0xD5, 0x6F, 0x6B, // 0x16
        0x20, 0x1D, 0x31, 0x96, 0x4A, 0xD9, 0x9F, 0xBF, 0x32, 0xD5, 0xD6, 0x1C, 0x49, 0x1B, 0xD9, 0xFC, // 0x17
        0xF8, 0xD8, 0x44, 0x63, 0xD6, 0x10, 0xD1, 0x2A, 0x44, 0x8E, 0x96, 0x90, 0xA6, 0xBB, 0x0B, 0xAD, // 0x18
        0x5C, 0xD4, 0x05, 0x7F, 0xA1, 0x30, 0x60, 0x44, 0x0A, 0xD9, 0xB6, 0x74, 0x5F, 0x24, 0x4F, 0x4E, // 0x19
        0xF4, 0x8A, 0xD6, 0x78, 0x59, 0x9C, 0x22, 0xC1, 0xD4, 0x11, 0x93, 0x3D, 0xF8, 0x45, 0xB8, 0x93, // 0x1A
        0xCA, 0xE7, 0xD2, 0x87, 0xA2, 0xEC, 0xC1, 0xCD, 0x94, 0x54, 0x2B, 0x5E, 0x1D, 0x94, 0x88, 0xB2, // 0x1B
        0xDE, 0x26, 0xD3, 0x7A, 0x39, 0x95, 0x6C, 0x2A, 0xD8, 0xC3, 0xA6, 0xAF, 0x21, 0xEB, 0xB3, 0x01, // 0x1C
        0x7C, 0xB6, 0x8B, 0x4D, 0xA3, 0x8D, 0x1D, 0xD9, 0x32, 0x67, 0x9C, 0xA9, 0x9F, 0xFB, 0x28, 0x52, // 0x1D
        0xA0, 0xB5, 0x56, 0xB4, 0x69, 0xAB, 0x36, 0x8F, 0x36, 0xDE, 0xC9, 0x09, 0x2E, 0xCB, 0x41, 0xB1, // 0x1E
        0x93, 0x9D, 0xE1, 0x9B, 0x72, 0x5F, 0xEE, 0xE2, 0x45, 0x2A, 0xBC, 0x17, 0x06, 0xD1, 0x47, 0x69, // 0x1F
        0xA4, 0xA4, 0xE6, 0x21, 0x38, 0x2E, 0xF1, 0xAF, 0x7B, 0x17, 0x7A, 0xE8, 0x42, 0xAD, 0x00, 0x31, // 0x20
        0xC3, 0x7F, 0x13, 0xE8, 0xCF, 0x84, 0xDB, 0x34, 0x74, 0x7B, 0xC3, 0xA0, 0xF1, 0x9D, 0x3A, 0x73, // 0x21
        0x2B, 0xF7, 0x83, 0x8A, 0xD8, 0x98, 0xE9, 0x5F, 0xA5, 0xF9, 0x01, 0xDA, 0x61, 0xFE, 0x35, 0xBB, // 0x22
        0xC7, 0x04, 0x62, 0x1E, 0x71, 0x4A, 0x66, 0xEA, 0x62, 0xE0, 0x4B, 0x20, 0x3D, 0xB8, 0xC2, 0xE5, // 0x23
        0xC9, 0x33, 0x85, 0x9A, 0xAB, 0x00, 0xCD, 0xCE, 0x4D, 0x8B, 0x8E, 0x9F, 0x3D, 0xE6, 0xC0, 0x0F, // 0x24
        0x18, 0x42, 0x56, 0x1F, 0x2B, 0x5F, 0x34, 0xE3, 0x51, 0x3E, 0xB7, 0x89, 0x77, 0x43, 0x1A, 0x65, // 0x25
        0xDC, 0xB0, 0xA0, 0x06, 0x5A, 0x50, 0xA1, 0x4E, 0x59, 0xAC, 0x97, 0x3F, 0x17, 0x58, 0xA3, 0xA3, // 0x26
        0xC4, 0xDB, 0xAE, 0x83, 0xE2, 0x9C, 0xF2, 0x54, 0xA3, 0xDD, 0x37, 0x4E, 0x80, 0x7B, 0xF4, 0x25, // 0x27
        0xBF, 0xAE, 0xEB, 0x49, 0x82, 0x65, 0xC5, 0x7C, 0x64, 0xB8, 0xC1, 0x7E, 0x19, 0x06, 0x44, 0x09, // 0x28
        0x79, 0x7C, 0xEC, 0xC3, 0xB3, 0xEE, 0x0A, 0xC0, 0x3B, 0xD8, 0xE6, 0xC1, 0xE0, 0xA8, 0xB1, 0xA4, // 0x29
        0x75, 0x34, 0xFE, 0x0B, 0xD6, 0xD0, 0xC2, 0x8D, 0x68, 0xD4, 0xE0, 0x2A, 0xE7, 0xD5, 0xD1, 0x55, // 0x2A
        0xFA, 0xB3, 0x53, 0x26, 0x97, 0x4F, 0x4E, 0xDF, 0xE4, 0xC3, 0xA8, 0x14, 0xC3, 0x2F, 0x0F, 0x88, // 0x2B
        0xEC, 0x97, 0xB3, 0x86, 0xB4, 0x33, 0xC6, 0xBF, 0x4E, 0x53, 0x9D, 0x95, 0xEB, 0xB9, 0x79, 0xE4, // 0x2C
        0xB3, 0x20, 0xA2, 0x04, 0xCF, 0x48, 0x06, 0x29, 0xB5, 0xDD, 0x8E, 0xFC, 0x98, 0xD4, 0x17, 0x7B, // 0x2D
        0x5D, 0xFC, 0x0D, 0x4F, 0x2C, 0x39, 0xDA, 0x68, 0x4A, 0x33, 0x74, 0xED, 0x49, 0x58, 0xA7, 0x3A, // 0x2E
        0xD7, 0x5A, 0x54, 0x22, 0xCE, 0xD9, 0xA3, 0xD6, 0x2B, 0x55, 0x7D, 0x8D, 0xE8, 0xBE, 0xC7, 0xEC, // 0x2F
        0x6B, 0x4A, 0xEE, 0x43, 0x45, 0xAE, 0x70, 0x07, 0xCF, 0x8D, 0xCF, 0x4E, 0x4A, 0xE9, 0x3C, 0xFA, // 0x30
        0x2B, 0x52, 0x2F, 0x66, 0x4C, 0x2D, 0x11, 0x4C, 0xFE, 0x61, 0x31, 0x8C, 0x56, 0x78, 0x4E, 0xA6, // 0x31
        0x3A, 0xA3, 0x4E, 0x44, 0xC6, 0x6F, 0xAF, 0x7B, 0xFA, 0xE5, 0x53, 0x27, 0xEF, 0xCF, 0xCC, 0x24, // 0x32
        0x2B, 0x5C, 0x78, 0xBF, 0xC3, 0x8E, 0x49, 0x9D, 0x41, 0xC3, 0x3C, 0x5C, 0x7B, 0x27, 0x96, 0xCE, // 0x33
        0xF3, 0x7E, 0xEA, 0xD2, 0xC0, 0xC8, 0x23, 0x1D, 0xA9, 0x9B, 0xFA, 0x49, 0x5D, 0xB7, 0x08, 0x1B, // 0x34
        0x70, 0x8D, 0x4E, 0x6F, 0xD1, 0xF6, 0x6F, 0x1D, 0x1E, 0x1F, 0xCB, 0x02, 0xF9, 0xB3, 0x99, 0x26, // 0x35
        0x0F, 0x67, 0x16, 0xE1, 0x80, 0x69, 0x9C, 0x51, 0xFC, 0xC7, 0xAD, 0x6E, 0x4F, 0xB8, 0x46, 0xC9, // 0x36
        0x56, 0x0A, 0x49, 0x4A, 0x84, 0x4C, 0x8E, 0xD9, 0x82, 0xEE, 0x0B, 0x6D, 0xC5, 0x7D, 0x20, 0x8D, // 0x37
        0x12, 0x46, 0x8D, 0x7E, 0x1C, 0x42, 0x20, 0x9B, 0xBA, 0x54, 0x26, 0x83, 0x5E, 0xB0, 0x33, 0x03, // 0x38
        0xC4, 0x3B, 0xB6, 0xD6, 0x53, 0xEE, 0x67, 0x49, 0x3E, 0xA9, 0x5F, 0xBC, 0x0C, 0xED, 0x6F, 0x8A, // 0x39
        0x2C, 0xC3, 0xCF, 0x8C, 0x28, 0x78, 0xA5, 0xA6, 0x63, 0xE2, 0xAF, 0x2D, 0x71, 0x5E, 0x86, 0xBA, // 0x3A
        0x83, 0x3D, 0xA7, 0x0C, 0xED, 0x6A, 0x20, 0x12, 0xD1, 0x96, 0xE6, 0xFE, 0x5C, 0x4D, 0x37, 0xC5, // 0x3B
        0xC7, 0x43, 0xD0, 0x67, 0x42, 0xEE, 0x90, 0xB8, 0xCA, 0x75, 0x50, 0x35, 0x20, 0xAD, 0xBC, 0xCE, // 0x3C
        0x8A, 0xE3, 0x66, 0x3F, 0x8D, 0x9E, 0x82, 0xA1, 0xED, 0xE6, 0x8C, 0x9C, 0xE8, 0x25, 0x6D, 0xAA, // 0x3D
        0x7F, 0xC9, 0x6F, 0x0B, 0xB1, 0x48, 0x5C, 0xA5, 0x5D, 0xD3, 0x64, 0xB7, 0x7A, 0xF5, 0xE4, 0xEA, // 0x3E
        0x91, 0xB7, 0x65, 0x78, 0x8B, 0xCB, 0x8B, 0xD4, 0x02, 0xED, 0x55, 0x3A, 0x66, 0x62, 0xD0, 0xAD, // 0x3F
        0x28, 0x24, 0xF9, 0x10, 0x1B, 0x8D, 0x0F, 0x7B, 0x6E, 0xB2, 0x63, 0xB5, 0xB5, 0x5B, 0x2E, 0xBB, // 0x40
        0x30, 0xE2, 0x57, 0x5D, 0xE0, 0xA2, 0x49, 0xCE, 0xE8, 0xCF, 0x2B, 0x5E, 0x4D, 0x9F, 0x52, 0xC7, // 0x41
        0x5E, 0xE5, 0x04, 0x39, 0x62, 0x32, 0x02, 0xFA, 0x85, 0x39, 0x3F, 0x72, 0xBB, 0x77, 0xFD, 0x1A, // 0x42
        0xF8, 0x81, 0x74, 0xB1, 0xBD, 0xE9, 0xBF, 0xDD, 0x45, 0xE2, 0xF5, 0x55, 0x89, 0xCF, 0x46, 0xAB, // 0x43
        0x7D, 0xF4, 0x92, 0x65, 0xE3, 0xFA, 0xD6, 0x78, 0xD6, 0xFE, 0x78, 0xAD, 0xBB, 0x3D, 0xFB, 0x63, // 0x44
        0x74, 0x7F, 0xD6, 0x2D, 0xC7, 0xA1, 0xCA, 0x96, 0xE2, 0x7A, 0xCE, 0xFF, 0xAA, 0x72, 0x3F, 0xF7, // 0x45
        0x1E, 0x58, 0xEB, 0xD0, 0x65, 0xBB, 0xF1, 0x68, 0xC5, 0xBD, 0xF7, 0x46, 0xBA, 0x7B, 0xE1, 0x00, // 0x46
        0x24, 0x34, 0x7D, 0xAF, 0x5E, 0x4B, 0x35, 0x72, 0x7A, 0x52, 0x27, 0x6B, 0xA0, 0x54, 0x74, 0xDB, // 0x47
        0x09, 0xB1, 0xC7, 0x05, 0xC3, 0x5F, 0x53, 0x66, 0x77, 0xC0, 0xEB, 0x36, 0x77, 0xDF, 0x83, 0x07, // 0x48
        0xCC, 0xBE, 0x61, 0x5C, 0x05, 0xA2, 0x00, 0x33, 0x37, 0x8E, 0x59, 0x64, 0xA7, 0xDD, 0x70, 0x3D, // 0x49
        0x0D, 0x47, 0x50, 0xBB, 0xFC, 0xB0, 0x02, 0x81, 0x30, 0xE1, 0x84, 0xDE, 0xA8, 0xD4, 0x84, 0x13, // 0x4A
        0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42, 0x28, 0x8B, // 0x4B
        0x7A, 0xD3, 0x1A, 0x8B, 0x4B, 0xEF, 0xC2, 0xC2, 0xB3, 0x99, 0x01, 0xA9, 0xFE, 0x76, 0xB9, 0x87, // 0x4C
        0xBE, 0x78, 0x78, 0x17, 0xC7, 0xF1, 0x6F, 0x1A, 0xE0, 0xEF, 0x3B, 0xDE, 0x4C, 0xC2, 0xD7, 0x86, // 0x4D
        0x7C, 0xD8, 0xB8, 0x91, 0x91, 0x0A, 0x43, 0x14, 0xD0, 0x53, 0x3D, 0xD8, 0x4C, 0x45, 0xBE, 0x16, // 0x4E
        0x32, 0x72, 0x2C, 0x88, 0x07, 0xCF, 0x35, 0x7D, 0x4A, 0x2F, 0x51, 0x19, 0x44, 0xAE, 0x68, 0xDA, // 0x4F
        0x7E, 0x6B, 0xBF, 0xF6, 0xF6, 0x87, 0xB8, 0x98, 0xEE, 0xB5, 0x1B, 0x32, 0x16, 0xE4, 0x6E, 0x5D, // 0x50
        0x08, 0xEA, 0x5A, 0x83, 0x49, 0xB5, 0x9D, 0xB5, 0x3E, 0x07, 0x79, 0xB1, 0x9A, 0x59, 0xA3, 0x54, // 0x51
        0xF3, 0x12, 0x81, 0xBF, 0xE6, 0x9F, 0x51, 0xD1, 0x64, 0x08, 0x25, 0x21, 0xFF, 0xBB, 0x22, 0x61, // 0x52
        0xAF, 0xFE, 0x8E, 0xB1, 0x3D, 0xD1, 0x7E, 0xD8, 0x0A, 0x61, 0x24, 0x1C, 0x95, 0x92, 0x56, 0xB6, // 0x53
        0x92, 0xCD, 0xB4, 0xC2, 0x5B, 0xF2, 0x35, 0x5A, 0x23, 0x09, 0xE8, 0x19, 0xC9, 0x14, 0x42, 0x35, // 0x54
        0xE1, 0xC6, 0x5B, 0x22, 0x6B, 0xE1, 0xDA, 0x02, 0xBA, 0x18, 0xFA, 0x21, 0x34, 0x9E, 0xF9, 0x6D, // 0x55
        0x14, 0xEC, 0x76, 0xCE, 0x97, 0xF3, 0x8A, 0x0A, 0x34, 0x50, 0x6C, 0x53, 0x9A, 0x5C, 0x9A, 0xB4, // 0x56
        0x1C, 0x9B, 0xC4, 0x90, 0xE3, 0x06, 0x64, 0x81, 0xFA, 0x59, 0xFD, 0xB6, 0x00, 0xBB, 0x28, 0x70, // 0x57
        0x43, 0xA5, 0xCA, 0xCC, 0x0D, 0x6C, 0x2D, 0x3F, 0x2B, 0xD9, 0x89, 0x67, 0x6B, 0x3F, 0x7F, 0x57, // 0x58
        0x00, 0xEF, 0xFD, 0x18, 0x08, 0xA4, 0x05, 0x89, 0x3C, 0x38, 0xFB, 0x25, 0x72, 0x70, 0x61, 0x06, // 0x59
        0xEE, 0xAF, 0x49, 0xE0, 0x09, 0x87, 0x9B, 0xEF, 0xAA, 0xD6, 0x32, 0x6A, 0x32, 0x13, 0xC4, 0x29, // 0x5A
        0x8D, 0x26, 0xB9, 0x0F, 0x43, 0x1D, 0xBB, 0x08, 0xDB, 0x1D, 0xDA, 0xC5, 0xB5, 0x2C, 0x92, 0xED, // 0x5B
        0x57, 0x7C, 0x30, 0x60, 0xAE, 0x6E, 0xBE, 0xAE, 0x3A, 0xAB, 0x18, 0x19, 0xC5, 0x71, 0x68, 0x0B, // 0x5C
        0x11, 0x5A, 0x5D, 0x20, 0xD5, 0x3A, 0x8D, 0xD3, 0x9C, 0xC5, 0xAF, 0x41, 0x0F, 0x0F, 0x18, 0x6F, // 0x5D
        0x0D, 0x4D, 0x51, 0xAB, 0x23, 0x79, 0xBF, 0x80, 0x3A, 0xBF, 0xB9, 0x0E, 0x75, 0xFC, 0x14, 0xBF, // 0x5E
        0x99, 0x93, 0xDA, 0x3E, 0x7D, 0x2E, 0x5B, 0x15, 0xF2, 0x52, 0xA4, 0xE6, 0x6B, 0xB8, 0x5A, 0x98, // 0x5F
        0xF4, 0x28, 0x30, 0xA5, 0xFB, 0x0D, 0x8D, 0x76, 0x0E, 0xA6, 0x71, 0xC2, 0x2B, 0xDE, 0x66, 0x9D, // 0x60
        0xFB, 0x5F, 0xEB, 0x7F, 0xC7, 0xDC, 0xDD, 0x69, 0x37, 0x01, 0x97, 0x9B, 0x29, 0x03, 0x5C, 0x47, // 0x61
        0x02, 0x32, 0x6A, 0xE7, 0xD3, 0x96, 0xCE, 0x7F, 0x1C, 0x41, 0x9D, 0xD6, 0x52, 0x07, 0xED, 0x09, // 0x62
        0x9C, 0x9B, 0x13, 0x72, 0xF8, 0xC6, 0x40, 0xCF, 0x1C, 0x62, 0xF5, 0xD5, 0x92, 0xDD, 0xB5, 0x82, // 0x63
        0x03, 0xB3, 0x02, 0xE8, 0x5F, 0xF3, 0x81, 0xB1, 0x3B, 0x8D, 0xAA, 0x2A, 0x90, 0xFF, 0x5E, 0x61, // 0x64
        0xBC, 0xD7, 0xF9, 0xD3, 0x2F, 0xAC, 0xF8, 0x47, 0xC0, 0xFB, 0x4D, 0x2F, 0x30, 0x9A, 0xBD, 0xA6, // 0x65
        0xF5, 0x55, 0x96, 0xE9, 0x7F, 0xAF, 0x86, 0x7F, 0xAC, 0xB3, 0x3A, 0xE6, 0x9C, 0x8B, 0x6F, 0x93, // 0x66
        0xEE, 0x29, 0x70, 0x93, 0xF9, 0x4E, 0x44, 0x59, 0x44, 0x17, 0x1F, 0x8E, 0x86, 0xE1, 0x70, 0xFC, // 0x67
        0xE4, 0x34, 0x52, 0x0C, 0xF0, 0x88, 0xCF, 0xC8, 0xCD, 0x78, 0x1B, 0x6C, 0xCF, 0x8C, 0x48, 0xC4, // 0x68
        0xC1, 0xBF, 0x66, 0x81, 0x8E, 0xF9, 0x53, 0xF2, 0xE1, 0x26, 0x6B, 0x6F, 0x55, 0x0C, 0xC9, 0xCD, // 0x69
        0x56, 0x0F, 0xFF, 0x8F, 0x3C, 0x96, 0x49, 0x14, 0x45, 0x16, 0xF1, 0xBC, 0xBF, 0xCE, 0xA3, 0x0C, // 0x6A
        0x24, 0x08, 0xDC, 0x75, 0x37, 0x60, 0xA2, 0x9F, 0x05, 0x54, 0xB5, 0xF2, 0x43, 0x85, 0x73, 0x99, // 0x6B
        0xDD, 0xD5, 0xB5, 0x6A, 0x59, 0xC5, 0x5A, 0xE8, 0x3B, 0x96, 0x67, 0xC7, 0x5C, 0x2A, 0xE2, 0xDC, // 0x6C
        0xAA, 0x68, 0x67, 0x72, 0xE0, 0x2D, 0x44, 0xD5, 0xCD, 0xBB, 0x65, 0x04, 0xBC, 0xD5, 0xBF, 0x4E, // 0x6D
        0x1F, 0x17, 0xF0, 0x14, 0xE7, 0x77, 0xA2, 0xFE, 0x4B, 0x13, 0x6B, 0x56, 0xCD, 0x7E, 0xF7, 0xE9, // 0x6E
        0xC9, 0x35, 0x48, 0xCF, 0x55, 0x8D, 0x75, 0x03, 0x89, 0x6B, 0x2E, 0xEB, 0x61, 0x8C, 0xA9, 0x02, // 0x6F
        0xDE, 0x34, 0xC5, 0x41, 0xE7, 0xCA, 0x86, 0xE8, 0xBE, 0xA7, 0xC3, 0x1C, 0xEC, 0xE4, 0x36, 0x0F, // 0x70
        0xDD, 0xE5, 0xFF, 0x55, 0x1B, 0x74, 0xF6, 0xF4, 0xE0, 0x16, 0xD7, 0xAB, 0x22, 0x31, 0x1B, 0x6A, // 0x71
        0xB0, 0xE9, 0x35, 0x21, 0x33, 0x3F, 0xD7, 0xBA, 0xB4, 0x76, 0x2C, 0xCB, 0x4D, 0x80, 0x08, 0xD8, // 0x72
        0x38, 0x14, 0x69, 0xC4, 0xC3, 0xF9, 0x1B, 0x96, 0x33, 0x63, 0x8E, 0x4D, 0x5F, 0x3D, 0xF0, 0x29, // 0x73
        0xFA, 0x48, 0x6A, 0xD9, 0x8E, 0x67, 0x16, 0xEF, 0x6A, 0xB0, 0x87, 0xF5, 0x89, 0x45, 0x7F, 0x2A, // 0x74
        0x32, 0x1A, 0x09, 0x12, 0x50, 0x14, 0x8A, 0x3E, 0x96, 0x3D, 0xEA, 0x02, 0x59, 0x32, 0xE1, 0x8F, // 0x75
        0x4B, 0x00, 0xBE, 0x29, 0xBC, 0xB0, 0x28, 0x64, 0xCE, 0xFD, 0x43, 0xA9, 0x6F, 0xD9, 0x5C, 0xED, // 0x76
        0x57, 0x7D, 0xC4, 0xFF, 0x02, 0x44, 0xE2, 0x80, 0x91, 0xF4, 0xCA, 0x0A, 0x75, 0x69, 0xFD, 0xA8, // 0x77
        0x83, 0x53, 0x36, 0xC6, 0x18, 0x03, 0xE4, 0x3E, 0x4E, 0xB3, 0x0F, 0x6B, 0x6E, 0x79, 0x9B, 0x7A, // 0x78
        0x5C, 0x92, 0x65, 0xFD, 0x7B, 0x59, 0x6A, 0xA3, 0x7A, 0x2F, 0x50, 0x9D, 0x85, 0xE9, 0x27, 0xF8, // 0x79
        0x9A, 0x39, 0xFB, 0x89, 0xDF, 0x55, 0xB2, 0x60, 0x14, 0x24, 0xCE, 0xA6, 0xD9, 0x65, 0x0A, 0x9D, // 0x7A
        0x8B, 0x75, 0xBE, 0x91, 0xA8, 0xC7, 0x5A, 0xD2, 0xD7, 0xA5, 0x94, 0xA0, 0x1C, 0xBB, 0x95, 0x91, // 0x7B
        0x95, 0xC2, 0x1B, 0x8D, 0x05, 0xAC, 0xF5, 0xEC, 0x5A, 0xEE, 0x77, 0x81, 0x23, 0x95, 0xC4, 0xD7, // 0x7C
        0xB9, 0xA4, 0x61, 0x64, 0x36, 0x33, 0xFA, 0x5D, 0x94, 0x88, 0xE2, 0xD3, 0x28, 0x1E, 0x01, 0xA2, // 0x7D
        0xB8, 0xB0, 0x84, 0xFB, 0x9F, 0x4C, 0xFA, 0xF7, 0x30, 0xFE, 0x73, 0x25, 0xA2, 0xAB, 0x89, 0x7D, // 0x7E
        0x5F, 0x8C, 0x17, 0x9F, 0xC1, 0xB2, 0x1D, 0xF1, 0xF6, 0x36, 0x7A, 0x9C, 0xF7, 0xD3, 0xD4, 0x7C, // 0x7F
    ];
}

/// <summary>
/// Static dispatch shim for the KIRK engine. Callers pick between the six-argument overload
/// (thread a specific <see cref="KirkState"/> through, matching libkirk's
/// <c>kirk_sceUtilsBufferCopyWithRange</c> C signature) and the five-argument overload
/// (uses <see cref="KirkState.Default"/> for convenience).
/// </summary>
public static class KirkEngine
{
    /// <summary>
    /// Runs one KIRK command against the caller's <paramref name="kirk"/> state. Argument order
    /// and semantics match libkirk's <c>kirk_sceUtilsBufferCopyWithRange</c>.
    /// </summary>
    /// <param name="kirk">The state carrying the PRNG, the fuse-ID mirror and the fixed KIRK-1 key.</param>
    /// <param name="outbuff">Output buffer. Ignored by commands that write only to <paramref name="inbuff"/>.</param>
    /// <param name="outSize">Length of <paramref name="outbuff"/>.</param>
    /// <param name="inbuff">Input buffer. Some commands (CMD1, CMD10) also write into it.</param>
    /// <param name="inSize">Length of <paramref name="inbuff"/>.</param>
    /// <param name="cmd">One of the <c>KirkState.KIRK_CMD_*</c> constants.</param>
    /// <returns>A <c>KIRK_*</c> return code.</returns>
    public static int sceUtilsBufferCopyWithRange(KirkState kirk, byte[]? outbuff, int outSize, byte[]? inbuff, int inSize, int cmd)
    {
        ArgumentNullException.ThrowIfNull(kirk);
        return kirk.SceUtilsBufferCopyWithRange(outbuff, outSize, inbuff, inSize, cmd);
    }

    /// <summary>
    /// Convenience shim that dispatches to <see cref="KirkState.Default"/>. Matches the C
    /// signature the pspdecrypt-style callers expect, minus the state pointer.
    /// </summary>
    public static int sceUtilsBufferCopyWithRange(byte[]? outbuff, int outSize, byte[]? inbuff, int inSize, int cmd)
        => KirkState.Default.SceUtilsBufferCopyWithRange(outbuff, outSize, inbuff, inSize, cmd);
}

