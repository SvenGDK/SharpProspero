// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Pfs;

/// <summary>How much of a PFS file the validator inspects.</summary>
public enum ScePfsValidationLevel
{
    /// <summary>No validation.</summary>
    None = 0,

    /// <summary>Validate the header only.</summary>
    HeaderOnly = 1,

    /// <summary>Validate the header and the block table.</summary>
    BlockTable = 2,
}

/// <summary>
/// PFS memory-to-memory decompression bindings. A workspace buffer, sized by
/// <see cref="scePfsGetWorkBufferSize"/>, feeds the decompressor. <see cref="scePfsPread"/> reads a
/// range of the uncompressed data directly out of a PFS buffer held in memory.
/// </summary>
public static unsafe partial class ScePfs
{
    private const string Lib = "libScePfs";

    /// <summary>The supplied argument is invalid.</summary>
    public const int ErrorInvalidArg = unchecked((int)0x8A780001);

    /// <summary>The supplied buffer is not a valid PFS file.</summary>
    public const int ErrorInvalidPfsFile = unchecked((int)0x8A780002);

    /// <summary>The PFS metadata is invalid.</summary>
    public const int ErrorInvalidMetadata = unchecked((int)0x8A780003);

    /// <summary>The PFS compression algorithm is invalid.</summary>
    public const int ErrorInvalidAlgorithm = unchecked((int)0x8A780004);

    /// <summary>The offset and length fall outside the file.</summary>
    public const int ErrorOutOfBounds = unchecked((int)0x8A780005);

    /// <summary>The Kraken decoder reported an error.</summary>
    public const int ErrorKrakenDecode = unchecked((int)0x8A780006);

    /// <summary>
    /// Returns the size in bytes of the workspace buffer the decompressor requires. The caller
    /// allocates a buffer of at least this size and passes it to <see cref="scePfsPread"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial nuint scePfsGetWorkBufferSize();

    /// <summary>
    /// Checks whether <paramref name="pfsBuffer"/> holds a valid PFS file. The depth of the check
    /// is set by <paramref name="validationLevel"/>. Zero on success.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePfsValidate(void* pfsBuffer, ScePfsValidationLevel validationLevel);

    /// <summary>
    /// Writes the original uncompressed byte count of the PFS file in <paramref name="pfsBuffer"/>
    /// to <paramref name="size"/>. Zero on success.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePfsGetUncompressedSize(void* pfsBuffer, nuint* size);

    /// <summary>
    /// Reads <paramref name="length"/> bytes at <paramref name="offset"/> from the uncompressed
    /// view of the PFS file in <paramref name="pfsBuffer"/> and writes them to
    /// <paramref name="outputBuffer"/>. <paramref name="workBuffer"/> is a workspace buffer of at
    /// least <see cref="scePfsGetWorkBufferSize"/> bytes. Zero on success.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePfsPread(void* outputBuffer, nuint length, nuint offset, void* pfsBuffer, void* workBuffer);
}
