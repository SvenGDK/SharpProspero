// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// An I/O vector for scatter/gather operations and <see cref="KernelMount.nmount"/> key-value pairs.
/// Each pair contributes two entries: the even-indexed entry is a NUL-terminated key (for example
/// <c>"fstype"</c>), and the following entry is its NUL-terminated value (for example <c>"nullfs"</c>).
/// The pair count includes both keys and values.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceIovec
{
    /// <summary>Base address of the buffer.</summary>
    public void* Base;

    /// <summary>Length of the buffer in bytes.</summary>
    public nuint Length;
}

/// <summary>
/// Filesystem mount and unmount operations from <c>libkernel</c>. These system calls require the process
/// to be running in a promoted (unjailed) context to succeed.
/// </summary>
public static unsafe partial class KernelMount
{
    private const string Lib = "libkernel";

    /// <summary>Update an existing mount in place.</summary>
    public const int MntUpdate = 0x10000;

    /// <summary>Force the operation.</summary>
    public const int MntForce = 0x80000;

    /// <summary>
    /// Mounts a filesystem described by the <paramref name="iov"/> key-value array.
    /// </summary>
    /// <param name="iov">Array of key-value <see cref="SceIovec"/> pairs.</param>
    /// <param name="niov">Number of entries in the array (keys + values).</param>
    /// <param name="flags">Mount flags (<see cref="MntUpdate"/>, etc.).</param>
    /// <returns>Zero on success, or -1 on error.</returns>
    [LibraryImport(Lib)]
    public static partial int nmount(SceIovec* iov, uint niov, int flags);

    /// <summary>
    /// Unmounts the filesystem at <paramref name="path"/>.
    /// </summary>
    /// <param name="path">A NUL-terminated UTF-8 mount point path.</param>
    /// <param name="flags">Unmount flags (e.g. <see cref="MntForce"/>).</param>
    /// <returns>Zero on success, or -1 on error.</returns>
    [LibraryImport(Lib)]
    public static partial int unmount(byte* path, int flags);

    /// <summary>
    /// Fills a pair of <see cref="SceIovec"/> entries with a NUL-terminated key and a NUL-terminated
    /// value. The caller must keep the strings alive for the duration of the <see cref="nmount"/> call.
    /// </summary>
    public static void SetPair(SceIovec* iov, byte* key, int keyLen, byte* value, int valueLen)
    {
        iov[0].Base = key;
        iov[0].Length = (nuint)keyLen;
        iov[1].Base = value;
        iov[1].Length = (nuint)valueLen;
    }

    /// <summary>
    /// Fills a pair of <see cref="SceIovec"/> entries with a NUL-terminated key and a null value, for
    /// flag-style mount options such as <c>"async"</c>.
    /// </summary>
    public static void SetFlag(SceIovec* iov, byte* key, int keyLen)
    {
        iov[0].Base = key;
        iov[0].Length = (nuint)keyLen;
        iov[1].Base = null;
        iov[1].Length = 0;
    }

    /// <summary>Measures a NUL-terminated byte string.</summary>
    internal static int StringLength(byte* s)
    {
        int len = 0;
        while (s[len] != 0) len++;
        return len;
    }
}
