// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.IO;

/// <summary>
/// FreeBSD <c>struct iovec</c> for scatter/gather I/O and <c>nmount</c> key-value pairs.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct FreeBsdIovec
{
    /// <summary>Base address of the buffer.</summary>
    public void* iov_base;

    /// <summary>Length of the buffer in bytes.</summary>
    public nuint iov_len;
}

/// <summary>
/// FreeBSD <c>struct statfs</c> as returned by <see cref="PayloadMount.statfs"/>. Layout matches
/// the FreeBSD 12.x kernel structure (<c>STATFS_VERSION 0x20030518</c>).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct FreeBsdStatfs
{
    /// <summary>Structure version (<c>0x20030518</c>).</summary>
    public uint f_version;

    /// <summary>Filesystem type number.</summary>
    public uint f_type;

    /// <summary>Mount flags (<c>MNT_*</c>).</summary>
    public ulong f_flags;

    /// <summary>Fundamental filesystem block size.</summary>
    public ulong f_bsize;

    /// <summary>Optimal transfer block size.</summary>
    public ulong f_iosize;

    /// <summary>Total data blocks in the filesystem.</summary>
    public ulong f_blocks;

    /// <summary>Free blocks in the filesystem.</summary>
    public ulong f_bfree;

    /// <summary>Free blocks available to non-superuser.</summary>
    public long f_bavail;

    /// <summary>Total file nodes in the filesystem.</summary>
    public ulong f_files;

    /// <summary>Free file nodes in the filesystem.</summary>
    public long f_ffree;

    /// <summary>Synchronous writes since mount.</summary>
    public ulong f_syncwrites;

    /// <summary>Asynchronous writes since mount.</summary>
    public ulong f_asyncwrites;

    /// <summary>Synchronous reads since mount.</summary>
    public ulong f_syncreads;

    /// <summary>Asynchronous reads since mount.</summary>
    public ulong f_asyncreads;

    /// <summary>Reserved.</summary>
    private fixed ulong f_spare[10];

    /// <summary>Maximum filename length.</summary>
    public uint f_namemax;

    /// <summary>User id of the mount owner.</summary>
    public uint f_owner;

    /// <summary>Filesystem identifier (8 bytes).</summary>
    public fixed byte f_fsid[8];

    /// <summary>Reserved character space.</summary>
    private fixed byte f_charspare[80];

    /// <summary>Filesystem type name (e.g. "nullfs", "exfatfs", "pfs").</summary>
    public fixed byte f_fstypename[16];

    /// <summary>Mounted-from device or path.</summary>
    public fixed byte f_mntfromname[88];

    /// <summary>Mount point path.</summary>
    public fixed byte f_mntonname[88];
}

/// <summary>
/// Filesystem mount and unmount operations for a payload context. Wraps <c>nmount</c>,
/// <c>unmount</c>, and <c>statfs</c> from <c>libkernel</c>.
/// </summary>
/// <remarks>
/// <c>nmount</c> takes an array of <see cref="FreeBsdIovec"/> pairs where each even-indexed entry
/// is a NUL-terminated key (e.g. "fstype") and the following entry is its NUL-terminated value
/// (e.g. "nullfs"). The pair count includes both keys and values.
/// </remarks>
public static unsafe partial class PayloadMount
{
    private const string Lib = "libkernel";

    /// <summary>Read-only mount.</summary>
    public const int MntReadOnly = 0x01;

    /// <summary>Update an existing mount in place.</summary>
    public const int MntUpdate = 0x10000;

    /// <summary>Force the operation.</summary>
    public const int MntForce = 0x80000;

    /// <summary>Disable access-time updates.</summary>
    public const int MntNoAtime = 0x10000000;

    /// <summary>
    /// Mounts a filesystem described by the <paramref name="iov"/> key-value array.
    /// </summary>
    /// <param name="iov">Array of key-value <see cref="FreeBsdIovec"/> pairs.</param>
    /// <param name="niov">Number of entries in the array (keys + values).</param>
    /// <param name="flags">Mount flags (<c>MntReadOnly</c>, <c>MntUpdate</c>, etc.).</param>
    /// <returns>Zero on success, or -1 on error.</returns>
    [LibraryImport(Lib)]
    public static partial int nmount(FreeBsdIovec* iov, uint niov, int flags);

    /// <summary>
    /// Unmounts the filesystem at <paramref name="path"/>.
    /// </summary>
    /// <param name="path">A NUL-terminated UTF-8 mount point path.</param>
    /// <param name="flags">Unmount flags (e.g. <see cref="MntForce"/>).</param>
    /// <returns>Zero on success, or -1 on error.</returns>
    [LibraryImport(Lib)]
    public static partial int unmount(byte* path, int flags);

    /// <summary>
    /// Reads filesystem statistics for the mount point at <paramref name="path"/>.
    /// </summary>
    /// <param name="path">A NUL-terminated UTF-8 path.</param>
    /// <param name="buf">Buffer to receive the statistics.</param>
    /// <returns>Zero on success, or -1 on error.</returns>
    [LibraryImport(Lib)]
    public static partial int statfs(byte* path, FreeBsdStatfs* buf);

    /// <summary>
    /// Fills a <see cref="FreeBsdIovec"/> pair with a NUL-terminated key and a NUL-terminated
    /// value. The caller must pin the strings for the duration of the <see cref="nmount"/> call.
    /// </summary>
    public static void SetIovecPair(FreeBsdIovec* iov, byte* key, int keyLen, byte* value, int valueLen)
    {
        iov[0].iov_base = key;
        iov[0].iov_len = (nuint)keyLen;
        iov[1].iov_base = value;
        iov[1].iov_len = (nuint)valueLen;
    }

    /// <summary>
    /// Fills a <see cref="FreeBsdIovec"/> pair with a NUL-terminated key and a null value
    /// (for flag-style mount options like "async").
    /// </summary>
    public static void SetIovecFlag(FreeBsdIovec* iov, byte* key, int keyLen)
    {
        iov[0].iov_base = key;
        iov[0].iov_len = (nuint)keyLen;
        iov[1].iov_base = null;
        iov[1].iov_len = 0;
    }

    /// <summary>
    /// Mounts a nullfs overlay of <paramref name="source"/> at <paramref name="target"/>.
    /// </summary>
    /// <returns>Zero on success, or -1 on error.</returns>
    public static int MountNullfs(byte* source, byte* target)
    {
        FreeBsdIovec* iov = stackalloc FreeBsdIovec[6];

        byte* kFstype = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vNullfs = stackalloc byte[] { (byte)'n', (byte)'u', (byte)'l', (byte)'l', (byte)'f', (byte)'s', 0 };
        byte* kFspath = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };

        SetIovecPair(&iov[0], kFstype, 7, vNullfs, 7);
        SetIovecPair(&iov[2], kFspath, 7, target, StringLength(target) + 1);
        SetIovecPair(&iov[4], kFrom, 5, source, StringLength(source) + 1);

        return nmount(iov, 6, 0);
    }

    /// <summary>
    /// Remounts the filesystem at <paramref name="path"/> as read-write by issuing an
    /// <see cref="nmount"/> update call that clears the read-only flag.
    /// </summary>
    /// <returns>Zero on success, or -1 on error.</returns>
    public static int RemountReadWrite(byte* path)
    {
        FreeBsdIovec* iov = stackalloc FreeBsdIovec[4];

        byte* kFspath = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* vFrom = stackalloc byte[] { (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/', (byte)'l', (byte)'v', (byte)'d', (byte)'0', 0 };

        SetIovecPair(&iov[0], kFspath, 7, path, StringLength(path) + 1);
        SetIovecPair(&iov[2], kFrom, 5, vFrom, 10);

        return nmount(iov, 4, MntUpdate);
    }

    /// <summary>
    /// Mounts a UFS filesystem from a device path.
    /// </summary>
    /// <param name="devPath">Device path (e.g. <c>/dev/md0</c>).</param>
    /// <param name="mountPoint">Target mount point directory.</param>
    /// <param name="readOnly">If true, mount with <see cref="MntReadOnly"/>.</param>
    /// <returns>Zero on success.</returns>
    public static int NmountUfs(byte* devPath, byte* mountPoint, bool readOnly = false)
    {
        FreeBsdIovec* iov = stackalloc FreeBsdIovec[6];
        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vUfs = stackalloc byte[] { (byte)'u', (byte)'f', (byte)'s', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };

        SetIovecPair(&iov[0], kFstype, 7, vUfs, 4);
        SetIovecPair(&iov[2], kFspath, 7, mountPoint, StringLength(mountPoint) + 1);
        SetIovecPair(&iov[4], kFrom, 5, devPath, StringLength(devPath) + 1);

        return nmount(iov, 6, readOnly ? MntReadOnly : 0);
    }

    /// <summary>
    /// Mounts an exFAT filesystem from a device path with large, timezone=static,
    /// async, noatime, and ignoreacl flags. Always read-only.
    /// </summary>
    /// <returns>Zero on success.</returns>
    public static int NmountExfat(byte* devPath, byte* mountPoint)
    {
        FreeBsdIovec* iov = stackalloc FreeBsdIovec[16];
        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vExfatfs = stackalloc byte[] {
            (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kLarge = stackalloc byte[] {
            (byte)'l', (byte)'a', (byte)'r', (byte)'g', (byte)'e', 0 };
        byte* vYes = stackalloc byte[] { (byte)'y', (byte)'e', (byte)'s', 0 };
        byte* kTimezone = stackalloc byte[] {
            (byte)'t', (byte)'i', (byte)'m', (byte)'e', (byte)'z', (byte)'o', (byte)'n',
            (byte)'e', 0 };
        byte* vStatic = stackalloc byte[] {
            (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'i', (byte)'c', 0 };
        byte* kAsync = stackalloc byte[] {
            (byte)'a', (byte)'s', (byte)'y', (byte)'n', (byte)'c', 0 };
        byte* kNoatime = stackalloc byte[] {
            (byte)'n', (byte)'o', (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e', 0 };
        byte* kIgnoreacl = stackalloc byte[] {
            (byte)'i', (byte)'g', (byte)'n', (byte)'o', (byte)'r', (byte)'e', (byte)'a',
            (byte)'c', (byte)'l', 0 };

        SetIovecPair(&iov[0], kFstype, 7, vExfatfs, 8);
        SetIovecPair(&iov[2], kFrom, 5, devPath, StringLength(devPath) + 1);
        SetIovecPair(&iov[4], kFspath, 7, mountPoint, StringLength(mountPoint) + 1);
        SetIovecPair(&iov[6], kLarge, 6, vYes, 4);
        SetIovecPair(&iov[8], kTimezone, 9, vStatic, 7);
        SetIovecFlag(&iov[10], kAsync, 6);
        SetIovecFlag(&iov[12], kNoatime, 8);
        SetIovecFlag(&iov[14], kIgnoreacl, 10);

        return nmount(iov, 16, MntReadOnly);
    }

    /// <summary>
    /// Returns whether the path at <paramref name="path"/> is a mount point by comparing
    /// the filesystem identifier of the path and its parent.
    /// </summary>
    public static bool IsMounted(byte* path)
    {
        FreeBsdStatfs pathStat = default;
        FreeBsdStatfs parentStat = default;
        if (statfs(path, &pathStat) != 0)
            return false;
        // Build parent path: path + "/.."
        int len = StringLength(path);
        byte* parent = stackalloc byte[len + 4];
        for (int i = 0; i < len; i++) parent[i] = path[i];
        parent[len] = (byte)'/';
        parent[len + 1] = (byte)'.';
        parent[len + 2] = (byte)'.';
        parent[len + 3] = 0;
        if (statfs(parent, &parentStat) != 0)
            return true;
        // Different fsid means it is a mount point.
        for (int i = 0; i < 8; i++)
            if (pathStat.f_fsid[i] != parentStat.f_fsid[i])
                return true;
        return false;
    }

    private static int StringLength(byte* s)
    {
        int len = 0;
        while (s[len] != 0) len++;
        return len;
    }
}
