// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Kernel;
using System;
using System.Collections.Generic;
using System.Text;

namespace SharpProspero.Platform;

/// <summary>
/// One key-value pair in a mount option table, as <c>nmount</c> takes. A pair with a null
/// <see cref="Value"/> is a flag-style option whose presence alone is meaningful (e.g. "async").
/// </summary>
/// <param name="Key">The key (e.g. "fstype", "fspath", "from").</param>
/// <param name="Value">The value, or null for a flag-style option.</param>
public readonly record struct MountOption(string Key, string? Value);

/// <summary>
/// Filesystem mount and unmount operations for an application module running with elevated
/// privileges. The process must be promoted (unjailed) before any of these calls succeed.
/// </summary>
/// <remarks>
/// <c>RemountSystemExRw</c> remounts <c>/system_ex</c> as read-write so the application can create
/// directories underneath it. <c>NullMount</c> bind-mounts a source directory over a target so the
/// source appears in the target's place. <c>Unmount</c> detaches a mounted filesystem.
/// </remarks>
/// <example>
/// <code>
/// MountService.RemountSystemExRw();
/// MountService.NullMount("/data/homebrew/MyApp", "/system_ex/app/CUSA00000");
/// // ... run the application ...
/// MountService.Unmount("/system_ex/app/CUSA00000");
/// </code>
/// </example>
public static unsafe class MountService
{
    /// <summary>
    /// The mount options for remounting <c>/system_ex</c> as read-write with the exfatfs filesystem
    /// type. Each pair is a key and its value; a null value marks a flag-style option whose presence
    /// alone is meaningful.
    /// </summary>
    public static IReadOnlyList<MountOption> SystemExMountOptions { get; } =
    [
        new("fstype", "exfatfs"),
        new("fspath", "/system_ex"),
        new("from", "/dev/ssd0.system_ex"),
        new("large", "yes"),
        new("timezone", "static"),
        new("async", null),
        new("ignoreacl", null),
    ];

    /// <summary>
    /// Remounts <c>/system_ex</c> as read-write so the application can create directories under it.
    /// This is needed once per boot before any null-mount into <c>/system_ex/app/</c> can succeed.
    /// The process must be promoted (unjailed) for the call to be permitted.
    /// </summary>
    /// <exception cref="ProsperoException">The remount failed.</exception>
    public static void RemountSystemExRw()
    {
        // 7 options = 14 iovec entries (each option is a key-value pair).
        SceIovec* iov = stackalloc SceIovec[14];

        fixed (byte* kFstype = "fstype\0"u8, vExfatfs = "exfatfs\0"u8,
                     kFspath = "fspath\0"u8, vSystemEx = "/system_ex\0"u8,
                     kFrom = "from\0"u8, vDevice = "/dev/ssd0.system_ex\0"u8,
                     kLarge = "large\0"u8, vYes = "yes\0"u8,
                     kTimezone = "timezone\0"u8, vStatic = "static\0"u8,
                     kAsync = "async\0"u8,
                     kIgnoreacl = "ignoreacl\0"u8)
        {
            KernelMount.SetPair(&iov[0], kFstype, 7, vExfatfs, 8);
            KernelMount.SetPair(&iov[2], kFspath, 7, vSystemEx, 11);
            KernelMount.SetPair(&iov[4], kFrom, 5, vDevice, 20);
            KernelMount.SetPair(&iov[6], kLarge, 6, vYes, 4);
            KernelMount.SetPair(&iov[8], kTimezone, 9, vStatic, 7);
            KernelMount.SetFlag(&iov[10], kAsync, 6);
            KernelMount.SetFlag(&iov[12], kIgnoreacl, 10);

            int rc = KernelMount.nmount(iov, 14, KernelMount.MntUpdate);
            ThrowOnError(rc, nameof(KernelMount.nmount));
        }
    }

    /// <summary>
    /// Bind-mounts <paramref name="source"/> over <paramref name="target"/> using nullfs, so the
    /// contents of the source directory appear at the target path. The target directory must exist.
    /// </summary>
    /// <param name="source">The source directory to overlay (e.g. <c>/data/homebrew/MyApp</c>).</param>
    /// <param name="target">The target mount point (e.g. <c>/system_ex/app/CUSA00000</c>).</param>
    /// <exception cref="ArgumentException"><paramref name="source"/> or <paramref name="target"/> is null or empty.</exception>
    /// <exception cref="ProsperoException">The mount failed.</exception>
    public static void NullMount(string source, string target)
    {
        ArgumentException.ThrowIfNullOrEmpty(source);
        ArgumentException.ThrowIfNullOrEmpty(target);

        int srcLen = Encoding.UTF8.GetByteCount(source);
        int dstLen = Encoding.UTF8.GetByteCount(target);
        byte* srcBuf = stackalloc byte[srcLen + 1];
        byte* dstBuf = stackalloc byte[dstLen + 1];
        Encoding.UTF8.GetBytes(source, new Span<byte>(srcBuf, srcLen));
        srcBuf[srcLen] = 0;
        Encoding.UTF8.GetBytes(target, new Span<byte>(dstBuf, dstLen));
        dstBuf[dstLen] = 0;

        // 3 options = 6 iovec entries.
        SceIovec* iov = stackalloc SceIovec[6];

        fixed (byte* kFstype = "fstype\0"u8, vNullfs = "nullfs\0"u8,
                     kFrom = "from\0"u8,
                     kFspath = "fspath\0"u8)
        {
            KernelMount.SetPair(&iov[0], kFstype, 7, vNullfs, 7);
            KernelMount.SetPair(&iov[2], kFrom, 5, srcBuf, srcLen + 1);
            KernelMount.SetPair(&iov[4], kFspath, 7, dstBuf, dstLen + 1);

            int rc = KernelMount.nmount(iov, 6, 0);
            ThrowOnError(rc, nameof(KernelMount.nmount));
        }
    }

    /// <summary>
    /// Unmounts the filesystem at <paramref name="target"/>.
    /// </summary>
    /// <param name="target">The mount point to unmount.</param>
    /// <exception cref="ArgumentException"><paramref name="target"/> is null or empty.</exception>
    /// <exception cref="ProsperoException">The unmount failed.</exception>
    public static void Unmount(string target)
    {
        ArgumentException.ThrowIfNullOrEmpty(target);

        int len = Encoding.UTF8.GetByteCount(target);
        byte* buf = stackalloc byte[len + 1];
        Encoding.UTF8.GetBytes(target, new Span<byte>(buf, len));
        buf[len] = 0;

        int rc = KernelMount.unmount(buf, 0);
        ThrowOnError(rc, nameof(KernelMount.unmount));
    }

    /// <summary>
    /// Throws a <see cref="ProsperoException"/> when a BSD-style call returns -1. Reads the error
    /// number from the thread-local errno and wraps it in the kernel facility code so the exception
    /// carries a concrete reason.
    /// </summary>
    private static void ThrowOnError(int result, string operation)
    {
        if (result != -1)
            return;
        int errno = *KernelSystem.__error();
        throw new ProsperoException(operation, SceResult.KernelFacility | errno);
    }
}
