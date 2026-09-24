// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Payload;

/// <summary>
/// Provides access to the CRT-emitted functions the toolchain statically links into every
/// payload: the kernel log, the raw syscall gateway, and the payload arguments accessor.
/// <para>
/// These symbols live in the payload's own <c>.text</c> section (emitted by the CRT start
/// object), not in an SPRX module. NativeAOT resolves them at link time through
/// DirectPInvoke — the library name on the <c>[LibraryImport]</c> attribute is a placeholder
/// that the linker never sends to the loader. The placeholder <c>"libScePosix"</c> is
/// declared in <c>Prospero.Payload.props</c> as a DirectPInvoke target for this purpose.
/// </para>
/// <para>
/// All methods carry <c>[SuppressGCTransition]</c> because the CRT functions are thin
/// in-process trampolines (a handful of instructions, no kernel transition, no blocking).
/// SPRX-resolved functions like <c>sceUserServiceInitialize</c> should NOT use
/// <c>[SuppressGCTransition]</c> — they may block on kernel calls.
/// </para>
/// </summary>
public static unsafe partial class PayloadCrt
{
    /// <summary>
    /// The DirectPInvoke placeholder library name for CRT-emitted symbols. This name does
    /// not correspond to a real SPRX module — the symbols are resolved at link time from the
    /// CRT start object that the toolchain statically links into every payload.
    /// </summary>
    internal const string Lib = "libScePosix";

    // ---- Kernel log ----

    /// <summary>
    /// Writes a NUL-terminated message to the kernel log ring buffer. The message appears in
    /// the device's <c>dmesg</c> output and in the klog relay if one is running.
    /// </summary>
    /// <param name="message">A NUL-terminated UTF-8 byte string.</param>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__prospero_klog")]
    public static partial void Klog(byte* message);

    /// <summary>
    /// Writes a <see cref="ReadOnlySpan{T}"/> message to the kernel log. The span must
    /// contain a trailing NUL byte (use <c>"text\0"u8</c> or <c>"text\n"u8</c>).
    /// </summary>
    public static void Klog(ReadOnlySpan<byte> message)
    {
        fixed (byte* p = message)
            Klog(p);
    }

    // ---- Payload arguments ----

    /// <summary>
    /// Returns the <see cref="PayloadArgs"/> block the loader handed to this payload at
    /// start-up, or <see langword="null"/> if the loader did not supply one.
    /// </summary>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__prospero_get_payload_args")]
    public static partial PayloadArgs* GetPayloadArgs();

    // ---- Raw syscall gateway ----
    //
    // The CRT-emitted syscall shuffler rearranges the C calling convention registers into
    // the FreeBSD syscall ABI and dispatches through the getpid+10 gadget. The shuffler
    // handles seven arguments total (sysno + six user args, the sixth from the caller's
    // stack frame).
    //
    // Each overload accepts a different argument count. The entry point is the same symbol;
    // the C calling convention passes unused arguments harmlessly in registers.

    /// <summary>Invokes a FreeBSD syscall with one argument.</summary>
    /// <param name="sysno">The FreeBSD syscall number (e.g. 6 for <c>SYS_close</c>).</param>
    /// <param name="arg1">First argument.</param>
    /// <returns>The syscall return value, or a negative errno on failure.</returns>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_crt_syscall")]
    public static partial long Syscall(int sysno, long arg1);

    /// <summary>Invokes a FreeBSD syscall with two arguments.</summary>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_crt_syscall")]
    public static partial long Syscall(int sysno, long arg1, long arg2);

    /// <summary>Invokes a FreeBSD syscall with three arguments.</summary>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_crt_syscall")]
    public static partial long Syscall(int sysno, long arg1, long arg2, long arg3);

    /// <summary>Invokes a FreeBSD syscall with four arguments.</summary>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_crt_syscall")]
    public static partial long Syscall(int sysno, long arg1, long arg2, long arg3, long arg4);

    /// <summary>Invokes a FreeBSD syscall with five arguments.</summary>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_crt_syscall")]
    public static partial long Syscall(int sysno, long arg1, long arg2, long arg3, long arg4, long arg5);

    /// <summary>Invokes a FreeBSD syscall with six arguments. The sixth argument is loaded
    /// from the caller's stack frame by the CRT shuffler.</summary>
    [SuppressGCTransition]
    [LibraryImport(Lib, EntryPoint = "__sp_crt_syscall")]
    public static partial long Syscall(int sysno, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);

    // ---- FreeBSD syscall numbers ----

    /// <summary>SYS_read (3) — read from a file descriptor.</summary>
    public const int SYS_read = 3;

    /// <summary>SYS_write (4) — write to a file descriptor.</summary>
    public const int SYS_write = 4;

    /// <summary>SYS_open (5) — open or create a file.</summary>
    public const int SYS_open = 5;

    /// <summary>SYS_close (6) — close a file descriptor.</summary>
    public const int SYS_close = 6;

    /// <summary>SYS_getdirentries (196) — read directory entries into a buffer.</summary>
    public const int SYS_getdirentries = 196;

    /// <summary>SYS_lseek (478) — reposition read/write file offset.</summary>
    public const int SYS_lseek = 478;

    /// <summary>SYS_stat (188) — get file status by pathname.</summary>
    public const int SYS_stat = 188;

    /// <summary>SYS_fstat (189) — get file status by descriptor.</summary>
    public const int SYS_fstat = 189;

    /// <summary>SYS_lstat (190) — get file status by pathname without following a symbolic link.</summary>
    public const int SYS_lstat = 190;

    /// <summary>SYS_unlink (10) — remove a directory entry.</summary>
    public const int SYS_unlink = 10;

    /// <summary>SYS_rename (128) — change the name of a file.</summary>
    public const int SYS_rename = 128;

    /// <summary>SYS_mkdir (136) — make a directory.</summary>
    public const int SYS_mkdir = 136;

    /// <summary>SYS_rmdir (137) — remove a directory.</summary>
    public const int SYS_rmdir = 137;

    /// <summary>SYS_accept (30) — accept a connection on a socket.</summary>
    public const int SYS_accept = 30;

    /// <summary>SYS_socket (97) — create an endpoint for communication.</summary>
    public const int SYS_socket = 97;

    /// <summary>SYS_bind (104) — bind a name to a socket.</summary>
    public const int SYS_bind = 104;

    /// <summary>SYS_setsockopt (105) — set options on a socket.</summary>
    public const int SYS_setsockopt = 105;

    /// <summary>SYS_listen (106) — listen for connections on a socket.</summary>
    public const int SYS_listen = 106;

    /// <summary>SYS_nanosleep (240) — high-resolution sleep.</summary>
    public const int SYS_nanosleep = 240;

    // ---- DirectPInvoke resolution ----
    //
    // NativeAOT DirectPInvoke resolves [LibraryImport] calls at link time by searching ALL
    // libraries declared as <DirectPInvoke> targets in Prospero.Payload.props — currently
    // libkernel, libc, and libScePosix. The linker matches the EntryPoint (or method name)
    // against every declared library's exports and binds the first match.
    //
    // This means the library name in [LibraryImport] is a HINT, not a constraint: a call
    // declared as [LibraryImport("libc", EntryPoint = "getpid")] resolves to libkernel.so's
    // getpid export because the linker searches libkernel.so (a DirectPInvoke target) and
    // finds it there, even though getpid is not in libc_stub_weak.so.
    //
    // The SDK wrappers use the CORRECT library names for clarity and semantic accuracy. If
    // a payload declares its own raw [LibraryImport] with a wrong library name, it still
    // links and runs — but the declaration is misleading.
}
