// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Kekcall dispatch interface. Invokes kernel extension calls through the getppid
/// syscall trampoline with a magic calling convention. Each call number dispatches to
/// a specific kernel operation installed by the kernel payload.
/// </summary>
public static unsafe partial class PayloadKekcall
{
    /// <summary>
    /// Invokes a kekcall with the given call number and up to 6 arguments. The call
    /// routes through <c>getppid</c> with a magic marker in the first argument that
    /// distinguishes it from a normal getppid call.
    /// </summary>
    /// <param name="callNr">The kekcall number (0 = read/write dbregs, 1 = read dbregs,
    /// 2 = write dbregs, 3 = rdmsr, etc.).</param>
    /// <param name="arg1">First argument.</param>
    /// <param name="arg2">Second argument.</param>
    /// <param name="arg3">Third argument.</param>
    /// <param name="arg4">Fourth argument.</param>
    /// <param name="arg5">Fifth argument.</param>
    /// <param name="arg6">Sixth argument.</param>
    /// <returns>The return value from the kernel function.</returns>
    public static long Invoke(int callNr, long arg1 = 0, long arg2 = 0, long arg3 = 0,
        long arg4 = 0, long arg5 = 0, long arg6 = 0)
    {
        return CrtKekcall(callNr, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    /// <summary>Kekcall command number for the liveness check. Returns 0 when kstuff is
    /// already loaded and the kernel module is servicing kekcalls.</summary>
    public const int Check = -1;

    /// <summary>Kekcall command number for reading debug registers into a caller-supplied
    /// six-<c>ulong</c> buffer (DR0-DR3, DR6, DR7).</summary>
    public const int ReadDebugRegs = 1;

    /// <summary>Kekcall command number for writing debug registers from a caller-supplied
    /// six-<c>ulong</c> buffer.</summary>
    public const int WriteDebugRegs = 2;

    /// <summary>Kekcall command number for reading a model-specific register in kernel
    /// context. Arg1 = MSR number; the return low 32 bits carry RAX, the return upper
    /// 32 bits carry RDX (packed by the kernel-side handler).</summary>
    public const int ReadMsr = 3;

    /// <summary>Kekcall command number for the remote-syscall dispatcher: run
    /// <paramref name="Arg2"/> as a syscall in the process identified by
    /// <paramref name="Arg1"/> with the given argument tuple. Used to invoke
    /// <c>SYS_mlock</c> in another process's context (e.g. SceShellCore) so pinned
    /// pages survive the <c>phys_copyin</c> window.</summary>
    public const int RemoteSyscall = 5;

    /// <summary>Kekcall command number for reading the shared-area observability
    /// snapshot into a caller-supplied buffer. Only meaningful in observability
    /// builds; retail kernel modules return 0.</summary>
    public const int Snapshot = 6;

    /// <summary>
    /// Executes a syscall inside the target process's execution context. The kernel-side
    /// handler saves the target thread's register set, loads the caller's arguments,
    /// invokes the target syscall through the kernel's sysent table, then restores the
    /// original state. Enables cross-process operations that require the callee's
    /// credentials and address space, such as <c>SYS_mlock</c> against another
    /// process's text pages.
    /// </summary>
    /// <remarks>
    /// The <c>__sp_kekcall</c> CRT trampoline shifts every input register one slot down
    /// so the trapped <c>getppid</c> handler sees the caller's <c>a1</c> in <c>RDI</c>,
    /// <c>a2</c> in <c>RSI</c>, and so on. The kernel-side dispatcher then reads:
    /// <list type="bullet">
    ///   <item><c>a1</c> (<c>RDI</c>) → target PID.</item>
    ///   <item><c>a2</c> (<c>RSI</c>) → dispatcher-consumed, must not carry payload.</item>
    ///   <item><c>a3</c> (<c>RDX</c>) → target syscall number.</item>
    ///   <item><c>a4</c> (<c>R10</c>/<c>RCX</c>) → user pointer to a six-<c>long</c>
    ///     buffer holding the target syscall's argument tuple.</item>
    /// </list>
    /// Six argument slots are the on-device contract; callers that need more must
    /// marshal them through a shared kernel buffer.
    /// </remarks>
    /// <param name="targetPid">PID of the process the syscall runs in.</param>
    /// <param name="syscallNr">FreeBSD-derived syscall number (e.g. 203 for <c>SYS_mlock</c>).</param>
    /// <param name="arg1">First syscall argument.</param>
    /// <param name="arg2">Second syscall argument.</param>
    /// <param name="arg3">Third syscall argument.</param>
    /// <param name="arg4">Fourth syscall argument.</param>
    /// <param name="arg5">Fifth syscall argument.</param>
    /// <param name="arg6">Sixth syscall argument.</param>
    /// <returns>The syscall's return value on success, or a negative errno on failure
    /// (encoded exactly as the target syscall returns it).</returns>
    public static unsafe long InvokeRemoteSyscall(int targetPid, int syscallNr,
        long arg1 = 0, long arg2 = 0, long arg3 = 0, long arg4 = 0,
        long arg5 = 0, long arg6 = 0)
    {
        // The kernel handler copies six longs from the caller's user address
        // space at the pointer it reads from R10/RCX (a4). Build the argument
        // tuple on the caller's stack and pass its address; the handler treats
        // an unused trailing slot as zero, matching the ABI of the underlying
        // FreeBSD-derived syscall table.
        long* buf = stackalloc long[6];
        buf[0] = arg1;
        buf[1] = arg2;
        buf[2] = arg3;
        buf[3] = arg4;
        buf[4] = arg5;
        buf[5] = arg6;
        // a2 (RSI) is consumed by the dispatcher and must not carry payload;
        // a3 (RDX) carries the syscall number; a4 (R10) carries the buffer.
        return CrtKekcall(RemoteSyscall, targetPid, 0, syscallNr, (long)buf, 0, 0);
    }

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kekcall")]
    private static partial long CrtKekcall(int nr, long a1, long a2, long a3, long a4, long a5, long a6);
}
