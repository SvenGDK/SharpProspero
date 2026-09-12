// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Kernel FPU state management. Enters and leaves the kernel FPU context so that SSE/AVX
/// instructions can run safely in kernel mode without corrupting userspace FPU state.
/// </summary>
/// <remarks>
/// Enter and Leave accept nesting: only the outermost Enter issues the kernel
/// <c>fpu_kern_enter</c> call, and only the matching outermost Leave issues
/// <c>fpu_kern_leave</c>. Inner enter/leave pairs adjust the depth counter but
/// do not touch kernel FPU state. Callers that forget a Leave never trigger a
/// Leave with depth zero. The <c>NoCtx</c> flag bit tells the kernel to skip
/// saving/restoring a context pointer, since we do the pairing here.
/// </remarks>
public static class KernelFpu
{
    /// <summary>FreeBSD-derived <c>FPU_KERN_NOCTX</c> flag: use the kernel's per-thread
    /// stash instead of a caller-supplied context pointer. Matches the flag the
    /// on-device kernel expects when the third argument to <c>fpu_kern_enter</c>
    /// is the flags bitfield.</summary>
    public const ulong NoCtxFlag = 0x800;

    private static int s_depth;

    /// <summary>Returns the current nesting depth. Zero means no active FPU
    /// context; positive values mean that many Enters have not been matched
    /// by a Leave. Exposed so callers can assert their pairing invariants.</summary>
    public static int Depth => s_depth;

    /// <summary>
    /// Enters the kernel FPU context. Recursive enters increment a depth
    /// counter; only the outermost call issues the actual kernel enter.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="fpuKernEnterAddr">Kernel address of <c>fpu_kern_enter</c>.</param>
    /// <param name="sysentsAddr">Kernel address of the <c>sysent</c> table.</param>
    public static void Enter(PayloadKernelIo io, ulong fpuKernEnterAddr, ulong sysentsAddr)
    {
        if (s_depth++ == 0)
        {
            // Call convention: (rdi=thread=NULL uses curthread, rsi=ctx=NULL, rdx=flags).
            PayloadKfncall.Call(io, sysentsAddr, fpuKernEnterAddr, 0, 0, NoCtxFlag);
        }
    }

    /// <summary>
    /// Leaves the kernel FPU context. Recursive leaves decrement the depth
    /// counter; only the matching outermost call issues the actual kernel
    /// leave. A leave issued at depth zero is a no-op — pairing bugs cannot
    /// corrupt kernel FPU state.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="fpuKernLeaveAddr">Kernel address of <c>fpu_kern_leave</c>.</param>
    /// <param name="sysentsAddr">Kernel address of the <c>sysent</c> table.</param>
    public static void Leave(PayloadKernelIo io, ulong fpuKernLeaveAddr, ulong sysentsAddr)
    {
        if (s_depth == 0) return;
        if (--s_depth == 0)
        {
            PayloadKfncall.Call(io, sysentsAddr, fpuKernLeaveAddr, 0, 0);
        }
    }
}
