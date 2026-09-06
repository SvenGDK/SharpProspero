// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Kernel debug register manipulation through kekcall. Reads and writes DR0-DR7 for
/// hardware breakpoint/watchpoint installation.
/// </summary>
public static unsafe class KernelDebugRegs
{
    /// <summary>
    /// Reads debug registers (DR0-DR3, DR6, DR7 = 6 x uint64) from the current CPU.
    /// </summary>
    public static void Read(Span<ulong> regs)
    {
        if (regs.Length < 6) throw new ArgumentException("Buffer must hold at least 6 ulongs.");
        fixed (ulong* p = regs)
            PayloadKekcall.Invoke(1, (long)(nint)p);
    }

    /// <summary>
    /// Writes debug registers (DR0-DR3, DR6, DR7) on the current CPU.
    /// </summary>
    public static void Write(ReadOnlySpan<ulong> regs)
    {
        if (regs.Length < 6) throw new ArgumentException("Buffer must hold at least 6 ulongs.");
        fixed (ulong* p = regs)
            PayloadKekcall.Invoke(2, (long)(nint)p);
    }

    /// <summary>DR7 flag: enable local breakpoint 0.</summary>
    public const ulong Dr7L0 = 0x01;

    /// <summary>DR7 flag: enable local breakpoint 1.</summary>
    public const ulong Dr7L1 = 0x04;

    /// <summary>DR7 flag: enable local breakpoint 2.</summary>
    public const ulong Dr7L2 = 0x10;

    /// <summary>DR7 flag: enable local breakpoint 3.</summary>
    public const ulong Dr7L3 = 0x40;

    /// <summary>DR7 condition: break on execution.</summary>
    public const ulong Dr7CondExec = 0x00;

    /// <summary>DR7 condition: break on write.</summary>
    public const ulong Dr7CondWrite = 0x01;

    /// <summary>DR7 condition: break on I/O.</summary>
    public const ulong Dr7CondIo = 0x02;

    /// <summary>DR7 condition: break on read or write.</summary>
    public const ulong Dr7CondRw = 0x03;

    /// <summary>DR7 length: 1 byte.</summary>
    public const ulong Dr7Len1 = 0x00;

    /// <summary>DR7 length: 2 bytes.</summary>
    public const ulong Dr7Len2 = 0x01;

    /// <summary>DR7 length: 4 bytes.</summary>
    public const ulong Dr7Len4 = 0x03;

    /// <summary>DR7 length: 8 bytes.</summary>
    public const ulong Dr7Len8 = 0x02;
}
