// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>A time value with whole seconds and a nanosecond remainder.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct KernelTimespec
{
    /// <summary>Whole seconds.</summary>
    public long Seconds;

    /// <summary>Nanoseconds within the second, 0 to 999,999,999.</summary>
    public long Nanoseconds;
}

/// <summary>
/// Timing bindings. The process-time counter is a monotonic microsecond clock that starts at process
/// launch; the clock-get call reads one of the system clocks; the sleep call suspends the caller.
/// </summary>
public static unsafe partial class KernelClock
{
    private const string Lib = "libkernel";

    /// <summary>The wall-clock clock identifier.</summary>
    public const int ClockRealtime = 0;

    /// <summary>The monotonic clock identifier.</summary>
    public const int ClockMonotonic = 4;

    /// <summary>Microseconds elapsed since the process started, on a monotonic counter.</summary>
    [LibraryImport(Lib)]
    public static partial long sceKernelGetProcessTime();

    /// <summary>Reads clock <paramref name="clockId"/> into <paramref name="time"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelClockGettime(int clockId, KernelTimespec* time);

    /// <summary>Reads the smallest step clock <paramref name="clockId"/> can report.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelClockGetres(int clockId, KernelTimespec* time);

    /// <summary>Suspends the calling thread for <paramref name="microseconds"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelUsleep(uint microseconds);

    /// <summary>
    /// Suspends the calling thread for <paramref name="seconds"/> whole seconds.
    /// </summary>
    /// <returns>Zero when the whole interval elapsed, or the seconds left when the wait ended early.</returns>
    [LibraryImport(Lib)]
    public static partial uint sceKernelSleep(uint seconds);

    /// <summary>
    /// Suspends the calling thread for <paramref name="requested"/>. When the wait ends early the time
    /// left is written to <paramref name="remaining"/>, which may be null.
    /// </summary>
    /// <returns>Zero when the whole interval elapsed, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelNanosleep(KernelTimespec* requested, KernelTimespec* remaining);

    /// <summary>
    /// The monotonic counter that starts at process launch, in the counter's own units rather than in
    /// microseconds. Divide by <see cref="sceKernelGetProcessTimeCounterFrequency"/> for seconds.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial ulong sceKernelGetProcessTimeCounter();

    /// <summary>How many units of <see cref="sceKernelGetProcessTimeCounter"/> make one second.</summary>
    [LibraryImport(Lib)]
    public static partial ulong sceKernelGetProcessTimeCounterFrequency();

    /// <summary>The processor's own cycle counter.</summary>
    [LibraryImport(Lib)]
    public static partial ulong sceKernelReadTsc();

    /// <summary>How many units of <see cref="sceKernelReadTsc"/> make one second.</summary>
    [LibraryImport(Lib)]
    public static partial ulong sceKernelGetTscFrequency();

    /// <summary>
    /// Which processor the calling thread is running on at this instant. A thread free to move reports a
    /// different number from one call to the next.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetCurrentCpu();
}
