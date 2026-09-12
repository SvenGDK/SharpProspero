// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.Kernel;
using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Process;

/// <summary>
/// Thread creation and sleep primitives for a payload context. Wraps <c>scePthreadCreate</c>
/// from <c>libkernel</c> and the POSIX <c>sleep</c>, <c>usleep</c>, <c>nanosleep</c> from
/// <c>libkernel</c>.
/// </summary>
/// <remarks>
/// Application modules should use the threading types in <see cref="Interop.Kernel.KernelThread"/>
/// and the managed <c>Thread</c> type instead. These low-level bindings exist for payloads that
/// need to create operating-system threads directly.
/// </remarks>
public static unsafe partial class PayloadThread
{
    private const string LibC = "libc";
    private const string LibKernel = "libkernel";

    private const nuint ManagedThreadStackSize = 0x100000; // 1 MB

    /// <summary>
    /// Creates a thread with the per-thread control block that managed code requires.
    /// The thread's FSBASE is set to a fresh control block before the entry point runs,
    /// so GC transitions, exception handling, and stack canary checks work on the new
    /// thread. Optionally sets a thread name for process listings and debug output.
    /// </summary>
    /// <param name="thread">On success, receives the thread handle.</param>
    /// <param name="attr">Thread attributes, or null for defaults.</param>
    /// <param name="entry">The thread entry point; receives <paramref name="arg"/> and returns a pointer.</param>
    /// <param name="arg">Argument passed to <paramref name="entry"/>.</param>
    /// <param name="name">A NUL-terminated UTF-8 thread name, or null.</param>
    /// <returns>Zero on success, or a non-zero error code.</returns>
    public static int Create(
        nint* thread, void* attr, delegate* unmanaged<void*, void*> entry, void* arg, byte* name = null)
    {
        bool ownAttr = attr == null;
        byte* attrBuf = stackalloc byte[64];
        if (ownAttr)
        {
            scePthreadAttrInit((nint)attrBuf);
            scePthreadAttrSetstacksize((nint)attrBuf, ManagedThreadStackSize);
            attr = attrBuf;
        }

        int rc = pthread_create(thread, attr, entry, arg);

        if (ownAttr)
            scePthreadAttrDestroy((nint)attrBuf);

        if (rc == 0 && name != null)
            scePthreadRename(*thread, name);
        return rc;
    }

    [LibraryImport(LibC, EntryPoint = "pthread_create")]
    private static partial int pthread_create(
        nint* thread, void* attr, delegate* unmanaged<void*, void*> entry, void* arg);

    [LibraryImport(LibKernel)]
    private static partial int scePthreadAttrInit(nint attr);

    [LibraryImport(LibKernel)]
    private static partial int scePthreadAttrSetstacksize(nint attr, nuint stacksize);

    [LibraryImport(LibKernel)]
    private static partial int scePthreadAttrDestroy(nint attr);

    /// <summary>
    /// Creates a new operating-system thread directly, without the per-thread control block
    /// that managed code requires. Only use this for threads that will never call managed
    /// code. For threads that run managed entry points, use <see cref="Create"/> instead.
    /// </summary>
    [LibraryImport(LibKernel)]
    public static partial int scePthreadCreate(
        nint* thread, void* attr, delegate* unmanaged<void*, void*> entry, void* arg, byte* name);

    /// <summary>
    /// Suspends the calling thread for <paramref name="seconds"/> seconds.
    /// </summary>
    /// <returns>Zero when the full interval elapsed, or the remaining seconds if interrupted.</returns>
    [LibraryImport(LibKernel)]
    public static partial uint sleep(uint seconds);

    /// <summary>
    /// Suspends the calling thread for <paramref name="microseconds"/> microseconds.
    /// </summary>
    /// <returns>Zero on success, or -1 on error.</returns>
    [LibraryImport(LibKernel)]
    public static partial int usleep(uint microseconds);

    /// <summary>
    /// Suspends the calling thread for the interval specified in <paramref name="requested"/>.
    /// If interrupted, the remaining time is written to <paramref name="remaining"/> (when not null).
    /// </summary>
    /// <returns>Zero when the full interval elapsed, or -1 if interrupted.</returns>
    [LibraryImport(LibKernel)]
    public static partial int nanosleep(KernelTimespec* requested, KernelTimespec* remaining);

    /// <summary>
    /// Waits for the thread <paramref name="thread"/> to terminate. If
    /// <paramref name="valuePtr"/> is not null, the exit value is stored there.
    /// </summary>
    /// <returns>Zero on success, or a non-zero error code.</returns>
    [LibraryImport(LibKernel)]
    public static partial int scePthreadJoin(nint thread, void** valuePtr);

    /// <summary>
    /// Marks the thread <paramref name="thread"/> as detached. A detached thread's resources
    /// are automatically reclaimed when it exits.
    /// </summary>
    /// <returns>Zero on success, or a non-zero error code.</returns>
    [LibraryImport(LibKernel)]
    public static partial int scePthreadDetach(nint thread);

    /// <summary>
    /// Returns the thread handle of the calling thread.
    /// </summary>
    [LibraryImport(LibKernel)]
    public static partial nint scePthreadSelf();

    /// <summary>
    /// Sets the name of the calling thread. The name is visible in process listings and
    /// debug output.
    /// </summary>
    /// <returns>Zero on success, or a non-zero error code.</returns>
    [LibraryImport(LibKernel)]
    public static partial int scePthreadRename(nint thread, byte* name);
}
