// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.SystemService;

namespace SharpProspero.Application;

/// <summary>
/// Ends the process.
/// </summary>
/// <remarks>
/// <para>
/// An application module must not return from its entry point. The start object the toolchain links
/// in reports the return to the platform before the status reaches the C library, and the platform
/// treats that report as a fault: the process is killed, a crash report is written, and the user is
/// shown the box that says the application closed unexpectedly. The reason recorded is "Returned
/// from main with zero", so even a clean exit with nothing wrong is reported as a crash.
/// </para>
/// <para>
/// The C library's own <c>exit</c> is not a way out of that either. Its exit path funnels through
/// <c>_exit</c>, which issues the process-end system call. On the console's own retail firmware
/// the kernel's per-process syscall filter refuses that call for application module processes and
/// delivers signal twelve instead of ending the process. The thread-exit primitive also lands
/// there on the last thread: the library's own path runs <c>exit(0)</c> from within the
/// thread-teardown finalizer when no other thread is left to run, and the same filter fires.
/// </para>
/// <para>
/// The route that works asks the system launch controller to load a follow-on executable. Once
/// the controller accepts the request the platform's own process manager reclaims the display
/// and ends the caller from the outside, which is the same path a normal application takes when
/// the user picks the home button. The controller ignores the caller from the moment the
/// request lands, so the routine spins until it is reaped.
/// </para>
/// <code>
/// private static void Main()
/// {
///     using (var app = new Game())
///         app.Run();
///
///     ProcessExit.Exit();
/// }
/// </code>
/// <para>
/// Every teardown the module needs to run must run before this call. Nothing after it does.
/// </para>
/// </remarks>
public static unsafe partial class ProcessExit
{
    /// <summary>
    /// Ends the process with <paramref name="status"/>. Does not return.
    /// </summary>
    /// <remarks>
    /// The <paramref name="status"/> argument is accepted for source compatibility; the platform's
    /// exit path takes no status of its own.
    /// </remarks>
    /// <param name="status">The status the process ends with. Zero means it finished as intended.</param>
    public static void Exit(int status = 0)
    {
        _ = status;

        // Ask the launch controller to load a follow-on executable. The controller answers a
        // valid path with an IPC that the system-core daemon acts on by killing the caller, so
        // once the request lands the process ends from the outside. The "exit" sentinel path
        // is the one the controller resolves to the shell-return handler; any non-null string
        // is enough to pass the initial parameter check.
        LoadExecReturnToShell();

        // The controller call is one-shot and ignores the caller from the moment it accepts the
        // request. Spin so this method never falls off its own end. The reads and writes to the
        // volatile field prevent the JIT from proving the loop is either infinite or dead and
        // eliding it; a compiled infinite loop is what keeps a fresh main-thread return from
        // reaching the runtime start object, which would report the return as a fault.
        while (System.Threading.Volatile.Read(ref s_alive) != 0)
        {
            System.Threading.Volatile.Write(ref s_alive, 1);
        }
    }

    /// <summary>
    /// Ends the process and records it as an abnormal termination. Does not return.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use this where the module has decided it cannot carry on and wants that written down: the
    /// system raises the process into a fault, tears it down, and files a report describing the end as
    /// abnormal. The user is shown the box that says the application closed unexpectedly, which is the
    /// point - it is the reporting path, not the tidy way out. <see cref="Exit"/> remains the way a
    /// module that finished its work leaves.
    /// </para>
    /// <para>
    /// Nothing registered for teardown runs, so release anything that would outlive the process, such
    /// as an open file being written, before calling it.
    /// </para>
    /// </remarks>
    public static void ExitAbnormally()
    {
        SystemService.sceSystemServiceReportAbnormalTermination(null);

        // Reached only if a future platform ever declines the report and returns. Ending the
        // process through the normal exit path is still better than falling off the entry point.
        Exit(1);
    }

    // Asks the platform to load a follow-on executable. Passing "exit" as the sentinel path
    // is what the platform's own return-to-shell idiom uses: the launch controller resolves the
    // string to the shell-return handler, and the system-core daemon ends the caller from the
    // outside on the same message loop iteration the request lands on. The routine does not
    // check the return code because the caller is expected to be killed before it reaches back
    // here; the spin the caller runs afterwards is what handles the never-killed case.
    private static void LoadExecReturnToShell()
    {
        byte* path = stackalloc byte[]
        {
            (byte)'e', (byte)'x', (byte)'i', (byte)'t', 0
        };
        SystemService.sceSystemServiceLoadExec(path, null);
    }

    // Field the spin loop reads and writes to keep the compiler from eliding it. The field is
    // never mutated from outside this class, so the loop is effectively infinite.
    private static int s_alive = 1;
}
