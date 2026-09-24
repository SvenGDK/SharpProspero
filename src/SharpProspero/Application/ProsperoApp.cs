// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Diagnostics;
using SharpProspero.Graphics;
using SharpProspero.Input;
using SharpProspero.Interop;
using SharpProspero.Interop.SystemService;
using SharpProspero.Interop.UserService;
using SharpProspero.Threading;
using System;
using System.Diagnostics;

namespace SharpProspero.Application;

/// <summary>
/// Base class for an application module. Derive from it, override <see cref="OnFrame"/>, and call
/// <see cref="Run"/> from the module entry point. The base opens the display and controller, drives
/// a vertical-blank-paced loop, and tears everything down on exit.
/// </summary>
/// <remarks>Creates the application with <paramref name="config"/>, or the defaults when null.</remarks>
public abstract class ProsperoApp(AppConfig? config = null) : IDisposable
{
    private readonly FrameContext _context = new();
    private DisplayDevice? _display;
    private GamePad? _gamePad;
    private bool _disposed;
    private int _torn;
    private bool _userServiceInitialized;

    /// <summary>The startup settings.</summary>
    public AppConfig Config { get; } = config ?? new AppConfig();

    /// <summary>The display, available after <see cref="Run"/> has started.</summary>
    protected DisplayDevice Display => _display ?? throw new InvalidOperationException("The display is available only while running.");

    /// <summary>The controller, or null when none was opened.</summary>
    protected GamePad? GamePad => _gamePad;

    /// <summary>
    /// The hand-off point back to the frame thread, drained once per frame before <see cref="OnFrame"/>.
    /// Post work here from a worker thread to apply a background result to the drawing state safely.
    /// </summary>
    protected Dispatcher Dispatcher => _context.Dispatcher;

    /// <summary>
    /// Opens the display and controller and runs the frame loop until an override requests exit. The
    /// call returns after teardown.
    /// </summary>
    public void Run()
    {
        InitializeServices();

        // The display is opened for the system rather than for a user. An application of this kind
        // owns the whole output and the call takes only that, so passing a user here would refuse the
        // open for anyone who set one; the user matters to the controller, which is where it is used.
        _display = DisplayDevice.Open(Config.Width, Config.Height, Config.BufferCount, SceUser.System);
        if (Config.OpenGamePad)
            TryOpenGamePad();

        OnLoad();

        // Once loading has run, its teardown must run too, whether the loop ends by request or because a
        // frame threw. The exception still propagates so the caller sees it (and Dispose releases the
        // display and controller), but the override's own cleanup is not skipped on the way out.
        try
        {
            long previous = Stopwatch.GetTimestamp();
            double frequency = Stopwatch.Frequency;
            _context.Input = GamePadState.Neutral;

            while (true)
            {
                long now = Stopwatch.GetTimestamp();
                _context.DeltaSeconds = (now - previous) / frequency;
                _context.TotalSeconds += _context.DeltaSeconds;
                previous = now;

                _context.Surface = _display.BackBuffer;
                _context.PreviousInput = _context.Input;

                // A controller that was not there at start-up is looked for again now and then. Without
                // this a module that started a moment before the user signed in, or before the pad was
                // paired, stays deaf to it for as long as it runs.
                if (_gamePad is null && Config.OpenGamePad && _context.FrameIndex >= _nextGamePadAttempt)
                    TryOpenGamePad();

                _context.Input = _gamePad?.Read() ?? GamePadState.Neutral;

                // Apply anything a worker thread handed back before the frame draws.
                _context.Dispatcher.RunPending();

                OnFrame(_context);

                _display.Present(Config.FlipMode);
                _context.FrameIndex++;

                if (_context.ExitRequested)
                    break;
            }
        }
        finally
        {
            // A background thread may have posted work between the last run of the dispatcher and
            // the exit check; running it now lets it release anything it holds before the subclass
            // pulls resources out from under it. A throw here is caught so it cannot stop the rest
            // of teardown.
            try { _context.Dispatcher.RunPending(); }
            catch { }

            // Any still-running common dialog is drained here, before the subclass has a chance to
            // dispose it. The dialog subsystem's terminate calls are unconditional: a close in
            // flight leaves the shell holding an orphan client for this appId, and the shell's own
            // post-exit dialog cleanup then reaches into a client whose destructor already ran,
            // which is the crash the user sees on the way back to the home menu. The pump reads
            // the subsystem's own state and bounds the wait so a shell that never answers cannot
            // hold this path forever.
            try { DrainCommonDialogs(); }
            catch { }

            // Subclass releases what OnLoad brought up. A throw is caught for the same reason.
            try { OnUnload(); }
            catch { }

            // A callback the subclass queued during OnUnload is run one more time before base
            // teardown starts, so a background thread that raced with the unload does not leave
            // its resource holder alive past the finalizer.
            try { _context.Dispatcher.RunPending(); }
            catch { }

            // Base teardown, on the frame thread, before Run returns. Doing it here rather than
            // waiting for a caller-side Dispose means a caller that starts a run without a using
            // block still gets correct teardown.
            TearDown();
        }
    }

    // Polls the dialog subsystem's own "used" flag until it clears, at roughly the frame rate for
    // as long as one second. The dialog subsystem's worker thread advances the state independently
    // of the frame thread, so a short sleep between polls is what waits on it. Returns silently on
    // timeout; the caller then continues to teardown.
    private static void DrainCommonDialogs()
    {
        if (!Interop.Dialog.CommonDialog.sceCommonDialogIsUsed())
            return;
        for (int i = 0; i < 60; i++)
        {
            if (!Interop.Dialog.CommonDialog.sceCommonDialogIsUsed())
                return;
            System.Threading.Thread.Sleep(16);
        }
    }

    /// <summary>Called once after the display opens and before the first frame. Load resources here.</summary>
    protected virtual void OnLoad()
    {
    }

    /// <summary>Called once per frame. Draw into <see cref="FrameContext.Surface"/>.</summary>
    protected abstract void OnFrame(FrameContext context);

    /// <summary>Called once after the loop ends and before teardown. Release resources here.</summary>
    protected virtual void OnUnload()
    {
    }

    // How many frames pass before a missing controller is looked for again, and the frame the next
    // attempt is allowed on. Once a second is often enough to pick one up without asking the service
    // on every frame for something that is usually not there.
    private const long GamePadRetryFrames = 60;
    private long _nextGamePadAttempt;

    /// <summary>
    /// Opens the controller for <see cref="AppConfig.UserId"/>, resolving the launching user when that
    /// is <see cref="SceUser.Invalid"/>. A failure leaves the controller unopened and is recorded
    /// rather than passed on: a module that draws is more use than one that ends because a pad was not
    /// ready, and the next attempt follows shortly.
    /// </summary>
    private void TryOpenGamePad()
    {
        _nextGamePadAttempt = _context.FrameIndex + GamePadRetryFrames;
        try
        {
            // Open resolves the launching user itself when the setting names none.
            _gamePad = GamePad.Open(Config.UserId);
        }
        catch (ProsperoException failure)
        {
            _gamePad = null;
            Log.Warning($"The controller could not be opened: {failure.Message}");
        }
    }

    private void InitializeServices()
    {
        // The service calls are tolerant: a module launched by the system may find them already
        // started, which the return code reports without preventing the loop from running. Only the
        // first-success case counts as "we now owe a terminate on the way out"; a service that was
        // already up is one another layer brought up and will bring down itself.
        unsafe
        {
            int priority = 700;
            int rc = UserService.sceUserServiceInitialize(&priority);
            if (rc == 0)
                _userServiceInitialized = true;
        }

        if (Config.HideSplashScreen)
            SystemService.sceSystemServiceHideSplashScreen();
    }

    /// <summary>Tears down the controller, display and user-service session. Safe to call more than once.</summary>
    /// <remarks>
    /// Base teardown runs from <see cref="Run"/>'s finally-block, so a caller that starts a run without
    /// a using-block still gets correct teardown; the wrapping using-block reaches the same method
    /// through <see cref="Dispose"/>, and the idempotent guard makes the second call a no-op.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        TearDown();
        GC.SuppressFinalize(this);
    }

    // The base's own teardown, in one place, safe to call from both Run's finally and Dispose. The
    // controller closes first (it belongs to a user session, and closing it before terminating that
    // session is the order the service expects), then the display drains and releases its buffers,
    // then the user-service session ends. Each step is guarded so a throw in one still lets the
    // next run — leaking one holder because a previous step threw leaves the process holding a
    // device the system looks for on the way out, and the process is told that as a fault rather
    // than as a clean exit. The user-service terminate runs only when the initialize we ran on the
    // way in reported it as ours.
    private void TearDown()
    {
        // Atomic guard: whichever caller races here first wins the tear-down; the other returns
        // at once. Two concurrent tear-downs would otherwise both terminate the user service or
        // both dispose the display, and the second call to either is the fault the guard is here
        // to prevent.
        if (System.Threading.Interlocked.Exchange(ref _torn, 1) != 0)
            return;

        GamePad? gamePad = _gamePad;
        _gamePad = null;
        if (gamePad is not null)
        {
            try { gamePad.Dispose(); }
            catch { }
        }

        DisplayDevice? display = _display;
        _display = null;
        if (display is not null)
        {
            try { display.Dispose(); }
            catch { }
        }

        if (_userServiceInitialized)
        {
            try { UserService.sceUserServiceTerminate(); }
            catch { }
            _userServiceInitialized = false;
        }
    }
}
