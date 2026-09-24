// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Dialog;
using SharpProspero.Interop.Sysmodule;
using SharpProspero.Modules;
using System;
using Native = SharpProspero.Interop.Dialog.ErrorDialog;

namespace SharpProspero.Platform;

/// <summary>Where an open error dialog is.</summary>
public enum ErrorDialogState
{
    /// <summary>The dialog is on screen.</summary>
    Running,

    /// <summary>The dialog has closed.</summary>
    Closed,
}

/// <summary>
/// The system error dialog. Show it for an error code, poll it once per frame until it closes. It
/// presents the console's own message for the code, so a utility reports failures the way the system
/// does.
/// </summary>
/// <example>
/// <code>
/// using var dialog = ErrorDialog.Show(errorCode);
/// while (dialog.Update() != ErrorDialogState.Closed)
///     display.Present();
/// </code>
/// </example>
public sealed unsafe class ErrorDialog : IDisposable
{
    // The loadable module the dialog lives in, owned from the moment it is loaded so that every way out
    // of the open sequence gives it back rather than leaving it mapped for the life of the process.
    private readonly SystemModule _module;
    private bool _disposed;
    private bool _initialized;
    private bool _opened;

    private ErrorDialog(SystemModule module) => _module = module;

    /// <summary>
    /// Opens the error dialog for <paramref name="errorCode"/>. Brings the dialog subsystem up and
    /// loads the error-dialog module first.
    /// </summary>
    /// <exception cref="ProsperoException">The subsystem or the dialog refused to start.</exception>
    public static ErrorDialog Show(int errorCode, int userId = SceUser.System)
    {
        CommonDialog.EnsureInitialized();
        var dialog = new ErrorDialog(SystemModule.Load(SystemModuleId.ErrorDialog));
        try
        {
            SceResult.ThrowIfFailed(Native.sceErrorDialogInitialize(), nameof(Native.sceErrorDialogInitialize));
            dialog._initialized = true;

            SceErrorDialogParam param;
            Native.InitializeParam(&param);
            param.ErrorCode = errorCode;
            param.UserId = userId;
            SceResult.ThrowIfFailed(Native.sceErrorDialogOpen(&param), nameof(Native.sceErrorDialogOpen));
            dialog._opened = true;
            return dialog;
        }
        catch
        {
            dialog.Dispose();
            throw;
        }
    }

    /// <summary>Advances the dialog and reports where it is. Call once per frame.</summary>
    public ErrorDialogState Update()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Native.sceErrorDialogUpdateStatus() == CommonDialogStatus.Running
            ? ErrorDialogState.Running
            : ErrorDialogState.Closed;
    }

    /// <summary>Closes the dialog if it is open, drains its state to finished, shuts it down, and unloads the module.</summary>
    /// <remarks>
    /// The terminate call is unconditional. Terminating while the close is still in flight leaves
    /// the shell-side client bound to this application's identifier and faults the shell on its
    /// post-exit cleanup pass. Pumping the status past Running draws the close through cleanly.
    /// The wait is bounded so a shell that never answers cannot hold the exit path forever.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_opened)
            Native.sceErrorDialogClose();
        SpinUntilFinished();
        if (_initialized)
            Native.sceErrorDialogTerminate();
        _module.Dispose();
    }

    private void SpinUntilFinished()
    {
        if (!_opened)
            return;
        for (int i = 0; i < 60; i++)
        {
            if (Native.sceErrorDialogUpdateStatus() != CommonDialogStatus.Running)
                return;
            System.Threading.Thread.Sleep(16);
        }
    }
}
