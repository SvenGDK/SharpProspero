// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>The reason the signin dialog finished.</summary>
public enum SigninDialogResultType
{
    /// <summary>The user signed in.</summary>
    Ok = 0,

    /// <summary>The user closed the dialog without signing in.</summary>
    UserCanceled = 1,
}

/// <summary>How far along the signin dialog is.</summary>
public enum SigninDialogStatus
{
    /// <summary>The dialog service is not initialized.</summary>
    None = 0,

    /// <summary>Initialized, no dialog open.</summary>
    Initialized = 1,

    /// <summary>A dialog is open and running.</summary>
    Running = 2,

    /// <summary>The dialog has finished; read its result.</summary>
    Finished = 3,
}

/// <summary>The result the signin dialog delivers when it finishes.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SceSigninDialogResult
{
    /// <summary>Whether the user signed in or the dialog was cancelled.</summary>
    public SigninDialogResultType Result;

    private int _reserved0;
    private int _reserved1;
    private int _reserved2;
}

/// <summary>
/// The parameters the signin dialog is opened with. Build one through
/// <see cref="SigninDialog.InitializeParam"/> so the size is set and the user id starts at
/// <see cref="SceUser.Invalid"/>; the dialog rejects a block whose size does not match.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SceSigninDialogParam
{
    /// <summary>The size of this block, in bytes.</summary>
    public int Size;

    /// <summary>The user the signin runs for.</summary>
    public int UserId;

    private int _reserved0;
    private int _reserved1;
}

/// <summary>
/// Signin dialog bindings: the on-screen dialog that asks a chosen user for their credentials so
/// their profile is signed in. The dialog needs the common dialog subsystem initialized first through
/// <see cref="CommonDialog"/>.
/// </summary>
public static unsafe partial class SigninDialog
{
    private const string Lib = "libSceSigninDialog";

    /// <summary>Clears <paramref name="param"/>, sets its size and marks the user as unset.</summary>
    public static void InitializeParam(SceSigninDialogParam* param)
    {
        // The user id has to be a real signed-out user. A block cleared without further work would leave
        // the user id at zero, which is a valid signed-in id, so seed it with SceUser.Invalid to force
        // callers to name a real user rather than accidentally address the first signed-in one.
        *param = default;
        param->Size = sizeof(SceSigninDialogParam);
        param->UserId = SceUser.Invalid;
    }

    /// <summary>Starts the signin dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSigninDialogInitialize();

    /// <summary>Stops the signin dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSigninDialogTerminate();

    /// <summary>Opens the signin dialog with <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSigninDialogOpen(SceSigninDialogParam* param);

    /// <summary>Closes an open signin dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSigninDialogClose();

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial SigninDialogStatus sceSigninDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial SigninDialogStatus sceSigninDialogGetStatus();

    /// <summary>Reads the result of a finished dialog into <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSigninDialogGetResult(SceSigninDialogResult* result);
}
