// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>Which set of users the login dialog offers.</summary>
public enum LoginDialogMode
{
    /// <summary>Every user on the console.</summary>
    AllUsers = 0,

    /// <summary>Only the users who are not currently signed in.</summary>
    NotLoggedInUsersOnly = 1,
}

/// <summary>The reason the login dialog finished.</summary>
public enum LoginDialogResultType
{
    /// <summary>A user signed in.</summary>
    Ok = 0,

    /// <summary>The user closed the dialog without signing in.</summary>
    UserCanceled = 1,
}

/// <summary>How far along the login dialog is.</summary>
public enum LoginDialogStatus
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

/// <summary>The result the login dialog delivers when it finishes.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SceLoginDialogResult
{
    /// <summary>Whether a user signed in or the dialog was cancelled.</summary>
    public LoginDialogResultType Result;

    /// <summary>The user who signed in, or <see cref="SceUser.Invalid"/> on cancel.</summary>
    public int SelectedUser;

    private int _reserved0;
    private int _reserved1;
}

/// <summary>
/// The parameters the login dialog is opened with. Build one through
/// <see cref="LoginDialog.InitializeParam"/> so the size and the exclude lists carry the values the
/// service expects; the dialog rejects a block whose size does not match.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceLoginDialogParam
{
    /// <summary>The size of this block, in bytes.</summary>
    public int Size;

    /// <summary>Which set of users to offer.</summary>
    public LoginDialogMode Mode;

    /// <summary>Users hidden from the sign-in list. Each entry is a user id or <see cref="SceUser.Invalid"/>.</summary>
    public fixed int ExcludeUsersFromLoginList[LoginDialog.MaxLoginUsers];

    /// <summary>Users hidden from the sign-out list. Each entry is a user id or <see cref="SceUser.Invalid"/>.</summary>
    public fixed int ExcludeUsersFromLogoutList[LoginDialog.MaxLoginUsers];

    /// <summary>The user the dialog focuses initially, or <see cref="SceUser.Invalid"/> for the default.</summary>
    public int InitialFocus;

    private fixed int _reserved[5];
}

/// <summary>
/// Login dialog bindings: the on-screen dialog that lets the user sign in a profile. The dialog needs
/// the common dialog subsystem initialized first through <see cref="CommonDialog"/>.
/// </summary>
public static unsafe partial class LoginDialog
{
    private const string Lib = "libSceLoginDialog";

    /// <summary>The number of users the system allows at once.</summary>
    public const int MaxLoginUsers = 4;

    /// <summary>Clears <paramref name="param"/> and fills its size and the exclude lists.</summary>
    public static void InitializeParam(SceLoginDialogParam* param)
    {
        // The service inspects the exclude lists on every open and treats a raw zero as user id zero,
        // which is a valid signed-in user. A block cleared without further work would therefore hide the
        // first signed-in user from both lists. Seed both lists with SceUser.Invalid so a caller that
        // wants no exclusions gets none.
        *param = default;
        param->Size = sizeof(SceLoginDialogParam);
        for (int i = 0; i < MaxLoginUsers; i++)
        {
            param->ExcludeUsersFromLoginList[i] = SceUser.Invalid;
            param->ExcludeUsersFromLogoutList[i] = SceUser.Invalid;
        }
        param->InitialFocus = SceUser.Invalid;
    }

    /// <summary>Starts the login dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceLoginDialogInitialize();

    /// <summary>Stops the login dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceLoginDialogTerminate();

    /// <summary>Opens the login dialog with <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceLoginDialogOpen(SceLoginDialogParam* param);

    /// <summary>Closes an open login dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int sceLoginDialogClose();

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial LoginDialogStatus sceLoginDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial LoginDialogStatus sceLoginDialogGetStatus();

    /// <summary>Reads the result of a finished dialog into <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceLoginDialogGetResult(SceLoginDialogResult* result);
}
