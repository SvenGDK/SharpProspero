// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>The reason a common dialog finished.</summary>
public enum CommonDialogResult
{
    /// <summary>The user confirmed the dialog.</summary>
    Ok = 0,

    /// <summary>The user cancelled the dialog.</summary>
    UserCanceled = 1,
}

/// <summary>Which player invitation dialog to present.</summary>
public enum PlayerInvitationDialogMode
{
    /// <summary>Uninitialized. The service rejects a block left at this value.</summary>
    Invalid = 0,

    /// <summary>Send an invitation to a Player session.</summary>
    Send = 1,
}

/// <summary>The parameters the send-invitation dialog opens with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 72)]
public unsafe struct ScePlayerInvitationDialogSendParam
{
    /// <summary>The Player session id obtained from the server (UTF-8, NUL-terminated).</summary>
    public byte* SessionId;

    private fixed byte _reserved[64];
}

/// <summary>
/// The player invitation dialog's parameters. Always build one through
/// <see cref="PlayerInvitationDialog.InitializeParam"/> so the sizes and the check value are set;
/// the service rejects a block whose fields do not match what it expects.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 136)]
public unsafe struct ScePlayerInvitationDialogParam
{
    /// <summary>The shared dialog block.</summary>
    public CommonDialogBaseParam BaseParam;

    /// <summary>The size of this block, in bytes.</summary>
    public uint Size;

    /// <summary>The user the invitation is sent on behalf of.</summary>
    public int UserId;

    /// <summary>Which dialog to present.</summary>
    public PlayerInvitationDialogMode Mode;

    private int _pad0;

    /// <summary>The send parameters when <see cref="Mode"/> is <see cref="PlayerInvitationDialogMode.Send"/>.</summary>
    public ScePlayerInvitationDialogSendParam* SendParam;

    private fixed byte _reserved[64];
}

/// <summary>The result the player invitation dialog delivers when it finishes.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct ScePlayerInvitationDialogResult
{
    /// <summary>The dialog's termination code.</summary>
    public int ErrorCode;

    /// <summary>Whether the user confirmed or cancelled the dialog.</summary>
    public CommonDialogResult Result;

    private fixed byte _reserved[32];
}

/// <summary>
/// Player invitation dialog bindings: the on-screen dialog that lets a signed-in user invite friends
/// to their Player session. The dialog needs the common dialog subsystem initialized first through
/// <see cref="CommonDialog"/>.
/// </summary>
public static unsafe partial class PlayerInvitationDialog
{
    private const string Lib = "libScePlayerInvitationDialog";

    private const ulong MagicNumber = 0xC0D1A109;

    /// <summary>The maximum length of a Player session id, with the NUL.</summary>
    public const int SessionIdMaxSize = 45;

    /// <summary>Zeroes <paramref name="param"/> and fills the sizes, the check value and the user default.</summary>
    public static void InitializeParam(ScePlayerInvitationDialogParam* param)
    {
        // A raw zero for the user id would refer to a valid signed-in user. Seed the field with
        // SceUser.Invalid so a caller that has not chosen a user gets refused instead of silently
        // acting on the first signed-in profile.
        *param = default;
        param->BaseParam.Size = (ulong)sizeof(CommonDialogBaseParam);
        param->BaseParam.Magic = unchecked((uint)(MagicNumber + (ulong)&param->BaseParam));
        param->UserId = SceUser.Invalid;
        param->Mode = PlayerInvitationDialogMode.Invalid;
        param->Size = (uint)sizeof(ScePlayerInvitationDialogParam);
    }

    /// <summary>Starts the player invitation dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerInvitationDialogInitialize();

    /// <summary>Opens the dialog described by <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerInvitationDialogOpen(ScePlayerInvitationDialogParam* param);

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus scePlayerInvitationDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus scePlayerInvitationDialogGetStatus();

    /// <summary>Reads the result of a finished dialog into <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerInvitationDialogGetResult(ScePlayerInvitationDialogResult* result);

    /// <summary>Stops the player invitation dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerInvitationDialogTerminate();

    /// <summary>Closes an open player invitation dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerInvitationDialogClose();
}
