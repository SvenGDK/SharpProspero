// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>Options that steer the player selection dialog's behaviour, combined as bit flags.</summary>
[Flags]
public enum PlayerSelectionDialogBehaviorOption : uint
{
    /// <summary>No options.</summary>
    None = 0,

    /// <summary>Blocklisted players cannot be selected.</summary>
    DisableBlockedPlayer = 1u << 0,

    /// <summary>The Done button is enabled even when nobody is selected.</summary>
    EnableDoneButtonWhenNoOneSelected = 1u << 1,
}

/// <summary>Whether a player starts the dialog selected.</summary>
public enum PlayerSelectionDialogPlayerSelectStatus
{
    /// <summary>The player starts unselected.</summary>
    NotSelected = 0,

    /// <summary>The player starts selected.</summary>
    Selected = 1,
}

/// <summary>Whether the user can change a player's selection state.</summary>
public enum PlayerSelectionDialogPlayerEnableStatus
{
    /// <summary>The player's state can be changed.</summary>
    Enable = 0,

    /// <summary>The player's state is fixed.</summary>
    Disable = 1,
}

/// <summary>The label shown on a player tile.</summary>
public enum PlayerSelectionDialogPlayerLabel
{
    /// <summary>No label.</summary>
    None = 0,

    /// <summary>"Cannot Select".</summary>
    CantSelect = 1,

    /// <summary>"Joined".</summary>
    Joined = 2,
}

/// <summary>One player's starting state in the selection dialog.</summary>
[StructLayout(LayoutKind.Sequential, Size = 88)]
public unsafe struct ScePlayerSelectionDialogInitialPlayerStatus
{
    /// <summary>The player's account id.</summary>
    public ulong AccountId;

    /// <summary>Whether the player starts selected.</summary>
    public PlayerSelectionDialogPlayerSelectStatus SelectStatus;

    /// <summary>Whether the user can change this player's state.</summary>
    public PlayerSelectionDialogPlayerEnableStatus EnableStatus;

    /// <summary>The label shown on the player's tile.</summary>
    public PlayerSelectionDialogPlayerLabel Label;

    private fixed byte _reserved[64];
}

/// <summary>
/// The player selection dialog's parameters. Always build one through
/// <see cref="PlayerSelectionDialog.InitializeParam"/> so the sizes, the check value and the option
/// defaults are set; the service rejects a block whose fields do not match what it expects.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 216)]
public unsafe struct ScePlayerSelectionDialogParam
{
    /// <summary>The shared dialog block.</summary>
    public CommonDialogBaseParam BaseParam;

    /// <summary>The size of this block, in bytes.</summary>
    public nuint Size;

    /// <summary>The user who makes the selection.</summary>
    public int UserId;

    /// <summary>The title shown on the dialog (UTF-8, NUL-terminated).</summary>
    public fixed byte DialogTitle[PlayerSelectionDialog.MaxTitleSize];

    /// <summary>The maximum number of players the user can select.</summary>
    public uint MaxSelectable;

    /// <summary>The behaviour options.</summary>
    public PlayerSelectionDialogBehaviorOption BehaviorOptions;

    private int _pad0;

    /// <summary>The starting state per player, or null for all-default.</summary>
    public ScePlayerSelectionDialogInitialPlayerStatus* InitialPlayerStatusList;

    /// <summary>The number of entries in <see cref="InitialPlayerStatusList"/>.</summary>
    public uint InitialPlayerStatusListLength;

    private fixed byte _reserved[64];

    private int _pad1;
}

/// <summary>The result the player selection dialog delivers when it finishes.</summary>
[StructLayout(LayoutKind.Sequential, Size = 56)]
public unsafe struct ScePlayerSelectionDialogResult
{
    /// <summary>The dialog's termination code.</summary>
    public int Result;

    /// <summary>Whether the user confirmed or cancelled the selection.</summary>
    public CommonDialogResult UserAction;

    /// <summary>The account ids of the selected players. Owned by the service until the dialog is closed.</summary>
    public ulong* PlayerList;

    /// <summary>The number of entries in <see cref="PlayerList"/>.</summary>
    public uint PlayerListLength;

    private fixed byte _reserved[32];

    private int _pad0;
}

/// <summary>
/// Player selection dialog bindings: the on-screen dialog that lets a signed-in user pick friends
/// from their friend list. The dialog needs the common dialog subsystem initialized first through
/// <see cref="CommonDialog"/>.
/// </summary>
public static unsafe partial class PlayerSelectionDialog
{
    private const string Lib = "libScePlayerSelectionDialog";

    private const ulong MagicNumber = 0xC0D1A109;

    /// <summary>The maximum length of the dialog title in bytes, with the NUL.</summary>
    public const int MaxTitleSize = 64;

    /// <summary>The maximum number of players the dialog allows to be selected at once.</summary>
    public const int MaxSelectableSize = 256;

    /// <summary>The maximum number of entries the initial-status list can hold.</summary>
    public const int MaxPlayerListSize = 256;

    /// <summary>Zeroes <paramref name="param"/> and fills the sizes, the check value and the option defaults.</summary>
    public static void InitializeParam(ScePlayerSelectionDialogParam* param)
    {
        *param = default;
        param->BaseParam.Size = (ulong)sizeof(CommonDialogBaseParam);
        param->BaseParam.Magic = unchecked((uint)(MagicNumber + (ulong)&param->BaseParam));
        param->Size = (nuint)sizeof(ScePlayerSelectionDialogParam);
        param->UserId = SceUser.Invalid;
        param->BehaviorOptions = PlayerSelectionDialogBehaviorOption.None;
        param->MaxSelectable = MaxSelectableSize;
    }

    /// <summary>Starts the player selection dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerSelectionDialogInitialize();

    /// <summary>Opens the dialog described by <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerSelectionDialogOpen(ScePlayerSelectionDialogParam* param);

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus scePlayerSelectionDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus scePlayerSelectionDialogGetStatus();

    /// <summary>Reads the result of a finished dialog into <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerSelectionDialogGetResult(ScePlayerSelectionDialogResult* result);

    /// <summary>Stops the player selection dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerSelectionDialogTerminate();

    /// <summary>Closes an open player selection dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayerSelectionDialogClose();
}
