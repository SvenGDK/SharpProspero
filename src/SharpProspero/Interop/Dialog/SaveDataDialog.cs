// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.SaveData;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>Which save-data dialog to present.</summary>
public enum SaveDataDialogMode
{
    Invalid = 0,
    List = 1,
    UserMessage = 2,
    SystemMessage = 3,
    ErrorCode = 4,
    ProgressBar = 5,
    WizardList = 6,
    WizardConfirm = 7,
}

/// <summary>The wording a dialog uses.</summary>
public enum SaveDataDialogType
{
    Invalid = 0,
    Save = 1,
    Load = 2,
    Delete = 3,
}

/// <summary>Where the list focus starts.</summary>
public enum SaveDataDialogFocusPos
{
    ListHead = 0,
    ListTail = 1,
    DataHead = 2,
    DataTail = 3,
    DataLatest = 4,
    DataOldest = 5,
    DirName = 6,
}

/// <summary>The button set a message dialog shows.</summary>
public enum SaveDataDialogButtonType
{
    Ok = 0,
    YesNo = 1,
    None = 2,
    OkCancel = 3,
}

/// <summary>The button the user chose.</summary>
public enum SaveDataDialogButtonId
{
    Invalid = 0,
    Ok = 1,
    No = 2,
}

/// <summary>How a list item is laid out.</summary>
public enum SaveDataDialogItemStyle
{
    TitleDateSizeSubtitle = 0,
    TitleSubtitleDateSize = 1,
    TitleDateSize = 2,
}

/// <summary>Whether the background animates.</summary>
public enum SaveDataDialogAnimation
{
    On = 0,
    Off = 1,
}

/// <summary>A system-prepared message.</summary>
public enum SaveDataDialogSystemMessageType
{
    Invalid = 0,
    NoData = 1,
    Confirm = 2,
    Overwrite = 3,
    NoSpace = 4,
    Progress = 5,
    FileCorrupted = 6,
    Finished = 7,
    NoSpaceContinuable = 8,
    TotalSizeExceeded = 14,
}

/// <summary>The list of saves a list dialog shows.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSaveDataDialogItems
{
    /// <summary>The user whose saves are listed.</summary>
    public int UserId;
    private int _pad0;

    /// <summary>The title whose saves are listed, or null for the running application.</summary>
    public void* TitleId;

    /// <summary>The directories to list, or null for all.</summary>
    public SceSaveDataDirName* DirName;

    /// <summary>The number of entries in <see cref="DirName"/>.</summary>
    public uint DirNameNum;
    private int _pad1;

    /// <summary>A new-item entry to offer, or null.</summary>
    public void* NewItem;

    /// <summary>Where the focus starts.</summary>
    public SaveDataDialogFocusPos FocusPos;
    private int _pad2;

    /// <summary>The directory to focus when <see cref="FocusPos"/> is <see cref="SaveDataDialogFocusPos.DirName"/>.</summary>
    public SceSaveDataDirName* FocusPosDirName;

    /// <summary>How each item is laid out.</summary>
    public SaveDataDialogItemStyle ItemStyle;

    private fixed byte _reserved[36];
}

/// <summary>The parameters a save-data dialog opens with.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSaveDataDialogParam
{
    /// <summary>The common dialog block. Offset 0.</summary>
    public CommonDialogBaseParam BaseParam;

    /// <summary>The size of this structure, in bytes. Offset 48.</summary>
    public int Size;

    /// <summary>Which dialog to present. Offset 52.</summary>
    public SaveDataDialogMode Mode;

    /// <summary>The wording to use. Offset 56.</summary>
    public SaveDataDialogType DispType;
    private int _pad0;

    /// <summary>Animation settings, or null. Offset 64.</summary>
    public void* AnimParam;

    /// <summary>The list of saves for a list dialog. Offset 72.</summary>
    public SceSaveDataDialogItems* Items;

    /// <summary>A user message, or null. Offset 80.</summary>
    public void* UserMsgParam;

    /// <summary>A system message, or null. Offset 88.</summary>
    public void* SysMsgParam;

    /// <summary>An error code, or null. Offset 96.</summary>
    public void* ErrorCodeParam;

    /// <summary>A progress bar, or null. Offset 104.</summary>
    public void* ProgBarParam;

    /// <summary>User data passed back in the result, or null. Offset 112.</summary>
    public void* UserData;

    /// <summary>Options, or null. Offset 120.</summary>
    public void* OptionParam;

    /// <summary>Wizard settings, or null. Offset 128.</summary>
    public void* WizardParam;

    private fixed byte _reserved[16];
}

/// <summary>The result of a save-data dialog.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSaveDataDialogResult
{
    /// <summary>The mode the dialog ran in. Offset 0.</summary>
    public SaveDataDialogMode Mode;

    /// <summary>The dialog's result code. Offset 4.</summary>
    public int Result;

    /// <summary>The button the user chose. Offset 8.</summary>
    public SaveDataDialogButtonId ButtonId;
    private int _pad0;

    /// <summary>The chosen directory. Offset 16.</summary>
    public SceSaveDataDirName* DirName;

    /// <summary>The chosen save's parameters, or null. Offset 24.</summary>
    public void* Param;

    /// <summary>The user data passed at open time. Offset 32.</summary>
    public void* UserData;

    private fixed byte _reserved[32];
}

/// <summary>The parameters a save-data dialog closes with.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSaveDataDialogCloseParam
{
    /// <summary>The closing animation.</summary>
    public SaveDataDialogAnimation Anim;
    private fixed byte _reserved[32];
}

/// <summary>
/// Save-data dialog bindings: the on-screen dialog that lists, confirms, or reports on the user's
/// saves. The dialog needs the common dialog subsystem initialized and its module loaded first.
/// </summary>
public static unsafe partial class SaveDataDialog
{
    private const string Lib = "libSceSaveDataDialog";

    private const ulong MagicNumber = 0xC0D1A109;

    /// <summary>Sets the sizes and the check value the service requires, on a block cleared first.</summary>
    public static void InitializeParam(SceSaveDataDialogParam* param)
    {
        // Cleared here rather than left to the caller, as the sibling dialogs do. The service checks
        // that the reserved span of the block is entirely zero and refuses the whole call otherwise,
        // so a block holding anything from before is refused for a reason that names none of this.
        *param = default;
        param->BaseParam.Size = (ulong)sizeof(CommonDialogBaseParam);
        param->BaseParam.Magic = unchecked((uint)(MagicNumber + (ulong)&param->BaseParam));
        param->Size = sizeof(SceSaveDataDialogParam);
    }

    /// <summary>Starts the save-data dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogInitialize();

    /// <summary>Stops the save-data dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogTerminate();

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogGetStatus();

    /// <summary>Opens a dialog with <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogOpen(SceSaveDataDialogParam* param);

    /// <summary>Reads the result into <paramref name="result"/> once the dialog has finished.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogGetResult(SceSaveDataDialogResult* result);

    /// <summary>Closes the dialog with <paramref name="closeParam"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogClose(SceSaveDataDialogCloseParam* closeParam);

    /// <summary>Reports whether the dialog is ready to be shown.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogIsReadyToDisplay();

    /// <summary>The progress-bar target selector: the default bar in the dialog.</summary>
    public const int ProgressBarTargetBarDefault = 0;

    /// <summary>The progress-bar type: percentage.</summary>
    public const int ProgressBarTypePercentage = 0;

    /// <summary>
    /// Advances the progress bar in a running progress-bar dialog by <paramref name="delta"/>
    /// percentage points on the bar named by <paramref name="target"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogProgressBarInc(int target, uint delta);

    /// <summary>
    /// Sets the progress bar in a running progress-bar dialog to <paramref name="rate"/> percentage
    /// points on the bar named by <paramref name="target"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDialogProgressBarSetValue(int target, uint rate);
}
