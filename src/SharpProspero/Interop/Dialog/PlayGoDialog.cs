// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>Which PlayGo dialog to present.</summary>
public enum PlayGoDialogMode
{
    Invalid = 0,

    /// <summary>A progress bar over one or several chunk lists.</summary>
    ProgressBar = 1,

    /// <summary>A disc change prompt.</summary>
    DiscChange = 2,

    /// <summary>A prompt to install an optional chunk.</summary>
    RequestInstall = 3,
}

/// <summary>The layout the PlayGo progress bar uses.</summary>
public enum PlayGoDialogProgressBarType
{
    /// <summary>One caption over one list of chunks.</summary>
    SingleChunkList = 0,

    /// <summary>A row per named group of chunks.</summary>
    EnumeratedChunkList = 1,
}

/// <summary>The kind of disc change the dialog asks for.</summary>
public enum PlayGoDialogDiscChangeType
{
    /// <summary>The disc has to hold a chunk in one of the named language masks.</summary>
    LanguageMask = 0,
}

/// <summary>
/// One row of a chunk list. In single mode the label is the caption of the whole bar; in enumerated
/// mode each row carries its own caption above its own set of chunks.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 56)]
public unsafe struct ScePlayGoDialogChunkListItem
{
    /// <summary>The caption for the row (UTF-8, NUL-terminated).</summary>
    public byte* Label;

    /// <summary>The chunks whose progress the row shows.</summary>
    public ushort* ChunkIds;

    /// <summary>The number of entries in <see cref="ChunkIds"/>.</summary>
    public uint NumberOfEntries;

    private fixed byte _reserved[36];
}

/// <summary>The parameters the progress-bar dialog opens with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 80)]
public unsafe struct ScePlayGoDialogProgressBarParam
{
    /// <summary>Whether the bar shows one caption or one per row.</summary>
    public PlayGoDialogProgressBarType BarType;

    private fixed byte _reserved0[4];

    /// <summary>The rows to show.</summary>
    public ScePlayGoDialogChunkListItem* ChunkList;

    /// <summary>The number of entries in <see cref="ChunkList"/>.</summary>
    public uint NumberOfEntries;

    private fixed byte _reserved1[60];
}

/// <summary>The parameters the disc-change dialog opens with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct ScePlayGoDialogDiscChangeParam
{
    /// <summary>The kind of disc change to prompt for.</summary>
    public PlayGoDialogDiscChangeType Type;

    private fixed byte _padding[4];

    /// <summary>The languages the wanted chunk has to be in, as a bit mask.</summary>
    public ulong LanguageMask;

    private fixed byte _reserved[48];
}

/// <summary>The parameters the additional-install dialog opens with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 72)]
public unsafe struct ScePlayGoDialogRequestInstallParam
{
    /// <summary>The kind of optional chunk to install.</summary>
    public int Type;

    private fixed byte _reserved0[4];

    /// <summary>The optional chunk to install, as an 8-byte bit union whose meaning follows <see cref="Type"/>.</summary>
    public ulong* Option;

    private fixed byte _reserved1[56];
}

/// <summary>
/// The PlayGo dialog's parameters. Always build one through <see cref="PlayGoDialog.InitializeParam"/>
/// so the sizes and the check value are set; the service rejects a block whose fields do not match
/// what it expects.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 104)]
public unsafe struct ScePlayGoDialogParam
{
    /// <summary>The shared dialog block.</summary>
    public CommonDialogBaseParam BaseParam;

    /// <summary>The size of this block, in bytes.</summary>
    public nuint Size;

    /// <summary>The handle for the package the dialog reports on.</summary>
    public int Handle;

    /// <summary>Which dialog to present.</summary>
    public PlayGoDialogMode Mode;

    /// <summary>The parameter block for <see cref="PlayGoDialogMode.ProgressBar"/>, or null.</summary>
    public ScePlayGoDialogProgressBarParam* ProgBarParam;

    /// <summary>The parameter block for <see cref="PlayGoDialogMode.DiscChange"/>, or null.</summary>
    public ScePlayGoDialogDiscChangeParam* DiscChangeParam;

    /// <summary>The parameter block for <see cref="PlayGoDialogMode.RequestInstall"/>, or null.</summary>
    public ScePlayGoDialogRequestInstallParam* RequestInstallParam;

    private fixed byte _reserved[16];
}

/// <summary>The result the PlayGo dialog delivers when it finishes.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct ScePlayGoDialogResult
{
    /// <summary>The dialog that ran.</summary>
    public PlayGoDialogMode Mode;

    /// <summary>The dialog's result code. Zero for user confirmation, one for cancel, or <see cref="PlayGoDialog.ResultAutoClosed"/> when the system closed the dialog on the caller's behalf.</summary>
    public int Result;

    private fixed byte _reserved[32];
}

/// <summary>
/// PlayGo dialog bindings: the on-screen dialog that reports progress on a background install, asks
/// the user to swap discs, or prompts them to fetch an optional chunk. The dialog needs the common
/// dialog subsystem initialized first through <see cref="CommonDialog"/>, plus an open PlayGo handle.
/// </summary>
public static unsafe partial class PlayGoDialog
{
    private const string Lib = "libScePlayGoDialog";

    private const ulong MagicNumber = 0xC0D1A109;

    /// <summary>The maximum length of a message string in the single-chunk-list dialog, with the NUL.</summary>
    public const int MessageSize = 512;

    /// <summary>The maximum length of a row caption in the enumerated-chunk-list dialog, with the NUL.</summary>
    public const int ChunkListItemLabelSize = 128;

    /// <summary>The maximum number of chunk-list rows the dialog can show at once.</summary>
    public const int ChunkListItemMax = 10;

    /// <summary>The dialog closed on the system's own initiative.</summary>
    public const int ResultAutoClosed = 3;

    /// <summary>Zeroes <paramref name="param"/> and fills the sizes and the check value.</summary>
    public static void InitializeParam(ScePlayGoDialogParam* param)
    {
        *param = default;
        param->BaseParam.Size = (ulong)sizeof(CommonDialogBaseParam);
        param->BaseParam.Magic = unchecked((uint)(MagicNumber + (ulong)&param->BaseParam));
        param->Size = (nuint)sizeof(ScePlayGoDialogParam);
    }

    /// <summary>Starts the PlayGo dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayGoDialogInitialize();

    /// <summary>Opens the dialog described by <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayGoDialogOpen(ScePlayGoDialogParam* param);

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus scePlayGoDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus scePlayGoDialogGetStatus();

    /// <summary>Reads the result of a finished dialog into <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayGoDialogGetResult(ScePlayGoDialogResult* result);

    /// <summary>Stops the PlayGo dialog service.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayGoDialogTerminate();

    /// <summary>Closes an open PlayGo dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int scePlayGoDialogClose();
}
