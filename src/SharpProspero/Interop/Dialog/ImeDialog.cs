// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>The kind of on-screen keyboard shown.</summary>
public enum ImeType
{
    /// <summary>A normal text keyboard.</summary>
    Default = 0,

    /// <summary>An alphanumeric keyboard.</summary>
    BasicLatin = 1,

    /// <summary>A keyboard laid out for a web address.</summary>
    Url = 2,

    /// <summary>A keyboard laid out for an email address.</summary>
    Mail = 3,

    /// <summary>A number pad.</summary>
    Number = 4,
}

/// <summary>The label on the keyboard's enter key.</summary>
public enum ImeEnterLabel
{
    /// <summary>"Done".</summary>
    Default = 0,

    /// <summary>"Send".</summary>
    Send = 1,

    /// <summary>"Search".</summary>
    Search = 2,

    /// <summary>"Go".</summary>
    Go = 3,
}

/// <summary>The input engine. Only the default is defined.</summary>
public enum ImeInputMethod
{
    /// <summary>The default input engine. The only accepted value.</summary>
    Default = 0,
}

/// <summary>Which horizontal edge of the keyboard the display position refers to.</summary>
public enum ImeHorizontalAlignment
{
    Left = 0,
    Center = 1,
    Right = 2,
}

/// <summary>Which vertical edge of the keyboard the display position refers to.</summary>
public enum ImeVerticalAlignment
{
    Top = 0,
    Center = 1,
    Bottom = 2,
}

/// <summary>Where the keyboard is in its lifecycle.</summary>
public enum ImeDialogStatus
{
    /// <summary>Not running.</summary>
    None = 0,

    /// <summary>On screen; the user is typing.</summary>
    Running = 1,

    /// <summary>Closed; read the result.</summary>
    Finished = 2,
}

/// <summary>How the keyboard closed.</summary>
public enum ImeDialogEndStatus
{
    /// <summary>The user finished and accepted the text.</summary>
    Ok = 0,

    /// <summary>The user canceled.</summary>
    UserCanceled = 1,

    /// <summary>The keyboard was closed by the application before the user finished.</summary>
    Aborted = 2,
}

/// <summary>Options that shape the keyboard's behaviour.</summary>
[Flags]
public enum ImeOption : uint
{
    /// <summary>No option.</summary>
    None = 0x00000000,

    /// <summary>Allow more than one line of text.</summary>
    Multiline = 0x00000001,

    /// <summary>Do not capitalize the first letter automatically.</summary>
    NoAutoCapitalization = 0x00000002,

    /// <summary>Mask the text as a password.</summary>
    Password = 0x00000004,

    /// <summary>Prefer an external keyboard when one is connected.</summary>
    ExternalKeyboard = 0x00000010,

    /// <summary>Do not add typed strings to the input dictionary.</summary>
    NoLearning = 0x00000020,

    /// <summary>Hold the keyboard at its display position.</summary>
    FixedPosition = 0x00000040,

    /// <summary>Do not allow copy and paste.</summary>
    DisableCopyPaste = 0x00000080,

    /// <summary>Force the specified languages to be available. Value 0x8.</summary>
    LanguagesForced = 0x00000008,

    /// <summary>Disable automatic resume. Value 0x100.</summary>
    DisableResume = 0x00000100,

    /// <summary>Disable auto-spacing when accepting a predictive suggestion. Value 0x200.</summary>
    DisableAutoSpace = 0x00000200,

    /// <summary>Disable position adjustment of the panel. Value 0x800.</summary>
    DisablePositionAdjustment = 0x00000800,

    /// <summary>Use the extended pre-edit text buffer. Value 0x1000.</summary>
    ExpandedPreeditBuffer = 0x00001000,

    /// <summary>Use the Japanese alphanumeric key as Caps Lock. Value 0x2000.</summary>
    UseJapaneseEisuuKeyAsCapsLock = 0x00002000,

    /// <summary>Use 4K coordinates for panel positioning. Value 0x4000.</summary>
    UseOver2kCoordinates = 0x00004000,
}

/// <summary>
/// The parameters the keyboard is opened with. Fill it through
/// <see cref="ImeDialog.InitializeParam"/> so the reserved bytes and the invalid-user default are
/// set, then set the fields the application supplies.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 96)]
public unsafe struct SceImeDialogParam
{
    /// <summary>The user the keyboard belongs to.</summary>
    public int UserId;

    /// <summary>The keyboard layout.</summary>
    public ImeType Type;

    /// <summary>A bitmask of allowed languages, or 0 for the system default.</summary>
    public ulong SupportedLanguages;

    /// <summary>The label on the enter key.</summary>
    public ImeEnterLabel EnterLabel;

    /// <summary>The input engine. Must be <see cref="ImeInputMethod.Default"/>.</summary>
    public ImeInputMethod InputMethod;

    /// <summary>A text-filter callback, or null.</summary>
    public void* Filter;

    /// <summary>The behaviour options.</summary>
    public ImeOption Option;

    /// <summary>The longest text the user may enter, in characters, excluding the terminator.</summary>
    public uint MaxTextLength;

    /// <summary>The caller-owned UTF-16 buffer the entered text is written to.</summary>
    public char* InputTextBuffer;

    /// <summary>The display position, in pixels.</summary>
    public float PosX;

    /// <summary>The display position, in pixels.</summary>
    public float PosY;

    /// <summary>Which horizontal edge <see cref="PosX"/> refers to.</summary>
    public ImeHorizontalAlignment HorizontalAlignment;

    /// <summary>Which vertical edge <see cref="PosY"/> refers to.</summary>
    public ImeVerticalAlignment VerticalAlignment;

    /// <summary>A UTF-16 hint shown while the field is empty, or null.</summary>
    public char* Placeholder;

    /// <summary>A UTF-16 title shown above the field, or null.</summary>
    public char* Title;

    private fixed sbyte _reserved[16];
}

/// <summary>The result of a keyboard that has closed.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceImeDialogResult
{
    /// <summary>How the keyboard closed.</summary>
    public ImeDialogEndStatus EndStatus;

    private fixed sbyte _reserved[12];
}

/// <summary>
/// The on-screen keyboard. It is a system dialog: the application opens it, polls it each frame, and
/// reads the typed text back from the buffer it supplied. The higher-level
/// <see cref="Platform.TextInputDialog"/> drives the whole cycle.
/// </summary>
public static unsafe partial class ImeDialog
{
    private const string Lib = "libSceImeDialog";

    /// <summary>The keyboard is not open, so there is nothing to update or close yet.</summary>
    public const int NotRunning = unchecked((int)0x80BC0105);

    /// <summary>The keyboard is still open; its result is not ready to read.</summary>
    public const int NotFinished = unchecked((int)0x80BC0106);

    /// <summary>The keyboard is not in use by this caller.</summary>
    public const int NotInUse = unchecked((int)0x80BC0107);

    /// <summary>
    /// Zeroes <paramref name="param"/> and sets the user to the invalid default, matching the
    /// service's own initializer. Set the fields the application supplies afterward.
    /// </summary>
    public static void InitializeParam(SceImeDialogParam* param)
    {
        *param = default;
        param->UserId = SceUser.Invalid;
    }

    /// <summary>Opens the keyboard. Pass null for <paramref name="extendedParam"/> for the default look.</summary>
    [LibraryImport(Lib)]
    public static partial int sceImeDialogInit(SceImeDialogParam* param, void* extendedParam);

    /// <summary>Reports where the keyboard is in its lifecycle.</summary>
    [LibraryImport(Lib)]
    public static partial ImeDialogStatus sceImeDialogGetStatus();

    /// <summary>Reads how a closed keyboard ended.</summary>
    [LibraryImport(Lib)]
    public static partial int sceImeDialogGetResult(SceImeDialogResult* result);

    /// <summary>Closes the keyboard before the user finishes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceImeDialogAbort();

    /// <summary>Shuts the keyboard down. Call once it has finished.</summary>
    [LibraryImport(Lib)]
    public static partial int sceImeDialogTerm();

    /// <summary>Measures the area the keyboard will occupy, to place it.</summary>
    [LibraryImport(Lib)]
    public static partial int sceImeDialogGetPanelSizeExtended(
        SceImeDialogParam* param, void* extendedParam, uint* width, uint* height);
}
