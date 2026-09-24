// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Dialog;

/// <summary>How far along a dialog is.</summary>
public enum CommonDialogStatus
{
    /// <summary>The dialog subsystem is not initialized.</summary>
    None = 0,

    /// <summary>Initialized, no dialog open.</summary>
    Initialized = 1,

    /// <summary>A dialog is open and running.</summary>
    Running = 2,

    /// <summary>The dialog has finished; read its result.</summary>
    Finished = 3,
}

/// <summary>How the browser is presented.</summary>
public enum WebBrowserDialogMode
{
    /// <summary>Not a presentation; the value a zeroed block holds before a mode is chosen. The
    /// service rejects a block left this way, so a real call sets one of the modes below.</summary>
    Invalid = 0,

    /// <summary>The default full presentation.</summary>
    Default = 1,

    /// <summary>A window sized and placed by the caller.</summary>
    Custom = 2,
}

/// <summary>
/// The block every dialog call starts with. The size and the check value must both be set before the
/// service will accept it, which <see cref="WebBrowserDialog.InitializeParam"/> does.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 48)]
public unsafe struct CommonDialogBaseParam
{
    /// <summary>The size of this block, in bytes.</summary>
    public ulong Size;

    private fixed byte _reserved[36];

    /// <summary>The check value, derived from this block's own address.</summary>
    public uint Magic;
}

/// <summary>
/// The browser dialog's parameters. Always build one through
/// <see cref="WebBrowserDialog.InitializeParam"/> so the sizes and the check value are set; the
/// service rejects a block whose fields do not match what it expects.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 328)]
public unsafe struct WebBrowserDialogParam
{
    /// <summary>The common block. Offset 0.</summary>
    public CommonDialogBaseParam BaseParam;

    /// <summary>The size of this structure, in bytes. Offset 48.</summary>
    public ulong Size;

    /// <summary>How the browser is presented. Offset 56.</summary>
    public WebBrowserDialogMode Mode;

    /// <summary>The user the browser opens for. Offset 60.</summary>
    public int UserId;

    /// <summary>A null-terminated address to open. Offset 64.</summary>
    public byte* Url;

    /// <summary>Optional callback parameters. Offset 72.</summary>
    public void* CallbackInitParam;

    /// <summary>Window width, used in the custom mode. Offset 80.</summary>
    public ushort Width;

    /// <summary>Window height, used in the custom mode. Offset 82.</summary>
    public ushort Height;

    /// <summary>Window horizontal position, used in the custom mode. Offset 84.</summary>
    public ushort PositionX;

    /// <summary>Window vertical position, used in the custom mode. Offset 86.</summary>
    public ushort PositionY;

    /// <summary>Which interface parts to show, used in the custom mode. Offset 88.</summary>
    public uint Parts;

    /// <summary>Header width, used in the custom mode. Offset 92.</summary>
    public ushort HeaderWidth;

    /// <summary>Header horizontal position, used in the custom mode. Offset 94.</summary>
    public ushort HeaderPositionX;

    /// <summary>Header vertical position, used in the custom mode. Offset 96.</summary>
    public ushort HeaderPositionY;

    private ushort _padding;

    /// <summary>Which buttons the user may use, in the custom mode. Offset 100.</summary>
    public uint Control;

    /// <summary>Optional text-entry parameters. Offset 104.</summary>
    public void* ImeParam;

    /// <summary>Optional view parameters. Offset 112.</summary>
    public void* WebViewParam;

    /// <summary>Which presentation animation to use. Offset 120.</summary>
    public uint Animation;

    private fixed byte _reserved[202];

    private ushort _tailPadding;
}

/// <summary>The outcome of a finished browser dialog.</summary>
[StructLayout(LayoutKind.Sequential, Size = 256)]
public unsafe struct WebBrowserDialogResult
{
    /// <summary>The dialog's result code.</summary>
    public int Result;

    private int _padding;

    /// <summary>Optional callback result. </summary>
    public void* CallbackResultParam;

    private fixed byte _reserved[240];
}

/// <summary>
/// The allow-list a caller passes with
/// <see cref="WebBrowserDialog.sceWebBrowserDialogOpenForPredeterminedContent"/>. Each entry in
/// <see cref="Domain"/> is a null-terminated address the browser is allowed to reach; unused entries
/// stay null. Fill the block through
/// <see cref="WebBrowserDialog.InitializePredeterminedContentParam"/> so the size is set.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 424)]
public unsafe struct WebBrowserDialogPredeterminedContentParam
{
    /// <summary>The size of this block, in bytes.</summary>
    public ulong Size;

    /// <summary>The 20 allow-list entries, each a null-terminated address or null.</summary>
    public fixed ulong Domain[20];

    private fixed byte _reserved[256];
}

/// <summary>
/// The block the cookie-reset call takes. Fill it through
/// <see cref="WebBrowserDialog.InitializeResetCookieParam"/> so the size is set.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 264)]
public unsafe struct WebBrowserDialogResetCookieParam
{
    /// <summary>The size of this block, in bytes.</summary>
    public ulong Size;

    private fixed byte _reserved[256];
}

/// <summary>
/// The block the cookie-set call takes. Fill it through
/// <see cref="WebBrowserDialog.InitializeSetCookieParam"/> so the size is set, then point
/// <see cref="Url"/> at the address the cookie belongs to and <see cref="Cookie"/> at the cookie
/// string.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 280)]
public unsafe struct WebBrowserDialogSetCookieParam
{
    /// <summary>The size of this block, in bytes.</summary>
    public ulong Size;

    /// <summary>A null-terminated address the cookie is being set for.</summary>
    public byte* Url;

    /// <summary>A null-terminated cookie string.</summary>
    public byte* Cookie;

    private fixed byte _reserved[256];
}

/// <summary>
/// Browser-dialog bindings. Initialize the subsystem, open a dialog for an address, poll the status
/// each frame until it finishes, read the result, then close and terminate.
/// </summary>
public static unsafe partial class WebBrowserDialog
{
    private const string Lib = "libSceWebBrowserDialog";

    /// <summary>The value the check field is derived from.</summary>
    public const uint MagicNumber = 0xC0D1A109;

    /// <summary>
    /// Zeroes <paramref name="param"/> and fills in the sizes and the check value, which the service
    /// requires. The check value depends on the block's address, so fill it in only once the block is
    /// at the address the call will use, and do not copy the block afterwards.
    /// </summary>
    public static void InitializeParam(WebBrowserDialogParam* param)
    {
        new System.Span<byte>(param, sizeof(WebBrowserDialogParam)).Clear();
        param->BaseParam.Size = (ulong)sizeof(CommonDialogBaseParam);
        param->BaseParam.Magic = unchecked((uint)(MagicNumber + (ulong)&param->BaseParam));
        param->Size = (ulong)sizeof(WebBrowserDialogParam);
    }

    /// <summary>Zeroes <paramref name="param"/> and fills in its size field.</summary>
    public static void InitializePredeterminedContentParam(WebBrowserDialogPredeterminedContentParam* param)
    {
        new System.Span<byte>(param, sizeof(WebBrowserDialogPredeterminedContentParam)).Clear();
        param->Size = (ulong)sizeof(WebBrowserDialogPredeterminedContentParam);
    }

    /// <summary>Zeroes <paramref name="param"/> and fills in its size field.</summary>
    public static void InitializeResetCookieParam(WebBrowserDialogResetCookieParam* param)
    {
        new System.Span<byte>(param, sizeof(WebBrowserDialogResetCookieParam)).Clear();
        param->Size = (ulong)sizeof(WebBrowserDialogResetCookieParam);
    }

    /// <summary>Zeroes <paramref name="param"/> and fills in its size field.</summary>
    public static void InitializeSetCookieParam(WebBrowserDialogSetCookieParam* param)
    {
        new System.Span<byte>(param, sizeof(WebBrowserDialogSetCookieParam)).Clear();
        param->Size = (ulong)sizeof(WebBrowserDialogSetCookieParam);
    }

    /// <summary>Starts the browser-dialog subsystem.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogInitialize();

    /// <summary>Opens a dialog described by <paramref name="param"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogOpen(WebBrowserDialogParam* param);

    /// <summary>
    /// Opens a dialog described by <paramref name="param"/> without a parental-control check. The
    /// browser only reaches an address listed in <paramref name="param2"/>.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogOpenForPredeterminedContent(
        WebBrowserDialogParam* param,
        WebBrowserDialogPredeterminedContentParam* param2);

    /// <summary>Advances and returns the dialog's status. Call once per frame while it is open.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus sceWebBrowserDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus sceWebBrowserDialogGetStatus();

    /// <summary>Reads the result of a finished dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogGetResult(WebBrowserDialogResult* result);

    /// <summary>Closes an open dialog.</summary>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogClose();

    /// <summary>Shuts the browser-dialog subsystem down.</summary>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogTerminate();

    /// <summary>Clears the browser dialog's session cookies.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogResetCookie(WebBrowserDialogResetCookieParam* param);

    /// <summary>Adds one cookie to the browser dialog's session store.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceWebBrowserDialogSetCookie(WebBrowserDialogSetCookieParam* param);
}
