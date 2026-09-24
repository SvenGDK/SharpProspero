// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.Dialog;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Net;

/// <summary>How the access-point dialog runs.</summary>
public enum NetCtlApDialogMode
{
    /// <summary>Bring up an access-point connection.</summary>
    Connect = 0,
}

/// <summary>
/// The parameter block <see cref="NetCtlApDialog.sceNetCtlApDialogOpen"/> reads. Fill it through
/// <see cref="NetCtlApDialog.InitializeParam"/> so the sizes and the check value the service
/// requires are set, then set the fields that matter for the call.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 104)]
public unsafe struct SceNetCtlApDialogParam
{
    /// <summary>The shared dialog block. Offset 0.</summary>
    public CommonDialogBaseParam BaseParam;

    /// <summary>The size of this block, in bytes. Offset 48.</summary>
    public ulong Size;

    /// <summary>Padding the service requires cleared to zero. Offset 56.</summary>
    private fixed byte _padding[4];

    /// <summary>Which access-point flow to run. Offset 60.</summary>
    public NetCtlApDialogMode Mode;

    /// <summary>
    /// The option string, up to <see cref="NetCtlApDialog.OptStrLen"/> bytes plus a terminator.
    /// Offset 64.
    /// </summary>
    public fixed byte OptStr[9];

    /// <summary>Reserved. Cleared to zero. Offset 73.</summary>
    private fixed byte _reserved[31];
}

/// <summary>The result of an access-point dialog that has closed.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceNetCtlApDialogResult
{
    /// <summary>The result code. Offset 0.</summary>
    public int Result;

    /// <summary>Reserved. Offset 4.</summary>
    private fixed byte _reserved[36];
}

/// <summary>
/// The access-point dialog: the on-screen flow that walks the user through bringing up a
/// wireless connection. The dialog rides on the common dialog subsystem, so
/// <see cref="Dialog.CommonDialog.sceCommonDialogInitialize"/> comes first; every call after
/// <see cref="sceNetCtlApDialogInitialize"/> returns zero on success or a negative error code.
/// </summary>
public static unsafe partial class NetCtlApDialog
{
    private const string Lib = "libSceNetCtlApDialog";

    private const ulong MagicNumber = 0xC0D1A109;

    /// <summary>The dialog reported an internal error such as a network fault.</summary>
    public const int ErrorInternal = unchecked((int)0x81460001);

    /// <summary>The longest option string the parameter block accepts, excluding the terminator.</summary>
    public const int OptStrLen = 8;

    /// <summary>Zeroes <paramref name="param"/> and fills the sizes and the check value.</summary>
    public static void InitializeParam(SceNetCtlApDialogParam* param)
    {
        new System.Span<byte>(param, sizeof(SceNetCtlApDialogParam)).Clear();
        param->BaseParam.Size = (ulong)sizeof(CommonDialogBaseParam);
        param->BaseParam.Magic = unchecked((uint)(MagicNumber + (ulong)&param->BaseParam));
        param->Mode = NetCtlApDialogMode.Connect;
        param->Size = (ulong)sizeof(SceNetCtlApDialogParam);
    }

    /// <summary>Brings the dialog subsystem's access-point flow up.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApDialogInitialize();

    /// <summary>Shuts the dialog down.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApDialogTerminate();

    /// <summary>Opens the dialog described by <paramref name="param"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApDialogOpen(SceNetCtlApDialogParam* param);

    /// <summary>Closes an open dialog before it finishes on its own.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApDialogClose();

    /// <summary>Advances the dialog and returns its status.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus sceNetCtlApDialogUpdateStatus();

    /// <summary>Returns the dialog's status without advancing it.</summary>
    [LibraryImport(Lib)]
    public static partial CommonDialogStatus sceNetCtlApDialogGetStatus();

    /// <summary>Reads the result of a finished dialog into <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApDialogGetResult(SceNetCtlApDialogResult* result);
}
