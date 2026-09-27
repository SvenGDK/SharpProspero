// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Dialog;
using SharpProspero.Interop.SaveData;
using SharpProspero.Interop.Sysmodule;
using SharpProspero.Modules;
using System;
using System.Runtime.InteropServices;
using System.Text;
using Native = SharpProspero.Interop.Dialog.SaveDataDialog;

namespace SharpProspero.Platform;

/// <summary>
/// Shows the on-screen dialog that lists a user's saves so they can pick one, and reports which they
/// chose. Open the picker, poll it each frame until it finishes, then read the chosen directory.
/// </summary>
/// <example>
/// <code>
/// using var picker = SaveDataPicker.OpenList(userId);
/// while (!picker.TryGetResult(out string? directory))
///     context.Present();
/// if (directory is not null)
///     Console.WriteLine($"Picked {directory}");
/// </code>
/// </example>
public sealed unsafe class SaveDataPicker : IDisposable
{
    private SceSaveDataDialogItems* _items;

    // The loadable module the dialog lives in, owned from the moment it is loaded so that every way out
    // of the open sequence gives it back rather than leaving it mapped for the life of the process.
    private readonly SystemModule _module;
    private bool _disposed;
    private bool _initialized;

    private SaveDataPicker(SystemModule module, SceSaveDataDialogItems* items)
    {
        _module = module;
        _items = items;
    }

    /// <summary>
    /// Opens a dialog listing the saves of <paramref name="userId"/> for the running application, with
    /// the wording of <paramref name="type"/> (load by default).
    /// </summary>
    /// <exception cref="ProsperoException">The dialog could not be opened.</exception>
    public static SaveDataPicker OpenList(int userId, SaveDataDialogType type = SaveDataDialogType.Load)
    {
        CommonDialog.EnsureInitialized();

        // The item list is read by the service while the dialog is open, so it lives on the heap
        // for the picker's lifetime and is freed on dispose. Load the module BEFORE the allocation
        // so a failed load never orphans the items buffer with no path to Dispose; if the alloc
        // then throws, hand the module back before propagating the exception. The picker owns both
        // the module and the list from the moment each is taken, so every way out of this sequence
        // gives both back.
        SystemModule module = SystemModule.Load(SystemModuleId.SaveDataDialog);
        SceSaveDataDialogItems* items;
        try
        {
            items = (SceSaveDataDialogItems*)NativeMemory.AllocZeroed((nuint)sizeof(SceSaveDataDialogItems));
        }
        catch
        {
            module.Dispose();
            throw;
        }
        var picker = new SaveDataPicker(module, items);
        try
        {
            SceResult.ThrowIfFailed(Native.sceSaveDataDialogInitialize(), nameof(Native.sceSaveDataDialogInitialize));
            picker._initialized = true;

            items->UserId = userId;
            items->ItemStyle = SaveDataDialogItemStyle.TitleDateSizeSubtitle;
            items->FocusPos = SaveDataDialogFocusPos.DataLatest;

            SceSaveDataDialogParam param;
            new Span<byte>(&param, sizeof(SceSaveDataDialogParam)).Clear();
            Native.InitializeParam(&param);
            param.Mode = SaveDataDialogMode.List;
            param.DispType = type;
            param.Items = items;

            SceResult.ThrowIfFailed(Native.sceSaveDataDialogOpen(&param), nameof(Native.sceSaveDataDialogOpen));
            return picker;
        }
        catch
        {
            picker.Dispose();
            throw;
        }
    }

    /// <summary>The dialog's status. Poll it until it is <see cref="CommonDialogStatus.Finished"/>.</summary>
    public CommonDialogStatus Status
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (CommonDialogStatus)Native.sceSaveDataDialogUpdateStatus();
        }
    }

    /// <summary>
    /// Reads the outcome. Returns <see langword="false"/> while the dialog is still running. Once it
    /// has finished, returns <see langword="true"/> and sets <paramref name="directory"/> to the chosen
    /// save's directory, or null when the user backed out without choosing.
    /// </summary>
    /// <exception cref="ProsperoException">The result could not be read.</exception>
    public bool TryGetResult(out string? directory)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        directory = null;
        if ((CommonDialogStatus)Native.sceSaveDataDialogUpdateStatus() != CommonDialogStatus.Finished)
            return false;

        SceSaveDataDialogResult result;
        new Span<byte>(&result, sizeof(SceSaveDataDialogResult)).Clear();
        SceSaveDataDirName dirName;
        new Span<byte>(&dirName, sizeof(SceSaveDataDirName)).Clear();
        result.DirName = &dirName;

        SceResult.ThrowIfFailed(Native.sceSaveDataDialogGetResult(&result), nameof(Native.sceSaveDataDialogGetResult));
        if (result.DirName is not null)
        {
            string picked = ReadUtf8((byte*)result.DirName, 32);
            if (picked.Length > 0)
                directory = picked;
        }
        return true;
    }

    /// <summary>Stops the dialog service and unloads the module.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_initialized)
            Native.sceSaveDataDialogTerminate();
        _module.Dispose();
        if (_items is not null)
        {
            NativeMemory.Free(_items);
            _items = null;
        }
    }

    private static string ReadUtf8(byte* start, int maxLength)
    {
        int length = 0;
        while (length < maxLength && start[length] != 0)
            length++;
        return length == 0 ? string.Empty : Encoding.UTF8.GetString(start, length);
    }
}
