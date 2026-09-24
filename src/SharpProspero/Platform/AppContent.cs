// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Sysmodule;
using SharpProspero.Modules;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Native = SharpProspero.Interop.AppContent.AppContent;
using NativeAddcontInfo = SharpProspero.Interop.AppContent.SceAppContentAddcontInfo;
using NativeBoot = SharpProspero.Interop.AppContent.SceAppContentBootParam;
using NativeEntitlementLabel = SharpProspero.Interop.AppContent.SceNpUnifiedEntitlementLabel;
using NativeParam = SharpProspero.Interop.AppContent.SceAppContentInitParam;

namespace SharpProspero.Platform;

/// <summary>One piece of additional content the running title has available.</summary>
/// <param name="EntitlementLabel">The label that identifies this content.</param>
/// <param name="Status">The current status of this content.</param>
public readonly record struct AddcontInfo(string EntitlementLabel, uint Status);

/// <summary>
/// The application-content service: read the parameters the title was packaged with, and list the
/// additional content available to it. Bring it up once at startup, then read a parameter by its id
/// or enumerate additional content.
/// </summary>
public static unsafe class AppContent
{
    private static bool _initialized;

    /// <summary>
    /// Starts the service. Safe to call more than once; the first call does the work.
    /// </summary>
    /// <exception cref="ProsperoException">The service could not be started.</exception>
    public static void Initialize()
    {
        if (_initialized)
            return;

        // The module is given back when the service refuses to start. Without that, a caller that tries
        // again after a refusal loads it once more each time, and nothing ever unloads any of them.
        SystemModule module = SystemModule.Load(SystemModuleId.AppContent);
        try
        {
            NativeParam init = default;
            NativeBoot boot = default;
            SceResult.ThrowIfFailed(Native.sceAppContentInitialize(&init, &boot), nameof(Native.sceAppContentInitialize));
            _initialized = true;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Reads an integer application parameter. Parameter ids 1 to 4 are the user-defined parameters a
    /// title carries in its metadata.
    /// </summary>
    /// <exception cref="ProsperoException">The parameter could not be read.</exception>
    public static int GetIntParam(int paramId)
    {
        Initialize();
        int value = 0;
        SceResult.ThrowIfFailed(Native.sceAppContentAppParamGetInt(paramId, &value), nameof(Native.sceAppContentAppParamGetInt));
        return value;
    }

    /// <summary>
    /// Reads a string application parameter. The same parameter ids as <see cref="GetIntParam"/>
    /// apply: 1 to 4 are the user-defined parameters a title carries in its metadata.
    /// </summary>
    /// <exception cref="ProsperoException">The parameter could not be read.</exception>
    public static string GetStringParam(int paramId)
    {
        Initialize();
        const int capacity = 256;
        byte* buffer = stackalloc byte[capacity];
        SceResult.ThrowIfFailed(
            Native.sceAppContentAppParamGetString(paramId, buffer, (nuint)capacity),
            nameof(Native.sceAppContentAppParamGetString));

        int length = 0;
        while (length < capacity && buffer[length] != 0)
            length++;
        return length == 0 ? string.Empty : Encoding.UTF8.GetString(buffer, length);
    }

    /// <summary>
    /// Lists the additional content available to the running title. Only content belonging to the
    /// calling application is returned.
    /// </summary>
    /// <exception cref="ProsperoException">The list could not be read.</exception>
    public static IReadOnlyList<AddcontInfo> GetAddcontInfoList(uint serviceLabel = 0)
    {
        Initialize();

        int count = 0;
        SceResult.ThrowIfFailed(
            Native.sceAppContentGetAddcontInfoList(serviceLabel, null, 0, &count),
            nameof(Native.sceAppContentGetAddcontInfoList));

        if (count == 0)
            return [];

        var entries = (NativeAddcontInfo*)NativeMemory.AllocZeroed(
            (nuint)count, (nuint)sizeof(NativeAddcontInfo));
        try
        {
            int filled = 0;
            SceResult.ThrowIfFailed(
                Native.sceAppContentGetAddcontInfoList(serviceLabel, entries, count, &filled),
                nameof(Native.sceAppContentGetAddcontInfoList));

            var result = new List<AddcontInfo>(filled);
            for (int i = 0; i < filled; i++)
                result.Add(new AddcontInfo(ReadLabel(entries[i].EntitlementLabel.Data), entries[i].Status));
            return result;
        }
        finally
        {
            NativeMemory.Free(entries);
        }
    }

    /// <summary>
    /// Reads the status of one piece of additional content by its entitlement label.
    /// </summary>
    /// <exception cref="ProsperoException">The content could not be read.</exception>
    public static AddcontInfo GetAddcontInfo(uint serviceLabel, string entitlementLabel)
    {
        Initialize();
        ArgumentException.ThrowIfNullOrEmpty(entitlementLabel);

        NativeEntitlementLabel label = default;
        Encoding.UTF8.GetBytes(entitlementLabel, new Span<byte>(label.Data, 16));

        NativeAddcontInfo info = default;
        SceResult.ThrowIfFailed(
            Native.sceAppContentGetAddcontInfo(serviceLabel, &label, &info),
            nameof(Native.sceAppContentGetAddcontInfo));

        return new AddcontInfo(ReadLabel(info.EntitlementLabel.Data), info.Status);
    }

    private static string ReadLabel(byte* data)
    {
        int length = 0;
        while (length < 17 && data[length] != 0)
            length++;
        return length == 0 ? string.Empty : Encoding.UTF8.GetString(data, length);
    }
}
