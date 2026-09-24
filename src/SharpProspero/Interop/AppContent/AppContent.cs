// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.AppContent;

/// <summary>The parameters the app-content service is initialized with. Reserved; pass zeroed.</summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceAppContentInitParam
{
    private fixed byte _reserved[32];
}

/// <summary>The boot parameters the service fills in at initialization.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceAppContentBootParam
{
    private fixed byte _reserved1[4];

    /// <summary>The boot attribute the service reports.</summary>
    public uint Attr;

    private fixed byte _reserved2[32];
}

/// <summary>What a temporary-data mount does to the area it opens.</summary>
[System.Flags]
public enum AppContentTemporaryDataOption : uint
{
    /// <summary>Keep whatever the area already holds.</summary>
    None = 0,

    /// <summary>Empty the area as part of the mount.</summary>
    Format = 1 << 0,
}

/// <summary>A mount point path (up to 16 characters, null-terminated UTF-8).</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceAppContentMountPoint
{
    public fixed byte Data[16];
}

/// <summary>How far a queued additional-content download has got.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SceAppContentAddcontDownloadProgress
{
    /// <summary>The total size of the content, in bytes.</summary>
    public ulong DataSize;

    /// <summary>The bytes fetched so far.</summary>
    public ulong DownloadedSize;
}

/// <summary>The status and label of one piece of additional content.</summary>
[StructLayout(LayoutKind.Sequential, Size = 24)]
public struct SceAppContentAddcontInfo
{
    /// <summary>The label that names this content.</summary>
    public SceNpUnifiedEntitlementLabel EntitlementLabel;

    /// <summary>The current status of this content.</summary>
    public uint Status;
}

/// <summary>The label that names one piece of purchasable content.</summary>
[StructLayout(LayoutKind.Sequential, Size = 20)]
public unsafe struct SceNpUnifiedEntitlementLabel
{
    public fixed byte Data[17];
    private fixed byte _padding[3];
}

/// <summary>Additional-content and application-parameter bindings.</summary>
public static unsafe partial class AppContent
{
    private const string Lib = "libSceAppContent";

    /// <summary>The first user-defined application parameter.</summary>
    public const int AppParamUserDefined1 = 1;

    /// <summary>The longest a mount point path is, including the terminator.</summary>
    public const int MountPointDataMaxSize = 16;

    /// <summary>Starts the app-content service, filling in <paramref name="bootParam"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentInitialize(SceAppContentInitParam* initParam, SceAppContentBootParam* bootParam);

    /// <summary>Reads an integer application parameter into <paramref name="value"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentAppParamGetInt(int paramId, int* value);

    /// <summary>Reads a string application parameter into <paramref name="buf"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentAppParamGetString(int paramId, byte* buf, nuint bufSize);

    /// <summary>
    /// Opens the per-title writable scratch area and writes its mount point into
    /// <paramref name="mountPoint"/>. The area needs nothing declared in the package, so it is the one
    /// writable location an application always has.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentTemporaryDataMount2(
        AppContentTemporaryDataOption option, SceAppContentMountPoint* mountPoint);

    /// <summary>Closes the scratch area.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentTemporaryDataUnmount(SceAppContentMountPoint* mountPoint);

    /// <summary>Empties the mounted scratch area.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentTemporaryDataFormat(SceAppContentMountPoint* mountPoint);

    /// <summary>Reads the space left in the mounted scratch area, in kibibytes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentTemporaryDataGetAvailableSpaceKb(
        SceAppContentMountPoint* mountPoint, nuint* availableSpaceKb);

    /// <summary>Empties the mounted download-data area.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentDownloadDataFormat(SceAppContentMountPoint* mountPoint);

    /// <summary>Reads the space left in the mounted download-data area, in kibibytes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentDownloadDataGetAvailableSpaceKb(
        SceAppContentMountPoint* mountPoint, nuint* availableSpaceKb);

    /// <summary>Mounts the additional content named by <paramref name="entitlementLabel"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentAddcontMount(
        uint serviceLabel, SceNpUnifiedEntitlementLabel* entitlementLabel, SceAppContentMountPoint* mountPoint);

    /// <summary>Unmounts additional content.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentAddcontUnmount(SceAppContentMountPoint* mountPoint);

    /// <summary>Asks the system to fetch the additional content named by <paramref name="entitlementLabel"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentAddcontEnqueueDownload(
        uint serviceLabel, SceNpUnifiedEntitlementLabel* entitlementLabel);

    /// <summary>Reads how far that fetch has got.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentGetAddcontDownloadProgress(
        uint serviceLabel,
        SceNpUnifiedEntitlementLabel* entitlementLabel,
        SceAppContentAddcontDownloadProgress* progress);

    /// <summary>Lists the additional content available to the calling title.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentGetAddcontInfoList(
        uint serviceLabel, SceAppContentAddcontInfo* list, int listNum, int* hitNum);

    /// <summary>Reads the status of one piece of additional content by its entitlement label.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAppContentGetAddcontInfo(
        uint serviceLabel, SceNpUnifiedEntitlementLabel* entitlementLabel, SceAppContentAddcontInfo* info);
}
