// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.SaveData;

/// <summary>How a save is mounted.</summary>
[System.Flags]
public enum SaveDataMountMode : uint
{
    /// <summary>Read only.</summary>
    ReadOnly = 0x00000001,

    /// <summary>Read and write.</summary>
    ReadWrite = 0x00000002,

    /// <summary>Create the save if it does not exist.</summary>
    Create = 0x00000004,

    /// <summary>Copy the application's icon into a newly created save.</summary>
    CopyIcon = 0x00000010,

    /// <summary>
    /// Mount for read and write. Creates the save first when it does not exist, then mounts it for
    /// read and write.
    /// </summary>
    Create2 = 0x00000020,
}

/// <summary>How a save is unmounted.</summary>
[System.Flags]
public enum SaveDataUmountMode : uint
{
    /// <summary>Fail if there are uncommitted changes.</summary>
    Default = 0,

    /// <summary>Commit changes on unmount.</summary>
    Commit = 0x00000001,

    /// <summary>Copy the save into its backup slot after the unmount, on a separate thread.</summary>
    BackupAsync = 0x00010000,
}

/// <summary>The key a directory search sorts by.</summary>
public enum SaveDataSortKey : uint
{
    DirName = 0,
    UserParam = 1,
    Blocks = 2,
    ModifiedTime = 3,
    FreeBlocks = 5,
}

/// <summary>The order a directory search sorts in.</summary>
public enum SaveDataSortOrder : uint
{
    Ascending = 0,
    Descending = 1,
}

/// <summary>Which fields of <see cref="SceSaveDataParam"/> a set or get call carries.</summary>
public enum SaveDataParamType : uint
{
    /// <summary>Every field at once. The buffer is a whole <see cref="SceSaveDataParam"/>.</summary>
    All = 0,

    /// <summary>The title alone. The buffer is a UTF-8 string.</summary>
    Title = 1,

    /// <summary>The subtitle alone. The buffer is a UTF-8 string.</summary>
    SubTitle = 2,

    /// <summary>The detail text alone. The buffer is a UTF-8 string.</summary>
    Detail = 3,

    /// <summary>The user parameter alone. The buffer is a <see cref="uint"/>.</summary>
    UserParam = 4,

    /// <summary>The modified time alone. The buffer is a <see cref="long"/>.</summary>
    ModifiedTime = 5,
}

/// <summary>How an update opened by <see cref="SaveData.sceSaveDataPrepare"/> behaves.</summary>
public enum SaveDataPrepareMode : uint
{
    /// <summary>Mark the save broken for the duration of the update.</summary>
    Default = 0,

    /// <summary>Leave the save readable for the duration of the update.</summary>
    DestructOff = 1,
}

/// <summary>What <see cref="SaveData.sceSaveDataCommit"/> does after it confirms the update.</summary>
public enum SaveDataCommitMode : uint
{
    /// <summary>Confirm and stop there.</summary>
    Default = 0,

    /// <summary>Confirm, then start a backup that runs on its own.</summary>
    BackupAsync = 1,
}

/// <summary>Which event a call to <see cref="SaveData.sceSaveDataGetEventResult"/> reports on.</summary>
public enum SaveDataEventType : uint
{
    /// <summary>An unset event.</summary>
    Invalid = 0,

    /// <summary>The backup issued by an unmount call has completed.</summary>
    UmountBackupEnd = 1,

    /// <summary>The backup issued by <see cref="SaveData.sceSaveDataBackup"/> has completed.</summary>
    BackupEnd = 2,

    /// <summary>The memory synchronisation issued by <see cref="SaveData.sceSaveDataSyncSaveDataMemory"/> has completed.</summary>
    SaveDataMemorySyncEnd = 3,

    /// <summary>The backup issued by <see cref="SaveData.sceSaveDataCommit"/> has completed.</summary>
    CommitBackupEnd = 4,
}

/// <summary>Options for the save-data memory slot set up by <see cref="SaveData.sceSaveDataSetupSaveDataMemory2"/>.</summary>
[System.Flags]
public enum SaveDataMemoryOption : uint
{
    /// <summary>No options.</summary>
    None = 0,

    /// <summary>Use the parameter block passed alongside the setup.</summary>
    SetParam = 0x00000001,

    /// <summary>Double-buffer the memory image.</summary>
    DoubleBuffer = 0x00000002,
}

/// <summary>Options for the memory synchronisation call.</summary>
[System.Flags]
public enum SaveDataMemorySyncOption : uint
{
    /// <summary>No options.</summary>
    None = 0,

    /// <summary>Block the caller until the synchronisation finishes.</summary>
    Blocking = 0x00000001,
}

/// <summary>A title id (10 characters plus padding).</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceSaveDataTitleId
{
    public fixed byte Data[10];
    private fixed byte _padding[6];
}

/// <summary>A save directory name (up to 32 characters).</summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceSaveDataDirName
{
    public fixed byte Data[32];
}

/// <summary>A mount point path (up to 16 characters).</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceSaveDataMountPoint
{
    public fixed byte Data[16];
}

/// <summary>The parameters that describe a save: its title, subtitle, detail, and modified time.</summary>
[StructLayout(LayoutKind.Sequential, Size = 1328)]
public unsafe struct SceSaveDataParam
{
    public fixed byte Title[128];
    public fixed byte SubTitle[128];
    public fixed byte Detail[1024];
    public uint UserParam;
    private int _pad0;

    /// <summary>The modified time, as a Unix timestamp in seconds.</summary>
    public long Mtime;
    private fixed byte _reserved[32];
}

/// <summary>
/// A save icon. The caller owns the buffer and points <see cref="Buf"/> at it; the service reads
/// <see cref="DataSize"/> bytes out of it when saving and writes the byte count back into
/// <see cref="DataSize"/> when loading.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 56)]
public unsafe struct SceSaveDataIcon
{
    /// <summary>The icon image, encoded as a PNG.</summary>
    public void* Buf;

    /// <summary>The capacity of <see cref="Buf"/>, in bytes.</summary>
    public nuint BufSize;

    /// <summary>The bytes in use: set before saving, filled in by a load.</summary>
    public nuint DataSize;

    private fixed byte _reserved[32];
}

/// <summary>An identifier that ties a save to the account that owns it.</summary>
[StructLayout(LayoutKind.Sequential, Size = 80)]
public unsafe struct SceSaveDataFingerprint
{
    public fixed byte Data[65];
    private fixed byte _padding[15];
}

/// <summary>The parameters an update is opened with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceSaveDataPrepareParam
{
    /// <summary>A transaction resource id, or zero to run without one.</summary>
    public int Resource;

    public SaveDataPrepareMode PrepareMode;
    private fixed byte _reserved[32];
}

/// <summary>The parameters an update is confirmed with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceSaveDataCommitParam
{
    /// <summary>The transaction resource id the matching prepare was given.</summary>
    public int Resource;

    public SaveDataCommitMode CommitMode;
    private fixed byte _reserved[32];
}

/// <summary>The parameters of a backup.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataBackup
{
    public int UserId;
    private int _pad0;
    public SceSaveDataTitleId* TitleId;
    public SceSaveDataDirName* DirName;
    public SceSaveDataFingerprint* Fingerprint;
    private fixed byte _reserved[32];
}

/// <summary>The parameters a mount is opened with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 80)]
public unsafe struct SceSaveDataMount3
{
    public int UserId;
    private int _pad0;
    public SceSaveDataDirName* DirName;
    public ulong Blocks;
    public ulong SystemBlocks;
    public SaveDataMountMode MountMode;
    private int _pad1;
    public int Resource;
    private fixed byte _reserved[32];
}

/// <summary>The parameters a transferring mount is opened with.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataTransferringMount
{
    public int UserId;
    private int _pad0;
    public SceSaveDataTitleId* TitleId;
    public SceSaveDataDirName* DirName;
    public SceSaveDataFingerprint* Fingerprint;
    private fixed byte _reserved[32];
}

/// <summary>The result of a mount: the mount point path and status.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataMountResult
{
    public SceSaveDataMountPoint MountPoint;
    public ulong RequiredBlocks;
    public uint Unused;
    public uint MountStatus;
    private fixed byte _reserved[28];
    private int _pad0;
}

/// <summary>The size and free space of a mounted save.</summary>
[StructLayout(LayoutKind.Sequential, Size = 48)]
public unsafe struct SceSaveDataMountInfo
{
    public ulong Blocks;
    public ulong FreeBlocks;
    private fixed byte _reserved[32];
}

/// <summary>The parameters of a delete.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataDelete
{
    public int UserId;
    private int _pad0;
    public SceSaveDataTitleId* TitleId;
    public SceSaveDataDirName* DirName;
    public uint Unused;
    private fixed byte _reserved[32];
    private int _pad1;
}

/// <summary>The condition a directory search runs under.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataDirNameSearchCond
{
    public int UserId;
    private int _pad0;
    public SceSaveDataTitleId* TitleId;
    public SceSaveDataDirName* DirName;
    public SaveDataSortKey Key;
    public SaveDataSortOrder Order;
    private fixed byte _reserved[32];
}

/// <summary>The result of a directory search: the matching directories and their parameters.</summary>
[StructLayout(LayoutKind.Sequential, Size = 56)]
public unsafe struct SceSaveDataDirNameSearchResult
{
    public uint HitNum;
    private int _pad0;
    public SceSaveDataDirName* DirNames;
    public uint DirNamesNum;
    public uint SetNum;
    public SceSaveDataParam* Params;
    public void* Infos;
    private fixed byte _reserved[12];
    private int _pad1;
}

/// <summary>The parameters of a save-data memory sync.</summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceSaveDataMemorySync
{
    public int UserId;
    public uint SlotId;
    public SaveDataMemorySyncOption Option;
    private fixed byte _reserved[28];
}

/// <summary>
/// One area of the save-data memory image to set or get. <see cref="Buf"/> points at the caller's
/// buffer, <see cref="BufSize"/> is its byte count, and <see cref="Offset"/> is the position in the
/// memory image the transfer starts at.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataMemoryData
{
    public void* Buf;
    public nuint BufSize;
    public long Offset;
    private fixed byte _reserved[40];
}

/// <summary>The parameters of a save-data memory setup.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataMemorySetup2
{
    public SaveDataMemoryOption Option;
    public int UserId;
    public nuint MemorySize;
    public nuint IconMemorySize;
    public SceSaveDataParam* InitParam;
    public SceSaveDataIcon* InitIcon;
    public uint SlotId;
    private fixed byte _reserved[20];
}

/// <summary>The result of a save-data memory setup: the size the existing memory slot already has.</summary>
[StructLayout(LayoutKind.Sequential, Size = 24)]
public unsafe struct SceSaveDataMemorySetupResult
{
    public nuint ExistedMemorySize;
    private fixed byte _reserved[16];
}

/// <summary>The parameters of a save-data memory get.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataMemoryGet2
{
    public int UserId;
    private fixed byte _padding[4];
    public SceSaveDataMemoryData* Data;
    public SceSaveDataParam* Param;
    public SceSaveDataIcon* Icon;
    public uint SlotId;
    private fixed byte _reserved[28];
}

/// <summary>The parameters of a save-data memory set.</summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceSaveDataMemorySet2
{
    public int UserId;
    private fixed byte _padding[4];
    public SceSaveDataMemoryData* Data;
    public SceSaveDataParam* Param;
    public SceSaveDataIcon* Icon;
    public uint DataNum;
    public uint SlotId;
    private fixed byte _reserved[24];
}

/// <summary>The event a call to <see cref="SaveData.sceSaveDataGetEventResult"/> writes back.</summary>
[StructLayout(LayoutKind.Sequential, Size = 104)]
public unsafe struct SceSaveDataEvent
{
    /// <summary>The event's kind, from <see cref="SaveDataEventType"/>.</summary>
    public SaveDataEventType Type;

    /// <summary>The error code the event carries.</summary>
    public int ErrorCode;

    /// <summary>The user id the event applies to.</summary>
    public int UserId;
    private fixed byte _padding[4];

    /// <summary>The title id the event applies to.</summary>
    public SceSaveDataTitleId TitleId;

    /// <summary>The directory the event applies to.</summary>
    public SceSaveDataDirName DirName;

    private fixed byte _reserved[40];
}

/// <summary>Save data bindings.</summary>
public static unsafe partial class SaveData
{
    private const string Lib = "libSceSaveData";

    /// <summary>Starts the save-data service. Pass null for the default parameters.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataInitialize3(void* initParam);

    /// <summary>Stops the save-data service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataTerminate();

    /// <summary>Mounts a save, returning its mount point in <paramref name="result"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataMount3(SceSaveDataMount3* mount, SceSaveDataMountResult* result);

    /// <summary>Mounts a save from its backup for transfer to another user or console.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataTransferringMount(SceSaveDataTransferringMount* mount, SceSaveDataMountResult* result);

    /// <summary>Unmounts a save.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataUmount2(uint mode, SceSaveDataMountPoint* mountPoint);

    /// <summary>Reads the size and free space of a mounted save.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataGetMountInfo(SceSaveDataMountPoint* mountPoint, SceSaveDataMountInfo* info);

    /// <summary>Deletes a save.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDelete(SceSaveDataDelete* del);

    /// <summary>Searches for save directories matching <paramref name="cond"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDirNameSearch(SceSaveDataDirNameSearchCond* cond, SceSaveDataDirNameSearchResult* result);

    /// <summary>The width of a small save icon, in pixels.</summary>
    public const int IconWidthSmall = 688;

    /// <summary>The height of a small save icon, in pixels.</summary>
    public const int IconHeightSmall = 388;

    /// <summary>The width of a full-size save icon, in pixels.</summary>
    public const int IconWidthFull = 776;

    /// <summary>The height of a full-size save icon, in pixels.</summary>
    public const int IconHeightFull = 436;

    /// <summary>The largest an icon file may be, in bytes.</summary>
    public const int IconFileMaxSize = IconWidthFull * IconHeightFull * 4;

    /// <summary>The longest an icon path may be, including the terminator.</summary>
    public const int IconPathMaxSize = 128;

    /// <summary>The largest save-data memory image the service supports, in bytes.</summary>
    public const int MemoryMaxSize = 32 * 1024 * 1024;

    /// <summary>The largest number of memory slots one call to <see cref="sceSaveDataSetupSaveDataMemory2"/> can prepare.</summary>
    public const int MemorySetupMaxCount = 4;

    /// <summary>The largest number of memory data pointers one call to <see cref="sceSaveDataSetSaveDataMemory2"/> can carry.</summary>
    public const int MemoryDataNumMaxCount = 5;

    /// <summary>The block size, in bytes, that <see cref="SceSaveDataMount3.Blocks"/> is expressed in.</summary>
    public const int BlockSize2 = 65536;

    /// <summary>The smallest block count a save may be created with, including system-reserved blocks.</summary>
    public const int BlocksMin3 = 48;

    /// <summary>The largest block count a save may be created with, including system-reserved blocks.</summary>
    public const int BlocksMax2 = 16384;

    /// <summary>The smallest transaction resource size, in bytes.</summary>
    public const int TransactionResourceMinSize = 786432;

    /// <summary>The largest number of transaction resource ids that may be live at once.</summary>
    public const int TransactionResourceMaxCount = 16;

    /// <summary>Value the service writes into an unclaimed transaction-resource id.</summary>
    public const int TransactionResourceIdInvalid = -1;

    /// <summary>
    /// Writes the fields named by <paramref name="paramType"/> into the mounted save's parameter
    /// record, which is what the system browser lists the save by. For
    /// <see cref="SaveDataParamType.All"/> the buffer is a <see cref="SceSaveDataParam"/>; for a single
    /// field it is that field alone.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataSetParam(
        SceSaveDataMountPoint* mountPoint, SaveDataParamType paramType, void* paramBuf, nuint paramBufSize);

    /// <summary>
    /// Reads the fields named by <paramref name="paramType"/> back out, writing the byte count into
    /// <paramref name="gotSize"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataGetParam(
        SceSaveDataMountPoint* mountPoint, SaveDataParamType paramType, void* paramBuf, nuint paramBufSize, nuint* gotSize);

    /// <summary>Writes <paramref name="icon"/> into the mounted save as its icon.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataSaveIcon(SceSaveDataMountPoint* mountPoint, SceSaveDataIcon* icon);

    /// <summary>
    /// Writes the icon at <paramref name="path"/> into the mounted save, so the caller does not have to
    /// read the file itself. <paramref name="path"/> is a null-terminated UTF-8 string.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataSaveIconByPath(SceSaveDataMountPoint* mountPoint, byte* path);

    /// <summary>Reads the mounted save's icon into the buffer <paramref name="icon"/> points at.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataLoadIcon(SceSaveDataMountPoint* mountPoint, SceSaveDataIcon* icon);

    /// <summary>
    /// Reserves <paramref name="size"/> bytes of working space for a prepare and commit pair, returning
    /// a resource id, or a negative error code.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataCreateTransactionResource(uint size);

    /// <summary>Releases a resource id taken from <see cref="sceSaveDataCreateTransactionResource"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataDeleteTransactionResource(int resource);

    /// <summary>Opens an update on the mounted save.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataPrepare(SceSaveDataMountPoint* mountPoint, SceSaveDataPrepareParam* param);

    /// <summary>
    /// Confirms the update opened by <see cref="sceSaveDataPrepare"/>. This is the route to persisting a
    /// save without unmounting it; the unmount route sets <see cref="SaveDataUmountMode.Commit"/> instead.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataCommit(SceSaveDataCommitParam* param);

    /// <summary>Copies a save into its backup slot.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataBackup(SceSaveDataBackup* backup);

    /// <summary>Writes the running save-data memory image out to storage.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataSyncSaveDataMemory(SceSaveDataMemorySync* syncParam);

    /// <summary>
    /// Prepares the save-data memory slot the running application uses. Writes the existing memory-slot
    /// size into <paramref name="result"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataSetupSaveDataMemory2(
        SceSaveDataMemorySetup2* setupParam, SceSaveDataMemorySetupResult* result);

    /// <summary>Reads areas of the save-data memory image into caller-supplied buffers.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataGetSaveDataMemory2(SceSaveDataMemoryGet2* getParam);

    /// <summary>Writes caller-supplied buffers into areas of the save-data memory image.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataSetSaveDataMemory2(SceSaveDataMemorySet2* setParam);

    /// <summary>
    /// Reads the next completion event for the running application into <paramref name="event"/>. Pass
    /// null for <paramref name="eventParam"/> to receive the next event of any kind.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSaveDataGetEventResult(void* eventParam, SceSaveDataEvent* @event);
}
