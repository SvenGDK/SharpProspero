// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpProspero.Platform;

/// <summary>
/// Compilation disc information returned by the install service. Contains up to
/// <see cref="SceAppInstUtilCompilationDiscInfo.SlotCount"/> title-id entries, each occupying
/// <see cref="SceAppInstUtilCompilationDiscInfo.SlotSize"/> bytes as a null-terminated string.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = SceAppInstUtilCompilationDiscInfo.Size)]
public unsafe struct SceAppInstUtilCompilationDiscInfo
{
    /// <summary>Number of bytes per title-id slot.</summary>
    public const int SlotSize = 13;

    /// <summary>Maximum number of title-id slots in the structure.</summary>
    public const int SlotCount = 33;

    /// <summary>Total size of the structure in bytes.</summary>
    public const int Size = SlotCount * SlotSize;

    private fixed byte _data[Size];

    /// <summary>
    /// Returns the title id at <paramref name="index"/> as a string, or an empty string when the
    /// slot is unused.
    /// </summary>
    /// <param name="index">Zero-based slot index, from 0 to <see cref="SlotCount"/> minus one.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="index"/> is negative or not less than <see cref="SlotCount"/>.
    /// </exception>
    public readonly string GetTitleId(int index)
    {
        if ((uint)index >= SlotCount)
            throw new ArgumentOutOfRangeException(nameof(index));
        fixed (byte* p = _data)
        {
            byte* slot = p + index * SlotSize;
            int len = 0;
            while (len < SlotSize && slot[len] != 0)
                len++;
            return len == 0 ? string.Empty : Encoding.UTF8.GetString(slot, len);
        }
    }

    /// <summary>
    /// Returns the number of populated title-id slots. Slots are filled consecutively from
    /// index zero; the first slot whose leading byte is zero marks the end.
    /// </summary>
    public readonly int Count
    {
        get
        {
            fixed (byte* p = _data)
            {
                for (int i = 0; i < SlotCount; i++)
                {
                    if (p[i * SlotSize] == 0)
                        return i;
                }
                return SlotCount;
            }
        }
    }
}

/// <summary>
/// Installs a package from a file on the console. The install service is not part of the module set a
/// title links against, so it is loaded at run time and its entry points are resolved by name. Open
/// it once, install one or more packages, and dispose it to shut the service down.
/// </summary>
/// <example>
/// <code>
/// using var installer = PackageInstaller.Open();
/// installer.Install("/data/homebrew.pkg");
/// </code>
/// </example>
public sealed unsafe class PackageInstaller : IDisposable
{
    /// <summary>The module that carries the install service.</summary>
    public const string ModulePath = "/system/common/lib/libSceAppInstUtil.sprx";

    /// <summary>
    /// Minimum size, in bytes, of the buffer required by
    /// <see cref="AppGetInstallStatus(string, void*)"/>. The service writes a 12-byte status
    /// record describing the title's install state.
    /// </summary>
    public const int AppInstallStatusSize = 0x0C;

    /// <summary>
    /// Minimum size, in bytes, of the buffer required by
    /// <see cref="GetInstallStatus(string, void*)"/>. The service writes a 712-byte status
    /// record describing the content's full install state.
    /// </summary>
    public const int InstallStatusSize = 0x2C8;

    /// <summary>
    /// Size, in bytes, of the <see cref="SceAppInstUtilCompilationDiscInfo"/> structure filled
    /// by <see cref="GetCompilationDiscInfo(SceAppInstUtilCompilationDiscInfo*)"/>.
    /// </summary>
    public const int CompilationDiscInfoSize = SceAppInstUtilCompilationDiscInfo.Size;

    private readonly SystemLibrary _library;
    private readonly delegate* unmanaged<int> _terminate;
    private readonly delegate* unmanaged<byte*, ulong, int> _installPackage;
    private readonly delegate* unmanaged<byte*, byte*, int> _appExists;
    private readonly delegate* unmanaged<byte*, ulong*, int> _appGetSize;
    private readonly delegate* unmanaged<byte*, int> _appUninstall;
    private readonly delegate* unmanaged<byte*, uint, int> _appUninstall2;
    private readonly delegate* unmanaged<byte*, int> _prepareOverwrite;
    private readonly delegate* unmanaged<byte*, int*, int> _getInstallProgress;
    private readonly delegate* unmanaged<byte*, int> _cancelInstall;
    private readonly delegate* unmanaged<byte*, int> _pauseInstall;
    private readonly delegate* unmanaged<byte*, int> _resumeInstall;
    private readonly delegate* unmanaged<byte*, int> _appIsInInstalling;
    private readonly delegate* unmanaged<byte*, void*, int> _appGetInstallStatus;
    private readonly delegate* unmanaged<byte*, void*, int> _getInstallStatus;
    private readonly delegate* unmanaged<byte*, int*, int> _appGetStorageDestType;
    private readonly delegate* unmanaged<byte*, byte*, int> _appUnInstallAddcont;
    private readonly delegate* unmanaged<byte*, int> _appUnInstallPat;
    private readonly delegate* unmanaged<byte*, uint, int> _appUnInstallTypes;
    private readonly delegate* unmanaged<byte*, int> _appRecoverApp;
    private readonly delegate* unmanaged<byte*, int> _appDestroyPkg;
    private readonly delegate* unmanaged<byte*, int> _appDestroyMetadata;
    private readonly delegate* unmanaged<void*, int> _appGetCompilationDiscInfo;
    private bool _disposed;

    private PackageInstaller(
        SystemLibrary library,
        delegate* unmanaged<int> terminate,
        delegate* unmanaged<byte*, ulong, int> installPackage,
        delegate* unmanaged<byte*, byte*, int> appExists,
        delegate* unmanaged<byte*, ulong*, int> appGetSize,
        delegate* unmanaged<byte*, int> appUninstall,
        delegate* unmanaged<byte*, uint, int> appUninstall2,
        delegate* unmanaged<byte*, int> prepareOverwrite,
        delegate* unmanaged<byte*, int*, int> getInstallProgress,
        delegate* unmanaged<byte*, int> cancelInstall,
        delegate* unmanaged<byte*, int> pauseInstall,
        delegate* unmanaged<byte*, int> resumeInstall,
        delegate* unmanaged<byte*, int> appIsInInstalling,
        delegate* unmanaged<byte*, void*, int> appGetInstallStatus,
        delegate* unmanaged<byte*, void*, int> getInstallStatus,
        delegate* unmanaged<byte*, int*, int> appGetStorageDestType,
        delegate* unmanaged<byte*, byte*, int> appUnInstallAddcont,
        delegate* unmanaged<byte*, int> appUnInstallPat,
        delegate* unmanaged<byte*, uint, int> appUnInstallTypes,
        delegate* unmanaged<byte*, int> appRecoverApp,
        delegate* unmanaged<byte*, int> appDestroyPkg,
        delegate* unmanaged<byte*, int> appDestroyMetadata,
        delegate* unmanaged<void*, int> appGetCompilationDiscInfo)
    {
        _library = library;
        _terminate = terminate;
        _installPackage = installPackage;
        _appExists = appExists;
        _appGetSize = appGetSize;
        _appUninstall = appUninstall;
        _appUninstall2 = appUninstall2;
        _prepareOverwrite = prepareOverwrite;
        _getInstallProgress = getInstallProgress;
        _cancelInstall = cancelInstall;
        _pauseInstall = pauseInstall;
        _resumeInstall = resumeInstall;
        _appIsInInstalling = appIsInInstalling;
        _appGetInstallStatus = appGetInstallStatus;
        _getInstallStatus = getInstallStatus;
        _appGetStorageDestType = appGetStorageDestType;
        _appUnInstallAddcont = appUnInstallAddcont;
        _appUnInstallPat = appUnInstallPat;
        _appUnInstallTypes = appUnInstallTypes;
        _appRecoverApp = appRecoverApp;
        _appDestroyPkg = appDestroyPkg;
        _appDestroyMetadata = appDestroyMetadata;
        _appGetCompilationDiscInfo = appGetCompilationDiscInfo;
    }

    /// <summary>
    /// Loads the install service and starts it. Throws when the module is missing, an entry point is
    /// absent, or the service refuses to start.
    /// </summary>
    /// <exception cref="ProsperoException">The service could not be loaded or started.</exception>
    public static PackageInstaller Open()
    {
        SystemLibrary library = SystemLibrary.Open(ModulePath);
        try
        {
            var initialize = (delegate* unmanaged<int>)library.GetFunction("sceAppInstUtilInitialize");
            var terminate = (delegate* unmanaged<int>)library.GetFunction("sceAppInstUtilTerminate");
            var install = (delegate* unmanaged<byte*, ulong, int>)library.GetFunction("sceAppInstUtilAppInstallPkg");
            var appExists = (delegate* unmanaged<byte*, byte*, int>)library.GetFunction("sceAppInstUtilAppExists");
            var appGetSize = (delegate* unmanaged<byte*, ulong*, int>)library.GetFunction("sceAppInstUtilAppGetSize");
            var appUninstall = (delegate* unmanaged<byte*, int>)library.GetFunction("sceAppInstUtilAppUnInstall");

            // The option-taking uninstall is newer than the earliest supported system (it appears from
            // 3.00), so resolve it optionally: on a firmware that predates it, Open still succeeds and
            // the option-taking Uninstall reports it rather than the whole installer failing to load.
            library.TryGetFunction("sceAppInstUtilAppUnInstall2", out void* appUninstall2Ptr);
            var appUninstall2 = (delegate* unmanaged<byte*, uint, int>)appUninstall2Ptr;

            // Progress, status, overwrite, and lifecycle control. These are resolved optionally so
            // Open succeeds on systems whose firmware predates any of them. Methods that depend on a
            // missing entry point throw a descriptive exception when called.
            library.TryGetFunction("sceAppInstUtilAppPrepareOverwritePkg", out void* prepareOverwritePtr);
            library.TryGetFunction("sceAppInstUtilGetInstallProgress", out void* getInstallProgressPtr);
            library.TryGetFunction("sceAppInstUtilCancelInstall", out void* cancelInstallPtr);
            library.TryGetFunction("sceAppInstUtilPauseInstall", out void* pauseInstallPtr);
            library.TryGetFunction("sceAppInstUtilResumeInstall", out void* resumeInstallPtr);
            library.TryGetFunction("sceAppInstUtilAppIsInInstalling", out void* appIsInInstallingPtr);
            library.TryGetFunction("sceAppInstUtilAppGetAppInstallStatus", out void* appGetInstallStatusPtr);
            library.TryGetFunction("sceAppInstUtilGetInstallStatus", out void* getInstallStatusPtr);
            library.TryGetFunction("sceAppInstUtilAppGetStorageDestType", out void* appGetStorageDestTypePtr);
            library.TryGetFunction("sceAppInstUtilAppUnInstallAddcont", out void* appUnInstallAddcontPtr);
            library.TryGetFunction("sceAppInstUtilAppUnInstallPat", out void* appUnInstallPatPtr);
            library.TryGetFunction("sceAppInstUtilAppUnInstallTypes", out void* appUnInstallTypesPtr);
            library.TryGetFunction("sceAppInstUtilAppRecoverApp", out void* appRecoverAppPtr);
            library.TryGetFunction("sceAppInstUtilAppDestroyPkg", out void* appDestroyPkgPtr);
            library.TryGetFunction("sceAppInstUtilAppDestroyMetadata", out void* appDestroyMetadataPtr);
            library.TryGetFunction("sceAppInstUtilAppGetCompilationDiscInfo", out void* appGetCompilationDiscInfoPtr);

            SceResult.ThrowIfFailed(initialize(), "sceAppInstUtilInitialize");

            return new PackageInstaller(
                library, terminate, install, appExists, appGetSize, appUninstall, appUninstall2,
                (delegate* unmanaged<byte*, int>)prepareOverwritePtr,
                (delegate* unmanaged<byte*, int*, int>)getInstallProgressPtr,
                (delegate* unmanaged<byte*, int>)cancelInstallPtr,
                (delegate* unmanaged<byte*, int>)pauseInstallPtr,
                (delegate* unmanaged<byte*, int>)resumeInstallPtr,
                (delegate* unmanaged<byte*, int>)appIsInInstallingPtr,
                (delegate* unmanaged<byte*, void*, int>)appGetInstallStatusPtr,
                (delegate* unmanaged<byte*, void*, int>)getInstallStatusPtr,
                (delegate* unmanaged<byte*, int*, int>)appGetStorageDestTypePtr,
                (delegate* unmanaged<byte*, byte*, int>)appUnInstallAddcontPtr,
                (delegate* unmanaged<byte*, int>)appUnInstallPatPtr,
                (delegate* unmanaged<byte*, uint, int>)appUnInstallTypesPtr,
                (delegate* unmanaged<byte*, int>)appRecoverAppPtr,
                (delegate* unmanaged<byte*, int>)appDestroyPkgPtr,
                (delegate* unmanaged<byte*, int>)appDestroyMetadataPtr,
                (delegate* unmanaged<void*, int>)appGetCompilationDiscInfoPtr);
        }
        catch
        {
            library.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Installs the package at <paramref name="path"/>, an absolute path to a file on the console.
    /// The call hands the request to the service; the install itself continues in the background.
    /// </summary>
    /// <param name="path">Absolute path of the package file.</param>
    /// <param name="option">Reserved; leave zero unless a specific value is called for.</param>
    /// <exception cref="ProsperoException">The service rejected the request.</exception>
    public void Install(string path, ulong option = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ObjectDisposedException.ThrowIf(_disposed, this);

        int byteCount = Encoding.UTF8.GetByteCount(path);
        Span<byte> buffer = byteCount < 512 ? stackalloc byte[byteCount + 1] : new byte[byteCount + 1];
        int written = Encoding.UTF8.GetBytes(path, buffer);
        buffer[written] = 0;

        int rc;
        fixed (byte* p = buffer)
            rc = _installPackage(p, option);
        SceResult.ThrowIfFailed(rc, "sceAppInstUtilAppInstallPkg");
    }

    /// <summary>
    /// Reports whether an application with <paramref name="titleId"/> is installed.
    /// </summary>
    /// <param name="titleId">The title id to check, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request.</exception>
    public bool AppExists(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        byte exists = 0;
        SceResult.ThrowIfFailed(_appExists(id, &exists), "sceAppInstUtilAppExists");
        return exists != 0;
    }

    /// <summary>
    /// Reads the installed size of the application with <paramref name="titleId"/>, in bytes.
    /// </summary>
    /// <exception cref="ProsperoException">The service rejected the request.</exception>
    public ulong AppGetSize(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        ulong size = 0;
        SceResult.ThrowIfFailed(_appGetSize(id, &size), "sceAppInstUtilAppGetSize");
        return size;
    }

    /// <summary>
    /// Removes the installed application with <paramref name="titleId"/>. This deletes the application
    /// and its data, so confirm the id before calling. The call hands the request to the service and
    /// returns once it is accepted; the removal itself finishes in the background.
    /// </summary>
    /// <param name="titleId">The title id to remove, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request.</exception>
    public void Uninstall(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_appUninstall(id), "sceAppInstUtilAppUnInstall");
    }

    /// <summary>
    /// Removes the installed application with <paramref name="titleId"/>, passing an
    /// <paramref name="option"/> flag to the service. This is the option-taking form of
    /// <see cref="Uninstall(string)"/>; leave <paramref name="option"/> zero for the same behavior.
    /// This deletes the application and its data, so confirm the id before calling.
    /// </summary>
    /// <param name="titleId">The title id to remove, for example <c>CUSA00000</c>.</param>
    /// <param name="option">A service option flag. Zero requests the default behavior.</param>
    /// <exception cref="ProsperoException">
    /// The service rejected the request, or a non-zero <paramref name="option"/> was passed on a system
    /// whose firmware predates the option-taking uninstall (before 3.00).
    /// </exception>
    public void Uninstall(string titleId, uint option)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        if (_appUninstall2 is null)
        {
            // The option-taking uninstall is not present on this system's firmware (it is newer). With
            // no option the plain uninstall does the same removal; with one the request cannot be
            // honored, so it is reported rather than silently dropping the option.
            if (option != 0)
                throw new ProsperoException(
                    "sceAppInstUtilAppUnInstall2 is not available on this system's firmware; "
                    + "call Uninstall(titleId) for a removal without an option.", -1);
            SceResult.ThrowIfFailed(_appUninstall(id), "sceAppInstUtilAppUnInstall");
            return;
        }

        SceResult.ThrowIfFailed(_appUninstall2(id, option), "sceAppInstUtilAppUnInstall2");
    }

    /// <summary>
    /// Prepares the system to overwrite an already-installed application with
    /// <paramref name="titleId"/>. Call this before <see cref="Install(string, ulong)"/> when
    /// reinstalling a title that is already present on the system; without it the install service may
    /// reject the package.
    /// </summary>
    /// <param name="titleId">The title id to prepare for overwrite, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void PrepareOverwrite(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_prepareOverwrite, "sceAppInstUtilAppPrepareOverwritePkg");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_prepareOverwrite(id), "sceAppInstUtilAppPrepareOverwritePkg");
    }

    /// <summary>
    /// Reads the install progress of the application with <paramref name="titleId"/>.
    /// </summary>
    /// <param name="titleId">The title id to query, for example <c>CUSA00000</c>.</param>
    /// <returns>The progress value reported by the service.</returns>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public int GetInstallProgress(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_getInstallProgress, "sceAppInstUtilGetInstallProgress");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        int progress = 0;
        SceResult.ThrowIfFailed(_getInstallProgress(id, &progress), "sceAppInstUtilGetInstallProgress");
        return progress;
    }

    /// <summary>
    /// Cancels an active install identified by <paramref name="contentId"/>.
    /// </summary>
    /// <param name="contentId">The content id of the install to cancel.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void CancelInstall(string contentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_cancelInstall, "sceAppInstUtilCancelInstall");

        int count = Encoding.UTF8.GetByteCount(contentId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(contentId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_cancelInstall(id), "sceAppInstUtilCancelInstall");
    }

    /// <summary>
    /// Pauses an active install identified by <paramref name="contentId"/>. The install can be
    /// continued later with <see cref="ResumeInstall(string)"/>.
    /// </summary>
    /// <param name="contentId">The content id of the install to pause.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void PauseInstall(string contentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_pauseInstall, "sceAppInstUtilPauseInstall");

        int count = Encoding.UTF8.GetByteCount(contentId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(contentId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_pauseInstall(id), "sceAppInstUtilPauseInstall");
    }

    /// <summary>
    /// Resumes a previously paused install identified by <paramref name="contentId"/>.
    /// </summary>
    /// <param name="contentId">The content id of the install to resume.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void ResumeInstall(string contentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_resumeInstall, "sceAppInstUtilResumeInstall");

        int count = Encoding.UTF8.GetByteCount(contentId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(contentId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_resumeInstall(id), "sceAppInstUtilResumeInstall");
    }

    /// <summary>
    /// Reports whether the application with <paramref name="titleId"/> is currently being installed.
    /// Returns <see langword="false"/> when the title is not in the middle of an install, and
    /// <see langword="true"/> when it is.
    /// </summary>
    /// <param name="titleId">The title id to query, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The entry point is not available on this firmware.</exception>
    public bool AppIsInstalling(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appIsInInstalling, "sceAppInstUtilAppIsInInstalling");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        int rc = _appIsInInstalling(id);
        SceResult.ThrowIfFailed(rc, "sceAppInstUtilAppIsInInstalling");
        return rc != 0;
    }

    /// <summary>
    /// Queries the install status of an application with <paramref name="titleId"/>. The service
    /// writes a 12-byte (<see cref="AppInstallStatusSize"/>) status record into the buffer at
    /// <paramref name="outStatus"/>.
    /// </summary>
    /// <param name="titleId">The title id to query, for example <c>CUSA00000</c>.</param>
    /// <param name="outStatus">
    /// A buffer of at least <see cref="AppInstallStatusSize"/> bytes that receives the status record.
    /// </param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void AppGetInstallStatus(string titleId, void* outStatus)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ArgumentNullException.ThrowIfNull(outStatus);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appGetInstallStatus, "sceAppInstUtilAppGetAppInstallStatus");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(
            _appGetInstallStatus(id, outStatus), "sceAppInstUtilAppGetAppInstallStatus");
    }

    /// <summary>
    /// Queries the full install status of a content item identified by <paramref name="contentId"/>.
    /// The service writes a 712-byte (<see cref="InstallStatusSize"/>) status record into the buffer
    /// at <paramref name="outStatus"/>.
    /// </summary>
    /// <param name="contentId">The content id to query.</param>
    /// <param name="outStatus">
    /// A buffer of at least <see cref="InstallStatusSize"/> bytes that receives the status record.
    /// </param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void GetInstallStatus(string contentId, void* outStatus)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);
        ArgumentNullException.ThrowIfNull(outStatus);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_getInstallStatus, "sceAppInstUtilGetInstallStatus");

        int count = Encoding.UTF8.GetByteCount(contentId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(contentId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(
            _getInstallStatus(id, outStatus), "sceAppInstUtilGetInstallStatus");
    }

    /// <summary>
    /// Reads the storage destination type for the application with <paramref name="titleId"/>.
    /// Returns 0 for internal storage, 1 for extended storage.
    /// </summary>
    /// <param name="titleId">The title id to query, for example <c>CUSA00000</c>.</param>
    /// <returns>0 for internal storage, 1 for extended storage.</returns>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public int AppGetStorageDestType(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appGetStorageDestType, "sceAppInstUtilAppGetStorageDestType");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        int destType = 0;
        SceResult.ThrowIfFailed(
            _appGetStorageDestType(id, &destType), "sceAppInstUtilAppGetStorageDestType");
        return destType;
    }

    /// <summary>
    /// Removes the add-on content identified by <paramref name="addcontId"/> from the application
    /// with <paramref name="titleId"/>.
    /// </summary>
    /// <param name="titleId">The title id of the application, for example <c>CUSA00000</c>.</param>
    /// <param name="addcontId">The add-on content id to remove.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void UninstallAddcont(string titleId, string addcontId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ArgumentException.ThrowIfNullOrEmpty(addcontId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appUnInstallAddcont, "sceAppInstUtilAppUnInstallAddcont");

        int tidCount = Encoding.UTF8.GetByteCount(titleId);
        byte* tid = stackalloc byte[tidCount + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(tid, tidCount));
        tid[tidCount] = 0;

        int cidCount = Encoding.UTF8.GetByteCount(addcontId);
        byte* cid = stackalloc byte[cidCount + 1];
        Encoding.UTF8.GetBytes(addcontId, new Span<byte>(cid, cidCount));
        cid[cidCount] = 0;

        SceResult.ThrowIfFailed(
            _appUnInstallAddcont(tid, cid), "sceAppInstUtilAppUnInstallAddcont");
    }

    /// <summary>
    /// Removes the installed patch for the application with <paramref name="titleId"/>, restoring
    /// it to its base version.
    /// </summary>
    /// <param name="titleId">The title id to remove the patch from, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void UninstallPatch(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appUnInstallPat, "sceAppInstUtilAppUnInstallPat");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_appUnInstallPat(id), "sceAppInstUtilAppUnInstallPat");
    }

    /// <summary>
    /// Removes installed content of the specified <paramref name="types"/> for the application
    /// with <paramref name="titleId"/>.
    /// </summary>
    /// <param name="titleId">The title id to remove content from, for example <c>CUSA00000</c>.</param>
    /// <param name="types">A bitmask of content types to remove.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void UninstallTypes(string titleId, uint types)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appUnInstallTypes, "sceAppInstUtilAppUnInstallTypes");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_appUnInstallTypes(id, types), "sceAppInstUtilAppUnInstallTypes");
    }

    /// <summary>
    /// Attempts to recover a corrupted installation for the application with
    /// <paramref name="titleId"/>.
    /// </summary>
    /// <param name="titleId">The title id to recover, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void RecoverApp(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appRecoverApp, "sceAppInstUtilAppRecoverApp");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_appRecoverApp(id), "sceAppInstUtilAppRecoverApp");
    }

    /// <summary>
    /// Destroys the install package for the application with <paramref name="titleId"/>. This
    /// removes the stored package file used during installation.
    /// </summary>
    /// <param name="titleId">The title id whose package to destroy, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void DestroyPackage(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appDestroyPkg, "sceAppInstUtilAppDestroyPkg");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_appDestroyPkg(id), "sceAppInstUtilAppDestroyPkg");
    }

    /// <summary>
    /// Destroys the install metadata for the application with <paramref name="titleId"/>.
    /// </summary>
    /// <param name="titleId">The title id whose metadata to destroy, for example <c>CUSA00000</c>.</param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void DestroyMetadata(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appDestroyMetadata, "sceAppInstUtilAppDestroyMetadata");

        int count = Encoding.UTF8.GetByteCount(titleId);
        byte* id = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(titleId, new Span<byte>(id, count));
        id[count] = 0;

        SceResult.ThrowIfFailed(_appDestroyMetadata(id), "sceAppInstUtilAppDestroyMetadata");
    }

    /// <summary>
    /// Fills <paramref name="outInfo"/> with compilation disc information. The structure contains
    /// up to 33 title-id slots describing the titles on a compilation disc.
    /// </summary>
    /// <param name="outInfo">
    /// Pointer to a <see cref="SceAppInstUtilCompilationDiscInfo"/> that receives the disc
    /// information.
    /// </param>
    /// <exception cref="ProsperoException">The service rejected the request or is not available.</exception>
    public void GetCompilationDiscInfo(SceAppInstUtilCompilationDiscInfo* outInfo)
    {
        ArgumentNullException.ThrowIfNull(outInfo);
        ObjectDisposedException.ThrowIf(_disposed, this);
        RequireFunction(_appGetCompilationDiscInfo, "sceAppInstUtilAppGetCompilationDiscInfo");

        SceResult.ThrowIfFailed(
            _appGetCompilationDiscInfo(outInfo), "sceAppInstUtilAppGetCompilationDiscInfo");
    }

    /// <summary>Shuts the service down and unloads the module.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _terminate();
        _library.Dispose();
    }

    /// <summary>
    /// Throws a descriptive exception when an optionally resolved function pointer is null, indicating
    /// the entry point is not exported on the running firmware.
    /// </summary>
    private static void RequireFunction(void* functionPointer, string symbolName)
    {
        if (functionPointer is null)
            throw new ProsperoException(
                $"{symbolName} is not available on this system's firmware.", -1);
    }
}
