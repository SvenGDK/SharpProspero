// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.AppInstUtil;

/// <summary>
/// The system-side application installer service. A homebrew launcher places the application it
/// wants to install under <c>/user/app/&lt;title_id&gt;/</c> and calls <see cref="sceAppInstUtilAppInstallAll"/>
/// which walks that directory and registers every installable it finds so the shell reads them back
/// as ordinary applications and can launch them through <c>sceSystemServiceLaunchApp</c>.
/// </summary>
public static unsafe partial class AppInstUtil
{
    private const string Lib = "libSceAppInstUtil";

    /// <summary>
    /// Brings up the installer service so the other calls in this class answer. Must be called
    /// once per process before the first install or uninstall.
    /// </summary>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilInitialize();

    /// <summary>
    /// Tears down the installer service so the shell registry commits the current install pass
    /// and a following <see cref="sceAppInstUtilInitialize"/> reads it back fresh. A launcher that
    /// keeps the service open across an install and a launch reads the pre-install registry state
    /// on the launch call and answers with "title is not installed"; ending the service between
    /// the two calls flushes the pending registry update.
    /// </summary>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilTerminate();

    /// <summary>
    /// Removes the installed application with <paramref name="titleId"/>. Safe to call for a title
    /// that is not installed; the service answers with a "not installed" code that the caller can
    /// ignore before it lays the fresh copy down.
    /// </summary>
    /// <param name="titleId">A NUL-terminated ASCII title id (e.g. <c>"CUSA00000"</c>).</param>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppUnInstall(byte* titleId);

    /// <summary>
    /// Walks <c>/user/app/</c> and registers every installable application it finds. A homebrew
    /// launcher places the application under <c>/user/app/&lt;title_id&gt;/sce_sys/</c> before the
    /// call and reads back the newly installed titles after it returns.
    /// </summary>
    /// <param name="reserved">Reserved for future use; pass a null pointer.</param>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppInstallAll(void* reserved);

    /// <summary>
    /// Registers one installed application by title id from an install directory. The caller
    /// places the application at <paramref name="titleDir"/>/&lt;title_id&gt;/ before the call.
    /// </summary>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppInstallTitleDir(byte* titleId, byte* titleDir, void* reserved);

    /// <summary>
    /// Asks the installer service whether <paramref name="titleId"/> is registered as an
    /// installed application. The service answers by writing 0 (not installed) or non-zero
    /// (installed) into <paramref name="pExists"/> and returns zero on success. A launcher that
    /// has just registered a title through <see cref="sceAppInstUtilAppInstallTitleDir"/> can
    /// poll this call to know when the shell's registry has committed the install pass and the
    /// following <c>sceSystemServiceLaunchApp</c> will not answer "title is not installed".
    /// </summary>
    /// <param name="titleId">A NUL-terminated ASCII title id.</param>
    /// <param name="pExists">Receives 0 (not installed) or non-zero (installed).</param>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppExists(byte* titleId, int* pExists);

    /// <summary>
    /// Asks the installer service whether any install pass is currently in flight (either an
    /// initial install or a title update). The service answers by writing 0 (idle) or non-zero
    /// (an install is running) into <paramref name="pInInstalling"/> and returns zero on
    /// success. The query is service-wide, not per-title.
    /// </summary>
    /// <param name="pInInstalling">Receives 0 (idle) or non-zero (install pass running).</param>
    /// <returns>Zero on success, or a negative service code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppIsInInstalling(int* pInInstalling);
}
