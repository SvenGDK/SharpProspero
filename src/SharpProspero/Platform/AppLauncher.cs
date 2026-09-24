// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.AppInstUtil;
using SharpProspero.Interop.Kernel;
using SharpProspero.Storage;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Native = SharpProspero.Interop.SystemService.SystemService;
using UserNative = SharpProspero.Interop.UserService.UserService;

namespace SharpProspero.Platform;

/// <summary>
/// The result of a bind-mount launch, carrying the information needed to clean up the mount point
/// after the launched application exits.
/// </summary>
/// <param name="MountPoint">The mount point path under <c>/system_ex/app/</c>.</param>
/// <param name="TitleId">The title id that was launched.</param>
public readonly record struct LaunchHandle(string MountPoint, string TitleId);

/// <summary>
/// The application launch context passed to <c>sceSystemServiceLaunchApp</c>. The structure is
/// 32 bytes (0x20) with fields at fixed offsets.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 0x20)]
public struct SceAppLaunchCtx
{
    /// <summary>The structure size in bytes. Set to <c>sizeof(SceAppLaunchCtx) = 0x20</c>.</summary>
    [FieldOffset(0x00)] public uint StructSize;

    /// <summary>The user id to launch on behalf of.</summary>
    [FieldOffset(0x04)] public int UserId;

    /// <summary>Application option flags.</summary>
    [FieldOffset(0x08)] public uint AppOpt;

    /// <summary>Crash report flags.</summary>
    [FieldOffset(0x10)] public ulong CrashReport;

    /// <summary>Launch check flags.</summary>
    [FieldOffset(0x18)] public uint CheckFlag;
}

/// <summary>
/// Starts another installed application by its title id, so a module can act as a launcher. The
/// running application is replaced by the one started, so the call does not return to the caller when
/// it succeeds.
/// </summary>
/// <example>
/// <code>
/// AppLauncher.Launch("CUSA00000");
/// </code>
/// </example>
public static unsafe class AppLauncher
{
    /// <summary>The exact length of a title id.</summary>
    public const int TitleIdLength = 9;

    /// <summary>The system_ex app directory prefix.</summary>
    private const string SystemExAppPrefix = "/system_ex/app/";

    /// <summary>
    /// Offset of <c>ki_pid</c> in FreeBSD 12's <c>kinfo_proc</c> on amd64.
    /// </summary>
    private const int KinfoProcPidOffset = 0x48;

    // sysctl MIB constants for KERN_PROC_PROC.
    private const int CtlKern = 1;
    private const int KernProc = 14;
    private const int KernProcProc = 8;

    /// <summary>
    /// Starts the installed application with <paramref name="titleId"/> (a 9-character id), passing
    /// <paramref name="args"/> as its launch arguments. On success the current application is replaced
    /// and the call does not return.
    /// </summary>
    /// <param name="titleId">The 9-character title id to start, for example <c>CUSA00000</c>.</param>
    /// <param name="args">Launch arguments passed to the started application. May be empty.</param>
    /// <exception cref="ArgumentException"><paramref name="titleId"/> is not 9 characters.</exception>
    /// <exception cref="ProsperoException">The application could not be started.</exception>
    public static void Launch(string titleId, params string[] args)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        if (titleId.Length != TitleIdLength)
            throw new ArgumentException($"A title id is {TitleIdLength} characters.", nameof(titleId));

        Span<byte> id = stackalloc byte[TitleIdLength + 1];
        int written = Encoding.UTF8.GetBytes(titleId, id);
        id[written] = 0;

        if (args is null || args.Length == 0)
        {
            int rc;
            fixed (byte* pid = id)
                rc = Native.sceSystemServiceLaunchApp(pid, null, null);
            SceResult.ThrowIfFailed(rc, nameof(Native.sceSystemServiceLaunchApp));
            return;
        }

        // Build a null-terminated array of C-string arguments on the unmanaged heap. The array is
        // zeroed so that if encoding an argument throws mid-loop, the unset slots stay null and the
        // cleanup below frees only the entries it actually allocated.
        byte** argv = (byte**)NativeMemory.AllocZeroed((nuint)((args.Length + 1) * sizeof(nint)));
        try
        {
            for (int i = 0; i < args.Length; i++)
            {
                int count = Encoding.UTF8.GetByteCount(args[i]);
                var s = (byte*)NativeMemory.Alloc((nuint)(count + 1));
                Encoding.UTF8.GetBytes(args[i], new Span<byte>(s, count));
                s[count] = 0;
                argv[i] = s;
            }
            argv[args.Length] = null;

            int rc;
            fixed (byte* pid = id)
                rc = Native.sceSystemServiceLaunchApp(pid, argv, null);
            SceResult.ThrowIfFailed(rc, nameof(Native.sceSystemServiceLaunchApp));
        }
        finally
        {
            for (int i = 0; i < args.Length; i++)
                if (argv[i] is not null)
                    NativeMemory.Free(argv[i]);
            NativeMemory.Free(argv);
        }
    }

    /// <summary>
    /// Bind-mounts <paramref name="sourceFolder"/> to <c>/system_ex/app/&lt;titleId&gt;</c> and
    /// launches it as the foreground user. The process is not replaced; the launched application runs
    /// as a separate process. Call <see cref="Unmount"/> after the launched application exits to clean
    /// up the mount point.
    /// </summary>
    /// <param name="sourceFolder">
    /// An on-device directory containing the application's <c>eboot.bin</c>, <c>sce_sys/</c>, and
    /// <c>sce_module/</c>.
    /// </param>
    /// <param name="titleId">The 9-character title id to register the application under.</param>
    /// <param name="argv">Launch arguments, or null.</param>
    /// <param name="appOpt">Application option flags, or zero for the defaults.</param>
    /// <returns>A handle carrying the mount point, for <see cref="Unmount"/> after exit.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="sourceFolder"/> is empty, or <paramref name="titleId"/> is not 9 characters.
    /// </exception>
    /// <exception cref="ProsperoException">The mount or launch failed.</exception>
    public static LaunchHandle LaunchWithBindMount(string sourceFolder, string titleId,
        string[]? argv = null, uint appOpt = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(sourceFolder);
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        if (titleId.Length != TitleIdLength)
            throw new ArgumentException($"A title id is {TitleIdLength} characters.", nameof(titleId));

        // 1. Foreground user id. The user service must already be initialised by whoever set the
        //    application up; a ProsperoApp subclass does this once at start-up and terminates it
        //    at teardown. An earlier version of this method did its own Initialize/Terminate pair
        //    around the query — but in a shell that already keeps the service live for GamePad
        //    and the platform's launch IPC, that Terminate races the still-running consumers and
        //    the launch faults right after sceSystemServiceLaunchApp returns. Just read the id
        //    here.
        int uid;
        int userRc = UserNative.sceUserServiceGetForegroundUser(&uid);
        SceResult.ThrowIfFailed(userRc, nameof(UserNative.sceUserServiceGetForegroundUser));

        // 2. Destination path.
        string dst = SystemExAppPrefix + titleId;

        // Encode source and destination as NUL-terminated UTF-8.
        int srcByteCount = Encoding.UTF8.GetByteCount(sourceFolder);
        Span<byte> srcBytes = srcByteCount < 512
            ? stackalloc byte[srcByteCount + 1]
            : new byte[srcByteCount + 1];
        Encoding.UTF8.GetBytes(sourceFolder, srcBytes);
        srcBytes[srcByteCount] = 0;

        int dstByteCount = Encoding.UTF8.GetByteCount(dst);
        Span<byte> dstBytes = dstByteCount < 512
            ? stackalloc byte[dstByteCount + 1]
            : new byte[dstByteCount + 1];
        Encoding.UTF8.GetBytes(dst, dstBytes);
        dstBytes[dstByteCount] = 0;

        // 3. Create the mount point if it does not already exist.
        fixed (byte* pDst = dstBytes)
        {
            if (KernelFile.sceKernelCheckReachability(pDst) != 0)
            {
                RemountSystemExReadWrite();
                int mkrc = KernelFile.sceKernelMkdir(pDst, 0x1ED); // 0755
                if (mkrc < 0)
                    SceResult.ThrowIfFailed(mkrc, nameof(KernelFile.sceKernelMkdir));
            }
        }

        // 4. Unmount any leftover mount at the destination so the following bind mount reflects
        //    the current source. A previous run of this method that returned without
        //    <see cref="Unmount"/> being called (crash, unclean exit) leaves the old mount in
        //    place; a fresh mount over it faults with EBUSY, and re-using the stale mount would
        //    launch content from a source folder the caller no longer intends.
        fixed (byte* pDst = dstBytes)
            KernelMount.unmount(pDst, 0);

        // 5. Nullfs bind mount source -> /system_ex/app/<titleId>.
        fixed (byte* pSrc = srcBytes, pDst = dstBytes)
        {
            if (MountNullfs(pSrc, pDst) != 0)
            {
                int err = *KernelSystem.__error();
                throw new ProsperoException("nmount(nullfs)", SceResult.KernelFacility | (err & 0xFFFF));
            }
        }

        // 6. Build the launch context.
        SceAppLaunchCtx ctx = default;
        ctx.StructSize = 0x20;
        ctx.UserId = uid;
        ctx.AppOpt = appOpt;

        // 7. Encode the title id.
        Span<byte> idBytes = stackalloc byte[TitleIdLength + 1];
        Encoding.UTF8.GetBytes(titleId, idBytes);
        idBytes[TitleIdLength] = 0;

        // 8. Launch.
        if (argv is null || argv.Length == 0)
        {
            int rc;
            fixed (byte* pId = idBytes)
                rc = Native.sceSystemServiceLaunchApp(pId, null, &ctx);
            if (rc < 0)
            {
                // Clean up the mount on failure.
                fixed (byte* pDst = dstBytes)
                    KernelMount.unmount(pDst, 0);
                SceResult.ThrowIfFailed(rc, nameof(Native.sceSystemServiceLaunchApp));
            }
        }
        else
        {
            byte** argvNative = (byte**)NativeMemory.AllocZeroed((nuint)((argv.Length + 1) * sizeof(nint)));
            try
            {
                for (int i = 0; i < argv.Length; i++)
                {
                    int count = Encoding.UTF8.GetByteCount(argv[i]);
                    var s = (byte*)NativeMemory.Alloc((nuint)(count + 1));
                    Encoding.UTF8.GetBytes(argv[i], new Span<byte>(s, count));
                    s[count] = 0;
                    argvNative[i] = s;
                }
                argvNative[argv.Length] = null;

                int rc;
                fixed (byte* pId = idBytes)
                    rc = Native.sceSystemServiceLaunchApp(pId, argvNative, &ctx);
                if (rc < 0)
                {
                    fixed (byte* pDst = dstBytes)
                        KernelMount.unmount(pDst, 0);
                    SceResult.ThrowIfFailed(rc, nameof(Native.sceSystemServiceLaunchApp));
                }
            }
            finally
            {
                for (int i = 0; i < argv.Length; i++)
                    if (argvNative[i] is not null)
                        NativeMemory.Free(argvNative[i]);
                NativeMemory.Free(argvNative);
            }
        }

        return new LaunchHandle(dst, titleId);
    }

    /// <summary>
    /// Registers <paramref name="sourceFolder"/> as the installed application for
    /// <paramref name="titleId"/> and returns once the installer service has committed the
    /// registration. This is the install-only pass a launcher runs before the first launch of a
    /// backup that the shell has no record of; it does not start the application. The pass
    /// walks the sequence the shell's install pipeline requires: mount the runtime folder over
    /// <c>/system_ex/app/&lt;titleId&gt;/</c>, initialize the installer service, uninstall any
    /// prior copy under the same title id, copy trophy and UDS bindings into
    /// <c>/system_data/priv/appmeta/&lt;titleId&gt;/</c>, remount <c>/system_ex</c>, copy the
    /// full <c>sce_sys/</c> into <c>/user/app/&lt;titleId&gt;/sce_sys/</c>, copy the
    /// appmeta-classed files into <c>/user/appmeta/&lt;titleId&gt;/</c>, register the title
    /// through the installer service, write <c>mount.lnk</c>, flush the installer service,
    /// and wait for the shell's registry to publish the title. The <c>tbl_contentinfo</c>
    /// row that names <c>snd0.at9</c> as the title-card audio preview stays untouched
    /// because it lives in a SQLite database and firmware 10.01 ships no callable SQLite
    /// module a NativeAOT module can link, so the title-card audio is quiet on the first
    /// browse of an installed title until the shell rescans its metadata. Call
    /// <see cref="LaunchWithBindMount"/> afterwards to start the installed application.
    /// </summary>
    /// <param name="sourceFolder">
    /// The on-device folder that carries the application - its <c>eboot.bin</c>,
    /// <c>sce_sys/</c>, <c>sce_module/</c>, and any per-application data files. The folder
    /// itself is not moved; the install pass copies its <c>sce_sys/</c> tree into the shell's
    /// per-title directories and bind-mounts the folder at <c>/system_ex/app/&lt;titleId&gt;/</c>
    /// so the runtime can read the application content back from there.
    /// </param>
    /// <param name="titleId">The 9-character title id the shell registers the application under.</param>
    /// <returns>A handle carrying the mount point, for <see cref="Unmount"/> once the launched application has exited.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="sourceFolder"/> is empty, or <paramref name="titleId"/> is not 9 characters.
    /// </exception>
    /// <exception cref="ProsperoException">The install failed.</exception>
    public static LaunchHandle Install(string sourceFolder, string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(sourceFolder);
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        if (titleId.Length != TitleIdLength)
            throw new ArgumentException($"A title id is {TitleIdLength} characters.", nameof(titleId));

        // 1. Paths.
        string sourceTrimmed = sourceFolder.TrimEnd('/');
        string dst = SystemExAppPrefix + titleId;
        string sourceSceSys = sourceTrimmed + "/sce_sys";
        string userAppRoot = "/user/app/";
        string userAppTitle = userAppRoot + titleId;
        string userAppSceSys = userAppTitle + "/sce_sys";
        string userAppMeta = "/user/appmeta/" + titleId;
        string systemDataMeta = "/system_data/priv/appmeta/" + titleId;

        int srcByteCount = Encoding.UTF8.GetByteCount(sourceTrimmed);
        Span<byte> srcBytes = srcByteCount < 512
            ? stackalloc byte[srcByteCount + 1]
            : new byte[srcByteCount + 1];
        Encoding.UTF8.GetBytes(sourceTrimmed, srcBytes);
        srcBytes[srcByteCount] = 0;

        int dstByteCount = Encoding.UTF8.GetByteCount(dst);
        Span<byte> dstBytes = dstByteCount < 512
            ? stackalloc byte[dstByteCount + 1]
            : new byte[dstByteCount + 1];
        Encoding.UTF8.GetBytes(dst, dstBytes);
        dstBytes[dstByteCount] = 0;

        // 2. Create the mount point under /system_ex/app/<titleId>. The mkdir call runs with
        //    0755 and any failure is tolerated because /system_ex gets remounted below before
        //    the shell reads the mount point back. A caller whose /system_ex is still read-only
        //    from boot sees EROFS here, so remount once when the destination is not yet
        //    reachable and try again.
        fixed (byte* pDst = dstBytes)
        {
            if (KernelFile.sceKernelCheckReachability(pDst) != 0)
            {
                try { RemountSystemExReadWrite(); } catch (ProsperoException) { }
                KernelFile.sceKernelMkdir(pDst, 0x1ED); // 0755
            }
        }

        // 3. Unmount a leftover nullfs at the destination. A previous launch that was not
        //    unmounted leaves the mount in place; a fresh mount over it faults with EBUSY.
        fixed (byte* pDst = dstBytes)
            KernelMount.unmount(pDst, 0);

        // 4. Nullfs bind mount source -> /system_ex/app/<titleId>. The installer service and the
        //    shell both read the sce_sys/ metadata through this mount, so the mount must succeed
        //    for the install pass below to see the application's own sce_sys.
        fixed (byte* pSrc = srcBytes, pDst = dstBytes)
        {
            if (MountNullfs(pSrc, pDst) != 0)
            {
                int err = *KernelSystem.__error();
                throw new ProsperoException("nmount(nullfs)", SceResult.KernelFacility | (err & 0xFFFF));
            }
        }

        // 5. Bring up the installer service. Every call below reads or writes the shell's
        //    per-title registry through this service; a failure to initialise means the module
        //    is not loaded or the service is unavailable and the follow-up calls would return
        //    zero as a no-op instead of surfacing the missing service. Bail with the initialise
        //    code so the caller sees the real cause instead of a silent "title not installed"
        //    later on. On failure, unmount the nullfs bind so the mount point does not survive
        //    an exception path.
        int initRc = AppInstUtil.sceAppInstUtilInitialize();
        if (initRc != 0)
        {
            fixed (byte* pDst = dstBytes)
                KernelMount.unmount(pDst, 0);
            throw new ProsperoException(nameof(AppInstUtil.sceAppInstUtilInitialize), initRc);
        }
        Span<byte> idBytes = stackalloc byte[TitleIdLength + 1];
        Encoding.UTF8.GetBytes(titleId, idBytes);
        idBytes[TitleIdLength] = 0;

        // Everything from here runs inside the try so an exception on any downstream step
        // still tears the installer session down before it propagates out. A leaked
        // initialised session leaves the service busy for the next caller and its own
        // Initialize would then answer with a stale registry.
        LaunchHandle handle;
        bool sessionOpen = true;
        try
        {
            // 6. Drop any earlier registration under this title id. The uninstall answers with a
            //    code the caller ignores when nothing is registered.
            fixed (byte* pId = idBytes)
                AppInstUtil.sceAppInstUtilAppUnInstall(pId);

            // 7. Copy the trophy binding, UDS binding and param.json into
            //    /system_data/priv/appmeta/<titleId>/ so the shell picks up the trophy set on
            //    the first launch.
            CopyTrophyBindings(sourceSceSys, systemDataMeta);

            // 8. The shell's title-card audio preview lives in a SQLite row on
            //    /system_data/priv/mms/app.db whose <c>snd0info</c> column names
            //    <c>/user/appmeta/&lt;titleId&gt;/snd0.at9</c>. Firmware 10.01 ships
            //    <c>Mono.Data.Sqlite.dll.sprx</c>, <c>Sce.Vsh.SQLite.dll.sprx</c>, and
            //    <c>Sce.Vsh.SQLiteAux.dll.sprx</c> only as Mono AOT-compiled assemblies for the
            //    shell's Mono host, and no native SQLite module ships beside them, so a
            //    NativeAOT module has no in-process way to run the one-row UPDATE. The audio
            //    file itself still lands under <c>/user/appmeta/&lt;titleId&gt;/</c> via
            //    <see cref="CopyAppMetaFiles"/> and the shell rescans the row the next time it
            //    walks the app metadata, so the effect is limited to the first browse of the
            //    freshly-installed title card carrying no preview audio.

            // 9. Remount /system_ex read-write so the following /user/app/ writes see the
            //    flushed metadata region and the mount point remains reachable through the
            //    shell.
            try { RemountSystemExReadWrite(); } catch (ProsperoException) { }

            // 10. Create /user/app/<titleId>/sce_sys/ and copy the full sce_sys/ from the source
            //     folder. The installer service reads back /user/app/<titleId>/sce_sys/ for the
            //     shell metadata; /user/app/ itself is created at boot and is not (re)created here.
            try { FileSystem.CreateDirectoryRecursive(userAppTitle); } catch (ProsperoException) { }
            try { FileSystem.CreateDirectoryRecursive(userAppSceSys); } catch (ProsperoException) { }
            try
            {
                if (FileSystem.Exists(sourceSceSys))
                    FileSystem.CopyDirectory(sourceSceSys, userAppSceSys);
            }
            catch (ProsperoException) { }

            // 11. Copy the appmeta-classed files (param.sfo, param.json, .png, .dds, .at9) into
            //     /user/appmeta/<titleId>/. The shell only reads these file classes back for
            //     the title card and copying the whole sce_sys/ tree here leaves the shell
            //     scanning resource files it treats as broken metadata.
            CopyAppMetaFiles(sourceSceSys, userAppMeta);

            // 12. Register the title. The directed installer that names the /user/app/ install
            //     directory explicitly is present since firmware 5.x; firmware 12.00 and later
            //     drop it and only accept AppInstallAll, so the fallback runs when the directed
            //     call is unresolved or answers non-zero. A non-zero code from both is a hard
            //     failure the caller must see - the shell will not find a title id it never
            //     had a chance to record, and the follow-up launch would report a misleading
            //     "title is not installed" error instead of the real one.
            int installRc = -1;
            int titleDirByteCount = Encoding.UTF8.GetByteCount(userAppRoot);
            Span<byte> titleDirBytes = stackalloc byte[titleDirByteCount + 1];
            Encoding.UTF8.GetBytes(userAppRoot, titleDirBytes);
            titleDirBytes[titleDirByteCount] = 0;
            try
            {
                fixed (byte* pId = idBytes, pDir = titleDirBytes)
                    installRc = AppInstUtil.sceAppInstUtilAppInstallTitleDir(pId, pDir, null);
            }
            catch (EntryPointNotFoundException) { installRc = -1; }
            catch (DllNotFoundException) { installRc = -1; }
            if (installRc != 0)
                installRc = AppInstUtil.sceAppInstUtilAppInstallAll(null);
            if (installRc != 0)
                throw new ProsperoException(nameof(AppInstUtil.sceAppInstUtilAppInstallAll), installRc);

            // 13. Write mount.lnk - the source folder path with no trailing newline, so a
            //     later relaunch that reads the file re-resolves the same runtime folder
            //     without depending on the process that installed the title.
            try
            {
                string mountLnk = userAppTitle + "/mount.lnk";
                byte[] cwdBytes = Encoding.UTF8.GetBytes(sourceTrimmed);
                FileSystem.WriteAllBytes(mountLnk, cwdBytes);
            }
            catch (ProsperoException) { }

            // 14. Flush the installer service so the shell registry commits this install pass.
            //     A process that keeps the service open across install and launch reads the
            //     pre-install registry state on the launch call and answers "title is not
            //     installed"; ending the service and re-opening it commits the pending update.
            AppInstUtil.sceAppInstUtilTerminate();
            sessionOpen = false;
            int reinitRc = AppInstUtil.sceAppInstUtilInitialize();
            if (reinitRc != 0)
                throw new ProsperoException(nameof(AppInstUtil.sceAppInstUtilInitialize), reinitRc);
            sessionOpen = true;

            // 15. Wait until the installer service confirms the title is registered and no
            //     install pass is in flight, up to a two-second deadline. The shell publishes
            //     newly-installed titles asynchronously after the install call returns 0, and
            //     a launch call that lands before that publish reports "title is not
            //     installed" even though every file is on disk.
            WaitForTitleInstalled(idBytes);

            handle = new LaunchHandle(dst, titleId);
        }
        catch
        {
            // Undo the nullfs bind so the mount point does not survive the exception path.
            fixed (byte* pDst = dstBytes)
                KernelMount.unmount(pDst, 0);
            throw;
        }
        finally
        {
            // Close the installer session so the next caller's Initialize reads a clean state.
            // The flush pattern above may have already terminated it once and re-opened it;
            // this call closes whichever session is currently live. Errors on the teardown are
            // swallowed - the caller either sees the real failure the try block threw, or the
            // pass succeeded and there is nothing to surface.
            if (sessionOpen)
            {
                try { AppInstUtil.sceAppInstUtilTerminate(); }
                catch (ProsperoException) { }
            }
        }

        return handle;
    }

    /// <summary>
    /// Runs <see cref="Install"/> and then starts the installed application with
    /// <see cref="LaunchWithBindMount"/>. On failure of either half the mount point is
    /// unmounted before the exception surfaces so a caller does not have to clean up.
    /// </summary>
    /// <param name="sourceFolder">On-device folder carrying the application to install and launch.</param>
    /// <param name="titleId">The 9-character title id.</param>
    /// <param name="argv">Launch arguments, or null.</param>
    /// <param name="appOpt">Application option flags, or zero for the defaults.</param>
    /// <returns>A handle carrying the mount point, for <see cref="Unmount"/> after exit.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="sourceFolder"/> is empty, or <paramref name="titleId"/> is not 9 characters.
    /// </exception>
    /// <exception cref="ProsperoException">The install or launch failed.</exception>
    public static LaunchHandle InstallAndLaunch(string sourceFolder, string titleId,
        string[]? argv = null, uint appOpt = 0)
    {
        LaunchHandle installed = Install(sourceFolder, titleId);
        try
        {
            return LaunchWithBindMount(sourceFolder, titleId, argv, appOpt);
        }
        catch
        {
            try { Unmount(installed); } catch (ProsperoException) { }
            throw;
        }
    }

    /// <summary>
    /// Waits until the installer service answers "installed" for <paramref name="idBytes"/>, up
    /// to a two-second deadline. The shell publishes newly-installed titles asynchronously
    /// after the install call returns, and launching before that publish has landed answers
    /// "title is not installed" even though every file is on disk. Silent on deadline so a
    /// shell that never publishes still lets the launch call go through and surface its own
    /// error. The service-wide "install in flight" check runs alongside so a query that lands
    /// mid-commit does not read the pre-commit state.
    /// </summary>
    private static void WaitForTitleInstalled(ReadOnlySpan<byte> idBytes)
    {
        // The service expects a NUL-terminated title id string. idBytes is 9 bytes without a
        // terminator, so copy into a 10-byte buffer with the trailing zero.
        Span<byte> id = stackalloc byte[TitleIdLength + 1];
        for (int i = 0; i < TitleIdLength; i++)
            id[i] = idBytes[i];
        id[TitleIdLength] = 0;

        long deadlineMs = Environment.TickCount64 + 2000;
        while (Environment.TickCount64 < deadlineMs)
        {
            int exists = 0;
            int inInstalling = 0;
            int rcExists;
            int rcInstalling = AppInstUtil.sceAppInstUtilAppIsInInstalling(&inInstalling);
            fixed (byte* pId = id)
                rcExists = AppInstUtil.sceAppInstUtilAppExists(pId, &exists);

            // Ready when the service reports the title as installed AND no install pass is in
            // flight. A short-lived race where the commit lands between the two queries is
            // avoided by the AND, so the launch call sees a fully-committed shell state.
            if (rcExists == 0 && exists != 0 && rcInstalling == 0 && inInstalling == 0)
                return;

            System.Threading.Thread.Sleep(100);
        }
    }

    /// <summary>
    /// Copies the trophy binding, UDS binding, and <c>param.json</c> from the source
    /// <c>sce_sys</c> into <paramref name="systemDataMeta"/> so the shell registers the trophy
    /// set the first time the application launches. Failures are silent because the copy is
    /// best-effort and the shell treats the missing files the same as an application shipped
    /// without a trophy set.
    /// </summary>
    private static void CopyTrophyBindings(string sourceSceSys, string systemDataMeta)
    {
        try
        {
            string trophy2Dir = systemDataMeta + "/trophy2";
            string udsDir = systemDataMeta + "/uds";
            try { FileSystem.CreateDirectoryRecursive(systemDataMeta); } catch (ProsperoException) { }
            try { FileSystem.CreateDirectoryRecursive(trophy2Dir); } catch (ProsperoException) { }
            try { FileSystem.CreateDirectoryRecursive(udsDir); } catch (ProsperoException) { }

            string srcTrophy = sourceSceSys.TrimEnd('/') + "/trophy2/npbind.dat";
            if (FileSystem.Exists(srcTrophy))
                FileSystem.CopyFile(srcTrophy, trophy2Dir + "/npbind.dat");

            string srcUds = sourceSceSys.TrimEnd('/') + "/uds/npbind.dat";
            if (FileSystem.Exists(srcUds))
                FileSystem.CopyFile(srcUds, udsDir + "/npbind.dat");

            string srcParam = sourceSceSys.TrimEnd('/') + "/param.json";
            if (FileSystem.Exists(srcParam))
                FileSystem.CopyFile(srcParam, systemDataMeta + "/param.json");
        }
        catch (ProsperoException)
        {
        }
    }

    /// <summary>
    /// Copies the appmeta-classed files from <paramref name="sourceSceSys"/> into
    /// <paramref name="userAppMeta"/>: the SFO / JSON parameter file and every image and audio
    /// asset the shell reads back for the title card (<c>*.png</c>, <c>*.dds</c>, <c>*.at9</c>).
    /// Every other file in <c>sce_sys/</c> stays where it is; the shell rejects the appmeta
    /// tree if it carries files it does not expect.
    /// </summary>
    private static void CopyAppMetaFiles(string sourceSceSys, string userAppMeta)
    {
        try
        {
            try { FileSystem.CreateDirectoryRecursive(userAppMeta); } catch (ProsperoException) { }
            if (!FileSystem.Exists(sourceSceSys))
                return;
            if (!FileSystem.TryEnumerateDirectory(sourceSceSys, out IReadOnlyList<DirectoryEntry> entries, out _))
                return;

            foreach (DirectoryEntry entry in entries)
            {
                if (entry.Type == FileEntryType.Directory)
                    continue;
                if (!IsAppMetaFileName(entry.Name))
                    continue;
                string src = sourceSceSys.TrimEnd('/') + "/" + entry.Name;
                string dst = userAppMeta.TrimEnd('/') + "/" + entry.Name;
                try { FileSystem.CopyFile(src, dst); }
                catch (ProsperoException) { }
            }
        }
        catch (ProsperoException) { }
    }

    /// <summary>
    /// Reports whether <paramref name="name"/> is one the appmeta pass copies: the parameter
    /// files and the image / audio assets the shell reads for the title card.
    /// </summary>
    private static bool IsAppMetaFileName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return false;
        if (string.Equals(name, "param.sfo", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(name, "param.json", StringComparison.OrdinalIgnoreCase))
            return true;
        int dot = name.LastIndexOf('.');
        if (dot < 0)
            return false;
        string ext = name[dot..];
        return string.Equals(ext, ".png", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ext, ".dds", StringComparison.OrdinalIgnoreCase)
            || string.Equals(ext, ".at9", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Unmounts the bind mount created by <see cref="LaunchWithBindMount"/>. Call this after the
    /// launched application has exited.
    /// </summary>
    /// <param name="handle">The handle returned by <see cref="LaunchWithBindMount"/>.</param>
    /// <exception cref="ProsperoException">The unmount failed.</exception>
    public static void Unmount(LaunchHandle handle)
    {
        ArgumentException.ThrowIfNullOrEmpty(handle.MountPoint);
        int byteCount = Encoding.UTF8.GetByteCount(handle.MountPoint);
        Span<byte> path = byteCount < 512
            ? stackalloc byte[byteCount + 1]
            : new byte[byteCount + 1];
        Encoding.UTF8.GetBytes(handle.MountPoint, path);
        path[byteCount] = 0;

        fixed (byte* pPath = path)
        {
            if (KernelMount.unmount(pPath, 0) != 0)
            {
                int err = *KernelSystem.__error();
                throw new ProsperoException("unmount", SceResult.KernelFacility | (err & 0xFFFF));
            }
        }
    }

    /// <summary>
    /// Finds the process id of the running application with <paramref name="titleId"/> by walking the
    /// kernel's process table via <c>sysctl(KERN_PROC_PROC)</c> and checking each process with
    /// <c>sceKernelGetAppInfo</c>.
    /// </summary>
    /// <param name="titleId">The 9-character title id to look for.</param>
    /// <returns>The process id, or -1 if no running process owns that title id.</returns>
    /// <exception cref="ArgumentException"><paramref name="titleId"/> is not 9 characters.</exception>
    public static int FindAppPid(string titleId)
    {
        ArgumentException.ThrowIfNullOrEmpty(titleId);
        if (titleId.Length != TitleIdLength)
            throw new ArgumentException($"A title id is {TitleIdLength} characters.", nameof(titleId));

        Span<byte> target = stackalloc byte[TitleIdLength];
        Encoding.UTF8.GetBytes(titleId, target);

        // Query KERN_PROC_PROC for the buffer size. The FreeBSD sysctl convention for the
        // process walker is a four-element MIB terminated with a zero filter word; passing only
        // three elements makes the kernel treat the missing fourth word as random stack and
        // reject the call.
        int* mib = stackalloc int[4];
        mib[0] = CtlKern;
        mib[1] = KernProc;
        mib[2] = KernProcProc;
        mib[3] = 0;

        nuint size = 0;
        if (KernelSystem.sysctl(mib, 4, null, &size, null, 0) != 0)
            return -1;
        if (size == 0)
            return -1;

        // Add a margin because the process table can grow between calls.
        size += size / 8;

        byte* buf = (byte*)NativeMemory.Alloc(size);
        try
        {
            nuint actualSize = size;
            if (KernelSystem.sysctl(mib, 4, buf, &actualSize, null, 0) != 0)
                return -1;

            nuint offset = 0;
            while (offset + (nuint)KinfoProcPidOffset + sizeof(int) <= actualSize)
            {
                int entrySize = *(int*)(buf + offset); // ki_structsize at offset 0
                if (entrySize <= 0)
                    break;

                int pid = *(int*)(buf + offset + KinfoProcPidOffset);

                SceKernelAppInfo info = default;
                if (KernelProcess.sceKernelGetAppInfo(pid, &info) == 0)
                {
                    bool match = true;
                    for (int i = 0; i < TitleIdLength; i++)
                    {
                        if (info.TitleId[i] != target[i])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                        return pid;
                }

                offset += (nuint)entrySize;
            }

            return -1;
        }
        finally
        {
            NativeMemory.Free(buf);
        }
    }

    /// <summary>
    /// Remounts <c>/system_ex</c> as read-write. This is required once per boot before creating
    /// directories under <c>/system_ex/app/</c>.
    /// </summary>
    private static void RemountSystemExReadWrite()
    {
        // The nmount call remounts /system_ex read-write with the platform's own exfatfs options:
        //   fstype=exfatfs  fspath=/system_ex  from=/dev/ssd0.system_ex
        //   large=yes  timezone=static  async=(none)  ignoreacl=(none)
        //   Flag: MNT_UPDATE

        SceIovec* iov = stackalloc SceIovec[16];

        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vExfatfs = stackalloc byte[] {
            (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* vSystemEx = stackalloc byte[] {
            (byte)'/', (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m',
            (byte)'_', (byte)'e', (byte)'x', 0 };
        byte* kFrom = stackalloc byte[] {
            (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* vFrom = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/', (byte)'s', (byte)'s',
            (byte)'d', (byte)'0', (byte)'.', (byte)'s', (byte)'y', (byte)'s', (byte)'t',
            (byte)'e', (byte)'m', (byte)'_', (byte)'e', (byte)'x', 0 };
        byte* kLarge = stackalloc byte[] {
            (byte)'l', (byte)'a', (byte)'r', (byte)'g', (byte)'e', 0 };
        byte* vYes = stackalloc byte[] {
            (byte)'y', (byte)'e', (byte)'s', 0 };
        byte* kTimezone = stackalloc byte[] {
            (byte)'t', (byte)'i', (byte)'m', (byte)'e', (byte)'z', (byte)'o', (byte)'n',
            (byte)'e', 0 };
        byte* vStatic = stackalloc byte[] {
            (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'i', (byte)'c', 0 };
        byte* kAsync = stackalloc byte[] {
            (byte)'a', (byte)'s', (byte)'y', (byte)'n', (byte)'c', 0 };
        byte* kIgnoreacl = stackalloc byte[] {
            (byte)'i', (byte)'g', (byte)'n', (byte)'o', (byte)'r', (byte)'e', (byte)'a',
            (byte)'c', (byte)'l', 0 };

        KernelMount.SetPair(&iov[0], kFstype, 7, vExfatfs, 8);
        KernelMount.SetPair(&iov[2], kFspath, 7, vSystemEx, 11);
        KernelMount.SetPair(&iov[4], kFrom, 5, vFrom, 20);
        KernelMount.SetPair(&iov[6], kLarge, 6, vYes, 4);
        KernelMount.SetPair(&iov[8], kTimezone, 9, vStatic, 7);
        KernelMount.SetFlag(&iov[10], kAsync, 6);
        KernelMount.SetFlag(&iov[12], kIgnoreacl, 10);

        // Pair 7 (iov[14..15]) is unused — 7 pairs = 14 entries.
        if (KernelMount.nmount(iov, 14, KernelMount.MntUpdate) != 0)
        {
            int err = *KernelSystem.__error();
            throw new ProsperoException("nmount(system_ex, MNT_UPDATE)", SceResult.KernelFacility | (err & 0xFFFF));
        }
    }

    /// <summary>
    /// Performs a nullfs bind mount of <paramref name="source"/> at <paramref name="target"/>.
    /// </summary>
    /// <returns>Zero on success, or -1 on error.</returns>
    private static int MountNullfs(byte* source, byte* target)
    {
        SceIovec* iov = stackalloc SceIovec[6];

        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vNullfs = stackalloc byte[] {
            (byte)'n', (byte)'u', (byte)'l', (byte)'l', (byte)'f', (byte)'s', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kFrom = stackalloc byte[] {
            (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };

        KernelMount.SetPair(&iov[0], kFstype, 7, vNullfs, 7);
        KernelMount.SetPair(&iov[2], kFspath, 7, target, KernelMount.StringLength(target) + 1);
        KernelMount.SetPair(&iov[4], kFrom, 5, source, KernelMount.StringLength(source) + 1);

        return KernelMount.nmount(iov, 6, 0);
    }
}
