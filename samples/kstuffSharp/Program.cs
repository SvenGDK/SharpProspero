// Loader payload. Maps the separately-built installer ELF (InstallerBlob) into memory,
// calls its entry point (which installs the kernel module), then proceeds with the
// post-install steps: app.db patching (gated on *payloadout == 0), ShellUI trophy-patch
// monitor thread, /system_ex remount, disc-image mounting, and a persistent USB event loop.
// The installer binary handles the kekcall liveness check internally and returns early
// when the kernel module is already loaded from a previous run.

using System;
using System.Runtime.InteropServices;

using SharpProspero.Payload;
using SharpProspero.Payload.Bypass;
using SharpProspero.Payload.Elf;
using SharpProspero.Payload.IO;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Orchestration;
using SharpProspero.Payload.Posix;
using SharpProspero.Payload.Process;
using SharpProspero.Payload.Services;

namespace SampleApp;

internal static unsafe class Program
{
    // ---- FreeBSD constants ----

    private const int MaxPath = 1024;
    private const int F_OK = 0;

    // ---- Kernel structure offsets ----

    /// <summary>Offset of <c>p_dynlib</c> in <c>struct proc</c>.</summary>
    private const ulong ProcDynlib = 0x3e8;

    // ---- Shared state for background threads ----

    /// <summary>Kernel I/O primitive for process inspection.</summary>
    private static PayloadKernelIo s_io;

    /// <summary>PID of SceSysCore.elf for the ShellUI monitor.</summary>
    private static int s_sysCorePid;

    /// <summary>Firmware major.minor for vmspace offset lookups in background threads.</summary>
    private static uint s_fwMajorMinor;

    /// <summary>DMAP base for physical memory access in background threads.</summary>
    private static ulong s_dmapBase;

    /// <summary>
    /// Set during title scanning to prevent kqueue filesystem events triggered by the
    /// mount operations from causing re-entrant scanning.
    /// </summary>
    private static bool s_isMounting;

    // ---- LVD device control structures ----
    // These match the kernel's lvd_kernel_layer_t and lvd_ioctl_attach_t as defined in the
    // loader source. The SDK's LvdIoctlAttach has a different field layout (missing the
    // option_len/secondary_sector_size fields), so the correct structures are defined here.

    /// <summary>LVD layer descriptor for vnode-backed virtual disk images.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct LvdLayer
    {
        public ushort SourceType;
        public byte EntryFlags;
        public byte Reserved0;
        public uint Reserved1;
        public byte* Path;
        public ulong Offset;
        public ulong Size;
        public byte* BitmapPath;
        public ulong BitmapOffset;
        public ulong BitmapSize;
    }

    /// <summary>LVD attach ioctl request.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct LvdAttachRequest
    {
        public uint IoVersion;
        public int DeviceId;
        public uint SectorSize0;
        public uint SectorSize1;
        public ushort OptionLen;
        public ushort ImageType;
        public uint LayerCount;
        public ulong DeviceSize;
        public LvdLayer* LayersPtr;
    }

    // ---- Entry point ----

    [UnmanagedCallersOnly(EntryPoint = "__managed__Main")]
    public static int Main(void* args)
    {
        // ---- Step 1: Initialize ----
        // Read payload args, set process name, read firmware version.

        PayloadCrt.Klog("kstuff: start\n\0"u8);

        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null)
        {
            PayloadCrt.Klog("kstuff: no payload args\n\0"u8);
            PayloadNotification.SendKernelNotification("kstuff: no payload args"u8);
            return -1;
        }

        fixed (byte* name = "kstuff.elf\0"u8)
            PayloadProcessControl.sceKernelSetProcessName(name);

        PayloadCrt.Klog("kstuff: args ok\n\0"u8);

        PayloadKernelIo io = new(pargs);
        s_io = io;

        uint fw = PayloadKernel.GetFirmwareVersion(io);
        s_fwMajorMinor = (fw >> 16) & 0xFFFF;
        if (fw == 0)
        {
            PayloadCrt.Klog("kstuff: firmware version read failed\n\0"u8);
            PayloadNotification.SendKernelNotification("kstuff: firmware version read failed"u8);
            return -1;
        }
        PayloadCrt.Klog("kstuff: firmware version read ok\n\0"u8);

        // Read the DMAP base for physical memory access (needed by trophy patcher thread).
        PayloadCrt.Klog("sp:init:dmap\n\0"u8);
        ulong kdataBase = pargs->KernelDataBase;
        long pmapOff = KernelOffsets.KernelPmapStore(fw);
        if (pmapOff == 0)
        {
            PayloadCrt.Klog("kstuff: pmap offset missing for this firmware\n\0"u8);
            PayloadNotification.SendKernelNotification("kstuff: unsupported firmware for pmap"u8);
            return -1;
        }
        ulong pmapStore = kdataBase + (ulong)pmapOff;
        ulong dmapVirt = io.ReadU64(pmapStore + 32);
        ulong pmCr3 = io.ReadU64(pmapStore + 40);
        s_dmapBase = dmapVirt - pmCr3;
        PayloadCrt.Klog("sp:init:dmap:ok\n\0"u8);

        // ---- Step 2: Load and run the installer binary ----
        // Runs BEFORE dlsym enablement. The installer uses CRT syscalls and kernel
        // R/W only — no dlsym needed. The dlsym enablement widens eboot segments to
        // 0..MAX, which marks all addresses as XO text. NativeAOT code does RIP-relative
        // data reads from .text, so calling the installer after XO widening triggers
        // SYSTEM_XO_VIOLATION. The original avoids this because its installer is a flat
        // binary with no RIP-relative data reads.
        PayloadCrt.Klog("kstuff: loading installer\n\0"u8);
        if (!InstallerLoader.LoadAndRun(pargs))
        {
            PayloadCrt.Klog("kstuff: installer load failed\n\0"u8);
            return -1;
        }

        // ---- Step 3: Enable dlsym on 5.00+ ----
        // Widen the eboot segment range so sceKernelDlsym can resolve symbols from the
        // calling process's own image. Done AFTER the installer returns so the XO widening
        // does not affect the installer's NativeAOT code. Needed by app.db patching which
        // uses dlopen/dlsym to load libsqlite3.sprx.
        PayloadCrt.Klog("sp:dlsym:getpid\n\0"u8);
        int ownPid = PayloadProcessControl.getpid();
        if (ownPid > 0)
        {
            ulong proc = PayloadKernel.WalkAllprocForPid(io, ownPid);
            if (proc != 0)
            {
                PayloadCrt.Klog("sp:dlsym:proc\n\0"u8);
                ulong pDynlib = io.ReadU64(proc + ProcDynlib);
                if (pDynlib != 0)
                {
                    PayloadCrt.Klog("sp:dlsym:dynlib\n\0"u8);
                    ulong dynlibEboot = io.ReadU64(pDynlib);
                    if (dynlibEboot != 0)
                    {
                        PayloadCrt.Klog("sp:dlsym:eboot\n\0"u8);
                        ulong ebootSegments = io.ReadU64(dynlibEboot + 0x40);
                        if (ebootSegments != 0)
                        {
                            PayloadCrt.Klog("sp:dlsym:segments\n\0"u8);
                            io.WriteU64(ebootSegments + 0x08, 0);
                            io.WriteU64(ebootSegments + 0x10, 0xFFFF_FFFF_FFFF_FFFF);
                            PayloadCrt.Klog("kstuff: dlsym enabled\n\0"u8);
                        }
                    }
                }
            }
        }

        // ---- Step 4: Patch App.db ----
        // Gated on *payloadout == 0, matching the original. The installer leaves
        // payloadout at its initial value (0) on success or early return.
        if (*pargs->Payloadout == 0)
        {
            PayloadCrt.Klog("kstuff: patching app.db\n\0"u8);
            *pargs->Payloadout = PatchAppDb();
        }

        // ---- Step 5: ShellUI trophy patch monitor ----
        // Spawns a background thread that patches the running SceShellUI process's trophy
        // availability functions, then monitors SceSysCore.elf for fork/exec events and
        // re-applies the patches to new SceShellUI instances after rest-mode resume.
        // The initial patch happens inside the thread, matching the C implementation.

        StartShellUiMonitor(io);

        // ---- Step 6: Mount images ----
        // Remounts /system_ex as read-write with the exFAT filesystem driver, scans /user/app
        // for mount.lnk files, mounts referenced disc images (UFS/PFS/PFSC/exFAT) with nested
        // image support, and bind-mounts via nullfs.

        if (AutomountDisabled())
        {
            PayloadCrt.Klog("kstuff: automount disabled\n\0"u8);
        }
        else
        {
            PayloadCrt.Klog("kstuff: remounting /system_ex rw\n\0"u8);
            RemountSystemEx();

            PayloadCrt.Klog("kstuff: scanning titles\n\0"u8);
            ScanAndMountTitles();
        }

        // ---- Step 7: Success notification ----

        PayloadCrt.Klog("kstuff: ready\n\0"u8);
        PayloadNotification.SendKernelNotification("kstuff: ready"u8);

        // Enter the persistent USB/filesystem event monitor loop. This is unconditional:
        // the monitor watches for USB attach/detach events and re-scans titles regardless
        // of the automount sentinel file, because the sentinel may be removed at runtime.
        PayloadCrt.Klog("kstuff: entering usb monitor loop\n\0"u8);
        MonitorUsbChanges();

        return 0;
    }

    // ---- ShellUI monitor ----

    /// <summary>
    /// Spawns a background pthread that patches the running SceShellUI process's trophy
    /// availability checks and then monitors SceSysCore.elf for fork/exec events to
    /// re-apply patches to new SceShellUI instances after rest-mode resume. The initial
    /// patch on the currently running SceShellUI is performed inside the background thread,
    /// not on the main thread, matching the C implementation which retries the library
    /// handle lookup every 500ms for up to 30 seconds.
    /// </summary>
    private static void StartShellUiMonitor(PayloadKernelIo io)
    {
        // Spawn the background monitor thread. The thread patches the currently
        // running SceShellUI FIRST, then sets up the kqueue monitor for SceSysCore.elf.
        // This ordering matches the C reference where the initial patch is applied
        // before the SceSysCore.elf lookup, so the initial patch succeeds even if
        // SceSysCore.elf is not found.
        nint thread = 0;
        fixed (byte* threadName = "shellui_mon\0"u8)
        {
            int rc = PayloadThread.Create(
                &thread, null, &ShellUiMonitorThreadEntry, null, threadName);
            if (rc == 0)
            {
                PayloadThread.scePthreadDetach(thread);
                PayloadCrt.Klog("kstuff: shellui monitor thread started\n\0"u8);
            }
            else
            {
                PayloadCrt.Klog("kstuff: shellui monitor thread creation failed\n\0"u8);
            }
        }
    }

    /// <summary>
    /// Thread entry point for the ShellUI monitor. Performs the initial patch on the
    /// currently running SceShellUI (with retry), then delegates to the SDK's
    /// <see cref="PayloadShellUiMonitor.Run"/> which watches SceSysCore.elf for
    /// fork/exec events and re-applies trophy patches to new SceShellUI instances.
    /// </summary>
    [UnmanagedCallersOnly]
    private static void* ShellUiMonitorThreadEntry(void* arg)
    {
        PayloadCrt.Klog("sp:shellui:thread:start\n\0"u8);

        fixed (byte* shellUiName = "SceShellUI\0"u8)
        {
            PayloadCrt.Klog("sp:shellui:find:pid\n\0"u8);
            int shellUiPid = PayloadSysctl.FindPidByName(shellUiName);
            if (shellUiPid > 0)
            {
                PayloadCrt.Klog("sp:shellui:patch:start\n\0"u8);
                PayloadShellUiPatcher.PatchTrophyChecks(s_io, shellUiPid, s_dmapBase, s_fwMajorMinor);
                PayloadCrt.Klog("sp:shellui:patch:ok\n\0"u8);
                PayloadCrt.Klog("kstuff: shellui patched\n\0"u8);
            }
            else
            {
                PayloadCrt.Klog("sp:shellui:patch:nopid\n\0"u8);
                PayloadCrt.Klog("kstuff: SceShellUI not found for initial patch\n\0"u8);
            }
        }

        PayloadCrt.Klog("sp:shellui:syscore:find\n\0"u8);
        fixed (byte* sysCoreName = "SceSysCore.elf\0"u8)
        {
            s_sysCorePid = PayloadSysctl.FindPidByName(sysCoreName);
        }
        if (s_sysCorePid <= 0)
        {
            PayloadCrt.Klog("sp:shellui:syscore:fail\n\0"u8);
            PayloadCrt.Klog("kstuff: SceSysCore.elf not found, monitor skipped\n\0"u8);
            return null;
        }

        PayloadCrt.Klog("sp:shellui:monitor:start\n\0"u8);
        PayloadShellUiMonitor.Run(s_io, s_sysCorePid, s_dmapBase, s_fwMajorMinor);
        return null;
    }

    // ---- App.db DRM type patch + trigger installation ----

    /// <summary>
    /// Patches the application database: updates existing DRM types and installs persistent
    /// triggers for automatic correction of disc-type entries on future inserts/updates.
    /// </summary>
    private static int PatchAppDb()
    {
        PayloadCrt.Klog("sp:appdb:load\n\0"u8);
        PayloadAppDbPatcher.SqliteFunctions fns = PayloadAppDbPatcher.LoadSqlite();
        if (fns.Open == 0)
        {
            PayloadCrt.Klog("sp:appdb:load:fail\n\0"u8);
            PayloadCrt.Klog("kstuff: sqlite3 load failed, skipping app.db patch\n\0"u8);
            return -1;
        }
        PayloadCrt.Klog("sp:appdb:load:ok\n\0"u8);

        PayloadCrt.Klog("sp:appdb:triggers:start\n\0"u8);
        int trigResult = InstallDrmTriggers(fns);
        PayloadCrt.Klog("sp:appdb:triggers:done\n\0"u8);
        return trigResult;
    }

    /// <summary>
    /// Enumerates all tables in app.db matching <c>tbl_iconinfo_*</c> and installs persistent
    /// SQLite triggers that automatically correct the DRM type on insert and update operations.
    /// For each matching table, creates:
    /// <list type="bullet">
    /// <item><c>trig_update_drm_&lt;table&gt;</c>: after update of appDrmType, if new value is 1
    /// (disc), changes it to 5 (digital).</item>
    /// <item><c>trig_insert_drm_&lt;table&gt;</c>: after insert with appDrmType = 1, changes
    /// it to 5.</item>
    /// </list>
    /// Also performs a bulk update of existing rows in each matching table.
    /// </summary>
    private static int InstallDrmTriggers(PayloadAppDbPatcher.SqliteFunctions fns)
    {
        // Resolve sqlite3_column_text from the already-loaded libsqlite3.sprx.
        byte* libName = stackalloc byte[] {
            (byte)'l', (byte)'i', (byte)'b', (byte)'s', (byte)'q', (byte)'l', (byte)'i',
            (byte)'t', (byte)'e', (byte)'3', (byte)'.', (byte)'s', (byte)'p', (byte)'r',
            (byte)'x', 0 };
        byte* symColumnText = stackalloc byte[] {
            (byte)'s', (byte)'q', (byte)'l', (byte)'i', (byte)'t', (byte)'e', (byte)'3',
            (byte)'_', (byte)'c', (byte)'o', (byte)'l', (byte)'u', (byte)'m', (byte)'n',
            (byte)'_', (byte)'t', (byte)'e', (byte)'x', (byte)'t', 0 };

        PayloadCrt.Klog("sp:triggers:dlopen\n\0"u8);
        void* sqliteHandle = PayloadDlfcn.Dlopen(libName, PayloadDlfcn.RtldLazy);
        if (sqliteHandle == null) { PayloadCrt.Klog("sp:triggers:dlopen:fail\n\0"u8); return -1; }

        PayloadCrt.Klog("sp:triggers:dlsym\n\0"u8);
        void* colTextAddr = PayloadDlfcn.Dlsym(sqliteHandle, symColumnText);
        if (colTextAddr == null) { PayloadCrt.Klog("sp:triggers:dlsym:fail\n\0"u8); return -1; }

        var openFn = (delegate* unmanaged<byte*, nint*, int, nint, int>)fns.Open;
        var prepareFn = (delegate* unmanaged<nint, byte*, int, nint*, byte**, int>)fns.Prepare;
        var stepFn = (delegate* unmanaged<nint, int>)fns.Step;
        var finalizeFn = (delegate* unmanaged<nint, int>)fns.Finalize;
        var execFn = (delegate* unmanaged<nint, byte*, nint, nint, nint*, int>)fns.Exec;
        var closeFn = (delegate* unmanaged<nint, int>)fns.Close;
        var columnTextFn = (delegate* unmanaged<nint, int, byte*>)colTextAddr;

        PayloadCrt.Klog("sp:triggers:open\n\0"u8);
        nint db = 0;
        fixed (byte* dbPath = PayloadAppDbPatcher.AppDbPath)
        {
            if (openFn(dbPath, &db, 2 /* SQLITE_OPEN_READWRITE */, 0) != 0)
            { PayloadCrt.Klog("sp:triggers:open:fail\n\0"u8); return -1; }
        }
        PayloadCrt.Klog("sp:triggers:open:ok\n\0"u8);

        PayloadCrt.Klog("sp:triggers:query\n\0"u8);
        byte* query = stackalloc byte[] {
            (byte)'s', (byte)'e', (byte)'l', (byte)'e', (byte)'c', (byte)'t', (byte)' ',
            (byte)'t', (byte)'b', (byte)'l', (byte)'_', (byte)'n', (byte)'a', (byte)'m',
            (byte)'e', (byte)' ', (byte)'f', (byte)'r', (byte)'o', (byte)'m', (byte)' ',
            (byte)'s', (byte)'q', (byte)'l', (byte)'i', (byte)'t', (byte)'e', (byte)'_',
            (byte)'m', (byte)'a', (byte)'s', (byte)'t', (byte)'e', (byte)'r', (byte)' ',
            (byte)'w', (byte)'h', (byte)'e', (byte)'r', (byte)'e', (byte)' ', (byte)'t',
            (byte)'y', (byte)'p', (byte)'e', (byte)' ', (byte)'=', (byte)' ', (byte)'\'',
            (byte)'t', (byte)'a', (byte)'b', (byte)'l', (byte)'e', (byte)'\'', (byte)';',
            0 };

        nint stmt = 0;
        if (prepareFn(db, query, -1, &stmt, null) != 0)
        {
            PayloadCrt.Klog("sp:triggers:prepare:fail\n\0"u8);
            return -1;
        }

        byte* sqlBuf = stackalloc byte[4096];

        const int SqliteRow = 100;

        while (stepFn(stmt) == SqliteRow)
        {
            byte* tblName = columnTextFn(stmt, 0);
            if (tblName == null) continue;

            if (!StartsWith(tblName, "tbl_iconinfo_"u8)) continue;
            PayloadCrt.Klog("sp:triggers:table\n\0"u8);

            int nameLen = StringLength(tblName);

            // Trigger 1: after update of appDrmType when new.appDrmType = 1 -> set to 5.
            int pos = 0;
            AppendLiteral(sqlBuf, ref pos, "create trigger if not exists trig_update_drm_"u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " after update of appDrmType on "u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " when new.appDrmType = 1 begin update "u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " set appDrmType = 5 where titleId = old.titleId; end;"u8);
            sqlBuf[pos] = 0;
            if (execFn(db, sqlBuf, 0, 0, null) != 0)
                PayloadCrt.Klog("sp:triggers:exec1:fail\n\0"u8);

            pos = 0;
            AppendLiteral(sqlBuf, ref pos, "create trigger if not exists trig_insert_drm_"u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " after insert on "u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " when new.appDrmType = 1 begin update "u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " set appDrmType = 5 where titleId = new.titleId; end;"u8);
            sqlBuf[pos] = 0;
            if (execFn(db, sqlBuf, 0, 0, null) != 0)
                PayloadCrt.Klog("sp:triggers:exec2:fail\n\0"u8);

            pos = 0;
            AppendLiteral(sqlBuf, ref pos, "update "u8);
            CopyBytes(sqlBuf, ref pos, tblName, nameLen);
            AppendLiteral(sqlBuf, ref pos, " set appDrmType=5 where appDrmType=1;"u8);
            sqlBuf[pos] = 0;
            if (execFn(db, sqlBuf, 0, 0, null) != 0)
                PayloadCrt.Klog("sp:triggers:exec3:fail\n\0"u8);
        }

        finalizeFn(stmt);
        PayloadCrt.Klog("kstuff: app.db triggers installed\n\0"u8);
        return 0;
    }

    // ---- Automount check ----

    /// <summary>
    /// Returns <see langword="true"/> when the sentinel file <c>/data/.kstuff_noautomount</c>
    /// exists, indicating that automatic title mounting is disabled.
    /// </summary>
    private static bool AutomountDisabled()
    {
        fixed (byte* path = "/data/.kstuff_noautomount\0"u8)
            return PayloadFileSystem.access(path, F_OK) == 0;
    }

    // ---- /system_ex remount ----

    /// <summary>
    /// Remounts <c>/system_ex</c> read-write using the exFAT filesystem driver on the
    /// <c>/dev/ssd0.system_ex</c> partition. The MNT_UPDATE flag updates the existing
    /// mount in place without unmounting.
    /// </summary>
    private static void RemountSystemEx()
    {
        PayloadCrt.Klog("sp:remount:start\n\0"u8);
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* vFrom = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/', (byte)'s', (byte)'s',
            (byte)'d', (byte)'0', (byte)'.', (byte)'s', (byte)'y', (byte)'s', (byte)'t',
            (byte)'e', (byte)'m', (byte)'_', (byte)'e', (byte)'x', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* vFspath = stackalloc byte[] {
            (byte)'/', (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m',
            (byte)'_', (byte)'e', (byte)'x', 0 };
        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vExfatfs = stackalloc byte[] {
            (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
        byte* kLarge = stackalloc byte[] {
            (byte)'l', (byte)'a', (byte)'r', (byte)'g', (byte)'e', 0 };
        byte* vYes = stackalloc byte[] { (byte)'y', (byte)'e', (byte)'s', 0 };
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

        FreeBsdIovec* iov = stackalloc FreeBsdIovec[14];
        PayloadMount.SetIovecPair(&iov[0], kFrom, 5, vFrom, 20);
        PayloadMount.SetIovecPair(&iov[2], kFspath, 7, vFspath, 11);
        PayloadMount.SetIovecPair(&iov[4], kFstype, 7, vExfatfs, 8);
        PayloadMount.SetIovecPair(&iov[6], kLarge, 6, vYes, 4);
        PayloadMount.SetIovecPair(&iov[8], kTimezone, 9, vStatic, 7);
        PayloadMount.SetIovecFlag(&iov[10], kAsync, 6);
        PayloadMount.SetIovecFlag(&iov[12], kIgnoreacl, 10);

        int remountRc = PayloadMount.nmount(iov, 14, PayloadMount.MntUpdate);
        if (remountRc == 0)
            PayloadCrt.Klog("sp:remount:done\n\0"u8);
        else
            PayloadCrt.Klog("sp:remount:fail\n\0"u8);
    }

    // ---- Title scanning and mounting ----

    /// <summary>
    /// Scans <c>/user/app</c> for title directories containing <c>mount.lnk</c> files and
    /// bind-mounts their referenced source paths (with image detection and mounting) into
    /// <c>/system_ex/app</c>.
    /// </summary>
    private static void ScanAndMountTitles()
    {
        PayloadCrt.Klog("sp:scan:start\n\0"u8);
        s_isMounting = true;

        // Create base mount directories. Each mkdir is idempotent (EEXIST is ignored).
        fixed (byte* imgmnt = "/data/imgmnt\0"u8)
            PayloadFileSystem.mkdir(imgmnt, 0x1FF);
        fixed (byte* ufsmnt = "/data/imgmnt/ufsmnt\0"u8)
            PayloadFileSystem.mkdir(ufsmnt, 0x1FF);
        fixed (byte* pfsmnt = "/data/imgmnt/pfsmnt\0"u8)
            PayloadFileSystem.mkdir(pfsmnt, 0x1FF);
        fixed (byte* pfscmnt = "/data/imgmnt/pfscmnt\0"u8)
            PayloadFileSystem.mkdir(pfscmnt, 0x1FF);
        fixed (byte* exfatmnt = "/data/imgmnt/exfatmnt\0"u8)
            PayloadFileSystem.mkdir(exfatmnt, 0x1FF);

        fixed (byte* appDir = "/user/app\0"u8)
        {
            void* dir = PayloadFileSystem.opendir(appDir);
            if (dir == null)
            {
                PayloadCrt.Klog("kstuff: failed to open /user/app\n\0"u8);
                s_isMounting = false;
                return;
            }

            byte* mountLnkPath = stackalloc byte[MaxPath];
            byte* srcPath = stackalloc byte[MaxPath];

            while (true)
            {
                FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
                if (entry == null) break;

                // Title directories have exactly 9-character names (e.g. "CUSA12345").
                int nameLen = StringLength(entry->d_name);
                if (nameLen != 9) continue;

                // Build path: /user/app/<titleId>/mount.lnk
                int pos = 0;
                AppendLiteral(mountLnkPath, ref pos, "/user/app/"u8);
                CopyBytes(mountLnkPath, ref pos, entry->d_name, nameLen);
                AppendLiteral(mountLnkPath, ref pos, "/mount.lnk"u8);
                mountLnkPath[pos] = 0;

                FreeBsdStat st = default;
                if (PayloadFileSystem.stat(mountLnkPath, &st) != 0)
                    continue;

                if (ReadMountLink(mountLnkPath, srcPath, MaxPath) != 0)
                    continue;

                PayloadCrt.Klog("sp:scan:title\n\0"u8);
                BindMountTitle(entry->d_name, nameLen, srcPath);
            }

            PayloadFileSystem.closedir(dir);
        }

        s_isMounting = false;
        PayloadCrt.Klog("sp:scan:done\n\0"u8);
    }

    /// <summary>
    /// Reads a mount.lnk file and returns the NUL-terminated source path.
    /// The file content is read as-is; no whitespace stripping is applied because the
    /// mount.lnk files written by the system contain only the path with no trailing
    /// whitespace or newline characters.
    /// </summary>
    private static int ReadMountLink(byte* path, byte* outBuf, int outSize)
    {
        PayloadCrt.Klog("sp:lnk:open\n\0"u8);
        int fd = PayloadIo.open(path, PayloadFileSystem.O_RDONLY);
        if (fd < 0)
        {
            PayloadCrt.Klog("sp:lnk:fail\n\0"u8);
            return -1;
        }

        for (int i = 0; i < outSize; i++)
            outBuf[i] = 0;

        PayloadCrt.Klog("sp:lnk:read\n\0"u8);
        long n = PayloadIo.read(fd, outBuf, (nuint)(outSize - 1));
        PayloadIo.close(fd);

        if (n < 0)
        {
            PayloadCrt.Klog("sp:lnk:fail\n\0"u8);
            return -1;
        }

        PayloadCrt.Klog("sp:lnk:ok\n\0"u8);
        return 0;
    }

    /// <summary>
    /// Bind-mounts a title source path to <c>/system_ex/app/&lt;titleId&gt;</c>. Detects and
    /// mounts disc images in the source directory, including nested images inside PFSC
    /// containers, before performing the nullfs bind mount.
    /// </summary>
    private static void BindMountTitle(byte* titleId, int titleIdLen, byte* srcPath)
    {
        PayloadCrt.Klog("sp:bind:check\n\0"u8);
        if (AutomountDisabled()) return;

        // Build the target path: /system_ex/app/<titleId>
        byte* dstPath = stackalloc byte[MaxPath];
        int pos = 0;
        AppendLiteral(dstPath, ref pos, "/system_ex/app/"u8);
        CopyBytes(dstPath, ref pos, titleId, titleIdLen);
        dstPath[pos] = 0;

        // Check if already mounted by probing for sce_sys inside the target.
        byte* checkPath = stackalloc byte[MaxPath];
        int cpos = 0;
        CopyBytes(checkPath, ref cpos, dstPath, pos);
        AppendLiteral(checkPath, ref cpos, "/sce_sys"u8);
        checkPath[cpos] = 0;

        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(checkPath, &st) == 0)
        {
            PayloadCrt.Klog("sp:bind:already\n\0"u8);
            return; // Already mounted.
        }

        PayloadCrt.Klog("sp:bind:unmount\n\0"u8);
        PayloadMount.unmount(dstPath, 0);

        // Create the target directory. mkdir returns -1 with EEXIST if it already exists,
        // which is acceptable. Any other failure aborts the mount.
        PayloadCrt.Klog("sp:bind:mkdir\n\0"u8);
        if (PayloadFileSystem.mkdir(dstPath, 0x1ED) != 0) // 0755
        {
            // Check if the directory exists despite the failure (EEXIST case).
            FreeBsdStat mkst = default;
            if (PayloadFileSystem.stat(dstPath, &mkst) != 0)
            {
                PayloadCrt.Klog("kstuff: failed to create title mount dir\n\0"u8);
                return;
            }
        }

        // Attempt to detect and mount a disc image in the source directory.
        PayloadCrt.Klog("sp:bind:image\n\0"u8);
        byte* mountedSrc = stackalloc byte[MaxPath];
        if (MountSource(srcPath, mountedSrc))
        {
            // Use the mounted image path as the nullfs source.
            if (PayloadMount.MountNullfs(mountedSrc, dstPath) == 0)
            {
                PayloadCrt.Klog("sp:bind:nullfs:ok\n\0"u8);
                PayloadCrt.Klog("kstuff: title mounted\n\0"u8);
                return;
            }

            // Nullfs failed: clean up with both PFSC-style and PFS-style unmount.
            PayloadCrt.Klog("sp:bind:nullfs:fail\n\0"u8);
            // PFSC cleanup: force unmount + rmdir.
            PayloadMount.unmount(mountedSrc, PayloadMount.MntForce);
            PayloadFileSystem.rmdir(mountedSrc);
            // PFS cleanup: sceFsUmountSaveData + rmdir.
            UmountSaveDataOpt uopt = default;
            PayloadPfsMount.sceFsInitUmountSaveDataOpt(&uopt);
            PayloadPfsMount.sceFsUmountSaveData(&uopt, mountedSrc, -1, 1);
            PayloadFileSystem.rmdir(mountedSrc);
            PayloadCrt.Klog("kstuff: nullfs bind mount failed\n\0"u8);
            return;
        }

        // No image found or image mount failed: bind-mount the source folder directly.
        PayloadCrt.Klog("sp:bind:folder\n\0"u8);
        CopyString(mountedSrc, srcPath);
        if (PayloadMount.MountNullfs(mountedSrc, dstPath) == 0)
            PayloadCrt.Klog("kstuff: title mounted (folder)\n\0"u8);
    }

    /// <summary>
    /// Detects a disc image in <paramref name="srcPath"/>, mounts it, and writes the
    /// mount point path to <paramref name="outMountedPath"/>. Supports UFS, PFS, PFSC
    /// (including nested images), and exFAT image types.
    /// </summary>
    /// <returns><see langword="true"/> if an image was found and mounted.</returns>
    private static bool MountSource(byte* srcPath, byte* outMountedPath)
    {
        byte* imagePath = stackalloc byte[MaxPath];
        PayloadImageMount.ImageType imgType =
            PayloadImageMount.FindImageInDirectory(srcPath, imagePath, MaxPath);

        if (imgType == PayloadImageMount.ImageType.Unknown)
            return false;

        byte* mountPoint = stackalloc byte[MaxPath];

        switch (imgType)
        {
            case PayloadImageMount.ImageType.Ufs:
                PayloadCrt.Klog("sp:mount:detect:ufs\n\0"u8);
                if (MountUfsImage(imagePath, mountPoint))
                {
                    CopyString(outMountedPath, mountPoint);
                    return true;
                }
                break;

            case PayloadImageMount.ImageType.Pfs:
                PayloadCrt.Klog("sp:mount:detect:pfs\n\0"u8);
                if (MountPfsImage(imagePath, mountPoint))
                {
                    CopyString(outMountedPath, mountPoint);
                    return true;
                }
                break;

            case PayloadImageMount.ImageType.Pfsc:
                PayloadCrt.Klog("sp:mount:detect:pfsc\n\0"u8);
                if (MountPfscImage(imagePath, mountPoint))
                {
                    // Scan for nested images inside the PFSC mount.
                    PayloadCrt.Klog("sp:pfsc:nested:scan\n\0"u8);
                    byte* nestedImage = stackalloc byte[MaxPath];
                    PayloadImageMount.ImageType nestedType =
                        PayloadImageMount.FindImageInDirectory(mountPoint, nestedImage, MaxPath);

                    if (nestedType != PayloadImageMount.ImageType.Unknown)
                    {
                        if (nestedType == PayloadImageMount.ImageType.Ufs)
                            PayloadCrt.Klog("sp:pfsc:nested:ufs\n\0"u8);
                        else if (nestedType == PayloadImageMount.ImageType.Pfs)
                            PayloadCrt.Klog("sp:pfsc:nested:pfs\n\0"u8);
                        else if (nestedType == PayloadImageMount.ImageType.ExFat)
                            PayloadCrt.Klog("sp:pfsc:nested:exfat\n\0"u8);
                        byte* nestedMount = stackalloc byte[MaxPath];
                        bool nestedOk = nestedType switch
                        {
                            PayloadImageMount.ImageType.Ufs => MountUfsImage(nestedImage, nestedMount),
                            PayloadImageMount.ImageType.Pfs => MountPfsImage(nestedImage, nestedMount),
                            PayloadImageMount.ImageType.ExFat => MountExfatImage(nestedImage, nestedMount),
                            _ => false
                        };
                        if (nestedOk)
                        {
                            CopyString(outMountedPath, nestedMount);
                            return true;
                        }
                    }

                    // No nested image or nested mount failed: use the PFSC root.
                    CopyString(outMountedPath, mountPoint);
                    return true;
                }
                break;

            case PayloadImageMount.ImageType.ExFat:
                PayloadCrt.Klog("sp:mount:detect:exfat\n\0"u8);
                if (MountExfatImage(imagePath, mountPoint))
                {
                    CopyString(outMountedPath, mountPoint);
                    return true;
                }
                break;
        }

        return false;
    }

    // ---- UFS image mounting ----

    /// <summary>
    /// Mounts a UFS disc image via <c>md(4)</c> memory disk attach + <c>nmount</c>.
    /// Checks time freshness (skips images modified less than 12 seconds ago) and
    /// statfs-checks for an existing mount before attaching. Tries read-write first,
    /// falls back to read-only.
    /// </summary>
    private static bool MountUfsImage(byte* imagePath, byte* outMountPoint)
    {
        // Time-freshness check: skip images that were modified very recently to avoid
        // mounting a file that is still being written (e.g. USB transfer in progress).
        PayloadCrt.Klog("sp:ufs:stat\n\0"u8);
        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(imagePath, &st) != 0)
            return false;

        // SYS_clock_gettime (232) with CLOCK_REALTIME (0) to get the current wall-clock time.
        long* ts = stackalloc long[2];
        ts[0] = 0;
        ts[1] = 0;
        long clockRc = PayloadCrt.Syscall(232, 0, (long)ts);
        if (clockRc == 0 && ts[0] > 0 && (ts[0] - st.st_mtim_sec) < 12)
        {
            PayloadCrt.Klog("sp:ufs:fresh\n\0"u8);
            return false;
        }

        // Build mount point from filename without extension: /data/imgmnt/ufsmnt/<name>
        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int mpos = 0;
        AppendLiteral(outMountPoint, ref mpos, "/data/imgmnt/ufsmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref mpos, mountName, mnLen);
        outMountPoint[mpos] = 0;

        // Check if already mounted as UFS at this point.
        FreeBsdStatfs sfs = default;
        if (PayloadMount.statfs(outMountPoint, &sfs) == 0)
        {
            byte* ufsName = stackalloc byte[] {
                (byte)'u', (byte)'f', (byte)'s', 0 };
            if (FixedBytesEqual(sfs.f_fstypename, ufsName, 3))
            {
                PayloadCrt.Klog("sp:ufs:already\n\0"u8);
                return true; // Already mounted.
            }
        }

        PayloadCrt.Klog("sp:ufs:mkdir\n\0"u8);
        if (PayloadFileSystem.mkdir(outMountPoint, 0x1FF) != 0) // 0777
        {
            FreeBsdStat mkst = default;
            if (PayloadFileSystem.stat(outMountPoint, &mkst) != 0)
                return false;
        }

        PayloadCrt.Klog("sp:ufs:md:attach\n\0"u8);
        int unit = PayloadImageMount.MdAttach(imagePath, 512, true, (ulong)st.st_size);
        if (unit < 0)
        {
            PayloadCrt.Klog("sp:ufs:md:retry\n\0"u8);
            unit = PayloadImageMount.MdAttach(imagePath, 512, false, (ulong)st.st_size);
            if (unit < 0)
            {
                PayloadCrt.Klog("sp:ufs:md:fail\n\0"u8);
                return false;
            }
        }

        // Build device path: /dev/md<unit>
        byte* devPath = stackalloc byte[32];
        int dpos = 0;
        AppendLiteral(devPath, ref dpos, "/dev/md"u8);
        WriteInt(devPath, ref dpos, unit);
        devPath[dpos] = 0;

        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vUfs = stackalloc byte[] { (byte)'u', (byte)'f', (byte)'s', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };

        FreeBsdIovec* iov = stackalloc FreeBsdIovec[6];
        PayloadMount.SetIovecPair(&iov[0], kFstype, 7, vUfs, 4);
        PayloadMount.SetIovecPair(&iov[2], kFspath, 7, outMountPoint, StringLength(outMountPoint) + 1);
        PayloadMount.SetIovecPair(&iov[4], kFrom, 5, devPath, StringLength(devPath) + 1);

        // Try read-write first, fall back to read-only.
        PayloadCrt.Klog("sp:ufs:nmount:rw\n\0"u8);
        if (PayloadMount.nmount(iov, 6, 0) == 0)
        {
            PayloadCrt.Klog("sp:ufs:ok\n\0"u8);
            return true;
        }
        PayloadCrt.Klog("sp:ufs:nmount:ro\n\0"u8);
        if (PayloadMount.nmount(iov, 6, PayloadMount.MntReadOnly) == 0)
        {
            PayloadCrt.Klog("sp:ufs:ok\n\0"u8);
            return true;
        }

        PayloadCrt.Klog("sp:ufs:nmount:fail\n\0"u8);
        PayloadImageMount.MdDetach(unit);
        return false;
    }

    // ---- PFS image mounting ----

    /// <summary>
    /// Mounts a PFS disc image via <c>sceFsMountSaveData</c> from
    /// <c>libSceFsInternalForVsh</c> with a zeroed encryption key and "system" budget.
    /// Mount point uses the filename without extension.
    /// </summary>
    private static bool MountPfsImage(byte* imagePath, byte* outMountPoint)
    {
        // Build mount point from filename without extension: /data/imgmnt/pfsmnt/<name>
        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int mpos = 0;
        AppendLiteral(outMountPoint, ref mpos, "/data/imgmnt/pfsmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref mpos, mountName, mnLen);
        outMountPoint[mpos] = 0;

        // Clean up any stale mount at this point using PFS-specific unmount.
        PayloadCrt.Klog("sp:pfs:cleanup\n\0"u8);
        FreeBsdStat stCheck = default;
        if (PayloadFileSystem.stat(outMountPoint, &stCheck) == 0)
        {
            if (PayloadMount.IsMounted(outMountPoint))
            {
                UmountSaveDataOpt uopt = default;
                PayloadPfsMount.sceFsInitUmountSaveDataOpt(&uopt);
                PayloadPfsMount.sceFsUmountSaveData(&uopt, outMountPoint, -1, 1);
            }
            PayloadFileSystem.rmdir(outMountPoint);
        }

        PayloadCrt.Klog("sp:pfs:mkdir\n\0"u8);
        if (PayloadFileSystem.mkdir(outMountPoint, 0x1FF) != 0) // 0777
        {
            FreeBsdStat mkst = default;
            if (PayloadFileSystem.stat(outMountPoint, &mkst) != 0)
                return false;
        }

        PayloadCrt.Klog("sp:pfs:mount\n\0"u8);
        MountSaveDataOpt opt = default;
        PayloadPfsMount.sceFsInitMountSaveDataOpt(&opt);

        byte* budgetStr = stackalloc byte[] {
            (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m', 0 };
        opt.BudgetId = budgetStr;

        byte* key = stackalloc byte[0x20];
        for (int i = 0; i < 0x20; i++) key[i] = 0;

        int rc = PayloadPfsMount.sceFsMountSaveData(&opt, imagePath, outMountPoint, key);
        if (rc < 0)
        {
            PayloadCrt.Klog("sp:pfs:fail\n\0"u8);
            PayloadFileSystem.rmdir(outMountPoint);
            return false;
        }

        PayloadCrt.Klog("sp:pfs:ok\n\0"u8);
        return true;
    }

    // ---- PFSC image mounting ----

    /// <summary>
    /// Mounts a PFSC compressed image via <c>lvdctl</c> + PFS <c>nmount</c>.
    /// Tries multiple LVD image types (9, 8, 5, 10, 11) to find one that the kernel accepts,
    /// then mounts the resulting block device as a PFS filesystem with signature verification
    /// disabled, a zeroed EKPFS key, and an errmsg iovec pair for diagnostic output.
    /// Mount point uses the filename without extension.
    /// </summary>
    private static bool MountPfscImage(byte* imagePath, byte* outMountPoint)
    {
        // Build mount point from filename without extension: /data/imgmnt/pfscmnt/<name>
        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int mpos = 0;
        AppendLiteral(outMountPoint, ref mpos, "/data/imgmnt/pfscmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref mpos, mountName, mnLen);
        outMountPoint[mpos] = 0;

        // Clean up any stale PFSC mount: force unmount + rmdir.
        FreeBsdStat stCheck = default;
        if (PayloadFileSystem.stat(outMountPoint, &stCheck) == 0)
        {
            if (PayloadMount.IsMounted(outMountPoint))
            {
                PayloadMount.unmount(outMountPoint, PayloadMount.MntForce);
            }
            PayloadFileSystem.rmdir(outMountPoint);
        }

        if (PayloadFileSystem.mkdir(outMountPoint, 0x1FF) != 0) // 0777
        {
            FreeBsdStat mkst = default;
            if (PayloadFileSystem.stat(outMountPoint, &mkst) != 0)
            {
                PayloadFileSystem.rmdir(outMountPoint);
                return false;
            }
        }

        // Get the image file size for the LVD layer descriptor.
        PayloadCrt.Klog("sp:pfsc:stat\n\0"u8);
        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(imagePath, &st) != 0)
        {
            PayloadFileSystem.rmdir(outMountPoint);
            return false;
        }

        // Try multiple LVD image types. PFSC containers can use different type codes
        // depending on the firmware version and container format variant.
        ReadOnlySpan<ushort> imageTypes = stackalloc ushort[] { 9, 8, 5, 10, 11 };

        // Pre-allocate device path buffers outside the loop to satisfy CA2014.
        byte* lvdctlPath = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/', (byte)'l', (byte)'v',
            (byte)'d', (byte)'c', (byte)'t', (byte)'l', 0 };
        byte* devPath = stackalloc byte[32];

        for (int t = 0; t < imageTypes.Length; t++)
        {
            ushort imgType = imageTypes[t];

            // Build the LVD layer descriptor.
            LvdLayer layer = default;
            layer.SourceType = 1;   // vnode
            layer.EntryFlags = 1;   // read-only
            layer.Path = imagePath;
            layer.Size = (ulong)st.st_size;

            // Build the LVD attach request.
            LvdAttachRequest req = default;
            req.IoVersion = 0;
            req.DeviceId = -1;
            req.SectorSize0 = 4096;
            req.SectorSize1 = 4096;
            req.OptionLen = 0x1C;
            req.ImageType = imgType;
            req.LayerCount = 1;
            req.DeviceSize = (ulong)st.st_size;
            req.LayersPtr = &layer;

            int fd = PayloadIo.open(lvdctlPath, PayloadFileSystem.O_RDWR);
            if (fd < 0) break;

            PayloadCrt.Klog("sp:pfsc:lvd:attach\n\0"u8);
            int rc = PayloadIo.ioctl(fd, DeviceControl.SceLvdIocAttach, &req);
            PayloadIo.close(fd);

            if (rc != 0 || req.DeviceId < 0)
                continue;

            // Build device path: /dev/lvd<id>
            int dpos = 0;
            AppendLiteral(devPath, ref dpos, "/dev/lvd"u8);
            WriteInt(devPath, ref dpos, req.DeviceId);
            devPath[dpos] = 0;

            // Attempt PFS nmount on the LVD device.
            PayloadCrt.Klog("sp:pfsc:mount\n\0"u8);
            if (MountPfsOnDevice(devPath, outMountPoint))
            {
                PayloadCrt.Klog("sp:pfsc:ok\n\0"u8);
                return true;
            }

            // This image type didn't work; detach and try the next one.
        }

        PayloadCrt.Klog("sp:pfsc:fail\n\0"u8);
        PayloadFileSystem.rmdir(outMountPoint);
        return false;
    }

    /// <summary>
    /// Performs a PFS-type nmount on a block device path with signature verification disabled,
    /// "AC" master key mode, "system" budget, a zeroed EKPFS key, and an errmsg iovec pair
    /// for kernel diagnostic output.
    /// </summary>
    private static bool MountPfsOnDevice(byte* devPath, byte* mountPoint)
    {
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vPfs = stackalloc byte[] { (byte)'p', (byte)'f', (byte)'s', 0 };
        byte* kSigverify = stackalloc byte[] {
            (byte)'s', (byte)'i', (byte)'g', (byte)'v', (byte)'e', (byte)'r', (byte)'i',
            (byte)'f', (byte)'y', 0 };
        byte* v0 = stackalloc byte[] { (byte)'0', 0 };
        byte* kMkeymode = stackalloc byte[] {
            (byte)'m', (byte)'k', (byte)'e', (byte)'y', (byte)'m', (byte)'o', (byte)'d',
            (byte)'e', 0 };
        byte* vAC = stackalloc byte[] { (byte)'A', (byte)'C', 0 };
        byte* kBudgetid = stackalloc byte[] {
            (byte)'b', (byte)'u', (byte)'d', (byte)'g', (byte)'e', (byte)'t', (byte)'i',
            (byte)'d', 0 };
        byte* vSystem = stackalloc byte[] {
            (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m', 0 };
        byte* kPlaygo = stackalloc byte[] {
            (byte)'p', (byte)'l', (byte)'a', (byte)'y', (byte)'g', (byte)'o', 0 };
        byte* kDisc = stackalloc byte[] { (byte)'d', (byte)'i', (byte)'s', (byte)'c', 0 };
        byte* kEkpfs = stackalloc byte[] {
            (byte)'e', (byte)'k', (byte)'p', (byte)'f', (byte)'s', 0 };
        byte* kAsync = stackalloc byte[] {
            (byte)'a', (byte)'s', (byte)'y', (byte)'n', (byte)'c', 0 };
        byte* kNoatime = stackalloc byte[] {
            (byte)'n', (byte)'o', (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e', 0 };
        byte* kRdonly = stackalloc byte[] {
            (byte)'r', (byte)'d', (byte)'o', (byte)'n', (byte)'l', (byte)'y', 0 };
        byte* kErrmsg = stackalloc byte[] {
            (byte)'e', (byte)'r', (byte)'r', (byte)'m', (byte)'s', (byte)'g', 0 };
        byte* kForce = stackalloc byte[] {
            (byte)'f', (byte)'o', (byte)'r', (byte)'c', (byte)'e', 0 };

        // 64-character hex string of zeros for the EKPFS key.
        byte* ekpfsKey = stackalloc byte[65];
        for (int i = 0; i < 64; i++) ekpfsKey[i] = (byte)'0';
        ekpfsKey[64] = 0;

        // Error message buffer for kernel diagnostic output.
        byte* errmsgBuf = stackalloc byte[256];
        for (int i = 0; i < 256; i++) errmsgBuf[i] = 0;

        FreeBsdIovec* iov = stackalloc FreeBsdIovec[28];
        PayloadMount.SetIovecPair(&iov[0], kFrom, 5, devPath, StringLength(devPath) + 1);
        PayloadMount.SetIovecPair(&iov[2], kFspath, 7, mountPoint, StringLength(mountPoint) + 1);
        PayloadMount.SetIovecPair(&iov[4], kFstype, 7, vPfs, 4);
        PayloadMount.SetIovecPair(&iov[6], kSigverify, 10, v0, 2);
        PayloadMount.SetIovecPair(&iov[8], kMkeymode, 9, vAC, 3);
        PayloadMount.SetIovecPair(&iov[10], kBudgetid, 9, vSystem, 7);
        PayloadMount.SetIovecPair(&iov[12], kPlaygo, 7, v0, 2);
        PayloadMount.SetIovecPair(&iov[14], kDisc, 5, v0, 2);
        PayloadMount.SetIovecPair(&iov[16], kEkpfs, 6, ekpfsKey, 65);
        PayloadMount.SetIovecFlag(&iov[18], kAsync, 6);
        PayloadMount.SetIovecFlag(&iov[20], kNoatime, 8);
        PayloadMount.SetIovecFlag(&iov[22], kRdonly, 7);
        // errmsg iovec pair: key is NUL-terminated, value is a fixed-size buffer.
        PayloadMount.SetIovecPair(&iov[24], kErrmsg, 7, errmsgBuf, 256);
        PayloadMount.SetIovecFlag(&iov[26], kForce, 6);

        return PayloadMount.nmount(iov, 28, PayloadMount.MntReadOnly) == 0;
    }

    // ---- exFAT image mounting ----

    /// <summary>
    /// Mounts an exFAT disc image. First attempts <c>md(4)</c> memory disk attach; if that
    /// fails, falls back to <c>lvdctl</c> virtual disk attach. Both paths then <c>nmount</c>
    /// the resulting block device with the <c>exfatfs</c> filesystem driver.
    /// Mount point uses the filename without extension.
    /// </summary>
    private static bool MountExfatImage(byte* imagePath, byte* outMountPoint)
    {
        PayloadCrt.Klog("sp:exfat:stat\n\0"u8);
        // Build mount point from filename without extension: /data/imgmnt/exfatmnt/<name>
        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int mpos = 0;
        AppendLiteral(outMountPoint, ref mpos, "/data/imgmnt/exfatmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref mpos, mountName, mnLen);
        outMountPoint[mpos] = 0;

        if (PayloadFileSystem.mkdir(outMountPoint, 0x1FF) != 0) // 0777
        {
            FreeBsdStat mkst = default;
            if (PayloadFileSystem.stat(outMountPoint, &mkst) != 0)
                return false;
        }

        // Check if already mounted as exFAT at this point.
        FreeBsdStatfs sfs = default;
        if (PayloadMount.statfs(outMountPoint, &sfs) == 0)
        {
            byte* exfatName = stackalloc byte[] {
                (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
            if (FixedBytesEqual(sfs.f_fstypename, exfatName, 7))
            {
                PayloadCrt.Klog("sp:exfat:already\n\0"u8);
                return true; // Already mounted.
            }
        }

        // Path A: md(4) memory disk.
        PayloadCrt.Klog("sp:exfat:md:attach\n\0"u8);
        FreeBsdStat exSt = default;
        ulong exMediaSize = 0;
        if (PayloadFileSystem.stat(imagePath, &exSt) == 0)
            exMediaSize = (ulong)exSt.st_size;
        int unit = PayloadImageMount.MdAttach(imagePath, 512, true, exMediaSize);
        if (unit >= 0)
        {
            byte* devPath = stackalloc byte[32];
            int dpos = 0;
            AppendLiteral(devPath, ref dpos, "/dev/md"u8);
            WriteInt(devPath, ref dpos, unit);
            devPath[dpos] = 0;

            PayloadCrt.Klog("sp:exfat:md:nmount\n\0"u8);
            if (NmountExfat(devPath, outMountPoint))
            {
                PayloadCrt.Klog("sp:exfat:md:ok\n\0"u8);
                return true;
            }

            PayloadCrt.Klog("sp:exfat:md:fail\n\0"u8);
            PayloadImageMount.MdDetach(unit);
        }

        // Path B: lvdctl virtual disk fallback.
        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(imagePath, &st) != 0)
            return false;

        LvdLayer layer = default;
        layer.SourceType = 1;
        layer.EntryFlags = 1;
        layer.Path = imagePath;
        layer.Size = (ulong)st.st_size;

        LvdAttachRequest req = default;
        req.IoVersion = 1;
        req.DeviceId = -1;
        req.SectorSize0 = 512;
        req.SectorSize1 = 512;
        req.ImageType = 7; // exFAT
        req.LayerCount = 1;
        req.DeviceSize = (ulong)st.st_size;
        req.LayersPtr = &layer;

        byte* lvdctlPath = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/', (byte)'l', (byte)'v',
            (byte)'d', (byte)'c', (byte)'t', (byte)'l', 0 };

        PayloadCrt.Klog("sp:exfat:lvd:attach\n\0"u8);
        int lvdFd = PayloadIo.open(lvdctlPath, PayloadFileSystem.O_RDWR);
        if (lvdFd < 0) return false;

        int rc = PayloadIo.ioctl(lvdFd, DeviceControl.SceLvdIocAttach, &req);
        PayloadIo.close(lvdFd);

        if (rc != 0 || req.DeviceId < 0) return false;

        byte* lvdDevPath = stackalloc byte[32];
        int ldpos = 0;
        AppendLiteral(lvdDevPath, ref ldpos, "/dev/lvd"u8);
        WriteInt(lvdDevPath, ref ldpos, req.DeviceId);
        lvdDevPath[ldpos] = 0;

        PayloadCrt.Klog("sp:exfat:lvd:nmount\n\0"u8);
        if (NmountExfat(lvdDevPath, outMountPoint))
        {
            PayloadCrt.Klog("sp:exfat:lvd:ok\n\0"u8);
            return true;
        }

        PayloadCrt.Klog("sp:exfat:lvd:fail\n\0"u8);
        return false;
    }

    /// <summary>
    /// Performs the exFAT-specific <c>nmount</c> with the required filesystem options:
    /// large=yes, timezone=static, async, noatime, ignoreacl.
    /// </summary>
    private static bool NmountExfat(byte* devPath, byte* mountPoint)
    {
        byte* kFstype = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vExfatfs = stackalloc byte[] {
            (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
        byte* kFrom = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* kFspath = stackalloc byte[] {
            (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* kLarge = stackalloc byte[] {
            (byte)'l', (byte)'a', (byte)'r', (byte)'g', (byte)'e', 0 };
        byte* vYes = stackalloc byte[] { (byte)'y', (byte)'e', (byte)'s', 0 };
        byte* kTimezone = stackalloc byte[] {
            (byte)'t', (byte)'i', (byte)'m', (byte)'e', (byte)'z', (byte)'o', (byte)'n',
            (byte)'e', 0 };
        byte* vStatic = stackalloc byte[] {
            (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'i', (byte)'c', 0 };
        byte* kAsync = stackalloc byte[] {
            (byte)'a', (byte)'s', (byte)'y', (byte)'n', (byte)'c', 0 };
        byte* kNoatime = stackalloc byte[] {
            (byte)'n', (byte)'o', (byte)'a', (byte)'t', (byte)'i', (byte)'m', (byte)'e', 0 };
        byte* kIgnoreacl = stackalloc byte[] {
            (byte)'i', (byte)'g', (byte)'n', (byte)'o', (byte)'r', (byte)'e', (byte)'a',
            (byte)'c', (byte)'l', 0 };

        FreeBsdIovec* iov = stackalloc FreeBsdIovec[16];
        PayloadMount.SetIovecPair(&iov[0], kFstype, 7, vExfatfs, 8);
        PayloadMount.SetIovecPair(&iov[2], kFrom, 5, devPath, StringLength(devPath) + 1);
        PayloadMount.SetIovecPair(&iov[4], kFspath, 7, mountPoint, StringLength(mountPoint) + 1);
        PayloadMount.SetIovecPair(&iov[6], kLarge, 6, vYes, 4);
        PayloadMount.SetIovecPair(&iov[8], kTimezone, 9, vStatic, 7);
        PayloadMount.SetIovecFlag(&iov[10], kAsync, 6);
        PayloadMount.SetIovecFlag(&iov[12], kNoatime, 8);
        PayloadMount.SetIovecFlag(&iov[14], kIgnoreacl, 10);

        PayloadCrt.Klog("sp:exfat:iov\n\0"u8);
        return PayloadMount.nmount(iov, 16, PayloadMount.MntReadOnly) == 0;
    }

    // ---- USB/filesystem event monitor ----

    /// <summary>
    /// Enters a persistent kqueue-based loop watching for filesystem mount/unmount events
    /// (EVFILT_FS). When a USB device is attached or detached, re-scans /user/app and
    /// bind-mounts any new titles. Events triggered by internal mount operations (when
    /// <see cref="s_isMounting"/> is set) are skipped to prevent re-entrant scanning.
    /// This method is called unconditionally regardless of the automount sentinel file.
    /// </summary>
    private static void MonitorUsbChanges()
    {
        int kq = PayloadEvent.kqueue();
        if (kq < 0)
        {
            PayloadCrt.Klog("kstuff: kqueue creation failed\n\0"u8);
            return;
        }

        FreeBsdKevent ev = default;
        PayloadEvent.EvSet(&ev, 0, PayloadEvent.EvfiltFs,
            (ushort)(PayloadEvent.EvAdd | PayloadEvent.EvClear), 0, 0, null);

        if (PayloadEvent.kevent(kq, &ev, 1, null, 0, null) < 0)
        {
            PayloadCrt.Klog("kstuff: kevent register failed\n\0"u8);
            PayloadIo.close(kq);
            return;
        }

        PayloadCrt.Klog("kstuff: usb monitor active\n\0"u8);

        while (true)
        {
            FreeBsdKevent fired = default;
            if (PayloadEvent.kevent(kq, null, 0, &fired, 1, null) < 0)
            {
                PayloadCrt.Klog("kstuff: kevent wait failed\n\0"u8);
                break;
            }

            // Skip events triggered by internal mount operations.
            if (s_isMounting)
                continue;

            PayloadCrt.Klog("sp:usb:event\n\0"u8);
            PayloadThread.sleep(1);

            PayloadCrt.Klog("kstuff: fs event, rescanning titles\n\0"u8);
            ScanAndMountTitles();
        }

        PayloadIo.close(kq);
    }

    // ---- Utility functions ----

    /// <summary>
    /// Returns a pointer to the filename portion of a path (after the last '/'), or the
    /// entire path if no separator is found.
    /// </summary>
    private static byte* GetFilenamePointer(byte* path)
    {
        byte* last = path;
        byte* p = path;
        while (*p != 0)
        {
            if (*p == (byte)'/')
                last = p + 1;
            p++;
        }
        return last;
    }

    /// <summary>
    /// Copies the filename without its extension into <paramref name="dst"/>. Finds the
    /// last '.' in the filename and copies everything before it. If no '.' is found, copies
    /// the entire filename.
    /// </summary>
    private static void CopyFilenameNoExt(byte* dst, int dstSize, byte* filename)
    {
        int len = StringLength(filename);
        int dotPos = -1;
        for (int i = len - 1; i >= 0; i--)
        {
            if (filename[i] == (byte)'.')
            {
                dotPos = i;
                break;
            }
        }

        int copyLen = dotPos >= 0 ? dotPos : len;
        if (copyLen >= dstSize) copyLen = dstSize - 1;

        for (int i = 0; i < copyLen; i++)
            dst[i] = filename[i];
        dst[copyLen] = 0;
    }

    /// <summary>Returns the length of a NUL-terminated byte string.</summary>
    private static int StringLength(byte* s)
    {
        int len = 0;
        while (s[len] != 0) len++;
        return len;
    }

    /// <summary>Copies bytes from a ReadOnlySpan without the NUL terminator.</summary>
    private static void AppendLiteral(byte* dst, ref int pos, ReadOnlySpan<byte> src)
    {
        for (int i = 0; i < src.Length; i++)
            dst[pos++] = src[i];
    }

    /// <summary>Copies <paramref name="len"/> bytes from <paramref name="src"/> to
    /// <paramref name="dst"/> at offset <paramref name="pos"/>.</summary>
    private static void CopyBytes(byte* dst, ref int pos, byte* src, int len)
    {
        for (int i = 0; i < len; i++)
            dst[pos++] = src[i];
    }

    /// <summary>Copies a NUL-terminated string from <paramref name="src"/> to
    /// <paramref name="dst"/>, including the terminator.</summary>
    private static void CopyString(byte* dst, byte* src)
    {
        while (*src != 0) { *dst = *src; dst++; src++; }
        *dst = 0;
    }

    /// <summary>Writes the decimal representation of <paramref name="value"/> to
    /// <paramref name="dst"/> at <paramref name="pos"/>.</summary>
    private static void WriteInt(byte* dst, ref int pos, int value)
    {
        if (value < 0) { dst[pos++] = (byte)'-'; value = -value; }
        if (value == 0) { dst[pos++] = (byte)'0'; return; }
        int div = 1;
        while (value / div >= 10) div *= 10;
        while (div > 0)
        {
            dst[pos++] = (byte)('0' + (value / div) % 10);
            div /= 10;
        }
    }

    /// <summary>Checks if a NUL-terminated byte string starts with <paramref name="prefix"/>.</summary>
    private static bool StartsWith(byte* str, ReadOnlySpan<byte> prefix)
    {
        for (int i = 0; i < prefix.Length; i++)
        {
            if (str[i] == 0) return false;
            if (str[i] != prefix[i]) return false;
        }
        return true;
    }

    /// <summary>Compares a fixed-size byte array against a NUL-terminated string.</summary>
    private static bool FixedBytesEqual(byte* fixedBuf, byte* str, int len)
    {
        for (int i = 0; i < len; i++)
        {
            if (fixedBuf[i] != str[i]) return false;
        }
        return true;
    }
}


/// <summary>
/// Maps the installer ELF and calls its entry point. Uses kernel R/W to set
/// vm_map_entry max_protection (PS5's SYS_mprotect ignores PROT_EXEC — the
/// SDK's libc mprotect() routes through kernel_mprotect which modifies vm_map
/// entries directly via copyin).
/// </summary>
internal static unsafe class InstallerLoader
{
    private const ulong InstallerHintAddr = 0x926100000;

    public static bool LoadAndRun(PayloadArgs* pargs)
    {
        ReadOnlySpan<byte> elf = InstallerBlob.Data;
        if (elf.Length < 64)
        {
            PayloadCrt.Klog("kstuff: installer blob too small\n\0"u8);
            return false;
        }

        fixed (byte* elfPtr = elf)
        {
            if (elfPtr[0] != 0x7F || elfPtr[1] != (byte)'E' ||
                elfPtr[2] != (byte)'L' || elfPtr[3] != (byte)'F')
            {
                PayloadCrt.Klog("kstuff: installer: bad elf magic\n\0"u8);
                return false;
            }

            Elf64Ehdr* ehdr = (Elf64Ehdr*)elfPtr;
            Elf64Phdr* phdr = (Elf64Phdr*)(elfPtr + (int)ehdr->Phoff);
            int phnum = ehdr->Phnum;

            ulong minVaddr = ulong.MaxValue;
            ulong maxVaddr = 0;
            for (int i = 0; i < phnum; i++)
            {
                if (phdr[i].Vaddr < minVaddr) minVaddr = phdr[i].Vaddr;
                ulong end = phdr[i].Vaddr + phdr[i].Memsz;
                if (end > maxVaddr) maxVaddr = end;
            }

            if (maxVaddr == 0)
            {
                PayloadCrt.Klog("kstuff: installer: no loadable segments\n\0"u8);
                return false;
            }

            minVaddr = minVaddr & ~0xFFFUL;
            maxVaddr = (maxVaddr + 0xFFF) & ~0xFFFUL;
            ulong baseSize = maxVaddr - minVaddr;

            PayloadCrt.Klog("kstuff: installer: mapping\n\0"u8);
            long mapResult = PayloadCrt.Syscall(477 /* SYS_mmap */,
                (long)InstallerHintAddr, (long)baseSize,
                3 /* PROT_READ|PROT_WRITE */,
                0x1002 /* MAP_PRIVATE|MAP_ANON */,
                -1, 0);
            if (mapResult < 0x10000)
            {
                PayloadCrt.Klog("kstuff: installer: mmap failed\n\0"u8);
                return false;
            }

            byte* basePtr = (byte*)(ulong)mapResult;

            for (int i = 0; i < phnum; i++)
            {
                if (phdr[i].Type != 1 /* PT_LOAD */) continue;
                if (phdr[i].Memsz == 0 || phdr[i].Filesz == 0) continue;
                byte* dst = basePtr + (int)phdr[i].Vaddr;
                byte* src = elfPtr + (int)phdr[i].Offset;
                int filesz = (int)phdr[i].Filesz;
                for (int j = 0; j < filesz; j++)
                    dst[j] = src[j];
            }

            // Use kernel R/W to set vm_map_entry max_protection for executable
            // segments. SYS_mprotect (syscall 74) ignores PROT_EXEC on PS5.
            PayloadKernelIo io = new(pargs);
            for (int i = 0; i < phnum; i++)
            {
                if (phdr[i].Type != 1 /* PT_LOAD */ || phdr[i].Memsz == 0) continue;
                ulong segAddr = (ulong)basePtr + phdr[i].Vaddr;
                ulong segSize = (phdr[i].Memsz + 0xFFF) & ~0xFFFUL;
                int prot = 0;
                if ((phdr[i].Flags & 1) != 0) prot |= 4;
                if ((phdr[i].Flags & 2) != 0) prot |= 2;
                if ((phdr[i].Flags & 4) != 0) prot |= 1;

                if ((prot & 4) != 0)
                {
                    KernelSetVmemProtection(io, pargs, segAddr, segSize, (byte)prot);
                }
                PayloadCrt.Syscall(74 /* SYS_mprotect */, (long)segAddr, (long)segSize, prot);
            }

            PayloadCrt.Klog("kstuff: installer: calling entry\n\0"u8);
            ulong entryAddr = (ulong)basePtr + ehdr->Entry;
            var entry = (delegate* unmanaged<PayloadArgs*, void>)entryAddr;
            entry(pargs);

            PayloadCrt.Klog("kstuff: installer: returned\n\0"u8);
            return true;
        }
    }

    /// <summary>
    /// Sets vm_map_entry.max_protection for a memory range by walking the kernel's
    /// vm_map via kernel R/W. This is the equivalent of the SDK's kernel_mprotect /
    /// kernel_set_vmem_protection which modifies vm_map entries directly via copyin.
    /// </summary>
    private static void KernelSetVmemProtection(PayloadKernelIo io, PayloadArgs* pargs,
        ulong addr, ulong len, byte prot)
    {
        int ownPid = (int)PayloadCrt.Syscall(20 /* SYS_getpid */, 0);
        ulong proc = PayloadKernel.WalkAllprocForPid(io, ownPid);
        if (proc == 0) return;

        // proc + 0x200 = p_vmspace
        ulong vmspace = io.ReadU64(proc + KernelOffsets.ProcVmspace);
        if (vmspace == 0) return;

        // vmspace + 0x1d0 = pointer to the first vm_map_entry. The SDK's
        // kernel_get_vmem_entry reads directly from this offset.
        ulong firstEntry = io.ReadU64(vmspace + 0x1d0);
        if (firstEntry == 0) return;
        ulong entry = firstEntry;

        ulong endAddr = addr + len;
        bool foundMatch = false;

        for (int iter = 0; iter < 4096; iter++)
        {
            if (entry == 0) break;

            ulong entryStart = io.ReadU64(entry + 0x20);
            ulong entryEnd = io.ReadU64(entry + 0x28);

            if (entryStart >= endAddr)
            {
                if (foundMatch) break;
            }
            else if (entryEnd > addr)
            {
                foundMatch = true;
                byte protByte = prot;
                io.Write(entry + 0x64, &protByte, 1);
            }

            ulong next = io.ReadU64(entry + 0x08);
            if (next == entry || next == firstEntry || next == 0) break;
            entry = next;
        }
    }
}
