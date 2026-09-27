// Daemon payload: self-elevates, then listens on a TCP loopback socket for four families of
// requests from application modules. The escalation family raises a caller's credentials so its
// own file view widens. The file-broker family reads, writes, lists, and stats paths that the
// caller's sandbox does not bind. The mount family stat/mount/unmount partitions the caller
// cannot reach. The install family invokes the shell's install service and packs the on-disk
// layout an installed title needs. The daemon executes each request in its own namespace and
// returns the result over the same connection.
//
// The kernel addresses and structure field offsets come from the firmware-versioned tables in
// SharpProspero.Payload.Kernel.KernelOffsets (per-firmware switches for the small subset the
// daemon consults unconditionally) and SharpProspero.Payload.Kernel.KernelOffsetTables (the full
// 78-symbol table per firmware for callers that need any other symbol). Both are selected at run
// time from the value GetSystemSoftwareVersion returns. Every kernel access routes through the
// CRT-emitted accessors, which share a single pipe-primitive call chain initialized once during
// CRT startup from the loader's payload_args block. The root vnode is discovered at run time
// (walking the process list to init and reading its file-descriptor table's root directory) when
// the running firmware has no verified rootvnode offset on file, so the daemon carries every
// firmware whose allproc and kernel_pmap_store are recognized by KernelOffsets.IsSupportedForUnjail,
// which today spans 1.00 through 13.60 across every family in the offset table.

using System;
using System.Runtime.InteropServices;
using SharpProspero.Interop.Kernel;
using SharpProspero.Interop.SystemService;
using SharpProspero.Payload;
using SharpProspero.Payload.Bypass;
using SharpProspero.Payload.IO;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Posix;
using SharpProspero.Payload.Process;
using SharpProspero.Payload.Services;

namespace SampleApp;

internal static unsafe class Program
{
    // ---- FreeBSD socket constants ----

    private const int AF_INET      = 2;
    private const int SOCK_STREAM  = 1;
    private const int SOL_SOCKET   = 0xFFFF;
    private const int SO_REUSEADDR = 0x0004;
    private const int SO_NOSIGPIPE = 0x0800;
    private const int SIGPIPE      = 13;
    private const int SYS_sigaction = 416;

    // ---- Protocol constants ----

    private const int DaemonPort     = 9069;
    private const int CommandSize    = 0xA10;
    private const uint ExpectedMagic = 0xDEADBEEF;
    private const int MaxRetries     = 30;

    // Command codes carried at request offset 0x04. Codes six through eleven make up the file
    // broker: each names a path in the caller's own path space and asks the daemon to run the
    // operation there, and each returns its outcome and any data in the same reply layout.
    // Codes thirteen through twenty-four widen the daemon into filesystem, launch, and install
    // primitives an application module cannot reach on its own credential.
    private const int CmdEscalate                        = 5;
    private const int CmdStat                            = 6;
    private const int CmdMkdir                           = 7;
    private const int CmdUnlink                          = 8;
    private const int CmdList                            = 9;
    private const int CmdRead                            = 10;
    private const int CmdWrite                           = 11;
    private const int CmdRename                          = 12;
    private const int CmdStatfs                          = 13;
    private const int CmdUnmount                         = 14;
    private const int CmdMountNullfs                     = 15;
    private const int CmdRemountSystemEx                 = 16;
    private const int CmdFindPidByTitleId                = 17;
    private const int CmdArmLaunchAndWaitForExit         = 18;
    private const int CmdAppInstUtilInitialize           = 19;
    private const int CmdAppInstUtilAppUnInstall         = 20;
    private const int CmdAppInstUtilAppInstallTitleDir   = 21;
    private const int CmdCopyDirRecursive                = 22;
    private const int CmdCopySceSysToAppmeta             = 23;
    private const int CmdUpdateTrophy                    = 24;
    private const int CmdCopyFile                        = 25;

    // Syscall numbers for the mount, event, sysctl, and thread primitives the new handlers
    // reach past the SDK wrappers. Every value matches the FreeBSD-derived kernel entry table
    // on this firmware. The launch worker reaches thr_new (455) through the pthread_create
    // wrapper the SDK's Payload.Process.PayloadThread class calls, so its stack, TLS block,
    // and 104-byte thr_param struct are built the same way libc builds them for every other
    // thread the process runs.
    private const int SYS_unmount   = 22;
    private const int SYS_sysctl    = 202;
    private const int SYS_kqueue    = 362;
    private const int SYS_kevent    = 363;
    private const int SYS_nmount    = 378;
    private const int SYS_statfs    = 396;

    // sysctl MIB constants used by the process walker (KERN_PROC_PROC returns kinfo_proc for
    // every process in the system, walked by ki_structsize).
    private const int CTL_KERN       = 1;
    private const int KERN_PROC      = 14;
    private const int KERN_PROC_PROC = 8;

    // Mount flags. MNT_UPDATE re-mounts an existing filesystem in place so the daemon can flush
    // the shell's cached view of /system_ex after adding a title subdirectory.
    private const int MNT_UPDATE = 0x10000;

    // kinfo_proc offsets used by the sysctl-driven process walker. Structure size lives at the
    // very start of every record and drives the walker's stride; the pid sits at fixed offset
    // 0x48. The FreeBSD kinfo_proc struct on this firmware.
    private const int KinfoProcStructSize = 0x00;
    private const int KinfoProcPid        = 0x48;

    // Path-field sizes. The broker path field is 512 bytes so a fully qualified path with the
    // longest partition prefix and a nested asset name still fits in one request. The write
    // payload occupies the tail of the request; a read reply carries the file bytes at the same
    // offset in the reply, sized to the length the request asked for.
    private const int PathOffset  = 0x20;
    private const int PathBytes   = 0x200;
    private const int DataOffset  = 0x220;
    private const int DataBytes   = CommandSize - DataOffset; // 0x7F0 = 2032

    // Reply data field extends further than the request's because a reply does not have to
    // carry a duplicate copy of the path, so more of the buffer is free for the returned bytes.
    private const int ReplyDataOffset = 0x20;
    private const int ReplyDataBytes  = CommandSize - ReplyDataOffset; // 0x9F0 = 2544

    // Flag word for sceKernelOpen when a path is opened for read-only enumeration of a directory
    // and for a plain-file open under those same flags. Non-blocking and directory kind on read
    // paths; the reference libc opendir uses the same word.
    private const int OpenReadOnly    = 0x0000;
    private const int OpenWriteOnly   = 0x0001;
    private const int OpenReadWrite   = 0x0002;
    private const int OpenNonBlock    = 0x0004;
    private const int OpenAppend      = 0x0008;
    private const int OpenCreate      = 0x0200;
    private const int OpenTruncate    = 0x0400;
    private const int OpenDirectory   = 0x00120004;
    private const ushort DefaultMode  = 0x1B6;   // 0666
    private const ushort DefaultDMode = 0x1FF;   // 0777

    // ---- Socket and IO wrappers ----

    private static long SysRead(int fd, byte* buf, long count) =>
        PayloadCrt.Syscall(PayloadCrt.SYS_read, fd, (long)(nint)buf, count);

    private static long SysWrite(int fd, byte* buf, long count) =>
        PayloadCrt.Syscall(PayloadCrt.SYS_write, fd, (long)(nint)buf, count);

    private static int SysClose(int fd) =>
        (int)PayloadCrt.Syscall(PayloadCrt.SYS_close, fd);

    private static void SleepOneSecond()
    {
        long* ts = stackalloc long[4];
        ts[0] = 1;  // tv_sec
        ts[1] = 0;  // tv_nsec
        PayloadCrt.Syscall(PayloadCrt.SYS_nanosleep, (long)(nint)ts, (long)(nint)(ts + 2));
    }

    // ---- Entry point ----

    [UnmanagedCallersOnly(EntryPoint = "__managed__Main")]
    public static int Main(void* args)
    {
        PayloadCrt.Klog("unjail: daemon start\n\0"u8);

        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null)
        {
            PayloadCrt.Klog("unjail: no payload args\n\0"u8);
            PayloadNotification.SendKernelNotification("unjail: no payload args"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: args ok\n\0"u8);

        // Refuse cleanly on a firmware whose kernel offset tables carry no verified values for
        // the two lookups the daemon performs unconditionally (allproc for the process-list
        // walk that the credential escalation and root-vnode discovery both need, and
        // kernel_pmap_store for the direct-map read that reaches the shell's text section).
        // A firmware that is recognized but returns zero for either fails this gate the same
        // way an entirely unrecognized version does. Aborting here prevents the CRT and the
        // kernel accessors below from reading the wrong quadword against a kdata offset that
        // does not exist on this system, which on a real console would corrupt kernel memory
        // instead of failing cleanly.
        uint fw = PayloadKernel.GetSystemSoftwareVersion();
        if (!KernelOffsets.IsSupportedForUnjail(fw))
        {
            byte* msg = stackalloc byte[48];
            ReadOnlySpan<byte> prefix = "unjail: unsupported firmware 0x"u8;
            int i = 0;
            for (; i < prefix.Length; i++) msg[i] = prefix[i];
            for (int shift = 28; shift >= 0; shift -= 4)
            {
                byte nibble = (byte)((fw >> shift) & 0xF);
                msg[i++] = nibble < 10 ? (byte)('0' + nibble) : (byte)('A' + (nibble - 10));
            }
            msg[i++] = (byte)'\n';
            msg[i]   = 0;
            PayloadCrt.Klog(new ReadOnlySpan<byte>(msg, i + 1));
            PayloadNotification.SendKernelNotification("unjail: unsupported firmware, aborting"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: firmware supported\n\0"u8);

        int ownPid = PayloadProcessControl.getpid();
        if (ownPid <= 0)
        {
            PayloadCrt.Klog("unjail: getpid failed\n\0"u8);
            PayloadNotification.SendKernelNotification("unjail: getpid failed"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: getpid ok\n\0"u8);

        PayloadKernel.RaisePrivileges(ownPid);
        PayloadCrt.Klog("unjail: self raised\n\0"u8);

        PayloadKernel.SetUcredAuthId(ownPid, 0x4800000000010003);
        PayloadCrt.Klog("unjail: authid set\n\0"u8);

        ulong rootvnode = PayloadKernel.GetRootVnode();
        if (rootvnode == 0)
        {
            PayloadCrt.Klog("unjail: rootvnode read failed\n\0"u8);
            PayloadNotification.SendKernelNotification("unjail: rootvnode read failed"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: rootvnode cached\n\0"u8);

        // Open the kernel's nullfs mount gate for every subsequent nmount call the daemon
        // issues. modified_nullfs_mount refuses every fstype=nullfs request unless bit 0x100
        // (PR_ALLOW_MOUNT_NULLFS) is set in prison0.pr_allow, regardless of ucred fields. The
        // gate must be opened once at daemon startup so the install worker's nullfs of the
        // backup source folder into /system_ex/app/<TID> succeeds, and so the launch worker's
        // post-exit nullfs re-check succeeds too.
        switch (PayloadKernel.SetPrisonMountAllow(0x100))
        {
            case PayloadKernel.PrisonMountAllowResult.Applied:
                PayloadCrt.Klog("unjail: prison0 nullfs bit set ok\n\0"u8);
                break;
            case PayloadKernel.PrisonMountAllowResult.AlreadySet:
                PayloadCrt.Klog("unjail: prison0 nullfs bit already set\n\0"u8);
                break;
            case PayloadKernel.PrisonMountAllowResult.WriteRejected:
                PayloadCrt.Klog("unjail: prison0 nullfs bit write did not stick\n\0"u8);
                break;
            case PayloadKernel.PrisonMountAllowResult.PrisonNotFound:
                PayloadCrt.Klog("unjail: prison0 not found\n\0"u8);
                break;
        }

        // Apply the shell-side /data and /user mount unlock. The unlock rewrites two
        // permission-check call sites in the SceShellCore process to always report success
        // and rewrites one permission-check function body to always return the "not owned by
        // me" error the caller's error path treats as "the mount is available for me to
        // use". Together the three writes let every title's own open, mkdir, and read on
        // paths under /data and /user reach the file system through the shell's own mount
        // namespace, without the app having to route the call through the broker.
        //
        // The scan reads the shell's text section into a scratch buffer, matches the
        // firmware-specific signatures, and writes back through the direct physical memory
        // map. Every write is a fixed byte sequence that is the same across every firmware
        // family (only the site addresses change). A firmware whose signatures are not
        // encoded in the table gets a clean skip, without falling through to a stale
        // address on the next firmware group's signatures.
        ApplyShellCoreMountUnlock(pargs);

        // A write to a client that closed its half of the connection before the daemon's reply
        // would raise SIGPIPE with the default disposition and kill the daemon. Ignore the
        // signal process-wide: every unhandled failure is already reported through the reply's
        // negative-result word or through the underlying syscall's error return.
        IgnoreSigPipe();

        PayloadNotification.SendKernelNotification("unjail: daemon ready"u8);
        PayloadCrt.Klog("unjail: daemon ready, entering accept loop\n\0"u8);

        TcpAcceptLoop(rootvnode);
        return 0;
    }

    // Reads the firmware version and dmap base from the payload args, then hands the /data
    // and /user mount unlock over to the pattern-scan applier. Every step reports its own
    // status back through klog so a firmware whose text-section signatures have shifted
    // reads out as "chk missing" or "site missing" rather than a silent skip. The unlock is
    // best-effort: a partial match still applies whatever writes it can, and a total miss
    // does not fail the daemon start (broker-served access to the same paths still works).
    private static void ApplyShellCoreMountUnlock(PayloadArgs* pargs)
    {
        var io = new PayloadKernelIo(pargs);

        uint fw = PayloadKernel.GetFirmwareVersion(io);
        if (fw == 0)
        {
            PayloadCrt.Klog("unjail: shellcore unlock skipped, no fw\n\0"u8);
            return;
        }

        long pmapOff = KernelOffsets.KernelPmapStore(fw);
        if (pmapOff == 0)
        {
            PayloadCrt.Klog("unjail: shellcore unlock skipped, no pmap offset\n\0"u8);
            return;
        }

        ulong kdataBase = pargs->KernelDataBase;
        ulong pmapStore = kdataBase + (ulong)pmapOff;
        ulong dmapVirt = io.ReadU64(pmapStore + 32);
        ulong pmCr3 = io.ReadU64(pmapStore + 40);
        if (dmapVirt == 0 || pmCr3 == 0)
        {
            PayloadCrt.Klog("unjail: shellcore unlock skipped, no dmap\n\0"u8);
            return;
        }
        ulong dmapBase = dmapVirt - pmCr3;

        PayloadShellCoreDataMountPatch.Result result =
            PayloadShellCoreDataMountPatch.Apply(io, dmapBase, fw);

        // Emit a specific klog line for the reason so an on-device retest tells us exactly
        // where the unlock stopped, without having to add temporary instrumentation.
        switch (result.Stop)
        {
            case PayloadShellCoreDataMountPatch.Reason.Success when result.Applied == 3:
                PayloadCrt.Klog("unjail: shellcore unlock ok\n\0"u8);
                PayloadNotification.SendKernelNotification("unjail: shellcore unlock ok"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.Success:
                PayloadCrt.Klog("unjail: shellcore unlock partial\n\0"u8);
                PayloadNotification.SendKernelNotification("unjail: shellcore unlock partial"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.UnsupportedFirmware:
                PayloadCrt.Klog("unjail: shellcore unlock unsupported fw\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ShellCoreProcessNotFound:
                PayloadCrt.Klog("unjail: shellcore unlock no shellcore proc\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ShellCoreCr3ReadFailed:
                PayloadCrt.Klog("unjail: shellcore unlock cr3 read failed\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ShellCoreModuleBaseNotFound:
                PayloadCrt.Klog("unjail: shellcore unlock module base not found\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ShellCoreElfHeaderReadFailed:
                PayloadCrt.Klog("unjail: shellcore unlock elf header read failed\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ShellCoreTextSegmentNotFound:
                PayloadCrt.Klog("unjail: shellcore unlock text segment not found\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ShellCoreTextSegmentTooLarge:
                PayloadCrt.Klog("unjail: shellcore unlock text segment too large\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.ScratchAllocFailed:
                PayloadCrt.Klog("unjail: shellcore unlock scratch alloc failed\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.TextCopyoutFailed:
                PayloadCrt.Klog("unjail: shellcore unlock text copyout failed\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.NoSignaturesMatched:
                PayloadCrt.Klog("unjail: shellcore unlock signatures missed\n\0"u8);
                break;
            case PayloadShellCoreDataMountPatch.Reason.PhysCopyinRejected:
                PayloadCrt.Klog("unjail: shellcore unlock phys copyin rejected\n\0"u8);
                break;
            default:
                PayloadCrt.Klog("unjail: shellcore unlock unknown stop\n\0"u8);
                break;
        }
    }

    private static void IgnoreSigPipe()
    {
        // FreeBSD sigaction struct: sa_handler (8), sa_flags (4, padded to 8), sa_mask (16).
        // A sa_handler value of 1 requests SIG_IGN.
        byte* sa = stackalloc byte[32];
        new Span<byte>(sa, 32).Clear();
        *(nint*)sa = 1; // SIG_IGN
        PayloadCrt.Syscall(SYS_sigaction, SIGPIPE, (long)(nint)sa, 0);
    }

    // ---- TCP accept loop ----

    private static void TcpAcceptLoop(ulong rootvnode)
    {
        int s = (int)PayloadCrt.Syscall(PayloadCrt.SYS_socket, AF_INET, SOCK_STREAM, 0);
        if (s < 0)
        {
            PayloadCrt.Klog("unjail: socket failed\n\0"u8);
            return;
        }

        int one = 1;
        PayloadCrt.Syscall(PayloadCrt.SYS_setsockopt, s, SOL_SOCKET, SO_REUSEADDR,
                     (long)(nint)(&one), 4);

        // FreeBSD sockaddr_in: sin_len(1), sin_family(1), sin_port(2 BE),
        // sin_addr(4), sin_zero(8). Total 16 bytes.
        byte* addr = stackalloc byte[16];
        new Span<byte>(addr, 16).Clear();
        addr[0] = 16;                          // sin_len
        addr[1] = (byte)AF_INET;               // sin_family
        addr[2] = (byte)(DaemonPort >> 8);      // sin_port high (big-endian)
        addr[3] = (byte)(DaemonPort & 0xFF);    // sin_port low
        addr[4] = 127; addr[5] = 0; addr[6] = 0; addr[7] = 1;  // sin_addr = 127.0.0.1

        if (PayloadCrt.Syscall(PayloadCrt.SYS_bind, s, (long)(nint)addr, 16) < 0)
        {
            PayloadCrt.Klog("unjail: bind failed\n\0"u8);
            SysClose(s);
            return;
        }

        if (PayloadCrt.Syscall(PayloadCrt.SYS_listen, s, 4) < 0)
        {
            PayloadCrt.Klog("unjail: listen failed\n\0"u8);
            SysClose(s);
            return;
        }

        PayloadCrt.Klog("unjail: tcp listener ready\n\0"u8);

        byte* cmdBuf   = stackalloc byte[CommandSize];
        byte* replyBuf = stackalloc byte[CommandSize];

        while (true)
        {
            int client = (int)PayloadCrt.Syscall(PayloadCrt.SYS_accept, s, 0, 0);
            if (client < 0)
            {
                SleepOneSecond();
                continue;
            }

            // Clear the request buffer at the top of each iteration so a partial receive on
            // this connection cannot expose stale bytes (path field, data payload) left over
            // from the previous request; without this the dispatch would see fresh header
            // bytes but stale path or data bytes and operate on a path the current caller
            // never named.
            new Span<byte>(cmdBuf, CommandSize).Clear();

            int total = 0;
            while (total < CommandSize)
            {
                long n = SysRead(client, cmdBuf + total, CommandSize - total);
                if (n <= 0) break;
                total += (int)n;
            }

            new Span<byte>(replyBuf, CommandSize).Clear();
            *(uint*)(replyBuf + 0x00) = ExpectedMagic;

            // Only a fully-received request is dispatched. Short reads on loopback should not
            // happen under a well-behaved client, but the wire protocol is fixed-length and a
            // short read means the payload is not the request the client intended to send.
            if (total == CommandSize)
            {
                uint magic = *(uint*)(cmdBuf + 0);
                int cmd    = *(int*)(cmdBuf + 4);
                *(int*)(replyBuf + 0x04) = cmd;

                if (magic == ExpectedMagic)
                {
                    switch (cmd)
                    {
                        case CmdEscalate:                      HandleEscalate(cmdBuf, replyBuf, rootvnode);       break;
                        case CmdStat:                          HandleStat(cmdBuf, replyBuf);                      break;
                        case CmdMkdir:                         HandleMkdir(cmdBuf, replyBuf);                     break;
                        case CmdUnlink:                        HandleUnlink(cmdBuf, replyBuf);                    break;
                        case CmdList:                          HandleList(cmdBuf, replyBuf);                      break;
                        case CmdRead:                          HandleRead(cmdBuf, replyBuf);                      break;
                        case CmdWrite:                         HandleWrite(cmdBuf, replyBuf);                     break;
                        case CmdRename:                        HandleRename(cmdBuf, replyBuf);                    break;
                        case CmdStatfs:                        HandleStatfs(cmdBuf, replyBuf);                    break;
                        case CmdUnmount:                       HandleUnmount(cmdBuf, replyBuf);                   break;
                        case CmdMountNullfs:                   HandleMountNullfs(cmdBuf, replyBuf);               break;
                        case CmdRemountSystemEx:               HandleRemountSystemEx(cmdBuf, replyBuf);           break;
                        case CmdFindPidByTitleId:              HandleFindPidByTitleId(cmdBuf, replyBuf);          break;
                        case CmdArmLaunchAndWaitForExit:       HandleArmLaunchAndWaitForExit(cmdBuf, replyBuf);   break;
                        case CmdAppInstUtilInitialize:         HandleAppInstUtilInitialize(cmdBuf, replyBuf);     break;
                        case CmdAppInstUtilAppUnInstall:       HandleAppInstUtilAppUnInstall(cmdBuf, replyBuf);   break;
                        case CmdAppInstUtilAppInstallTitleDir: HandleAppInstUtilAppInstallTitleDir(cmdBuf, replyBuf); break;
                        case CmdCopyDirRecursive:              HandleCopyDirRecursive(cmdBuf, replyBuf);          break;
                        case CmdCopySceSysToAppmeta:           HandleCopySceSysToAppmeta(cmdBuf, replyBuf);       break;
                        case CmdUpdateTrophy:                  HandleUpdateTrophy(cmdBuf, replyBuf);              break;
                        case CmdCopyFile:                      HandleCopyFile(cmdBuf, replyBuf);                  break;
                        default:                               WriteResult(replyBuf, -22);                        break; // EINVAL
                    }
                }
                else
                {
                    WriteResult(replyBuf, -22);
                }
            }
            else
            {
                WriteResult(replyBuf, -5); // EIO
            }

            SysWrite(client, replyBuf, CommandSize);
            SysClose(client);
        }
    }

    // True when the request's path field carries a NUL byte within its declared length. A
    // client that misbuilds the request with no terminator would let the kernel read past
    // the field into the adjacent data payload, so every handler validates before use.
    private static bool PathIsTerminated(byte* path)
    {
        for (int i = 0; i < PathBytes; i++)
            if (path[i] == 0) return true;
        return false;
    }

    // ---- Command handlers ----

    private static void HandleEscalate(byte* cmdBuf, byte* replyBuf, ulong rootvnode)
    {
        int pid = *(int*)(cmdBuf + 8);
        if (pid <= 0)
        {
            WriteResult(replyBuf, -22);
            return;
        }
        bool ok = false;
        for (int r = 0; r < MaxRetries && !ok; r++)
            ok = PayloadKernel.JailbreakByPid(pid, rootvnode);
        // Compatibility with the earlier reply layout: the outcome word at 0x0C stays zero on
        // success and non-zero on failure. WriteResult writes the same word.
        WriteResult(replyBuf, ok ? 0 : -1);
        PayloadCrt.Klog(ok ? "unjail: pid jailbroken\n\0"u8 : "unjail: jailbreak failed\n\0"u8);
    }

    private static void HandleStat(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        // The libkernel stat wrapper is what a regular application call reaches; the raw stat
        // syscall is what the daemon's escalated ucred and root-vnode-pointed rootdir reach when
        // the wrapper refuses the path. A path such as /data lives on a partition the fpkg
        // module's mount namespace does not bind, and the wrapper's sandbox check refuses it
        // before the request ever reaches namei; the raw syscall lands directly in the kernel
        // dispatch table where the escalated credential and rootdir resolve the request.
        SceKernelStat st = default;
        int rc = KernelFile.stat(path, &st);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(PayloadCrt.SYS_stat, (long)(nint)path, (long)(nint)(&st));
        }
        if (rc != 0)
        {
            // Report the specific errno rather than a blanket -1 so a caller can see whether
            // /data is missing (ENOENT 2), refused (EACCES 13), or malformed at the request
            // layer (EINVAL 22). The raw syscall returns -errno on failure; a libkernel-side
            // failure that reached this point is reported as -1 without an errno pathway.
            WriteResult(replyBuf, rc);
            return;
        }
        WriteResult(replyBuf, 0);
        *(ulong*)(replyBuf + 0x10) = (ulong)st.Size;
        // Bits 12..15 of Mode hold the file kind; the client reads this to distinguish
        // directories from regular files without a second syscall.
        *(uint*)(replyBuf + 0x18) = st.Mode;
    }

    private static void HandleMkdir(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        uint mode = *(uint*)(cmdBuf + 0x18);
        if (mode == 0) mode = DefaultDMode;
        int rc = KernelFile.sceKernelMkdir(path, (ushort)mode);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(PayloadCrt.SYS_mkdir, (long)(nint)path, mode);
        }
        WriteResult(replyBuf, rc);
    }

    private static void HandleUnlink(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        int rc = KernelFile.sceKernelUnlink(path);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(PayloadCrt.SYS_unlink, (long)(nint)path);
        }
        WriteResult(replyBuf, rc);
    }

    private static void HandleList(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        long resumeOffset = *(long*)(cmdBuf + 8);

        // Open the directory. The libkernel wrapper applies its own sandbox check even from an
        // elevated process context, so a raw open syscall backs it up: the raw path lands
        // straight in the kernel dispatch table where the daemon's escalated ucred and rootdir
        // resolve the request against the whole file system. The same flag word both calls
        // use: the platform's own opendir routes O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC
        // through the raw open syscall (see libSceLibcInternal.sprx __opendir2), so a raw call
        // with those flags is what a directory listing needs the kernel to see. A raw call with
        // a bare O_RDONLY opens the path with no directory-kind check and, on a regular file
        // and on a symlink alike, the follow-up getdirentries answers ENOTDIR - not the
        // partition-namespace refusal the fallback set out to work around.
        int fd = KernelFile.sceKernelOpen(path, OpenDirectory, 0);
        if (fd < 0)
        {
            fd = (int)PayloadCrt.Syscall(PayloadCrt.SYS_open,
                (long)(nint)path, OpenDirectory, 0);
        }
        if (fd < 0)
        {
            // Bare O_RDONLY | O_DIRECTORY (0x20000) fallback. The composite word 0x00120004
            // above adds O_NONBLOCK (0x0004) and O_CLOEXEC (0x100000). On the FreeBSD-derived
            // kernel here, an nsfs directory open with those extra bits returns EINVAL for
            // /data and /user even with an escalated credential, while the bare-flag call
            // succeeds. Fires only when both prior opens failed, so a regular file still
            // reports the original -ENOTDIR from the composite call unchanged.
            fd = (int)PayloadCrt.Syscall(PayloadCrt.SYS_open,
                (long)(nint)path, 0x20000, 0);
        }
        KlogRc("list open"u8, fd);
        if (fd < 0)
        {
            WriteResult(replyBuf, fd);
            return;
        }
        try
        {
            if (resumeOffset > 0)
            {
                long seek = KernelFile.sceKernelLseek(fd, resumeOffset, KernelFile.SeekSet);
                if (seek < 0)
                {
                    seek = PayloadCrt.Syscall(PayloadCrt.SYS_lseek, fd, resumeOffset, KernelFile.SeekSet);
                }
                if (seek < 0)
                {
                    WriteResult(replyBuf, (int)seek);
                    return;
                }
            }

            long position = resumeOffset;
            int filled = KernelFile.sceKernelGetdirentries(fd, replyBuf + ReplyDataOffset,
                ReplyDataBytes, &position);
            if (filled < 0)
            {
                // Same raw-syscall fallback: the FreeBSD getdirentries syscall answers directly
                // when the libkernel wrapper's own check refuses.
                filled = (int)PayloadCrt.Syscall(PayloadCrt.SYS_getdirentries,
                    fd, (long)(nint)(replyBuf + ReplyDataOffset), ReplyDataBytes,
                    (long)(nint)(&position));
            }
            if (filled < 0)
            {
                WriteResult(replyBuf, filled);
                return;
            }

            // On FreeBSD, the basep argument to getdirentries is set to the file position
            // where the read began, not where the next read should resume from. To page
            // through a directory that does not fit in one reply we ask the kernel for the
            // file position after the read - that is the offset a follow-up request lseeks
            // to before its own getdirentries. A getdirentries return of zero already means
            // end-of-directory so the follow-up offset does not matter.
            long nextOffset;
            if (filled == 0)
            {
                nextOffset = position;
            }
            else
            {
                nextOffset = KernelFile.sceKernelLseek(fd, 0, KernelFile.SeekCurrent);
                if (nextOffset < 0)
                {
                    // A silent fall-back to `position` here would look like end-of-directory
                    // to the client because the next request would resume from the same
                    // offset the last one started at. Surface the failure so the caller can
                    // report it instead of silently truncating the listing.
                    WriteResult(replyBuf, (int)nextOffset);
                    return;
                }
            }

            WriteResult(replyBuf, filled);
            // Byte count at 0x10 tells the client how much of the reply data is packed dirent
            // records; the next-position at 0x18 is the offset a follow-up LIST request passes
            // back at 0x08 to continue the walk.
            *(ulong*)(replyBuf + 0x10) = (ulong)filled;
            *(long*)(replyBuf + 0x18) = nextOffset;
        }
        finally
        {
            KernelFile.sceKernelClose(fd);
        }
    }

    private static void HandleRead(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        long offset = *(long*)(cmdBuf + 8);
        uint length = *(uint*)(cmdBuf + 0x10);
        if (length == 0 || length > ReplyDataBytes) length = ReplyDataBytes;

        // The libkernel open, seek, and read wrappers apply the same sandbox check the enumerate
        // and stat paths do; the raw syscall backs each one so a file on a partition the module
        // does not bind (a game backup under /data, a metadata file under /user, ...) still reads
        // through the daemon's escalated ucred and rootdir-pointed-at-real-root file view.
        int fd = KernelFile.sceKernelOpen(path, OpenReadOnly, 0);
        if (fd < 0)
        {
            fd = (int)PayloadCrt.Syscall(PayloadCrt.SYS_open, (long)(nint)path, OpenReadOnly, 0);
        }
        if (fd < 0)
        {
            WriteResult(replyBuf, fd);
            return;
        }
        try
        {
            if (offset > 0)
            {
                long seek = KernelFile.sceKernelLseek(fd, offset, KernelFile.SeekSet);
                if (seek < 0)
                {
                    seek = PayloadCrt.Syscall(PayloadCrt.SYS_lseek, fd, offset, KernelFile.SeekSet);
                }
                if (seek < 0)
                {
                    WriteResult(replyBuf, (int)seek);
                    return;
                }
            }
            long n = KernelFile.sceKernelRead(fd, replyBuf + ReplyDataOffset, length);
            if (n < 0)
            {
                n = PayloadCrt.Syscall(PayloadCrt.SYS_read, fd, (long)(nint)(replyBuf + ReplyDataOffset), (long)length);
            }
            if (n < 0)
            {
                WriteResult(replyBuf, (int)n);
                return;
            }
            WriteResult(replyBuf, (int)n);
            *(ulong*)(replyBuf + 0x10) = (ulong)n;
        }
        finally
        {
            KernelFile.sceKernelClose(fd);
        }
    }

    private static void HandleWrite(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        long offset = *(long*)(cmdBuf + 8);
        uint length = *(uint*)(cmdBuf + 0x10);
        if (length > DataBytes) length = DataBytes;

        int flags = OpenReadWrite | OpenCreate;
        // A write starting at offset zero with no seek clears any tail from a previous write to
        // the same path; a write at a non-zero offset does not truncate so a range update leaves
        // bytes above the range in place.
        if (offset == 0)
            flags |= OpenTruncate;

        // Same libkernel-then-raw ladder the read handler uses: an open of a file on a partition
        // the module's mount namespace does not bind (a game backup landing under /data, a
        // settings blob written to /user) reaches the kernel dispatch table directly through the
        // raw syscall when the libkernel wrapper refuses.
        int fd = KernelFile.sceKernelOpen(path, flags, DefaultMode);
        if (fd < 0)
        {
            fd = (int)PayloadCrt.Syscall(PayloadCrt.SYS_open, (long)(nint)path, flags, DefaultMode);
        }
        if (fd < 0)
        {
            WriteResult(replyBuf, fd);
            return;
        }
        try
        {
            if (offset > 0)
            {
                long seek = KernelFile.sceKernelLseek(fd, offset, KernelFile.SeekSet);
                if (seek < 0)
                {
                    seek = PayloadCrt.Syscall(PayloadCrt.SYS_lseek, fd, offset, KernelFile.SeekSet);
                }
                if (seek < 0)
                {
                    WriteResult(replyBuf, (int)seek);
                    return;
                }
            }
            long n = KernelFile.sceKernelWrite(fd, cmdBuf + DataOffset, length);
            if (n < 0)
            {
                n = PayloadCrt.Syscall(PayloadCrt.SYS_write, fd, (long)(nint)(cmdBuf + DataOffset), (long)length);
            }
            if (n < 0)
            {
                WriteResult(replyBuf, (int)n);
                return;
            }
            WriteResult(replyBuf, (int)n);
            *(ulong*)(replyBuf + 0x10) = (ulong)n;
        }
        finally
        {
            KernelFile.sceKernelClose(fd);
        }
    }

    private static void HandleRename(byte* cmdBuf, byte* replyBuf)
    {
        // Source path lives at the same offset as every other command's path field. Destination
        // path lives at the data offset because a rename is the one command whose payload is
        // itself a second path, so the request layout doubles up both fields.
        byte* fromPath = cmdBuf + PathOffset;
        byte* toPath   = cmdBuf + DataOffset;
        if (fromPath[0] == 0 || !PathIsTerminated(fromPath)) { WriteResult(replyBuf, -22); return; }
        if (toPath[0] == 0   || !IsSecondPathTerminated(toPath)) { WriteResult(replyBuf, -22); return; }

        int rc = KernelFile.sceKernelRename(fromPath, toPath);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(PayloadCrt.SYS_rename, (long)(nint)fromPath, (long)(nint)toPath);
        }
        WriteResult(replyBuf, rc);
    }

    // The destination path for a rename shares its field with the ordinary write-data payload,
    // so its declared length is the data-region size rather than the path-region size. A NUL
    // must land within the data region for the kernel not to read past the request buffer.
    private static bool IsSecondPathTerminated(byte* path)
    {
        for (int i = 0; i < DataBytes; i++)
            if (path[i] == 0) return true;
        return false;
    }

    private static void WriteResult(byte* replyBuf, int result)
    {
        *(int*)(replyBuf + 0x08) = result;
        *(int*)(replyBuf + 0x0C) = result;
    }

    // Klog a "unjail: <op> rc=<value>\n" line with a decimal-formatted integer, so the daemon's
    // per-operation outcome can be read back through a later klog scan without a formatting
    // side-channel. Handles negative results and matches the log format the install and launch
    // chains parse for on-device verification.
    private static void KlogRc(ReadOnlySpan<byte> op, int rc)
    {
        byte* buf = stackalloc byte[128];
        int i = 0;
        ReadOnlySpan<byte> header = "unjail: "u8;
        for (int j = 0; j < header.Length; j++) buf[i++] = header[j];
        for (int j = 0; j < op.Length; j++) buf[i++] = op[j];
        ReadOnlySpan<byte> rcTag = " rc="u8;
        for (int j = 0; j < rcTag.Length; j++) buf[i++] = rcTag[j];

        int value = rc;
        if (value < 0) { buf[i++] = (byte)'-'; value = -value; }
        int startDigits = i;
        if (value == 0) { buf[i++] = (byte)'0'; }
        else
        {
            while (value > 0) { buf[i++] = (byte)('0' + (value % 10)); value /= 10; }
            int digitCount = i - startDigits;
            for (int j = 0; j < digitCount / 2; j++)
            {
                byte tmp = buf[startDigits + j];
                buf[startDigits + j] = buf[i - 1 - j];
                buf[i - 1 - j] = tmp;
            }
        }
        buf[i++] = (byte)'\n';
        buf[i] = 0;
        PayloadCrt.Klog(buf);
    }

    // ---- Filesystem primitive handlers ----

    // Reads statfs for a mount point. The reply's data region carries the sixteen-byte
    // f_fstypename string so the caller can decide whether the mount is a nullfs overlay
    // before unmounting it.
    private static void HandleStatfs(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        FreeBsdStatfs sfs = default;
        int rc = PayloadMount.statfs(path, &sfs);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(SYS_statfs, (long)(nint)path, (long)(nint)(&sfs));
        }
        if (rc != 0)
        {
            WriteResult(replyBuf, rc);
            KlogRc("statfs"u8, rc);
            return;
        }
        WriteResult(replyBuf, 0);
        for (int i = 0; i < 16; i++)
            (replyBuf + ReplyDataOffset)[i] = sfs.f_fstypename[i];
        KlogRc("statfs"u8, 0);
    }

    // Unmounts the target path with the flags carried at request +0x18. Callers must gate
    // this behind a CmdStatfs check that confirms the mount is a nullfs overlay; the daemon
    // does not repeat that check here so a wrong caller can only harm its own overlay.
    private static void HandleUnmount(byte* cmdBuf, byte* replyBuf)
    {
        byte* path = cmdBuf + PathOffset;
        if (path[0] == 0 || !PathIsTerminated(path)) { WriteResult(replyBuf, -22); return; }

        int flags = (int)*(uint*)(cmdBuf + 0x18);
        int rc = PayloadMount.unmount(path, flags);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(SYS_unmount, (long)(nint)path, flags);
        }
        WriteResult(replyBuf, rc);
        KlogRc("unmount"u8, rc);
    }

    // Mounts a nullfs overlay of the source path (data region) at the target path (path field).
    // The iovec array follows the FreeBSD nmount ABI: each string carries its trailing NUL so
    // the length field equals strlen + 1. Without prison0.pr_allow bit 0x100 the kernel refuses
    // the call before the ucred check even runs; the daemon opens that bit at startup.
    private static void HandleMountNullfs(byte* cmdBuf, byte* replyBuf)
    {
        byte* fspath = cmdBuf + PathOffset;
        byte* from   = cmdBuf + DataOffset;
        if (fspath[0] == 0 || !PathIsTerminated(fspath)) { WriteResult(replyBuf, -22); return; }
        if (from[0]   == 0 || !IsSecondPathTerminated(from)) { WriteResult(replyBuf, -22); return; }

        int rc = PayloadMount.MountNullfs(from, fspath);
        if (rc != 0)
        {
            FreeBsdIovec* iov = stackalloc FreeBsdIovec[6];
            byte* kFstype = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
            byte* vNullfs = stackalloc byte[] { (byte)'n', (byte)'u', (byte)'l', (byte)'l', (byte)'f', (byte)'s', 0 };
            byte* kFspath = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
            byte* kFrom   = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
            PayloadMount.SetIovecPair(&iov[0], kFstype, 7, vNullfs, 7);
            PayloadMount.SetIovecPair(&iov[2], kFspath, 7, fspath, StringLength(fspath) + 1);
            PayloadMount.SetIovecPair(&iov[4], kFrom,   5, from,   StringLength(from) + 1);
            rc = (int)PayloadCrt.Syscall(SYS_nmount, (long)(nint)iov, 6, 0);
        }
        WriteResult(replyBuf, rc);
        KlogRc("nullfs mount"u8, rc);
    }

    // Re-mounts /system_ex in place with MNT_UPDATE so the shell's cached view of the
    // partition flushes and picks up the /system_ex/app/<TID> directory a preceding
    // CmdMountNullfs added. EBUSY comes back when the mount is already in this exact
    // state; treat it as success so the caller does not have to know the current state.
    private static void HandleRemountSystemEx(byte* cmdBuf, byte* replyBuf)
    {
        FreeBsdIovec* iov = stackalloc FreeBsdIovec[14];
        byte* kFstype       = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'t', (byte)'y', (byte)'p', (byte)'e', 0 };
        byte* vExfatfs      = stackalloc byte[] { (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
        byte* kFrom         = stackalloc byte[] { (byte)'f', (byte)'r', (byte)'o', (byte)'m', 0 };
        byte* vSystemExDev  = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'s', (byte)'s', (byte)'d', (byte)'0', (byte)'.',
            (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m',
            (byte)'_', (byte)'e', (byte)'x', 0 };
        byte* kFspath       = stackalloc byte[] { (byte)'f', (byte)'s', (byte)'p', (byte)'a', (byte)'t', (byte)'h', 0 };
        byte* vSystemEx     = stackalloc byte[] {
            (byte)'/', (byte)'s', (byte)'y', (byte)'s', (byte)'t', (byte)'e', (byte)'m',
            (byte)'_', (byte)'e', (byte)'x', 0 };
        byte* kLarge        = stackalloc byte[] { (byte)'l', (byte)'a', (byte)'r', (byte)'g', (byte)'e', 0 };
        byte* vYes          = stackalloc byte[] { (byte)'y', (byte)'e', (byte)'s', 0 };
        byte* kTimezone     = stackalloc byte[] { (byte)'t', (byte)'i', (byte)'m', (byte)'e', (byte)'z', (byte)'o', (byte)'n', (byte)'e', 0 };
        byte* vStatic       = stackalloc byte[] { (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'i', (byte)'c', 0 };
        byte* kAsync        = stackalloc byte[] { (byte)'a', (byte)'s', (byte)'y', (byte)'n', (byte)'c', 0 };
        byte* kIgnoreacl    = stackalloc byte[] { (byte)'i', (byte)'g', (byte)'n', (byte)'o', (byte)'r', (byte)'e', (byte)'a', (byte)'c', (byte)'l', 0 };

        PayloadMount.SetIovecPair(&iov[0], kFstype, 7, vExfatfs, 8);
        PayloadMount.SetIovecPair(&iov[2], kFrom, 5, vSystemExDev, 20);
        PayloadMount.SetIovecPair(&iov[4], kFspath, 7, vSystemEx, 11);
        PayloadMount.SetIovecPair(&iov[6], kLarge, 6, vYes, 4);
        PayloadMount.SetIovecPair(&iov[8], kTimezone, 9, vStatic, 7);
        PayloadMount.SetIovecFlag(&iov[10], kAsync, 6);
        PayloadMount.SetIovecFlag(&iov[12], kIgnoreacl, 10);

        int rc = PayloadMount.nmount(iov, 14, MNT_UPDATE);
        if (rc != 0)
        {
            rc = (int)PayloadCrt.Syscall(SYS_nmount, (long)(nint)iov, 14, MNT_UPDATE);
        }
        // EBUSY means the update landed as a no-op because the mount already carries these
        // parameters. The caller treats that as success too.
        if (rc == -16) rc = 0;
        WriteResult(replyBuf, rc);
        KlogRc("system_ex remount"u8, rc);
    }

    // ---- Launch primitive handlers ----

    // Walks sysctl(KERN_PROC_PROC) once and returns the pid of the process whose sceKernelGetAppInfo
    // titleId matches the caller's request. Returns -1 when no running process carries that title.
    private static void HandleFindPidByTitleId(byte* cmdBuf, byte* replyBuf)
    {
        byte* titleId = cmdBuf + PathOffset;
        if (titleId[0] == 0 || !PathIsTerminated(titleId)) { WriteResult(replyBuf, -22); return; }

        int pid = FindPidByTitleId(titleId);
        WriteResult(replyBuf, pid);
        KlogRc("find_pid"u8, pid);
    }

    // Arms the launch worker: copies the caller's titleId and user id into a private page,
    // spawns a pthread on that page as its argument, and returns rc=0 to the caller. The worker
    // outlives the request handler; the caller is free to exit its own process once the reply
    // lands. The worker fires sceSystemServiceLaunchApp, blocks on kqueue/EVFILT_PROC/NOTE_EXIT
    // for the launched pid, sleeps a three-second grace window, then unmounts the nullfs
    // overlay at /system_ex/app/<TID> so the next install cycle starts on a clean mount table.
    private static void HandleArmLaunchAndWaitForExit(byte* cmdBuf, byte* replyBuf)
    {
        byte* titleId = cmdBuf + PathOffset;
        if (titleId[0] == 0 || !PathIsTerminated(titleId)) { WriteResult(replyBuf, -22); return; }

        // Allocate a single 4 KiB page for the worker's context. mmap MAP_ANON is zero-filled
        // by the kernel; the worker frees it via munmap when it exits.
        void* ctxPage = PayloadIo.mmap(null, 4096,
            PayloadIo.ProtRead | PayloadIo.ProtWrite,
            PayloadIo.MapPrivate | PayloadIo.MapAnon, -1, 0);
        if ((long)ctxPage == -1)
        {
            WriteResult(replyBuf, -12); // ENOMEM
            KlogRc("launch armed"u8, -12);
            return;
        }
        LaunchWorkerCtx* ctx = (LaunchWorkerCtx*)ctxPage;

        int idLen = 0;
        while (idLen < 15 && titleId[idLen] != 0) { ctx->TitleId[idLen] = titleId[idLen]; idLen++; }
        // Data region layout: u32 user_id at +0x220, u16 source_len at +0x224, char source[] at +0x226.
        ctx->UserId = *(uint*)(cmdBuf + DataOffset);

        nint thread = 0;
        fixed (byte* threadName = "unjail_launch\0"u8)
        {
            int rc = PayloadThread.Create(&thread, null, &LaunchWorkerEntry, ctxPage, threadName);
            if (rc != 0)
            {
                PayloadIo.munmap(ctxPage, 4096);
                WriteResult(replyBuf, -rc);
                KlogRc("launch armed"u8, -rc);
                return;
            }
        }
        PayloadThread.scePthreadDetach(thread);
        WriteResult(replyBuf, 0);
        KlogRc("launch armed"u8, 0);
    }

    // ---- Install primitive handlers ----

    private static void HandleAppInstUtilInitialize(byte* cmdBuf, byte* replyBuf)
    {
        int rc = PayloadAppInstaller.sceAppInstUtilInitialize();
        WriteResult(replyBuf, rc);
        KlogRc("instutil init"u8, rc);
    }

    private static void HandleAppInstUtilAppUnInstall(byte* cmdBuf, byte* replyBuf)
    {
        byte* titleId = cmdBuf + PathOffset;
        if (titleId[0] == 0 || !PathIsTerminated(titleId)) { WriteResult(replyBuf, -22); return; }

        int rc = PayloadAppInstaller.sceAppInstUtilAppUnInstall(titleId);
        WriteResult(replyBuf, rc);
        KlogRc("instutil uninstall"u8, rc);
    }

    // Registers the title identifier and directory pair with the install service. On the
    // firmware groups this daemon targets the direct call answers with zero on success; on
    // groups where the entry point moved (12.00 and later) the call returns non-zero and the
    // handler falls through to sceAppInstUtilAppInstallAll(null), which walks every pending row.
    private static void HandleAppInstUtilAppInstallTitleDir(byte* cmdBuf, byte* replyBuf)
    {
        byte* titleId = cmdBuf + PathOffset;
        byte* dir     = cmdBuf + DataOffset;
        if (titleId[0] == 0 || !PathIsTerminated(titleId)) { WriteResult(replyBuf, -22); return; }
        if (dir[0]     == 0 || !IsSecondPathTerminated(dir)) { WriteResult(replyBuf, -22); return; }

        int rc = PayloadAppInstaller.sceAppInstUtilAppInstallTitleDir(titleId, dir, null);
        if (rc != 0)
        {
            int rcAll = PayloadAppInstaller.sceAppInstUtilAppInstallAll(null);
            if (rcAll == 0) rc = 0;
        }
        WriteResult(replyBuf, rc);
        KlogRc("instutil install"u8, rc);
    }

    // ---- File-copy primitive handlers ----

    // Recursively copies every regular file and subdirectory from the source path (path field)
    // into the destination path (data region). The destination is created if missing; existing
    // files are overwritten. Reports the number of regular files copied.
    private static void HandleCopyDirRecursive(byte* cmdBuf, byte* replyBuf)
    {
        byte* src = cmdBuf + PathOffset;
        byte* dst = cmdBuf + DataOffset;
        if (src[0] == 0 || !PathIsTerminated(src)) { WriteResult(replyBuf, -22); return; }
        if (dst[0] == 0 || !IsSecondPathTerminated(dst)) { WriteResult(replyBuf, -22); return; }

        int files = CopyDirRecursive(src, dst);
        WriteResult(replyBuf, files >= 0 ? files : -1);
        KlogRc("copydir"u8, files);
    }

    // Copies a single file end-to-end at the daemon side. Reads chunk-by-chunk through the same
    // 8 MiB copy buffer CopyDirRecursive reuses, and never round-trips per chunk to the caller.
    // The socket-per-chunk pattern the caller's WriteRange loop had to fall back to for large
    // files ran the module out of ephemeral TCP ports on a multi-hundred-MB disc image; a single
    // CmdCopyFile call replaces every one of those round-trips.
    private static void HandleCopyFile(byte* cmdBuf, byte* replyBuf)
    {
        byte* src = cmdBuf + PathOffset;
        byte* dst = cmdBuf + DataOffset;
        if (src[0] == 0 || !PathIsTerminated(src)) { WriteResult(replyBuf, -22); return; }
        if (dst[0] == 0 || !IsSecondPathTerminated(dst)) { WriteResult(replyBuf, -22); return; }

        bool ok = CopyOneFile(src, dst);
        WriteResult(replyBuf, ok ? 0 : -1);
        KlogRc("copyfile"u8, ok ? 0 : -1);
    }

    // Copies the appmeta-visible files (param.json, param.sfo, and any .png/.dds/.at9 asset)
    // from the source sce_sys folder (path field) into /user/appmeta/<TID> (titleId in data
    // region). Top-level only; subdirectories are not copied here (upstream trophy2 and uds
    // files are copied through CmdUpdateTrophy instead). The parent /user/appmeta directory
    // is created world-writable to match the shell's own layout expectations.
    private static void HandleCopySceSysToAppmeta(byte* cmdBuf, byte* replyBuf)
    {
        byte* src     = cmdBuf + PathOffset;
        byte* titleId = cmdBuf + DataOffset;
        if (src[0] == 0 || !PathIsTerminated(src)) { WriteResult(replyBuf, -22); return; }
        if (titleId[0] == 0 || !IsSecondPathTerminated(titleId)) { WriteResult(replyBuf, -22); return; }

        byte* appmetaRoot = stackalloc byte[] {
            (byte)'/', (byte)'u', (byte)'s', (byte)'e', (byte)'r',
            (byte)'/', (byte)'a', (byte)'p', (byte)'p', (byte)'m', (byte)'e', (byte)'t', (byte)'a', 0 };
        PayloadFileSystem.mkdir(appmetaRoot, 0x1FF); // 0777

        byte* dst = stackalloc byte[256];
        ReadOnlySpan<byte> prefix = "/user/appmeta/"u8;
        for (int i = 0; i < prefix.Length; i++) dst[i] = prefix[i];
        int prefixLen = prefix.Length;
        int idLen = 0;
        while (idLen < 15 && titleId[idLen] != 0) { dst[prefixLen + idLen] = titleId[idLen]; idLen++; }
        dst[prefixLen + idLen] = 0;
        PayloadFileSystem.mkdir(dst, 0x1ED); // 0755

        void* dir = PayloadFileSystem.opendir(src);
        if (dir == null)
        {
            WriteResult(replyBuf, -1);
            KlogRc("appmeta copy"u8, -1);
            return;
        }

        int copied = 0;
        byte* srcPath = stackalloc byte[512];
        byte* dstPath = stackalloc byte[512];
        while (true)
        {
            FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
            if (entry == null) break;
            if (entry->d_type != PayloadFileSystem.DT_REG) continue;
            if (!IsAppmetaFile(entry->d_name)) continue;
            JoinPath(srcPath, src, entry->d_name);
            JoinPath(dstPath, dst, entry->d_name);
            if (CopyOneFile(srcPath, dstPath)) copied++;
        }
        PayloadFileSystem.closedir(dir);
        WriteResult(replyBuf, copied);
        KlogRc("appmeta copy"u8, copied);
    }

    // Populates /system_data/priv/appmeta/<TID> with the trophy data files that the shell's
    // trophy service reads on launch. Only the three files the reference dump chain copies
    // land here: trophy2/npbind.dat, uds/npbind.dat, and param.json. Missing sources silently
    // no-op so a title with no trophies still installs.
    private static void HandleUpdateTrophy(byte* cmdBuf, byte* replyBuf)
    {
        byte* titleId  = cmdBuf + PathOffset;
        byte* srcRoot  = cmdBuf + DataOffset;
        if (titleId[0] == 0 || !PathIsTerminated(titleId)) { WriteResult(replyBuf, -22); return; }
        if (srcRoot[0] == 0 || !IsSecondPathTerminated(srcRoot)) { WriteResult(replyBuf, -22); return; }

        byte* metaDir = stackalloc byte[256];
        ReadOnlySpan<byte> metaPrefix = "/system_data/priv/appmeta/"u8;
        for (int i = 0; i < metaPrefix.Length; i++) metaDir[i] = metaPrefix[i];
        int off = metaPrefix.Length;
        int idLen = 0;
        while (idLen < 15 && titleId[idLen] != 0) { metaDir[off + idLen] = titleId[idLen]; idLen++; }
        int metaLen = off + idLen;
        metaDir[metaLen] = 0;

        PayloadFileSystem.mkdir(metaDir, 0x1ED); // 0755

        byte* trophyDir = stackalloc byte[256];
        for (int i = 0; i < metaLen; i++) trophyDir[i] = metaDir[i];
        ReadOnlySpan<byte> tSuf = "/trophy2"u8;
        for (int i = 0; i < tSuf.Length; i++) trophyDir[metaLen + i] = tSuf[i];
        trophyDir[metaLen + tSuf.Length] = 0;
        PayloadFileSystem.mkdir(trophyDir, 0x1ED);

        byte* udsDir = stackalloc byte[256];
        for (int i = 0; i < metaLen; i++) udsDir[i] = metaDir[i];
        ReadOnlySpan<byte> uSuf = "/uds"u8;
        for (int i = 0; i < uSuf.Length; i++) udsDir[metaLen + i] = uSuf[i];
        udsDir[metaLen + uSuf.Length] = 0;
        PayloadFileSystem.mkdir(udsDir, 0x1ED);

        int srcLen = 0;
        while (srcRoot[srcLen] != 0) srcLen++;

        int trophyOk = TryCopyTrophyItem(srcRoot, srcLen, "/trophy2/npbind.dat"u8, metaDir, metaLen, "/trophy2/npbind.dat"u8);
        int udsOk    = TryCopyTrophyItem(srcRoot, srcLen, "/uds/npbind.dat"u8,     metaDir, metaLen, "/uds/npbind.dat"u8);
        int paramOk  = TryCopyTrophyItem(srcRoot, srcLen, "/param.json"u8,         metaDir, metaLen, "/param.json"u8);

        WriteResult(replyBuf, 0);
        // Pack the three per-file results into a single rc value so the caller can read the
        // outcome of each source in one klog line: bit 0 = trophy2, bit 1 = uds, bit 2 = param.
        int summary = trophyOk | (udsOk << 1) | (paramOk << 2);
        KlogRc("trophy update"u8, summary);
    }

    // ---- Helpers for the extended handlers ----

    // Buffer reused across every CopyOneFile call. Allocated on first use via mmap so the
    // daemon can walk a large recursive copy without allocating and freeing an eight-megabyte
    // block per file. The stack is not an option: the daemon's per-thread stack is 256 KiB.
    private static void* s_copyBuffer;
    private const nuint CopyBufferSize = 8 * 1024 * 1024;

    private static bool EnsureCopyBuffer()
    {
        if (s_copyBuffer != null) return true;
        void* p = PayloadIo.mmap(null, CopyBufferSize,
            PayloadIo.ProtRead | PayloadIo.ProtWrite,
            PayloadIo.MapPrivate | PayloadIo.MapAnon, -1, 0);
        if ((long)p == -1) return false;
        s_copyBuffer = p;
        return true;
    }

    private static int CopyDirRecursive(byte* src, byte* dst)
    {
        PayloadFileSystem.mkdir(dst, 0x1ED); // 0755

        void* dir = PayloadFileSystem.opendir(src);
        if (dir == null) return -1;

        int total = 0;
        byte* srcPath = stackalloc byte[1024];
        byte* dstPath = stackalloc byte[1024];
        while (true)
        {
            FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
            if (entry == null) break;
            if (entry->d_name[0] == (byte)'.' &&
                (entry->d_name[1] == 0 ||
                 (entry->d_name[1] == (byte)'.' && entry->d_name[2] == 0)))
                continue;

            JoinPath(srcPath, src, entry->d_name);
            JoinPath(dstPath, dst, entry->d_name);

            if (entry->d_type == PayloadFileSystem.DT_DIR)
            {
                int sub = CopyDirRecursive(srcPath, dstPath);
                if (sub < 0) { PayloadFileSystem.closedir(dir); return -1; }
                total += sub;
            }
            else if (entry->d_type == PayloadFileSystem.DT_REG)
            {
                if (!CopyOneFile(srcPath, dstPath)) { PayloadFileSystem.closedir(dir); return -1; }
                total++;
            }
        }
        PayloadFileSystem.closedir(dir);
        return total;
    }

    private static bool CopyOneFile(byte* src, byte* dst)
    {
        if (!EnsureCopyBuffer()) return false;

        FreeBsdStat srcStat = default;
        PayloadFileSystem.stat(src, &srcStat);

        int srcFd = PayloadIo.open(src, PayloadFileSystem.O_RDONLY);
        if (srcFd < 0) return false;

        ushort mode = (ushort)(srcStat.st_mode | 0x180); // ensure the daemon can rewrite the file later
        int dstFd = PayloadIo.open(dst,
            PayloadFileSystem.O_WRONLY | PayloadFileSystem.O_CREAT | PayloadFileSystem.O_TRUNC, mode);
        if (dstFd < 0)
        {
            PayloadIo.close(srcFd);
            return false;
        }

        byte* buf = (byte*)s_copyBuffer;
        bool ok = true;
        while (true)
        {
            long n = PayloadIo.read(srcFd, buf, CopyBufferSize);
            if (n <= 0) break;
            long written = 0;
            while (written < n)
            {
                long w = PayloadIo.write(dstFd, buf + written, (nuint)(n - written));
                if (w <= 0) { ok = false; break; }
                written += w;
            }
            if (!ok) break;
        }
        PayloadIo.close(dstFd);
        PayloadIo.close(srcFd);
        return ok;
    }

    private static int TryCopyTrophyItem(byte* srcBase, int srcLen, ReadOnlySpan<byte> srcSuf,
        byte* dstBase, int dstLen, ReadOnlySpan<byte> dstSuf)
    {
        byte* srcPath = stackalloc byte[512];
        byte* dstPath = stackalloc byte[512];
        for (int i = 0; i < srcLen; i++) srcPath[i] = srcBase[i];
        for (int i = 0; i < srcSuf.Length; i++) srcPath[srcLen + i] = srcSuf[i];
        srcPath[srcLen + srcSuf.Length] = 0;

        if (PayloadFileSystem.access(srcPath, PayloadFileSystem.F_OK) != 0) return 0;

        for (int i = 0; i < dstLen; i++) dstPath[i] = dstBase[i];
        for (int i = 0; i < dstSuf.Length; i++) dstPath[dstLen + i] = dstSuf[i];
        dstPath[dstLen + dstSuf.Length] = 0;

        return CopyOneFile(srcPath, dstPath) ? 1 : 0;
    }

    private static bool IsAppmetaFile(byte* name)
    {
        if (StrEqualIgnoreCase(name, "param.json"u8)) return true;
        if (StrEqualIgnoreCase(name, "param.sfo"u8)) return true;

        int len = 0;
        while (name[len] != 0) len++;
        if (len < 4) return false;

        byte* ext = name + len - 4;
        if (ext[0] != (byte)'.') return false;
        byte a = ToLowerAscii(ext[1]);
        byte b = ToLowerAscii(ext[2]);
        byte c = ToLowerAscii(ext[3]);
        if (a == (byte)'p' && b == (byte)'n' && c == (byte)'g') return true;
        if (a == (byte)'d' && b == (byte)'d' && c == (byte)'s') return true;
        if (a == (byte)'a' && b == (byte)'t' && c == (byte)'9') return true;
        return false;
    }

    private static bool StrEqualIgnoreCase(byte* a, ReadOnlySpan<byte> b)
    {
        for (int i = 0; i < b.Length; i++)
        {
            if (ToLowerAscii(a[i]) != ToLowerAscii(b[i])) return false;
        }
        return a[b.Length] == 0;
    }

    private static byte ToLowerAscii(byte c)
        => (c >= (byte)'A' && c <= (byte)'Z') ? (byte)(c + 32) : c;

    private static void JoinPath(byte* dst, byte* dir, byte* name)
    {
        int i = 0;
        while (*dir != 0) { dst[i++] = *dir; dir++; }
        dst[i++] = (byte)'/';
        while (*name != 0) { dst[i++] = *name; name++; }
        dst[i] = 0;
    }

    private static int StringLength(byte* s)
    {
        int n = 0;
        while (s[n] != 0) n++;
        return n;
    }

    // Walks sysctl(KERN_PROC_PROC) once and returns the pid of the first process whose
    // sceKernelGetAppInfo titleId matches the caller's request. The buffer is mmap'd (the
    // kinfo_proc set can exceed 64 KiB, past what the daemon's stack can hold) and freed
    // before returning.
    private static int FindPidByTitleId(byte* titleId)
    {
        int* mib = stackalloc int[4];
        mib[0] = CTL_KERN;
        mib[1] = KERN_PROC;
        mib[2] = KERN_PROC_PROC;
        mib[3] = 0;

        nuint size = 0;
        if (PayloadSysctl.sysctl(mib, 4, null, &size, null, 0) != 0)
            return -1;

        size += 4096;
        void* mapped = PayloadIo.mmap(null, size,
            PayloadIo.ProtRead | PayloadIo.ProtWrite,
            PayloadIo.MapPrivate | PayloadIo.MapAnon, -1, 0);
        if ((long)mapped == -1) return -1;
        byte* buf = (byte*)mapped;

        int idLen = 0;
        while (idLen < 10 && titleId[idLen] != 0) idLen++;

        int found = -1;
        nuint actualSize = size;
        if (PayloadSysctl.sysctl(mib, 4, buf, &actualSize, null, 0) == 0)
        {
            PayloadAppInfo info = default;
            nuint offset = 0;
            while (offset < actualSize)
            {
                byte* entry = buf + offset;
                int structSize = *(int*)(entry + KinfoProcStructSize);
                if (structSize <= 0) break;
                int pid = *(int*)(entry + KinfoProcPid);

                if (PayloadProcess.sceKernelGetAppInfo(pid, &info) == 0)
                {
                    bool match = true;
                    for (int j = 0; j < idLen; j++)
                    {
                        if (info.TitleId[j] != titleId[j]) { match = false; break; }
                    }
                    if (match && (idLen >= 10 || info.TitleId[idLen] == 0))
                    {
                        found = pid;
                        break;
                    }
                }
                offset += (nuint)structSize;
            }
        }
        PayloadIo.munmap(mapped, size);
        return found;
    }

    // ---- Launch worker ----

    // Context handed to the launch worker thread. The handler allocates a 4 KiB page for
    // this struct so the worker can outlive the request handler that spawned it.
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct LaunchWorkerCtx
    {
        public fixed byte TitleId[16];
        public uint UserId;
        public uint _pad;
    }

    // Runs on a detached pthread spawned by HandleArmLaunchAndWaitForExit. Sleeps briefly so
    // the calling app has time to run its own sceSystemServiceLoadExec("exit", NULL) and free
    // SceShellCore's foreground slot before the worker fires the launch, then delegates the
    // launch to the system-service call, blocks on kqueue/EVFILT_PROC/NOTE_EXIT for the
    // launched pid, and unmounts the /system_ex/app/<TID> nullfs overlay after a grace window.
    [UnmanagedCallersOnly]
    private static void* LaunchWorkerEntry(void* argVoid)
    {
        LaunchWorkerCtx* ctx = (LaunchWorkerCtx*)argVoid;

        // Wait two seconds so the caller's own exit path (sceSystemServiceLoadExec("exit", NULL))
        // completes and the shell's foreground slot is free before the launch call fires. The
        // reference dump_runner runs the launch AFTER its own module has exited; matching that
        // flow avoids the racy overlap where a caller with a still-open foreground slot could
        // interfere with the launched title's compositor claim.
        KernelTimespec preLaunchTs = default;
        preLaunchTs.Seconds = 2;
        preLaunchTs.Nanoseconds = 0;
        PayloadCrt.Syscall(PayloadCrt.SYS_nanosleep, (long)(nint)(&preLaunchTs), 0);

        // sceSystemServiceLaunchApp context: { u32 structsize; u32 user_id; u32 app_opt;
        // u32 pad; u64 crash_report; u32 check_flag }. 32 bytes with x86_64 alignment padding
        // (4 bytes internal before crash_report, 4 bytes trailing for 8-byte struct alignment).
        byte* launchCtx = stackalloc byte[32];
        for (int i = 0; i < 32; i++) launchCtx[i] = 0;
        *(uint*)(launchCtx + 0) = 32;
        *(uint*)(launchCtx + 4) = ctx->UserId;

        // argv points at a stack cell containing NULL, matching the reference call site's
        // argv[argc]==NULL layout. Passing a literal NULL as argv is undefined by the SDK.
        byte** argv = stackalloc byte*[1];
        argv[0] = null;

        int launchRc = SystemService.sceSystemServiceLaunchApp(ctx->TitleId, argv, launchCtx);
        if (launchRc < 0)
        {
            KlogRc("launchapp"u8, launchRc);
            PayloadIo.munmap(argVoid, 4096);
            return null;
        }
        KlogRc("launchapp"u8, launchRc);

        // Poll every 100 ms for up to five seconds for the launched pid.
        int launchedPid = -1;
        for (int poll = 0; poll < 50 && launchedPid < 0; poll++)
        {
            launchedPid = FindPidByTitleId(ctx->TitleId);
            if (launchedPid > 0) break;
            KernelTimespec pollTs = default;
            pollTs.Seconds = 0;
            pollTs.Nanoseconds = 100_000_000;
            PayloadCrt.Syscall(PayloadCrt.SYS_nanosleep, (long)(nint)(&pollTs), 0);
        }
        if (launchedPid < 0)
        {
            KlogRc("launch child pid"u8, -1);
            PayloadIo.munmap(argVoid, 4096);
            return null;
        }
        KlogRc("launch child pid"u8, launchedPid);

        int kq = PayloadEvent.kqueue();
        if (kq < 0)
        {
            kq = (int)PayloadCrt.Syscall(SYS_kqueue, 0);
        }
        if (kq < 0)
        {
            KlogRc("kqueue"u8, kq);
            PayloadIo.munmap(argVoid, 4096);
            return null;
        }

        FreeBsdKevent* changes   = stackalloc FreeBsdKevent[1];
        FreeBsdKevent* eventsOut = stackalloc FreeBsdKevent[1];
        PayloadEvent.EvSet(&changes[0], (nuint)launchedPid, PayloadEvent.EvfiltProc,
            PayloadEvent.EvAdd, PayloadEvent.NoteExit, 0, null);

        KernelTimespec waitTs = default;
        waitTs.Seconds = 1;
        waitTs.Nanoseconds = 0;

        while (true)
        {
            int n = PayloadEvent.kevent(kq, changes, 1, eventsOut, 1, &waitTs);
            // The registration is one-shot: after the first kevent call clears the changelist.
            changes[0].flags = 0;
            if (n > 0 && (eventsOut[0].fflags & PayloadEvent.NoteExit) != 0)
                break;
            if (n < 0) break;
        }
        SysClose(kq);

        // 3-second grace period so the shell's post-exit teardown finishes before the unmount
        KernelTimespec graceTs = default;
        graceTs.Seconds = 3;
        graceTs.Nanoseconds = 0;
        PayloadCrt.Syscall(PayloadCrt.SYS_nanosleep, (long)(nint)(&graceTs), 0);

        // Unmount /system_ex/app/<TID>. EBUSY can come back when the child's descriptor
        // teardown is still in flight; the loop retries five times at one-second intervals
        // before giving up.
        byte* mountPath = stackalloc byte[64];
        for (int i = 0; i < 64; i++) mountPath[i] = 0;
        ReadOnlySpan<byte> mountPrefix = "/system_ex/app/"u8;
        for (int i = 0; i < mountPrefix.Length; i++) mountPath[i] = mountPrefix[i];
        int prefixLen = mountPrefix.Length;
        for (int i = 0; i < 10 && ctx->TitleId[i] != 0; i++) mountPath[prefixLen + i] = ctx->TitleId[i];

        int unmountRc = PayloadMount.unmount(mountPath, 0);
        for (int retry = 0; retry < 5 && unmountRc != 0; retry++)
        {
            KernelTimespec retryTs = default;
            retryTs.Seconds = 1;
            retryTs.Nanoseconds = 0;
            PayloadCrt.Syscall(PayloadCrt.SYS_nanosleep, (long)(nint)(&retryTs), 0);
            unmountRc = PayloadMount.unmount(mountPath, 0);
        }
        KlogRc("child exited unmount"u8, unmountRc);

        PayloadIo.munmap(argVoid, 4096);
        return null;
    }
}
