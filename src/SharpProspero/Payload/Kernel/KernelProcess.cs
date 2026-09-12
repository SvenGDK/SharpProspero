// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Posix;
using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Walks the kernel's process list and modifies process credentials and directory jails.
/// </summary>
/// <remarks>
/// <para>
/// Two calling patterns are available. The <c>io</c>-based methods (<see cref="RemoveJail(PayloadKernelIo, ulong)"/>,
/// <see cref="EscalateCredentials(PayloadKernelIo, ulong)"/>) route every field access through the managed
/// <see cref="PayloadKernelIo"/> wrapper. The <c>pid</c>-based methods (<see cref="RemoveJail(int)"/>,
/// <see cref="EscalateCredentials(int)"/>) dispatch directly into the CRT-emitted kernel accessors,
/// bypassing the managed pipe wrapper entirely. The pid-based path is preferred for credential and
/// jail operations because it follows the same unmanaged call chain that every C payload uses.
/// </para>
/// <para>
/// Every address and field offset comes from <see cref="KernelOffsets"/>. Absolute kernel
/// addresses are computed at runtime from the loader-provided <c>kdata_base</c> and the
/// firmware-versioned offset tables, so the same binary works across all supported firmwares.
/// </para>
/// </remarks>
public static unsafe partial class PayloadKernel
{
    private const int MaxComm = 17;
    private const int MaxTitleId = 10;
    // Safety cap on the number of processes any single allproc walk visits.
    // The kernel's process list is well below this in practice; the cap only
    // exists so a corrupted or looped p_list link terminates the walk instead
    // of wedging the payload thread. 4096 matches the boundary the checked
    // walkers use so every allproc walker in this class caps the same way.
    private const int MaxAllprocIterations = 4096;

    // ---- Firmware version and address cache ----

    private static uint s_firmwareVersion;
    private static ulong s_kdataBase;
    private static ulong s_allprocAddr;
    private static ulong s_rootvnodeAddr;
    private static ulong s_qaFlagsAddr;
    private static ulong s_prison0;

    /// <summary>
    /// Queries the running firmware version via <c>sysctl({CTL_KERN, 46})</c> and caches the
    /// result. Returns a BCD-encoded version (e.g. <c>0x10010000</c> for FW 10.01).
    /// </summary>
    public static uint GetSystemSoftwareVersion()
    {
        if (s_firmwareVersion != 0)
            return s_firmwareVersion;
        int* mib = stackalloc int[2];
        mib[0] = 1;   // CTL_KERN
        mib[1] = 46;  // kern.sdk_version
        uint version = 0;
        nuint size = 4;
        PayloadSysctl.sysctl(mib, 2, &version, &size, null, 0);
        s_firmwareVersion = version;
        return version;
    }

    private static ulong KdataBase
    {
        get
        {
            if (s_kdataBase == 0)
                s_kdataBase = PayloadEntryPoint.Args->KernelDataBase;
            return s_kdataBase;
        }
    }

    private static ulong AllprocAddress
    {
        get
        {
            if (s_allprocAddr == 0)
                s_allprocAddr = KdataBase + KernelOffsets.Allproc(GetSystemSoftwareVersion());
            return s_allprocAddr;
        }
    }

    private static ulong RootvnodeAddress
    {
        get
        {
            if (s_rootvnodeAddr == 0)
                s_rootvnodeAddr = KdataBase + KernelOffsets.Rootvnode(GetSystemSoftwareVersion());
            return s_rootvnodeAddr;
        }
    }

    private static ulong QaFlagsAddress
    {
        get
        {
            if (s_qaFlagsAddr == 0)
                s_qaFlagsAddr = KdataBase + KernelOffsets.QaFlags(GetSystemSoftwareVersion());
            return s_qaFlagsAddr;
        }
    }

    /// <summary>
    /// Finds the <c>prison0</c> address by reading PID 1's credential prison pointer.
    /// PID 1 (init) is always in the root prison. The result is cached.
    /// </summary>
    public static ulong GetPrison0(PayloadKernelIo io)
    {
        if (s_prison0 != 0)
            return s_prison0;
        ulong proc = io.ReadU64(AllprocAddress);
        int safety = 0;
        while (proc != 0 && safety < 4096)
        {
            int pid = (int)io.ReadU32(proc + (ulong)KernelOffsets.ProcPid);
            if (pid == 1)
            {
                ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
                s_prison0 = io.ReadU64(ucred + (ulong)KernelOffsets.UcredPrison);
                return s_prison0;
            }
            proc = io.ReadU64(proc + (ulong)KernelOffsets.ProcList);
            safety++;
        }
        return 0;
    }

    /// <summary>
    /// Returns the cached <c>prison0</c> address. If not yet cached, constructs a temporary
    /// <see cref="PayloadKernelIo"/> from the payload arguments and calls <see cref="GetPrison0(PayloadKernelIo)"/>.
    /// </summary>
    public static ulong GetPrison0()
    {
        if (s_prison0 != 0)
            return s_prison0;
        var io = new PayloadKernelIo(PayloadEntryPoint.Args);
        return GetPrison0(io);
    }

    /// <summary>
    /// Walks the process list starting at <c>allproc</c> and returns the kernel address of the first
    /// process whose title identifier matches <paramref name="titleId"/>, or zero if none is found.
    /// </summary>
    public static ulong FindProcessByTitleId(PayloadKernelIo io, byte* titleId, int titleIdLength)
    {
        ulong proc = io.ReadU64(AllprocAddress);
        byte* buf = stackalloc byte[MaxTitleId + 1];
        buf[MaxTitleId] = 0;
        int safety = 0;
        while (proc != 0 && safety < MaxAllprocIterations)
        {
            io.Read(proc + (ulong)KernelOffsets.ProcTitleId, buf, MaxTitleId);
            if (MatchName(buf, titleId, titleIdLength))
                return proc;
            proc = io.ReadU64(proc + (ulong)KernelOffsets.ProcList);
            safety++;
        }
        return 0;
    }

    /// <summary>
    /// Walks the process list starting at <c>allproc</c> and returns the kernel address of the first
    /// process whose <c>p_comm</c> matches the given name, or zero if none is found.
    /// </summary>
    public static ulong FindProcessByName(PayloadKernelIo io, byte* name, int nameLength)
    {
        ulong proc = io.ReadU64(AllprocAddress);
        byte* comm = stackalloc byte[MaxComm + 1];
        comm[MaxComm] = 0;
        int safety = 0;
        while (proc != 0 && safety < MaxAllprocIterations)
        {
            io.Read(proc + (ulong)KernelOffsets.ProcComm, comm, MaxComm);
            if (MatchName(comm, name, nameLength))
                return proc;
            proc = io.ReadU64(proc + (ulong)KernelOffsets.ProcList);
            safety++;
        }
        return 0;
    }

    /// <summary>
    /// Returns the kernel address of the first process whose <c>p_comm</c> matches the given name,
    /// or zero if none is found. Dispatches into the CRT-emitted process walker, which traverses
    /// the allproc list and compares names entirely in unmanaged code without any managed copyout
    /// calls on the walk path.
    /// </summary>
    public static ulong FindProcessByComm(ReadOnlySpan<byte> name)
    {
        fixed (byte* p = name)
            return CrtFindProcByComm(p, name.Length);
    }

    /// <summary>
    /// Walks the process list starting at <c>allproc</c> and returns the kernel address of the process
    /// with the given <paramref name="pid"/>, or zero if none is found.
    /// </summary>
    public static ulong FindProcessByPid(PayloadKernelIo io, int pid)
    {
        ulong proc = io.ReadU64(AllprocAddress);
        int safety = 0;
        while (proc != 0 && safety < MaxAllprocIterations)
        {
            int p = (int)io.ReadU32(proc + (ulong)KernelOffsets.ProcPid);
            if (p == pid)
                return proc;
            proc = io.ReadU64(proc + (ulong)KernelOffsets.ProcList);
            safety++;
        }
        return 0;
    }

    /// <summary>
    /// Walks the process list starting at <c>allproc</c> and returns the kernel address of the
    /// process with the given <paramref name="pid"/>, or zero if none is found. Uses the checked
    /// <see cref="PayloadKernelIo.TryReadU64"/> and <see cref="PayloadKernelIo.TryReadU32"/>
    /// methods so a copyout failure terminates the walk immediately rather than producing a
    /// silent zero that could be mistaken for a genuine list tail. Caps the walk at 4096
    /// iterations to prevent an infinite loop on a corrupted list.
    /// </summary>
    public static ulong WalkAllprocForPid(PayloadKernelIo io, int pid)
    {
        if (!io.TryReadU64(AllprocAddress, out ulong proc))
            return 0;
        int safety = 0;
        while (proc != 0 && safety < 4096)
        {
            if (io.TryReadU32(proc + (ulong)KernelOffsets.ProcPid, out uint p) && (int)p == pid)
                return proc;
            if (!io.TryReadU64(proc + (ulong)KernelOffsets.ProcList, out proc))
                return 0;
            safety++;
        }
        return 0;
    }

    /// <summary>
    /// Applies the full 11-write credential and filesystem escalation to a process whose kernel
    /// address is already known. The write set covers eleven fields:
    /// five uid/gid fields zeroed, authorization id set, two capability quadwords set to all-ones,
    /// one attribute byte set, and the root and jail directory vnodes pointed at the kernel's own
    /// root vnode.
    /// </summary>
    /// <returns><see langword="true"/> when the credential and filedesc pointers were read
    /// successfully and all writes were issued; <see langword="false"/> if either pointer read
    /// failed.</returns>
    public static bool JailbreakProcess(PayloadKernelIo io, ulong proc, ulong rootvnode)
    {
        if (!io.TryReadU64(proc + (ulong)KernelOffsets.ProcUcred, out ulong ucred) || ucred == 0)
            return false;
        if (!io.TryReadU64(proc + (ulong)KernelOffsets.ProcFd, out ulong fd) || fd == 0)
            return false;

        io.WriteU32(ucred + (ulong)KernelOffsets.UcredUid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredRuid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredSvuid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredNgroups, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredRgid, 0);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceAuthId, 0x4801000000000013);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceCaps, 0xFFFF_FFFF_FFFF_FFFF);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceCaps + 8, 0xFFFF_FFFF_FFFF_FFFF);
        byte attr0 = 0x80;
        io.Write(ucred + (ulong)KernelOffsets.UcredSceAttr0, &attr0, 1);
        io.WriteU64(fd + (ulong)KernelOffsets.FdRdir, rootvnode);
        io.WriteU64(fd + (ulong)KernelOffsets.FdJdir, rootvnode);

        return true;
    }

    /// <summary>
    /// Walks the process list to locate the process with the given <paramref name="pid"/>, reads
    /// the root vnode, and applies the 11-write credential and filesystem escalation. Returns
    /// <see langword="false"/> if the process is not found or the root vnode is unreadable.
    /// </summary>
    public static bool JailbreakByPid(PayloadKernelIo io, int pid)
    {
        ulong proc = WalkAllprocForPid(io, pid);
        if (proc == 0)
            return false;
        ulong rootvnode = io.ReadU64(RootvnodeAddress);
        if (rootvnode == 0)
            return false;
        return JailbreakProcess(io, proc, rootvnode);
    }

    /// <summary>
    /// Removes the filesystem jail from a process by pointing its root and jail directory vnodes
    /// to the kernel's own root vnode.
    /// </summary>
    public static void RemoveJail(PayloadKernelIo io, ulong proc)
    {
        ulong rootvnode = io.ReadU64(RootvnodeAddress);
        ulong filedesc = io.ReadU64(proc + (ulong)KernelOffsets.ProcFd);
        io.WriteU64(filedesc + (ulong)KernelOffsets.FdRdir, rootvnode);
        io.WriteU64(filedesc + (ulong)KernelOffsets.FdJdir, rootvnode);
    }

    /// <summary>
    /// Sets a process's credential to root with no prison and full authorization and capabilities.
    /// </summary>
    public static void EscalateCredentials(PayloadKernelIo io, ulong proc)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredUid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredRuid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredSvuid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredRgid, 0);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredSvgid, 0);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredPrison, GetPrison0(io));
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceAuthId, 0xFFFF_FFFF_FFFF_FFFF);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceCaps, 0xFFFF_FFFF_FFFF_FFFF);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceCaps + 8, 0xFFFF_FFFF_FFFF_FFFF);
    }

    // ---- Individual kernel_* accessors ----
    //
    // Each field is also available as a standalone accessor (get_root_vnode, get_proc_rootdir,
    // get_ucred_authid, etc.). The existing RemoveJail and EscalateCredentials methods compose
    // multiple field writes into one operation. These individual accessors let template code
    // access one field at a time.

    /// <summary>
    /// Returns the kernel's root vnode pointer. This is the vnode that an unjailed process's
    /// file descriptor table root directory should point to.
    /// </summary>
    public static ulong GetRootVnode(PayloadKernelIo io)
    {
        return io.ReadU64(RootvnodeAddress);
    }

    /// <summary>
    /// Reads the root directory vnode from a process's file descriptor table.
    /// </summary>
    public static ulong GetProcRootDir(PayloadKernelIo io, ulong proc)
    {
        ulong filedesc = io.ReadU64(proc + (ulong)KernelOffsets.ProcFd);
        return io.ReadU64(filedesc + (ulong)KernelOffsets.FdRdir);
    }

    /// <summary>
    /// Sets the root directory vnode in a process's file descriptor table.
    /// </summary>
    public static void SetProcRootDir(PayloadKernelIo io, ulong proc, ulong vnode)
    {
        ulong filedesc = io.ReadU64(proc + (ulong)KernelOffsets.ProcFd);
        io.WriteU64(filedesc + (ulong)KernelOffsets.FdRdir, vnode);
    }

    /// <summary>
    /// Reads the jail directory vnode from a process's file descriptor table.
    /// </summary>
    public static ulong GetProcJailDir(PayloadKernelIo io, ulong proc)
    {
        ulong filedesc = io.ReadU64(proc + (ulong)KernelOffsets.ProcFd);
        return io.ReadU64(filedesc + (ulong)KernelOffsets.FdJdir);
    }

    /// <summary>
    /// Sets the jail directory vnode in a process's file descriptor table.
    /// </summary>
    public static void SetProcJailDir(PayloadKernelIo io, ulong proc, ulong vnode)
    {
        ulong filedesc = io.ReadU64(proc + (ulong)KernelOffsets.ProcFd);
        io.WriteU64(filedesc + (ulong)KernelOffsets.FdJdir, vnode);
    }

    /// <summary>
    /// Reads the authorization id from a process's credential.
    /// </summary>
    public static ulong GetUcredAuthId(PayloadKernelIo io, ulong proc)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        return io.ReadU64(ucred + (ulong)KernelOffsets.UcredSceAuthId);
    }

    /// <summary>
    /// Sets the authorization id in a process's credential.
    /// </summary>
    public static void SetUcredAuthId(PayloadKernelIo io, ulong proc, ulong authId)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredSceAuthId, authId);
    }

    /// <summary>
    /// Reads the sixteen-byte capability set from a process's credential.
    /// </summary>
    public static void GetUcredCaps(PayloadKernelIo io, ulong proc, byte* caps)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.Read(ucred + (ulong)KernelOffsets.UcredSceCaps, caps, 16);
    }

    /// <summary>
    /// Writes the sixteen-byte capability set in a process's credential.
    /// </summary>
    public static void SetUcredCaps(PayloadKernelIo io, ulong proc, byte* caps)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.Write(ucred + (ulong)KernelOffsets.UcredSceCaps, caps, 16);
    }

    /// <summary>
    /// Reads the thirty-two-byte attribute set from a process's credential.
    /// </summary>
    public static void GetUcredAttrs(PayloadKernelIo io, ulong proc, byte* attrs)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.Read(ucred + (ulong)KernelOffsets.UcredSceAttrs, attrs, 32);
    }

    /// <summary>
    /// Writes the thirty-two-byte attribute set in a process's credential.
    /// </summary>
    public static void SetUcredAttrs(PayloadKernelIo io, ulong proc, byte* attrs)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.Write(ucred + (ulong)KernelOffsets.UcredSceAttrs, attrs, 32);
    }

    /// <summary>
    /// Reads the firmware version from the kernel data section.
    /// </summary>
    /// <remarks>
    /// The firmware version is stored as a 32-bit value in the kernel data section. The CRT
    /// reads this during <c>__kernel_init</c> and caches it in a global. The offset from
    /// kdata_base to the version word is firmware-specific; for FW 10.01 this value lives at a
    /// fixed location that the CRT discovers during init. This method reads it through the
    /// pipe primitive at a known offset.
    /// </remarks>
    public static uint GetFirmwareVersion(PayloadKernelIo io)
    {
        return GetSystemSoftwareVersion();
    }

    /// <summary>
    /// Reads the sixteen-byte QA flags from the kernel data section.
    /// </summary>
    public static void GetQaFlags(PayloadKernelIo io, byte* qaflags)
    {
        io.Read(QaFlagsAddress, qaflags, 16);
    }

    /// <summary>
    /// Writes the sixteen-byte QA flags to the kernel data section.
    /// </summary>
    public static void SetQaFlags(PayloadKernelIo io, byte* qaflags)
    {
        io.Write(QaFlagsAddress, qaflags, 16);
    }

    /// <summary>
    /// Reads a single byte from a kernel data address. Useful for reading TARGETID,
    /// SECURITY_FLAGS, and UTOKEN_FLAGS.
    /// </summary>
    public static byte GetKernelByte(PayloadKernelIo io, ulong kaddr)
    {
        byte value;
        io.Read(kaddr, &value, 1);
        return value;
    }

    /// <summary>
    /// Reads the effective user id from a process's credential.
    /// </summary>
    public static uint GetUcredUid(PayloadKernelIo io, ulong proc)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        return io.ReadU32(ucred + (ulong)KernelOffsets.UcredUid);
    }

    /// <summary>
    /// Sets the effective user id in a process's credential.
    /// </summary>
    public static void SetUcredUid(PayloadKernelIo io, ulong proc, uint uid)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.WriteU32(ucred + (ulong)KernelOffsets.UcredUid, uid);
    }

    /// <summary>
    /// Reads the prison pointer from a process's credential.
    /// </summary>
    public static ulong GetUcredPrison(PayloadKernelIo io, ulong proc)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        return io.ReadU64(ucred + (ulong)KernelOffsets.UcredPrison);
    }

    /// <summary>
    /// Sets the prison pointer in a process's credential.
    /// </summary>
    public static void SetUcredPrison(PayloadKernelIo io, ulong proc, ulong prison)
    {
        ulong ucred = io.ReadU64(proc + (ulong)KernelOffsets.ProcUcred);
        io.WriteU64(ucred + (ulong)KernelOffsets.UcredPrison, prison);
    }

    /// <summary>
    /// Reads the process identifier from a proc structure.
    /// </summary>
    public static int GetProcPid(PayloadKernelIo io, ulong proc)
    {
        return (int)io.ReadU32(proc + (ulong)KernelOffsets.ProcPid);
    }

    /// <summary>
    /// Reads the title identifier from a proc structure into the caller's buffer using the CRT's
    /// copyout primitive directly. The buffer should be at least ten bytes.
    /// </summary>
    public static void ReadProcTitleId(ulong proc, Span<byte> titleId)
    {
        fixed (byte* p = titleId)
            CrtCopyoutDirect(proc + (ulong)KernelOffsets.ProcTitleId, p, (ulong)titleId.Length);
    }

    // ---- Pid-based credential and jail operations ----
    //
    // These overloads dispatch directly into the CRT-emitted kernel accessors, which use the
    // same copyout/copyin mechanism internally but without any managed GC transition wrapper.
    // Prefer these over the io-based overloads for credential and jail operations.

    /// <summary>
    /// Removes the filesystem jail from a process by pointing its root and jail directory vnodes
    /// to the kernel's own root vnode. Dispatches through the CRT-emitted accessors.
    /// </summary>
    public static void RemoveJail(int pid)
    {
        ulong rootvnode = CrtGetRootVnode();
        CrtSetProcRootdir(pid, rootvnode);
        CrtSetProcJaildir(pid, rootvnode);
    }

    /// <summary>
    /// Sets a process's credential to root with no prison and full authorization and capabilities.
    /// Dispatches through the CRT-emitted accessors.
    /// </summary>
    public static void EscalateCredentials(int pid)
    {
        CrtSetUcredUid(pid, 0);
        CrtSetUcredRuid(pid, 0);
        CrtSetUcredSvuid(pid, 0);
        CrtSetUcredRgid(pid, 0);
        CrtSetUcredSvgid(pid, 0);
        CrtSetUcredPrison(pid, GetPrison0());
        CrtSetUcredAuthid(pid, 0xFFFF_FFFF_FFFF_FFFF);
        byte* caps = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
            caps[i] = 0xFF;
        CrtSetUcredCaps(pid, caps);
    }

    /// <summary>
    /// Sets the authorization id in a process's credential.
    /// Dispatches through the CRT-emitted accessor.
    /// </summary>
    public static void SetUcredAuthId(int pid, ulong authId)
    {
        CrtSetUcredAuthid(pid, authId);
    }

    /// <summary>
    /// Returns the kernel's root vnode pointer by reading the BSS-cached address through the
    /// CRT-emitted accessor. The CRT's init function populates this address from the per-firmware
    /// offset table; the accessor dereferences it via copyout and returns the vnode struct pointer.
    /// Returns zero if the BSS slot was never populated (unsupported firmware) or the copyout fails.
    /// </summary>
    public static ulong GetRootVnode()
    {
        return CrtGetRootVnode();
    }

    /// <summary>
    /// Applies the full 11-write credential and filesystem escalation to a process identified by
    /// its pid, using the CRT-emitted per-field accessors. Each accessor internally walks the
    /// allproc list to locate the target process, so no managed allproc traversal is needed.
    /// Returns <see langword="false"/> if the initial uid write fails (process not found) or if either
    /// filesystem directory write fails (target exited mid-sequence), <see langword="true"/> otherwise.
    /// </summary>
    /// <param name="pid">Target process identifier.</param>
    /// <param name="rootvnode">Root vnode pointer (from <see cref="GetRootVnode()"/>).</param>
    public static bool JailbreakByPid(int pid, ulong rootvnode)
    {
        if (CrtSetUcredUid(pid, 0) != 0)
            return false;
        CrtSetUcredRuid(pid, 0);
        CrtSetUcredSvuid(pid, 0);
        CrtSetUcredNgroups(pid, 0);
        CrtSetUcredRgid(pid, 0);
        CrtSetUcredAuthid(pid, 0x4801000000000013);
        byte* caps = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
            caps[i] = 0xFF;
        CrtSetUcredCaps(pid, caps);
        CrtSetUcredSceAttr0(pid, 0x80);
        if (CrtSetProcRootdir(pid, rootvnode) != 0)
            return false;
        if (CrtSetProcJaildir(pid, rootvnode) != 0)
            return false;
        return true;
    }

    /// <summary>
    /// Escapes the filesystem jail and raises the effective uid to root with full capabilities on
    /// a running process, without touching the prison pointer, the real / saved user or group
    /// identifiers, the authorisation identifier, or the attribute set. The narrower footprint
    /// avoids the kernel
    /// bookkeeping paths that trap after a broader credential rewrite: cr_prison carries a
    /// reference-counted pointer whose list linkage the kernel walks on later scheduling
    /// decisions, and swapping it out from under a live process leaves the previous prison's
    /// process list carrying a dangling entry that panics on the next iterating traversal.
    /// </summary>
    /// <remarks>
    /// Both the root directory and the jail directory are pointed at the kernel's root vnode.
    /// Setting the jail directory to the root vnode tells the kernel's path-resolution helper
    /// that the jail boundary coincides with the filesystem root, effectively removing the
    /// jail constraint. A null jail directory causes a page fault in the kernel's namei path
    /// when the process exits or performs any path resolution.
    /// </remarks>
    public static void RaisePrivileges(int pid)
    {
        ulong rootvnode = CrtGetRootVnode();
        CrtSetProcRootdir(pid, rootvnode);
        CrtSetProcJaildir(pid, rootvnode);
        CrtSetUcredUid(pid, 0);
        byte* caps = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
            caps[i] = 0xFF;
        CrtSetUcredCaps(pid, caps);
    }

    private static bool MatchName(byte* comm, byte* name, int length)
    {
        for (int i = 0; i < length; i++)
        {
            if (comm[i] != name[i])
                return false;
        }
        return comm[length] == 0;
    }

    // ---- CRT kernel accessor P/Invoke declarations ----
    //
    // Each declaration maps to a function the CRT emits in the payload text section. The
    // [SuppressGCTransition] attribute eliminates the RhpPInvoke/RhpPInvokeReturn wrapper,
    // making these calls structurally identical to unmanaged-to-unmanaged calls. All of these
    // functions are short, non-blocking, and do not allocate managed memory.

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_get_root_vnode")]
    private static partial ulong CrtGetRootVnode();

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_proc_rootdir")]
    private static partial int CrtSetProcRootdir(int pid, ulong vnode);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_proc_jaildir")]
    private static partial int CrtSetProcJaildir(int pid, ulong vnode);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_uid")]
    private static partial int CrtSetUcredUid(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_ruid")]
    private static partial int CrtSetUcredRuid(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_svuid")]
    private static partial int CrtSetUcredSvuid(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_rgid")]
    private static partial int CrtSetUcredRgid(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_svgid")]
    private static partial int CrtSetUcredSvgid(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_ngroups")]
    private static partial int CrtSetUcredNgroups(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_sce_attr0")]
    private static partial int CrtSetUcredSceAttr0(int pid, int val);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_prison")]
    private static partial int CrtSetUcredPrison(int pid, ulong prison);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_authid")]
    private static partial int CrtSetUcredAuthid(int pid, ulong authid);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_set_ucred_caps")]
    private static partial int CrtSetUcredCaps(int pid, byte* caps);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_find_proc_by_comm")]
    private static partial ulong CrtFindProcByComm(byte* name, int length);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kernel_copyout")]
    private static partial int CrtCopyoutDirect(ulong kaddr, void* uaddr, ulong len);
}
