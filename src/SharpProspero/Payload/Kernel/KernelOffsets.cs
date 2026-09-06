// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Firmware-versioned kernel data offsets. Each method takes a BCD-encoded firmware version
/// (as returned by the kernel's system software version query) and returns the kdata-relative
/// offset for the named kernel symbol on that firmware. Add <see cref="KdataBase"/> to obtain
/// an absolute kernel virtual address.
/// </summary>
/// <remarks>
/// <para>
/// The firmware version uses a four-byte BCD encoding where byte 3 is the major version,
/// byte 2 the minor, byte 1 the patch, and byte 0 the sub-patch. Only the upper 16 bits
/// (major + minor) vary across the offset groups. For example, firmware 10.01 is
/// <c>0x10010000</c> and firmware 4.03 is <c>0x04030000</c>.
/// </para>
/// <para>
/// Structure field offsets (process, credential, file descriptor) are firmware-invariant
/// and included as constants in this class alongside the per-firmware lookup methods.
/// </para>
/// </remarks>
public static class KernelOffsets
{
    // ---- Firmware version masks ----

    /// <summary>Masks a full version to its major.minor group.</summary>
    public const uint VersionMask = 0xFFFF0000;

    // ---- Firmware version constants (BCD-encoded) ----

    /// <summary>Firmware 1.00.</summary>
    public const uint Fw100 = 0x01000000;
    /// <summary>Firmware 1.01.</summary>
    public const uint Fw101 = 0x01010000;
    /// <summary>Firmware 1.02.</summary>
    public const uint Fw102 = 0x01020000;
    /// <summary>Firmware 1.05.</summary>
    public const uint Fw105 = 0x01050000;
    /// <summary>Firmware 1.10.</summary>
    public const uint Fw110 = 0x01100000;
    /// <summary>Firmware 1.11.</summary>
    public const uint Fw111 = 0x01110000;
    /// <summary>Firmware 1.12.</summary>
    public const uint Fw112 = 0x01120000;
    /// <summary>Firmware 1.13.</summary>
    public const uint Fw113 = 0x01130000;
    /// <summary>Firmware 1.14.</summary>
    public const uint Fw114 = 0x01140000;
    /// <summary>Firmware 2.00.</summary>
    public const uint Fw200 = 0x02000000;
    /// <summary>Firmware 2.20.</summary>
    public const uint Fw220 = 0x02200000;
    /// <summary>Firmware 2.25.</summary>
    public const uint Fw225 = 0x02250000;
    /// <summary>Firmware 2.26.</summary>
    public const uint Fw226 = 0x02260000;
    /// <summary>Firmware 2.30.</summary>
    public const uint Fw230 = 0x02300000;
    /// <summary>Firmware 2.50.</summary>
    public const uint Fw250 = 0x02500000;
    /// <summary>Firmware 2.70.</summary>
    public const uint Fw270 = 0x02700000;
    /// <summary>Firmware 3.00.</summary>
    public const uint Fw300 = 0x03000000;
    /// <summary>Firmware 3.10.</summary>
    public const uint Fw310 = 0x03100000;
    /// <summary>Firmware 3.20.</summary>
    public const uint Fw320 = 0x03200000;
    /// <summary>Firmware 3.21.</summary>
    public const uint Fw321 = 0x03210000;
    /// <summary>Firmware 4.00.</summary>
    public const uint Fw400 = 0x04000000;
    /// <summary>Firmware 4.02.</summary>
    public const uint Fw402 = 0x04020000;
    /// <summary>Firmware 4.03.</summary>
    public const uint Fw403 = 0x04030000;
    /// <summary>Firmware 4.50.</summary>
    public const uint Fw450 = 0x04500000;
    /// <summary>Firmware 4.51.</summary>
    public const uint Fw451 = 0x04510000;
    /// <summary>Firmware 5.00.</summary>
    public const uint Fw500 = 0x05000000;
    /// <summary>Firmware 5.02.</summary>
    public const uint Fw502 = 0x05020000;
    /// <summary>Firmware 5.10.</summary>
    public const uint Fw510 = 0x05100000;
    /// <summary>Firmware 5.50.</summary>
    public const uint Fw550 = 0x05500000;
    /// <summary>Firmware 6.00.</summary>
    public const uint Fw600 = 0x06000000;
    /// <summary>Firmware 6.02.</summary>
    public const uint Fw602 = 0x06020000;
    /// <summary>Firmware 6.50.</summary>
    public const uint Fw650 = 0x06500000;
    /// <summary>Firmware 7.00.</summary>
    public const uint Fw700 = 0x07000000;
    /// <summary>Firmware 7.01.</summary>
    public const uint Fw701 = 0x07010000;
    /// <summary>Firmware 7.20.</summary>
    public const uint Fw720 = 0x07200000;
    /// <summary>Firmware 7.40.</summary>
    public const uint Fw740 = 0x07400000;
    /// <summary>Firmware 7.60.</summary>
    public const uint Fw760 = 0x07600000;
    /// <summary>Firmware 7.61.</summary>
    public const uint Fw761 = 0x07610000;
    /// <summary>Firmware 8.00.</summary>
    public const uint Fw800 = 0x08000000;
    /// <summary>Firmware 8.20.</summary>
    public const uint Fw820 = 0x08200000;
    /// <summary>Firmware 8.40.</summary>
    public const uint Fw840 = 0x08400000;
    /// <summary>Firmware 8.60.</summary>
    public const uint Fw860 = 0x08600000;
    /// <summary>Firmware 9.00.</summary>
    public const uint Fw900 = 0x09000000;
    /// <summary>Firmware 9.05.</summary>
    public const uint Fw905 = 0x09050000;
    /// <summary>Firmware 9.20.</summary>
    public const uint Fw920 = 0x09200000;
    /// <summary>Firmware 9.40.</summary>
    public const uint Fw940 = 0x09400000;
    /// <summary>Firmware 9.60.</summary>
    public const uint Fw960 = 0x09600000;
    /// <summary>Firmware 10.00.</summary>
    public const uint Fw1000 = 0x10000000;
    /// <summary>Firmware 10.01.</summary>
    public const uint Fw1001 = 0x10010000;
    /// <summary>Firmware 10.20.</summary>
    public const uint Fw1020 = 0x10200000;
    /// <summary>Firmware 10.40.</summary>
    public const uint Fw1040 = 0x10400000;
    /// <summary>Firmware 10.60.</summary>
    public const uint Fw1060 = 0x10600000;
    /// <summary>Firmware 11.00.</summary>
    public const uint Fw1100 = 0x11000000;
    /// <summary>Firmware 11.20.</summary>
    public const uint Fw1120 = 0x11200000;
    /// <summary>Firmware 11.40.</summary>
    public const uint Fw1140 = 0x11400000;
    /// <summary>Firmware 11.60.</summary>
    public const uint Fw1160 = 0x11600000;
    /// <summary>Firmware 12.00.</summary>
    public const uint Fw1200 = 0x12000000;
    /// <summary>Firmware 12.02.</summary>
    public const uint Fw1202 = 0x12020000;
    /// <summary>Firmware 12.20.</summary>
    public const uint Fw1220 = 0x12200000;
    /// <summary>Firmware 12.40.</summary>
    public const uint Fw1240 = 0x12400000;
    /// <summary>Firmware 12.60.</summary>
    public const uint Fw1260 = 0x12600000;
    /// <summary>Firmware 12.70.</summary>
    public const uint Fw1270 = 0x12700000;

    /// <summary>
    /// Returns the kdata-relative offset of the <c>allproc</c> list head for the given
    /// firmware version, or zero if the firmware is not recognized.
    /// </summary>
    public static ulong Allproc(uint firmwareVersion) => (firmwareVersion & VersionMask) switch
    {
        Fw100 or Fw101 or Fw102 or Fw105
        or Fw110 or Fw111 or Fw112 or Fw113 or Fw114 => 0x26D1C18,

        Fw200 or Fw220 or Fw225 or Fw226
        or Fw230 or Fw250 or Fw270 => 0x2701C28,

        Fw300 or Fw310 or Fw320 or Fw321 => 0x276DC58,

        Fw400 or Fw402 or Fw403 or Fw450 or Fw451 => 0x27EDCB8,

        Fw500 or Fw502 or Fw510 or Fw550 => 0x291DD00,

        Fw600 or Fw602 or Fw650 => 0x2869D20,

        Fw700 or Fw701 or Fw720 or Fw740 or Fw760 or Fw761 => 0x2859D50,

        Fw800 or Fw820 or Fw840 or Fw860 => 0x2875D50,

        Fw900 or Fw905 or Fw920 or Fw940 or Fw960 => 0x2755D50,

        Fw1000 or Fw1001 or Fw1020 or Fw1040 or Fw1060 => 0x2765D70,

        Fw1100 or Fw1120 or Fw1140 or Fw1160 => 0x2875D70,

        Fw1200 or Fw1202 or Fw1220 or Fw1240 or Fw1260 or Fw1270 => 0x2885E00,

        _ => 0,
    };

    /// <summary>
    /// Returns the kdata-relative offset of the kernel security flags for the given
    /// firmware version, or zero if the firmware is not recognized.
    /// </summary>
    public static ulong SecurityFlags(uint firmwareVersion) => (firmwareVersion & VersionMask) switch
    {
        Fw100 or Fw101 or Fw102 or Fw105
        or Fw110 or Fw111 or Fw112 or Fw113 or Fw114 => 0x6241074,

        Fw200 or Fw220 or Fw225 or Fw226
        or Fw230 or Fw250 or Fw270 => 0x63E1274,

        Fw300 or Fw310 or Fw320 or Fw321 => 0x6466474,

        Fw400 => 0x6506474,

        Fw402 or Fw403 or Fw450 or Fw451 => 0x6505474,

        Fw500 or Fw502 or Fw510 or Fw550 => 0x66466EC,

        Fw600 or Fw602 or Fw650 => 0x65968EC,

        Fw700 or Fw701 or Fw720 or Fw740 or Fw760 or Fw761 => 0x0AC8064,

        Fw800 or Fw820 or Fw840 or Fw860 => 0x0AC3064,

        Fw900 => 0x0D72064,

        Fw905 or Fw920 or Fw940 or Fw960 => 0x0D73064,

        Fw1000 or Fw1001 or Fw1020 or Fw1040 or Fw1060 => 0x0D79064,

        _ => 0,
    };

    /// <summary>
    /// Returns the kdata-relative offset of the QA flags for the given firmware version,
    /// or zero if the firmware is not recognized.
    /// </summary>
    public static ulong QaFlags(uint firmwareVersion)
    {
        uint masked = firmwareVersion & VersionMask;

        if (masked is Fw100 or Fw101 or Fw102 or Fw105
            or Fw110 or Fw111 or Fw112 or Fw113 or Fw114
            or Fw200 or Fw220 or Fw225 or Fw226
            or Fw230 or Fw250 or Fw270
            or Fw300 or Fw310 or Fw320 or Fw321
            or Fw400 or Fw402 or Fw403 or Fw450 or Fw451
            or Fw500 or Fw502 or Fw510 or Fw550)
            return 0x6241098;

        ulong secFlags = SecurityFlags(firmwareVersion);
        return secFlags != 0 ? secFlags + 0x24 : 0;
    }

    /// <summary>
    /// Returns the kdata-relative offset of the utoken flags for the given firmware version,
    /// or zero if the firmware is not recognized.
    /// </summary>
    public static ulong UtokenFlags(uint firmwareVersion)
    {
        uint masked = firmwareVersion & VersionMask;

        if (masked is Fw100 or Fw101 or Fw102 or Fw105
            or Fw110 or Fw111 or Fw112 or Fw113 or Fw114
            or Fw200 or Fw220 or Fw225 or Fw226
            or Fw230 or Fw250 or Fw270
            or Fw300 or Fw310 or Fw320 or Fw321
            or Fw400 or Fw402 or Fw403 or Fw450 or Fw451
            or Fw500 or Fw502 or Fw510 or Fw550)
            return 0x6646710;

        ulong secFlags = SecurityFlags(firmwareVersion);
        return secFlags != 0 ? secFlags + 0x8C : 0;
    }

    /// <summary>
    /// Returns the kdata-relative offset of the root vnode pointer for the given firmware
    /// version, or zero if the firmware is not recognized.
    /// </summary>
    public static ulong Rootvnode(uint firmwareVersion) => (firmwareVersion & VersionMask) switch
    {
        Fw100 or Fw101 or Fw102 or Fw105
        or Fw110 or Fw111 or Fw112 or Fw113 or Fw114 => 0x6565540,

        Fw200 or Fw220 or Fw225 or Fw226
        or Fw230 or Fw250 or Fw270 => 0x67134C0,

        Fw300 or Fw310 or Fw320 or Fw321 => 0x67AB4C0,

        Fw400 or Fw402 or Fw403 or Fw450 or Fw451 => 0x66E74C0,

        Fw500 or Fw502 or Fw510 or Fw550 => 0x6853510,

        Fw600 or Fw602 or Fw650 => 0x679F510,

        Fw700 or Fw701 or Fw720 or Fw740 or Fw760 or Fw761 => 0x30C7510,

        Fw800 or Fw820 or Fw840 or Fw860 => 0x30FB510,

        Fw900 or Fw905 or Fw920 or Fw940 or Fw960 => 0x2FDB510,

        Fw1000 or Fw1001 or Fw1020 or Fw1040 or Fw1060 => 0x2FA3510,

        _ => 0,
    };

    /// <summary>
    /// Returns the kernel data section base address for the given firmware version,
    /// or zero if the firmware is not recognized.
    /// </summary>
    public static ulong KdataBase(uint firmwareVersion) => (firmwareVersion & VersionMask) switch
    {
        Fw100 or Fw101 or Fw102 or Fw105
        or Fw110 or Fw111 or Fw112 or Fw113 or Fw114 => 0xFFFFFFFF_80D40000,

        Fw200 or Fw220 or Fw225 or Fw226
        or Fw230 or Fw250 or Fw270 => 0xFFFFFFFF_80D60000,

        Fw300 or Fw310 or Fw320 or Fw321 => 0xFFFFFFFF_80D70000,

        Fw400 or Fw402 or Fw403 => 0xFFFFFFFF_80E10000,

        Fw450 or Fw451 => 0xFFFFFFFF_80E10000,

        Fw500 or Fw502 or Fw510 or Fw550 => 0xFFFFFFFF_80E10000,

        Fw600 or Fw602 or Fw650 => 0xFFFFFFFF_80E10000,

        Fw700 or Fw701 or Fw720 or Fw740 or Fw760 or Fw761 => 0xFFFFFFFF_80E10000,

        Fw800 or Fw820 or Fw840 or Fw860 => 0xFFFFFFFF_80E10000,

        Fw900 or Fw905 or Fw920 or Fw940 or Fw960 => 0xFFFFFFFF_80ED0000,

        Fw1000 or Fw1001 or Fw1020 or Fw1040 or Fw1060 => 0xFFFFFFFF_80ED0000,

        _ => 0,
    };

    /// <summary>
    /// Returns <see langword="true"/> when the firmware version is recognized and all
    /// five kernel data offsets are available.
    /// </summary>
    public static bool IsSupported(uint firmwareVersion) => Allproc(firmwareVersion) != 0;

    // ---- FW 10.01 absolute addresses (for backward compatibility) ----

    /// <summary>Kernel data section base for FW 10.01.</summary>
    public const ulong KdataBase1001 = 0xffffffff_80ED0000;

    /// <summary>Absolute <c>allproc</c> address for FW 10.01.</summary>
    public const ulong Allproc1001 = 0xffffffff_83635d70;

    /// <summary>Absolute <c>rootvnode</c> address for FW 10.01.</summary>
    public const ulong Rootvnode1001 = 0xffffffff_83e73510;

    /// <summary>The host prison (<c>prison0</c>) absolute address for FW 10.01.</summary>
    public const ulong Prison0_1001 = 0xffffffff_82cdf4e0;

    // ---- Firmware-invariant structure field offsets ----

    /// <summary><c>p_list.le_next</c>: offset zero, the link that chains every process.</summary>
    public const int ProcList = 0x00;

    /// <summary><c>p_ucred</c>: the process credential pointer.</summary>
    public const int ProcUcred = 0x40;

    /// <summary><c>p_fd</c>: the file descriptor table pointer.</summary>
    public const int ProcFd = 0x48;

    /// <summary><c>p_pid</c>: the process identifier (four bytes).</summary>
    public const int ProcPid = 0xBC;

    /// <summary>The title identifier for the running application, a ten-byte inline string.</summary>
    public const int ProcTitleId = 0x470;

    /// <summary><c>p_vmspace</c>: the address space pointer (eight bytes).</summary>
    public const int ProcVmspace = 0x200;

    /// <summary><c>p_comm</c>: the process name, an inline seventeen-byte array.</summary>
    public const int ProcComm = 0x5DC;

    /// <summary>
    /// Returns the byte offset of the <c>vm_pmap</c> sub-structure inside <c>struct vmspace</c>
    /// for the given firmware version. The pmap stores the process page-table root (CR3)
    /// at <c>pm_pml4</c> (+32) and <c>pm_cr3</c> (+40).
    /// </summary>
    public static int VmspacePmapOffset(uint fwMajorMinor) => fwMajorMinor switch
    {
        <= 0x102 => 0x2C0,
        <= 0x550 => 0x2E0,
        _ => 0x2E8,
    };

    /// <summary><c>fd_rdir</c>: the root directory vnode in the file descriptor table.</summary>
    public const int FdRdir = 0x10;

    /// <summary><c>fd_jdir</c>: the jail directory vnode in the file descriptor table.</summary>
    public const int FdJdir = 0x18;

    /// <summary><c>cr_uid</c>: the effective user identifier (four bytes).</summary>
    public const int UcredUid = 0x04;

    /// <summary><c>cr_ruid</c>: the real user identifier (four bytes).</summary>
    public const int UcredRuid = 0x08;

    /// <summary><c>cr_svuid</c>: the saved user identifier (four bytes).</summary>
    public const int UcredSvuid = 0x0C;

    /// <summary><c>cr_ngroups</c>: the supplementary group count (four bytes).</summary>
    public const int UcredNgroups = 0x10;

    /// <summary><c>cr_rgid</c>: the real group identifier (four bytes).</summary>
    public const int UcredRgid = 0x14;

    /// <summary><c>cr_svgid</c>: the saved group identifier (four bytes).</summary>
    public const int UcredSvgid = 0x18;

    /// <summary><c>cr_prison</c>: the prison pointer the credential belongs to.</summary>
    public const int UcredPrison = 0x30;

    /// <summary><c>cr_sceAuthID</c>: the authorization identifier (eight bytes).</summary>
    public const int UcredSceAuthId = 0x58;

    /// <summary><c>cr_sceCaps</c>: the first eight bytes of the capability set.</summary>
    public const int UcredSceCaps = 0x60;

    /// <summary><c>cr_sceAttrs</c>: the base of the 32-byte attribute block.</summary>
    public const int UcredSceAttrs = 0x80;

    /// <summary>The privilege attribute byte within the attribute block (one byte).</summary>
    public const int UcredSceAttr0 = 0x83;

    /// <summary><c>pr_ref</c>: the prison reference count (four bytes).</summary>
    public const int PrisonRef = 0x14;

    // ---- Thread list traversal offsets ----

    /// <summary><c>p_threads.tqh_first</c>: pointer to the first thread in the process.</summary>
    public const int ProcThreads = 0x10;

    /// <summary><c>td_plist.tqe_next</c>: pointer to the next thread in the process's thread list.</summary>
    public const int ThreadListNext = 0x10;

    /// <summary><c>td_pcb</c>: pointer to the thread's process control block.</summary>
    public const int ThreadPcb = 0x3F8;

    /// <summary><c>td_proc</c>: pointer to the owning process from a thread.</summary>
    public const int ThreadProc = 0x08;

    /// <summary><c>td_retval</c>: the two-register system call return value.</summary>
    public const int ThreadRetval = 0x408;

    /// <summary><c>td_frame</c>: pointer to the user-mode trap frame saved on entry.</summary>
    public const int ThreadFrame = 0x460;

    // ---- PCB structure offsets ----

    /// <summary>
    /// Base offset of <c>pcb_dr0</c> in the PCB. The six debug register save slots
    /// (DR0, DR1, DR2, DR3, DR6, DR7) follow contiguously at eight-byte intervals.
    /// On firmware 10.00 and later, add the value returned by <see cref="PcbShift"/>
    /// to obtain the actual offset.
    /// </summary>
    public const int PcbDr0Base = 0x78;

    /// <summary>
    /// Base offset of <c>pcb_flags</c> in the PCB. On firmware 10.00 and later, add
    /// the value returned by <see cref="PcbShift"/> to obtain the actual offset.
    /// </summary>
    public const int PcbFlagsBase = 0x100;

    /// <summary><c>PCB_DBREGS</c>: when set in <c>pcb_flags</c>, <c>cpu_switch</c> restores
    /// DR0-DR3, DR6, and DR7 from the PCB save area on context switch.</summary>
    public const uint PcbDbregsFlag = 0x02;

    /// <summary>
    /// Returns the byte shift applied to all PCB fields from <c>pcb_fsbase</c> onward
    /// on the given firmware. Returns 16 on firmware 10.00 and later, zero otherwise.
    /// </summary>
    public static int PcbShift(uint firmwareVersion) =>
        (firmwareVersion & VersionMask) >= Fw1000 ? 0x10 : 0;

    /// <summary>
    /// Base offset of <c>pcb_fsbase</c> (the FS segment base save slot) in the PCB.
    /// On firmware 10.00 and later, add the value returned by <see cref="PcbShift"/>.
    /// </summary>
    public const int PcbFsBase = 0x40;

    /// <summary>
    /// Base offset of <c>pcb_gsbase</c> (the GS segment base save slot) in the PCB.
    /// On firmware 10.00 and later, add the value returned by <see cref="PcbShift"/>.
    /// </summary>
    public const int PcbGsBase = 0x48;

    // ---- Sysentvec structure offsets ----

    /// <summary>Offset of <c>sv_table</c> within the <c>sysentvec</c> structure (pointer to the sysent array).</summary>
    public const int SysentvecTable = 0x08;

    // ---- Syscall frame offsets ----

    /// <summary>
    /// Base offset from RSP to the RSI save slot on the syscall kernel stack frame.
    /// On firmware 10.00 and later, add the value returned by <see cref="PcbShift"/>.
    /// </summary>
    public const int SyscallRspToRsiBase = 0x88;

    /// <summary>
    /// Base offset from RSP to the full register stash on the syscall kernel stack frame.
    /// On firmware 10.00 and later, add the value returned by <see cref="PcbShift"/>.
    /// </summary>
    public const int SyscallRspToRegsStashBase = 0x110;

    // ---- Mailbox stack frame offsets ----

    /// <summary>Offset from RSP to the SELF context pointer during <c>decryptSelfBlock</c> mailbox handling.</summary>
    public const int MailboxDecryptSelfBlockRspToSelfContext = 0x118;

    /// <summary>Offset from RSP to the target virtual address during <c>decryptSelfBlock</c> mailbox handling.</summary>
    public const int MailboxDecryptSelfBlockRspToTargetVa = 0x10;

    /// <summary>Offset from RSP to the saved RBP during <c>decryptSelfBlock</c> mailbox handling.</summary>
    public const int MailboxDecryptSelfBlockRspToRbp = 0x120;

    /// <summary>Size of the mini syscore header structure in bytes.</summary>
    public const int MiniSyscoreHeaderSize = 0x6A0;

    // ---- Detailed per-firmware syscall table offsets ----

    /// <summary>
    /// Returns the kdata-relative offset of the PS5 sysent table for the given firmware.
    /// </summary>
    public static ulong Sysents(uint fw) => (fw & VersionMask) switch
    {
        Fw300 or Fw310 or Fw320 or Fw321 => 0x16F720,
        Fw400 or Fw402 or Fw403 or Fw450 or Fw451 => 0x1709C0,
        Fw500 or Fw502 => 0x1B1EF0,
        Fw510 => 0x1B2040,
        Fw550 => 0x1B2210,
        Fw600 => 0x1B49A0,
        Fw602 or Fw650 => 0x1B49F0,
        Fw700 or Fw701 => 0x1B7030,
        Fw720 or Fw740 => 0x1B71A0,
        Fw760 or Fw761 => 0x1B7260,
        Fw800 or Fw820 or Fw840 or Fw860 => 0x1A7DB0,
        Fw900 or Fw905 => 0x1AAC10,
        Fw920 or Fw940 or Fw960 => 0x1AAC60,
        Fw1000 or Fw1001 => 0x1AD100,
        Fw1020 or Fw1040 or Fw1060 => 0x1AD120,
        Fw1100 or Fw1120 => 0x1B0B70,
        Fw1140 => 0x1B0B20,
        Fw1160 => 0x1B08E0,
        Fw1200 or Fw1202 or Fw1220 or Fw1240 or Fw1260 or Fw1270 => 0x1AF4D0,
        _ => 0,
    };

    /// <summary>
    /// Returns the kdata-relative offset of the sysentvec structure.
    /// </summary>
    public static ulong Sysentvec(uint fw) => (fw & VersionMask) switch
    {
        Fw300 or Fw310 or Fw320 or Fw321 => 0xCA0CD8,
        Fw400 or Fw402 or Fw403 or Fw450 or Fw451 => 0xD11BB8,
        Fw500 or Fw502 or Fw510 or Fw550 => 0xE00BE8,
        Fw600 or Fw602 or Fw650 => 0xE210A8,
        Fw700 or Fw701 => 0xE21AB8,
        Fw720 or Fw740 or Fw760 or Fw761 => 0xE21B78,
        Fw800 or Fw820 or Fw840 or Fw860 => 0xE21CA8,
        Fw900 or Fw905 or Fw920 or Fw940 or Fw960 => 0xDBA648,
        Fw1000 or Fw1001 or Fw1020 or Fw1040 or Fw1060 => 0xDBA6D8,
        Fw1100 or Fw1120 => 0xDCBC78,
        Fw1140 or Fw1160 => 0xDCBC98,
        Fw1200 or Fw1202 or Fw1220 or Fw1240 or Fw1260 or Fw1270 => 0xDCC978,
        _ => 0,
    };

    /// <summary>
    /// Returns the offset of <c>p_sysent</c> in <c>struct proc</c> for the given firmware.
    /// </summary>
    public static int ProcSysent(uint fw) => (fw & VersionMask) switch
    {
        >= Fw1200 => 0xA08,
        >= Fw1000 => 0xA00,
        >= Fw700 => 0x9F8,
        >= Fw600 => 0x9E8,
        _ => 0x9C0,
    };

    // =========================================================================
    // FW 10.01 kernel module offsets (kdata-relative, signed)
    //
    // Each value is a signed offset relative to KdataBase. Positive values
    // address the kernel data segment; negative values address the kernel text
    // segment (located below KdataBase in virtual memory). To obtain an
    // absolute kernel virtual address: KdataBase1001 + (ulong)offset.
    // =========================================================================

    // ---- IDT/GDT/TSS/PCPU infrastructure (FW 10.01) ----

    /// <summary>Kdata-relative offset of the Interrupt Descriptor Table.</summary>
    public const long Idt_1001 = 0x2D5C300;

    /// <summary>Kdata-relative offset of the per-CPU GDT array.</summary>
    public const long GdtArray_1001 = 0x2D5D5E0;

    /// <summary>Kdata-relative offset of the per-CPU TSS array.</summary>
    public const long TssArray_1001 = 0x2D5EFE0;

    /// <summary>Kdata-relative offset of the per-CPU data array.</summary>
    public const long PcpuArray_1001 = 0x2D70F00;

    // ---- Interrupt/return ROP gadgets (FW 10.01) ----

    /// <summary>Kdata-relative offset of the <c>doreti_iret</c> instruction (IRET return from interrupt).</summary>
    public const long DoretiIret_1001 = -0xA6EB13;

    /// <summary>Kdata-relative offset of <c>add rsp; iret</c> (seven bytes before <c>doreti_iret</c>).</summary>
    public const long AddRspIret_1001 = DoretiIret_1001 - 7;

    /// <summary>Kdata-relative offset of <c>swapgs; add rsp; iret</c> (ten bytes before <c>doreti_iret</c>).</summary>
    public const long SwapgsAddRspIret_1001 = DoretiIret_1001 - 10;

    /// <summary>Kdata-relative offset of the <c>justreturn</c> gadget (returns from a system call with no side effect).</summary>
    public const long Justreturn_1001 = -0xA6ED40;

    /// <summary>Kdata-relative offset of <c>justreturn + 8</c> (pops one register, then returns).</summary>
    public const long JustreturnPop_1001 = Justreturn_1001 + 8;

    /// <summary>Kdata-relative offset of the <c>pop-all; iret</c> gadget (restores all GPRs from the stack, then IRET).</summary>
    public const long PopAllIret_1001 = -0xA6EB72;

    /// <summary>Kdata-relative offset of <c>pop-all-except-rdi; iret</c> (four bytes past <see cref="PopAllIret_1001"/>).</summary>
    public const long PopAllExceptRdiIret_1001 = PopAllIret_1001 + 4;

    /// <summary>Kdata-relative offset of the <c>push-pop-all; iret</c> gadget.</summary>
    public const long PushPopAllIret_1001 = -0xA10540;

    /// <summary>Kdata-relative offset of the <c>nop; ret</c> gadget (two bytes past <c>wrmsr; ret</c>).</summary>
    public const long NopRet_1001 = WrmsrRet_1001 + 2;

    /// <summary>Kdata-relative offset of the <c>rep movsb; pop rbp; ret</c> gadget.</summary>
    public const long RepMovsbPopRbpRet_1001 = -0xA32466;

    /// <summary>Kdata-relative offset of the <c>copyin</c> kernel function.</summary>
    public const long Copyin_1001 = -0xA32D30;

    /// <summary>Kdata-relative offset of the <c>copyout</c> kernel function.</summary>
    public const long Copyout_1001 = -0xA32DE0;

    // ---- MSR and control register gadgets (FW 10.01) ----

    /// <summary>Kdata-relative offset of the RDMSR gadget entry point.</summary>
    public const long RdmsrStart_1001 = -0xA7024A;

    /// <summary>Kdata-relative offset of the <c>wrmsr; ret</c> gadget.</summary>
    public const long WrmsrRet_1001 = -0xA7161C;

    /// <summary>Kdata-relative offset of the <c>mov rax, cr0</c> gadget.</summary>
    public const long MovRaxCr0_1001 = -0xA75DA1;

    /// <summary>Kdata-relative offset of the <c>mov cr0, rax</c> gadget.</summary>
    public const long MovCr0Rax_1001 = -0xA75D9C;

    /// <summary>Kdata-relative offset of the <c>mov rax, cr3</c> gadget.</summary>
    public const long MovRaxCr3_1001 = -0x3C9A2F;

    /// <summary>Kdata-relative offset of the <c>mov cr3, rax; mov ds, ...</c> gadget.</summary>
    public const long MovCr3RaxMovDs_1001 = -0xA756A9;

    // ---- Debug register transfer gadgets (FW 10.01) ----

    /// <summary>Kdata-relative offset of the DR-to-GPR transfer gadget (reads DR0-DR3/DR6/DR7 into GPRs).</summary>
    public const long Dr2GprStart_1001 = -0xA75C53;

    /// <summary>Kdata-relative offset of the first GPR-to-DR transfer gadget (writes GPRs into DR0-DR3).</summary>
    public const long Gpr2Dr1Start_1001 = -0xA75B3A;

    /// <summary>Kdata-relative offset of the second GPR-to-DR transfer gadget (writes GPRs into DR6/DR7).</summary>
    public const long Gpr2Dr2Start_1001 = -0xA75A47;

    // ---- Context switch (FW 10.01) ----

    /// <summary>Kdata-relative offset of the <c>cpu_switch</c> function (thread context switch entry).</summary>
    public const long CpuSwitch_1001 = -0xA75E40;

    // ---- SBL mailbox function and return addresses (FW 10.01) ----

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox</c> (SBL service dispatch).</summary>
    public const long SceSblServiceMailbox_1001 = -0x6F8B10;

    /// <summary>Kdata-relative offset of <c>sceSblAuthMgrSmIsLoadable2</c> (SELF loadability check).</summary>
    public const long SceSblAuthMgrSmIsLoadable2_1001 = -0x941160;

    /// <summary>Kdata-relative return address inside the <c>verifyHeader</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrVerifyHeader_1001 = -0x940E47;

    /// <summary>Kdata-relative return address inside the <c>loadSelfSegment</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrLoadSelfSegment_1001 = -0x940AD4;

    /// <summary>Kdata-relative return address inside the <c>decryptSelfBlock</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrDecryptSelfBlock_1001 = -0x94051D;

    /// <summary>Kdata-relative return address inside the <c>decryptMultipleSelfBlocks</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrDecryptMultipleSelfBlocks_1001 = -0x93FD52;

    /// <summary>Kdata-relative return address inside <c>sceSblAuthMgrSmFinalize</c>'s call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrSceSblAuthMgrSmFinalize_1001 = -0x9411D8;

    /// <summary>Kdata-relative return address inside the <c>verifySuperBlock</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrVerifySuperBlock_1001 = -0x9EA679;

    /// <summary>Kdata-relative return address inside the first <c>sceSblPfsClearKey</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrSceSblPfsClearKey1_1001 = -0x9EACF2;

    /// <summary>Kdata-relative return address inside the second <c>sceSblPfsClearKey</c> call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrSceSblPfsClearKey2_1001 = -0x9EAC8D;

    /// <summary>Kdata-relative return address inside the NPDRM command 5 call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrNpdrmCmd5_1001 = -0x34D98A;

    /// <summary>Kdata-relative return address inside the NPDRM command 6 call to <c>sceSblServiceMailbox</c>.</summary>
    public const long SceSblServiceMailboxLrNpdrmCmd6_1001 = -0x34D755;

    // ---- CCP/crypto function and data addresses (FW 10.01) ----

    /// <summary>Kdata-relative offset of <c>sceSblServiceCryptAsync</c> (asynchronous CCP crypto dispatch).</summary>
    public const long SceSblServiceCryptAsync_1001 = -0x98A590;

    /// <summary>Kdata-relative offset of the singleton dereference inside <c>sceSblServiceCryptAsync</c> (trap target for fpkg crypto interception).</summary>
    public const long SceSblServiceCryptAsyncDerefSingleton_1001 = -0x98A556;

    /// <summary>Kdata-relative offset of the <c>crypt_message_resolve</c> function (resolves a completed crypto message).</summary>
    public const long CryptMessageResolve_1001 = -0x4B5A50;

    /// <summary>Kdata-relative offset of the crypto singleton array in the kernel data segment.</summary>
    public const long CryptSingletonArray_1001 = 0x2C35D70;

    /// <summary>Kdata-relative offset of <c>sceSblPfsSetKeys</c> (registers PFS encryption/signing keys).</summary>
    public const long SceSblPfsSetKeys_1001 = -0x9EB870;

    // ---- SELF loading and decryption addresses (FW 10.01) ----

    /// <summary>Kdata-relative offset of the <c>loadSelfSegment</c> epilogue (function exit point).</summary>
    public const long LoadSelfSegmentEpilogue_1001 = -0x940A67;

    /// <summary>Kdata-relative offset of the <c>loadSelfSegment</c> debug watchpoint address.</summary>
    public const long LoadSelfSegmentWatchpoint_1001 = -0x2FC6A7;

    /// <summary>Kdata-relative return address after the watchpoint instruction inside <c>loadSelfSegment</c>.</summary>
    public const long LoadSelfSegmentWatchpointLr_1001 = -0x940CA7;

    /// <summary>Kdata-relative return address after the watchpoint instruction inside <c>decryptSelfBlock</c>.</summary>
    public const long DecryptSelfBlockWatchpointLr_1001 = -0x94093E;

    /// <summary>Kdata-relative offset of the <c>decryptSelfBlock</c> epilogue (function exit point).</summary>
    public const long DecryptSelfBlockEpilogue_1001 = -0x9408DB;

    /// <summary>Kdata-relative return address after the watchpoint instruction inside <c>decryptMultipleSelfBlocks</c>.</summary>
    public const long DecryptMultipleSelfBlocksWatchpointLr_1001 = -0x940209;

    /// <summary>Kdata-relative offset of the <c>decryptMultipleSelfBlocks</c> epilogue (function exit point).</summary>
    public const long DecryptMultipleSelfBlocksEpilogue_1001 = -0x93FFEF;

    // ---- Syscall hooking addresses (FW 10.01) ----

    /// <summary>Kdata-relative offset of the instruction just before the syscall dispatch (hook entry point).</summary>
    public const long SyscallBefore_1001 = -0x893E21;

    /// <summary>Kdata-relative offset of the instruction just after the syscall dispatch (hook return point).</summary>
    public const long SyscallAfter_1001 = -0x893DED;

    /// <summary>Kdata-relative offset of the CFI table <c>jmp; int3</c> trampoline used to redirect syscall entries.</summary>
    public const long SyscallCfiTableJmpInt3_1001 = -0xA06998;

    /// <summary>
    /// Returns the kdata-relative offset of the CFI table <c>jmp; int3</c>
    /// trampoline for the given firmware.
    /// </summary>
    public static long SyscallCfiTableJmpInt3(uint fw) => (fw & VersionMask) switch
    {
        Fw1000 or Fw1001 => SyscallCfiTableJmpInt3_1001,
        _ => SyscallCfiTableJmpInt3_1001,
    };

    /// <summary>Kdata-relative offset of the <c>mprotect</c> permission-check patch start.</summary>
    public const long MprotectFixStart_1001 = -0x9A8293;

    /// <summary>Kdata-relative offset of the <c>mprotect</c> permission-check patch end (six bytes past start).</summary>
    public const long MprotectFixEnd_1001 = MprotectFixStart_1001 + 6;

    /// <summary>Kdata-relative offset of the ASLR enforcement patch start.</summary>
    public const long AslrFixStart_1001 = -0x8F033D;

    /// <summary>Kdata-relative offset of the ASLR enforcement patch end (two bytes past start).</summary>
    public const long AslrFixEnd_1001 = AslrFixStart_1001 + 2;

    // ---- Kernel data-section addresses (FW 10.01) ----

    /// <summary>Kdata-relative offset of the mini syscore header in the data segment.</summary>
    public const long MiniSyscoreHeader_1001 = 0xE896D8;

    /// <summary>Kdata-relative offset of the kernel <c>malloc</c> function.</summary>
    public const long Malloc_1001 = -0xBB850;

    /// <summary>Kdata-relative offset of the <c>M_temp</c> (or equivalent) malloc type descriptor.</summary>
    public const long MallocType_1001 = 0x1407470;

    /// <summary>Kdata-relative offset of the <c>kernel_pmap_store</c> (kernel page-map address).</summary>
    public const long KernelPmapStore_1001 = 0x2CF0EF8;

    /// <summary>Kdata-relative offset of the PS4-compatibility sysent table.</summary>
    public const long SysentsPs4_1001 = 0x1A4BB0;

    /// <summary>Kdata-relative offset of the PS4-compatibility <c>sysentvec</c> structure.</summary>
    public const long SysentvecPs4_1001 = 0xDBA850;
}
