// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Bypass;
using SharpProspero.Payload.Elf;
using System;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Deploys the kernel module by loading per-CPU ELF images into kernel memory, building
/// private CR3 page tables, patching the IDT and TSS, cloning and hooking the sysent
/// tables, poisoning the crypto singleton array, and applying ShellCore patches.
/// </summary>
/// <remarks>
/// <para>
/// The installer receives two pre-built ELF binaries: the kelf (kernel-mode handler) and
/// the uelf (user-mode trampoline). Both are loaded once per CPU, with per-CPU symbol
/// values (PCPU address, IST slots, TSS base) resolved at load time. The kelf entry stub
/// embeds the interrupt handler addresses and IST stack pointers that the installer writes
/// into the IDT and TSS.
/// </para>
/// <para>
/// All kernel memory writes route through <see cref="PayloadKernelIo"/>. Kernel heap
/// allocation uses <see cref="PayloadKfncall"/> to invoke the kernel's <c>malloc</c>.
/// Physical address translation for page table construction uses
/// <see cref="KernelPaging.VirtToPhys"/>.
/// </para>
/// </remarks>
public static unsafe class KernelModuleInstaller
{
    // ---- Hardware and structure constants ----

    private const int Ncpus = 16;
    private const int Int1IstIndex = 4;
    private const int Int3IstIndex = 7;
    private const int Int13IstIndex = 3;
    private const int SharedAreaSize = 2048;
    private const int ComparisonTableSize = 65536;
    private const int ComparisonTableAlign = 65536;
    private const int SysentStructSize = 48;
    private const int SysentSyCallOffset = 8;
    private const int SysentvecCopySize = 0x500;
    private const int TssStride = 0x68;
    private const int TssIstBase = 28;
    private const int CopyChunkSize = 0x1000;
    private const int PageSize = 4096;
    private const int MNowait = 0x0001;
    private const int MaxSymbols = 128;
    private const int InitialBlockSize = 8 * 1024 * 1024;

    // ---- FreeBSD syscall numbers ----

    private const int SysExecve = 59;
    private const int SysUnmount = 22;
    private const int SysIoctl = 54;
    private const int SysMprotect = 74;
    private const int SysNmount = 378;
    private const int SysMdbgCall = 573;
    private const int SysDynlibLoadPrx = 594;
    private const int SysGetSelfAuthInfo = 607;
    private const int SysGetSdkCompiledVersion = 647;
    private const int SysGetPprSdkCompiledVersion = 713;
    private const int SysGetppid = 39;

    // ---- Per-CPU stride helpers ----

    private static int PcpuStride(uint fwMajorMinor) => fwMajorMinor >= 0x700 ? 0x980 : 0x900;

    /// <summary>
    /// Computes an absolute kernel virtual address from <c>kdata_base</c> and a signed
    /// kdata-relative offset. Negative offsets address the kernel text segment below
    /// <c>kdata_base</c>; positive offsets address the kernel data segment above it.
    /// </summary>
    private static ulong Abs(ulong kdb, long offset) => kdb + unchecked((ulong)offset);

    /// <summary>
    /// Installs the kernel module into the running kernel.
    /// </summary>
    /// <param name="io">Kernel read/write primitive.</param>
    /// <param name="kelfBlob">The kelf (kernel-mode handler) ELF binary.</param>
    /// <param name="uelfBlob">The uelf (user-mode trampoline) ELF binary.</param>
    /// <param name="fw">BCD-encoded firmware version.</param>
    /// <returns><see langword="true"/> on success.</returns>
    public static bool Install(PayloadKernelIo io, ReadOnlySpan<byte> kelfBlob,
        ReadOnlySpan<byte> uelfBlob, uint fw)
    {
        // ---- Already-installed gate ----
        // Defence-in-depth: skip installation if the kekcall channel already
        // responds to the KEKCALL_CHECK query. A second Install() over a live
        // kernel module would overwrite IDT/sysent/TSS entries mid-flight and
        // panic the kernel. The installer entry point also performs this check
        // before calling Install(); this second check protects direct callers.
        try
        {
            long already = PayloadKekcall.Invoke(-1);
            if (already == 0)
            {
                PayloadCrt.Klog("sp:install:already_loaded\n\0"u8);
                return true;
            }
        }
        catch
        {
            // Kekcall channel not yet available -- first install path.
        }

        // ---- Initialize trace-based kernel function calling ----

        if (!PayloadKfncall.Setup(io, fw))
            return false;

        // ---- Resolve kernel addresses ----
        // Use the exploit-provided kdata_base (ground truth), not the lookup table.

        PayloadCrt.Klog("sp:install:start\n\0"u8);
        ulong kdb = PayloadEntryPoint.Args->KernelDataBase;
        if (kdb == 0) { PayloadCrt.Klog("sp:install:kdb:fail\n\0"u8); return false; }

        uint fwMm = (fw >> 16) & 0xFFFF;
        ulong sysentsAddr = kdb + KernelOffsets.Sysents(fw);
        if (sysentsAddr == kdb) { PayloadCrt.Klog("sp:install:sysents:fail\n\0"u8); return false; }
        ulong mallocAddr = Abs(kdb, KernelOffsets.Malloc_1001);
        ulong mallocType = Abs(kdb, KernelOffsets.MallocType_1001);
        ulong idtBase = Abs(kdb, KernelOffsets.Idt_1001);
        ulong tssBase = Abs(kdb, KernelOffsets.TssArray_1001);
        ulong pcpuBase = Abs(kdb, KernelOffsets.PcpuArray_1001);
        long pmapOff = KernelOffsets.KernelPmapStore(fw);
        if (pmapOff == 0) return false;
        ulong pmapStore = Abs(kdb, pmapOff);
        ulong cfiJmpInt3 = Abs(kdb, KernelOffsets.SyscallCfiTableJmpInt3(fw));
        ulong doretiIret = Abs(kdb, KernelOffsets.DoretiIret_1001);
        ulong sysentvecAddr = kdb + KernelOffsets.Sysentvec(fw);
        ulong sysentvecPs4 = Abs(kdb, KernelOffsets.SysentvecPs4_1001);
        ulong sysentsPs4Addr = Abs(kdb, KernelOffsets.SysentsPs4_1001);
        ulong cryptSingleton = Abs(kdb, KernelOffsets.CryptSingletonArray_1001);

        // ---- Step 1: Read per-CPU IST4 values and original IDT handlers ----

        ulong* percpuIst4 = stackalloc ulong[Ncpus];
        for (int cpu = 0; cpu < Ncpus; cpu++)
        {
            ulong tss = tssBase + (ulong)(cpu * TssStride);
            percpuIst4[cpu] = io.ReadU64(tss + (ulong)(TssIstBase + Int1IstIndex * 8));
        }

        // Use the original IDT handlers saved by Setup() BEFORE it patched the IDT
        // for tracing. Reading from the IDT now would return the trace gadget addresses.
        ulong int1Handler = PayloadKfncall.OriginalInt1Handler;
        ulong int3Handler = PayloadKfncall.OriginalInt3Handler;
        ulong int13Handler = PayloadKfncall.OriginalInt13Handler;

        // ---- Step 2: Warmup allocations + main kernel memory block ----
        PayloadCrt.Klog("sp:install:warmup\n\0"u8);
        for (int i = 0; i < 0x180; i++)
            PayloadKfncall.Call(io, sysentsAddr, mallocAddr, 0x100, mallocType, MNowait);
        PayloadCrt.Klog("sp:install:warmup:done\n\0"u8);

        PayloadCrt.Klog("sp:install:malloc\n\0"u8);
        ulong blockStart = PayloadKfncall.Call(io, sysentsAddr, mallocAddr,
            (ulong)InitialBlockSize, mallocType, MNowait);
        if (blockStart == 0) { PayloadCrt.Klog("sp:install:malloc:fail\n\0"u8); return false; }
        PayloadCrt.Klog("sp:install:malloc:ok\n\0"u8);
        ulong blockPos = blockStart;
        ulong blockEnd = blockStart + (ulong)InitialBlockSize;

        // ---- Step 3: Build comparison table ----

        ulong compRaw = BumpAlloc(ref blockPos, blockEnd, ComparisonTableSize * 2);
        if (compRaw == 0) return false;
        ulong compTable = AlignUp(compRaw, ComparisonTableAlign);

        byte* compData = stackalloc byte[256];
        for (int i = 0; i < 256; i++)
        {
            for (int j = 0; j < 256; j++)
                compData[j] = (byte)(8 * (1 + (i > j ? 1 : 0) - (i < j ? 1 : 0)));
            io.Write(compTable + (ulong)(i * 256), compData, 256);
        }

        // ---- Step 4: Allocate and zero shared area ----

        ulong sharedAreaKva;
        if (compTable - compRaw > SharedAreaSize)
            sharedAreaKva = compTable - SharedAreaSize;
        else
            sharedAreaKva = compTable + ComparisonTableSize;

        ZeroKernel(io, sharedAreaKva, SharedAreaSize);

        // ---- Step 5: Read DMAP base and kernel CR3 ----

        ReadDmapAndCr3(io, pmapStore, out ulong dmapBase, out ulong kernelCr3);

        // ---- Step 6: Find empty PML4 indices ----

        ulong uelfVirtBase = FindEmptyPml4Index(io, dmapBase, kernelCr3, 0);
        if (uelfVirtBase == 0) return false;
        ulong dmemVirtBase = FindEmptyPml4Index(io, dmapBase, kernelCr3, 1);
        if (dmemVirtBase == 0) return false;

        // Convert shared area to DMEM-offset physical address
        ulong sharedAreaPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, sharedAreaKva);
        if (sharedAreaPhys == ulong.MaxValue) return false;
        ulong sharedAreaDmem = sharedAreaPhys + dmemVirtBase;

        // ---- Step 6a: Allocate uelf data buffers ----

        // cr3_phys_addr: 8-byte buffer for the kernel CR3 physical address.
        // The uelf's virt2phys walker reads this value to start page-table walks.
        ulong cr3Storage = BumpAlloc(ref blockPos, blockEnd, 8);
        if (cr3Storage == 0) return false;
        io.WriteU64(cr3Storage, kernelCr3);

        // wrmsr_args: 24-byte buffer for the wrmsr gadget arguments.
        // Populated by the dispatcher's gsbase-restoration sequence.
        ulong wrmsrArgsBuf = BumpAlloc(ref blockPos, blockEnd, 24);
        if (wrmsrArgsBuf == 0) return false;
        ZeroKernel(io, wrmsrArgsBuf, 24);

        // ---- Step 7: Build symbol table ----

        byte[][] symNames = new byte[MaxSymbols][];
        ulong[] symValues = new ulong[MaxSymbols];
        int symCount = 0;

        int pcpuIdx = -1, uelfCr3Idx = -1, uelfEntryIdx = -1;
        int istErrcIdx = -1, istNoerrcIdx = -1, ist4Idx = -1, tssIdx = -1;

        void AddSym(ReadOnlySpan<byte> name, ulong val)
        {
            symNames[symCount] = name.ToArray();
            symValues[symCount] = val;
            symCount++;
        }

        // Non-kernel symbols
        AddSym("comparison_table"u8, compTable);
        AddSym("dmem"u8, dmemVirtBase);
        AddSym("int1_handler"u8, int1Handler);
        AddSym("int3_handler"u8, int3Handler);
        AddSym("int13_handler"u8, int13Handler);

        istErrcIdx = symCount;
        AddSym(".ist_errc"u8, 0);
        istNoerrcIdx = symCount;
        AddSym(".ist_noerrc"u8, 0);
        ist4Idx = symCount;
        AddSym(".ist4"u8, 0);
        pcpuIdx = symCount;
        AddSym(".pcpu"u8, 0);

        AddSym("shared_area"u8, sharedAreaDmem);

        tssIdx = symCount;
        AddSym(".tss"u8, 0);
        uelfCr3Idx = symCount;
        AddSym(".uelf_cr3"u8, 0);
        uelfEntryIdx = symCount;
        AddSym(".uelf_entry"u8, 0);
        AddSym(".fwver"u8, fwMm);

        // Kernel offsets: each is kdata_base + signed offset
        AddSym("allproc"u8, kdb + KernelOffsets.Allproc(fw));
        AddSym("idt"u8, idtBase);
        AddSym("gdt_array"u8, Abs(kdb, KernelOffsets.GdtArray_1001));
        AddSym("tss_array"u8, tssBase);
        AddSym("pcpu_array"u8, pcpuBase);
        AddSym("doreti_iret"u8, doretiIret);
        AddSym("add_rsp_iret"u8, Abs(kdb, KernelOffsets.AddRspIret_1001));
        AddSym("swapgs_add_rsp_iret"u8, Abs(kdb, KernelOffsets.SwapgsAddRspIret_1001));
        AddSym("rep_movsb_pop_rbp_ret"u8, Abs(kdb, KernelOffsets.RepMovsbPopRbpRet_1001));
        AddSym("rdmsr_start"u8, Abs(kdb, KernelOffsets.RdmsrStart_1001));
        AddSym("wrmsr_ret"u8, Abs(kdb, KernelOffsets.WrmsrRet_1001));
        AddSym("dr2gpr_start"u8, Abs(kdb, KernelOffsets.Dr2GprStart_1001));
        AddSym("gpr2dr_1_start"u8, Abs(kdb, KernelOffsets.Gpr2Dr1Start_1001));
        AddSym("gpr2dr_2_start"u8, Abs(kdb, KernelOffsets.Gpr2Dr2Start_1001));
        AddSym("mov_cr3_rax_mov_ds"u8, Abs(kdb, KernelOffsets.MovCr3RaxMovDs_1001));
        AddSym("mov_rax_cr3"u8, Abs(kdb, KernelOffsets.MovRaxCr3_1001));
        AddSym("nop_ret"u8, Abs(kdb, KernelOffsets.NopRet_1001));
        AddSym("cpu_switch"u8, Abs(kdb, KernelOffsets.CpuSwitch_1001));
        AddSym("mprotect_fix_start"u8, Abs(kdb, KernelOffsets.MprotectFixStart_1001));
        AddSym("mprotect_fix_end"u8, Abs(kdb, KernelOffsets.MprotectFixEnd_1001));
        AddSym("aslr_fix_start"u8, Abs(kdb, KernelOffsets.AslrFixStart_1001));
        AddSym("aslr_fix_end"u8, Abs(kdb, KernelOffsets.AslrFixEnd_1001));
        AddSym("sysents"u8, sysentsAddr);
        AddSym("sysents_ps4"u8, sysentsPs4Addr);
        AddSym("sysentvec"u8, sysentvecAddr);
        AddSym("sysentvec_ps4"u8, sysentvecPs4);
        AddSym("sceSblServiceMailbox"u8, Abs(kdb, KernelOffsets.SceSblServiceMailbox_1001));
        AddSym("sceSblAuthMgrSmIsLoadable2"u8, Abs(kdb, KernelOffsets.SceSblAuthMgrSmIsLoadable2_1001));
        AddSym("syscall_before"u8, Abs(kdb, KernelOffsets.SyscallBefore_1001));
        AddSym("syscall_after"u8, Abs(kdb, KernelOffsets.SyscallAfter_1001));
        AddSym("malloc"u8, mallocAddr);
        AddSym("M_something"u8, mallocType);
        AddSym("loadSelfSegment_epilogue"u8, Abs(kdb, KernelOffsets.LoadSelfSegmentEpilogue_1001));
        AddSym("loadSelfSegment_watchpoint"u8, Abs(kdb, KernelOffsets.LoadSelfSegmentWatchpoint_1001));
        AddSym("loadSelfSegment_watchpoint_lr"u8, Abs(kdb, KernelOffsets.LoadSelfSegmentWatchpointLr_1001));
        AddSym("decryptSelfBlock_watchpoint_lr"u8, Abs(kdb, KernelOffsets.DecryptSelfBlockWatchpointLr_1001));
        AddSym("decryptSelfBlock_epilogue"u8, Abs(kdb, KernelOffsets.DecryptSelfBlockEpilogue_1001));
        AddSym("decryptMultipleSelfBlocks_epilogue"u8, Abs(kdb, KernelOffsets.DecryptMultipleSelfBlocksEpilogue_1001));
        AddSym("decryptMultipleSelfBlocks_watchpoint_lr"u8, Abs(kdb, KernelOffsets.DecryptMultipleSelfBlocksWatchpointLr_1001));
        AddSym("sceSblServiceMailbox_lr_verifyHeader"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrVerifyHeader_1001));
        AddSym("sceSblServiceMailbox_lr_loadSelfSegment"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrLoadSelfSegment_1001));
        AddSym("sceSblServiceMailbox_lr_decryptSelfBlock"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrDecryptSelfBlock_1001));
        AddSym("sceSblServiceMailbox_lr_decryptMultipleSelfBlocks"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrDecryptMultipleSelfBlocks_1001));
        AddSym("sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrSceSblAuthMgrSmFinalize_1001));
        AddSym("sceSblServiceMailbox_lr_verifySuperBlock"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrVerifySuperBlock_1001));
        AddSym("sceSblServiceMailbox_lr_sceSblPfsClearKey_1"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrSceSblPfsClearKey1_1001));
        AddSym("sceSblServiceMailbox_lr_sceSblPfsClearKey_2"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrSceSblPfsClearKey2_1001));
        AddSym("sceSblServiceMailbox_lr_npdrm_cmd_5"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrNpdrmCmd5_1001));
        AddSym("sceSblServiceMailbox_lr_npdrm_cmd_6"u8, Abs(kdb, KernelOffsets.SceSblServiceMailboxLrNpdrmCmd6_1001));
        AddSym("sceSblPfsSetKeys"u8, Abs(kdb, KernelOffsets.SceSblPfsSetKeys_1001));
        AddSym("sceSblServiceCryptAsync"u8, Abs(kdb, KernelOffsets.SceSblServiceCryptAsync_1001));
        AddSym("sceSblServiceCryptAsync_deref_singleton"u8, Abs(kdb, KernelOffsets.SceSblServiceCryptAsyncDerefSingleton_1001));
        AddSym("copyin"u8, Abs(kdb, KernelOffsets.Copyin_1001));
        AddSym("copyout"u8, Abs(kdb, KernelOffsets.Copyout_1001));
        AddSym("crypt_message_resolve"u8, Abs(kdb, KernelOffsets.CryptMessageResolve_1001));
        AddSym("justreturn"u8, Abs(kdb, KernelOffsets.Justreturn_1001));
        AddSym("justreturn_pop"u8, Abs(kdb, KernelOffsets.JustreturnPop_1001));
        AddSym("mini_syscore_header"u8, Abs(kdb, KernelOffsets.MiniSyscoreHeader_1001));
        AddSym("pop_all_iret"u8, Abs(kdb, KernelOffsets.PopAllIret_1001));
        AddSym("pop_all_except_rdi_iret"u8, Abs(kdb, KernelOffsets.PopAllExceptRdiIret_1001));
        AddSym("push_pop_all_iret"u8, Abs(kdb, KernelOffsets.PushPopAllIret_1001));
        AddSym("kernel_pmap_store"u8, pmapStore);
        AddSym("crypt_singleton_array"u8, cryptSingleton);
        AddSym("mov_rax_cr0"u8, Abs(kdb, KernelOffsets.MovRaxCr0_1001));
        AddSym("mov_cr0_rax"u8, Abs(kdb, KernelOffsets.MovCr0Rax_1001));
        AddSym("syscall_cfi_table_jmp_int3"u8, cfiJmpInt3);

        // Absolute offset (not kdata-relative)
        AddSym("p_sysent"u8, (ulong)KernelOffsets.ProcSysent(fw));

        // ---- Kernel structure field offsets (constant across firmware) ----
        AddSym("td_frame"u8, (ulong)KernelOffsets.ThreadFrame);
        AddSym("td_proc"u8, (ulong)KernelOffsets.ThreadProc);
        AddSym("p_sysent_off"u8, (ulong)KernelOffsets.ProcSysent(fw));
        AddSym("iret_rax"u8, 0x30);
        AddSym("sysent_sy_call"u8, (ulong)SysentSyCallOffset);
        AddSym("sysent_size"u8, (ulong)SysentStructSize);
        AddSym("pcb_gsbase"u8, (ulong)(KernelOffsets.PcbGsBase + KernelOffsets.PcbShift(fw)));

        // Syscall frame offsets (firmware-dependent via PcbShift)
        AddSym("syscall_rsp_to_rsi"u8, (ulong)(KernelOffsets.SyscallRspToRsiBase + KernelOffsets.PcbShift(fw)));
        AddSym("syscall_extra"u8, fwMm >= 0x1000 ? 0x10UL : 0UL);

        // Fself inline constant values
        AddSym("fself_backup_frame_size"u8, (ulong)((48 + KernelOffsets.MiniSyscoreHeaderSize + 15) & ~15));
        AddSym("mini_syscore_header_size"u8, (ulong)KernelOffsets.MiniSyscoreHeaderSize);

        // Uelf data buffer pointers
        AddSym("cr3_phys_addr"u8, cr3Storage);
        AddSym("wrmsr_args"u8, wrmsrArgsBuf);

        // ---- Sysent comparison targets (computed at install time) ----
        AddSym("sysent_nmount"u8, sysentsAddr + (ulong)(SysNmount * SysentStructSize));
        AddSym("sysent_unmount"u8, sysentsAddr + (ulong)(SysUnmount * SysentStructSize));
        AddSym("sysent_getppid"u8, sysentsAddr + (ulong)(SysGetppid * SysentStructSize));
        AddSym("sysent_execve"u8, sysentsAddr + (ulong)(SysExecve * SysentStructSize));
        AddSym("sysent_dynlib_load_prx"u8, sysentsAddr + (ulong)(SysDynlibLoadPrx * SysentStructSize));
        AddSym("sysent_get_self_auth_info"u8, sysentsAddr + (ulong)(SysGetSelfAuthInfo * SysentStructSize));
        AddSym("sysent_get_sdk_compiled_version"u8, sysentsAddr + (ulong)(SysGetSdkCompiledVersion * SysentStructSize));
        AddSym("sysent_get_ppr_sdk_compiled_version"u8, sysentsAddr + (ulong)(SysGetPprSdkCompiledVersion * SysentStructSize));
        AddSym("sysent_mprotect"u8, sysentsAddr + (ulong)(SysMprotect * SysentStructSize));
        AddSym("sysent_mdbg_call"u8, sysentsAddr + (ulong)(SysMdbgCall * SysentStructSize));
        AddSym("sysent_ioctl"u8, sysentsAddr + (ulong)(SysIoctl * SysentStructSize));

        // ---- Disabled subsystem handlers (zero = guarded call skips) ----
        AddSym("outer_pfs_handler"u8, 0);
        AddSym("inner_pfs_handler"u8, 0);

        // ---- DR breakpoint targets (zero = disabled until armed) ----
        AddSym("ppfs_read_outer_block"u8, 0);
        AddSym("read_naps_pfs_image_start"u8, 0);

        // ---- Step 8: Per-CPU ELF loading ----

        byte[] kelfWork = kelfBlob.ToArray();
        byte[] uelfWork = uelfBlob.ToArray();
        ulong[] kelfEntries = new ulong[Ncpus];

        fixed (byte* kelfPtr = kelfWork)
        fixed (byte* uelfPtr = uelfWork)
        {
            int pcpuStr = PcpuStride(fwMm);

            for (int cpu = 0; cpu < Ncpus; cpu++)
            {
                ulong tss = tssBase + (ulong)(cpu * TssStride);

                symValues[pcpuIdx] = pcpuBase + (ulong)(cpu * pcpuStr);
                symValues[uelfCr3Idx] = 0;
                symValues[uelfEntryIdx] = 0;
                symValues[istErrcIdx] = tss + (ulong)(TssIstBase + Int13IstIndex * 8);
                symValues[istNoerrcIdx] = tss + (ulong)(TssIstBase + Int1IstIndex * 8);
                symValues[ist4Idx] = percpuIst4[cpu];
                symValues[tssIdx] = tss;

                // Load uelf into kernel at the custom virtual base
                bool ok = LoadKelf(io, uelfPtr, uelfWork.Length, symNames, symValues, symCount,
                    ref blockPos, blockEnd, sysentsAddr, mallocAddr, mallocType,
                    uelfVirtBase,
                    out ulong uelfBase, out ulong uelfEnd, out ulong uelfEntry);
                if (!ok) return false;

                // Allocate uelf CR3 page table pages (5 pages, page-aligned)
                ulong cr3Raw = BumpAlloc(ref blockPos, blockEnd, 24576);
                if (cr3Raw == 0) return false;
                ulong cr3Kva = AlignUp(cr3Raw, PageSize);

                // Resolve physical address of uelf CR3 for the kelf
                ulong cr3Phys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, cr3Kva);
                if (cr3Phys == ulong.MaxValue) return false;

                symValues[uelfCr3Idx] = cr3Phys;
                symValues[uelfEntryIdx] = uelfEntry - uelfBase + uelfVirtBase;

                // Load kelf into kernel (kelf maps at its allocation address)
                ok = LoadKelf(io, kelfPtr, kelfWork.Length, symNames, symValues, symCount,
                    ref blockPos, blockEnd, sysentsAddr, mallocAddr, mallocType,
                    0,
                    out _, out _, out ulong kelfEntry);
                if (!ok) return false;

                kelfEntries[cpu] = kelfEntry;

                // Build uelf CR3 page tables
                BuildUelfCr3(io, cr3Kva, uelfBase, uelfEnd, uelfVirtBase,
                    dmemVirtBase, dmapBase, kernelCr3);
            }
        }

        // ---- Step 8a: Set SFMASK TF bit ----
        // SYSCALL clears EFLAGS bits set in SFMASK. Setting the TF bit (bit 8)
        // prevents spurious single-step traps during syscall entry after the IDT
        // is patched with the kernel module's interrupt handlers.

        if (!WriteSfmaskTfBit(io, ref blockPos, blockEnd, sysentsAddr))
            return false;

        // ---- Step 9: Patch IDT ----

        // INT2 -> doreti_iret (NMI recovery)
        KernelIdt.WriteGateTarget(io, idtBase, 2, doretiIret);

        // INT13 -> kelf[0] entry (first 8 bytes of the entry stub)
        ulong entry0 = kelfEntries[0];
        ulong handlerInt13 = io.ReadU64(entry0);
        KernelIdt.WriteGateTarget(io, idtBase, 13, handlerInt13);
        io.WriteU8(idtBase + 16 * 13 + 4, Int13IstIndex);

        // INT1 -> kelf[0] entry + 16
        ulong handlerInt1 = io.ReadU64(entry0 + 16);
        KernelIdt.WriteGateTarget(io, idtBase, 1, handlerInt1);
        io.WriteU8(idtBase + 16 * 1 + 4, Int1IstIndex);

        // INT3 -> kelf[0] entry + 32
        ulong handlerInt3 = io.ReadU64(entry0 + 32);
        KernelIdt.WriteGateTarget(io, idtBase, 3, handlerInt3);
        io.WriteU8(idtBase + 16 * 3 + 4, Int3IstIndex);

        // ---- Step 10: Patch TSS IST entries per-CPU ----

        for (int cpu = 0; cpu < Ncpus; cpu++)
        {
            ulong entry = kelfEntries[cpu];
            ulong tss = tssBase + (ulong)(cpu * TssStride);

            // IST3 (INT13) = entry + 8
            ulong ist3Val = io.ReadU64(entry + 8);
            io.WriteU64(tss + (ulong)(TssIstBase + Int13IstIndex * 8), ist3Val);

            // IST4 (INT1) = entry + 24
            ulong ist4Val = io.ReadU64(entry + 24);
            io.WriteU64(tss + (ulong)(TssIstBase + Int1IstIndex * 8), ist4Val);

            // IST7 (INT3) = entry + 40
            ulong ist7Val = io.ReadU64(entry + 40);
            io.WriteU64(tss + (ulong)(TssIstBase + Int3IstIndex * 8), ist7Val);
        }

        // ---- Step 11: Clone sysent tables and hook syscalls ----

        if (!CloneAndHookSysent(io, ref blockPos, blockEnd, sysentsAddr, mallocAddr, mallocType,
            sysentvecAddr, sysentvecPs4, sysentsPs4Addr, cfiJmpInt3, fw))
            return false;

        // ---- Step 12: Poison crypto singleton entries ----

        // XTS singleton: crypt_singleton_array + 11*8 + 2*8 + 6
        io.WriteU16(cryptSingleton + 11 * 8 + 2 * 8 + 6, 0xDEB7);
        // HMAC singleton: crypt_singleton_array + 11*8 + 9*8 + 6
        io.WriteU16(cryptSingleton + 11 * 8 + 9 * 8 + 6, 0xDEB7);

        // ---- Step 13: Patch IDT gate type bytes ----

        // INT9 and INT179: set type to 0x8E (present, ring-0, 64-bit interrupt gate)
        io.WriteU8(idtBase + 16 * 9 + 5, 0x8E);
        io.WriteU8(idtBase + 16 * 179 + 5, 0x8E);

        // ---- Step 14: Apply ShellCore patches ----

        // ShellCore patches target user-mode virtual addresses in the SceShellCore process.
        // PhysCopyin translates those addresses through the process page tables, so the
        // process CR3 (not the kernel CR3) is required.
        ulong shellCoreCr3 = GetProcessCr3(io, dmapBase, fw);
        if (shellCoreCr3 != 0)
        {
            ConsoleKitType kit = PayloadShellCorePatcher.DetectKitType();
            PayloadShellCorePatcher.Apply(io, shellCoreCr3, dmapBase, fw, kit);
        }

        return true;
    }

    // ---- Kernel bump allocator ----

    private static ulong BumpAlloc(ref ulong pos, ulong end, int size)
    {
        ulong aligned = (ulong)((size + 15) & ~15);
        if (pos + aligned > end) return 0;
        ulong result = pos;
        pos += aligned;
        return result;
    }

    private static ulong AlignUp(ulong value, ulong alignment)
    {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    // ---- Chunked kernel memory operations ----

    private static void WriteToKernel(PayloadKernelIo io, ulong kaddr, byte* src, int len)
    {
        while (len > 0)
        {
            int chunk = len < CopyChunkSize ? len : CopyChunkSize;
            io.Write(kaddr, src, chunk);
            kaddr += (ulong)chunk;
            src += chunk;
            len -= chunk;
        }
    }

    private static void ZeroKernel(PayloadKernelIo io, ulong kaddr, int len)
    {
        byte* zeros = stackalloc byte[CopyChunkSize];
        for (int i = 0; i < CopyChunkSize; i++) zeros[i] = 0;
        while (len > 0)
        {
            int chunk = len < CopyChunkSize ? len : CopyChunkSize;
            io.Write(kaddr, zeros, chunk);
            kaddr += (ulong)chunk;
            len -= chunk;
        }
    }

    private static void CopyKernelToKernel(PayloadKernelIo io, ulong dst, ulong src, int len)
    {
        byte* buf = stackalloc byte[CopyChunkSize];
        while (len > 0)
        {
            int chunk = len < CopyChunkSize ? len : CopyChunkSize;
            io.Read(src, buf, chunk);
            io.Write(dst, buf, chunk);
            src += (ulong)chunk;
            dst += (ulong)chunk;
            len -= chunk;
        }
    }

    // ---- SFMASK MSR ----

    /// <summary>
    /// Sets the TF bit (bit 8) in the SFMASK MSR (0xC0000084) so that SYSCALL clears
    /// EFLAGS.TF on entry. Without this, the single-step trap flag survives into the
    /// syscall handler after the IDT is patched, causing spurious INT1 traps.
    /// </summary>
    /// <remarks>
    /// The kernel's rdmsr/wrmsr instruction sequences are raw gadgets that require
    /// ECX = MSR number and EDX:EAX = value, which does not match the standard AMD64
    /// calling convention used by <see cref="PayloadKfncall.Call"/>. This method writes
    /// small calling-convention thunks into kernel heap memory (which is supervisor-mode
    /// executable, as proven by the kelf loading path) that bridge from the standard
    /// register mapping to the MSR instruction operands.
    /// </remarks>
    private static bool WriteSfmaskTfBit(PayloadKernelIo io, ref ulong blockPos,
        ulong blockEnd, ulong sysentsAddr)
    {
        const ulong SfmaskMsr = 0xC0000084;
        const ulong TfBit = 0x100;

        // Allocate space for rdmsr and wrmsr thunks (12 + 9 bytes, 16-byte aligned)
        ulong thunkBase = BumpAlloc(ref blockPos, blockEnd, 32);
        if (thunkBase == 0) return false;

        ulong rdmsrThunk = thunkBase;
        ulong wrmsrThunk = thunkBase + 16;

        // rdmsr thunk: arg1 (RDI) = MSR number, returns full 64-bit value in RAX.
        //   mov ecx, edi      -- ECX = MSR number from first argument
        //   rdmsr              -- EDX:EAX = MSR[ECX]
        //   shl rdx, 32       -- shift high half into position
        //   or  rax, rdx      -- combine into single 64-bit return value
        //   ret
        byte* rc = stackalloc byte[]
        {
            0x89, 0xF9,
            0x0F, 0x32,
            0x48, 0xC1, 0xE2, 0x20,
            0x48, 0x09, 0xD0,
            0xC3
        };
        io.Write(rdmsrThunk, rc, 12);

        // wrmsr thunk: arg1 (RDI) = low 32, arg2 (RSI) = high 32, arg3 (RDX) = MSR.
        //   mov eax, edi      -- EAX = low 32 bits from first argument
        //   mov ecx, edx      -- ECX = MSR number from third argument (before EDX clobber)
        //   mov edx, esi      -- EDX = high 32 bits from second argument
        //   wrmsr              -- MSR[ECX] = EDX:EAX
        //   ret
        byte* wc = stackalloc byte[]
        {
            0x89, 0xF8,
            0x89, 0xD1,
            0x89, 0xF2,
            0x0F, 0x30,
            0xC3
        };
        io.Write(wrmsrThunk, wc, 9);

        // Read current SFMASK, set TF bit, write back
        ulong sfmask = PayloadKfncall.Call(io, sysentsAddr, rdmsrThunk, SfmaskMsr);
        sfmask |= TfBit;
        PayloadKfncall.Call(io, sysentsAddr, wrmsrThunk,
            sfmask & 0xFFFFFFFF, sfmask >> 32, SfmaskMsr);

        return true;
    }

    // ---- DMAP and CR3 ----

    private static void ReadDmapAndCr3(PayloadKernelIo io, ulong pmapStore,
        out ulong dmapBase, out ulong cr3)
    {
        ulong dmapVirt = io.ReadU64(pmapStore + 32);
        ulong cr3Phys = io.ReadU64(pmapStore + 40);
        dmapBase = dmapVirt - cr3Phys;
        cr3 = cr3Phys;
    }

    /// <summary>
    /// Reads the CR3 page-table root for the SceShellCore process. Walks the process
    /// list to find SceShellCore, then reads <c>proc->p_vmspace->vm_pmap.pm_cr3</c>.
    /// Returns zero if the process or any intermediate pointer cannot be resolved.
    /// </summary>
    private static ulong GetProcessCr3(PayloadKernelIo io, ulong dmapBase, uint fw)
    {
        ReadOnlySpan<byte> shellcoreName = "SceShellCore"u8;
        ulong proc;
        fixed (byte* p = shellcoreName)
            proc = PayloadKernel.FindProcessByName(io, p, shellcoreName.Length);
        if (proc == 0) return 0;

        ulong vmspace = io.ReadU64(proc + (ulong)KernelOffsets.ProcVmspace);
        if (vmspace == 0) return 0;

        uint fwMm = (fw >> 16) & 0xFFFF;
        int pmapOff = KernelOffsets.VmspacePmapOffset(fwMm);
        ulong pmCr3 = io.ReadU64(vmspace + (ulong)pmapOff + 40);
        return pmCr3;
    }

    // ---- PML4 index scanner ----

    private static ulong FindEmptyPml4Index(PayloadKernelIo io, ulong dmapBase,
        ulong cr3, int skip)
    {
        ulong pml4Addr = dmapBase + cr3;
        for (int i = 256; i < 512; i++)
        {
            ulong entry = io.ReadU64(pml4Addr + (ulong)(i * 8));
            if (entry == 0)
            {
                if (skip == 0)
                    return ((ulong)i << 39) | 0xFFFF_8000_0000_0000UL;
                skip--;
            }
        }
        return 0;
    }

    // ---- ELF loader ----

    /// <summary>
    /// Converts a virtual address from the ELF's dynamic section to a file offset by
    /// searching the PT_LOAD segments.
    /// </summary>
    private static int VirtToFileOffset(Elf64Phdr* phdr, int phnum, ulong addr)
    {
        for (int i = 0; i < phnum; i++)
        {
            if (phdr[i].Type != ElfConstants.PtLoad) continue;
            if (addr >= phdr[i].Vaddr && addr < phdr[i].Vaddr + phdr[i].Filesz)
                return (int)(addr - phdr[i].Vaddr + phdr[i].Offset);
        }
        return -1;
    }

    /// <summary>
    /// Compares a NUL-terminated byte string at <paramref name="a"/> against a name byte
    /// array. The name may start with '.' for one-shot resolution; the comparison skips
    /// the leading dot and returns whether the remainder matches.
    /// </summary>
    private static bool NameMatches(byte* a, byte[] name, out bool isOneShot)
    {
        isOneShot = false;
        int start = 0;
        if (name.Length > 0 && name[0] == (byte)'.')
        {
            isOneShot = true;
            start = 1;
        }
        for (int i = start; i < name.Length; i++)
        {
            if (a[i - start] != name[i]) return false;
        }
        return a[name.Length - start] == 0;
    }

    /// <summary>
    /// Loads an ELF binary into kernel memory with full symbol resolution, relocations,
    /// and BSS zeroing.
    /// </summary>
    private static bool LoadKelf(PayloadKernelIo io, byte* blob, int blobLen,
        byte[][] symNames, ulong[] symValues, int symCount,
        ref ulong blockPos, ulong blockEnd,
        ulong sysentsAddr, ulong mallocAddr, ulong mallocType,
        ulong mappedKptr,
        out ulong baseOut, out ulong endOut, out ulong entryOut)
    {
        baseOut = 0;
        endOut = 0;
        entryOut = 0;

        if (blobLen < sizeof(Elf64Ehdr)) return false;

        Elf64Ehdr* ehdr = (Elf64Ehdr*)blob;
        Elf64Phdr* phdr = (Elf64Phdr*)(blob + (int)ehdr->Phoff);
        int phnum = ehdr->Phnum;

        // Find PT_DYNAMIC and compute total virtual size
        Elf64Dyn* dynamic = null;
        int dynamicSize = 0;
        ulong kernelSize = 0;

        for (int i = 0; i < phnum; i++)
        {
            if (phdr[i].Type == ElfConstants.PtDynamic)
            {
                dynamic = (Elf64Dyn*)(blob + (int)phdr[i].Offset);
                dynamicSize = (int)phdr[i].Filesz;
            }
            else if (phdr[i].Type == ElfConstants.PtLoad)
            {
                ulong limit = phdr[i].Vaddr + phdr[i].Memsz;
                if (limit > kernelSize)
                    kernelSize = limit;
            }
        }

        kernelSize = AlignUp(kernelSize, PageSize);
        if (kernelSize == 0) return false;

        // Allocate kernel memory for the image (page-aligned)
        ulong raw = BumpAlloc(ref blockPos, blockEnd, (int)kernelSize + PageSize);
        if (raw == 0) return false;
        ulong kptr = AlignUp(raw, PageSize);

        if (mappedKptr == 0)
            mappedKptr = kptr;

        baseOut = kptr;
        endOut = kptr + kernelSize;

        // Copy PT_LOAD segments and zero BSS
        for (int i = 0; i < phnum; i++)
        {
            if (phdr[i].Type != ElfConstants.PtLoad) continue;

            ulong dst = kptr + phdr[i].Vaddr;
            byte* src = blob + (int)phdr[i].Offset;
            int filesz = (int)phdr[i].Filesz;
            int memsz = (int)phdr[i].Memsz;

            WriteToKernel(io, dst, src, filesz);
            if (memsz > filesz)
                ZeroKernel(io, dst + (ulong)filesz, memsz - filesz);
        }

        // Parse dynamic section for STRTAB, SYMTAB, RELA, RELASZ
        if (dynamic == null) goto done;

        byte* strtab = null;
        Elf64Sym* symtab = null;
        Elf64Rela* rela = null;
        int relasz = 0;
        int dynEntries = dynamicSize / sizeof(Elf64Dyn);

        for (int i = 0; i < dynEntries; i++)
        {
            long tag = dynamic[i].Tag;
            ulong val = dynamic[i].Val;
            if (tag == ElfConstants.DtStrtab)
            {
                int off = VirtToFileOffset(phdr, phnum, val);
                if (off >= 0) strtab = blob + off;
            }
            else if (tag == ElfConstants.DtSymtab)
            {
                int off = VirtToFileOffset(phdr, phnum, val);
                if (off >= 0) symtab = (Elf64Sym*)(blob + off);
            }
            else if (tag == ElfConstants.DtRela)
            {
                int off = VirtToFileOffset(phdr, phnum, val);
                if (off >= 0) rela = (Elf64Rela*)(blob + off);
            }
            else if (tag == ElfConstants.DtRelasz)
            {
                relasz = (int)val;
            }
        }

        // Apply relocations
        if (rela != null && strtab != null && symtab != null)
        {
            int relaCount = relasz / sizeof(Elf64Rela);
            for (int i = 0; i < relaCount; i++)
            {
                uint type = rela[i].Type;
                uint symIdx = rela[i].Sym;
                ulong offset = rela[i].Offset;
                long addend = rela[i].Addend;

                if (type == ElfConstants.RX8664_64 || type == ElfConstants.RX8664GlobDat)
                {
                    Elf64Sym* sym = &symtab[symIdx];
                    ulong value = sym->Value;

                    if (value == 0)
                    {
                        byte* name = strtab + sym->Name;
                        bool resolved = false;

                        for (int s = 0; s < symCount; s++)
                        {
                            if (NameMatches(name, symNames[s], out bool oneShot))
                            {
                                if (!oneShot)
                                    sym->Value = symValues[s];
                                value = symValues[s];
                                resolved = true;
                                break;
                            }
                        }

                        if (!resolved) return false;
                    }

                    if (type == ElfConstants.RX8664GlobDat && addend != 0)
                        return false;

                    if (offset + 8 > kernelSize)
                        return false;

                    io.WriteU64(kptr + offset, (ulong)addend + value);
                }
                else if (type == ElfConstants.RX8664Relative)
                {
                    if (offset + 8 > kernelSize)
                        return false;

                    io.WriteU64(kptr + offset, mappedKptr + (ulong)addend);
                }
                else
                {
                    return false;
                }
            }
        }

    done:
        entryOut = kptr + ehdr->Entry;
        return true;
    }

    // ---- Uelf CR3 page table builder ----

    private static void BuildUelfCr3(PayloadKernelIo io, ulong cr3Kva,
        ulong uelfBase, ulong uelfEnd, ulong uelfVirtBase,
        ulong dmemVirtBase, ulong dmapBase, ulong kernelCr3)
    {
        ulong pml4Kva = cr3Kva;
        ulong pdptKva = cr3Kva + 4096;
        ulong pdKva = cr3Kva + 8192;
        ulong ptKva = cr3Kva + 12288;
        ulong pdptDmemKva = cr3Kva + 16384;

        // Zero PML4, then copy the kernel's upper half (entries 256-511)
        ZeroKernel(io, pml4Kva, PageSize);
        CopyKernelToKernel(io, pml4Kva + 2048, dmapBase + kernelCr3 + 2048, 2048);

        // Wire PML4 entries for uelf and DMEM
        ulong pml4iUelf = (uelfVirtBase >> 39) & 511;
        ulong pml4iDmem = (dmemVirtBase >> 39) & 511;
        ulong pdptPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, pdptKva);
        if (pdptPhys == ulong.MaxValue) return;
        ulong pdptDmemPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, pdptDmemKva);
        if (pdptDmemPhys == ulong.MaxValue) return;
        io.WriteU64(pml4Kva + pml4iUelf * 8, pdptPhys | 7);
        io.WriteU64(pml4Kva + pml4iDmem * 8, pdptDmemPhys | 7);

        // Zero PDPT, wire entry -> PD
        ZeroKernel(io, pdptKva, PageSize);
        ulong pdpti = (uelfVirtBase >> 30) & 511;
        ulong pdPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, pdKva);
        if (pdPhys == ulong.MaxValue) return;
        io.WriteU64(pdptKva + pdpti * 8, pdPhys | 7);

        // Zero PD, wire entry -> PT
        ZeroKernel(io, pdKva, PageSize);
        ulong pdi = (uelfVirtBase >> 21) & 511;
        ulong ptPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, ptKva);
        if (ptPhys == ulong.MaxValue) return;
        io.WriteU64(pdKva + pdi * 8, ptPhys | 7);

        // Zero PT, fill with physical mappings of the uelf code pages
        ZeroKernel(io, ptKva, PageSize);
        ulong ptIdx = 0;
        for (ulong va = uelfBase; va < uelfEnd; va += PageSize, ptIdx++)
        {
            ulong pa = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, va);
            if (pa == ulong.MaxValue) continue;
            io.WriteU64(ptKva + ptIdx * 8, pa | 7);
        }

        // Fill DMEM PDPT with 512 x 1 GB identity-mapped pages
        // Flags: Present(1) + RW(2) + User(4) + PS(0x80) = 0x87
        for (ulong i = 0; i < 512; i++)
            io.WriteU64(pdptDmemKva + i * 8, (i << 30) | 0x87);
    }

    // ---- Sysent table cloning and syscall hooking ----

    private static bool CloneAndHookSysent(PayloadKernelIo io,
        ref ulong blockPos, ulong blockEnd,
        ulong sysentsAddr, ulong mallocAddr, ulong mallocType,
        ulong sysentvecAddr, ulong sysentvecPs4, ulong sysentsPs4Addr,
        ulong cfiJmpInt3, uint fw)
    {
        // Read the syscall counts from the sysentvec structures (sv_size at offset 0)
        int ps4SvSize = (int)io.ReadU32(sysentvecPs4);
        int ps5SvSize = (int)io.ReadU32(sysentvecAddr);
        if (ps4SvSize <= 0 || ps5SvSize <= 0) return false;

        int ps4TableSize = ps4SvSize * SysentStructSize;
        int ps5TableSize = ps5SvSize * SysentStructSize;

        // Read the original tables into user memory
        byte[] ps4Table = new byte[ps4TableSize];
        byte[] ps5Table = new byte[ps5TableSize];

        fixed (byte* p4 = ps4Table)
        fixed (byte* p5 = ps5Table)
        {
            ReadFromKernel(io, sysentsPs4Addr, p4, ps4TableSize);
            ReadFromKernel(io, sysentsAddr, p5, ps5TableSize);
        }

        // PS4 syscalls to hook
        ReadOnlySpan<int> ps4Hooks = stackalloc int[]
        {
            SysExecve, SysDynlibLoadPrx, SysGetSelfAuthInfo,
            SysGetSdkCompiledVersion, SysGetppid, SysMprotect
        };

        // PS5 syscalls to hook
        ReadOnlySpan<int> ps5Hooks = stackalloc int[]
        {
            SysExecve, SysDynlibLoadPrx, SysGetSelfAuthInfo,
            SysGetSdkCompiledVersion, SysGetPprSdkCompiledVersion,
            SysGetppid, SysNmount, SysUnmount, SysMprotect, SysMdbgCall
        };

        // ShellCore-only additional hooks
        ReadOnlySpan<int> shellcoreExtraHooks = stackalloc int[] { SysIoctl };

        // Hook PS4 table
        fixed (byte* p4 = ps4Table)
        {
            for (int i = 0; i < ps4Hooks.Length; i++)
            {
                int sysno = ps4Hooks[i];
                if (sysno < ps4SvSize)
                    *(ulong*)(p4 + sysno * SysentStructSize + SysentSyCallOffset) = cfiJmpInt3;
            }
        }

        // Hook PS5 table
        fixed (byte* p5 = ps5Table)
        {
            for (int i = 0; i < ps5Hooks.Length; i++)
            {
                int sysno = ps5Hooks[i];
                if (sysno < ps5SvSize)
                    *(ulong*)(p5 + sysno * SysentStructSize + SysentSyCallOffset) = cfiJmpInt3;
            }
        }

        // Create the ShellCore variant (PS5 table + extra hooks)
        byte[] shellcoreTable = new byte[ps5TableSize];
        Buffer.BlockCopy(ps5Table, 0, shellcoreTable, 0, ps5TableSize);

        fixed (byte* sc = shellcoreTable)
        {
            for (int i = 0; i < shellcoreExtraHooks.Length; i++)
            {
                int sysno = shellcoreExtraHooks[i];
                if (sysno < ps5SvSize)
                    *(ulong*)(sc + sysno * SysentStructSize + SysentSyCallOffset) = cfiJmpInt3;
            }
        }

        // Allocate kernel copies and write the tables
        ulong fakePs4 = BumpAlloc(ref blockPos, blockEnd, ps4TableSize);
        ulong fakePs5 = BumpAlloc(ref blockPos, blockEnd, ps5TableSize);
        ulong fakeShellcore = BumpAlloc(ref blockPos, blockEnd, ps5TableSize);
        if (fakePs4 == 0 || fakePs5 == 0 || fakeShellcore == 0) return false;

        fixed (byte* p4 = ps4Table)
            WriteToKernel(io, fakePs4, p4, ps4TableSize);
        fixed (byte* p5 = ps5Table)
            WriteToKernel(io, fakePs5, p5, ps5TableSize);
        fixed (byte* sc = shellcoreTable)
            WriteToKernel(io, fakeShellcore, sc, ps5TableSize);

        // Redirect sysentvec sv_table pointers to the cloned tables
        io.WriteU64(sysentvecPs4 + (ulong)KernelOffsets.SysentvecTable, fakePs4);
        io.WriteU64(sysentvecAddr + (ulong)KernelOffsets.SysentvecTable, fakePs5);

        // Create a full sysentvec clone for ShellCore with the shellcore sysent table
        ulong fakeSysentvec = BumpAlloc(ref blockPos, blockEnd, SysentvecCopySize);
        if (fakeSysentvec == 0) return false;

        CopyKernelToKernel(io, fakeSysentvec, sysentvecAddr, SysentvecCopySize);
        io.WriteU64(fakeSysentvec + (ulong)KernelOffsets.SysentvecTable, fakeShellcore);

        // Find SceShellCore and redirect its p_sysent to the cloned sysentvec
        ReadOnlySpan<byte> shellcoreName = "SceShellCore"u8;
        ulong shellcoreProc;
        fixed (byte* p = shellcoreName)
            shellcoreProc = PayloadKernel.FindProcessByName(io, p, shellcoreName.Length);

        if (shellcoreProc == 0) return false;

        int pSysentOff = KernelOffsets.ProcSysent(fw);
        io.WriteU64(shellcoreProc + (ulong)pSysentOff, fakeSysentvec);

        return true;
    }

    // ---- Chunked kernel read ----

    private static void ReadFromKernel(PayloadKernelIo io, ulong kaddr, byte* dst, int len)
    {
        while (len > 0)
        {
            int chunk = len < CopyChunkSize ? len : CopyChunkSize;
            io.Read(kaddr, dst, chunk);
            kaddr += (ulong)chunk;
            dst += chunk;
            len -= chunk;
        }
    }

}
