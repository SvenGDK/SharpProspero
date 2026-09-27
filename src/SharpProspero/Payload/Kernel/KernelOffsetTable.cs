// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// A full per-firmware kernel offset table. Each nullable field carries the
/// kdata-relative offset for one named kernel symbol on the firmware named by
/// <see cref="FirmwareVersion"/>. Positive offsets address the kernel data
/// segment; negative offsets address the kernel text segment (located below
/// <c>kdata_base</c> in virtual memory). Absolute kernel virtual addresses
/// are computed by adding the offset to <c>kdata_base</c>, which is looked up
/// per firmware via <see cref="KernelOffsets.KdataBase"/>. A null field means
/// the symbol is not on file for this firmware and callers must either derive
/// it another way or refuse the operation.
/// </summary>
public sealed record KernelOffsetTable
{
    /// <summary>The BCD-encoded firmware version this table covers.</summary>
    public required uint FirmwareVersion { get; init; }

    /// <summary>Kdata-relative offset of <c>allproc</c>, or null when unknown for this firmware.</summary>
    public long? Allproc { get; init; }

    /// <summary>Kdata-relative offset of <c>idt</c>, or null when unknown for this firmware.</summary>
    public long? Idt { get; init; }

    /// <summary>Kdata-relative offset of <c>gdt_array</c>, or null when unknown for this firmware.</summary>
    public long? GdtArray { get; init; }

    /// <summary>Kdata-relative offset of <c>tss_array</c>, or null when unknown for this firmware.</summary>
    public long? TssArray { get; init; }

    /// <summary>Kdata-relative offset of <c>pcpu_array</c>, or null when unknown for this firmware.</summary>
    public long? PcpuArray { get; init; }

    /// <summary>Kdata-relative offset of <c>doreti_iret</c>, or null when unknown for this firmware.</summary>
    public long? DoretiIret { get; init; }

    /// <summary>Kdata-relative offset of <c>add_rsp_iret</c>, or null when unknown for this firmware.</summary>
    public long? AddRspIret { get; init; }

    /// <summary>Kdata-relative offset of <c>swapgs_add_rsp_iret</c>, or null when unknown for this firmware.</summary>
    public long? SwapgsAddRspIret { get; init; }

    /// <summary>Kdata-relative offset of <c>rep_movsb_pop_rbp_ret</c>, or null when unknown for this firmware.</summary>
    public long? RepMovsbPopRbpRet { get; init; }

    /// <summary>Kdata-relative offset of <c>rdmsr_start</c>, or null when unknown for this firmware.</summary>
    public long? RdmsrStart { get; init; }

    /// <summary>Kdata-relative offset of <c>wrmsr_ret</c>, or null when unknown for this firmware.</summary>
    public long? WrmsrRet { get; init; }

    /// <summary>Kdata-relative offset of <c>dr2gpr_start</c>, or null when unknown for this firmware.</summary>
    public long? Dr2gprStart { get; init; }

    /// <summary>Kdata-relative offset of <c>gpr2dr_1_start</c>, or null when unknown for this firmware.</summary>
    public long? Gpr2dr1Start { get; init; }

    /// <summary>Kdata-relative offset of <c>gpr2dr_2_start</c>, or null when unknown for this firmware.</summary>
    public long? Gpr2dr2Start { get; init; }

    /// <summary>Kdata-relative offset of <c>mov_cr3_rax_mov_ds</c>, or null when unknown for this firmware.</summary>
    public long? MovCr3RaxMovDs { get; init; }

    /// <summary>Kdata-relative offset of <c>mov_rax_cr3</c>, or null when unknown for this firmware.</summary>
    public long? MovRaxCr3 { get; init; }

    /// <summary>Kdata-relative offset of <c>nop_ret</c>, or null when unknown for this firmware.</summary>
    public long? NopRet { get; init; }

    /// <summary>Kdata-relative offset of <c>cpu_switch</c>, or null when unknown for this firmware.</summary>
    public long? CpuSwitch { get; init; }

    /// <summary>Kdata-relative offset of <c>mprotect_fix_start</c>, or null when unknown for this firmware.</summary>
    public long? MprotectFixStart { get; init; }

    /// <summary>Kdata-relative offset of <c>mprotect_fix_end</c>, or null when unknown for this firmware.</summary>
    public long? MprotectFixEnd { get; init; }

    /// <summary>Kdata-relative offset of <c>aslr_fix_start</c>, or null when unknown for this firmware.</summary>
    public long? AslrFixStart { get; init; }

    /// <summary>Kdata-relative offset of <c>aslr_fix_end</c>, or null when unknown for this firmware.</summary>
    public long? AslrFixEnd { get; init; }

    /// <summary>Kdata-relative offset of <c>sysents</c>, or null when unknown for this firmware.</summary>
    public long? Sysents { get; init; }

    /// <summary>Kdata-relative offset of <c>sysents_ps4</c>, or null when unknown for this firmware.</summary>
    public long? SysentsPs4 { get; init; }

    /// <summary>Kdata-relative offset of <c>sysentvec</c>, or null when unknown for this firmware.</summary>
    public long? Sysentvec { get; init; }

    /// <summary>Kdata-relative offset of <c>sysentvec_ps4</c>, or null when unknown for this firmware.</summary>
    public long? SysentvecPs4 { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailbox { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblAuthMgrSmIsLoadable2</c>, or null when unknown for this firmware.</summary>
    public long? SceSblAuthMgrSmIsLoadable2 { get; init; }

    /// <summary>Kdata-relative offset of <c>syscall_before</c>, or null when unknown for this firmware.</summary>
    public long? SyscallBefore { get; init; }

    /// <summary>Kdata-relative offset of <c>syscall_after</c>, or null when unknown for this firmware.</summary>
    public long? SyscallAfter { get; init; }

    /// <summary>Kdata-relative offset of <c>malloc</c>, or null when unknown for this firmware.</summary>
    public long? Malloc { get; init; }

    /// <summary>Kdata-relative offset of <c>M_something</c>, or null when unknown for this firmware.</summary>
    public long? MSomething { get; init; }

    /// <summary>Kdata-relative offset of <c>loadSelfSegment_epilogue</c>, or null when unknown for this firmware.</summary>
    public long? LoadSelfSegmentEpilogue { get; init; }

    /// <summary>Kdata-relative offset of <c>loadSelfSegment_watchpoint</c>, or null when unknown for this firmware.</summary>
    public long? LoadSelfSegmentWatchpoint { get; init; }

    /// <summary>Kdata-relative offset of <c>loadSelfSegment_watchpoint_lr</c>, or null when unknown for this firmware.</summary>
    public long? LoadSelfSegmentWatchpointLr { get; init; }

    /// <summary>Kdata-relative offset of <c>decryptSelfBlock_watchpoint_lr</c>, or null when unknown for this firmware.</summary>
    public long? DecryptSelfBlockWatchpointLr { get; init; }

    /// <summary>Kdata-relative offset of <c>decryptSelfBlock_epilogue</c>, or null when unknown for this firmware.</summary>
    public long? DecryptSelfBlockEpilogue { get; init; }

    /// <summary>Kdata-relative offset of <c>decryptMultipleSelfBlocks_epilogue</c>, or null when unknown for this firmware.</summary>
    public long? DecryptMultipleSelfBlocksEpilogue { get; init; }

    /// <summary>Kdata-relative offset of <c>decryptMultipleSelfBlocks_watchpoint_lr</c>, or null when unknown for this firmware.</summary>
    public long? DecryptMultipleSelfBlocksWatchpointLr { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_verifyHeader</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrVerifyHeader { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_loadSelfSegment</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrLoadSelfSegment { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_decryptSelfBlock</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrDecryptSelfBlock { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_decryptMultipleSelfBlocks</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrDecryptMultipleSelfBlocks { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_sceSblAuthMgrSmFinalize</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrSceSblAuthMgrSmFinalize { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_verifySuperBlock</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrVerifySuperBlock { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_sceSblPfsClearKey_1</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrSceSblPfsClearKey1 { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_sceSblPfsClearKey_2</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrSceSblPfsClearKey2 { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_npdrm_cmd_5</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrNpdrmCmd5 { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_npdrm_cmd_6</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrNpdrmCmd6 { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblPfsSetKeys</c>, or null when unknown for this firmware.</summary>
    public long? SceSblPfsSetKeys { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceCryptAsync</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceCryptAsync { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceCryptAsync_deref_singleton</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceCryptAsyncDerefSingleton { get; init; }

    /// <summary>Kdata-relative offset of <c>copyin</c>, or null when unknown for this firmware.</summary>
    public long? Copyin { get; init; }

    /// <summary>Kdata-relative offset of <c>copyout</c>, or null when unknown for this firmware.</summary>
    public long? Copyout { get; init; }

    /// <summary>Kdata-relative offset of <c>crypt_message_resolve</c>, or null when unknown for this firmware.</summary>
    public long? CryptMessageResolve { get; init; }

    /// <summary>Kdata-relative offset of <c>justreturn</c>, or null when unknown for this firmware.</summary>
    public long? Justreturn { get; init; }

    /// <summary>Kdata-relative offset of <c>justreturn_pop</c>, or null when unknown for this firmware.</summary>
    public long? JustreturnPop { get; init; }

    /// <summary>Kdata-relative offset of <c>mini_syscore_header</c>, or null when unknown for this firmware.</summary>
    public long? MiniSyscoreHeader { get; init; }

    /// <summary>Kdata-relative offset of <c>pop_all_iret</c>, or null when unknown for this firmware.</summary>
    public long? PopAllIret { get; init; }

    /// <summary>Kdata-relative offset of <c>pop_all_except_rdi_iret</c>, or null when unknown for this firmware.</summary>
    public long? PopAllExceptRdiIret { get; init; }

    /// <summary>Kdata-relative offset of <c>push_pop_all_iret</c>, or null when unknown for this firmware.</summary>
    public long? PushPopAllIret { get; init; }

    /// <summary>Kdata-relative offset of <c>kernel_pmap_store</c>, or null when unknown for this firmware.</summary>
    public long? KernelPmapStore { get; init; }

    /// <summary>Kdata-relative offset of <c>crypt_singleton_array</c>, or null when unknown for this firmware.</summary>
    public long? CryptSingletonArray { get; init; }

    /// <summary>Kdata-relative offset of <c>mov_rax_cr0</c>, or null when unknown for this firmware.</summary>
    public long? MovRaxCr0 { get; init; }

    /// <summary>Kdata-relative offset of <c>cr0_load</c>, or null when unknown for this firmware.</summary>
    public long? Cr0Load { get; init; }

    /// <summary>Kdata-relative offset of <c>cr0_clear_store</c>, or null when unknown for this firmware.</summary>
    public long? Cr0ClearStore { get; init; }

    /// <summary>Kdata-relative offset of <c>cr0_write_ret</c>, or null when unknown for this firmware.</summary>
    public long? Cr0WriteRet { get; init; }

    /// <summary>Kdata-relative offset of <c>store_rax_rdi</c>, or null when unknown for this firmware.</summary>
    public long? StoreRaxRdi { get; init; }

    /// <summary>Kdata-relative offset of <c>syscall_cfi_table_jmp_int3</c>, or null when unknown for this firmware.</summary>
    public long? SyscallCfiTableJmpInt3 { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_get_xts_index</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsGetXtsIndex { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_get_cmac_index</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsGetCmacIndex { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_get_xts_return</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsGetXtsReturn { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_get_cmac_return</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsGetCmacReturn { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_cleanup_keys</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsCleanupKeys { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_clear_key_missing</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsClearKeyMissing { get; init; }

    /// <summary>Kdata-relative offset of <c>sceSblServiceMailbox_lr_verifyImage</c>, or null when unknown for this firmware.</summary>
    public long? SceSblServiceMailboxLrVerifyImage { get; init; }

    /// <summary>Kdata-relative offset of <c>ppr_pfs_verify_image_no_key_success</c>, or null when unknown for this firmware.</summary>
    public long? PprPfsVerifyImageNoKeySuccess { get; init; }

    /// <summary>Kdata-relative offset of <c>p_sysent</c>, or null when unknown for this firmware.</summary>
    public long? PSysent { get; init; }

}
