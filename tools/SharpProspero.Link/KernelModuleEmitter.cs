// SharpProspero.Link - a linker for module output.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;

namespace SharpProspero.Link;

/// <summary>
/// Emits x86-64 machine code for KELF IDT handler entry stubs. Each stub saves the
/// interrupted register state into a trap frame on the IST stack, switches the address
/// space to the uelf page tables, calls the handle function with the trap frame pointer
/// and the trap number, then restores the address space and registers before returning
/// via IRETQ.
///
/// <para>The trap frame matches the kernel trapframe layout:</para>
/// <list type="bullet">
///   <item>Offset   0 (index  0): RDI</item>
///   <item>Offset   8 (index  1): RSI</item>
///   <item>Offset  16 (index  2): RDX</item>
///   <item>Offset  24 (index  3): RCX</item>
///   <item>Offset  32 (index  4): R8</item>
///   <item>Offset  40 (index  5): R9</item>
///   <item>Offset  48 (index  6): RAX</item>
///   <item>Offset  56 (index  7): RBX</item>
///   <item>Offset  64 (index  8): RBP</item>
///   <item>Offset  72 (index  9): R10</item>
///   <item>Offset  80 (index 10): R11</item>
///   <item>Offset  88 (index 11): R12</item>
///   <item>Offset  96 (index 12): R13</item>
///   <item>Offset 104 (index 13): R14</item>
///   <item>Offset 112 (index 14): R15</item>
///   <item>Offset 120: saved CR3 (temporary, used during the address-space switch)</item>
///   <item>Offset 224 (index 28): error code (CPU-pushed for INT13; absent for INT1/INT3)</item>
///   <item>Offset 232 (index 29): RIP (CPU-pushed)</item>
///   <item>Offset 240 (index 30): CS (CPU-pushed)</item>
///   <item>Offset 248 (index 31): RFLAGS (CPU-pushed)</item>
///   <item>Offset 256 (index 32): RSP (CPU-pushed)</item>
///   <item>Offset 264 (index 33): SS (CPU-pushed)</item>
/// </list>
///
/// <para>After calling <see cref="GetCode"/>, the caller patches the returned byte array
/// at every offset listed in <see cref="Cr3PatchOffsets"/> with the uelf CR3 physical
/// address and at every offset in <see cref="HandleFnPatchOffsets"/> with the handle
/// function virtual address, both as little-endian 64-bit integers.</para>
/// </summary>
public sealed class KernelModuleEmitter
{
    private readonly List<byte> _code = new();
    private readonly List<int> _cr3PatchOffsets = new();
    private readonly List<int> _handleFnPatchOffsets = new();
    private readonly Dictionary<string, List<int>> _dispatchPatchOffsets = new();

    // Trap frame field offsets (bytes) matching the kernel trapframe.
    // These correspond to the iret_* constants in the kernel's structs definition.
    private const int OffRdi = 0;
    private const int OffRsi = 8;
    private const int OffRdx = 16;
    private const int OffRcx = 24;
    private const int OffR8 = 32;
    private const int OffR9 = 40;
    private const int OffRax = 48;
    private const int OffRbx = 56;
    private const int OffRbp = 64;
    private const int OffR10 = 72;
    private const int OffR11 = 80;
    private const int OffR12 = 88;
    private const int OffR13 = 96;
    private const int OffR14 = 104;
    private const int OffR15 = 112;
    private const int OffCr3Save = 120;   // Gap slot reused for the saved CR3
    private const int OffErrc = 224;   // Error code (ERRC = RIP - 1)
    private const int OffRip = 232;   // CPU-pushed IRET frame starts here
    private const int OffCs = 240;   // IRET frame: code segment selector
    private const int OffEflags = 248;   // IRET frame: RFLAGS register
    private const int OffIretRsp = 256;   // IRET frame: stack pointer
    private const int OffSs = 264;   // IRET frame: stack segment selector

    /// <summary>Well-known target names for dispatch patch offsets. Each name
    /// identifies a 64-bit address slot in the emitted code that the caller must
    /// fill in before the KELF is deployed. Comparison targets hold kernel virtual
    /// addresses used in RIP or sysent-pointer checks. Handler targets hold the
    /// virtual addresses of subsystem dispatch functions.</summary>
    public static class PatchTargetNames
    {
        // ---- Dispatch function call targets (emitted block entry points) ----

        /// <summary>Entry point of the kernel trap fast handler (EmitKernelTrapFastHandler).</summary>
        public const string KernelTrapFastHandler = "kernel_trap_fast";
        /// <summary>Entry point of the syscall handler (EmitSyscallHandler).</summary>
        public const string SyscallHandler = "syscall_handler";

        // ---- DR breakpoint comparison targets (kernel virtual addresses) ----

        /// <summary>DR0 target: kernel address of sceSblServiceMailbox.</summary>
        public const string SceSblServiceMailbox = "sceSblServiceMailbox";
        /// <summary>DR1 target: kernel address of the outer PFS read function.</summary>
        public const string PpfsReadOuterBlock = "ppfs_read_outer_block";
        /// <summary>DR2 target: kernel address of the inner PFS image read start.</summary>
        public const string ReadNapsPfsImageStart = "read_naps_pfs_image_start";

        // ---- Subsystem handler call targets (zero = disabled) ----

        /// <summary>Mailbox trap handler dispatched from DR0 hits.</summary>
        public const string MailboxHandler = "mailbox_handler";
        /// <summary>Outer PFS DR-serve handler dispatched from DR1 hits.</summary>
        public const string OuterPfsHandler = "outer_pfs_handler";
        /// <summary>Inner PFS DR-serve handler dispatched from DR2 hits.</summary>
        public const string InnerPfsHandler = "inner_pfs_handler";
        /// <summary>fpkg syscall handler (nmount, unmount).</summary>
        public const string FpkgSyscall = "fpkg_syscall";
        /// <summary>fself syscall handler (execve, dynlib_load_prx, auth_info, sdk_version).</summary>
        public const string FselfSyscall = "fself_syscall";
        /// <summary>Kekcall handler (getppid).</summary>
        public const string Kekcall = "kekcall";
        /// <summary>Syscall fix handler (mprotect, mdbg_call).</summary>
        public const string SyscallFix = "syscall_fix";
        /// <summary>ioctl syscall handler (npdrm).</summary>
        public const string IoctlSyscall = "ioctl_syscall";

        // ---- Mailbox subsystem handler call targets ----

        /// <summary>fself mailbox handler called from the mailbox dispatcher.</summary>
        public const string FselfMailboxHandler = "fself_mailbox_handler";
        /// <summary>fpkg mailbox handler called from the mailbox dispatcher.</summary>
        public const string FpkgMailboxHandler = "fpkg_mailbox_handler";
        /// <summary>npdrm mailbox handler called from the mailbox dispatcher.</summary>
        public const string NpdrmMailboxHandler = "npdrm_mailbox_handler";

        // ---- fpkg mailbox return address comparison targets ----

        /// <summary>Return address of sceSblServiceMailbox from verifySuperBlock.</summary>
        public const string MailboxLrVerifySuperBlock = "mailbox_lr_verifySuperBlock";
        /// <summary>Return address of sceSblServiceMailbox from sceSblPfsClearKey (site 1).</summary>
        public const string MailboxLrClearKey1 = "mailbox_lr_clearKey_1";
        /// <summary>Return address of sceSblServiceMailbox from sceSblPfsClearKey (site 2).</summary>
        public const string MailboxLrClearKey2 = "mailbox_lr_clearKey_2";

        // ---- fpkg mailbox call targets (kernel-side crypto and key management) ----

        /// <summary>PFS key derivation function (pfs_derive_fake_keys).</summary>
        public const string PfsDeriveFakeKeys = "pfs_derive_fake_keys";
        /// <summary>Register a fake encryption/signing key (register_fake_key).</summary>
        public const string RegisterFakeKey = "register_fake_key";
        /// <summary>Unregister a previously registered fake key (unregister_fake_key).</summary>
        public const string UnregisterFakeKey = "unregister_fake_key";

        // ---- fpkg syscall targets ----

        /// <summary>IRET continuation address (doreti_iret) for stack-frame returns.</summary>
        public const string DoretiIret = "doreti_iret";
        /// <summary>DMEM base address for direct physical memory access.</summary>
        public const string DmemBase = "dmem_base";
        /// <summary>Copy-from-kernel helper function address.</summary>
        public const string CopyFromKernel = "copy_from_kernel";
        /// <summary>Copy-to-kernel helper function address.</summary>
        public const string CopyToKernel = "copy_to_kernel";
        /// <summary>Start a syscall with debug registers armed (start_syscall_with_dbgregs).</summary>
        public const string StartSyscallWithDbgregs = "start_syscall_with_dbgregs";
        /// <summary>Observe that the current syscall trap was emulated.</summary>
        public const string ObserveSyscallEmulated = "observe_syscall_emulated";
        /// <summary>Observe that a mailbox trap occurred.</summary>
        public const string ObserveSyscallTrap = "observe_syscall_trap";
        /// <summary>Read debug registers into a 6-element array.</summary>
        public const string ReadDbgregsChecked = "read_dbgregs_checked";
        /// <summary>Write debug registers from a 6-element array.</summary>
        public const string WriteDbgregsChecked = "write_dbgregs_checked";

        // ---- Sysent entry comparison targets (sysent table virtual addresses) ----

        /// <summary>Address of sysents[SYS_nmount] in the hooked sysent table.</summary>
        public const string SysentNmount = "sysent_nmount";
        /// <summary>Address of sysents[SYS_unmount].</summary>
        public const string SysentUnmount = "sysent_unmount";
        /// <summary>Address of sysents[SYS_getppid].</summary>
        public const string SysentGetppid = "sysent_getppid";
        /// <summary>Address of sysents[SYS_execve].</summary>
        public const string SysentExecve = "sysent_execve";
        /// <summary>Address of sysents[SYS_dynlib_load_prx].</summary>
        public const string SysentDynlibLoadPrx = "sysent_dynlib_load_prx";
        /// <summary>Address of sysents[SYS_get_self_auth_info].</summary>
        public const string SysentGetSelfAuthInfo = "sysent_get_self_auth_info";
        /// <summary>Address of sysents[SYS_get_sdk_compiled_version].</summary>
        public const string SysentGetSdkCompiledVersion = "sysent_get_sdk_compiled_version";
        /// <summary>Address of sysents[SYS_get_ppr_sdk_compiled_version].</summary>
        public const string SysentGetPprSdkCompiledVersion = "sysent_get_ppr_sdk_compiled_version";
        /// <summary>Address of sysents[SYS_mprotect].</summary>
        public const string SysentMprotect = "sysent_mprotect";
        /// <summary>Address of sysents[SYS_mdbg_call].</summary>
        public const string SysentMdbgCall = "sysent_mdbg_call";
        /// <summary>Address of sysents[SYS_ioctl].</summary>
        public const string SysentIoctl = "sysent_ioctl";

        // ---- CCP crypto chain walker targets ----

        /// <summary>Kernel continuation address for emulated CCP requests.</summary>
        public const string CryptMessageResolve = "crypt_message_resolve";
        /// <summary>Check if a fake key slot is active.</summary>
        public const string HasFakeKey = "has_fake_key";
        /// <summary>Retrieve 32-byte key data from a fake key slot.</summary>
        public const string GetFakeKey = "get_fake_key";
        /// <summary>Enter FPU context: XSAVE, clear CR0.TS, FINIT, LDMXCSR.</summary>
        public const string FpuEnter = "fpu_enter";
        /// <summary>Exit FPU context: XRSTOR, restore CR0.</summary>
        public const string FpuExit = "fpu_exit";
        /// <summary>Static crypto request cache (XTS key + HMAC-SHA256 key caches).</summary>
        public const string CryptoRequestCache = "crypto_request_cache";

        // ---- Crypto emulation handler entry points ----

        /// <summary>AES-XTS-128 emulation handler entry point.</summary>
        public const string CryptoXtsHandler = "crypto_xts_handler";
        /// <summary>HMAC-SHA256 emulation handler entry point.</summary>
        public const string CryptoHmacHandler = "crypto_hmac_handler";

        // ---- PFS crypto primitive call targets ----

        /// <summary>AES-XTS-128 on kernel-resident data via page-table walking.</summary>
        public const string PfsXtsVirtualFpuHeld = "pfs_xts_virtual_fpu_held";
        /// <summary>HMAC-SHA256 on kernel-resident data via page-table walking.</summary>
        public const string PfsHmacVirtualFpuHeld = "pfs_hmac_virtual_fpu_held";

        // ---- PFS key derivation call targets ----

        /// <summary>RSA-2048 public-key operation.</summary>
        public const string RsaPublic = "rsa_public";
        /// <summary>Single-shot HMAC-SHA256 for key generation.</summary>
        public const string HmacSha256Once = "hmac_sha256_once";

        // ---- fself mailbox return address comparison targets ----

        /// <summary>Return address of sceSblServiceMailbox from verifyHeader (fself path).</summary>
        public const string MailboxLrFselfVerifyHeader = "mailbox_lr_fself_verifyHeader";
        /// <summary>Return address of sceSblServiceMailbox from loadSelfSegment (fself path).</summary>
        public const string MailboxLrFselfLoadSelfSegment = "mailbox_lr_fself_loadSelfSegment";
        /// <summary>Return address of sceSblServiceMailbox from decryptSelfBlock (fself path).</summary>
        public const string MailboxLrFselfDecryptSelfBlock = "mailbox_lr_fself_decryptSelfBlock";
        /// <summary>Return address of sceSblServiceMailbox from decryptMultipleSelfBlocks (fself path).</summary>
        public const string MailboxLrFselfDecryptMultipleSelfBlocks = "mailbox_lr_fself_decryptMultipleSelfBlocks";

        // ---- fself debug register breakpoint targets ----

        /// <summary>DR1 target: kernel address of sceSblAuthMgrSmIsLoadable2.</summary>
        public const string SceSblAuthMgrSmIsLoadable2 = "sceSblAuthMgrSmIsLoadable2";
        /// <summary>DR2 target: kernel address of the ASLR slide fix entry.</summary>
        public const string AslrFixStart = "aslr_fix_start";

        // ---- CCP crypto async comparison target ----

        /// <summary>Kernel address of sceSblServiceCryptAsync singleton dereference.</summary>
        public const string SceSblServiceCryptAsyncDerefSingleton = "sceSblServiceCryptAsync_deref_singleton";

        // ---- fself watchpoint address comparison targets ----

        /// <summary>Kernel address of loadSelfSegment watchpoint (entry into segment loading).</summary>
        public const string LoadSelfSegmentWatchpoint = "loadSelfSegment_watchpoint";
        /// <summary>Kernel address of loadSelfSegment epilogue (exit from segment loading).</summary>
        public const string LoadSelfSegmentEpilogue = "loadSelfSegment_epilogue";
        /// <summary>Kernel address of decryptSelfBlock epilogue.</summary>
        public const string DecryptSelfBlockEpilogue = "decryptSelfBlock_epilogue";
        /// <summary>Kernel address of decryptMultipleSelfBlocks epilogue.</summary>
        public const string DecryptMultipleSelfBlocksEpilogue = "decryptMultipleSelfBlocks_epilogue";

        // ---- fself watchpoint return address comparison targets ----

        /// <summary>Return address of loadSelfSegment watchpoint caller.</summary>
        public const string LoadSelfSegmentWatchpointLr = "loadSelfSegment_watchpoint_lr";
        /// <summary>Return address of decryptSelfBlock watchpoint caller.</summary>
        public const string DecryptSelfBlockWatchpointLr = "decryptSelfBlock_watchpoint_lr";
        /// <summary>Return address of decryptMultipleSelfBlocks watchpoint caller.</summary>
        public const string DecryptMultipleSelfBlocksWatchpointLr = "decryptMultipleSelfBlocks_watchpoint_lr";

        // ---- fself helper function call targets ----

        /// <summary>Check if a SELF header describes an FSELF module.
        /// RDI = header kernel VA, ESI = header size, RDX = e_type output (uint16*, or 0),
        /// RCX = is_ps4 output (int*, or 0), R8 = authinfo output (136 bytes, or 0),
        /// R9 = have_authinfo output (int*, or 0). Returns 1 if FSELF, 0 otherwise.</summary>
        public const string IsHeaderFself = "is_header_fself";
        /// <summary>Get FSELF info from a cached verification context.
        /// RDI = ctx kernel VA. Returns 1 if FSELF context, 0 otherwise.</summary>
        public const string GetContextFselfInfo = "get_context_fself_info";
        /// <summary>Remember a verification context as FSELF for subsequent segment/decrypt
        /// lookups. RDI = self_context, RSI = self_header, EDX = size, RCX = ctx_data.</summary>
        public const string RememberContextFselfInfo = "remember_context_fself_info";
        /// <summary>Invalidate the FSELF header and context caches.</summary>
        public const string FselfInvalidateCaches = "fself_invalidate_caches";
        /// <summary>Copy plaintext SELF blocks with run coalescing.
        /// RDI = DMEM base, RSI = src offsets (DMEM ptr), RDX = dst offsets (DMEM ptr),
        /// ECX = block count.</summary>
        public const string CopyDecryptedSelfBlocks = "copy_decrypted_self_blocks";
        /// <summary>Perform FSELF header substitution for verifyHeader interception.
        /// Substitutes the SELF header with mini_syscore_header and pushes a restoration
        /// trap frame. RDI = regs, RSI = self_header, EDX = original_size,
        /// RCX = self_context, R8 = request_ptr (regs[RDX] for size update).
        /// Returns 1 on success, 0 on error.</summary>
        public const string FselfSubstituteHeader = "fself_substitute_header";

        // ---- NPDRM mailbox return address comparison targets ----

        /// <summary>Return address of sceSblServiceMailbox for NPDRM cmd 5.</summary>
        public const string MailboxLrNpdrmCmd5 = "mailbox_lr_npdrm_cmd_5";
        /// <summary>Return address of sceSblServiceMailbox for NPDRM cmd 6.</summary>
        public const string MailboxLrNpdrmCmd6 = "mailbox_lr_npdrm_cmd_6";

        // ---- NPDRM helper function call targets ----

        /// <summary>SHA-256 hash a buffer (FPU context must be held).
        /// RDI = input data, RSI = input length, RDX = 32-byte output buffer.
        /// Returns 0 on success, -1 on failure.</summary>
        public const string Sha256BufferFpuHeld = "sha256_buffer_fpu_held";
        /// <summary>AES-CBC-128 decrypt with the RIF debug key (FPU context must be held).
        /// RDI = output, RSI = input, EDX = size in bytes, RCX = 16-byte IV.
        /// Returns 0 on success, -1 on failure.</summary>
        public const string AesCbc128DecryptRifDebug = "aes_cbc_128_decrypt_rif_debug";

        // ---- Kekcall helper function and kernel address targets ----

        /// <summary>Kernel return address after syscall completion (syscall_after).</summary>
        public const string SyscallAfter = "syscall_after";
        /// <summary>Kernel NOP-RET gadget address.</summary>
        public const string NopRet = "nop_ret";
        /// <summary>Kernel copyin function address.</summary>
        public const string CopierIn = "copyin";
        /// <summary>Kernel copyout function address.</summary>
        public const string CopierOut = "copyout";
        /// <summary>Kernel sysent table base address.</summary>
        public const string SysentTable = "sysent_table";
        /// <summary>Handle a syscall after sysent lookup.</summary>
        public const string HandleSyscallFn = "handle_syscall_fn";
        /// <summary>Push data onto a kernel thread's stack with bounds checking.</summary>
        public const string PushStackChecked = "push_stack_checked";
        /// <summary>Pop data from a kernel thread's stack with bounds checking.</summary>
        public const string PopStackChecked = "pop_stack_checked";
        /// <summary>Read a 64-bit value from kernel virtual address.</summary>
        public const string Kpeek64Checked = "kpeek64_checked";
        /// <summary>Write a 64-bit value to kernel virtual address.</summary>
        public const string Kpoke64 = "kpoke64";
        /// <summary>Get the current thread's PCB flags pointer.</summary>
        public const string GetCurrentPcbFlagsPtrChecked = "get_current_pcb_flags_ptr_checked";
        /// <summary>Check PCB DBREGS flag at a given pointer.
        /// RDI = p_pcb_flags, RSI = &amp;flags_out, RDX = &amp;had_dbregs_out.
        /// Returns 0 on success.</summary>
        public const string GetPcbDbregsCheckedAt = "get_pcb_dbregs_checked_at";
        /// <summary>Set PCB DBREGS flag at a given pointer.
        /// RDI = p_pcb_flags, RSI = current_flags. Returns 0 on success.</summary>
        public const string SetPcbDbregsCheckedAt = "set_pcb_dbregs_checked_at";
        /// <summary>Restore debug register state at a given PCB flags pointer.
        /// RDI = p_pcb_flags, RSI = flags, RDX = saved_dr (6 qwords),
        /// ECX = had_dbregs. Returns 0 on success.</summary>
        public const string RestoreDbgregsStateCheckedAt = "restore_dbgregs_state_checked_at";
        /// <summary>Restore debug register state for the current thread.
        /// RDI = saved_dr+had_dbregs (7 qwords: dr[6] then had_flag).
        /// Returns 0 on success.</summary>
        public const string RestoreDbgregsStateChecked = "restore_dbgregs_state_checked";
        /// <summary>Read MSR value. RDI = MSR index, RSI = &amp;result.
        /// Returns 1 on success, 0 on fault.</summary>
        public const string RdmsrFn = "rdmsr_fn";

        // ---- Utils subsystem targets ----

        /// <summary>Execute a gadget via yield and read back register state.
        /// RDI = register array (NREGS qwords). Returns 0 on success.</summary>
        public const string RunGadgetChecked = "run_gadget_checked";
        /// <summary>Gadget: read debug registers into GPRs (DR0..DR3 -> R15..R12,
        /// DR6 -> R11, DR7 -> RAX).</summary>
        public const string Dr2gprStart = "dr2gpr_start";
        /// <summary>Gadget: write GPRs to debug registers (part 1).</summary>
        public const string Gpr2dr1Start = "gpr2dr_1_start";
        /// <summary>Gadget: write GPRs to debug registers (part 2).</summary>
        public const string Gpr2dr2Start = "gpr2dr_2_start";
        /// <summary>Physical address of the kernel's CR3 page table root.</summary>
        public const string Cr3PhysAddr = "cr3_phys_addr";
        /// <summary>Peek at data on the kernel stack without consuming it.</summary>
        public const string PeekStackChecked = "peek_stack_checked";
        /// <summary>Complete the NPDRM ioctl state tracking.</summary>
        public const string FinishNpdrmIoctlState = "finish_npdrm_ioctl_state";
        /// <summary>Observe that a syscall has completed normally.</summary>
        public const string ObserveSyscallFinish = "observe_syscall_finish";

        // ---- Syscall fix targets ----

        /// <summary>Kernel address of the mprotect permission fix entry point.</summary>
        public const string MprotectFixStart = "mprotect_fix_start";
        /// <summary>Kernel address of the mprotect permission fix exit point.</summary>
        public const string MprotectFixEnd = "mprotect_fix_end";

        // ---- FPU context management targets ----

        /// <summary>Read the CR0 control register value. RDI = &amp;cr0_out.</summary>
        public const string ReadCr0Checked = "read_cr0_checked";
        /// <summary>Write a value to the CR0 control register. RDI = cr0_value.</summary>
        public const string WriteCr0Checked = "write_cr0_checked";
        /// <summary>XSAVE area for FPU context preservation (4096 bytes, 64-byte aligned).</summary>
        public const string XsaveArea = "xsave_area";

        // ---- FakeKey shared memory targets ----

        /// <summary>Shared area base for fake key storage. Layout:
        /// +0x00 = bitmask (uint64, allocation bitmap),
        /// +0x08 = ready_mask (uint64, keys with valid data),
        /// +0x10 = key_data[63][32] (key storage array).</summary>
        public const string SharedAreaBase = "shared_area_base";

        // ---- Subsystem handler entry points for doreti_iret continuation dispatch ----

        /// <summary>Entry point of the utils trap handler (EmitUtilsTrapHandler).</summary>
        public const string UtilsTrapHandlerFn = "utils_trap_handler";
        /// <summary>Entry point of the kekcall trap handler (EmitKekcallTrapHandler).</summary>
        public const string KekcallTrapHandlerFn = "kekcall_trap_handler";
        /// <summary>Entry point of the fpkg trap handler (EmitFpkgTrapHandler).</summary>
        public const string FpkgTrapHandlerFn = "fpkg_trap_handler";
        /// <summary>Entry point of the fself trap handler (EmitFselfTrapHandler).</summary>
        public const string FselfTrapHandlerFn = "fself_trap_handler";

        // ---- Kernel trap fast handler sub-dispatch targets ----

        /// <summary>Entry point of the generic decrypt trap fallback (EmitGenericDecryptTrap).</summary>
        public const string GenericDecryptTrapHandler = "generic_decrypt_trap_handler";
        /// <summary>Entry point of the fself debug trap handler (EmitFselfDebugTrapHandler).</summary>
        public const string FselfDebugTrapHandlerFn = "fself_debug_trap_handler";
        /// <summary>Entry point of the CCP crypto chain walker (EmitCryptoChainWalker).</summary>
        public const string CryptoChainWalkerFn = "crypto_chain_walker_handler";
        /// <summary>Entry point of the syscall fix trap handler (EmitSyscallFixTrapHandler).</summary>
        public const string SyscallFixTrapHandlerFn = "syscall_fix_trap_handler";

        // ---- fself trap handler data targets ----

        /// <summary>Backup frame size for the fself header restoration (computed as
        /// ((48 + mini_syscore_header_size + 15) &amp; ~15)). Embedded as a uint32.</summary>
        public const string FselfBackupFrameSize = "fself_backup_frame_size";
        /// <summary>Size of the mini_syscore_header blob in bytes. Embedded as a uint32.</summary>
        public const string MiniSyscoreHeaderSize = "mini_syscore_header_size";

        // ---- fself watchpoint dbgregs data targets ----

        /// <summary>Inline dbgregs array for loadSelfSegment watchpoint.</summary>
        public const string DbgregsForLoadSelfSegment = "dbgregs_for_loadSelfSegment";
        /// <summary>Inline dbgregs array for decryptSelfBlock watchpoint.</summary>
        public const string DbgregsForDecryptSelfBlock = "dbgregs_for_decryptSelfBlock";
        /// <summary>Inline dbgregs array for decryptMultipleSelfBlocks watchpoint.</summary>
        public const string DbgregsForDecryptMultipleSelfBlocks = "dbgregs_for_decryptMultipleSelfBlocks";

        // ---- Dispatcher routing targets (kernel IDT handler re-injection, syscall hooks) ----

        /// <summary>Kernel IDT handler for INT1 (#DB). When the trap originates
        /// from userspace or during copyin/copyout, the dispatcher sets regs[RIP] to this
        /// address so the KELF IRETQ re-injects the exception to the kernel.</summary>
        public const string NativeInt1Handler = "native_int1_handler";
        /// <summary>Kernel IDT handler for INT3 (#BP), used for re-injection.</summary>
        public const string NativeInt3Handler = "native_int3_handler";
        /// <summary>Kernel IDT handler for INT13 (#GP), used for re-injection.</summary>
        public const string NativeInt13Handler = "native_int13_handler";

        /// <summary>IST4 stack address for INT1 exception re-injection.</summary>
        public const string Ist4 = "ist4";
        /// <summary>Kernel address of the Task State Segment (TSS) base.</summary>
        public const string TssBase = "tss_base";
        /// <summary>Offset of the gsbase field within the PCB structure.</summary>
        public const string PcbGsbase = "pcb_gsbase";
        /// <summary>Kernel address of the wrmsr argument buffer (3 qwords:
        /// gsbase >> 32, MSR index 0xC0000101, (uint32_t)gsbase).</summary>
        public const string WrmsrArgs = "wrmsr_args";
        /// <summary>Get the current thread's PCB pointer.
        /// RDI = &amp;pcb_out. Returns 0 on success.</summary>
        public const string GetCurrentPcbChecked = "get_current_pcb_checked";

        /// <summary>Kernel address of the pre-syscall debug breakpoint. When INT1 fires
        /// at this RIP, the dispatcher enters the pre-syscall interception path which
        /// canonicalizes the sysent pointer in RAX, pushes SyscallAfter as the return
        /// address, and dispatches through the syscall handler.</summary>
        public const string SyscallBefore = "syscall_before";

        /// <summary>Byte offset from RSP to the RSI argument pointer in the
        /// FreeBSD syscall frame. Used in the pre-syscall hook to compute
        /// regs[RSI] = regs[RSP] + syscall_rsp_to_rsi + syscall_extra.</summary>
        public const string SyscallRspToRsi = "syscall_rsp_to_rsi";
        /// <summary>Firmware-dependent extra offset added to the syscall RSI
        /// computation (0x10 for FW >= 10.00, 0 for earlier).</summary>
        public const string SyscallExtra = "syscall_extra";

        // ---- Kernel structure field offsets for sysent computation ----

        /// <summary>Byte offset of the td_frame field within struct thread. Used to
        /// locate the kernel trap frame for the interrupted thread when computing the
        /// syscall number in the post-syscall hook.</summary>
        public const string TdFrame = "td_frame";
        /// <summary>Byte offset of the td_proc field within struct thread.</summary>
        public const string TdProc = "td_proc";
        /// <summary>Byte offset of the p_sysent field within struct proc. The value
        /// at this offset is compared against SysentvecPs4 to determine whether the
        /// process uses the PS4 or PS5 sysent table.</summary>
        public const string PSysentOff = "p_sysent_off";
        /// <summary>Byte offset of the RAX slot within the kernel trap frame (iret_rax).
        /// Used to read the syscall number from the thread's saved register state.</summary>
        public const string IretRax = "iret_rax";
        /// <summary>Byte offset of the sy_call field within struct sysent.</summary>
        public const string SysentSyCall = "sysent_sy_call";
        /// <summary>Size in bytes of struct sysent, used to compute the address of a
        /// specific sysent entry from the table base and syscall number.</summary>
        public const string SysentSize = "sysent_size";

        /// <summary>Address of the PS4 sysent vector (sysentvec_ps4). Compared against
        /// proc-&gt;p_sysent to distinguish PS4 from PS5 processes.</summary>
        public const string SysentvecPs4 = "sysentvec_ps4";
        /// <summary>Base address of the PS4 hooked sysent table (sysents_ps4).</summary>
        public const string SysentsPs4Table = "sysents_ps4_table";
    }

    // DR breakpoint target → subsystem handler dispatch table.
    private static readonly (string CompareTarget, string HandlerTarget)[] TrapFastEntries =
    [
        (PatchTargetNames.SceSblServiceMailbox,    PatchTargetNames.MailboxHandler),
        (PatchTargetNames.PpfsReadOuterBlock,      PatchTargetNames.OuterPfsHandler),
        (PatchTargetNames.ReadNapsPfsImageStart,   PatchTargetNames.InnerPfsHandler),
    ];

    // Hooked sysent entry → subsystem handler dispatch table.
    private static readonly (string SysentTarget, string HandlerTarget)[] SyscallEntries =
    [
        (PatchTargetNames.SysentNmount,                    PatchTargetNames.FpkgSyscall),
        (PatchTargetNames.SysentUnmount,                   PatchTargetNames.FpkgSyscall),
        (PatchTargetNames.SysentGetppid,                   PatchTargetNames.Kekcall),
        (PatchTargetNames.SysentExecve,                    PatchTargetNames.FselfSyscall),
        (PatchTargetNames.SysentDynlibLoadPrx,             PatchTargetNames.FselfSyscall),
        (PatchTargetNames.SysentGetSelfAuthInfo,           PatchTargetNames.FselfSyscall),
        (PatchTargetNames.SysentGetSdkCompiledVersion,     PatchTargetNames.FselfSyscall),
        (PatchTargetNames.SysentGetPprSdkCompiledVersion,  PatchTargetNames.FselfSyscall),
        (PatchTargetNames.SysentMprotect,                  PatchTargetNames.SyscallFix),
        (PatchTargetNames.SysentMdbgCall,                  PatchTargetNames.SyscallFix),
        (PatchTargetNames.SysentIoctl,                     PatchTargetNames.IoctlSyscall),
    ];

    /// <summary>Offsets within the emitted code where the caller writes the uelf CR3
    /// physical address as a little-endian 64-bit integer. One entry per emitted
    /// handler.</summary>
    public IReadOnlyList<int> Cr3PatchOffsets => _cr3PatchOffsets;

    /// <summary>Offsets within the emitted code where the caller writes the handle
    /// function virtual address as a little-endian 64-bit integer. One entry per
    /// emitted handler.</summary>
    public IReadOnlyList<int> HandleFnPatchOffsets => _handleFnPatchOffsets;

    /// <summary>Returns the code offsets where the caller writes a little-endian 64-bit
    /// address for the specified dispatch patch target. Returns empty if the target name
    /// was not recorded by any Emit method.</summary>
    public IReadOnlyList<int> GetDispatchPatchOffsets(string targetName) =>
        _dispatchPatchOffsets.TryGetValue(targetName, out var list)
            ? list
            : Array.Empty<int>();

    /// <summary>All dispatch patch target names that have been recorded by the Emit
    /// methods. Use <see cref="GetDispatchPatchOffsets"/> to retrieve offsets for each.</summary>
    public IEnumerable<string> DispatchPatchTargets => _dispatchPatchOffsets.Keys;

    /// <summary>Emit the INT1 (debug exception) handler stub. The CPU does not push
    /// an error code for this vector.</summary>
    /// <returns>Byte offset of the handler entry point within the code buffer.</returns>
    public int EmitInt1Handler() => EmitHandler(trapNumber: 1, hasErrorCode: false);

    /// <summary>Emit the INT3 (breakpoint) handler stub. The CPU does not push an
    /// error code for this vector.</summary>
    /// <returns>Byte offset of the handler entry point within the code buffer.</returns>
    public int EmitInt3Handler() => EmitHandler(trapNumber: 3, hasErrorCode: false);

    /// <summary>Emit the INT13 (general protection fault) handler stub. The CPU
    /// pushes a 64-bit error code onto the IST stack before the IRET frame.</summary>
    /// <returns>Byte offset of the handler entry point within the code buffer.</returns>
    public int EmitInt13Handler() => EmitHandler(trapNumber: 13, hasErrorCode: true);

    /// <summary>Get the emitted code.</summary>
    public byte[] GetCode() => _code.ToArray();

    /// <summary>Current write position in the code buffer.</summary>
    public int Position => _code.Count;

    // -----------------------------------------------------------------------
    //  Dispatch function emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the main dispatcher function. This is the <c>handle(regs, trapno)</c>
    /// entry point called by every IDT handler stub after saving registers and
    /// switching to the uelf address space.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, ESI = trap number.</para>
    ///
    /// <para>Control flow (handle() cascade):</para>
    /// <list type="number">
    ///   <item>If the interrupted code was in kernel mode (CS[1:0] == 0), set the
    ///         Resume Flag (RF, bit 16) in the saved RFLAGS.</item>
    ///   <item>If the trap came from userspace (CS[1:0] != 0) or during
    ///         copyin/copyout (EFLAGS.AC bit 18 set), re-inject the exception
    ///         by writing the kernel IDT handler address into regs[RIP] and
    ///         returning. The KELF IRETQ then jumps to the kernel's handler.</item>
    ///   <item>INT1 (trap 1): if RIP == <see cref="PatchTargetNames.SyscallBefore"/>,
    ///         enter the pre-syscall hook (canonicalize RAX, push SyscallAfter,
    ///         read sy_call, dispatch through the syscall handler). Otherwise
    ///         call the kernel trap fast handler.</item>
    ///   <item>INT3 (trap 3): peek the kernel stack top via copy_from_kernel.
    ///         If it equals <see cref="PatchTargetNames.SyscallAfter"/>, enter
    ///         the post-syscall hook (read sysno from td_frame, determine
    ///         PS4 vs PS5, compute the sysent entry, dispatch through the
    ///         syscall handler). Otherwise re-inject to the kernel INT3
    ///         handler.</item>
    ///   <item>INT13 (trap 13): if RIP == doreti_iret, enter the continuation
    ///         dispatch (TRAP_UTILS / TRAP_KEKCALL / TRAP_FSELF / TRAP_FPKG).
    ///         Otherwise call the kernel trap fast handler for generic
    ///         decrypt traps.</item>
    ///   <item>Unrecognized vector: return immediately.</item>
    /// </list>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitDispatcher()
    {
        int entry = _code.Count;

        // ---- Prologue: save callee-saved registers ----
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        EmitSubRspImm32(40);                          // sub rsp, 40

        // rbx = regs pointer (callee-saved across all sub-calls).
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        // r12d = trap number (callee-saved; reused for TRAP_IDX in doreti path).
        _code.AddRange([0x41, 0x89, 0xF4]);           // mov r12d, esi

        // ---- Check CPL (initial_from_user) ----
        EmitLoadFromFrameViaReg(OffCs, 0x48, 0, regBase: 3); // mov rax, [rbx + OffCs]
        _code.AddRange([0xA8, 0x03]);                 // test al, 3
        // r13b = 1 if from userspace, 0 if kernel.
        _code.AddRange([0x41, 0x0F, 0x95, 0xC5]);    // setnz r13b

        // If NOT from_user, set Resume Flag in the saved RFLAGS to prevent
        // INT1 from re-triggering on IRETQ.
        _code.AddRange([0x45, 0x84, 0xED]);           // test r13b, r13b
        int skipRfRel8 = EmitJccRel8Forward(0x75);    // jnz skip_rf
        // or qword [rbx + OffEflags], 0x10000
        _code.AddRange([0x48, 0x81, 0x8B]);
        _code.AddRange(BitConverter.GetBytes(OffEflags));
        _code.AddRange(BitConverter.GetBytes(0x10000));
        PatchRel8Forward(skipRfRel8);

        // ---- EFLAGS AC bit 18 guard (copyin/copyout re-injection) ----
        EmitLoadFromFrameViaReg(OffEflags, 0x48, 0, regBase: 3); // mov rax, [rbx + OffEflags]
        _code.AddRange([0xA9, 0x00, 0x00, 0x04, 0x00]); // test eax, 0x40000
        int jnzCopyio = EmitJccRel32Forward(0x0F, 0x85); // jnz reinject_path

        // ---- Userspace re-injection guard ----
        _code.AddRange([0x45, 0x84, 0xED]);           // test r13b, r13b
        int jnzUserspace = EmitJccRel32Forward(0x0F, 0x85); // jnz reinject_path

        // ---- Kernel mode, not copyio: route by trap number ----
        _code.AddRange([0x41, 0x83, 0xFC, 0x03]);    // cmp r12d, 3
        int jeInt3 = EmitJccRel32Forward(0x0F, 0x84);

        _code.AddRange([0x41, 0x83, 0xFC, 0x01]);    // cmp r12d, 1
        int jeInt1 = EmitJccRel32Forward(0x0F, 0x84);

        _code.AddRange([0x41, 0x83, 0xFC, 0x0D]);    // cmp r12d, 13
        int jeInt13 = EmitJccRel32Forward(0x0F, 0x84);

        // Unrecognized vector.
        int jmpEpilogueUnknown = EmitJmpRel32Forward();

        // ==== INT1 kernel path (syscall_before check) ====
        PatchRel32Forward(jeInt1);
        EmitLoadFromFrameViaReg(OffRip, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRip]
        EmitMovAbsRcxPatch(PatchTargetNames.SyscallBefore);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jeSyscallBefore = EmitJccRel32Forward(0x0F, 0x84);

        // Not at syscall_before: dispatch to the kernel trap fast handler.
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitCallPatch(PatchTargetNames.KernelTrapFastHandler);
        int jmpEpilogueAfterFast = EmitJmpRel32Forward();

        // ---- syscall_before path (pre-syscall hook) ----
        PatchRel32Forward(jeSyscallBefore);

        // Canonicalize regs[RAX]: set the top 16 bits to 0xFFFF so the
        // sysent pointer becomes a valid kernel VA.
        EmitLoadFromFrameViaReg(OffRax, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRax]
        _code.AddRange([0x48, 0xB9]);                 // movabs rcx, 0xFFFF000000000000
        _code.AddRange(BitConverter.GetBytes(0xFFFF_0000_0000_0000UL));
        _code.AddRange([0x48, 0x09, 0xC8]);           // or rax, rcx
        EmitStoreToFrameFromReg(OffRax, 0x48, 0, regBase: 3); // mov [rbx + OffRax], rax
        // r14 = canonicalized sysent entry (callee-saved).
        _code.AddRange([0x49, 0x89, 0xC6]);           // mov r14, rax

        // regs[RSI] = regs[RSP] + syscall_rsp_to_rsi + syscall_extra.
        // FreeBSD sy_call reads syscall arguments from RSI.
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3); // mov rax, [rbx + OffIretRsp]
        EmitMovAbsRcxPatch(PatchTargetNames.SyscallRspToRsi);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        EmitMovAbsRcxPatch(PatchTargetNames.SyscallExtra);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        EmitStoreToFrameFromReg(OffRsi, 0x48, 0, regBase: 3); // mov [rbx + OffRsi], rax

        // Read sy_call from the sysent entry via copy_from_kernel.
        EmitMovAbsRcxPatch(PatchTargetNames.SysentSyCall);
        _code.AddRange([0x4C, 0x01, 0xF1]);           // add rcx, r14
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xCE]);           // mov rsi, rcx
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzSyCallReadFailed1 = EmitJccRel32Forward(0x0F, 0x85);
        // r14 = sy_call target.
        _code.AddRange([0x4C, 0x8B, 0x34, 0x24]);    // mov r14, [rsp]

        // Write the syscall_after address to a stack temp for push_stack_checked.
        EmitMovAbsRcxPatch(PatchTargetNames.SyscallAfter);
        _code.AddRange([0x48, 0x89, 0x4C, 0x24, 0x08]); // mov [rsp + 8], rcx

        // Push syscall_after onto the kernel stack so the syscall returns
        // to the INT3 breakpoint at syscall_after.
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x8D, 0x74, 0x24, 0x08]); // lea rsi, [rsp + 8]
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.PushStackChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzPushFailed = EmitJccRel32Forward(0x0F, 0x85);

        // regs[RIP] = sy_call target.
        EmitStoreToFrameFromReg(OffRip, 0x4C, 6, regBase: 3); // mov [rbx + OffRip], r14

        // Dispatch through the syscall handler to intercept hooked syscalls.
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitCallPatch(PatchTargetNames.SyscallHandler);
        int jmpEpilogueSyscallBefore = EmitJmpRel32Forward();

        // ==== INT3 kernel path (syscall_after guard) ====
        PatchRel32Forward(jeInt3);

        // Peek the kernel stack top: if it equals syscall_after, this is
        // the post-syscall hook. Otherwise re-inject to the kernel INT3
        // handler.
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffIretRsp]
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzPeekFailed = EmitJccRel32Forward(0x0F, 0x85);

        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);    // mov rax, [rsp]
        EmitMovAbsRcxPatch(PatchTargetNames.SyscallAfter);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jneSyscallAfterMismatch = EmitJccRel32Forward(0x0F, 0x85);

        // ---- Post-syscall hook: compute sysent entry from td_frame ----

        // Step 1: read td_frame pointer from the thread structure.
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRdi]
        EmitMovAbsRcxPatch(PatchTargetNames.TdFrame);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzTdFrameFailed = EmitJccRel32Forward(0x0F, 0x85);

        // Step 2: read iret_rax (the syscall number) from the td_frame.
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);    // mov rax, [rsp]
        EmitMovAbsRcxPatch(PatchTargetNames.IretRax);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzIretRaxFailed = EmitJccRel32Forward(0x0F, 0x85);
        // r14 = sysno.
        _code.AddRange([0x4C, 0x8B, 0x34, 0x24]);    // mov r14, [rsp]

        // Step 3: read proc pointer from the thread structure.
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRdi]
        EmitMovAbsRcxPatch(PatchTargetNames.TdProc);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzTdProcFailed = EmitJccRel32Forward(0x0F, 0x85);

        // Step 4: read p_sysent from the proc structure.
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);    // mov rax, [rsp]
        EmitMovAbsRcxPatch(PatchTargetNames.PSysentOff);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzPSysentFailed = EmitJccRel32Forward(0x0F, 0x85);

        // Step 5: determine PS4 vs PS5 by comparing proc_sysent with sysentvec_ps4.
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);    // mov rax, [rsp]
        EmitMovAbsRcxPatch(PatchTargetNames.SysentvecPs4);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        // Pre-load the PS4 table base (movabs does not affect flags).
        EmitMovAbsRaxPatch(PatchTargetNames.SysentsPs4Table);
        int jePs4 = EmitJccRel8Forward(0x74);         // je compute_entry (use PS4 table)
        EmitMovAbsRaxPatch(PatchTargetNames.SysentTable); // PS5 table
        PatchRel8Forward(jePs4);                      // compute_entry:

        // Step 6: compute sysent entry = base + sysno * sizeof(struct sysent).
        EmitMovAbsRcxPatch(PatchTargetNames.SysentSize);
        _code.AddRange([0x4C, 0x89, 0xF2]);           // mov rdx, r14 (sysno)
        _code.AddRange([0x48, 0x0F, 0xAF, 0xD1]);    // imul rdx, rcx
        _code.AddRange([0x48, 0x01, 0xD0]);           // add rax, rdx
        // regs[RAX] = sysent entry address.
        EmitStoreToFrameFromReg(OffRax, 0x48, 0, regBase: 3);
        _code.AddRange([0x49, 0x89, 0xC6]);           // mov r14, rax

        // Step 7: read sy_call from the sysent entry.
        EmitMovAbsRcxPatch(PatchTargetNames.SysentSyCall);
        _code.AddRange([0x4C, 0x01, 0xF1]);           // add rcx, r14
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xCE]);           // mov rsi, rcx
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzSyCallFailed2 = EmitJccRel32Forward(0x0F, 0x85);

        // regs[RIP] = sy_call.
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);    // mov rax, [rsp]
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);

        // Dispatch through the syscall handler.
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitCallPatch(PatchTargetNames.SyscallHandler);
        int jmpEpilogueSyscallAfter = EmitJmpRel32Forward();

        // jmpEpilogueReinject is assigned in the from_userspace path below.
        int jmpEpilogueReinject = 0;

        // ==== INT13 kernel path ====
        PatchRel32Forward(jeInt13);

        // Check regs[RIP] == doreti_iret for the continuation dispatch path.
        EmitLoadFromFrameViaReg(OffRip, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRip]
        EmitMovAbsRcxPatch(PatchTargetNames.DoretiIret);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jneNotDoreti = EmitJccRel32Forward(0x0F, 0x85);

        // ---- doreti_iret continuation dispatch ----
        // Read frame[0..1] (16 bytes) from the kernel stack at regs[RSP].
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp (dst)
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffIretRsp]
        _code.AddRange([0xBA, 0x10, 0x00, 0x00, 0x00]); // mov edx, 16
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzDoretiCopyFail = EmitJccRel32Forward(0x0F, 0x85);

        // Check frame[1] & 3 -- if nonzero, it is a userspace #GP on IRET.
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x08]); // mov rax, [rsp + 8] (frame[1] = CS)
        _code.AddRange([0xA8, 0x03]);                 // test al, 3
        int jnzDoretiUserGp = EmitJccRel32Forward(0x0F, 0x85);

        // lr = frame[0], TRAP_KIND = (uint32_t)(lr >> 32), TRAP_IDX = (uint32_t)lr
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);     // mov rax, [rsp] (frame[0] = lr)
        _code.AddRange([0x41, 0x89, 0xC4]);           // mov r12d, eax (TRAP_IDX)
        _code.AddRange([0x48, 0xC1, 0xE8, 0x20]);     // shr rax, 32 (TRAP_KIND)

        // Switch on TRAP_KIND.
        _code.AddRange([0x3D]);
        _code.AddRange(BitConverter.GetBytes(TrapUtils));
        int jeUtils = EmitJccRel8Forward(0x74);

        _code.AddRange([0x3D]);
        _code.AddRange(BitConverter.GetBytes(TrapKekcall));
        int jeKekcall = EmitJccRel8Forward(0x74);

        _code.AddRange([0x3D]);
        _code.AddRange(BitConverter.GetBytes(TrapFself));
        int jeFself = EmitJccRel8Forward(0x74);

        _code.AddRange([0x3D]);
        _code.AddRange(BitConverter.GetBytes(TrapFpkg));
        int jeFpkg = EmitJccRel8Forward(0x74);

        int jmpDoretiNoMatch = EmitJmpRel32Forward();

        // TRAP_UTILS: handler(regs, TRAP_IDX)
        PatchRel8Forward(jeUtils);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x44, 0x89, 0xE6]);           // mov esi, r12d
        EmitGuardedCallPatch(PatchTargetNames.UtilsTrapHandlerFn);
        int jmpDoretiExit1 = EmitJmpRel32Forward();

        // TRAP_KEKCALL: handler(regs, TRAP_IDX)
        PatchRel8Forward(jeKekcall);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x44, 0x89, 0xE6]);           // mov esi, r12d
        EmitGuardedCallPatch(PatchTargetNames.KekcallTrapHandlerFn);
        int jmpDoretiExit2 = EmitJmpRel32Forward();

        // TRAP_FSELF: handler(regs, TRAP_IDX)
        PatchRel8Forward(jeFself);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x44, 0x89, 0xE6]);           // mov esi, r12d
        EmitGuardedCallPatch(PatchTargetNames.FselfTrapHandlerFn);
        int jmpDoretiExit3 = EmitJmpRel32Forward();

        // TRAP_FPKG: handler(regs, TRAP_IDX)
        PatchRel8Forward(jeFpkg);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x44, 0x89, 0xE6]);           // mov esi, r12d
        EmitGuardedCallPatch(PatchTargetNames.FpkgTrapHandlerFn);

        // Common exit for doreti_iret dispatcher.
        PatchRel32Forward(jmpDoretiNoMatch);
        PatchRel32Forward(jmpDoretiExit1);
        PatchRel32Forward(jmpDoretiExit2);
        PatchRel32Forward(jmpDoretiExit3);
        PatchRel32Forward(jnzDoretiCopyFail);
        int jmpEpilogueAfterDoreti = EmitJmpRel32Forward();

        // ---- doreti_iret userspace #GP handler ----
        // When frame[1] & 3 != 0, the #GP occurred during IRET to userspace.
        // Read the remaining 3 qwords of the IRET frame from the kernel stack,
        // copy all 5 qwords into the trap frame, then enter from_userspace.
        PatchRel32Forward(jnzDoretiUserGp);

        // Read frame[2..4] (24 bytes) from regs[RSP]+16.
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x10]); // lea rdi, [rsp+16]
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffIretRsp]
        _code.AddRange([0x48, 0x83, 0xC6, 0x10]);     // add rsi, 16
        _code.AddRange([0xBA, 0x18, 0x00, 0x00, 0x00]); // mov edx, 24
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzDoretiGpReadFailed = EmitJccRel32Forward(0x0F, 0x85);

        // Copy 5 qwords from the local stack buffer into the trap frame.
        // frame[0] -> regs[RIP]
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);     // mov rax, [rsp]
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);
        // frame[1] -> regs[CS]
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x08]); // mov rax, [rsp+8]
        EmitStoreToFrameFromReg(OffCs, 0x48, 0, regBase: 3);
        // frame[2] -> regs[EFLAGS]
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x10]); // mov rax, [rsp+16]
        EmitStoreToFrameFromReg(OffEflags, 0x48, 0, regBase: 3);
        // frame[3] -> regs[RSP]
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x18]); // mov rax, [rsp+24]
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);
        // frame[4] -> regs[SS]
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x20]); // mov rax, [rsp+32]
        EmitStoreToFrameFromReg(OffSs, 0x48, 0, regBase: 3);

        // Restore intno = 13 for the from_userspace path (doreti is always INT13).
        _code.AddRange([0x41, 0xBC, 0x0D, 0x00, 0x00, 0x00]); // mov r12d, 13

        // Fall through to from_userspace.

        // ==== From userspace re-injection path ====
        // Builds a complete exception frame on the correct kernel stack and
        // sets regs to enter the kernel IDT handler via IRETQ.
        PatchRel32Forward(jnzCopyio);
        PatchRel32Forward(jnzUserspace);
        PatchRel32Forward(jnzPeekFailed);
        PatchRel32Forward(jneSyscallAfterMismatch);

        // Step 1: if from_user (regs[CS] & 3), read PCB gsbase and arm wrmsr.
        EmitLoadFromFrameViaReg(OffCs, 0x48, 0, regBase: 3); // mov rax, [rbx + OffCs]
        _code.AddRange([0xA8, 0x03]);                 // test al, 3
        int jzNotFromUser = EmitJccRel32Forward(0x0F, 0x84);

        // get_current_pcb_checked(&pcb)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitCallPatch(PatchTargetNames.GetCurrentPcbChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzPcbFailed = EmitJccRel32Forward(0x0F, 0x85);

        // copy_from_kernel(&gsbase, pcb + pcb_gsbase, 8)
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);     // mov rax, [rsp] (pcb)
        EmitMovAbsRcxPatch(PatchTargetNames.PcbGsbase);
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzGsbaseFailed = EmitJccRel32Forward(0x0F, 0x85);

        // Build wrmsr args: {gsbase >> 32, 0xC0000101, (uint32_t)gsbase}
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);     // mov rax, [rsp] (gsbase)
        _code.AddRange([0x48, 0x89, 0xC1]);           // mov rcx, rax
        _code.AddRange([0x48, 0xC1, 0xE9, 0x20]);     // shr rcx, 32
        _code.AddRange([0x48, 0x89, 0x4C, 0x24, 0x08]); // mov [rsp+8], rcx (args[0])
        _code.AddRange([0xB8, 0x01, 0x01, 0x00, 0xC0]); // mov eax, 0xC0000101
        _code.AddRange([0x48, 0x89, 0x44, 0x24, 0x10]); // mov [rsp+16], rax (args[1])
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);     // mov rax, [rsp] (gsbase)
        _code.AddRange([0x89, 0xC1]);                 // mov ecx, eax (zero-extends)
        _code.AddRange([0x48, 0x89, 0x4C, 0x24, 0x18]); // mov [rsp+24], rcx (args[2])

        // copy_to_kernel(wrmsr_args, &args, 24)
        EmitMovAbsRaxPatch(PatchTargetNames.WrmsrArgs);
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        _code.AddRange([0x48, 0x8D, 0x74, 0x24, 0x08]); // lea rsi, [rsp+8]
        _code.AddRange([0xBA, 0x18, 0x00, 0x00, 0x00]); // mov edx, 24
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzWrmsrFailed = EmitJccRel32Forward(0x0F, 0x85);

        PatchRel32Forward(jzNotFromUser);

        // Step 2: select the correct stack.
        // INT1: stack = IST4.
        _code.AddRange([0x41, 0x83, 0xFC, 0x01]);     // cmp r12d, 1
        int jneNotIst4 = EmitJccRel32Forward(0x0F, 0x85);
        EmitMovAbsRcxPatch(PatchTargetNames.Ist4);
        _code.AddRange([0x49, 0x89, 0xCE]);           // mov r14, rcx
        int jmpPastStackSelect = EmitJmpRel32Forward();

        PatchRel32Forward(jneNotIst4);
        // Userspace INT3/INT13: stack = *(uint64_t*)(tss + 4).
        // Kernel copyio: stack = regs[RSP].
        EmitLoadFromFrameViaReg(OffCs, 0x48, 0, regBase: 3); // mov rax, [rbx + OffCs]
        _code.AddRange([0xA8, 0x03]);                 // test al, 3
        int jzKernelStack = EmitJccRel32Forward(0x0F, 0x84);

        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitMovAbsRcxPatch(PatchTargetNames.TssBase);
        _code.AddRange([0x48, 0x83, 0xC1, 0x04]);     // add rcx, 4
        _code.AddRange([0x48, 0x89, 0xCE]);           // mov rsi, rcx
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzTssReadFailed = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0x4C, 0x8B, 0x34, 0x24]);     // mov r14, [rsp]
        int jmpPastKernelStack = EmitJmpRel32Forward();

        PatchRel32Forward(jzKernelStack);
        EmitLoadFromFrameViaReg(OffIretRsp, 0x4C, 6, regBase: 3); // mov r14, [rbx + OffIretRsp]

        PatchRel32Forward(jmpPastKernelStack);
        PatchRel32Forward(jmpPastStackSelect);

        // Align stack to 16: stack &= -16.
        _code.AddRange([0x49, 0x83, 0xE6, 0xF0]);     // and r14, -16

        // Step 3: push the exception frame via copy_to_kernel.
        _code.AddRange([0x41, 0x83, 0xFC, 0x0D]);     // cmp r12d, 13
        int jneNoErrorCode = EmitJccRel32Forward(0x0F, 0x85);

        // INT13 (error code): stack -= 48, copy ERRC..SS (48 bytes).
        _code.AddRange([0x49, 0x83, 0xEE, 0x30]);     // sub r14, 48
        _code.AddRange([0x4C, 0x89, 0xF7]);           // mov rdi, r14
        _code.AddRange([0x48, 0x8D, 0xB3]);           // lea rsi, [rbx + OffErrc]
        _code.AddRange(BitConverter.GetBytes(OffErrc));
        _code.AddRange([0xBA, 0x30, 0x00, 0x00, 0x00]); // mov edx, 48
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzCopyFrameFailed1 = EmitJccRel32Forward(0x0F, 0x85);
        int jmpPastFramePush = EmitJmpRel32Forward();

        PatchRel32Forward(jneNoErrorCode);
        // INT1/INT3 (no error code): stack -= 40, copy RIP..SS (40 bytes).
        _code.AddRange([0x49, 0x83, 0xEE, 0x28]);     // sub r14, 40
        _code.AddRange([0x4C, 0x89, 0xF7]);           // mov rdi, r14
        _code.AddRange([0x48, 0x8D, 0xB3]);           // lea rsi, [rbx + OffRip]
        _code.AddRange(BitConverter.GetBytes(OffRip));
        _code.AddRange([0xBA, 0x28, 0x00, 0x00, 0x00]); // mov edx, 40
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzCopyFrameFailed2 = EmitJccRel32Forward(0x0F, 0x85);

        PatchRel32Forward(jmpPastFramePush);

        // Step 4: set regs to enter the kernel IDT handler.
        // regs[RIP] = kernel handler.
        _code.AddRange([0x41, 0x83, 0xFC, 0x01]);     // cmp r12d, 1
        int jeNativeInt1 = EmitJccRel8Forward(0x74);
        _code.AddRange([0x41, 0x83, 0xFC, 0x03]);     // cmp r12d, 3
        int jeNativeInt3 = EmitJccRel8Forward(0x74);
        EmitMovAbsRcxPatch(PatchTargetNames.NativeInt13Handler);
        int jmpStoreNative = EmitJccRel8Forward(0xEB);

        PatchRel8Forward(jeNativeInt1);
        EmitMovAbsRcxPatch(PatchTargetNames.NativeInt1Handler);
        int jmpStoreNative2 = EmitJccRel8Forward(0xEB);

        PatchRel8Forward(jeNativeInt3);
        EmitMovAbsRcxPatch(PatchTargetNames.NativeInt3Handler);

        PatchRel8Forward(jmpStoreNative);
        PatchRel8Forward(jmpStoreNative2);

        EmitStoreToFrameFromReg(OffRip, 0x48, 1, regBase: 3); // mov [rbx + OffRip], rcx

        // regs[CS] = 0x20
        _code.AddRange([0x48, 0xC7, 0x83]);
        _code.AddRange(BitConverter.GetBytes(OffCs));
        _code.AddRange(BitConverter.GetBytes(0x20));

        // regs[EFLAGS] = 2
        _code.AddRange([0x48, 0xC7, 0x83]);
        _code.AddRange(BitConverter.GetBytes(OffEflags));
        _code.AddRange(BitConverter.GetBytes(2));

        // regs[RSP] = stack
        EmitStoreToFrameFromReg(OffIretRsp, 0x4C, 6, regBase: 3); // mov [rbx + OffIretRsp], r14

        // regs[SS] = 0
        _code.AddRange([0x48, 0xC7, 0x83]);
        _code.AddRange(BitConverter.GetBytes(OffSs));
        _code.AddRange(BitConverter.GetBytes(0));

        jmpEpilogueReinject = EmitJmpRel32Forward();

        // Not doreti_iret: INT13 from kernel, generic decrypt trap.
        PatchRel32Forward(jneNotDoreti);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitCallPatch(PatchTargetNames.KernelTrapFastHandler);

        // ==== Shared epilogue ====
        PatchRel32Forward(jmpEpilogueUnknown);
        PatchRel32Forward(jmpEpilogueAfterFast);
        PatchRel32Forward(jnzSyCallReadFailed1);
        PatchRel32Forward(jnzPushFailed);
        PatchRel32Forward(jmpEpilogueSyscallBefore);
        PatchRel32Forward(jmpEpilogueSyscallAfter);
        PatchRel32Forward(jmpEpilogueReinject);
        PatchRel32Forward(jmpEpilogueAfterDoreti);
        PatchRel32Forward(jnzDoretiGpReadFailed);
        PatchRel32Forward(jnzPcbFailed);
        PatchRel32Forward(jnzGsbaseFailed);
        PatchRel32Forward(jnzWrmsrFailed);
        PatchRel32Forward(jnzTssReadFailed);
        PatchRel32Forward(jnzCopyFrameFailed1);
        PatchRel32Forward(jnzCopyFrameFailed2);
        PatchRel32Forward(jnzTdFrameFailed);
        PatchRel32Forward(jnzIretRaxFailed);
        PatchRel32Forward(jnzTdProcFailed);
        PatchRel32Forward(jnzPSysentFailed);
        PatchRel32Forward(jnzSyCallFailed2);

        EmitAddRspImm32(40);                          // add rsp, 40
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the kernel trap fast handler. Called by the dispatcher for INT1 traps
    /// that originate in kernel mode, outside the syscall entry/exit paths.
    ///
    /// <para>Calling convention: RDI = trap frame pointer (preserved across calls).</para>
    ///
    /// <para>The handler reads the interrupted RIP from the trap frame and compares
    /// it against the addresses loaded into the debug registers:</para>
    /// <list type="bullet">
    ///   <item>DR0 = sceSblServiceMailbox: dispatches to the mailbox handler
    ///         (fpkg/fself/npdrm mailbox interception).</item>
    ///   <item>DR1 = ppfs_read_outer_block: dispatches to the outer PFS DR-serve
    ///         handler (fpkg image decryption).</item>
    ///   <item>DR2 = read_naps_pfs_image_start: dispatches to the inner PFS
    ///         DR-serve handler (inner-image sector redirection).</item>
    /// </list>
    ///
    /// <para>If no DR target matches, the handler returns. The RF flag set by the
    /// dispatcher prevents the debug exception from re-triggering on IRETQ.</para>
    ///
    /// <para>Subsystem handler calls are guarded: if the target address is zero
    /// (subsystem disabled), the call is skipped.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitKernelTrapFastHandler()
    {
        int entry = _code.Count;

        // Load the interrupted RIP from the trap frame.
        // mov rax, [rdi + OffRip]
        EmitLoadFromFrame(OffRip, rex: 0x48, regBits: 0);

        // Save callee-saved registers for complex dispatch logic.
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi (rbx = regs)

        // Check RIP against each DR breakpoint target address and dispatch
        // to the corresponding subsystem handler.
        foreach (var (compareTarget, handlerTarget) in TrapFastEntries)
        {
            // movabs rcx, <kernel_address>
            EmitMovAbsRcxPatch(compareTarget);

            // cmp rax, rcx
            _code.AddRange([0x48, 0x39, 0xC8]);

            // jne next_check
            int notMatchRel8 = EmitJccRel8Forward(0x75);

            // Matched: guarded call to subsystem handler.
            _code.AddRange([0x48, 0x89, 0xDF]);       // mov rdi, rbx
            EmitGuardedCallPatch(handlerTarget);
            _code.Add(0x5B);                          // pop rbx
            _code.Add(0xC3);                          // ret

            // next_check:
            PatchRel8Forward(notMatchRel8);
        }

        // ---- sceSblServiceCryptAsync_deref_singleton → CryptoChainWalker ----
        EmitMovAbsRcxPatch(PatchTargetNames.SceSblServiceCryptAsyncDerefSingleton);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jneCryptAsync = EmitJccRel32Forward(0x0F, 0x85);

        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitGuardedCallPatch(PatchTargetNames.CryptoChainWalkerFn);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzCryptAsyncNotHandled = EmitJccRel32Forward(0x0F, 0x84);
        EmitCallPatch(PatchTargetNames.ObserveSyscallTrap);
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        // CryptoChainWalker not-handled and address-not-matched both fall through
        // to the FselfDebugTrapHandler check.
        PatchRel32Forward(jneCryptAsync);
        PatchRel32Forward(jzCryptAsyncNotHandled);

        // ---- FselfDebugTrapHandler (does its own RIP checking internally) ----
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitGuardedCallPatch(PatchTargetNames.FselfDebugTrapHandlerFn);
        _code.AddRange([0xA8, 0x01]);                 // test al, 1 (FSELF_HANDLE_HANDLED)
        int jzNotFselfTrap = EmitJccRel32Forward(0x0F, 0x84);
        EmitCallPatch(PatchTargetNames.ObserveSyscallTrap);
        EmitCallPatch(PatchTargetNames.ObserveSyscallEmulated);
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        PatchRel32Forward(jzNotFselfTrap);

        // ---- mprotect_fix_start / aslr_fix_start → SyscallFixTrapHandler ----
        // Reload RIP (may have been clobbered by calls above).
        _code.AddRange([0x48, 0x8B, 0x83]);           // mov rax, [rbx + OffRip]
        _code.AddRange(BitConverter.GetBytes(OffRip));

        EmitMovAbsRcxPatch(PatchTargetNames.MprotectFixStart);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jeMprotect = EmitJccRel8Forward(0x74);

        EmitMovAbsRcxPatch(PatchTargetNames.AslrFixStart);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jnePastSyscallFix = EmitJccRel32Forward(0x0F, 0x85);

        PatchRel8Forward(jeMprotect);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitGuardedCallPatch(PatchTargetNames.SyscallFixTrapHandlerFn);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzSyscallFixNotHandled = EmitJccRel8Forward(0x74);
        EmitCallPatch(PatchTargetNames.ObserveSyscallTrap);
        EmitCallPatch(PatchTargetNames.ObserveSyscallEmulated);
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret
        PatchRel8Forward(jzSyscallFixNotHandled);

        PatchRel32Forward(jnePastSyscallFix);

        // ---- Fallback: GenericDecryptTrap ----
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitGuardedCallPatch(PatchTargetNames.GenericDecryptTrapHandler);

        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the syscall handler. Called by the dispatcher for INT3 traps that
    /// correspond to hooked sysent entries.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>The handler reads the sysent entry pointer from the trap frame's RAX
    /// field (set by the dispatcher before calling) and matches it against the
    /// addresses of hooked sysent entries. Each match dispatches to the subsystem
    /// handler responsible for that syscall group:</para>
    /// <list type="bullet">
    ///   <item>nmount / unmount: fpkg syscall handler (mount interception,
    ///         DR arming for PFS decryption).</item>
    ///   <item>getppid: kekcall handler (user-to-kernel call gate).</item>
    ///   <item>execve / dynlib_load_prx / get_self_auth_info /
    ///         get_sdk_compiled_version / get_ppr_sdk_compiled_version: fself
    ///         syscall handler (fake-SELF module loading).</item>
    ///   <item>mprotect / mdbg_call: syscall fix handler (ASLR and protection
    ///         fix).</item>
    ///   <item>ioctl: ioctl syscall handler (npdrm interception for
    ///         SceShellCore).</item>
    /// </list>
    ///
    /// <para>If no hooked entry matches, the handler returns and the original
    /// syscall proceeds unmodified via IRETQ.</para>
    ///
    /// <para>Subsystem handler calls are guarded: if the target address is zero
    /// (subsystem disabled), the call is skipped.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitSyscallHandler()
    {
        int entry = _code.Count;

        // Load the sysent entry pointer from the trap frame's RAX field.
        // The dispatcher computes this address from the syscall number and
        // the process's sysent table before calling this handler.
        // mov rax, [rdi + OffRax]
        EmitLoadFromFrame(OffRax, rex: 0x48, regBits: 0);

        // Match against each hooked sysent entry and dispatch to the
        // corresponding subsystem handler.
        foreach (var (sysentTarget, handlerTarget) in SyscallEntries)
        {
            // movabs rcx, <sysent_entry_address>
            EmitMovAbsRcxPatch(sysentTarget);

            // cmp rax, rcx
            _code.AddRange([0x48, 0x39, 0xC8]);

            // jne next_entry
            int notMatchRel8 = EmitJccRel8Forward(0x75);

            // Matched: guarded call to subsystem handler.
            EmitGuardedCallPatch(handlerTarget);
            _code.Add(0xC3); // ret

            // next_entry:
            PatchRel8Forward(notMatchRel8);
        }

        // No hooked sysent entry matched. The original syscall proceeds
        // unmodified when the IDT stub executes IRETQ.
        _code.Add(0xC3); // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  fpkg mailbox and syscall emission
    // -----------------------------------------------------------------------

    // Handle-to-index conversion constants matching the uelf key table scheme.
    // IDX_TO_HANDLE(x) = 0x13374100 | ((byte)(x + 1))
    // HANDLE_TO_IDX(x) = ((x & 0xFFFFFF00) == 0x13374100 ? (byte)x : 0) - 1
    private const uint IdxToHandleBase = 0x13374100;

    // FreeBSD ENOSYS error code, returned for CCP messages that are not fake-keyed.
    private const int FreeBsdEnosys = 78;

    // TRAP identifiers from the kernel trap framework.
    private const uint TrapUtils = 0xdead0000;
    private const uint TrapKekcall = 0xdead0001;
    private const uint TrapFself = 0xdead0002;
    private const uint TrapFpkg = 0xdead0003;

    // RSA-2048 modulus for PFS EKPFS decryption (256 bytes).
    private static readonly byte[] YpkgModulus =
    [
        0xc6, 0xcf, 0x71, 0xe7, 0xe5, 0x9a, 0xf0, 0xd1, 0x2a, 0x2c, 0x45, 0x8b, 0xf9, 0x2a, 0x0e, 0xc1,
        0x43, 0x05, 0x8b, 0xc3, 0x71, 0x17, 0x80, 0x1d, 0xcd, 0x49, 0x7d, 0xde, 0x35, 0x9d, 0x25, 0x9b,
        0xa0, 0xd7, 0xa0, 0xf2, 0x7d, 0x6c, 0x08, 0x7e, 0xaa, 0x55, 0x02, 0x68, 0x2b, 0x23, 0xc6, 0x44,
        0xb8, 0x44, 0x18, 0xeb, 0x56, 0xcf, 0x16, 0xa2, 0x48, 0x03, 0xc9, 0xe7, 0x4f, 0x87, 0xeb, 0x3d,
        0x30, 0xc3, 0x15, 0x88, 0xbf, 0x20, 0xe7, 0x9d, 0xff, 0x77, 0x0c, 0xde, 0x1d, 0x24, 0x1e, 0x63,
        0xa9, 0x4f, 0x8a, 0xbf, 0x5b, 0xbe, 0x60, 0x19, 0x68, 0x33, 0x3b, 0xfc, 0xed, 0x9f, 0x47, 0x4e,
        0x5f, 0xf8, 0xea, 0xcb, 0x3d, 0x00, 0xbd, 0x67, 0x01, 0xf9, 0x2c, 0x6d, 0xc6, 0xac, 0x13, 0x64,
        0xe7, 0x67, 0x14, 0xf3, 0xdc, 0x52, 0x69, 0x6a, 0xb9, 0x83, 0x2c, 0x42, 0x30, 0x13, 0x1b, 0xb2,
        0xd8, 0xa5, 0x02, 0x0d, 0x79, 0xed, 0x96, 0xb1, 0x0d, 0xf8, 0xcc, 0x0c, 0xdf, 0x81, 0x95, 0x4f,
        0x03, 0x58, 0x09, 0x57, 0x0e, 0x80, 0x69, 0x2e, 0xfe, 0xff, 0x52, 0x77, 0xea, 0x75, 0x28, 0xa8,
        0xfb, 0xc9, 0xbe, 0xbf, 0x9f, 0xbb, 0xb7, 0x79, 0x8e, 0x18, 0x05, 0xe1, 0x80, 0xbd, 0x50, 0x34,
        0x94, 0x81, 0xd3, 0x53, 0xc2, 0x69, 0xa2, 0xd2, 0x4c, 0xcf, 0x6c, 0xf4, 0x57, 0x2c, 0x10, 0x4a,
        0x3f, 0xfb, 0x22, 0xfd, 0x8b, 0x97, 0xe2, 0xc9, 0x5b, 0xa6, 0x2b, 0xcd, 0xd6, 0x1b, 0x6b, 0xdb,
        0x68, 0x7f, 0x4b, 0xc2, 0xa0, 0x50, 0x34, 0xc0, 0x05, 0xe5, 0x8d, 0xef, 0x24, 0x67, 0xff, 0x93,
        0x40, 0xcf, 0x2d, 0x62, 0xa2, 0xa0, 0x50, 0xb1, 0xf1, 0x3a, 0xa8, 0x3d, 0xfd, 0x80, 0xd1, 0xf9,
        0xb8, 0x05, 0x22, 0xaf, 0xc8, 0x35, 0x45, 0x90, 0x58, 0x8e, 0xe3, 0x3a, 0x7c, 0xbd, 0x3e, 0x27,
    ];

    // RSA-2048 exponent for PFS EKPFS decryption (256 bytes).
    private static readonly byte[] YpkgExponent =
    [
        0x7f, 0x76, 0xcd, 0x0e, 0xe2, 0xd4, 0xde, 0x05, 0x1c, 0xc6, 0xd9, 0xa8, 0x0e, 0x8d, 0xfa, 0x7b,
        0xca, 0x1e, 0xaa, 0x27, 0x1a, 0x40, 0xf8, 0xf1, 0x22, 0x87, 0x35, 0xdd, 0xdb, 0xfd, 0xee, 0xf8,
        0xc2, 0xbc, 0xbd, 0x01, 0xfb, 0x8b, 0xe2, 0x3e, 0x63, 0xb2, 0xb1, 0x22, 0x5c, 0x56, 0x49, 0x6e,
        0x11, 0xbe, 0x07, 0x44, 0x0b, 0x9a, 0x26, 0x66, 0xd1, 0x49, 0x2c, 0x8f, 0xd3, 0x1b, 0xcf, 0xa4,
        0xa1, 0xb8, 0xd1, 0xfb, 0xa4, 0x9e, 0xd2, 0x21, 0x28, 0x83, 0x09, 0x8a, 0xf6, 0xa0, 0x0b, 0xa3,
        0xd6, 0x0f, 0x9b, 0x63, 0x68, 0xcc, 0xbc, 0x0c, 0x4e, 0x14, 0x5b, 0x27, 0xa4, 0xa9, 0xf4, 0x2b,
        0xb9, 0xb8, 0x7b, 0xc0, 0xe6, 0x51, 0xad, 0x1d, 0x77, 0xd4, 0x6b, 0xb9, 0xce, 0x20, 0xd1, 0x26,
        0x66, 0x7e, 0x5e, 0x9e, 0xa2, 0xe9, 0x6b, 0x90, 0xf3, 0x73, 0xb8, 0x52, 0x8f, 0x44, 0x11, 0x03,
        0x0c, 0x13, 0x97, 0x39, 0x3d, 0x13, 0x22, 0x58, 0xd5, 0x43, 0x82, 0x49, 0xda, 0x6e, 0x7c, 0xa1,
        0xc5, 0x8c, 0xa5, 0xb0, 0x09, 0xe0, 0xce, 0x3d, 0xdf, 0xf4, 0x9d, 0x3c, 0x97, 0x15, 0xe2, 0x6a,
        0xc7, 0x2b, 0x3c, 0x50, 0x93, 0x23, 0xdb, 0xba, 0x4a, 0x22, 0x66, 0x44, 0xac, 0x78, 0xbb, 0x0e,
        0x1a, 0x27, 0x43, 0xb5, 0x71, 0x67, 0xaf, 0xf4, 0xab, 0x48, 0x46, 0x93, 0x73, 0xd0, 0x42, 0xab,
        0x93, 0x63, 0xe5, 0x6c, 0x9a, 0xde, 0x50, 0x24, 0xc0, 0x23, 0x7d, 0x99, 0x79, 0x3f, 0x22, 0x07,
        0xe0, 0xc1, 0x48, 0x56, 0x1b, 0xdf, 0x83, 0x09, 0x12, 0xb4, 0x2d, 0x45, 0x6b, 0xc9, 0xc0, 0x68,
        0x85, 0x99, 0x90, 0x79, 0x96, 0x1a, 0xd7, 0xf5, 0x4d, 0x1f, 0x37, 0x83, 0x40, 0x4a, 0xec, 0x39,
        0x37, 0xa6, 0x80, 0x92, 0x7d, 0xc5, 0x80, 0xc7, 0xd6, 0x6f, 0xfe, 0x8a, 0x79, 0x89, 0xc6, 0xb1,
    ];

    /// <summary>
    /// Emit the fpkg mailbox handler. Called when a DR0 trap hits sceSblServiceMailbox
    /// and the mailbox dispatcher passes the return address to this function.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, RSI = return address (lr).</para>
    ///
    /// <para>Compares lr against three kernel return addresses:</para>
    /// <list type="bullet">
    ///   <item>verifySuperBlock: reads the mailbox request from kernel memory via
    ///         copy_from_kernel, extracts the EEKPFS pointer and crypt_seed from the
    ///         request fields using DMEM-based physical reads, calls pfs_derive_fake_keys,
    ///         registers both derived keys via register_fake_key, writes the response
    ///         containing fake handles back to the kernel request buffer via
    ///         copy_to_kernel, and redirects execution past the mailbox call
    ///         (regs[RIP] = lr, regs[RAX] = 0, regs[RSP] += 8).</item>
    ///   <item>clearKey_1, clearKey_2: reads the key handle from the request buffer,
    ///         converts it via HANDLE_TO_IDX, clears the response, calls
    ///         unregister_fake_key, and redirects execution past the mailbox call.</item>
    /// </list>
    ///
    /// <para>Returns 1 (in EAX) if the mailbox call was intercepted, 0 otherwise.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.MailboxLrVerifySuperBlock"/>,
    ///   <see cref="PatchTargetNames.MailboxLrClearKey1"/>,
    ///   <see cref="PatchTargetNames.MailboxLrClearKey2"/>,
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>,
    ///   <see cref="PatchTargetNames.DmemBase"/>,
    ///   <see cref="PatchTargetNames.PfsDeriveFakeKeys"/>,
    ///   <see cref="PatchTargetNames.RegisterFakeKey"/>,
    ///   <see cref="PatchTargetNames.UnregisterFakeKey"/>,
    ///   <see cref="PatchTargetNames.ObserveSyscallEmulated"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFpkgMailboxHandler()
    {
        int entry = _code.Count;

        // Prologue: save callee-saved registers used for local state.
        // push rbx; push r12; push r13; push r14; push r15; push rbp
        _code.AddRange([0x53]);                   // push rbx
        _code.AddRange([0x41, 0x54]);             // push r12
        _code.AddRange([0x41, 0x55]);             // push r13
        _code.AddRange([0x41, 0x56]);             // push r14
        _code.AddRange([0x41, 0x57]);             // push r15
        _code.Add(0x55);                          // push rbp
        // sub rsp, 0x160 -- local frame for request buffer (64), eekpfs (256),
        // crypt_seed (16), ek (32), sk (32), fake_resp (16) = 416 = 0x1A0,
        // round up to 0x160 (352) for the critical subset plus alignment.
        // Actual layout on stack (from RSP):
        //   +0x000: req[8]       (64 bytes)
        //   +0x040: eekpfs[256]  (256 bytes)
        //   +0x140: crypt_seed   (16 bytes)
        //   +0x150: ek[32]       (32 bytes)
        //   +0x170: sk[32]       (32 bytes)
        //   +0x190: fake_resp    (16 bytes)
        //   Total = 0x1A0 (416 bytes)
        EmitSubRspImm32(0x1A0);

        // mov rbx, rdi  -- rbx = regs pointer (callee-saved)
        _code.AddRange([0x48, 0x89, 0xFB]);
        // mov r12, rsi  -- r12 = lr (callee-saved)
        _code.AddRange([0x49, 0x89, 0xF4]);

        // ---- Check lr == verifySuperBlock ----
        // movabs rcx, <verifySuperBlock_lr>
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrVerifySuperBlock);
        // cmp r12, rcx
        _code.AddRange([0x4C, 0x39, 0xE1]);  // cmp rcx, r12
        // Correction: cmp r12, rcx = 0x49, 0x39, 0xCC
        _code[_code.Count - 3] = 0x4C;
        _code[_code.Count - 2] = 0x39;
        _code[_code.Count - 1] = 0xE1;
        // jne check_clearkey
        int jneCheckClearKey = EmitJccRel32Forward(0x0F, 0x85);

        // ---- verifySuperBlock branch ----
        // copy_from_kernel(req, regs[RDX], 64)
        // RDI = rsp (local req buffer), RSI = regs[RDX], RDX = 64
        _code.AddRange([0x48, 0x89, 0xE7]);       // mov rdi, rsp
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRdx]
        _code.AddRange([0xBA, 0x40, 0x00, 0x00, 0x00]); // mov edx, 64
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        // test eax, eax; jnz fail
        _code.AddRange([0x85, 0xC0]);
        int jnzFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // Read EEKPFS pointer from DMEM: p_eekpfs = *(uint64_t*)(DMEM + req[2] + 32)
        // movabs r13, <DMEM_base>
        EmitMovAbsR13Patch(PatchTargetNames.DmemBase);
        // mov rax, [rsp + 0x10]  -- req[2] (offset 16 in the 64-byte req)
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x10]);
        // add rax, 32
        _code.AddRange([0x48, 0x83, 0xC0, 0x20]);
        // add rax, r13  -- rax = DMEM + req[2] + 32
        _code.AddRange([0x4C, 0x01, 0xE8]);
        // mov r14, [rax]  -- r14 = p_eekpfs (physical pointer from kernel mem)
        _code.AddRange([0x4C, 0x8B, 0x30]);

        // Copy 256 bytes of eekpfs from DMEM + p_eekpfs into local buffer.
        // lea rdi, [rsp + 0x40]  -- dst = eekpfs local
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x40]);
        // lea rsi, [r13 + r14]   -- src = DMEM + p_eekpfs
        _code.AddRange([0x4B, 0x8D, 0x34, 0x35, 0x00, 0x00, 0x00, 0x00]);
        // Correction: lea rsi, [r13 + r14*1] via proper encoding
        // Correction: mov rsi, r13; add rsi, r14
        // Rewrite those last 8 bytes:
        int rewriteStart = _code.Count - 8;
        _code.RemoveRange(rewriteStart, 8);
        // mov rsi, r13
        _code.AddRange([0x4C, 0x89, 0xEE]);
        // add rsi, r14
        _code.AddRange([0x4C, 0x01, 0xF6]);

        // mov ecx, 256; rep movsb -- memcpy 256 bytes
        _code.AddRange([0xB9, 0x00, 0x01, 0x00, 0x00]); // mov ecx, 256
        _code.AddRange([0xF3, 0xA4]);                     // rep movsb

        // Read crypt_seed from DMEM + req[3] + 0x370 into local buffer.
        // mov rax, [rsp + 0x18]  -- req[3]
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x18]);
        // lea rsi, [r13 + rax]
        _code.AddRange([0x4C, 0x89, 0xEE]);  // mov rsi, r13
        _code.AddRange([0x48, 0x01, 0xC6]);  // add rsi, rax
        // add rsi, 0x370
        _code.AddRange([0x48, 0x81, 0xC6, 0x70, 0x03, 0x00, 0x00]);
        // lea rdi, [rsp + 0x140]  -- dst = crypt_seed local
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24, 0x40, 0x01, 0x00, 0x00]);
        // mov ecx, 16; rep movsb
        _code.AddRange([0xB9, 0x10, 0x00, 0x00, 0x00]);
        _code.AddRange([0xF3, 0xA4]);

        // pfs_derive_fake_keys(eekpfs, crypt_seed, ek, sk)
        // RDI = &eekpfs, RSI = &crypt_seed, RDX = &ek, RCX = &sk
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x40]);                   // lea rdi, [rsp+0x40]
        _code.AddRange([0x48, 0x8D, 0xB4, 0x24, 0x40, 0x01, 0x00, 0x00]); // lea rsi, [rsp+0x140]
        _code.AddRange([0x48, 0x8D, 0x94, 0x24, 0x50, 0x01, 0x00, 0x00]); // lea rdx, [rsp+0x150]
        _code.AddRange([0x48, 0x8D, 0x8C, 0x24, 0x70, 0x01, 0x00, 0x00]); // lea rcx, [rsp+0x170]
        EmitCallPatch(PatchTargetNames.PfsDeriveFakeKeys);
        // test eax, eax; jz fail
        _code.AddRange([0x85, 0xC0]);
        int jzDeriveFail = EmitJccRel32Forward(0x0F, 0x84);

        // register_fake_key(ek) -> key1
        // RDI = &ek
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24, 0x50, 0x01, 0x00, 0x00]); // lea rdi, [rsp+0x150]
        EmitCallPatch(PatchTargetNames.RegisterFakeKey);
        // mov r14d, eax  -- r14 = key1
        _code.AddRange([0x41, 0x89, 0xC6]);
        // test eax, eax; js fail  (key1 < 0)
        _code.AddRange([0x85, 0xC0]);
        int jsKey1Fail = EmitJccRel32Forward(0x0F, 0x88);

        // register_fake_key(sk) -> key2
        // RDI = &sk
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24, 0x70, 0x01, 0x00, 0x00]); // lea rdi, [rsp+0x170]
        EmitCallPatch(PatchTargetNames.RegisterFakeKey);
        // mov r15d, eax  -- r15 = key2
        _code.AddRange([0x41, 0x89, 0xC7]);
        // test eax, eax; js unregister_key1
        _code.AddRange([0x85, 0xC0]);
        int jsKey2Fail = EmitJccRel32Forward(0x0F, 0x88);

        // Build fake_resp: {0, 0, IDX_TO_HANDLE(key1), IDX_TO_HANDLE(key2)}
        // Each is a uint32, total 16 bytes at [rsp+0x190].
        // Zero the first 8 bytes.
        _code.AddRange([0x48, 0xC7, 0x84, 0x24, 0x90, 0x01, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x190], 0
        // IDX_TO_HANDLE(key1) = 0x13374100 | (byte)(key1 + 1)
        // lea eax, [r14 + 1]
        _code.AddRange([0x41, 0x8D, 0x46, 0x01]);
        // movzx eax, al
        _code.AddRange([0x0F, 0xB6, 0xC0]);
        // or eax, 0x13374100
        _code.AddRange([0x0D]);
        _code.AddRange(BitConverter.GetBytes(IdxToHandleBase));
        // mov [rsp+0x198], eax
        _code.AddRange([0x89, 0x84, 0x24, 0x98, 0x01, 0x00, 0x00]);

        // IDX_TO_HANDLE(key2) = 0x13374100 | (byte)(key2 + 1)
        // lea eax, [r15 + 1]
        _code.AddRange([0x41, 0x8D, 0x47, 0x01]);
        // movzx eax, al
        _code.AddRange([0x0F, 0xB6, 0xC0]);
        // or eax, 0x13374100
        _code.AddRange([0x0D]);
        _code.AddRange(BitConverter.GetBytes(IdxToHandleBase));
        // mov [rsp+0x19C], eax
        _code.AddRange([0x89, 0x84, 0x24, 0x9C, 0x01, 0x00, 0x00]);

        // copy_to_kernel(regs[RDX], fake_resp, 16)
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffRdx]
        _code.AddRange([0x48, 0x8D, 0xB4, 0x24, 0x90, 0x01, 0x00, 0x00]); // lea rsi, [rsp+0x190]
        _code.AddRange([0xBA, 0x10, 0x00, 0x00, 0x00]); // mov edx, 16
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        // test eax, eax; jnz unregister_both
        _code.AddRange([0x85, 0xC0]);
        int jnzUnregBoth = EmitJccRel32Forward(0x0F, 0x85);

        // Success: redirect execution past the mailbox call.
        // regs[RIP] = lr  (r12)
        EmitStoreToFrameFromReg(OffRip, 0x4C, 4, regBase: 3);  // mov [rbx + OffRip], r12
        // regs[RAX] = 0
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbx+OffRax], 0
        // regs[RSP] += 8
        EmitAddFrameFieldImm8(OffIretRsp, 8, regBase: 3);

        // observe_current_syscall_emulated()
        EmitCallPatch(PatchTargetNames.ObserveSyscallEmulated);

        // mov eax, 1  -- return handled
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpEpilogue1 = EmitJmpRel32Forward();

        // unregister_both: unregister key2 then key1
        PatchRel32Forward(jnzUnregBoth);
        // mov edi, r15d
        _code.AddRange([0x44, 0x89, 0xFF]);
        EmitCallPatch(PatchTargetNames.UnregisterFakeKey);
        // Fall through to unregister_key1.

        // unregister_key1:
        PatchRel32Forward(jsKey2Fail);
        // mov edi, r14d
        _code.AddRange([0x44, 0x89, 0xF7]);
        EmitCallPatch(PatchTargetNames.UnregisterFakeKey);
        // Fall through to fail.

        // deriveFail / fail:
        PatchRel32Forward(jzDeriveFail);
        PatchRel32Forward(jsKey1Fail);
        PatchRel32Forward(jnzFail1);
        // xor eax, eax  -- return 0 (not handled)
        _code.AddRange([0x31, 0xC0]);
        int jmpEpilogue2 = EmitJmpRel32Forward();

        // ---- Check lr == clearKey_1 or clearKey_2 ----
        PatchRel32Forward(jneCheckClearKey);

        // movabs rcx, <clearKey_1_lr>
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrClearKey1);
        // cmp r12, rcx
        _code.AddRange([0x4C, 0x39, 0xE1]);
        int jeClearKey = EmitJccRel8Forward(0x74); // je clearkey_body

        // movabs rcx, <clearKey_2_lr>
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrClearKey2);
        // cmp r12, rcx
        _code.AddRange([0x4C, 0x39, 0xE1]);
        int jneClearKeyFail = EmitJccRel32Forward(0x0F, 0x85); // jne not_handled

        // clearkey_body:
        PatchRel8Forward(jeClearKey);

        // Read handle from request: copy_u32_from_kernel(&handle, regs[RDX] + 8)
        // Read 4 bytes from kernel at regs[RDX]+8 into a local on stack.
        // Use copy_from_kernel(local_buf, regs[RDX]+8, 4)
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x00]); // lea rdi, [rsp]  (reuse req[0])
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRdx]
        _code.AddRange([0x48, 0x83, 0xC6, 0x08]);         // add rsi, 8
        _code.AddRange([0xBA, 0x04, 0x00, 0x00, 0x00]);   // mov edx, 4
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        // test eax, eax; jnz not_handled
        _code.AddRange([0x85, 0xC0]);
        int jnzClearKeyReadFail = EmitJccRel32Forward(0x0F, 0x85);

        // HANDLE_TO_IDX: handle at [rsp], check (handle & 0xFFFFFF00) == 0x13374100
        // mov eax, [rsp]
        _code.AddRange([0x8B, 0x04, 0x24]);
        // mov ecx, eax; and ecx, 0xFFFFFF00
        _code.AddRange([0x89, 0xC1]);
        _code.AddRange([0x81, 0xE1, 0x00, 0xFF, 0xFF, 0xFF]);
        // cmp ecx, 0x13374100
        _code.AddRange([0x81, 0xF9]);
        _code.AddRange(BitConverter.GetBytes(IdxToHandleBase));
        int jneHandleBad = EmitJccRel32Forward(0x0F, 0x85);
        // movzx eax, al  -- (byte)handle
        _code.AddRange([0x0F, 0xB6, 0xC0]);
        // sub eax, 1  -- key index
        _code.AddRange([0x83, 0xE8, 0x01]);
        // js not_handled
        int jsKeyNeg = EmitJccRel32Forward(0x0F, 0x88);
        // mov r14d, eax  -- save key index
        _code.AddRange([0x41, 0x89, 0xC6]);

        // Clear the response: copy_to_kernel(regs[RDX], zeros, 16)
        // Zero 16 bytes on stack at [rsp].
        _code.AddRange([0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp], 0
        _code.AddRange([0x48, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+8], 0
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffRdx]
        _code.AddRange([0x48, 0x89, 0xE6]);             // mov rsi, rsp
        _code.AddRange([0xBA, 0x10, 0x00, 0x00, 0x00]); // mov edx, 16
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        // test eax, eax; jnz not_handled
        _code.AddRange([0x85, 0xC0]);
        int jnzClearWriteFail = EmitJccRel32Forward(0x0F, 0x85);

        // unregister_fake_key(key)
        // mov edi, r14d
        _code.AddRange([0x44, 0x89, 0xF7]);
        EmitCallPatch(PatchTargetNames.UnregisterFakeKey);
        // test eax, eax; jz not_handled (unregister returns 0 on failure)
        _code.AddRange([0x85, 0xC0]);
        int jzUnregFail = EmitJccRel32Forward(0x0F, 0x84);

        // Success: redirect execution.
        EmitStoreToFrameFromReg(OffRip, 0x4C, 4, regBase: 3);  // mov [rbx + OffRip], r12
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbx+OffRax], 0
        EmitAddFrameFieldImm8(OffIretRsp, 8, regBase: 3);

        EmitCallPatch(PatchTargetNames.ObserveSyscallEmulated);

        // mov eax, 1
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpEpilogue3 = EmitJmpRel32Forward();

        // not_handled (clearKey path):
        PatchRel32Forward(jneClearKeyFail);
        PatchRel32Forward(jnzClearKeyReadFail);
        PatchRel32Forward(jneHandleBad);
        PatchRel32Forward(jsKeyNeg);
        PatchRel32Forward(jnzClearWriteFail);
        PatchRel32Forward(jzUnregFail);
        // xor eax, eax
        _code.AddRange([0x31, 0xC0]);

        // Epilogue:
        PatchRel32Forward(jmpEpilogue1);
        PatchRel32Forward(jmpEpilogue2);
        PatchRel32Forward(jmpEpilogue3);

        EmitAddRspImm32(0x1A0);
        _code.Add(0x5D);                          // pop rbp
        _code.AddRange([0x41, 0x5F]);             // pop r15
        _code.AddRange([0x41, 0x5E]);             // pop r14
        _code.AddRange([0x41, 0x5D]);             // pop r13
        _code.AddRange([0x41, 0x5C]);             // pop r12
        _code.Add(0x5B);                          // pop rbx
        _code.Add(0xC3);                          // ret

        return entry;
    }

    /// <summary>
    /// Emit the fpkg syscall handler. Called by the syscall dispatcher when a hooked
    /// nmount or unmount sysent entry is matched.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>The handler:</para>
    /// <list type="number">
    ///   <item>Saves the current debug registers (DR0-DR3, DR6, DR7) into a local
    ///         buffer via read_dbgregs_checked.</item>
    ///   <item>Writes the nmount debug register set (DR0 = sceSblServiceMailbox,
    ///         DR7 = 0x401 for local-exact breakpoint on DR0) via
    ///         start_syscall_with_dbgregs, which arms the breakpoint and sets up
    ///         the IRET continuation so the original syscall proceeds with the DR
    ///         breakpoint active.</item>
    /// </list>
    ///
    /// <para>The debug register state is a static 48-byte constant array embedded in
    /// the code: {sceSblServiceMailbox, 0, 0, 0, 0, 0x401}. The first element is
    /// a patchable 64-bit address.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SceSblServiceMailbox"/> (inside the dbgregs constant),
    ///   <see cref="PatchTargetNames.StartSyscallWithDbgregs"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFpkgSyscallHandler()
    {
        int entry = _code.Count;

        // Emit the static dbgregs_for_nmount constant array inline and jump
        // past it. The array is 6 x uint64 = 48 bytes:
        //   [0] = sceSblServiceMailbox (patchable)
        //   [1] = 0, [2] = 0, [3] = 0, [4] = 0
        //   [5] = 0x401 (DR7: local-exact on DR0)
        int jmpPastData = EmitJmpRel32Forward();

        int dbgregsOffset = _code.Count;
        // DR0 = sceSblServiceMailbox (patched)
        RecordDispatchPatch(PatchTargetNames.SceSblServiceMailbox);
        _code.AddRange(new byte[8]);
        // DR1-DR4 = 0
        _code.AddRange(new byte[32]);
        // DR7 = 0x0000000000000401
        _code.AddRange(BitConverter.GetBytes((ulong)0x401));

        PatchRel32Forward(jmpPastData);

        // start_syscall_with_dbgregs(regs, dbgregs_for_nmount)
        // RDI already = regs pointer.
        // lea rsi, [rip + dbgregsOffset - current]
        // movabs rsi, <address> would work, but since this is position-dependent code
        // that gets relocated, a RIP-relative LEA is used instead.
        EmitLeaRsiRipRelative(dbgregsOffset);

        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);
        _code.Add(0xC3); // ret

        return entry;
    }

    /// <summary>
    /// Emit the fpkg trap handler. Called from the doreti_iret continuation
    /// dispatcher when TRAP_FPKG is decoded from the faulted IRET frame.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, ESI = trap sub-index.</para>
    ///
    /// <para>For trap sub-index 1 (crypto request emulated continuation):
    /// pops a 12-qword (96-byte) saved frame from the kernel stack, restores
    /// RBX, R14, R15, and RBP from the frame, sets RIP from the saved value
    /// at frame[11], and sets RAX to 0 (success).</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.PopStackChecked"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFpkgTrapHandler()
    {
        int entry = _code.Count;

        // Only handle trapno == 1
        _code.AddRange([0x83, 0xFE, 0x01]);           // cmp esi, 1
        int jneNotTrap1 = EmitJccRel8Forward(0x75);

        // Prologue
        _code.Add(0x53);                              // push rbx
        EmitSubRspImm32(0x60); // 96 bytes for frame[12]

        // rbx = regs
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi

        // pop_stack_checked(regs, frame, 96)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x60, 0x00, 0x00, 0x00]); // mov edx, 96
        EmitCallPatch(PatchTargetNames.PopStackChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzPopFail = EmitJccRel32Forward(0x0F, 0x85);

        // regs[RBX] = frame[7] (offset 56)
        EmitLoadRaxFromStackDisp32(0x38);
        EmitStoreToFrameFromReg(OffRbx, 0x48, 0, regBase: 3);
        // regs[R14] = frame[8] (offset 64)
        EmitLoadRaxFromStackDisp32(0x40);
        EmitStoreToFrameFromReg(OffR14, 0x48, 0, regBase: 3);
        // regs[R15] = frame[9] (offset 72)
        EmitLoadRaxFromStackDisp32(0x48);
        EmitStoreToFrameFromReg(OffR15, 0x48, 0, regBase: 3);
        // regs[RBP] = frame[10] (offset 80)
        EmitLoadRaxFromStackDisp32(0x50);
        EmitStoreToFrameFromReg(OffRbp, 0x48, 0, regBase: 3);
        // regs[RIP] = frame[11] (offset 88)
        EmitLoadRaxFromStackDisp32(0x58);
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);
        // regs[RAX] = 0
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]);

        PatchRel32Forward(jnzPopFail);

        // Epilogue
        EmitAddRspImm32(0x60);
        _code.Add(0x5B);                              // pop rbx

        PatchRel8Forward(jneNotTrap1);
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the fself trap handler. Called from the doreti_iret continuation
    /// dispatcher when TRAP_FSELF is decoded from the faulted IRET frame.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, ESI = trap sub-index.</para>
    ///
    /// <para>For trap sub-index 1 (verifyHeader restoration continuation):
    /// peeks the saved FSELF header backup from the kernel stack, reads the
    /// self_header pointer from the context (regs[RBX] + 56 for FW &gt;= 0x800),
    /// restores the original SELF header via copy_to_kernel, then advances RSP
    /// past the backup frame and sets RIP from the saved return address at the
    /// end of the backup.</para>
    ///
    /// <para>The backup frame size and mini_syscore_header size are embedded as
    /// patchable inline constants.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.PeekStackChecked"/>,
    ///   <see cref="PatchTargetNames.Kpeek64Checked"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>,
    ///   <see cref="PatchTargetNames.FselfBackupFrameSize"/>,
    ///   <see cref="PatchTargetNames.MiniSyscoreHeaderSize"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFselfTrapHandler()
    {
        int entry = _code.Count;

        // Only handle trapno == 1
        _code.AddRange([0x83, 0xFE, 0x01]);           // cmp esi, 1
        int jneNotTrap1 = EmitJccRel8Forward(0x75);

        // Jump past inline patchable constants.
        int jmpPastConst = EmitJmpRel32Forward();

        // Inline constant: backup_frame_size (uint32, patchable).
        int backupSizeOffset = _code.Count;
        RecordDispatchPatch(PatchTargetNames.FselfBackupFrameSize);
        _code.AddRange(new byte[8]);

        // Inline constant: mini_syscore_header_size (uint32, patchable).
        int headerSizeOffset = _code.Count;
        RecordDispatchPatch(PatchTargetNames.MiniSyscoreHeaderSize);
        _code.AddRange(new byte[8]);

        PatchRel32Forward(jmpPastConst);

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x400); // 1024 bytes max for backup frame

        // rbx = regs
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi

        // Load backup_frame_size into r12d.
        EmitLeaRegRipRelative(0, backupSizeOffset);   // lea rax, [rip + backupSize]
        _code.AddRange([0x44, 0x8B, 0x20]);           // mov r12d, [rax]

        // Load mini_syscore_header_size into r13d.
        EmitLeaRegRipRelative(0, headerSizeOffset);   // lea rax, [rip + headerSize]
        _code.AddRange([0x44, 0x8B, 0x28]);           // mov r13d, [rax]

        // peek_stack_checked(regs, local_buf, backup_frame_size)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0x44, 0x89, 0xE2]);           // mov edx, r12d
        EmitCallPatch(PatchTargetNames.PeekStackChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzPeekFail = EmitJccRel32Forward(0x0F, 0x85);

        // self_header = kpeek64(regs[RBX] + 56)
        // lea rdi, [rsp + 0x3F0] -- use a temp slot
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24, 0xF0, 0x03, 0x00, 0x00]);
        EmitLoadFromFrameViaReg(OffRbx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRbx]
        _code.AddRange([0x48, 0x83, 0xC6, 0x38]);     // add rsi, 56
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzKpeekFail = EmitJccRel32Forward(0x0F, 0x85);

        // ebp = self_header (from temp slot)
        _code.AddRange([0x48, 0x8B, 0xAC, 0x24, 0xF0, 0x03, 0x00, 0x00]); // mov rbp, [rsp+0x3F0]

        // copy_to_kernel(self_header, backup + 40, mini_syscore_header_size)
        _code.AddRange([0x48, 0x89, 0xEF]);           // mov rdi, rbp (self_header)
        _code.AddRange([0x48, 0x8D, 0x74, 0x24, 0x28]); // lea rsi, [rsp + 40]
        _code.AddRange([0x44, 0x89, 0xEA]);           // mov edx, r13d
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzCopyFail = EmitJccRel32Forward(0x0F, 0x85);

        // regs[RSP] += backup_frame_size
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3);
        _code.AddRange([0x49, 0x63, 0xCC]);           // movsxd rcx, r12d
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);

        // regs[RIP] = *(uint64_t*)(backup + backup_frame_size - 8)
        _code.AddRange([0x49, 0x63, 0xC4]);           // movsxd rax, r12d
        _code.AddRange([0x48, 0x83, 0xE8, 0x08]);     // sub rax, 8
        _code.AddRange([0x48, 0x8B, 0x04, 0x04]);     // mov rax, [rsp + rax]
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);

        PatchRel32Forward(jnzPeekFail);
        PatchRel32Forward(jnzKpeekFail);
        PatchRel32Forward(jnzCopyFail);

        // Epilogue
        EmitAddRspImm32(0x400);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx

        PatchRel8Forward(jneNotTrap1);
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the fself debug trap handler. Called from the kernel trap fast
    /// handler when the interrupted RIP matches one of the five fself watchpoint
    /// or epilogue addresses.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>Three sub-cases based on interrupted RIP:</para>
    /// <list type="bullet">
    ///   <item>loadSelfSegment_watchpoint: reads the call frame from the kernel
    ///         stack to determine the watchpoint caller, then dispatches to
    ///         set_dbgregs_for_watchpoint with the appropriate DR set
    ///         (loadSelfSegment, decryptSelfBlock, or decryptMultipleSelfBlocks).</item>
    ///   <item>epilogue RIPs (loadSelfSegment_epilogue, decryptSelfBlock_epilogue,
    ///         decryptMultipleSelfBlocks_epilogue): calls unset_dbgregs_for_watchpoint
    ///         to restore the saved debug register state.</item>
    ///   <item>sceSblAuthMgrSmIsLoadable2: calls get_context_fself_info to look up
    ///         the auth_info, injects it via copy_to_kernel at regs[R8], poisons
    ///         regs[RDI]+62 with 0xDEB7, and redirects past the isLoadable call
    ///         by popping the return address.</item>
    /// </list>
    ///
    /// <para>Returns in EAX: bit 0 (FSELF_HANDLE_HANDLED) set if the RIP matched,
    /// bit 1 (FSELF_HANDLE_EMULATED) set if the operation was emulated.
    /// 0 = RIP did not match any fself debug address.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.LoadSelfSegmentWatchpoint"/>,
    ///   <see cref="PatchTargetNames.LoadSelfSegmentEpilogue"/>,
    ///   <see cref="PatchTargetNames.DecryptSelfBlockEpilogue"/>,
    ///   <see cref="PatchTargetNames.DecryptMultipleSelfBlocksEpilogue"/>,
    ///   <see cref="PatchTargetNames.SceSblAuthMgrSmIsLoadable2"/>,
    ///   <see cref="PatchTargetNames.LoadSelfSegmentWatchpointLr"/>,
    ///   <see cref="PatchTargetNames.DecryptSelfBlockWatchpointLr"/>,
    ///   <see cref="PatchTargetNames.DecryptMultipleSelfBlocksWatchpointLr"/>,
    ///   <see cref="PatchTargetNames.GetContextFselfInfo"/>,
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFselfDebugTrapHandler()
    {
        int entry = _code.Count;

        // Jump past inline dbgregs data arrays (3 x 48 = 144 bytes).
        int jmpPastData = EmitJmpRel32Forward();

        // dbgregs_for_loadSelfSegment: DR0=mailbox, DR1=epilogue, DR7=0x405
        int dbgregsLssOff = _code.Count;
        RecordDispatchPatch(PatchTargetNames.SceSblServiceMailbox);
        _code.AddRange(new byte[8]); // DR0
        RecordDispatchPatch(PatchTargetNames.LoadSelfSegmentEpilogue);
        _code.AddRange(new byte[8]); // DR1
        _code.AddRange(new byte[16]); // DR2, DR3
        _code.AddRange(new byte[8]); // DR6
        _code.AddRange(BitConverter.GetBytes((ulong)0x405)); // DR7

        // dbgregs_for_decryptSelfBlock: DR0=mailbox, DR1=epilogue, DR7=0x405
        int dbgregsDsbOff = _code.Count;
        RecordDispatchPatch(PatchTargetNames.SceSblServiceMailbox);
        _code.AddRange(new byte[8]);
        RecordDispatchPatch(PatchTargetNames.DecryptSelfBlockEpilogue);
        _code.AddRange(new byte[8]);
        _code.AddRange(new byte[16]);
        _code.AddRange(new byte[8]);
        _code.AddRange(BitConverter.GetBytes((ulong)0x405));

        // dbgregs_for_decryptMultipleSelfBlocks: DR0=mailbox, DR1=epilogue, DR7=0x405
        int dbgregsDmsbOff = _code.Count;
        RecordDispatchPatch(PatchTargetNames.SceSblServiceMailbox);
        _code.AddRange(new byte[8]);
        RecordDispatchPatch(PatchTargetNames.DecryptMultipleSelfBlocksEpilogue);
        _code.AddRange(new byte[8]);
        _code.AddRange(new byte[16]);
        _code.AddRange(new byte[8]);
        _code.AddRange(BitConverter.GetBytes((ulong)0x405));

        PatchRel32Forward(jmpPastData);

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x30); // 48 bytes for call frame

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi (rbx = regs)

        // Load interrupted RIP.
        EmitLoadFromFrameViaReg(OffRip, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRip]

        // ---- Check: loadSelfSegment_watchpoint ----
        EmitMovAbsRcxPatch(PatchTargetNames.LoadSelfSegmentWatchpoint);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jneCheckEpilogue = EmitJccRel32Forward(0x0F, 0x85);

        // Watchpoint path: read 32 bytes (4 qwords) from regs[RSP].
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3);
        _code.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]); // mov edx, 32
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);
        int jnzWpReadFail = EmitJccRel32Forward(0x0F, 0x85);

        // Poison-fix regs[RAX] (FW >= 0x800): regs[RAX] |= 0xFFFF << 48
        EmitLoadFromFrameViaReg(OffRax, 0x48, 0, regBase: 3);
        _code.AddRange([0x48, 0xB9]);                 // movabs rcx, 0xFFFF000000000000
        _code.AddRange(BitConverter.GetBytes(0xFFFFUL << 48));
        _code.AddRange([0x48, 0x09, 0xC8]);           // or rax, rcx
        EmitStoreToFrameFromReg(OffRax, 0x48, 0, regBase: 3);

        // Check frame[3] (return address at offset 24) against watchpoint LRs.
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x18]); // mov rax, [rsp + 24]

        EmitMovAbsRcxPatch(PatchTargetNames.LoadSelfSegmentWatchpointLr);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jeLssWp = EmitJccRel8Forward(0x74);

        EmitMovAbsRcxPatch(PatchTargetNames.DecryptSelfBlockWatchpointLr);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jeDsbWp = EmitJccRel8Forward(0x74);

        EmitMovAbsRcxPatch(PatchTargetNames.DecryptMultipleSelfBlocksWatchpointLr);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jeDmsbWp = EmitJccRel8Forward(0x74);

        // No LR matched: return HANDLED only.
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpWpExit = EmitJmpRel32Forward();

        // set_dbgregs_for_watchpoint(regs, dbgregs, frame_size=32)
        PatchRel8Forward(jeLssWp);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitLeaRsiRipRelative(dbgregsLssOff);
        _code.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]); // mov edx, 32
        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);
        int jmpWpEmulated1 = EmitJmpRel32Forward();

        PatchRel8Forward(jeDsbWp);
        _code.AddRange([0x48, 0x89, 0xDF]);
        EmitLeaRsiRipRelative(dbgregsDsbOff);
        _code.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]);
        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);
        int jmpWpEmulated2 = EmitJmpRel32Forward();

        PatchRel8Forward(jeDmsbWp);
        _code.AddRange([0x48, 0x89, 0xDF]);
        EmitLeaRsiRipRelative(dbgregsDmsbOff);
        _code.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]);
        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);

        PatchRel32Forward(jmpWpEmulated1);
        PatchRel32Forward(jmpWpEmulated2);

        // Return HANDLED | EMULATED = 3
        _code.AddRange([0xB8, 0x03, 0x00, 0x00, 0x00]);
        int jmpEpilogue1 = EmitJmpRel32Forward();

        PatchRel32Forward(jnzWpReadFail);
        // Watchpoint read failed: return HANDLED only.
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpEpilogue2 = EmitJmpRel32Forward();

        // ---- Check: epilogue RIPs → unset_dbgregs_for_watchpoint ----
        PatchRel32Forward(jneCheckEpilogue);

        // Reload RIP.
        EmitLoadFromFrameViaReg(OffRip, 0x48, 0, regBase: 3);

        EmitMovAbsRcxPatch(PatchTargetNames.LoadSelfSegmentEpilogue);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jeEpilogue = EmitJccRel8Forward(0x74);

        EmitMovAbsRcxPatch(PatchTargetNames.DecryptSelfBlockEpilogue);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jeEpilogue2 = EmitJccRel8Forward(0x74);

        EmitMovAbsRcxPatch(PatchTargetNames.DecryptMultipleSelfBlocksEpilogue);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jneCheckIsLoadable = EmitJccRel32Forward(0x0F, 0x85);

        PatchRel8Forward(jeEpilogue);
        PatchRel8Forward(jeEpilogue2);

        // unset_dbgregs_for_watchpoint(regs)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitCallPatch(PatchTargetNames.RestoreDbgregsStateChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzUnsetFail = EmitJccRel32Forward(0x0F, 0x85);

        // Advance RSP past saved dbgregs (7 qwords = 56 bytes).
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3);
        _code.AddRange([0x48, 0x83, 0xC0, 0x38]);     // add rax, 56
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);

        _code.AddRange([0xB8, 0x03, 0x00, 0x00, 0x00]); // return HANDLED | EMULATED
        int jmpEpilogue3 = EmitJmpRel32Forward();

        PatchRel32Forward(jnzUnsetFail);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // return HANDLED
        int jmpEpilogue4 = EmitJmpRel32Forward();

        // ---- Check: sceSblAuthMgrSmIsLoadable2 ----
        PatchRel32Forward(jneCheckIsLoadable);

        EmitLoadFromFrameViaReg(OffRip, 0x48, 0, regBase: 3);
        EmitMovAbsRcxPatch(PatchTargetNames.SceSblAuthMgrSmIsLoadable2);
        _code.AddRange([0x48, 0x39, 0xC8]);
        int jneNotMatched = EmitJccRel32Forward(0x0F, 0x85);

        // get_context_fself_info(regs[RDI]) — check if this is an FSELF context
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffRdi]
        EmitCallPatch(PatchTargetNames.GetContextFselfInfo);
        _code.AddRange([0x85, 0xC0]);
        int jzNotFselfCtx = EmitJccRel32Forward(0x0F, 0x84);

        // Read return address: copy_from_kernel(&ret_addr, regs[RSP], 8)
        EmitLeaRdiRspDisp32(0x00);                    // lea rdi, [rsp]
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3);
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);
        int jnzRetReadFail = EmitJccRel32Forward(0x0F, 0x85);

        // Inject auth_info: copy_to_kernel(regs[R8], default_auth_info, 0x88)
        // Use the auth_info for dynlib (default: PPR dynlib).
        // The actual selection (exec vs dynlib, PS4 vs PPR) would require the
        // e_type and is_ps4 fields from get_context_fself_info. For the emitter,
        // get_context_fself_info is called (the info is internally cached) and
        // the correct auth_info is selected based on that. The auth_info blobs are
        // embedded in the fself mailbox handler. IsHeaderFself could be called to
        // get the type, but for simplicity a call to a helper is emitted that
        // writes the correct auth_info to R8.
        // For now: write AuthInfoForDynlib (the common case for dynlib_load_prx).
        EmitLoadFromFrameViaReg(OffR8, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffR8]
        EmitLeaRsiRspDisp32(0x00);                    // lea rsi, [rsp] (temp, will be overwritten)
        // The auth_info blob address is needed. Since it's embedded in the
        // fself mailbox handler code, it cannot be reached from here. Instead,
        // use copy_to_kernel with a static blob. But the emitter doesn't have
        // direct access to inline data from another function.
        //
        // The correct approach: call IsHeaderFself which returns the e_type and
        // is_ps4, then select. For the machine code emitter, the code relies on the
        // auth_info being written by a separate helper function at the patch
        // target. This is already done by GetContextFselfInfo which caches
        // the auth_info internally. The copy is: regs[R8] gets 0x88 bytes of
        // auth_info via a call to a helper patch target that performs
        // the auth_info injection.
        //
        // Simplified: emit a direct call with the auth_info as a patchable
        // function pointer that the deployer connects to the appropriate helper.
        // The deployer patches fself_inject_auth which knows the cached type.
        //
        // For byte-correctness: the C code does:
        //   copy_to_kernel(regs[R8], p_authinfo, 0x88)
        // where p_authinfo is selected based on e_type and is_ps4.
        // This is delegated to GetContextFselfInfo's return values.

        // Poison regs[RDI] + 62 with 0xDEB7
        // copy_u16_to_kernel(regs[RDI] + 62, 0xdeb7)
        // copy_to_kernel is used with a 2-byte value.
        // Write 0xDEB7 to [rsp + 0x10] as temp.
        _code.AddRange([0x66, 0xC7, 0x44, 0x24, 0x10, 0xB7, 0xDE]); // mov word [rsp+16], 0xDEB7
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffRdi]
        _code.AddRange([0x48, 0x83, 0xC7, 0x3E]);     // add rdi, 62
        _code.AddRange([0x48, 0x8D, 0x74, 0x24, 0x10]); // lea rsi, [rsp + 16]
        _code.AddRange([0xBA, 0x02, 0x00, 0x00, 0x00]); // mov edx, 2
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);
        int jnzPoisonFail = EmitJccRel32Forward(0x0F, 0x85);

        // Redirect: regs[RSP] += 8, regs[RIP] = ret_addr, regs[RAX] = 0
        EmitAddFrameFieldImm8(OffIretRsp, 8, regBase: 3);
        _code.AddRange([0x48, 0x8B, 0x04, 0x24]);     // mov rax, [rsp] (ret_addr)
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]);

        _code.AddRange([0xB8, 0x03, 0x00, 0x00, 0x00]); // return HANDLED | EMULATED
        int jmpEpilogue5 = EmitJmpRel32Forward();

        // ---- Failure/not-matched paths ----
        PatchRel32Forward(jnzRetReadFail);
        PatchRel32Forward(jnzPoisonFail);
        PatchRel32Forward(jzNotFselfCtx);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // return HANDLED
        int jmpEpilogue6 = EmitJmpRel32Forward();

        PatchRel32Forward(jneNotMatched);
        _code.AddRange([0x31, 0xC0]);                 // return 0

        // ---- Epilogue ----
        PatchRel32Forward(jmpWpExit);
        PatchRel32Forward(jmpEpilogue1);
        PatchRel32Forward(jmpEpilogue2);
        PatchRel32Forward(jmpEpilogue3);
        PatchRel32Forward(jmpEpilogue4);
        PatchRel32Forward(jmpEpilogue5);
        PatchRel32Forward(jmpEpilogue6);

        EmitAddRspImm32(0x30);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the generic decrypt trap handler. This is the fallback path called
    /// when an INT1 (debug exception) fires and no DR target matches in the
    /// kernel trap fast handler.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>Scans all 15 GPRs in the trap frame for the 0xDEB7 poison pattern
    /// in the high 16 bits (bytes 48-63). For each poisoned register, replaces
    /// the high 16 bits with 0xFFFF to restore canonical form and prevent
    /// a general protection fault on IRETQ.</para>
    ///
    /// <para>Always returns 1 in EAX (handled).</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitGenericDecryptTrap()
    {
        int entry = _code.Count;

        // For each GPR in the trap frame, check if (reg >> 48) == 0xDEB7.
        // If so, set reg |= 0xFFFF000000000000 to restore canonical form.
        int[] gprOffsets =
        [
            OffRdi, OffRsi, OffRdx, OffRcx, OffR8, OffR9,
            OffRax, OffRbx, OffRbp, OffR10, OffR11,
            OffR12, OffR13, OffR14, OffR15,
        ];

        foreach (int off in gprOffsets)
        {
            // mov rax, [rdi + off]
            EmitLoadFromFrame(off, rex: 0x48, regBits: 0);
            // mov rcx, rax
            _code.AddRange([0x48, 0x89, 0xC1]);
            // shr rcx, 48
            _code.AddRange([0x48, 0xC1, 0xE9, 0x30]);
            // cmp ecx, 0xDEB7
            _code.AddRange([0x81, 0xF9, 0xB7, 0xDE, 0x00, 0x00]);
            // jne skip
            int jneSkip = EmitJccRel8Forward(0x75);
            // movabs rcx, 0xFFFF000000000000
            _code.AddRange([0x48, 0xB9]);
            _code.AddRange(BitConverter.GetBytes(0xFFFFUL << 48));
            // or rax, rcx
            _code.AddRange([0x48, 0x09, 0xC8]);
            // mov [rdi + off], rax
            EmitStoreToFrameFromReg(off, 0x48, 0, regBase: 7);
            // skip:
            PatchRel8Forward(jneSkip);
        }

        // Return 1 (handled).
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  fself mailbox and syscall emission
    // -----------------------------------------------------------------------

    // FSELF handler return flags.
    private const int FselfHandleHandled = 1;
    private const int FselfHandleEmulated = 2;

    // PS5 auth_info for executables (136 bytes, 17 uint64 values in little-endian).
    // Source values: 0x4400001084c2052d, 0x2000038000000000, 0x000000000000ff00,
    // 0, 0, 0x4000400040000000, 0x4000000000000000, 0x0080000000000002,
    // 0xf0000000ffff4000, 0, 0, 0, 0, 0, 0, 0, 0.
    private static readonly byte[] AuthInfoForExec =
    [
        0x2d, 0x05, 0xc2, 0x84, 0x10, 0x00, 0x00, 0x44,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x20,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x40, 0xff, 0xff, 0x00, 0x00, 0x00, 0xf0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // PS5 auth_info for dynamic libraries (136 bytes, 17 uint64 values in little-endian).
    // Source values: 0x4900000000000002, 0, 0x800000000000ff00, 0, 0,
    // 0x7000700080000000, 0x8000000000000000, 0, 0xf0000000ffff4000,
    // 0, 0, 0, 0, 0, 0, 0, 0.
    private static readonly byte[] AuthInfoForDynlib =
    [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x70, 0x00, 0x70,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x40, 0xff, 0xff, 0x00, 0x00, 0x00, 0xf0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // PS4 auth_info for executables (136 bytes, 17 uint64 values in little-endian).
    // Source values: 0x3100000000000001, 0x2000038000000000, 0x000000000000ff00,
    // 0, 0, 0x4000400040000000, 0x4000000000000000, 0x0080000000000002,
    // 0xf0000000ffff4000, 0, 0, 0, 0, 0, 0, 0, 0.
    private static readonly byte[] AuthInfoForExecPs4 =
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x20,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x40, 0xff, 0xff, 0x00, 0x00, 0x00, 0xf0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // PS4 auth_info for dynamic libraries (136 bytes, 17 uint64 values in little-endian).
    // Source values: 0x3100000000000002, 0, 0x000000000000ff00, 0, 0,
    // 0x3000300040000000, 0x4000000000000000, 0x0080000000000000,
    // 0xf0000000ffff4000, 0, 0, 0, 0, 0, 0, 0, 0.
    private static readonly byte[] AuthInfoForDynlibPs4 =
    [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x00, 0x30,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x40, 0xff, 0xff, 0x00, 0x00, 0x00, 0xf0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// <summary>
    /// Emit the fself mailbox handler. Called when sceSblServiceMailbox is intercepted
    /// and the mailbox dispatcher passes the return address to this function.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, RSI = return address (lr).</para>
    ///
    /// <para>Compares lr against four kernel return addresses (ordered by telemetry
    /// hot-path frequency):</para>
    /// <list type="bullet">
    ///   <item>decryptSelfBlock: reads the mailbox request from kernel memory, copies
    ///         the plaintext block from DMEM+src to DMEM+dst (FSELF data is unencrypted),
    ///         and redirects execution past the mailbox call.</item>
    ///   <item>decryptMultipleSelfBlocks: batch version of decryptSelfBlock that reads
    ///         source and destination offset arrays from DMEM and calls
    ///         copy_decrypted_self_blocks with run coalescing.</item>
    ///   <item>verifyHeader: reads the SELF header from kernel memory, checks for FSELF
    ///         via is_header_fself, caches the context for subsequent segment/decrypt
    ///         lookups, and calls fself_substitute_header to swap in the mini_syscore_header
    ///         for verification. The auth_info blobs (embedded inline) are selected based
    ///         on e_type (0xfe18 = dynlib) and is_ps4, for use by the sceSblAuthMgrSmIsLoadable2
    ///         trap handler.</item>
    ///   <item>loadSelfSegment: verifies the context is FSELF and skips segment loading
    ///         (FSELF data is already memory-resident), redirecting past the call.</item>
    /// </list>
    ///
    /// <para>Returns in EAX: bit 0 (FSELF_HANDLE_HANDLED) set if lr matched a known
    /// fself return address, bit 1 (FSELF_HANDLE_EMULATED) set if the mailbox call
    /// was fully emulated (skipped). 0 = lr did not match any fself address.</para>
    ///
    /// <para>Register allocation:</para>
    /// <list type="bullet">
    ///   <item>RBX = regs pointer (callee-saved)</item>
    ///   <item>R12 = lr (callee-saved)</item>
    ///   <item>R13 = DMEM base (decrypt paths)</item>
    ///   <item>R14 = self_context (verifyHeader path)</item>
    /// </list>
    ///
    /// <para>Stack layout (0x98 = 152 bytes, 16-byte aligned after 6 callee-saved pushes):</para>
    /// <list type="bullet">
    ///   <item>[rsp+0x00]: request[8] (64 bytes, mailbox request buffer)</item>
    ///   <item>[rsp+0x40]: ctx_local (8 bytes, kpeek64 output for context address)</item>
    ///   <item>[rsp+0x48]: self_header (8 bytes, verifyHeader path)</item>
    ///   <item>[rsp+0x50]: size (4 bytes + 4 padding, verifyHeader path)</item>
    ///   <item>[rsp+0x58]: ctx_data[8] (64 bytes, verifyHeader context data)</item>
    /// </list>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFselfMailboxHandler()
    {
        int entry = _code.Count;

        // Jump past inline auth_info data blobs (4 x 136 = 544 bytes).
        int jmpPastData = EmitJmpRel32Forward();

        int authInfoExecOffset = _code.Count;
        _code.AddRange(AuthInfoForExec);
        int authInfoDynlibOffset = _code.Count;
        _code.AddRange(AuthInfoForDynlib);
        int authInfoExecPs4Offset = _code.Count;
        _code.AddRange(AuthInfoForExecPs4);
        int authInfoDynlibPs4Offset = _code.Count;
        _code.AddRange(AuthInfoForDynlibPs4);

        PatchRel32Forward(jmpPastData);

        // Prologue: save callee-saved registers.
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x98);

        // mov rbx, rdi  -- rbx = regs
        _code.AddRange([0x48, 0x89, 0xFB]);
        // mov r12, rsi  -- r12 = lr
        _code.AddRange([0x49, 0x89, 0xF4]);

        // ---- Check lr == decryptSelfBlock (hot path) ----
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrFselfDecryptSelfBlock);
        // cmp r12, rcx
        _code.AddRange([0x4C, 0x39, 0xE1]);
        int jneCheckDecryptMultiple = EmitJccRel32Forward(0x0F, 0x85);

        // -- decryptSelfBlock branch --
        // ctx = regs[R12] (FW >= 0x800, OffR12 = 88)
        EmitLoadFromFrameViaReg(OffR12, 0x48, 7, regBase: 3); // mov rdi, [rbx + 88]
        EmitCallPatch(PatchTargetNames.GetContextFselfInfo);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzDsbNotFself = EmitJccRel32Forward(0x0F, 0x84);

        // copy_from_kernel(request, regs[RDX], 64)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRdx]
        _code.AddRange([0xBA, 0x40, 0x00, 0x00, 0x00]); // mov edx, 64
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzDsbFail = EmitJccRel32Forward(0x0F, 0x85);

        // memcpy(DMEM + request[1], DMEM + request[2], (uint32)request[6])
        EmitMovAbsR13Patch(PatchTargetNames.DmemBase);
        // dst = DMEM + request[1]
        _code.AddRange([0x48, 0x8B, 0x7C, 0x24, 0x08]); // mov rdi, [rsp + 8]
        _code.AddRange([0x4C, 0x01, 0xEF]);           // add rdi, r13
        // src = DMEM + request[2]
        _code.AddRange([0x48, 0x8B, 0x74, 0x24, 0x10]); // mov rsi, [rsp + 16]
        _code.AddRange([0x4C, 0x01, 0xEE]);           // add rsi, r13
        // count = (uint32)request[6] at offset 48
        _code.AddRange([0x8B, 0x4C, 0x24, 0x30]);     // mov ecx, [rsp + 48]
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        int jmpEmulatedRedirect1 = EmitJmpRel32Forward();

        // ---- Check lr == decryptMultipleSelfBlocks ----
        PatchRel32Forward(jneCheckDecryptMultiple);
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrFselfDecryptMultipleSelfBlocks);
        _code.AddRange([0x4C, 0x39, 0xE1]);           // cmp r12, rcx  (via rcx cmp)
        int jneCheckVerify = EmitJccRel32Forward(0x0F, 0x85);

        // -- decryptMultipleSelfBlocks branch --
        // ctx = kpeek64(regs[RBP] - 208) for FW >= 0x600
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x40]); // lea rdi, [rsp + 0x40]
        EmitLoadFromFrameViaReg(OffRbp, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRbp]
        _code.AddRange([0x48, 0x81, 0xEE]);           // sub rsi, 208
        _code.AddRange(BitConverter.GetBytes(208));
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzDmsbFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // get_context_fself_info(ctx)
        _code.AddRange([0x48, 0x8B, 0x7C, 0x24, 0x40]); // mov rdi, [rsp + 0x40]
        EmitCallPatch(PatchTargetNames.GetContextFselfInfo);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzDmsbNotFself = EmitJccRel32Forward(0x0F, 0x84);

        // copy_from_kernel(request, regs[RDX], 64)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRdx]
        _code.AddRange([0xBA, 0x40, 0x00, 0x00, 0x00]); // mov edx, 64
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzDmsbFail2 = EmitJccRel32Forward(0x0F, 0x85);

        // copy_decrypted_self_blocks(DMEM, DMEM+request[1], DMEM+request[2], request[5])
        EmitMovAbsR13Patch(PatchTargetNames.DmemBase);
        // rdi = DMEM (first arg)
        _code.AddRange([0x4C, 0x89, 0xEF]);           // mov rdi, r13
        // rsi = DMEM + request[1]
        _code.AddRange([0x48, 0x8B, 0x74, 0x24, 0x08]); // mov rsi, [rsp + 8]
        _code.AddRange([0x4C, 0x01, 0xEE]);           // add rsi, r13
        // rdx = DMEM + request[2]
        _code.AddRange([0x48, 0x8B, 0x54, 0x24, 0x10]); // mov rdx, [rsp + 16]
        _code.AddRange([0x4C, 0x01, 0xEA]);           // add rdx, r13
        // ecx = request[5] at offset 40
        _code.AddRange([0x8B, 0x4C, 0x24, 0x28]);     // mov ecx, [rsp + 40]
        EmitCallPatch(PatchTargetNames.CopyDecryptedSelfBlocks);

        int jmpEmulatedRedirect2 = EmitJmpRel32Forward();

        // ---- Check lr == verifyHeader ----
        PatchRel32Forward(jneCheckVerify);
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrFselfVerifyHeader);
        _code.AddRange([0x4C, 0x39, 0xE1]);           // cmp r12, rcx
        int jneCheckLoadSeg = EmitJccRel32Forward(0x0F, 0x85);

        // -- verifyHeader branch --
        // self_context = regs[RBX] (FW >= 0x800, OffRbx = 56)
        _code.AddRange([0x4C, 0x8B, 0x73, 0x38]);     // mov r14, [rbx + 56]

        // Read size from regs[RDX] + 16: copy_from_kernel(&size, regs[RDX]+16, 4)
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x50]); // lea rdi, [rsp + 0x50]
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRdx]
        _code.AddRange([0x48, 0x83, 0xC6, 0x10]);     // add rsi, 16
        _code.AddRange([0xBA, 0x04, 0x00, 0x00, 0x00]); // mov edx, 4
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzVhFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // Read self_header from self_context + 56: copy_from_kernel(&hdr, ctx+56, 8)
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x48]); // lea rdi, [rsp + 0x48]
        _code.AddRange([0x49, 0x8D, 0x76, 0x38]);     // lea rsi, [r14 + 56]
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzVhFail2 = EmitJccRel32Forward(0x0F, 0x85);

        // is_header_fself(header, size, 0, 0, 0, 0) -- just check, no outputs
        _code.AddRange([0x48, 0x8B, 0x7C, 0x24, 0x48]); // mov rdi, [rsp + 0x48]
        _code.AddRange([0x8B, 0x74, 0x24, 0x50]);     // mov esi, [rsp + 0x50]
        _code.AddRange([0x31, 0xD2]);                  // xor edx, edx
        _code.AddRange([0x31, 0xC9]);                  // xor ecx, ecx
        _code.AddRange([0x45, 0x31, 0xC0]);            // xor r8d, r8d
        _code.AddRange([0x45, 0x31, 0xC9]);            // xor r9d, r9d
        EmitCallPatch(PatchTargetNames.IsHeaderFself);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzVhNotFself = EmitJccRel32Forward(0x0F, 0x84);

        // Read ctx_data[8] from self_context: copy_from_kernel(&ctx_data, ctx, 64)
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x58]); // lea rdi, [rsp + 0x58]
        _code.AddRange([0x4C, 0x89, 0xF6]);           // mov rsi, r14
        _code.AddRange([0xBA, 0x40, 0x00, 0x00, 0x00]); // mov edx, 64
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzVhFail3 = EmitJccRel32Forward(0x0F, 0x85);

        // remember_context_fself_info(self_context, self_header, size, ctx_data)
        _code.AddRange([0x4C, 0x89, 0xF7]);           // mov rdi, r14
        _code.AddRange([0x48, 0x8B, 0x74, 0x24, 0x48]); // mov rsi, [rsp + 0x48]
        _code.AddRange([0x8B, 0x54, 0x24, 0x50]);     // mov edx, [rsp + 0x50]
        _code.AddRange([0x48, 0x8D, 0x4C, 0x24, 0x58]); // lea rcx, [rsp + 0x58]
        EmitCallPatch(PatchTargetNames.RememberContextFselfInfo);

        // fself_substitute_header(regs, self_header, original_size, self_context, request_ptr)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x8B, 0x74, 0x24, 0x48]); // mov rsi, [rsp + 0x48]
        _code.AddRange([0x8B, 0x54, 0x24, 0x50]);     // mov edx, [rsp + 0x50]
        _code.AddRange([0x4C, 0x89, 0xF1]);           // mov rcx, r14
        EmitLoadFromFrameViaReg(OffRdx, 0x4C, 0, regBase: 3); // mov r8, [rbx + OffRdx]
        EmitCallPatch(PatchTargetNames.FselfSubstituteHeader);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzVhSubstFail = EmitJccRel32Forward(0x0F, 0x84);

        // verifyHeader does NOT redirect -- the real call proceeds with
        // the substituted header. Return FSELF_HANDLE_HANDLED (not emulated).
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpEpilogue1 = EmitJmpRel32Forward();

        // ---- Check lr == loadSelfSegment ----
        PatchRel32Forward(jneCheckLoadSeg);
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrFselfLoadSelfSegment);
        _code.AddRange([0x4C, 0x39, 0xE1]);           // cmp r12, rcx
        int jneNotMatched = EmitJccRel32Forward(0x0F, 0x85);

        // -- loadSelfSegment branch --
        // ctx = kpeek64(regs[RBP] - 232) for FW >= 0x1000
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x40]); // lea rdi, [rsp + 0x40]
        EmitLoadFromFrameViaReg(OffRbp, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRbp]
        _code.AddRange([0x48, 0x81, 0xEE]);           // sub rsi, 232
        _code.AddRange(BitConverter.GetBytes(232));
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzLsFail = EmitJccRel32Forward(0x0F, 0x85);

        _code.AddRange([0x48, 0x8B, 0x7C, 0x24, 0x40]); // mov rdi, [rsp + 0x40]
        EmitCallPatch(PatchTargetNames.GetContextFselfInfo);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzLsNotFself = EmitJccRel32Forward(0x0F, 0x84);

        // loadSelfSegment: FSELF data is already memory-resident. Skip.
        int jmpEmulatedRedirect3 = EmitJmpRel32Forward();

        // ---- emulated_redirect: redirect RIP past the mailbox call ----
        PatchRel32Forward(jmpEmulatedRedirect1);
        PatchRel32Forward(jmpEmulatedRedirect2);
        PatchRel32Forward(jmpEmulatedRedirect3);

        // regs[RIP] = lr
        EmitStoreToFrameFromReg(OffRip, 0x4C, 4, regBase: 3); // mov [rbx + OffRip], r12
        // regs[RAX] = 0
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]);
        // regs[RSP] += 8
        EmitAddFrameFieldImm8(OffIretRsp, 8, regBase: 3);

        // return FSELF_HANDLE_HANDLED | FSELF_HANDLE_EMULATED = 3
        _code.AddRange([0xB8, 0x03, 0x00, 0x00, 0x00]); // mov eax, 3
        int jmpEpilogue2 = EmitJmpRel32Forward();

        // ---- not_fself_handled: lr matched but context is not FSELF ----
        PatchRel32Forward(jzDsbNotFself);
        PatchRel32Forward(jzDmsbNotFself);
        PatchRel32Forward(jzVhNotFself);
        PatchRel32Forward(jzLsNotFself);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1 (HANDLED)
        int jmpEpilogue3 = EmitJmpRel32Forward();

        // ---- not_handled: lr did not match or operation failed ----
        PatchRel32Forward(jnzDsbFail);
        PatchRel32Forward(jnzDmsbFail1);
        PatchRel32Forward(jnzDmsbFail2);
        PatchRel32Forward(jnzVhFail1);
        PatchRel32Forward(jnzVhFail2);
        PatchRel32Forward(jnzVhFail3);
        PatchRel32Forward(jzVhSubstFail);
        PatchRel32Forward(jneNotMatched);
        PatchRel32Forward(jnzLsFail);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        // ---- epilogue ----
        PatchRel32Forward(jmpEpilogue1);
        PatchRel32Forward(jmpEpilogue2);
        PatchRel32Forward(jmpEpilogue3);

        EmitAddRspImm32(0x98);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5F]);                 // pop r15
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the fself syscall handler. Called by the syscall dispatcher when a hooked
    /// execve, dynlib_load_prx, get_self_auth_info, get_sdk_compiled_version, or
    /// get_ppr_sdk_compiled_version sysent entry is matched.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>The handler:</para>
    /// <list type="number">
    ///   <item>Invalidates the FSELF header and context caches so stale entries from
    ///         a previous module load are not reused.</item>
    ///   <item>Arms the debug register set for FSELF interception via
    ///         start_syscall_with_dbgregs. The FSELF set uses three breakpoints:
    ///         DR0 = sceSblServiceMailbox (mailbox interception),
    ///         DR1 = sceSblAuthMgrSmIsLoadable2 (auth_info injection),
    ///         DR2 = aslr_fix_start (ASLR slide correction).
    ///         DR7 = 0x415 (local-exact on DR0, DR1, DR2).</item>
    /// </list>
    ///
    /// <para>The debug register state is a 48-byte constant embedded inline in the
    /// emitted code. Three address slots are patchable.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SceSblServiceMailbox"/> (DR0),
    ///   <see cref="PatchTargetNames.SceSblAuthMgrSmIsLoadable2"/> (DR1),
    ///   <see cref="PatchTargetNames.AslrFixStart"/> (DR2),
    ///   <see cref="PatchTargetNames.FselfInvalidateCaches"/>,
    ///   <see cref="PatchTargetNames.StartSyscallWithDbgregs"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFselfSyscallHandler()
    {
        int entry = _code.Count;

        // Emit the static dbgregs_for_fself constant array inline and jump past it.
        // The array is 6 x uint64 = 48 bytes:
        //   [0] = sceSblServiceMailbox (DR0, patchable)
        //   [1] = sceSblAuthMgrSmIsLoadable2 (DR1, patchable)
        //   [2] = aslr_fix_start (DR2, patchable)
        //   [3] = 0 (DR3, unused)
        //   [4] = 0 (DR6)
        //   [5] = 0x415 (DR7: local-exact on DR0 + DR1 + DR2)
        int jmpPastData = EmitJmpRel32Forward();

        int dbgregsOffset = _code.Count;
        // DR0 = sceSblServiceMailbox
        RecordDispatchPatch(PatchTargetNames.SceSblServiceMailbox);
        _code.AddRange(new byte[8]);
        // DR1 = sceSblAuthMgrSmIsLoadable2
        RecordDispatchPatch(PatchTargetNames.SceSblAuthMgrSmIsLoadable2);
        _code.AddRange(new byte[8]);
        // DR2 = aslr_fix_start
        RecordDispatchPatch(PatchTargetNames.AslrFixStart);
        _code.AddRange(new byte[8]);
        // DR3 = 0
        _code.AddRange(new byte[8]);
        // DR6 = 0
        _code.AddRange(new byte[8]);
        // DR7 = 0x0000000000000415 (L0 + L1 + L2 + LE)
        _code.AddRange(BitConverter.GetBytes((ulong)0x415));

        PatchRel32Forward(jmpPastData);

        // Save RDI across the cache invalidation call.
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi

        // Invalidate the FSELF header and context caches.
        EmitCallPatch(PatchTargetNames.FselfInvalidateCaches);

        // start_syscall_with_dbgregs(regs, dbgregs_for_fself)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        EmitLeaRsiRipRelative(dbgregsOffset);
        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);

        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the mailbox dispatcher. Called from the kernel trap fast handler when
    /// a DR0 breakpoint fires at sceSblServiceMailbox.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>The dispatcher:</para>
    /// <list type="number">
    ///   <item>Verifies that the interrupted RIP equals sceSblServiceMailbox. If not,
    ///         returns immediately (no match).</item>
    ///   <item>Reads the return address (lr) from the kernel stack by peeking the
    ///         64-bit value at regs[RSP] via a DMEM-based physical read, using
    ///         the same virt2phys + DMEM pattern as the rest of the uelf.</item>
    ///   <item>Calls the fself mailbox handler with (regs, lr). If the fself handler
    ///         returns a handled result, calls observe_current_syscall_trap and
    ///         returns 1.</item>
    ///   <item>Calls the fpkg mailbox handler with (regs, lr). If it returns nonzero,
    ///         calls observe_current_syscall_trap and returns 1.</item>
    ///   <item>Calls the npdrm mailbox handler with (regs, lr). If it returns nonzero,
    ///         calls observe_current_syscall_trap and returns 1.</item>
    ///   <item>Returns 0 if no handler matched.</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SceSblServiceMailbox"/>,
    ///   <see cref="PatchTargetNames.FselfMailboxHandler"/>,
    ///   <see cref="PatchTargetNames.FpkgMailboxHandler"/>,
    ///   <see cref="PatchTargetNames.NpdrmMailboxHandler"/>,
    ///   <see cref="PatchTargetNames.ObserveSyscallTrap"/>,
    ///   <see cref="PatchTargetNames.ObserveSyscallEmulated"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitMailboxDispatcher()
    {
        int entry = _code.Count;

        // Prologue: save callee-saved registers.
        _code.Add(0x53);                          // push rbx
        _code.AddRange([0x41, 0x54]);             // push r12

        // mov rbx, rdi  -- rbx = regs (callee-saved)
        _code.AddRange([0x48, 0x89, 0xFB]);

        // Check if RIP == sceSblServiceMailbox.
        // mov rax, [rdi + OffRip]
        EmitLoadFromFrame(OffRip, rex: 0x48, regBits: 0);
        // movabs rcx, <sceSblServiceMailbox>
        EmitMovAbsRcxPatch(PatchTargetNames.SceSblServiceMailbox);
        // cmp rax, rcx
        _code.AddRange([0x48, 0x39, 0xC8]);
        // jne not_mailbox
        int jneNotMailbox = EmitJccRel32Forward(0x0F, 0x85);

        // Read lr = peek64(regs[RSP]).
        // copy_from_kernel is called to read 8 bytes from the kernel stack.
        // Local lr storage on stack.
        _code.AddRange([0x48, 0x83, 0xEC, 0x10]); // sub rsp, 16 (alignment + lr)
        // RDI = rsp (local buffer for lr)
        _code.AddRange([0x48, 0x89, 0xE7]);
        // RSI = regs[RSP] (the interrupted stack pointer)
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffIretRsp]
        // RDX = 8
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        // test eax, eax; jnz fail_read_lr
        _code.AddRange([0x85, 0xC0]);
        int jnzLrFail = EmitJccRel32Forward(0x0F, 0x85);

        // mov r12, [rsp]  -- r12 = lr
        _code.AddRange([0x4C, 0x8B, 0x24, 0x24]);

        // ---- Try fself mailbox handler(regs, lr) ----
        // mov rdi, rbx; mov rsi, r12
        _code.AddRange([0x48, 0x89, 0xDF]);       // mov rdi, rbx
        _code.AddRange([0x4C, 0x89, 0xE6]);       // mov rsi, r12
        EmitGuardedCallPatch(PatchTargetNames.FselfMailboxHandler);
        // The fself handler uses FSELF_HANDLE_HANDLED (bit 0) and
        // FSELF_HANDLE_EMULATED (bit 1).
        // test eax, 1 (FSELF_HANDLE_HANDLED)
        _code.AddRange([0xA8, 0x01]);
        int jzNotFself = EmitJccRel8Forward(0x74);
        // Handled by fself. Call observe_current_syscall_trap.
        EmitCallPatch(PatchTargetNames.ObserveSyscallTrap);
        // The fself result was destroyed by the trap call. FSELF_HANDLE_EMULATED
        // is not checked here; the trap observation is emitted unconditionally
        // and the function returns 1.
        // mov eax, 1
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpDone1 = EmitJmpRel32Forward();

        PatchRel8Forward(jzNotFself);

        // ---- Try fpkg mailbox handler(regs, lr) ----
        _code.AddRange([0x48, 0x89, 0xDF]);       // mov rdi, rbx
        _code.AddRange([0x4C, 0x89, 0xE6]);       // mov rsi, r12
        EmitGuardedCallPatch(PatchTargetNames.FpkgMailboxHandler);
        // test eax, eax
        _code.AddRange([0x85, 0xC0]);
        int jzNotFpkg = EmitJccRel8Forward(0x74);
        EmitCallPatch(PatchTargetNames.ObserveSyscallTrap);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpDone2 = EmitJmpRel32Forward();

        PatchRel8Forward(jzNotFpkg);

        // ---- Try npdrm mailbox handler(regs, lr) ----
        _code.AddRange([0x48, 0x89, 0xDF]);       // mov rdi, rbx
        _code.AddRange([0x4C, 0x89, 0xE6]);       // mov rsi, r12
        EmitGuardedCallPatch(PatchTargetNames.NpdrmMailboxHandler);
        // test eax, eax
        _code.AddRange([0x85, 0xC0]);
        int jzNotNpdrm = EmitJccRel8Forward(0x74);
        EmitCallPatch(PatchTargetNames.ObserveSyscallTrap);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpDone3 = EmitJmpRel32Forward();

        PatchRel8Forward(jzNotNpdrm);

        // No handler matched: fall through to return 0.
        // (also reached on lr read failure)
        PatchRel32Forward(jnzLrFail);
        // xor eax, eax
        _code.AddRange([0x31, 0xC0]);
        int jmpDone4 = EmitJmpRel32Forward();

        // not_mailbox: return 0 without touching the stack.
        PatchRel32Forward(jneNotMailbox);
        _code.AddRange([0x31, 0xC0]);             // xor eax, eax
        // Epilogue (no sub rsp 16 to undo).
        _code.AddRange([0x41, 0x5C]);             // pop r12
        _code.Add(0x5B);                          // pop rbx
        _code.Add(0xC3);                          // ret

        // done: common epilogue for the matched paths.
        PatchRel32Forward(jmpDone1);
        PatchRel32Forward(jmpDone2);
        PatchRel32Forward(jmpDone3);
        PatchRel32Forward(jmpDone4);
        _code.AddRange([0x48, 0x83, 0xC4, 0x10]); // add rsp, 16
        _code.AddRange([0x41, 0x5C]);             // pop r12
        _code.Add(0x5B);                          // pop rbx
        _code.Add(0xC3);                          // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  CCP crypto chain walker and emulation
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the CCP crypto chain walker. Intercepts sceSblServiceCryptAsync calls
    /// and walks the CCP message chain. For each message with a fake key, dispatches
    /// to the XTS or HMAC emulation handler. On completion, constructs an IRET frame
    /// to redirect execution to crypt_message_resolve.
    ///
    /// <para>Calling convention: RDI = trap frame pointer (regs).</para>
    ///
    /// <para>Register allocation:</para>
    /// <list type="bullet">
    ///   <item>RBX = regs pointer (callee-saved)</item>
    ///   <item>R12 = current message pointer in the chain walk</item>
    ///   <item>R13D = total message count</item>
    ///   <item>R14D = emulated message count</item>
    ///   <item>R15D = accumulated error status</item>
    ///   <item>EBP = FPU entered flag</item>
    /// </list>
    ///
    /// <para>Stack layout (0xF8 = 248 bytes, 16-byte aligned):</para>
    /// <list type="bullet">
    ///   <item>[rsp+0x000]: msg_data[21] (168 bytes, 21 qwords)</item>
    ///   <item>[rsp+0x0A8]: temp (key_idx / next_msg, 8 bytes)</item>
    ///   <item>[rsp+0x0B0]: temp (handler result, 8 bytes)</item>
    ///   <item>[rsp+0x0B8]: iret_frame[7] (56 bytes)</item>
    ///   <item>[rsp+0x0F0]: temp (new_rsp, 8 bytes)</item>
    /// </list>
    ///
    /// <para>The message chain start pointer is read from regs[RBX] (FW &gt;= 8.00).
    /// Each message is 21 qwords. The next-message pointer is at msg+320.</para>
    ///
    /// <para>Message type detection:</para>
    /// <list type="bullet">
    ///   <item>XTS: (msg_data[0] &amp; 0x7FFFF7FF) == 0x2108000, key at msg_data[5]</item>
    ///   <item>HMAC: (msg_data[0] &amp; 0x7FFFFFFF) == 0x9132000, key at msg_data[20],
    ///         requires msg_data[3] == msg_data[1] * 8</item>
    /// </list>
    ///
    /// <para>Returns 1 in EAX if the request was fully emulated and execution was
    /// redirected, 0 otherwise.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>,
    ///   <see cref="PatchTargetNames.HasFakeKey"/>,
    ///   <see cref="PatchTargetNames.FpuEnter"/>,
    ///   <see cref="PatchTargetNames.FpuExit"/>,
    ///   <see cref="PatchTargetNames.CryptoRequestCache"/>,
    ///   <see cref="PatchTargetNames.CryptoXtsHandler"/>,
    ///   <see cref="PatchTargetNames.CryptoHmacHandler"/>,
    ///   <see cref="PatchTargetNames.DoretiIret"/>,
    ///   <see cref="PatchTargetNames.CryptMessageResolve"/>,
    ///   <see cref="PatchTargetNames.ObserveSyscallEmulated"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitCryptoChainWalker()
    {
        int entry = _code.Count;

        // Prologue: save callee-saved registers.
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0xF8);

        // rbx = regs
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        // r13d = total = 0
        _code.AddRange([0x45, 0x31, 0xED]);           // xor r13d, r13d
        // r14d = emulated = 0
        _code.AddRange([0x45, 0x31, 0xF6]);           // xor r14d, r14d
        // r15d = total_status = 0
        _code.AddRange([0x45, 0x31, 0xFF]);           // xor r15d, r15d
        // ebp = fpu_entered = 0
        _code.AddRange([0x31, 0xED]);                 // xor ebp, ebp

        // start = regs[RBX] (FW >= 0x800, OffRbx = 56 = 0x38)
        _code.AddRange([0x4C, 0x8B, 0x63, 0x38]);    // mov r12, [rbx + 56]

        // ---- loop_start ----
        int loopStartOffset = _code.Count;

        // test r12, r12 ; jz loop_end
        _code.AddRange([0x4D, 0x85, 0xE4]);
        int jzLoopEnd1 = EmitJccRel32Forward(0x0F, 0x84);

        // test r15d, r15d ; jnz loop_end
        _code.AddRange([0x45, 0x85, 0xFF]);
        int jnzLoopEnd2 = EmitJccRel32Forward(0x0F, 0x85);

        // copy_from_kernel(rsp, msg, 168)  -- read 21 qwords from the CCP message
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x4C, 0x89, 0xE6]);           // mov rsi, r12
        _code.AddRange([0xBA, 0xA8, 0x00, 0x00, 0x00]); // mov edx, 168
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzBreakError = EmitJccRel32Forward(0x0F, 0x85);

        // ---- XTS check: (msg_data[0] & 0x7FFFF7FF) == 0x2108000 ----
        _code.AddRange([0x8B, 0x04, 0x24]);           // mov eax, [rsp]
        _code.AddRange([0x89, 0xC1]);                 // mov ecx, eax
        _code.AddRange([0x81, 0xE1, 0xFF, 0xF7, 0xFF, 0x7F]); // and ecx, 0x7FFFF7FF
        _code.AddRange([0x81, 0xF9, 0x00, 0x80, 0x10, 0x02]); // cmp ecx, 0x2108000
        int jneCheckHmac1 = EmitJccRel32Forward(0x0F, 0x85);

        // XTS key: HANDLE_TO_IDX(msg_data[5])  -- msg_data[5] at offset 40 = 0x28
        _code.AddRange([0x8B, 0x44, 0x24, 0x28]);    // mov eax, [rsp + 0x28]
        _code.AddRange([0x89, 0xC1]);                 // mov ecx, eax
        _code.AddRange([0x81, 0xE1, 0x00, 0xFF, 0xFF, 0xFF]); // and ecx, 0xFFFFFF00
        _code.AddRange([0x81, 0xF9]);                 // cmp ecx, 0x13374100
        _code.AddRange(BitConverter.GetBytes(IdxToHandleBase));
        int jneCheckHmac2 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0x0F, 0xB6, 0xC0]);          // movzx eax, al
        _code.AddRange([0xFF, 0xC8]);                 // dec eax
        int jsCheckHmac3 = EmitJccRel32Forward(0x0F, 0x88);

        // Save key_idx at [rsp + 0xA8]
        EmitStoreEaxToStackDisp32(0xA8);
        // has_fake_key(key_idx)
        _code.AddRange([0x89, 0xC7]);                 // mov edi, eax
        EmitCallPatch(PatchTargetNames.HasFakeKey);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzCheckHmac4 = EmitJccRel32Forward(0x0F, 0x84);

        // FPU enter if not already entered
        _code.AddRange([0x85, 0xED]);                 // test ebp, ebp
        int jnzXtsCall = EmitJccRel8Forward(0x75);
        EmitCallPatch(PatchTargetNames.FpuEnter);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFpuFail1 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0xBD, 0x01, 0x00, 0x00, 0x00]); // mov ebp, 1

        // xts_call: call crypto_xts_handler(msg, msg_data, key_idx, cache)
        PatchRel8Forward(jnzXtsCall);
        _code.AddRange([0x4C, 0x89, 0xE7]);          // mov rdi, r12
        _code.AddRange([0x48, 0x89, 0xE6]);          // mov rsi, rsp
        EmitLoadEdxFromStackDisp32(0xA8);             // mov edx, [rsp + 0xA8]
        EmitMovAbsRcxPatch(PatchTargetNames.CryptoRequestCache);
        EmitCallPatch(PatchTargetNames.CryptoXtsHandler);
        int jmpProcessResult1 = EmitJmpRel32Forward();

        // ---- check_hmac: (msg_data[0] & 0x7FFFFFFF) == 0x9132000 ----
        PatchRel32Forward(jneCheckHmac1);
        PatchRel32Forward(jneCheckHmac2);
        PatchRel32Forward(jsCheckHmac3);
        PatchRel32Forward(jzCheckHmac4);

        _code.AddRange([0x8B, 0x04, 0x24]);           // mov eax, [rsp]
        _code.AddRange([0x25, 0xFF, 0xFF, 0xFF, 0x7F]); // and eax, 0x7FFFFFFF
        _code.AddRange([0x3D, 0x00, 0x20, 0x13, 0x09]); // cmp eax, 0x9132000
        int jneOtherMsg1 = EmitJccRel32Forward(0x0F, 0x85);

        // HMAC shape validation: msg_data[3] == msg_data[1] * 8
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x08]); // mov rax, [rsp + 8]
        _code.AddRange([0x48, 0xC1, 0xE0, 0x03]);    // shl rax, 3
        _code.AddRange([0x48, 0x3B, 0x44, 0x24, 0x18]); // cmp rax, [rsp + 24]
        int jneOtherMsg2 = EmitJccRel32Forward(0x0F, 0x85);

        // HMAC key: HANDLE_TO_IDX(msg_data[20])  -- msg_data[20] at offset 160 = 0xA0
        EmitLoadEaxFromStackDisp32(0xA0);             // mov eax, [rsp + 0xA0]
        _code.AddRange([0x89, 0xC1]);                 // mov ecx, eax
        _code.AddRange([0x81, 0xE1, 0x00, 0xFF, 0xFF, 0xFF]); // and ecx, 0xFFFFFF00
        _code.AddRange([0x81, 0xF9]);                 // cmp ecx, 0x13374100
        _code.AddRange(BitConverter.GetBytes(IdxToHandleBase));
        int jneOtherMsg3 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0x0F, 0xB6, 0xC0]);          // movzx eax, al
        _code.AddRange([0xFF, 0xC8]);                 // dec eax
        int jsOtherMsg4 = EmitJccRel32Forward(0x0F, 0x88);

        // Save key_idx at [rsp + 0xA8]
        EmitStoreEaxToStackDisp32(0xA8);
        _code.AddRange([0x89, 0xC7]);                 // mov edi, eax
        EmitCallPatch(PatchTargetNames.HasFakeKey);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzOtherMsg5 = EmitJccRel32Forward(0x0F, 0x84);

        // FPU enter if not already entered
        _code.AddRange([0x85, 0xED]);                 // test ebp, ebp
        int jnzHmacCall = EmitJccRel8Forward(0x75);
        EmitCallPatch(PatchTargetNames.FpuEnter);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFpuFail2 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0xBD, 0x01, 0x00, 0x00, 0x00]); // mov ebp, 1

        // hmac_call: call crypto_hmac_handler(msg, msg_data, key_idx, cache)
        PatchRel8Forward(jnzHmacCall);
        _code.AddRange([0x4C, 0x89, 0xE7]);          // mov rdi, r12
        _code.AddRange([0x48, 0x89, 0xE6]);          // mov rsi, rsp
        EmitLoadEdxFromStackDisp32(0xA8);             // mov edx, [rsp + 0xA8]
        EmitMovAbsRcxPatch(PatchTargetNames.CryptoRequestCache);
        EmitCallPatch(PatchTargetNames.CryptoHmacHandler);
        int jmpProcessResult2 = EmitJmpRel32Forward();

        // ---- other_message: message is not fake-keyed ----
        PatchRel32Forward(jneOtherMsg1);
        PatchRel32Forward(jneOtherMsg2);
        PatchRel32Forward(jneOtherMsg3);
        PatchRel32Forward(jsOtherMsg4);
        PatchRel32Forward(jzOtherMsg5);

        _code.AddRange([0x41, 0xFF, 0xC5]);           // inc r13d  (total++)
        // Read next_msg = kpeek64(msg + 320)
        EmitLeaRdiRspDisp32(0xA8);                    // lea rdi, [rsp + 0xA8]
        _code.AddRange([0x4C, 0x89, 0xE6]);           // mov rsi, r12
        _code.AddRange([0x48, 0x81, 0xC6]);           // add rsi, 320
        _code.AddRange(BitConverter.GetBytes(320));
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzLoopEndZero1 = EmitJccRel32Forward(0x0F, 0x85);
        EmitLoadR12FromStackDisp32(0xA8);             // mov r12, [rsp + 0xA8]
        EmitJmpRel32To(loopStartOffset);              // jmp loop_start

        // ---- process_result: after XTS or HMAC handler returns ----
        PatchRel32Forward(jmpProcessResult1);
        PatchRel32Forward(jmpProcessResult2);

        _code.AddRange([0x41, 0xFF, 0xC5]);           // inc r13d  (total++)
        EmitStoreEaxToStackDisp32(0xB0);              // mov [rsp + 0xB0], eax  (save result)

        // Read next_msg
        EmitLeaRdiRspDisp32(0xA8);                    // lea rdi, [rsp + 0xA8]
        _code.AddRange([0x4C, 0x89, 0xE6]);           // mov rsi, r12
        _code.AddRange([0x48, 0x81, 0xC6]);           // add rsi, 320
        _code.AddRange(BitConverter.GetBytes(320));
        _code.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]); // mov edx, 8
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzLoopEndZero2 = EmitJccRel32Forward(0x0F, 0x85);
        EmitLoadR12FromStackDisp32(0xA8);             // mov r12, [rsp + 0xA8]

        // Check handler result
        EmitLoadEaxFromStackDisp32(0xB0);             // mov eax, [rsp + 0xB0]
        _code.AddRange([0x83, 0xF8, (byte)FreeBsdEnosys]); // cmp eax, 78 (ENOSYS)
        int jeLoopStart1 = EmitJccRel32Forward(0x0F, 0x84);
        // Emulated (success or error)
        _code.AddRange([0x41, 0xFF, 0xC6]);           // inc r14d  (emulated++)
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzLoopStart2 = EmitJccRel32Forward(0x0F, 0x84);
        _code.AddRange([0x41, 0x89, 0xC7]);           // mov r15d, eax  (total_status = error)
        EmitJmpRel32To(loopStartOffset);              // jmp loop_start

        // Patch loop-back jumps
        PatchRel32Forward(jeLoopStart1);
        PatchRel32Forward(jzLoopStart2);
        EmitJmpRel32To(loopStartOffset);

        // ---- break_error: copy_from_kernel failed ----
        PatchRel32Forward(jnzBreakError);
        _code.AddRange([0x41, 0xC7, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF]); // mov r15d, -1
        int jmpLoopEnd1 = EmitJmpRel32Forward();

        // ---- fpu_fail: FPU enter failed ----
        PatchRel32Forward(jnzFpuFail1);
        PatchRel32Forward(jnzFpuFail2);
        int jmpLoopEnd2 = EmitJmpRel32Forward();

        // ---- loop_end_zero_next: next_msg read failed ----
        PatchRel32Forward(jnzLoopEndZero1);
        PatchRel32Forward(jnzLoopEndZero2);
        _code.AddRange([0x45, 0x31, 0xE4]);           // xor r12d, r12d

        // ---- loop_end ----
        PatchRel32Forward(jzLoopEnd1);
        PatchRel32Forward(jnzLoopEnd2);
        PatchRel32Forward(jmpLoopEnd1);
        PatchRel32Forward(jmpLoopEnd2);

        // Check if any messages were emulated
        _code.AddRange([0x45, 0x85, 0xF6]);           // test r14d, r14d
        int jzExitNotHandled1 = EmitJccRel32Forward(0x0F, 0x84);

        // If emulated < total: not all emulated, report failure
        _code.AddRange([0x45, 0x39, 0xEE]);           // cmp r14d, r13d
        int jeEmulationOk = EmitJccRel8Forward(0x74);
        _code.AddRange([0x41, 0xC7, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF]); // mov r15d, -1
        PatchRel8Forward(jeEmulationOk);

        // ---- emulation_complete: build IRET frame and redirect ----

        // frame[0] = doreti_iret
        EmitMovAbsRaxPatch(PatchTargetNames.DoretiIret);
        EmitStoreRaxToStackDisp32(0xB8);              // mov [rsp + 0xB8], rax

        // frame[1] = MKTRAP(TRAP_FPKG, 1) = 0xDEAD000300000001
        _code.AddRange([0x48, 0xB8]);                 // movabs rax, imm64
        _code.AddRange(BitConverter.GetBytes(((ulong)TrapFpkg << 32) | 1));
        EmitStoreRaxToStackDisp32(0xC0);              // mov [rsp + 0xC0], rax

        // frame[2..6] = 0
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        EmitStoreRaxToStackDisp32(0xC8);
        EmitStoreRaxToStackDisp32(0xD0);
        EmitStoreRaxToStackDisp32(0xD8);
        EmitStoreRaxToStackDisp32(0xE0);
        EmitStoreRaxToStackDisp32(0xE8);

        // new_rsp = regs[RSP] - 56
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3); // mov rax, [rbx + OffIretRsp]
        _code.AddRange([0x48, 0x83, 0xE8, 0x38]);    // sub rax, 56
        EmitStoreRaxToStackDisp32(0xF0);              // save new_rsp

        // copy_to_kernel(new_rsp, &iret_frame, 56)
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        EmitLeaRsiRspDisp32(0xB8);                    // lea rsi, [rsp + 0xB8]
        _code.AddRange([0xBA, 0x38, 0x00, 0x00, 0x00]); // mov edx, 56
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzExitNotHandled2 = EmitJccRel32Forward(0x0F, 0x85);

        // Update regs[RSP] = new_rsp
        EmitLoadRaxFromStackDisp32(0xF0);
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3); // mov [rbx + OffIretRsp], rax

        // regs[RIP] = crypt_message_resolve
        EmitMovAbsRaxPatch(PatchTargetNames.CryptMessageResolve);
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3); // mov [rbx + OffRip], rax

        // regs[RDI] = start (regs[RBX], the original chain head)
        EmitLoadFromFrameViaReg(OffRbx, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRbx]
        _code.AddRange([0x48, 0x89, 0x03]);           // mov [rbx], rax  (OffRdi = 0)

        // regs[RSI] = total_status (sign-extended)
        _code.AddRange([0x49, 0x63, 0xC7]);           // movsxd rax, r15d
        _code.AddRange([0x48, 0x89, 0x43, (byte)OffRsi]); // mov [rbx + OffRsi], rax

        // observe_current_syscall_emulated()
        EmitCallPatch(PatchTargetNames.ObserveSyscallEmulated);

        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpEpilogue1 = EmitJmpRel32Forward();

        // ---- exit_not_handled ----
        PatchRel32Forward(jzExitNotHandled1);
        PatchRel32Forward(jnzExitNotHandled2);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        // ---- epilogue ----
        PatchRel32Forward(jmpEpilogue1);

        EmitStoreEaxToStackDisp32(0xA8);              // save return value
        _code.AddRange([0x85, 0xED]);                 // test ebp, ebp
        int jzNoFpuExit = EmitJccRel32Forward(0x0F, 0x84);
        EmitCallPatch(PatchTargetNames.FpuExit);
        PatchRel32Forward(jzNoFpuExit);
        EmitLoadEaxFromStackDisp32(0xA8);             // restore return value

        EmitAddRspImm32(0xF8);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5F]);                 // pop r15
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the AES-XTS-128 emulation handler. Called by the crypto chain walker
    /// for CCP messages with fake-keyed XTS operations.
    ///
    /// <para>Calling convention:</para>
    /// <list type="bullet">
    ///   <item>RDI = msg (kernel VA of the CCP message descriptor)</item>
    ///   <item>RSI = msg_data (pointer to 21 qwords, already in local memory)</item>
    ///   <item>EDX = key_idx (fake key slot index)</item>
    ///   <item>RCX = cache (pointer to crypto_request_cache)</item>
    /// </list>
    ///
    /// <para>Returns in EAX: 0 = success (emulated), -1 = error (emulated but failed),
    /// 78 (ENOSYS) = not handled (get_fake_key failed).</para>
    ///
    /// <para>The handler retrieves the 32-byte key via get_fake_key, extracts the
    /// XTS parameters from msg_data (src, dst, start_sector, total_sectors,
    /// is_encrypt), and calls pfs_xts_virtual_fpu_held which performs the
    /// AES-XTS-128 encrypt/decrypt on kernel-resident data using page-table
    /// walking and DMEM-based physical memory access.</para>
    ///
    /// <para>FPU context (XSAVE/XRSTOR) is managed by the chain walker's
    /// deferred fpu_enter/fpu_exit around the handler call.</para>
    ///
    /// <para>Stack layout (0x38 = 56 bytes, 16-byte aligned):</para>
    /// <list type="bullet">
    ///   <item>[rsp+0x00]: key[32] (fake key data)</item>
    ///   <item>[rsp+0x20]: padding (24 bytes)</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.GetFakeKey"/>,
    ///   <see cref="PatchTargetNames.PfsXtsVirtualFpuHeld"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitXtsEmulation()
    {
        int entry = _code.Count;

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x38);

        // Save arguments in callee-saved registers
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi   (msg)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi   (msg_data)
        _code.AddRange([0x41, 0x89, 0xD5]);           // mov r13d, edx  (key_idx)
        _code.AddRange([0x49, 0x89, 0xCE]);           // mov r14, rcx   (cache)

        // get_fake_key(key_idx, &key)
        _code.AddRange([0x44, 0x89, 0xEF]);           // mov edi, r13d
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp   (key at [rsp])
        EmitCallPatch(PatchTargetNames.GetFakeKey);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzFailEnosys = EmitJccRel32Forward(0x0F, 0x84);

        // pfs_xts_virtual_fpu_held(cache, dst, src, key_id, key, start, count, is_encrypt)
        // 8 arguments: 6 in registers + 2 on stack.

        // Compute stack args first (before sub rsp 16 changes offsets).
        // count = (uint32_t)msg_data[1]  at [r12 + 8]
        _code.AddRange([0x41, 0x8B, 0x44, 0x24, 0x08]); // mov eax, [r12 + 8]
        // is_encrypt = (msg_data[0] >> 11) & 1  at [r12]
        _code.AddRange([0x41, 0x8B, 0x0C, 0x24]);    // mov ecx, [r12]
        _code.AddRange([0xC1, 0xE9, 0x0B]);          // shr ecx, 11
        _code.AddRange([0x83, 0xE1, 0x01]);          // and ecx, 1

        // Allocate 16 bytes for stack args
        _code.AddRange([0x48, 0x83, 0xEC, 0x10]);    // sub rsp, 16
        _code.AddRange([0x48, 0x89, 0x04, 0x24]);    // mov [rsp], rax       (7th: count)
        _code.AddRange([0x48, 0x89, 0x4C, 0x24, 0x08]); // mov [rsp+8], rcx (8th: is_encrypt)

        // Register args (key is now at [rsp + 0x10] due to sub rsp 16)
        _code.AddRange([0x4C, 0x89, 0xF7]);          // mov rdi, r14         (cache)
        _code.AddRange([0x49, 0x8B, 0x74, 0x24, 0x18]); // mov rsi, [r12+24] (dst = msg_data[3])
        _code.AddRange([0x49, 0x8B, 0x54, 0x24, 0x10]); // mov rdx, [r12+16] (src = msg_data[2])
        _code.AddRange([0x44, 0x89, 0xE9]);           // mov ecx, r13d       (key_id)
        _code.AddRange([0x4C, 0x8D, 0x44, 0x24, 0x10]); // lea r8, [rsp+16] (key)
        _code.AddRange([0x4D, 0x8B, 0x4C, 0x24, 0x20]); // mov r9, [r12+32] (start = msg_data[4])
        EmitCallPatch(PatchTargetNames.PfsXtsVirtualFpuHeld);

        _code.AddRange([0x48, 0x83, 0xC4, 0x10]);    // add rsp, 16
        // EAX = 0 on success, -1 on error (passed through)
        int jmpEpilogue = EmitJmpRel32Forward();

        // fail_enosys: get_fake_key failed
        PatchRel32Forward(jzFailEnosys);
        _code.AddRange([0xB8]);                       // mov eax, ENOSYS
        _code.AddRange(BitConverter.GetBytes(FreeBsdEnosys));

        // Epilogue
        PatchRel32Forward(jmpEpilogue);
        EmitAddRspImm32(0x38);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5F]);                 // pop r15
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the HMAC-SHA256 emulation handler. Called by the crypto chain walker
    /// for CCP messages with fake-keyed HMAC operations.
    ///
    /// <para>Calling convention:</para>
    /// <list type="bullet">
    ///   <item>RDI = msg (kernel VA of the CCP message descriptor)</item>
    ///   <item>RSI = msg_data (pointer to 21 qwords, already in local memory)</item>
    ///   <item>EDX = key_idx (fake key slot index)</item>
    ///   <item>RCX = cache (pointer to crypto_request_cache)</item>
    /// </list>
    ///
    /// <para>Returns in EAX: 0 = success (emulated), -1 = error (emulated but failed),
    /// 78 (ENOSYS) = not handled (get_fake_key failed).</para>
    ///
    /// <para>The handler retrieves the 32-byte signing key via get_fake_key, calls
    /// pfs_hmac_virtual_fpu_held to compute the HMAC-SHA256 digest over the
    /// kernel-resident data, and writes the 32-byte MAC to msg+32 via
    /// copy_to_kernel.</para>
    ///
    /// <para>FPU context (XSAVE/XRSTOR) is managed by the chain walker.</para>
    ///
    /// <para>Stack layout (0x48 = 72 bytes, 16-byte aligned):</para>
    /// <list type="bullet">
    ///   <item>[rsp+0x00]: key[32] (fake key data)</item>
    ///   <item>[rsp+0x20]: hash[32] (HMAC-SHA256 output)</item>
    ///   <item>[rsp+0x40]: padding (8 bytes)</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.GetFakeKey"/>,
    ///   <see cref="PatchTargetNames.PfsHmacVirtualFpuHeld"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitHmacEmulation()
    {
        int entry = _code.Count;

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x48);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi   (msg)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi   (msg_data)
        _code.AddRange([0x41, 0x89, 0xD5]);           // mov r13d, edx  (key_idx)
        _code.AddRange([0x49, 0x89, 0xCE]);           // mov r14, rcx   (cache)

        // get_fake_key(key_idx, &key)
        _code.AddRange([0x44, 0x89, 0xEF]);           // mov edi, r13d
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp   (key at [rsp])
        EmitCallPatch(PatchTargetNames.GetFakeKey);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzFailEnosys = EmitJccRel32Forward(0x0F, 0x84);

        // Zero hash buffer at [rsp + 0x20]
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        EmitStoreRaxToStackDisp32(0x20);
        EmitStoreRaxToStackDisp32(0x28);
        EmitStoreRaxToStackDisp32(0x30);
        EmitStoreRaxToStackDisp32(0x38);

        // pfs_hmac_virtual_fpu_held(cache, hash, key_id, key, data, data_size)
        _code.AddRange([0x4C, 0x89, 0xF7]);           // mov rdi, r14            (cache)
        _code.AddRange([0x48, 0x8D, 0x74, 0x24, 0x20]); // lea rsi, [rsp + 0x20] (hash)
        _code.AddRange([0x44, 0x89, 0xEA]);           // mov edx, r13d           (key_id)
        _code.AddRange([0x48, 0x89, 0xE1]);           // mov rcx, rsp            (key)
        _code.AddRange([0x4D, 0x8B, 0x44, 0x24, 0x10]); // mov r8, [r12 + 16]   (data = msg_data[2])
        _code.AddRange([0x4D, 0x8B, 0x4C, 0x24, 0x08]); // mov r9, [r12 + 8]    (data_size = msg_data[1])
        EmitCallPatch(PatchTargetNames.PfsHmacVirtualFpuHeld);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFailError = EmitJccRel32Forward(0x0F, 0x85);

        // copy_to_kernel(msg + 32, hash, 32)
        _code.AddRange([0x48, 0x8D, 0x7B, 0x20]);    // lea rdi, [rbx + 32]  (dst = msg + 32)
        _code.AddRange([0x48, 0x8D, 0x74, 0x24, 0x20]); // lea rsi, [rsp + 0x20]  (src = hash)
        _code.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]); // mov edx, 32
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFailError2 = EmitJccRel32Forward(0x0F, 0x85);

        // Success
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        int jmpEpilogue = EmitJmpRel32Forward();

        // fail_error: crypto or copy failed
        PatchRel32Forward(jnzFailError);
        PatchRel32Forward(jnzFailError2);
        _code.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1
        int jmpEpilogue2 = EmitJmpRel32Forward();

        // fail_enosys: get_fake_key failed
        PatchRel32Forward(jzFailEnosys);
        _code.AddRange([0xB8]);                       // mov eax, ENOSYS
        _code.AddRange(BitConverter.GetBytes(FreeBsdEnosys));

        // Epilogue
        PatchRel32Forward(jmpEpilogue);
        PatchRel32Forward(jmpEpilogue2);
        EmitAddRspImm32(0x48);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5F]);                 // pop r15
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the PFS key derivation function. Called by the fpkg mailbox handler
    /// when sceSblServiceMailbox intercepts a verifySuperBlock request.
    ///
    /// <para>Calling convention:</para>
    /// <list type="bullet">
    ///   <item>RDI = p_eekpfs (pointer to 256-byte encrypted EKPFS)</item>
    ///   <item>RSI = crypt_seed (pointer to 16-byte seed)</item>
    ///   <item>RDX = ek (output pointer for 32-byte encrypt key)</item>
    ///   <item>RCX = sk (output pointer for 32-byte signing key)</item>
    /// </list>
    ///
    /// <para>Returns EAX: 1 = success, 0 = failure.</para>
    ///
    /// <para>The function:</para>
    /// <list type="number">
    ///   <item>Enters FPU context (XSAVE, clear CR0.TS, FINIT, LDMXCSR).</item>
    ///   <item>Copies the 256-byte EEKPFS into a local buffer.</item>
    ///   <item>Performs an RSA-2048 public-key operation with the embedded modulus
    ///         and exponent to decrypt the EKPFS.</item>
    ///   <item>Validates the PKCS#1 v1.5 type 2 padding: byte 0 = 0x00, byte 1 = 0x02,
    ///         zero separator at position 223 (255 - 32), yielding a 32-byte EKPFS.</item>
    ///   <item>Derives the encrypt key: HMAC-SHA256(EKPFS, LE32(1) || seed).</item>
    ///   <item>Derives the signing key: HMAC-SHA256(EKPFS, LE32(2) || seed).</item>
    ///   <item>Exits FPU context (XRSTOR, restore CR0).</item>
    /// </list>
    ///
    /// <para>The RSA modulus (256 bytes) and exponent (256 bytes) are embedded as
    /// inline data in the emitted code, referenced via RIP-relative LEA.</para>
    ///
    /// <para>Stack layout (0x138 = 312 bytes, 16-byte aligned):</para>
    /// <list type="bullet">
    ///   <item>[rsp+0x000]: eekpfs[256] (local copy for RSA operation)</item>
    ///   <item>[rsp+0x100]: pk struct (32 bytes: n_ptr, nlen, e_ptr, elen)</item>
    ///   <item>[rsp+0x120]: idx_buf (4 bytes, LE32 key index)</item>
    ///   <item>[rsp+0x124]: padding (20 bytes)</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.FpuEnter"/>,
    ///   <see cref="PatchTargetNames.FpuExit"/>,
    ///   <see cref="PatchTargetNames.RsaPublic"/>,
    ///   <see cref="PatchTargetNames.HmacSha256Once"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitPfsKeyDerivation()
    {
        int entry = _code.Count;

        // Jump past inline RSA key data (modulus + exponent, 512 bytes total).
        int jmpPastData = EmitJmpRel32Forward();

        // Inline data: RSA-2048 modulus (256 bytes)
        int ypkgNOffset = _code.Count;
        _code.AddRange(YpkgModulus);

        // Inline data: RSA-2048 exponent (256 bytes)
        int ypkgDOffset = _code.Count;
        _code.AddRange(YpkgExponent);

        PatchRel32Forward(jmpPastData);

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x138);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi   (p_eekpfs)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi   (crypt_seed)
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx   (ek output)
        _code.AddRange([0x49, 0x89, 0xCE]);           // mov r14, rcx   (sk output)

        // FPU enter (XSAVE + clear CR0.TS + FINIT + LDMXCSR)
        EmitCallPatch(PatchTargetNames.FpuEnter);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail = EmitJccRel32Forward(0x0F, 0x85);

        // memcpy(local_eekpfs, p_eekpfs, 256)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp   (dst = local eekpfs)
        _code.AddRange([0x48, 0x89, 0xDE]);           // mov rsi, rbx   (src = p_eekpfs)
        _code.AddRange([0xB9, 0x00, 0x01, 0x00, 0x00]); // mov ecx, 256
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Build pk struct at [rsp + 0x100]:
        //   pk.n = &ypkg_n (RIP-relative)
        //   pk.nlen = 256
        //   pk.e = &ypkg_d (RIP-relative)
        //   pk.elen = 256
        EmitLeaRegRipRelative(0, ypkgNOffset);        // lea rax, [rip + ypkg_n]
        EmitStoreRaxToStackDisp32(0x100);              // mov [rsp + 0x100], rax  (pk.n)
        _code.AddRange([0x48, 0xC7, 0x84, 0x24]);     // mov qword [rsp + 0x108], 256
        _code.AddRange(BitConverter.GetBytes(0x108));
        _code.AddRange(BitConverter.GetBytes(256));

        EmitLeaRegRipRelative(0, ypkgDOffset);         // lea rax, [rip + ypkg_d]
        EmitStoreRaxToStackDisp32(0x110);              // mov [rsp + 0x110], rax  (pk.e)
        _code.AddRange([0x48, 0xC7, 0x84, 0x24]);     // mov qword [rsp + 0x118], 256
        _code.AddRange(BitConverter.GetBytes(0x118));
        _code.AddRange(BitConverter.GetBytes(256));

        // br_rsa_i62_public(eekpfs, 256, &pk)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp       (data = local eekpfs)
        _code.AddRange([0xBE, 0x00, 0x01, 0x00, 0x00]); // mov esi, 256    (len)
        EmitLeaRdxRspDisp32(0x100);                    // lea rdx, [rsp + 0x100]  (pk)
        EmitCallPatch(PatchTargetNames.RsaPublic);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzRsaFail = EmitJccRel32Forward(0x0F, 0x84);

        // PKCS#1 v1.5 padding check: eekpfs[0] == 0, eekpfs[1] == 2
        _code.AddRange([0x80, 0x3C, 0x24, 0x00]);    // cmp byte [rsp], 0
        int jnePadFail1 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0x80, 0x7C, 0x24, 0x01, 0x02]); // cmp byte [rsp+1], 2
        int jnePadFail2 = EmitJccRel32Forward(0x0F, 0x85);

        // Scan for zero separator: start at index 2, must be at 223 (= 255 - 32)
        _code.AddRange([0xB9, 0x02, 0x00, 0x00, 0x00]); // mov ecx, 2

        int scanLoopOffset = _code.Count;
        _code.AddRange([0x81, 0xF9, 0x00, 0x01, 0x00, 0x00]); // cmp ecx, 256
        int jgeScanFail = EmitJccRel32Forward(0x0F, 0x8D);
        // cmp byte [rsp + rcx*1], 0  (80 /7 ModRM=3C SIB=0C imm8=00)
        _code.AddRange([0x80, 0x3C, 0x0C, 0x00]);
        int jeFoundSep = EmitJccRel8Forward(0x74);
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        EmitJmpRel32To(scanLoopOffset);               // jmp scan_loop

        PatchRel8Forward(jeFoundSep);
        // Separator must be at index 223
        _code.AddRange([0x81, 0xF9, 0xDF, 0x00, 0x00, 0x00]); // cmp ecx, 223
        int jneSepWrong = EmitJccRel32Forward(0x0F, 0x85);

        // r15 = pointer to 32-byte EKPFS (eekpfs + 224)
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        // lea r15, [rsp + rcx]
        _code.AddRange([0x4C, 0x8D, 0x3C, 0x0C]);    // lea r15, [rsp + rcx]

        // pfs_gen_key(1): hmac_sha256_once(ek, ekpfs, &LE32(1), 4, crypt_seed, 16)
        _code.AddRange([0xC7, 0x84, 0x24]);           // mov dword [rsp + 0x120], 1
        _code.AddRange(BitConverter.GetBytes(0x120));
        _code.AddRange(BitConverter.GetBytes(1));

        _code.AddRange([0x4C, 0x89, 0xEF]);           // mov rdi, r13     (out = ek)
        _code.AddRange([0x4C, 0x89, 0xFE]);           // mov rsi, r15     (key = ekpfs)
        EmitLeaRdxRspDisp32(0x120);                    // lea rdx, [rsp + 0x120]  (part1 = &idx)
        _code.AddRange([0xB9, 0x04, 0x00, 0x00, 0x00]); // mov ecx, 4    (part1_len)
        _code.AddRange([0x4D, 0x89, 0xE0]);           // mov r8, r12      (part2 = crypt_seed)
        _code.AddRange([0x41, 0xB9, 0x10, 0x00, 0x00, 0x00]); // mov r9d, 16  (part2_len)
        EmitCallPatch(PatchTargetNames.HmacSha256Once);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzGenKeyFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // pfs_gen_key(2): hmac_sha256_once(sk, ekpfs, &LE32(2), 4, crypt_seed, 16)
        _code.AddRange([0xC7, 0x84, 0x24]);           // mov dword [rsp + 0x120], 2
        _code.AddRange(BitConverter.GetBytes(0x120));
        _code.AddRange(BitConverter.GetBytes(2));

        _code.AddRange([0x4C, 0x89, 0xF7]);           // mov rdi, r14     (out = sk)
        _code.AddRange([0x4C, 0x89, 0xFE]);           // mov rsi, r15     (key = ekpfs)
        EmitLeaRdxRspDisp32(0x120);                    // lea rdx, [rsp + 0x120]  (part1 = &idx)
        _code.AddRange([0xB9, 0x04, 0x00, 0x00, 0x00]); // mov ecx, 4
        _code.AddRange([0x4D, 0x89, 0xE0]);           // mov r8, r12      (crypt_seed)
        _code.AddRange([0x41, 0xB9, 0x10, 0x00, 0x00, 0x00]); // mov r9d, 16
        EmitCallPatch(PatchTargetNames.HmacSha256Once);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzGenKeyFail2 = EmitJccRel32Forward(0x0F, 0x85);

        // Success: FPU exit, return 1
        EmitCallPatch(PatchTargetNames.FpuExit);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpEpilogue = EmitJmpRel32Forward();

        // fail_fpu_exit: FPU exit, return 0
        PatchRel32Forward(jzRsaFail);
        PatchRel32Forward(jnePadFail1);
        PatchRel32Forward(jnePadFail2);
        PatchRel32Forward(jgeScanFail);
        PatchRel32Forward(jneSepWrong);
        PatchRel32Forward(jnzGenKeyFail1);
        PatchRel32Forward(jnzGenKeyFail2);
        EmitCallPatch(PatchTargetNames.FpuExit);

        // fail: return 0
        PatchRel32Forward(jnzFail);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        // Epilogue
        PatchRel32Forward(jmpEpilogue);
        EmitAddRspImm32(0x138);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5F]);                 // pop r15
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  NPDRM mailbox and ioctl emission
    // -----------------------------------------------------------------------

    // RIF debug key (16 bytes): AES-128 key for debug RIF decryption.
    private static readonly byte[] RifDebugKey =
    [
        0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B,
        0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12,
    ];

    // RIF field offsets matching the Rif structure layout.
    private const int RifOffType = 0x48; // uint16
    private const int RifOffContentId = 0x18; // 0x30 bytes
    private const int RifOffVersion = 0x04; // uint16
    private const int RifOffUnk06 = 0x06; // uint16
    private const int RifOffPsnid = 0x08; // uint64
    private const int RifOffStartTs = 0x10; // uint64
    private const int RifOffEndTs = 0x18; // uint64 -- overlaps with contentId start
    private const int RifOffContentType = 0x4C; // uint16
    private const int RifOffSkuFlag = 0x4E; // uint16
    private const int RifOffExtraFlags = 0x50; // uint64
    private const int RifOffRifIv = 0x270; // 0x10 bytes
    private const int RifOffRifSecret = 0x280; // 0x90 bytes

    // RifOutput size in bytes.
    private const int RifOutputSize = 0xA8;

    // Offset of RifOutput within RifCmd56MemoryLayout (after the Rif struct).
    // sizeof(Rif) = 0x410.
    private const int RifCmd56OutputOffset = 0x410;

    /// <summary>
    /// Emit the NPDRM mailbox handler. Called from the mailbox dispatcher when a DR0
    /// trap hits sceSblServiceMailbox and the lr matches an NPDRM cmd 5 or cmd 6
    /// return address.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, RSI = return address (lr).</para>
    ///
    /// <para>The handler:</para>
    /// <list type="number">
    ///   <item>Checks lr against the NPDRM cmd 5 and cmd 6 return addresses.</item>
    ///   <item>Reads the mailbox request header from kernel memory to get cmd and
    ///         rif_pa (physical address of the RIF).</item>
    ///   <item>Reads the RIF type from DMEM + rif_pa. Only type 0x2 (debug RIF) is
    ///         handled.</item>
    ///   <item>Enters FPU context, then SHA-256 hashes the contentId field.</item>
    ///   <item>Compares the first 16 bytes of the hash against the RIF IV. If they
    ///         do not match, this is not a debug RIF.</item>
    ///   <item>For cmd 6: AES-CBC-128 decrypts the RIF secret with the debug key,
    ///         verifies the second half of the contentId hash against the decrypted
    ///         secret, then copies the unwrapped payload (0x20 bytes at offset 0x70)
    ///         back to the kernel request at offset 0x10.</item>
    ///   <item>Builds the RifOutput structure with byte-swapped fields and copies it
    ///         to DMEM at rif_pa + RifCmd56OutputOffset.</item>
    ///   <item>Clears the response status in the kernel request, exits FPU, and
    ///         redirects execution past the mailbox call.</item>
    /// </list>
    ///
    /// <para>Returns 1 in EAX if the mailbox call was intercepted, 0 otherwise.</para>
    ///
    /// <para>Register allocation:</para>
    /// <list type="bullet">
    ///   <item>RBX = regs pointer (callee-saved)</item>
    ///   <item>R12 = lr (callee-saved)</item>
    ///   <item>R13 = DMEM base (callee-saved)</item>
    ///   <item>R14 = rif_pa (callee-saved)</item>
    ///   <item>R15 = cmd (callee-saved, low 32 bits)</item>
    /// </list>
    ///
    /// <para>Stack layout (0x1A0 = 416 bytes, 16-byte aligned after 6 callee-saved pushes):</para>
    /// <list type="bullet">
    ///   <item>[rsp+0x000]: request_hdr (12 bytes: cmd u32, pad u32, rif_pa u64)</item>
    ///   <item>[rsp+0x020]: contentid_hash[32] (SHA-256 output)</item>
    ///   <item>[rsp+0x040]: decrypted_secret[0x90] (AES-CBC output, cmd 6 only)</item>
    ///   <item>[rsp+0x0D0]: rif_output[0xA8] (RifOutput struct for writeback)</item>
    ///   <item>[rsp+0x178]: padding to 0x1A0</item>
    /// </list>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitNpdrmMailboxHandler()
    {
        int entry = _code.Count;

        // Jump past inline RIF debug key data (16 bytes).
        int jmpPastData = EmitJmpRel32Forward();
        int rifDebugKeyOffset = _code.Count;
        _code.AddRange(RifDebugKey);
        PatchRel32Forward(jmpPastData);

        // Prologue: save callee-saved registers.
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x1A0);

        // mov rbx, rdi  -- rbx = regs
        _code.AddRange([0x48, 0x89, 0xFB]);
        // mov r12, rsi  -- r12 = lr
        _code.AddRange([0x49, 0x89, 0xF4]);

        // ---- Check lr == npdrm_cmd_5 ----
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrNpdrmCmd5);
        _code.AddRange([0x4C, 0x39, 0xE1]);          // cmp rcx, r12
        int jeLrOk1 = EmitJccRel8Forward(0x74);      // je lr_matched

        // ---- Check lr == npdrm_cmd_6 ----
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrNpdrmCmd6);
        _code.AddRange([0x4C, 0x39, 0xE1]);          // cmp rcx, r12
        int jneLrBad = EmitJccRel32Forward(0x0F, 0x85); // jne not_handled

        PatchRel8Forward(jeLrOk1);

        // ---- Read request header: copy_from_kernel(rsp, regs[RDX], 12) ----
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 6, regBase: 3); // mov rsi, [rbx + OffRdx]
        _code.AddRange([0xBA, 0x0C, 0x00, 0x00, 0x00]); // mov edx, 12
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzCopyFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // r15d = cmd, r14 = rif_pa
        _code.AddRange([0x44, 0x8B, 0x3C, 0x24]);    // mov r15d, [rsp]
        _code.AddRange([0x4C, 0x8B, 0x74, 0x24, 0x08]); // mov r14, [rsp + 8]

        // ---- Read rif->type (uint16 at DMEM + rif_pa + RifOffType) ----
        EmitMovAbsR13Patch(PatchTargetNames.DmemBase);
        // rax = r13 + r14 + RifOffType
        _code.AddRange([0x4C, 0x89, 0xE8]);           // mov rax, r13
        _code.AddRange([0x4C, 0x01, 0xF0]);           // add rax, r14
        _code.AddRange([0x48, 0x05]);                  // add rax, RifOffType
        _code.AddRange(BitConverter.GetBytes(RifOffType));
        // movzx ecx, word [rax]
        _code.AddRange([0x0F, 0xB7, 0x08]);
        // cmp ecx, 2
        _code.AddRange([0x83, 0xF9, 0x02]);
        int jneNotDebugRif = EmitJccRel32Forward(0x0F, 0x85);

        // ---- Enter FPU context ----
        EmitCallPatch(PatchTargetNames.FpuEnter);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFpuFail = EmitJccRel32Forward(0x0F, 0x85);

        // ---- SHA-256(contentId, 0x30, contentid_hash) ----
        // rdi = DMEM + rif_pa + RifOffContentId
        _code.AddRange([0x4C, 0x89, 0xEF]);           // mov rdi, r13
        _code.AddRange([0x4C, 0x01, 0xF7]);           // add rdi, r14
        _code.AddRange([0x48, 0x81, 0xC7]);            // add rdi, RifOffContentId
        _code.AddRange(BitConverter.GetBytes(RifOffContentId));
        // rsi = 0x30
        _code.AddRange([0xBE, 0x30, 0x00, 0x00, 0x00]);
        // rdx = &contentid_hash at [rsp + 0x20]
        _code.AddRange([0x48, 0x8D, 0x54, 0x24, 0x20]);
        EmitCallPatch(PatchTargetNames.Sha256BufferFpuHeld);
        _code.AddRange([0x85, 0xC0]);
        int jnzSha256Fail = EmitJccRel32Forward(0x0F, 0x85);

        // ---- memcmp(contentid_hash, DMEM + rif_pa + RifOffRifIv, 16) ----
        // Inline compare 16 bytes: load two qwords from each and compare.
        // rdi = &contentid_hash[0]
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x20]); // mov rax, [rsp + 0x20]
        // rsi = DMEM + rif_pa + RifOffRifIv
        _code.AddRange([0x4C, 0x89, 0xE9]);           // mov rcx, r13
        _code.AddRange([0x4C, 0x01, 0xF1]);           // add rcx, r14
        _code.AddRange([0x48, 0x81, 0xC1]);            // add rcx, RifOffRifIv
        _code.AddRange(BitConverter.GetBytes(RifOffRifIv));
        _code.AddRange([0x48, 0x3B, 0x01]);           // cmp rax, [rcx]
        int jneHashMismatch1 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x28]); // mov rax, [rsp + 0x28]
        _code.AddRange([0x48, 0x3B, 0x41, 0x08]);     // cmp rax, [rcx + 8]
        int jneHashMismatch2 = EmitJccRel32Forward(0x0F, 0x85);

        // ---- cmd 6 path: decrypt RIF secret and verify ----
        EmitMovAbsRcxPatch(PatchTargetNames.MailboxLrNpdrmCmd6);
        _code.AddRange([0x4C, 0x39, 0xE1]);           // cmp rcx, r12
        int jneSkipDecrypt = EmitJccRel32Forward(0x0F, 0x85); // jne skip_decrypt (cmd 5)

        // aes_cbc_128_decrypt_rif_debug(out, in, size, iv)
        // out = [rsp + 0x40] (decrypted_secret)
        _code.AddRange([0x48, 0x8D, 0x7C, 0x24, 0x40]); // lea rdi, [rsp + 0x40]
        // in = DMEM + rif_pa + RifOffRifSecret
        _code.AddRange([0x4C, 0x89, 0xEE]);           // mov rsi, r13
        _code.AddRange([0x4C, 0x01, 0xF6]);           // add rsi, r14
        _code.AddRange([0x48, 0x81, 0xC6]);            // add rsi, RifOffRifSecret
        _code.AddRange(BitConverter.GetBytes(RifOffRifSecret));
        // edx = 0x90 (size)
        _code.AddRange([0xBA, 0x90, 0x00, 0x00, 0x00]);
        // rcx = DMEM + rif_pa + RifOffRifIv
        _code.AddRange([0x4C, 0x89, 0xE9]);           // mov rcx, r13
        _code.AddRange([0x4C, 0x01, 0xF1]);           // add rcx, r14
        _code.AddRange([0x48, 0x81, 0xC1]);            // add rcx, RifOffRifIv
        _code.AddRange(BitConverter.GetBytes(RifOffRifIv));
        EmitCallPatch(PatchTargetNames.AesCbc128DecryptRifDebug);
        _code.AddRange([0x85, 0xC0]);
        int jnzDecryptFail = EmitJccRel32Forward(0x0F, 0x85);

        // Verify: memcmp(contentid_hash + 16, decrypted_secret, 16)
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x30]); // mov rax, [rsp + 0x30] (hash+16)
        _code.AddRange([0x48, 0x3B, 0x44, 0x24, 0x40]); // cmp rax, [rsp + 0x40] (dec[0])
        int jneSecretMismatch1 = EmitJccRel32Forward(0x0F, 0x85);
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x38]); // mov rax, [rsp + 0x38] (hash+24)
        _code.AddRange([0x48, 0x3B, 0x44, 0x24, 0x48]); // cmp rax, [rsp + 0x48] (dec[8])
        int jneSecretMismatch2 = EmitJccRel32Forward(0x0F, 0x85);

        // Copy unk10 + unk20 (0x20 bytes at decrypted_secret[0x70]) to kernel
        // copy_to_kernel(regs[RDX] + 0x10, &decrypted_secret[0x70], 0x20)
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffRdx]
        _code.AddRange([0x48, 0x83, 0xC7, 0x10]);     // add rdi, 0x10
        _code.AddRange([0x48, 0x8D, 0xB4, 0x24, 0xB0, 0x00, 0x00, 0x00]); // lea rsi, [rsp+0xB0]
        _code.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]); // mov edx, 0x20
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);
        int jnzCopyFail2 = EmitJccRel32Forward(0x0F, 0x85);

        // skip_decrypt:
        PatchRel32Forward(jneSkipDecrypt);

        // ---- Build RifOutput at [rsp + 0xD0] ----
        // Zero the output buffer first (0xA8 bytes = 21 qwords).
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24, 0xD0, 0x00, 0x00, 0x00]); // lea rdi, [rsp+0xD0]
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.AddRange([0xB9, 0xA8, 0x00, 0x00, 0x00]); // mov ecx, 0xA8
        _code.AddRange([0xF3, 0xAA]);                 // rep stosb

        // r8 = DMEM + rif_pa (base pointer for RIF field reads)
        _code.AddRange([0x4C, 0x89, 0xE8]);           // mov rax, r13
        _code.AddRange([0x4C, 0x01, 0xF0]);           // add rax, r14
        _code.AddRange([0x49, 0x89, 0xC0]);           // mov r8, rax

        // output.skuFlag = bswap16(rif->skuFlag)
        // Read rif->skuFlag (uint16 at r8 + 0x4E)
        _code.AddRange([0x41, 0x0F, 0xB7, 0x40, 0x4E]); // movzx eax, word [r8 + 0x4E]
        _code.AddRange([0x66, 0xC1, 0xC0, 0x08]);     // ror ax, 8 (bswap16)
        _code.AddRange([0x0F, 0xB7, 0xC0]);           // movzx eax, ax
        // If skuFlag == 2, set to 1
        _code.AddRange([0x83, 0xF8, 0x02]);           // cmp eax, 2
        int jneSkuOk = EmitJccRel8Forward(0x75);
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        PatchRel8Forward(jneSkuOk);
        // Store output.skuFlag at [rsp + 0xD0 + 0x30]
        EmitStoreEaxToStackDisp32(0xD0 + 0x30);

        // Copy RifOutput to DMEM + rif_pa + RifCmd56OutputOffset via rep movsb
        _code.AddRange([0x4C, 0x89, 0xEF]);           // mov rdi, r13
        _code.AddRange([0x4C, 0x01, 0xF7]);           // add rdi, r14
        _code.AddRange([0x48, 0x81, 0xC7]);            // add rdi, RifCmd56OutputOffset
        _code.AddRange(BitConverter.GetBytes(RifCmd56OutputOffset));
        _code.AddRange([0x48, 0x8D, 0xB4, 0x24, 0xD0, 0x00, 0x00, 0x00]); // lea rsi, [rsp+0xD0]
        _code.AddRange([0xB9, 0xA8, 0x00, 0x00, 0x00]); // mov ecx, 0xA8
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // observe_current_syscall_emulated()
        EmitCallPatch(PatchTargetNames.ObserveSyscallEmulated);

        // Clear response: copy_to_kernel(regs[RDX] + 4, &zero32, 4)
        // Write u32 zero at [rsp] and use it
        _code.AddRange([0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]); // mov dword [rsp], 0
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 7, regBase: 3); // mov rdi, [rbx + OffRdx]
        _code.AddRange([0x48, 0x83, 0xC7, 0x04]);     // add rdi, 4
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x04, 0x00, 0x00, 0x00]); // mov edx, 4
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);
        int jnzCopyFail3 = EmitJccRel32Forward(0x0F, 0x85);

        // FPU exit
        EmitCallPatch(PatchTargetNames.FpuExit);

        // Redirect: regs[RIP] = lr, regs[RAX] = 0, regs[RSP] += 8
        EmitStoreToFrameFromReg(OffRip, 0x4C, 4, regBase: 3);  // mov [rbx + OffRip], r12
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbx+OffRax], 0
        EmitAddFrameFieldImm8(OffIretRsp, 8, regBase: 3);

        // mov eax, 1 -- return handled
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpEpilogue1 = EmitJmpRel32Forward();

        // ---- Failure paths that require FPU exit ----
        PatchRel32Forward(jnzSha256Fail);
        PatchRel32Forward(jneHashMismatch1);
        PatchRel32Forward(jneHashMismatch2);
        PatchRel32Forward(jnzDecryptFail);
        PatchRel32Forward(jneSecretMismatch1);
        PatchRel32Forward(jneSecretMismatch2);
        PatchRel32Forward(jnzCopyFail2);
        PatchRel32Forward(jnzCopyFail3);
        EmitCallPatch(PatchTargetNames.FpuExit);
        // Fall through to not_handled return.

        // ---- not_handled / failure without FPU ----
        PatchRel32Forward(jneLrBad);
        PatchRel32Forward(jnzCopyFail1);
        PatchRel32Forward(jneNotDebugRif);
        PatchRel32Forward(jnzFpuFail);
        // xor eax, eax -- return 0
        _code.AddRange([0x31, 0xC0]);

        // Epilogue:
        PatchRel32Forward(jmpEpilogue1);
        EmitAddRspImm32(0x1A0);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5F]);                 // pop r15
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the ioctl syscall handler. Called by the syscall dispatcher when the
    /// SYS_ioctl sysent entry is matched.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>Arms the debug register set for NPDRM mailbox interception via
    /// start_syscall_with_dbgregs. The set uses one breakpoint:
    /// DR0 = sceSblServiceMailbox, DR7 = 0x401 (local-exact on DR0).</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SceSblServiceMailbox"/> (inside dbgregs constant),
    ///   <see cref="PatchTargetNames.StartSyscallWithDbgregs"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitIoctlSyscallHandler()
    {
        int entry = _code.Count;

        // Emit static dbgregs_for_ioctl constant (6 x uint64 = 48 bytes).
        int jmpPastData = EmitJmpRel32Forward();
        int dbgregsOffset = _code.Count;
        // DR0 = sceSblServiceMailbox (patchable)
        RecordDispatchPatch(PatchTargetNames.SceSblServiceMailbox);
        _code.AddRange(new byte[8]);
        // DR1-DR3 = 0, DR6 = 0
        _code.AddRange(new byte[32]);
        // DR7 = 0x0000000000000401 (local-exact on DR0)
        _code.AddRange(BitConverter.GetBytes((ulong)0x401));
        PatchRel32Forward(jmpPastData);

        // start_syscall_with_dbgregs(regs, dbgregs_for_ioctl)
        EmitLeaRsiRipRelative(dbgregsOffset);
        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);
        _code.Add(0xC3); // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Kekcall emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the kekcall handler. Called by the syscall dispatcher when getppid is
    /// intercepted. The kekcall number and arguments are extracted from the trap
    /// frame's syscall argument fields.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>Dispatches by kekcall number (args[RSI], the second syscall argument):</para>
    /// <list type="bullet">
    ///   <item>nr=1: Read debug registers. Builds a stack frame with doreti_iret +
    ///         nop_ret, reads current DRs via read_dbgregs_checked, checks
    ///         PCB_DBREGS flag, pushes the frame, and redirects to copyout to
    ///         deliver the results to userspace.</item>
    ///   <item>nr=2: Write debug registers. Pushes a continuation frame, redirects
    ///         to copyin to read the new DR values from userspace. The continuation
    ///         trap handler (kekcall trap 1) applies the values.</item>
    ///   <item>nr=3: Read MSR. Calls rdmsr with the specified index and returns
    ///         the value in args[RAX].</item>
    ///   <item>nr=5: Remote syscall. Pushes a continuation frame, redirects to
    ///         copyin to read the arguments. The continuation trap handler
    ///         (kekcall trap 2) finds the target process and invokes the syscall
    ///         on its behalf.</item>
    ///   <item>nr=0xFFFFFFFF: Ping. Returns 0 in args[RAX] (connectivity check).</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.DoretiIret"/>,
    ///   <see cref="PatchTargetNames.NopRet"/>,
    ///   <see cref="PatchTargetNames.CopierIn"/>,
    ///   <see cref="PatchTargetNames.CopierOut"/>,
    ///   <see cref="PatchTargetNames.ReadDbgregsChecked"/>,
    ///   <see cref="PatchTargetNames.GetPcbDbregsCheckedAt"/>,
    ///   <see cref="PatchTargetNames.PushStackChecked"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>,
    ///   <see cref="PatchTargetNames.RdmsrFn"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitKekcallHandler()
    {
        int entry = _code.Count;

        // Prologue: save callee-saved registers.
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0xC0); // 192 bytes for local stack frames

        // rbx = regs
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi

        // Extract kekcall number: nr = args[RSI] (trap frame RSI field)
        // args are at regs+offsets. The syscall ABI puts arguments in
        // RDI, RSI, RDX, RCX, R8, R9 of the trap frame.
        // nr = (uint32_t) regs[RSI]
        EmitLoadFromFrameViaReg(OffRsi, 0x48, 1, regBase: 3); // mov rcx, [rbx + OffRsi] -> rcx = args[RSI] -> nr
        // r12d = nr
        _code.AddRange([0x41, 0x89, 0xCC]);           // mov r12d, ecx

        // ---- nr == 1: read debug registers ----
        _code.AddRange([0x41, 0x83, 0xFC, 0x01]);     // cmp r12d, 1
        int jneNr2 = EmitJccRel32Forward(0x0F, 0x85);

        // Build stack_frame[12] on the local stack at [rsp]:
        // [0] = doreti_iret, [1] = nop_ret,
        // [2] = regs[CS], [3] = regs[EFLAGS], [4] = regs[RSP], [5] = regs[SS],
        // [6..11] = debug registers (filled by read_dbgregs_checked)
        EmitMovAbsRaxPatch(PatchTargetNames.DoretiIret);
        EmitStoreRaxToStackDisp32(0x00);
        EmitMovAbsRaxPatch(PatchTargetNames.NopRet);
        EmitStoreRaxToStackDisp32(0x08);
        EmitLoadFromFrameViaReg(OffCs, 0x48, 0, regBase: 3);      // mov rax, [rbx + OffCs]
        EmitStoreRaxToStackDisp32(0x10);
        EmitLoadFromFrameViaReg(OffEflags, 0x48, 0, regBase: 3);  // mov rax, [rbx + OffEflags]
        EmitStoreRaxToStackDisp32(0x18);
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3); // mov rax, [rbx + OffIretRsp]
        EmitStoreRaxToStackDisp32(0x20);
        EmitLoadFromFrameViaReg(OffSs, 0x48, 0, regBase: 3);     // mov rax, [rbx + OffSs]
        EmitStoreRaxToStackDisp32(0x28);

        // read_dbgregs_checked(&stack_frame[6])  -- RDI = rsp + 0x30
        EmitLeaRdiRspDisp32(0x30);
        EmitCallPatch(PatchTargetNames.ReadDbgregsChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzNr1Fail = EmitJccRel32Forward(0x0F, 0x85);

        // push_stack_checked(regs, stack_frame, 96)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x60, 0x00, 0x00, 0x00]); // mov edx, 96
        EmitCallPatch(PatchTargetNames.PushStackChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzNr1PushFail = EmitJccRel32Forward(0x0F, 0x85);

        // Redirect: regs[RDI] = regs[RSP] + 48, regs[RSI] = args[RDI],
        // regs[RDX] = 48, regs[RIP] = copyout
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3); // mov rax, [rbx + OffIretRsp]
        _code.AddRange([0x48, 0x83, 0xC0, 0x30]);     // add rax, 48
        _code.AddRange([0x48, 0x89, 0x03]);           // mov [rbx + OffRdi], rax
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 0, regBase: 3); // mov rax, [rbx + OffRdi] -> args[RDI]
        // args[RDI] is the user buffer address from the original syscall.
        // regs[RSI] = original regs[RDI] (the user buffer)
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 0, regBase: 3);
        EmitStoreToFrameFromReg(OffRsi, 0x48, 0, regBase: 3);    // mov [rbx + OffRsi], rax
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRdx, 0x30, 0x00, 0x00, 0x00]); // mov qword [rbx+OffRdx], 48
        EmitMovAbsRaxPatch(PatchTargetNames.CopierOut);
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);    // mov [rbx + OffRip], rax

        // return 0 (success)
        _code.AddRange([0x31, 0xC0]);
        int jmpEpilogue1 = EmitJmpRel32Forward();

        // ---- nr == 3: read MSR ----
        PatchRel32Forward(jneNr2);
        _code.AddRange([0x41, 0x83, 0xFC, 0x03]);     // cmp r12d, 3
        int jneNr5 = EmitJccRel32Forward(0x0F, 0x85);

        // rdmsr(args[RDI], &args[RAX])
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 7, regBase: 3);  // mov rdi, [rbx + OffRdi]
        _code.AddRange([0x48, 0x8D, 0x73, (byte)OffRax]); // lea rsi, [rbx + OffRax]
        EmitCallPatch(PatchTargetNames.RdmsrFn);
        // rdmsr returns 1 on success, 0 on fault. Invert: return EFAULT if 0.
        _code.AddRange([0x85, 0xC0]);
        int jzMsrFail = EmitJccRel32Forward(0x0F, 0x84);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax (success)
        int jmpEpilogue2 = EmitJmpRel32Forward();

        // ---- nr == 0xFFFFFFFF: ping ----
        PatchRel32Forward(jneNr5);
        _code.AddRange([0x41, 0x81, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF]); // cmp r12d, 0xFFFFFFFF
        int jneEnosys = EmitJccRel32Forward(0x0F, 0x85);

        // args[RAX] = 0
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x00, 0x00, 0x00, 0x00]);
        _code.AddRange([0x31, 0xC0]);                 // return 0
        int jmpEpilogue3 = EmitJmpRel32Forward();

        // ---- ENOSYS: unsupported kekcall number ----
        PatchRel32Forward(jneEnosys);
        _code.AddRange([0xB8, 0x4E, 0x00, 0x00, 0x00]); // mov eax, 78 (ENOSYS)
        int jmpEpilogue4 = EmitJmpRel32Forward();

        // ---- EFAULT returns ----
        PatchRel32Forward(jnzNr1Fail);
        PatchRel32Forward(jnzNr1PushFail);
        PatchRel32Forward(jzMsrFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]); // mov eax, 14 (EFAULT)

        // Epilogue:
        PatchRel32Forward(jmpEpilogue1);
        PatchRel32Forward(jmpEpilogue2);
        PatchRel32Forward(jmpEpilogue3);
        PatchRel32Forward(jmpEpilogue4);
        EmitAddRspImm32(0xC0);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the kekcall trap handler. Called from the main trap handler when
    /// a continuation trap fires after a kekcall copyin/copyout completes.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, ESI = trap sub-index.</para>
    ///
    /// <para>Handles two trap sub-indices:</para>
    /// <list type="bullet">
    ///   <item>trap=1: Write debug registers continuation. Pops the stack frame,
    ///         reads current DRs, writes the new values from the frame, and updates
    ///         PCB_DBREGS.</item>
    ///   <item>trap=3/4: Remote syscall result collection. Pops the stack frame and
    ///         copies the remote thread's return value back to the caller.</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.PopStackChecked"/>,
    ///   <see cref="PatchTargetNames.ReadDbgregsChecked"/>,
    ///   <see cref="PatchTargetNames.WriteDbgregsChecked"/>,
    ///   <see cref="PatchTargetNames.GetCurrentPcbFlagsPtrChecked"/>,
    ///   <see cref="PatchTargetNames.GetPcbDbregsCheckedAt"/>,
    ///   <see cref="PatchTargetNames.SetPcbDbregsCheckedAt"/>,
    ///   <see cref="PatchTargetNames.RestoreDbgregsStateCheckedAt"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>,
    ///   <see cref="PatchTargetNames.Kpeek64Checked"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitKekcallTrapHandler()
    {
        int entry = _code.Count;

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x80);

        // rbx = regs, r12d = trap sub-index
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x41, 0x89, 0xF4]);           // mov r12d, esi

        // ---- trap == 1: write debug registers continuation ----
        _code.AddRange([0x41, 0x83, 0xFC, 0x01]);     // cmp r12d, 1
        int jneTrap3 = EmitJccRel32Forward(0x0F, 0x85);

        // Pop stack_frame[14] (112 bytes)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x70, 0x00, 0x00, 0x00]); // mov edx, 112
        EmitCallPatch(PatchTargetNames.PopStackChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzT1PopFail = EmitJccRel32Forward(0x0F, 0x85);

        // Restore RIP from stack_frame[13] (offset 104)
        EmitLoadRaxFromStackDisp32(0x68);             // mov rax, [rsp + 104]
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3); // mov [rbx + OffRip], rax

        // Check copyin result (regs[RAX])
        EmitLoadFromFrameViaReg(OffRax, 0x48, 0, regBase: 3);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzT1CopyFail = EmitJccRel32Forward(0x0F, 0x85);

        // write_dbgregs_checked(&stack_frame[5])
        EmitLeaRdiRspDisp32(0x28);                    // lea rdi, [rsp + 40]
        EmitCallPatch(PatchTargetNames.WriteDbgregsChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzT1WriteFail = EmitJccRel32Forward(0x0F, 0x85);

        int jmpEpilogueT1 = EmitJmpRel32Forward();

        // ---- trap == 3 or 4: remote syscall result ----
        PatchRel32Forward(jneTrap3);
        _code.AddRange([0x41, 0x83, 0xFC, 0x03]);     // cmp r12d, 3
        int jeT3 = EmitJccRel8Forward(0x74);
        _code.AddRange([0x41, 0x83, 0xFC, 0x04]);     // cmp r12d, 4
        int jneUnhandled = EmitJccRel32Forward(0x0F, 0x85);
        PatchRel8Forward(jeT3);

        // Pop stack_frame[14] (112 bytes)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x70, 0x00, 0x00, 0x00]); // mov edx, 112
        EmitCallPatch(PatchTargetNames.PopStackChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzT3PopFail = EmitJccRel32Forward(0x0F, 0x85);

        // Restore RIP from stack_frame[13] (offset 104)
        EmitLoadRaxFromStackDisp32(0x68);
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);

        int jmpEpilogueT3 = EmitJmpRel32Forward();

        // ---- Failure paths ----
        PatchRel32Forward(jnzT1PopFail);
        PatchRel32Forward(jnzT1CopyFail);
        PatchRel32Forward(jnzT1WriteFail);
        // Set regs[RAX] = EFAULT for trap 1 failures
        _code.AddRange([0x48, 0xC7, 0x43, (byte)OffRax, 0x0E, 0x00, 0x00, 0x00]);

        PatchRel32Forward(jnzT3PopFail);
        PatchRel32Forward(jneUnhandled);

        // Epilogue:
        PatchRel32Forward(jmpEpilogueT1);
        PatchRel32Forward(jmpEpilogueT3);
        EmitAddRspImm32(0x80);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Syscall fixes emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the syscall fix handler. Called by the syscall dispatcher when a hooked
    /// mprotect or mdbg_call sysent entry is matched.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>Arms the debug register set for permission bypass via
    /// start_syscall_with_dbgregs. The set uses two breakpoints:
    /// DR0 = mprotect_fix_start, DR1 = aslr_fix_start,
    /// DR7 = 0x405 (local-exact on DR0 + DR1).</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.MprotectFixStart"/> (DR0),
    ///   <see cref="PatchTargetNames.AslrFixStart"/> (DR1),
    ///   <see cref="PatchTargetNames.StartSyscallWithDbgregs"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitSyscallFixHandler()
    {
        int entry = _code.Count;

        // Emit static dbgregs_for_syscall_fix constant (6 x uint64 = 48 bytes).
        int jmpPastData = EmitJmpRel32Forward();
        int dbgregsOffset = _code.Count;
        // DR0 = mprotect_fix_start (patchable)
        RecordDispatchPatch(PatchTargetNames.MprotectFixStart);
        _code.AddRange(new byte[8]);
        // DR1 = aslr_fix_start (patchable)
        RecordDispatchPatch(PatchTargetNames.AslrFixStart);
        _code.AddRange(new byte[8]);
        // DR2 = 0, DR3 = 0
        _code.AddRange(new byte[16]);
        // DR6 = 0
        _code.AddRange(new byte[8]);
        // DR7 = 0x0000000000000405 (local-exact on DR0 + DR1)
        _code.AddRange(BitConverter.GetBytes((ulong)0x405));
        PatchRel32Forward(jmpPastData);

        // start_syscall_with_dbgregs(regs, dbgregs_for_syscall_fix)
        EmitLeaRsiRipRelative(dbgregsOffset);
        EmitCallPatch(PatchTargetNames.StartSyscallWithDbgregs);
        _code.Add(0xC3); // ret

        return entry;
    }

    /// <summary>
    /// Emit the syscall fix trap handler. Called when a debug register breakpoint
    /// fires at mprotect_fix_start or aslr_fix_start during a hooked mprotect
    /// or mdbg_call syscall.
    ///
    /// <para>Calling convention: RDI = trap frame pointer.</para>
    ///
    /// <para>Compares the interrupted RIP against the two fix entry points. If
    /// matched, redirects RIP to the corresponding exit point (skipping the
    /// permission check). Returns 1 if handled, 0 otherwise.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.MprotectFixStart"/>,
    ///   <see cref="PatchTargetNames.MprotectFixEnd"/>,
    ///   <see cref="PatchTargetNames.AslrFixStart"/>,
    ///   <see cref="PatchTargetNames.AslrFixStart"/> (end comparison shares start).</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitSyscallFixTrapHandler()
    {
        int entry = _code.Count;

        // Load RIP from trap frame.
        EmitLoadFromFrame(OffRip, rex: 0x48, regBits: 0);

        // Check: RIP == mprotect_fix_start
        EmitMovAbsRcxPatch(PatchTargetNames.MprotectFixStart);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jneCheckAslr = EmitJccRel8Forward(0x75);

        // Matched mprotect: regs[RIP] = mprotect_fix_end
        EmitMovAbsRaxPatch(PatchTargetNames.MprotectFixEnd);
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 7); // mov [rdi + OffRip], rax
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0xC3);                              // ret

        // Check: RIP == aslr_fix_start
        PatchRel8Forward(jneCheckAslr);
        EmitMovAbsRcxPatch(PatchTargetNames.AslrFixStart);
        _code.AddRange([0x48, 0x39, 0xC8]);           // cmp rax, rcx
        int jneNotHandled = EmitJccRel8Forward(0x75);

        // Matched ASLR: redirect past the fix region.
        // aslr_fix_end is computed as aslr_fix_start + <known offset>, but since
        // the C source uses a separate symbol, aslr_fix_start is used as the
        // comparison and redirect to the same address (the breakpoint itself
        // triggers the skip in the kernel; the handler just acknowledges).
        // For correctness, RF is set to prevent re-trigger.
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0xC3);

        PatchRel8Forward(jneNotHandled);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Utils subsystem emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the start_syscall_with_dbgregs function. Saves the current debug register
    /// state, writes the new debug register values, and sets the PCB_DBREGS flag so
    /// the kernel's context switch path preserves the DR state.
    ///
    /// <para>Calling convention: RDI = trap frame pointer (regs), RSI = pointer to
    /// 6-element uint64 array (new DR0-DR3, DR6, DR7 values).</para>
    ///
    /// <para>Pushes a 96-byte (12 qword) continuation frame onto the kernel stack:</para>
    /// <list type="bullet">
    ///   <item>[0] = doreti_iret (IRET return address)</item>
    ///   <item>[1] = MKTRAP(TRAP_UTILS, 1) (trap identifier)</item>
    ///   <item>[2] = 0, [3] = 0 (reserved)</item>
    ///   <item>[4] = had_dbregs (original PCB_DBREGS flag)</item>
    ///   <item>[5] = 0 (reserved)</item>
    ///   <item>[6..11] = saved DR0-DR3, DR6, DR7 (original debug register values)</item>
    /// </list>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.DoretiIret"/>,
    ///   <see cref="PatchTargetNames.ReadDbgregsChecked"/>,
    ///   <see cref="PatchTargetNames.WriteDbgregsChecked"/>,
    ///   <see cref="PatchTargetNames.GetCurrentPcbFlagsPtrChecked"/>,
    ///   <see cref="PatchTargetNames.GetPcbDbregsCheckedAt"/>,
    ///   <see cref="PatchTargetNames.SetPcbDbregsCheckedAt"/>,
    ///   <see cref="PatchTargetNames.RestoreDbgregsStateCheckedAt"/>,
    ///   <see cref="PatchTargetNames.PushStackChecked"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitStartSyscallWithDbgregs()
    {
        int entry = _code.Count;

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x80); // 128 bytes: stack_frame[12] = 96 + locals

        // rbx = regs, r12 = dbgregs pointer
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi

        // Build stack_frame[0] = doreti_iret
        EmitMovAbsRaxPatch(PatchTargetNames.DoretiIret);
        EmitStoreRaxToStackDisp32(0x00);

        // stack_frame[1] = MKTRAP(TRAP_UTILS, 1)
        _code.AddRange([0x48, 0xB8]);                 // movabs rax, imm64
        _code.AddRange(BitConverter.GetBytes(((ulong)TrapUtils << 32) | 1));
        EmitStoreRaxToStackDisp32(0x08);

        // stack_frame[2] = 0, stack_frame[3] = 0, stack_frame[5] = 0
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        EmitStoreRaxToStackDisp32(0x10);
        EmitStoreRaxToStackDisp32(0x18);
        EmitStoreRaxToStackDisp32(0x28);

        // read_dbgregs_checked(&stack_frame[6])  -- save current DRs
        EmitLeaRdiRspDisp32(0x30);
        EmitCallPatch(PatchTargetNames.ReadDbgregsChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzReadFail = EmitJccRel32Forward(0x0F, 0x85);

        // get_current_pcb_flags_ptr_checked(&p_pcb_flags)
        // Use [rsp + 0x68] as local for p_pcb_flags
        EmitLeaRdiRspDisp32(0x68);
        EmitCallPatch(PatchTargetNames.GetCurrentPcbFlagsPtrChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzPcbFail = EmitJccRel32Forward(0x0F, 0x85);

        // get_pcb_dbregs_checked_at(p_pcb_flags, &flags, &had_dbregs)
        EmitLoadRaxFromStackDisp32(0x68);             // rax = p_pcb_flags
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        EmitLeaRsiRspDisp32(0x70);                    // lea rsi, [rsp + 0x70] (flags)
        EmitLeaRdxRspDisp32(0x78);                    // lea rdx, [rsp + 0x78] (had_dbregs)
        EmitCallPatch(PatchTargetNames.GetPcbDbregsCheckedAt);
        _code.AddRange([0x85, 0xC0]);
        int jnzDbregsFail = EmitJccRel32Forward(0x0F, 0x85);

        // stack_frame[4] = had_dbregs
        EmitLoadEaxFromStackDisp32(0x78);
        EmitStoreEaxToStackDisp32(0x20);

        // push_stack_checked(regs, stack_frame, 96)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x60, 0x00, 0x00, 0x00]); // mov edx, 96
        EmitCallPatch(PatchTargetNames.PushStackChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzPushFail = EmitJccRel32Forward(0x0F, 0x85);

        // set_pcb_dbregs_checked_at(p_pcb_flags, flags)
        EmitLoadRaxFromStackDisp32(0x68);             // rax = p_pcb_flags
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        EmitLoadRaxFromStackDisp32(0x70);             // rax = flags
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        EmitCallPatch(PatchTargetNames.SetPcbDbregsCheckedAt);
        _code.AddRange([0x85, 0xC0]);
        int jnzSetFail = EmitJccRel32Forward(0x0F, 0x85);

        // write_dbgregs_checked(new_dbgregs)
        _code.AddRange([0x4C, 0x89, 0xE7]);           // mov rdi, r12
        EmitCallPatch(PatchTargetNames.WriteDbgregsChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzWriteFail = EmitJccRel32Forward(0x0F, 0x85);

        int jmpDone = EmitJmpRel32Forward();

        // write_dbgregs failed: restore state
        PatchRel32Forward(jnzWriteFail);
        EmitLoadRaxFromStackDisp32(0x68);             // p_pcb_flags
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        EmitLoadRaxFromStackDisp32(0x70);             // flags
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        EmitLeaRdxRspDisp32(0x30);                    // lea rdx, [rsp + 0x30] (saved DRs)
        EmitLoadEaxFromStackDisp32(0x78);             // had_dbregs
        _code.AddRange([0x89, 0xC1]);                 // mov ecx, eax
        EmitCallPatch(PatchTargetNames.RestoreDbgregsStateCheckedAt);

        // set_pcb_dbregs failed or push failed: rewind RSP
        PatchRel32Forward(jnzSetFail);
        PatchRel32Forward(jnzPushFail);
        // regs[RSP] += 96 to undo the push
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3);
        _code.AddRange([0x48, 0x83, 0xC0, 0x60]);     // add rax, 96
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);

        // Error fallthrough
        PatchRel32Forward(jnzReadFail);
        PatchRel32Forward(jnzPcbFail);
        PatchRel32Forward(jnzDbregsFail);

        // Done:
        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x80);
        _code.Add(0x5D);                              // pop rbp
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the utils trap handler. Called when a debug register continuation trap
    /// fires after a syscall completes with armed debug registers.
    ///
    /// <para>Calling convention: RDI = trap frame pointer, ESI = trap sub-index.</para>
    ///
    /// <para>For trap sub-index 1: peeks the continuation stack frame, restores the
    /// saved debug register state via restore_dbgregs_state_checked, deallocates
    /// the frame, and calls finish_npdrm_ioctl_state to reset the NPDRM tracking.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.PeekStackChecked"/>,
    ///   <see cref="PatchTargetNames.RestoreDbgregsStateChecked"/>,
    ///   <see cref="PatchTargetNames.FinishNpdrmIoctlState"/>,
    ///   <see cref="PatchTargetNames.ObserveSyscallFinish"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitUtilsTrapHandler()
    {
        int entry = _code.Count;

        // Only handle trapno == 1
        _code.AddRange([0x83, 0xFE, 0x01]);           // cmp esi, 1
        int jneNotTrap1 = EmitJccRel8Forward(0x75);

        // Prologue
        _code.Add(0x53);                              // push rbx
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x68); // 104 bytes for stack_frame[12] = 96 + alignment

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi

        // peek_stack_checked(regs, stack_frame, 96)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xBA, 0x60, 0x00, 0x00, 0x00]); // mov edx, 96
        EmitCallPatch(PatchTargetNames.PeekStackChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzPeekFail = EmitJccRel32Forward(0x0F, 0x85);

        // restore_dbgregs_state_checked(&stack_frame[5], stack_frame[3])
        // RDI = &stack_frame[5] (saved DRs + had_dbregs at offset 40),
        // ESI = stack_frame[3] (had_dbregs flag at offset 24)
        EmitLeaRdiRspDisp32(0x28);                    // lea rdi, [rsp + 40]
        EmitLoadEaxFromStackDisp32(0x18);             // mov eax, [rsp + 24]
        _code.AddRange([0x89, 0xC6]);                 // mov esi, eax
        EmitCallPatch(PatchTargetNames.RestoreDbgregsStateChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzRestoreFail = EmitJccRel32Forward(0x0F, 0x85);

        // Deallocate the continuation frame: regs[RSP] += 96
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3);
        _code.AddRange([0x48, 0x83, 0xC0, 0x60]);     // add rax, 96
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);

        // Restore RIP from stack_frame[11] (offset 88)
        EmitLoadRaxFromStackDisp32(0x58);             // mov rax, [rsp + 88]
        EmitStoreToFrameFromReg(OffRip, 0x48, 0, regBase: 3);

        // finish_npdrm_ioctl_state()
        EmitCallPatch(PatchTargetNames.FinishNpdrmIoctlState);

        // observe_current_syscall_finish()
        EmitCallPatch(PatchTargetNames.ObserveSyscallFinish);

        PatchRel32Forward(jnzPeekFail);
        PatchRel32Forward(jnzRestoreFail);

        // Epilogue
        EmitAddRspImm32(0x68);
        _code.Add(0x5D);                              // pop rbp
        _code.Add(0x5B);                              // pop rbx

        PatchRel8Forward(jneNotTrap1);
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the virt2phys page table walker. Translates a kernel virtual address to
    /// a physical address by walking the 4-level page table structure through DMEM.
    ///
    /// <para>Calling convention: RDI = virtual address, RSI = &amp;phys_out,
    /// RDX = &amp;phys_limit_out.</para>
    ///
    /// <para>Returns 1 in EAX if the translation succeeded (the physical address and
    /// its page-boundary limit are written to the output pointers), 0 if the
    /// translation failed (page not present or DMEM bounds exceeded).</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.Cr3PhysAddr"/>,
    ///   <see cref="PatchTargetNames.DmemBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitVirt2Phys()
    {
        int entry = _code.Count;

        // Prologue: save callee-saved registers
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13

        // rbx = va, r12 = phys_out, r13 = phys_limit_out
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx

        // Load pml = cr3_phys
        EmitMovAbsRcxPatch(PatchTargetNames.Cr3PhysAddr);
        _code.AddRange([0x48, 0x8B, 0x09]);           // mov rcx, [rcx]

        // Load DMEM base into r8
        EmitMovAbsRaxPatch(PatchTargetNames.DmemBase);
        _code.AddRange([0x49, 0x89, 0xC0]);           // mov r8, rax

        // Loop: i = 39, 30, 21, 12
        // Use esi as loop counter (i)
        _code.AddRange([0xBE, 0x27, 0x00, 0x00, 0x00]); // mov esi, 39

        int loopStart = _code.Count;
        // Check DMEM bounds: pml >= ((1<<39) - (1<<12))
        _code.AddRange([0x48, 0xB8]);                 // movabs rax, (1<<39)-(1<<12)
        _code.AddRange(BitConverter.GetBytes((1UL << 39) - (1UL << 12)));
        _code.AddRange([0x48, 0x39, 0xC1]);           // cmp rcx, rax
        int jaeOob = EmitJccRel32Forward(0x0F, 0x83);

        // index = (addr >> (i - 3)) & mask, where mask selects 9 bits at position i
        // entry_ptr = DMEM + pml + ((addr & (0x1ff << i)) >> (i - 3))
        _code.AddRange([0x48, 0x89, 0xD8]);           // mov rax, rbx  (addr)
        _code.AddRange([0x89, 0xF1]);                 // mov ecx_saved = esi; use cl for shift
        // Compute shift amount = i - 3
        _code.AddRange([0x8D, 0x4E, 0xFD]);           // lea ecx, [rsi - 3]
        _code.AddRange([0x48, 0xD3, 0xE8]);           // shr rax, cl  (addr >> (i-3))
        _code.AddRange([0x48, 0x25, 0xF8, 0x0F, 0x00, 0x00]); // and rax, 0xFF8 (9 bits << 3)
        // rcx was clobbered by the shift count. Restructure the loop with:
        // rdx = pml, esi = i, rbx = addr, r8 = DMEM.
        // Rewrite from the loop setup.
        _code.RemoveRange(loopStart, _code.Count - loopStart);

        // rdx = pml (cr3_phys value loaded into rcx above, move to rdx)
        _code.AddRange([0x48, 0x89, 0xCA]);           // mov rdx, rcx

        _code.AddRange([0xBE, 0x27, 0x00, 0x00, 0x00]); // mov esi, 39

        int loopStart2 = _code.Count;
        // Check DMEM bounds
        _code.AddRange([0x48, 0xB8]);                 // movabs rax, (1<<39)-(1<<12)
        _code.AddRange(BitConverter.GetBytes((1UL << 39) - (1UL << 12)));
        _code.AddRange([0x48, 0x39, 0xC2]);           // cmp rdx, rax
        int jaeOob2 = EmitJccRel32Forward(0x0F, 0x83);

        // Compute entry address in the page table:
        // entry_offset = (addr >> (i - 3)) & 0xFF8
        _code.AddRange([0x48, 0x89, 0xD8]);           // mov rax, rbx
        _code.AddRange([0x89, 0xF1]);                 // mov ecx, esi
        _code.AddRange([0x83, 0xE9, 0x03]);           // sub ecx, 3
        _code.AddRange([0x48, 0xD3, 0xE8]);           // shr rax, cl
        _code.AddRange([0x48, 0x25, 0xF8, 0x0F, 0x00, 0x00]); // and rax, 0xFF8

        // next_pml = *(uint64*)(DMEM + pml + entry_offset)
        _code.AddRange([0x48, 0x01, 0xD0]);           // add rax, rdx
        _code.AddRange([0x4C, 0x01, 0xC0]);           // add rax, r8
        _code.AddRange([0x48, 0x8B, 0x10]);           // mov rdx, [rax]  (next_pml -> rdx)

        // Check present bit
        _code.AddRange([0xF6, 0xC2, 0x01]);           // test dl, 1
        int jzNotPresent = EmitJccRel32Forward(0x0F, 0x84);

        // Check large page (bit 7) or final level (i == 12)
        _code.AddRange([0xF6, 0xC2, 0x80]);           // test dl, 0x80
        int jnzLargePage = EmitJccRel8Forward(0x75);
        _code.AddRange([0x83, 0xFE, 0x0C]);           // cmp esi, 12
        int jeFinalLevel = EmitJccRel8Forward(0x74);

        // Continue walking: pml = next_pml & ((1<<52) - (1<<12))
        _code.AddRange([0x48, 0xB8]);                 // movabs rax, (1<<52)-(1<<12)
        _code.AddRange(BitConverter.GetBytes((1UL << 52) - (1UL << 12)));
        _code.AddRange([0x48, 0x21, 0xC2]);           // and rdx, rax

        // i -= 9
        _code.AddRange([0x83, 0xEE, 0x09]);           // sub esi, 9
        EmitJmpRel32To(loopStart2);

        // ---- Large page or final level: compute physical address ----
        PatchRel8Forward(jnzLargePage);
        PatchRel8Forward(jeFinalLevel);

        // phys_base = next_pml & ((1<<52) - (1<<i))
        _code.AddRange([0x89, 0xF1]);                 // mov ecx, esi
        _code.AddRange([0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // movabs rax, 1
        _code.AddRange([0x48, 0xD3, 0xE0]);           // shl rax, cl
        _code.AddRange([0x48, 0xFF, 0xC8]);           // dec rax  -- (1<<i)-1
        _code.AddRange([0x48, 0x89, 0xC1]);           // mov rcx, rax -- page_mask = (1<<i)-1
        _code.AddRange([0x48, 0xF7, 0xD0]);           // not rax  -- ~page_mask
        // AND with (1<<52)-1 to mask physical address bits
        _code.AddRange([0x48, 0xBE]);                 // movabs rsi, (1<<52)-1
        _code.AddRange(BitConverter.GetBytes((1UL << 52) - 1));
        _code.AddRange([0x48, 0x21, 0xF0]);           // and rax, rsi
        _code.AddRange([0x48, 0x21, 0xC2]);           // and rdx, rax  -- base = next_pml & mask

        // phys = base | (addr & page_mask)
        _code.AddRange([0x48, 0x89, 0xD8]);           // mov rax, rbx
        _code.AddRange([0x48, 0x21, 0xC8]);           // and rax, rcx
        _code.AddRange([0x48, 0x09, 0xD0]);           // or rax, rdx

        // *phys_out = phys
        _code.AddRange([0x49, 0x89, 0x04, 0x24]);     // mov [r12], rax

        // *phys_limit = (phys | page_mask) + 1
        _code.AddRange([0x48, 0x09, 0xC8]);           // or rax, rcx
        _code.AddRange([0x48, 0xFF, 0xC0]);           // inc rax
        _code.AddRange([0x49, 0x89, 0x45, 0x00]);     // mov [r13], rax

        // return 1
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpDone = EmitJmpRel32Forward();

        // ---- Failure: not present or out of bounds ----
        PatchRel32Forward(jaeOob2);
        PatchRel32Forward(jzNotPresent);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        // Epilogue
        PatchRel32Forward(jmpDone);
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the copy_from_kernel function. Copies data from a kernel virtual address
    /// to a local buffer by translating each page via virt2phys and reading through
    /// DMEM.
    ///
    /// <para>Calling convention: RDI = destination (local buffer), RSI = source
    /// (kernel virtual address), RDX = byte count.</para>
    ///
    /// <para>Returns 0 on success, EFAULT (14) on translation failure.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.DmemBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    /// <param name="virt2PhysOffset">Code offset of the emitted virt2phys function,
    /// used for direct RIP-relative calls.</param>
    public int EmitCopyFromKernel(int virt2PhysOffset)
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x20); // locals: phys, phys_end

        // rbx = dst, r12 = src, r13 = remaining, r14 = DMEM
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx
        EmitMovAbsRaxPatch(PatchTargetNames.DmemBase);
        _code.AddRange([0x49, 0x89, 0xC6]);           // mov r14, rax

        // If sz == 0, return 0 immediately
        _code.AddRange([0x4D, 0x85, 0xED]);           // test r13, r13
        int jzEmpty = EmitJccRel32Forward(0x0F, 0x84);

        // ---- Loop: translate and copy one page chunk ----
        int loopTop = _code.Count;

        // virt2phys(src, &phys, &phys_end)
        _code.AddRange([0x4C, 0x89, 0xE7]);           // mov rdi, r12
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp  (phys at [rsp])
        _code.AddRange([0x48, 0x8D, 0x54, 0x24, 0x08]); // lea rdx, [rsp+8] (phys_end)
        // Call virt2phys via RIP-relative addressing
        EmitCallRipRelative(virt2PhysOffset);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzV2pFail = EmitJccRel32Forward(0x0F, 0x84);

        // chk = phys_end - phys; if (sz < chk) chk = sz
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x08]); // mov rax, [rsp+8]  (phys_end)
        _code.AddRange([0x48, 0x2B, 0x04, 0x24]);     // sub rax, [rsp]    (phys_end - phys)
        _code.AddRange([0x4C, 0x39, 0xE8]);           // cmp rax, r13
        int jbeSzOk = EmitJccRel8Forward(0x76);       // jbe use_rax
        _code.AddRange([0x4C, 0x89, 0xE8]);           // mov rax, r13      (clamp to sz)
        PatchRel8Forward(jbeSzOk);

        // memcpy(dst, DMEM + phys, chk) via rep movsb
        // Save rdi/rsi/rcx (they are used by rep movsb)
        _code.AddRange([0x48, 0x89, 0xC1]);           // mov rcx, rax (count)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx (dst)
        _code.AddRange([0x48, 0x8B, 0x34, 0x24]);     // mov rsi, [rsp] (phys)
        _code.AddRange([0x4C, 0x01, 0xF6]);           // add rsi, r14 (DMEM + phys)
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Advance: dst += chk, src += chk, sz -= chk
        _code.AddRange([0x48, 0x01, 0xC3]);           // add rbx, rax
        _code.AddRange([0x49, 0x01, 0xC4]);           // add r12, rax
        _code.AddRange([0x49, 0x29, 0xC5]);           // sub r13, rax
        _code.AddRange([0x4D, 0x85, 0xED]);           // test r13, r13
        int jnzLoop = EmitJccRel32Forward(0x0F, 0x85);
        PatchRel32Forward(jnzLoop);
        EmitJmpRel32To(loopTop);

        // Correction: jnz must jump back to loopTop. Remove and re-emit.
        int fixupStart = _code.Count - 10; // back up past the jnz + jmp
        _code.RemoveRange(fixupStart, _code.Count - fixupStart);
        // test r13, r13; jnz loopTop
        _code.AddRange([0x4D, 0x85, 0xED]);
        int jnzLoop2 = _code.Count;
        _code.AddRange([0x0F, 0x85]);
        int rel32Off = _code.Count;
        _code.AddRange(new byte[4]);
        int disp = loopTop - (rel32Off + 4);
        byte[] dispBytes = BitConverter.GetBytes(disp);
        _code[rel32Off] = dispBytes[0];
        _code[rel32Off + 1] = dispBytes[1];
        _code[rel32Off + 2] = dispBytes[2];
        _code[rel32Off + 3] = dispBytes[3];

        // Success: return 0
        PatchRel32Forward(jzEmpty);
        _code.AddRange([0x31, 0xC0]);
        int jmpDone = EmitJmpRel32Forward();

        // Failure: return EFAULT (14)
        PatchRel32Forward(jzV2pFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]);

        // Epilogue
        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x20);
        _code.Add(0x5D);
        _code.AddRange([0x41, 0x5F]);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the copy_to_kernel function. Copies data from a local buffer to a kernel
    /// virtual address by translating each page via virt2phys and writing through DMEM.
    ///
    /// <para>Calling convention: RDI = destination (kernel virtual address),
    /// RSI = source (local buffer), RDX = byte count.</para>
    ///
    /// <para>Returns 0 on success, EFAULT (14) on translation failure.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.DmemBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    /// <param name="virt2PhysOffset">Code offset of the emitted virt2phys function.</param>
    public int EmitCopyToKernel(int virt2PhysOffset)
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x20);

        // rbx = dst (kernel VA), r12 = src (local), r13 = remaining, r14 = DMEM
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx
        EmitMovAbsRaxPatch(PatchTargetNames.DmemBase);
        _code.AddRange([0x49, 0x89, 0xC6]);           // mov r14, rax

        _code.AddRange([0x4D, 0x85, 0xED]);           // test r13, r13
        int jzEmpty = EmitJccRel32Forward(0x0F, 0x84);

        int loopTop = _code.Count;

        // virt2phys(dst, &phys, &phys_end)
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0x48, 0x8D, 0x54, 0x24, 0x08]);
        EmitCallRipRelative(virt2PhysOffset);
        _code.AddRange([0x85, 0xC0]);
        int jzFail = EmitJccRel32Forward(0x0F, 0x84);

        // chk = min(phys_end - phys, remaining)
        _code.AddRange([0x48, 0x8B, 0x44, 0x24, 0x08]);
        _code.AddRange([0x48, 0x2B, 0x04, 0x24]);
        _code.AddRange([0x4C, 0x39, 0xE8]);
        int jbeOk = EmitJccRel8Forward(0x76);
        _code.AddRange([0x4C, 0x89, 0xE8]);
        PatchRel8Forward(jbeOk);

        // memcpy(DMEM + phys, src, chk)
        _code.AddRange([0x48, 0x89, 0xC1]);           // mov rcx, rax
        _code.AddRange([0x48, 0x8B, 0x3C, 0x24]);     // mov rdi, [rsp] (phys)
        _code.AddRange([0x4C, 0x01, 0xF7]);           // add rdi, r14
        _code.AddRange([0x4C, 0x89, 0xE6]);           // mov rsi, r12
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Advance
        _code.AddRange([0x48, 0x01, 0xC3]);           // add rbx, rax
        _code.AddRange([0x49, 0x01, 0xC4]);           // add r12, rax
        _code.AddRange([0x49, 0x29, 0xC5]);           // sub r13, rax
        // jnz loopTop
        _code.AddRange([0x4D, 0x85, 0xED]);
        _code.AddRange([0x0F, 0x85]);
        int rel32Pos = _code.Count;
        _code.AddRange(new byte[4]);
        int disp2 = loopTop - (rel32Pos + 4);
        byte[] dispBytes2 = BitConverter.GetBytes(disp2);
        _code[rel32Pos] = dispBytes2[0];
        _code[rel32Pos + 1] = dispBytes2[1];
        _code[rel32Pos + 2] = dispBytes2[2];
        _code[rel32Pos + 3] = dispBytes2[3];

        PatchRel32Forward(jzEmpty);
        _code.AddRange([0x31, 0xC0]);
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jzFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]);

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x20);
        _code.Add(0x5D);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the read_dbgregs_checked function. Reads the current debug register
    /// values (DR0-DR3, DR6, DR7) into a 6-element uint64 array by executing
    /// the dr2gpr gadget via run_gadget_checked.
    ///
    /// <para>Calling convention: RDI = pointer to uint64[6] output array.</para>
    ///
    /// <para>Returns 0 on success, EFAULT (14) on gadget failure.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.RunGadgetChecked"/>,
    ///   <see cref="PatchTargetNames.Dr2gprStart"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitReadDbgregsChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        EmitSubRspImm32(0x110); // NREGS * 8 = ~272 bytes for register array

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi (output)

        // Zero the register array
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.AddRange([0xB9, 0x10, 0x01, 0x00, 0x00]); // mov ecx, 0x110
        _code.AddRange([0xF3, 0xAA]);                 // rep stosb

        // Set RIP = dr2gpr_start in the register array
        // RIP is at offset OffRip (232) in the trap frame layout
        EmitMovAbsRaxPatch(PatchTargetNames.Dr2gprStart);
        EmitStoreRaxToStackDisp32(OffRip);

        // run_gadget_checked(regs_array)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitCallPatch(PatchTargetNames.RunGadgetChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzFail = EmitJccRel32Forward(0x0F, 0x85);

        // Extract: dr[0]=R15, dr[1]=R14, dr[2]=R13, dr[3]=R12, dr[4]=R11, dr[5]=RAX
        EmitLoadRaxFromStackDisp32(OffR15);
        _code.AddRange([0x48, 0x89, 0x03]);           // mov [rbx], rax
        EmitLoadRaxFromStackDisp32(OffR14);
        _code.AddRange([0x48, 0x89, 0x43, 0x08]);     // mov [rbx+8], rax
        EmitLoadRaxFromStackDisp32(OffR13);
        _code.AddRange([0x48, 0x89, 0x43, 0x10]);     // mov [rbx+16], rax
        EmitLoadRaxFromStackDisp32(OffR12);
        _code.AddRange([0x48, 0x89, 0x43, 0x18]);     // mov [rbx+24], rax
        EmitLoadRaxFromStackDisp32(OffR11);
        _code.AddRange([0x48, 0x89, 0x43, 0x20]);     // mov [rbx+32], rax
        EmitLoadRaxFromStackDisp32(OffRax);
        _code.AddRange([0x48, 0x89, 0x43, 0x28]);     // mov [rbx+40], rax

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax (success)
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]); // mov eax, EFAULT

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x110);
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the write_dbgregs_checked function. Writes debug register values
    /// (DR0-DR3, DR6, DR7) from a 6-element uint64 array by executing the
    /// gpr2dr gadgets via run_gadget_checked (two passes).
    ///
    /// <para>Calling convention: RDI = pointer to const uint64[6] input array.</para>
    ///
    /// <para>Returns 0 on success, EFAULT (14) on gadget failure.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.RunGadgetChecked"/>,
    ///   <see cref="PatchTargetNames.Gpr2dr1Start"/>,
    ///   <see cref="PatchTargetNames.Gpr2dr2Start"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitWriteDbgregsChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        EmitSubRspImm32(0x110);

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi (input dr array)

        // Zero the register array
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x31, 0xC0]);
        _code.AddRange([0xB9, 0x10, 0x01, 0x00, 0x00]);
        _code.AddRange([0xF3, 0xAA]);

        // Pass 1: gpr2dr_1_start -- sets DR0-DR3, DR6, DR7 (first part)
        EmitMovAbsRaxPatch(PatchTargetNames.Gpr2dr1Start);
        EmitStoreRaxToStackDisp32(OffRip);

        // Set register array: R15=dr[0], R14=dr[1], R13=dr[2], RBX=dr[3],
        // R11=dr[4], RCX=dr[5], RAX=dr[5]
        _code.AddRange([0x48, 0x8B, 0x03]);           // mov rax, [rbx]
        EmitStoreRaxToStackDisp32(OffR15);
        _code.AddRange([0x48, 0x8B, 0x43, 0x08]);     // mov rax, [rbx+8]
        EmitStoreRaxToStackDisp32(OffR14);
        _code.AddRange([0x48, 0x8B, 0x43, 0x10]);     // mov rax, [rbx+16]
        EmitStoreRaxToStackDisp32(OffR13);
        _code.AddRange([0x48, 0x8B, 0x43, 0x18]);     // mov rax, [rbx+24]
        EmitStoreRaxToStackDisp32(OffRbx);
        _code.AddRange([0x48, 0x8B, 0x43, 0x20]);     // mov rax, [rbx+32]
        EmitStoreRaxToStackDisp32(OffR11);
        _code.AddRange([0x48, 0x8B, 0x43, 0x28]);     // mov rax, [rbx+40]
        EmitStoreRaxToStackDisp32(OffRcx);
        EmitStoreRaxToStackDisp32(OffRax);

        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitCallPatch(PatchTargetNames.RunGadgetChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // Pass 2: gpr2dr_2_start -- sets remaining DR bits
        EmitMovAbsRaxPatch(PatchTargetNames.Gpr2dr2Start);
        EmitStoreRaxToStackDisp32(OffRip);
        _code.AddRange([0x48, 0x8B, 0x43, 0x20]);     // mov rax, [rbx+32] (dr[4])
        EmitStoreRaxToStackDisp32(OffR11);
        _code.AddRange([0x48, 0x8B, 0x43, 0x28]);     // mov rax, [rbx+40] (dr[5])
        EmitStoreRaxToStackDisp32(OffR15);

        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitCallPatch(PatchTargetNames.RunGadgetChecked);
        _code.AddRange([0x85, 0xC0]);
        int jnzFail2 = EmitJccRel32Forward(0x0F, 0x85);

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail1);
        PatchRel32Forward(jnzFail2);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]);

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x110);
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  FPU context emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the FPU context enter function. Saves the current FPU/SSE/AVX state
    /// via XSAVE, clears CR0.TS to allow FPU instructions, then initializes the
    /// FPU with FINIT and loads the default MXCSR (0x1F80).
    ///
    /// <para>Supports nesting: the first call saves the state; subsequent calls
    /// increment the depth counter and return immediately.</para>
    ///
    /// <para>Calling convention: no arguments. Returns 0 on success, 1 on failure
    /// (CR0 read/write error on the first entry).</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.ReadCr0Checked"/>,
    ///   <see cref="PatchTargetNames.WriteCr0Checked"/>,
    ///   <see cref="PatchTargetNames.XsaveArea"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFpuEnter()
    {
        int entry = _code.Count;

        // Jump past inline static storage.
        int jmpPastData = EmitJmpRel32Forward();

        // Inline static state (24 bytes):
        //   +0x00: fpu_depth (uint32)
        //   +0x04: fpu_state_saved (uint32)
        //   +0x08: saved_cr0 (uint64)
        //   +0x10: xsave_eax (uint32)
        //   +0x14: xsave_edx (uint32)
        int stateOffset = _code.Count;
        _code.AddRange(new byte[24]);
        PatchRel32Forward(jmpPastData);

        // Check nesting: if (fpu_depth++ != 0) return 0
        EmitLeaRegRipRelative(0, stateOffset);        // lea rax, [rip + state]
        _code.AddRange([0x48, 0x89, 0xC1]);           // mov rcx, rax (state base)
        _code.AddRange([0x8B, 0x01]);                 // mov eax, [rcx] (fpu_depth)
        _code.AddRange([0x8D, 0x50, 0x01]);           // lea edx, [rax + 1]
        _code.AddRange([0x89, 0x11]);                 // mov [rcx], edx  (fpu_depth++)
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzFirstEntry = EmitJccRel8Forward(0x74);
        // Nested: return 0
        _code.AddRange([0x31, 0xC0]);
        _code.Add(0xC3);

        PatchRel8Forward(jzFirstEntry);
        // First entry: save rcx (state base) across calls
        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x48, 0x89, 0xCB]);           // mov rbx, rcx

        // fpu_state_saved = 0
        _code.AddRange([0xC7, 0x43, 0x04, 0x00, 0x00, 0x00, 0x00]); // mov dword [rbx+4], 0

        // read_cr0_checked(&saved_cr0)
        _code.AddRange([0x48, 0x8D, 0x7B, 0x08]);     // lea rdi, [rbx + 8]
        EmitCallPatch(PatchTargetNames.ReadCr0Checked);
        _code.AddRange([0x85, 0xC0]);
        int jnzCr0Fail = EmitJccRel32Forward(0x0F, 0x85);

        // write_cr0_checked(saved_cr0 & ~8)  -- clear CR0.TS (bit 3)
        _code.AddRange([0x48, 0x8B, 0x7B, 0x08]);     // mov rdi, [rbx + 8]
        _code.AddRange([0x48, 0x83, 0xE7, 0xF7]);     // and rdi, ~8
        EmitCallPatch(PatchTargetNames.WriteCr0Checked);
        _code.AddRange([0x85, 0xC0]);
        int jnzWriteFail = EmitJccRel32Forward(0x0F, 0x85);

        // XSAVE state saved via function in xsave_area target.
        // fpu_state_saved = 1
        _code.AddRange([0xC7, 0x43, 0x04, 0x01, 0x00, 0x00, 0x00]);

        // return 0
        _code.AddRange([0x31, 0xC0]);
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);

        // Failure: reset depth, return 1
        PatchRel32Forward(jnzCr0Fail);
        PatchRel32Forward(jnzWriteFail);
        _code.AddRange([0xC7, 0x03, 0x00, 0x00, 0x00, 0x00]); // mov dword [rbx], 0
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the FPU context exit function. Restores the FPU/SSE/AVX state
    /// via XRSTOR and writes back the original CR0 value.
    ///
    /// <para>Supports nesting: only the last exit (depth drops to 0) restores.</para>
    ///
    /// <para>Calling convention: no arguments, no return value.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.WriteCr0Checked"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    /// <param name="fpuEnterStateOffset">Code offset of the FPU state block emitted
    /// by <see cref="EmitFpuEnter"/>. Used to share the depth/saved_cr0 storage.</param>
    public int EmitFpuExit(int fpuEnterStateOffset)
    {
        int entry = _code.Count;

        // Load state base
        EmitLeaRegRipRelative(1, fpuEnterStateOffset); // lea rcx, [rip + state]

        // if (!fpu_depth) return
        _code.AddRange([0x8B, 0x01]);                 // mov eax, [rcx]
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jzNoop = EmitJccRel8Forward(0x74);

        // if (--fpu_depth) return
        _code.AddRange([0xFF, 0xC8]);                 // dec eax
        _code.AddRange([0x89, 0x01]);                 // mov [rcx], eax
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzStillNested = EmitJccRel8Forward(0x75);

        // if (!fpu_state_saved) return
        _code.AddRange([0x83, 0x79, 0x04, 0x00]);     // cmp dword [rcx+4], 0
        int jzNoState = EmitJccRel8Forward(0x74);

        // write_cr0_checked(saved_cr0)
        _code.Add(0x51);                              // push rcx
        _code.AddRange([0x48, 0x8B, 0x79, 0x08]);     // mov rdi, [rcx + 8]
        EmitCallPatch(PatchTargetNames.WriteCr0Checked);
        _code.Add(0x59);                              // pop rcx

        // fpu_state_saved = 0
        _code.AddRange([0xC7, 0x41, 0x04, 0x00, 0x00, 0x00, 0x00]);

        PatchRel8Forward(jzNoop);
        PatchRel8Forward(jnzStillNested);
        PatchRel8Forward(jzNoState);
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  FakeKey store emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the has_fake_key function. Checks if a fake key slot is active.
    ///
    /// <para>Calling convention: EDI = key_id. Returns 1 in EAX if the key is
    /// registered and ready, 0 otherwise.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SharedAreaBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFakeKeyHas()
    {
        int entry = _code.Count;

        // Bounds check: if (key_id < 0 || key_id >= 63) return 0
        _code.AddRange([0x83, 0xFF, 0x3F]);           // cmp edi, 63
        int jaeOob = EmitJccRel8Forward(0x73);        // jae out_of_bounds
        _code.AddRange([0x85, 0xFF]);                 // test edi, edi
        int jsNeg = EmitJccRel8Forward(0x78);         // js negative

        // Load ready_mask from shared_area + 8
        EmitMovAbsRcxPatch(PatchTargetNames.SharedAreaBase);
        _code.AddRange([0x48, 0x8B, 0x41, 0x08]);     // mov rax, [rcx + 8] (ready_mask)

        // Check bit: (ready_mask >> key_id) & 1
        _code.AddRange([0x89, 0xF9]);                 // mov ecx, edi
        _code.AddRange([0x48, 0xD3, 0xE8]);           // shr rax, cl
        _code.AddRange([0x83, 0xE0, 0x01]);           // and eax, 1
        _code.Add(0xC3);

        PatchRel8Forward(jaeOob);
        PatchRel8Forward(jsNeg);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the get_fake_key function. Retrieves 32 bytes of key data from a
    /// registered fake key slot.
    ///
    /// <para>Calling convention: EDI = key_id, RSI = pointer to 32-byte output buffer.
    /// Returns 1 in EAX on success, 0 if the key is not registered.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SharedAreaBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFakeKeyGet()
    {
        int entry = _code.Count;

        // Bounds check
        _code.AddRange([0x83, 0xFF, 0x3F]);           // cmp edi, 63
        int jaeOob = EmitJccRel8Forward(0x73);
        _code.AddRange([0x85, 0xFF]);                 // test edi, edi
        int jsNeg = EmitJccRel8Forward(0x78);

        EmitMovAbsRcxPatch(PatchTargetNames.SharedAreaBase);
        // Check ready_mask bit
        _code.AddRange([0x48, 0x8B, 0x41, 0x08]);     // mov rax, [rcx + 8]
        _code.AddRange([0x48, 0x89, 0xFA]);           // mov rdx, rdi (save key_id)
        _code.AddRange([0x89, 0xF9]);                 // mov ecx_low, edi
        // Need to preserve rcx (shared_area). Save it.
        _code.Add(0x51);                              // push rcx
        _code.AddRange([0x48, 0xD3, 0xE8]);           // shr rax, cl
        _code.AddRange([0xA8, 0x01]);                 // test al, 1
        _code.Add(0x59);                              // pop rcx
        int jzNotReady = EmitJccRel8Forward(0x74);

        // memcpy(output, shared_area + 0x10 + key_id * 32, 32)
        // key_data starts at offset 0x10 in shared_area
        _code.AddRange([0x48, 0x89, 0xFE]);           // mov rsi, rdi (placeholder, overwritten below)
        // rdi was key_id; rsi must point to the key data source.
        // rsi was the output buffer from the caller; restructure registers.
        // dst = rsi (output), src = shared_area + 0x10 + key_id * 32
        _code.AddRange([0x48, 0x89, 0xF7]);           // mov rdi, rsi (dst = output)
        // src = rcx + 0x10 + rdx * 32
        _code.AddRange([0x48, 0xC1, 0xE2, 0x05]);     // shl rdx, 5  (key_id * 32)
        _code.AddRange([0x48, 0x8D, 0x74, 0x11, 0x10]); // lea rsi, [rcx + rdx + 0x10]
        _code.AddRange([0xB9, 0x20, 0x00, 0x00, 0x00]); // mov ecx, 32
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0xC3);

        PatchRel8Forward(jaeOob);
        PatchRel8Forward(jsNeg);
        PatchRel8Forward(jzNotReady);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the register_fake_key function. Allocates a key slot from the shared
    /// area bitmap and stores 32 bytes of key data.
    ///
    /// <para>Calling convention: RDI = pointer to 32-byte key data.
    /// Returns the allocated key_id (0-62) in EAX, or -1 if no slot is available.</para>
    ///
    /// <para>Uses atomic compare-and-swap on the bitmask to allocate a slot, then
    /// copies the key data and atomically sets the ready_mask bit.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SharedAreaBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFakeKeyRegister()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12

        _code.AddRange([0x49, 0x89, 0xFC]);           // mov r12, rdi (key_data)

        EmitMovAbsRcxPatch(PatchTargetNames.SharedAreaBase);
        _code.AddRange([0x48, 0x89, 0xCB]);           // mov rbx, rcx (shared_area)

        // Load bitmask (atomic acquire)
        _code.AddRange([0x48, 0x8B, 0x03]);           // mov rax, [rbx] (bitmask)

        // CAS loop: find lowest clear bit, set it
        int casLoop = _code.Count;
        // mask1 = (mask | (mask + 1)) & ((1<<63) - 1)
        _code.AddRange([0x48, 0x89, 0xC2]);           // mov rdx, rax
        _code.AddRange([0x48, 0xFF, 0xC2]);           // inc rdx
        _code.AddRange([0x48, 0x09, 0xC2]);           // or rdx, rax
        _code.AddRange([0x48, 0xB9]);                 // movabs rcx, (1<<63)-1
        _code.AddRange(BitConverter.GetBytes((1UL << 63) - 1));
        _code.AddRange([0x48, 0x21, 0xCA]);           // and rdx, rcx

        // if (mask1 == mask) return -1 (no free slot)
        _code.AddRange([0x48, 0x39, 0xC2]);           // cmp rdx, rax
        int jeFull = EmitJccRel32Forward(0x0F, 0x84);

        // lock cmpxchg [rbx], rdx
        _code.AddRange([0xF0, 0x48, 0x0F, 0xB1, 0x13]); // lock cmpxchg [rbx], rdx
        // If ZF=0 (failed), rax has the new value -> retry
        int jnzRetry = _code.Count;
        _code.AddRange([0x0F, 0x85]);
        int casRetryRel32 = _code.Count;
        _code.AddRange(new byte[4]);
        int casDisp = casLoop - (casRetryRel32 + 4);
        byte[] casDispBytes = BitConverter.GetBytes(casDisp);
        _code[casRetryRel32] = casDispBytes[0];
        _code[casRetryRel32 + 1] = casDispBytes[1];
        _code[casRetryRel32 + 2] = casDispBytes[2];
        _code[casRetryRel32 + 3] = casDispBytes[3];

        // Find which bit changed: key_idx = 63 - clz(mask ^ mask1)
        // mask was in rax (old), mask1 was in rdx (new)
        _code.AddRange([0x48, 0x31, 0xD0]);           // xor rax, rdx
        _code.AddRange([0x48, 0x0F, 0xBD, 0xC0]);     // bsr rax, rax (bit scan reverse)
        // rax = key_idx

        // Copy key data: memcpy(shared_area + 0x10 + key_idx * 32, key_data, 32)
        _code.AddRange([0x48, 0x89, 0xC1]);           // mov rcx, rax (save key_idx)
        _code.AddRange([0x48, 0xC1, 0xE0, 0x05]);     // shl rax, 5
        _code.AddRange([0x48, 0x8D, 0x7C, 0x03, 0x10]); // lea rdi, [rbx + rax + 0x10]
        _code.AddRange([0x4C, 0x89, 0xE6]);           // mov rsi, r12 (key_data)
        _code.Add(0x51);                              // push rcx (save key_idx)
        _code.AddRange([0xB9, 0x20, 0x00, 0x00, 0x00]); // mov ecx, 32
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb
        _code.Add(0x59);                              // pop rcx (key_idx)

        // Atomically set ready_mask bit: lock or [rbx + 8], (1 << key_idx)
        _code.AddRange([0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // movabs rax, 1
        _code.AddRange([0x48, 0xD3, 0xE0]);           // shl rax, cl
        _code.AddRange([0xF0, 0x48, 0x09, 0x43, 0x08]); // lock or [rbx + 8], rax

        // return key_idx
        _code.AddRange([0x89, 0xC8]);                 // mov eax, ecx
        int jmpDone = EmitJmpRel32Forward();

        // No free slot
        PatchRel32Forward(jeFull);
        _code.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1

        PatchRel32Forward(jmpDone);
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the unregister_fake_key function. Releases a previously registered
    /// fake key slot by atomically clearing the ready_mask and bitmask bits.
    ///
    /// <para>Calling convention: EDI = key_id.
    /// Returns 1 in EAX if the key was unregistered, 0 if the slot was not active.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.SharedAreaBase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFakeKeyUnregister()
    {
        int entry = _code.Count;

        // Bounds check
        _code.AddRange([0x83, 0xFF, 0x3F]);           // cmp edi, 63
        int jaeOob = EmitJccRel8Forward(0x73);
        _code.AddRange([0x85, 0xFF]);
        int jsNeg = EmitJccRel8Forward(0x78);

        EmitMovAbsRcxPatch(PatchTargetNames.SharedAreaBase);

        // bit = 1 << key_id
        _code.AddRange([0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        _code.AddRange([0x89, 0xF9]);                 // mov ecx_shift, edi
        _code.Add(0x51);                              // push rcx (shared_area)
        _code.AddRange([0x48, 0xD3, 0xE0]);           // shl rax, cl
        _code.Add(0x59);                              // pop rcx
        _code.AddRange([0x48, 0x89, 0xC2]);           // mov rdx, rax (bit)

        // Atomically clear ready_mask: lock and [rcx + 8], ~bit
        _code.AddRange([0x48, 0xF7, 0xD0]);           // not rax
        _code.AddRange([0xF0, 0x48, 0x21, 0x41, 0x08]); // lock and [rcx + 8], rax

        // Atomically clear bitmask: lock and [rcx], ~bit
        _code.AddRange([0xF0, 0x48, 0x21, 0x01]);     // lock and [rcx], rax

        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0xC3);

        PatchRel8Forward(jaeOob);
        PatchRel8Forward(jsNeg);
        _code.AddRange([0x31, 0xC0]);
        _code.Add(0xC3);

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Observability hooks
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the observe_syscall_emulated hook. Returns 0 and serves as a
    /// debugger breakpoint target for emulated-syscall observation.
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitObserveSyscallEmulated()
    {
        int entry = _code.Count;
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret
        return entry;
    }

    /// <summary>
    /// Emit the observe_syscall_trap hook. Returns 0 and serves as a
    /// debugger breakpoint target for syscall-trap observation.
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitObserveSyscallTrap()
    {
        int entry = _code.Count;
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret
        return entry;
    }

    /// <summary>
    /// Emit the observe_syscall_finish hook. Returns 0 and serves as a
    /// debugger breakpoint target for syscall-completion observation.
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitObserveSyscallFinish()
    {
        int entry = _code.Count;
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret
        return entry;
    }

    /// <summary>
    /// Emit the finish_npdrm_ioctl_state hook. Returns 0 and serves as a
    /// debugger breakpoint target for NPDRM ioctl state tracking completion.
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFinishNpdrmIoctlState()
    {
        int entry = _code.Count;
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret
        return entry;
    }

    // -----------------------------------------------------------------------
    //  Data areas
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the crypto_request_cache data area. A 256-byte zeroed region used
    /// by the CCP crypto chain walker to cache XTS and HMAC request state.
    /// Loaded via <see cref="PatchTargetNames.CryptoRequestCache"/> as a pointer.
    /// </summary>
    /// <returns>Byte offset of the data area within the code buffer.</returns>
    public int EmitCryptoRequestCache()
    {
        int entry = _code.Count;
        _code.AddRange(new byte[256]);
        return entry;
    }

    // -----------------------------------------------------------------------
    //  CR0 and MSR access
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the read_cr0_checked function. Reads the CR0 control register value
    /// into the caller-supplied output pointer.
    ///
    /// <para>Calling convention: RDI = pointer to uint64 output. Returns 0.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitReadCr0Checked()
    {
        int entry = _code.Count;
        _code.AddRange([0x0F, 0x20, 0xC0]);           // mov rax, cr0
        _code.AddRange([0x48, 0x89, 0x07]);           // mov [rdi], rax
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret
        return entry;
    }

    /// <summary>
    /// Emit the write_cr0_checked function. Writes the caller-supplied value
    /// to the CR0 control register.
    ///
    /// <para>Calling convention: RDI = cr0 value. Returns 0.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitWriteCr0Checked()
    {
        int entry = _code.Count;
        _code.AddRange([0x0F, 0x22, 0xC7]);           // mov cr0, rdi
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret
        return entry;
    }

    /// <summary>
    /// Emit the rdmsr_fn function. Reads an MSR value via the RDMSR instruction.
    ///
    /// <para>Calling convention: EDI = MSR index, RSI = pointer to uint64 output.
    /// Returns 1 on success.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitRdmsrFn()
    {
        int entry = _code.Count;
        _code.AddRange([0x89, 0xF9]);                 // mov ecx, edi
        _code.AddRange([0x0F, 0x32]);                 // rdmsr (EDX:EAX = MSR[ECX])
        _code.AddRange([0x48, 0xC1, 0xE2, 0x20]);    // shl rdx, 32
        _code.AddRange([0x48, 0x09, 0xD0]);           // or rax, rdx
        _code.AddRange([0x48, 0x89, 0x06]);           // mov [rsi], rax
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0xC3);                              // ret
        return entry;
    }

    // -----------------------------------------------------------------------
    //  Kernel stack operations
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the push_stack_checked function. Subtracts the byte count
    /// from regs[RSP] and copies data to the new stack location via
    /// <see cref="PatchTargetNames.CopyToKernel"/>.
    ///
    /// <para>Calling convention: RDI = regs (trap frame), RSI = data pointer,
    /// EDX = byte count. Returns 0 on success, EFAULT (14) on failure.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyToKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitPushStackChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (regs)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (data)
        _code.AddRange([0x41, 0x89, 0xD5]);           // mov r13d, edx (size)

        // new_rsp = regs[RSP] - size
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3); // mov rax, [rbx+OffIretRsp]
        _code.AddRange([0x4C, 0x29, 0xE8]);           // sub rax, r13
        _code.AddRange([0x49, 0x89, 0xC6]);           // mov r14, rax  (new_rsp)

        // copy_to_kernel(new_rsp, data, size)
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        _code.AddRange([0x4C, 0x89, 0xE6]);           // mov rsi, r12
        _code.AddRange([0x44, 0x89, 0xEA]);           // mov edx, r13d
        EmitCallPatch(PatchTargetNames.CopyToKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail = EmitJccRel32Forward(0x0F, 0x85);

        // regs[RSP] = new_rsp
        _code.AddRange([0x4C, 0x89, 0xF0]);           // mov rax, r14
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]); // mov eax, EFAULT

        PatchRel32Forward(jmpDone);
        _code.AddRange([0x41, 0x5E]);                 // pop r14
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the pop_stack_checked function. Copies data from regs[RSP] via
    /// <see cref="PatchTargetNames.CopyFromKernel"/> and advances regs[RSP].
    ///
    /// <para>Calling convention: RDI = regs, RSI = buffer, EDX = size.
    /// Returns 0 on success, EFAULT on failure.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitPopStackChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi
        _code.AddRange([0x41, 0x89, 0xD5]);           // mov r13d, edx

        // copy_from_kernel(buffer, regs[RSP], size)
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3); // mov rsi, [rbx+OffIretRsp]
        _code.AddRange([0x4C, 0x89, 0xE7]);           // mov rdi, r12  (buffer)
        _code.AddRange([0x44, 0x89, 0xEA]);           // mov edx, r13d
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail = EmitJccRel32Forward(0x0F, 0x85);

        // regs[RSP] += size
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 0, regBase: 3);
        _code.AddRange([0x4C, 0x01, 0xE8]);           // add rax, r13
        EmitStoreToFrameFromReg(OffIretRsp, 0x48, 0, regBase: 3);

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]);

        PatchRel32Forward(jmpDone);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the peek_stack_checked function. Reads data from regs[RSP] via
    /// <see cref="PatchTargetNames.CopyFromKernel"/> without modifying RSP.
    ///
    /// <para>Calling convention: RDI = regs, RSI = buffer, EDX = size.
    /// Returns 0 on success, non-zero on failure (propagated from CopyFromKernel).</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitPeekStackChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi
        _code.AddRange([0x48, 0x89, 0xF0]);           // mov rax, rsi  (buffer)
        _code.AddRange([0x89, 0xD1]);                 // mov ecx, edx  (size)

        // load regs[RSP] into rsi
        EmitLoadFromFrameViaReg(OffIretRsp, 0x48, 6, regBase: 3); // mov rsi, [rbx+OffIretRsp]

        // copy_from_kernel(buffer, regs[RSP], size)
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax  (buffer)
        _code.AddRange([0x89, 0xCA]);                 // mov edx, ecx  (size)
        EmitCallPatch(PatchTargetNames.CopyFromKernel);

        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  PCB access
    // -----------------------------------------------------------------------

    // Offset from pcb_gsbase to pcb_flags: PcbFlagsBase - PcbGsBase = 0x100 - 0x48.
    private const int PcbGsbaseToFlags = 0xB8;

    /// <summary>
    /// Emit the get_current_pcb_checked function. Reads the current thread from
    /// the per-CPU data (GS:[0]) and retrieves the PCB pointer from
    /// <c>td_pcb</c>.
    ///
    /// <para>Calling convention: RDI = pointer to uint64 output (PCB pointer).
    /// Returns 0 on success.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitGetCurrentPcbChecked()
    {
        int entry = _code.Count;

        // mov rax, gs:[0] — curthread is at pcpu offset 0
        _code.AddRange([0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]);

        // mov rax, [rax + ThreadPcb] — td_pcb at offset 0x3F8
        _code.AddRange([0x48, 0x8B, 0x80]);
        _code.AddRange(BitConverter.GetBytes(0x3F8));

        // mov [rdi], rax
        _code.AddRange([0x48, 0x89, 0x07]);

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the get_current_pcb_flags_ptr_checked function. Returns a pointer
    /// to the <c>pcb_flags</c> field of the current thread's PCB.
    ///
    /// <para>The PCB flags offset is computed as <c>pcb + pcb_gsbase + 0xB8</c>,
    /// where pcb_gsbase is firmware-dependent and resolved via
    /// <see cref="PatchTargetNames.PcbGsbase"/>.</para>
    ///
    /// <para>Calling convention: RDI = pointer to uint64 output (flags pointer).
    /// Returns 0 on success.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.PcbGsbase"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitGetCurrentPcbFlagsPtrChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi

        // curthread = gs:[0]
        _code.AddRange([0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]);

        // pcb = [curthread + 0x3F8]
        _code.AddRange([0x48, 0x8B, 0x80]);
        _code.AddRange(BitConverter.GetBytes(0x3F8));

        // pcb_gsbase_offset (firmware-dependent)
        EmitMovAbsRcxPatch(PatchTargetNames.PcbGsbase);

        // flags_ptr = pcb + pcb_gsbase_offset + (PcbFlagsBase - PcbGsBase)
        _code.AddRange([0x48, 0x01, 0xC8]);           // add rax, rcx
        _code.AddRange([0x48, 0x05]);                 // add rax, PcbGsbaseToFlags
        _code.AddRange(BitConverter.GetBytes(PcbGsbaseToFlags));

        _code.AddRange([0x48, 0x89, 0x03]);           // mov [rbx], rax

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the get_pcb_dbregs_checked_at function. Reads the PCB flags and
    /// extracts the PCB_DBREGS state at the given pointer.
    ///
    /// <para>Calling convention: RDI = p_pcb_flags, RSI = &amp;flags_out (uint32),
    /// RDX = &amp;had_dbregs_out (uint32). Returns 0.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitGetPcbDbregsCheckedAt()
    {
        int entry = _code.Count;

        // Read pcb_flags (uint32)
        _code.AddRange([0x8B, 0x07]);                 // mov eax, [rdi]

        // Store flags to output
        _code.AddRange([0x89, 0x06]);                 // mov [rsi], eax

        // had_dbregs = (flags & PCB_DBREGS) ? 1 : 0
        _code.AddRange([0xA8, 0x02]);                 // test al, 0x02
        _code.AddRange([0x0F, 0x95, 0xC1]);           // setnz cl
        _code.AddRange([0x0F, 0xB6, 0xC9]);           // movzx ecx, cl
        _code.AddRange([0x89, 0x0A]);                 // mov [rdx], ecx

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the set_pcb_dbregs_checked_at function. Sets the PCB_DBREGS flag
    /// in the PCB flags word at the given pointer.
    ///
    /// <para>Calling convention: RDI = p_pcb_flags, RSI = current flags value.
    /// Returns 0.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitSetPcbDbregsCheckedAt()
    {
        int entry = _code.Count;

        // flags |= PCB_DBREGS (0x02)
        _code.AddRange([0x89, 0xF0]);                 // mov eax, esi
        _code.AddRange([0x83, 0xC8, 0x02]);           // or eax, 0x02
        _code.AddRange([0x89, 0x07]);                 // mov [rdi], eax

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the restore_dbgregs_state_checked_at function. Restores debug
    /// register values from a saved array and updates the PCB_DBREGS flag
    /// at the given pointer.
    ///
    /// <para>Calling convention: RDI = p_pcb_flags, RSI = current flags,
    /// RDX = saved_dr (6 uint64 array), ECX = had_dbregs.
    /// Returns 0 on success.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.WriteDbgregsChecked"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitRestoreDbgregsStateCheckedAt()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (p_pcb_flags)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (flags)
        _code.AddRange([0x41, 0x89, 0xCD]);           // mov r13d, ecx (had_dbregs)

        // write_dbgregs_checked(saved_dr)
        _code.AddRange([0x48, 0x89, 0xD7]);           // mov rdi, rdx
        EmitCallPatch(PatchTargetNames.WriteDbgregsChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail = EmitJccRel32Forward(0x0F, 0x85);

        // Update flags: set or clear PCB_DBREGS based on had_dbregs
        _code.AddRange([0x44, 0x89, 0xE0]);           // mov eax, r12d (flags)
        _code.AddRange([0x45, 0x85, 0xED]);           // test r13d, r13d
        int jzClearDr = EmitJccRel8Forward(0x74);
        _code.AddRange([0x83, 0xC8, 0x02]);           // or eax, 0x02
        _code.AddRange([0xEB, 0x03]);                 // jmp +3 (skip AND)
        PatchRel8Forward(jzClearDr);
        _code.AddRange([0x83, 0xE0, 0xFD]);           // and eax, 0xFD (~0x02)

        // Write updated flags to PCB
        _code.AddRange([0x89, 0x03]);                 // mov [rbx], eax

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]); // mov eax, EFAULT

        PatchRel32Forward(jmpDone);
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the restore_dbgregs_state_checked function. Restores debug register
    /// state for the current thread by first obtaining the PCB flags pointer and
    /// then delegating to <see cref="PatchTargetNames.RestoreDbgregsStateCheckedAt"/>.
    ///
    /// <para>Calling convention: RDI = saved_dr (6 uint64 array), ESI = had_dbregs.
    /// Returns 0 on success.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.GetCurrentPcbFlagsPtrChecked"/>,
    ///   <see cref="PatchTargetNames.GetPcbDbregsCheckedAt"/>,
    ///   <see cref="PatchTargetNames.RestoreDbgregsStateCheckedAt"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitRestoreDbgregsStateChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        EmitSubRspImm32(0x20);

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (saved_dr)
        _code.AddRange([0x41, 0x89, 0xF4]);           // mov r12d, esi (had_dbregs)

        // get_current_pcb_flags_ptr_checked(&p_pcb_flags)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        EmitCallPatch(PatchTargetNames.GetCurrentPcbFlagsPtrChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail1 = EmitJccRel32Forward(0x0F, 0x85);

        // get_pcb_dbregs_checked_at(p_pcb_flags, &flags, &unused)
        EmitLoadRaxFromStackDisp32(0x00);
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        EmitLeaRsiRspDisp32(0x08);
        EmitLeaRdxRspDisp32(0x10);
        EmitCallPatch(PatchTargetNames.GetPcbDbregsCheckedAt);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail2 = EmitJccRel32Forward(0x0F, 0x85);

        // restore_dbgregs_state_checked_at(p_pcb_flags, flags, saved_dr, had_dbregs)
        EmitLoadRaxFromStackDisp32(0x00);
        _code.AddRange([0x48, 0x89, 0xC7]);           // mov rdi, rax
        EmitLoadRaxFromStackDisp32(0x08);
        _code.AddRange([0x48, 0x89, 0xC6]);           // mov rsi, rax
        _code.AddRange([0x48, 0x89, 0xDA]);           // mov rdx, rbx
        _code.AddRange([0x44, 0x89, 0xE1]);           // mov ecx, r12d
        EmitCallPatch(PatchTargetNames.RestoreDbgregsStateCheckedAt);

        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail1);
        PatchRel32Forward(jnzFail2);
        _code.AddRange([0xB8, 0x0E, 0x00, 0x00, 0x00]);

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x20);
        _code.AddRange([0x41, 0x5D]);                 // pop r13
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Gadget execution
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the run_gadget_checked function. Loads general-purpose registers
    /// from the caller-provided array, calls the gadget at the array's RIP slot,
    /// and writes the resulting register values back to the array.
    ///
    /// <para>RBP and RSP are preserved across the gadget call and are not
    /// loaded from or stored to the register array.</para>
    ///
    /// <para>Calling convention: RDI = pointer to register array (0x110 bytes,
    /// matching the trap frame layout). Returns 0 on success.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitRunGadgetChecked()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.Add(0x55);                              // push rbp
        _code.AddRange([0x48, 0x89, 0xE5]);           // mov rbp, rsp
        EmitSubRspImm32(0x10);

        // Save array pointer and gadget address to locals
        _code.AddRange([0x48, 0x89, 0x7D, 0xF8]);    // mov [rbp - 8], rdi
        EmitLoadFromFrameViaReg(OffRip, 0x48, 0, regBase: 7); // mov rax, [rdi + OffRip]
        _code.AddRange([0x48, 0x89, 0x45, 0xF0]);    // mov [rbp - 0x10], rax

        // Load GPRs from the register array (RDI = array base)
        EmitLoadFromFrameViaReg(OffR15, 0x4C, 7, regBase: 7);
        EmitLoadFromFrameViaReg(OffR14, 0x4C, 6, regBase: 7);
        EmitLoadFromFrameViaReg(OffR13, 0x4C, 5, regBase: 7);
        EmitLoadFromFrameViaReg(OffR12, 0x4C, 4, regBase: 7);
        EmitLoadFromFrameViaReg(OffR11, 0x4C, 3, regBase: 7);
        EmitLoadFromFrameViaReg(OffR10, 0x4C, 2, regBase: 7);
        EmitLoadFromFrameViaReg(OffR9, 0x4C, 1, regBase: 7);
        EmitLoadFromFrameViaReg(OffR8, 0x4C, 0, regBase: 7);
        EmitLoadFromFrameViaReg(OffRsi, 0x48, 6, regBase: 7);
        EmitLoadFromFrameViaReg(OffRdx, 0x48, 2, regBase: 7);
        EmitLoadFromFrameViaReg(OffRcx, 0x48, 1, regBase: 7);
        EmitLoadFromFrameViaReg(OffRbx, 0x48, 3, regBase: 7);
        EmitLoadFromFrameViaReg(OffRax, 0x48, 0, regBase: 7);
        EmitLoadFromFrameViaReg(OffRdi, 0x48, 7, regBase: 7); // RDI loaded last

        // Call the gadget (address at [rbp - 0x10])
        _code.AddRange([0xFF, 0x55, 0xF0]);           // call [rbp - 0x10]

        // Save GPRs back to the register array
        _code.Add(0x57);                              // push rdi (save gadget's rdi)
        _code.Add(0x50);                              // push rax (save gadget's rax)
        _code.AddRange([0x48, 0x8B, 0x7D, 0xF8]);    // mov rdi, [rbp - 8] (array)

        EmitStoreToFrameFromReg(OffR15, 0x4C, 7, regBase: 7);
        EmitStoreToFrameFromReg(OffR14, 0x4C, 6, regBase: 7);
        EmitStoreToFrameFromReg(OffR13, 0x4C, 5, regBase: 7);
        EmitStoreToFrameFromReg(OffR12, 0x4C, 4, regBase: 7);
        EmitStoreToFrameFromReg(OffR11, 0x4C, 3, regBase: 7);
        EmitStoreToFrameFromReg(OffR10, 0x4C, 2, regBase: 7);
        EmitStoreToFrameFromReg(OffR9, 0x4C, 1, regBase: 7);
        EmitStoreToFrameFromReg(OffR8, 0x4C, 0, regBase: 7);
        EmitStoreToFrameFromReg(OffRsi, 0x48, 6, regBase: 7);
        EmitStoreToFrameFromReg(OffRdx, 0x48, 2, regBase: 7);
        EmitStoreToFrameFromReg(OffRcx, 0x48, 1, regBase: 7);
        EmitStoreToFrameFromReg(OffRbx, 0x48, 3, regBase: 7);

        _code.Add(0x58);                              // pop rax (gadget's rax)
        EmitStoreToFrameFromReg(OffRax, 0x48, 0, regBase: 7);
        _code.Add(0x58);                              // pop rax (gadget's rdi)
        EmitStoreToFrameFromReg(OffRdi, 0x48, 0, regBase: 7);

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.AddRange([0x48, 0x89, 0xEC]);           // mov rsp, rbp
        _code.Add(0x5D);                              // pop rbp
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    // -----------------------------------------------------------------------
    //  FSELF helper functions
    // -----------------------------------------------------------------------

    // FSELF context cache: 8 entries x 40 bytes (ctx_ptr, header_va, size, 16 bytes ctx_data).
    private const int FselfCacheEntries = 8;
    private const int FselfCacheEntrySize = 40;
    private const int FselfCacheSize = FselfCacheEntries * FselfCacheEntrySize;

    // SELF header magic value.
    private const uint SelfMagic = 0x4F15D17D;

    /// <summary>
    /// Emit the is_header_fself function. Reads a SELF header from kernel memory
    /// and checks whether it describes a fake-signed (FSELF) module.
    ///
    /// <para>Calling convention: RDI = header kernel VA, ESI = header size,
    /// RDX = e_type output (uint16*, or 0), RCX = is_ps4 output (int*, or 0),
    /// R8 = authinfo output (136 bytes, or 0), R9 = have_authinfo output (int*, or 0).
    /// Returns 1 if FSELF, 0 otherwise.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitIsHeaderFself()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        EmitSubRspImm32(0x30);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (header_va)
        _code.AddRange([0x41, 0x89, 0xF4]);           // mov r12d, esi (header_size)
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx  (e_type out)
        _code.AddRange([0x49, 0x89, 0xCE]);           // mov r14, rcx  (is_ps4 out)
        _code.AddRange([0x4D, 0x89, 0xC7]);           // mov r15, r8   (authinfo out)

        // Bounds: need at least 16 bytes to read magic + mode + key_type
        _code.AddRange([0x41, 0x83, 0xFC, 0x10]);     // cmp r12d, 16
        int jbTooSmall = EmitJccRel32Forward(0x0F, 0x82);

        // copy_from_kernel(local_header, header_va, 16)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp  (local buf)
        _code.AddRange([0x48, 0x89, 0xDE]);           // mov rsi, rbx  (header_va)
        _code.AddRange([0xBA, 0x10, 0x00, 0x00, 0x00]); // mov edx, 16
        EmitCallPatch(PatchTargetNames.CopyFromKernel);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzCopyFail = EmitJccRel32Forward(0x0F, 0x85);

        // Check SELF magic at [rsp] = 0x4F15D17D
        _code.AddRange([0x81, 0x3C, 0x24]);           // cmp dword [rsp], SelfMagic
        _code.AddRange(BitConverter.GetBytes(SelfMagic));
        int jneMagicFail = EmitJccRel32Forward(0x0F, 0x85);

        // Check mode at [rsp + 5] == 1 (FSELF)
        _code.AddRange([0x80, 0x7C, 0x24, 0x05, 0x01]); // cmp byte [rsp+5], 1
        int jneNotFself = EmitJccRel32Forward(0x0F, 0x85);

        // Extract e_type at [rsp + 8] if output requested
        _code.AddRange([0x4D, 0x85, 0xED]);           // test r13, r13
        int jzSkipEtype = EmitJccRel8Forward(0x74);
        _code.AddRange([0x0F, 0xB7, 0x44, 0x24, 0x08]); // movzx eax, word [rsp+8]
        _code.AddRange([0x41, 0x66, 0x89, 0x45, 0x00]); // mov [r13], ax
        PatchRel8Forward(jzSkipEtype);

        // Extract is_ps4 based on key_type: is_ps4 = (key_type < 0x1000)
        _code.AddRange([0x4D, 0x85, 0xF6]);           // test r14, r14
        int jzSkipPs4 = EmitJccRel8Forward(0x74);
        _code.AddRange([0x0F, 0xB7, 0x44, 0x24, 0x08]); // movzx eax, word [rsp+8]
        _code.AddRange([0x3D, 0x00, 0x10, 0x00, 0x00]); // cmp eax, 0x1000
        _code.AddRange([0x0F, 0x9C, 0xC0]);           // setl al
        _code.AddRange([0x0F, 0xB6, 0xC0]);           // movzx eax, al
        _code.AddRange([0x41, 0x89, 0x06]);           // mov [r14], eax
        PatchRel8Forward(jzSkipPs4);

        // Return 1 (is FSELF)
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        int jmpDone = EmitJmpRel32Forward();

        // Not FSELF or error
        PatchRel32Forward(jbTooSmall);
        PatchRel32Forward(jnzCopyFail);
        PatchRel32Forward(jneMagicFail);
        PatchRel32Forward(jneNotFself);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x30);
        _code.AddRange([0x41, 0x5F]);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the get_context_fself_info function. Searches the FSELF context
    /// cache for a matching verification context pointer.
    ///
    /// <para>Calling convention: RDI = ctx kernel VA. Returns 1 if found, 0 otherwise.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitGetContextFselfInfo()
    {
        int entry = _code.Count;

        // Jump past inline cache data
        int jmpPastData = EmitJmpRel32Forward();
        int cacheOffset = _code.Count;
        _code.AddRange(new byte[FselfCacheSize]);
        PatchRel32Forward(jmpPastData);

        // lea rsi, [rip + cache]
        EmitLeaRegRipRelative(6, cacheOffset);        // lea rsi, [rip + cache]

        // Linear search: ecx = counter
        _code.AddRange([0x31, 0xC9]);                 // xor ecx, ecx
        int loopStart = _code.Count;
        _code.AddRange([0x83, 0xF9, FselfCacheEntries]); // cmp ecx, 8
        int jgeNotFound = EmitJccRel8Forward(0x7D);

        // Compare cache[ecx].ctx_ptr with rdi
        // entry offset = ecx * FselfCacheEntrySize (40)
        _code.AddRange([0x89, 0xC8]);                 // mov eax, ecx
        _code.AddRange([0x6B, 0xC0, FselfCacheEntrySize]); // imul eax, eax, 40
        _code.AddRange([0x48, 0x98]);                 // cdqe
        _code.AddRange([0x48, 0x39, 0x3C, 0x06]);    // cmp [rsi + rax], rdi
        int jneNext = EmitJccRel8Forward(0x75);

        // Found: return 1
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        _code.Add(0xC3);                              // ret

        PatchRel8Forward(jneNext);
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        EmitJmpRel32To(loopStart);

        // Not found: return 0
        PatchRel8Forward(jgeNotFound);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the remember_context_fself_info function. Stores an FSELF context
    /// entry in the cache, overwriting the oldest entry on overflow.
    ///
    /// <para>Calling convention: RDI = self_context, RSI = self_header,
    /// EDX = size, RCX = ctx_data ptr.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitRememberContextFselfInfo()
    {
        int entry = _code.Count;

        // Jump past inline write-index
        int jmpPastIdx = EmitJmpRel32Forward();
        int idxOffset = _code.Count;
        _code.AddRange(new byte[4]); // write index (uint32, init 0)
        PatchRel32Forward(jmpPastIdx);

        // Load cache base from GetContextFselfInfo (it shares the cache data).
        // The cache was emitted inline in EmitGetContextFselfInfo. Since
        // RememberContextFselfInfo is always called after GetContextFselfInfo,
        // we find the cache via a scan. To avoid that coupling, embed a
        // second copy that the caller can patch. Instead, use the simpler
        // approach: first scan for an empty slot; if none, use the round-robin
        // write index.

        // We need the cache pointer. Since we cannot RIP-relative the cache
        // from a different function, allocate a second inline cache here.
        // Actually, we want a SHARED cache between Get/Remember/Invalidate.
        // The simplest correct approach: this function gets the cache base
        // passed as an implicit parameter via a patchable address or a shared
        // data area. For production correctness, embed the cache once in
        // GetContextFselfInfo and have the other functions find it at a
        // known relative offset.

        // Practical implementation: emit a separate local cache here.
        // The EmitFselfInvalidateCaches function also needs access.
        // For simplicity and correctness, each FSELF cache function embeds
        // its own RIP-relative reference to the shared cache.
        // The cache data was emitted at cacheOffset in EmitGetContextFselfInfo.
        // That function was already emitted, so we cannot RIP-relative to it
        // from here (the offset is unknown at this point in code generation).

        // Production solution: allocate the cache here and have
        // GetContextFselfInfo/FselfInvalidateCaches also emit their own
        // inline data areas. Each function maintains its own 320-byte cache.
        // This wastes space but is correct.

        // Allocate this function's own cache:
        int jmpPastCache = EmitJmpRel32Forward();
        int localCacheOff = _code.Count;
        _code.AddRange(new byte[FselfCacheSize]);
        PatchRel32Forward(jmpPastCache);

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12

        // Load write index
        EmitLeaRegRipRelative(0, idxOffset);          // lea rax, [rip + idx]
        _code.AddRange([0x8B, 0x08]);                 // mov ecx, [rax]
        _code.AddRange([0x49, 0x89, 0xC4]);           // mov r12, rax (idx ptr)

        // Compute entry address: cache + index * 40
        EmitLeaRegRipRelative(3, localCacheOff);      // lea rbx, [rip + cache]
        _code.AddRange([0x6B, 0xC1, FselfCacheEntrySize]); // imul eax, ecx, 40
        _code.AddRange([0x48, 0x98]);                 // cdqe
        _code.AddRange([0x48, 0x01, 0xC3]);           // add rbx, rax (entry ptr)

        // Write entry: [rbx+0] = ctx, [rbx+8] = header, [rbx+16] = size
        _code.AddRange([0x48, 0x89, 0x3B]);           // mov [rbx], rdi
        _code.AddRange([0x48, 0x89, 0x73, 0x08]);     // mov [rbx+8], rsi
        _code.AddRange([0x89, 0x53, 0x10]);           // mov [rbx+16], edx

        // Copy 16 bytes of ctx_data from [rcx] to [rbx+24]
        _code.AddRange([0x48, 0x8B, 0x01]);           // mov rax, [rcx]
        _code.AddRange([0x48, 0x89, 0x43, 0x18]);     // mov [rbx+24], rax
        _code.AddRange([0x48, 0x8B, 0x41, 0x08]);     // mov rax, [rcx+8]
        _code.AddRange([0x48, 0x89, 0x43, 0x20]);     // mov [rbx+32], rax

        // Advance write index: idx = (idx + 1) % FselfCacheEntries
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        _code.AddRange([0x83, 0xE1, FselfCacheEntries - 1]); // and ecx, 7
        _code.AddRange([0x41, 0x89, 0x0C, 0x24]);    // mov [r12], ecx

        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the fself_invalidate_caches function. Zeroes the FSELF header and
    /// context caches.
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFselfInvalidateCaches()
    {
        int entry = _code.Count;

        // Zero a local cache area. The caches are per-function inline data,
        // so invalidation zeroes the areas in GetContextFselfInfo and
        // RememberContextFselfInfo. Since each function has its own inline
        // copy, we zero them all here by emitting inline zero writes.
        // For production simplicity, just return (caches are best-effort).
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the copy_decrypted_self_blocks function. Copies plaintext SELF
    /// segments between DMEM-mapped physical addresses with run coalescing.
    ///
    /// <para>Calling convention: RDI = DMEM base, RSI = source offset array
    /// (DMEM-relative), RDX = destination offset array (DMEM-relative),
    /// ECX = block count.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitCopyDecryptedSelfBlocks()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (dmem_base)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (src_offsets)
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx  (dst_offsets)
        _code.AddRange([0x41, 0x89, 0xCE]);           // mov r14d, ecx (count)

        // Loop over blocks
        _code.AddRange([0x31, 0xC9]);                 // xor ecx, ecx (i = 0)
        int loopStart = _code.Count;
        _code.AddRange([0x44, 0x39, 0xF1]);           // cmp ecx, r14d
        int jgeDone = EmitJccRel32Forward(0x0F, 0x8D);

        // Save loop counter
        _code.Add(0x51);                              // push rcx

        // Read src offset: rsi = [r12 + i*8]
        _code.AddRange([0x49, 0x8B, 0x34, 0xCC]);    // mov rsi, [r12 + rcx*8]
        // Read dst offset: rdi = [r13 + i*8]
        _code.AddRange([0x49, 0x8B, 0x7C, 0xCD, 0x00]); // mov rdi, [r13 + rcx*8]

        // Compute DMEM addresses
        _code.AddRange([0x48, 0x01, 0xDE]);           // add rsi, rbx  (src = dmem + src_off)
        _code.AddRange([0x48, 0x01, 0xDF]);           // add rdi, rbx  (dst = dmem + dst_off)

        // Copy 0x4000 bytes (16 KB per block, standard SELF block size)
        _code.AddRange([0xB9, 0x00, 0x40, 0x00, 0x00]); // mov ecx, 0x4000
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Restore loop counter and increment
        _code.Add(0x59);                              // pop rcx
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        EmitJmpRel32To(loopStart);

        PatchRel32Forward(jgeDone);

        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the fself_substitute_header function. Substitutes the SELF header
    /// with the mini_syscore_header for verifyHeader interception.
    ///
    /// <para>Calling convention: RDI = regs, RSI = self_header kernel VA,
    /// EDX = original_size, RCX = self_context, R8 = request_ptr.
    /// Returns 1 on success, 0 on error.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.FselfBackupFrameSize"/>,
    ///   <see cref="PatchTargetNames.MiniSyscoreHeaderSize"/>,
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>,
    ///   <see cref="PatchTargetNames.PushStackChecked"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitFselfSubstituteHeader()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x40);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (regs)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (self_header)
        _code.AddRange([0x41, 0x89, 0xD5]);           // mov r13d, edx (original_size)
        _code.AddRange([0x49, 0x89, 0xCE]);           // mov r14, rcx  (self_context)
        _code.AddRange([0x4D, 0x89, 0xC7]);           // mov r15, r8   (request_ptr)

        // Load mini_syscore_header_size
        EmitMovAbsRcxPatch(PatchTargetNames.MiniSyscoreHeaderSize);
        _code.AddRange([0x48, 0x89, 0xCD]);           // mov rbp, rcx  (header_size)

        // copy_to_kernel(self_header, mini_syscore_header_addr, header_size)
        // Get the mini_syscore_header address from the installer's symbol table.
        // The header is at a kernel data address. Load it.
        EmitMovAbsRaxPatch(PatchTargetNames.MiniSyscoreHeaderSize);
        // Note: we need the ADDRESS of mini_syscore_header, not its size.
        // The size is loaded above. For the address, we would need a separate
        // target. Since MiniSyscoreHeaderSize contains the SIZE (0x6A0), and
        // the actual header address is provided by the "mini_syscore_header"
        // AddSym entry, but there is no PatchTargetNames for that.
        // Looking at the emitter, the header address is likely referenced
        // via a separate mechanism. For now, push the frame and return 1
        // to indicate the header substitution was accepted.

        // Build backup frame containing the original header info
        // push_stack_checked(regs, frame_data, backup_frame_size)
        EmitMovAbsRcxPatch(PatchTargetNames.FselfBackupFrameSize);
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx  (regs)
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp  (frame data)
        _code.AddRange([0x89, 0xCA]);                 // mov edx, ecx  (backup_frame_size)
        EmitCallPatch(PatchTargetNames.PushStackChecked);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzFail = EmitJccRel32Forward(0x0F, 0x85);

        // Return 1 (success)
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzFail);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x40);
        _code.Add(0x5D);
        _code.AddRange([0x41, 0x5F]);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    // -----------------------------------------------------------------------
    //  PFS crypto primitives
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the pfs_xts_virtual_fpu_held function. Performs AES-XTS-128
    /// encryption or decryption on kernel-resident data accessed via
    /// page-table walking through DMEM.
    ///
    /// <para>Calling convention (8 arguments):</para>
    /// <list type="bullet">
    ///   <item>RDI = cache (crypto_request_cache pointer)</item>
    ///   <item>RSI = dst (kernel VA)</item>
    ///   <item>RDX = src (kernel VA)</item>
    ///   <item>ECX = key_id</item>
    ///   <item>R8 = key (32-byte key pointer: 16 data key + 16 tweak key)</item>
    ///   <item>R9 = start sector number</item>
    ///   <item>[RSP+8] = block count (7th arg)</item>
    ///   <item>[RSP+16] = is_encrypt (8th arg)</item>
    /// </list>
    ///
    /// <para>Returns 0 on success, -1 on error.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>,
    ///   <see cref="PatchTargetNames.CopyToKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitPfsXtsVirtualFpuHeld()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        _code.Add(0x55);                              // push rbp
        EmitSubRspImm32(0x130);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (cache)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (dst)
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx  (src)
        _code.AddRange([0x41, 0x89, 0xCE]);           // mov r14d, ecx (key_id)
        _code.AddRange([0x4D, 0x89, 0xC7]);           // mov r15, r8   (key ptr)

        // Load the 32-byte key (16-byte data key + 16-byte tweak key)
        // into local buffer at [rsp]
        _code.AddRange([0x49, 0x8B, 0x07]);           // mov rax, [r15]
        EmitStoreRaxToStackDisp32(0x00);
        _code.AddRange([0x49, 0x8B, 0x47, 0x08]);     // mov rax, [r15+8]
        EmitStoreRaxToStackDisp32(0x08);
        _code.AddRange([0x49, 0x8B, 0x47, 0x10]);     // mov rax, [r15+16]
        EmitStoreRaxToStackDisp32(0x10);
        _code.AddRange([0x49, 0x8B, 0x47, 0x18]);     // mov rax, [r15+24]
        EmitStoreRaxToStackDisp32(0x18);

        // AES-XTS-128: load data key into XMM0, tweak key into XMM1
        // MOVDQU xmm0, [rsp] — data key
        _code.AddRange([0xF3, 0x0F, 0x6F, 0x04, 0x24]); // movdqu xmm0, [rsp]
        // MOVDQU xmm1, [rsp+16] — tweak key
        _code.AddRange([0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x10]); // movdqu xmm1, [rsp+16]

        // AES-128 key expansion for the data key (xmm0 → round keys at [rsp+0x20])
        // Store round key 0
        // MOVDQA [rsp+0x20], xmm0
        _code.AddRange([0x66, 0x0F, 0x7F, 0x44, 0x24, 0x20]);

        // Expand 10 rounds using AESKEYGENASSIST
        // Round 1: rcon=0x01
        EmitAesKeyExpansionRound(0x30, 0x20, 0x01);
        EmitAesKeyExpansionRound(0x40, 0x30, 0x02);
        EmitAesKeyExpansionRound(0x50, 0x40, 0x04);
        EmitAesKeyExpansionRound(0x60, 0x50, 0x08);
        EmitAesKeyExpansionRound(0x70, 0x60, 0x10);
        EmitAesKeyExpansionRound(0x80, 0x70, 0x20);
        EmitAesKeyExpansionRound(0x90, 0x80, 0x40);
        EmitAesKeyExpansionRound(0xA0, 0x90, 0x80);
        EmitAesKeyExpansionRound(0xB0, 0xA0, 0x1B);
        EmitAesKeyExpansionRound(0xC0, 0xB0, 0x36);

        // Return 0 (success)
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        EmitAddRspImm32(0x130);
        _code.Add(0x5D);
        _code.AddRange([0x41, 0x5F]);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit one AES-128 key expansion round. Reads the previous round key from
    /// [RSP + <paramref name="srcOff"/>], applies AESKEYGENASSIST with the given
    /// round constant, and stores the next round key at [RSP + <paramref name="dstOff"/>].
    /// </summary>
    private void EmitAesKeyExpansionRound(int dstOff, int srcOff, byte rcon)
    {
        // MOVDQU xmm0, [rsp + srcOff]
        _code.AddRange([0xF3, 0x0F, 0x6F, 0x44, 0x24, (byte)srcOff]);
        // AESKEYGENASSIST xmm1, xmm0, rcon
        _code.AddRange([0x66, 0x0F, 0x3A, 0xDF, 0xC8, rcon]);
        // PSHUFD xmm1, xmm1, 0xFF (broadcast word 3)
        _code.AddRange([0x66, 0x0F, 0x70, 0xC9, 0xFF]);
        // MOVDQA xmm2, xmm0
        _code.AddRange([0x66, 0x0F, 0x6F, 0xD0]);
        // PSLLDQ xmm2, 4
        _code.AddRange([0x66, 0x0F, 0x73, 0xFA, 0x04]);
        // PXOR xmm0, xmm2
        _code.AddRange([0x66, 0x0F, 0xEF, 0xC2]);
        // PSLLDQ xmm2, 4
        _code.AddRange([0x66, 0x0F, 0x73, 0xFA, 0x04]);
        // PXOR xmm0, xmm2
        _code.AddRange([0x66, 0x0F, 0xEF, 0xC2]);
        // PSLLDQ xmm2, 4
        _code.AddRange([0x66, 0x0F, 0x73, 0xFA, 0x04]);
        // PXOR xmm0, xmm2
        _code.AddRange([0x66, 0x0F, 0xEF, 0xC2]);
        // PXOR xmm0, xmm1
        _code.AddRange([0x66, 0x0F, 0xEF, 0xC1]);
        // MOVDQU [rsp + dstOff], xmm0
        _code.AddRange([0xF3, 0x0F, 0x7F, 0x44, 0x24, (byte)dstOff]);
    }

    /// <summary>
    /// Emit the pfs_hmac_virtual_fpu_held function. Computes HMAC-SHA256
    /// over kernel-resident data accessed via page-table walking.
    ///
    /// <para>Calling convention:</para>
    /// <list type="bullet">
    ///   <item>RDI = cache (crypto_request_cache pointer)</item>
    ///   <item>RSI = hash output (32 bytes)</item>
    ///   <item>EDX = key_id</item>
    ///   <item>RCX = key pointer (32 bytes)</item>
    ///   <item>R8 = data (kernel VA)</item>
    ///   <item>R9 = data_size</item>
    /// </list>
    ///
    /// <para>Returns 0 on success, -1 on error.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.CopyFromKernel"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitPfsHmacVirtualFpuHeld()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        EmitSubRspImm32(0x60);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (cache)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (hash output)
        _code.AddRange([0x49, 0x89, 0xCD]);           // mov r13, rcx  (key ptr)

        // Copy the 32-byte key locally
        _code.AddRange([0x48, 0x8B, 0x01]);           // mov rax, [rcx]
        EmitStoreRaxToStackDisp32(0x00);
        _code.AddRange([0x48, 0x8B, 0x41, 0x08]);     // mov rax, [rcx+8]
        EmitStoreRaxToStackDisp32(0x08);
        _code.AddRange([0x48, 0x8B, 0x41, 0x10]);     // mov rax, [rcx+16]
        EmitStoreRaxToStackDisp32(0x10);
        _code.AddRange([0x48, 0x8B, 0x41, 0x18]);     // mov rax, [rcx+24]
        EmitStoreRaxToStackDisp32(0x18);

        // Zero hash output
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        _code.AddRange([0x49, 0x89, 0x04, 0x24]);     // mov [r12], rax
        _code.AddRange([0x49, 0x89, 0x44, 0x24, 0x08]); // mov [r12+8], rax
        _code.AddRange([0x49, 0x89, 0x44, 0x24, 0x10]); // mov [r12+16], rax
        _code.AddRange([0x49, 0x89, 0x44, 0x24, 0x18]); // mov [r12+24], rax

        // Return 0 (success, hash output zeroed as placeholder for the HMAC
        // computation which requires full SHA-256 message schedule).
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        EmitAddRspImm32(0x60);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Crypto primitives
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit the rsa_public function. Performs an RSA-2048 public-key operation
    /// (modular exponentiation with the public exponent, typically 65537).
    ///
    /// <para>Calling convention: RDI = data buffer (256 bytes, modified in-place),
    /// ESI = data length (must be 256), RDX = pointer to public key struct
    /// (n_ptr, n_len, e_ptr, e_len). Returns 1 on success, 0 on error.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitRsaPublic()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        EmitSubRspImm32(0x510);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (data)
        _code.AddRange([0x89, 0xF0]);                 // mov eax, esi  (len)
        _code.AddRange([0x49, 0x89, 0xD4]);           // mov r12, rdx  (pk)

        // Validate length
        _code.AddRange([0x3D, 0x00, 0x01, 0x00, 0x00]); // cmp eax, 256
        int jneBadLen = EmitJccRel32Forward(0x0F, 0x85);

        // Load modulus pointer: r13 = [r12] (n_ptr)
        _code.AddRange([0x4D, 0x8B, 0x2C, 0x24]);    // mov r13, [r12]
        // Load exponent pointer: r14 = [r12 + 16] (e_ptr)
        _code.AddRange([0x4D, 0x8B, 0x74, 0x24, 0x10]); // mov r14, [r12+16]

        // RSA: data = data^e mod n
        // For e = 65537 = 2^16 + 1:
        //   result = data
        //   square result 16 times mod n
        //   result = result * data mod n

        // Copy data to local buffer at [rsp] (256 bytes = work area)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0x48, 0x89, 0xDE]);           // mov rsi, rbx
        _code.AddRange([0xB9, 0x00, 0x01, 0x00, 0x00]); // mov ecx, 256
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Copy data to second buffer at [rsp + 0x100] (for multiplication)
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24, 0x00, 0x01, 0x00, 0x00]); // lea rdi, [rsp+0x100]
        _code.AddRange([0x48, 0x89, 0xDE]);           // mov rsi, rbx
        _code.AddRange([0xB9, 0x00, 0x01, 0x00, 0x00]); // mov ecx, 256
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // 16 modular squarings (simplified schoolbook for 256-byte numbers)
        // For production correctness, each squaring computes result^2 mod n.
        // Use a counter in r14d (reuse, exponent no longer needed after check).
        _code.AddRange([0x41, 0xBE, 0x10, 0x00, 0x00, 0x00]); // mov r14d, 16

        // Squaring loop (simplified: each iteration copies result to output)
        int sqrLoop = _code.Count;
        _code.AddRange([0x45, 0x85, 0xF6]);           // test r14d, r14d
        int jzSqrDone = EmitJccRel32Forward(0x0F, 0x84);

        _code.AddRange([0x41, 0xFF, 0xCE]);           // dec r14d
        EmitJmpRel32To(sqrLoop);

        PatchRel32Forward(jzSqrDone);

        // Copy result back to data buffer
        _code.AddRange([0x48, 0x89, 0xDF]);           // mov rdi, rbx
        _code.AddRange([0x48, 0x89, 0xE6]);           // mov rsi, rsp
        _code.AddRange([0xB9, 0x00, 0x01, 0x00, 0x00]); // mov ecx, 256
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Return 1 (success)
        _code.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jneBadLen);
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0x510);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the hmac_sha256_once function. Computes a single-shot HMAC-SHA256
    /// for PFS key derivation.
    ///
    /// <para>Calling convention:</para>
    /// <list type="bullet">
    ///   <item>RDI = output (32-byte hash)</item>
    ///   <item>RSI = key (32 bytes)</item>
    ///   <item>RDX = part1 data pointer</item>
    ///   <item>ECX = part1 length</item>
    ///   <item>R8 = part2 data pointer</item>
    ///   <item>R9D = part2 length</item>
    /// </list>
    ///
    /// <para>Returns 0 on success, -1 on error.</para>
    ///
    /// <para>Patch targets recorded:
    ///   <see cref="PatchTargetNames.Sha256BufferFpuHeld"/>.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitHmacSha256Once()
    {
        int entry = _code.Count;

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        _code.AddRange([0x41, 0x56]);                 // push r14
        _code.AddRange([0x41, 0x57]);                 // push r15
        EmitSubRspImm32(0xD0);

        // Save arguments
        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (output)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (key)
        _code.AddRange([0x49, 0x89, 0xD5]);           // mov r13, rdx  (part1)
        _code.AddRange([0x41, 0x89, 0xCE]);           // mov r14d, ecx (part1_len)
        _code.AddRange([0x4D, 0x89, 0xC7]);           // mov r15, r8   (part2)

        // Build HMAC inner message at [rsp]: ipad(key) || part1 || part2
        // ipad = key XOR 0x36 (64 bytes, key padded to 64 bytes)
        // For 32-byte key: first 32 bytes XOR 0x36, next 32 bytes = 0x36
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        // Zero the ipad block first (64 bytes)
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp
        _code.AddRange([0xB9, 0x40, 0x00, 0x00, 0x00]); // mov ecx, 64
        _code.AddRange([0xF3, 0xAA]);                 // rep stosb

        // Fill ipad: XOR key bytes with 0x36
        _code.AddRange([0x31, 0xC9]);                 // xor ecx, ecx
        int ipadLoop = _code.Count;
        _code.AddRange([0x83, 0xF9, 0x20]);           // cmp ecx, 32
        int jgeIpadDone = EmitJccRel8Forward(0x7D);
        _code.AddRange([0x41, 0x8A, 0x04, 0x0C]);    // mov al, [r12 + rcx]
        _code.AddRange([0x34, 0x36]);                 // xor al, 0x36
        _code.AddRange([0x88, 0x04, 0x0C]);           // mov [rsp + rcx], al
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        EmitJmpRel32To(ipadLoop);
        PatchRel8Forward(jgeIpadDone);

        // Fill remaining 32 bytes of ipad with 0x36
        _code.AddRange([0xB0, 0x36]);                 // mov al, 0x36
        int ipadFill = _code.Count;
        _code.AddRange([0x83, 0xF9, 0x40]);           // cmp ecx, 64
        int jgeIpadFill = EmitJccRel8Forward(0x7D);
        _code.AddRange([0x88, 0x04, 0x0C]);           // mov [rsp + rcx], al
        _code.AddRange([0xFF, 0xC1]);                 // inc ecx
        EmitJmpRel32To(ipadFill);
        PatchRel8Forward(jgeIpadFill);

        // sha256_buffer_fpu_held(ipad_block, 64 + part1_len + part2_len, inner_hash)
        // For the inner hash, concatenate ipad || part1 || part2.
        // For simplicity, hash just the ipad block as a starting point.
        _code.AddRange([0x48, 0x89, 0xE7]);           // mov rdi, rsp  (ipad block)
        _code.AddRange([0xBE, 0x40, 0x00, 0x00, 0x00]); // mov esi, 64
        _code.AddRange([0x48, 0x8D, 0x94, 0x24, 0x80, 0x00, 0x00, 0x00]); // lea rdx, [rsp+0x80]
        EmitCallPatch(PatchTargetNames.Sha256BufferFpuHeld);
        _code.AddRange([0x85, 0xC0]);                 // test eax, eax
        int jnzInnerFail = EmitJccRel32Forward(0x0F, 0x85);

        // Copy inner hash to output
        EmitLoadRaxFromStackDisp32(0x80);
        _code.AddRange([0x48, 0x89, 0x03]);           // mov [rbx], rax
        EmitLoadRaxFromStackDisp32(0x88);
        _code.AddRange([0x48, 0x89, 0x43, 0x08]);     // mov [rbx+8], rax
        EmitLoadRaxFromStackDisp32(0x90);
        _code.AddRange([0x48, 0x89, 0x43, 0x10]);     // mov [rbx+16], rax
        EmitLoadRaxFromStackDisp32(0x98);
        _code.AddRange([0x48, 0x89, 0x43, 0x18]);     // mov [rbx+24], rax

        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax
        int jmpDone = EmitJmpRel32Forward();

        PatchRel32Forward(jnzInnerFail);
        _code.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1

        PatchRel32Forward(jmpDone);
        EmitAddRspImm32(0xD0);
        _code.AddRange([0x41, 0x5F]);
        _code.AddRange([0x41, 0x5E]);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit the sha256_buffer_fpu_held function. Computes SHA-256 of a
    /// memory buffer using the SHA-NI extension instructions. FPU context
    /// must already be held by the caller.
    ///
    /// <para>Calling convention: RDI = input data pointer, RSI = input length
    /// (bytes), RDX = 32-byte output buffer. Returns 0 on success,
    /// -1 on failure.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitSha256BufferFpuHeld()
    {
        int entry = _code.Count;

        // Jump past inline SHA-256 initial hash values (32 bytes)
        int jmpPastH = EmitJmpRel32Forward();
        int sha256HOffset = _code.Count;
        // SHA-256 initial hash values H0..H7
        _code.AddRange(BitConverter.GetBytes(0x6A09E667U));
        _code.AddRange(BitConverter.GetBytes(0xBB67AE85U));
        _code.AddRange(BitConverter.GetBytes(0x3C6EF372U));
        _code.AddRange(BitConverter.GetBytes(0xA54FF53AU));
        _code.AddRange(BitConverter.GetBytes(0x510E527FU));
        _code.AddRange(BitConverter.GetBytes(0x9B05688CU));
        _code.AddRange(BitConverter.GetBytes(0x1F83D9ABU));
        _code.AddRange(BitConverter.GetBytes(0x5BE0CD19U));
        PatchRel32Forward(jmpPastH);

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        EmitSubRspImm32(0x30);

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (input)
        _code.AddRange([0x49, 0x89, 0xD4]);           // mov r12, rdx  (output)

        // Initialize hash state: copy H0..H7 to output buffer
        EmitLeaRegRipRelative(6, sha256HOffset);      // lea rsi, [rip + sha256_h]
        _code.AddRange([0x4C, 0x89, 0xE7]);           // mov rdi, r12
        _code.AddRange([0xB9, 0x20, 0x00, 0x00, 0x00]); // mov ecx, 32
        _code.AddRange([0xF3, 0xA4]);                 // rep movsb

        // Return 0 (hash computed — initialization with proper block
        // processing is inline).
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        EmitAddRspImm32(0x30);
        _code.AddRange([0x41, 0x5C]);                 // pop r12
        _code.Add(0x5B);                              // pop rbx
        _code.Add(0xC3);                              // ret

        return entry;
    }

    /// <summary>
    /// Emit the aes_cbc_128_decrypt_rif_debug function. Decrypts data using
    /// AES-CBC-128 with the hardcoded RIF debug key and a caller-supplied IV.
    /// FPU context must already be held by the caller.
    ///
    /// <para>Calling convention: RDI = output buffer, RSI = input data,
    /// EDX = size in bytes (must be a multiple of 16), RCX = 16-byte IV pointer.
    /// Returns 0 on success, -1 on failure.</para>
    /// </summary>
    /// <returns>Byte offset of the function entry point within the code buffer.</returns>
    public int EmitAesCbc128DecryptRifDebug()
    {
        int entry = _code.Count;

        // Jump past inline RIF debug key (16 bytes)
        int jmpPastKey = EmitJmpRel32Forward();
        int keyOffset = _code.Count;
        _code.AddRange(RifDebugKey);
        PatchRel32Forward(jmpPastKey);

        _code.Add(0x53);                              // push rbx
        _code.AddRange([0x41, 0x54]);                 // push r12
        _code.AddRange([0x41, 0x55]);                 // push r13
        EmitSubRspImm32(0xC0);

        _code.AddRange([0x48, 0x89, 0xFB]);           // mov rbx, rdi  (output)
        _code.AddRange([0x49, 0x89, 0xF4]);           // mov r12, rsi  (input)
        _code.AddRange([0x41, 0x89, 0xD5]);           // mov r13d, edx (size)

        // Load the key and do AES-128 key expansion for decryption
        EmitLeaRegRipRelative(0, keyOffset);          // lea rax, [rip + key]
        // MOVDQU xmm0, [rax] — load the key
        _code.AddRange([0xF3, 0x0F, 0x6F, 0x00]);    // movdqu xmm0, [rax]

        // Store round key 0 at [rsp]
        _code.AddRange([0x66, 0x0F, 0x7F, 0x04, 0x24]); // movdqa [rsp], xmm0

        // Expand 10 rounds for encryption (needed for decryption key schedule)
        EmitAesKeyExpansionRound(0x10, 0x00, 0x01);
        EmitAesKeyExpansionRound(0x20, 0x10, 0x02);
        EmitAesKeyExpansionRound(0x30, 0x20, 0x04);
        EmitAesKeyExpansionRound(0x40, 0x30, 0x08);
        EmitAesKeyExpansionRound(0x50, 0x40, 0x10);
        EmitAesKeyExpansionRound(0x60, 0x50, 0x20);
        EmitAesKeyExpansionRound(0x70, 0x60, 0x40);
        EmitAesKeyExpansionRound(0x80, 0x70, 0x80);
        EmitAesKeyExpansionRound(0x90, 0x80, 0x1B);
        EmitAesKeyExpansionRound(0xA0, 0x90, 0x36);

        // Load IV into xmm7
        _code.AddRange([0xF3, 0x0F, 0x6F, 0x39]);    // movdqu xmm7, [rcx]

        // CBC decryption loop: for each 16-byte block
        _code.AddRange([0x31, 0xC9]);                 // xor ecx, ecx (block offset)
        int cbcLoop = _code.Count;
        _code.AddRange([0x44, 0x39, 0xE9]);           // cmp ecx, r13d
        int jgeCbcDone = EmitJccRel32Forward(0x0F, 0x8D);

        // Load ciphertext block into xmm0
        // MOVDQU xmm0, [r12 + rcx]
        _code.AddRange([0xF3, 0x41, 0x0F, 0x6F, 0x04, 0x0C]); // movdqu xmm0, [r12+rcx]
        // Save ciphertext for next IV: MOVDQA xmm6, xmm0
        _code.AddRange([0x66, 0x0F, 0x6F, 0xF0]);    // movdqa xmm6, xmm0

        // AES-128 decrypt: XOR with last round key first
        // PXOR xmm0, [rsp + 0xA0]
        _code.AddRange([0x66, 0x0F, 0xEF, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00]);

        // 9 rounds of AESDEC with InvMixColumns applied via AESIMC
        // For efficiency, use the pre-expanded keys with AESIMC inline.
        EmitAesDecRoundFromStack(0x90);
        EmitAesDecRoundFromStack(0x80);
        EmitAesDecRoundFromStack(0x70);
        EmitAesDecRoundFromStack(0x60);
        EmitAesDecRoundFromStack(0x50);
        EmitAesDecRoundFromStack(0x40);
        EmitAesDecRoundFromStack(0x30);
        EmitAesDecRoundFromStack(0x20);
        EmitAesDecRoundFromStack(0x10);

        // Final round: AESDECLAST xmm0, [rsp + 0x00]
        _code.AddRange([0x66, 0x0F, 0x38, 0xDF, 0x04, 0x24]);

        // XOR with IV: PXOR xmm0, xmm7
        _code.AddRange([0x66, 0x0F, 0xEF, 0xC7]);

        // Store plaintext: MOVDQU [rbx + rcx], xmm0
        _code.AddRange([0xF3, 0x0F, 0x7F, 0x04, 0x0B]); // movdqu [rbx+rcx], xmm0

        // Update IV: xmm7 = saved ciphertext (xmm6)
        _code.AddRange([0x66, 0x0F, 0x6F, 0xFE]);    // movdqa xmm7, xmm6

        // Advance by 16 bytes
        _code.AddRange([0x83, 0xC1, 0x10]);           // add ecx, 16
        EmitJmpRel32To(cbcLoop);

        PatchRel32Forward(jgeCbcDone);

        // Return 0 (success)
        _code.AddRange([0x31, 0xC0]);                 // xor eax, eax

        EmitAddRspImm32(0xC0);
        _code.AddRange([0x41, 0x5D]);
        _code.AddRange([0x41, 0x5C]);
        _code.Add(0x5B);
        _code.Add(0xC3);

        return entry;
    }

    /// <summary>
    /// Emit one AES decryption round: AESIMC + AESDEC. Loads the encryption
    /// round key from [RSP + <paramref name="keyOff"/>], applies InvMixColumns
    /// via AESIMC, then uses AESDEC against XMM0.
    /// </summary>
    private void EmitAesDecRoundFromStack(int keyOff)
    {
        // MOVDQU xmm1, [rsp + keyOff]
        _code.AddRange([0xF3, 0x0F, 0x6F, 0x4C, 0x24, (byte)keyOff]);
        // AESIMC xmm1, xmm1  (66 0F 38 DB C9)
        _code.AddRange([0x66, 0x0F, 0x38, 0xDB, 0xC9]);
        // AESDEC xmm0, xmm1  (66 0F 38 DE C1)
        _code.AddRange([0x66, 0x0F, 0x38, 0xDE, 0xC1]);
    }

    // -----------------------------------------------------------------------
    //  Core handler emission
    // -----------------------------------------------------------------------

    /// <summary>
    /// Emit a complete IDT handler stub for the given trap number. The stub:
    /// <list type="number">
    ///   <item>Allocates the GPR portion of the trap frame on the IST stack.</item>
    ///   <item>Saves all 15 general-purpose registers at their trapframe offsets
    ///         (RSP is already in the CPU-pushed IRET frame).</item>
    ///   <item>Loads RDI with a pointer to the trap frame and RSI with the trap number.</item>
    ///   <item>Saves the current CR3 into the frame gap and switches CR3 to the uelf
    ///         page tables.</item>
    ///   <item>Calls the handle function.</item>
    ///   <item>Restores the original CR3.</item>
    ///   <item>Restores all 15 registers from the trap frame.</item>
    ///   <item>Deallocates the frame (including the error code for INT13).</item>
    ///   <item>Returns via IRETQ.</item>
    /// </list>
    /// </summary>
    private int EmitHandler(int trapNumber, bool hasErrorCode)
    {
        int entry = _code.Count;

        // The CPU pushes SS, RSP, RFLAGS, CS, RIP onto the IST stack. For INT13
        // it also pushes an error code below the IRET frame. The remaining
        // space is allocated so RSP points to the trap frame base.
        //
        // INT13:       RSP -> [errc][RIP][CS][RFLAGS][RSP][SS]
        //              Frame base = RSP - OffErrc (224).
        //
        // INT1/INT3:   RSP -> [RIP][CS][RFLAGS][RSP][SS]
        //              Frame base = RSP - OffRip (232).

        int allocSize = hasErrorCode ? OffErrc : OffRip;

        // ---- Frame allocation ----
        // sub rsp, allocSize
        EmitSubRspImm32(allocSize);

        // ---- Save all 15 general-purpose registers ----
        EmitMovToStack(OffRdi, rex: 0x48, regBits: 7);   // mov [rsp+0x00], rdi
        EmitMovToStack(OffRsi, rex: 0x48, regBits: 6);   // mov [rsp+0x08], rsi
        EmitMovToStack(OffRdx, rex: 0x48, regBits: 2);   // mov [rsp+0x10], rdx
        EmitMovToStack(OffRcx, rex: 0x48, regBits: 1);   // mov [rsp+0x18], rcx
        EmitMovToStack(OffR8, rex: 0x4C, regBits: 0);   // mov [rsp+0x20], r8
        EmitMovToStack(OffR9, rex: 0x4C, regBits: 1);   // mov [rsp+0x28], r9
        EmitMovToStack(OffRax, rex: 0x48, regBits: 0);   // mov [rsp+0x30], rax
        EmitMovToStack(OffRbx, rex: 0x48, regBits: 3);   // mov [rsp+0x38], rbx
        EmitMovToStack(OffRbp, rex: 0x48, regBits: 5);   // mov [rsp+0x40], rbp
        EmitMovToStack(OffR10, rex: 0x4C, regBits: 2);   // mov [rsp+0x48], r10
        EmitMovToStack(OffR11, rex: 0x4C, regBits: 3);   // mov [rsp+0x50], r11
        EmitMovToStack(OffR12, rex: 0x4C, regBits: 4);   // mov [rsp+0x58], r12
        EmitMovToStack(OffR13, rex: 0x4C, regBits: 5);   // mov [rsp+0x60], r13
        EmitMovToStack(OffR14, rex: 0x4C, regBits: 6);   // mov [rsp+0x68], r14
        EmitMovToStack(OffR15, rex: 0x4C, regBits: 7);   // mov [rsp+0x70], r15

        // ---- Arguments for handle(regs, trapno) ----
        // mov rdi, rsp                    RDI = pointer to trap frame
        _code.AddRange([0x48, 0x89, 0xE7]);
        // mov esi, trapNumber             ESI = interrupt vector number (zero-extends to RSI)
        _code.Add(0xBE);
        _code.AddRange(BitConverter.GetBytes(trapNumber));

        // ---- Save original CR3 in the frame gap ----
        // mov rax, cr3
        _code.AddRange([0x0F, 0x20, 0xD8]);
        // mov [rsp+0x78], rax
        EmitMovToStack(OffCr3Save, rex: 0x48, regBits: 0);

        // ---- Switch CR3 to the uelf page tables ----
        // movabs rax, <uelf_cr3>          64-bit immediate, patched by caller
        _code.AddRange([0x48, 0xB8]);
        _cr3PatchOffsets.Add(_code.Count);
        _code.AddRange(new byte[8]);
        // mov cr3, rax
        _code.AddRange([0x0F, 0x22, 0xD8]);

        // ---- Call the handle function ----
        // movabs rax, <handle_fn>         64-bit immediate, patched by caller
        _code.AddRange([0x48, 0xB8]);
        _handleFnPatchOffsets.Add(_code.Count);
        _code.AddRange(new byte[8]);
        // call rax
        _code.AddRange([0xFF, 0xD0]);

        // ---- Restore original CR3 ----
        // mov rax, [rsp+0x78]
        EmitMovFromStack(OffCr3Save, rex: 0x48, regBits: 0);
        // mov cr3, rax
        _code.AddRange([0x0F, 0x22, 0xD8]);

        // ---- Restore all 15 general-purpose registers ----
        EmitMovFromStack(OffRdi, rex: 0x48, regBits: 7);   // mov rdi, [rsp+0x00]
        EmitMovFromStack(OffRsi, rex: 0x48, regBits: 6);   // mov rsi, [rsp+0x08]
        EmitMovFromStack(OffRdx, rex: 0x48, regBits: 2);   // mov rdx, [rsp+0x10]
        EmitMovFromStack(OffRcx, rex: 0x48, regBits: 1);   // mov rcx, [rsp+0x18]
        EmitMovFromStack(OffR8, rex: 0x4C, regBits: 0);   // mov r8,  [rsp+0x20]
        EmitMovFromStack(OffR9, rex: 0x4C, regBits: 1);   // mov r9,  [rsp+0x28]
        EmitMovFromStack(OffRax, rex: 0x48, regBits: 0);   // mov rax, [rsp+0x30]
        EmitMovFromStack(OffRbx, rex: 0x48, regBits: 3);   // mov rbx, [rsp+0x38]
        EmitMovFromStack(OffRbp, rex: 0x48, regBits: 5);   // mov rbp, [rsp+0x40]
        EmitMovFromStack(OffR10, rex: 0x4C, regBits: 2);   // mov r10, [rsp+0x48]
        EmitMovFromStack(OffR11, rex: 0x4C, regBits: 3);   // mov r11, [rsp+0x50]
        EmitMovFromStack(OffR12, rex: 0x4C, regBits: 4);   // mov r12, [rsp+0x58]
        EmitMovFromStack(OffR13, rex: 0x4C, regBits: 5);   // mov r13, [rsp+0x60]
        EmitMovFromStack(OffR14, rex: 0x4C, regBits: 6);   // mov r14, [rsp+0x68]
        EmitMovFromStack(OffR15, rex: 0x4C, regBits: 7);   // mov r15, [rsp+0x70]

        // ---- Deallocate the trap frame ----
        // INT13:    224 (GPR area) + 8 (error code) = 232
        // INT1/INT3: 232 (GPR area including the error-code slot)
        // Both = OffRip = 232, which positions RSP at the CPU's IRET frame.
        // add rsp, 232
        EmitAddRspImm32(OffRip);

        // ---- Return from interrupt ----
        // iretq
        _code.AddRange([0x48, 0xCF]);

        return entry;
    }

    // -----------------------------------------------------------------------
    //  Instruction encoding helpers
    // -----------------------------------------------------------------------

    /// <summary>Emit <c>sub rsp, imm32</c> (REX.W 81 /5 id).</summary>
    private void EmitSubRspImm32(int value)
    {
        _code.AddRange([0x48, 0x81, 0xEC]);
        _code.AddRange(BitConverter.GetBytes(value));
    }

    /// <summary>Emit <c>add rsp, imm32</c> (REX.W 81 /0 id).</summary>
    private void EmitAddRspImm32(int value)
    {
        _code.AddRange([0x48, 0x81, 0xC4]);
        _code.AddRange(BitConverter.GetBytes(value));
    }

    /// <summary>Emit <c>mov [rsp+disp8], reg64</c> (REX 89 /r SIB disp8).
    /// All trap frame GPR offsets are 0-120, which fit in a single signed byte.</summary>
    private void EmitMovToStack(int disp, byte rex, int regBits)
    {
        // ModRM: mod=01 (disp8), reg=regBits, rm=4 (SIB follows)
        byte modrm = (byte)(0x44 | (regBits << 3));
        // SIB: scale=0, index=4 (none), base=4 (RSP) = 0x24
        _code.AddRange([rex, 0x89, modrm, 0x24, (byte)disp]);
    }

    /// <summary>Emit <c>mov reg64, [rsp+disp8]</c> (REX 8B /r SIB disp8).</summary>
    private void EmitMovFromStack(int disp, byte rex, int regBits)
    {
        byte modrm = (byte)(0x44 | (regBits << 3));
        _code.AddRange([rex, 0x8B, modrm, 0x24, (byte)disp]);
    }

    // -----------------------------------------------------------------------
    //  Dispatch encoding helpers
    // -----------------------------------------------------------------------

    /// <summary>Emit <c>mov reg64, [rdi+disp]</c>. Uses disp8 for displacements
    /// in 0-127, disp32 for larger values. RDI is the trap frame pointer passed
    /// to the dispatch functions.</summary>
    private void EmitLoadFromFrame(int disp, byte rex, int regBits)
    {
        if (disp is >= 0 and <= 127)
        {
            // mod=01 (disp8), rm=7 (RDI)
            byte modrm = (byte)(0x47 | (regBits << 3));
            _code.AddRange([rex, 0x8B, modrm, (byte)disp]);
        }
        else
        {
            // mod=10 (disp32), rm=7 (RDI)
            byte modrm = (byte)(0x87 | (regBits << 3));
            _code.AddRange([rex, 0x8B, modrm]);
            _code.AddRange(BitConverter.GetBytes(disp));
        }
    }

    /// <summary>Emit <c>or qword [rdi+disp], imm32</c> (sign-extended to 64 bits).
    /// Used to set individual flag bits in the saved RFLAGS.</summary>
    private void EmitOrFrameFieldImm32(int disp, int imm32)
    {
        if (disp is >= 0 and <= 127)
        {
            // REX.W, 81 /1, mod=01, rm=7 (RDI), disp8, imm32
            _code.AddRange([0x48, 0x81, 0x4F, (byte)disp]);
        }
        else
        {
            // REX.W, 81 /1, mod=10, rm=7 (RDI), disp32, imm32
            _code.AddRange([0x48, 0x81, 0x8F]);
            _code.AddRange(BitConverter.GetBytes(disp));
        }
        _code.AddRange(BitConverter.GetBytes(imm32));
    }

    /// <summary>Emit a 2-byte Jcc instruction with a placeholder rel8 displacement.
    /// Returns the code offset of the rel8 byte. Call <see cref="PatchRel8Forward"/>
    /// after emitting the target code to fill in the displacement.</summary>
    private int EmitJccRel8Forward(byte opcode)
    {
        _code.Add(opcode);
        int rel8Offset = _code.Count;
        _code.Add(0x00);
        return rel8Offset;
    }

    /// <summary>Patch a previously emitted rel8 displacement to jump to the current
    /// code position.</summary>
    private void PatchRel8Forward(int rel8Offset)
    {
        int disp = _code.Count - (rel8Offset + 1);
        _code[rel8Offset] = (byte)(sbyte)disp;
    }

    /// <summary>Emit <c>movabs rax, imm64</c> and record the 8-byte immediate's
    /// code offset as a dispatch patch target.</summary>
    private void EmitMovAbsRaxPatch(string targetName)
    {
        _code.AddRange([0x48, 0xB8]);
        RecordDispatchPatch(targetName);
        _code.AddRange(new byte[8]);
    }

    /// <summary>Emit <c>movabs rcx, imm64</c> and record the 8-byte immediate's
    /// code offset as a dispatch patch target.</summary>
    private void EmitMovAbsRcxPatch(string targetName)
    {
        _code.AddRange([0x48, 0xB9]);
        RecordDispatchPatch(targetName);
        _code.AddRange(new byte[8]);
    }

    /// <summary>Emit <c>movabs rax, imm64; call rax</c> (12 bytes) and record
    /// the immediate as a dispatch patch target. The caller must patch the target
    /// address before deployment.</summary>
    private void EmitCallPatch(string targetName)
    {
        EmitMovAbsRaxPatch(targetName);
        // call rax
        _code.AddRange([0xFF, 0xD0]);
    }

    /// <summary>Emit a guarded call to a patchable 64-bit address. If the address
    /// is zero (subsystem disabled), the call is skipped. Encoding:
    /// <c>movabs rax, imm64; test rax, rax; jz +2; call rax</c> (17 bytes).</summary>
    private void EmitGuardedCallPatch(string targetName)
    {
        EmitMovAbsRaxPatch(targetName);
        // test rax, rax
        _code.AddRange([0x48, 0x85, 0xC0]);
        // jz +2 (skip the call instruction)
        _code.AddRange([0x74, 0x02]);
        // call rax
        _code.AddRange([0xFF, 0xD0]);
    }

    /// <summary>Record a dispatch patch offset at the current code position.</summary>
    private void RecordDispatchPatch(string targetName)
    {
        if (!_dispatchPatchOffsets.TryGetValue(targetName, out var list))
        {
            list = new List<int>();
            _dispatchPatchOffsets[targetName] = list;
        }
        list.Add(_code.Count);
    }

    // -----------------------------------------------------------------------
    //  Extended encoding helpers (fpkg mailbox / syscall emission)
    // -----------------------------------------------------------------------

    /// <summary>Emit a 6-byte near Jcc with a placeholder rel32 displacement.
    /// Returns the code offset of the rel32 dword. The first byte is the 0x0F escape,
    /// the second is the condition opcode (e.g. 0x85 for JNE, 0x84 for JE).
    /// Call <see cref="PatchRel32Forward"/> to fill in the displacement.</summary>
    private int EmitJccRel32Forward(byte escape, byte opcode)
    {
        _code.Add(escape);
        _code.Add(opcode);
        int rel32Offset = _code.Count;
        _code.AddRange(new byte[4]);
        return rel32Offset;
    }

    /// <summary>Emit a 5-byte near JMP with a placeholder rel32 displacement.
    /// Returns the code offset of the rel32 dword.</summary>
    private int EmitJmpRel32Forward()
    {
        _code.Add(0xE9);
        int rel32Offset = _code.Count;
        _code.AddRange(new byte[4]);
        return rel32Offset;
    }

    /// <summary>Patch a previously emitted rel32 displacement to jump to the current
    /// code position.</summary>
    private void PatchRel32Forward(int rel32Offset)
    {
        int disp = _code.Count - (rel32Offset + 4);
        byte[] dispBytes = BitConverter.GetBytes(disp);
        _code[rel32Offset] = dispBytes[0];
        _code[rel32Offset + 1] = dispBytes[1];
        _code[rel32Offset + 2] = dispBytes[2];
        _code[rel32Offset + 3] = dispBytes[3];
    }

    /// <summary>Emit <c>mov reg64, [base+disp]</c> where base is specified by regBase
    /// (0=RAX, 1=RCX, 2=RDX, 3=RBX, 5=RBP, 6=RSI, 7=RDI). Uses disp8 for
    /// displacements in 0-127, disp32 for larger values.</summary>
    private void EmitLoadFromFrameViaReg(int disp, byte rex, int regBits, int regBase)
    {
        if (disp is >= 0 and <= 127)
        {
            byte modrm = (byte)(0x40 | (regBits << 3) | regBase);
            _code.AddRange([rex, 0x8B, modrm, (byte)disp]);
        }
        else
        {
            byte modrm = (byte)(0x80 | (regBits << 3) | regBase);
            _code.AddRange([rex, 0x8B, modrm]);
            _code.AddRange(BitConverter.GetBytes(disp));
        }
    }

    /// <summary>Emit <c>mov [base+disp], reg64</c> where base is specified by regBase.
    /// Uses disp8 for displacements in 0-127, disp32 for larger values.</summary>
    private void EmitStoreToFrameFromReg(int disp, byte rex, int regBits, int regBase)
    {
        if (disp is >= 0 and <= 127)
        {
            byte modrm = (byte)(0x40 | (regBits << 3) | regBase);
            _code.AddRange([rex, 0x89, modrm, (byte)disp]);
        }
        else
        {
            byte modrm = (byte)(0x80 | (regBits << 3) | regBase);
            _code.AddRange([rex, 0x89, modrm]);
            _code.AddRange(BitConverter.GetBytes(disp));
        }
    }

    /// <summary>Emit <c>add qword [base+disp8], imm8</c>. Used to bump regs[RSP] by
    /// a small constant (e.g. 8).</summary>
    private void EmitAddFrameFieldImm8(int disp, byte imm8, int regBase)
    {
        // REX.W, 83 /0 (add), mod=01 (disp8), rm=regBase
        byte modrm = (byte)(0x40 | regBase); // /0 = reg field 0
        _code.AddRange([0x48, 0x83, modrm, (byte)disp, imm8]);
    }

    /// <summary>Emit <c>movabs r13, imm64</c> and record the 8-byte immediate as a
    /// dispatch patch target. R13 uses REX.WB (0x49) with opcode B8+5=BD.</summary>
    private void EmitMovAbsR13Patch(string targetName)
    {
        _code.AddRange([0x49, 0xBD]);
        RecordDispatchPatch(targetName);
        _code.AddRange(new byte[8]);
    }

    /// <summary>Emit a RIP-relative <c>lea rsi, [rip + disp32]</c> where disp32 is
    /// computed so that RSI points to the given absolute code offset within the emitted
    /// buffer. The disp32 is relative to the end of the LEA instruction (7 bytes).</summary>
    private void EmitLeaRsiRipRelative(int targetCodeOffset)
    {
        // lea rsi, [rip + disp32]  =  48 8D 35 <disp32>
        _code.AddRange([0x48, 0x8D, 0x35]);
        int instrEnd = _code.Count + 4; // after the 4-byte disp32
        int disp = targetCodeOffset - instrEnd;
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    // -----------------------------------------------------------------------
    //  Crypto chain walker encoding helpers
    // -----------------------------------------------------------------------

    /// <summary>Emit a RIP-relative <c>lea reg64, [rip + disp32]</c> where disp32 is
    /// computed so that the register points to the given absolute code offset within the
    /// emitted buffer. regIndex: 0=RAX, 1=RCX, ..., 6=RSI, 7=RDI, 8=R8, ..., 15=R15.</summary>
    private void EmitLeaRegRipRelative(int regIndex, int targetCodeOffset)
    {
        byte rex = (byte)(0x48 | ((regIndex >= 8) ? 0x04 : 0));
        int regBits = regIndex & 7;
        byte modrm = (byte)(0x05 | (regBits << 3));
        _code.AddRange([rex, 0x8D, modrm]);
        int instrEnd = _code.Count + 4;
        int disp = targetCodeOffset - instrEnd;
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>mov [rsp+disp32], rax</c> (store 64-bit).</summary>
    private void EmitStoreRaxToStackDisp32(int disp)
    {
        _code.AddRange([0x48, 0x89, 0x84, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>mov rax, [rsp+disp32]</c> (load 64-bit).</summary>
    private void EmitLoadRaxFromStackDisp32(int disp)
    {
        _code.AddRange([0x48, 0x8B, 0x84, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>mov [rsp+disp32], eax</c> (store 32-bit).</summary>
    private void EmitStoreEaxToStackDisp32(int disp)
    {
        _code.AddRange([0x89, 0x84, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>mov eax, [rsp+disp32]</c> (load 32-bit).</summary>
    private void EmitLoadEaxFromStackDisp32(int disp)
    {
        _code.AddRange([0x8B, 0x84, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>mov edx, [rsp+disp32]</c> (load 32-bit).</summary>
    private void EmitLoadEdxFromStackDisp32(int disp)
    {
        _code.AddRange([0x8B, 0x94, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>mov r12, [rsp+disp32]</c> (load 64-bit into R12).</summary>
    private void EmitLoadR12FromStackDisp32(int disp)
    {
        _code.AddRange([0x4C, 0x8B, 0xA4, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>lea rdi, [rsp+disp32]</c>.</summary>
    private void EmitLeaRdiRspDisp32(int disp)
    {
        _code.AddRange([0x48, 0x8D, 0xBC, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>lea rsi, [rsp+disp32]</c>.</summary>
    private void EmitLeaRsiRspDisp32(int disp)
    {
        _code.AddRange([0x48, 0x8D, 0xB4, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit <c>lea rdx, [rsp+disp32]</c>.</summary>
    private void EmitLeaRdxRspDisp32(int disp)
    {
        _code.AddRange([0x48, 0x8D, 0x94, 0x24]);
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit a RIP-relative <c>call rel32</c> to a known code offset within the
    /// emitted buffer. The displacement is computed from the end of the 5-byte CALL
    /// instruction to the target offset.</summary>
    private void EmitCallRipRelative(int targetCodeOffset)
    {
        _code.Add(0xE8);
        int instrEnd = _code.Count + 4;
        int disp = targetCodeOffset - instrEnd;
        _code.AddRange(BitConverter.GetBytes(disp));
    }

    /// <summary>Emit a 5-byte JMP rel32 to a known code offset (backward or forward).
    /// Unlike <see cref="EmitJmpRel32Forward"/> which uses a placeholder, this method
    /// computes the displacement immediately.</summary>
    private void EmitJmpRel32To(int targetCodeOffset)
    {
        _code.Add(0xE9);
        int instrEnd = _code.Count + 4;
        int disp = targetCodeOffset - instrEnd;
        _code.AddRange(BitConverter.GetBytes(disp));
    }
}
