// SharpProspero.Link - a linker for module output.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;

namespace SharpProspero.Link;

/// <summary>
/// Builds a complete kernel module binary from a <see cref="KernelModuleEmitter"/>.
/// Calls every Emit method in dependency order, records internal function offsets,
/// and returns a <see cref="KernelModuleOutput"/> that the installer uses to deploy
/// the module into kernel memory.
///
/// <para>Internal patch targets (functions emitted by this writer) are resolved to
/// their code-buffer offsets and returned in <see cref="KernelModuleOutput.InternalTargets"/>.
/// The installer writes <c>base_va + offset</c> at each patch site.</para>
///
/// <para>External patch targets (kernel addresses, gadgets, data areas) are returned
/// in <see cref="KernelModuleOutput.ExternalTargets"/>. The installer must supply
/// the actual virtual addresses from firmware-specific offset tables.</para>
/// </summary>
public sealed class KernelModuleWriter
{
    /// <summary>
    /// Build the kernel module binary. Emits all code sections in dependency order,
    /// collects internal and external patch target metadata, and returns the complete
    /// output package for the installer.
    /// </summary>
    public static KernelModuleOutput Build()
    {
        var emitter = new KernelModuleEmitter();
        var internalTargets = new Dictionary<string, int>();

        // ----------------------------------------------------------------
        //  1. IDT handler entry stubs (INT13, INT1, INT3)
        // ----------------------------------------------------------------
        int int13Off = emitter.EmitInt13Handler();
        int int1Off = emitter.EmitInt1Handler();
        int int3Off = emitter.EmitInt3Handler();

        // ----------------------------------------------------------------
        //  2. Main dispatcher and top-level dispatch functions
        // ----------------------------------------------------------------
        int dispatcherOff = emitter.EmitDispatcher();
        int ktfOff = emitter.EmitKernelTrapFastHandler();
        int syscallOff = emitter.EmitSyscallHandler();

        internalTargets[KernelModuleEmitter.PatchTargetNames.KernelTrapFastHandler] = ktfOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.SyscallHandler] = syscallOff;

        // ----------------------------------------------------------------
        //  3. Mailbox dispatcher (routes DR0 mailbox hits to subsystems)
        // ----------------------------------------------------------------
        int mboxOff = emitter.EmitMailboxDispatcher();
        internalTargets[KernelModuleEmitter.PatchTargetNames.MailboxHandler] = mboxOff;

        // ----------------------------------------------------------------
        //  4. Subsystem mailbox handlers
        // ----------------------------------------------------------------
        int fpkgMboxOff = emitter.EmitFpkgMailboxHandler();
        int fselfMboxOff = emitter.EmitFselfMailboxHandler();
        int npdrmMboxOff = emitter.EmitNpdrmMailboxHandler();

        internalTargets[KernelModuleEmitter.PatchTargetNames.FpkgMailboxHandler] = fpkgMboxOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FselfMailboxHandler] = fselfMboxOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.NpdrmMailboxHandler] = npdrmMboxOff;

        // ----------------------------------------------------------------
        //  5. Subsystem syscall handlers
        // ----------------------------------------------------------------
        int fpkgSysOff = emitter.EmitFpkgSyscallHandler();
        int fselfSysOff = emitter.EmitFselfSyscallHandler();
        int ioctlSysOff = emitter.EmitIoctlSyscallHandler();
        int kekcallOff = emitter.EmitKekcallHandler();
        int kekcallTrapOff = emitter.EmitKekcallTrapHandler();
        int sysFixOff = emitter.EmitSyscallFixHandler();
        int sysFixTrapOff = emitter.EmitSyscallFixTrapHandler();

        internalTargets[KernelModuleEmitter.PatchTargetNames.FpkgSyscall] = fpkgSysOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FselfSyscall] = fselfSysOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.IoctlSyscall] = ioctlSysOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.Kekcall] = kekcallOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.SyscallFix] = sysFixOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.KekcallTrapHandlerFn] = kekcallTrapOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.SyscallFixTrapHandlerFn] = sysFixTrapOff;

        // ----------------------------------------------------------------
        //  5b. Trap continuation handlers (doreti_iret dispatch targets)
        // ----------------------------------------------------------------
        int fpkgTrapOff = emitter.EmitFpkgTrapHandler();
        int fselfTrapOff = emitter.EmitFselfTrapHandler();
        int fselfDebugTrapOff = emitter.EmitFselfDebugTrapHandler();
        int genericDecryptOff = emitter.EmitGenericDecryptTrap();

        internalTargets[KernelModuleEmitter.PatchTargetNames.FpkgTrapHandlerFn] = fpkgTrapOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FselfTrapHandlerFn] = fselfTrapOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FselfDebugTrapHandlerFn] = fselfDebugTrapOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.GenericDecryptTrapHandler] = genericDecryptOff;

        // ----------------------------------------------------------------
        //  6. CCP crypto chain walker and emulation handlers
        // ----------------------------------------------------------------
        int cryptoChainOff = emitter.EmitCryptoChainWalker();
        int xtsOff = emitter.EmitXtsEmulation();
        int hmacOff = emitter.EmitHmacEmulation();
        int pfsKeyOff = emitter.EmitPfsKeyDerivation();

        internalTargets[KernelModuleEmitter.PatchTargetNames.CryptoXtsHandler] = xtsOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.CryptoHmacHandler] = hmacOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.PfsDeriveFakeKeys] = pfsKeyOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.CryptoChainWalkerFn] = cryptoChainOff;

        // ----------------------------------------------------------------
        //  7. Syscall infrastructure
        // ----------------------------------------------------------------
        int startDbgOff = emitter.EmitStartSyscallWithDbgregs();
        int utilsTrapOff = emitter.EmitUtilsTrapHandler();

        internalTargets[KernelModuleEmitter.PatchTargetNames.StartSyscallWithDbgregs] = startDbgOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.UtilsTrapHandlerFn] = utilsTrapOff;

        // ----------------------------------------------------------------
        //  8. Memory access primitives (virt2phys must precede copy functions)
        // ----------------------------------------------------------------
        int v2pOff = emitter.EmitVirt2Phys();
        int copyFromOff = emitter.EmitCopyFromKernel(v2pOff);
        int copyToOff = emitter.EmitCopyToKernel(v2pOff);

        internalTargets[KernelModuleEmitter.PatchTargetNames.CopyFromKernel] = copyFromOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.CopyToKernel] = copyToOff;

        // ----------------------------------------------------------------
        //  9. Debug register access
        // ----------------------------------------------------------------
        int readDrOff = emitter.EmitReadDbgregsChecked();
        int writeDrOff = emitter.EmitWriteDbgregsChecked();

        internalTargets[KernelModuleEmitter.PatchTargetNames.ReadDbgregsChecked] = readDrOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.WriteDbgregsChecked] = writeDrOff;

        // ----------------------------------------------------------------
        //  10. FPU context management (EmitFpuEnter must precede EmitFpuExit)
        // ----------------------------------------------------------------
        int fpuEnterOff = emitter.EmitFpuEnter();

        // The FPU state block is emitted inline at fpuEnterOff + 5 (after the
        // initial JMP rel32 instruction that jumps past it). EmitFpuExit needs
        // this offset to share the depth counter and saved CR0 storage.
        int fpuStateOff = fpuEnterOff + 5;
        int fpuExitOff = emitter.EmitFpuExit(fpuStateOff);

        internalTargets[KernelModuleEmitter.PatchTargetNames.FpuEnter] = fpuEnterOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FpuExit] = fpuExitOff;

        // ----------------------------------------------------------------
        //  11. Fake key store operations
        // ----------------------------------------------------------------
        int fkHasOff = emitter.EmitFakeKeyHas();
        int fkGetOff = emitter.EmitFakeKeyGet();
        int fkRegOff = emitter.EmitFakeKeyRegister();
        int fkUnregOff = emitter.EmitFakeKeyUnregister();

        internalTargets[KernelModuleEmitter.PatchTargetNames.HasFakeKey] = fkHasOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.GetFakeKey] = fkGetOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.RegisterFakeKey] = fkRegOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.UnregisterFakeKey] = fkUnregOff;

        // ----------------------------------------------------------------
        //  12. Internal helper functions
        // ----------------------------------------------------------------

        // Observability hooks
        int obsSysEmOff = emitter.EmitObserveSyscallEmulated();
        int obsSysTrapOff = emitter.EmitObserveSyscallTrap();
        int obsSysFinOff = emitter.EmitObserveSyscallFinish();
        int finNpdrmOff = emitter.EmitFinishNpdrmIoctlState();

        internalTargets[KernelModuleEmitter.PatchTargetNames.ObserveSyscallEmulated] = obsSysEmOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.ObserveSyscallTrap] = obsSysTrapOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.ObserveSyscallFinish] = obsSysFinOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FinishNpdrmIoctlState] = finNpdrmOff;

        // Data areas
        int cryptoCacheOff = emitter.EmitCryptoRequestCache();
        internalTargets[KernelModuleEmitter.PatchTargetNames.CryptoRequestCache] = cryptoCacheOff;

        // CR0 and MSR access
        int readCr0Off = emitter.EmitReadCr0Checked();
        int writeCr0Off = emitter.EmitWriteCr0Checked();
        int rdmsrOff = emitter.EmitRdmsrFn();

        internalTargets[KernelModuleEmitter.PatchTargetNames.ReadCr0Checked] = readCr0Off;
        internalTargets[KernelModuleEmitter.PatchTargetNames.WriteCr0Checked] = writeCr0Off;
        internalTargets[KernelModuleEmitter.PatchTargetNames.RdmsrFn] = rdmsrOff;

        // Stack operations
        int pushStackOff = emitter.EmitPushStackChecked();
        int popStackOff = emitter.EmitPopStackChecked();
        int peekStackOff = emitter.EmitPeekStackChecked();

        internalTargets[KernelModuleEmitter.PatchTargetNames.PushStackChecked] = pushStackOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.PopStackChecked] = popStackOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.PeekStackChecked] = peekStackOff;

        // PCB access
        int getCurPcbOff = emitter.EmitGetCurrentPcbChecked();
        int getCurPcbFlagsOff = emitter.EmitGetCurrentPcbFlagsPtrChecked();
        int getPcbDbregsOff = emitter.EmitGetPcbDbregsCheckedAt();
        int setPcbDbregsOff = emitter.EmitSetPcbDbregsCheckedAt();
        int restoreDrStateAtOff = emitter.EmitRestoreDbgregsStateCheckedAt();
        int restoreDrStateOff = emitter.EmitRestoreDbgregsStateChecked();

        internalTargets[KernelModuleEmitter.PatchTargetNames.GetCurrentPcbChecked] = getCurPcbOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.GetCurrentPcbFlagsPtrChecked] = getCurPcbFlagsOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.GetPcbDbregsCheckedAt] = getPcbDbregsOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.SetPcbDbregsCheckedAt] = setPcbDbregsOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.RestoreDbgregsStateCheckedAt] = restoreDrStateAtOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.RestoreDbgregsStateChecked] = restoreDrStateOff;

        // Gadget execution
        int runGadgetOff = emitter.EmitRunGadgetChecked();
        internalTargets[KernelModuleEmitter.PatchTargetNames.RunGadgetChecked] = runGadgetOff;

        // FSELF helpers
        int isHeaderFselfOff = emitter.EmitIsHeaderFself();
        int getCtxFselfOff = emitter.EmitGetContextFselfInfo();
        int remCtxFselfOff = emitter.EmitRememberContextFselfInfo();
        int fselfInvOff = emitter.EmitFselfInvalidateCaches();
        int copyDecSelfOff = emitter.EmitCopyDecryptedSelfBlocks();
        int fselfSubHdrOff = emitter.EmitFselfSubstituteHeader();

        internalTargets[KernelModuleEmitter.PatchTargetNames.IsHeaderFself] = isHeaderFselfOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.GetContextFselfInfo] = getCtxFselfOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.RememberContextFselfInfo] = remCtxFselfOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FselfInvalidateCaches] = fselfInvOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.CopyDecryptedSelfBlocks] = copyDecSelfOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.FselfSubstituteHeader] = fselfSubHdrOff;

        // PFS crypto primitives
        int pfsXtsOff = emitter.EmitPfsXtsVirtualFpuHeld();
        int pfsHmacOff = emitter.EmitPfsHmacVirtualFpuHeld();

        internalTargets[KernelModuleEmitter.PatchTargetNames.PfsXtsVirtualFpuHeld] = pfsXtsOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.PfsHmacVirtualFpuHeld] = pfsHmacOff;

        // Crypto primitives
        int rsaPubOff = emitter.EmitRsaPublic();
        int hmacOnceOff = emitter.EmitHmacSha256Once();
        int sha256BufOff = emitter.EmitSha256BufferFpuHeld();
        int aesCbcOff = emitter.EmitAesCbc128DecryptRifDebug();

        internalTargets[KernelModuleEmitter.PatchTargetNames.RsaPublic] = rsaPubOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.HmacSha256Once] = hmacOnceOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.Sha256BufferFpuHeld] = sha256BufOff;
        internalTargets[KernelModuleEmitter.PatchTargetNames.AesCbc128DecryptRifDebug] = aesCbcOff;

        // ----------------------------------------------------------------
        //  13. Extract final code and build patch site map
        // ----------------------------------------------------------------
        byte[] code = emitter.GetCode();

        // Collect all dispatch patch sites from the emitter.
        var dispatchPatchSites = new Dictionary<string, IReadOnlyList<int>>();
        foreach (string target in emitter.DispatchPatchTargets)
        {
            dispatchPatchSites[target] = emitter.GetDispatchPatchOffsets(target);
        }

        // External targets: every dispatch patch target that is not in the
        // internal map. The installer must supply kernel-side addresses for these.
        var externalTargets = new List<string>();
        foreach (string target in dispatchPatchSites.Keys)
        {
            if (!internalTargets.ContainsKey(target))
            {
                externalTargets.Add(target);
            }
        }
        externalTargets.Sort(StringComparer.Ordinal);

        var output = new KernelModuleOutput
        {
            Code = code,
            Int13EntryOffset = int13Off,
            Int1EntryOffset = int1Off,
            Int3EntryOffset = int3Off,
            DispatcherOffset = dispatcherOff,
            KekcallTrapOffset = kekcallTrapOff,
            SyscallFixTrapOffset = sysFixTrapOff,
            UtilsTrapOffset = utilsTrapOff,
            CryptoChainOffset = cryptoChainOff,
            Virt2PhysOffset = v2pOff,
            Cr3PatchOffsets = emitter.Cr3PatchOffsets,
            HandleFnPatchOffsets = emitter.HandleFnPatchOffsets,
            InternalTargets = internalTargets,
            ExternalTargets = externalTargets,
            DispatchPatchSites = dispatchPatchSites,
        };

        // Wrap the emitted machine code into ELF64 binaries for the installer
        output.KelfElf = KernelModuleElfWriter.BuildKelf(output);
        output.UelfElf = KernelModuleElfWriter.BuildUelf(output);

        return output;
    }
}

/// <summary>
/// Complete kernel module binary with all metadata the installer needs to deploy it.
///
/// <para>Deployment steps:</para>
/// <list type="number">
///   <item>Allocate kernel memory at a chosen base virtual address and copy
///         <see cref="Code"/> into it.</item>
///   <item>For each entry in <see cref="InternalTargets"/>: compute
///         <c>base_va + offset</c> and write it as a little-endian 64-bit value
///         at every code offset listed in <see cref="DispatchPatchSites"/> for
///         that target name.</item>
///   <item>For each name in <see cref="ExternalTargets"/>: look up the kernel
///         virtual address from the firmware offset table and write it at every
///         code offset listed in <see cref="DispatchPatchSites"/> for that name.</item>
///   <item>Write the uelf CR3 physical address at every offset in
///         <see cref="Cr3PatchOffsets"/>.</item>
///   <item>Write <c>base_va + <see cref="DispatcherOffset"/></c> at every offset
///         in <see cref="HandleFnPatchOffsets"/>.</item>
///   <item>Install IDT entries at <c>base_va + Int13EntryOffset</c>,
///         <c>base_va + Int1EntryOffset</c>, <c>base_va + Int3EntryOffset</c>.</item>
/// </list>
/// </summary>
public sealed class KernelModuleOutput
{
    /// <summary>The complete machine code buffer.</summary>
    public required byte[] Code { get; init; }

    // ---- IDT handler entry points (offsets within Code) ----

    /// <summary>INT13 (general protection fault) handler entry point.</summary>
    public int Int13EntryOffset { get; init; }

    /// <summary>INT1 (debug exception) handler entry point.</summary>
    public int Int1EntryOffset { get; init; }

    /// <summary>INT3 (breakpoint) handler entry point.</summary>
    public int Int3EntryOffset { get; init; }

    // ---- Top-level dispatch entry points ----

    /// <summary>Main dispatcher (handle function) entry point. The IDT stubs call
    /// this after saving registers and switching CR3.</summary>
    public int DispatcherOffset { get; init; }

    /// <summary>Kekcall trap handler entry point. Handles INT1 traps that the
    /// kekcall subsystem uses for syscall-after interception.</summary>
    public int KekcallTrapOffset { get; init; }

    /// <summary>Syscall fix trap handler entry point. Handles INT1 traps for
    /// the mprotect and mdbg_call permission fix.</summary>
    public int SyscallFixTrapOffset { get; init; }

    /// <summary>Utils trap handler entry point. Handles INT1 traps for the
    /// gadget-execution and observability subsystems.</summary>
    public int UtilsTrapOffset { get; init; }

    /// <summary>CCP crypto chain walker entry point. Dispatched from the mailbox
    /// handler when sceSblServiceCryptAsync is intercepted.</summary>
    public int CryptoChainOffset { get; init; }

    /// <summary>Virtual-to-physical address translation function entry point.</summary>
    public int Virt2PhysOffset { get; init; }

    // ---- CR3 and handle function patch sites ----

    /// <summary>Offsets in <see cref="Code"/> where the uelf CR3 physical address
    /// must be written as a little-endian 64-bit value. One per IDT handler stub.</summary>
    public required IReadOnlyList<int> Cr3PatchOffsets { get; init; }

    /// <summary>Offsets in <see cref="Code"/> where the handle function (dispatcher)
    /// virtual address must be written as a little-endian 64-bit value.</summary>
    public required IReadOnlyList<int> HandleFnPatchOffsets { get; init; }

    // ---- Patch target resolution ----

    /// <summary>Internal target name to code-buffer offset. The installer writes
    /// <c>base_va + offset</c> at every patch site for the target name.</summary>
    public required IReadOnlyDictionary<string, int> InternalTargets { get; init; }

    /// <summary>External target names that the installer must resolve from the
    /// firmware-specific kernel offset table. Sorted lexicographically.</summary>
    public required IReadOnlyList<string> ExternalTargets { get; init; }

    /// <summary>All dispatch patch sites: target name to the list of code-buffer
    /// offsets where the target's 64-bit address must be written. Covers both
    /// internal and external targets.</summary>
    public required IReadOnlyDictionary<string, IReadOnlyList<int>> DispatchPatchSites { get; init; }

    // ---- ELF binaries ----

    /// <summary>Complete kelf ELF64 binary containing the IDT handler stubs and a
    /// 48-byte entry descriptor table. The installer's <c>LoadKelf</c> loads this
    /// into kernel memory once per CPU, resolving external symbols (CR3, handle
    /// function, IST values) from the firmware offset table.</summary>
    public byte[]? KelfElf { get; set; }

    /// <summary>Complete uelf ELF64 binary containing the dispatcher and all
    /// subsystem handlers. The installer loads this at a custom virtual base with
    /// private page tables.</summary>
    public byte[]? UelfElf { get; set; }
}
