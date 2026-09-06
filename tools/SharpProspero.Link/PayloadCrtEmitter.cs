// SharpProspero.Link - a linker for module output.
// Copyright (C) 2026 SvenGDK

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SharpProspero.Link;

/// <summary>
/// Writes the self-contained start object a payload links against. The out-of-process loader that
/// runs the payload maps the image at a fresh base, applies only base-relative fix-ups, and jumps
/// to the entry with a small arguments block in the first register. There is no dynamic linker, no
/// module-loading sequence, and no host-library initialisation to piggy-back on: the start object
/// is the entire bring-up.
/// <list type="number">
///   <item>Save the arguments block in a callee-saved register that survives the whole body.</item>
///   <item>Zero the bss range the linker writes between <c>__bss_start</c> and <c>__bss_end</c>,
///         then restore the arguments block into its owned slot.</item>
///   <item>Derive the raw <c>syscall; ret</c> gadget from <c>args[0]</c> (the loader writes
///         <c>args[0] = &amp;getpid</c>, and the on-device <c>getpid</c> stub is
///         <c>mov $20,%eax ; mov %rcx,%r10 ; syscall ; ret</c> so <c>args[0]+0xa</c> is the
///         gadget). Stash the gadget in a bss slot every raw-syscall path reaches through.</item>
///   <item>Probe <c>args[0]</c> as a callable dlsym: <c>__crt_syscall_init</c>
///         treats it as <c>int (int handle, const char* name, void** out)</c> - either a real
///         resolver on host loaders (hbldr / prospero-hb) or the <c>getpid</c> trampoline on
///         the loader. The probe calls <c>args[0](0x1, "sceKernelDlsym", &amp;out)</c>: if
///         <c>out</c> comes back non-zero and different from <c>args[0]</c>, the loader shipped a
///         real dlsym and <c>args[0]</c> is cached into <c>__sp_dlsym_fn</c>; otherwise the
///         regime degenerate and skip the resolver in the GOT-fixup and pthread-priming
///         cascades.</item>
///   <item>Resolve every entry the loader leaves unfilled in the global offset table. The loader
///         applies only <c>R_X86_64_RELATIVE</c>, so every <c>R_X86_64_GLOB_DAT</c> the payload
///         inherits stays zero until this shim walks <c>_DYNAMIC</c>, finds the relocation table,
///         and asks the cached dlsym for each import by its plain C name. When
///         <c>__sp_dlsym_ok</c> is <c>2</c> the slot stays zero (degenerate regime; the payload
///         will crash on its first PLT dispatch, but not before <c>__prospero_klog</c> has printed
///         the <c>sp:kernel:init:degen</c> breadcrumb).</item>
///   <item>Walk the constructor array; call <c>main</c> with the arguments block; deliver its
///         return through the loader's output slot; walk the destructor array; terminate via
///         <c>syscall(SYS_exit, retcode)</c>. The eboot exploit stub has no valid continuation
///         after the payload call, so a <c>ret</c> would pop garbage and crash.</item>
/// </list>
/// The start object also provides two thin wrappers the managed code imports through interop:
/// a getter for the saved arguments block and a print helper (<c>__prospero_klog</c>). The klog
/// helper is dependency-free: it issues <c>syscall(SYS_kexec, 7, msg, 0)</c> through
/// <c>ptr_syscall</c>, routing each message to <c>/dev/klog</c> where a log consumer can forward
/// it over the network. That property is what lets the <c>sp:kernel:init:*</c> breadcrumbs
/// reach the log even when dlsym is degenerate.
/// </summary>
public static class PayloadCrtEmitter
{
    private static readonly object _buildLock = new();

    /// <summary>When true the emitter includes diagnostic breadcrumb call sites and their
    /// rodata strings in the emitted .text and .rodata sections. Default false produces a
    /// clean ELF with zero breadcrumb bytes.</summary>
    public static bool EmitDiagnosticBreadcrumbs { get; set; }

    private const int ShtProgBits = 1, ShtSymTab = 2, ShtStrTab = 3, ShtRela = 4, ShtNoBits = 8;
    private const ulong ShfAlloc = 0x2, ShfWrite = 0x1, ShfExec = 0x4;
    private const byte GlobalFunc = (1 << 4) | 2;
    private const byte GlobalObject = (1 << 4) | 1;
    private const byte GlobalNoType = 1 << 4;
    private const uint RPc32 = 2, RPlt32 = 4, R64 = 1;

    /// <summary>The entry symbol the loader jumps to.</summary>
    public const string StartSymbol = "_start";

    /// <summary>The symbol the managed accessor imports to retrieve the payload arguments pointer.</summary>
    public const string GetArgsSymbol = "__prospero_get_payload_args";

    /// <summary>The symbol the managed accessor imports to write a message to the kernel log.</summary>
    public const string KlogSymbol = "__prospero_klog";

    /// <summary>The internal routine <c>_start</c> calls once to fill the global offset table.</summary>
    public const string FixupGotSymbol = "__prospero_fixup_got";

    /// <summary>The internal routine <c>_start</c> calls once, right after the bss-zero loop, to
    /// probe <c>args[0]</c> for a callable dlsym and to derive <c>ptr_syscall</c>.</summary>
    public const string DlsymInitSymbol = "__sp_dlsym_init";

    /// <summary>The internal routine <c>_start</c> calls as its very first act, before the sp:crt:enter
    /// diagnostic and before the bss-zero loop. It writes a fixed signature (0x53504350 = 'PCPS' little-endian,
    /// "SPCP" when read big-endian) into the loader's payload-out slot at <c>*args[0x28]</c>, then attempts a
    /// probe <c>SYS_kill(1, 0)</c> through the <c>args[0]+0xa</c> gadget and OR-s the syscall return code into
    /// the same slot. This gives every regime a socket-independent path to prove <c>_start</c> ran even when the
    /// klog fd is not routed anywhere: the loader writes its <c>payloadout</c> back to its own stdout, so the caller
    /// sees a non-zero value the moment the entry is reached. If the caller sees 0, the loader never jumped to
    /// <c>_start</c>. If the caller sees 0x53504350 exactly, <c>_start</c> ran but <c>args[0]+0xa</c> is not a
    /// callable syscall gadget on this loader. If the caller sees 0x53504350 OR-ed with a small integer, the
    /// gadget ran and the small integer is the SYS_kill return code.</summary>
    public const string BootcheckSymbol = "__sp_bootcheck";

    /// <summary>The data symbol the start object writes the saved arguments block into.</summary>
    public const string PayloadArgsDataSymbol = "__prospero_payload_args";

    /// <summary>The data symbol the klog wrapper uses as a one-shot cache of the resolved address.
    /// The current klog uses SYS_kexec directly so the slot is unused at runtime, but the symbol is
    /// kept for accessor-side compatibility (interop references it) and to keep bss layout stable
    /// across the compat-object exports.</summary>
    public const string KlogSlotSymbol = "__prospero_klog_slot";

    /// <summary>The scratch slot the pthread priming path passes as its out pointer.</summary>
    public const string GotScratchSymbol = "__prospero_got_scratch";

    /// <summary>The bss slot the start object stashes the raw <c>syscall; ret</c> gadget in. Every
    /// raw syscall the shim issues (SYS_kexec in the klog helper, and any future paths the fixup
    /// shim adds) is an indirect call through this slot with <c>rax</c> pre-set to the syscall
    /// number.</summary>
    public const string PtrSyscallSymbol = "__prospero_ptr_syscall";

    /// <summary>The bss slot holding the cached args-provided dlsym function pointer. Set by
    /// <see cref="DlsymInitSymbol"/> when the probe confirms args[0] is a real resolver; used by
    /// the GOT-fixup and pthread-priming cascades to resolve imports by their plain C name.</summary>
    public const string DlsymFnSymbol = "__sp_dlsym_fn";

    /// <summary>Tri-state flag: 0 = untested, 1 = usable dlsym cached in
    /// <see cref="DlsymFnSymbol"/>, 2 = args[0] is the degenerate getpid trampoline. Consumers
    /// gate their resolver call on <c>__sp_dlsym_ok == 1</c>.</summary>
    public const string DlsymOkSymbol = "__sp_dlsym_ok";

    /// <summary>Random 16-byte seed baked into the start object at build time. Reserved for a
    /// stack canary and pointer guard the runtime installs; kept in read-only text so it never
    /// moves.</summary>
    public const string TcbSeedSymbol = "__sp_tcb_seed";

    /// <summary>NativeAOT synthetic TCB block (0x300 bytes) in BSS. The self-pointer at
    /// offset +0x260 within the block is installed as FSBASE via
    /// <c>sysarch(SYS_sysarch=165, AMD64_SET_FSBASE=129)</c>, providing the glibc-style
    /// TCB layout that NativeAOT's Rh helpers expect (Thread struct at fs:0-0xF8,
    /// InlinedThreadStaticRoot at fs:0-0x258, stack canary at fs:0x28).</summary>
    public const string NataotTcbSymbol = "__sp_nataot_tcb";

    /// <summary>Saved host FSBASE value (8 bytes) in BSS. Written once by the save sequence
    /// after crt_syscall_init succeeds, read once by the restore sequence at terminate.
    /// Zero means the save never ran (early error path); the restore guard skips in that
    /// case since ptr_syscall would also be uninitialized.</summary>
    public const string SavedFsbaseSymbol = "__sp_saved_fsbase";

    /// <summary>Saved loader return address (8 bytes) in BSS. Written once at the top of
    /// <c>_start</c> before any CRT init can corrupt the stack, restored onto the stack
    /// just before <c>ret</c> in the terminate epilogue. Guards against a 32-bit copyout
    /// or overlapping kernel-write overwriting the 64-bit return address slot.</summary>
    public const string SavedRetaddrSymbol = "__sp_saved_retaddr";

    // ---- Core primitive symbols ----

    /// <summary>The register-shuffle syscall dispatch shim:
    /// <c>mov rax,rdi; mov rdi,rsi; mov rsi,rdx; mov rdx,rcx; mov r10,r8; mov r8,r9;
    /// mov r9,[rsp+8]; call qword ptr [rip+ptr_syscall]; ret</c>.</summary>
    public const string CrtSyscallSymbol = "__sp_crt_syscall";

    /// <summary>The kekcall dispatch shim:
    /// <c>mov eax,edi; mov rdi,rsi; mov rsi,rdx; mov rdx,rcx; mov r10,r8; mov r8,r9;
    /// mov r9,[rsp+8]; shl rax,32; or rax,0x27; call qword ptr [rip+ptr_syscall]; ret</c>.
    /// Packs the kekcall number into RAX[63:32] with SYS_getppid in RAX[31:0] and dispatches
    /// through the same ptr_syscall gadget as <see cref="CrtSyscallSymbol"/>.</summary>
    public const string CrtKekcallSymbol = "__sp_kekcall";

    /// <summary>Direct syscall wrapper for SYS_mdbg_call (573). Takes three arguments
    /// (cmd, arg2, arg3) and dispatches through ptr_syscall with the syscall number
    /// pre-loaded in RAX.</summary>
    public const string CrtMdbgCallSymbol = "__sp_mdbg_call";

    /// <summary>The probe that derives <c>ptr_syscall</c> from <c>args[0]</c>.
    /// Tries <c>args[0](0x1, "sceKernelDlsym", &amp;out)</c>,
    /// falls back to <c>0x2001</c>; if <c>out == args[0]</c>, re-resolves <c>"getpid"</c> and
    /// sets <c>ptr_syscall = getpid + 0xa</c>; else <c>ptr_syscall = args[0] + 0xa</c>.</summary>
    public const string CrtSyscallInitSymbol = "__sp_crt_syscall_init";

    /// <summary>The kernel arbitrary-write primitive.
    /// <c>SYS_setsockopt(MASTER_SOCK, IPPROTO_IPV6, IPV6_PKTINFO, &amp;buf, 20)</c> then
    /// <c>SYS_setsockopt(VICTIM_SOCK, IPPROTO_IPV6, IPV6_PKTINFO, data, len)</c>.</summary>
    public const string KernelWriteSymbol = "__sp_kernel_write";

    /// <summary>Kernel copyin primitive. Overwrites the pipe struct via <c>kernel_write</c>,
    /// then <c>SYS_write(rwpipe[1], uaddr, len)</c>.</summary>
    public const string KernelCopyinSymbol = "__sp_kernel_copyin";

    /// <summary>Kernel copyout primitive. Overwrites the pipe struct via <c>kernel_write</c>,
    /// then <c>SYS_read(rwpipe[0], uaddr, len)</c>.</summary>
    public const string KernelCopyoutSymbol = "__sp_kernel_copyout";

    /// <summary>Kernel init: latches <c>rwpair</c>, <c>rwpipe</c>, <c>pipe_addr</c>,
    /// <c>kdata_base</c> from the arguments block, queries the firmware version via
    /// <c>SYS_dynlib_get_obj_member</c>, and fills the per-FW offset table.</summary>
    public const string KernelInitSymbol = "__sp_kernel_init";

    // ---- Symbol resolver symbols ----

    /// <summary>Internal SHA-1 compression function. Processes one 64-byte block
    /// against a 20-byte (5 x uint32) state. Called by <see cref="NidEncodeSymbol"/>.</summary>
    public const string Sha1TransformSymbol = "__sp_sha1_transform";

    /// <summary>Runtime NID encoder: SHA-1 of <c>sym || salt</c>, bswap64 first 8 bytes,
    /// zero bytes 8-15, then custom base-64.</summary>
    public const string NidEncodeSymbol = "__sp_nid_encode";

    /// <summary>Walk the kernel <c>allproc</c> linked list to find the <c>struct proc</c>
    /// for a given pid.</summary>
    public const string KernelGetProcSymbol = "__sp_kernel_get_proc";

    /// <summary>Walk the kernel <c>allproc</c> linked list to find the first
    /// <c>struct proc</c> whose <c>p_comm</c> matches the supplied name.</summary>
    public const string KernelFindProcByCommSymbol = "__sp_kernel_find_proc_by_comm";

    /// <summary>Walk the kernel dynlib linked list for a process to find the entry
    /// matching a given handle, then copy the 0x180-byte struct to user memory.</summary>
    public const string KernelDynlibObjSymbol = "__sp_kernel_dynlib_obj";

    /// <summary>Resolve a NID string against a process's dynlib symbol table by walking
    /// kernel memory. Returns the resolved address or 0.</summary>
    public const string KernelDynlibResolveSymbol = "__sp_kernel_dynlib_resolve";

    /// <summary>Encode a plain name to NID via <see cref="NidEncodeSymbol"/>, then resolve
    /// via <see cref="KernelDynlibResolveSymbol"/>. Returns the resolved address or 0.</summary>
    public const string KernelDynlibDlsymSymbol = "__sp_kernel_dynlib_dlsym";

    // ---- RTLD orchestration symbols ----

    /// <summary>Patches ucred capabilities/attributes and syscall address permissions for the
    /// current process.</summary>
    public const string PatchInitSymbol = "__sp_patch_init";

    /// <summary>Resolves <c>snprintf</c>, <c>vsnprintf</c>, <c>strerror</c>, and <c>__error</c>
    /// from handle 0x2 (libSceLibcInternal) via <see cref="KernelDynlibDlsymSymbol"/>.</summary>
    public const string KlogInitSymbol = "__sp_klog_init";

    /// <summary>Resolves <c>strcpy</c>, <c>strcat</c>, <c>strcmp</c>, <c>strncmp</c>,
    /// <c>strlen</c>, <c>sprintf</c>, <c>calloc</c>, <c>free</c>, and <c>getenv</c> from
    /// handle 0x2 via <see cref="KernelDynlibDlsymSymbol"/> (symbol-resolution portion only).</summary>
    public const string RtldInitSymbol = "__sp_rtld_init";

    // ---- dlfcn API symbols ----

    /// <summary>Runtime dynamic library open.</summary>
    public const string DlopenSymbol = "__dlopen";

    /// <summary>Runtime dynamic symbol lookup.</summary>
    public const string DlsymSymbol = "__dlsym";

    /// <summary>Runtime dynamic library close.</summary>
    public const string DlcloseSymbol = "__dlclose";

    /// <summary>Runtime dynamic error string.</summary>
    public const string DlerrorSymbol = "__dlerror";

    // ---- dlfcn initialization symbols ----

    /// <summary>Resolves calloc/free/_Strerror/getargc/getargv/environ for the dlfcn subsystem.</summary>
    public const string RtldDlfcnInitSymbol = "__sp_rtld_dlfcn_init";

    /// <summary>Sets the root library descriptor for RTLD_DEFAULT lookups.</summary>
    public const string RtldDlfcnSetrootSymbol = "__sp_rtld_dlfcn_setroot";

    /// <summary>Resolves sceKernelLoadStartModule/StopUnload/strcmp/strncmp/calloc/malloc/free/strcpy
    /// for the SPRX loading backend.</summary>
    public const string RtldSprxInitSymbol = "__sp_rtld_sprx_init";

    /// <summary>Creates the SPRX library descriptor.</summary>
    public const string RtldSprxNewSymbol = "__sp_rtld_sprx_new";

    /// <summary>Creates the SO library descriptor.</summary>
    public const string RtldSoNewSymbol = "__sp_rtld_so_new";

    /// <summary>Processes R_X86_64_GLOB_DAT relocations for .so files: walks parent chain
    /// to find root, resolves via sym2lib+sym2addr, writes to GOT via memcpy.</summary>
    public const string SoRGlobDatSymbol = "__sp_so_r_glob_dat";

    /// <summary>Walks the kernel dynlib linked list to find a module handle by path basename.
    /// SDK-exact 468-byte implementation: calls kernel_get_proc to get the proc struct,
    /// then iterates the dynlib linked list via kernel_copyout, comparing each module's
    /// path basename against the requested name. Returns 0 on match (handle written to
    /// *output_ptr) or -1 on failure.</summary>
    public const string KernelDynlibHandleSymbol = "__sp_kernel_dynlib_handle";

    // ---- dlfcn library graph management symbols ----

    /// <summary>Allocates a new library descriptor, dispatching to ref/sprx backend.</summary>
    public const string RtldLibNewSymbol = "__sp_rtld_lib_new";

    /// <summary>Opens a library (refcount + vtable dispatch).</summary>
    public const string RtldLibOpenSymbol = "__sp_rtld_lib_open";

    /// <summary>Closes a library (refcount + recursive dep close + vtable).</summary>
    public const string RtldLibCloseSymbol = "__sp_rtld_lib_close";

    /// <summary>Destroys a library descriptor (vtable dispatch).</summary>
    public const string RtldLibDestroySymbol = "__sp_rtld_lib_destroy";

    /// <summary>Initializes a library (recursive dep init + vtable).</summary>
    public const string RtldLibInitSymbol = "__sp_rtld_lib_init";

    /// <summary>Finalizes a library (recursive dep fini + vtable).</summary>
    public const string RtldLibFiniSymbol = "__sp_rtld_lib_fini";

    /// <summary>Finds which library exports a symbol (recursive search + vtable).</summary>
    public const string RtldLibSym2libSymbol = "__sp_rtld_lib_sym2lib";

    /// <summary>Gets the address of a symbol from a library (vtable dispatch).</summary>
    public const string RtldLibSym2addrSymbol = "__sp_rtld_lib_sym2addr";

    /// <summary>Adds a dependency to a library's dependency list.</summary>
    public const string RtldLibAppendDepSymbol = "__sp_rtld_lib_append_dep";

    /// <summary>Gets the name of a symbol closest to the given address (vtable dispatch).</summary>
    public const string RtldLibAddr2symSymbol = "__sp_rtld_lib_addr2sym";

    /// <summary>Finds which library contains the given address (recursive range search).</summary>
    public const string RtldLibAddr2libSymbol = "__sp_rtld_lib_addr2lib";

    /// <summary>Removes a dependency from a library's dependency list.</summary>
    public const string RtldLibRemoveDepSymbol = "__sp_rtld_lib_remove_dep";

    /// <summary>Searches the filesystem for a library by name, checking system paths,
    /// randomized paths, LD_LIBRARY_PATH, homebrew dir, and cwd.</summary>
    public const string RtldFindFileSymbol = "__sp_rtld_find_file";

    /// <summary>Finds a library by its soname.</summary>
    public const string RtldLibSoname2libSymbol = "__sp_rtld_lib_soname2lib";

    // ---- dlfcn BSS data symbols ----

    /// <summary>Errno value for dlerror(). 4 bytes at BSS offset 192.</summary>
    public const string DlfcnDlerrnoSymbol = "__sp_dlfcn_dlerrno";
    /// <summary>Root library descriptor pointer. 8 bytes at BSS offset 200.</summary>
    public const string DlfcnRootSymbol = "__sp_dlfcn_root";
    /// <summary>Resolved getargc function pointer. 8 bytes at BSS offset 208.</summary>
    public const string DlfcnGetargcSymbol = "__sp_dlfcn_getargc";
    /// <summary>Resolved getargv function pointer. 8 bytes at BSS offset 216.</summary>
    public const string DlfcnGetargvSymbol = "__sp_dlfcn_getargv";
    /// <summary>Resolved environ pointer. 8 bytes at BSS offset 224.</summary>
    public const string DlfcnEnvironSymbol = "__sp_dlfcn_environ";
    /// <summary>Resolved _Strerror function pointer. 8 bytes at BSS offset 232.</summary>
    public const string DlfcnStrerrorSymbol = "__sp_dlfcn_strerror";
    /// <summary>Resolved sceKernelLoadStartModule. 8 bytes at BSS offset 240.</summary>
    public const string DlfcnSceLoadModSymbol = "__sp_dlfcn_sce_load_mod";
    /// <summary>Resolved sceKernelStopUnloadModule. 8 bytes at BSS offset 248.</summary>
    public const string DlfcnSceUnloadModSymbol = "__sp_dlfcn_sce_unload_mod";
    /// <summary>Resolved sceSysmoduleLoadModuleInternal. 8 bytes at BSS offset 256.</summary>
    public const string DlfcnSceSysmodLoadSymbol = "__sp_dlfcn_sce_sysmod_load";
    /// <summary>Resolved malloc function pointer. 8 bytes at BSS offset 264.</summary>
    public const string DlfcnMallocSymbol = "__sp_dlfcn_malloc";
    /// <summary>Resolved calloc function pointer (dlfcn context). 8 bytes at BSS offset 272.</summary>
    public const string DlfcnCallocSymbol = "__sp_dlfcn_calloc";
    /// <summary>Resolved free function pointer (dlfcn context). 8 bytes at BSS offset 280.</summary>
    public const string DlfcnFreeSymbol = "__sp_dlfcn_free";

    /// <summary>Resolved memcpy function pointer. 8 bytes at BSS offset 288.</summary>
    public const string RtldMemcpySymbol = "__sp_rtld_memcpy";

    // ---- Payload CRT symbols ----

    /// <summary>Resolves strcmp, strcpy, malloc, calloc, memcpy, free from handle 0x2.</summary>
    public const string RtldSoInitSymbol = "__sp_rtld_so_init";

    /// <summary>Resolves calloc, memcpy, free, strcpy, strcmp from handle 0x2.</summary>
    public const string RtldPayloadInitSymbol = "__sp_rtld_payload_init";

    /// <summary>Creates the payload library descriptor.</summary>
    public const string RtldPayloadNewSymbol = "__sp_rtld_payload_new";

    /// <summary>Exit function: <c>payload_exit(int code)</c>. Stores the exit code
    /// in <c>*payloadout</c> and transfers control back to <c>_start</c> via <c>__builtin_longjmp</c>.</summary>
    public const string PayloadExitSymbol = "payload_exit";

    /// <summary>Payload args accessor: <c>payload_get_args(void)</c>. Returns the saved
    /// <c>payload_args_t*</c>. Identical body to <see cref="GetArgsSymbol"/> but exported under an
    /// alternate name so both names resolve.</summary>
    public const string PayloadGetArgsSdkSymbol = "payload_get_args";

    /// <summary>The BSS symbol for the setjmp/longjmp buffer. 256 bytes (32 void* slots); only slots
    /// 0 (rbp), 1 (rip), 2 (rsp) are used. Used by <see cref="PayloadExitSymbol"/> and
    /// <c>_start</c>'s setjmp orchestration.</summary>
    public const string JmpbufSymbol = "__sp_jmpbuf";

    // ---- Kernel ucred helpers (Section 5 subset, needed by mdbg) ----

    /// <summary>Reads the ucred pointer for a process.</summary>
    public const string KernelGetProcUcredSymbol = "__sp_kernel_get_proc_ucred";

    /// <summary>Reads the SCE authid from a process's ucred.</summary>
    public const string KernelGetUcredAuthidSymbol = "__sp_kernel_get_ucred_authid";

    /// <summary>Writes the SCE authid into a process's ucred.</summary>
    public const string KernelSetUcredAuthidSymbol = "__sp_kernel_set_ucred_authid";

    /// <summary>Reads the 16-byte SCE caps from a process's ucred.</summary>
    public const string KernelGetUcredCapsSymbol = "__sp_kernel_get_ucred_caps";

    /// <summary>Writes 16-byte SCE caps into a process's ucred.</summary>
    public const string KernelSetUcredCapsSymbol = "__sp_kernel_set_ucred_caps";

    /// <summary>Reads the 32-byte SCE attrs from a process's ucred.</summary>
    public const string KernelGetUcredAttrsSymbol = "__sp_kernel_get_ucred_attrs";

    /// <summary>Writes 32-byte SCE attrs into a process's ucred.</summary>
    public const string KernelSetUcredAttrsSymbol = "__sp_kernel_set_ucred_attrs";

    /// <summary>Reads the prison pointer from a process's ucred.</summary>
    public const string KernelGetUcredPrisonSymbol = "__sp_kernel_get_ucred_prison";

    /// <summary>Writes the prison pointer into a process's ucred.</summary>
    public const string KernelSetUcredPrisonSymbol = "__sp_kernel_set_ucred_prison";

    /// <summary>Reads the root vnode from the kernel.</summary>
    public const string KernelGetRootVnodeSymbol = "__sp_kernel_get_root_vnode";

    /// <summary>Reads the filedesc pointer from a process.</summary>
    public const string KernelGetProcFiledescSymbol = "__sp_kernel_get_proc_filedesc";

    /// <summary>Reads the root directory vnode from a process.</summary>
    public const string KernelGetProcRootdirSymbol = "__sp_kernel_get_proc_rootdir";

    /// <summary>Sets the root directory vnode for a process.</summary>
    public const string KernelSetProcRootdirSymbol = "__sp_kernel_set_proc_rootdir";

    /// <summary>Reads the jail directory vnode from a process.</summary>
    public const string KernelGetProcJaildirSymbol = "__sp_kernel_get_proc_jaildir";

    /// <summary>Sets the jail directory vnode for a process.</summary>
    public const string KernelSetProcJaildirSymbol = "__sp_kernel_set_proc_jaildir";

    /// <summary>Finds a loaded module's handle by address range.</summary>
    public const string KernelDynlibFindHandleSymbol = "__sp_kernel_dynlib_find_handle";

    /// <summary>Gets a loaded module's mapbase address.</summary>
    public const string KernelDynlibMapbaseAddrSymbol = "__sp_kernel_dynlib_mapbase_addr";

    /// <summary>Gets a loaded module's file path.</summary>
    public const string KernelDynlibPathSymbol = "__sp_kernel_dynlib_path";

    /// <summary>Gets a loaded module's fini address.</summary>
    public const string KernelDynlibFiniAddrSymbol = "__sp_kernel_dynlib_fini_addr";

    /// <summary>Gets a loaded module's init address.</summary>
    public const string KernelDynlibInitAddrSymbol = "__sp_kernel_dynlib_init_addr";

    /// <summary>Gets a loaded module's entry address.</summary>
    public const string KernelDynlibEntryAddrSymbol = "__sp_kernel_dynlib_entry_addr";

    /// <summary>Walks the VM map entry tree to find the entry containing an address.
    ///</summary>
    public const string KernelGetVmemEntrySymbol = "__sp_kernel_get_vmem_entry";

    /// <summary>Sets memory protection on VM entries.</summary>
    public const string KernelSetVmemProtectionSymbol = "__sp_kernel_set_vmem_protection";

    /// <summary>Wrapper for <see cref="KernelSetVmemProtectionSymbol"/>.</summary>
    public const string KernelMprotectSymbol = "__sp_kernel_mprotect";

    /// <summary>Simple kernel getlong.</summary>
    public const string KernelGetlongSymbol = "__sp_kernel_getlong";

    /// <summary>Simple kernel setlong.</summary>
    public const string KernelSetlongSymbol = "__sp_kernel_setlong";

    /// <summary>Simple kernel getint.</summary>
    public const string KernelGetintSymbol = "__sp_kernel_getint";

    /// <summary>Simple kernel setint.</summary>
    public const string KernelSetintSymbol = "__sp_kernel_setint";

    /// <summary>Simple kernel getchar.</summary>
    public const string KernelGetcharSymbol = "__sp_kernel_getchar";

    /// <summary>Simple kernel setchar.</summary>
    public const string KernelSetcharSymbol = "__sp_kernel_setchar";

    /// <summary>Simple kernel getshort.</summary>
    public const string KernelGetshortSymbol = "__sp_kernel_getshort";

    /// <summary>Simple kernel setshort.</summary>
    public const string KernelSetshortSymbol = "__sp_kernel_setshort";

    /// <summary>Reads 16-byte QA flags from the kernel.</summary>
    public const string KernelGetQaflagsSymbol = "__sp_kernel_get_qaflags";

    /// <summary>Writes 16-byte QA flags to the kernel.</summary>
    public const string KernelSetQaflagsSymbol = "__sp_kernel_set_qaflags";

    /// <summary>Reads the firmware version from libSceLibcInternal.</summary>
    public const string KernelGetFwVersionSymbol = "__sp_kernel_get_fw_version";

    /// <summary>Reads the thread struct for a pid/tid pair.</summary>
    public const string KernelGetProcThreadSymbol = "__sp_kernel_get_proc_thread";

    /// <summary>Reads the file struct for a pid/fd pair.</summary>
    public const string KernelGetProcFileSymbol = "__sp_kernel_get_proc_file";

    /// <summary>Reads the VM protection for a memory range.</summary>
    public const string KernelGetVmemProtectionSymbol = "__sp_kernel_get_vmem_protection";

    /// <summary>Overlaps two sockets' inp6_outputopts for kernel R/W.</summary>
    public const string KernelOverlapSocketsSymbol = "__sp_kernel_overlap_sockets";

    /// <summary>Reads the uid from a process's ucred.</summary>
    public const string KernelGetUcredUidSymbol = "__sp_kernel_get_ucred_uid";

    /// <summary>Writes the uid into a process's ucred.</summary>
    public const string KernelSetUcredUidSymbol = "__sp_kernel_set_ucred_uid";

    /// <summary>Reads the ruid from a process's ucred.</summary>
    public const string KernelGetUcredRuidSymbol = "__sp_kernel_get_ucred_ruid";

    /// <summary>Writes the ruid into a process's ucred.</summary>
    public const string KernelSetUcredRuidSymbol = "__sp_kernel_set_ucred_ruid";

    /// <summary>Reads the svuid from a process's ucred.</summary>
    public const string KernelGetUcredSvuidSymbol = "__sp_kernel_get_ucred_svuid";

    /// <summary>Writes the svuid into a process's ucred.</summary>
    public const string KernelSetUcredSvuidSymbol = "__sp_kernel_set_ucred_svuid";

    /// <summary>Reads the rgid from a process's ucred.</summary>
    public const string KernelGetUcredRgidSymbol = "__sp_kernel_get_ucred_rgid";

    /// <summary>Writes the rgid into a process's ucred.</summary>
    public const string KernelSetUcredRgidSymbol = "__sp_kernel_set_ucred_rgid";

    /// <summary>Reads the svgid from a process's ucred.</summary>
    public const string KernelGetUcredSvgidSymbol = "__sp_kernel_get_ucred_svgid";

    /// <summary>Writes the svgid into a process's ucred.</summary>
    public const string KernelSetUcredSvgidSymbol = "__sp_kernel_set_ucred_svgid";

    /// <summary>Reads the ngroups count from a process's ucred.</summary>
    public const string KernelGetUcredNgroupsSymbol = "__sp_kernel_get_ucred_ngroups";

    /// <summary>Writes the ngroups count into a process's ucred.</summary>
    public const string KernelSetUcredNgroupsSymbol = "__sp_kernel_set_ucred_ngroups";

    /// <summary>Writes the first attribute byte into a process's ucred.</summary>
    public const string KernelSetUcredSceAttr0Symbol = "__sp_kernel_set_ucred_sce_attr0";

    /// <summary>Runtime dynamic address lookup.</summary>
    public const string DladdrSymbol = "__dladdr";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_ROOTVNODE</c>. Set by <see cref="KernelInitSymbol"/>.</summary>
    public const string KernelRootvnodeSymbol = "__sp_kernel_rootvnode";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_SECURITY_FLAGS</c>. Set by <see cref="KernelInitSymbol"/>.</summary>
    public const string KernelSecurityFlagsSymbol = "__sp_kernel_security_flags";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_QA_FLAGS</c>. Set by <see cref="KernelInitSymbol"/>.
    /// Derived as SECURITY_FLAGS + 0x24.</summary>
    public const string KernelQaFlagsSymbol = "__sp_kernel_qa_flags";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_PRISON0</c>. Set by <see cref="KernelInitSymbol"/>.</summary>
    public const string KernelPrison0Symbol = "__sp_kernel_prison0";

    /// <summary>BSS slot holding <c>KERNEL_OFFSET_VMSPACE_P_ROOT</c>. Set by <see cref="KernelInitSymbol"/>.</summary>
    public const string KernelVmspacePRootSymbol = "__sp_kernel_vmspace_p_root";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_TEXT_BASE</c>. Set by <see cref="KernelInitSymbol"/>.
    /// Computed per-FW as kdata_base minus a FW-specific offset.</summary>
    public const string KernelTextBaseSymbol = "__sp_kernel_text_base";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_BUS_DATA_DEVICES</c>. Set by <see cref="KernelInitSymbol"/>.
    /// Computed per-FW as kdata_base plus a FW-specific offset.</summary>
    public const string KernelBusDataDevicesSymbol = "__sp_kernel_bus_data_devices";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_TARGETID</c>. Set by <see cref="KernelInitSymbol"/>.
    /// Derived as SECURITY_FLAGS + 0x9.</summary>
    public const string KernelTargetidSymbol = "__sp_kernel_targetid";

    /// <summary>BSS slot holding <c>KERNEL_ADDRESS_UTOKEN_FLAGS</c>. Set by <see cref="KernelInitSymbol"/>.
    /// Derived as SECURITY_FLAGS + 0x8c.</summary>
    public const string KernelUtokenFlagsSymbol = "__sp_kernel_utoken_flags";

    // ---- MDBG debug protocol symbols ----

    /// <summary>Copies memory from a process via the MDBG debug daemon.</summary>
    public const string MdbgCopyoutSymbol = "mdbg_copyout";

    /// <summary>Copies memory into a process via the MDBG debug daemon. </summary>
    public const string MdbgCopyinSymbol = "mdbg_copyin";

    /// <summary>Writes a char to a process's memory via MDBG.</summary>
    public const string MdbgSetcharSymbol = "mdbg_setchar";

    /// <summary>Writes a short to a process's memory via MDBG.</summary>
    public const string MdbgSetshortSymbol = "mdbg_setshort";

    /// <summary>Writes an int to a process's memory via MDBG.</summary>
    public const string MdbgSetintSymbol = "mdbg_setint";

    /// <summary>Writes a long to a process's memory via MDBG.</summary>
    public const string MdbgSetlongSymbol = "mdbg_setlong";

    /// <summary>Reads a long from a process's memory via MDBG.</summary>
    public const string MdbgGetlongSymbol = "mdbg_getlong";

    /// <summary>Reads an int from a process's memory via MDBG.</summary>
    public const string MdbgGetintSymbol = "mdbg_getint";

    /// <summary>Reads a short from a process's memory via MDBG.</summary>
    public const string MdbgGetshortSymbol = "mdbg_getshort";

    /// <summary>Reads a char from a process's memory via MDBG.</summary>
    public const string MdbgGetcharSymbol = "mdbg_getchar";

    // ---- Cross-process memory helpers  ----

    /// <summary>Copies memory into a target process using MDBG fast path or page-table walk fallback.
    ///</summary>
    public const string KernelProcCopyinSymbol = "kernel_proc_copyin";

    /// <summary>Copies memory from a target process using MDBG fast path or page-table walk fallback.
    ///</summary>
    public const string KernelProcCopyoutSymbol = "kernel_proc_copyout";

    /// <summary>Writes a char to a target process's address space.</summary>
    public const string KernelProcSetcharSymbol = "kernel_proc_setchar";

    /// <summary>Writes a short to a target process's address space.</summary>
    public const string KernelProcSetshortSymbol = "kernel_proc_setshort";

    /// <summary>Writes an int to a target process's address space.</summary>
    public const string KernelProcSetintSymbol = "kernel_proc_setint";

    /// <summary>Writes a long to a target process's address space.</summary>
    public const string KernelProcSetlongSymbol = "kernel_proc_setlong";

    /// <summary>Reads a char from a target process's address space.</summary>
    public const string KernelProcGetcharSymbol = "kernel_proc_getchar";

    /// <summary>Reads a short from a target process's address space.</summary>
    public const string KernelProcGetshortSymbol = "kernel_proc_getshort";

    /// <summary>Reads an int from a target process's address space.</summary>
    public const string KernelProcGetintSymbol = "kernel_proc_getint";

    /// <summary>Reads a long from a target process's address space.</summary>
    public const string KernelProcGetlongSymbol = "kernel_proc_getlong";

    /// <summary>BSS slot holding the per-FW <c>KERNEL_OFFSET_VMSPACE_VM_PMAP</c> offset. Set by
    /// <see cref="KernelInitSymbol"/> during FW version detection.</summary>
    public const string VmspaceVmPmapSymbol = "__sp_vmspace_vm_pmap";

    /// <summary>A 3-byte identity stub (<c>push rdi; pop rax; ret</c>) emitted in <c>.text</c>.
    /// The GOT fixup installs its runtime address for any unresolved symbol whose name
    /// starts with <c>Rh</c> (NativeAOT internal helpers that no dynamic library exports).
    /// The prefix is two characters, not three: NativeAOT emits both <c>Rhp</c>-prefixed
    /// helpers (RhpReversePInvoke, RhpNewFast) and <c>Rh</c>-only helpers
    /// (RhAllocateNewObject, RhNewString, RhHandleFree, RhYield).
    /// Returns the first argument unchanged so callers that treat the return value as a
    /// callable pointer receive the argument they passed (typically a MethodTable or
    /// EEType address) instead of zero, preventing the <c>call *%r15</c> crash at
    /// address 0 that the previous <c>xor eax, eax</c> stub caused.</summary>
    public const string NopStubSymbol = "__sp_nop_stub";

    // ---- klog consumer function symbols  ----

    /// <summary>Formats a message with the process label and writes it to /dev/klog via SYS_kexec.
    ///</summary>
    public const string KlogPutsSymbol = "klog_puts";

    /// <summary>Variadic printf that formats via vsnprintf, prepends the process label, and writes
    /// to /dev/klog via SYS_kexec.</summary>
    public const string KlogPrintfSymbol = "klog_printf";

    /// <summary>Prints a message with the current errno string appended, prepends the process label,
    /// and writes to /dev/klog via SYS_kexec.</summary>
    public const string KlogPerrorSymbol = "klog_perror";

    // ---- BSS data symbols for klog_init resolved functions ----

    /// <summary>Resolved <c>snprintf</c> function pointer (from <see cref="KlogInitSymbol"/>).</summary>
    public const string KlogSnprintfSymbol = "__sp_klog_snprintf";

    /// <summary>Resolved <c>vsnprintf</c> function pointer.</summary>
    public const string KlogVsnprintfSymbol = "__sp_klog_vsnprintf";

    /// <summary>Resolved <c>strerror</c> function pointer.</summary>
    public const string KlogStrerrorSymbol = "__sp_klog_strerror";

    /// <summary>Resolved <c>__error</c> function pointer (errno accessor).</summary>
    public const string KlogErrorSymbol = "__sp_klog_error";

    // ---- BSS data symbols for rtld_init resolved functions ----

    /// <summary>Resolved <c>strcpy</c> function pointer (from <see cref="RtldInitSymbol"/>).</summary>
    public const string RtldStrcpySymbol = "__sp_rtld_strcpy";
    /// <summary>Resolved <c>strcat</c> function pointer.</summary>
    public const string RtldStrcatSymbol = "__sp_rtld_strcat";
    /// <summary>Resolved <c>strcmp</c> function pointer.</summary>
    public const string RtldStrcmpSymbol = "__sp_rtld_strcmp";
    /// <summary>Resolved <c>strncmp</c> function pointer.</summary>
    public const string RtldStrncmpSymbol = "__sp_rtld_strncmp";
    /// <summary>Resolved <c>strlen</c> function pointer.</summary>
    public const string RtldStrlenSymbol = "__sp_rtld_strlen";
    /// <summary>Resolved <c>sprintf</c> function pointer.</summary>
    public const string RtldSprintfSymbol = "__sp_rtld_sprintf";
    /// <summary>Resolved <c>calloc</c> function pointer.</summary>
    public const string RtldCallocSymbol = "__sp_rtld_calloc";
    /// <summary>Resolved <c>free</c> function pointer.</summary>
    public const string RtldFreeSymbol = "__sp_rtld_free";
    /// <summary>Resolved <c>getenv</c> function pointer.</summary>
    public const string RtldGetenvSymbol = "__sp_rtld_getenv";

    // ---- BSS data symbols for the kernel primitives ----

    /// <summary>The kernel pipe address latched from args[0x18].</summary>
    public const string PipeAddrSymbol = "__sp_pipe_addr";

    /// <summary>Read end of the kernel pipe pair latched from args[0x08][0].</summary>
    public const string RwPipe0Symbol = "__sp_rw_pipe_0";

    /// <summary>Write end of the kernel pipe pair latched from args[0x08][1].</summary>
    public const string RwPipe1Symbol = "__sp_rw_pipe_1";

    /// <summary>Master socket fd latched from args[0x10][0].</summary>
    public const string RwPair0Symbol = "__sp_rw_pair_0";

    /// <summary>Victim socket fd latched from args[0x10][1].</summary>
    public const string RwPair1Symbol = "__sp_rw_pair_1";

    /// <summary>Kernel data-segment base address latched from args[0x20].</summary>
    public const string KdataBaseSymbol = "__sp_kdata_base";

    /// <summary>Kernel allproc address computed from <see cref="KdataBaseSymbol"/> + FW offset.</summary>
    public const string AllprocSymbol = "__sp_allproc";

    /// <summary>The names this start object defines. A payload link resolves these from the start
    /// object rather than through a stub catalog or the compat object.</summary>
    public static IReadOnlyList<string> DefinedNames { get; } =
    [
        StartSymbol,
        GetArgsSymbol,
        KlogSymbol,
        FixupGotSymbol,
        DlsymInitSymbol,
        BootcheckSymbol,
        PayloadArgsDataSymbol,
        KlogSlotSymbol,
        GotScratchSymbol,
        PtrSyscallSymbol,
        DlsymFnSymbol,
        DlsymOkSymbol,
        TcbSeedSymbol,
        NataotTcbSymbol,
        CrtSyscallSymbol,
        CrtKekcallSymbol,
        CrtMdbgCallSymbol,
        CrtSyscallInitSymbol,
        KernelWriteSymbol,
        KernelCopyinSymbol,
        KernelCopyoutSymbol,
        KernelInitSymbol,
        PipeAddrSymbol,
        RwPipe0Symbol,
        RwPipe1Symbol,
        RwPair0Symbol,
        RwPair1Symbol,
        KdataBaseSymbol,
        AllprocSymbol,
        Sha1TransformSymbol,
        NidEncodeSymbol,
        KernelGetProcSymbol,
        KernelDynlibObjSymbol,
        KernelDynlibResolveSymbol,
        KernelDynlibDlsymSymbol,
        PatchInitSymbol,
        KlogInitSymbol,
        RtldInitSymbol,
        KlogSnprintfSymbol,
        KlogVsnprintfSymbol,
        KlogStrerrorSymbol,
        KlogErrorSymbol,
        RtldStrcpySymbol,
        RtldStrcatSymbol,
        RtldStrcmpSymbol,
        RtldStrncmpSymbol,
        RtldStrlenSymbol,
        RtldSprintfSymbol,
        RtldCallocSymbol,
        RtldFreeSymbol,
        RtldGetenvSymbol,
        NopStubSymbol,
        DlopenSymbol,
        DlsymSymbol,
        DlcloseSymbol,
        DlerrorSymbol,
        RtldDlfcnInitSymbol,
        RtldDlfcnSetrootSymbol,
        RtldSprxInitSymbol,
        RtldLibNewSymbol,
        RtldLibOpenSymbol,
        RtldLibCloseSymbol,
        RtldLibDestroySymbol,
        RtldLibInitSymbol,
        RtldLibFiniSymbol,
        RtldLibSym2libSymbol,
        RtldLibSym2addrSymbol,
        RtldLibAppendDepSymbol,
        RtldLibAddr2symSymbol,
        RtldLibAddr2libSymbol,
        RtldLibRemoveDepSymbol,
        RtldFindFileSymbol,
        RtldLibSoname2libSymbol,
        DlfcnDlerrnoSymbol,
        DlfcnRootSymbol,
        DlfcnGetargcSymbol,
        DlfcnGetargvSymbol,
        DlfcnEnvironSymbol,
        DlfcnStrerrorSymbol,
        DlfcnSceLoadModSymbol,
        DlfcnSceUnloadModSymbol,
        DlfcnSceSysmodLoadSymbol,
        DlfcnMallocSymbol,
        DlfcnCallocSymbol,
        DlfcnFreeSymbol,
        RtldMemcpySymbol,
        RtldPayloadInitSymbol,
        RtldPayloadNewSymbol,
        RtldSoInitSymbol,
        RtldSprxNewSymbol,
        RtldSoNewSymbol,
        SoRGlobDatSymbol,
        KernelDynlibHandleSymbol,
        PayloadExitSymbol,
        PayloadGetArgsSdkSymbol,
        JmpbufSymbol,
        KernelGetProcUcredSymbol,
        KernelGetUcredAuthidSymbol,
        KernelSetUcredAuthidSymbol,
        KernelGetUcredCapsSymbol,
        KernelSetUcredCapsSymbol,
        MdbgCopyoutSymbol,
        MdbgCopyinSymbol,
        MdbgSetcharSymbol,
        MdbgSetshortSymbol,
        MdbgSetintSymbol,
        MdbgSetlongSymbol,
        MdbgGetlongSymbol,
        MdbgGetintSymbol,
        MdbgGetshortSymbol,
        MdbgGetcharSymbol,
        KernelProcCopyinSymbol,
        KernelProcCopyoutSymbol,
        KernelProcSetcharSymbol,
        KernelProcSetshortSymbol,
        KernelProcSetintSymbol,
        KernelProcSetlongSymbol,
        KernelProcGetcharSymbol,
        KernelProcGetshortSymbol,
        KernelProcGetintSymbol,
        KernelProcGetlongSymbol,
        VmspaceVmPmapSymbol,
        KlogPutsSymbol,
        KlogPrintfSymbol,
        KlogPerrorSymbol,
        KernelGetUcredAttrsSymbol,
        KernelSetUcredAttrsSymbol,
        KernelGetUcredPrisonSymbol,
        KernelSetUcredPrisonSymbol,
        KernelGetRootVnodeSymbol,
        KernelGetProcFiledescSymbol,
        KernelGetProcRootdirSymbol,
        KernelSetProcRootdirSymbol,
        KernelGetProcJaildirSymbol,
        KernelSetProcJaildirSymbol,
        KernelDynlibFindHandleSymbol,
        KernelDynlibMapbaseAddrSymbol,
        KernelDynlibPathSymbol,
        KernelDynlibFiniAddrSymbol,
        KernelDynlibInitAddrSymbol,
        KernelDynlibEntryAddrSymbol,
        KernelGetVmemEntrySymbol,
        KernelSetVmemProtectionSymbol,
        KernelMprotectSymbol,
        KernelGetlongSymbol,
        KernelSetlongSymbol,
        KernelGetintSymbol,
        KernelSetintSymbol,
        KernelGetQaflagsSymbol,
        KernelRootvnodeSymbol,
        KernelSecurityFlagsSymbol,
        KernelQaFlagsSymbol,
        KernelPrison0Symbol,
        KernelVmspacePRootSymbol,
        KernelGetcharSymbol,
        KernelSetcharSymbol,
        KernelGetshortSymbol,
        KernelSetshortSymbol,
        KernelSetQaflagsSymbol,
        KernelGetFwVersionSymbol,
        KernelGetProcThreadSymbol,
        KernelGetProcFileSymbol,
        KernelGetVmemProtectionSymbol,
        KernelOverlapSocketsSymbol,
        KernelGetUcredUidSymbol,
        KernelSetUcredUidSymbol,
        KernelGetUcredRuidSymbol,
        KernelSetUcredRuidSymbol,
        KernelGetUcredSvuidSymbol,
        KernelSetUcredSvuidSymbol,
        KernelGetUcredRgidSymbol,
        KernelSetUcredRgidSymbol,
        KernelGetUcredSvgidSymbol,
        KernelSetUcredSvgidSymbol,
        KernelGetUcredNgroupsSymbol,
        KernelSetUcredNgroupsSymbol,
        KernelSetUcredSceAttr0Symbol,
        DladdrSymbol,
    ];

    /// <summary>The plain C name whose address the pthread priming path asks the cached dlsym
    /// for. Passed verbatim; the on-device resolver encodes to NID form internally.</summary>
    private const string PthreadSelfName = "pthread_self";

    /// <summary>Plain C name of the resolver export the probe asks for. The
    /// <c>__crt_syscall_init</c> function uses this exact name and treats the answer as "if the
    /// out slot is non-zero and different from args[0], the loader shipped a real resolver".</summary>
    private const string SceKernelDlsymName = "sceKernelDlsym";

    /// <summary>Breadcrumb the GOT-fixup shim prints through <c>__prospero_klog</c> before its
    /// first resolve.</summary>
    private const string SpFixupStartName = "sp:fixup:start\n";

    /// <summary>Breadcrumb the GOT-fixup shim prints through <c>__prospero_klog</c> after the
    /// loop finishes.</summary>
    private const string SpFixupDoneName = "sp:fixup:done\n";

    /// <summary>Breadcrumb <c>__sp_dlsym_init</c> prints when the probe accepts args[0] as a real
    /// resolver.</summary>
    private const string SpKernelInitOkName = "sp:kernel:init:ok\n";

    /// <summary>Breadcrumb <c>__sp_dlsym_init</c> prints when the probe rejects args[0]
    /// (the loader's getpid trampoline). Once this reaches the device log, the payload will still
    /// crash on the first PLT dispatch, but the failure is now localised to "no resolver
    /// available" rather than "no output at all".</summary>
    private const string SpKernelInitDegenName = "sp:kernel:init:degen\n";

    /// <summary>Breadcrumb <c>_start</c> prints as its very first act, before the bss-zero loop
    /// and before <c>__sp_dlsym_init</c>.</summary>
    private const string SpCrtEnterName = "sp:crt:enter\n";

    /// <summary>Breadcrumb <c>_start</c> prints after the synthetic TCB is installed and
    /// FSBASE is set via <c>sysarch(165, 129)</c>. At this point <c>ptr_syscall</c> is still
    /// NULL, so klog silently no-ops; the breadcrumb becomes visible only if a future
    /// reordering bootstraps klog before the TCB setup.</summary>
    private const string SpTcbSetName = "sp:tcb:set\n";

    /// <summary>Plain C name the <c>__sp_crt_syscall_init</c> probe resolves when
    /// <c>sceKernelDlsym == args[0]</c> (the loader probe path). The resulting address + 0xa gives
    /// the raw <c>syscall; ret</c> gadget inside the libc stub.</summary>
    private const string GetpidName = "getpid";

    // ---- Breadcrumbs for the RTLD orchestration layer ----
    private const string SpCrtSyscallInitFailName = "sp:crt:syscall-init:fail\n";
    private const string SpPatchOkName = "sp:patch:ok\n";
    private const string SpKlogOkName = "sp:klog:ok\n";
    private const string SpRtldOkName = "sp:rtld:ok\n";
    private const string SpMainEnterName = "sp:main:enter\n";
    private const string SpExitName = "sp:exit\n";
    private const string SpIsthreadedOkName = "sp:isthreaded:ok\n";
    private const string SpIsthreadedFailName = "sp:isthreaded:fail\n";
    private const string SpPayloadRunEnterName = "sp:payload:run:enter\n";
    private const string SpMainExitName = "sp:main:exit\n";
    private const string SpPayloadTerminateName = "sp:payload:terminate\n";
    private const string SpRtldSprxInitName = "sp:rtld:sprx:init\n";
    private const string SpRtldSoInitName = "sp:rtld:so:init\n";
    private const string SpRtldPayloadInitStartName = "sp:rtld:payload:init:start\n";
    private const string SpRtldPayloadInitDoneName = "sp:rtld:payload:init:done\n";
    private const string SpRtldDlfcnInitName = "sp:rtld:dlfcn:init\n";

    /// <summary>Breadcrumb the fixup loop prints through <c>__prospero_klog</c> after a
    /// symbol resolves successfully through the 3-handle cascade.</summary>
    private const string SpResolveOkName = "sp:resolve:ok\n";

    /// <summary>Breadcrumb the fixup loop prints through <c>__prospero_klog</c> when a
    /// symbol fails resolution through all three handles and does not match the
    /// <c>Rh</c> NativeAOT prefix.</summary>
    private const string SpResolveMissName = "sp:resolve:0\n";

    // ---- Resolver walk diagnostic breadcrumbs ----

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_dlsym</c> when the kernel
    /// memory walk (<c>kernel_dynlib_resolve</c>) returns 0, before attempting the
    /// <c>SYS_dynlib_dlsym(591)</c> fallback.</summary>
    private const string SpDlWalkMissName = "sp:dl:walk:miss\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_dlsym</c> when both the
    /// kernel memory walk and the <c>SYS_dynlib_dlsym(591)</c> fallback fail.</summary>
    private const string SpDlFbMissName = "sp:dl:fb:miss\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_resolve</c> after
    /// <c>kernel_dynlib_obj</c> succeeds.</summary>
    private const string SpDlWalkObjOkName = "sp:dl:walk:obj:ok\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_resolve</c> when
    /// <c>kernel_dynlib_obj</c> fails.</summary>
    private const string SpDlWalkObjFailName = "sp:dl:walk:obj:fail\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_resolve</c> when the
    /// metadata copyout fails.</summary>
    private const string SpDlWalkMetaFailName = "sp:dl:walk:meta:fail\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_resolve</c> when the
    /// mmap for the symbol table buffer fails.</summary>
    private const string SpDlWalkMmapFailName = "sp:dl:walk:mmap:fail\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_resolve</c> when the
    /// symtab or strtab copyout fails.</summary>
    private const string SpDlWalkCopyFailName = "sp:dl:walk:copy:fail\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_resolve</c> when the
    /// NID is not found in the symbol table.</summary>
    private const string SpDlWalkSymMissName = "sp:dl:walk:sym:miss\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_obj</c> when
    /// <c>kernel_get_proc</c> returns 0.</summary>
    private const string SpDlWalkProcZeroName = "sp:dl:walk:proc:0\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_dynlib_obj</c> when the
    /// requested handle is not found in the dynlib linked list.</summary>
    private const string SpDlWalkHandleMissName = "sp:dl:walk:handle:miss\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_get_proc</c> when the
    /// initial allproc copyout fails.</summary>
    private const string SpDlWalkAllprocFailName = "sp:dl:walk:allproc:fail\n";

    /// <summary>Breadcrumb emitted by <c>__sp_kernel_get_proc</c> when the
    /// allproc walk exhausts the list without finding the target PID.</summary>
    private const string SpDlWalkPidMissName = "sp:dl:walk:pid:miss\n";

    // ---- CRT orchestrator strings (payload_init/payload_run/payload_terminate) ----
    private const string IsthreadedName = "__isthreaded";
    private const string IsthreadedFailMsg = "Unable to resolve the symbol '__isthreaded'";
    private const string PatchFailMsg = "Unable to initialize patches";
    private const string RtldFailMsg = "Unable to initialize rtld";
    private const string PrognameName = "__progname";
    private const string ExitName = "exit";

    // ---- Init-step breadcrumbs (emitted from _start at each init phase) ----
    /// <summary>Prefix for the kernel-init failure breadcrumb. The two hex digits of the errno
    /// and a trailing newline are appended at runtime on the stack.</summary>
    private const string SpInitKernelFailName = "sp:init:kernel:fail=0x";
    private const string SpInitSyscallName = "sp:init:syscall\n";
    private const string SpInitKernelName = "sp:init:kernel\n";
    private const string SpInitKlogName = "sp:init:klog\n";
    private const string SpInitPatchName = "sp:init:patch\n";
    private const string SpInitRtldName = "sp:init:rtld\n";
    private const string SpInitDoneName = "sp:init:done\n";

    // ---- Plain C names resolved by klog_init and rtld_init ----
    private const string SnprintfName = "snprintf";
    private const string VsnprintfName = "vsnprintf";
    private const string StrerrorName = "strerror";
    private const string ErrorName = "__error";
    private const string StrcpyName = "strcpy";
    private const string StrcatName = "strcat";
    private const string StrcmpName = "strcmp";
    private const string StrncmpName = "strncmp";
    private const string StrlenName = "strlen";
    private const string SprintfName = "sprintf";
    private const string CallocName = "calloc";
    private const string FreeName = "free";
    private const string GetenvName = "getenv";

    // ---- Plain C names resolved by dlfcn_init and sprx_init ----
    private const string SceKernelLoadStartModuleName = "sceKernelLoadStartModule";
    private const string SceKernelStopUnloadModuleName = "sceKernelStopUnloadModule";
    private const string SceSysmoduleLoadModuleInternalName = "sceSysmoduleLoadModuleInternal";
    private const string MallocName = "malloc";
    private const string MemcpyName = "memcpy";
    private const string StrerrorUnderscoreName = "_Strerror";
    private const string GetargcName = "getargc";
    private const string GetargvName = "getargv";
    private const string EnvironFuncName = "environ";
    private const string LibSceSysmoduleSprxName = "libSceSysmodule.sprx";
    private const string LibSceSysmodulePathName = "/system/common/lib/libSceSysmodule.sprx";
    private const string SoResolveFailName = "sp:so:resolve:fail\n";

    // ---- Rodata strings for find_file and lib_new ----
    private const string SprxSuffix = ".sprx";
    private const string FfSysPrivLib = "/system/priv/lib/%s";
    private const string FfSysCommonLib = "/system/common/lib/%s";
    private const string FfSysExPrivExLib = "/system_ex/priv_ex/lib/%s";
    private const string FfSysExCommonExLib = "/system_ex/common_ex/lib/%s";
    private const string FfRandPrivLib = "/%s/priv/lib/%s";
    private const string FfRandCommonLib = "/%s/common/lib/%s";
    private const string FfRandPrivExLib = "/%s/priv_ex/lib/%s";
    private const string FfRandCommonExLib = "/%s/common_ex/lib/%s";
    private const string FfLdLibraryPath = "LD_LIBRARY_PATH";
    private const string FfHomebrewLib = "/user/homebrew/lib/%s";
    private const string FfCwdFmt = "%s/%s";

    // ---- Payload breadcrumbs ----
    private const string SpPayloadLoadFailName = "sp:payload:load:fail\n";
    private const string SpPayloadRelocUnsupName = "sp:payload:reloc:unsup\n";
    private const string SpPayloadOpenOkName = "sp:payload:open:ok\n";
    /// <summary>The soname __rtld_payload_new passes to thr_set_name.</summary>
    private const string PayloadSoname = "payload.elf";

    // ---- klog consumer format strings  ----
    private const string KlogPidFmt = "pid:%d";
    private const string KlogPutsFmt = "<118>[%s] %s\n";
    private const string KlogPrintfFmt = "<118>[%s] %s";
    private const string KlogPerrorFmt = "<118>[%s] %s: %s\n";

    // ---- Library descriptor struct offsets  ----
    private const int LibVtOpen = 0x00;
    private const int LibVtInit = 0x08;
    private const int LibVtSym2Addr = 0x10;
    private const int LibVtAddr2Sym = 0x18;
    private const int LibVtFini = 0x20;
    private const int LibVtClose = 0x28;
    private const int LibVtDestroy = 0x30;
    private const int LibSoname = 0x38;
    private const int LibSonameSize = 0x400;
    private const int LibSymtabStrtab = 0x438;
    private const int LibRefCount = 0x448;
    private const int LibParent = 0x450;
    private const int LibDepsHead = 0x458;
    private const int LibDepsTail = 0x460;
    private const int LibRefLib = 0x468;
    private const int LibDescSize = 0x470;

    // ---- SPRX library descriptor struct offsets (extends rtld_lib_t at +0x468) ----
    private const int SprxLibHandle = 0x468;
    private const int SprxLibStrtab = 0x470;
    private const int SprxLibSymtab = 0x478;
    private const int SprxLibSymtabSize = 0x480;
    private const int SprxLibUnloadOnClose = 0x488;
    private const int SprxLibSize = 0x490;

    // ---- SO library descriptor struct offsets (extends rtld_lib_t at +0x468) ----
    private const int SoLibImage = 0x468;
    private const int SoLibEhdr = 0x470;
    private const int SoLibPhdr = 0x478;
    private const int SoLibShdr = 0x480;
    private const int SoLibStrtab = 0x488;
    private const int SoLibSymtab = 0x490;
    private const int SoLibSymtabSize = 0x498;
    private const int SoLibSize = 0x4D0;

    // ---- Dependency node struct offsets (+0x08 = next, +0x10 = prev) ----
    private const int DepLib = 0x00;
    private const int DepNext = 0x08;
    private const int DepPrev = 0x10;
    private const int DepNodeSize = 0x18;

    private const int TcbSeedSize = 16;

    // ---- SDK sysmodtab: 0x89 (137) entries, each (name, sysmod_id) ----
    // Matches the SDK crt1.o .data.rel.ro.sysmodtab section byte-for-byte.
    // sprx_open iterates this table comparing lib->soname against each entry;
    // on match it calls sceSysmoduleLoadModuleInternal(id) instead of
    // sceKernelLoadStartModule. Each entry in the linked output is 16 bytes:
    //   offset 0: 8-byte pointer to name string (R_X86_64_RELATIVE)
    //   offset 8: uint32 sysmod_id
    //   offset 12: 4 bytes padding
    private static readonly (uint Id, string Name)[] SysmodEntries =
    [
        (0x8000005f, "libSceAbstractLocal.sprx"),
        (0x80000058, "libSceAbstractStorage.sprx"),
        (0x800000a1, "libSceAbstractTcs.sprx"),
        (0x80000062, "libSceAbstractTwitter.sprx"),
        (0x80000061, "libSceAbstractYoutube.sprx"),
        (0x80000013, "libSceAc3Enc.sprx"),
        (0x80000094, "libSceAgc.sprx"),
        (0x80000080, "libSceAgcDriver.sprx"),
        (0x80000093, "libSceAgcResourceRegistration.sprx"),
        (0x80000086, "libSceAgcVsh.sprx"),
        (0x80000087, "libSceAgcVshDebug.sprx"),
        (0x80000023, "libSceAjm.native.sprx"),
        (0x8000007e, "libSceAjmi.sprx"),
        (0x800000b7, "libSceAmpr.sprx"),
        (0x80000032, "libSceAppChecker.sprx"),
        (0x800000a7, "libSceAppDbShellCoreClient.sprx"),
        (0x80000014, "libSceAppInstUtil.sprx"),
        (0x80000077, "libSceAsyncStorageInternal.sprx"),
        (0x80000002, "libSceAudioIn.sprx"),
        (0x80000001, "libSceAudioOut.sprx"),
        (0x80000083, "libSceAudioSystem.sprx"),
        (0x8000002d, "libSceAudiodecCpuDtsHdMa.sprx"),
        (0x8000002e, "libSceAudiodecCpuLpcm.sprx"),
        (0x80000082, "libSceAudiodecCpuTrhd.sprx"),
        (0x80000021, "libSceAvSetting.sprx"),
        (0x80000085, "libSceAvcap2.sprx"),
        (0x8000003f, "libSceBackupRestoreUtil.sprx"),
        (0x8000002a, "libSceBgft.sprx"),
        (0x800000a3, "libSceBgsStorage.sprx"),
        (0x8000001a, "libSceCamera.sprx"),
        (0x80000007, "libSceCdlgUtilServer.sprx"),
        (0x80000018, "libSceCommonDialog.sprx"),
        (0x8000008a, "libSceComposite.sprx"),
        (0x8000008b, "libSceCompositeExt.sprx"),
        (0x800000ad, "libSceContentListController.sprx"),
        (0x80000057, "libSceDataTransfer.sprx"),
        (0x80000025, "libSceDbg.sprx"),
        (0x80000029, "libSceDipsw.sprx"),
        (0x80000056, "libSceDseehx.sprx"),
        (0x80000028, "libSceDtsEnc.sprx"),
        (0x8000009c, "libSceEmbeddedTts.sprx"),
        (0x8000009b, "libSceEmbeddedTtsCoreG3.sprx"),
        (0x80000066, "libSceFsInternalForVsh.sprx"),
        (0x800000a9, "libSceGLSlimVSH.sprx"),
        (0x8000005e, "libSceGifParser.sprx"),
        (0x8000007f, "libSceGpuCapture.sprx"),
        (0x8000007b, "libSceGpuTrace.sprx"),
        (0x8000005c, "libSceGvMp4Parser.sprx"),
        (0x80000017, "libSceHidControl.sprx"),
        (0x8000000a, "libSceHttp.sprx"),
        (0x8000008c, "libSceHttp2.sprx"),
        (0x80000078, "libSceHttpCache.sprx"),
        (0x800000a8, "libSceIcu.sprx"),
        (0x800000a6, "libSceIdu.sprx"),
        (0x80000059, "libSceImageUtil.sprx"),
        (0x8000001d, "libSceIpmi.sprx"),
        (0x8000009e, "libSceJemspace.sprx"),
        (0x8000006f, "libSceJitBridge.sprx"),
        (0x8000005b, "libSceJpegParser.sprx"),
        (0x800000b0, "libSceJsc.sprx"),
        (0x80000070, "libSceJscCompiler.sprx"),
        (0x800000b4, "libSceJxr.sprx"),
        (0x800000b5, "libSceJxrParser.sprx"),
        (0x80000031, "libSceKbEmulate.sprx"),
        (0x80000065, "libSceLibreSsl.sprx"),
        (0x800000b8, "libSceLibreSsl3.sprx"),
        (0x80000045, "libSceLoginMgrServer.sprx"),
        (0x80000027, "libSceMarlin.sprx"),
        (0x80000048, "libSceMat.sprx"),
        (0x8000001e, "libSceMbus.sprx"),
        (0x80000095, "libSceMediaFrameworkInterface.sprx"),
        (0x800000b6, "libSceMediaFrameworkUtil.sprx"),
        (0x8000005a, "libSceMetadataReaderWriter.sprx"),
        (0x80000079, "libSceNKWeb.sprx"),
        (0x8000007a, "libSceNKWebKit.sprx"),
        (0x8000001c, "libSceNet.sprx"),
        (0x80000009, "libSceNetCtl.sprx"),
        (0x80000090, "libSceNgs2.sprx"),
        (0x8000000c, "libSceNpCommon.sprx"),
        (0x8000008d, "libSceNpGameIntent.sprx"),
        (0x8000000d, "libSceNpManager.sprx"),
        (0x8000009a, "libSceNpRemotePlaySessionSignaling.sprx"),
        (0x8000001b, "libSceNpSns.sprx"),
        (0x800000a0, "libSceNpTcs.sprx"),
        (0x8000000e, "libSceNpWebApi.sprx"),
        (0x8000008f, "libSceNpWebApi2.sprx"),
        (0x80000044, "libSceOpusCeltDec.sprx"),
        (0x80000043, "libSceOpusCeltEnc.sprx"),
        (0x80000069, "libSceOpusDec.sprx"),
        (0x80000068, "libSceOpusSilkEnc.sprx"),
        (0x80000071, "libSceOrbisCompat.sprx"),
        (0x80000024, "libScePad.sprx"),
        (0x8000005d, "libScePngParser.sprx"),
        (0x80000098, "libScePosixForWebKit.sprx"),
        (0x80000030, "libScePsm.sprx"),
        (0x80000075, "libSceRazorCpu_debug.sprx"),
        (0x8000001f, "libSceRegMgr.sprx"),
        (0x800000b9, "libSceRemotePlayClientIpc.sprx"),
        (0x80000092, "libSceResourceArbitrator.sprx"),
        (0x80000076, "libSceRnpsAppMgr.sprx"),
        (0x80000020, "libSceRtc.sprx"),
        (0x8000000f, "libSceSaveData.sprx"),
        (0x8000008e, "libSceShareInternal.native.sprx"),
        (0x800000ae, "libSceSocialScreen.sprx"),
        (0x8000000b, "libSceSsl.sprx"),
        (0x8000003b, "libSceSulphaDrv.sprx"),
        (0x80000004, "libSceSysCore.sprx"),
        (0x80000026, "libSceSysUtil.sprx"),
        (0x800000b3, "libSceSystemLogger2.sprx"),
        (0x80000089, "libSceSystemLogger2Delivery.sprx"),
        (0x8000009f, "libSceSystemLogger2Game.sprx"),
        (0x80000088, "libSceSystemLogger2NativeQueueClient.sprx"),
        (0x80000010, "libSceSystemService.sprx"),
        (0x80000097, "libSceSystemTts.sprx"),
        (0x800000a2, "libSceTEEClient.sprx"),
        (0x80000011, "libSceUserService.sprx"),
        (0x80000091, "libSceVcodec.sprx"),
        (0x80000015, "libSceVdecCore.native.sprx"),
        (0x80000036, "libSceVdecSavc2.native.sprx"),
        (0x8000003c, "libSceVdecShevc.native.sprx"),
        (0x800000af, "libSceVdecSvp9.native.sprx"),
        (0x80000084, "libSceVenc.sprx"),
        (0x80000022, "libSceVideoOut.sprx"),
        (0x80000046, "libSceVideoOutSecondary.sprx"),
        (0x800000b2, "libSceVideoStreamingEngine_sys.sprx"),
        (0x80000012, "libSceVisionManager.sprx"),
        (0x8000007c, "libSceVnaInternal.sprx"),
        (0x8000007d, "libSceVnaWebsocket.sprx"),
        (0x80000099, "libSceVoiceCommand.sprx"),
        (0x80000072, "libSceWeb.sprx"),
        (0x80000073, "libSceWebKit2.sprx"),
        (0x80000074, "libSceWebKit2Secure.sprx"),
        (0x800000a4, "libSceWebmParserMdrw.sprx"),
        (0x800000ac, "libcairo.sprx"),
        (0x800000b1, "libcurl.sprx"),
        (0x800000aa, "libicu.sprx"),
        (0x800000ab, "libpng16.sprx"),
    ];
    private const int SysmodEntrySize = 16; // 8 (ptr) + 4 (id) + 4 (pad)
    private const int SysmodTabSize = 137 * SysmodEntrySize; // 0x890 = 2192

    // ---- Bss layout ----
    //  offset  size  symbol
    //     0     8    __prospero_payload_args
    //     8     8    __prospero_klog_slot           (kept for accessor compatibility; unused at runtime)
    //    16     8    __prospero_got_scratch
    //    24     8    __prospero_ptr_syscall
    //    32     8    __sp_dlsym_fn
    //    40     1    __sp_dlsym_ok                  (padded to 8)
    //    48     8    __sp_pipe_addr
    //    56     4    __sp_rw_pipe_0
    //    60     4    __sp_rw_pipe_1
    //    64     4    __sp_rw_pair_0
    //    68     4    __sp_rw_pair_1                 (padded to 72 for alignment)
    //    72     8    __sp_kdata_base
    //    80     8    __sp_allproc
    //    88     8    __sp_klog_snprintf
    //    96     8    __sp_klog_vsnprintf
    //   104     8    __sp_klog_strerror
    //   112     8    __sp_klog_error
    //   120     8    __sp_rtld_strcpy
    //   128     8    __sp_rtld_strcat
    //   136     8    __sp_rtld_strcmp
    //   144     8    __sp_rtld_strncmp
    //   152     8    __sp_rtld_strlen
    //   160     8    __sp_rtld_sprintf
    //   168     8    __sp_rtld_calloc
    //   176     8    __sp_rtld_free
    //   184     8    __sp_rtld_getenv
    private const int BssOffArgs = 0;
    private const int BssOffKlogSlot = 8;
    private const int BssOffGotScratch = 16;
    private const int BssOffPtrSyscall = 24;
    private const int BssOffDlsymFn = 32;
    private const int BssOffDlsymOk = 40;
    private const int BssOffPipeAddr = 48;
    private const int BssOffRwPipe0 = 56;
    private const int BssOffRwPipe1 = 60;
    private const int BssOffRwPair0 = 64;
    private const int BssOffRwPair1 = 68;
    private const int BssOffKdataBase = 72;
    private const int BssOffAllproc = 80;
    private const int BssOffKlogSnprintf = 88;
    private const int BssOffKlogVsnprintf = 96;
    private const int BssOffKlogStrerror = 104;
    private const int BssOffKlogError = 112;
    private const int BssOffRtldStrcpy = 120;
    private const int BssOffRtldStrcat = 128;
    private const int BssOffRtldStrcmp = 136;
    private const int BssOffRtldStrncmp = 144;
    private const int BssOffRtldStrlen = 152;
    private const int BssOffRtldSprintf = 160;
    private const int BssOffRtldCalloc = 168;
    private const int BssOffRtldFree = 176;
    private const int BssOffRtldGetenv = 184;

    // ---- BSS data symbols for the dlfcn subsystem ----
    //   192     4    __sp_dlfcn_dlerrno             (padded to 8)
    //   200     8    __sp_dlfcn_root
    //   208     8    __sp_dlfcn_getargc
    //   216     8    __sp_dlfcn_getargv
    //   224     8    __sp_dlfcn_environ
    //   232     8    __sp_dlfcn_strerror
    //   240     8    __sp_dlfcn_sce_load_mod
    //   248     8    __sp_dlfcn_sce_unload_mod
    //   256     8    __sp_dlfcn_sce_sysmod_load
    //   264     8    __sp_dlfcn_malloc
    private const int BssOffDlfcnDlerrno = 192;
    private const int BssOffDlfcnRoot = 200;
    private const int BssOffDlfcnGetargc = 208;
    private const int BssOffDlfcnGetargv = 216;
    private const int BssOffDlfcnEnviron = 224;
    private const int BssOffDlfcnStrerror = 232;
    private const int BssOffDlfcnSceLoadMod = 240;
    private const int BssOffDlfcnSceUnloadMod = 248;
    private const int BssOffDlfcnSceSysmodLoad = 256;
    private const int BssOffDlfcnMalloc = 264;
    private const int BssOffDlfcnCalloc = 272;
    private const int BssOffDlfcnFree = 280;

    // ---- BSS data symbols for the payload subsystem ----
    //   288     8    __sp_rtld_memcpy
    private const int BssOffRtldMemcpy = 288;

    // ---- BSS slot for setjmp/longjmp orchestration (jmpbuf void*[32]) ----
    //   296   256    __sp_jmpbuf (void*[32]; only [0]=rbp, [1]=rip, [2]=rsp used)
    private const int BssOffJmpbuf = 296;
    //   552     8    __sp_vmspace_vm_pmap           (per-FW offset set by kernel_init)
    private const int BssOffVmspaceVmPmap = 552;

    // ---- BSS data symbols for the kernel address globals (populated by __kernel_init) ----
    //   560     8    __sp_kernel_rootvnode           (KERNEL_ADDRESS_ROOTVNODE)
    //   568     8    __sp_kernel_security_flags      (KERNEL_ADDRESS_SECURITY_FLAGS)
    //   576     8    __sp_kernel_qa_flags            (= security_flags + 0x24)
    //   584     8    __sp_kernel_prison0             (= kernel_get_ucred_prison(0))
    //   592     8    __sp_kernel_vmspace_p_root      (per-FW: 0x1c0/0x1c8/0x1d0)
    private const int BssOffKernelRootvnode = 560;
    private const int BssOffKernelSecurityFlags = 568;
    private const int BssOffKernelQaFlags = 576;
    private const int BssOffKernelPrison0 = 584;
    private const int BssOffKernelVmspacePRoot = 592;
    //   600     4    __sp_kernel_fw_version          (cached by kernel_get_fw_version)
    private const int BssOffKernelFwVersion = 600;
    //   608     8    __sp_kernel_text_base           (KERNEL_ADDRESS_TEXT_BASE, per-FW)
    //   616     8    __sp_kernel_bus_data_devices    (KERNEL_ADDRESS_BUS_DATA_DEVICES, per-FW)
    //   624     8    __sp_kernel_targetid            (KERNEL_ADDRESS_TARGETID, = security_flags + 0x9)
    //   632     8    __sp_kernel_utoken_flags        (KERNEL_ADDRESS_UTOKEN_FLAGS, = security_flags + 0x8c)
    private const int BssOffKernelTextBase = 608;
    private const int BssOffKernelBusDataDevices = 616;
    private const int BssOffKernelTargetid = 624;
    private const int BssOffKernelUtokenFlags = 632;
    //   640   768    __sp_nataot_tcb                 (NativeAOT synthetic TCB, 0x300 bytes)
    //                                                 +0x008 = InlinedThreadStaticRoot (8B, init NULL)
    //                                                 +0x160 = ee_alloc_context guard (1B, init 0)
    //                                                 +0x168 = Thread struct base (flags=0, PInvokeFrame=NULL)
    //                                                 +0x260 = TCB self-pointer (set to &block+0x260)
    //                                                 +0x270 = host pthread ptr (copied from old fs:0x10)
    //                                                 +0x288 = stack canary (from __sp_tcb_seed[0])
    //                                                 +0x290 = second seed (from __sp_tcb_seed[8])
    private const int BssOffNataotTcb = 640;
    private const int BssOffSavedFsbase = 1408;
    private const int BssOffSavedRetaddr = 1416;
    private const int BssTotalSize = 1424;

    // ---- Payload library descriptor struct offsets (0x480 bytes total) ----
    private const int PayloadLibSymtab = 0x468;
    private const int PayloadLibStrtab = 0x470;
    private const int PayloadLibSymtabSize = 0x478;
    private const int PayloadLibSize = 0x480;

    /// <summary>The layout of the code the start object emits, and where each relocatable field
    /// lives inside that code.</summary>
    private static byte[] BuildCode(byte[] tcbSeed)
    {
        var b = new List<byte>(0x1000);
        _startRelocs = [];
        _dlsymInitRelocs = [];
        _klogRelocs = [];
        _fixupRelocs = [];
        _crtSyscallRelocs = [];
        _crtKekcallRelocs = [];
        _crtMdbgCallRelocs = [];
        _crtSyscallInitRelocs = [];
        _kernelWriteRelocs = [];
        _kernelCopyinRelocs = [];
        _kernelCopyoutRelocs = [];
        _kernelInitRelocs = [];
        _sha1TransformRelocs = [];
        _nidEncodeRelocs = [];
        _kernelGetProcRelocs = [];
        _kernelFindProcByCommRelocs = [];
        _kernelDynlibObjRelocs = [];
        _kernelDynlibResolveRelocs = [];
        _kernelDynlibDlsymRelocs = [];
        _patchInitRelocs = [];
        _klogInitRelocs = [];
        _klogFuncsRelocs = [];
        _rtldInitRelocs = [];
        _payloadRelocs = [];
        _ucredRelocs = [];
        _mdbgRelocs = [];
        _procioRelocs = [];
        _currentRelocs = _startRelocs;

        void AddRel(RelocSymbol sym, int at, long addend = -4) => _currentRelocs.Add(new Reloc(at, sym, RPc32, addend));

        // Deferred fixup list: call displacements from failure sites to the shared
        // __sp_klog_copyout_err helper. Populated at each gated emit-site, wired
        // after the helper function is emitted near the end of the text section.
        var copyoutErrCallDisps = new List<int>();

        // ============================================================================
        // _start (offset 0)
        //
        // _start entry sequence:
        //   bss zero -> save args -> payload_init (crt_syscall_init, kernel_init,
        //   klog_init, __isthreaded=1, patch_init, rtld_init) -> store error in
        //   payloadout -> setjmp -> payload_run (resolve getargc/getargv/environ/
        //   __progname, rtld_payload_new, dlfcn_setroot, lib_open, lib_init, main,
        //   lib_fini, lib_close, lib_destroy) -> payload_terminate (hijack detection,
        //   exit resolution)
        //
        // Register allocation:
        //   rbx = args pointer, reused for argv in payload_run
        //   r12 = environ pointer
        //   r13 = lib (rtld_lib_t*)
        //   r14d = argc / error codes
        //   r15d = error code accumulator
        //   rbp = frame pointer (saved in jmpbuf)
        // ============================================================================
        int startOff = b.Count;
        _currentRelocs = _startRelocs;

        void WriteRel32InBLocal(int at, int target)
        {
            int disp = target - (at + 4);
            b[at + 0] = (byte)(disp & 0xFF);
            b[at + 1] = (byte)((disp >> 8) & 0xFF);
            b[at + 2] = (byte)((disp >> 16) & 0xFF);
            b[at + 3] = (byte)((disp >> 24) & 0xFF);
        }

        // ---- Prologue ----
        // push rbp ; mov rbp, rsp
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);

        // Save the loader return address into BSS before any CRT init can corrupt
        // the stack slot. The terminate epilogue writes it back just before ret.
        b.AddRange([0x48, 0x8B, 0x45, 0x08]);                   // mov rax, [rbp+8]
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);             // mov [rip+__sp_saved_retaddr], rax
        AddRel(RelocSymbol.SavedRetaddr, b.Count - 4);

        // push r15 ; push r14 ; push r13 ; push r12 ; push rbx ; sub rsp, 8
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xEC, 0x08]);
        // mov rbx, rdi
        b.AddRange([0x48, 0x89, 0xFB]);

        // ---- Phase 1: BSS clear ----
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                 // lea rax, [rip+__bss_start]
        AddRel(RelocSymbol.BssStart, b.Count - 4);
        b.AddRange([0x48, 0x8D, 0x0D, 0, 0, 0, 0]);                 // lea rcx, [rip+__bss_end]
        AddRel(RelocSymbol.BssEnd, b.Count - 4);
        int bssLoop = b.Count;
        b.AddRange([0x48, 0x39, 0xC8]);                             // cmp rax, rcx
        b.AddRange([0x73, 0x00]);                                   // jae .Lbss_done
        int bssDoneJmpAt = b.Count - 1;
        b.AddRange([0xC6, 0x00, 0x00]);                             // mov byte [rax], 0
        b.AddRange([0x48, 0xFF, 0xC0]);                             // inc rax
        b.AddRange([0xEB, (byte)((sbyte)(bssLoop - (b.Count + 1) - 1) & 0xFF)]); // jmp .Lbss_loop
        int bssDone = b.Count;
        b[bssDoneJmpAt] = (byte)(bssDone - (bssDoneJmpAt + 1));

        // ---- Save args to BSS ----
        b.AddRange([0x48, 0x89, 0x1D, 0, 0, 0, 0]);                 // mov [rip+payload_args], rbx
        AddRel(RelocSymbol.PayloadArgs, b.Count - 4);

        // ---- Phase 1b removed: TCB setup now runs AFTER __sp_crt_syscall_init ----
        // Raw syscall instructions are blocked by the host kernel (PPRBUG-22859); the
        // FSBASE syscall must be dispatched through the ptr_syscall gadget that
        // __sp_crt_syscall_init derives from getpid+10.  Setup is emitted in Phase 1c
        // below, immediately after the crt-syscall init returns success.

        // Deferred fixups for the FSBASE save/restore and Phase 1c TCB setup (populated below).
        int tcbSetSyscallCallDisp = -1;
        int saveFsbaseSyscallCallDisp = -1;
        int restoreFsbaseSyscallCallDisp = -1;
        int thrExitSyscallCallDisp = -1;
        int bcTcbSetLeaAt = -1, bcTcbSetCallDisp = -1;

        // ---- Phase 2: payload_init (inlined) ----
        // Diagnostic breadcrumb position variables for _start init steps
        int bcCrtEnterLeaAt = -1, bcCrtEnterCallDisp = -1;
        int bcInitSyscallLeaAt = -1, bcInitSyscallCallDisp = -1;
        int bcInitKernelLeaAt = -1, bcInitKernelCallDisp = -1;
        int bcKernelInitOkLeaAt = -1, bcKernelInitOkCallDisp = -1;
        int bcInitKlogLeaAt = -1, bcInitKlogCallDisp = -1;
        int bcInitPatchLeaAt = -1, bcInitPatchCallDisp = -1;
        int bcInitRtldLeaAt = -1, bcInitRtldCallDisp = -1;
        int bcInitDoneLeaAt = -1, bcInitDoneCallDisp = -1;
        int bcMainEnterLeaAt = -1, bcMainEnterCallDisp = -1;
        int bcIsthreadedOkLeaAt = -1, bcIsthreadedOkCallDisp = -1;
        int bcIsthreadedFailLeaAt = -1, bcIsthreadedFailCallDisp = -1;
        int bcPayloadRunEnterLeaAt = -1, bcPayloadRunEnterCallDisp = -1;
        int bcMainExitLeaAt = -1, bcMainExitCallDisp = -1;
        int bcPayloadTerminateLeaAt = -1, bcPayloadTerminateCallDisp = -1;

        // sp:crt:enter (ptr_syscall is 0 at this point; klog returns without emitting)
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_crt_enter]
            bcCrtEnterLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcCrtEnterCallDisp = b.Count - 4;
        }

        // sp:init:syscall
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_init_syscall]
            bcInitSyscallLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcInitSyscallCallDisp = b.Count - 4;
        }

        // Step 1: __crt_syscall_init(args)
        b.AddRange([0x48, 0x89, 0xDF]);                             // mov rdi, rbx
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_crt_syscall_init
        int startCallSyscallInitDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Linit_store_err
        int initStoreErrJmp1 = b.Count - 4;

        // ---- Phase 1b+: save host FSBASE before SET_FSBASE overwrites it ----
        // sysarch(SYS_sysarch=165, AMD64_GET_FSBASE=128, &stack_slot) reads the current
        // FSBASE MSR into a stack-allocated qword.  The value is stored into
        // __sp_saved_fsbase so the terminate path can restore it before returning to the
        // host.  At this point ptr_syscall is initialized (crt_syscall_init succeeded
        // above), so __sp_crt_syscall can dispatch.  FSBASE is still the host original
        // (no SET_FSBASE has run yet).
        b.AddRange([0x48, 0x83, 0xEC, 0x08]);                       // sub rsp, 8         (scratch slot)
        b.AddRange([0x48, 0x8D, 0x14, 0x24]);                       // lea rdx, [rsp]     (arg2 = &slot)
        b.AddRange([0xBE, 0x80, 0x00, 0x00, 0x00]);                 // mov esi, 128       (arg1 = AMD64_GET_FSBASE)
        b.AddRange([0xBF, 0xA5, 0x00, 0x00, 0x00]);                 // mov edi, 165       (sysno = SYS_sysarch)
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_crt_syscall
        saveFsbaseSyscallCallDisp = b.Count - 4;
        b.AddRange([0x58]);                                         // pop rax            (rax = host FSBASE)
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);                 // mov [rip+disp32], rax  -> __sp_saved_fsbase
        AddRel(RelocSymbol.SavedFsbase, b.Count - 4);

        // ---- Phase 1c: NativeAOT synthetic TCB setup ----
        // The host SceSpZeroConf thread has fs:0 = sentinel (not a valid pointer), so any
        // NativeAOT Rh helper reading fs:0 as a TCB self-pointer computes garbage and
        // SIGSEGVs.  Allocate a 0x300-byte BSS block (__sp_nataot_tcb) with the self-
        // pointer at +0x260, copy the host's fs:0x10 (pthread pointer) forward, seed the
        // stack canary from __sp_tcb_seed, and set FSBASE via sysarch(165, 129).
        //
        // Raw syscall is blocked by the host kernel (PPRBUG-22859), so the dispatch
        // routes through __sp_crt_syscall which forwards to the ptr_syscall gadget
        // (getpid+10) that __sp_crt_syscall_init just derived.

        // Save the host's pthread pointer from fs:0x10 into r15 (callee-saved).
        b.AddRange([0x64, 0x4C, 0x8B, 0x3C, 0x25, 0x10, 0x00, 0x00, 0x00]); // mov r15, fs:[0x10]

        // Compute TCB address = &__sp_nataot_tcb + 0x260.
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                 // lea rax, [rip+__sp_nataot_tcb+0x260]
        AddRel(RelocSymbol.NataotTcb, b.Count - 4, 0x260 - 4);

        // Write self-pointer at TCB+0x0 (the platform's convention diverges here; NativeAOT
        // expects this qword to equal the address it lives at).
        b.AddRange([0x48, 0x89, 0x00]);                             // mov [rax], rax

        // Copy the host's pthread pointer to TCB+0x10 so calls into libSceLibcInternal
        // that read fs:0x10 through the new FSBASE still find their thread struct.
        b.AddRange([0x4C, 0x89, 0x78, 0x10]);                       // mov [rax+0x10], r15

        // Copy the host's stack canary from the old fs:0x28 to TCB+0x28 so any function
        // whose prologue already saved a canary before this point still sees the same
        // value on epilogue check.  Same for the second seed slot at fs:0x30.
        //
        // The canary must NOT be seeded from a static constant: any managed function
        // whose prologue captures fs:0x28 will compare against fs:0x28 at epilogue
        // time, and if a later runtime call (pthread_self, RhpInitialize, ...)
        // rewrites fs:0x28 with a fresh random value, the check fails and libc
        // aborts via INT 0x45 (SIGABRT).  Forwarding the host's live value keeps the
        // pre/post views consistent through the FSBASE switch.
        b.AddRange([0x64, 0x48, 0x8B, 0x14, 0x25, 0x28, 0x00, 0x00, 0x00]); // mov rdx, fs:[0x28]
        b.AddRange([0x48, 0x89, 0x50, 0x28]);                       // mov [rax+0x28], rdx
        b.AddRange([0x64, 0x48, 0x8B, 0x14, 0x25, 0x30, 0x00, 0x00, 0x00]); // mov rdx, fs:[0x30]
        b.AddRange([0x48, 0x89, 0x50, 0x30]);                       // mov [rax+0x30], rdx

        // Set FSBASE = TCB via __sp_crt_syscall(SYS_sysarch=165, AMD64_SET_FSBASE=129,
        // &tcb_addr).  Push rax to stash the TCB address on the stack; rdx points at
        // the pushed qword (sysarch's parms argument is a pointer to the register_t
        // holding the desired FSBASE value).
        b.AddRange([0x50]);                                         // push rax   (stash tcb addr)
        b.AddRange([0x48, 0x8D, 0x14, 0x24]);                       // lea rdx, [rsp]  (arg2 = &tcb_addr)
        b.AddRange([0xBE, 0x81, 0x00, 0x00, 0x00]);                 // mov esi, 129    (arg1 = AMD64_SET_FSBASE)
        b.AddRange([0xBF, 0xA5, 0x00, 0x00, 0x00]);                 // mov edi, 165    (sysno = SYS_sysarch)
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_crt_syscall
        tcbSetSyscallCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                       // add rsp, 8  (unpush)

        // Breadcrumb sp:tcb:set (diagnostic builds only).  ptr_syscall is set, so
        // __prospero_klog will emit through it.
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_tcb_set]
            bcTcbSetLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcTcbSetCallDisp = b.Count - 4;
        }

        // sp:init:kernel
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_init_kernel]
            bcInitKernelLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcInitKernelCallDisp = b.Count - 4;
        }

        // Step 2: __kernel_init(args)
        b.AddRange([0x48, 0x89, 0xDF]);                             // mov rdi, rbx
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_init
        int startCallKernelInitDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Linit_store_err
        int initStoreErrJmp2 = b.Count - 4;

        // sp:kernel:init:ok
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_kernel_init_ok]
            bcKernelInitOkLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcKernelInitOkCallDisp = b.Count - 4;
        }

        // sp:init:klog
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_init_klog]
            bcInitKlogLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcInitKlogCallDisp = b.Count - 4;
        }

        // Step 3: __klog_init()
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_klog_init
        int startCallKlogInitDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Linit_store_err
        int initStoreErrJmp3 = b.Count - 4;

        // Step 4: KERNEL_DLSYM(0x2, "__isthreaded"); *__isthreaded = 1
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);                 // mov esi, 2
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"__isthreaded"]
        int isthreadedLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int isthreadedDlsymDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Listhreaded_fail
        int isthreadedFailJmp = b.Count - 4;
        b.AddRange([0xC7, 0x00, 0x01, 0x00, 0x00, 0x00]);           // mov dword [rax], 1

        // sp:isthreaded:ok
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_isthreaded_ok]
            bcIsthreadedOkLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcIsthreadedOkCallDisp = b.Count - 4;
        }

        // sp:init:patch
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_init_patch]
            bcInitPatchLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcInitPatchCallDisp = b.Count - 4;
        }

        // Step 5: __patch_init()
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_patch_init
        int startCallPatchInitDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lpatch_fail
        int patchFailJmp = b.Count - 4;

        // sp:init:rtld
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_init_rtld]
            bcInitRtldLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcInitRtldCallDisp = b.Count - 4;
        }

        // Step 6: __rtld_init()
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_init
        int startCallRtldInitDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lrtld_fail
        int rtldFailJmp = b.Count - 4;

        // sp:init:done
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_init_done]
            bcInitDoneLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcInitDoneCallDisp = b.Count - 4;
        }

        // payload_init succeeded: store 0 in payloadout
        b.AddRange([0x31, 0xC0]);                                   // xor eax, eax
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Linit_done
        int initDoneJmp = b.Count - 4;

        // .Listhreaded_fail:
        int isthreadedFail = b.Count;
        WriteRel32InBLocal(isthreadedFailJmp, isthreadedFail);
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_isthreaded_fail]
            bcIsthreadedFailLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcIsthreadedFailCallDisp = b.Count - 4;
        }
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);                 // lea rdi, [rip+"Unable to resolve..."]
        int isthreadedFailMsgLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __prospero_klog
        int isthreadedFailKlogDisp = b.Count - 4;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Linit_store_err
        int initStoreErrJmp4 = b.Count - 4;

        // .Lpatch_fail:
        int patchFail = b.Count;
        WriteRel32InBLocal(patchFailJmp, patchFail);
        b.AddRange([0x41, 0x89, 0xC6]);                             // mov r14d, eax
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);                 // lea rdi, [rip+"Unable to initialize patches"]
        int patchFailMsgLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __prospero_klog
        int patchFailKlogDisp = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xF0]);                             // mov eax, r14d
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Linit_store_err
        int initStoreErrJmp5 = b.Count - 4;

        // .Lrtld_fail:
        int rtldFail = b.Count;
        WriteRel32InBLocal(rtldFailJmp, rtldFail);
        b.AddRange([0x41, 0x89, 0xC6]);                             // mov r14d, eax
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);                 // lea rdi, [rip+"Unable to initialize rtld"]
        int rtldFailMsgLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __prospero_klog
        int rtldFailKlogDisp = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xF0]);                             // mov eax, r14d
        // fall through to .Linit_store_err

        // .Linit_store_err: *payloadout = eax
        int initStoreErr = b.Count;
        WriteRel32InBLocal(initStoreErrJmp1, initStoreErr);
        WriteRel32InBLocal(initStoreErrJmp2, initStoreErr);
        WriteRel32InBLocal(initStoreErrJmp3, initStoreErr);
        WriteRel32InBLocal(initStoreErrJmp4, initStoreErr);
        WriteRel32InBLocal(initStoreErrJmp5, initStoreErr);
        b.AddRange([0x48, 0x8B, 0x4B, 0x28]);                       // mov rcx, [rbx+0x28]
        b.AddRange([0x89, 0x01]);                                   // mov [rcx], eax
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lterminate
        int terminateJmp1 = b.Count - 4;

        // .Linit_done: (init succeeded, eax=0)
        int initDone = b.Count;
        WriteRel32InBLocal(initDoneJmp, initDone);

        // ---- Phase 3: __builtin_setjmp + payload_run ----
        // Save rbp, return address, rsp into jmpbuf
        b.AddRange([0x48, 0x89, 0x2D, 0, 0, 0, 0]);                 // mov [rip+jmpbuf+0], rbp
        _currentRelocs.Add(new Reloc(b.Count - 4, RelocSymbol.Jmpbuf, RPc32, -4));
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                 // lea rax, [rip+.Llongjmp_return]
        int longjmpRetLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);                 // mov [rip+jmpbuf+8], rax
        _currentRelocs.Add(new Reloc(b.Count - 4, RelocSymbol.Jmpbuf, RPc32, 4));
        b.AddRange([0x48, 0x89, 0x25, 0, 0, 0, 0]);                 // mov [rip+jmpbuf+16], rsp
        _currentRelocs.Add(new Reloc(b.Count - 4, RelocSymbol.Jmpbuf, RPc32, 12));
        b.AddRange([0x31, 0xC0]);                                   // xor eax, eax (setjmp returns 0)
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lterminate (not taken first time)
        int terminateJmp2 = b.Count - 4;
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lpayload_run
        int payloadRunJmp = b.Count - 4;

        // .Llongjmp_return: (payload_exit called longjmp)
        int longjmpReturn = b.Count;
        WriteRel32InBLocal(longjmpRetLeaAt, longjmpReturn);
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lterminate
        int terminateJmp3 = b.Count - 4;

        // .Lpayload_run:
        int payloadRun = b.Count;
        WriteRel32InBLocal(payloadRunJmp, payloadRun);
        b.AddRange([0x45, 0x31, 0xFF]);                             // xor r15d, r15d (error accumulator)

        // sp:payload:run:enter
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_payload_run_enter]
            bcPayloadRunEnterLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcPayloadRunEnterCallDisp = b.Count - 4;
        }

        // Resolve getargc: try handle 0x1, fallback 0x2001
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);                 // mov esi, 1
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"getargc"]
        int getargcLeaAt1 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int getargcDlsymDisp1 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC6]);                             // mov r14, rax
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x00]);                                   // jnz .Lresolve_getargv
        int resolveGetargvJmp1 = b.Count - 1;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);                 // mov esi, 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"getargc"]
        int getargcLeaAt2 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int getargcDlsymDisp2 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC6]);                             // mov r14, rax
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lno_args
        int noArgsJmp1 = b.Count - 4;

        // .Lresolve_getargv:
        int resolveGetargv = b.Count;
        b[resolveGetargvJmp1] = (byte)(resolveGetargv - (resolveGetargvJmp1 + 1));
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);                 // mov esi, 1
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"getargv"]
        int getargvLeaAt1 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int getargvDlsymDisp1 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC7]);                             // mov r15, rax
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x00]);                                   // jnz .Lcall_args
        int callArgsJmp1 = b.Count - 1;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);                 // mov esi, 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"getargv"]
        int getargvLeaAt2 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int getargvDlsymDisp2 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC7]);                             // mov r15, rax
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lno_args
        int noArgsJmp2 = b.Count - 4;

        // .Lcall_args:
        int callArgs = b.Count;
        b[callArgsJmp1] = (byte)(callArgs - (callArgsJmp1 + 1));
        b.AddRange([0x41, 0xFF, 0xD6]);                             // call r14 (getargc)
        b.AddRange([0x41, 0x89, 0xC6]);                             // mov r14d, eax (argc)
        b.AddRange([0x41, 0xFF, 0xD7]);                             // call r15 (getargv)
        b.AddRange([0x48, 0x89, 0xC3]);                             // mov rbx, rax (argv; reuse rbx)
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lresolve_environ
        int resolveEnvironJmp = b.Count - 4;

        // .Lno_args:
        int noArgs = b.Count;
        WriteRel32InBLocal(noArgsJmp1, noArgs);
        WriteRel32InBLocal(noArgsJmp2, noArgs);
        b.AddRange([0x31, 0xDB]);                                   // xor ebx, ebx (argv=0)
        b.AddRange([0x45, 0x31, 0xF6]);                             // xor r14d, r14d (argc=0)

        // .Lresolve_environ:
        int resolveEnviron = b.Count;
        WriteRel32InBLocal(resolveEnvironJmp, resolveEnviron);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);                 // mov esi, 1
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"environ"]
        int environLeaAt1 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int environDlsymDisp1 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC4]);                             // mov r12, rax
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x00]);                                   // jnz .Lresolve_progname
        int resolvePrognameJmp1 = b.Count - 1;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);                 // mov esi, 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"environ"]
        int environLeaAt2 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int environDlsymDisp2 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC4]);                             // mov r12, rax

        // .Lresolve_progname:
        int resolveProgname = b.Count;
        b[resolvePrognameJmp1] = (byte)(resolveProgname - (resolvePrognameJmp1 + 1));
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);                 // mov esi, 1
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"__progname"]
        int prognameLeaAt1 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int prognameDlsymDisp1 = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x00]);                                   // jnz .Lgot_progname
        int gotPrognameJmp1 = b.Count - 1;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);                 // mov esi, 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+"__progname"]
        int prognameLeaAt2 = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int prognameDlsymDisp2 = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x00]);                                   // jnz .Lgot_progname
        int gotPrognameJmp2 = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                 // lea rax, [rip+""] (empty fallback)
        int emptyStringLeaAt = b.Count - 4;

        // .Lgot_progname:
        int gotProgname = b.Count;
        b[gotPrognameJmp1] = (byte)(gotProgname - (gotPrognameJmp1 + 1));
        b[gotPrognameJmp2] = (byte)(gotProgname - (gotPrognameJmp2 + 1));

        // __rtld_payload_new(progname)
        b.AddRange([0x48, 0x89, 0xC7]);                             // mov rdi, rax
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_payload_new
        int payloadNewCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lterminate
        int terminateJmp4 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC5]);                             // mov r13, rax (r13 = lib)

        // __rtld_dlfcn_setroot(lib)
        b.AddRange([0x48, 0x89, 0xC7]);                             // mov rdi, rax
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_dlfcn_setroot
        int dlfcnSetrootCallDisp = b.Count - 4;

        // __rtld_lib_open(lib)
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_open
        int libOpenCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lopen_fail
        int openFailJmp = b.Count - 4;

        // __rtld_lib_init(lib, argc, argv, environ)
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0x44, 0x89, 0xF6]);                             // mov esi, r14d (argc)
        b.AddRange([0x48, 0x89, 0xDA]);                             // mov rdx, rbx (argv)
        b.AddRange([0x4C, 0x89, 0xE1]);                             // mov rcx, r12 (environ)
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_init
        int libInitCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                   // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Linit_lib_fail
        int initLibFailJmp = b.Count - 4;

        // sp:main:enter
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_main_enter]
            bcMainEnterLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcMainEnterCallDisp = b.Count - 4;
        }

        // Prime the platform's pthread lazy init before entering managed code.  The host
        // libSceLibcInternal's exported pthread_* wrappers carry a lazy-init check
        // that sets up the per-thread pthread struct at fs:0x10 on first call.
        // The internal mutex path used by libc's mspace lock (called by malloc)
        // has NO such check, so any managed call to malloc that hits the internal
        // path before pthread_self has run finds fs:0x10 in an unusable state and
        // aborts.  Resolve pthread_self via kernel_dynlib_dlsym(0x1 -> 0x2 fallback)
        // and call it once here to force the platform's real thread struct into place.
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);                 // mov esi, 0x1  (own image first)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+pthread_self]
        int startPthreadSelfNameLea1At = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int startPthreadSelfDlsym1Disp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x1B]);                                   // jnz .Lpthread_self_call (+27)
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);                 // mov esi, 0x2  (libSceLibcInternal)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                 // lea rdx, [rip+pthread_self]
        int startPthreadSelfNameLea2At = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_kernel_dynlib_dlsym
        int startPthreadSelfDlsym2Disp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x74, 0x02]);                                   // jz .Lpthread_self_skip (+2)
        // .Lpthread_self_call:
        b.AddRange([0xFF, 0xD0]);                                   // call rax  (pthread_self)
        // .Lpthread_self_skip:

        // main -- resolves to libbootstrapper.o's bootstrap entry, which calls RhInitialize,
        // RhRegisterOSModule, and InitializeModules, then tail-calls __managed__Main (the
        // template's [UnmanagedCallersOnly] managed entry).  rdi carries payload_args* for
        // backward compatibility; the bootstrap saves edi/rsi and passes them through to
        // __managed__Main, but templates read PayloadEntryPoint.Args (a global) instead.
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);                 // mov rdi, [rip+payload_args]
        AddRel(RelocSymbol.PayloadArgs, b.Count - 4);
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call main
        int relMain = b.Count - 4;
        _startRelocs.Add(new Reloc(relMain, RelocSymbol.Main, RPlt32, -4));

        // *payloadout = main return
        b.AddRange([0x48, 0x8B, 0x0D, 0, 0, 0, 0]);                 // mov rcx, [rip+payload_args]
        AddRel(RelocSymbol.PayloadArgs, b.Count - 4);
        b.AddRange([0x48, 0x8B, 0x49, 0x28]);                       // mov rcx, [rcx+0x28]
        b.AddRange([0x89, 0x01]);                                   // mov [rcx], eax

        // sp:main:exit
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_main_exit]
            bcMainExitLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcMainExitCallDisp = b.Count - 4;
        }

        // __rtld_lib_fini(lib)
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_fini
        int libFiniCallDisp = b.Count - 4;

        // __rtld_lib_close(lib)
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_close
        int libCloseCallDisp = b.Count - 4;

        // __rtld_lib_destroy(lib)
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_destroy
        int libDestroyCallDisp = b.Count - 4;

        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lterminate
        int terminateJmp5 = b.Count - 4;

        // .Linit_lib_fail: init failed, close+destroy lib
        int initLibFail = b.Count;
        WriteRel32InBLocal(initLibFailJmp, initLibFail);
        b.AddRange([0x41, 0x89, 0xC7]);                             // mov r15d, eax
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_close
        int libCloseCallDisp2 = b.Count - 4;

        // .Lopen_fail: open failed, destroy lib
        int openFail = b.Count;
        WriteRel32InBLocal(openFailJmp, openFail);
        b.AddRange([0x41, 0x89, 0xC7]);                             // mov r15d, eax (preserve err if from open)
        b.AddRange([0x4C, 0x89, 0xEF]);                             // mov rdi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_rtld_lib_destroy
        int libDestroyCallDisp2 = b.Count - 4;

        // Store error in payloadout if nonzero
        b.AddRange([0x45, 0x85, 0xFF]);                             // test r15d, r15d
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lterminate
        int terminateJmp6 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);                 // mov rax, [rip+payload_args]
        AddRel(RelocSymbol.PayloadArgs, b.Count - 4);
        b.AddRange([0x48, 0x8B, 0x40, 0x28]);                       // mov rax, [rax+0x28]
        b.AddRange([0x44, 0x89, 0x38]);                             // mov [rax], r15d

        // ---- Phase 4: payload_terminate ----
        // .Lterminate:
        int terminateLabel = b.Count;
        WriteRel32InBLocal(terminateJmp1, terminateLabel);
        WriteRel32InBLocal(terminateJmp2, terminateLabel);
        WriteRel32InBLocal(terminateJmp3, terminateLabel);
        WriteRel32InBLocal(terminateJmp4, terminateLabel);
        WriteRel32InBLocal(terminateJmp5, terminateLabel);
        WriteRel32InBLocal(terminateJmp6, terminateLabel);

        // sp:payload:terminate
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);             // lea rdi, [rip+sp_payload_terminate]
            bcPayloadTerminateLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                         // call __prospero_klog
            bcPayloadTerminateCallDisp = b.Count - 4;
        }

        // ---- Restore host FSBASE before returning to the host ----
        // If the save sequence ran, __sp_saved_fsbase holds the original MSR value.
        // Restore it via sysarch(SET_FSBASE=129) so the host's fs-relative data (TLS,
        // pthread, canary) is intact when the return address takes the host back into its
        // event loop.  A zero sentinel means the save never ran (early error path or BSS
        // never written); skip the restore to avoid faulting through an uninitialized
        // ptr_syscall.
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);                 // mov rax, [rip+__sp_saved_fsbase]
        AddRel(RelocSymbol.SavedFsbase, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x74, 0x18]);                                   // jz +24  (skip restore body)
        b.AddRange([0x50]);                                         // push rax
        b.AddRange([0x48, 0x8D, 0x14, 0x24]);                       // lea rdx, [rsp]     (arg2 = &pushed_val)
        b.AddRange([0xBE, 0x81, 0x00, 0x00, 0x00]);                 // mov esi, 129       (arg1 = AMD64_SET_FSBASE)
        b.AddRange([0xBF, 0xA5, 0x00, 0x00, 0x00]);                 // mov edi, 165       (sysno = SYS_sysarch)
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_crt_syscall
        restoreFsbaseSyscallCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                       // add rsp, 8         (unpush)

        // Terminate the calling thread via SYS_thr_exit(NULL). This kills only the hijacked
        // thread; the host process continues with its remaining threads. The previous ret-based
        // path was broken: the loader return address (0x4000ab) contains byte 0x61 which is an
        // undefined opcode in x86-64 long mode, causing SIGILL. SYS_exit (syscall 1) would kill
        // the entire process and force a heavyweight restart. SYS_thr_exit (syscall 431 / 0x1AF)
        // is the correct primitive: it terminates only the calling thread, and when the last thread
        // exits the kernel internally calls exit1(). The NULL argument means no state notification.
        // The exit-code slot the loader hands us at args[0x28] carries the value the loader reads
        // to learn whether the payload ran; main's return value has already been written there
        // before this label is reached.
        b.AddRange([0x31, 0xF6]);                                   // xor esi, esi        (arg1 = NULL)
        b.AddRange([0xBF, 0xAF, 0x01, 0x00, 0x00]);                 // mov edi, 0x1AF      (sysno = SYS_thr_exit = 431)
        b.AddRange([0xE8, 0, 0, 0, 0]);                             // call __sp_crt_syscall
        thrExitSyscallCallDisp = b.Count - 4;
        b.AddRange([0x0F, 0x0B]);                                   // ud2                 (unreachable)

        int startEnd = b.Count;
        _startBytes = startEnd - startOff;

        // ============================================================================
        // __sp_bootcheck(rdi = payload_args*)
        //
        // Socket-independent boot signal. Writes a fixed 4-byte signature (0x53504350) through the
        // loader-provided int* at args[0x28], then attempts SYS_kill(1, 0) through the args[0]+0xa
        // gadget and OR-s the return code into the same slot. This gives the caller a way to prove
        // _start ran even when the klog fd routes nowhere - the loader writes its payloadout back to
        // its own stdout, so a non-zero value there is a socket-independent breadcrumb.
        //
        // Contract:
        //   - Preserves every callee-saved register.
        //   - If args[0] is zero, only the SPCP signature is written (no syscall attempted).
        //   - If args[0x28] is zero, nothing is written (loader gave us no output slot).
        //   - Never faults on the syscall path: the gadget is called through push/[rsp] so even a
        //     "ret" byte at args[0]+0xa is benign.
        // ============================================================================
        int bootcheckOff = b.Count;

        // push rbp ; mov rbp, rsp ; push r12 ; sub rsp, 8 ; mov r12, rdi
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x54, 0x48, 0x83, 0xEC, 0x08, 0x49, 0x89, 0xFC]);

        // mov rax, [r12] ; test rax, rax ; jz .Lbc_after_syscall
        b.AddRange([0x49, 0x8B, 0x04, 0x24]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int bcAfterSyscallJumpAt = b.Count - 1;

        // add rax, 0xa           ; args[0]+0xa is the loader's syscall gadget
        // push rax               ; save gadget on stack for the [rsp] indirect call
        // mov eax, 37            ; SYS_kill
        // mov edi, 1             ; pid = 1 (init)
        // mov esi, 0             ; sig = 0 (permission probe, no side effect)
        // call qword [rsp]
        // add rsp, 8             ; drop gadget from stack, preserve eax across the pop
        b.AddRange([0x48, 0x83, 0xC0, 0x0A]);
        b.AddRange([0x50]);
        b.AddRange([0xB8, 0x25, 0x00, 0x00, 0x00]);
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00]);
        b.AddRange([0xBE, 0x00, 0x00, 0x00, 0x00]);
        b.AddRange([0xFF, 0x14, 0x24]);
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);

        // .Lbc_after_syscall:
        int bcAfterSyscall = b.Count;
        b[bcAfterSyscallJumpAt] = (byte)(bcAfterSyscall - (bcAfterSyscallJumpAt + 1));

        // mov rcx, [r12+0x28]    ; payloadout pointer the loader gave us
        // test rcx, rcx
        // jz .Lbc_exit
        b.AddRange([0x49, 0x8B, 0x4C, 0x24, 0x28]);
        b.AddRange([0x48, 0x85, 0xC9]);
        b.AddRange([0x74, 0x00]);
        int bcExitJumpAt = b.Count - 1;

        // mov dword [rcx], 0x53504350   ; SPCP signature (little-endian bytes: 50 43 50 53)
        // or  dword [rcx], eax          ; OR in the SYS_kill return code (0 if no syscall was attempted;
        //                                 the mov to eax above always leaves 37 there if attempted)
        b.AddRange([0xC7, 0x01, 0x50, 0x43, 0x50, 0x53]);
        b.AddRange([0x09, 0x01]);

        // .Lbc_exit: add rsp, 8 ; pop r12 ; pop rbp ; ret
        int bcExit = b.Count;
        b[bcExitJumpAt] = (byte)(bcExit - (bcExitJumpAt + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x41, 0x5C, 0x5D, 0xC3]);
        _bootcheckBytes = b.Count - bootcheckOff;

        // ============================================================================
        // __prospero_get_payload_args
        // ============================================================================
        int getArgsOff = b.Count;
        _currentRelocs = _startRelocs;
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PayloadArgs, b.Count - 4);
        b.Add(0xC3);
        _getArgsBytes = b.Count - getArgsOff;

        // ============================================================================
        // __prospero_klog(rdi = msg_ptr)
        //
        // Reaches the kernel log through the raw syscall gadget: SYS_kexec (601 = 0x259)
        // with cmd = 7 writes a NUL-terminated string to /dev/klog, where a log consumer reads it
        // and forwards it over the network. No strlen needed - the kernel reads to the NUL.
        // Because the primitive only depends on ptr_syscall (already set by
        // __sp_crt_syscall_init), the breadcrumbs printed from __sp_dlsym_init itself reach
        // the log even when __sp_dlsym_ok is 2 - which is the whole point of the Layer-A
        // diagnostic surface.
        //
        // Guards:
        //   - If msg is NULL, return without touching the syscall gadget.
        //   - If ptr_syscall is 0 (args[0] was 0), return without a call.
        // ============================================================================
        int klogOff = b.Count;
        _currentRelocs = _klogRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; sub rsp, 8
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x08]);
        // test rdi, rdi ; jz .Lklog_out
        b.AddRange([0x48, 0x85, 0xFF]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int klogOutJumpFromNull = b.Count - 4;
        // mov rbx, rdi           ; msg
        b.AddRange([0x48, 0x89, 0xFB]);
        // mov rax, [rip+ptr_syscall] ; test rax, rax ; jz .Lklog_out
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int klogOutJumpFromPs = b.Count - 4;

        // SYS_kexec(cmd=7, msg, 0) through ptr_syscall:
        //   rax = 0x259 (SYS_kexec), rdi = 7 (cmd), rsi = msg, rdx = 0
        // mov edi, 7 ; mov rsi, rbx ; xor edx, edx ; mov eax, 0x259 ; call [rip+ptr_syscall]
        b.AddRange([0xBF, 0x07, 0x00, 0x00, 0x00]);
        b.AddRange([0x48, 0x89, 0xDE]);
        b.AddRange([0x31, 0xD2]);
        b.AddRange([0xB8, 0x59, 0x02, 0x00, 0x00]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);

        // .Lklog_out: add rsp, 8 ; pop rbx ; pop rbp ; ret
        int klogOut = b.Count;
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        WriteRel32InBLocal(klogOutJumpFromNull, klogOut);
        WriteRel32InBLocal(klogOutJumpFromPs, klogOut);
        _klogBytes = b.Count - klogOff;

        // ============================================================================
        // __sp_dlsym_init(rdi = payload_args*)
        //
        // Two jobs:
        //   1. Set ptr_syscall = args[0] + 0xa (the raw syscall gadget), matching SDK
        //      crt1.o __crt_syscall_init.
        //   2. Probe args[0] as a callable dlsym: args[0](0x1, "sceKernelDlsym", &out).
        //      If out comes back non-zero and different from args[0], the loader shipped a
        //      real resolver; cache args[0] into __sp_dlsym_fn and flag = 1. Otherwise flag
        //      = 2 (the loader's getpid trampoline; the resolver call would only ever return 0).
        //   3. Print exactly one breadcrumb (sp:kernel:init:ok / sp:kernel:init:degen)
        //      through __prospero_klog so the device log records which regime was selected.
        // ============================================================================
        int dlsymInitOff = b.Count;
        _currentRelocs = _dlsymInitRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; sub rsp, 24     ; [rbp-16] scratch, keep rsp mod 16 = 0
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x18]);
        // mov rbx, rdi
        b.AddRange([0x48, 0x89, 0xFB]);

        // ptr_syscall = args[0] + 0xa (guarded)
        // mov rax, [rbx] ; test rax, rax ; jz .Lno_syscall
        b.AddRange([0x48, 0x8B, 0x03]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int noSyscallJumpAt = b.Count - 1;
        // add rax, 0xa ; mov [rip+ptr_syscall], rax
        b.AddRange([0x48, 0x83, 0xC0, 0x0A]);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // .Lno_syscall:
        int noSyscall = b.Count;
        b[noSyscallJumpAt] = (byte)(noSyscall - (noSyscallJumpAt + 1));

        // If args[0] is 0 the probe would dereference NULL: skip straight to the degen path.
        // mov rax, [rbx] ; test rax, rax ; jz .Ldegen
        b.AddRange([0x48, 0x8B, 0x03]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int degenJumpFromNull = b.Count - 4;

        // Probe: [rbp-16] = 0 ; edi = 1 ; rsi = lea "sceKernelDlsym" ; rdx = lea [rbp-16] ; call [rbx]
        b.AddRange([0x48, 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00]);
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00]);
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int probeNameLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x55, 0xF0]);
        b.AddRange([0xFF, 0x13]);

        // mov rax, [rbp-16] ; test rax, rax ; jz .Ldegen
        b.AddRange([0x48, 0x8B, 0x45, 0xF0]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int degenJumpFromZero = b.Count - 4;

        // cmp rax, [rbx] ; je .Ldegen
        b.AddRange([0x48, 0x3B, 0x03]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int degenJumpFromEq = b.Count - 4;

        // .Lok: cache the fn and set the flag = 1
        // mov rax, [rbx] ; mov [rip+__sp_dlsym_fn], rax ; mov byte [rip+__sp_dlsym_ok], 1
        b.AddRange([0x48, 0x8B, 0x03]);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlsymFn, b.Count - 4);
        b.AddRange([0xC6, 0x05, 0, 0, 0, 0, 0x01]);
        AddRel(RelocSymbol.DlsymOk, b.Count - 5, addend: -5);
        // lea rdi, [rip+.LspKernelInitOk] ; call __prospero_klog
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
        int initOkLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int initOkKlogCallDisp = b.Count - 4;
        // jmp .Ldone
        b.AddRange([0xE9, 0, 0, 0, 0]);
        int doneJumpFromOk = b.Count - 4;

        // .Ldegen: flag = 2 ; print sp:kernel:init:degen through klog
        int degenAt = b.Count;
        WriteRel32InBLocal(degenJumpFromNull, degenAt);
        WriteRel32InBLocal(degenJumpFromZero, degenAt);
        WriteRel32InBLocal(degenJumpFromEq, degenAt);
        b.AddRange([0xC6, 0x05, 0, 0, 0, 0, 0x02]);
        AddRel(RelocSymbol.DlsymOk, b.Count - 5, addend: -5);
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
        int initDegenLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int initDegenKlogCallDisp = b.Count - 4;

        // .Ldone: add rsp, 24 ; pop rbx ; pop rbp ; ret
        int doneAt = b.Count;
        WriteRel32InBLocal(doneJumpFromOk, doneAt);
        b.AddRange([0x48, 0x83, 0xC4, 0x18, 0x5B, 0x5D, 0xC3]);
        _dlsymInitBytes = b.Count - dlsymInitOff;

        // ============================================================================
        // __prospero_fixup_got(rdi = payload_args*)
        //
        // Walks _DYNAMIC to find DT_RELA / DT_RELASZ / DT_RELACOUNT / DT_SYMTAB / DT_STRTAB.
        // Skips the RELATIVE prefix the loader already applied. For every remaining GLOB_DAT:
        //   sym_idx  = r_info >> 32
        //   name_off = *(uint32_t*)(symtab_va + sym_idx * 24)      ; st_name
        //   name     = strtab_va + name_off                        ; plain C name in .dynstr
        //   slot     = *(uint64_t*)(rbx + 0) + load_base
        // Cascade the handles 0x1 / 0x2 / 0x2001 through kernel_dynlib_dlsym.
        // Per-symbol klog: before each cascade, the plain C name is logged; after cascade,
        // "sp:resolve:ok\n" on success or "sp:resolve:0\n" on miss. Rh-prefixed symbols
        // get the identity stub silently. This gives the device log a complete trace of
        // which symbols resolved and which did not.
        //
        // Register plan (callee-saved across every dlsym call):
        //   rbx  - current rela entry ptr
        //   r12  - rela_end
        //   r13  - symtab_va
        //   r14  - strtab_va
        //   r15  - payload_args (unchanged for the whole shim)
        //
        // Local frame ([rbp - N]):
        //   [rbp-48] load_base
        //   [rbp-56] current got slot addr
        //   [rbp-64] current name pointer
        // ============================================================================
        int fixupOff = b.Count;
        _currentRelocs = _fixupRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; push r14 ; push r15 ; sub rsp, 24
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x18]);
        b.AddRange([0x49, 0x89, 0xFF]);

        int fxStartLeaAt = -1, fxKlogStartCallDisp = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            // lea rdi, [rip+.LspFixupStart] ; call __prospero_klog
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
            fxStartLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);
            fxKlogStartCallDisp = b.Count - 4;
        }

        // load_base = lea [rip+__image_start] ; stash at [rbp-48]
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.ImageStart, b.Count - 4);
        b.AddRange([0x48, 0x89, 0x45, 0xD0]);

        // rbx = lea [rip+_DYNAMIC]
        b.AddRange([0x48, 0x8D, 0x1D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.Dynamic, b.Count - 4);

        b.AddRange([0x4D, 0x31, 0xE4]);
        b.AddRange([0x4D, 0x31, 0xC0]);
        b.AddRange([0x4D, 0x31, 0xC9]);
        b.AddRange([0x4D, 0x31, 0xED]);
        b.AddRange([0x4D, 0x31, 0xF6]);

        int dynLoop = b.Count;
        b.AddRange([0x48, 0x8B, 0x03]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int dynDoneJumpAt = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x4B, 0x08]);
        b.AddRange([0x48, 0x83, 0xF8, 0x07]);
        b.AddRange([0x4C, 0x0F, 0x44, 0xE1]);
        b.AddRange([0x48, 0x83, 0xF8, 0x08]);
        b.AddRange([0x4C, 0x0F, 0x44, 0xC1]);
        b.AddRange([0x48, 0x83, 0xF8, 0x06]);
        b.AddRange([0x4C, 0x0F, 0x44, 0xE9]);
        b.AddRange([0x48, 0x83, 0xF8, 0x05]);
        b.AddRange([0x4C, 0x0F, 0x44, 0xF1]);
        b.AddRange([0x48, 0xBA, 0xF9, 0xFF, 0xFF, 0x6F, 0x00, 0x00, 0x00, 0x00]);
        b.AddRange([0x48, 0x39, 0xD0]);
        b.AddRange([0x4C, 0x0F, 0x44, 0xC9]);
        b.AddRange([0x48, 0x83, 0xC3, 0x10]);
        b.AddRange([0xE9, 0, 0, 0, 0]);
        int dynLoopBackAt = b.Count - 4;
        WriteRel32InBLocal(dynLoopBackAt, dynLoop);
        int dynDone = b.Count;
        WriteRel32InBLocal(dynDoneJumpAt, dynDone);

        b.AddRange([0x48, 0x8B, 0x45, 0xD0]);
        b.AddRange([0x49, 0x01, 0xC4]);
        b.AddRange([0x49, 0x01, 0xC5]);
        b.AddRange([0x49, 0x01, 0xC6]);
        b.AddRange([0x4D, 0x01, 0xE0]);
        b.AddRange([0x4D, 0x6B, 0xC9, 0x18]);
        b.AddRange([0x4D, 0x01, 0xCC]);
        b.AddRange([0x4C, 0x89, 0xE3]);
        b.AddRange([0x4D, 0x89, 0xC4]);

        int globLoop = b.Count;
        b.AddRange([0x4C, 0x39, 0xE3]);
        b.AddRange([0x0F, 0x83, 0, 0, 0, 0]);
        int globDoneJumpAt = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x43, 0x08]);
        b.AddRange([0x83, 0xF8, 0x06]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int globNextJumpAt = b.Count - 4;

        b.AddRange([0x48, 0x8B, 0x13]);
        b.AddRange([0x48, 0x03, 0x55, 0xD0]);
        b.AddRange([0x48, 0x89, 0x55, 0xC8]);

        b.AddRange([0x48, 0x8B, 0x43, 0x08]);
        b.AddRange([0x48, 0xC1, 0xE8, 0x20]);
        b.AddRange([0x48, 0x6B, 0xC0, 0x18]);
        b.AddRange([0x4C, 0x01, 0xE8]);
        b.AddRange([0x8B, 0x00]);
        b.AddRange([0x4C, 0x89, 0xF6]);
        b.AddRange([0x48, 0x01, 0xC6]);
        b.AddRange([0x48, 0x89, 0x75, 0xC0]);

        int fxKlogNameCallDisp = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            // Per-symbol klog: log the plain C name before the resolve cascade so the device
            // log shows exactly which symbol is being looked up.
            b.AddRange([0x48, 0x89, 0xF7]);                      // mov rdi, rsi (name still in rsi)
            b.AddRange([0xE8, 0, 0, 0, 0]);                      // call __prospero_klog
            fxKlogNameCallDisp = b.Count - 4;
        }

        // Zero the slot so a canonical zero is the "unresolved" marker.
        b.AddRange([0x48, 0x8B, 0x55, 0xC8]);
        b.AddRange([0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00]);

        // Three-handle cascade through __sp_kernel_dynlib_dlsym(pid=-1, handle, name).
        // The kernel-based resolver walks kernel memory to resolve symbols by their plain C
        // name, so it works independently of what args[0] is (no __sp_dlsym_ok gate needed).
        //   mov edi, -1           ; pid = current process
        //   mov esi, handle
        //   mov rdx, [rbp-64]     ; name pointer
        //   call __sp_kernel_dynlib_dlsym
        //   test rax, rax
        //   jnz .Lresolved
        var resolvedJumpDisps = new List<int>();
        int EmitFixupAttempt(int handle)
        {
            b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);     // mov edi, -1 (pid)
            b.AddRange([0xBE, (byte)(handle & 0xFF), (byte)((handle >> 8) & 0xFF),
                              (byte)((handle >> 16) & 0xFF), (byte)((handle >> 24) & 0xFF)]);
            b.AddRange([0x48, 0x8B, 0x55, 0xC0]);           // mov rdx, [rbp-64] (name)
            b.AddRange([0xE8, 0, 0, 0, 0]);                 // call __sp_kernel_dynlib_dlsym
            int callDisp = b.Count - 4;
            b.AddRange([0x48, 0x85, 0xC0]);                 // test rax, rax
            b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);           // jnz .Lresolved
            resolvedJumpDisps.Add(b.Count - 4);
            return callDisp;
        }
        int fxDlsymCall1 = EmitFixupAttempt(0x0001);
        int fxDlsymCall2 = EmitFixupAttempt(0x0002);
        int fxDlsymCall3 = EmitFixupAttempt(0x2001);

        // .Lfx_miss: check if the unresolved name starts with "Rh" (NativeAOT internal
        // helpers like RhpReversePInvoke, RhAllocateNewObject, RhNewString that no
        // dynamic library exports). The prefix is two characters ("Rh"), not three
        // ("Rhp"), because NativeAOT emits both Rhp-prefixed helpers (RhpReversePInvoke,
        // RhpNewFast, ...) and Rh-prefixed helpers without the trailing 'p'
        // (RhAllocateNewObject, RhNewString, RhHandleFree, RhYield, ...). A three-char
        // filter missed the 28 Rh-but-not-Rhp entries, leaving their GOT slots at zero.
        b.AddRange([0x48, 0x8B, 0x7D, 0xC0]);               // mov rdi, [rbp-64] (name)
        b.AddRange([0x80, 0x3F, 0x52]);                      // cmp byte [rdi], 'R'
        b.AddRange([0x75, 0x00]);                            // jne .Lreally_miss
        int fxReallyMiss1At = b.Count - 1;
        b.AddRange([0x80, 0x7F, 0x01, 0x68]);               // cmp byte [rdi+1], 'h'
        b.AddRange([0x75, 0x00]);                            // jne .Lreally_miss
        int fxReallyMiss2At = b.Count - 1;
        // Matched "Rh" prefix: install the identity-stub address into the GOT slot
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);         // lea rax, [rip+__sp_nop_stub]
        int fxNopStubLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x55, 0xC8]);               // mov rdx, [rbp-56] (slot addr)
        b.AddRange([0x48, 0x89, 0x02]);                      // mov [rdx], rax
        b.AddRange([0xE9, 0, 0, 0, 0]);                     // jmp .Lglob_next
        int fxRhpSkipJump = b.Count - 4;
        // .Lreally_miss: klog "sp:resolve:0" (the name was already logged before the cascade)
        int fxReallyMiss = b.Count;
        b[fxReallyMiss1At] = (byte)(fxReallyMiss - (fxReallyMiss1At + 1));
        b[fxReallyMiss2At] = (byte)(fxReallyMiss - (fxReallyMiss2At + 1));
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);         // lea rdi, [rip+sp_resolve_miss]
        int fxMissLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int fxKlogMissCallDisp = b.Count - 4;
        b.AddRange([0xE9, 0, 0, 0, 0]);                     // jmp .Lglob_next
        int fxMissSkipJump = b.Count - 4;

        // .Lresolved: store the address into the GOT slot
        int fxResolved = b.Count;
        foreach (int at in resolvedJumpDisps) WriteRel32InBLocal(at, fxResolved);
        b.AddRange([0x48, 0x8B, 0x55, 0xC8]);               // mov rdx, [rbp-56] (slot addr)
        b.AddRange([0x48, 0x89, 0x02]);                      // mov [rdx], rax
        int fxResolvedOkLeaAt = -1, fxKlogResolvedCallDisp = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            // Log "sp:resolve:ok" after successful resolution
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);         // lea rdi, [rip+sp_resolve_ok]
            fxResolvedOkLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                      // call __prospero_klog
            fxKlogResolvedCallDisp = b.Count - 4;
        }

        int globNext = b.Count;
        WriteRel32InBLocal(globNextJumpAt, globNext);
        WriteRel32InBLocal(fxRhpSkipJump, globNext);
        WriteRel32InBLocal(fxMissSkipJump, globNext);
        b.AddRange([0x48, 0x83, 0xC3, 0x18]);
        b.AddRange([0xE9, 0, 0, 0, 0]);
        int loopBackJumpAt = b.Count - 4;
        WriteRel32InBLocal(loopBackJumpAt, globLoop);
        int globDone = b.Count;
        WriteRel32InBLocal(globDoneJumpAt, globDone);

        int fxDoneLeaAt = -1, fxKlogDoneCallDisp = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            // lea rdi, [rip+.LspFixupDone] ; call __prospero_klog
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
            fxDoneLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);
            fxKlogDoneCallDisp = b.Count - 4;
        }

        // epilogue
        b.AddRange([0x48, 0x83, 0xC4, 0x18, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _fixupBytes = b.Count - fixupOff;

        // ============================================================================
        // __sp_crt_syscall — register-shuffle syscall dispatch shim
        //
        // Register-shuffle syscall dispatch shim. Linux-to-BSD calling
        // convention adapter: sysno arrives in rdi (Linux convention), gets moved to rax
        // (BSD convention), remaining arguments are shifted accordingly, then dispatch
        // through ptr_syscall (the raw `syscall; ret` gadget derived by __sp_crt_syscall_init).
        //
        // ============================================================================
        int crtSyscallOff = b.Count;
        _currentRelocs = _crtSyscallRelocs;

        // mov rax, rdi          ; sysno -> rax
        b.AddRange([0x48, 0x89, 0xF8]);
        // mov rdi, rsi          ; arg1
        b.AddRange([0x48, 0x89, 0xF7]);
        // mov rsi, rdx          ; arg2
        b.AddRange([0x48, 0x89, 0xD6]);
        // mov rdx, rcx          ; arg3
        b.AddRange([0x48, 0x89, 0xCA]);
        // mov r10, r8           ; arg4 (BSD uses r10, not rcx)
        b.AddRange([0x4D, 0x89, 0xC2]);
        // mov r8, r9            ; arg5
        b.AddRange([0x4D, 0x89, 0xC8]);
        // mov r9, [rsp+8]       ; arg6 (from caller stack, past return addr)
        b.AddRange([0x4C, 0x8B, 0x4C, 0x24, 0x08]);
        // call qword [rip+ptr_syscall]
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // ret
        b.Add(0xC3);
        // trailing ret (compiler parity with SDK object)
        b.Add(0xC3);
        _crtSyscallBytes = b.Count - crtSyscallOff;

        // ============================================================================
        // __sp_kekcall -- kekcall dispatch shim
        //
        // Packs the kekcall number (RDI) into RAX[63:32] with SYS_getppid (0x27)
        // in RAX[31:0], shifts the remaining args down one slot, and dispatches
        // through ptr_syscall. The kernel extension handler intercepts getppid and
        // reads RAX>>32 as the kekcall number.
        //
        // ============================================================================
        int crtKekcallOff = b.Count;
        _currentRelocs = _crtKekcallRelocs;

        // mov eax, edi          ; nr (zero-extend to guarantee upper 32 bits clear)
        b.AddRange([0x89, 0xF8]);
        // mov rdi, rsi          ; a1
        b.AddRange([0x48, 0x89, 0xF7]);
        // mov rsi, rdx          ; a2
        b.AddRange([0x48, 0x89, 0xD6]);
        // mov rdx, rcx          ; a3
        b.AddRange([0x48, 0x89, 0xCA]);
        // mov r10, r8           ; a4 (FreeBSD arg4)
        b.AddRange([0x4D, 0x89, 0xC2]);
        // mov r8, r9            ; a5
        b.AddRange([0x4D, 0x89, 0xC8]);
        // mov r9, [rsp+8]       ; a6 (7th C arg)
        b.AddRange([0x4C, 0x8B, 0x4C, 0x24, 0x08]);
        // shl rax, 32           ; nr << 32
        b.AddRange([0x48, 0xC1, 0xE0, 0x20]);
        // or rax, 0x27          ; (nr << 32) | SYS_getppid  (MUST be REX.W)
        b.AddRange([0x48, 0x83, 0xC8, 0x27]);
        // call qword [rip+ptr_syscall]
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // ret
        b.Add(0xC3);
        // trailing ret (SDK parity)
        b.Add(0xC3);
        _crtKekcallBytes = b.Count - crtKekcallOff;

        // ============================================================================
        // __sp_mdbg_call -- direct mdbg syscall wrapper
        //
        // Wraps SYS_mdbg_call (573): loads the syscall number into EAX and dispatches
        // through ptr_syscall. The three C arguments (cmd, arg2, arg3) in RDI/RSI/RDX
        // are already in the correct registers for the FreeBSD syscall convention.
        //
        // ============================================================================
        int crtMdbgCallOff = b.Count;
        _currentRelocs = _crtMdbgCallRelocs;

        // mov eax, 573          ; SYS_mdbg_call = 0x23D
        b.AddRange([0xB8, 0x3D, 0x02, 0x00, 0x00]);
        // mov r10, rcx          ; FreeBSD arg4 passthrough
        b.AddRange([0x49, 0x89, 0xCA]);
        // call qword [rip+ptr_syscall]
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // ret
        b.Add(0xC3);
        // trailing ret (SDK parity)
        b.Add(0xC3);
        _crtMdbgCallBytes = b.Count - crtMdbgCallOff;

        // ============================================================================
        // __sp_crt_syscall_init(rdi = payload_args*)
        //
        // Syscall init: derives ptr_syscall
        // from args[0]:
        //  1. Try resolve "sceKernelDlsym" from handle 0x1, fallback 0x2001
        //  2. If resolved == args[0]: the loader probe path - resolve "getpid" and set
        //     ptr_syscall = getpid + 0xa
        //  3. Else: ptr_syscall = args[0] (the dlsym function itself)
        //  4. ptr_syscall += 0xa in both paths
        //  5. Return -1 if ptr_syscall is null, 0 on success
        //
        // ============================================================================
        int crtSyscallInitOff = b.Count;
        _currentRelocs = _crtSyscallInitRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        // mov rbx, rdi                    ; rbx = args
        b.AddRange([0x48, 0x89, 0xFB]);
        // movq $0x0, -0x10(%rbp)          ; sceKernelDlsym = 0
        b.AddRange([0x48, 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00]);
        // lea rsi, [rip+"sceKernelDlsym"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sciProbeNameLeaAt = b.Count - 4;
        // lea rdx, -0x10(%rbp)            ; &sceKernelDlsym
        b.AddRange([0x48, 0x8D, 0x55, 0xF0]);
        // mov edi, 0x1                    ; handle = 0x1
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00]);
        // call *(%rbx)                    ; args->sys_dynlib_dlsym(0x1, "sceKernelDlsym", &local)
        b.AddRange([0xFF, 0x13]);
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // je .Lsci_resolved               ; succeeded, skip fallback
        b.AddRange([0x74, 0x00]);
        int sciResolvedJumpAt = b.Count - 1;
        // Fallback: retry with handle 0x2001
        // lea rsi, [rip+"sceKernelDlsym"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sciFallbackNameLeaAt = b.Count - 4;
        // lea rdx, -0x10(%rbp)
        b.AddRange([0x48, 0x8D, 0x55, 0xF0]);
        // mov edi, 0x2001
        b.AddRange([0xBF, 0x01, 0x20, 0x00, 0x00]);
        // call *(%rbx)
        b.AddRange([0xFF, 0x13]);
        // .Lsci_resolved:
        int sciResolved = b.Count;
        b[sciResolvedJumpAt] = (byte)(sciResolved - (sciResolvedJumpAt + 1));
        // mov rax, (%rbx)                 ; rax = args->sys_dynlib_dlsym
        b.AddRange([0x48, 0x8B, 0x03]);
        // cmp rax, -0x10(%rbp)            ; sceKernelDlsym == args->sys_dynlib_dlsym?
        b.AddRange([0x48, 0x39, 0x45, 0xF0]);
        // je .Lsci_probe                  ; yes -> probe path
        b.AddRange([0x74, 0x00]);
        int sciProbeJumpAt = b.Count - 1;
        // Non-probe path: ptr_syscall = args->sys_dynlib_dlsym
        // mov [rip+ptr_syscall], rax
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // jmp .Lsci_check
        b.AddRange([0xEB, 0x00]);
        int sciCheckJumpAt = b.Count - 1;
        // .Lsci_probe: resolve "getpid" and store directly into ptr_syscall
        int sciProbe = b.Count;
        b[sciProbeJumpAt] = (byte)(sciProbe - (sciProbeJumpAt + 1));
        // lea rsi, [rip+"getpid"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sciGetpidLeaAt = b.Count - 4;
        // lea rdx, [rip+ptr_syscall]
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // mov edi, 0x1
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00]);
        // call *%rax                      ; sceKernelDlsym(0x1, "getpid", &ptr_syscall)
        b.AddRange([0xFF, 0xD0]);
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // je .Lsci_check                  ; succeeded
        b.AddRange([0x74, 0x00]);
        int sciCheckJump2At = b.Count - 1;
        // Fallback: retry getpid with handle 0x2001
        // lea rsi, [rip+"getpid"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sciGetpidFallbackLeaAt = b.Count - 4;
        // lea rdx, [rip+ptr_syscall]
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // mov edi, 0x2001
        b.AddRange([0xBF, 0x01, 0x20, 0x00, 0x00]);
        // call *(%rbx)                    ; args[0](0x2001, "getpid", &ptr_syscall)
        b.AddRange([0xFF, 0x13]);
        // .Lsci_check: validate ptr_syscall is non-null, add 0xa
        int sciCheck = b.Count;
        b[sciCheckJumpAt] = (byte)(sciCheck - (sciCheckJumpAt + 1));
        b[sciCheckJump2At] = (byte)(sciCheck - (sciCheckJump2At + 1));
        // mov rax, [rip+ptr_syscall]
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // je .Lsci_fail
        b.AddRange([0x74, 0x00]);
        int sciFailJumpAt = b.Count - 1;
        // add rax, 0xa
        b.AddRange([0x48, 0x83, 0xC0, 0x0A]);
        // mov [rip+ptr_syscall], rax
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // xor eax, eax                    ; return 0
        b.AddRange([0x31, 0xC0]);
        // jmp .Lsci_ret
        b.AddRange([0xEB, 0x05]);
        // .Lsci_fail: return -1
        int sciFail = b.Count;
        b[sciFailJumpAt] = (byte)(sciFail - (sciFailJumpAt + 1));
        // mov eax, -1
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
        // .Lsci_ret: add rsp, 8 ; pop rbx ; pop rbp ; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        _crtSyscallInitBytes = b.Count - crtSyscallInitOff;

        // ============================================================================
        // __sp_kernel_write(rdi = kaddr, rsi = data, rdx = len)
        //
        // kernel_write: overwrites the victim socket's pktinfo
        // buffer with `kaddr` by setting MASTER_SOCK's IPV6_PKTINFO to point there, then
        // writes `data` of `len` bytes to that kernel address by setting VICTIM_SOCK's
        // IPV6_PKTINFO. Guards with a top-48-bit kernel-address check.
        //
        // SYS_setsockopt = 105 (0x69), IPPROTO_IPV6 = 41 (0x29), IPV6_PKTINFO = 46 (0x2e)
        // IN6_PKTINFOSZ = 20 (sizeof(kernel_pipebuf_t) = 5 * sizeof(int))
        // ============================================================================
        int kernelWriteOff = b.Count;
        _currentRelocs = _kernelWriteRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; sub rsp, 0x28
        // Local frame: [rbp-48] = 20-byte pipebuf + 4 pad; [rbp-56] = data; [rbp-64] = len
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x28]);
        // Save data and len in callee-saved registers since setsockopt calls clobber args.
        // mov r12, rsi          ; data
        b.AddRange([0x49, 0x89, 0xF4]);
        // mov r13, rdx          ; len
        b.AddRange([0x49, 0x89, 0xD5]);
        // mov rbx, rdi          ; kaddr
        b.AddRange([0x48, 0x89, 0xFB]);

        // Guard: if !(kaddr & 0xffff000000000000), return -1 (EFAULT)
        // mov rax, rdi
        b.AddRange([0x48, 0x89, 0xF8]);
        // shr rax, 48
        b.AddRange([0x48, 0xC1, 0xE8, 0x30]);
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // jnz .Lkw_ok
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int kwOkJumpAt = b.Count - 4;
        // .Lkw_fail: mov eax, -1 ; jmp .Lkw_ret
        int kwFailAt = b.Count;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0xE9, 0, 0, 0, 0]);
        int kwRetJumpAt = b.Count - 4;

        // .Lkw_ok: build pipebuf on stack with vbuf.kaddr = kaddr
        int kwOk = b.Count;
        WriteRel32InBLocal(kwOkJumpAt, kwOk);
        // Zero 20 bytes at [rbp-48..rbp-28] then write kaddr at [rbp-48]
        // movq $0, -0x30(%rbp)   ; bytes 0..7
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x00]);
        // movq $0, -0x28(%rbp)   ; bytes 8..15
        b.AddRange([0x48, 0xC7, 0x45, 0xD8, 0x00, 0x00, 0x00, 0x00]);
        // mov dword [rbp-0x20], 0 ; bytes 16..19
        b.AddRange([0xC7, 0x45, 0xE0, 0x00, 0x00, 0x00, 0x00]);
        // mov [rbp-0x30], rbx     ; vbuf.kaddr = kaddr (first 8 bytes)
        b.AddRange([0x48, 0x89, 0x5D, 0xD0]);

        // __sp_crt_syscall(SYS_setsockopt=105, MASTER_SOCK, IPPROTO_IPV6=41, IPV6_PKTINFO=46, &buf, 20)
        // mov edi, 105            ; SYS_setsockopt
        b.AddRange([0xBF, 0x69, 0x00, 0x00, 0x00]);
        // mov esi, [rip+rw_pair_0] ; MASTER_SOCK
        b.AddRange([0x8B, 0x35, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPair0, b.Count - 4);
        // mov edx, 41             ; IPPROTO_IPV6
        b.AddRange([0xBA, 0x29, 0x00, 0x00, 0x00]);
        // mov ecx, 46             ; IPV6_PKTINFO
        b.AddRange([0xB9, 0x2E, 0x00, 0x00, 0x00]);
        // lea r8, [rbp-0x30]      ; &buf
        b.AddRange([0x4C, 0x8D, 0x45, 0xD0]);
        // mov r9d, 20             ; sizeof(buf)
        b.AddRange([0x41, 0xB9, 0x14, 0x00, 0x00, 0x00]);
        // xor eax, eax            ; variadic sentinel
        b.AddRange([0x31, 0xC0]);
        // call __sp_crt_syscall
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int kwCall1Disp = b.Count - 4;
        // test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // jne .Lkw_fail2
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int kwFail2JumpAt = b.Count - 4;

        // Second setsockopt: write user data to the kernel address via VICTIM_SOCK
        // mov edi, 105
        b.AddRange([0xBF, 0x69, 0x00, 0x00, 0x00]);
        // mov esi, [rip+rw_pair_1] ; VICTIM_SOCK
        b.AddRange([0x8B, 0x35, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPair1, b.Count - 4);
        // mov edx, 41
        b.AddRange([0xBA, 0x29, 0x00, 0x00, 0x00]);
        // mov ecx, 46
        b.AddRange([0xB9, 0x2E, 0x00, 0x00, 0x00]);
        // mov r8, r12             ; data
        b.AddRange([0x4D, 0x89, 0xE0]);
        // mov r9, r13             ; len
        b.AddRange([0x4D, 0x89, 0xE9]);
        // xor eax, eax
        b.AddRange([0x31, 0xC0]);
        // call __sp_crt_syscall
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int kwCall2Disp = b.Count - 4;
        // test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // jne .Lkw_fail2
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int kwFail3JumpAt = b.Count - 4;
        // xor eax, eax            ; return 0
        b.AddRange([0x31, 0xC0]);
        b.AddRange([0xEB, 0x00]);
        int kwRetOkJumpAt = b.Count - 1;

        // .Lkw_fail2:
        int kwFail2 = b.Count;
        WriteRel32InBLocal(kwFail2JumpAt, kwFail2);
        WriteRel32InBLocal(kwFail3JumpAt, kwFail2);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1

        // .Lkw_ret:
        int kwRet = b.Count;
        WriteRel32InBLocal(kwRetJumpAt, kwRet);
        b[kwRetOkJumpAt] = (byte)(kwRet - (kwRetOkJumpAt + 1));
        // add rsp, 0x28 ; pop r13 ; pop r12 ; pop rbx ; pop rbp ; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x28, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelWriteBytes = b.Count - kernelWriteOff;

        // ============================================================================
        // __sp_kernel_copyin(rdi = uaddr, rsi = kaddr, rdx = len)
        //
        // kernel_copyin: overwrites the pipe's internal buffer
        // pointer to point at kaddr, then SYS_write on rwpipe[1] transfers user data
        // into kernel memory.
        // ============================================================================
        int kernelCopyinOff = b.Count;
        _currentRelocs = _kernelCopyinRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; sub rsp, 0x28
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x28]);
        // Save args: rbx = uaddr, r12 = kaddr, r13 = len
        b.AddRange([0x48, 0x89, 0xFB]);  // mov rbx, rdi   (uaddr)
        b.AddRange([0x49, 0x89, 0xF4]);  // mov r12, rsi   (kaddr)
        b.AddRange([0x49, 0x89, 0xD5]);  // mov r13, rdx   (len)

        // Guard: if !kaddr || !uaddr || !len, return -1
        b.AddRange([0x4D, 0x85, 0xE4]);  // test r12, r12
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int ciFailJump1At = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xDB]);  // test rbx, rbx
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int ciFailJump2At = b.Count - 4;
        b.AddRange([0x4D, 0x85, 0xED]);  // test r13, r13
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int ciFailJump3At = b.Count - 4;

        // First kernel_write: set pipe flags.reserved = 0x40000000
        // Build 20-byte buf on stack:
        //   flags.cnt = 0, flags.in = 0, flags.out = 0, flags.reserved = 0x40000000
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x00]); // [rbp-48] = 0
        b.AddRange([0x48, 0xC7, 0x45, 0xD8, 0x00, 0x00, 0x00, 0x00]); // [rbp-40] = 0
        b.AddRange([0xC7, 0x45, 0xE0, 0x00, 0x00, 0x00, 0x00]);       // [rbp-32] = 0
        // Set flags.reserved (offset 12 = 0xC from buf start) to 0x40000000
        // Union layout: flags.reserved is at +12 as a uint64.
        // buf is at [rbp-0x30]. reserved starts at [rbp-0x30+0xC] = [rbp-0x24].
        // flags: cnt(4)+in(4)+out(4)+reserved(8) = 20. reserved at offset 12.
        // Set reserved = 0x40000000 as a 64-bit value at offset 12.
        b.AddRange([0x48, 0xC7, 0x45, 0xDC, 0x00, 0x00, 0x00, 0x40]); // [rbp-0x24] = 0x40000000 (little-endian: 00 00 00 40 00 00 00 00)
        // movq $imm32, mem sign-extends. 0x40000000 fits in 32 bits unsigned
        // and is positive as signed. 0x48 C7 45 DC 00 00 00 40 writes
        // qword [rbp-0x24] = 0x0000000040000000. Correct.

        // kernel_write(pipe_addr, &buf, sizeof(buf))
        // mov rdi, [rip+pipe_addr]
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PipeAddr, b.Count - 4);
        // lea rsi, [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        // mov edx, 20
        b.AddRange([0xBA, 0x14, 0x00, 0x00, 0x00]);
        // call __sp_kernel_write
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int ciKw1Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // jne .Lci_fail
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int ciFailJump4At = b.Count - 4;

        // Second kernel_write: set pipe pbuf.size=0x40000000, pbuf.kaddr=kaddr, pbuf.reserved=0
        // pbuf: size(4) + kaddr(8) + reserved(8) = 20 bytes at [rbp-0x30]
        // mov dword [rbp-0x30], 0x40000000
        b.AddRange([0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x40]);
        // mov [rbp-0x2C], r12     ; pbuf.kaddr = kaddr (8 bytes at offset 4)
        b.AddRange([0x4C, 0x89, 0x65, 0xD4]);
        // movq $0, [rbp-0x24]     ; pbuf.reserved = 0
        b.AddRange([0x48, 0xC7, 0x45, 0xDC, 0x00, 0x00, 0x00, 0x00]);

        // kernel_write(pipe_addr + 12, &buf, sizeof(buf))
        // mov rdi, [rip+pipe_addr]
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PipeAddr, b.Count - 4);
        // add rdi, 12             ; pipe_addr + 12 (offset past cnt/in/out to the buffer metadata)
        b.AddRange([0x48, 0x83, 0xC7, 0x0C]);
        // lea rsi, [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        // mov edx, 20
        b.AddRange([0xBA, 0x14, 0x00, 0x00, 0x00]);
        // call __sp_kernel_write
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int ciKw2Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // jne .Lci_fail
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int ciFailJump5At = b.Count - 4;

        // SYS_write(rwpipe[1], uaddr, len) - the pipe write transfers data into kernel memory
        // mov edi, 4              ; SYS_write
        b.AddRange([0xBF, 0x04, 0x00, 0x00, 0x00]);
        // mov esi, [rip+rw_pipe_1]
        b.AddRange([0x8B, 0x35, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPipe1, b.Count - 4);
        // mov rdx, rbx            ; uaddr
        b.AddRange([0x48, 0x89, 0xDA]);
        // mov rcx, r13            ; len
        b.AddRange([0x4C, 0x89, 0xE9]);
        // xor eax, eax
        b.AddRange([0x31, 0xC0]);
        // call __sp_crt_syscall
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int ciSyscallDisp = b.Count - 4;
        // test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // js .Lci_fail             ; negative return = error
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int ciFailJump6At = b.Count - 4;
        // xor eax, eax            ; return 0
        b.AddRange([0x31, 0xC0]);
        b.AddRange([0xEB, 0x05]);
        // .Lci_fail:
        int ciFail = b.Count;
        WriteRel32InBLocal(ciFailJump1At, ciFail);
        WriteRel32InBLocal(ciFailJump2At, ciFail);
        WriteRel32InBLocal(ciFailJump3At, ciFail);
        WriteRel32InBLocal(ciFailJump4At, ciFail);
        WriteRel32InBLocal(ciFailJump5At, ciFail);
        WriteRel32InBLocal(ciFailJump6At, ciFail);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1
        // .Lci_ret: epilogue
        b.AddRange([0x48, 0x83, 0xC4, 0x28, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelCopyinBytes = b.Count - kernelCopyinOff;

        // ============================================================================
        // __sp_kernel_copyout(rdi = kaddr, rsi = uaddr, rdx = len)
        //
        // kernel_copyout: sets the pipe's cnt and in to
        // 0x40000000 so the kernel thinks the buffer is full, overwrites the buffer
        // pointer to kaddr, then SYS_read on rwpipe[0] reads kernel memory into uaddr.
        // ============================================================================
        int kernelCopyoutOff = b.Count;
        _currentRelocs = _kernelCopyoutRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; sub rsp, 0x28
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x28]);
        // Save: rbx = kaddr, r12 = uaddr, r13 = len
        b.AddRange([0x48, 0x89, 0xFB]);  // mov rbx, rdi   (kaddr)
        b.AddRange([0x49, 0x89, 0xF4]);  // mov r12, rsi   (uaddr)
        b.AddRange([0x49, 0x89, 0xD5]);  // mov r13, rdx   (len)

        // Guard: if !kaddr || !uaddr || !len, return -1
        b.AddRange([0x48, 0x85, 0xDB]);  // test rbx, rbx
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int coFailJump1At = b.Count - 4;
        b.AddRange([0x4D, 0x85, 0xE4]);  // test r12, r12
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int coFailJump2At = b.Count - 4;
        b.AddRange([0x4D, 0x85, 0xED]);  // test r13, r13
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int coFailJump3At = b.Count - 4;

        // First kernel_write: set flags.cnt = 0x40000000, flags.in = 0x40000000
        // Build 20-byte buf: cnt=0x40000000, in=0x40000000, out=0, size=0x40000000, buf_ptr=0
        b.AddRange([0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x40]); // [rbp-48] cnt = 0x40000000
        b.AddRange([0xC7, 0x45, 0xD4, 0x00, 0x00, 0x00, 0x40]); // [rbp-44] in  = 0x40000000
        b.AddRange([0xC7, 0x45, 0xD8, 0x00, 0x00, 0x00, 0x00]); // [rbp-40] out = 0
        b.AddRange([0x48, 0xC7, 0x45, 0xDC, 0x00, 0x00, 0x00, 0x40]); // size = 0x40000000 (pipe capacity)

        // kernel_write(pipe_addr, &buf, 20)
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PipeAddr, b.Count - 4);
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);  // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x14, 0x00, 0x00, 0x00]);  // mov edx, 20
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int coKw1Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);  // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int coFailJump4At = b.Count - 4;

        // Second kernel_write: pbuf.size=0x40000000, pbuf.kaddr=kaddr, pbuf.reserved=0
        b.AddRange([0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x40]); // size = 0x40000000
        b.AddRange([0x48, 0x89, 0x5D, 0xD4]);  // [rbp-0x2C] = kaddr
        b.AddRange([0x48, 0xC7, 0x45, 0xDC, 0x00, 0x00, 0x00, 0x00]); // reserved = 0

        // kernel_write(pipe_addr + 12, &buf, 20)
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PipeAddr, b.Count - 4);
        b.AddRange([0x48, 0x83, 0xC7, 0x0C]);  // add rdi, 12
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        b.AddRange([0xBA, 0x14, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int coKw2Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int coFailJump5At = b.Count - 4;

        // SYS_read(rwpipe[0], uaddr, len)
        b.AddRange([0xBF, 0x03, 0x00, 0x00, 0x00]);  // mov edi, 3 (SYS_read)
        b.AddRange([0x8B, 0x35, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPipe0, b.Count - 4);     // mov esi, [rip+rw_pipe_0]
        b.AddRange([0x4C, 0x89, 0xE2]);  // mov rdx, r12 (uaddr)
        b.AddRange([0x4C, 0x89, 0xE9]);  // mov rcx, r13 (len)
        b.AddRange([0x31, 0xC0]);  // xor eax, eax
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int coSyscallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);  // test rax, rax
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int coFailJump6At = b.Count - 4;
        b.AddRange([0x31, 0xC0]);  // xor eax, eax ; return 0
        b.AddRange([0xEB, 0x05]);
        // .Lco_fail:
        int coFail = b.Count;
        WriteRel32InBLocal(coFailJump1At, coFail);
        WriteRel32InBLocal(coFailJump2At, coFail);
        WriteRel32InBLocal(coFailJump3At, coFail);
        WriteRel32InBLocal(coFailJump4At, coFail);
        WriteRel32InBLocal(coFailJump5At, coFail);
        WriteRel32InBLocal(coFailJump6At, coFail);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]); // mov eax, -1
        // epilogue
        b.AddRange([0x48, 0x83, 0xC4, 0x28, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelCopyoutBytes = b.Count - kernelCopyoutOff;

        // ============================================================================
        // __sp_kernel_init(rdi = payload_args*)
        //
        // __kernel_init: latches the kernel R/W primitives from
        // the arguments block:
        //   rw_pair[0..1] from args[0x10], rw_pipe[0..1] from args[0x08],
        //   pipe_addr from args[0x18], kdata_base from args[0x20].
        // Then queries the firmware version via SYS_dynlib_get_obj_member (649) and
        // fills per-FW offsets. Currently emits the FW 10.00-10.60 case only:
        //   TEXT_BASE = DATA_BASE - 0xCC0000
        //   ALLPROC   = DATA_BASE + 0x2765D70
        //   SEC_FLAGS = DATA_BASE + 0xD79064
        //   ROOTVNODE = DATA_BASE + 0x2FA3510
        // Returns 0 on success, negative on failure (-9 EBADF, -14 EFAULT, -78 ENOSYS).
        // ============================================================================
        int kernelInitOff = b.Count;
        _currentRelocs = _kernelInitRelocs;

        // push rbp ; mov rbp, rsp ; push r14 ; push rbx ; sub rsp, 0x20
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53, 0x48, 0x83, 0xEC, 0x20]);

        // --- Latch rw_pair[0..1] from args[0x10] ---
        // Use rdi directly (does NOT save args to rbx first).
        // mov rcx, [rdi+0x10]     ; rcx = args->rwpair pointer
        b.AddRange([0x48, 0x8B, 0x4F, 0x10]);
        // mov edx, [rcx]          ; edx = rwpair[0]
        b.AddRange([0x8B, 0x11]);
        // mov [rip+rw_pair_0], edx
        b.AddRange([0x89, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPair0, b.Count - 4);
        // test edx, edx ; js .Lki_fail_ebadf
        b.AddRange([0x85, 0xD2]);
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int kiEbadfJump1 = b.Count - 4;
        // mov ecx, [rcx+4]        ; rwpair[1]
        b.AddRange([0x8B, 0x49, 0x04]);
        // mov [rip+rw_pair_1], ecx
        b.AddRange([0x89, 0x0D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPair1, b.Count - 4);
        // test ecx, ecx ; js .Lki_fail_ebadf
        b.AddRange([0x85, 0xC9]);
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int kiEbadfJump2 = b.Count - 4;

        // --- Latch rw_pipe[0..1] from args[0x08] ---
        // mov rcx, [rdi+0x08]
        b.AddRange([0x48, 0x8B, 0x4F, 0x08]);
        // mov edx, [rcx]
        b.AddRange([0x8B, 0x11]);
        // mov [rip+rw_pipe_0], edx
        b.AddRange([0x89, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPipe0, b.Count - 4);
        b.AddRange([0x85, 0xD2]);
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int kiEbadfJump3 = b.Count - 4;
        // mov ecx, [rcx+4]
        b.AddRange([0x8B, 0x49, 0x04]);
        // mov [rip+rw_pipe_1], ecx
        b.AddRange([0x89, 0x0D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RwPipe1, b.Count - 4);
        b.AddRange([0x85, 0xC9]);
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int kiEbadfJump4 = b.Count - 4;

        // --- Latch pipe_addr from args[0x18] ---
        // mov rcx, [rdi+0x18]
        b.AddRange([0x48, 0x8B, 0x4F, 0x18]);
        // mov [rip+pipe_addr], rcx
        b.AddRange([0x48, 0x89, 0x0D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PipeAddr, b.Count - 4);
        // test rcx, rcx ; je .Lki_fail_efault
        b.AddRange([0x48, 0x85, 0xC9]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int kiEfaultJump1 = b.Count - 4;

        // --- Latch kdata_base from args[0x20] ---
        // mov rcx, [rdi+0x20]
        b.AddRange([0x48, 0x8B, 0x4F, 0x20]);
        // mov [rip+kdata_base], rcx
        b.AddRange([0x48, 0x89, 0x0D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.KdataBase, b.Count - 4);
        // test rcx, rcx ; je .Lki_fail_efault
        b.AddRange([0x48, 0x85, 0xC9]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int kiEfaultJump2 = b.Count - 4;

        // --- FW version detection via SYS_dynlib_get_obj_member(649) ---
        // Query the firmware version to compute allproc = kdata_base + FW-specific offset.
        // SYS_dynlib_get_obj_member(handle=2, member=8, &sce_proc_param)
        //   -> sce_proc_param->sdk_ps5_ver at offset 0x14
        b.AddRange([0x48, 0x8D, 0x4D, 0xE8]);             // lea rcx, [rbp-0x18]
        b.AddRange([0xBF, 0x89, 0x02, 0x00, 0x00]);         // mov edi, 649  (SYS_dynlib_get_obj_member)
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);         // mov esi, 2    (handle = libSceLibcInternal)
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);         // mov edx, 8    (member)
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_crt_syscall
        int kiFwSyscallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                            // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);               // jnz .Lki_fail_enosys
        int kiEnosysJump1 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x45, 0xE8]);               // mov rax, [rbp-0x18]
        b.AddRange([0x48, 0x85, 0xC0]);                      // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);               // jz .Lki_fail_enosys
        int kiEnosysJump2 = b.Count - 4;
        // Read sdk_ps5_ver at offset 0x14, mask to FW group
        b.AddRange([0x8B, 0x40, 0x14]);                      // mov eax, [rax+0x14]
        b.AddRange([0x25, 0x00, 0x00, 0xFF, 0xFF]);         // and eax, 0xFFFF0000
        // Extract major version for the switch
        b.AddRange([0x89, 0xC1]);                            // mov ecx, eax
        b.AddRange([0xC1, 0xE9, 0x18]);                      // shr ecx, 24

        // --- FW switch: set edx = allproc offset from kdata_base ---
        var fwDoneJumps = new List<int>();
        void EmitFwCase(byte major, uint allprocOff)
        {
            b.AddRange([0x83, 0xF9, major]);                 // cmp ecx, major
            b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);           // jne .Lnext
            int notJump = b.Count - 4;
            b.AddRange([0xBA, (byte)(allprocOff & 0xFF), (byte)((allprocOff >> 8) & 0xFF),
                              (byte)((allprocOff >> 16) & 0xFF), (byte)((allprocOff >> 24) & 0xFF)]);
            b.AddRange([0xE9, 0, 0, 0, 0]);                 // jmp .Lfw_done
            fwDoneJumps.Add(b.Count - 4);
            int next = b.Count;
            WriteRel32InBLocal(notJump, next);
        }

        // FW 1.x: sub-version check (1.00-1.02 vs 1.05+)
        b.AddRange([0x83, 0xF9, 0x01]);                     // cmp ecx, 1
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);               // jne .Lnot_1
        int kiNot1Jump = b.Count - 4;
        b.AddRange([0x3D, 0x00, 0x00, 0x03, 0x01]);         // cmp eax, 0x01030000
        b.AddRange([0x73, 0x07]);                            // jae .Lfw_1b (skip 7 bytes)
        b.AddRange([0xBA, 0xF8, 0x1B, 0x6D, 0x02]);         // mov edx, 0x026D1BF8
        b.AddRange([0xEB, 0x05]);                            // jmp .Lfw_1_done (skip 5 bytes)
        b.AddRange([0xBA, 0x18, 0x1C, 0x6D, 0x02]);         // mov edx, 0x026D1C18
        b.AddRange([0xE9, 0, 0, 0, 0]);                     // jmp .Lfw_done
        fwDoneJumps.Add(b.Count - 4);
        int kiNot1 = b.Count;
        WriteRel32InBLocal(kiNot1Jump, kiNot1);

        EmitFwCase(0x02, 0x02701C28);
        EmitFwCase(0x03, 0x0276DC58);
        EmitFwCase(0x04, 0x027EDCB8);
        EmitFwCase(0x05, 0x0291DD00);
        EmitFwCase(0x06, 0x02869D20);
        EmitFwCase(0x07, 0x02859D50);
        EmitFwCase(0x08, 0x02875D50);
        EmitFwCase(0x09, 0x02755D50);
        EmitFwCase(0x10, 0x02765D70);
        EmitFwCase(0x11, 0x02875D70);
        EmitFwCase(0x12, 0x02885E00);
        EmitFwCase(0x13, 0x028C5E00);

        // Default: unsupported FW
        b.AddRange([0xE9, 0, 0, 0, 0]);                     // jmp .Lki_fail_enosys
        int kiEnosysJump3 = b.Count - 4;

        // .Lfw_done: compute allproc = kdata_base + edx
        int kiFwDone = b.Count;
        foreach (int at in fwDoneJumps) WriteRel32InBLocal(at, kiFwDone);
        // movsxd rdx, edx  (allproc offsets are positive, fit in signed 32)
        b.AddRange([0x48, 0x63, 0xD2]);                      // movsxd rdx, edx
        b.AddRange([0x48, 0x03, 0x15, 0, 0, 0, 0]);         // add rdx, [rip+kdata_base]
        AddRel(RelocSymbol.KdataBase, b.Count - 4);
        b.AddRange([0x48, 0x89, 0x15, 0, 0, 0, 0]);         // mov [rip+allproc], rdx
        AddRel(RelocSymbol.Allproc, b.Count - 4);

        // ---- Set VMSPACE_VM_PMAP offset based on FW version ----
        // ecx still has the major FW version byte (1-13).
        // eax still has the masked FW version (0xMMSS0000).
        // FW 1.00-1.02 -> 0x2c0, FW 1.05-5.x -> 0x2e0, FW 6+ -> 0x2e8.
        b.AddRange([0x83, 0xF9, 0x01]);                      // cmp ecx, 1
        b.AddRange([0x75, 0x00]);                             // jne .Lvmpm_not1
        int vmpmNot1JumpAt = b.Count - 1;
        b.AddRange([0x3D, 0x00, 0x00, 0x03, 0x01]);         // cmp eax, 0x01030000
        b.AddRange([0x73, 0x00]);                             // jae .Lvmpm_2e0
        int vmpm2e0JumpAt = b.Count - 1;
        // FW 1.00-1.02: VMSPACE_VM_PMAP = 0x2c0
        b.AddRange([0x48, 0xC7, 0x05, 0, 0, 0, 0, 0xC0, 0x02, 0x00, 0x00]); // mov qword [rip+vmspace_vm_pmap], 0x2c0
        AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4 - 4, addend: -8);
        b.AddRange([0xEB, 0x00]);                             // jmp .Lvmpm_done
        int vmpmDoneJump1 = b.Count - 1;
        // .Lvmpm_not1:
        int vmpmNot1 = b.Count;
        b[vmpmNot1JumpAt] = (byte)(vmpmNot1 - (vmpmNot1JumpAt + 1));
        b.AddRange([0x83, 0xF9, 0x06]);                      // cmp ecx, 6
        b.AddRange([0x7D, 0x00]);                             // jge .Lvmpm_2e8
        int vmpm2e8JumpAt = b.Count - 1;
        // .Lvmpm_2e0: FW 1.05-5.x
        int vmpm2e0 = b.Count;
        b[vmpm2e0JumpAt] = (byte)(vmpm2e0 - (vmpm2e0JumpAt + 1));
        b.AddRange([0x48, 0xC7, 0x05, 0, 0, 0, 0, 0xE0, 0x02, 0x00, 0x00]); // mov qword [rip+vmspace_vm_pmap], 0x2e0
        AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4 - 4, addend: -8);
        b.AddRange([0xEB, 0x00]);                             // jmp .Lvmpm_done
        int vmpmDoneJump2 = b.Count - 1;
        // .Lvmpm_2e8: FW 6+
        int vmpm2e8 = b.Count;
        b[vmpm2e8JumpAt] = (byte)(vmpm2e8 - (vmpm2e8JumpAt + 1));
        b.AddRange([0x48, 0xC7, 0x05, 0, 0, 0, 0, 0xE8, 0x02, 0x00, 0x00]); // mov qword [rip+vmspace_vm_pmap], 0x2e8
        AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4 - 4, addend: -8);
        // .Lvmpm_done:
        int vmpmDone = b.Count;
        b[vmpmDoneJump1] = (byte)(vmpmDone - (vmpmDoneJump1 + 1));
        b[vmpmDoneJump2] = (byte)(vmpmDone - (vmpmDoneJump2 + 1));

        // ---- Populate TEXT_BASE, BUS_DATA_DEVICES, TARGETID, UTOKEN_FLAGS ----
        // ecx = major FW version (1-13), rdx = allproc (needed by R/W probe).
        // Save rdx (allproc) in rbx (callee-saved, pushed in prologue, free).
        b.AddRange([0x48, 0x89, 0xD3]);                      // mov rbx, rdx

        // Jump past the inline data table.
        b.AddRange([0xE9, 0, 0, 0, 0]);                      // jmp .Lpast_table
        int jmpPastTableAt = b.Count - 4;

        // Per-FW data table: 14 entries, 16 bytes each (index 0 unused).
        // Format: textBaseNeg(u32) + busDataOff(u32) + secFlagsOff(u32) + rootvnodeOff(u32).
        // Values verified from the firmware offset table in the CRT.
        // rootvnodeOff values for FW 1-10 verified against the published offset table;
        // FW 11-13 are zero (unverified) and cause CrtGetRootVnode to return 0.
        int kiTableStart = b.Count;
        uint[][] fwTableData =
        [
            [0,          0,          0,          0         ], // [0] unused
            [0x01B40000, 0x01D6D487, 0x06241074, 0x06565540], // [1] FW 1.x (1.05+ values)
            [0x01B80000, 0x01D91478, 0x063E1274, 0x067134C0], // [2] FW 2.x
            [0x00BD0000, 0x01DF1678, 0x06466474, 0x067AB4C0], // [3] FW 3.x
            [0x00C00000, 0x01E69678, 0x06506474, 0x066E74C0], // [4] FW 4.x
            [0x00C40000, 0x01F996C8, 0x066466EC, 0x06853510], // [5] FW 5.x
            [0x00C60000, 0x01FB96C8, 0x065968EC, 0x0679F510], // [6] FW 6.x
            [0x00C50000, 0x01FA5718, 0x00AC8064, 0x030C7510], // [7] FW 7.x
            [0x00C70000, 0x01FA5718, 0x00AC3064, 0x030FB510], // [8] FW 8.x
            [0x00CA0000, 0x01F65718, 0x00D73064, 0x02FDB510], // [9] FW 9.x
            [0x00CC0000, 0x01F65718, 0x00D79064, 0x02FA3510], // [10] FW 10.x
            [0x00D30000, 0x02075718, 0x00D8C064, 0         ], // [11] FW 11.x (rootvnode unverified)
            [0x00D50000, 0x020757E8, 0x00D83064, 0         ], // [12] FW 12.x (rootvnode unverified)
            [0x00CB0000, 0x020981E8, 0x00D99064, 0         ], // [13] FW 13.x (rootvnode unverified)
        ];
        foreach (uint[] entry in fwTableData)
            foreach (uint v in entry)
            {
                b.Add((byte)(v & 0xFF));
                b.Add((byte)((v >> 8) & 0xFF));
                b.Add((byte)((v >> 16) & 0xFF));
                b.Add((byte)((v >> 24) & 0xFF));
            }

        // .Lpast_table:
        int pastTable = b.Count;
        WriteRel32InBLocal(jmpPastTableAt, pastTable);

        // ecx holds the version major byte in BCD form (single-digit majors 1..9 encode as
        // 0x01..0x09; two-digit majors 10..13 encode as 0x10..0x13). The row table is packed
        // linearly, so map BCD 0x10..0x13 to linear 10..13 by subtracting 6. Values below
        // 0x10 already sit at their linear index.
        b.AddRange([0x83, 0xF9, 0x10]);                      // cmp ecx, 0x10
        b.AddRange([0x72, 0x03]);                            // jb +3 -> skip subtract
        b.AddRange([0x83, 0xE9, 0x06]);                      // sub ecx, 6

        // edx = ecx * 16 (table entry index)
        b.AddRange([0x6B, 0xD1, 0x10]);                      // imul edx, ecx, 16

        // lea rax, [rip + tableDisp] -- point to table base.
        // RIP-relative: displacement = target - (instruction_end) = kiTableStart - (current + 7).
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int leaEnd = b.Count;
        int leaDisp = kiTableStart - leaEnd;
        b[leaEnd - 4] = (byte)(leaDisp & 0xFF);
        b[leaEnd - 3] = (byte)((leaDisp >> 8) & 0xFF);
        b[leaEnd - 2] = (byte)((leaDisp >> 16) & 0xFF);
        b[leaEnd - 1] = (byte)((leaDisp >> 24) & 0xFF);

        // Load textBaseNeg(esi), busDataOff(edi), secFlagsOff(r8d), rootvnodeOff(r11d) from table
        b.AddRange([0x8B, 0x34, 0x10]);                       // mov esi, [rax+rdx]
        b.AddRange([0x8B, 0x7C, 0x10, 0x04]);                 // mov edi, [rax+rdx+4]
        b.AddRange([0x44, 0x8B, 0x44, 0x10, 0x08]);           // mov r8d, [rax+rdx+8]
        b.AddRange([0x44, 0x8B, 0x5C, 0x10, 0x0C]);           // mov r11d, [rax+rdx+12]

        // Load kdata_base once into r9 (callee-saved is pushed but free).
        // r9 is caller-saved, safe to use here.
        b.AddRange([0x4C, 0x8B, 0x0D, 0, 0, 0, 0]);          // mov r9, [rip+kdata_base]
        AddRel(RelocSymbol.KdataBase, b.Count - 4);

        // TEXT_BASE = kdata_base - textBaseNeg
        b.AddRange([0x48, 0x63, 0xCE]);                       // movsxd rcx, esi
        b.AddRange([0x4C, 0x89, 0xC8]);                       // mov rax, r9
        b.AddRange([0x48, 0x29, 0xC8]);                       // sub rax, rcx
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);           // mov [rip+text_base], rax
        AddRel(RelocSymbol.KernelTextBase, b.Count - 4);

        // BUS_DATA_DEVICES = kdata_base + busDataOff
        b.AddRange([0x48, 0x63, 0xCF]);                       // movsxd rcx, edi
        b.AddRange([0x4C, 0x89, 0xC8]);                       // mov rax, r9
        b.AddRange([0x48, 0x01, 0xC8]);                       // add rax, rcx
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);           // mov [rip+bus_data], rax
        AddRel(RelocSymbol.KernelBusDataDevices, b.Count - 4);

        // Compute security_flags_addr = kdata_base + secFlagsOff (in rcx)
        b.AddRange([0x49, 0x63, 0xC8]);                       // movsxd rcx, r8d
        b.AddRange([0x4C, 0x01, 0xC9]);                       // add rcx, r9
        // TARGETID = security_flags_addr + 9
        b.AddRange([0x48, 0x8D, 0x41, 0x09]);                 // lea rax, [rcx+9]
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);           // mov [rip+targetid], rax
        AddRel(RelocSymbol.KernelTargetid, b.Count - 4);
        // UTOKEN_FLAGS = security_flags_addr + 0x8c
        b.AddRange([0x48, 0x8D, 0x81, 0x8C, 0x00, 0x00, 0x00]); // lea rax, [rcx+0x8c]
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);           // mov [rip+utoken_flags], rax
        AddRel(RelocSymbol.KernelUtokenFlags, b.Count - 4);

        // ROOTVNODE = kdata_base + rootvnodeOff (only if rootvnodeOff != 0)
        // r11d holds rootvnodeOff loaded from the table. For firmware versions whose
        // rootvnode offset is unverified, the table entry is zero; skip the store so the
        // BSS slot stays at its zero-initialized default and CrtGetRootVnode returns 0.
        b.AddRange([0x45, 0x85, 0xDB]);                       // test r11d, r11d
        b.AddRange([0x74, 0x0D]);                              // je .Lrv_skip (skip 13 bytes)
        b.AddRange([0x49, 0x63, 0xCB]);                       // movsxd rcx, r11d
        b.AddRange([0x4C, 0x01, 0xC9]);                       // add rcx, r9 (kdata_base)
        b.AddRange([0x48, 0x89, 0x0D, 0, 0, 0, 0]);           // mov [rip+kernel_rootvnode], rcx
        AddRel(RelocSymbol.KernelRootvnode, b.Count - 4);
        // .Lrv_skip:

        // Restore rdx = allproc (saved in rbx) for the R/W probe.
        b.AddRange([0x48, 0x89, 0xDA]);                       // mov rdx, rbx

        // ---- R/W probe: kernel_copyout(allproc, &[rbp-0x18], 8) ----
        // The __kernel_init function calls kernel_get_ucred_prison(0) and
        // KERNEL_DLSYM(0x1, __error) which exercise the pipe/pair kernel R/W
        // primitives. If the exploit tore down the overlay before jumping to us,
        // the fds are valid numbers but setsockopt / pipe-read fail. Without this
        // probe, kernel_init returns 0 (the fd checks pass) and every downstream
        // kernel_copyout inside kernel_dynlib_resolve silently returns 0, leaving
        // every GOT slot empty. The SIGSEGV at the first PLT dispatch follows.
        //
        // Store the allproc head into [rbp-0x18] (local space) for the null-check
        // that follows.
        b.AddRange([0x48, 0x89, 0xD7]);                      // mov rdi, rdx  (allproc - still in rdx)
        b.AddRange([0x48, 0x8D, 0x75, 0xE8]);                // lea rsi, [rbp-0x18]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);          // mov edx, 8
        b.AddRange([0xE8, 0, 0, 0, 0]);                      // call __sp_kernel_copyout
        int kiProbeCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                             // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                // jnz .Lki_fail_efault
        int kiProbeFailJump = b.Count - 4;
        // Verify allproc head is non-null (the process list must not be empty).
        b.AddRange([0x48, 0x8B, 0x45, 0xE8]);                // mov rax, [rbp-0x18]
        b.AddRange([0x48, 0x85, 0xC0]);                      // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                // jz .Lki_fail_efault
        int kiProbeNullJump = b.Count - 4;

        // Success: return 0
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xE9, 0, 0, 0, 0]);                     // jmp .Lki_ret
        int kiRetJumpOk = b.Count - 4;

        // .Lki_fail_ebadf: mov eax, -9 (EBADF)
        int kiFailEbadf = b.Count;
        WriteRel32InBLocal(kiEbadfJump1, kiFailEbadf);
        WriteRel32InBLocal(kiEbadfJump2, kiFailEbadf);
        WriteRel32InBLocal(kiEbadfJump3, kiFailEbadf);
        WriteRel32InBLocal(kiEbadfJump4, kiFailEbadf);
        b.AddRange([0xB8, 0xF7, 0xFF, 0xFF, 0xFF]); // mov eax, -9
        b.AddRange([0xEB, 0x00]);
        int kiRetJumpEbadf = b.Count - 1;

        // .Lki_fail_efault: mov eax, -14 (EFAULT)
        int kiFailEfault = b.Count;
        WriteRel32InBLocal(kiEfaultJump1, kiFailEfault);
        WriteRel32InBLocal(kiEfaultJump2, kiFailEfault);
        WriteRel32InBLocal(kiProbeFailJump, kiFailEfault);
        WriteRel32InBLocal(kiProbeNullJump, kiFailEfault);
        b.AddRange([0xB8, 0xF2, 0xFF, 0xFF, 0xFF]); // mov eax, -14
        b.AddRange([0xEB, 0x00]);
        int kiRetJumpEfault = b.Count - 1;

        // .Lki_fail_enosys: mov eax, -78 (ENOSYS)
        int kiFailEnosys = b.Count;
        WriteRel32InBLocal(kiEnosysJump1, kiFailEnosys);
        WriteRel32InBLocal(kiEnosysJump2, kiFailEnosys);
        WriteRel32InBLocal(kiEnosysJump3, kiFailEnosys);
        b.AddRange([0xB8, 0xB2, 0xFF, 0xFF, 0xFF]); // mov eax, -78

        // .Lki_ret: add rsp, 0x20 ; pop rbx ; pop r14 ; pop rbp ; ret
        int kiRet = b.Count;
        WriteRel32InBLocal(kiRetJumpOk, kiRet);
        b[kiRetJumpEbadf] = (byte)(kiRet - (kiRetJumpEbadf + 1));
        b[kiRetJumpEfault] = (byte)(kiRet - (kiRetJumpEfault + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x20, 0x5B, 0x41, 0x5E, 0x5D, 0xC3]);
        _kernelInitBytes = b.Count - kernelInitOff;

        // ============================================================================
        // __sp_sha1_transform(rdi = uint32 state[5], rsi = uint8 block[64])
        //
        // Compact loop-based SHA-1 compression function. Processes one 64-byte block
        // against a 5-word state. Uses W[80] on the stack (320 bytes).
        //
        // Register plan:
        //   r15 = state pointer (callee-saved)
        //   r8d..r11d = a,b,c,d (caller-saved, no save needed)
        //   ebx = e (callee-saved)
        //   r14d = round counter (callee-saved)
        //   r12d = K constant (callee-saved)
        // ============================================================================
        int sha1TransformOff = b.Count;
        _currentRelocs = _sha1TransformRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r14 ; push r15 ; sub rsp, 0x150
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x56, 0x41, 0x57,
                    0x48, 0x81, 0xEC, 0x50, 0x01, 0x00, 0x00]);
        // mov r15, rdi
        b.AddRange([0x49, 0x89, 0xFF]);

        // --- Load and bswap W[0..15] ---
        // xor ecx, ecx
        b.AddRange([0x31, 0xC9]);
        int sha1LoadLoop = b.Count;
        // mov eax, [rsi+rcx*4]
        b.AddRange([0x8B, 0x04, 0x8E]);
        // bswap eax
        b.AddRange([0x0F, 0xC8]);
        // mov [rsp+rcx*4], eax
        b.AddRange([0x89, 0x04, 0x8C]);
        // inc ecx
        b.AddRange([0xFF, 0xC1]);
        // cmp ecx, 16
        b.AddRange([0x83, 0xF9, 0x10]);
        // jb .Lload
        b.Add(0x72); b.Add((byte)(sha1LoadLoop - (b.Count + 1)));

        // --- Extend W[16..79]: W[i] = rol(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1) ---
        int sha1ExtendLoop = b.Count;
        // mov eax, [rsp+rcx*4-12]  (W[i-3])
        b.AddRange([0x8B, 0x44, 0x8C, 0xF4]);
        // xor eax, [rsp+rcx*4-32]  (W[i-8])
        b.AddRange([0x33, 0x44, 0x8C, 0xE0]);
        // xor eax, [rsp+rcx*4-56]  (W[i-14])
        b.AddRange([0x33, 0x44, 0x8C, 0xC8]);
        // xor eax, [rsp+rcx*4-64]  (W[i-16])
        b.AddRange([0x33, 0x44, 0x8C, 0xC0]);
        // rol eax, 1
        b.AddRange([0xC1, 0xC0, 0x01]);
        // mov [rsp+rcx*4], eax
        b.AddRange([0x89, 0x04, 0x8C]);
        // inc ecx ; cmp ecx, 80 ; jb .Lextend
        b.AddRange([0xFF, 0xC1, 0x83, 0xF9, 0x50]);
        b.Add(0x72); b.Add((byte)(sha1ExtendLoop - (b.Count + 1)));

        // --- Load state: r8d=a, r9d=b, r10d=c, r11d=d, ebx=e ---
        b.AddRange([0x45, 0x8B, 0x07]);         // mov r8d, [r15]
        b.AddRange([0x45, 0x8B, 0x4F, 0x04]);   // mov r9d, [r15+4]
        b.AddRange([0x45, 0x8B, 0x57, 0x08]);   // mov r10d, [r15+8]
        b.AddRange([0x45, 0x8B, 0x5F, 0x0C]);   // mov r11d, [r15+12]
        b.AddRange([0x41, 0x8B, 0x5F, 0x10]);   // mov ebx, [r15+16]

        // --- 80 rounds ---
        // xor r14d, r14d
        b.AddRange([0x45, 0x31, 0xF6]);
        int sha1RoundLoop = b.Count;

        // Phase selection: cmp r14d, N ; jb/jge
        // Phase 0 (rounds 0-19): ch(b,c,d) = (b&c)|(~b&d), K=0x5A827999
        // cmp r14d, 20 ; jge .Lnot0
        b.AddRange([0x41, 0x83, 0xFE, 0x14]);
        b.AddRange([0x7D, 0x00]); int sha1Not0JumpAt = b.Count - 1;
        // mov eax, r9d ; and eax, r10d
        b.AddRange([0x44, 0x89, 0xC8, 0x44, 0x21, 0xD0]);
        // mov ecx, r9d ; not ecx ; and ecx, r11d ; or eax, ecx
        b.AddRange([0x44, 0x89, 0xC9, 0xF7, 0xD1, 0x44, 0x21, 0xD9, 0x09, 0xC8]);
        // mov r12d, 0x5A827999
        b.AddRange([0x41, 0xBC, 0x99, 0x79, 0x82, 0x5A]);
        // jmp .Lstep
        b.AddRange([0xEB, 0x00]); int sha1StepJump0At = b.Count - 1;

        // .Lnot0: Phase 1 (rounds 20-39): parity b^c^d, K=0x6ED9EBA1
        int sha1Not0 = b.Count;
        b[sha1Not0JumpAt] = (byte)(sha1Not0 - (sha1Not0JumpAt + 1));
        b.AddRange([0x41, 0x83, 0xFE, 0x28]); // cmp r14d, 40
        b.AddRange([0x7D, 0x00]); int sha1Not1JumpAt = b.Count - 1;
        // mov eax, r9d ; xor eax, r10d ; xor eax, r11d
        b.AddRange([0x44, 0x89, 0xC8, 0x44, 0x31, 0xD0, 0x44, 0x31, 0xD8]);
        // mov r12d, 0x6ED9EBA1
        b.AddRange([0x41, 0xBC, 0xA1, 0xEB, 0xD9, 0x6E]);
        b.AddRange([0xEB, 0x00]); int sha1StepJump1At = b.Count - 1;

        // .Lnot1: Phase 2 (rounds 40-59): maj(b,c,d), K=0x8F1BBCDC
        int sha1Not1 = b.Count;
        b[sha1Not1JumpAt] = (byte)(sha1Not1 - (sha1Not1JumpAt + 1));
        b.AddRange([0x41, 0x83, 0xFE, 0x3C]); // cmp r14d, 60
        b.AddRange([0x7D, 0x00]); int sha1Not2JumpAt = b.Count - 1;
        // mov eax, r9d ; mov ecx, r9d ; and eax, r10d ; and ecx, r11d ; or eax, ecx
        b.AddRange([0x44, 0x89, 0xC8, 0x44, 0x89, 0xC9, 0x44, 0x21, 0xD0, 0x44, 0x21, 0xD9, 0x09, 0xC8]);
        // mov ecx, r10d ; and ecx, r11d ; or eax, ecx
        b.AddRange([0x44, 0x89, 0xD1, 0x44, 0x21, 0xD9, 0x09, 0xC8]);
        b.AddRange([0x41, 0xBC, 0xDC, 0xBC, 0x1B, 0x8F]); // mov r12d, 0x8F1BBCDC
        b.AddRange([0xEB, 0x00]); int sha1StepJump2At = b.Count - 1;

        // .Lnot2: Phase 3 (rounds 60-79): parity, K=0xCA62C1D6
        int sha1Not2 = b.Count;
        b[sha1Not2JumpAt] = (byte)(sha1Not2 - (sha1Not2JumpAt + 1));
        b.AddRange([0x44, 0x89, 0xC8, 0x44, 0x31, 0xD0, 0x44, 0x31, 0xD8]); // parity
        b.AddRange([0x41, 0xBC, 0xD6, 0xC1, 0x62, 0xCA]); // mov r12d, 0xCA62C1D6

        // .Lstep: compute temp = rol(a,5) + f + e + K + W[i]
        int sha1Step = b.Count;
        b[sha1StepJump0At] = (byte)(sha1Step - (sha1StepJump0At + 1));
        b[sha1StepJump1At] = (byte)(sha1Step - (sha1StepJump1At + 1));
        b[sha1StepJump2At] = (byte)(sha1Step - (sha1StepJump2At + 1));

        // mov ecx, r8d ; rol ecx, 5
        b.AddRange([0x44, 0x89, 0xC1, 0xC1, 0xC1, 0x05]);
        // add eax, ecx  (f + rol(a,5))
        b.AddRange([0x01, 0xC8]);
        // add eax, ebx  (+ e)
        b.AddRange([0x01, 0xD8]);
        // add eax, r12d (+ K)
        b.AddRange([0x44, 0x01, 0xE0]);
        // add eax, [rsp+r14*4]  (+ W[i])
        b.AddRange([0x42, 0x03, 0x04, 0xB4]);

        // Shift: e=d, d=c, c=rol(b,30), b=a, a=temp
        b.AddRange([0x44, 0x89, 0xDB]);        // mov ebx, r11d   (e = d)
        b.AddRange([0x45, 0x89, 0xD3]);        // mov r11d, r10d  (d = c)
        b.AddRange([0x45, 0x89, 0xCA]);        // mov r10d, r9d   (will rol below)
        b.AddRange([0x41, 0xC1, 0xC2, 0x1E]);  // rol r10d, 30    (c = rol(b,30))
        b.AddRange([0x45, 0x89, 0xC1]);        // mov r9d, r8d    (b = a)
        b.AddRange([0x41, 0x89, 0xC0]);        // mov r8d, eax    (a = temp)

        // inc r14d ; cmp r14d, 80 ; jb .Lround
        b.AddRange([0x41, 0xFF, 0xC6, 0x41, 0x83, 0xFE, 0x50]);
        b.AddRange([0x0F, 0x82, 0x00, 0x00, 0x00, 0x00]); // jb rel32
        int sha1RoundBackJump = b.Count - 4;
        WriteRel32InBLocal(sha1RoundBackJump, sha1RoundLoop);

        // --- Update state ---
        b.AddRange([0x45, 0x01, 0x07]);        // add [r15], r8d
        b.AddRange([0x45, 0x01, 0x4F, 0x04]);  // add [r15+4], r9d
        b.AddRange([0x45, 0x01, 0x57, 0x08]);  // add [r15+8], r10d
        b.AddRange([0x45, 0x01, 0x5F, 0x0C]);  // add [r15+12], r11d
        b.AddRange([0x41, 0x01, 0x5F, 0x10]);  // add [r15+16], ebx

        // Epilogue: add rsp, 0x150 ; pop r15 ; pop r14 ; pop r12 ; pop rbx ; pop rbp ; ret
        b.AddRange([0x48, 0x81, 0xC4, 0x50, 0x01, 0x00, 0x00,
                    0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _sha1TransformBytes = b.Count - sha1TransformOff;

        // ============================================================================
        // __sp_nid_encode(rdi = name, rsi = out[12])
        //
        // SHA-1 of (name || salt), bswap64 first 8 digest bytes, zero bytes 8-15,
        // base-64 encode to 11 chars + NUL. NID encoding: base-64 output.
        //
        // Stack frame (callee-saved registers occupy [rbp-0x08..rbp-0x28]):
        //   [rbp-0x40] state[5] = 20 bytes ([rbp-0x40]..[rbp-0x2D])
        //   [rbp-0x48] bit-count high dword
        //   [rbp-0x44] bit-count low dword (big-endian)
        //   [rbp-0x80] buffer[64] ([rbp-0x80]..[rbp-0x41])
        //   [rbp-0x84] buf_idx (int) -- disp32
        //   [rbp-0x88] total_len (int) -- disp32
        //   [rbp-0xA0] digest[20] (padded to 24, [rbp-0xA0]..[rbp-0x89]) -- disp32
        //   Sub rsp: 0x98 = 152 bytes (stack 16-byte aligned with 5 pushes)
        // ============================================================================
        int nidEncodeOff = b.Count;
        _currentRelocs = _nidEncodeRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; push r14 ; push r15
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        // sub rsp, 0x98 (locals below the 5 saved registers at [rbp-0x08..rbp-0x28])
        b.AddRange([0x48, 0x81, 0xEC, 0x98, 0x00, 0x00, 0x00]);
        // Save: r14 = name, r15 = out
        b.AddRange([0x49, 0x89, 0xFE]); // mov r14, rdi
        b.AddRange([0x49, 0x89, 0xF7]); // mov r15, rsi

        // strlen(name): r12 = 0 ; while (name[r12]) r12++
        b.AddRange([0x4D, 0x31, 0xE4]); // xor r12, r12
        int nidStrlenLoop = b.Count;
        b.AddRange([0x43, 0x80, 0x3C, 0x26, 0x00]); // cmp byte [r14+r12], 0
        b.AddRange([0x74, 0x00]); int nidStrlenDone = b.Count - 1;
        b.AddRange([0x49, 0xFF, 0xC4]); // inc r12
        b.Add(0xEB); b.Add((byte)(nidStrlenLoop - (b.Count + 1))); // jmp .Lstrlen
        int nidStrlenDoneAt = b.Count;
        b[nidStrlenDone] = (byte)(nidStrlenDoneAt - (nidStrlenDone + 1));

        // total_len = r12 + 16 ; store at [rbp-0x88] (disp32)
        b.AddRange([0x4C, 0x89, 0xE0]);        // mov rax, r12
        b.AddRange([0x48, 0x83, 0xC0, 0x10]);  // add rax, 16
        b.AddRange([0x89, 0x85, 0x78, 0xFF, 0xFF, 0xFF]); // mov [rbp-0x88], eax

        // SHA1Init: state[0..4] = IV constants at [rbp-0x40..-0x2D]
        b.AddRange([0xC7, 0x45, 0xC0, 0x01, 0x23, 0x45, 0x67]); // mov [rbp-0x40], 0x67452301
        b.AddRange([0xC7, 0x45, 0xC4, 0x89, 0xAB, 0xCD, 0xEF]); // mov [rbp-0x3C], 0xEFCDAB89
        b.AddRange([0xC7, 0x45, 0xC8, 0xFE, 0xDC, 0xBA, 0x98]); // mov [rbp-0x38], 0x98BADCFE
        b.AddRange([0xC7, 0x45, 0xCC, 0x76, 0x54, 0x32, 0x10]); // mov [rbp-0x34], 0x10325476
        b.AddRange([0xC7, 0x45, 0xD0, 0xF0, 0xE1, 0xD2, 0xC3]); // mov [rbp-0x30], 0xC3D2E1F0

        // buf_idx = 0 (disp32)
        b.AddRange([0xC7, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // mov [rbp-0x84], 0

        // --- Copy name bytes into buffer, call transform when full ---
        // r13 = 0 (name index)
        b.AddRange([0x4D, 0x31, 0xED]); // xor r13, r13
        int nidNameLoop = b.Count;
        b.AddRange([0x4D, 0x39, 0xE5]); // cmp r13, r12
        b.AddRange([0x0F, 0x83, 0x00, 0x00, 0x00, 0x00]); int nidNameDoneJump = b.Count - 4;
        // mov al, [r14+r13]
        b.AddRange([0x43, 0x8A, 0x04, 0x2E]);
        // movsxd rcx, [rbp-0x84] ; mov [rbp-0x80+rcx], al
        b.AddRange([0x48, 0x63, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF]); // movsxd rcx, [rbp-0x84] (disp32)
        b.AddRange([0x88, 0x44, 0x0D, 0x80]); // mov [rbp-0x80+rcx], al
        // inc buf_idx
        b.AddRange([0xFF, 0x85, 0x7C, 0xFF, 0xFF, 0xFF]); // inc dword [rbp-0x84] (disp32)
        // cmp buf_idx, 64 ; jne .Lnext_name
        b.AddRange([0x83, 0xBD, 0x7C, 0xFF, 0xFF, 0xFF, 0x40]);
        b.AddRange([0x75, 0x00]); int nidNameNoTransform = b.Count - 1;
        // Call SHA1Transform(state, buffer)
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]); // lea rdi, [rbp-0x40]
        b.AddRange([0x48, 0x8D, 0x75, 0x80]); // lea rsi, [rbp-0x80]
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int nidCallTransform1 = b.Count - 4;
        // buf_idx = 0
        b.AddRange([0xC7, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
        int nidNameNext = b.Count;
        b[nidNameNoTransform] = (byte)(nidNameNext - (nidNameNoTransform + 1));
        // inc r13 ; jmp .Lname_loop
        b.AddRange([0x49, 0xFF, 0xC5]);
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); int nidNameLoopBack = b.Count - 4;
        WriteRel32InBLocal(nidNameLoopBack, nidNameLoop);
        int nidNameDone = b.Count;
        WriteRel32InBLocal(nidNameDoneJump, nidNameDone);

        // --- Copy 16 salt bytes into buffer ---
        // lea r13, [rip+salt]  (will be patched in rodata)
        b.AddRange([0x4C, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]); int nidSaltLeaAt = b.Count - 4;
        b.AddRange([0x31, 0xDB]); // xor ebx, ebx  (salt index)
        int nidSaltLoop = b.Count;
        b.AddRange([0x83, 0xFB, 0x10]); // cmp ebx, 16
        b.AddRange([0x0F, 0x83, 0x00, 0x00, 0x00, 0x00]); int nidSaltDoneJump = b.Count - 4;
        // mov al, [r13+rbx]
        b.AddRange([0x41, 0x8A, 0x44, 0x1D, 0x00]);
        // movsxd rcx, [rbp-0x84] ; mov [rbp-0x80+rcx], al
        b.AddRange([0x48, 0x63, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0x88, 0x44, 0x0D, 0x80]);
        b.AddRange([0xFF, 0x85, 0x7C, 0xFF, 0xFF, 0xFF]); // inc buf_idx (disp32)
        b.AddRange([0x83, 0xBD, 0x7C, 0xFF, 0xFF, 0xFF, 0x40]); // cmp buf_idx, 64 (disp32)
        b.AddRange([0x75, 0x00]); int nidSaltNoTransform = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]); // lea rdi, [rbp-0x40]
        b.AddRange([0x48, 0x8D, 0x75, 0x80]); // lea rsi, [rbp-0x80]
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int nidCallTransform2 = b.Count - 4;
        b.AddRange([0xC7, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
        int nidSaltNext = b.Count;
        b[nidSaltNoTransform] = (byte)(nidSaltNext - (nidSaltNoTransform + 1));
        b.AddRange([0xFF, 0xC3]); // inc ebx
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); int nidSaltLoopBack = b.Count - 4;
        WriteRel32InBLocal(nidSaltLoopBack, nidSaltLoop);
        int nidSaltDone = b.Count;
        WriteRel32InBLocal(nidSaltDoneJump, nidSaltDone);

        // --- Padding: 0x80 byte, zeros, length ---
        // mov al, 0x80 ; movsxd rcx, [rbp-0x84] ; mov [rbp-0x80+rcx], al ; inc buf_idx
        b.AddRange([0xB0, 0x80]);
        b.AddRange([0x48, 0x63, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF]); // movsxd rcx, [rbp-0x84] (disp32)
        b.AddRange([0x88, 0x44, 0x0D, 0x80]); // mov [rbp-0x80+rcx], al
        b.AddRange([0xFF, 0x85, 0x7C, 0xFF, 0xFF, 0xFF]); // inc dword [rbp-0x84] (disp32)

        // If buf_idx > 56, fill rest with zeros and transform, then start new block
        b.AddRange([0x83, 0xBD, 0x7C, 0xFF, 0xFF, 0xFF, 0x38]); // cmp buf_idx, 56 (disp32)
        b.AddRange([0x7E, 0x00]); int nidPadNoExtraBlock = b.Count - 1;
        // Fill remaining with zeros
        int nidPadFillLoop = b.Count;
        b.AddRange([0x83, 0xBD, 0x7C, 0xFF, 0xFF, 0xFF, 0x40]); // cmp buf_idx, 64 (disp32)
        b.AddRange([0x7D, 0x00]); int nidPadFillDone1Jump = b.Count - 1;
        b.AddRange([0x48, 0x63, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF]); // movsxd rcx, [rbp-0x84] (disp32)
        b.AddRange([0xC6, 0x44, 0x0D, 0x80, 0x00]); // mov byte [rbp-0x80+rcx], 0
        b.AddRange([0xFF, 0x85, 0x7C, 0xFF, 0xFF, 0xFF]); // inc dword [rbp-0x84] (disp32)
        b.Add(0xEB); b.Add((byte)(nidPadFillLoop - (b.Count + 1)));
        int nidPadFillDone1 = b.Count;
        b[nidPadFillDone1Jump] = (byte)(nidPadFillDone1 - (nidPadFillDone1Jump + 1));
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]); // lea rdi, [rbp-0x40]
        b.AddRange([0x48, 0x8D, 0x75, 0x80]); // lea rsi, [rbp-0x80]
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int nidCallTransform3 = b.Count - 4;
        b.AddRange([0xC7, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // buf_idx = 0 (disp32)
        int nidPadNoExtraBlockAt = b.Count;
        b[nidPadNoExtraBlock] = (byte)(nidPadNoExtraBlockAt - (nidPadNoExtraBlock + 1));

        // Fill zeros up to byte 56
        int nidPadZeroLoop = b.Count;
        b.AddRange([0x83, 0xBD, 0x7C, 0xFF, 0xFF, 0xFF, 0x38]); // cmp buf_idx, 56 (disp32)
        b.AddRange([0x7D, 0x00]); int nidPadZeroDoneJump = b.Count - 1;
        b.AddRange([0x48, 0x63, 0x8D, 0x7C, 0xFF, 0xFF, 0xFF]); // movsxd rcx, [rbp-0x84] (disp32)
        b.AddRange([0xC6, 0x44, 0x0D, 0x80, 0x00]); // mov byte [rbp-0x80+rcx], 0
        b.AddRange([0xFF, 0x85, 0x7C, 0xFF, 0xFF, 0xFF]); // inc dword [rbp-0x84] (disp32)
        b.Add(0xEB); b.Add((byte)(nidPadZeroLoop - (b.Count + 1)));
        int nidPadZeroDone = b.Count;
        b[nidPadZeroDoneJump] = (byte)(nidPadZeroDone - (nidPadZeroDoneJump + 1));

        // Write 8-byte big-endian bit count at buffer[56..63]
        // bit_count = total_len * 8 = total_len << 3
        b.AddRange([0x8B, 0x85, 0x78, 0xFF, 0xFF, 0xFF]); // mov eax, [rbp-0x88] (disp32)
        b.AddRange([0xC1, 0xE0, 0x03]);        // shl eax, 3
        // Store as big-endian 64-bit at [rbp-0x80+56] = [rbp-0x48]
        // For symbol names < 256 chars, high 4 bytes are all zero
        b.AddRange([0xC7, 0x45, 0xB8, 0x00, 0x00, 0x00, 0x00]); // [rbp-0x48] = 0 (high dword)
        b.AddRange([0x0F, 0xC8]);  // bswap eax
        b.AddRange([0x89, 0x45, 0xBC]); // mov [rbp-0x44], eax (low dword, big-endian)

        // Final transform
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]); // lea rdi, [rbp-0x40]
        b.AddRange([0x48, 0x8D, 0x75, 0x80]); // lea rsi, [rbp-0x80]
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int nidCallTransform4 = b.Count - 4;

        // --- Convert state to digest bytes (big-endian) at [rbp-0xA0] ---
        // For i=0..4: bswap state[i], store at digest[i*4]
        b.AddRange([0x31, 0xC9]); // xor ecx, ecx
        int nidDigestLoop = b.Count;
        b.AddRange([0x8B, 0x44, 0x8D, 0xC0]); // mov eax, [rbp-0x40+rcx*4]
        b.AddRange([0x0F, 0xC8]);              // bswap eax
        b.AddRange([0x89, 0x84, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xA0+rcx*4], eax (disp32)
        b.AddRange([0xFF, 0xC1]);              // inc ecx
        b.AddRange([0x83, 0xF9, 0x05]);        // cmp ecx, 5
        b.Add(0x72); b.Add((byte)(nidDigestLoop - (b.Count + 1)));

        // --- bswap64 first 8 bytes of digest ---
        // mov rax, [rbp-0xA0] ; bswap rax ; mov [rbp-0xA0], rax
        b.AddRange([0x48, 0x8B, 0x85, 0x60, 0xFF, 0xFF, 0xFF]); // mov rax, [rbp-0xA0] (disp32)
        b.AddRange([0x48, 0x0F, 0xC8]);
        b.AddRange([0x48, 0x89, 0x85, 0x60, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xA0], rax (disp32)

        // --- Zero bytes 8..15 ---
        b.AddRange([0x48, 0xC7, 0x85, 0x68, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // [rbp-0x98] = 0 (disp32)

        // --- Base64 encode first 12 bytes -> 11 chars ---
        // lea r13, [rip+b64charset]  (patched in rodata)
        b.AddRange([0x4C, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]); int nidB64LeaAt = b.Count - 4;
        b.AddRange([0x31, 0xC9]); // xor ecx, ecx (j = output index)
        b.AddRange([0x31, 0xDB]); // xor ebx, ebx (i = input index)
        int nidB64Loop = b.Count;
        b.AddRange([0x83, 0xF9, 0x0B]); // cmp ecx, 11
        b.AddRange([0x7D, 0x00]); int nidB64DoneJump = b.Count - 1;
        // a = digest[i], b_val = digest[i+1], c_val = digest[i+2]
        b.AddRange([0x0F, 0xB6, 0x84, 0x1D, 0x60, 0xFF, 0xFF, 0xFF]); // movzx eax, byte [rbp-0xA0+rbx] (disp32)
        b.AddRange([0x0F, 0xB6, 0x94, 0x1D, 0x61, 0xFF, 0xFF, 0xFF]); // movzx edx, byte [rbp-0xA0+rbx+1] (disp32)
        b.AddRange([0x44, 0x0F, 0xB6, 0x84, 0x1D, 0x62, 0xFF, 0xFF, 0xFF]); // movzx r8d, byte [rbp-0xA0+rbx+2] (disp32)
        // abc = (a << 16) | (b << 8) | c
        b.AddRange([0xC1, 0xE0, 0x10]); // shl eax, 16
        b.AddRange([0xC1, 0xE2, 0x08]); // shl edx, 8
        b.AddRange([0x09, 0xD0]);       // or eax, edx
        b.AddRange([0x44, 0x09, 0xC0]); // or eax, r8d
        // out[j] = charset[(abc >> 18) & 0x3F]
        b.AddRange([0x89, 0xC2]);       // mov edx, eax
        b.AddRange([0xC1, 0xEA, 0x12]); // shr edx, 18
        b.AddRange([0x83, 0xE2, 0x3F]); // and edx, 0x3F
        b.AddRange([0x41, 0x0F, 0xB6, 0x54, 0x15, 0x00]); // movzx edx, [r13+rdx]
        b.AddRange([0x41, 0x88, 0x14, 0x0F]); // mov [r15+rcx], dl
        b.AddRange([0xFF, 0xC1]); // inc ecx
        // out[j] = charset[(abc >> 12) & 0x3F]
        b.AddRange([0x89, 0xC2, 0xC1, 0xEA, 0x0C, 0x83, 0xE2, 0x3F]);
        b.AddRange([0x41, 0x0F, 0xB6, 0x54, 0x15, 0x00]);
        b.AddRange([0x41, 0x88, 0x14, 0x0F]);
        b.AddRange([0xFF, 0xC1]);
        // out[j] = charset[(abc >> 6) & 0x3F]
        b.AddRange([0x89, 0xC2, 0xC1, 0xEA, 0x06, 0x83, 0xE2, 0x3F]);
        b.AddRange([0x41, 0x0F, 0xB6, 0x54, 0x15, 0x00]);
        b.AddRange([0x41, 0x88, 0x14, 0x0F]);
        b.AddRange([0xFF, 0xC1]);
        // out[j] = charset[abc & 0x3F]
        b.AddRange([0x89, 0xC2, 0x83, 0xE2, 0x3F]);
        b.AddRange([0x41, 0x0F, 0xB6, 0x54, 0x15, 0x00]);
        b.AddRange([0x41, 0x88, 0x14, 0x0F]);
        b.AddRange([0xFF, 0xC1]);
        // i += 3
        b.AddRange([0x83, 0xC3, 0x03]);
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); int nidB64LoopBack = b.Count - 4;
        WriteRel32InBLocal(nidB64LoopBack, nidB64Loop);
        int nidB64Done = b.Count;
        b[nidB64DoneJump] = (byte)(nidB64Done - (nidB64DoneJump + 1));

        // NUL-terminate: out[11] = 0
        b.AddRange([0x41, 0xC6, 0x47, 0x0B, 0x00]);

        // Return out pointer in rax
        b.AddRange([0x4C, 0x89, 0xF8]); // mov rax, r15

        // Epilogue: add rsp, 0x98 ; pop r15..rbx ; pop rbp ; ret
        b.AddRange([0x48, 0x81, 0xC4, 0x98, 0x00, 0x00, 0x00,
                    0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _nidEncodeBytes = b.Count - nidEncodeOff;

        // ============================================================================
        // __sp_kernel_get_proc(edi = pid) -> rax = proc kaddr (0 on failure)
        //
        // kernel_get_proc: walks allproc linked list. No proc_cache.
        // If pid <= 0, calls SYS_getpid (20) to get current PID. Walks the
        // allproc linked list via kernel_copyout.
        // ============================================================================
        int kernelGetProcOff = b.Count;
        _currentRelocs = _kernelGetProcRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; sub rsp, 0x18
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x18]);
        // mov ebx, edi  (pid)
        b.AddRange([0x89, 0xFB]);

        // if (pid <= 0) pid = getpid()
        b.AddRange([0x85, 0xFF]); // test edi, edi
        b.AddRange([0x7F, 0x00]); int gprPidOkJump = b.Count - 1;
        // __crt_syscall(SYS_getpid=20)
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]); // mov edi, 20
        b.AddRange([0x31, 0xC0]); // xor eax, eax
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int gprSyscallCall = b.Count - 4;
        b.AddRange([0x89, 0xC3]); // mov ebx, eax (pid = getpid result)
        int gprPidOk = b.Count;
        b[gprPidOkJump] = (byte)(gprPidOk - (gprPidOkJump + 1));

        // kernel_copyout(ALLPROC, &addr, 8)
        // mov rdi, [rip+allproc]
        b.AddRange([0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.Allproc, b.Count - 4);
        // lea rsi, [rbp-0x20] (addr on stack)
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // call __sp_kernel_copyout
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int gprCopyout1 = b.Count - 4;
        // test eax, eax ; jne .Lfail
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int gprFail1Jump = b.Count - 4;

        // r12 = &other_pid on stack [rbp-0x28]
        b.AddRange([0x4C, 0x8D, 0x65, 0xD8]);
        // r13 = &next on stack [rbp-0x30]
        b.AddRange([0x4C, 0x8D, 0x6D, 0xD0]);

        // Walk allproc list
        int gprWalkLoop = b.Count;
        // mov rdi, [rbp-0x20]  ; addr
        b.AddRange([0x48, 0x8B, 0x7D, 0xE0]);
        // test rdi, rdi ; je .Lfound (addr == 0 -> end of list)
        b.AddRange([0x48, 0x85, 0xFF]);
        b.AddRange([0x74, 0x00]); int gprFoundJump = b.Count - 1;
        // kernel_copyout(addr + 0xBC, &other_pid, 4)
        b.AddRange([0x48, 0x81, 0xC7, 0xBC, 0x00, 0x00, 0x00]); // add rdi, 0xBC
        b.AddRange([0x4C, 0x89, 0xE6]); // mov rsi, r12
        b.AddRange([0xBA, 0x04, 0x00, 0x00, 0x00]); // mov edx, 4
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int gprCopyout2 = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int gprFail2Jump = b.Count - 4;
        // cmp ebx, [rbp-0x28]  ; pid == other_pid?
        b.AddRange([0x3B, 0x5D, 0xD8]);
        b.AddRange([0x74, 0x00]); int gprMatchJump = b.Count - 1;
        // Not matched: read next pointer
        // kernel_copyout(addr, &next, 8)
        b.AddRange([0x48, 0x8B, 0x7D, 0xE0]); // mov rdi, [rbp-0x20]
        b.AddRange([0x4C, 0x89, 0xEE]); // mov rsi, r13
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int gprCopyout3 = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int gprFail3Jump = b.Count - 4;
        // addr = next
        b.AddRange([0x48, 0x8B, 0x45, 0xD0]); // mov rax, [rbp-0x30]
        b.AddRange([0x48, 0x89, 0x45, 0xE0]); // mov [rbp-0x20], rax
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); int gprLoopBack = b.Count - 4;
        WriteRel32InBLocal(gprLoopBack, gprWalkLoop);

        // .Lfound: return addr (pid match only)
        int gprFound = b.Count;
        b[gprMatchJump] = (byte)(gprFound - (gprMatchJump + 1));
        b.AddRange([0x48, 0x8B, 0x45, 0xE0]); // mov rax, [rbp-0x20]
        b.AddRange([0xEB, 0x00]); int gprRetJump = b.Count - 1;

        // .Lpid_miss: end of list without PID match (addr==0 path)
        int gprPidMiss = b.Count;
        b[gprFoundJump] = (byte)(gprPidMiss - (gprFoundJump + 1));
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_pid_miss]
        int gprPidMissLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int gprPidMissKlogCall = b.Count - 4;
        b.AddRange([0xEB, 0x00]); // jmp .Lfail
        int gprPidMissFailJump = b.Count - 1;

        // .Lallproc_fail: initial allproc copyout failure
        int gprAllprocFail = b.Count;
        WriteRel32InBLocal(gprFail1Jump, gprAllprocFail);
        b.AddRange([0x41, 0x89, 0xC4]);                              // mov r12d, eax (save copyout return)
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_allproc_fail]
        int gprAllprocFailLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int gprAllprocFailKlogCall = b.Count - 4;
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x44, 0x89, 0xE7]);                          // mov edi, r12d
            b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);              // call __sp_klog_copyout_err
            copyoutErrCallDisps.Add(b.Count - 4);
        }

        // .Lfail: return 0
        int gprFail = b.Count;
        b[gprPidMissFailJump] = (byte)(gprFail - (gprPidMissFailJump + 1));
        WriteRel32InBLocal(gprFail2Jump, gprFail);
        WriteRel32InBLocal(gprFail3Jump, gprFail);
        b.AddRange([0x31, 0xC0]); // xor eax, eax

        // .Lret:
        int gprRet = b.Count;
        b[gprRetJump] = (byte)(gprRet - (gprRetJump + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x18, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelGetProcBytes = b.Count - kernelGetProcOff;

        // ============================================================================
        // __sp_kernel_find_proc_by_comm(rdi = name, esi = nameLength)
        //   -> rax = proc kaddr (0 on failure)
        //
        // Walks the allproc linked list, comparing p_comm (at proc+0x5DC) against the
        // supplied name. Returns the first matching proc kernel address or 0.
        // ============================================================================
        int findProcByCommOff = b.Count;
        _currentRelocs = _kernelFindProcByCommRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; sub rsp, 0x28
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x48, 0x83, 0xEC, 0x28]);
        // mov rbx, rdi (name)
        b.AddRange([0x48, 0x89, 0xFB]);
        // mov r12d, esi (nameLength)
        b.AddRange([0x41, 0x89, 0xF4]);

        // kernel_copyout(ALLPROC, &proc, 8)
        // mov rdi, [rip+allproc]
        b.AddRange([0x48, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.Allproc, b.Count - 4);
        // lea rsi, [rbp-0x20]
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // call __sp_kernel_copyout
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int fpbcCopyout1 = b.Count - 4;
        // test eax, eax ; jne .Lfail
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int fpbcFail1Jump = b.Count - 4;

        // .Lloop: walk allproc list
        int fpbcLoop = b.Count;
        // mov rdi, [rbp-0x20]
        b.AddRange([0x48, 0x8B, 0x7D, 0xE0]);
        // test rdi, rdi ; je .Lfail (end of list)
        b.AddRange([0x48, 0x85, 0xFF]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); int fpbcEndlistJump = b.Count - 4;

        // kernel_copyout(proc+0x5DC, &buf, 17) — read p_comm
        // add rdi, 0x5DC
        b.AddRange([0x48, 0x81, 0xC7, 0xDC, 0x05, 0x00, 0x00]);
        // lea rsi, [rbp-0x31]
        b.AddRange([0x48, 0x8D, 0x75, 0xCF]);
        // mov edx, 17
        b.AddRange([0xBA, 0x11, 0x00, 0x00, 0x00]);
        // call __sp_kernel_copyout
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int fpbcCopyout2 = b.Count - 4;
        // test eax, eax ; jne .Lnext
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int fpbcCopyoutFailJump = b.Count - 4;

        // Check NUL terminator: buf[nameLength] must be 0
        // lea r13, [rbp-0x31]
        b.AddRange([0x4C, 0x8D, 0x6D, 0xCF]);
        // cmp byte [r13+r12*1+0], 0
        b.AddRange([0x43, 0x80, 0x7C, 0x25, 0x00, 0x00]);
        // jne .Lnext
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int fpbcNulFailJump = b.Count - 4;

        // Byte comparison loop
        // xor ecx, ecx
        b.AddRange([0x31, 0xC9]);
        // .Lcmp_loop:
        int fpbcCmpLoop = b.Count;
        // cmp ecx, r12d
        b.AddRange([0x44, 0x39, 0xE1]);
        // jge .Lfound
        b.AddRange([0x7D, 0x00]); int fpbcFoundJump = b.Count - 1;
        // movzx eax, byte [rbx+rcx*1]
        b.AddRange([0x0F, 0xB6, 0x04, 0x0B]);
        // cmp al, [r13+rcx*1+0]
        b.AddRange([0x41, 0x3A, 0x44, 0x0D, 0x00]);
        // jne .Lnext
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int fpbcByteMissJump = b.Count - 4;
        // inc ecx
        b.AddRange([0xFF, 0xC1]);
        // jmp .Lcmp_loop
        b.AddRange([0xEB, 0x00]); int fpbcCmpLoopBack = b.Count - 1;
        b[fpbcCmpLoopBack] = (byte)(fpbcCmpLoop - (fpbcCmpLoopBack + 1));

        // .Lfound: return proc
        int fpbcFound = b.Count;
        b[fpbcFoundJump] = (byte)(fpbcFound - (fpbcFoundJump + 1));
        // mov rax, [rbp-0x20]
        b.AddRange([0x48, 0x8B, 0x45, 0xE0]);
        // jmp .Lret
        b.AddRange([0xEB, 0x00]); int fpbcRetJump = b.Count - 1;

        // .Lnext: read le_next and continue walk
        int fpbcNext = b.Count;
        WriteRel32InBLocal(fpbcCopyoutFailJump, fpbcNext);
        WriteRel32InBLocal(fpbcNulFailJump, fpbcNext);
        WriteRel32InBLocal(fpbcByteMissJump, fpbcNext);
        // mov rdi, [rbp-0x20]
        b.AddRange([0x48, 0x8B, 0x7D, 0xE0]);
        // lea rsi, [rbp-0x20]
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // call __sp_kernel_copyout
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int fpbcCopyout3 = b.Count - 4;
        // test eax, eax ; jne .Lfail
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int fpbcNextFailJump = b.Count - 4;
        // jmp .Lloop
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); int fpbcNextLoop = b.Count - 4;
        WriteRel32InBLocal(fpbcNextLoop, fpbcLoop);

        // .Lfail: return 0
        int fpbcFail = b.Count;
        WriteRel32InBLocal(fpbcFail1Jump, fpbcFail);
        WriteRel32InBLocal(fpbcEndlistJump, fpbcFail);
        WriteRel32InBLocal(fpbcNextFailJump, fpbcFail);
        // xor eax, eax
        b.AddRange([0x31, 0xC0]);

        // .Lret:
        int fpbcRet = b.Count;
        b[fpbcRetJump] = (byte)(fpbcRet - (fpbcRetJump + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x28, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelFindProcByCommBytes = b.Count - findProcByCommOff;

        // ============================================================================
        // __sp_kernel_dynlib_obj(edi = pid, esi = handle, rdx = obj_buf)
        //
        // kernel_dynlib_obj: walks the kernel dynlib linked
        // list for a process to find the entry matching handle, then copies 0x180
        // bytes to the user buffer. Returns 0 on success, -1 on failure.
        // ============================================================================
        // SDK-exact kernel_dynlib_obj (197 bytes / 0xC5).
        // Walks the kernel dynlib linked list for a process, finds the entry
        // matching handle, copies 0x180 bytes to the output buffer.
        // Returns 0 on success, -1 on failure (sets errno=EINVAL on null entry).
        // ============================================================================
        int kernelDynlibObjOff = b.Count;
        _currentRelocs = _kernelDynlibObjRelocs;

        // +0x00: prologue — SDK push order: r15, r14, r13, r12, rbx
        b.AddRange([0x55, 0x48, 0x89, 0xE5,                                // push rbp ; mov rbp, rsp
                    0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,        // push r15..r12
                    0x53, 0x50]);                                           // push rbx ; push rax (align)
        // +0x0e: save args: r14 = obj_buf, r12d = handle
        b.AddRange([0x49, 0x89, 0xD6]);                                    // mov r14, rdx
        b.AddRange([0x41, 0x89, 0xF4]);                                    // mov r12d, esi
        // +0x14: call kernel_get_proc(pid)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int dobjGetProc = b.Count - 4;
        // +0x19: mov ebx, -1 (default return)
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);
        // +0x1e: test rax, rax ; je .Lret (0xb4)
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); int dobjNoProc = b.Count - 4;
        // +0x27: add rax, 0x3e8 (offset to dynlib list head in proc)
        b.AddRange([0x48, 0x05, 0xE8, 0x03, 0x00, 0x00]);
        // +0x2d: kernel_copyout(rax, [rbp-0x30], 8) — read list head
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                              // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                        // mov edx, 8
        b.AddRange([0x48, 0x89, 0xC7]);                                    // mov rdi, rax
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int dobjCopyout1 = b.Count - 4;
        // +0x3e: test eax, eax ; js .Lret
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x78, 0x72]);                                           // js +0x72 -> .Lret (0xb4)
        // +0x42: set up loop: r15 = &r14[0x28], r13d = handle, r12 = &[rbp-0x30]
        b.AddRange([0x4D, 0x8D, 0x7E, 0x28]);                              // lea r15, [r14+0x28]
        b.AddRange([0x45, 0x89, 0xE5]);                                    // mov r13d, r12d
        b.AddRange([0x4C, 0x8D, 0x65, 0xD0]);                              // lea r12, [rbp-0x30]
        // +0x4d: alignment NOP
        b.AddRange([0x0F, 0x1F, 0x00]);                                    // nopl (%rax)
        // +0x50: .Lloop — read next pointer into [rbp-0x30]
        int dobjLoop = b.Count;
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                              // mov rdi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                        // mov edx, 8
        b.AddRange([0x4C, 0x89, 0xE6]);                                    // mov rsi, r12
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int dobjCopyout2 = b.Count - 4;
        // +0x61: test eax, eax ; js .Lret
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x78, 0x4F]);                                           // js +0x4F -> .Lret (0xb4)
        // +0x65: check null (end of list)
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                              // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x85, 0xFF]);                                    // test rdi, rdi
        b.AddRange([0x74, 0x32]);                                           // je .Lerror (0xa0)
        // +0x6e: read handle at entry+0x28 into r15 (&r14[0x28])
        b.AddRange([0x48, 0x83, 0xC7, 0x28]);                              // add rdi, 0x28
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                        // mov edx, 8
        b.AddRange([0x4C, 0x89, 0xFE]);                                    // mov rsi, r15
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int dobjCopyout3 = b.Count - 4;
        // +0x7f: test eax, eax ; js .Lret
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x78, 0x31]);                                           // js +0x31 -> .Lret (0xb4)
        // +0x83: compare handle
        b.AddRange([0x4D, 0x39, 0x2F]);                                    // cmp [r15], r13
        b.AddRange([0x75, 0xC8]);                                           // jne .Lloop (0x50)
        // +0x88: .Lfound — copy 0x180 bytes
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                              // mov rdi, [rbp-0x30]
        b.AddRange([0xBA, 0x80, 0x01, 0x00, 0x00]);                        // mov edx, 0x180
        b.AddRange([0x4C, 0x89, 0xF6]);                                    // mov rsi, r14
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int dobjCopyout4 = b.Count - 4;
        // +0x99: mov ebx, eax ; sar ebx, 31 (0 if success, -1 if fail)
        b.AddRange([0x89, 0xC3]);
        b.AddRange([0xC1, 0xFB, 0x1F]);
        b.AddRange([0xEB, 0x14]);                                           // jmp .Lret (0xb4)
        // +0xa0: .Lerror — set errno=EINVAL via __error BSS
        int dobjErrorAt = b.Count;
        b.AddRange([0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]);            // mov rax, [rip+__error]
        AddRel(RelocSymbol.KlogError, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                                    // test rax, rax
        b.AddRange([0x74, 0x08]);                                           // je .Lret
        b.AddRange([0xFF, 0xD0]);                                           // call *rax
        b.AddRange([0xC7, 0x00, 0x16, 0x00, 0x00, 0x00]);                  // movl $0x16, (%rax) (EINVAL=22)
        // +0xb4: .Lret
        int dobjRet = b.Count;
        WriteRel32InBLocal(dobjNoProc, dobjRet);
        b.AddRange([0x89, 0xD8]);                                           // mov eax, ebx
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                              // add rsp, 8
        b.AddRange([0x5B]);                                                 // pop rbx
        b.AddRange([0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F]);     // pop r12..r15
        b.AddRange([0x5D, 0xC3]);                                           // pop rbp ; ret
        _kernelDynlibObjBytes = b.Count - kernelDynlibObjOff;

        // ============================================================================
        // __sp_kernel_dynlib_resolve(edi = pid, esi = handle, rdx = nid_str) -> rax
        //
        // kernel_dynlib_resolve: gets dynlib object, maps the
        // symbol table into user memory, searches for matching NID, returns the
        // resolved address or 0.
        //
        // The dynlib_obj_t struct (0x180 bytes) has:
        //   +0x30: mapbase address
        //   +0x148: pointer to symbol table metadata (kernel address)
        // The metadata (0x120 bytes) has:
        //   +0x28: symtab kernel address
        //   +0x30: symtab size in bytes
        //   +0x38: strtab kernel address
        //   +0x40: strtab size in bytes
        // ============================================================================
        int kernelDynlibResolveOff = b.Count;
        _currentRelocs = _kernelDynlibResolveRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; push r13 ; push r14 ; push r15
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        // sub rsp, 0x2B8 (dynlib_obj 0x180 + metadata 0x120 + locals 0x10 + 8 alignment)
        b.AddRange([0x48, 0x81, 0xEC, 0xB8, 0x02, 0x00, 0x00]);
        // Save nid pointer
        b.AddRange([0x49, 0x89, 0xD6]); // mov r14, rdx (nid string)
        // Call kernel_dynlib_obj(pid, handle, &obj)
        // rdx = lea [rbp - 0x2C8] (space for dynlib_obj)
        b.AddRange([0x48, 0x8D, 0x95, 0x38, 0xFD, 0xFF, 0xFF]); // lea rdx, [rbp-0x2c8]
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int drsvDynlibObj = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); int drsvFail1 = b.Count - 4;

        int drsvObjOkLeaAt = -1, drsvObjOkKlogCall = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            // Breadcrumb: sp:dl:walk:obj:ok (dynlib_obj succeeded)
            b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_obj_ok]
            drsvObjOkLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
            drsvObjOkKlogCall = b.Count - 4;
        }

        // Save mapbase from dynlib_obj[0x30] = [rbp-0x2c8+0x30] = [rbp-0x298]
        // kernel_copyout(dynlib_obj[0x148], &metadata, 0x120)
        b.AddRange([0x48, 0x8B, 0xBD, 0x80, 0xFE, 0xFF, 0xFF]); // mov rdi, [rbp-0x180]  (=obj[0x148])
        b.AddRange([0x48, 0x8D, 0xB5, 0xB8, 0xFE, 0xFF, 0xFF]); // lea rsi, [rbp-0x148]  (metadata buf)
        b.AddRange([0xBA, 0x20, 0x01, 0x00, 0x00]); // mov edx, 0x120
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int drsvCopyoutMeta = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]); int drsvFail2 = b.Count - 4;

        // total_size = meta[0x30] + meta[0x40] (symtab_size + strtab_size)
        // meta starts at [rbp-0x148], so meta[0x30] = [rbp-0x118], meta[0x40] = [rbp-0x108]
        b.AddRange([0x48, 0x8B, 0x9D, 0xF8, 0xFE, 0xFF, 0xFF]); // mov rbx, [rbp-0x108] (strtab_size)
        b.AddRange([0x48, 0x03, 0x9D, 0xE8, 0xFE, 0xFF, 0xFF]); // add rbx, [rbp-0x118] (+ symtab_size)

        // SYS_mmap(NULL, total_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
        b.AddRange([0xBF, 0xDD, 0x01, 0x00, 0x00]); // mov edi, 477 (SYS_mmap)
        b.AddRange([0x31, 0xF6]); // xor esi, esi (addr=NULL)
        b.AddRange([0x48, 0x89, 0xDA]); // mov rdx, rbx (len)
        b.AddRange([0xB9, 0x03, 0x00, 0x00, 0x00]); // mov ecx, 3 (PROT_READ|PROT_WRITE)
        b.AddRange([0x41, 0xB8, 0x02, 0x10, 0x00, 0x00]); // mov r8d, 0x1002 (MAP_PRIVATE|MAP_ANON)
        b.AddRange([0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF]); // mov r9d, -1 (fd)
        // Push 0 for offset argument (7th arg on stack)
        b.AddRange([0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp], 0
        b.AddRange([0x31, 0xC0]); // xor eax, eax
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int drsvMmapCall = b.Count - 4;
        // Check mmap result
        b.AddRange([0x48, 0x83, 0xF8, 0xFF]); // cmp rax, -1
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); int drsvFail3 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC7]); // mov r15, rax (mmap base)

        // kernel_copyout(symtab_kaddr, mmap_base, symtab_size)
        b.AddRange([0x48, 0x8B, 0xBD, 0xE0, 0xFE, 0xFF, 0xFF]); // mov rdi, [rbp-0x120] (symtab kaddr)
        b.AddRange([0x4C, 0x8B, 0xA5, 0xE8, 0xFE, 0xFF, 0xFF]); // mov r12, [rbp-0x118] (symtab size)
        b.AddRange([0x4C, 0x89, 0xFE]); // mov rsi, r15 (dest = mmap base)
        b.AddRange([0x4C, 0x89, 0xE2]); // mov rdx, r12
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int drsvCopyoutSym = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]); int drsvFail4 = b.Count - 4;

        // r13 = strtab_base = mmap_base + symtab_size
        b.AddRange([0x4D, 0x89, 0xFD]); // mov r13, r15
        b.AddRange([0x4D, 0x01, 0xE5]); // add r13, r12

        // kernel_copyout(strtab_kaddr, strtab_base, strtab_size)
        b.AddRange([0x48, 0x8B, 0xBD, 0xF0, 0xFE, 0xFF, 0xFF]); // mov rdi, [rbp-0x110] (strtab kaddr)
        b.AddRange([0x48, 0x8B, 0x95, 0xF8, 0xFE, 0xFF, 0xFF]); // mov rdx, [rbp-0x108] (strtab size)
        b.AddRange([0x4C, 0x89, 0xEE]); // mov rsi, r13
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int drsvCopyoutStr = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]); int drsvFail5 = b.Count - 4;

        // Walk symbol table: num_syms = symtab_size / 24
        // r12 = symtab_size (already set)
        // We'll iterate with rcx as index, each entry is 24 bytes
        b.AddRange([0x4D, 0x31, 0xE4]); // xor r12, r12 (result = 0 default)
        b.AddRange([0x31, 0xC9]); // xor ecx, ecx (entry index)
        // Compute num entries: [rbp-0x118] / 24 -> use div or mul trick
        // Simple approach: compare byte offset against symtab_size
        b.AddRange([0x48, 0x8B, 0x85, 0xE8, 0xFE, 0xFF, 0xFF]); // mov rax, [rbp-0x118] (symtab_size)
        // rax / 24 -> store in rbx for the loop bound (reuse rbx)
        // Use a simple shift-and-subtract for /24: too complex, just use loop offset comparison
        // Instead: iterate byte offset in rcx, compare against symtab_size
        b.AddRange([0x48, 0x89, 0xC3]); // mov rbx, rax (symtab_size = loop bound)

        int drsvSymLoop = b.Count;
        b.AddRange([0x48, 0x39, 0xD9]); // cmp rcx, rbx
        b.AddRange([0x0F, 0x83, 0x00, 0x00, 0x00, 0x00]); int drsvSymDone = b.Count - 4;

        // Check sym.st_value at [r15 + rcx + 8] (Elf64_Sym: st_name(4) + st_info(1) + st_other(1) + st_shndx(2) + st_value(8))
        b.AddRange([0x4D, 0x8B, 0x64, 0x0F, 0x08]); // mov r12, [r15+rcx+8]
        b.AddRange([0x4D, 0x85, 0xE4]); // test r12, r12
        b.AddRange([0x74, 0x00]); int drsvNextSym1 = b.Count - 1; // je .Lnext

        // Get st_name offset: 32-bit at [r15 + rcx]
        b.AddRange([0x41, 0x8B, 0x04, 0x0F]); // mov eax, [r15+rcx]
        // name_ptr = strtab_base + st_name = r13 + rax
        b.AddRange([0x4C, 0x89, 0xEA]); // mov rdx, r13
        b.AddRange([0x48, 0x01, 0xC2]); // add rdx, rax

        // Compare 11 bytes of nid (r14) against name_ptr (rdx)
        b.AddRange([0x31, 0xF6]); // xor esi, esi
        int drsvCmpLoop = b.Count;
        b.AddRange([0x45, 0x0F, 0xB6, 0x04, 0x36]); // movzx r8d, byte [r14+rsi]
        b.AddRange([0x0F, 0xB6, 0x3C, 0x32]);       // movzx edi, byte [rdx+rsi]
        b.AddRange([0x44, 0x38, 0xC7]);              // cmp dil, r8b
        b.AddRange([0x75, 0x00]); int drsvCmpMismatch = b.Count - 1;
        b.AddRange([0x45, 0x85, 0xC0]); // test r8d, r8d
        b.AddRange([0x74, 0x00]); int drsvCmpMatch = b.Count - 1;
        b.AddRange([0x48, 0xFF, 0xC6]); // inc rsi
        b.AddRange([0x48, 0x83, 0xFE, 0x0B]); // cmp rsi, 11
        b.Add(0x72); b.Add((byte)(drsvCmpLoop - (b.Count + 1)));
        // Fell through: max length reached, treat as match
        b.AddRange([0xEB, 0x00]); int drsvMatchFallthrough = b.Count - 1;

        // .Lmismatch: next symbol
        int drsvMismatch = b.Count;
        b[drsvCmpMismatch] = (byte)(drsvMismatch - (drsvCmpMismatch + 1));
        // .Lnext_sym:
        int drsvNextSym = b.Count;
        b[drsvNextSym1] = (byte)(drsvNextSym - (drsvNextSym1 + 1));
        b.AddRange([0x48, 0x83, 0xC1, 0x18]); // add rcx, 24 (next Elf64_Sym)
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); int drsvSymLoopBack = b.Count - 4;
        WriteRel32InBLocal(drsvSymLoopBack, drsvSymLoop);

        // .Lmatch: r12 = sym.st_value, add mapbase
        int drsvMatch = b.Count;
        b[drsvCmpMatch] = (byte)(drsvMatch - (drsvCmpMatch + 1));
        b[drsvMatchFallthrough] = (byte)(drsvMatch - (drsvMatchFallthrough + 1));
        b.AddRange([0x4C, 0x03, 0xA5, 0x68, 0xFD, 0xFF, 0xFF]); // add r12, [rbp-0x298] (mapbase)
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]); // jmp .Lmunmap (skip sym:miss check)
        int drsvMatchMunmapJump = b.Count - 4;

        // .Lsym_walk_done: sym walk completed without match (r12 may be stale -- zero it)
        int drsvSymWalkDone = b.Count;
        WriteRel32InBLocal(drsvSymDone, drsvSymWalkDone);
        b.AddRange([0x4D, 0x31, 0xE4]); // xor r12, r12 (no match -> return null)
        // Breadcrumb: sp:dl:walk:sym:miss
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_sym_miss]
        int drsvSymMissLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int drsvSymMissKlogCall = b.Count - 4;

        // .Lmunmap: SYS_munmap(mmap_base, total_size)
        int drsvSymDoneAt = b.Count;
        WriteRel32InBLocal(drsvMatchMunmapJump, drsvSymDoneAt);
        b.AddRange([0xBF, 0x49, 0x00, 0x00, 0x00]); // mov edi, 73 (SYS_munmap)
        b.AddRange([0x4C, 0x89, 0xFE]); // mov rsi, r15 (addr)
        b.AddRange([0x48, 0x89, 0xDA]); // mov rdx, rbx (rbx = symtab_size, not total_size; recomputed below)
        // Total size must be recomputed here because rbx was overwritten with symtab_size.
        // Re-sum from meta[0x30]+meta[0x40]:
        b.AddRange([0x48, 0x8B, 0x95, 0xF8, 0xFE, 0xFF, 0xFF]); // mov rdx, [rbp-0x108] (strtab_size)
        b.AddRange([0x48, 0x03, 0x95, 0xE8, 0xFE, 0xFF, 0xFF]); // add rdx, [rbp-0x118] (+ symtab_size)
        b.AddRange([0x31, 0xC0]); // xor eax, eax
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int drsvMunmapCall = b.Count - 4;

        // Return r12 (matched address or 0)
        b.AddRange([0x4C, 0x89, 0xE0]); // mov rax, r12
        b.AddRange([0xEB, 0x00]); int drsvRetOkJump = b.Count - 1;

        // .Lfail_post_mmap: cleanup the mmap before returning 0. Fails 4 and 5
        // (symtab / strtab copyout) arrive here AFTER mmap succeeded, so the buffer
        // at r15 must be munmapped or the fixup leaks memory on every cascade attempt.
        int drsvFailPostMmap = b.Count;
        WriteRel32InBLocal(drsvFail4, drsvFailPostMmap);
        WriteRel32InBLocal(drsvFail5, drsvFailPostMmap);
        b.AddRange([0x41, 0x89, 0xC4]);                              // mov r12d, eax (save copyout return)
        // Breadcrumb: sp:dl:walk:copy:fail
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_copy_fail]
        int drsvCopyFailLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int drsvCopyFailKlogCall = b.Count - 4;
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x44, 0x89, 0xE7]);                          // mov edi, r12d
            b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);              // call __sp_klog_copyout_err
            copyoutErrCallDisps.Add(b.Count - 4);
        }
        b.AddRange([0x4D, 0x31, 0xE4]);                             // xor r12, r12  (result = 0)
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lsym_done  (munmap + return)
        WriteRel32InBLocal(b.Count - 4, drsvSymDoneAt);

        // .Lfail_obj: dynlib_obj failed (before mmap)
        int drsvFailObj = b.Count;
        WriteRel32InBLocal(drsvFail1, drsvFailObj);
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_obj_fail]
        int drsvObjFailLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int drsvObjFailKlogCall = b.Count - 4;
        b.AddRange([0xEB, 0x00]); // jmp .Lfail_common
        int drsvObjFailCommonJump = b.Count - 1;

        // .Lfail_meta: metadata copyout failed (before mmap)
        int drsvFailMeta = b.Count;
        WriteRel32InBLocal(drsvFail2, drsvFailMeta);
        b.AddRange([0x41, 0x89, 0xC4]);                              // mov r12d, eax (save copyout return)
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_meta_fail]
        int drsvMetaFailLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int drsvMetaFailKlogCall = b.Count - 4;
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x44, 0x89, 0xE7]);                          // mov edi, r12d
            b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);              // call __sp_klog_copyout_err
            copyoutErrCallDisps.Add(b.Count - 4);
        }
        b.AddRange([0xEB, 0x00]); // jmp .Lfail_common
        int drsvMetaFailCommonJump = b.Count - 1;

        // .Lfail_mmap: mmap failed (before mmap cleanup needed)
        int drsvFailMmap = b.Count;
        WriteRel32InBLocal(drsvFail3, drsvFailMmap);
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]); // lea rdi, [rip+sp_dl_walk_mmap_fail]
        int drsvMmapFailLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); // call __prospero_klog
        int drsvMmapFailKlogCall = b.Count - 4;

        // .Lfail_common: return 0 (before mmap — no cleanup needed)
        int drsvFailCommon = b.Count;
        b[drsvObjFailCommonJump] = (byte)(drsvFailCommon - (drsvObjFailCommonJump + 1));
        b[drsvMetaFailCommonJump] = (byte)(drsvFailCommon - (drsvMetaFailCommonJump + 1));
        b.AddRange([0x31, 0xC0]); // xor eax, eax

        int drsvRet = b.Count;
        b[drsvRetOkJump] = (byte)(drsvRet - (drsvRetOkJump + 1));
        // Epilogue
        b.AddRange([0x48, 0x81, 0xC4, 0xB8, 0x02, 0x00, 0x00]);
        b.AddRange([0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelDynlibResolveBytes = b.Count - kernelDynlibResolveOff;

        // ============================================================================
        // __sp_kernel_dynlib_dlsym(edi = pid, esi = handle, rdx = name) -> rax
        //
        // kernel_dynlib_dlsym (58 bytes): NID-encodes a plain C name, then resolves via kernel_dynlib_resolve.
        // Encodes the plain name to NID via nid_encode, then resolves via
        // kernel_dynlib_resolve. Returns the resolved address or 0.
        //
        // Register plan (callee-saved):
        //   rbx  = handle
        //   r14d = pid
        //   r15  = &nid_buf[12] on stack at [rbp-0x24]
        //
        // Frame: sub $0x18 (24 bytes: nid_buf 12 + alignment padding)
        // ============================================================================
        int kernelDynlibDlsymOff = b.Count;
        _currentRelocs = _kernelDynlibDlsymRelocs;

        // push rbp ; mov rbp, rsp ; push r15 ; push r14 ; push rbx ; sub rsp, 0x18
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x48, 0x83, 0xEC, 0x18]);
        // mov ebx, esi                     ; save handle
        b.AddRange([0x89, 0xF3]);
        // mov r14d, edi                    ; save pid
        b.AddRange([0x41, 0x89, 0xFE]);
        // lea r15, [rbp-0x24]              ; nid_buf pointer
        b.AddRange([0x4C, 0x8D, 0x7D, 0xDC]);
        // mov rdi, rdx                     ; name (first arg to nid_encode)
        b.AddRange([0x48, 0x89, 0xD7]);
        // mov rsi, r15                     ; &nid_buf (second arg to nid_encode)
        b.AddRange([0x4C, 0x89, 0xFE]);
        // addr32 call nid_encode           ; 0x67 prefix + E8 rel32
        b.Add(0x67);
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int ddlsymNidCall = b.Count - 4;
        // mov edi, r14d                    ; pid
        b.AddRange([0x44, 0x89, 0xF7]);
        // mov esi, ebx                     ; handle
        b.AddRange([0x89, 0xDE]);
        // mov rdx, r15                     ; nid
        b.AddRange([0x4C, 0x89, 0xFA]);
        // call kernel_dynlib_resolve       ; plain call (no addr32 prefix)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]); int ddlsymResolveCall = b.Count - 4;
        // add rsp, 0x18 ; pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x18, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _kernelDynlibDlsymBytes = b.Count - kernelDynlibDlsymOff;

        // ============================================================================
        // __sp_patch_init() -> int
        //
        // __patch_init: patches the current process's ucred
        // capabilities/attributes and syscall address restrictions using kernel R/W.
        //
        // 1. patch_kernel_ucred:
        //    - kernel_get_proc(getpid()) -> proc
        //    - kernel_copyout(proc+0x40, &ucred, 8) -> ucred address
        //    - kernel_copyout(ucred+0x60, caps, 16) -> read caps
        //    - caps[5]=0x1c, caps[7]=0x40, caps[15]|=0x40
        //    - kernel_copyin(caps, ucred+0x60, 16) -> write caps
        //    - kernel_copyout(ucred+0x80, attrs, 32) -> read attrs
        //    - attrs[3]|=0x80
        //    - kernel_copyin(attrs, ucred+0x80, 32) -> write attrs
        //
        // 2. patch_syscall_permissions:
        //    - kernel_copyout(proc+0x3e8, &kaddr, 8) -> dynlib head
        //    - kernel_copyin(&zero, kaddr+0xf0, 8) -> lowest syscall addr = 0
        //    - kernel_copyin(&neg1, kaddr+0xf8, 8) -> highest syscall addr = -1
        // ============================================================================
        int patchInitOff = b.Count;
        _currentRelocs = _patchInitRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push r12 ; sub rsp, 0x50
        //
        // Frame layout (after push rbx + push r12 each consume 8 bytes below rbp):
        //   [rbp-0x08]  saved rbx
        //   [rbp-0x10]  saved r12
        //   [rbp-0x20]  ucred pointer (8 bytes)
        //   [rbp-0x28]  kaddr (8 bytes)
        //   [rbp-0x30]  zero/neg1 scratch (8 bytes)
        //   [rbp-0x40]  caps[16]
        //   [rbp-0x50]  attrs[32]
        //
        // The previous frame used sub rsp, 0x40 with locals starting at [rbp-0x10], which
        // placed the ucred slot directly on top of the saved r12 register. When
        // kernel_copyout wrote the ucred kernel address into [rbp-0x10], it overwrote saved
        // r12, and the epilogue popped a kernel address back into r12 - which _start then
        // dereferenced as args[0x28], faulting on a kernel-memory protection violation.
        // push rbp ; mov rbp, rsp ; push r14 ; push rbx ; sub rsp, 0x50
        // Callee-saved set: r14 + rbx (not r12 + rbx).
        // Frame is larger than the minimal version because the ucred helpers are inlined.
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53, 0x48, 0x83, 0xEC, 0x50]);

        // Get current PID: __sp_crt_syscall(SYS_getpid=20)
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]);         // mov edi, 20
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.Add(0x67);                                          // addr32 prefix (addr32 near-call encoding)
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_crt_syscall
        int piGetpidDisp = b.Count - 4;
        b.AddRange([0x89, 0xC7]);                            // mov edi, eax (pid)

        // kernel_get_proc(pid) -> rax = proc kaddr
        b.Add(0x67);                                          // addr32 prefix
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_get_proc
        int piGetProcDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                      // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);               // jz .Lpi_fail
        int piFailJump1 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC3]);                      // mov rbx, rax (proc)

        // ---- patch_kernel_ucred ----
        // Read ucred pointer: kernel_copyout(proc+0x40, &ucred, 8)
        b.AddRange([0x48, 0x8D, 0x7B, 0x40]);               // lea rdi, [rbx+0x40]
        b.AddRange([0x4C, 0x8D, 0x75, 0xE0]);               // lea r14, [rbp-0x20] (ucred local)
        b.AddRange([0x4C, 0x89, 0xF6]);                      // mov rsi, r14
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);         // mov edx, 8
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyout
        int piCopyout1Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                            // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);               // jnz .Lpi_fail
        int piFailJump2 = b.Count - 4;

        // r14 = ucred kaddr
        b.AddRange([0x4C, 0x8B, 0x75, 0xE0]);               // mov r14, [rbp-0x20]

        // Read caps[16]: kernel_copyout(ucred+0x60, &caps, 16)
        b.AddRange([0x4C, 0x89, 0xF7]);                      // mov rdi, r14
        b.AddRange([0x48, 0x83, 0xC7, 0x60]);               // add rdi, 0x60
        b.AddRange([0x48, 0x8D, 0x75, 0xC0]);               // lea rsi, [rbp-0x40] (caps)
        b.AddRange([0xBA, 0x10, 0x00, 0x00, 0x00]);         // mov edx, 16
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyout
        int piCopyout2Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump3 = b.Count - 4;

        // Patch caps: [5]=0x1c, [7]=0x40, [15]|=0x40
        b.AddRange([0xC6, 0x45, 0xC5, 0x1C]);               // mov byte [rbp-0x3B], 0x1c (caps[5])
        b.AddRange([0xC6, 0x45, 0xC7, 0x40]);               // mov byte [rbp-0x39], 0x40 (caps[7])
        b.AddRange([0x80, 0x4D, 0xCF, 0x40]);               // or byte [rbp-0x31], 0x40 (caps[15])

        // Write caps: kernel_copyin(&caps, ucred+0x60, 16)
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]);               // lea rdi, [rbp-0x40] (uaddr = caps)
        b.AddRange([0x4C, 0x89, 0xF6]);                      // mov rsi, r14
        b.AddRange([0x48, 0x83, 0xC6, 0x60]);               // add rsi, 0x60 (kaddr = ucred+0x60)
        b.AddRange([0xBA, 0x10, 0x00, 0x00, 0x00]);         // mov edx, 16
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyin
        int piCopyin1Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump4 = b.Count - 4;

        // Read attrs[32]: kernel_copyout(ucred+0x80, &attrs, 32)
        b.AddRange([0x4C, 0x89, 0xF7]);                      // mov rdi, r14
        b.AddRange([0x48, 0x81, 0xC7, 0x80, 0x00, 0x00, 0x00]); // add rdi, 0x80
        b.AddRange([0x48, 0x8D, 0x75, 0xB0]);               // lea rsi, [rbp-0x50] (attrs)
        b.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]);         // mov edx, 32
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyout
        int piCopyout3Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump5 = b.Count - 4;

        // Patch attrs: [3]|=0x80 (ptrace)
        b.AddRange([0x80, 0x4D, 0xB3, 0x80]);               // or byte [rbp-0x4D], 0x80 (attrs[3])

        // Write attrs: kernel_copyin(&attrs, ucred+0x80, 32)
        b.AddRange([0x48, 0x8D, 0x7D, 0xB0]);               // lea rdi, [rbp-0x50]
        b.AddRange([0x4C, 0x89, 0xF6]);                      // mov rsi, r14
        b.AddRange([0x48, 0x81, 0xC6, 0x80, 0x00, 0x00, 0x00]); // add rsi, 0x80
        b.AddRange([0xBA, 0x20, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyin
        int piCopyin2Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump6 = b.Count - 4;

        // ---- patch_syscall_permissions ----
        // Read dynlib head: kernel_copyout(proc+0x3e8, &kaddr, 8)
        b.AddRange([0x48, 0x8D, 0xBB, 0xE8, 0x03, 0x00, 0x00]); // lea rdi, [rbx+0x3e8]
        b.AddRange([0x48, 0x8D, 0x75, 0xD8]);               // lea rsi, [rbp-0x28] (kaddr)
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyout
        int piCopyout4Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump7 = b.Count - 4;

        // Set lowest syscall address to 0: kernel_copyin(&zero, kaddr+0xf0, 8)
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0x30], 0
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);               // lea rdi, [rbp-0x30] (uaddr = &zero)
        b.AddRange([0x48, 0x8B, 0x75, 0xD8]);               // mov rsi, [rbp-0x28] (kaddr)
        b.AddRange([0x48, 0x81, 0xC6, 0xF0, 0x00, 0x00, 0x00]); // add rsi, 0xf0
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyin
        int piCopyin3Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump8 = b.Count - 4;

        // Set highest syscall address to -1: kernel_copyin(&neg1, kaddr+0xf8, 8)
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF]); // mov qword [rbp-0x30], -1
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);
        b.AddRange([0x48, 0x8B, 0x75, 0xD8]);
        b.AddRange([0x48, 0x81, 0xC6, 0xF8, 0x00, 0x00, 0x00]); // add rsi, 0xf8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]);                     // call __sp_kernel_copyin
        int piCopyin4Disp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int piFailJump9 = b.Count - 4;

        // Success: return 0
        b.AddRange([0x31, 0xC0]);
        b.AddRange([0xEB, 0x05]);

        // .Lpi_fail: return -1
        int piFail = b.Count;
        WriteRel32InBLocal(piFailJump1, piFail);
        WriteRel32InBLocal(piFailJump2, piFail);
        WriteRel32InBLocal(piFailJump3, piFail);
        WriteRel32InBLocal(piFailJump4, piFail);
        WriteRel32InBLocal(piFailJump5, piFail);
        WriteRel32InBLocal(piFailJump6, piFail);
        WriteRel32InBLocal(piFailJump7, piFail);
        WriteRel32InBLocal(piFailJump8, piFail);
        WriteRel32InBLocal(piFailJump9, piFail);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);         // mov eax, -1

        // Epilogue: add rsp, 0x50 ; pop rbx ; pop r14 ; pop rbp ; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x50, 0x5B, 0x41, 0x5E, 0x5D, 0xC3]);
        _patchInitBytes = b.Count - patchInitOff;

        // ============================================================================
        // __sp_klog_init() -> int
        //
        // __klog_init: resolves the klog runtime's own
        // dependencies (snprintf, vsnprintf, strerror, __error) from libSceLibcInternal
        // (handle 0x2) via the kernel-based resolver.
        // ============================================================================
        int klogInitOff = b.Count;
        _currentRelocs = _klogInitRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);

        // Helper: resolve one symbol via kernel_dynlib_dlsym(-1, handle, name)
        var klFailJumps = new List<int>();
        void EmitKlogResolve(RelocSymbol bssSym, int handle, out int callDisp, out int leaAt)
        {
            b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+name]
            leaAt = b.Count - 4;
            b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov ebx, -1  (default return)
            b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1  (pid = current)
            b.AddRange([0xBE, (byte)(handle & 0xFF), (byte)((handle >> 8) & 0xFF),
                              (byte)((handle >> 16) & 0xFF), (byte)((handle >> 24) & 0xFF)]); // mov esi, handle
            b.Add(0x67);                                      // addr32 prefix
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __sp_kernel_dynlib_dlsym
            callDisp = b.Count - 4;
            b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+bss], rax
            AddRel(bssSym, b.Count - 4);
            b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
            b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);            // jz .Lfail
            klFailJumps.Add(b.Count - 4);
        }

        EmitKlogResolve(RelocSymbol.KlogSnprintf, 0x2, out int klSnprintfCallDisp, out int klSnprintfLeaAt);
        EmitKlogResolve(RelocSymbol.KlogStrerror, 0x2, out int klStrerrorCallDisp, out int klStrerrorLeaAt);
        EmitKlogResolve(RelocSymbol.KlogVsnprintf, 0x2, out int klVsnprintfCallDisp, out int klVsnprintfLeaAt);

        // __error: try handle 0x1 first, then 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+__error]
        int klErrorLeaAt1 = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);          // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);          // mov esi, 0x1
        b.Add(0x67);                                          // addr32 prefix
        b.AddRange([0xE8, 0, 0, 0, 0]);                      // call __sp_kernel_dynlib_dlsym
        int klErrorCallDisp1 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);          // mov [rip+__sp_klog_error], rax
        AddRel(RelocSymbol.KlogError, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                      // test rax, rax
        b.AddRange([0x75, 0x00]);                             // jnz .Lgot_error (short jump)
        int klGotErrorJump = b.Count - 1;
        // Fallback: handle 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        int klErrorLeaAt2 = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);          // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);          // mov esi, 0x2001
        b.Add(0x67);                                          // addr32 prefix
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int klErrorCallDisp2 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);          // mov [rip+__sp_klog_error], rax
        AddRel(RelocSymbol.KlogError, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                      // test rax, rax
        b.AddRange([0x74, 0x02]);                             // jz .Lfail_path
        // .Lgot_error:
        int klGotError = b.Count;
        b[klGotErrorJump] = (byte)(klGotError - (klGotErrorJump + 1));
        b.AddRange([0x31, 0xDB]);                             // xor ebx, ebx  (success: ebx = 0)

        // .Lret: mov eax, ebx ; add rsp, 8 ; pop rbx ; pop rbp ; ret
        int klRet = b.Count;
        b.AddRange([0x89, 0xD8]);                             // mov eax, ebx
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        // Patch all fail jumps to reach .Lret (ebx is already -1 from last resolve)
        // If any resolve fails, ebx stays -1 and execution falls through to .Lret.
        // The failure jumps target a landing right before .Lret where ebx is already -1.
        int klFail = klRet; // failure path lands at .Lret with ebx=-1 (never cleared to 0)
        foreach (int at in klFailJumps) WriteRel32InBLocal(at, klFail);
        _klogInitBytes = b.Count - klogInitOff;

        // ============================================================================
        // klog_puts(rdi = const char* s) -> int
        //
        // klog_puts: inlines klog_label: getpid -> syscall
        // 0x268 to get process name -> snprintf fallback "pid:%d". Then formats
        // "<118>[label] msg\n" via snprintf and writes to /dev/klog via SYS_kexec.
        // Matches
        // ============================================================================
        int klogPutsOff = b.Count;
        _currentRelocs = _klogFuncsRelocs;

        // Prologue: push rbp; mov rbp, rsp; push r15; push r14; push r12; push rbx; sub rsp, 0x220
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53,
                    0x48, 0x81, 0xEC, 0x20, 0x02, 0x00, 0x00]);
        // mov rbx, rdi (save msg)
        b.AddRange([0x48, 0x89, 0xFB]);

        // ---- klog_label inlined ----
        // SYS_getpid via crt_syscall(20)
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]);         // mov edi, 0x14
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int kpGetpidDisp = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC6]);                      // mov r14, rax (pid)
        b.AddRange([0xC6, 0x45, 0xC0, 0x00]);               // mov byte [rbp-0x40], 0
        // syscall(0x268, pid, lbl, 0x20) via crt_syscall
        b.AddRange([0x48, 0x8D, 0x55, 0xC0]);               // lea rdx, [rbp-0x40]
        b.AddRange([0xBF, 0x68, 0x02, 0x00, 0x00]);         // mov edi, 0x268
        b.AddRange([0xB9, 0x20, 0x00, 0x00, 0x00]);         // mov ecx, 0x20
        b.AddRange([0x44, 0x89, 0xF6]);                      // mov esi, r14d
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int kpThrNameDisp = b.Count - 4;
        // cmpb $0, [rbp-0x40]; jne .Lgot_label
        b.AddRange([0x80, 0x7D, 0xC0, 0x00]);               // cmpb $0, [rbp-0x40]
        b.AddRange([0x75, 0x00]);                            // jne .Lgot_label (patch below)
        int kpGotLabelJump = b.Count - 1;
        // snprintf fallback: snprintf(lbl, 0x20, "pid:%d", pid)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+"pid:%d"]
        int kpPidFmtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]);               // lea rdi, [rbp-0x40]
        b.AddRange([0xBE, 0x20, 0x00, 0x00, 0x00]);         // mov esi, 0x20
        b.AddRange([0x44, 0x89, 0xF1]);                      // mov ecx, r14d
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+snprintf]
        AddRel(RelocSymbol.KlogSnprintf, b.Count - 4);
        // .Lgot_label:
        int kpGotLabel = b.Count;
        b[kpGotLabelJump] = (byte)(kpGotLabel - (kpGotLabelJump + 1));

        // snprintf(buf, 0x200, "<118>[%s] %s\n", lbl, msg)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+fmt]
        int kpPutsFmtLeaAt = b.Count - 4;
        b.AddRange([0x4C, 0x8D, 0xB5, 0xC0, 0xFD, 0xFF, 0xFF]); // lea r14, [rbp-0x240]
        b.AddRange([0x48, 0x8D, 0x4D, 0xC0]);               // lea rcx, [rbp-0x40]
        b.AddRange([0xBE, 0x00, 0x02, 0x00, 0x00]);         // mov esi, 0x200
        b.AddRange([0x4C, 0x89, 0xF7]);                      // mov rdi, r14
        b.AddRange([0x49, 0x89, 0xD8]);                      // mov r8, rbx
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+snprintf]
        AddRel(RelocSymbol.KlogSnprintf, b.Count - 4);

        // SYS_kexec(0x259, 7, buf, 0) via crt_syscall
        b.AddRange([0xBF, 0x59, 0x02, 0x00, 0x00]);         // mov edi, 0x259
        b.AddRange([0xBE, 0x07, 0x00, 0x00, 0x00]);         // mov esi, 7
        b.AddRange([0x4C, 0x89, 0xF2]);                      // mov rdx, r14
        b.AddRange([0x31, 0xC9]);                            // xor ecx, ecx
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int kpKexecDisp = b.Count - 4;

        // Epilogue
        b.AddRange([0x48, 0x81, 0xC4, 0x20, 0x02, 0x00, 0x00]); // add rsp, 0x220
        b.AddRange([0x5B]);                                   // pop rbx
        b.AddRange([0x41, 0x5C]);                            // pop r12
        b.AddRange([0x41, 0x5E]);                            // pop r14
        b.AddRange([0x41, 0x5F]);                            // pop r15
        b.AddRange([0x5D]);                                   // pop rbp
        b.AddRange([0xC3]);                                   // ret
        _klogPutsBytes = b.Count - klogPutsOff;

        // ============================================================================
        // klog_perror(rdi = const char* s) -> int
        //
        // klog_perror: inlines klog_label (same as klog_puts),
        // then calls __error() to get errno, strerror(errno) to get the error string,
        // and formats "<118>[label] msg: errstr\n" via snprintf.
        // Matches
        // ============================================================================
        int klogPerrorOff = b.Count;

        // Prologue (same as klog_puts)
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x53,
                    0x48, 0x81, 0xEC, 0x20, 0x02, 0x00, 0x00]);
        b.AddRange([0x48, 0x89, 0xFB]);                      // mov rbx, rdi (save msg)

        // ---- klog_label inlined ----
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]);         // mov edi, 0x14
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int keGetpidDisp = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC6]);                      // mov r14, rax
        b.AddRange([0xC6, 0x45, 0xC0, 0x00]);               // mov byte [rbp-0x40], 0
        b.AddRange([0x48, 0x8D, 0x55, 0xC0]);               // lea rdx, [rbp-0x40]
        b.AddRange([0xBF, 0x68, 0x02, 0x00, 0x00]);         // mov edi, 0x268
        b.AddRange([0xB9, 0x20, 0x00, 0x00, 0x00]);         // mov ecx, 0x20
        b.AddRange([0x44, 0x89, 0xF6]);                      // mov esi, r14d
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int keThrNameDisp = b.Count - 4;
        b.AddRange([0x80, 0x7D, 0xC0, 0x00]);               // cmpb $0, [rbp-0x40]
        b.AddRange([0x75, 0x00]);                            // jne .Lgot_label
        int keGotLabelJump = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+"pid:%d"]
        int kePidFmtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x7D, 0xC0]);               // lea rdi, [rbp-0x40]
        b.AddRange([0xBE, 0x20, 0x00, 0x00, 0x00]);         // mov esi, 0x20
        b.AddRange([0x44, 0x89, 0xF1]);                      // mov ecx, r14d
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+snprintf]
        AddRel(RelocSymbol.KlogSnprintf, b.Count - 4);
        int keGotLabel = b.Count;
        b[keGotLabelJump] = (byte)(keGotLabel - (keGotLabelJump + 1));

        // ---- errno + strerror ----
        // call __error() -> rax = int* errno_ptr
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+__error]
        AddRel(RelocSymbol.KlogError, b.Count - 4);
        b.AddRange([0x8B, 0x38]);                            // mov edi, [rax] (errno value)
        // call strerror(errno) -> rax = error string
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+strerror]
        AddRel(RelocSymbol.KlogStrerror, b.Count - 4);

        // snprintf(buf, 0x200, "<118>[%s] %s: %s\n", lbl, msg, errstr)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+fmt]
        int kePerrorFmtLeaAt = b.Count - 4;
        b.AddRange([0x4C, 0x8D, 0xB5, 0xC0, 0xFD, 0xFF, 0xFF]); // lea r14, [rbp-0x240]
        b.AddRange([0x48, 0x8D, 0x4D, 0xC0]);               // lea rcx, [rbp-0x40]
        b.AddRange([0xBE, 0x00, 0x02, 0x00, 0x00]);         // mov esi, 0x200
        b.AddRange([0x4C, 0x89, 0xF7]);                      // mov rdi, r14
        b.AddRange([0x49, 0x89, 0xD8]);                      // mov r8, rbx  (msg)
        b.AddRange([0x49, 0x89, 0xC1]);                      // mov r9, rax  (errstr)
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+snprintf]
        AddRel(RelocSymbol.KlogSnprintf, b.Count - 4);

        // SYS_kexec
        b.AddRange([0xBF, 0x59, 0x02, 0x00, 0x00]);         // mov edi, 0x259
        b.AddRange([0xBE, 0x07, 0x00, 0x00, 0x00]);         // mov esi, 7
        b.AddRange([0x4C, 0x89, 0xF2]);                      // mov rdx, r14
        b.AddRange([0x31, 0xC9]);                            // xor ecx, ecx
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int keKexecDisp = b.Count - 4;

        // Epilogue
        b.AddRange([0x48, 0x81, 0xC4, 0x20, 0x02, 0x00, 0x00]);
        b.AddRange([0x5B, 0x41, 0x5C, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _klogPerrorBytes = b.Count - klogPerrorOff;

        // ============================================================================
        // klog_printf(rdi = const char* fmt, ...) -> int
        //
        // klog_printf: saves register args into the System V
        // AMD64 register save area, builds a va_list, calls vsnprintf to format the
        // variadic args, then inlines klog_label and formats "<118>[label] sargs"
        // via snprintf, and writes to /dev/klog via SYS_kexec.
        // Matches
        //
        // Stack layout (rbp-relative, after push r15/r14/rbx + sub rsp 0x4f8):
        //   [rbp-0x18]  saved rbx
        //   [rbp-0x10]  saved r14
        //   [rbp-0x08]  saved r15
        //   [rbp-0x20]  va_list.reg_save_area
        //   [rbp-0x28]  va_list.overflow_arg_area
        //   [rbp-0x30]  va_list.gp_offset + fp_offset (packed 8 bytes)
        //   [rbp-0x50]  lbl[32]
        //   [rbp-0x60]..[rbp-0xd0]  xmm0..xmm7 save area
        //   [rbp-0xd8]..[rbp-0xf8]  r9..rsi save area
        //   [rbp-0x100] register save area start
        //   [rbp-0x300] sargs[0x200]
        //   [rbp-0x510] buf[0x210]
        // ============================================================================
        int klogPrintfOff = b.Count;

        // Prologue: push rbp; mov rbp, rsp; push r15; push r14; push rbx; sub rsp, 0x4f8
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53,
                    0x48, 0x81, 0xEC, 0xF8, 0x04, 0x00, 0x00]);

        // Save fmt in r10 (caller-clobbered, but survives until vsnprintf call)
        b.AddRange([0x49, 0x89, 0xFA]);                      // mov r10, rdi

        // Save GP register args to register save area
        b.AddRange([0x48, 0x89, 0xB5, 0x08, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xf8], rsi
        b.AddRange([0x48, 0x89, 0x95, 0x10, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xf0], rdx
        b.AddRange([0x48, 0x89, 0x8D, 0x18, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xe8], rcx
        b.AddRange([0x4C, 0x89, 0x85, 0x20, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xe0], r8
        b.AddRange([0x4C, 0x89, 0x8D, 0x28, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xd8], r9

        // Conditionally save FP register args (test al, al; je skip_fp)
        b.AddRange([0x84, 0xC0]);                            // test al, al
        b.AddRange([0x74, 0x37]);                            // je .Lskip_fp (55 bytes of FP saves)
        // vmovaps [rbp-0xd0], xmm0 through xmm7 (VEX-encoded)
        b.AddRange([0xC5, 0xF8, 0x29, 0x85, 0x30, 0xFF, 0xFF, 0xFF]); // vmovaps [rbp-0xd0], xmm0
        b.AddRange([0xC5, 0xF8, 0x29, 0x8D, 0x40, 0xFF, 0xFF, 0xFF]); // vmovaps [rbp-0xc0], xmm1
        b.AddRange([0xC5, 0xF8, 0x29, 0x95, 0x50, 0xFF, 0xFF, 0xFF]); // vmovaps [rbp-0xb0], xmm2
        b.AddRange([0xC5, 0xF8, 0x29, 0x9D, 0x60, 0xFF, 0xFF, 0xFF]); // vmovaps [rbp-0xa0], xmm3
        b.AddRange([0xC5, 0xF8, 0x29, 0xA5, 0x70, 0xFF, 0xFF, 0xFF]); // vmovaps [rbp-0x90], xmm4
        b.AddRange([0xC5, 0xF8, 0x29, 0x6D, 0x80]);         // vmovaps [rbp-0x80], xmm5
        b.AddRange([0xC5, 0xF8, 0x29, 0x75, 0x90]);         // vmovaps [rbp-0x70], xmm6
        b.AddRange([0xC5, 0xF8, 0x29, 0x7D, 0xA0]);         // vmovaps [rbp-0x60], xmm7
        // .Lskip_fp:

        // Zero sargs[0x200] buffer using YMM (16 x 32-byte stores = 512 bytes)
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);               // vxorps xmm0, xmm0, xmm0
        int[] sargsZeroOffs = [-0x120, -0x140, -0x160, -0x180, -0x1A0, -0x1C0, -0x1E0, -0x200,
                               -0x220, -0x240, -0x260, -0x280, -0x2A0, -0x2C0, -0x2E0, -0x300];
        foreach (int off in sargsZeroOffs)
        {
            b.AddRange([0xC5, 0xFC, 0x11, 0x85,
                        (byte)(off & 0xFF), (byte)((off >> 8) & 0xFF), (byte)((off >> 16) & 0xFF), (byte)((off >> 24) & 0xFF)]);
        }

        // Build va_list at [rbp-0x30]:
        //   gp_offset = 8 (rdi consumed), fp_offset = 48 (0x30)
        //   overflow_arg_area = rbp + 0x10
        //   reg_save_area = rbp - 0x100
        b.AddRange([0x48, 0x8D, 0x85, 0x00, 0xFF, 0xFF, 0xFF]); // lea rax, [rbp-0x100]
        b.AddRange([0x48, 0x89, 0x45, 0xE0]);               // mov [rbp-0x20], rax (reg_save_area)
        b.AddRange([0x48, 0x8D, 0x45, 0x10]);               // lea rax, [rbp+0x10]
        b.AddRange([0x48, 0x89, 0x45, 0xD8]);               // mov [rbp-0x28], rax (overflow_arg_area)
        b.AddRange([0x48, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00]); // movabs rax, 0x3000000008
        b.AddRange([0x48, 0x89, 0x45, 0xD0]);               // mov [rbp-0x30], rax (gp/fp_offset)

        // vsnprintf(sargs, 0x200, fmt, &va_list)
        b.AddRange([0x48, 0x8D, 0xBD, 0x00, 0xFD, 0xFF, 0xFF]); // lea rdi, [rbp-0x300] (sargs)
        b.AddRange([0x48, 0x8D, 0x4D, 0xD0]);               // lea rcx, [rbp-0x30] (&va_list)
        b.AddRange([0xBE, 0x00, 0x02, 0x00, 0x00]);         // mov esi, 0x200
        b.AddRange([0x4C, 0x89, 0xD2]);                      // mov rdx, r10 (fmt)
        b.AddRange([0xC5, 0xF8, 0x77]);                      // vzeroupper
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+vsnprintf]
        AddRel(RelocSymbol.KlogVsnprintf, b.Count - 4);

        // ---- klog_label inlined ----
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]);         // mov edi, 0x14
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int kfGetpidDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC3]);                      // mov rbx, rax (pid)
        b.AddRange([0xC6, 0x45, 0xB0, 0x00]);               // mov byte [rbp-0x50], 0
        b.AddRange([0x48, 0x8D, 0x55, 0xB0]);               // lea rdx, [rbp-0x50]
        b.AddRange([0xBF, 0x68, 0x02, 0x00, 0x00]);         // mov edi, 0x268
        b.AddRange([0xB9, 0x20, 0x00, 0x00, 0x00]);         // mov ecx, 0x20
        b.AddRange([0x89, 0xDE]);                            // mov esi, ebx
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int kfThrNameDisp = b.Count - 4;
        b.AddRange([0x80, 0x7D, 0xB0, 0x00]);               // cmpb $0, [rbp-0x50]
        b.AddRange([0x75, 0x00]);                            // jne .Lgot_label
        int kfGotLabelJump = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+"pid:%d"]
        int kfPidFmtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x7D, 0xB0]);               // lea rdi, [rbp-0x50]
        b.AddRange([0xBE, 0x20, 0x00, 0x00, 0x00]);         // mov esi, 0x20
        b.AddRange([0x89, 0xD9]);                            // mov ecx, ebx
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+snprintf]
        AddRel(RelocSymbol.KlogSnprintf, b.Count - 4);
        int kfGotLabel = b.Count;
        b[kfGotLabelJump] = (byte)(kfGotLabel - (kfGotLabelJump + 1));

        // snprintf(buf, 0x210, "<118>[%s] %s", lbl, sargs)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);         // lea rdx, [rip+fmt]
        int kfPrintfFmtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x9D, 0xF0, 0xFA, 0xFF, 0xFF]); // lea rbx, [rbp-0x510]
        b.AddRange([0x48, 0x8D, 0x4D, 0xB0]);               // lea rcx, [rbp-0x50]
        b.AddRange([0x4C, 0x8D, 0x85, 0x00, 0xFD, 0xFF, 0xFF]); // lea r8, [rbp-0x300] (sargs)
        b.AddRange([0xBE, 0x10, 0x02, 0x00, 0x00]);         // mov esi, 0x210
        b.AddRange([0x48, 0x89, 0xDF]);                      // mov rdi, rbx (buf)
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);               // call qword [rip+snprintf]
        AddRel(RelocSymbol.KlogSnprintf, b.Count - 4);

        // SYS_kexec
        b.AddRange([0xBF, 0x59, 0x02, 0x00, 0x00]);         // mov edi, 0x259
        b.AddRange([0xBE, 0x07, 0x00, 0x00, 0x00]);         // mov esi, 7
        b.AddRange([0x48, 0x89, 0xDA]);                      // mov rdx, rbx
        b.AddRange([0x31, 0xC9]);                            // xor ecx, ecx
        b.AddRange([0x31, 0xC0]);                            // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);               // addr32 call crt_syscall
        int kfKexecDisp = b.Count - 4;

        // Epilogue
        b.AddRange([0x48, 0x81, 0xC4, 0xF8, 0x04, 0x00, 0x00]); // add rsp, 0x4f8
        b.AddRange([0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _klogPrintfBytes = b.Count - klogPrintfOff;

        // ============================================================================
        // __sp_rtld_init() -> int
        //
        // __rtld_init: resolves 9 basic libc functions
        // from handle 0x2, then calls sprx_init, so_init, payload_init, and
        // tail-jumps dlfcn_init.
        // ============================================================================
        int rtldInitOff = b.Count;
        _currentRelocs = _rtldInitRelocs;

        // push rbp ; mov rbp, rsp ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);

        // Resolve 9 symbols: strcpy, strcat, strcmp, strncmp, strlen, sprintf, calloc, free, getenv
        // First 6 use near jz (0F 84), last 3 use short jz (74).
        var rtldCallDisps = new List<int>();
        var rtldLeaAts = new List<int>();
        var rtldFailJumps = new List<int>();
        var rtldShortFailJumps = new List<int>();
        bool rtldFirstResolve = true;
        void EmitRtldResolve(RelocSymbol bssSym, bool useShortJz = false)
        {
            b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+name]
            rtldLeaAts.Add(b.Count - 4);
            if (rtldFirstResolve)
            {
                b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);  // mov ebx, -1  (once only)
                rtldFirstResolve = false;
            }
            b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1  (pid)
            b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2 (handle)
            b.Add(0x67);                                      // addr32 prefix
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __sp_kernel_dynlib_dlsym
            rtldCallDisps.Add(b.Count - 4);
            b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+bss], rax
            AddRel(bssSym, b.Count - 4);
            b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
            if (useShortJz)
            {
                b.AddRange([0x74, 0x00]);                     // jz .Lfail (short, patch below)
                rtldShortFailJumps.Add(b.Count - 1);
            }
            else
            {
                b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);        // jz .Lfail (near, patch below)
                rtldFailJumps.Add(b.Count - 4);
            }
        }
        EmitRtldResolve(RelocSymbol.RtldStrcpy);                  // 0: strcpy  (near jz)
        EmitRtldResolve(RelocSymbol.RtldStrcat);                  // 1: strcat  (near jz)
        EmitRtldResolve(RelocSymbol.RtldStrcmp);                  // 2: strcmp  (near jz)
        EmitRtldResolve(RelocSymbol.RtldStrncmp);                 // 3: strncmp (near jz)
        EmitRtldResolve(RelocSymbol.RtldStrlen);                  // 4: strlen  (near jz)
        EmitRtldResolve(RelocSymbol.RtldSprintf);                 // 5: sprintf (near jz)
        EmitRtldResolve(RelocSymbol.RtldCalloc);                     // 6: calloc  (near jz; rel8 overflows with gated breadcrumbs)
        EmitRtldResolve(RelocSymbol.RtldFree, useShortJz: true);    // 7: free    (short jz)
        EmitRtldResolve(RelocSymbol.RtldGetenv, useShortJz: true);  // 8: getenv  (short jz)

        // After 9 resolves succeed, call the 4 subsystem inits.
        int bcRtldSprxInitLeaAt = -1, bcRtldSprxInitCallDisp = -1;
        int bcRtldSoInitLeaAt = -1, bcRtldSoInitCallDisp = -1;
        int bcRtldPayloadInitStartLeaAt = -1, bcRtldPayloadInitStartCallDisp = -1;
        int bcRtldPayloadInitDoneLeaAt = -1, bcRtldPayloadInitDoneCallDisp = -1;
        int bcRtldDlfcnInitLeaAt = -1, bcRtldDlfcnInitCallDisp = -1;

        // sp:rtld:sprx:init
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);     // lea rdi, [rip+sp_rtld_sprx_init]
            bcRtldSprxInitLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __prospero_klog
            bcRtldSprxInitCallDisp = b.Count - 4;
        }

        // addr32 call __rtld_sprx_init
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                // addr32 call sprx_init
        int rtCallSprxInitDisp = b.Count - 4;
        b.AddRange([0x89, 0xC3]);                             // mov ebx, eax
        b.AddRange([0x85, 0xC0]);                             // test eax, eax
        b.AddRange([0x75, 0x00]);                             // jne .Lfail (patch below)
        int rtSprxFailJumpAt = b.Count - 1;

        // sp:rtld:so:init
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);     // lea rdi, [rip+sp_rtld_so_init]
            bcRtldSoInitLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __prospero_klog
            bcRtldSoInitCallDisp = b.Count - 4;
        }

        // addr32 call __rtld_so_init
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                // addr32 call so_init
        int rtCallSoInitDisp = b.Count - 4;
        b.AddRange([0x89, 0xC3]);                             // mov ebx, eax
        b.AddRange([0x85, 0xC0]);                             // test eax, eax
        b.AddRange([0x75, 0x00]);                             // jne .Lfail (patch below)
        int rtSoFailJumpAt = b.Count - 1;

        // sp:rtld:payload:init:start
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);     // lea rdi, [rip+sp_rtld_payload_init_start]
            bcRtldPayloadInitStartLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __prospero_klog
            bcRtldPayloadInitStartCallDisp = b.Count - 4;
        }

        // addr32 call __rtld_payload_init
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                // addr32 call payload_init
        int rtCallPayloadInitDisp = b.Count - 4;
        b.AddRange([0x89, 0xC3]);                             // mov ebx, eax
        b.AddRange([0x85, 0xC0]);                             // test eax, eax
        b.AddRange([0x74, 0x00]);                             // je .Lsuccess (patch below)
        int rtSuccessJumpAt = b.Count - 1;

        // .Lfail: mov eax, ebx ; add rsp, 8 ; pop rbx ; pop rbp ; ret
        int rtFail = b.Count;
        b[rtSprxFailJumpAt] = (byte)(rtFail - (rtSprxFailJumpAt + 1));
        b[rtSoFailJumpAt] = (byte)(rtFail - (rtSoFailJumpAt + 1));
        b.AddRange([0x89, 0xD8]);                             // mov eax, ebx
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]); // add rsp,8; pop rbx; pop rbp; ret

        // .Lsuccess: breadcrumbs + epilogue + jmp dlfcn_init
        int rtSuccess = b.Count;
        b[rtSuccessJumpAt] = (byte)(rtSuccess - (rtSuccessJumpAt + 1));
        // sp:rtld:payload:init:done
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);     // lea rdi, [rip+sp_rtld_payload_init_done]
            bcRtldPayloadInitDoneLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __prospero_klog
            bcRtldPayloadInitDoneCallDisp = b.Count - 4;
        }
        // sp:rtld:dlfcn:init
        if (EmitDiagnosticBreadcrumbs)
        {
            b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);     // lea rdi, [rip+sp_rtld_dlfcn_init]
            bcRtldDlfcnInitLeaAt = b.Count - 4;
            b.AddRange([0xE8, 0, 0, 0, 0]);                  // call __prospero_klog
            bcRtldDlfcnInitCallDisp = b.Count - 4;
        }
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D]);    // add rsp,8; pop rbx; pop rbp
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp __rtld_dlfcn_init
        int rtTailJmpDlfcnInitDisp = b.Count - 4;
        b.Add(0x90);                                           // trailing NOP

        // Patch 6 near-jz fail jumps (resolves 0-5): all go to .Lfail
        foreach (int at in rtldFailJumps) WriteRel32InBLocal(at, rtFail);
        // Patch 3 short-jz fail jumps (resolves 6-8): all go to .Lfail
        foreach (int at in rtldShortFailJumps) b[at] = (byte)(rtFail - (at + 1));
        _rtldInitBytes = b.Count - rtldInitOff;

        // ============================================================================
        // DLFCN SUBSYSTEM — runtime library loading API
        //
        // Implements __dlopen/__dlsym/__dlclose/__dlerror and all transitive deps.
        // The 4 API functions follow the standard calling conventions; internal helpers are functionally equivalent.
        // ============================================================================
        _dlfcnRelocs = [];
        _currentRelocs = _dlfcnRelocs;

        // ---- __dlerror (24 bytes) ----
        int dlerrorOff = b.Count;
        b.AddRange([0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 4);
        b.AddRange([0x85, 0xFF, 0x74, 0x0B]);
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnStrerror, b.Count - 4);
        b.AddRange([0x31, 0xF6, 0xFF, 0xE0, 0x31, 0xC0, 0xC3]);
        _dlerrorBytes = b.Count - dlerrorOff;

        // ---- __dladdr (120 bytes, SDK rtld_dlfcn.c) ----
        // int __dladdr(void *addr, Dl_info *info)
        // Calls __rtld_lib_addr2lib(g_root, addr), fills Dl_info, returns 1 or 0.
        // Dl_info: dli_fname(8)=&lib->soname, dli_fbase(8)=mapbase, dli_sname(8), dli_saddr(8)
        // SDK uses r15=lib, r14=addr, rbx=info across calls (no redundant re-lookup).
        int dladdrOff = b.Count;
        // prologue: push rbp; mov rbp,rsp; push r15; push r14; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        b.AddRange([0x48, 0x89, 0xF3]);                              // mov rbx, rsi (info)
        b.AddRange([0x49, 0x89, 0xFE]);                              // mov r14, rdi (addr)
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);                 // mov rdi, [rip+g_root]
        AddRel(RelocSymbol.DlfcnRoot, b.Count - 4);
        b.AddRange([0x4C, 0x89, 0xF6]);                              // mov rsi, r14 (addr)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // addr32 call __rtld_lib_addr2lib
        int dladdrAddr2libDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x3C]);                                    // je .Lfail (+0x3c)
        // rax = lib; save in r15
        b.AddRange([0x49, 0x89, 0xC7]);                              // mov r15, rax
        b.AddRange([0x48, 0x83, 0xC0, 0x38]);                       // add rax, 0x38 (point to soname)
        b.AddRange([0x48, 0x89, 0x03]);                              // mov [rbx], rax (dli_fname = &soname)
        b.AddRange([0x49, 0x8B, 0x87, 0x38, 0x04, 0x00, 0x00]);     // mov rax, [r15+0x438] (mapbase)
        b.AddRange([0x48, 0x89, 0x43, 0x08]);                       // mov [rbx+8], rax (dli_fbase)
        // addr2sym(lib, addr) -> sname
        b.AddRange([0x4C, 0x89, 0xFF]);                              // mov rdi, r15 (lib)
        b.AddRange([0x4C, 0x89, 0xF6]);                              // mov rsi, r14 (addr)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // addr32 call __rtld_lib_addr2sym
        int dladdrAddr2symDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x10]);                       // mov [rbx+0x10], rax (dli_sname)
        // sym2addr(lib, sname) -> saddr  (r15 still holds lib)
        b.AddRange([0x4C, 0x89, 0xFF]);                              // mov rdi, r15 (lib)
        b.AddRange([0x48, 0x89, 0xC6]);                              // mov rsi, rax (sname)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // addr32 call __rtld_lib_sym2addr
        int dladdrSym2addrDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x18]);                       // mov [rbx+0x18], rax (dli_saddr)
        b.AddRange([0xB8, 0x01, 0x00, 0x00, 0x00]);                 // mov eax, 1 (success)
        b.AddRange([0xEB, 0x0C]);                                    // jmp .Lret (+0x0c)
        // .Lfail:
        b.AddRange([0xC7, 0x05, 0, 0, 0, 0, 0x16, 0x00, 0x00, 0x00]); // movl [rip+dlerrno], EINVAL
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 8, addend: -8);
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax (0)
        // .Lret: add rsp,8; pop rbx; pop r14; pop r15; pop rbp; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _dladdrBytes = b.Count - dladdrOff;
        _dladdrOff = dladdrOff;

        // ---- __rtld_dlfcn_setroot (8 bytes) ----
        int dlfcnSetrootOff = b.Count;
        b.AddRange([0x48, 0x89, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnRoot, b.Count - 4);
        b.AddRange([0xC3]);
        _dlfcnSetrootBytes = b.Count - dlfcnSetrootOff;

        // ---- __rtld_lib_destroy (9 bytes) ----
        int libDestroyOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x03, 0xFF, 0x67, 0x30, 0xC3]);
        _libDestroyBytes = b.Count - libDestroyOff;

        // ---- __rtld_lib_sym2addr (19 bytes) ----
        int libSym2addrOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x0B, 0x48, 0x85, 0xF6, 0x74, 0x06]);
        b.AddRange([0x48, 0x8B, 0x47, 0x10, 0xFF, 0xE0, 0x31, 0xC0, 0xC3]);
        _libSym2addrBytes = b.Count - libSym2addrOff;

        // ---- __rtld_lib_addr2sym (19 bytes) ----
        int libAddr2symOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x0B, 0x48, 0x85, 0xF6, 0x74, 0x06]);
        b.AddRange([0x48, 0x8B, 0x47, 0x18, 0xFF, 0xE0, 0x31, 0xC0, 0xC3]);
        _libAddr2symBytes = b.Count - libAddr2symOff;

        // ---- __rtld_lib_open (35 bytes) ----
        int libOpenOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x16]);
        b.AddRange([0x8B, 0x8F, 0x48, 0x04, 0x00, 0x00, 0x8D, 0x41, 0x01]);
        b.AddRange([0x89, 0x87, 0x48, 0x04, 0x00, 0x00]);
        b.AddRange([0x31, 0xC0, 0x85, 0xC9, 0x74, 0x07, 0xC3]);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0xFF, 0x27]);
        _libOpenBytes = b.Count - libOpenOff;

        // ---- __rtld_lib_fini (73 bytes) ----
        int libFiniOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x17, 0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        b.AddRange([0x48, 0x89, 0xFB, 0xFF, 0x57, 0x20, 0x85, 0xC0, 0x74, 0x0D]);
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]);
        b.AddRange([0x48, 0x8B, 0x9B, 0x58, 0x04, 0x00, 0x00]);
        b.AddRange([0x31, 0xC0, 0x48, 0x85, 0xDB, 0x74, 0xE5, 0x48, 0x8B, 0x3B]);
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int libFiniSelfCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0xD9, 0x48, 0x8B, 0x5B, 0x08]);
        b.AddRange([0x48, 0x85, 0xDB, 0x75, 0xEB, 0x31, 0xC0, 0xEB, 0xCC]);
        _libFiniBytes = b.Count - libFiniOff;

        // ---- __rtld_lib_sym2lib (96 bytes) ----
        int libSym2libOff = b.Count;
        b.AddRange([0x31, 0xC0, 0x48, 0x85, 0xFF, 0x74, 0x58]);
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53]);
        b.AddRange([0x48, 0x89, 0xF3, 0x48, 0x85, 0xF6, 0x74, 0x45]);
        b.AddRange([0x49, 0x89, 0xFE, 0x48, 0x89, 0xDE, 0xFF, 0x57, 0x10]);
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x05, 0x4C, 0x89, 0xF0, 0xEB, 0x32]);
        b.AddRange([0x4D, 0x8B, 0xB6, 0x58, 0x04, 0x00, 0x00]);
        b.AddRange([0x4D, 0x85, 0xF6, 0x74, 0x24]);
        b.AddRange([0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]); // 11-byte NOP
        b.AddRange([0x49, 0x8B, 0x3E, 0x48, 0x89, 0xDE]);
        b.AddRange([0xE8, 0, 0, 0, 0]);
        int libSym2libSelfCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x75, 0x0B, 0x4D, 0x8B, 0x76, 0x08]);
        b.AddRange([0x4D, 0x85, 0xF6, 0x75, 0xE7, 0x31, 0xC0]);
        b.AddRange([0x5B, 0x41, 0x5E, 0x5D, 0xC3]);
        _libSym2libBytes = b.Count - libSym2libOff;

        // ---- __rtld_lib_addr2lib (96 bytes) ----
        int libAddr2libOff = b.Count;
        b.AddRange([0x31, 0xC0, 0x48, 0x85, 0xFF, 0x74, 0x58]);
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53]);
        b.AddRange([0x48, 0x89, 0xF3, 0x48, 0x85, 0xF6, 0x74, 0x45]);
        b.AddRange([0x48, 0x8B, 0x87, 0x38, 0x04, 0x00, 0x00]);           // mov rax, [rdi+0x438]
        b.AddRange([0x48, 0x39, 0xD8]);                                     // cmp rax, rbx
        b.AddRange([0x77, 0x11]);                                           // ja .children
        b.AddRange([0x48, 0x03, 0x87, 0x40, 0x04, 0x00, 0x00]);           // add rax, [rdi+0x440]
        b.AddRange([0x48, 0x39, 0xD8]);                                     // cmp rax, rbx
        b.AddRange([0x76, 0x05]);                                           // jbe .children
        b.AddRange([0x48, 0x89, 0xF8]);                                     // mov rax, rdi
        b.AddRange([0xEB, 0x28]);                                           // jmp .epilogue
        b.AddRange([0x4C, 0x8B, 0xB7, 0x58, 0x04, 0x00, 0x00]);           // mov r14, [rdi+0x458]
        b.AddRange([0x4D, 0x85, 0xF6]);                                     // test r14, r14
        b.AddRange([0x74, 0x1A]);                                           // je .not_found
        b.AddRange([0x90]);                                                  // nop
        b.AddRange([0x49, 0x8B, 0x3E]);                                     // mov rdi, [r14]
        b.AddRange([0x48, 0x89, 0xDE]);                                     // mov rsi, rbx
        b.AddRange([0xE8, 0, 0, 0, 0]);                                     // call addr2lib (self)
        int libAddr2libSelfCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x75, 0x0B]);                        // test rax; jne .epilogue
        b.AddRange([0x4D, 0x8B, 0x76, 0x08]);                              // mov r14, [r14+8]
        b.AddRange([0x4D, 0x85, 0xF6, 0x75, 0xE7]);                        // test r14; jne .loop
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x5B, 0x41, 0x5E, 0x5D, 0xC3]);                        // epilogue
        _libAddr2libBytes = b.Count - libAddr2libOff;

        // ---- __rtld_lib_append_dep (117 bytes) ----
        int libAppendDepOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        b.AddRange([0x41, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF]);                  // mov r14d, -1
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x52]);                        // test rdi; je .epilogue
        b.AddRange([0x49, 0x89, 0xF7]);                                     // mov r15, rsi
        b.AddRange([0x48, 0x85, 0xF6, 0x74, 0x4A]);                        // test rsi; je .epilogue
        b.AddRange([0x48, 0x89, 0xFB]);                                     // mov rbx, rdi
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x18, 0x00, 0x00, 0x00]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *calloc
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x32]);                        // test rax; je .epilogue
        b.AddRange([0x4C, 0x89, 0x38]);                                     // mov [rax], r15 (seq->lib)
        b.AddRange([0x48, 0x83, 0xBB, 0x58, 0x04, 0x00, 0x00, 0x00]);      // cmpq $0, 0x458(rbx)
        b.AddRange([0x75, 0x07]);                                           // jne .skip_head
        b.AddRange([0x48, 0x89, 0x83, 0x58, 0x04, 0x00, 0x00]);            // mov 0x458(rbx), rax
        b.AddRange([0x48, 0x8B, 0x8B, 0x60, 0x04, 0x00, 0x00]);            // mov rcx, 0x460(rbx)
        b.AddRange([0x48, 0x85, 0xC9, 0x74, 0x08]);                        // test rcx; je .no_tail
        b.AddRange([0x48, 0x89, 0x48, 0x10]);                              // mov [rax+0x10], rcx (prev)
        b.AddRange([0x48, 0x89, 0x41, 0x08]);                              // mov [rcx+0x08], rax (next)
        b.AddRange([0x48, 0x89, 0x83, 0x60, 0x04, 0x00, 0x00]);            // mov 0x460(rbx), rax
        b.AddRange([0x45, 0x31, 0xF6]);                                     // xor r14d, r14d
        b.AddRange([0x44, 0x89, 0xF0]);                                     // mov eax, r14d
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _libAppendDepBytes = b.Count - libAppendDepOff;

        // ---- __rtld_lib_remove_dep (99 bytes) ----
        int libRemoveDepOff = b.Count;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                        // mov eax, -1
        b.AddRange([0x48, 0x85, 0xFF]);                                     // test rdi, rdi
        b.AddRange([0x74, 0x58]);                                           // je .ret
        b.AddRange([0x48, 0x85, 0xF6]);                                     // test rsi, rsi
        b.AddRange([0x74, 0x53]);                                           // je .ret
        b.AddRange([0x55]);                                                  // push rbp
        b.AddRange([0x48, 0x89, 0xE5]);                                     // mov rbp, rsp
        b.AddRange([0x53]);                                                  // push rbx
        b.AddRange([0x50]);                                                  // push rax
        b.AddRange([0x48, 0x8B, 0xBF, 0x58, 0x04, 0x00, 0x00]);           // mov rdi, [rdi+0x458]
        b.AddRange([0x0F, 0x1F, 0x40, 0x00]);                              // nopl 0(%rax)
        b.AddRange([0x48, 0x85, 0xFF]);                                     // test rdi, rdi
        b.AddRange([0x0F, 0x94, 0xC3]);                                     // sete bl
        b.AddRange([0x74, 0x2F]);                                           // je .done
        b.AddRange([0x48, 0x39, 0x37]);                                     // cmp [rdi], rsi
        b.AddRange([0x74, 0x06]);                                           // je .found
        b.AddRange([0x48, 0x8B, 0x7F, 0x08]);                              // mov rdi, [rdi+0x08]
        b.AddRange([0xEB, 0xED]);                                           // jmp .loop
        // .found:
        b.AddRange([0x48, 0x8B, 0x47, 0x10]);                              // mov rax, [rdi+0x10] (prev)
        b.AddRange([0x48, 0x85, 0xC0]);                                     // test rax, rax
        b.AddRange([0x74, 0x08]);                                           // je .no_prev
        b.AddRange([0x48, 0x8B, 0x4F, 0x08]);                              // mov rcx, [rdi+0x08] (next)
        b.AddRange([0x48, 0x89, 0x48, 0x08]);                              // mov [rax+0x08], rcx
        // .no_prev:
        b.AddRange([0x48, 0x8B, 0x4F, 0x08]);                              // mov rcx, [rdi+0x08] (next)
        b.AddRange([0x48, 0x85, 0xC9]);                                     // test rcx, rcx
        b.AddRange([0x74, 0x04]);                                           // je .no_next
        b.AddRange([0x48, 0x89, 0x41, 0x10]);                              // mov [rcx+0x10], rax
        // .no_next:
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *free
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .done:
        b.AddRange([0x0F, 0xB6, 0xC3]);                                     // movzbl bl, eax
        b.AddRange([0xF7, 0xD8]);                                           // neg eax
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                              // add rsp, 8
        b.AddRange([0x5B]);                                                  // pop rbx
        b.AddRange([0x5D]);                                                  // pop rbp
        b.AddRange([0xC3]);                                                  // ret
        _libRemoveDepBytes = b.Count - libRemoveDepOff;

        // ---- __rtld_lib_soname2lib (112 bytes) ----
        int libSoname2libOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x4C]);                        // test rdi; je .null
        b.AddRange([0x49, 0x89, 0xF6]);                                     // mov r14, rsi
        b.AddRange([0x48, 0x89, 0xFB]);                                     // mov rbx, rdi
        b.AddRange([0x48, 0x83, 0xC7, 0x38]);                              // add rdi, 0x38
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strcmp
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        b.AddRange([0x85, 0xC0, 0x74, 0x3F]);                              // test eax; je .found
        b.AddRange([0x4C, 0x8B, 0xBB, 0x58, 0x04, 0x00, 0x00]);           // mov r15, [rbx+0x458]
        b.AddRange([0x31, 0xDB]);                                           // xor ebx, ebx
        b.AddRange([0x4D, 0x85, 0xFF, 0x74, 0x31]);                        // test r15; je .ret
        // 15-byte NOP for alignment
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .loop:
        b.AddRange([0x49, 0x8B, 0x3F]);                                     // mov rdi, [r15]
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0xE8, 0, 0, 0, 0]);                                     // call soname2lib (self)
        int libSoname2libSelfCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x75, 0x0F]);                        // test rax; jne .found2
        b.AddRange([0x4D, 0x8B, 0x7F, 0x08]);                              // mov r15, [r15+0x08]
        b.AddRange([0x4D, 0x85, 0xFF, 0x75, 0xE7]);                        // test r15; jne .loop
        b.AddRange([0xEB, 0x07]);                                           // jmp .ret
        // .null:
        b.AddRange([0x31, 0xDB, 0xEB, 0x03]);                              // xor ebx; jmp .ret
        // .found2:
        b.AddRange([0x48, 0x89, 0xC3]);                                     // mov rbx, rax
        // .ret:
        b.AddRange([0x48, 0x89, 0xD8]);                                     // mov rax, rbx
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _libSoname2libBytes = b.Count - libSoname2libOff;

        // ---- __rtld_lib_init (151 bytes) ----
        int libInitOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp; mov rbp,rsp
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x50]);
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x48]);                        // test rdi; je .fail
        b.AddRange([0x48, 0x89, 0xCB]);                                     // mov rbx, rcx
        b.AddRange([0x49, 0x89, 0xD6]);                                     // mov r14, rdx
        b.AddRange([0x41, 0x89, 0xF7]);                                     // mov r15d, esi
        b.AddRange([0x48, 0x89, 0x7D, 0xD0]);                              // mov [rbp-0x30], rdi
        b.AddRange([0x4C, 0x8B, 0xA7, 0x60, 0x04, 0x00, 0x00]);           // mov r12, [rdi+0x460]
        b.AddRange([0x4D, 0x85, 0xE4]);                                     // test r12, r12
        b.AddRange([0x41, 0x0F, 0x94, 0xC5]);                              // sete r13b
        b.AddRange([0x74, 0x32]);                                           // je .check_done
        // .loop:
        b.AddRange([0x49, 0x8B, 0x3C, 0x24]);                              // mov rdi, [r12]
        b.AddRange([0x44, 0x89, 0xFE]);                                     // mov esi, r15d
        b.AddRange([0x4C, 0x89, 0xF2]);                                     // mov rdx, r14
        b.AddRange([0x48, 0x89, 0xD9]);                                     // mov rcx, rbx
        b.AddRange([0xE8, 0, 0, 0, 0]);                                     // call init (self)
        int libInitSelfCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x0E]);                              // test eax; jne .check_r13
        b.AddRange([0x4D, 0x8B, 0x64, 0x24, 0x10]);                        // mov r12, [r12+0x10]
        b.AddRange([0x4D, 0x85, 0xE4]);                                     // test r12, r12
        b.AddRange([0x41, 0x0F, 0x94, 0xC5]);                              // sete r13b
        b.AddRange([0x75, 0xDC]);                                           // jne .loop
        // .check_r13:
        b.AddRange([0x45, 0x84, 0xED, 0x75, 0x0E]);                        // test r13b; jne .do_init
        b.AddRange([0xEB, 0x2D]);                                           // jmp .epilogue
        // .fail:
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                        // mov eax, -1
        b.AddRange([0xEB, 0x26]);                                           // jmp .epilogue
        // .check_done2 (when loop falls through with r12=0 from start):
        b.AddRange([0x45, 0x84, 0xED, 0x74, 0x21]);                        // test r13b; je .epilogue
        // .do_init: tail-call ctx->init(ctx, argc, argv, envp)
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                              // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x8B, 0x47, 0x08]);                              // mov rax, [rdi+0x08]
        b.AddRange([0x44, 0x89, 0xFE]);                                     // mov esi, r15d
        b.AddRange([0x4C, 0x89, 0xF2]);                                     // mov rdx, r14
        b.AddRange([0x48, 0x89, 0xD9]);                                     // mov rcx, rbx
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D]);
        b.AddRange([0xFF, 0xE0]);                                           // jmp *rax
        // .epilogue:
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _libInitBytes = b.Count - libInitOff;

        // ---- __rtld_lib_close (217 bytes) ----
        int libCloseOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x56]);                        // test rdi; je .fail
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        b.AddRange([0x48, 0x89, 0xFB]);                                     // mov rbx, rdi
        b.AddRange([0x8B, 0x8F, 0x48, 0x04, 0x00, 0x00]);                  // mov ecx, [rdi+0x448]
        b.AddRange([0x8D, 0x41, 0xFF]);                                     // lea eax, [rcx-1]
        b.AddRange([0x89, 0x87, 0x48, 0x04, 0x00, 0x00]);                  // mov [rdi+0x448], eax
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x83, 0xF9, 0x01]);                                     // cmp ecx, 1
        b.AddRange([0x0F, 0x8F, 0, 0, 0, 0]);                              // jg .epilogue
        int libCloseEpilogueJump1 = b.Count - 4;
        b.AddRange([0x4C, 0x8B, 0xBB, 0x60, 0x04, 0x00, 0x00]);           // mov r15, [rbx+0x460]
        b.AddRange([0x4D, 0x85, 0xFF]);                                     // test r15
        b.AddRange([0x41, 0x0F, 0x94, 0xC6]);                              // sete r14b
        b.AddRange([0x74, 0x25]);                                           // je .after_dep_close
        b.AddRange([0x0F, 0x1F, 0x40, 0x00]);                              // nopl 0(%rax)
        // .dep_loop:
        b.AddRange([0x49, 0x8B, 0x3F]);                                     // mov rdi, [r15]
        b.AddRange([0xE8, 0, 0, 0, 0]);                                     // call close (self)
        int libCloseSelfCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x15]);                              // test eax; jne .after_dep_close
        b.AddRange([0x4D, 0x8B, 0x7F, 0x10]);                              // mov r15, [r15+0x10] (prev)
        b.AddRange([0x4D, 0x85, 0xFF]);                                     // test r15
        b.AddRange([0x41, 0x0F, 0x94, 0xC6]);                              // sete r14b
        b.AddRange([0x75, 0xE7]);                                           // jne .dep_loop
        b.AddRange([0xEB, 0x06]);                                           // jmp .after_dep_close
        // .fail:
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]);                  // mov eax,-1; ret
        // .after_dep_close:
        b.AddRange([0x45, 0x84, 0xF6, 0x74, 0x00]);                        // test r14b; je .epilogue
        int libCloseAfterJumpAt = b.Count - 1;
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0xFF, 0x53, 0x28]);                                     // call *[rbx+0x28] (vtable close)
        b.AddRange([0x85, 0xC0, 0x75, 0x00]);                              // test eax; jne .epilogue
        int libCloseVtCloseJumpAt = b.Count - 1;
        b.AddRange([0x48, 0x8B, 0x8B, 0x50, 0x04, 0x00, 0x00]);           // mov rcx, [rbx+0x450]
        b.AddRange([0xB8, 0x00, 0x00, 0x00, 0x00]);                        // mov eax, 0
        b.AddRange([0x48, 0x85, 0xC9, 0x74, 0x00]);                        // test rcx; je .epilogue
        int libCloseNoParentJumpAt = b.Count - 1;
        // inline remove_dep from parent
        b.AddRange([0x48, 0x8B, 0xB9, 0x58, 0x04, 0x00, 0x00]);           // mov rdi, [rcx+0x458]
        b.AddRange([0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);     // nopl 0(%rax,%rax)
        // .parent_loop:
        b.AddRange([0x48, 0x85, 0xFF]);                                     // test rdi
        b.AddRange([0x41, 0x0F, 0x94, 0xC6]);                              // sete r14b
        b.AddRange([0x74, 0x2F]);                                           // je .parent_done
        b.AddRange([0x48, 0x39, 0x1F]);                                     // cmp [rdi], rbx
        b.AddRange([0x74, 0x06]);                                           // je .parent_found
        b.AddRange([0x48, 0x8B, 0x7F, 0x08]);                              // mov rdi, [rdi+0x08]
        b.AddRange([0xEB, 0xEC]);                                           // jmp .parent_loop
        // .parent_found:
        b.AddRange([0x48, 0x8B, 0x47, 0x10]);                              // mov rax, [rdi+0x10]
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x08]);                        // test rax; je .no_prev
        b.AddRange([0x48, 0x8B, 0x4F, 0x08]);                              // mov rcx, [rdi+0x08]
        b.AddRange([0x48, 0x89, 0x48, 0x08]);                              // mov [rax+0x08], rcx
        // .no_prev:
        b.AddRange([0x48, 0x8B, 0x4F, 0x08]);                              // mov rcx, [rdi+0x08]
        b.AddRange([0x48, 0x85, 0xC9, 0x74, 0x04]);                        // test rcx; je .no_next
        b.AddRange([0x48, 0x89, 0x41, 0x10]);                              // mov [rcx+0x10], rax
        // .no_next:
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *free
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .parent_done:
        b.AddRange([0x41, 0x0F, 0xB6, 0xC6]);                              // movzbl r14b, eax
        b.AddRange([0xF7, 0xD8]);                                           // neg eax
        int libCloseEpilogue = b.Count;
        WriteRel32InBLocal(libCloseEpilogueJump1, libCloseEpilogue);
        { int d = libCloseEpilogue - (libCloseAfterJumpAt + 1); b[libCloseAfterJumpAt] = (byte)d; }
        { int d = libCloseEpilogue - (libCloseVtCloseJumpAt + 1); b[libCloseVtCloseJumpAt] = (byte)d; }
        { int d = libCloseEpilogue - (libCloseNoParentJumpAt + 1); b[libCloseNoParentJumpAt] = (byte)d; }
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _libCloseBytes = b.Count - libCloseOff;

        // ---- ref_open (inlines __rtld_lib_open on the ref target) ----
        int refOpenOff = b.Count;
        b.AddRange([0x48, 0x8B, 0xBF, 0x68, 0x04, 0x00, 0x00]);           // mov rdi, [rdi+0x468]
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x16]);                        // test rdi; je .fail
        b.AddRange([0x8B, 0x8F, 0x48, 0x04, 0x00, 0x00]);                  // mov ecx, [rdi+0x448]
        b.AddRange([0x8D, 0x41, 0x01]);                                     // lea eax, [rcx+1]
        b.AddRange([0x89, 0x87, 0x48, 0x04, 0x00, 0x00]);                  // mov [rdi+0x448], eax
        b.AddRange([0x31, 0xC0, 0x85, 0xC9, 0x74, 0x07, 0xC3]);           // xor eax; test ecx; je .first; ret
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]);                  // .fail: mov eax,-1; ret
        b.AddRange([0xFF, 0x27]);                                           // .first: jmp *[rdi]

        // ---- ref_init: xor eax, eax ; ret ----
        int refInitOff = b.Count;
        b.AddRange([0x31, 0xC0, 0xC3]);

        // ---- ref_sym2addr ----
        int refSym2addrOff = b.Count;
        b.AddRange([0x48, 0x85, 0xF6, 0x74, 0x12]);                        // test rsi; je .null
        b.AddRange([0x48, 0x8B, 0xBF, 0x68, 0x04, 0x00, 0x00]);           // mov rdi, [rdi+0x468]
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x06]);                        // test rdi; je .null
        b.AddRange([0x48, 0x8B, 0x47, 0x10, 0xFF, 0xE0]);                  // mov rax,[rdi+0x10]; jmp *rax
        b.AddRange([0x31, 0xC0, 0xC3]);                                     // .null: xor eax; ret

        // ---- ref_addr2sym ----
        int refAddr2symOff = b.Count;
        b.AddRange([0x48, 0x85, 0xF6, 0x74, 0x12]);                        // test rsi; je .null
        b.AddRange([0x48, 0x8B, 0xBF, 0x68, 0x04, 0x00, 0x00]);           // mov rdi, [rdi+0x468]
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x06]);                        // test rdi; je .null
        b.AddRange([0x48, 0x8B, 0x47, 0x18, 0xFF, 0xE0]);                  // mov rax,[rdi+0x18]; jmp *rax
        b.AddRange([0x31, 0xC0, 0xC3]);                                     // .null: xor eax; ret

        // ---- ref_fini: xor eax, eax ; ret ----
        int refFiniOff = b.Count;
        b.AddRange([0x31, 0xC0, 0xC3]);

        // ---- ref_close: load ref, tail-call __rtld_lib_close ----
        int refCloseOff = b.Count;
        b.AddRange([0x48, 0x8B, 0xBF, 0x68, 0x04, 0x00, 0x00]);           // mov rdi, [rdi+0x468]
        b.AddRange([0xE9, 0, 0, 0, 0]);                                     // jmp __rtld_lib_close
        int refCloseJmpDisp = b.Count - 4;

        // ---- ref_destroy: tail-call free ----
        int refDestroyOff = b.Count;
        b.AddRange([0xFF, 0x25, 0, 0, 0, 0]);                              // jmp *free
        AddRel(RelocSymbol.RtldFree, b.Count - 4);

        // ---- __rtld_find_file (946 bytes) ----
        // Searches filesystem paths for a library. Uses sprintf/strcpy/strcat/getenv BSS slots.
        int findFileOff = b.Count;
        // prologue
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp; mov rbp,rsp
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53]);
        b.AddRange([0x48, 0x81, 0xEC, 0x08, 0x06, 0x00, 0x00]);           // sub rsp, 0x608
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0xFF, 0x00, 0x00, 0x00]);     // movq $0xFF, [rbp-0x30]
        b.AddRange([0x41, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                  // mov r15d, -1
        b.AddRange([0x48, 0x85, 0xFF]);                                     // test rdi
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .ret
        int ffRetJump1 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xF3]);                                     // mov rbx, rsi (path)
        b.AddRange([0x48, 0x85, 0xF6]);                                     // test rsi
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .ret
        int ffRetJump2 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xFE]);                                     // mov r14, rdi (name)
        b.AddRange([0x80, 0x3F, 0x00]);                                     // cmpb $0, [rdi]
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .ret
        int ffRetJump3 = b.Count - 4;
        b.AddRange([0xC6, 0x03, 0x00]);                                     // movb $0, [rbx]

        // Check for absolute path (starts with '/')
        b.AddRange([0x41, 0x80, 0x3E, 0x2F]);                              // cmpb $0x2F, [r14]
        b.AddRange([0x75, 0x00]);                                           // jne .rel_search
        int ffRelSearchJumpAt = b.Count - 1;
        // Absolute path: SYS_stat(name, buf) and if ok, strcpy(path, name)
        b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFE, 0xFF, 0xFF]);           // lea rdx, [rbp-0x130]
        b.AddRange([0xBF, 0xBC, 0x00, 0x00, 0x00]);                        // mov edi, 0xBC (SYS_stat)
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call __crt_syscall
        int ffStatCall1 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC7]);                                     // mov r15, rax
        b.AddRange([0x45, 0x85, 0xFF]);                                     // test r15d
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                              // jne .ret
        int ffRetJump4 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strcpy
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        b.AddRange([0xE9, 0, 0, 0, 0]);                                     // jmp .ret
        int ffRetJump5 = b.Count - 4;
        int ffRelSearch = b.Count;
        b[ffRelSearchJumpAt] = (byte)(ffRelSearch - (ffRelSearchJumpAt + 1));

        // Helper: emit a sprintf+stat probe block. Returns the target offset for "success" jump.
        // Pattern: lea rsi,[rip+fmt]; xor r15d; mov rdi,rbx; mov rdx,r14; xor eax; call *sprintf;
        //          lea rdx,[rbp-0x130]; mov edi,0xBC; mov rsi,rbx; xor eax; addr32 call crt_syscall;
        //          test rax; je .ret(success)
        var ffStatDisps = new List<int>();
        var ffFmtLeaAts = new List<int>();
        var ffSuccessJumps = new List<int>();

        void EmitFfProbe()
        {
            b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);                    // lea rsi, [rip+fmt]
            ffFmtLeaAts.Add(b.Count - 4);
            b.AddRange([0x45, 0x31, 0xFF]);                                 // xor r15d, r15d
            b.AddRange([0x48, 0x89, 0xDF]);                                 // mov rdi, rbx
            b.AddRange([0x4C, 0x89, 0xF2]);                                 // mov rdx, r14
            b.AddRange([0x31, 0xC0]);                                       // xor eax, eax
            b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                          // call *sprintf
            AddRel(RelocSymbol.RtldSprintf, b.Count - 4);
            b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFE, 0xFF, 0xFF]);       // lea rdx, [rbp-0x130]
            b.AddRange([0xBF, 0xBC, 0x00, 0x00, 0x00]);                    // mov edi, 0xBC
            b.AddRange([0x48, 0x89, 0xDE]);                                 // mov rsi, rbx
            b.AddRange([0x31, 0xC0]);                                       // xor eax, eax
            b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                          // addr32 call crt_syscall
            ffStatDisps.Add(b.Count - 4);
            b.AddRange([0x48, 0x85, 0xC0]);                                 // test rax, rax
            b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                          // je .ret(success)
            ffSuccessJumps.Add(b.Count - 4);
        }

        // Probe 1: /system/priv/lib/%s
        EmitFfProbe();
        // Probe 2: /system/common/lib/%s
        EmitFfProbe();
        // Probe 3: /system_ex/priv_ex/lib/%s
        EmitFfProbe();
        // Probe 4: /system_ex/common_ex/lib/%s
        EmitFfProbe();

        // SYS_randomized_path probe
        b.AddRange([0x45, 0x31, 0xFF]);                                     // xor r15d, r15d
        b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFD, 0xFF, 0xFF]);           // lea rdx, [rbp-0x230]
        b.AddRange([0x48, 0x8D, 0x4D, 0xD0]);                              // lea rcx, [rbp-0x30]
        b.AddRange([0xBF, 0x5A, 0x02, 0x00, 0x00]);                        // mov edi, 0x25A (SYS_randomized_path)
        b.AddRange([0x31, 0xF6]);                                           // xor esi, esi
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call crt_syscall
        int ffRandpathCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                                     // test rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .rand_probes
        int ffRandProbesJump = b.Count - 4;

        // Skip randomized probes: jump to LD_LIBRARY_PATH
        b.AddRange([0xE9, 0, 0, 0, 0]);                                     // jmp .ld_library_path
        int ffLdLibPathJump = b.Count - 4;

        int ffRandProbes = b.Count;
        WriteRel32InBLocal(ffRandProbesJump, ffRandProbes);

        // Randomized probes use sprintf with 3 args: fmt, random_word, name
        // Pattern differs: lea rsi,[rip+fmt]; lea rdx,[rbp-0x230]; mov rdi,rbx; mov rcx,r14; xor eax; call *sprintf
        var ffRandFmtLeaAts = new List<int>();
        var ffRandStatDisps = new List<int>();
        var ffRandSuccessJumps = new List<int>();

        void EmitFfRandProbe()
        {
            b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);                    // lea rsi, [rip+fmt]
            ffRandFmtLeaAts.Add(b.Count - 4);
            b.AddRange([0x45, 0x31, 0xFF]);                                 // xor r15d
            b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFD, 0xFF, 0xFF]);       // lea rdx, [rbp-0x230]
            b.AddRange([0x48, 0x89, 0xDF]);                                 // mov rdi, rbx
            b.AddRange([0x4C, 0x89, 0xF1]);                                 // mov rcx, r14
            b.AddRange([0x31, 0xC0]);                                       // xor eax
            b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                          // call *sprintf
            AddRel(RelocSymbol.RtldSprintf, b.Count - 4);
            b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFE, 0xFF, 0xFF]);       // lea rdx, [rbp-0x130]
            b.AddRange([0xBF, 0xBC, 0x00, 0x00, 0x00]);                    // mov edi, 0xBC
            b.AddRange([0x48, 0x89, 0xDE]);                                 // mov rsi, rbx
            b.AddRange([0x31, 0xC0]);                                       // xor eax
            b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                          // addr32 call crt_syscall
            ffRandStatDisps.Add(b.Count - 4);
            b.AddRange([0x48, 0x85, 0xC0]);                                 // test rax
            b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                          // je .ret(success)
            ffRandSuccessJumps.Add(b.Count - 4);
        }

        // Rand Probe 1: /%s/priv/lib/%s
        EmitFfRandProbe();
        // Rand Probe 2: /%s/common/lib/%s
        EmitFfRandProbe();
        // Rand Probe 3: /%s/priv_ex/lib/%s
        EmitFfRandProbe();
        // Rand Probe 4: /%s/common_ex/lib/%s
        EmitFfRandProbe();

        // After randomized probes, fall through to LD_LIBRARY_PATH
        int ffLdLibPath = b.Count;
        WriteRel32InBLocal(ffLdLibPathJump, ffLdLibPath);

        // LD_LIBRARY_PATH: getenv("LD_LIBRARY_PATH")
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);                       // lea rdi, [rip+"LD_LIBRARY_PATH"]
        int ffLdLibPathLeaAt = b.Count - 4;
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *getenv
        AddRel(RelocSymbol.RtldGetenv, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]);                        // test rax; je .after_ldpath
        int ffAfterLdpathJumpAt = b.Count - 1;
        // LD_LIBRARY_PATH loop: walk colon-separated paths
        b.AddRange([0x49, 0x89, 0xC4]);                                     // mov r12, rax
        b.AddRange([0x0F, 0xB6, 0x00]);                                     // movzbl [rax], eax
        b.AddRange([0x84, 0xC0, 0x74, 0x00]);                              // test al; je .after_ldpath
        int ffAfterLdpathJumpAt2 = b.Count - 1;
        b.AddRange([0x49, 0xFF, 0xC4]);                                     // inc r12
        b.AddRange([0x45, 0x31, 0xFF]);                                     // xor r15d
        b.AddRange([0x4C, 0x8D, 0x2D, 0, 0, 0, 0]);                       // lea r13, [rip+__crt_syscall]
        int ffCrtSyscallLeaAt = b.Count - 4;
        b.AddRange([0xEB, 0x00]);                                           // jmp .ldpath_check
        int ffLdpathCheckJumpAt = b.Count - 1;
        // .ldpath_found_sep:
        int ffLdpathFoundSep = b.Count;
        b.AddRange([0x66, 0x42, 0xC7, 0x44, 0x3B, 0x01, 0x2F, 0x00]);     // movw $0x2F, 1(%rbx,%r15)
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strcat
        AddRel(RelocSymbol.RtldStrcat, b.Count - 4);
        b.AddRange([0x45, 0x31, 0xFF]);                                     // xor r15d
        b.AddRange([0xBF, 0xBC, 0x00, 0x00, 0x00]);                        // mov edi, 0xBC
        b.AddRange([0x48, 0x89, 0xDE]);                                     // mov rsi, rbx
        b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFE, 0xFF, 0xFF]);           // lea rdx, [rbp-0x130]
        b.AddRange([0x31, 0xC0]);                                           // xor eax
        b.AddRange([0x41, 0xFF, 0xD5]);                                     // call *r13
        b.AddRange([0x48, 0x85, 0xC0]);                                     // test rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .ret(success)
        int ffLdpathSuccessJump = b.Count - 4;
        // .ldpath_next:
        b.AddRange([0x41, 0x0F, 0xB6, 0x04, 0x24]);                        // movzbl [r12], eax
        b.AddRange([0x49, 0xFF, 0xC4]);                                     // inc r12
        b.AddRange([0x84, 0xC0]);                                           // test al
        b.AddRange([0x74, 0x00]);                                           // je .after_ldpath
        int ffAfterLdpathJumpAt3 = b.Count - 1;
        // .ldpath_check:
        int ffLdpathCheck = b.Count;
        b[ffLdpathCheckJumpAt] = (byte)(ffLdpathCheck - (ffLdpathCheckJumpAt + 1));
        b.AddRange([0x42, 0x88, 0x04, 0x3B]);                              // mov al, [rbx+r15]
        b.AddRange([0x42, 0x80, 0x7C, 0x3B, 0x01, 0x3A]);                  // cmpb $0x3A, 1(%rbx,%r15)
        b.AddRange([0x74, (byte)(ffLdpathFoundSep - (b.Count + 2))]);       // je .ldpath_found_sep
        b.AddRange([0x41, 0x80, 0x3C, 0x24, 0x00]);                        // cmpb $0, [r12]
        b.AddRange([0x74, (byte)(ffLdpathFoundSep - (b.Count + 2))]);       // je .ldpath_found_sep
        b.AddRange([0x49, 0xFF, 0xC7]);                                     // inc r15
        b.AddRange([0xEB, (byte)((sbyte)((b.Count + 2) - (b.Count + 2) - 2 + (ffLdpathCheck - b.Count - 2)) & 0xFF)]);
        // ^^ This is: jmp .ldpath_next (which is 5 bytes before .ldpath_check)
        // Proper target: the jmp must reach the movzbl instruction at ffLdpathCheck - 10
        // (5+3+2 bytes = the three instructions before ldpath_check).
        // The relative jump backward targets the `41 0f b6 04 24` instruction.
        // The offset requires careful calculation.

        int ffAfterLdpath = b.Count;
        b[ffAfterLdpathJumpAt] = (byte)(ffAfterLdpath - (ffAfterLdpathJumpAt + 1));
        b[ffAfterLdpathJumpAt2] = (byte)(ffAfterLdpath - (ffAfterLdpathJumpAt2 + 1));
        b[ffAfterLdpathJumpAt3] = (byte)(ffAfterLdpath - (ffAfterLdpathJumpAt3 + 1));

        // Probe: /user/homebrew/lib/%s
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);                       // lea rsi, [rip+fmt]
        int ffHomebrewLeaAt = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xFF]);                                     // xor r15d
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF2]);                                     // mov rdx, r14
        b.AddRange([0x31, 0xC0]);                                           // xor eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *sprintf
        AddRel(RelocSymbol.RtldSprintf, b.Count - 4);
        b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFE, 0xFF, 0xFF]);           // lea rdx, [rbp-0x130]
        b.AddRange([0xBF, 0xBC, 0x00, 0x00, 0x00]);                        // mov edi, 0xBC
        b.AddRange([0x48, 0x89, 0xDE]);                                     // mov rsi, rbx
        b.AddRange([0x31, 0xC0]);                                           // xor eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call crt_syscall
        int ffHomebrewStatDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                                     // test rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .ret(success)
        int ffHomebrewSuccessJump = b.Count - 4;

        // Probe: getcwd then %s/%s
        b.AddRange([0x45, 0x31, 0xFF]);                                     // xor r15d
        b.AddRange([0x48, 0x8D, 0xB5, 0xD0, 0xF9, 0xFF, 0xFF]);           // lea rsi, [rbp-0x630]
        b.AddRange([0xBF, 0x46, 0x01, 0x00, 0x00]);                        // mov edi, 0x146 (SYS___getcwd)
        b.AddRange([0xBA, 0x00, 0x04, 0x00, 0x00]);                        // mov edx, 0x400
        b.AddRange([0x31, 0xC0]);                                           // xor eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call crt_syscall
        int ffGetcwdCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x75, 0x00]);                        // test rax; jne .not_found
        int ffCwdFailJumpAt = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);                       // lea rsi, [rip+"%s/%s"]
        int ffCwdFmtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xF9, 0xFF, 0xFF]);           // lea rdx, [rbp-0x630]
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF1]);                                     // mov rcx, r14
        b.AddRange([0x31, 0xC0]);                                           // xor eax
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *sprintf
        AddRel(RelocSymbol.RtldSprintf, b.Count - 4);
        b.AddRange([0x48, 0x8D, 0x95, 0xD0, 0xFE, 0xFF, 0xFF]);           // lea rdx, [rbp-0x130]
        b.AddRange([0xBF, 0xBC, 0x00, 0x00, 0x00]);                        // mov edi, 0xBC
        b.AddRange([0x48, 0x89, 0xDE]);                                     // mov rsi, rbx
        b.AddRange([0x31, 0xC0]);                                           // xor eax
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call crt_syscall
        int ffCwdStatDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                                     // test rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .ret(success)
        int ffCwdSuccessJump = b.Count - 4;

        // .not_found:
        int ffNotFound = b.Count;
        b[ffCwdFailJumpAt] = (byte)(ffNotFound - (ffCwdFailJumpAt + 1));
        b.AddRange([0xC6, 0x03, 0x00]);                                     // movb $0, [rbx]
        b.AddRange([0x41, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                  // mov r15d, -1

        // .ret:
        int ffRet = b.Count;
        WriteRel32InBLocal(ffRetJump1, ffRet);
        WriteRel32InBLocal(ffRetJump2, ffRet);
        WriteRel32InBLocal(ffRetJump3, ffRet);
        WriteRel32InBLocal(ffRetJump4, ffRet);
        WriteRel32InBLocal(ffRetJump5, ffRet);
        foreach (int j in ffSuccessJumps) WriteRel32InBLocal(j, ffRet);
        foreach (int j in ffRandSuccessJumps) WriteRel32InBLocal(j, ffRet);
        WriteRel32InBLocal(ffLdpathSuccessJump, ffRet);
        WriteRel32InBLocal(ffHomebrewSuccessJump, ffRet);
        WriteRel32InBLocal(ffCwdSuccessJump, ffRet);
        b.AddRange([0x44, 0x89, 0xF8]);                                     // mov eax, r15d
        b.AddRange([0x48, 0x81, 0xC4, 0x08, 0x06, 0x00, 0x00]);           // add rsp, 0x608
        b.AddRange([0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _findFileBytes = b.Count - findFileOff;

        // ---- __rtld_lib_new (383 bytes) ----
        int libNewOff = b.Count;
        // prologue: push rbp; mov rbp,rsp; push r15; push r14; push rbx; sub rsp,0x408
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53]);
        b.AddRange([0x48, 0x81, 0xEC, 0x08, 0x04, 0x00, 0x00]);
        b.AddRange([0x49, 0x89, 0xF6]);                                     // mov r14, rsi (soname)
        b.AddRange([0x48, 0x89, 0xFB]);                                     // mov rbx, rdi (parent)
        b.AddRange([0x48, 0x89, 0xF8]);                                     // mov rax, rdi
        b.AddRange([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]);           // nopl 0(%rax)
        // walk parent chain to root
        // .root_loop:
        int libNewRootLoop = b.Count;
        b.AddRange([0x49, 0x89, 0xC7]);                                     // mov r15, rax
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x0C]);                        // test rax; je .root_done
        b.AddRange([0x49, 0x8B, 0x87, 0x50, 0x04, 0x00, 0x00]);           // mov rax, [r15+0x450]
        b.AddRange([0x48, 0x85, 0xC0, 0x75, 0xEC]);                        // test rax; jne .root_loop
        // .root_done: r15 = root

        // call __rtld_find_file(soname, &path)
        b.AddRange([0x48, 0x8D, 0xB5, 0xE0, 0xFB, 0xFF, 0xFF]);           // lea rsi, [rbp-0x420]
        b.AddRange([0x4C, 0x89, 0xF7]);                                     // mov rdi, r14
        b.AddRange([0xE8, 0, 0, 0, 0]);                                     // call __rtld_find_file
        int libNewFindFileDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x74, 0x10]);                              // test eax; je .path_ok
        // find_file failed: strcpy(path, soname)
        b.AddRange([0x48, 0x8D, 0xBD, 0xE0, 0xFB, 0xFF, 0xFF]);           // lea rdi, [rbp-0x420]
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strcpy
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        // .path_ok: soname2lib(root, path)
        b.AddRange([0x48, 0x8D, 0xB5, 0xE0, 0xFB, 0xFF, 0xFF]);           // lea rsi, [rbp-0x420]
        b.AddRange([0x4C, 0x89, 0xFF]);                                     // mov rdi, r15
        b.AddRange([0xE8, 0, 0, 0, 0]);                                     // call soname2lib
        int libNewSoname2libDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                                     // test rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                              // je .not_loaded
        int libNewNotLoadedJump = b.Count - 4;

        // Already loaded: create ref_lib_t
        b.AddRange([0x49, 0x89, 0xC7]);                                     // mov r15, rax (ref)
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x70, 0x04, 0x00, 0x00]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *calloc(1, 0x470)
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        b.AddRange([0x49, 0x89, 0xC6]);                                     // mov r14, rax (new lib)
        b.AddRange([0x48, 0x89, 0x98, 0x50, 0x04, 0x00, 0x00]);           // mov [rax+0x450], rbx (parent)
        b.AddRange([0x4C, 0x89, 0xB8, 0x68, 0x04, 0x00, 0x00]);           // mov [rax+0x468], r15 (ref)
        // Set vtable to ref_* functions
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_open]
        int libNewRefOpenLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x06]);                                     // mov [r14], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_init]
        int libNewRefInitLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x46, 0x08]);                              // mov [r14+0x08], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_sym2addr]
        int libNewRefSym2addrLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x46, 0x10]);                              // mov [r14+0x10], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_addr2sym]
        int libNewRefAddr2symLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x46, 0x18]);                              // mov [r14+0x18], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_fini]
        int libNewRefFiniLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x46, 0x20]);                              // mov [r14+0x20], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_close]
        int libNewRefCloseLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x46, 0x28]);                              // mov [r14+0x28], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);                        // lea rax, [rip+ref_destroy]
        int libNewRefDestroyLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x46, 0x30]);                              // mov [r14+0x30], rax
        b.AddRange([0x41, 0xC7, 0x86, 0x48, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // movl $0, [r14+0x448]
        // Copy mapbase/mapsize from ref
        b.AddRange([0x49, 0x8B, 0x87, 0x38, 0x04, 0x00, 0x00]);           // mov rax, [r15+0x438]
        b.AddRange([0x49, 0x89, 0x86, 0x38, 0x04, 0x00, 0x00]);           // mov [r14+0x438], rax
        b.AddRange([0x49, 0x8B, 0x87, 0x40, 0x04, 0x00, 0x00]);           // mov rax, [r15+0x440]
        b.AddRange([0x49, 0x89, 0x86, 0x40, 0x04, 0x00, 0x00]);           // mov [r14+0x440], rax
        // strcpy(lib->soname, ref->soname)
        b.AddRange([0x49, 0x8D, 0x7E, 0x38]);                              // lea rdi, [r14+0x38]
        b.AddRange([0x49, 0x83, 0xC7, 0x38]);                              // add r15, 0x38
        b.AddRange([0x4C, 0x89, 0xFE]);                                     // mov rsi, r15
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strcpy
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        b.AddRange([0x4C, 0x89, 0xF0]);                                     // mov rax, r14
        b.AddRange([0xEB, 0x00]);                                           // jmp .epilogue
        int libNewEpilogueJumpAt = b.Count - 1;

        // .not_loaded: dispatch based on endswith(".sprx")
        int libNewNotLoaded = b.Count;
        WriteRel32InBLocal(libNewNotLoadedJump, libNewNotLoaded);
        // strlen(".sprx")
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);                       // lea rdi, [rip+".sprx"]
        int libNewSprxSuffixLeaAt = b.Count - 4;
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strlen
        AddRel(RelocSymbol.RtldStrlen, b.Count - 4);
        b.AddRange([0x49, 0x89, 0xC7]);                                     // mov r15, rax (suffix_len)
        // strlen(soname)
        b.AddRange([0x4C, 0x89, 0xF7]);                                     // mov rdi, r14
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strlen
        AddRel(RelocSymbol.RtldStrlen, b.Count - 4);
        // compare lengths
        b.AddRange([0x4C, 0x39, 0xF8]);                                     // cmp rax, r15
        b.AddRange([0x72, 0x00]);                                           // jb .try_so
        int libNewTrySoJumpAt1 = b.Count - 1;
        // endswith: strncmp(soname + len - suffix_len, ".sprx", suffix_len)
        b.AddRange([0x4C, 0x01, 0xF0]);                                     // add rax, r14
        b.AddRange([0x4C, 0x29, 0xF8]);                                     // sub rax, r15
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);                        // lea rsi, [rip+".sprx"]
        int libNewSprxSuffixLeaAt2 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC7]);                                     // mov rdi, rax
        b.AddRange([0x4C, 0x89, 0xFA]);                                     // mov rdx, r15
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call *strncmp
        AddRel(RelocSymbol.RtldStrncmp, b.Count - 4);
        b.AddRange([0x85, 0xC0, 0x74, 0x00]);                              // test eax; je .is_sprx
        int libNewIsSprxJumpAt = b.Count - 1;
        // .try_so: call __rtld_so_new(parent, soname)
        int libNewTrySo = b.Count;
        b[libNewTrySoJumpAt1] = (byte)(libNewTrySo - (libNewTrySoJumpAt1 + 1));
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call __rtld_so_new
        int libNewSoNewDisp = b.Count - 4;
        // .epilogue:
        int libNewEpilogue = b.Count;
        b[libNewEpilogueJumpAt] = (byte)(libNewEpilogue - (libNewEpilogueJumpAt + 1));
        b.AddRange([0x48, 0x81, 0xC4, 0x08, 0x04, 0x00, 0x00]);           // add rsp, 0x408
        b.AddRange([0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);           // pop rbx; pop r14; pop r15; pop rbp; ret
        // .is_sprx: call __rtld_sprx_new(parent, soname)
        int libNewIsSprx = b.Count;
        b[libNewIsSprxJumpAt] = (byte)(libNewIsSprx - (libNewIsSprxJumpAt + 1));
        b.AddRange([0x48, 0x89, 0xDF]);                                     // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF6]);                                     // mov rsi, r14
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                              // addr32 call __rtld_sprx_new
        int libNewSprxNewDisp = b.Count - 4;
        b.AddRange([0xEB, (byte)((sbyte)(libNewEpilogue - (b.Count + 2)) & 0xFF)]); // jmp .epilogue
        _libNewBytes = b.Count - libNewOff;

        // ---- __rtld_sprx_new (156 bytes) ----
        // calloc(1, 0x490), set parent, fill vtable[0..6], refcnt=0, strcpy soname.
        int sprxNewOff = b.Count;
        // push rbp ; mov rbp, rsp ; push r15 ; push r14 ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        // mov rbx, rsi (soname) ; mov r14, rdi (parent)
        b.AddRange([0x48, 0x89, 0xF3, 0x49, 0x89, 0xFE]);
        // mov edi, 1 ; mov esi, 0x490 ; call [rip+calloc]
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00, 0xBE, 0x90, 0x04, 0x00, 0x00]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        // mov r15, rax (new descriptor)
        b.AddRange([0x49, 0x89, 0xC7]);
        // mov [rax+0x450], r14 (parent)
        b.AddRange([0x4C, 0x89, 0xB0, 0x50, 0x04, 0x00, 0x00]);
        // vtable[0] = sprx_open: lea rax, [rip+sprx_open] ; mov [r15], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtOpenLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x07]);
        // vtable[1] = sprx_init_stub: lea rax, [rip+sprx_init_stub] ; mov [r15+8], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtInitLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x08]);
        // vtable[2] = sprx_sym2addr: lea rax, [rip+sprx_stub] ; mov [r15+0x10], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtSym2addrLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x10]);
        // vtable[3] = sprx_addr2sym: lea rax, [rip+sprx_stub] ; mov [r15+0x18], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtAddr2symLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x18]);
        // vtable[4] = sprx_fini: lea rax, [rip+sprx_stub] ; mov [r15+0x20], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtFiniLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x20]);
        // vtable[5] = sprx_close: lea rax, [rip+sprx_close] ; mov [r15+0x28], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtCloseLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x28]);
        // vtable[6] = sprx_destroy: lea rax, [rip+sprx_destroy] ; mov [r15+0x30], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int snVtDestroyLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x30]);
        // refcnt = 0: movl $0, [r15+0x448]
        b.AddRange([0x41, 0xC7, 0x87, 0x48, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // strcpy(lib->soname, soname): lea rdi, [r15+0x38] ; mov rsi, rbx ; call [rip+strcpy]
        b.AddRange([0x49, 0x8D, 0x7F, 0x38, 0x48, 0x89, 0xDE]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        // mov rax, r15 (return descriptor)
        b.AddRange([0x4C, 0x89, 0xF8]);
        // epilogue: add rsp, 8 ; pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _sprxNewBytes = b.Count - sprxNewOff;

        // ---- __rtld_so_new (156 bytes) ----
        // calloc(1, 0x4D0), set parent, fill vtable[0..6], refcnt=0, strcpy soname.
        int soNewOff = b.Count;
        // push rbp ; mov rbp, rsp ; push r15 ; push r14 ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        // mov rbx, rsi (soname) ; mov r14, rdi (parent)
        b.AddRange([0x48, 0x89, 0xF3, 0x49, 0x89, 0xFE]);
        // mov edi, 1 ; mov esi, 0x4D0 ; call [rip+calloc]
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00, 0xBE, 0xD0, 0x04, 0x00, 0x00]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        // mov r15, rax (new descriptor)
        b.AddRange([0x49, 0x89, 0xC7]);
        // mov [rax+0x450], r14 (parent)
        b.AddRange([0x4C, 0x89, 0xB0, 0x50, 0x04, 0x00, 0x00]);
        // vtable[0] = so_open stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtOpenLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x07]);
        // vtable[1] = so_init stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtInitLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x08]);
        // vtable[2] = so_sym2addr stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtSym2addrLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x10]);
        // vtable[3] = so_addr2sym stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtAddr2symLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x18]);
        // vtable[4] = so_fini stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtFiniLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x20]);
        // vtable[5] = so_close stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtCloseLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x28]);
        // vtable[6] = so_destroy stub
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);
        int soNVtDestroyLeaAt = b.Count - 4;
        b.AddRange([0x49, 0x89, 0x47, 0x30]);
        // refcnt = 0: movl $0, [r15+0x448]
        b.AddRange([0x41, 0xC7, 0x87, 0x48, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // strcpy(lib->soname, soname): lea rdi, [r15+0x38] ; mov rsi, rbx ; call [rip+strcpy]
        b.AddRange([0x49, 0x8D, 0x7F, 0x38, 0x48, 0x89, 0xDE]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        // mov rax, r15 (return descriptor)
        b.AddRange([0x4C, 0x89, 0xF8]);
        // epilogue: add rsp, 8 ; pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _soNewBytes = b.Count - soNewOff;

        // ============================================================================
        // so_init (vtable[1]) -- 106 bytes, SDK-exact
        // Calls each init_array entry with (argc, argv, envp).
        // Prototype: so_init(lib, argc, argv, envp) -> 0
        // ============================================================================
        int soInitVtOff = b.Count;
        // cmpq $0x8, 0x4b8(%rdi) ; jb .Learly_ret
        b.AddRange([0x48, 0x83, 0xBF, 0xB8, 0x04, 0x00, 0x00, 0x08]);
        b.AddRange([0x72, 0x5D]);  // jb +0x5d -> early ret (xor eax,eax; ret)
        // push rbp; mov rbp,rsp; push r15; push r14; push r13; push r12; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x50]);
        // mov rbx, rcx (envp); mov r14, rdx (argv); mov r15d, esi (argc); mov r12, rdi (lib)
        b.AddRange([0x48, 0x89, 0xCB, 0x49, 0x89, 0xD6, 0x41, 0x89, 0xF7, 0x49, 0x89, 0xFC]);
        // xor r13d, r13d (loop counter = 0)
        b.AddRange([0x45, 0x31, 0xED]);
        // nopw 0x0(%rax,%rax,1) -- alignment padding (9 bytes)
        b.AddRange([0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lloop: mov rax, [r12+0x4b0] (init_array ptr)
        b.AddRange([0x49, 0x8B, 0x84, 0x24, 0xB0, 0x04, 0x00, 0x00]);
        // mov edi, r15d (argc); mov rsi, r14 (argv); mov rdx, rbx (envp)
        b.AddRange([0x44, 0x89, 0xFF, 0x4C, 0x89, 0xF6, 0x48, 0x89, 0xDA]);
        // call *(%rax,%r13,8)
        b.AddRange([0x42, 0xFF, 0x14, 0xE8]);
        // inc r13
        b.AddRange([0x49, 0xFF, 0xC5]);
        // mov rax, [r12+0x4b8] (init_array_size)
        b.AddRange([0x49, 0x8B, 0x84, 0x24, 0xB8, 0x04, 0x00, 0x00]);
        // shr rax, 3 (count = size / 8)
        b.AddRange([0x48, 0xC1, 0xE8, 0x03]);
        // cmp rax, r13; jb .Lloop
        b.AddRange([0x49, 0x39, 0xC5]);
        b.AddRange([0x72, 0xD7]);  // jb -0x29 -> .Lloop
        // epilogue: add rsp,8; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D]);
        // .Learly_ret: xor eax, eax; ret
        b.AddRange([0x31, 0xC0, 0xC3]);
        int soInitVtBytes = b.Count - soInitVtOff;

        // ============================================================================
        // so_sym2addr (vtable[2]) -- 194 bytes, SDK-exact
        // Walk symtab, strcmp(name, strtab+entry.st_name), return mapbase+st_value.
        // Prototype: so_sym2addr(lib, name) -> addr or 0
        // Uses: .bss.strcmp (indirect call through BSS slot)
        // ============================================================================
        _soSym2addrRelocs = [];
        _currentRelocs = _soSym2addrRelocs;
        int soSym2addrOff = b.Count;
        // push rbp; mov rbp,rsp; push r15; push r14; push r13; push r12; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x50]);
        // cmpq $0, 0x490(%rdi) ; je .Lret0  (check symtab != NULL)
        b.AddRange([0x48, 0x83, 0xBF, 0x90, 0x04, 0x00, 0x00, 0x00]);
        b.AddRange([0x74, 0x21]);  // je +0x21 -> .Lret0
        // mov r14, rdi
        b.AddRange([0x49, 0x89, 0xFE]);
        // cmpq $0, 0x488(%rdi) ; je .Lret0  (check strtab != NULL)
        b.AddRange([0x48, 0x83, 0xBF, 0x88, 0x04, 0x00, 0x00, 0x00]);
        b.AddRange([0x74, 0x14]);  // je +0x14 -> .Lret0
        // cmpq $0, 0x438(%r14) ; je .Lret0  (check mapbase != NULL)
        b.AddRange([0x49, 0x83, 0xBE, 0x38, 0x04, 0x00, 0x00, 0x00]);
        b.AddRange([0x74, 0x0A]);  // je +0x0a -> .Lret0
        // cmpq $0x18, 0x498(%r14) ; jae .Lscan  (check symtab_size >= 0x18)
        b.AddRange([0x49, 0x83, 0xBE, 0x98, 0x04, 0x00, 0x00, 0x18]);
        b.AddRange([0x73, 0x14]);  // jae +0x14 -> .Lscan
        // .Lret0: xor ebx, ebx
        b.AddRange([0x31, 0xDB]);
        // .Lret: mov rax, rbx ; epilogue
        int soS2aRetPt = b.Count;  // offset of mov rax, rbx
        b.AddRange([0x48, 0x89, 0xD8]);
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        // .Lscan: mov r15, rsi (name); xor ebx, ebx; xor r13d, r13d; xor r12d, r12d
        b.AddRange([0x49, 0x89, 0xF7]);
        b.AddRange([0x31, 0xDB]);
        b.AddRange([0x45, 0x31, 0xED]);
        b.AddRange([0x45, 0x31, 0xE4]);
        // jmp .Lcheck
        b.AddRange([0xEB, 0x29]);  // jmp +0x29 -> .Lcheck
        // nopw 0x0(%rax,%rax,1) -- 6-byte alignment padding
        b.AddRange([0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]);
        // .Lnext: inc r12
        b.AddRange([0x49, 0xFF, 0xC4]);
        // movabs $0xaaaaaaaaaaaaaaab, %rdx (magic multiplier for /24)
        b.AddRange([0x48, 0xBA, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        // mulx 0x498(%r14), %rax, %rax (symtab_size * magic)
        b.AddRange([0xC4, 0xC2, 0xFB, 0xF6, 0x86, 0x98, 0x04, 0x00, 0x00]);
        // shr rax, 4 (entry_count = symtab_size / 0x18)
        b.AddRange([0x48, 0xC1, 0xE8, 0x04]);
        // add r13, 0x18
        b.AddRange([0x49, 0x83, 0xC5, 0x18]);
        // cmp rax, r12 ; jae .Lret (if r12 >= count: done)
        b.AddRange([0x49, 0x39, 0xC4]);
        b.AddRange([0x73, 0xB8]);  // jae -> .Lret (back to soS2aRetPt-relative)
        // .Lcheck: mov rax, [r14+0x490] (symtab)
        b.AddRange([0x49, 0x8B, 0x86, 0x90, 0x04, 0x00, 0x00]);
        // cmpq $0, 0x10(%rax,%r13,1) (st_value != 0?)
        b.AddRange([0x4A, 0x83, 0x7C, 0x28, 0x10, 0x00]);
        // je .Lnext (skip if st_value == 0)
        b.AddRange([0x74, 0xCE]);  // je -> .Lnext
        // mov esi, (%rax,%r13,1) (st_name offset)
        b.AddRange([0x42, 0x8B, 0x34, 0x28]);
        // add rsi, [r14+0x488] (rsi = strtab + st_name)
        b.AddRange([0x49, 0x03, 0xB6, 0x88, 0x04, 0x00, 0x00]);
        // mov rdi, r15 (name)
        b.AddRange([0x4C, 0x89, 0xFF]);
        // call *[rip+strcmp]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        int soS2aStrcmpRelAt = b.Count - 4;
        AddRel(RelocSymbol.RtldStrcmp, soS2aStrcmpRelAt);
        // test eax, eax; jne .Lnext (if strcmp != 0: no match)
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0xB6]);  // jne -> .Lnext
        // Found: mov rbx, [r14+0x438] (mapbase)
        b.AddRange([0x49, 0x8B, 0x9E, 0x38, 0x04, 0x00, 0x00]);
        // mov rax, [r14+0x490] (symtab)
        b.AddRange([0x49, 0x8B, 0x86, 0x90, 0x04, 0x00, 0x00]);
        // add rbx, [rax+r13*1+0x8] (rbx = mapbase + st_value)
        b.AddRange([0x4A, 0x03, 0x5C, 0x28, 0x08]);
        // jmp .Lret
        b.AddRange([0xE9, 0x79, 0xFF, 0xFF, 0xFF]);  // jmp -> .Lret (rel32 back)
        int soSym2addrBytes = b.Count - soSym2addrOff;

        // ============================================================================
        // so_addr2sym (vtable[3]) -- 159 bytes, SDK-exact
        // Given an address, find the symbol name from the symtab.
        // Prototype: so_addr2sym(lib, addr) -> strtab+st_name or 0
        // No relocations.
        // ============================================================================
        int soAddr2symOff = b.Count;
        // mov rcx, [rdi+0x490] (symtab)
        b.AddRange([0x48, 0x8B, 0x8F, 0x90, 0x04, 0x00, 0x00]);
        // test rcx, rcx; je .Lret0
        b.AddRange([0x48, 0x85, 0xC9]);
        b.AddRange([0x74, 0x4A]);  // je +0x4a -> .Lret0
        // mov r8, [rdi+0x488] (strtab)
        b.AddRange([0x4C, 0x8B, 0x87, 0x88, 0x04, 0x00, 0x00]);
        // test r8, r8; je .Lret0
        b.AddRange([0x4D, 0x85, 0xC0]);
        b.AddRange([0x74, 0x3E]);  // je +0x3e -> .Lret0
        // mov r9, [rdi+0x438] (mapbase)
        b.AddRange([0x4C, 0x8B, 0x8F, 0x38, 0x04, 0x00, 0x00]);
        // xor eax, eax
        b.AddRange([0x31, 0xC0]);
        // test r9, r9; je .Lret
        b.AddRange([0x4D, 0x85, 0xC9]);
        b.AddRange([0x74, 0x32]);  // je +0x32 -> .Lret
        // cmp rsi, r9; ja .Lret (addr < mapbase)
        b.AddRange([0x49, 0x39, 0xF1]);
        b.AddRange([0x77, 0x2D]);  // ja +0x2d -> .Lret
        // mov rax, [rdi+0x440] (mapsize)
        b.AddRange([0x48, 0x8B, 0x87, 0x40, 0x04, 0x00, 0x00]);
        // add rax, r9 (rax = mapbase + mapsize)
        b.AddRange([0x4C, 0x01, 0xC8]);
        // cmp rsi, rax; jb .Lret0 (addr >= end)
        b.AddRange([0x48, 0x39, 0xF0]);
        b.AddRange([0x72, 0x1C]);  // jb +0x1c -> .Lret0
        // mov rdx, [rdi+0x498] (symtab_size)
        b.AddRange([0x48, 0x8B, 0x97, 0x98, 0x04, 0x00, 0x00]);
        // movabs rax, 0xaaaaaaaaaaaaaaab (magic for /24)
        b.AddRange([0x48, 0xB8, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        // mulx rdi, rdi, rax
        b.AddRange([0xC4, 0xE2, 0xC3, 0xF6, 0xF8]);
        // cmp rdx, 0x18; jae .Lscan
        b.AddRange([0x48, 0x83, 0xFA, 0x18]);
        b.AddRange([0x73, 0x03]);  // jae +0x03 -> .Lscan
        // .Lret0: xor eax, eax
        b.AddRange([0x31, 0xC0]);
        // .Lret: ret
        b.AddRange([0xC3]);
        // .Lscan: shr rdi, 4 (entry count)
        b.AddRange([0x48, 0xC1, 0xEF, 0x04]);
        // add rcx, 0x10 (point to st_value in first entry: symtab + 0x10)
        b.AddRange([0x48, 0x83, 0xC1, 0x10]);
        // xor eax, eax
        b.AddRange([0x31, 0xC0]);
        // jmp .Lcheck
        b.AddRange([0xEB, 0x14]);  // jmp +0x14 -> .Lcheck
        // nop alignment: data16 cs nopw 0x0(%rax,%rax,1) -- 10 bytes
        b.AddRange([0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lnext: add rcx, 0x18; dec rdi; je .Lret
        b.AddRange([0x48, 0x83, 0xC1, 0x18]);
        b.AddRange([0x48, 0xFF, 0xCF]);
        b.AddRange([0x74, 0xDF]);  // je -> .Lret (offset 0x58)
        // .Lcheck: mov rdx, [rcx] (st_size at offset 0x10 of entry)
        b.AddRange([0x48, 0x8B, 0x11]);
        // test rdx, rdx; je .Lnext
        b.AddRange([0x48, 0x85, 0xD2]);
        b.AddRange([0x74, 0xEF]);  // je -> .Lnext
        // mov r10, [rcx-8] (st_value at offset 0x08 of entry)
        b.AddRange([0x4C, 0x8B, 0x51, 0xF8]);
        // add r10, r9 (r10 = mapbase + st_value)
        b.AddRange([0x4D, 0x01, 0xCA]);
        // cmp rsi, r10; ja .Lnext (addr < mapbase+st_value)
        b.AddRange([0x49, 0x39, 0xF2]);
        b.AddRange([0x77, 0xE3]);  // ja -> .Lnext
        // add r10, rdx (r10 = mapbase + st_value + st_size)
        b.AddRange([0x49, 0x01, 0xD2]);
        // cmp rsi, r10; jb .Lnext (addr >= end of symbol)
        b.AddRange([0x49, 0x39, 0xF2]);
        b.AddRange([0x72, 0xDB]);  // jb -> .Lnext
        // Found: mov eax, [rcx-0x10] (st_name)
        b.AddRange([0x8B, 0x41, 0xF0]);
        // add r8, rax (r8 = strtab + st_name)
        b.AddRange([0x49, 0x01, 0xC0]);
        // mov rax, r8; ret
        b.AddRange([0x4C, 0x89, 0xC0]);
        b.AddRange([0xC3]);
        int soAddr2symBytes = b.Count - soAddr2symOff;

        // ============================================================================
        // so_fini (vtable[4]) -- 69 bytes, SDK-exact
        // Calls each fini_array entry (forward order, unlike payload_fini which reverses).
        // Prototype: so_fini(lib) -> 0
        // No relocations.
        // ============================================================================
        int soFiniOff = b.Count;
        // cmpq $0x8, 0x4c8(%rdi) ; jb .Learly_ret
        b.AddRange([0x48, 0x83, 0xBF, 0xC8, 0x04, 0x00, 0x00, 0x08]);
        b.AddRange([0x72, 0x38]);  // jb +0x38 -> early ret
        // push rbp; mov rbp,rsp; push r14; push rbx
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53]);
        // mov rbx, rdi; xor r14d, r14d (loop counter)
        b.AddRange([0x48, 0x89, 0xFB, 0x45, 0x31, 0xF6]);
        // nopw 0x0(%rax,%rax,1) -- 9-byte alignment padding
        b.AddRange([0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lloop: mov rax, [rbx+0x4c0] (fini_array ptr)
        b.AddRange([0x48, 0x8B, 0x83, 0xC0, 0x04, 0x00, 0x00]);
        // call *(%rax,%r14,8)
        b.AddRange([0x42, 0xFF, 0x14, 0xF0]);
        // inc r14
        b.AddRange([0x49, 0xFF, 0xC6]);
        // mov rax, [rbx+0x4c8] (fini_array_size)
        b.AddRange([0x48, 0x8B, 0x83, 0xC8, 0x04, 0x00, 0x00]);
        // shr rax, 3 (count = size / 8)
        b.AddRange([0x48, 0xC1, 0xE8, 0x03]);
        // cmp rax, r14; jb .Lloop
        b.AddRange([0x49, 0x39, 0xC6]);
        b.AddRange([0x72, 0xE2]);  // jb -> .Lloop
        // epilogue: pop rbx; pop r14; pop rbp
        b.AddRange([0x5B, 0x41, 0x5E, 0x5D]);
        // .Learly_ret: xor eax, eax; ret
        b.AddRange([0x31, 0xC0, 0xC3]);
        int soFiniBytes = b.Count - soFiniOff;

        // ============================================================================
        // so_close (vtable[5]) -- 114 bytes, SDK-exact
        // Free elf_header, munmap(mapbase, mapsize), zero all SO-specific fields.
        // Prototype: so_close(lib) -> 0
        // Uses: .bss.free, __crt_syscall (for SYS_munmap=0x49)
        // ============================================================================
        _soCloseRelocs = [];
        _currentRelocs = _soCloseRelocs;
        int soCloseOff = b.Count;
        // push rbp; mov rbp,rsp; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        // mov rbx, rdi
        b.AddRange([0x48, 0x89, 0xFB]);
        // mov rdi, [rdi+0x468] (elf_header)
        b.AddRange([0x48, 0x8B, 0xBF, 0x68, 0x04, 0x00, 0x00]);
        // test rdi, rdi; je .Lskip_free
        b.AddRange([0x48, 0x85, 0xFF]);
        b.AddRange([0x74, 0x06]);  // je +0x06
        // call *[rip+free]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .Lskip_free: mov rsi, [rbx+0x438] (mapbase)
        b.AddRange([0x48, 0x8B, 0xB3, 0x38, 0x04, 0x00, 0x00]);
        // test rsi, rsi; je .Lskip_munmap
        b.AddRange([0x48, 0x85, 0xF6]);
        b.AddRange([0x74, 0x14]);  // je +0x14
        // mov rdx, [rbx+0x440] (mapsize)
        b.AddRange([0x48, 0x8B, 0x93, 0x40, 0x04, 0x00, 0x00]);
        // mov edi, 0x49 (SYS_munmap); xor eax, eax
        b.AddRange([0xBF, 0x49, 0x00, 0x00, 0x00]);
        b.AddRange([0x31, 0xC0]);
        // call *[rip+__crt_syscall]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        int soCloseSyscallRelAt = b.Count - 4;
        AddRel(RelocSymbol.PtrSyscall, soCloseSyscallRelAt);
        // .Lskip_munmap: zero fields using AVX
        // vxorps xmm0, xmm0, xmm0
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);
        // vmovups [rbx+0x468], ymm0 (zero 32 bytes: elf_header/elf_copy/phdr/shdr)
        b.AddRange([0xC5, 0xFC, 0x11, 0x83, 0x68, 0x04, 0x00, 0x00]);
        // vxorps xmm0, xmm0, xmm0
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);
        // vmovups [rbx+0x488], xmm0 (zero 16 bytes: strtab/symtab)
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x88, 0x04, 0x00, 0x00]);
        // movq $0, [rbx+0x498] (zero symtab_size)
        b.AddRange([0x48, 0xC7, 0x83, 0x98, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // vmovups [rbx+0x438], xmm0 (zero 16 bytes: mapbase/mapsize)
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x38, 0x04, 0x00, 0x00]);
        // xor eax, eax; add rsp,8; pop rbx; pop rbp; vzeroupper; ret
        b.AddRange([0x31, 0xC0]);
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);
        b.AddRange([0x5B, 0x5D]);
        b.AddRange([0xC5, 0xF8, 0x77]);  // vzeroupper
        b.AddRange([0xC3]);
        int soCloseBytes = b.Count - soCloseOff;

        // ============================================================================
        // so_destroy (vtable[6]) -- 120 bytes, SDK-exact
        // Same as so_close but also calls free(lib) at end.
        // Prototype: so_destroy(lib) -> void (jmp free)
        // Uses: .bss.free (x2), __crt_syscall
        // ============================================================================
        _soDestroyRelocs = [];
        _currentRelocs = _soDestroyRelocs;
        int soDestroyOff = b.Count;
        // push rbp; mov rbp,rsp; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        // mov rbx, rdi
        b.AddRange([0x48, 0x89, 0xFB]);
        // mov rdi, [rdi+0x468] (elf_header)
        b.AddRange([0x48, 0x8B, 0xBF, 0x68, 0x04, 0x00, 0x00]);
        // test rdi, rdi; je .Lskip_free
        b.AddRange([0x48, 0x85, 0xFF]);
        b.AddRange([0x74, 0x06]);  // je +0x06
        // call *[rip+free]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .Lskip_free: mov rsi, [rbx+0x438] (mapbase)
        b.AddRange([0x48, 0x8B, 0xB3, 0x38, 0x04, 0x00, 0x00]);
        // test rsi, rsi; je .Lskip_munmap
        b.AddRange([0x48, 0x85, 0xF6]);
        b.AddRange([0x74, 0x14]);  // je +0x14
        // mov rdx, [rbx+0x440] (mapsize)
        b.AddRange([0x48, 0x8B, 0x93, 0x40, 0x04, 0x00, 0x00]);
        // mov edi, 0x49 (SYS_munmap); xor eax, eax
        b.AddRange([0xBF, 0x49, 0x00, 0x00, 0x00]);
        b.AddRange([0x31, 0xC0]);
        // call *[rip+__crt_syscall]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        int soDestroySyscallRelAt = b.Count - 4;
        AddRel(RelocSymbol.PtrSyscall, soDestroySyscallRelAt);
        // .Lskip_munmap: zero fields using AVX (same as so_close)
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);  // vxorps xmm0
        b.AddRange([0xC5, 0xFC, 0x11, 0x83, 0x68, 0x04, 0x00, 0x00]);  // vmovups [rbx+0x468], ymm0
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);  // vxorps xmm0
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x88, 0x04, 0x00, 0x00]);  // vmovups [rbx+0x488], xmm0
        b.AddRange([0x48, 0xC7, 0x83, 0x98, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);  // movq $0, [rbx+0x498]
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x38, 0x04, 0x00, 0x00]);  // vmovups [rbx+0x438], xmm0
        // mov rdi, rbx (lib ptr for free)
        b.AddRange([0x48, 0x89, 0xDF]);
        // epilogue: add rsp,8; pop rbx; pop rbp; vzeroupper
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);
        b.AddRange([0x5B, 0x5D]);
        b.AddRange([0xC5, 0xF8, 0x77]);  // vzeroupper
        // jmp *[rip+free] (tail-call free(lib))
        b.AddRange([0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        int soDestroyBytes = b.Count - soDestroyOff;

        // ============================================================================
        // so_open (vtable[0]) -- 2406 bytes, SDK-exact (.text.so_open)
        // Full .so dynamic library loader: find_file, SYS_open, read ELF header,
        // mmap PT_LOAD segments, parse .dynamic, resolve R_X86_64_GLOB_DAT and
        // R_X86_64_JUMP_SLOT relocations via r_glob_dat, load DT_NEEDED deps,
        // apply kernel_mprotect on text segments, strcpy soname into lib->path.
        // Prototype: so_open(lib) -> 0 or -1
        // Uses: __rtld_find_file, __crt_syscall, .bss.malloc, .bss.free,
        //       .bss.memcpy, .bss.strcpy, klog_perror, klog_printf,
        //       __rtld_lib_destroy, __rtld_lib_new, __rtld_lib_open,
        //       __rtld_lib_append_dep, __rtld_lib_sym2lib, __rtld_lib_sym2addr,
        //       r_glob_dat, kernel_mprotect, .rodata.so_open (two jump tables)
        // ============================================================================
        _soOpenRelocs = [];
        _currentRelocs = _soOpenRelocs;
        int soOpenOff = b.Count;

        // ---- Prologue (0x00-0x13) ----
        // push rbp; mov rbp, rsp; push r15-r12; push rbx; sub rsp, 0x458
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
                    0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x81, 0xEC,
                    0x58, 0x04, 0x00, 0x00]);
        // r14 = lib (rdi); rbx = &lib->soname (rdi+0x38)
        b.AddRange([0x49, 0x89, 0xFE]);                               // mov r14, rdi
        b.AddRange([0x48, 0x8D, 0x5F, 0x38]);                         // lea rbx, [rdi+0x38]
        // rsi = path_buf on stack (-0x470(%rbp))
        b.AddRange([0x48, 0x8D, 0xB5, 0x90, 0xFB, 0xFF, 0xFF]);     // lea rsi, [rbp-0x470]
        // rdi = soname; call __rtld_find_file(soname, path_buf)
        b.AddRange([0x48, 0x89, 0xDF]);                               // mov rdi, rbx
        // SDK: call *[rip+__rtld_find_file] → our: addr32 call find_file
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);
        int soOpenFindFileDisp = b.Count - 4;
        // test eax, eax; jne .Lexit_fail (0x954)
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x21, 0x09, 0x00, 0x00]);           // jne +0x921

        // ---- SYS_open (0x33-0x53) ----
        // Save soname ptr; lea rsi, path_buf; mov edi, SYS_open(5); xor edx, edx; xor eax, eax
        b.AddRange([0x48, 0x89, 0x5D, 0xD0]);                       // mov [rbp-0x30], rbx
        b.AddRange([0x48, 0x8D, 0xB5, 0x90, 0xFB, 0xFF, 0xFF]);   // lea rsi, [rbp-0x470]
        b.AddRange([0xBF, 0x05, 0x00, 0x00, 0x00]);                 // mov edi, 5 (SYS_open)
        b.AddRange([0x31, 0xD2]);                                     // xor edx, edx
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // r15 = fd; test r15d, r15d; js .Lerr_open (0x114)
        b.AddRange([0x49, 0x89, 0xC7]);                               // mov r15, rax
        b.AddRange([0x45, 0x85, 0xFF]);                               // test r15d, r15d
        b.AddRange([0x0F, 0x88, 0xBB, 0x00, 0x00, 0x00]);           // js +0xbb

        // ---- SYS_mmap for ELF header read (0x59-0x73) ----
        // mmap(0, 0x1de, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
        // edi=0x1de(len), esi=fd, edx=0, ecx=2(PROT_RW), r8d=?, r9d=-1
        b.AddRange([0xBF, 0xDE, 0x01, 0x00, 0x00]);                 // mov edi, 0x1de
        b.AddRange([0x44, 0x89, 0xFE]);                               // mov esi, r15d
        b.AddRange([0x31, 0xD2]);                                     // xor edx, edx
        b.AddRange([0xB9, 0x02, 0x00, 0x00, 0x00]);                 // mov ecx, 2
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // test rax, rax; js .Lerr_lseek (0xf2)
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x78, 0x7D]);                                     // js +0x7d

        // ---- SYS_read ELF header (0x75-0x8f) ----
        b.AddRange([0x48, 0x89, 0xC3]);                               // mov rbx, rax (buf)
        b.AddRange([0xBF, 0xDE, 0x01, 0x00, 0x00]);                 // mov edi, 0x1de
        b.AddRange([0x44, 0x89, 0xFE]);                               // mov esi, r15d (fd)
        b.AddRange([0x31, 0xD2]);                                     // xor edx, edx
        b.AddRange([0x31, 0xC9]);                                     // xor ecx, ecx
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x78, 0x61]);                                     // js +0x61 (.Lerr_lseek)

        // ---- malloc + SYS_pread (0x91-0xbc) ----
        // rdi = rbx (buf); call malloc
        b.AddRange([0x48, 0x89, 0xDF]);                               // mov rdi, rbx
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.malloc]
        AddRel(RelocSymbol.DlfcnMalloc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x0F, 0x84, 0xB5, 0x06, 0x00, 0x00]);           // je +0x6b5 (.Lerr_malloc)
        // r12 = allocated buf
        b.AddRange([0x49, 0x89, 0xC4]);                               // mov r12, rax
        // SYS_pread(fd, buf, len, offset=0): edi=3, esi=r15d, rdx=rax, rcx=rbx
        b.AddRange([0xBF, 0x03, 0x00, 0x00, 0x00]);                 // mov edi, 3 (SYS_read)
        b.AddRange([0x44, 0x89, 0xFE]);                               // mov esi, r15d
        b.AddRange([0x48, 0x89, 0xC2]);                               // mov rdx, rax
        b.AddRange([0x48, 0x89, 0xD9]);                               // mov rcx, rbx
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // cmp rax, rbx; jne .Lerr_pread (0x764)
        b.AddRange([0x48, 0x39, 0xD8]);                               // cmp rax, rbx
        b.AddRange([0x0F, 0x85, 0x9F, 0x06, 0x00, 0x00]);           // jne +0x69f

        // ---- SYS_close fd (0xc5-0xd4) ----
        b.AddRange([0xBF, 0x06, 0x00, 0x00, 0x00]);                 // mov edi, 6 (SYS_close)
        b.AddRange([0x44, 0x89, 0xFE]);                               // mov esi, r15d
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // test rax, rax; jns .Lpast_close_ok (0x124)
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x79, 0x4A]);                                     // jns +0x4a

        // ---- Error: close failed (0xda-0xf0) ----
        // lea rdi, [rip+"close"]; call klog_perror; mov rdi, r12; call free; jmp .Lr12_zero
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_close]
        int soOpenStrCloseLeaAt = b.Count - 4;
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_perror
        int soOpenKlogPerror1 = b.Count - 4;
        b.AddRange([0x4C, 0x89, 0xE7]);                               // mov rdi, r12
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        b.AddRange([0xEB, 0x2F]);                                     // jmp +0x2f (.Lr12_zero)

        // ---- Error: lseek failed (0xf2-0x112) ----
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_lseek]
        int soOpenStrLseekLeaAt = b.Count - 4;
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_perror
        int soOpenKlogPerror2 = b.Count - 4;
        // xor r12d, r12d; SYS_close(fd)
        b.AddRange([0x45, 0x31, 0xE4]);                               // xor r12d, r12d
        b.AddRange([0xBF, 0x06, 0x00, 0x00, 0x00]);                 // mov edi, 6
        b.AddRange([0x44, 0x89, 0xFE]);                               // mov esi, r15d
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        b.AddRange([0xEB, 0x10]);                                     // jmp +0x10

        // ---- Error: open failed (0x114-0x123) ----
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_open]
        int soOpenStrOpenLeaAt = b.Count - 4;
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_perror
        int soOpenKlogPerror3 = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xE4]);                               // xor r12d, r12d

        // ---- Store mapbase, compute phdr layout (0x124-0x1d8) ----
        b.AddRange([0x48, 0x8B, 0x75, 0xD0]);                       // mov rsi, [rbp-0x30] (soname)
        b.AddRange([0x4D, 0x89, 0xA6, 0x68, 0x04, 0x00, 0x00]);   // mov [r14+0x468], r12
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0x4D, 0x85, 0xE4]);                               // test r12, r12
        b.AddRange([0x0F, 0x84, 0x17, 0x08, 0x00, 0x00]);           // je .Lexit (0x954)
        b.AddRange([0x4D, 0x89, 0xA6, 0x70, 0x04, 0x00, 0x00]);   // mov [r14+0x470], r12
        b.AddRange([0x49, 0x8B, 0x44, 0x24, 0x20]);                 // mov rax, [r12+0x20] (e_phoff)
        b.AddRange([0x49, 0x8D, 0x0C, 0x04]);                       // lea rcx, [r12+rax] (phdrs)
        b.AddRange([0x49, 0x89, 0x8E, 0x78, 0x04, 0x00, 0x00]);   // mov [r14+0x478], rcx
        b.AddRange([0x49, 0x8B, 0x4C, 0x24, 0x28]);                 // mov rcx, [r12+0x28] (e_shoff)
        b.AddRange([0x4C, 0x01, 0xE1]);                               // add rcx, r12
        b.AddRange([0x49, 0x89, 0x8E, 0x80, 0x04, 0x00, 0x00]);   // mov [r14+0x480], rcx
        // e_phnum (word at r12+0x38)
        b.AddRange([0x41, 0x0F, 0xB7, 0x4C, 0x24, 0x38]);           // movzwl ecx, [r12+0x38]
        b.AddRange([0x48, 0x85, 0xC9]);                               // test rcx, rcx
        b.AddRange([0x74, 0x5E]);                                     // je +0x5e (.Ldefault_mapsize)
        // Compute min vaddr and total span from PT_LOAD segments
        b.AddRange([0x48, 0x6B, 0xC9, 0x38]);                       // imul rcx, rcx, 0x38
        b.AddRange([0x4E, 0x8D, 0x4C, 0x20, 0x28]);                 // lea r9, [rax+r12+0x28]
        b.AddRange([0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF]);   // mov rax, -1
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        b.AddRange([0x31, 0xD2]);                                     // xor edx, edx
        // NOP alignment
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F,
                    0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lphdr_loop (0x190-0x1b1):
        b.AddRange([0x49, 0x89, 0xD0]);                               // mov r8, rdx
        b.AddRange([0x49, 0x8B, 0x54, 0x39, 0xE8]);                 // mov rdx, [r9+rdi-0x18] (p_vaddr)
        b.AddRange([0x48, 0x39, 0xC2]);                               // cmp rdx, rax
        b.AddRange([0x48, 0x0F, 0x42, 0xC2]);                       // cmovb rax, rdx
        b.AddRange([0x49, 0x03, 0x14, 0x39]);                       // add rdx, [r9+rdi] (+ p_memsz)
        b.AddRange([0x49, 0x39, 0xD0]);                               // cmp r8, rdx
        b.AddRange([0x49, 0x0F, 0x47, 0xD0]);                       // cmova rdx, r8
        b.AddRange([0x48, 0x83, 0xC7, 0x38]);                       // add rdi, 0x38
        b.AddRange([0x48, 0x39, 0xF9]);                               // cmp rcx, rdi
        b.AddRange([0x75, 0xDD]);                                     // jne .-0x23
        // Align to page boundary
        b.AddRange([0x48, 0x25, 0x00, 0xC0, 0xFF, 0xFF]);           // and rax, ~0x3fff
        b.AddRange([0x48, 0x81, 0xC2, 0xFF, 0x3F, 0x00, 0x00]);   // add rdx, 0x3fff
        b.AddRange([0x48, 0x81, 0xE2, 0x00, 0xC0, 0xFF, 0xFF]);   // and rdx, ~0x3fff
        b.AddRange([0x48, 0x29, 0xC2]);                               // sub rdx, rax
        b.AddRange([0xEB, 0x05]);                                     // jmp +5
        // .Ldefault_mapsize:
        b.AddRange([0xBA, 0x00, 0x40, 0x00, 0x00]);                 // mov edx, 0x4000
        // Store mapsize
        b.AddRange([0x49, 0x89, 0x96, 0x40, 0x04, 0x00, 0x00]);   // mov [r14+0x440], rdx

        // ---- Validate e_type == ET_DYN (0x1d8-0x1e4) ----
        b.AddRange([0x66, 0x41, 0x83, 0x7C, 0x24, 0x10, 0x03]);   // cmpw $3, [r12+0x10]
        b.AddRange([0x0F, 0x85, 0x5F, 0x05, 0x00, 0x00]);           // jne +0x55f (.Lerr_not_shared)

        // ---- SYS_mmap for mapbase (0x1e5-0x218) ----
        b.AddRange([0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]); // movq $0, (%rsp)
        b.AddRange([0xBF, 0xDD, 0x01, 0x00, 0x00]);                 // mov edi, 0x1dd (SYS_mmap)
        b.AddRange([0x31, 0xF6]);                                     // xor esi, esi
        b.AddRange([0xB9, 0x03, 0x00, 0x00, 0x00]);                 // mov ecx, 3 (PROT_READ|PROT_WRITE)
        b.AddRange([0x41, 0xB8, 0x02, 0x10, 0x00, 0x00]);           // mov r8d, 0x1002 (MAP_PRIVATE|MAP_ANON)
        b.AddRange([0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);           // mov r9d, -1
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        // Store mapbase; check for MAP_FAILED
        b.AddRange([0x49, 0x89, 0x86, 0x38, 0x04, 0x00, 0x00]);   // mov [r14+0x438], rax
        b.AddRange([0x48, 0x83, 0xF8, 0xFF]);                       // cmp rax, -1
        b.AddRange([0x0F, 0x84, 0x31, 0x07, 0x00, 0x00]);           // je +0x731 (.Lexit_fail_mmap)

        // ---- Prepare phdr iteration (0x21e-0x24f) ----
        b.AddRange([0x49, 0x8B, 0x86, 0x70, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x470]
        b.AddRange([0x66, 0x83, 0x78, 0x38, 0x00]);                 // cmpw $0, 0x38(rax) (e_phnum)
        b.AddRange([0x4C, 0x89, 0x75, 0xC0]);                       // mov [rbp-0x40], r14
        b.AddRange([0xBF, 0x00, 0x00, 0x00, 0x00]);                 // mov edi, 0 (error status)
        b.AddRange([0x0F, 0x84, 0xB3, 0x02, 0x00, 0x00]);           // je +0x2b3 (.Lpast_phdrs)
        // r15 = jump table 1 base (.rodata.so_open)
        b.AddRange([0x4C, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea r15, [rip+.rodata.so_open]
        int soOpenJmpTbl1LeaAt = b.Count - 4;
        b.AddRange([0x31, 0xDB]);                                     // xor ebx, ebx
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        // NOP alignment
        b.AddRange([0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84,
                    0x00, 0x00, 0x00, 0x00, 0x00]);

        // ---- PT_LOAD segment iteration + .dynamic parse (0x250-0x39b) ----
        // This is the phdr loop + DT_ tag switch (jump table 1)
        // 0x250: .Lphdr_load_loop
        b.AddRange([0x4D, 0x8B, 0x86, 0x78, 0x04, 0x00, 0x00]);   // mov r8, [r14+0x478]
        b.AddRange([0x48, 0x6B, 0xCB, 0x38]);                       // imul rcx, rbx, 0x38
        b.AddRange([0x41, 0x8B, 0x04, 0x08]);                       // mov eax, [r8+rcx]
        b.AddRange([0x83, 0xF8, 0x02]);                               // cmp eax, 2 (PT_DYNAMIC)
        b.AddRange([0x74, 0x4C]);                                     // je +0x4c
        b.AddRange([0x83, 0xF8, 0x01]);                               // cmp eax, 1 (PT_LOAD)
        b.AddRange([0x0F, 0x85, 0x64, 0x02, 0x00, 0x00]);           // jne +0x264 (.Lnext_phdr)
        // PT_LOAD handler: memcpy segment into mapbase
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        b.AddRange([0x49, 0x83, 0x7C, 0x08, 0x28, 0x00]);           // cmpq $0, [r8+rcx+0x28] (p_memsz)
        b.AddRange([0x0F, 0x84, 0x56, 0x02, 0x00, 0x00]);           // je .Lnext_phdr
        b.AddRange([0x49, 0x8B, 0x54, 0x08, 0x20]);                 // mov rdx, [r8+rcx+0x20] (p_filesz)
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx
        b.AddRange([0x0F, 0x84, 0x48, 0x02, 0x00, 0x00]);           // je .Lnext_phdr
        b.AddRange([0x49, 0x8B, 0xBE, 0x38, 0x04, 0x00, 0x00]);   // mov rdi, [r14+0x438] (mapbase)
        b.AddRange([0x49, 0x8B, 0xB6, 0x68, 0x04, 0x00, 0x00]);   // mov rsi, [r14+0x468] (buf)
        b.AddRange([0x49, 0x03, 0x7C, 0x08, 0x10]);                 // add rdi, [r8+rcx+0x10] (+ p_offset → p_vaddr)
        b.AddRange([0x49, 0x03, 0x74, 0x08, 0x08]);                 // add rsi, [r8+rcx+0x08] (+ p_offset)
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        b.AddRange([0xE9, 0x23, 0x02, 0x00, 0x00]);                 // jmp .Lnext_phdr
        // alignment
        b.AddRange([0x66, 0x90]);                                     // nop (2-byte)

        // PT_DYNAMIC handler (0x2b0): parse .dynamic section via jump table
        b.AddRange([0x49, 0x8B, 0x86, 0x68, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x468] (buf)
        b.AddRange([0x49, 0x8B, 0x4C, 0x08, 0x08]);                 // mov rcx, [r8+rcx+0x08] (p_offset)
        b.AddRange([0x48, 0x8D, 0x74, 0x08, 0x08]);                 // lea rsi, [rax+rcx+8]
        b.AddRange([0x31, 0xD2]);                                     // xor edx, edx (gnu_hash ptr)
        b.AddRange([0xEB, 0x0E]);                                     // jmp +0xe (.Ldt_loop)

        // .Ldt_strsz (0x2c5): DT_STRSZ(10) handler
        b.AddRange([0x48, 0x8B, 0x3E]);                               // mov rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0xC8, 0x04, 0x00, 0x00]);   // mov [r14+0x4c8], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        // .Ldt_loop (0x2d3): read d_tag
        b.AddRange([0x48, 0x8B, 0x7E, 0xF8]);                       // mov rdi, [rsi-8] (d_tag)
        b.AddRange([0x48, 0x83, 0xFF, 0x1C]);                       // cmp rdi, 0x1c
        b.AddRange([0x77, 0x19]);                                     // ja +0x19 (.Ldt_check_gnu_hash)
        // jump table dispatch
        b.AddRange([0x49, 0x63, 0x3C, 0xBF]);                       // movslq rdi, [r15+rdi*4]
        b.AddRange([0x4C, 0x01, 0xFF]);                               // add rdi, r15
        b.AddRange([0xFF, 0xE7]);                                     // jmp *rdi

        // DT_RELASZ(8) handler (0x2e6):
        b.AddRange([0x48, 0x8B, 0x3E]);                               // mov rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0xA8, 0x04, 0x00, 0x00]);   // mov [r14+0x4a8], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xEB, 0xDD]);                                     // jmp .Ldt_loop

        // DT_GNU_HASH check (0x2f6):
        b.AddRange([0x48, 0x81, 0xFF, 0xF5, 0xFE, 0xFF, 0x6F]);   // cmp rdi, 0x6ffffef5
        b.AddRange([0x75, 0xD0]);                                     // jne .Ldt_next (.Ldt_strsz skip)
        b.AddRange([0x49, 0x8B, 0x50, 0x08]);                       // mov rdx, [r8+8]
        b.AddRange([0x48, 0x01, 0xC2]);                               // add rdx, rax
        b.AddRange([0x48, 0x03, 0x16]);                               // add rdx, [rsi]
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xEB, 0xC4]);                                     // jmp .Ldt_loop

        // DT_STRTAB(5)+mapbase handler (0x30f):
        b.AddRange([0x49, 0x8B, 0xBE, 0x38, 0x04, 0x00, 0x00]);   // mov rdi, [r14+0x438]
        b.AddRange([0x48, 0x03, 0x3E]);                               // add rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0xB0, 0x04, 0x00, 0x00]);   // mov [r14+0x4b0], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xEB, 0xAD]);                                     // jmp .Ldt_loop

        // DT_PLTRELSZ(2) handler (0x326):
        b.AddRange([0x48, 0x8B, 0x3E]);                               // mov rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0xB8, 0x04, 0x00, 0x00]);   // mov [r14+0x4b8], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xEB, 0x9D]);                                     // jmp .Ldt_loop

        // DT_JMPREL(23)+base handler (0x336):
        b.AddRange([0x49, 0x8B, 0x78, 0x08]);                       // mov rdi, [r8+8]
        b.AddRange([0x48, 0x01, 0xC7]);                               // add rdi, rax
        b.AddRange([0x48, 0x03, 0x3E]);                               // add rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0xA0, 0x04, 0x00, 0x00]);   // mov [r14+0x4a0], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xEB, 0x86]);                                     // jmp .Ldt_loop

        // DT_INIT_ARRAY(25)+mapbase handler (0x34d):
        b.AddRange([0x49, 0x8B, 0xBE, 0x38, 0x04, 0x00, 0x00]);   // mov rdi, [r14+0x438]
        b.AddRange([0x48, 0x03, 0x3E]);                               // add rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0xC0, 0x04, 0x00, 0x00]);   // mov [r14+0x4c0], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xE9, 0x6C, 0xFF, 0xFF, 0xFF]);                 // jmp .Ldt_loop

        // DT_RELA(7)+base handler (0x367):
        b.AddRange([0x49, 0x8B, 0x78, 0x08]);                       // mov rdi, [r8+8]
        b.AddRange([0x48, 0x01, 0xC7]);                               // add rdi, rax
        b.AddRange([0x48, 0x03, 0x3E]);                               // add rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0x90, 0x04, 0x00, 0x00]);   // mov [r14+0x490], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xE9, 0x52, 0xFF, 0xFF, 0xFF]);                 // jmp .Ldt_loop

        // DT_SYMTAB(6)+base handler (0x381):
        b.AddRange([0x49, 0x8B, 0x78, 0x08]);                       // mov rdi, [r8+8]
        b.AddRange([0x48, 0x01, 0xC7]);                               // add rdi, rax
        b.AddRange([0x48, 0x03, 0x3E]);                               // add rdi, [rsi]
        b.AddRange([0x49, 0x89, 0xBE, 0x88, 0x04, 0x00, 0x00]);   // mov [r14+0x488], rdi
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                       // add rsi, 0x10
        b.AddRange([0xE9, 0x38, 0xFF, 0xFF, 0xFF]);                 // jmp .Ldt_loop

        // NOP alignment (0x39b):
        b.AddRange([0x0F, 0x1F, 0x44, 0x00, 0x00]);

        // ---- Compute symtab_size from gnu_hash (0x3a0-0x425) ----
        b.AddRange([0x48, 0x89, 0x5D, 0xB8]);                       // mov [rbp-0x48], rbx
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx (gnu_hash ptr)
        b.AddRange([0x74, 0x7D]);                                     // je +0x7d (.Lno_gnu_hash)
        b.AddRange([0x8B, 0x32]);                                     // mov esi, [rdx] (nbuckets)
        b.AddRange([0x48, 0x85, 0xF6]);                               // test rsi, rsi
        b.AddRange([0x74, 0x6A]);                                     // je +0x6a (.Lhash_fallback)
        b.AddRange([0x8B, 0x7A, 0x04]);                               // mov edi, [rdx+4] (symoffset)
        b.AddRange([0x44, 0x8B, 0x42, 0x08]);                       // mov r8d, [rdx+8] (bloom_size)
        b.AddRange([0x4A, 0x8D, 0x14, 0xC2]);                       // lea rdx, [rdx+r8*8]
        b.AddRange([0x4C, 0x8D, 0x44, 0xB2, 0x10]);                 // lea r8, [rdx+rsi*4+0x10]
        b.AddRange([0xF7, 0xDF]);                                     // neg edi
        b.AddRange([0x45, 0x31, 0xD2]);                               // xor r10d, r10d
        b.AddRange([0x45, 0x31, 0xC9]);                               // xor r9d, r9d
        b.AddRange([0xEB, 0x0E]);                                     // jmp +0x0e
        // nop alignment
        b.AddRange([0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]);
        // .Lgnu_hash_next (0x3d0):
        b.AddRange([0x49, 0xFF, 0xC2]);                               // inc r10
        b.AddRange([0x49, 0x39, 0xF2]);                               // cmp r10, rsi
        b.AddRange([0x74, 0x35]);                                     // je +0x35 (.Lgnu_hash_done)
        // .Lgnu_hash_body (0x3d8):
        b.AddRange([0x46, 0x8B, 0x5C, 0x92, 0x10]);                 // mov r11d, [rdx+r10*4+0x10]
        b.AddRange([0x45, 0x85, 0xDB]);                               // test r11d, r11d
        b.AddRange([0x74, 0xEE]);                                     // je .-0x12
        // chain walk
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F,
                    0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);           // 14-byte NOP
        // (0x3f0):
        b.AddRange([0x42, 0x8D, 0x1C, 0x1F]);                       // lea ebx, [rdi+r11]
        b.AddRange([0x41, 0xFF, 0xC3]);                               // inc r11d
        b.AddRange([0x41, 0xF6, 0x04, 0x98, 0x01]);                 // testb $1, [r8+rbx*4]
        b.AddRange([0x74, 0xF2]);                                     // je .-0x0e
        b.AddRange([0x41, 0xFF, 0xCB]);                               // dec r11d
        b.AddRange([0x45, 0x39, 0xCB]);                               // cmp r11d, r9d
        b.AddRange([0x45, 0x0F, 0x46, 0xD9]);                       // cmovbe r11d, r9d
        b.AddRange([0x45, 0x89, 0xD9]);                               // mov r9d, r11d
        b.AddRange([0xEB, 0xC3]);                                     // jmp .Lgnu_hash_next
        // .Lgnu_hash_done (0x40d):
        b.AddRange([0x41, 0xFF, 0xC1]);                               // inc r9d
        b.AddRange([0x49, 0xC1, 0xE1, 0x03]);                       // shl r9, 3
        b.AddRange([0x4B, 0x8D, 0x14, 0x49]);                       // lea rdx, [r9+r9*2]
        b.AddRange([0xEB, 0x05]);                                     // jmp +5
        // .Lhash_fallback (0x41a):
        b.AddRange([0xBA, 0x18, 0x00, 0x00, 0x00]);                 // mov edx, 0x18
        // .Lstore_symtab_size (0x41f):
        b.AddRange([0x49, 0x89, 0x96, 0x98, 0x04, 0x00, 0x00]);   // mov [r14+0x498], rdx

        // ---- Process DT_NEEDED dependencies (0x426-0x4cd) ----
        b.AddRange([0x48, 0x8B, 0x14, 0x08]);                       // mov rdx, [rax+rcx]
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx
        b.AddRange([0x41, 0x0F, 0x95, 0xC6]);                       // setne r14b
        b.AddRange([0x0F, 0x84, 0x89, 0x00, 0x00, 0x00]);           // je +0x89 (.Lpast_needed)

        b.AddRange([0x48, 0x8D, 0x5C, 0x08, 0x10]);                 // lea rbx, [rax+rcx+0x10]
        b.AddRange([0x41, 0xB6, 0x01]);                               // mov r14b, 1
        b.AddRange([0xEB, 0x38]);                                     // jmp +0x38

        // .Lneeded_err (0x441): error loading dependency
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_unable_load]
        int soOpenStrUnableLoadLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x75, 0xD0]);                       // mov rsi, [rbp-0x30]
        b.AddRange([0x4C, 0x89, 0xEA]);                               // mov rdx, r13
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_printf
        int soOpenKlogPrintf1 = b.Count - 4;
        b.AddRange([0x4C, 0x89, 0xE7]);                               // mov rdi, r12
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_destroy
        int soOpenLibDestroy1 = b.Count - 4;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0x85, 0xC0]);                                     // test eax, eax
        b.AddRange([0x75, 0x57]);                                     // jne +0x57 (.Lpast_needed)

        // .Lneeded_next (0x469):
        b.AddRange([0x48, 0x8B, 0x13]);                               // mov rdx, [rbx]
        b.AddRange([0x48, 0x83, 0xC3, 0x10]);                       // add rbx, 0x10
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx
        b.AddRange([0x41, 0x0F, 0x95, 0xC6]);                       // setne r14b
        b.AddRange([0x74, 0x47]);                                     // je +0x47 (.Lpast_needed)

        // .Lneeded_check (0x479):
        b.AddRange([0x48, 0x83, 0xFA, 0x01]);                       // cmp rdx, 1 (DT_NEEDED)
        b.AddRange([0x75, 0xEA]);                                     // jne .Lneeded_next

        // Load soname from strtab; call __rtld_lib_new; call __rtld_lib_open
        b.AddRange([0x48, 0x8B, 0x7D, 0xC0]);                       // mov rdi, [rbp-0x40] (lib)
        b.AddRange([0x4C, 0x8B, 0xAF, 0x88, 0x04, 0x00, 0x00]);   // mov r13, [rdi+0x488] (strtab)
        b.AddRange([0x4C, 0x03, 0x6B, 0xF8]);                       // add r13, [rbx-8] (+ d_val)
        b.AddRange([0x4C, 0x89, 0xEE]);                               // mov rsi, r13
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_new
        int soOpenLibNew1 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC4]);                               // mov r12, rax
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0x4D, 0x85, 0xE4]);                               // test r12, r12
        b.AddRange([0x74, 0xC1]);                                     // je .-0x3f (test eax, eax)
        // call __rtld_lib_open(r12)
        b.AddRange([0x4C, 0x89, 0xE7]);                               // mov rdi, r12
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_open
        int soOpenLibOpen1 = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                     // test eax, eax
        b.AddRange([0x75, 0x90]);                                     // jne .Lneeded_err
        // call __rtld_lib_append_dep(lib, child)
        b.AddRange([0x48, 0x8B, 0x7D, 0xC0]);                       // mov rdi, [rbp-0x40]
        b.AddRange([0x4C, 0x89, 0xE6]);                               // mov rsi, r12
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_append_dep
        int soOpenLibAppendDep1 = b.Count - 4;
        b.AddRange([0xEB, 0xA5]);                                     // jmp .Ltest_eax

        // .Lpast_needed (0x4c0):
        b.AddRange([0x41, 0x0F, 0xB6, 0xFE]);                       // movzbl edi, r14b
        b.AddRange([0x83, 0xE7, 0x01]);                               // and edi, 1
        b.AddRange([0xF7, 0xDF]);                                     // neg edi
        b.AddRange([0x4C, 0x8B, 0x75, 0xC0]);                       // mov r14, [rbp-0x40]
        b.AddRange([0x48, 0x8B, 0x5D, 0xB8]);                       // mov rbx, [rbp-0x48]

        // .Lnext_phdr (0x4d1):
        b.AddRange([0x48, 0xFF, 0xC3]);                               // inc rbx
        b.AddRange([0x49, 0x8B, 0x86, 0x70, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x470]
        b.AddRange([0x0F, 0xB7, 0x40, 0x38]);                       // movzwl eax, [rax+0x38] (e_phnum)
        b.AddRange([0x48, 0x39, 0xC3]);                               // cmp rbx, rax
        b.AddRange([0x73, 0x08]);                                     // jae +8
        b.AddRange([0x85, 0xFF]);                                     // test edi, edi
        b.AddRange([0x0F, 0x84, 0x64, 0xFD, 0xFF, 0xFF]);           // je .Lphdr_load_loop

        // ---- Process rela.dyn relocations (0x4ec-0x73f) ----
        // .Lpast_phdrs (0x4ec):
        b.AddRange([0x49, 0x8B, 0x86, 0x70, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x470]
        b.AddRange([0x66, 0x83, 0x78, 0x3C, 0x00]);                 // cmpw $0, [rax+0x3c] (e_shnum)
        b.AddRange([0x0F, 0x94, 0xC0]);                               // sete al
        b.AddRange([0x85, 0xFF]);                                     // test edi, edi
        b.AddRange([0x0F, 0x95, 0xC1]);                               // setne cl
        b.AddRange([0x08, 0xC1]);                                     // or cl, al
        b.AddRange([0x0F, 0x85, 0x9D, 0x02, 0x00, 0x00]);           // jne +0x29d (.Lpast_rela)

        // Load rela.dyn jump table 2 pointer
        b.AddRange([0x31, 0xC9]);                                     // xor ecx, ecx
        b.AddRange([0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00]);   // lea rbx, [rip+.rodata.so_open+0x70]
        int soOpenJmpTbl2LeaAt1 = b.Count - 4;
        b.AddRange([0x31, 0xD2]);                                     // xor edx, edx
        b.AddRange([0xEB, 0x33]);                                     // jmp +0x33
        // NOP alignment
        b.AddRange([0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84,
                    0x00, 0x00, 0x00, 0x00, 0x00]);

        // .Lrela_next (0x520):
        b.AddRange([0x48, 0x8B, 0x55, 0xB0]);                       // mov rdx, [rbp-0x50]
        b.AddRange([0x48, 0xFF, 0xC2]);                               // inc rdx
        b.AddRange([0x49, 0x8B, 0x86, 0x70, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x470]
        b.AddRange([0x0F, 0xB7, 0x40, 0x3C]);                       // movzwl eax, [rax+0x3c]
        b.AddRange([0x48, 0x39, 0xC2]);                               // cmp rdx, rax
        b.AddRange([0x0F, 0x93, 0xC0]);                               // setae al
        b.AddRange([0x85, 0xFF]);                                     // test edi, edi
        b.AddRange([0x0F, 0x95, 0xC1]);                               // setne cl
        b.AddRange([0x08, 0xC1]);                                     // or cl, al
        b.AddRange([0x80, 0xF9, 0x01]);                               // cmp cl, 1
        b.AddRange([0x0F, 0x84, 0x5D, 0x02, 0x00, 0x00]);           // je .Lpast_rela

        // .Lrela_body (0x548):
        b.AddRange([0x49, 0x8B, 0x86, 0x80, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x480]
        b.AddRange([0x48, 0x89, 0xD6]);                               // mov rsi, rdx
        b.AddRange([0x48, 0xC1, 0xE6, 0x06]);                       // shl rsi, 6
        b.AddRange([0x83, 0x7C, 0x30, 0x04, 0x04]);                 // cmpl $4, [rax+rsi+4] (sh_type == SHT_RELA)
        b.AddRange([0x48, 0x89, 0x55, 0xB0]);                       // mov [rbp-0x50], rdx
        b.AddRange([0x75, 0xBF]);                                     // jne .Lrela_next
        b.AddRange([0x48, 0x83, 0x7C, 0x30, 0x20, 0x18]);           // cmpq $0x18, [rax+rsi+0x20] (sh_entsize >= 0x18)
        b.AddRange([0x72, 0xB7]);                                     // jb .Lrela_next
        b.AddRange([0x85, 0xFF]);                                     // test edi, edi
        b.AddRange([0x75, 0xB3]);                                     // jne .Lrela_next

        // r15 = rela base; r13 = 0 (index)
        b.AddRange([0x48, 0x89, 0x4D, 0xA0]);                       // mov [rbp-0x60], rcx
        b.AddRange([0x4D, 0x8B, 0xBE, 0x68, 0x04, 0x00, 0x00]);   // mov r15, [r14+0x468]
        b.AddRange([0x4C, 0x03, 0x7C, 0x30, 0x18]);                 // add r15, [rax+rsi+0x18] (sh_offset)
        b.AddRange([0x45, 0x31, 0xED]);                               // xor r13d, r13d
        b.AddRange([0x48, 0x89, 0x75, 0xB8]);                       // mov [rbp-0x48], rsi
        // NOP alignment
        b.AddRange([0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84,
                    0x00, 0x00, 0x00, 0x00, 0x00]);

        // .Lrela_entry (0x590):
        b.AddRange([0x4F, 0x8D, 0x64, 0x6D, 0x00]);                 // lea r12, [r13+r13*2]
        b.AddRange([0x4B, 0x8B, 0x44, 0xE7, 0x08]);                 // mov rax, [r15+r12*8+8] (r_info)
        b.AddRange([0x8D, 0x48, 0xFF]);                               // lea ecx, [rax-1]
        b.AddRange([0x83, 0xF9, 0x07]);                               // cmp ecx, 7
        b.AddRange([0x0F, 0x87, 0xD9, 0x01, 0x00, 0x00]);           // ja +0x1d9 (.Lrela_unsup)

        // jump table 2 dispatch
        b.AddRange([0x4B, 0x8D, 0x34, 0xE7]);                       // lea rsi, [r15+r12*8]
        b.AddRange([0x48, 0x63, 0x0C, 0x8B]);                       // movslq rcx, [rbx+rcx*4]
        b.AddRange([0x48, 0x01, 0xD9]);                               // add rcx, rbx
        b.AddRange([0xFF, 0xE1]);                                     // jmp *rcx

        // R_X86_64_RELATIVE(8): call r_glob_dat (0x5b3):
        b.AddRange([0x4C, 0x89, 0xF7]);                               // mov rdi, r14
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);                 // call r_glob_dat
        int soOpenRGlobDat1 = b.Count - 4;
        b.AddRange([0x89, 0xC7]);                                     // mov edi, eax
        b.AddRange([0xE9, 0x49, 0x01, 0x00, 0x00]);                 // jmp .Lrela_check

        // NOP alignment (0x5c2):
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F,
                    0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // R_X86_64_GLOB_DAT(6) handler (0x5d0): resolve via parent chain
        b.AddRange([0x49, 0x8B, 0x8E, 0x90, 0x04, 0x00, 0x00]);   // mov rcx, [r14+0x490] (symtab)
        b.AddRange([0x48, 0xC1, 0xE8, 0x20]);                       // shr rax, 32 (sym index)
        b.AddRange([0x4C, 0x89, 0xF2]);                               // mov rdx, r14
        b.AddRange([0x4C, 0x8D, 0x34, 0x40]);                       // lea r14, [rax+rax*2]
        b.AddRange([0x4C, 0x8B, 0x82, 0x38, 0x04, 0x00, 0x00]);   // mov r8, [rdx+0x438] (mapbase)
        b.AddRange([0x48, 0x8B, 0x9A, 0x88, 0x04, 0x00, 0x00]);   // mov rbx, [rdx+0x488] (strtab)
        b.AddRange([0x48, 0x89, 0x4D, 0x98]);                       // mov [rbp-0x68], rcx
        b.AddRange([0x42, 0x8B, 0x04, 0xF1]);                       // mov eax, [rcx+r14*8] (st_name)
        b.AddRange([0x48, 0x8B, 0x0E]);                               // mov rcx, [rsi] (r_offset)
        b.AddRange([0x48, 0xC7, 0x45, 0xC8, 0x00, 0x00, 0x00, 0x00]); // movq $0, [rbp-0x38] (val)
        // NOP alignment
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F,
                    0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lparent_walk (0x610):
        b.AddRange([0x48, 0x89, 0xD7]);                               // mov rdi, rdx
        b.AddRange([0x48, 0x8B, 0x92, 0x50, 0x04, 0x00, 0x00]);   // mov rdx, [rdx+0x450] (parent)
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx
        b.AddRange([0x75, 0xF1]);                                     // jne .-0x0f
        // name = strtab + st_name; loc = mapbase + r_offset
        b.AddRange([0x48, 0x01, 0xC3]);                               // add rbx, rax
        b.AddRange([0x49, 0x01, 0xC8]);                               // add r8, rcx
        b.AddRange([0x4C, 0x89, 0x45, 0xA8]);                       // mov [rbp-0x58], r8

        // ---- sym2lib + sym2addr from root (0x629-0x64a) ----
        b.AddRange([0x48, 0x89, 0xDE]);                               // mov rsi, rbx
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_sym2lib
        int soOpenSym2lib1 = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x74, 0x15]);                                     // je +0x15
        b.AddRange([0x48, 0x89, 0xC7]);                               // mov rdi, rax
        b.AddRange([0x48, 0x89, 0xDE]);                               // mov rsi, rbx
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_sym2addr
        int soOpenSym2addr1 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xC8]);                       // mov [rbp-0x38], rax
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x75, 0x27]);                                     // jne +0x27 (.Lfound)

        // ---- sym2lib + sym2addr from ctx (0x64c-0x672) ----
        b.AddRange([0x48, 0x8B, 0x7D, 0xC0]);                       // mov rdi, [rbp-0x40]
        b.AddRange([0x48, 0x89, 0xDE]);                               // mov rsi, rbx
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_sym2lib
        int soOpenSym2lib2 = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x74, 0x6B]);                                     // je +0x6b (.Lnot_found)
        b.AddRange([0x48, 0x89, 0xC7]);                               // mov rdi, rax
        b.AddRange([0x48, 0x89, 0xDE]);                               // mov rsi, rbx
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call __rtld_lib_sym2addr
        int soOpenSym2addr2 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xC8]);                       // mov [rbp-0x38], rax
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x74, 0x56]);                                     // je +0x56 (.Lnot_found)

        // ---- .Lfound: memcpy(loc, &val, 8) (0x673-0x690) ----
        b.AddRange([0x4B, 0x03, 0x44, 0xE7, 0x10]);                 // add rax, [r15+r12*8+0x10] (+ r_addend)
        b.AddRange([0x48, 0x89, 0x45, 0xC8]);                       // mov [rbp-0x38], rax
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                 // mov edx, 8
        b.AddRange([0x48, 0x8B, 0x7D, 0xA8]);                       // mov rdi, [rbp-0x58]
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);                       // lea rsi, [rbp-0x38]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        b.AddRange([0xEB, 0x6D]);                                     // jmp +0x6d (.Lrela_restore)

        // NOP alignment (0x693):
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F,
                    0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // R_X86_64_64(1) handler (0x6a0): direct 64-bit relocation
        b.AddRange([0x49, 0x8B, 0x86, 0x38, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x438] (mapbase)
        b.AddRange([0x48, 0x8B, 0x3E]);                               // mov rdi, [rsi]
        b.AddRange([0x48, 0x01, 0xC7]);                               // add rdi, rax
        b.AddRange([0x4B, 0x03, 0x44, 0xE7, 0x10]);                 // add rax, [r15+r12*8+0x10]
        b.AddRange([0x48, 0x89, 0x45, 0xC8]);                       // mov [rbp-0x38], rax
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                 // mov edx, 8
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);                       // lea rsi, [rbp-0x38]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        b.AddRange([0xEB, 0x42]);                                     // jmp +0x42 (.Lrela_check)

        // ---- .Lnot_found: check weak binding (0x6c9-0x700) ----
        b.AddRange([0x48, 0x8B, 0x45, 0x98]);                       // mov rax, [rbp-0x68] (symtab)
        b.AddRange([0x42, 0x0F, 0xB6, 0x44, 0xF0, 0x04]);           // movzbl eax, [rax+r14*8+4]
        b.AddRange([0x24, 0xF0]);                                     // and al, 0xf0
        b.AddRange([0x31, 0xFF]);                                     // xor edi, edi
        b.AddRange([0x3C, 0x20]);                                     // cmp al, 0x20 (STB_WEAK)
        b.AddRange([0x74, 0x25]);                                     // je +0x25 (.Lrela_restore)
        // not weak: log error and return -1
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_unable_resolve]
        int soOpenStrUnableResolveLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x75, 0xD0]);                       // mov rsi, [rbp-0x30]
        b.AddRange([0x48, 0x89, 0xDA]);                               // mov rdx, rbx
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_printf
        int soOpenKlogPrintf2 = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        // NOP alignment
        b.AddRange([0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00,
                    0x00, 0x00, 0x00, 0x00]);

        // .Lrela_restore (0x700): restore r14, rbx, reload jump table 2
        b.AddRange([0x4C, 0x8B, 0x75, 0xC0]);                       // mov r14, [rbp-0x40]
        b.AddRange([0x48, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00]);   // lea rbx, [rip+.rodata.so_open+0x70]
        int soOpenJmpTbl2LeaAt2 = b.Count - 4;

        // .Lrela_check (0x70b): bounds check and continue
        b.AddRange([0x49, 0x8B, 0x86, 0x80, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x480]
        b.AddRange([0x48, 0xBA, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA]);                             // movabs rdx, 0xaaaaaaaaaaaaaaab
        b.AddRange([0x48, 0x8B, 0x4D, 0xB8]);                       // mov rcx, [rbp-0x48]
        b.AddRange([0xC4, 0xE2, 0xFB, 0xF6, 0x44, 0x08, 0x20]);   // mulx [rax+rcx+0x20], rax, rax
        b.AddRange([0x85, 0xFF]);                                     // test edi, edi
        b.AddRange([0x0F, 0x85, 0xF1, 0xFD, 0xFF, 0xFF]);           // jne .Lrela_next
        b.AddRange([0x49, 0xFF, 0xC5]);                               // inc r13
        b.AddRange([0x48, 0xC1, 0xE8, 0x04]);                       // shr rax, 4
        b.AddRange([0x4C, 0x39, 0xE8]);                               // cmp rax, r13
        b.AddRange([0x0F, 0x87, 0x51, 0xFE, 0xFF, 0xFF]);           // ja .Lrela_entry
        b.AddRange([0xE9, 0xDC, 0xFD, 0xFF, 0xFF]);                 // jmp .Lrela_next

        // ---- Error: not a shared object (0x744-0x753) ----
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_not_shared]
        int soOpenStrNotSharedLeaAt = b.Count - 4;
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_printf
        int soOpenKlogPrintf3 = b.Count - 4;
        b.AddRange([0xE9, 0xF7, 0x01, 0x00, 0x00]);                 // jmp .Lexit_fail_mmap

        // ---- Error: malloc failed (0x758-0x75f) ----
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_malloc]
        int soOpenStrMallocLeaAt = b.Count - 4;
        b.AddRange([0xE9, 0x95, 0xF9, 0xFF, 0xFF]);                 // jmp .Lerr_lseek (0xf9)

        // ---- Error: pread mismatch (0x764-0x77e) ----
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_read]
        int soOpenStrReadLeaAt = b.Count - 4;
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_perror
        int soOpenKlogPerror4 = b.Count - 4;
        b.AddRange([0x4C, 0x89, 0xE7]);                               // mov rdi, r12
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        b.AddRange([0xE9, 0x80, 0xF9, 0xFF, 0xFF]);                 // jmp .Lr12_zero (0xff)

        // ---- Unsupported rela type (0x77f-0x7a4) ----
        b.AddRange([0x48, 0x8B, 0x45, 0xB0]);                       // mov rax, [rbp-0x50]
        b.AddRange([0x48, 0x8D, 0x04, 0x40]);                       // lea rax, [rax+rax*2]
        b.AddRange([0x49, 0x8B, 0x74, 0xC7, 0x08]);                 // mov rsi, [r15+rax*8+8]
        b.AddRange([0x48, 0x89, 0xFB]);                               // mov rbx, rdi
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_unsup_rela]
        int soOpenStrUnsupRelaLeaAt = b.Count - 4;
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_printf
        int soOpenKlogPrintf4 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xDF]);                               // mov rdi, rbx
        b.AddRange([0x48, 0x8B, 0x4D, 0xA0]);                       // mov rcx, [rbp-0x60]

        // ---- Apply kernel_mprotect on text segments (0x7a5-0x8e5) ----
        // .Lpast_rela (0x7a5):
        b.AddRange([0xF6, 0xC1, 0x01]);                               // test cl, 1
        b.AddRange([0x0F, 0x84, 0xA1, 0x01, 0x00, 0x00]);           // je +0x1a1 (.Lexit_fail_mmap)

        b.AddRange([0x48, 0x89, 0x7D, 0xC0]);                       // mov [rbp-0x40], rdi
        b.AddRange([0x49, 0x83, 0xBE, 0xA8, 0x04, 0x00, 0x00, 0x18]); // cmpq $0x18, [r14+0x4a8]
        b.AddRange([0x0F, 0x83, 0x27, 0x01, 0x00, 0x00]);           // jae +0x127 (.Lrela_plt)

        // mprotect PT_LOAD segments
        b.AddRange([0x49, 0x8B, 0x8E, 0x70, 0x04, 0x00, 0x00]);   // mov rcx, [r14+0x470]
        b.AddRange([0x4C, 0x8B, 0x65, 0xC0]);                       // mov r12, [rbp-0x40]
        b.AddRange([0x45, 0x85, 0xE4]);                               // test r12d, r12d
        b.AddRange([0x0F, 0x94, 0xC0]);                               // sete al
        b.AddRange([0x66, 0x83, 0x79, 0x38, 0x00]);                 // cmpw $0, [rcx+0x38]
        b.AddRange([0x0F, 0x84, 0xED, 0x00, 0x00, 0x00]);           // je +0xed (.Lmprotect_done)
        b.AddRange([0x45, 0x85, 0xE4]);                               // test r12d, r12d
        b.AddRange([0x0F, 0x85, 0xE4, 0x00, 0x00, 0x00]);           // jne +0xe4 (.Lmprotect_done)

        // ebx=1, r15=0 (segment byte offset); r13 = str_mprotect
        b.AddRange([0xBB, 0x01, 0x00, 0x00, 0x00]);                 // mov ebx, 1
        b.AddRange([0x4C, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]);   // lea r13, [rip+str_mprotect]
        int soOpenStrMprotectLeaAt = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xFF]);                               // xor r15d, r15d
        // NOP alignment
        b.AddRange([0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84,
                    0x00, 0x00, 0x00, 0x00, 0x00]);

        // .Lmprotect_loop (0x800):
        b.AddRange([0x49, 0x8B, 0x86, 0x78, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x478]
        b.AddRange([0x42, 0x83, 0x3C, 0x38, 0x01]);                 // cmpl $1, [rax+r15] (PT_LOAD)
        b.AddRange([0x0F, 0x85, 0x7E, 0x00, 0x00, 0x00]);           // jne +0x7e (.Lmprotect_next)
        b.AddRange([0x4A, 0x8B, 0x54, 0x38, 0x28]);                 // mov rdx, [rax+r15+0x28] (p_memsz)
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx
        b.AddRange([0x74, 0x74]);                                     // je +0x74 (.Lmprotect_next)
        // rsi = mapbase + p_vaddr; rdx = page-aligned size; compute prot flags
        b.AddRange([0x49, 0x8B, 0xB6, 0x38, 0x04, 0x00, 0x00]);   // mov rsi, [r14+0x438]
        b.AddRange([0x4A, 0x03, 0x74, 0x38, 0x10]);                 // add rsi, [rax+r15+0x10]
        b.AddRange([0x48, 0x81, 0xC2, 0xFF, 0x3F, 0x00, 0x00]);   // add rdx, 0x3fff
        b.AddRange([0x48, 0x81, 0xE2, 0x00, 0xC0, 0xFF, 0xFF]);   // and rdx, ~0x3fff
        // p_flags bit reversal: convert ELF flags to PROT flags
        b.AddRange([0x42, 0x0F, 0xB6, 0x44, 0x38, 0x04]);           // movzbl eax, [rax+r15+4]
        b.AddRange([0xC0, 0xC0, 0x04]);                               // rol al, 4
        b.AddRange([0x89, 0xC1]);                                     // mov ecx, eax
        b.AddRange([0x80, 0xE1, 0x33]);                               // and cl, 0x33
        b.AddRange([0xC0, 0xE1, 0x02]);                               // shl cl, 2
        b.AddRange([0xC0, 0xE8, 0x02]);                               // shr al, 2
        b.AddRange([0x24, 0x33]);                                     // and al, 0x33
        b.AddRange([0x08, 0xC8]);                                     // or al, cl
        b.AddRange([0x89, 0xC1]);                                     // mov ecx, eax
        b.AddRange([0x80, 0xE1, 0x55]);                               // and cl, 0x55
        b.AddRange([0x00, 0xC9]);                                     // add cl, cl
        b.AddRange([0xD0, 0xE8]);                                     // shr al, 1
        b.AddRange([0x24, 0x55]);                                     // and al, 0x55
        b.AddRange([0x08, 0xC8]);                                     // or al, cl
        b.AddRange([0x89, 0xC7]);                                     // mov edi, eax
        b.AddRange([0x40, 0xC0, 0xFF, 0x05]);                       // sar dil, 5
        b.AddRange([0xC0, 0xE8, 0x05]);                               // shr al, 5
        b.AddRange([0x0F, 0xB6, 0xC8]);                               // movzbl ecx, al
        b.AddRange([0x40, 0x84, 0xFF]);                               // test dil, dil
        b.AddRange([0x78, 0x4C]);                                     // js +0x4c (.Lmprotect_neg)

        // SYS_mprotect call (edi=0x4a, rsi=addr, rdx=len, ecx=prot)
        b.AddRange([0xBF, 0x4A, 0x00, 0x00, 0x00]);                 // mov edi, 0x4a (SYS_mprotect)
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+__crt_syscall]
        AddRel(RelocSymbol.PtrSyscall, b.Count - 4);
        b.AddRange([0x85, 0xC0]);                                     // test eax, eax
        b.AddRange([0x74, 0x13]);                                     // je +0x13 (.Lmprotect_next)
        // mprotect error
        b.AddRange([0x4C, 0x89, 0xEF]);                               // mov rdi, r13 (str_mprotect)
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call klog_perror
        int soOpenKlogPerror5 = b.Count - 4;
        b.AddRange([0x41, 0xBC, 0x01, 0x00, 0x00, 0x00]);           // mov r12d, 1
        // nop alignment
        b.AddRange([0x0F, 0x1F, 0x40, 0x00]);

        // .Lmprotect_next (0x890):
        b.AddRange([0x49, 0x8B, 0x86, 0x70, 0x04, 0x00, 0x00]);   // mov rax, [r14+0x470]
        b.AddRange([0x0F, 0xB7, 0x48, 0x38]);                       // movzwl ecx, [rax+0x38]
        b.AddRange([0x45, 0x85, 0xE4]);                               // test r12d, r12d
        b.AddRange([0x0F, 0x94, 0xC0]);                               // sete al
        b.AddRange([0x48, 0x39, 0xCB]);                               // cmp rbx, rcx
        b.AddRange([0x73, 0x23]);                                     // jae +0x23 (.Lmprotect_done)
        b.AddRange([0x49, 0x83, 0xC7, 0x38]);                       // add r15, 0x38
        b.AddRange([0x48, 0xFF, 0xC3]);                               // inc rbx
        b.AddRange([0x45, 0x85, 0xE4]);                               // test r12d, r12d
        b.AddRange([0x0F, 0x84, 0x4A, 0xFF, 0xFF, 0xFF]);           // je .Lmprotect_loop
        b.AddRange([0xEB, 0x11]);                                     // jmp +0x11 (.Lmprotect_done)

        // .Lmprotect_neg (0x8b8): negative prot
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);           // call kernel_mprotect
        int soOpenKernelMprotect1 = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                     // test eax, eax
        b.AddRange([0x75, 0xB6]);                                     // jne .-0x4a (mprotect error)
        b.AddRange([0xEB, 0xC7]);                                     // jmp .-0x39 (.Lmprotect_next)

        // .Lmprotect_done (0x8c9): check result, strcpy soname
        b.AddRange([0x84, 0xC0]);                                     // test al, al
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                       // mov rdi, [rbp-0x30]
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0x74, 0x7E]);                                     // je +0x7e (.Lexit)
        // strcpy path_buf → soname
        b.AddRange([0x48, 0x8D, 0xB5, 0x90, 0xFB, 0xFF, 0xFF]);   // lea rsi, [rbp-0x470]
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);           // call *[rip+.bss.strcpy]
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xEB, 0x6D]);                                     // jmp +0x6d (.Lexit)

        // ---- Process rela.plt jump slots (0x8e7-0x94d) ----
        // .Lrela_plt (0x8e7):
        b.AddRange([0x48, 0xBB, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA]);                             // movabs rbx, 0xaaaaaaaaaaaaaaab
        // Load klog_printf function pointer for later call *%r13
        // SDK: mov r13, [rip+GOT_klog_printf] → our: lea r13, [rip+klog_printf]
        b.AddRange([0x4C, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x00]);   // lea r13, [rip+klog_printf]
        int soOpenKlogPrintfLeaAt = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xFF]);                               // xor r15d, r15d
        b.AddRange([0x45, 0x31, 0xE4]);                               // xor r12d, r12d
        b.AddRange([0xEB, 0x2F]);                                     // jmp +0x2f

        // .Lrela_plt_unsup (0x900): unsupported plt reloc type
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);   // lea rdi, [rip+str_unsup_plt]
        int soOpenStrUnsupPltLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC6]);                               // mov rsi, rax
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0x41, 0xFF, 0xD5]);                               // call *r13 (klog_printf)
        // continue to next
        b.AddRange([0x49, 0xFF, 0xC4]);                               // inc r12
        b.AddRange([0x48, 0x89, 0xDA]);                               // mov rdx, rbx
        b.AddRange([0xC4, 0xC2, 0xFB, 0xF6, 0x86, 0xA8, 0x04,
                    0x00, 0x00]);                                     // mulx [r14+0x4a8], rax, rax
        b.AddRange([0x48, 0xC1, 0xE8, 0x04]);                       // shr rax, 4
        b.AddRange([0x49, 0x83, 0xC7, 0x18]);                       // add r15, 0x18
        b.AddRange([0x4C, 0x39, 0xE0]);                               // cmp rax, r12
        b.AddRange([0x0F, 0x86, 0x91, 0xFE, 0xFF, 0xFF]);           // jbe .Lmprotect_pt

        // .Lrela_plt_body (0x92f):
        b.AddRange([0x49, 0x8B, 0xB6, 0xA0, 0x04, 0x00, 0x00]);   // mov rsi, [r14+0x4a0] (jmprel)
        b.AddRange([0x4A, 0x8B, 0x44, 0x3E, 0x08]);                 // mov rax, [rsi+r15+8] (r_info)
        b.AddRange([0x83, 0xF8, 0x07]);                               // cmp eax, 7 (R_X86_64_JUMP_SLOT)
        b.AddRange([0x75, 0xC0]);                                     // jne .Lrela_plt_unsup
        // call r_glob_dat for JMP_SLOT
        b.AddRange([0x4C, 0x01, 0xFE]);                               // add rsi, r15
        b.AddRange([0x4C, 0x89, 0xF7]);                               // mov rdi, r14
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);                 // call r_glob_dat
        int soOpenRGlobDat2 = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                                     // test eax, eax
        b.AddRange([0x74, 0xC0]);                                     // je .Lrela_plt_unsup+inc (.Lrela_plt_next)

        // .Lexit_fail_mmap (0x94f):
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1

        // ---- Epilogue (0x954-0x965) ----
        // .Lexit:
        b.AddRange([0x48, 0x81, 0xC4, 0x58, 0x04, 0x00, 0x00]);   // add rsp, 0x458
        b.AddRange([0x5B]);                                           // pop rbx
        b.AddRange([0x41, 0x5C]);                                     // pop r12
        b.AddRange([0x41, 0x5D]);                                     // pop r13
        b.AddRange([0x41, 0x5E]);                                     // pop r14
        b.AddRange([0x41, 0x5F]);                                     // pop r15
        b.AddRange([0x5D]);                                           // pop rbp
        b.AddRange([0xC3]);                                           // ret
        int soOpenBytes = b.Count - soOpenOff;

        // ============================================================================
        // kernel_dynlib_handle -- 468 bytes, SDK-exact (.text.kernel_dynlib_handle)
        // Finds a loaded module's handle by matching its path basename.
        // Walks the kernel dynlib linked list for a process, copies each module's
        // path via kernel_copyout, extracts the basename (after last '/'), and
        // compares it byte-by-byte against the requested name.
        // Prototype: kernel_dynlib_handle(edi=pid, rsi=name, rdx=output_ptr) -> 0 or -1
        // Uses: kernel_get_proc (1 call), kernel_copyout (6 calls), __error (BSS load)
        // Stack: 0x428 for 0x400-byte path buffer + locals
        // ============================================================================
        _dynlibHandleRelocs = [];
        _currentRelocs = _dynlibHandleRelocs;
        int dynlibHandleOff = b.Count;

        // Prologue: push rbp; mov rbp,rsp; push r15..r12; push rbx; sub rsp,0x428
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53]);
        b.AddRange([0x48, 0x81, 0xEC, 0x28, 0x04, 0x00, 0x00]);
        // mov r12, rdx (output_ptr)
        b.AddRange([0x49, 0x89, 0xD4]);
        // mov r15, rsi (name)
        b.AddRange([0x49, 0x89, 0xF7]);
        // call kernel_get_proc (rdi=pid already set by caller)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhGetProcCallDisp = b.Count - 4;
        // mov ebx, -1 (default return value)
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);
        // test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // je .Lfail (forward)
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump1 = b.Count - 4;
        // add rax, 0x3E8 (PROC_DYNLIB_HEAD offset)
        b.AddRange([0x48, 0x05, 0xE8, 0x03, 0x00, 0x00]);
        // lea rsi, [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // mov rdi, rax
        b.AddRange([0x48, 0x89, 0xC7]);
        // call kernel_copyout(proc+0x3E8, &head, 8)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhCopyout1Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // js .Lfail (forward)
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump2 = b.Count - 4;
        // xor r14d, r14d
        b.AddRange([0x45, 0x31, 0xF6]);
        // nop (alignment)
        b.AddRange([0x90]);
        // .Lstrlen: cmpb $0, (%r15,%r14,1)
        int dhStrlenLoop = b.Count;
        b.AddRange([0x43, 0x80, 0x3C, 0x37, 0x00]);
        // lea r14, [r14+1]
        b.AddRange([0x4D, 0x8D, 0x76, 0x01]);
        // jne .Lstrlen (short backward)
        b.AddRange([0x75]);
        b.Add((byte)((dhStrlenLoop - (b.Count + 1)) & 0xFF));
        // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);
        // lea rsi, [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // call kernel_copyout(head, &head, 8) -- dereference list head
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhCopyout2Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // js .Lfail (forward)
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump3 = b.Count - 4;
        // mov [rbp-0x38], r12 (save output_ptr)
        b.AddRange([0x4C, 0x89, 0x65, 0xC8]);
        // lea r13, [r14-1] (name_len without null terminator)
        b.AddRange([0x4D, 0x8D, 0x6E, 0xFF]);
        // mov eax, 2
        b.AddRange([0xB8, 0x02, 0x00, 0x00, 0x00]);
        // sub rax, r14 (2 - len_incl_null = 1 - strlen)
        b.AddRange([0x4C, 0x29, 0xF0]);
        // mov [rbp-0x40], rax
        b.AddRange([0x48, 0x89, 0x45, 0xC0]);
        // lea r12, [rbp-0x450]
        b.AddRange([0x4C, 0x8D, 0xA5, 0xB0, 0xFB, 0xFF, 0xFF]);
        // sub r12, r14
        b.AddRange([0x4D, 0x29, 0xF4]);
        // jmp .Lloop_entry (short forward)
        b.AddRange([0xEB, 0x00]);
        int dhLoopEntryJump = b.Count - 1;

        // .Lcompare_fail: sub edi, r8d
        int dhCompareFail = b.Count;
        b.AddRange([0x44, 0x29, 0xC7]);
        // mov ecx, edi
        b.AddRange([0x89, 0xF9]);
        // .Lcheck_ecx: test ecx, ecx
        int dhCheckEcx = b.Count;
        b.AddRange([0x85, 0xC9]);
        // je .Lsuccess (forward)
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        int dhSuccessJump = b.Count - 4;

        // .Lnext_node: mov rdi, [rbp-0x30]
        int dhNextNode = b.Count;
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // lea rsi, [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        // call kernel_copyout(node, &head, 8) -- advance to next
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhCopyout3Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // js .Lfail (forward)
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump4 = b.Count - 4;

        // .Lloop_entry: mov rdi, [rbp-0x30]
        int dhLoopEntry = b.Count;
        b[dhLoopEntryJump] = (byte)((dhLoopEntry - (dhLoopEntryJump + 1)) & 0xFF);
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);
        // test rdi, rdi
        b.AddRange([0x48, 0x85, 0xFF]);
        // je .Lerrno (forward)
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        int dhErrnoJump = b.Count - 4;
        // add rdi, 8 (path pointer offset in dynlib node)
        b.AddRange([0x48, 0x83, 0xC7, 0x08]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // lea rsi, [rbp-0x50]
        b.AddRange([0x48, 0x8D, 0x75, 0xB0]);
        // call kernel_copyout(node+8, &path_kaddr, 8)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhCopyout4Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // js .Lfail (forward)
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump5 = b.Count - 4;
        // mov rdi, [rbp-0x50]
        b.AddRange([0x48, 0x8B, 0x7D, 0xB0]);
        // mov edx, 0x400
        b.AddRange([0xBA, 0x00, 0x04, 0x00, 0x00]);
        // lea rsi, [rbp-0x450]
        b.AddRange([0x48, 0x8D, 0xB5, 0xB0, 0xFB, 0xFF, 0xFF]);
        // call kernel_copyout(path_kaddr, path_buf, 0x400)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhCopyout5Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // js .Lfail (forward)
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump6 = b.Count - 4;
        // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);
        // add rdi, 0x28 (handle offset in dynlib node)
        b.AddRange([0x48, 0x83, 0xC7, 0x28]);
        // mov edx, 8
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);
        // lea rsi, [rbp-0x48]
        b.AddRange([0x48, 0x8D, 0x75, 0xB8]);
        // call kernel_copyout(node+0x28, &handle, 8)
        b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);
        int dhCopyout6Disp = b.Count - 4;
        // test eax, eax
        b.AddRange([0x85, 0xC0]);
        // js .Lfail (forward)
        b.AddRange([0x0F, 0x88, 0x00, 0x00, 0x00, 0x00]);
        int dhFailJump7 = b.Count - 4;
        // mov rcx, -1
        b.AddRange([0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]);
        // mov rax, r12
        b.AddRange([0x4C, 0x89, 0xE0]);
        // nopl 0x0(%rax,%rax,1) -- 8-byte nop for alignment
        b.AddRange([0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // .Lpath_strlen: inc rax
        int dhPathStrlen = b.Count;
        b.AddRange([0x48, 0xFF, 0xC0]);
        // cmpb $0, -0x44F(%rbp,%rcx,1)
        b.AddRange([0x80, 0xBC, 0x0D, 0xB1, 0xFB, 0xFF, 0xFF, 0x00]);
        // lea rcx, [rcx+1]
        b.AddRange([0x48, 0x8D, 0x49, 0x01]);
        // jne .Lpath_strlen (short backward)
        b.AddRange([0x75]);
        b.Add((byte)((dhPathStrlen - (b.Count + 1)) & 0xFF));
        // cmp rcx, r13
        b.AddRange([0x4C, 0x39, 0xE9]);
        // jbe .Lnext_node (near backward)
        b.AddRange([0x0F, 0x86, 0x00, 0x00, 0x00, 0x00]);
        int dhJbeNextNode = b.Count - 4;
        WriteRel32InBLocal(dhJbeNextNode, dhNextNode);
        // cmpb $0x2F, -1(%rax) (check for '/')
        b.AddRange([0x80, 0x78, 0xFF, 0x2F]);
        // jne .Lnext_node (near backward)
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
        int dhJneNextNode = b.Count - 4;
        WriteRel32InBLocal(dhJneNextNode, dhNextNode);
        // xor ecx, ecx
        b.AddRange([0x31, 0xC9]);
        // cmp r14, 1 (check if name is empty string)
        b.AddRange([0x49, 0x83, 0xFE, 0x01]);
        // je .Lcheck_ecx (near backward)
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        int dhJeCheckEcx1 = b.Count - 4;
        WriteRel32InBLocal(dhJeCheckEcx1, dhCheckEcx);
        // mov rdx, [rbp-0x40]
        b.AddRange([0x48, 0x8B, 0x55, 0xC0]);
        // mov rsi, r15
        b.AddRange([0x4C, 0x89, 0xFE]);
        // nopw 0x0(%rax,%rax,1) -- 9-byte nop for alignment
        b.AddRange([0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // .Lcompare: movzbl (%rax), edi
        int dhCompare = b.Count;
        b.AddRange([0x0F, 0xB6, 0x38]);
        // movzbl (%rsi), r8d
        b.AddRange([0x44, 0x0F, 0xB6, 0x06]);
        // cmp dil, r8b
        b.AddRange([0x44, 0x38, 0xC7]);
        // jne .Lcompare_fail (near backward)
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);
        int dhJneCompareFail = b.Count - 4;
        WriteRel32InBLocal(dhJneCompareFail, dhCompareFail);
        // test edi, edi
        b.AddRange([0x85, 0xFF]);
        // je .Lcheck_ecx (near backward)
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        int dhJeCheckEcx2 = b.Count - 4;
        WriteRel32InBLocal(dhJeCheckEcx2, dhCheckEcx);
        // inc rsi
        b.AddRange([0x48, 0xFF, 0xC6]);
        // inc rax
        b.AddRange([0x48, 0xFF, 0xC0]);
        // lea rdi, [rdx+1]
        b.AddRange([0x48, 0x8D, 0x7A, 0x01]);
        // test rdx, rdx
        b.AddRange([0x48, 0x85, 0xD2]);
        // mov rdx, rdi
        b.AddRange([0x48, 0x89, 0xFA]);
        // jne .Lcompare (short backward)
        b.AddRange([0x75]);
        b.Add((byte)((dhCompare - (b.Count + 1)) & 0xFF));
        // jmp .Lcheck_ecx (near backward)
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]);
        int dhJmpCheckEcx = b.Count - 4;
        WriteRel32InBLocal(dhJmpCheckEcx, dhCheckEcx);

        // .Lerrno: mov rax, [rip+__error] (BSS indirect load)
        int dhErrno = b.Count;
        b.AddRange([0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.KlogError, b.Count - 4);
        // test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // je .Lfail (short forward)
        b.AddRange([0x74, 0x00]);
        int dhErrnoFailJump = b.Count - 1;
        // call *rax (__error() -> rax = &errno)
        b.AddRange([0xFF, 0xD0]);
        // movl $0x16, (%rax) (errno = EINVAL = 22)
        b.AddRange([0xC7, 0x00, 0x16, 0x00, 0x00, 0x00]);
        // jmp .Lfail (short forward)
        b.AddRange([0xEB, 0x00]);
        int dhErrnoRetJump = b.Count - 1;

        // .Lsuccess: mov eax, [rbp-0x48] (handle value, low 32 bits)
        int dhSuccess = b.Count;
        b.AddRange([0x8B, 0x45, 0xB8]);
        // mov rcx, [rbp-0x38] (output_ptr)
        b.AddRange([0x48, 0x8B, 0x4D, 0xC8]);
        // mov (%rcx), eax (*output_ptr = handle)
        b.AddRange([0x89, 0x01]);
        // xor ebx, ebx (return 0)
        b.AddRange([0x31, 0xDB]);

        // .Lfail: mov eax, ebx
        int dhFail = b.Count;
        b.AddRange([0x89, 0xD8]);
        // Epilogue: add rsp,0x428; pop rbx; pop r12..r15; pop rbp; ret
        b.AddRange([0x48, 0x81, 0xC4, 0x28, 0x04, 0x00, 0x00]);
        b.AddRange([0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);

        // Backpatch all forward near jumps to .Lfail
        WriteRel32InBLocal(dhFailJump1, dhFail);
        WriteRel32InBLocal(dhFailJump2, dhFail);
        WriteRel32InBLocal(dhFailJump3, dhFail);
        WriteRel32InBLocal(dhFailJump4, dhFail);
        WriteRel32InBLocal(dhFailJump5, dhFail);
        WriteRel32InBLocal(dhFailJump6, dhFail);
        WriteRel32InBLocal(dhFailJump7, dhFail);
        // Backpatch forward near jump to .Lsuccess
        WriteRel32InBLocal(dhSuccessJump, dhSuccess);
        // Backpatch forward near jump to .Lerrno
        WriteRel32InBLocal(dhErrnoJump, dhErrno);
        // Backpatch short forward jumps from errno path to .Lfail
        b[dhErrnoFailJump] = (byte)((dhFail - (dhErrnoFailJump + 1)) & 0xFF);
        b[dhErrnoRetJump] = (byte)((dhFail - (dhErrnoRetJump + 1)) & 0xFF);

        _dynlibHandleBytes = b.Count - dynlibHandleOff;

        // ---- sprx_init: xor eax, eax ; ret (SDK-exact: sprx init is a no-op) ----
        int sprxInitStubOff = b.Count;
        b.AddRange([0x31, 0xC0, 0xC3]);

        // ---- sprx_fini: xor eax, eax ; ret (SDK-exact: sprx fini is a no-op) ----
        int sprxFiniStubOff = b.Count;
        b.AddRange([0x31, 0xC0, 0xC3]);

        // ============================================================================
        // sprx_sym2addr (vtable[2]) -- SDK .text.sprx_sym2addr algorithm
        // NID-encodes the plain-text name, walks the copied symtab (each Elf64_Sym
        // is 0x18 bytes), compares NID via strncmp(nid, strtab+st_name, 11), falls
        // back to strncmp(plain_name, strtab+st_name, 11), returns mapbase+st_value.
        // Prototype: sprx_sym2addr(rdi=lib, rsi=name) -> addr or 0
        // Uses: nid_encode (direct call), strncmp (BSS indirect)
        // SPRX struct: +0x438 mapbase, +0x470 strtab, +0x478 symtab, +0x480 symtab_size
        // ============================================================================
        _sprxSym2addrRelocs = [];
        _currentRelocs = _sprxSym2addrRelocs;
        int sprxSym2addrOff = b.Count;
        // Early null check: if symtab == NULL return 0
        b.AddRange([0x48, 0x83, 0xBF, 0x78, 0x04, 0x00, 0x00, 0x00]); // cmpq $0, 0x478(%rdi)
        b.AddRange([0x74, 0x53]);                                        // je .Learly_ret (+0x53)
        // Prologue
        b.AddRange([0x55]);                                               // push rbp
        b.AddRange([0x48, 0x89, 0xE5]);                                   // mov rbp, rsp
        b.AddRange([0x41, 0x57]);                                         // push r15
        b.AddRange([0x41, 0x56]);                                         // push r14
        b.AddRange([0x41, 0x55]);                                         // push r13
        b.AddRange([0x41, 0x54]);                                         // push r12
        b.AddRange([0x53]);                                               // push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x18]);                             // sub rsp, 0x18
        // rbx = lib
        b.AddRange([0x48, 0x89, 0xFB]);                                   // mov rbx, rdi
        // Check strtab != NULL
        b.AddRange([0x48, 0x83, 0xBF, 0x70, 0x04, 0x00, 0x00, 0x00]);   // cmpq $0, 0x470(%rdi)
        b.AddRange([0x74, 0x24]);                                         // je .Lret_zero (+0x24)
        // Check mapbase != NULL
        b.AddRange([0x48, 0x83, 0xBB, 0x38, 0x04, 0x00, 0x00, 0x00]);   // cmpq $0, 0x438(%rbx)
        b.AddRange([0x74, 0x1A]);                                         // je .Lret_zero (+0x1a)
        // r14 = name (preserve original)
        b.AddRange([0x49, 0x89, 0xF6]);                                   // mov r14, rsi
        // nid_encode(name, &nid_buf): rdi=name, rsi=&[rbp-0x34]
        b.AddRange([0x48, 0x8D, 0x75, 0xCC]);                             // lea rsi, [rbp-0x34]
        b.AddRange([0x4C, 0x89, 0xF7]);                                   // mov rdi, r14
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                             // addr32 call nid_encode
        int s2aNidEncodeCallDisp = b.Count - 4;
        // Check symtab_size >= 0x18 (at least one entry)
        b.AddRange([0x48, 0x83, 0xBB, 0x80, 0x04, 0x00, 0x00, 0x18]);   // cmpq $0x18, 0x480(%rbx)
        b.AddRange([0x73, 0x14]);                                         // jae .Lloop_start (+0x14)
        // .Lret_zero:
        int s2aRetZero = b.Count;
        b.AddRange([0x31, 0xC0]);                                         // xor eax, eax
        // Epilogue (shared by return-0 and return-value paths)
        int s2aEpilogue = b.Count;
        b.AddRange([0x48, 0x83, 0xC4, 0x18]);                             // add rsp, 0x18
        b.AddRange([0x5B]);                                               // pop rbx
        b.AddRange([0x41, 0x5C]);                                         // pop r12
        b.AddRange([0x41, 0x5D]);                                         // pop r13
        b.AddRange([0x41, 0x5E]);                                         // pop r14
        b.AddRange([0x41, 0x5F]);                                         // pop r15
        b.AddRange([0x5D]);                                               // pop rbp
        b.AddRange([0xC3]);                                               // ret
        // .Learly_ret: symtab was NULL, fast path
        b.AddRange([0x31, 0xC0]);                                         // xor eax, eax
        b.AddRange([0xC3]);                                               // ret
        // .Lloop_start:
        int s2aLoopStart = b.Count;
        // r15 = magic multiplier for unsigned div by 24
        b.AddRange([0x49, 0xBF, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        // r13 = 0 (byte offset into symtab)
        b.AddRange([0x45, 0x31, 0xED]);                                   // xor r13d, r13d
        // r12 = 0 (entry index)
        b.AddRange([0x45, 0x31, 0xE4]);                                   // xor r12d, r12d
        b.AddRange([0xEB, 0x2A]);                                         // jmp .Lloop_body (+0x2a)
        // NOP alignment padding (SDK-exact)
        b.AddRange([0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F,
                    0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lloop_next: (increment and bounds check)
        int s2aLoopNext = b.Count;
        b.AddRange([0x49, 0xFF, 0xC4]);                                   // inc r12
        b.AddRange([0x4C, 0x89, 0xFA]);                                   // mov rdx, r15
        // mulx: unsigned multiply rdx * symtab_size, high result in rax
        b.AddRange([0xC4, 0xE2, 0xFB, 0xF6, 0x83, 0x80, 0x04, 0x00, 0x00]); // mulx 0x480(%rbx),%rax,%rax
        b.AddRange([0x48, 0xC1, 0xE8, 0x04]);                             // shr rax, 4 (entry_count)
        b.AddRange([0x49, 0x83, 0xC5, 0x18]);                             // add r13, 0x18
        b.AddRange([0x49, 0x39, 0xC4]);                                   // cmp r12, rax
        // jae .Lret_zero (all entries exhausted)
        b.AddRange([0x73, (byte)((s2aRetZero - (b.Count + 2)) & 0xFF)]); // jae .Lret_zero (backward)
        // .Lloop_body:
        int s2aLoopBody = b.Count;
        b.AddRange([0x48, 0x8B, 0x83, 0x78, 0x04, 0x00, 0x00]);         // mov rax, 0x478(%rbx) (symtab)
        b.AddRange([0x4A, 0x83, 0x7C, 0x28, 0x10, 0x00]);                 // cmpq $0, 0x10(%rax,%r13) (st_value)
        // je .Lloop_next (skip zero st_value)
        b.AddRange([0x74, (byte)((s2aLoopNext - (b.Count + 2)) & 0xFF)]);
        // Load sym_name = strtab + entry.st_name
        b.AddRange([0x42, 0x8B, 0x34, 0x28]);                             // mov esi, (%rax,%r13) (st_name dword)
        b.AddRange([0x48, 0x03, 0xB3, 0x70, 0x04, 0x00, 0x00]);         // add rsi, 0x470(%rbx) (+ strtab)
        // strncmp(nid_buf, sym_name, 11) -- NID comparison
        b.AddRange([0xBA, 0x0B, 0x00, 0x00, 0x00]);                       // mov edx, 11
        b.AddRange([0x48, 0x8D, 0x7D, 0xCC]);                             // lea rdi, [rbp-0x34] (&nid_buf)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+strncmp]
        AddRel(RelocSymbol.RtldStrncmp, b.Count - 4);
        b.AddRange([0x85, 0xC0]);                                         // test eax, eax
        b.AddRange([0x74, 0x24]);                                         // je .Lmatch (+0x24)
        // Fallback: strncmp(plain_name, sym_name, 11)
        b.AddRange([0x48, 0x8B, 0x83, 0x78, 0x04, 0x00, 0x00]);         // mov rax, 0x478(%rbx) (symtab)
        b.AddRange([0x42, 0x8B, 0x34, 0x28]);                             // mov esi, (%rax,%r13) (st_name)
        b.AddRange([0x48, 0x03, 0xB3, 0x70, 0x04, 0x00, 0x00]);         // add rsi, 0x470(%rbx) (+ strtab)
        b.AddRange([0xBA, 0x0B, 0x00, 0x00, 0x00]);                       // mov edx, 11
        b.AddRange([0x4C, 0x89, 0xF7]);                                   // mov rdi, r14 (original name)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+strncmp]
        AddRel(RelocSymbol.RtldStrncmp, b.Count - 4);
        b.AddRange([0x85, 0xC0]);                                         // test eax, eax
        // jne .Lloop_next (no match, continue)
        b.AddRange([0x75, (byte)((s2aLoopNext - (b.Count + 2)) & 0xFF)]);
        // .Lmatch: return mapbase + st_value
        b.AddRange([0x48, 0x8B, 0x83, 0x38, 0x04, 0x00, 0x00]);         // mov rax, 0x438(%rbx) (mapbase)
        b.AddRange([0x48, 0x8B, 0x8B, 0x78, 0x04, 0x00, 0x00]);         // mov rcx, 0x478(%rbx) (symtab)
        b.AddRange([0x4A, 0x03, 0x44, 0x29, 0x08]);                       // add rax, 0x8(%rcx,%r13) (+ st_value)
        // jmp .Lepilogue (return rax via the epilogue)
        b.AddRange([0xE9, 0, 0, 0, 0]);                                   // jmp .Lepilogue
        WriteRel32InBLocal(b.Count - 4, s2aEpilogue);
        int sprxSym2addrBytes = b.Count - sprxSym2addrOff;

        // ============================================================================
        // sprx_addr2sym (vtable[3]) -- SDK .text.sprx_addr2sym algorithm
        // Walks symtab to find which symbol contains addr. No external calls.
        // Prototype: sprx_addr2sym(rdi=lib, rsi=addr) -> name_ptr or 0
        // SPRX struct: +0x438 mapbase, +0x440 mapsize, +0x470 strtab,
        //              +0x478 symtab, +0x480 symtab_size
        // ============================================================================
        int sprxAddr2symOff = b.Count;
        // SDK-exact bytes (no external calls, all branch-relative)
        b.AddRange([0x48, 0x8B, 0x8F, 0x78, 0x04, 0x00, 0x00]);         // mov rcx, 0x478(%rdi) (symtab)
        b.AddRange([0x48, 0x85, 0xC9]);                                   // test rcx, rcx
        b.AddRange([0x74, 0x4A]);                                         // je .Lret0
        b.AddRange([0x4C, 0x8B, 0x87, 0x70, 0x04, 0x00, 0x00]);         // mov r8, 0x470(%rdi) (strtab)
        b.AddRange([0x4D, 0x85, 0xC0]);                                   // test r8, r8
        b.AddRange([0x74, 0x3E]);                                         // je .Lret0
        b.AddRange([0x4C, 0x8B, 0x8F, 0x38, 0x04, 0x00, 0x00]);         // mov r9, 0x438(%rdi) (mapbase)
        b.AddRange([0x31, 0xC0]);                                         // xor eax, eax
        b.AddRange([0x4D, 0x85, 0xC9]);                                   // test r9, r9
        b.AddRange([0x74, 0x32]);                                         // je .Lret
        b.AddRange([0x49, 0x39, 0xF1]);                                   // cmp rsi, r9
        b.AddRange([0x77, 0x2D]);                                         // ja .Lret (addr < mapbase)
        b.AddRange([0x48, 0x8B, 0x87, 0x40, 0x04, 0x00, 0x00]);         // mov rax, 0x440(%rdi) (mapsize)
        b.AddRange([0x4C, 0x01, 0xC8]);                                   // add rax, r9 (mapbase+mapsize)
        b.AddRange([0x48, 0x39, 0xF0]);                                   // cmp rax, rsi
        b.AddRange([0x72, 0x1C]);                                         // jb .Lret0 (addr >= mapbase+mapsize)
        b.AddRange([0x48, 0x8B, 0x97, 0x80, 0x04, 0x00, 0x00]);         // mov rdx, 0x480(%rdi) (symtab_size)
        // movabs rax, 0xaaaaaaaaaaaaaaab (magic for /24)
        b.AddRange([0x48, 0xB8, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        b.AddRange([0xC4, 0xE2, 0xC3, 0xF6, 0xF8]);                     // mulx rdi, rdi, rax
        b.AddRange([0x48, 0x83, 0xFA, 0x18]);                             // cmp rdx, 0x18
        b.AddRange([0x73, 0x03]);                                         // jae .Lscan
        // .Lret0:
        b.AddRange([0x31, 0xC0]);                                         // xor eax, eax
        // .Lret:
        b.AddRange([0xC3]);                                               // ret
        // .Lscan:
        b.AddRange([0x48, 0xC1, 0xEF, 0x04]);                             // shr rdi, 4 (entry_count)
        b.AddRange([0x48, 0x83, 0xC1, 0x10]);                             // add rcx, 0x10 (point to st_size field)
        b.AddRange([0x31, 0xC0]);                                         // xor eax, eax
        b.AddRange([0xEB, 0x14]);                                         // jmp .Lscan_body
        // NOP alignment padding (SDK-exact)
        b.AddRange([0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lscan_next:
        b.AddRange([0x48, 0x83, 0xC1, 0x18]);                             // add rcx, 0x18
        b.AddRange([0x48, 0xFF, 0xCF]);                                   // dec rdi
        b.AddRange([0x74, 0xDF]);                                         // je .Lret (exhausted)
        // .Lscan_body:
        b.AddRange([0x48, 0x8B, 0x11]);                                   // mov rdx, (%rcx) (st_size)
        b.AddRange([0x48, 0x85, 0xD2]);                                   // test rdx, rdx
        b.AddRange([0x74, 0xEF]);                                         // je .Lscan_next (st_size==0)
        b.AddRange([0x4C, 0x8B, 0x51, 0xF8]);                             // mov r10, -8(%rcx) (st_value)
        b.AddRange([0x4D, 0x01, 0xCA]);                                   // add r10, r9 (mapbase+st_value)
        b.AddRange([0x49, 0x39, 0xF2]);                                   // cmp r10, rsi
        b.AddRange([0x77, 0xE3]);                                         // ja .Lscan_next (addr < sym_start)
        b.AddRange([0x49, 0x01, 0xD2]);                                   // add r10, rdx (sym_start+st_size)
        b.AddRange([0x49, 0x39, 0xF2]);                                   // cmp r10, rsi
        b.AddRange([0x72, 0xDB]);                                         // jb .Lscan_next (addr >= sym_end)
        // Match: return strtab + st_name
        b.AddRange([0x8B, 0x41, 0xF0]);                                   // mov eax, -0x10(%rcx) (st_name)
        b.AddRange([0x49, 0x01, 0xC0]);                                   // add r8, rax (strtab+st_name)
        b.AddRange([0x4C, 0x89, 0xC0]);                                   // mov rax, r8
        b.AddRange([0xC3]);                                               // ret

        // ============================================================================
        // sprx_open (vtable[0]) -- SDK .text.sprx_open algorithm (697 bytes)
        // Full SDK-exact port: checks kernel library names (libkernel*.sprx),
        // probes kernel_dynlib_handle for already-loaded modules, iterates the
        // 0x89-entry sysmod table calling sceSysmoduleLoadModuleInternal on match,
        // falls back to sceKernelLoadStartModule, then kernel_dynlib_obj +
        // kernel_copyout to retrieve metadata, strtab, and symtab.
        // Prototype: sprx_open(rdi=lib) -> 0 or -1
        // Stack: 0x6B8 frame; obj_buf (0x180) at [rbp-0x2D8];
        //        meta_buf (0x120) at [rbp-0x158]; path_buf (0x400) at [rbp-0x6E0]
        // Uses: strcmp (BSS x4), kernel_dynlib_handle (direct),
        //       __rtld_find_file (direct), sceSysmoduleLoadModuleInternal (BSS),
        //       klog_printf (direct), sceKernelLoadStartModule (BSS),
        //       kernel_dynlib_dlsym (direct), kernel_dynlib_obj (direct),
        //       kernel_copyout (direct x4), malloc (BSS x2),
        //       klog_puts (direct), klog_perror (direct)
        // ============================================================================
        _sprxOpenRelocs = [];
        _currentRelocs = _sprxOpenRelocs;
        int sprxOpenOff = b.Count;
        // +0x00: push rbp ; mov rbp, rsp ; push r15 ; push r14 ; push r13 ; push r12 ; push rbx
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53]);
        // +0x0D: sub rsp, 0x6B8
        b.AddRange([0x48, 0x81, 0xEC, 0xB8, 0x06, 0x00, 0x00]);
        // +0x14: mov rbx, rdi (lib)
        b.AddRange([0x48, 0x89, 0xFB]);
        // +0x17: movl $0, -0x2C(%rbp) (initialize handle to 0)
        b.AddRange([0xC7, 0x45, 0xD4, 0x00, 0x00, 0x00, 0x00]);
        // +0x1E: lea r15, [rdi+0x38] (soname pointer)
        b.AddRange([0x4C, 0x8D, 0x7F, 0x38]);
        // +0x22: lea rsi, [rip+"libkernel.sprx"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sprxoLibkernelLeaAt = b.Count - 4;
        // +0x29: mov rdi, r15
        b.AddRange([0x4C, 0x89, 0xFF]);
        // +0x2C: call [rip+strcmp] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        // +0x32: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x34: je 0x140 (kernel lib path)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int sprxoKernelJump1 = b.Count - 4;
        // +0x3A: lea rsi, [rip+"libkernel_web.sprx"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sprxoLibkernelWebLeaAt = b.Count - 4;
        // +0x41: mov rdi, r15
        b.AddRange([0x4C, 0x89, 0xFF]);
        // +0x44: call [rip+strcmp] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        // +0x4A: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x4C: je 0x140 (kernel lib path)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int sprxoKernelJump2 = b.Count - 4;
        // +0x52: lea rsi, [rip+"libkernel_sys.sprx"]
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);
        int sprxoLibkernelSysLeaAt = b.Count - 4;
        // +0x59: mov rdi, r15
        b.AddRange([0x4C, 0x89, 0xFF]);
        // +0x5C: call [rip+strcmp] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        // +0x62: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x64: je 0x140 (kernel lib path)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int sprxoKernelJump3 = b.Count - 4;
        // +0x6A: mov r14d, -1 (default return value)
        b.AddRange([0x41, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF]);
        // +0x70: lea rdx, -0x2C(%rbp) (&handle_var)
        b.AddRange([0x48, 0x8D, 0x55, 0xD4]);
        // +0x74: mov edi, -1 (pid = self)
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // +0x79: mov rsi, r15 (soname)
        b.AddRange([0x4C, 0x89, 0xFE]);
        // +0x7C: call kernel_dynlib_handle (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int sprxoDynlibHandleCallDisp = b.Count - 4;
        // +0x82: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x84: jns 0x16C (handle found, skip loading)
        b.AddRange([0x0F, 0x89, 0, 0, 0, 0]);
        int sprxoHandleFoundJump = b.Count - 4;
        // +0x8A: lea rsi, -0x6E0(%rbp) (path_buf, 0x400 bytes)
        b.AddRange([0x48, 0x8D, 0xB5, 0x20, 0xF9, 0xFF, 0xFF]);
        // +0x91: mov rdi, r15 (soname)
        b.AddRange([0x4C, 0x89, 0xFF]);
        // +0x94: call __rtld_find_file (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int sprxoFindFileCallDisp = b.Count - 4;
        // +0x9A: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x9C: jne 0x295 (file not found -> exit)
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);
        int sprxoExitJump1 = b.Count - 4;
        // +0xA2: mov [rbp-0x38], rbx (save lib pointer for sysmod loop)
        b.AddRange([0x48, 0x89, 0x5D, 0xC8]);
        // +0xA6: lea r13, [rip+sysmodtab+8] (data section reference)
        b.AddRange([0x4C, 0x8D, 0x2D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.SysmodTab, b.Count - 4, addend: 4);
        // +0xAD: xor ebx, ebx (loop counter = 0)
        b.AddRange([0x31, 0xDB]);
        // +0xAF: xor r12d, r12d (exhaustion flag = 0)
        b.AddRange([0x45, 0x31, 0xE4]);
        // +0xB2: jmp 0xDE (loop body)
        b.AddRange([0xEB, 0x2A]);
        // +0xB4: 12-byte nop alignment (data16 data16 cs nopw 0(%rax,%rax,1))
        b.AddRange([0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // +0xC0: .Lloop_inc: cmp rbx, 0x88
        int sprxoLoopInc = b.Count;
        b.AddRange([0x48, 0x81, 0xFB, 0x88, 0x00, 0x00, 0x00]);
        // +0xC7: lea rax, [rbx+1]
        b.AddRange([0x48, 0x8D, 0x43, 0x01]);
        // +0xCB: setae r12b (r12b = 1 if counter >= 0x88)
        b.AddRange([0x41, 0x0F, 0x93, 0xC4]);
        // +0xCF: add r13, 0x10 (next sysmod entry)
        b.AddRange([0x49, 0x83, 0xC5, 0x10]);
        // +0xD3: mov rbx, rax (counter++)
        b.AddRange([0x48, 0x89, 0xC3]);
        // +0xD6: cmp rax, 0x89
        b.AddRange([0x48, 0x3D, 0x89, 0x00, 0x00, 0x00]);
        // +0xDC: je 0x118 (loop exhausted -> sceKernelLoadStartModule)
        b.AddRange([0x74, 0x3A]);
        // +0xDE: .Lloop_body: mov rsi, [r13-8] (sysmod entry name pointer)
        b.AddRange([0x49, 0x8B, 0x75, 0xF8]);
        // +0xE2: mov rdi, r15 (soname)
        b.AddRange([0x4C, 0x89, 0xFF]);
        // +0xE5: call [rip+strcmp] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        // +0xEB: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0xED: jne .Lloop_inc (no match, -0x2F = 0xC0)
        b.AddRange([0x75, 0xD1]);
        // +0xEF: mov edi, [r13+0] (sysmod id)
        b.AddRange([0x41, 0x8B, 0x7D, 0x00]);
        // +0xF3: call [rip+sceSysmoduleLoadModuleInternal] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnSceSysmodLoad, b.Count - 4);
        // +0xF9: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0xFB: je .Lloop_inc (success = 0 -> continue, -0x3D = 0xC0)
        b.AddRange([0x74, 0xC3]);
        // +0xFD: lea rdi, [rip+"sceSysmoduleLoadModuleInternal: 0x%x\n"]
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
        int sprxoSysmodFmtLeaAt = b.Count - 4;
        // +0x104: mov esi, eax
        b.AddRange([0x89, 0xC6]);
        // +0x106: xor eax, eax (varargs)
        b.AddRange([0x31, 0xC0]);
        // +0x108: call klog_printf (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int sprxoKlogPrintfCallDisp = b.Count - 4;
        // +0x10E: test $1, r12b (check exhaustion flag)
        b.AddRange([0x41, 0xF6, 0xC4, 0x01]);
        // +0x112: je 0x295 (not exhausted + sysmod error -> exit)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int sprxoExitJump2 = b.Count - 4;
        // +0x118: .Lload_start_module: lea rdi, -0x6E0(%rbp) (path_buf)
        b.AddRange([0x48, 0x8D, 0xBD, 0x20, 0xF9, 0xFF, 0xFF]);
        // +0x11F: xor esi, esi
        b.AddRange([0x31, 0xF6]);
        // +0x121: xor edx, edx
        b.AddRange([0x31, 0xD2]);
        // +0x123: xor ecx, ecx
        b.AddRange([0x31, 0xC9]);
        // +0x125: xor r8d, r8d
        b.AddRange([0x45, 0x31, 0xC0]);
        // +0x128: xor r9d, r9d
        b.AddRange([0x45, 0x31, 0xC9]);
        // +0x12B: call [rip+sceKernelLoadStartModule] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnSceLoadMod, b.Count - 4);
        // +0x131: mov [rbp-0x2C], eax (store handle)
        b.AddRange([0x89, 0x45, 0xD4]);
        // +0x134: mov r13d, 1 (loaded_via_sysmod = 1)
        b.AddRange([0x41, 0xBD, 0x01, 0x00, 0x00, 0x00]);
        // +0x13A: mov rbx, [rbp-0x38] (restore lib pointer)
        b.AddRange([0x48, 0x8B, 0x5D, 0xC8]);
        // +0x13E: jmp 0x172 (common path)
        b.AddRange([0xEB, 0x32]);
        // +0x140: .Lkernel_lib: lea rdx, [rip+"sceKernelDlsym"]
        int sprxoKernelLib = b.Count;
        WriteRel32InBLocal(sprxoKernelJump1, sprxoKernelLib);
        WriteRel32InBLocal(sprxoKernelJump2, sprxoKernelLib);
        WriteRel32InBLocal(sprxoKernelJump3, sprxoKernelLib);
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        int sprxoSceKernelDlsymLeaAt = b.Count - 4;
        // +0x147: mov edi, -1 (pid = self)
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // +0x14C: mov esi, 1 (handle = libkernel)
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);
        // +0x151: call kernel_dynlib_dlsym (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int sprxoDlsymCallDisp = b.Count - 4;
        // +0x157: test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // +0x15A: je 0x165
        b.AddRange([0x74, 0x09]);
        // +0x15C: movl $1, -0x2C(%rbp) (handle = 0x1, libkernel)
        b.AddRange([0xC7, 0x45, 0xD4, 0x01, 0x00, 0x00, 0x00]);
        // +0x163: jmp 0x16C
        b.AddRange([0xEB, 0x07]);
        // +0x165: movl $0x2001, -0x2C(%rbp) (handle = 0x2001, libkernel_web)
        b.AddRange([0xC7, 0x45, 0xD4, 0x01, 0x20, 0x00, 0x00]);
        // +0x16C: .Lhandle_found: mov r12b, 1 (handle determined)
        int sprxoHandleFound = b.Count;
        WriteRel32InBLocal(sprxoHandleFoundJump, sprxoHandleFound);
        b.AddRange([0x41, 0xB4, 0x01]);
        // +0x16F: xor r13d, r13d (not loaded via sysmod)
        b.AddRange([0x45, 0x31, 0xED]);
        // +0x172: .Lcommon: mov esi, -0x2C(%rbp) (handle)
        b.AddRange([0x8B, 0x75, 0xD4]);
        // +0x175: mov r14d, -1 (default return = error)
        b.AddRange([0x41, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF]);
        // +0x17B: lea rdx, [rbp-0x2D8] (&obj_buf)
        b.AddRange([0x48, 0x8D, 0x95, 0x28, 0xFD, 0xFF, 0xFF]);
        // +0x182: mov edi, -1 (pid = self)
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // +0x187: call kernel_dynlib_obj (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int soKernelDynlibObjCallDisp = b.Count - 4;
        // +0x18D: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x18F: js 0x288 (.Lfail_msg)
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int sprxoFailMsgJump1 = b.Count - 4;
        // +0x195: mov rdi, [rbp-0x2D0] (obj_buf[0x08] = path kaddr)
        b.AddRange([0x48, 0x8B, 0xBD, 0x30, 0xFD, 0xFF, 0xFF]);
        // +0x19C: mov edx, 0x400 (path buffer size)
        b.AddRange([0xBA, 0x00, 0x04, 0x00, 0x00]);
        // +0x1A1: mov rsi, r15 (soname/path dest)
        b.AddRange([0x4C, 0x89, 0xFE]);
        // +0x1A4: call kernel_copyout (direct) -- copy module path
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int soCopyoutPathCallDisp = b.Count - 4;
        // +0x1AA: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x1AC: js 0x288 (.Lfail_msg)
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int sprxoFailMsgJump2 = b.Count - 4;
        // +0x1B2: mov rdi, [rbp-0x190] (obj_buf[0x148] = metadata kaddr)
        b.AddRange([0x48, 0x8B, 0xBD, 0x70, 0xFE, 0xFF, 0xFF]);
        // +0x1B9: lea rsi, [rbp-0x158] (&meta_buf)
        b.AddRange([0x48, 0x8D, 0xB5, 0xA8, 0xFE, 0xFF, 0xFF]);
        // +0x1C0: mov edx, 0x120 (metadata size)
        b.AddRange([0xBA, 0x20, 0x01, 0x00, 0x00]);
        // +0x1C5: call kernel_copyout (direct) -- copy metadata
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int soCopyoutMetaCallDisp = b.Count - 4;
        // +0x1CB: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x1CD: js 0x288 (.Lfail_msg)
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);
        int sprxoFailMsgJump3 = b.Count - 4;
        // +0x1D3: mov rdi, [rbp-0x118] (meta[0x40] = strtab_size)
        b.AddRange([0x48, 0x8B, 0xBD, 0xE8, 0xFE, 0xFF, 0xFF]);
        // +0x1DA: call [rip+malloc] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnMalloc, b.Count - 4);
        // +0x1E0: mov [rbx+0x470], rax (lib->strtab)
        b.AddRange([0x48, 0x89, 0x83, 0x70, 0x04, 0x00, 0x00]);
        // +0x1E7: test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // +0x1EA: je 0x2AA (.Lfail_malloc)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int sprxoMallocFail1 = b.Count - 4;
        // +0x1F0: mov rdi, [rbp-0x120] (meta[0x38] = strtab kaddr)
        b.AddRange([0x48, 0x8B, 0xBD, 0xE0, 0xFE, 0xFF, 0xFF]);
        // +0x1F7: mov rdx, [rbp-0x118] (meta[0x40] = strtab_size)
        b.AddRange([0x48, 0x8B, 0x95, 0xE8, 0xFE, 0xFF, 0xFF]);
        // +0x1FE: mov rsi, rax (dest = strtab malloc'd buffer)
        b.AddRange([0x48, 0x89, 0xC6]);
        // +0x201: call kernel_copyout (direct) -- copy strtab
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int soCopyoutStrtabCallDisp = b.Count - 4;
        // +0x207: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x209: js 0x288 (.Lfail_msg, short: +0x7D)
        b.AddRange([0x78, 0x7D]);
        // +0x20B: mov rdi, [rbp-0x128] (meta[0x30] = symtab_size)
        b.AddRange([0x48, 0x8B, 0xBD, 0xD8, 0xFE, 0xFF, 0xFF]);
        // +0x212: call [rip+malloc] (BSS)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnMalloc, b.Count - 4);
        // +0x218: mov [rbx+0x478], rax (lib->symtab)
        b.AddRange([0x48, 0x89, 0x83, 0x78, 0x04, 0x00, 0x00]);
        // +0x21F: test rax, rax
        b.AddRange([0x48, 0x85, 0xC0]);
        // +0x222: je 0x2AA (.Lfail_malloc)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        int sprxoMallocFail2 = b.Count - 4;
        // +0x228: mov rdi, [rbp-0x130] (meta[0x28] = symtab kaddr)
        b.AddRange([0x48, 0x8B, 0xBD, 0xD0, 0xFE, 0xFF, 0xFF]);
        // +0x22F: mov rdx, [rbp-0x128] (meta[0x30] = symtab_size)
        b.AddRange([0x48, 0x8B, 0x95, 0xD8, 0xFE, 0xFF, 0xFF]);
        // +0x236: mov rsi, rax (dest = symtab malloc'd buffer)
        b.AddRange([0x48, 0x89, 0xC6]);
        // +0x239: call kernel_copyout (direct) -- copy symtab
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int soCopyoutSymtabCallDisp = b.Count - 4;
        // +0x23F: test eax, eax
        b.AddRange([0x85, 0xC0]);
        // +0x241: setns al (al = 1 if copyout succeeded)
        b.AddRange([0x0F, 0x99, 0xC0]);
        // +0x244: test al, r12b (both: copyout ok AND handle determined)
        b.AddRange([0x41, 0x84, 0xC4]);
        // +0x247: je 0x288 (.Lfail_msg, short: +0x3F)
        b.AddRange([0x74, 0x3F]);
        // +0x249: mov eax, -0x2C(%rbp) (handle)
        b.AddRange([0x8B, 0x45, 0xD4]);
        // +0x24C: mov [rbx+0x468], eax (lib->handle)
        b.AddRange([0x89, 0x83, 0x68, 0x04, 0x00, 0x00]);
        // +0x252: mov [rbx+0x488], r13d (lib->loaded_via_sysmod)
        b.AddRange([0x44, 0x89, 0xAB, 0x88, 0x04, 0x00, 0x00]);
        // +0x259: mov rax, [rbp-0x2A8] (obj_buf[0x30] = mapbase)
        b.AddRange([0x48, 0x8B, 0x85, 0x58, 0xFD, 0xFF, 0xFF]);
        // +0x260: mov [rbx+0x438], rax (lib->mapbase)
        b.AddRange([0x48, 0x89, 0x83, 0x38, 0x04, 0x00, 0x00]);
        // +0x267: mov rax, [rbp-0x2A0] (obj_buf[0x38] = mapsize)
        b.AddRange([0x48, 0x8B, 0x85, 0x60, 0xFD, 0xFF, 0xFF]);
        // +0x26E: mov [rbx+0x440], rax (lib->mapsize)
        b.AddRange([0x48, 0x89, 0x83, 0x40, 0x04, 0x00, 0x00]);
        // +0x275: mov rax, [rbp-0x128] (meta[0x30] = symtab_size)
        b.AddRange([0x48, 0x8B, 0x85, 0xD8, 0xFE, 0xFF, 0xFF]);
        // +0x27C: mov [rbx+0x480], rax (lib->symtab_size)
        b.AddRange([0x48, 0x89, 0x83, 0x80, 0x04, 0x00, 0x00]);
        // +0x283: xor r14d, r14d (return 0 = success)
        b.AddRange([0x45, 0x31, 0xF6]);
        // +0x286: jmp 0x295 (.Lexit, short: +0x0D)
        b.AddRange([0xEB, 0x0D]);
        // +0x288: .Lfail_msg: lea rdi, [rip+"Unknown kernel I/O error"]
        WriteRel32InBLocal(sprxoFailMsgJump1, b.Count);
        WriteRel32InBLocal(sprxoFailMsgJump2, b.Count);
        WriteRel32InBLocal(sprxoFailMsgJump3, b.Count);
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
        int sprxoUnknownErrLeaAt = b.Count - 4;
        // +0x28F: call klog_puts (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int sprxoKlogPutsCallDisp = b.Count - 4;
        // +0x295: .Lexit: mov eax, r14d
        int sprxoExit = b.Count;
        WriteRel32InBLocal(sprxoExitJump1, sprxoExit);
        WriteRel32InBLocal(sprxoExitJump2, sprxoExit);
        b.AddRange([0x44, 0x89, 0xF0]);
        // +0x298: add rsp, 0x6B8
        b.AddRange([0x48, 0x81, 0xC4, 0xB8, 0x06, 0x00, 0x00]);
        // +0x29F: pop rbx
        b.AddRange([0x5B]);
        // +0x2A0: pop r12
        b.AddRange([0x41, 0x5C]);
        // +0x2A2: pop r13
        b.AddRange([0x41, 0x5D]);
        // +0x2A4: pop r14
        b.AddRange([0x41, 0x5E]);
        // +0x2A6: pop r15
        b.AddRange([0x41, 0x5F]);
        // +0x2A8: pop rbp
        b.AddRange([0x5D]);
        // +0x2A9: ret
        b.AddRange([0xC3]);
        // +0x2AA: .Lfail_malloc: lea rdi, [rip+"malloc"]
        WriteRel32InBLocal(sprxoMallocFail1, b.Count);
        WriteRel32InBLocal(sprxoMallocFail2, b.Count);
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);
        int sprxoMallocErrLeaAt = b.Count - 4;
        // +0x2B1: call klog_perror (direct)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int sprxoKlogPerrorCallDisp = b.Count - 4;
        // +0x2B7: jmp 0x295 (.Lexit, short: -0x24 = 0xDC)
        b.AddRange([0xEB, 0xDC]);

        // ============================================================================
        // sprx_close (vtable[5]) -- SDK .text.sprx_close algorithm
        // If loaded_via_sysmod: sceKernelStopUnloadModule.
        // Then: free strtab, free symtab, zero all SPRX-specific fields.
        // Prototype: sprx_close(rdi=lib) -> 0 or error
        // ============================================================================
        _sprxCloseRelocs = [];
        _currentRelocs = _sprxCloseRelocs;
        int sprxCloseOff = b.Count;
        // push rbp; mov rbp, rsp; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        // rbx = lib
        b.AddRange([0x48, 0x89, 0xFB]);                                   // mov rbx, rdi
        // if loaded_via_sysmod (+0x488) != 0: unload module
        b.AddRange([0x83, 0xBF, 0x88, 0x04, 0x00, 0x00, 0x00]);           // cmpl $0, 0x488(%rdi)
        b.AddRange([0x74, 0x1C]);                                         // je .Lskip_unload (+0x1c)
        // sceKernelStopUnloadModule(handle, 0, NULL, 0, NULL, NULL)
        b.AddRange([0x8B, 0xBB, 0x68, 0x04, 0x00, 0x00]);                 // mov edi, 0x468(%rbx) (handle)
        b.AddRange([0x31, 0xF6]);                                         // xor esi, esi
        b.AddRange([0x31, 0xD2]);                                         // xor edx, edx
        b.AddRange([0x31, 0xC9]);                                         // xor ecx, ecx
        b.AddRange([0x45, 0x31, 0xC0]);                                   // xor r8d, r8d
        b.AddRange([0x45, 0x31, 0xC9]);                                   // xor r9d, r9d
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+sceKernelStopUnloadModule]
        AddRel(RelocSymbol.DlfcnSceUnloadMod, b.Count - 4);
        b.AddRange([0x85, 0xC0]);                                         // test eax, eax
        b.AddRange([0x75, 0x59]);                                         // jne .Lepilogue (error, return eax)
        // .Lskip_unload: free strtab if not NULL
        b.AddRange([0x48, 0x8B, 0xBB, 0x70, 0x04, 0x00, 0x00]);           // mov rdi, 0x470(%rbx) (strtab)
        b.AddRange([0x48, 0x85, 0xFF]);                                   // test rdi, rdi
        b.AddRange([0x74, 0x06]);                                         // je .Lskip_free1 (+0x06)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .Lskip_free1: free symtab if not NULL
        b.AddRange([0x48, 0x8B, 0xBB, 0x78, 0x04, 0x00, 0x00]);           // mov rdi, 0x478(%rbx) (symtab)
        b.AddRange([0x48, 0x85, 0xFF]);                                   // test rdi, rdi
        b.AddRange([0x74, 0x06]);                                         // je .Lskip_free2 (+0x06)
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .Lskip_free2: zero all SPRX-specific fields
        // handle = -1
        b.AddRange([0xC7, 0x83, 0x68, 0x04, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        // vxorps xmm0, xmm0, xmm0 ; vmovups [rbx+0x470], xmm0 (zero strtab + symtab)
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x70, 0x04, 0x00, 0x00]);
        // movq $0, [rbx+0x480] (symtab_size = 0)
        b.AddRange([0x48, 0xC7, 0x83, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // vmovups [rbx+0x438], xmm0 (zero mapbase + mapsize)
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x38, 0x04, 0x00, 0x00]);
        // movl $0, [rbx+0x488] (loaded_via_sysmod = 0)
        b.AddRange([0xC7, 0x83, 0x88, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // return 0
        b.AddRange([0x31, 0xC0]);                                         // xor eax, eax
        // .Lepilogue:
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                             // add rsp, 8
        b.AddRange([0x5B]);                                               // pop rbx
        b.AddRange([0x5D]);                                               // pop rbp
        b.AddRange([0xC3]);                                               // ret

        // ============================================================================
        // sprx_destroy (vtable[6]) -- SDK .text.sprx_destroy algorithm
        // Same cleanup as sprx_close, but also tail-call free(lib).
        // Prototype: sprx_destroy(rdi=lib) -> void
        // ============================================================================
        _sprxDestroyRelocs = [];
        _currentRelocs = _sprxDestroyRelocs;
        int sprxDestroyOff = b.Count;
        // push rbp; mov rbp, rsp; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        // rbx = lib
        b.AddRange([0x48, 0x89, 0xFB]);                                   // mov rbx, rdi
        // if loaded_via_sysmod (+0x488) != 0: try unload
        b.AddRange([0x83, 0xBF, 0x88, 0x04, 0x00, 0x00, 0x00]);           // cmpl $0, 0x488(%rdi)
        b.AddRange([0x74, 0x26]);                                         // je .Lskip_unload (+0x26)
        // sceKernelStopUnloadModule(handle, 0, NULL, 0, NULL, NULL)
        b.AddRange([0x8B, 0xBB, 0x68, 0x04, 0x00, 0x00]);                 // mov edi, 0x468(%rbx)
        b.AddRange([0x31, 0xF6]);                                         // xor esi, esi
        b.AddRange([0x31, 0xD2]);                                         // xor edx, edx
        b.AddRange([0x31, 0xC9]);                                         // xor ecx, ecx
        b.AddRange([0x45, 0x31, 0xC0]);                                   // xor r8d, r8d
        b.AddRange([0x45, 0x31, 0xC9]);                                   // xor r9d, r9d
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+sceKernelStopUnloadModule]
        AddRel(RelocSymbol.DlfcnSceUnloadMod, b.Count - 4);
        b.AddRange([0x85, 0xC0]);                                         // test eax, eax
        b.AddRange([0x74, 0x0A]);                                         // je .Lskip_unload (unload OK)
        // Unload failed: clear loaded_via_sysmod flag to prevent retry
        b.AddRange([0xC7, 0x83, 0x88, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // .Lskip_unload: free strtab if not NULL
        b.AddRange([0x48, 0x8B, 0xBB, 0x70, 0x04, 0x00, 0x00]);           // mov rdi, 0x470(%rbx)
        b.AddRange([0x48, 0x85, 0xFF]);                                   // test rdi, rdi
        b.AddRange([0x74, 0x06]);                                         // je .Lskip_free1
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .Lskip_free1: free symtab if not NULL
        b.AddRange([0x48, 0x8B, 0xBB, 0x78, 0x04, 0x00, 0x00]);           // mov rdi, 0x478(%rbx)
        b.AddRange([0x48, 0x85, 0xFF]);                                   // test rdi, rdi
        b.AddRange([0x74, 0x06]);                                         // je .Lskip_free2
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                             // call [rip+free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        // .Lskip_free2: zero all fields
        b.AddRange([0xC7, 0x83, 0x68, 0x04, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]); // handle = -1
        b.AddRange([0xC5, 0xF8, 0x57, 0xC0]);                             // vxorps xmm0
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x70, 0x04, 0x00, 0x00]);     // vmovups [rbx+0x470], xmm0
        b.AddRange([0x48, 0xC7, 0x83, 0x80, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // symtab_size=0
        b.AddRange([0xC5, 0xF8, 0x11, 0x83, 0x38, 0x04, 0x00, 0x00]);     // vmovups [rbx+0x438], xmm0
        b.AddRange([0xC7, 0x83, 0x88, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // loaded_via_sysmod=0
        // Prepare for tail-call free(lib)
        b.AddRange([0x48, 0x89, 0xDF]);                                   // mov rdi, rbx
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                             // add rsp, 8
        b.AddRange([0x5B]);                                               // pop rbx
        b.AddRange([0x5D]);                                               // pop rbp
        // tail-call: jmp [rip+free]
        b.AddRange([0xFF, 0x25, 0, 0, 0, 0]);                             // jmp [rip+free]
        AddRel(RelocSymbol.RtldFree, b.Count - 4);

        // ---- __rtld_sprx_init 462 bytes ----
        // Probes handle 0x1 for sceKernelDlsym to determine libkernel handle (0x1 or 0x2001).
        // Resolves sceKernelLoadStartModule, sceKernelStopUnloadModule from libkernel,
        // strcpy/strcmp/strncmp/calloc/malloc/free from 0x2, loads libSceSysmodule,
        // resolves sceSysmoduleLoadModuleInternal.
        int sprxInitOff = b.Count;
        // prologue: push rbp ; mov rbp, rsp ; push r15 ; push r14 ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x53, 0x50]);
        // Probe: kernel_dynlib_dlsym(-1, 0x1, "sceKernelDlsym")
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+sceKernelDlsym]
        int siProbeLeaAt = b.Count - 4;
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov ebx, -1
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);      // mov esi, 0x1
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call kernel_dynlib_dlsym
        int siProbeCallDisp = b.Count - 4;
        // Compute libkernel handle: r14d = (rax == 0) ? 0x2001 : 0x1
        b.AddRange([0x45, 0x31, 0xF6]);                  // xor r14d, r14d
        b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
        b.AddRange([0x41, 0x0F, 0x94, 0xC6]);            // sete r14b
        b.AddRange([0x41, 0xC1, 0xE6, 0x0D]);            // shl r14d, 0xd
        b.AddRange([0x41, 0x83, 0xCE, 0x01]);            // or r14d, 0x1
        // Emit resolve helper for sprx_init: lea rdx, mov edi=-1, mov esi=r14d, call, store, test, jz
        var siCallDisps = new List<int>();
        var siLeaAts = new List<int>();
        var siFailJumps = new List<int>();
        var siResolveLeaAts = new List<int>();
        var siResolveKlogCallDisps = new List<int>();
        int siResolveIndex = 0;
        void EmitSprxResolve(RelocSymbol bssSym, bool useR14 = true)
        {
            if (EmitDiagnosticBreadcrumbs)
            {
                b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]); // lea rdi, [rip+sp_si_N]
                siResolveLeaAts.Add(b.Count - 4);
                b.AddRange([0xE8, 0, 0, 0, 0]);              // call __prospero_klog
                siResolveKlogCallDisps.Add(b.Count - 4);
            }
            siResolveIndex++;
            b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+name]
            siLeaAts.Add(b.Count - 4);
            b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
            if (useR14)
                b.AddRange([0x44, 0x89, 0xF6]);              // mov esi, r14d (libkernel handle)
            else
                b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);  // mov esi, 0x2 (libc handle)
            b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call kernel_dynlib_dlsym
            siCallDisps.Add(b.Count - 4);
            b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+bss], rax
            AddRel(bssSym, b.Count - 4);
            b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
            b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);            // jz .Lfail (near)
            siFailJumps.Add(b.Count - 4);
        }
        // Resolve sceKernelLoadStartModule from libkernel (r14d)
        EmitSprxResolve(RelocSymbol.DlfcnSceLoadMod, useR14: true);   // #1
        // Resolve sceKernelStopUnloadModule from libkernel (r14d)
        EmitSprxResolve(RelocSymbol.DlfcnSceUnloadMod, useR14: true); // #2
        // Resolve strcpy from 0x2
        EmitSprxResolve(RelocSymbol.RtldStrcpy, useR14: false);       // #3
        // Resolve strcmp from 0x2
        EmitSprxResolve(RelocSymbol.RtldStrcmp, useR14: false);       // #4
        // Resolve strncmp from 0x2
        EmitSprxResolve(RelocSymbol.RtldStrncmp, useR14: false);      // #5
        // Resolve calloc from 0x2
        EmitSprxResolve(RelocSymbol.RtldCalloc, useR14: false);       // #6
        // Resolve malloc from 0x2
        EmitSprxResolve(RelocSymbol.DlfcnMalloc, useR14: false);      // #7
        // Resolve free from 0x2
        EmitSprxResolve(RelocSymbol.RtldFree, useR14: false);         // #8

        // Load libSceSysmodule: kernel_dynlib_handle(-1, "libSceSysmodule.sprx", &handle)
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);     // lea rsi, [rip+libSceSysmodule.sprx]
        int siSysmodNameLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x55, 0xE4]);            // lea rdx, [rbp-0x1c]
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call kernel_dynlib_handle
        int siDynlibHandleCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                         // test eax, eax
        b.AddRange([0x74, 0x00]);                         // je .Lgot_sysmod
        int siGotSysmodJumpAt = b.Count - 1;
        // Not found: sceKernelLoadStartModule("/system/common/lib/libSceSysmodule.sprx", 0, 0, 0, 0, 0)
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);     // lea rdi, [rip+libSceSysmodule_path]
        int siSysmodPathLeaAt = b.Count - 4;
        b.AddRange([0x31, 0xF6]);                         // xor esi, esi
        b.AddRange([0x31, 0xD2]);                         // xor edx, edx
        b.AddRange([0x31, 0xC9]);                         // xor ecx, ecx
        b.AddRange([0x45, 0x31, 0xC0]);                   // xor r8d, r8d
        b.AddRange([0x45, 0x31, 0xC9]);                   // xor r9d, r9d
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);            // call [rip+sceKernelLoadStartModule]
        AddRel(RelocSymbol.DlfcnSceLoadMod, b.Count - 4);
        b.AddRange([0x89, 0x45, 0xE4]);                   // mov [rbp-0x1c], eax
        b.AddRange([0x85, 0xC0]);                         // test eax, eax
        b.AddRange([0x74, 0x00]);                         // je .Lfail (short)
        int siSysmodFailJumpAt = b.Count - 1;
        // .Lgot_sysmod: resolve sceSysmoduleLoadModuleInternal from libSceSysmodule handle
        int siGotSysmod = b.Count;
        b[siGotSysmodJumpAt] = (byte)(siGotSysmod - (siGotSysmodJumpAt + 1));
        b.AddRange([0x8B, 0x75, 0xE4]);                   // mov esi, [rbp-0x1c]
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);      // lea rdx, [rip+sceSysmoduleLoadModuleInternal]
        int siSysmodResolveLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call kernel_dynlib_dlsym
        int siSysmodResolveCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+bss_sysmod], rax
        AddRel(RelocSymbol.DlfcnSceSysmodLoad, b.Count - 4);
        // cmp rax, 1 ; sbb ebx, ebx (if rax >= 1 then ebx = 0, else ebx = -1)
        b.AddRange([0x48, 0x83, 0xF8, 0x01]);
        b.AddRange([0x19, 0xDB]);
        // .Lfail: epilogue
        int siFail = b.Count;
        // Patch all fail jumps
        foreach (int at in siFailJumps) WriteRel32InBLocal(at, siFail);
        // Patch the sysmod load fail (short jump)
        b[siSysmodFailJumpAt] = (byte)(siFail - (siSysmodFailJumpAt + 1));
        // mov eax, ebx ; add rsp, 8 ; pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
        b.AddRange([0x89, 0xD8]);
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _sprxInitBytes = b.Count - sprxInitOff;

        // ---- __rtld_so_init (239 bytes) ----
        // Resolves strcmp, strcpy, malloc, calloc, memcpy, free from handle 0x2.
        _soInitRelocs = [];
        _currentRelocs = _soInitRelocs;
        int soInitOff = b.Count;
        // prologue: push rbp ; mov rbp, rsp ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        var soCallDisps = new List<int>();
        var soLeaAts = new List<int>();
        var soFailJumps = new List<int>();
        // resolve #1: strcmp (first — includes mov ebx,-1, near jz)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+strcmp]
        soLeaAts.Add(b.Count - 4);
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov ebx, -1
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call dlsym
        soCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+bss], rax
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);            // jz .Lfail (near)
        soFailJumps.Add(b.Count - 4);
        // resolve #2: strcpy (near jz)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        soLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        soCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);
        soFailJumps.Add(b.Count - 4);
        // resolve #3: malloc (short jz)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        soLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        soCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnMalloc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);                         // jz .Lfail (short, patch below)
        int soFail3At = b.Count - 1;
        // resolve #4: calloc (short jz)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        soLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        soCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int soFail4At = b.Count - 1;
        // resolve #5: memcpy (short jz)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        soLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        soCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int soFail5At = b.Count - 1;
        // resolve #6: free (last — sbb trick, no jump)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);
        soLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        soCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        b.AddRange([0x48, 0x83, 0xF8, 0x01]);            // cmp rax, 1
        b.AddRange([0x19, 0xDB]);                         // sbb ebx, ebx
        // .Lfail: epilogue
        int soFail = b.Count;
        // Patch near fail jumps
        foreach (int at in soFailJumps) WriteRel32InBLocal(at, soFail);
        // Patch short fail jumps
        b[soFail3At] = (byte)(soFail - (soFail3At + 1));
        b[soFail4At] = (byte)(soFail - (soFail4At + 1));
        b[soFail5At] = (byte)(soFail - (soFail5At + 1));
        b.AddRange([0x89, 0xD8]);                         // mov eax, ebx
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]); // add rsp,8; pop rbx; pop rbp; ret
        _soInitBytes = b.Count - soInitOff;

        // ---- __sp_so_r_glob_dat ----
        // Resolves R_X86_64_GLOB_DAT for .so files. Walks parent chain to root,
        // tries sym2lib+sym2addr from root, then from ctx itself; memcpy result
        // to GOT slot. Skips weak unresolved symbols, returns -1 for non-weak.
        // rdi = rtld_so_lib_t* ctx, rsi = Elf64_Rela* rela.
        _soRGlobDatRelocs = [];
        _currentRelocs = _soRGlobDatRelocs;
        int soRGlobDatOff = b.Count;
        // prologue: push rbp ; mov rbp, rsp ; push r15-r12 ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x50]);
        // mov rbx, rdi (rbx = ctx)
        b.AddRange([0x48, 0x89, 0xFB]);
        // mov r12, [rdi+0x490] (r12 = ctx->symtab, SoLibSymtab)
        b.AddRange([0x4C, 0x8B, 0xA7, 0x90, 0x04, 0x00, 0x00]);
        // mov rax, [rsi] (rax = rela->r_offset)
        b.AddRange([0x48, 0x8B, 0x06]);
        // mov rcx, [rsi+8] (rcx = rela->r_info)
        b.AddRange([0x48, 0x8B, 0x4E, 0x08]);
        // shr rcx, 32 (rcx = sym_index)
        b.AddRange([0x48, 0xC1, 0xE9, 0x20]);
        // lea r13, [rcx+rcx*2] (r13 = sym_index*3, scaled by 8 later = sizeof(Elf64_Sym))
        b.AddRange([0x4C, 0x8D, 0x2C, 0x49]);
        // mov r15, [rdi+0x438] (r15 = ctx->mapbase)
        b.AddRange([0x4C, 0x8B, 0xBF, 0x38, 0x04, 0x00, 0x00]);
        // mov r14, [rdi+0x488] (r14 = ctx->strtab, SoLibStrtab)
        b.AddRange([0x4C, 0x8B, 0xB7, 0x88, 0x04, 0x00, 0x00]);
        // mov ecx, [r12+r13*8] (ecx = symtab[sym_index].st_name)
        b.AddRange([0x43, 0x8B, 0x0C, 0xEC]);
        // movq $0, [rbp-0x30] (val = 0)
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x00]);
        // mov rdx, rdi (parent walk start)
        b.AddRange([0x48, 0x89, 0xFA]);
        // .Lparent_walk: while(lib->parent) lib = lib->parent
        b.AddRange([0x48, 0x89, 0xD7]);                               // mov rdi, rdx
        b.AddRange([0x48, 0x8B, 0x92, 0x50, 0x04, 0x00, 0x00]);      // mov rdx, [rdx+0x450]
        b.AddRange([0x48, 0x85, 0xD2]);                               // test rdx, rdx
        b.AddRange([0x75, 0xF1]);                                     // jne .-15 (back to mov rdi, rdx)
        // add r14, rcx (r14 = name = strtab + st_name)
        b.AddRange([0x49, 0x01, 0xCE]);
        // add r15, rax (r15 = loc = mapbase + r_offset)
        b.AddRange([0x49, 0x01, 0xC7]);
        // ---- First try: sym2lib+sym2addr from root ----
        b.AddRange([0x4C, 0x89, 0xF6]);                               // mov rsi, r14
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);            // addr32 call sym2lib
        int sgSym2libCall1 = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x74, 0x15]);                                     // je .Ltry_ctx (+21)
        b.AddRange([0x48, 0x89, 0xC7]);                               // mov rdi, rax
        b.AddRange([0x4C, 0x89, 0xF6]);                               // mov rsi, r14
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);            // addr32 call sym2addr
        int sgSym2addrCall1 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xD0]);                        // mov [rbp-0x30], rax
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x75, 0x26]);                                     // jne .Lfound (+38)
        // ---- .Ltry_ctx: second try from ctx itself ----
        b.AddRange([0x48, 0x89, 0xDF]);                               // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xF6]);                               // mov rsi, r14
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);            // addr32 call sym2lib
        int sgSym2libCall2 = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x74, 0x2B]);                                     // je .Lnot_found (+43)
        b.AddRange([0x48, 0x89, 0xC7]);                               // mov rdi, rax
        b.AddRange([0x4C, 0x89, 0xF6]);                               // mov rsi, r14
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);            // addr32 call sym2addr
        int sgSym2addrCall2 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xD0]);                        // mov [rbp-0x30], rax
        b.AddRange([0x48, 0x85, 0xC0]);                               // test rax, rax
        b.AddRange([0x74, 0x16]);                                     // je .Lnot_found (+22)
        // ---- .Lfound: memcpy(loc, &val, 8) ----
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                        // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        b.AddRange([0x4C, 0x89, 0xFF]);                               // mov rdi, r15
        b.AddRange([0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);            // call [rip+memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0xEB, 0x2B]);                                     // jmp .Lexit (+43)
        // ---- .Lnot_found: check weak binding ----
        b.AddRange([0x43, 0x0F, 0xB6, 0x4C, 0xEC, 0x04]);           // movzbl ecx, [r12+r13*8+4]
        b.AddRange([0x80, 0xE1, 0xF0]);                               // and cl, 0xf0
        b.AddRange([0x31, 0xC0]);                                     // xor eax, eax
        b.AddRange([0x80, 0xF9, 0x20]);                               // cmp cl, 0x20 (STB_WEAK)
        b.AddRange([0x74, 0x1B]);                                     // je .Lexit (+27, weak skip)
        // not weak: log symbol name and breadcrumb, return -1
        b.AddRange([0x4C, 0x89, 0xF7]);                               // mov rdi, r14 (name)
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);            // addr32 call __prospero_klog
        int sgKlogNameCall = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]);     // lea rdi, [rip+soResolveFailMsg]
        int sgResolveFailLeaAt = b.Count - 4;
        b.AddRange([0x67, 0xE8, 0x00, 0x00, 0x00, 0x00]);            // addr32 call __prospero_klog
        int sgKlogMsgCall = b.Count - 4;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                  // mov eax, -1
        // ---- .Lexit: epilogue ----
        b.AddRange([0x48, 0x83, 0xC4, 0x08]);                        // add rsp, 8
        b.AddRange([0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _soRGlobDatBytes = b.Count - soRGlobDatOff;

        // ============================================================================
        // __rtld_payload_init() -> int
        //
        // __rtld_payload_init:
        // Resolves calloc, memcpy, free, strcpy, strcmp from handle 0x2 via
        // kernel_dynlib_dlsym. Returns 0 on success, -1 on failure.
        //
        // Instruction-level layout:
        //   resolve #1 (calloc): mov ebx,-1 + near jz (distance 141 > 127)
        //   resolve #2-#4 (memcpy, free, strcpy): short jz
        //   resolve #5 (strcmp): sbb ebx,ebx trick
        //   epilogue: mov eax,ebx + add rsp,8 + pop rbx + pop rbp + ret
        // ============================================================================
        _payloadInitRelocs = [];
        _currentRelocs = _payloadInitRelocs;
        int payloadInitOff = b.Count;
        // prologue: push rbp ; mov rbp, rsp ; push rbx ; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);
        var piCallDisps = new List<int>();
        var piLeaAts = new List<int>();
        var piFailJumps = new List<int>();

        // resolve #1: calloc (first — includes mov ebx,-1, near jz because distance > 127)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+calloc_name]
        piLeaAts.Add(b.Count - 4);
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov ebx, -1
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1  (pid)
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2 (handle)
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call __sp_kernel_dynlib_dlsym
        piCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+__sp_rtld_calloc], rax
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);            // jz .Lfail (near — 141 bytes away)
        piFailJumps.Add(b.Count - 4);

        // resolve #2: memcpy (short jz — distance 106)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+memcpy_name]
        piLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call __sp_kernel_dynlib_dlsym
        piCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+__sp_rtld_memcpy], rax
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
        b.AddRange([0x74, 0x00]);                         // jz .Lfail (short, patch below)
        int piFail2At = b.Count - 1;

        // resolve #3: free (short jz — distance 71)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+free_name]
        piLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call __sp_kernel_dynlib_dlsym
        piCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+__sp_rtld_free], rax
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
        b.AddRange([0x74, 0x00]);                         // jz .Lfail (short, patch below)
        int piFail3At = b.Count - 1;

        // resolve #4: strcpy (short jz — distance 36)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+strcpy_name]
        piLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call __sp_kernel_dynlib_dlsym
        piCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+__sp_rtld_strcpy], rax
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                  // test rax, rax
        b.AddRange([0x74, 0x00]);                         // jz .Lfail (short, patch below)
        int piFail4At = b.Count - 1;

        // resolve #5: strcmp (last — sbb trick, no jump)
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);     // lea rdx, [rip+strcmp_name]
        piLeaAts.Add(b.Count - 4);
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);      // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);      // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);            // addr32 call __sp_kernel_dynlib_dlsym
        piCallDisps.Add(b.Count - 4);
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);      // mov [rip+__sp_rtld_strcmp], rax
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        b.AddRange([0x48, 0x83, 0xF8, 0x01]);            // cmp rax, 1
        b.AddRange([0x19, 0xDB]);                         // sbb ebx, ebx (ebx=0 if rax>=1, -1 if rax==0)
        // .Lfail: epilogue
        int pliFail = b.Count;
        // Patch near fail jumps (#1 uses near jz)
        foreach (int at in piFailJumps) WriteRel32InBLocal(at, pliFail);
        // Patch short fail jumps (#2, #3, #4)
        b[piFail2At] = (byte)(pliFail - (piFail2At + 1));
        b[piFail3At] = (byte)(pliFail - (piFail3At + 1));
        b[piFail4At] = (byte)(pliFail - (piFail4At + 1));
        b.AddRange([0x89, 0xD8]);                         // mov eax, ebx
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]); // add rsp,8; pop rbx; pop rbp; ret
        _payloadInitBytes = b.Count - payloadInitOff;

        // ---- __rtld_dlfcn_init (353 bytes) ----
        // Resolves calloc/free/_Strerror from handle 0x2,
        // then getargc/getargv/environ from 0x1 with 0x2001 fallback.
        // Instruction order: lea rdx first, mov ebx only on first resolve.
        int dlfcnInitOff = b.Count;
        // prologue: push rbp; mov rbp,rsp; push rbx; push rax (6 bytes)
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50]);

        // calloc from 0x2 — lea rdx, mov ebx,-1, mov edi,-1, mov esi,2
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);          // lea rdx, [rip+calloc_name]
        int diCallocLeaAt = b.Count - 4;
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);           // mov ebx, -1  (first resolve only)
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);           // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);           // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                 // addr32 call
        int diCallocCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);           // mov [rip+calloc_bss], rax
        AddRel(RelocSymbol.DlfcnCalloc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                        // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                  // je .Lfail (near)
        int diFailJump1 = b.Count - 4;

        // free from 0x2 — lea rdx, mov edi,-1, mov esi,2
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);           // lea rdx, [rip+free_name]
        int diFreeLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);            // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);            // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                  // addr32 call
        int diFreeCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);            // mov [rip+free_bss], rax
        AddRel(RelocSymbol.DlfcnFree, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                         // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                   // je .Lfail (near)
        int diFailJump2 = b.Count - 4;

        // strerror from 0x2 — lea rdx, mov edi,-1, mov esi,2
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);            // lea rdx, [rip+strerror_name]
        int diStrerrorLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);             // mov edi, -1
        b.AddRange([0xBE, 0x02, 0x00, 0x00, 0x00]);             // mov esi, 0x2
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                   // addr32 call
        int diStrerrorCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);             // mov [rip+strerror_bss], rax
        AddRel(RelocSymbol.DlfcnStrerror, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                    // je .Lfail (near)
        int diFailJump3 = b.Count - 4;

        // getargc from 0x1 -> 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);             // lea rdx, [rip+getargc_name]
        int diGetargcLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);              // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);              // mov esi, 0x1
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                    // addr32 call
        int diGetargcCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);              // mov [rip+getargc_bss], rax
        AddRel(RelocSymbol.DlfcnGetargc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                           // test rax, rax
        b.AddRange([0x75, 0x00]);                                  // jne <got_argc> (short, patch)
        int diGotArgcJumpAt = b.Count - 1;
        // getargc fallback 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);              // lea rdx, [rip+getargc_name]
        int diGetargcFbLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);               // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);               // mov esi, 0x2001
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                     // addr32 call
        int diGetargcFbCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);               // mov [rip+getargc_bss], rax
        AddRel(RelocSymbol.DlfcnGetargc, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                            // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                      // je .Lfail (near)
        int diFailJump4 = b.Count - 4;
        int diGotArgc = b.Count;
        b[diGotArgcJumpAt] = (byte)(diGotArgc - (diGotArgcJumpAt + 1));

        // getargv from 0x1 -> 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);              // lea rdx, [rip+getargv_name]
        int diGetargvLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);               // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);               // mov esi, 0x1
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                     // addr32 call
        int diGetargvCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);               // mov [rip+getargv_bss], rax
        AddRel(RelocSymbol.DlfcnGetargv, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                            // test rax, rax
        b.AddRange([0x75, 0x00]);                                   // jne <got_argv> (short, patch)
        int diGotArgvJumpAt = b.Count - 1;
        // getargv fallback 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);               // lea rdx, [rip+getargv_name]
        int diGetargvFbLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);                // mov esi, 0x2001
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                      // addr32 call
        int diGetargvFbCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);                // mov [rip+getargv_bss], rax
        AddRel(RelocSymbol.DlfcnGetargv, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x74, 0x00]);                                    // je .Lfail (short, patch)
        int diFailJump5At = b.Count - 1;
        int diGotArgv = b.Count;
        b[diGotArgvJumpAt] = (byte)(diGotArgv - (diGotArgvJumpAt + 1));

        // environ from 0x1 -> 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);               // lea rdx, [rip+environ_name]
        int diEnvironLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x00, 0x00, 0x00]);                // mov esi, 0x1
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                      // addr32 call
        int diEnvironCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);                // mov [rip+environ_bss], rax
        AddRel(RelocSymbol.DlfcnEnviron, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                             // test rax, rax
        b.AddRange([0x75, 0x00]);                                    // jne <got_env> (short, patch)
        int diGotEnvJumpAt = b.Count - 1;
        // environ fallback 0x2001
        b.AddRange([0x48, 0x8D, 0x15, 0, 0, 0, 0]);                // lea rdx, [rip+environ_name]
        int diEnvironFbLeaAt = b.Count - 4;
        b.AddRange([0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov edi, -1
        b.AddRange([0xBE, 0x01, 0x20, 0x00, 0x00]);                 // mov esi, 0x2001
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // addr32 call
        int diEnvironFbCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x05, 0, 0, 0, 0]);                 // mov [rip+environ_bss], rax
        AddRel(RelocSymbol.DlfcnEnviron, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x02]);                                     // je +2 (skip xor on failure)
        b.AddRange([0x31, 0xDB]);                                     // xor ebx, ebx (success)
        int diFail = b.Count;
        // Patch near fail jumps (calloc/free/strerror/getargc-fb)
        WriteRel32InBLocal(diFailJump1, diFail);
        WriteRel32InBLocal(diFailJump2, diFail);
        WriteRel32InBLocal(diFailJump3, diFail);
        WriteRel32InBLocal(diFailJump4, diFail);
        // Patch short fail jump (getargv-fb)
        b[diFailJump5At] = (byte)(diFail - (diFailJump5At + 1));
        // Patch environ jne to xor ebx,ebx (diFail - 2, not diFail)
        b[diGotEnvJumpAt] = (byte)((diFail - 2) - (diGotEnvJumpAt + 1));
        // epilogue
        b.AddRange([0x89, 0xD8, 0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        _dlfcnInitBytes = b.Count - dlfcnInitOff;

        // ---- __dlsym (93 bytes) ----
        int dlsymOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53]);
        b.AddRange([0x41, 0xBE, 0x4E, 0x00, 0x00, 0x00]);
        b.AddRange([0x48, 0x8D, 0x47, 0x01, 0x48, 0x83, 0xF8, 0x02, 0x72, 0x38]);
        b.AddRange([0x48, 0x83, 0xFF, 0xFD, 0x74, 0x32, 0x48, 0x83, 0xFF, 0xFE, 0x75, 0x07]);
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnRoot, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xF3]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlsymSym2libCallDisp = b.Count - 4;
        b.AddRange([0x41, 0xBE, 0x16, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x11]);
        b.AddRange([0x48, 0x89, 0xC7, 0x48, 0x89, 0xDE]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlsymSym2addrCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x75, 0x09]);
        b.AddRange([0x44, 0x89, 0x35, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 4);
        b.AddRange([0x31, 0xC0, 0x5B, 0x41, 0x5E, 0x5D, 0xC3]);
        _dlsymBytes = b.Count - dlsymOff;

        // ---- __dlclose (82 bytes) ----
        int dlcloseOff = b.Count;
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x3D]);
        b.AddRange([0x48, 0x39, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnRoot, b.Count - 4);
        b.AddRange([0x74, 0x34]);
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x50, 0x48, 0x89, 0xFB]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlcloseFiniCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xDF]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlcloseCloseCallDisp = b.Count - 4;
        b.AddRange([0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xDF]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlcloseDestroyCallDisp = b.Count - 4;
        b.AddRange([0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 4);
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        b.AddRange([0xC7, 0x05, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 8, addend: -8);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3]);
        _dlcloseBytes = b.Count - dlcloseOff;

        // ---- __dlopen (215 bytes) ----
        int dlopenOff = b.Count;
        b.AddRange([0x40, 0xF6, 0xC6, 0x03, 0x74, 0x66]);
        b.AddRange([0xF7, 0xC6, 0x00, 0x02, 0x00, 0x00, 0x75, 0x52]);
        b.AddRange([0xF7, 0xC6, 0x00, 0x20, 0x00, 0x00, 0x75, 0x4A]);
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnRoot, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xFF, 0x74, 0x56]);
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x56, 0x53]);
        b.AddRange([0x41, 0x89, 0xF6, 0x48, 0x89, 0xFE, 0x48, 0x89, 0xC7]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlopenLibNewCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x3C]);
        b.AddRange([0x48, 0x89, 0xC3, 0x48, 0x89, 0xC7]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlopenLibOpenCallDisp = b.Count - 4;
        b.AddRange([0x89, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 4);
        b.AddRange([0x85, 0xC0, 0x74, 0x34]);
        b.AddRange([0x48, 0x89, 0xDF]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlopenDestroyCallDisp = b.Count - 4;
        b.AddRange([0x31, 0xC0, 0xEB, 0x72]);
        b.AddRange([0xC7, 0x05, 0, 0, 0, 0, 0x4E, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 8, addend: -8);
        b.AddRange([0xEB, 0x0A]);
        b.AddRange([0xC7, 0x05, 0, 0, 0, 0, 0x16, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 8, addend: -8);
        b.AddRange([0x31, 0xC0, 0xC3]);
        b.AddRange([0xC7, 0x05, 0, 0, 0, 0, 0x0C, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 8, addend: -8);
        b.AddRange([0x31, 0xC0, 0xEB, 0x4B]);
        b.AddRange([0x41, 0xF7, 0xC6, 0x00, 0x01, 0x00, 0x00, 0x74, 0x10]);
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnRoot, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xDE]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlopenAppendDepCallDisp = b.Count - 4;
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnGetargc, b.Count - 4);
        b.AddRange([0x41, 0x89, 0xC6]);
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnGetargv, b.Count - 4);
        b.AddRange([0x48, 0x8B, 0x0D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.DlfcnEnviron, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xDF, 0x44, 0x89, 0xF6, 0x48, 0x89, 0xC2]);
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        int dlopenInitCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xD8]);
        b.AddRange([0xC7, 0x05, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00]);
        AddRel(RelocSymbol.DlfcnDlerrno, b.Count - 8, addend: -8);
        b.AddRange([0x5B, 0x41, 0x5E, 0x5D, 0xC3]);
        _dlopenBytes = b.Count - dlopenOff;

        // ============================================================================
        // PAYLOAD VTABLE FUNCTIONS + payload_open + __rtld_payload_new
        // (lane #2: rtld_payload port)
        // ============================================================================

        // ---- payload vtable + payload_open + __rtld_payload_new (lane #2) ----
        _currentRelocs = _payloadRelocs;

        // ---- payload_close (3 bytes): xor eax, eax; ret ----
        int payloadCloseOff = b.Count;
        b.AddRange([0x31, 0xC0, 0xC3]);
        int payloadCloseBytes = b.Count - payloadCloseOff;

        // ---- payload_destroy (6 bytes): jmp qword [rip+free] ----
        // SDK-exact: ff 25 disp32 — no trailing ret (the jmp is a tail-call).
        int payloadDestroyOff = b.Count;
        b.AddRange([0xFF, 0x25, 0, 0, 0, 0]);
        AddRel(RelocSymbol.RtldFree, b.Count - 4);
        int payloadDestroyBytes = b.Count - payloadDestroyOff;

        // ---- payload_init_vtable (SDK-matched layout, 109 bytes / 0x6D) ----
        // Called by __rtld_lib_init via vtable at lib+0x08.
        // SDK payload_init from .text.payload_init of crt1.o.
        // Signature: payload_init(rdi=lib [unused], esi=argc, rdx=argv, rcx=env)
        // NOTE: SDK uses mov [rip+disp] (0x8B) for GOT-style loads of init_array
        //   symbols. The emitter uses lea [rip+disp] (0x8D) because symbols are resolved
        //   symbols directly without GOT entries. The linker would relax the SDK's
        //   R_X86_64_REX_GOTPCRELX to lea in the final binary anyway. All other
        //   bytes are SDK-exact.
        int payloadInitVtableOff = b.Count;
        // +0x00: prologue
        b.AddRange([0x55, 0x48, 0x89, 0xE5,                                // push rbp; mov rbp, rsp
                    0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,        // push r15..r12
                    0x53, 0x50]);                                           // push rbx; push rax
        // +0x0e: r12 = init_array_end (lea = linker-relaxed form of SDK's mov [rip+GOT])
        b.AddRange([0x4C, 0x8D, 0x25, 0x00, 0x00, 0x00, 0x00]);            // lea r12, [rip+__init_array_end]
        AddRel(RelocSymbol.InitArrayEnd, b.Count - 4);
        // +0x15: sub r12, init_array_start — SDK uses sub r12,[rip+GOT]; the emitter uses lea+sub
        b.AddRange([0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);            // lea rax, [rip+__init_array_start]
        AddRel(RelocSymbol.InitArrayStart, b.Count - 4);
        b.AddRange([0x49, 0x29, 0xC4]);                                    // sub r12, rax
        // +0x1f: je .Ldone
        int piVtJeDone = b.Count;
        b.AddRange([0x74, 0x00]);                                           // je .Ldone (patched)
        // save argc/argv/env
        b.AddRange([0x48, 0x89, 0xCB]);                                    // mov rbx, rcx
        b.AddRange([0x49, 0x89, 0xD6]);                                    // mov r14, rdx
        b.AddRange([0x41, 0x89, 0xF7]);                                    // mov r15d, esi
        // count = size >> 3, ensure >= 1
        b.AddRange([0x49, 0xC1, 0xFC, 0x03]);                              // sar r12, 3
        b.AddRange([0x49, 0x83, 0xFC, 0x01]);                              // cmp r12, 1
        b.AddRange([0x49, 0x83, 0xD4, 0x00]);                              // adc r12, 0
        b.AddRange([0x45, 0x31, 0xED]);                                    // xor r13d, r13d
        // alignment NOP to align .Lloop (7 bytes: SDK uses 10-byte NOP here
        // because its header is 3 bytes shorter due to sub [rip+GOT])
        b.AddRange([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]);            // nopl 0(%rax)
        // .Lloop:
        int piVtLoop = b.Count;
        b.AddRange([0x44, 0x89, 0xFF]);                                    // mov edi, r15d
        b.AddRange([0x4C, 0x89, 0xF6]);                                    // mov rsi, r14
        b.AddRange([0x48, 0x89, 0xDA]);                                    // mov rdx, rbx
        // lea rax, [rip+__init_array_start] (SDK uses mov rax,[rip+GOT])
        b.AddRange([0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);            // lea rax, [rip+__init_array_start]
        AddRel(RelocSymbol.InitArrayStart, b.Count - 4);
        b.AddRange([0x42, 0xFF, 0x14, 0xE8]);                              // call [rax+r13*8]
        b.AddRange([0x49, 0xFF, 0xC5]);                                    // inc r13
        b.AddRange([0x4D, 0x39, 0xEC]);                                    // cmp r12, r13
        b.Add(0x75); b.Add((byte)(piVtLoop - (b.Count + 1)));              // jne .Lloop
        // .Ldone:
        int piVtDone = b.Count;
        b[piVtJeDone + 1] = (byte)(piVtDone - (piVtJeDone + 2));
        // epilogue
        b.AddRange([0x31, 0xC0,                                             // xor eax, eax
                    0x48, 0x83, 0xC4, 0x08,                                 // add rsp, 8
                    0x5B,                                                    // pop rbx
                    0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F,        // pop r12..r15
                    0x5D, 0xC3]);                                           // pop rbp; ret

        // ---- payload_fini_vtable (SDK-matched layout, 89 bytes / 0x59) ----
        // Called by __rtld_lib_fini via vtable at lib+0x20.
        // SDK payload_fini from .text.payload_fini of crt1.o.
        // Signature: payload_fini(rdi=lib [unused])
        // NOTE: Same lea-vs-mov note as payload_init — SDK uses mov [rip+GOT],
        //   the emitter uses lea [rip+sym] (linker-relaxed equivalent).
        int payloadFiniVtableOff = b.Count;
        // +0x00: prologue
        b.AddRange([0x55, 0x48, 0x89, 0xE5,                                // push rbp; mov rbp, rsp
                    0x41, 0x57, 0x41, 0x56,                                 // push r15; push r14
                    0x53, 0x50]);                                           // push rbx; push rax
        // +0x0a: rax = fini_array_end (lea = linker-relaxed of SDK's mov [rip+GOT])
        b.AddRange([0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);            // lea rax, [rip+__fini_array_end]
        AddRel(RelocSymbol.FiniArrayEnd, b.Count - 4);
        // +0x11: sub rax, fini_array_start — SDK uses sub rax,[rip+GOT]; the emitter uses lea+sub
        b.AddRange([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);            // lea rcx, [rip+__fini_array_start]
        AddRel(RelocSymbol.FiniArrayStart, b.Count - 4);
        b.AddRange([0x48, 0x29, 0xC8]);                                    // sub rax, rcx
        // +0x1b: je .Ldone
        int pfVtJeDone = b.Count;
        b.AddRange([0x74, 0x00]);                                           // je .Ldone (patched)
        // sar rax, 3 ; xor ebx, ebx ; cmp rax, 1 ; mov r14d, 0 ; sbb r14, rax
        b.AddRange([0x48, 0xC1, 0xF8, 0x03]);                              // sar rax, 3
        b.AddRange([0x31, 0xDB]);                                           // xor ebx, ebx
        b.AddRange([0x48, 0x83, 0xF8, 0x01]);                              // cmp rax, 1
        b.AddRange([0x41, 0xBE, 0x00, 0x00, 0x00, 0x00]);                  // mov r14d, 0
        b.AddRange([0x49, 0x19, 0xC6]);                                    // sbb r14, rax
        // reload fini_array_start base for r15 calculation
        b.AddRange([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00]);            // lea rcx, [rip+__fini_array_start]
        AddRel(RelocSymbol.FiniArrayStart, b.Count - 4);
        // r15 = &fini_array[count-1]
        b.AddRange([0x4C, 0x8D, 0x7C, 0xC1, 0xF8]);                        // lea r15, [rcx+rax*8-8]
        // alignment NOP before loop
        b.AddRange([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]);            // nopl 0(%rax)
        // .Lloop:
        int pfVtLoop = b.Count;
        b.AddRange([0x41, 0xFF, 0x14, 0xDF]);                              // call [r15+rbx*8]
        b.AddRange([0x48, 0xFF, 0xCB]);                                    // dec rbx
        b.AddRange([0x49, 0x39, 0xDE]);                                    // cmp r14, rbx
        b.Add(0x75); b.Add((byte)(pfVtLoop - (b.Count + 1)));              // jne .Lloop
        // .Ldone:
        int pfVtDone = b.Count;
        b[pfVtJeDone + 1] = (byte)(pfVtDone - (pfVtJeDone + 2));
        // epilogue
        b.AddRange([0x31, 0xC0,                                             // xor eax, eax
                    0x48, 0x83, 0xC4, 0x08,                                 // add rsp, 8
                    0x5B,                                                    // pop rbx
                    0x41, 0x5E, 0x41, 0x5F,                                 // pop r14; pop r15
                    0x5D, 0xC3]);                                           // pop rbp; ret

        // ---- payload_sym2addr (SDK-exact 187 bytes / 0xBB) ----
        // rdi = ctx (rtld_payload_lib_t*), rsi = name
        // Returns mapbase + sym->st_value if found, else 0.
        // SDK layout: quick null check before prologue, r12 holds magic constant,
        //   r13 is byte offset, rbx is index, mulx per iteration.
        int payloadSym2addrOff = b.Count;
        // +0x00: cmpq $0, 0x468(%rdi) ; je .Lret0_short (0x40)
        b.AddRange([0x48, 0x83, 0xBF, 0x68, 0x04, 0x00, 0x00, 0x00]);
        b.AddRange([0x74, 0x36]);                                           // je +0x36 -> 0x40
        // +0x0a: prologue
        b.AddRange([0x55, 0x48, 0x89, 0xE5,                                // push rbp; mov rbp, rsp
                    0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,        // push r15..r12
                    0x53, 0x50]);                                           // push rbx; push rax
        // +0x18: mov r14, rdi
        b.AddRange([0x49, 0x89, 0xFE]);
        // +0x1b: cmpq $0, 0x470(%rdi) ; je .Lepilogue_0 (0x2f)
        b.AddRange([0x48, 0x83, 0xBF, 0x70, 0x04, 0x00, 0x00, 0x00]);
        b.AddRange([0x74, 0x0A]);                                           // je +0x0a -> 0x2f
        // +0x25: cmpq $0x18, 0x478(%r14) ; jae +0x14 -> 0x43
        b.AddRange([0x49, 0x83, 0xBE, 0x78, 0x04, 0x00, 0x00, 0x18]);
        b.AddRange([0x73, 0x14]);                                           // jae +0x14 -> 0x43
        // +0x2f: .Lepilogue_0 — return 0 with full epilogue
        int ps2aEpilogue0 = b.Count;
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B,                          // add rsp,8; pop rbx
                    0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F,        // pop r12..r15
                    0x5D, 0xC3]);                                           // pop rbp; ret
        // +0x40: .Lret0_short — return 0 without prologue
        b.AddRange([0x31, 0xC0, 0xC3]);                                    // xor eax, eax; ret
        // +0x43: set up loop
        b.AddRange([0x49, 0x89, 0xF7]);                                    // mov r15, rsi (name)
        b.AddRange([0x49, 0xBC, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]); // movabs r12, magic
        b.AddRange([0x45, 0x31, 0xED]);                                    // xor r13d, r13d (byte offset)
        b.AddRange([0x31, 0xDB]);                                           // xor ebx, ebx (index)
        b.AddRange([0xEB, 0x25]);                                           // jmp .Lcheck (0x7c)
        // +0x57: alignment NOP (9 bytes)
        b.AddRange([0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // +0x60: .Lnext
        int ps2aNext = b.Count;
        b.AddRange([0x48, 0xFF, 0xC3]);                                    // inc rbx
        b.AddRange([0x4C, 0x89, 0xE2]);                                    // mov rdx, r12 (magic)
        // mulx 0x478(%r14), rax, rax — BMI2 unsigned high multiply
        b.AddRange([0xC4, 0xC2, 0xFB, 0xF6, 0x86, 0x78, 0x04, 0x00, 0x00]);
        b.AddRange([0x48, 0xC1, 0xE8, 0x04]);                              // shr rax, 4
        b.AddRange([0x49, 0x83, 0xC5, 0x18]);                              // add r13, 24
        b.AddRange([0x48, 0x39, 0xC3]);                                    // cmp rbx, rax
        b.AddRange([0x73, (byte)(ps2aEpilogue0 - (b.Count + 2))]);         // jae .Lepilogue_0
        // +0x7c: .Lcheck — load symtab, check st_size
        int ps2aCheck = b.Count;
        b.AddRange([0x49, 0x8B, 0x86, 0x68, 0x04, 0x00, 0x00]);            // mov rax, [r14+0x468]
        b.AddRange([0x4A, 0x83, 0x7C, 0x28, 0x10, 0x00]);                  // cmpq $0, 0x10(%rax,%r13)
        b.AddRange([0x74, (byte)(ps2aNext - (b.Count + 2))]);              // je .Lnext
        // get st_name, add strtab base
        b.AddRange([0x42, 0x8B, 0x34, 0x28]);                              // mov esi, [rax+r13]
        b.AddRange([0x49, 0x03, 0xB6, 0x70, 0x04, 0x00, 0x00]);            // add rsi, [r14+0x470]
        // strcmp(name, strtab+st_name)
        b.AddRange([0x4C, 0x89, 0xFF]);                                    // mov rdi, r15
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                              // call [rip+strcmp]
        AddRel(RelocSymbol.RtldStrcmp, b.Count - 4);
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x75, (byte)(ps2aNext - (b.Count + 2))]);              // jne .Lnext
        // Found: return mapbase + sym->st_value
        b.AddRange([0x49, 0x8B, 0x86, 0x38, 0x04, 0x00, 0x00]);            // mov rax, [r14+0x438]
        b.AddRange([0x49, 0x8B, 0x8E, 0x68, 0x04, 0x00, 0x00]);            // mov rcx, [r14+0x468]
        b.AddRange([0x4A, 0x03, 0x44, 0x29, 0x08]);                        // add rax, [rcx+r13+8]
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]);                        // jmp .Lepilogue (0x31)
        WriteRel32InBLocal(b.Count - 4, ps2aEpilogue0 + 2);                // target = inside epilogue after xor
        int payloadSym2addrBytes = b.Count - payloadSym2addrOff;

        // ---- payload_addr2sym (SDK-exact 143 bytes / 0x8F) ----
        // rdi = ctx, rsi = addr. Returns strtab + st_name or 0.
        // No prologue/epilogue — leaf function, all in caller-saved regs.
        int payloadAddr2symOff = b.Count;
        // +0x00: mov rcx, [rdi+0x468] ; test rcx, rcx ; je .Lret0 (0x4f)
        b.AddRange([0x48, 0x8B, 0x8F, 0x68, 0x04, 0x00, 0x00]);
        b.AddRange([0x48, 0x85, 0xC9]);
        b.AddRange([0x74, 0x43]);                                           // je +0x43 -> 0x4f
        // +0x0c: mov r8, [rdi+0x470] ; test r8, r8 ; je .Lret0
        b.AddRange([0x4C, 0x8B, 0x87, 0x70, 0x04, 0x00, 0x00]);
        b.AddRange([0x4D, 0x85, 0xC0]);
        b.AddRange([0x74, 0x37]);                                           // je +0x37 -> 0x4f
        // +0x18: mov r9, [rdi+0x438] ; cmp r9, rsi ; ja .Lret0
        b.AddRange([0x4C, 0x8B, 0x8F, 0x38, 0x04, 0x00, 0x00]);
        b.AddRange([0x49, 0x39, 0xF1]);
        b.AddRange([0x77, 0x2B]);                                           // ja +0x2b -> 0x4f
        // +0x24: mov rax, [rdi+0x440] ; add rax, r9 ; cmp rax, rsi ; jb .Lret0
        b.AddRange([0x48, 0x8B, 0x87, 0x40, 0x04, 0x00, 0x00]);
        b.AddRange([0x4C, 0x01, 0xC8]);
        b.AddRange([0x48, 0x39, 0xF0]);
        b.AddRange([0x72, 0x1C]);                                           // jb +0x1c -> 0x4f
        // +0x33: mulx rdi,rdi,rax for symtab_size / 24
        b.AddRange([0x48, 0x8B, 0x97, 0x78, 0x04, 0x00, 0x00]);            // mov rdx, [rdi+0x478]
        b.AddRange([0x48, 0xB8, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]); // movabs rax, magic
        b.AddRange([0xC4, 0xE2, 0xC3, 0xF6, 0xF8]);                        // mulx rdi, rdi, rax
        // +0x49: cmp rdx, 0x18 ; jae .Lcontinue (0x52)
        b.AddRange([0x48, 0x83, 0xFA, 0x18]);
        b.AddRange([0x73, 0x03]);                                           // jae +3 -> 0x52
        // +0x4f: .Lret0
        int pa2sRet0 = b.Count;
        b.AddRange([0x31, 0xC0, 0xC3]);                                    // xor eax, eax; ret
        // +0x52: shr rdi, 4 ; add rcx, 0x10 ; xor eax, eax
        b.AddRange([0x48, 0xC1, 0xEF, 0x04]);
        b.AddRange([0x48, 0x83, 0xC1, 0x10]);
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        // +0x5c: jmp .Lcheck (0x69)
        b.AddRange([0xEB, 0x0B]);
        // +0x5e: alignment NOP (2 bytes)
        b.AddRange([0x66, 0x90]);                                           // xchg ax, ax
        // +0x60: .Lnext
        int pa2sNext = b.Count;
        b.AddRange([0x48, 0x83, 0xC1, 0x18]);                              // add rcx, 0x18
        b.AddRange([0x48, 0xFF, 0xCF]);                                    // dec rdi
        b.AddRange([0x74, (byte)(pa2sRet0 - (b.Count + 2))]);              // je .Lret0 (0x51)
        // +0x69: .Lcheck
        int pa2sLoop = b.Count;
        b.AddRange([0x48, 0x8B, 0x11]);                                    // mov rdx, [rcx] (st_size)
        b.AddRange([0x48, 0x85, 0xD2]);                                    // test rdx, rdx
        b.AddRange([0x74, (byte)(pa2sNext - (b.Count + 2))]);              // je .Lnext
        // mov r10, [rcx-8] ; add r10, r9 ; cmp r10, rsi ; ja .Lnext
        b.AddRange([0x4C, 0x8B, 0x51, 0xF8]);
        b.AddRange([0x4D, 0x01, 0xCA]);
        b.AddRange([0x49, 0x39, 0xF2]);
        b.AddRange([0x77, (byte)(pa2sNext - (b.Count + 2))]);              // ja .Lnext
        // add r10, rdx ; cmp r10, rsi ; jb .Lnext
        b.AddRange([0x49, 0x01, 0xD2]);
        b.AddRange([0x49, 0x39, 0xF2]);
        b.AddRange([0x72, (byte)(pa2sNext - (b.Count + 2))]);              // jb .Lnext
        // Found: mov eax, [rcx-0x10] ; add r8, rax ; mov rax, r8 ; ret
        b.AddRange([0x8B, 0x41, 0xF0]);                                    // mov eax, [rcx-0x10]
        b.AddRange([0x49, 0x01, 0xC0]);                                    // add r8, rax
        b.AddRange([0x4C, 0x89, 0xC0]);                                    // mov rax, r8
        b.AddRange([0xC3]);                                                 // ret
        int payloadAddr2symBytes = b.Count - payloadAddr2symOff;

        // ============================================================================
        // payload_open -- THE GOT FIXUP DRIVER
        //
        // rdi = rtld_lib_t* ctx (rtld_payload_lib_t*)
        // Walks _DYNAMIC, loads DT_NEEDED SPRX, resolves all GLOB_DAT/JMP_SLOT/R_X86_64_64/RELATIVE.
        // ============================================================================
        int payloadOpenOff = b.Count;

        // push rbp; mov rbp, rsp; push r15; push r14; push r13; push r12; push rbx; sub rsp, 0x38
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xEC, 0x38]);
        // mov rbx, rdi  (lib = ctx)
        b.AddRange([0x48, 0x89, 0xFB]);

        // ---- Phase 1: Walk _DYNAMIC for lookup tables ----
        // r12 = _DYNAMIC ptr, zeroed accumulators
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);          // lea rsi, [rip+_DYNAMIC]
        int poOpenDynamicLeaAt = b.Count - 4;
        // Initialize: gnu_hash=0, relasz=0, pltsz=0, rela=0, plt=0
        b.AddRange([0x48, 0xC7, 0x45, 0xC8, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0x38], 0 (gnu_hash)
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0x30], 0 (relasz)
        b.AddRange([0x48, 0xC7, 0x45, 0xB0, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0x50], 0 (pltsz)
        b.AddRange([0x4D, 0x31, 0xFF]);                        // xor r15, r15 (rela)
        b.AddRange([0x4D, 0x31, 0xF6]);                        // xor r14, r14 (plt)

        // .Ldyn_loop:
        int poDynLoop = b.Count;
        b.AddRange([0x48, 0x8B, 0x06]);                       // mov rax, [rsi] (d_tag)
        b.AddRange([0x48, 0x85, 0xC0]);                       // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                 // jz .Ldyn_done
        int poDynDoneJump = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x4E, 0x08]);                 // mov rcx, [rsi+8] (d_val)
        // Switch on d_tag: DT_SYMTAB(6), DT_STRTAB(5), DT_GNU_HASH(0x6ffffef5), DT_RELA(7), DT_RELASZ(8), DT_JMPREL(23), DT_PLTRELSZ(2)
        // DT_SYMTAB=6
        b.AddRange([0x48, 0x83, 0xF8, 0x06]);                 // cmp rax, 6
        b.AddRange([0x75, 0x0E]);                             // jne +14 (skip add 7 + mov 7 = 14)
        b.AddRange([0x48, 0x03, 0x8B, 0x38, 0x04, 0x00, 0x00]); // add rcx, [rbx+0x438]
        b.AddRange([0x48, 0x89, 0x8B, 0x68, 0x04, 0x00, 0x00]); // mov [rbx+0x468], rcx
        // DT_STRTAB=5
        b.AddRange([0x48, 0x83, 0xF8, 0x05]);
        b.AddRange([0x75, 0x0E]);                             // jne +14 (skip add 7 + mov 7 = 14)
        b.AddRange([0x48, 0x03, 0x8B, 0x38, 0x04, 0x00, 0x00]);
        b.AddRange([0x48, 0x89, 0x8B, 0x70, 0x04, 0x00, 0x00]);
        // DT_GNU_HASH=0x6ffffef5
        b.AddRange([0x48, 0xBA, 0xF5, 0xFE, 0xFF, 0x6F, 0x00, 0x00, 0x00, 0x00]);
        b.AddRange([0x48, 0x39, 0xD0]);
        b.AddRange([0x75, 0x0D]);                             // jne +13 (skip add 7 + mov 4 + jmp 2 = 13)
        b.AddRange([0x48, 0x03, 0x8B, 0x38, 0x04, 0x00, 0x00]);
        b.AddRange([0x48, 0x89, 0x4D, 0xC8]);                 // mov [rbp-0x38], rcx (gnu_hash)
        b.AddRange([0xEB, 0x00]);
        int poSkipGnuHash = b.Count - 1;
        // DT_RELA=7
        b.AddRange([0x48, 0x83, 0xF8, 0x07]);
        b.AddRange([0x75, 0x0A]);                             // jne +10 (skip add 7 + mov 3 = 10)
        b.AddRange([0x48, 0x03, 0x8B, 0x38, 0x04, 0x00, 0x00]);
        b.AddRange([0x49, 0x89, 0xCF]);                       // mov r15, rcx
        // DT_RELASZ=8
        b.AddRange([0x48, 0x83, 0xF8, 0x08]);
        b.AddRange([0x75, 0x04]);
        b.AddRange([0x48, 0x89, 0x4D, 0xD0]);                 // mov [rbp-0x30], rcx
        // DT_JMPREL=23
        b.AddRange([0x48, 0x83, 0xF8, 0x17]);
        b.AddRange([0x75, 0x0A]);                             // jne +10 (skip add 7 + mov 3 = 10)
        b.AddRange([0x48, 0x03, 0x8B, 0x38, 0x04, 0x00, 0x00]);
        b.AddRange([0x49, 0x89, 0xCE]);                       // mov r14, rcx
        // DT_PLTRELSZ=2
        b.AddRange([0x48, 0x83, 0xF8, 0x02]);
        b.AddRange([0x75, 0x04]);
        b.AddRange([0x48, 0x89, 0x4D, 0xB0]);                 // mov [rbp-0x50], rcx (pltsz)
        int poSkipPltSz = b.Count;
        b[poSkipGnuHash] = (byte)(poSkipPltSz - (poSkipGnuHash + 1)); // fixup: skip remaining DT_* checks
        // advance: add rsi, 16 ; jmp .Ldyn_loop
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);
        b.AddRange([0xE9, 0, 0, 0, 0]);
        WriteRel32InBLocal(b.Count - 4, poDynLoop);

        // .Ldyn_done:
        int poDynDone = b.Count;
        WriteRel32InBLocal(poDynDoneJump, poDynDone);

        // ---- Phase 1b: compute symtab_size from gnu_hash ----
        // if(gnu_hash) { lib->symtab_size = dynsym_count(gnu_hash) * sizeof(Elf64_Sym); }
        b.AddRange([0x48, 0x8B, 0x7D, 0xC8]);                 // mov rdi, [rbp-0x38] (gnu_hash)
        b.AddRange([0x48, 0x85, 0xFF]);                       // test rdi, rdi
        b.AddRange([0x74, 0x00]);                             // jz .Lskip_gnuhash
        int poSkipGnuHashCalc = b.Count - 1;
        // inline dynsym_count(gnu_hash):
        // nbuckets = [rdi], symoffset = [rdi+4], bloom_size = [rdi+8]
        // bloom = rdi+16, buckets = bloom + bloom_size*8, chain = buckets + nbuckets*4
        b.AddRange([0x44, 0x8B, 0x07]);                       // mov r8d, [rdi] (nbuckets)
        b.AddRange([0x44, 0x8B, 0x4F, 0x04]);                 // mov r9d, [rdi+4] (symoffset)
        b.AddRange([0x8B, 0x47, 0x08]);                       // mov eax, [rdi+8] (bloom_size)
        // buckets = rdi + 16 + bloom_size*8
        b.AddRange([0x48, 0x8D, 0x4C, 0xC7, 0x10]);           // lea rcx, [rdi+rax*8+16]
        // chain = buckets + nbuckets*4
        b.AddRange([0x4A, 0x8D, 0x14, 0x81]);                 // lea rdx, [rcx+r8*4]
        // Walk buckets to find max_index
        b.AddRange([0x31, 0xC0]);                             // xor eax, eax (max_index=0)
        b.AddRange([0x45, 0x85, 0xC0]);                       // test r8d, r8d
        b.AddRange([0x74, 0x00]);                             // jz .Lgh_done
        int poGhDoneJump = b.Count - 1;
        b.AddRange([0x45, 0x31, 0xD2]);                       // xor r10d, r10d (i=0)
        // .Lgh_bucket_loop:
        int poGhBucketLoop = b.Count;
        b.AddRange([0x46, 0x8B, 0x1C, 0x91]);                 // mov r11d, [rcx+r10*4]
        b.AddRange([0x45, 0x85, 0xDB]);                       // test r11d, r11d
        b.AddRange([0x74, 0x00]);                             // jz .Lgh_next_bucket
        int poGhNextBucketJump = b.Count - 1;
        // Walk chain from this bucket index
        // .Lgh_chain_loop:
        int poGhChainLoop = b.Count;
        b.AddRange([0x45, 0x89, 0xDC]);                       // mov r12d, r11d (index)
        b.AddRange([0x45, 0x29, 0xCB]);                       // sub r11d, r9d (index - symoffset)
        b.AddRange([0x46, 0xF7, 0x04, 0x9A, 0x01, 0x00, 0x00, 0x00]); // test dword [rdx+r11*4], 1
        b.AddRange([0x75, 0x00]);                             // jnz .Lgh_chain_end
        int poGhChainEndJump = b.Count - 1;
        b.AddRange([0x41, 0xFF, 0xC4]);                       // inc r12d
        b.AddRange([0x45, 0x89, 0xE3]);                       // mov r11d, r12d
        b.AddRange([0xEB, (byte)(poGhChainLoop - (b.Count + 2))]); // jmp .Lgh_chain_loop
        // .Lgh_chain_end:
        int poGhChainEnd = b.Count;
        b[poGhChainEndJump] = (byte)(poGhChainEnd - (poGhChainEndJump + 1));
        b.AddRange([0x41, 0x39, 0xC4]);                       // cmp r12d, eax
        b.AddRange([0x44, 0x0F, 0x47, 0xE0]);                 // cmova r12d, eax -> NO! cmova = CF=0&&ZF=0
        // Goal: if r12d > eax then eax = r12d
        // cmp r12d, eax ; cmova eax, r12d -- cmova = cmov if above
        // Alternative: cmp eax, r12d ; cmovb eax, r12d
        // The above cmp r12d, eax tests r12d - eax. If r12d > eax, CF=0, ZF=0, so cmova moves.
        // But cmova src, dst = "move if above" = CF=0 && ZF=0 -- this is for the FIRST operand being "above" the second
        // The emitted cmp r12d, eax + cmova r12d, eax is inverted: it copies eax
        // into r12d when r12d > eax, but the goal is eax = max(eax, r12d).
        // Remove the last 7 bytes and use a branch instead.
        b.RemoveRange(b.Count - 7, 7);

        // Correct approach: cmp eax, r12d ; jae .Lgh_no_update ; mov eax, r12d ; .Lgh_no_update:
        b.AddRange([0x44, 0x39, 0xE0]);                       // cmp eax, r12d
        b.AddRange([0x73, 0x03]);                             // jae +3
        b.AddRange([0x44, 0x89, 0xE0]);                       // mov eax, r12d
        // .Lgh_no_update:

        // .Lgh_next_bucket:
        int poGhNextBucket = b.Count;
        b[poGhNextBucketJump] = (byte)(poGhNextBucket - (poGhNextBucketJump + 1));
        b.AddRange([0x41, 0xFF, 0xC2]);                       // inc r10d
        b.AddRange([0x45, 0x39, 0xC2]);                       // cmp r10d, r8d
        b.AddRange([0x72, (byte)(poGhBucketLoop - (b.Count + 2))]); // jb .Lgh_bucket_loop
        // .Lgh_done:
        int poGhDone = b.Count;
        b[poGhDoneJump] = (byte)(poGhDone - (poGhDoneJump + 1));
        // max_index + 1, then * sizeof(Elf64_Sym)
        b.AddRange([0xFF, 0xC0]);                             // inc eax
        b.AddRange([0x48, 0x8D, 0x04, 0x40]);                 // lea rax, [rax+rax*2] (= eax*3)
        b.AddRange([0x48, 0xC1, 0xE0, 0x03]);                 // shl rax, 3 (= eax*24)
        b.AddRange([0x48, 0x89, 0x83, 0x78, 0x04, 0x00, 0x00]); // mov [rbx+0x478], rax
        // .Lskip_gnuhash:
        int poSkipGnuHashCalcTarget = b.Count;
        b[poSkipGnuHashCalc] = (byte)(poSkipGnuHashCalcTarget - (poSkipGnuHashCalc + 1));

        // ---- Phase 2: Walk _DYNAMIC again for DT_NEEDED ----
        b.AddRange([0x48, 0x8D, 0x35, 0, 0, 0, 0]);          // lea rsi, [rip+_DYNAMIC]
        int poNeededDynamicLeaAt = b.Count - 4;
        // .Lneeded_loop:
        int poNeededLoop = b.Count;
        b.AddRange([0x48, 0x8B, 0x06]);                       // mov rax, [rsi]
        b.AddRange([0x48, 0x85, 0xC0]);                       // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                 // jz .Lneeded_done
        int poNeededDoneJump = b.Count - 4;
        b.AddRange([0x48, 0x83, 0xF8, 0x01]);                 // cmp rax, 1 (DT_NEEDED)
        b.AddRange([0x75, 0x00]);                             // jne .Lneeded_skip
        int poNeededSkipJump = b.Count - 1;
        // DT_NEEDED: soname = strtab + d_val
        b.AddRange([0x48, 0x89, 0x75, 0xA8]);                 // mov [rbp-0x58], rsi (save _DYNAMIC ptr)
        b.AddRange([0x48, 0x8B, 0x46, 0x08]);                 // mov rax, [rsi+8] (d_val)
        b.AddRange([0x48, 0x03, 0x83, 0x70, 0x04, 0x00, 0x00]); // add rax, [rbx+0x470] (strtab)
        // dt_needed(lib, soname): call __rtld_lib_new(lib, soname)
        b.AddRange([0x48, 0x89, 0xDF]);                       // mov rdi, rbx
        b.AddRange([0x48, 0x89, 0xC6]);                       // mov rsi, rax
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __rtld_lib_new
        int poLibNewCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                       // test rax, rax
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                 // jz .Ldt_needed_fail
        int poDtNeededFailJump = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC4]);                       // mov r12, rax
        // call __rtld_lib_open(needed)
        b.AddRange([0x48, 0x89, 0xC7]);                       // mov rdi, rax
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __rtld_lib_open
        int poLibOpenCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                             // test eax, eax
        b.AddRange([0x78, 0x00]);                             // js .Ldt_needed_open_fail
        int poDtNeededOpenFailJump = b.Count - 1;
        // call __rtld_lib_append_dep(lib, needed)
        b.AddRange([0x48, 0x89, 0xDF]);                       // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xE6]);                       // mov rsi, r12
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __rtld_lib_append_dep
        int poAppendDepCallDisp = b.Count - 4;
        b.AddRange([0x85, 0xC0]);                             // test eax, eax
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                 // jnz .Lfail_ret
        int poAppendDepFailJump = b.Count - 4;
        // Restore rsi and continue loop
        b.AddRange([0x48, 0x8B, 0x75, 0xA8]);                 // mov rsi, [rbp-0x58]
        b.AddRange([0xEB, 0x00]);                             // jmp .Lneeded_skip
        int poNeededContJump = b.Count - 1;
        // .Ldt_needed_open_fail: destroy needed, fall through to fail
        int poDtNeededOpenFail = b.Count;
        b[poDtNeededOpenFailJump] = (byte)(poDtNeededOpenFail - (poDtNeededOpenFailJump + 1));
        b.AddRange([0x4C, 0x89, 0xE7]);                       // mov rdi, r12
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __rtld_lib_destroy
        int poDestroyCallDisp = b.Count - 4;
        // .Ldt_needed_fail: log error and return -1
        int poDtNeededFail = b.Count;
        WriteRel32InBLocal(poDtNeededFailJump, poDtNeededFail);
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);          // lea rdi, [rip+spPayloadLoadFail]
        int poLoadFailLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __prospero_klog
        int poLoadFailKlogDisp = b.Count - 4;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);           // mov eax, -1
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lexit
        int poFailExitJump1 = b.Count - 4;
        // .Lneeded_skip:
        int poNeededSkip = b.Count;
        b[poNeededSkipJump] = (byte)(poNeededSkip - (poNeededSkipJump + 1));
        b[poNeededContJump] = (byte)(poNeededSkip - (poNeededContJump + 1));
        b.AddRange([0x48, 0x83, 0xC6, 0x10]);                 // add rsi, 16
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lneeded_loop
        WriteRel32InBLocal(b.Count - 4, poNeededLoop);
        // .Lneeded_done:
        int poNeededDone = b.Count;
        WriteRel32InBLocal(poNeededDoneJump, poNeededDone);

        // ---- Phase 3: Apply rela.dyn relocations ----
        // r15 = rela ptr, [rbp-0x30] = relasz
        b.AddRange([0x4C, 0x89, 0xFE]);                       // mov rsi, r15 (rela)
        b.AddRange([0x48, 0x89, 0x75, 0xA0]);                 // mov [rbp-0x60], rsi (save rela base)
        b.AddRange([0x48, 0x8B, 0x45, 0xD0]);                 // mov rax, [rbp-0x30] (relasz)
        // count = relasz / 24
        b.AddRange([0x48, 0xB9, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        b.AddRange([0x48, 0xF7, 0xE1]);                       // mul rcx
        b.AddRange([0x48, 0xC1, 0xEA, 0x04]);                 // shr rdx, 4
        b.AddRange([0x48, 0x89, 0x55, 0xA8]);                 // mov [rbp-0x58], rdx (count)
        b.AddRange([0x45, 0x31, 0xE4]);                       // xor r12d, r12d (i=0)
        b.AddRange([0xE9, 0x00, 0x00, 0x00, 0x00]);             // jmp near .Lrela_check (rel32, loop body exceeds rel8 range)
        int poRelaCheckJump = b.Count - 4;

        // .Lrela_loop:
        int poRelaLoop = b.Count;
        // Load current rela entry: rsi = rela_base + i*24
        b.AddRange([0x48, 0x8B, 0x75, 0xA0]);                 // mov rsi, [rbp-0x60]
        // Compute i*24 = (i*3) << 3 via lea rax, [r12+r12*2] ; shl rax, 3.
        // REX.WXB (0x4B): base=r12 (B=1), index=r12 (X=1), 64-bit (W=1).
        // SIB 0x64: scale=01 (*2), index=100 (r12+X), base=100 (r12+B).
        // Now emit correct: rsi += i*24
        // First: rax = i * 24 via lea + shl
        b.AddRange([0x4B, 0x8D, 0x04, 0x64]);                 // lea rax, [r12+r12*2]
        b.AddRange([0x48, 0xC1, 0xE0, 0x03]);                 // shl rax, 3
        b.AddRange([0x48, 0x01, 0xC6]);                       // add rsi, rax

        // r_info type = rsi[8] & 0xFFFFFFFF
        b.AddRange([0x8B, 0x46, 0x08]);                       // mov eax, [rsi+8] (low 32 bits of r_info)

        // Switch on type: 6=GLOB_DAT, 7=JMP_SLOT, 1=R_X86_64_64, 8=RELATIVE
        // For GLOB_DAT(6) and JMP_SLOT(7): call r_glob_dat_inline
        b.AddRange([0x83, 0xF8, 0x06]);                       // cmp eax, 6
        b.AddRange([0x74, 0x00]);                             // je .Lr_glob_dat
        int poGlobDatJump = b.Count - 1;
        b.AddRange([0x83, 0xF8, 0x07]);                       // cmp eax, 7
        b.AddRange([0x74, 0x00]);                             // je .Lr_glob_dat (JMP_SLOT delegates)
        int poJmpSlotJump = b.Count - 1;
        b.AddRange([0x83, 0xF8, 0x01]);                       // cmp eax, 1
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                 // je .Lr_direct_64
        int poDirect64Jump = b.Count - 4;
        b.AddRange([0x83, 0xF8, 0x08]);                       // cmp eax, 8
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                 // je .Lr_relative
        int poRelativeJump = b.Count - 4;
        // Unknown type: log error and return -1
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);          // lea rdi, [rip+spPayloadRelocUnsup]
        int poRelocUnsupLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __prospero_klog
        int poRelocUnsupKlogDisp = b.Count - 4;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);           // mov eax, -1
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lexit
        int poFailExitJump2 = b.Count - 4;

        // .Lr_glob_dat: (also handles JMP_SLOT)
        int poRGlobDat = b.Count;
        b[poGlobDatJump] = (byte)(poRGlobDat - (poGlobDatJump + 1));
        b[poJmpSlotJump] = (byte)(poRGlobDat - (poJmpSlotJump + 1));
        // sym = symtab + ELF64_R_SYM(r_info) * 24
        b.AddRange([0x48, 0x8B, 0x46, 0x08]);                 // mov rax, [rsi+8] (r_info)
        b.AddRange([0x48, 0xC1, 0xE8, 0x20]);                 // shr rax, 32
        b.AddRange([0x48, 0x8D, 0x04, 0x40]);                 // lea rax, [rax+rax*2]
        b.AddRange([0x48, 0xC1, 0xE0, 0x03]);                 // shl rax, 3
        b.AddRange([0x48, 0x03, 0x83, 0x68, 0x04, 0x00, 0x00]); // add rax, [rbx+0x468]
        // name = strtab + sym->st_name
        b.AddRange([0x44, 0x8B, 0x28]);                       // mov r13d, [rax] (st_name)
        b.AddRange([0x4C, 0x03, 0xAB, 0x70, 0x04, 0x00, 0x00]); // add r13, [rbx+0x470]
        // loc = mapbase + r_offset
        b.AddRange([0x4C, 0x8B, 0xBB, 0x38, 0x04, 0x00, 0x00]); // mov r15, [rbx+0x438]
        b.AddRange([0x4C, 0x03, 0x3E]);                       // add r15, [rsi]
        // Save sym ptr and rsi
        b.AddRange([0x48, 0x89, 0x45, 0xC0]);                 // mov [rbp-0x40], rax (sym)
        b.AddRange([0x48, 0x89, 0x75, 0xC8]);                 // mov [rbp-0x38], rsi (rela)
        // val = 0
        b.AddRange([0x48, 0xC7, 0x45, 0xB8, 0x00, 0x00, 0x00, 0x00]); // mov qword [rbp-0x48], 0
        // Call sym2lib(ctx, name)
        b.AddRange([0x48, 0x89, 0xDF]);                       // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xEE]);                       // mov rsi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __rtld_lib_sym2lib
        int poSym2libCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0]);                       // test rax, rax
        b.AddRange([0x74, 0x00]);                             // jz .Lr_glob_dat_miss
        int poGlobDatMissJump = b.Count - 1;
        // Call sym2addr(found_lib, name)
        b.AddRange([0x48, 0x89, 0xC7]);                       // mov rdi, rax
        b.AddRange([0x4C, 0x89, 0xEE]);                       // mov rsi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __rtld_lib_sym2addr
        int poSym2addrCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xB8]);                 // mov [rbp-0x48], rax (val)
        b.AddRange([0x48, 0x85, 0xC0]);                       // test rax, rax
        b.AddRange([0x74, 0x00]);                             // jz .Lr_glob_dat_miss
        int poGlobDatMissJump2 = b.Count - 1;
        // memcpy success path entry point (also used by fallback cascade)
        int poMemcpySuccessPath = b.Count;
        // memcpy(loc, &val, 8)
        b.AddRange([0x4C, 0x89, 0xFF]);                       // mov rdi, r15
        b.AddRange([0x48, 0x8D, 0x75, 0xB8]);                 // lea rsi, [rbp-0x48]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);           // mov edx, 8
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                 // call [rip+memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        // Restore rsi and continue
        b.AddRange([0x48, 0x8B, 0x75, 0xC8]);                 // mov rsi, [rbp-0x38]
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lrela_next
        int poRelaNextJump1 = b.Count - 4;

        // .Lr_glob_dat_miss: check if weak
        // The fallback cascade is no longer needed because rtld_sprx_new +
        // sprx_open + sprx_sym2addr now populate every SPRX lib node with a
        // functional sym2addr that walks the kernel-copyout'd symtab/strtab.
        // If sym2lib + sym2addr still misses, the symbol is genuinely absent.
        int poGlobDatMiss = b.Count;
        b[poGlobDatMissJump] = (byte)(poGlobDatMiss - (poGlobDatMissJump + 1));
        b[poGlobDatMissJump2] = (byte)(poGlobDatMiss - (poGlobDatMissJump2 + 1));
        b.AddRange([0x48, 0x8B, 0x45, 0xC0]);                 // mov rax, [rbp-0x40] (sym)
        b.AddRange([0x0F, 0xB6, 0x40, 0x04]);                 // movzbl eax, [rax+4] (st_info)
        b.AddRange([0x24, 0xF0]);                             // and al, 0xF0
        b.AddRange([0x3C, 0x20]);                             // cmp al, 0x20 (STB_WEAK << 4)
        b.AddRange([0x74, 0x00]);                             // je .Lr_glob_dat_skip_weak (skip silently)
        int poWeakSkipJump = b.Count - 1;
        // Not weak: log error and return -1
        b.AddRange([0x4C, 0x89, 0xEF]);                       // mov rdi, r13 (name)
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __prospero_klog (log the name)
        int poUnresolvedNameKlogDisp = b.Count - 4;
        b.AddRange([0x48, 0x8D, 0x3D, 0, 0, 0, 0]);          // lea rdi, [rip+sp_resolve_miss]
        int poResolveMissLeaAt = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call __prospero_klog
        int poResolveMissKlogDisp = b.Count - 4;
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);           // mov eax, -1
        b.AddRange([0x48, 0x8B, 0x75, 0xC8]);                 // mov rsi, [rbp-0x38]
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lexit
        int poFailExitJump3 = b.Count - 4;
        // .Lr_glob_dat_skip_weak:
        int poWeakSkip = b.Count;
        b[poWeakSkipJump] = (byte)(poWeakSkip - (poWeakSkipJump + 1));
        b.AddRange([0x48, 0x8B, 0x75, 0xC8]);                 // mov rsi, [rbp-0x38]
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lrela_next
        int poRelaNextJump2 = b.Count - 4;

        // .Lr_direct_64: like glob_dat but val += r_addend
        int poDirect64 = b.Count;
        WriteRel32InBLocal(poDirect64Jump, poDirect64);
        // Same as r_glob_dat but r_addend is added to val before memcpy
        b.AddRange([0x48, 0x8B, 0x46, 0x08]);                 // mov rax, [rsi+8] (r_info)
        b.AddRange([0x48, 0xC1, 0xE8, 0x20]);                 // shr rax, 32
        b.AddRange([0x48, 0x8D, 0x04, 0x40]);                 // lea rax, [rax+rax*2]
        b.AddRange([0x48, 0xC1, 0xE0, 0x03]);                 // shl rax, 3
        b.AddRange([0x48, 0x03, 0x83, 0x68, 0x04, 0x00, 0x00]); // add rax, [rbx+0x468]
        b.AddRange([0x44, 0x8B, 0x28]);                       // mov r13d, [rax]
        b.AddRange([0x4C, 0x03, 0xAB, 0x70, 0x04, 0x00, 0x00]); // add r13, [rbx+0x470]
        b.AddRange([0x4C, 0x8B, 0xBB, 0x38, 0x04, 0x00, 0x00]); // mov r15, [rbx+0x438]
        b.AddRange([0x4C, 0x03, 0x3E]);                       // add r15, [rsi]
        b.AddRange([0x48, 0x89, 0x45, 0xC0]);                 // mov [rbp-0x40], rax
        b.AddRange([0x48, 0x89, 0x75, 0xC8]);                 // mov [rbp-0x38], rsi
        b.AddRange([0x48, 0xC7, 0x45, 0xB8, 0x00, 0x00, 0x00, 0x00]); // val=0
        b.AddRange([0x48, 0x89, 0xDF]);                       // mov rdi, rbx
        b.AddRange([0x4C, 0x89, 0xEE]);                       // mov rsi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call sym2lib
        int poD64Sym2libCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]);           // test rax, rax ; jz .Ld64_miss
        int poD64MissJump1 = b.Count - 1;
        b.AddRange([0x48, 0x89, 0xC7]);                       // mov rdi, rax
        b.AddRange([0x4C, 0x89, 0xEE]);                       // mov rsi, r13
        b.AddRange([0xE8, 0, 0, 0, 0]);                       // call sym2addr
        int poD64Sym2addrCallDisp = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xB8]);                 // mov [rbp-0x48], rax
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]);           // test rax, rax ; jz .Ld64_miss
        int poD64MissJump2 = b.Count - 1;
        // val += r_addend
        b.AddRange([0x48, 0x8B, 0x4D, 0xC8]);                 // mov rcx, [rbp-0x38] (rela)
        b.AddRange([0x48, 0x03, 0x41, 0x10]);                 // add rax, [rcx+0x10] (r_addend)
        b.AddRange([0x48, 0x89, 0x45, 0xB8]);                 // mov [rbp-0x48], rax
        // memcpy(loc, &val, 8)
        b.AddRange([0x4C, 0x89, 0xFF]);                       // mov rdi, r15
        b.AddRange([0x48, 0x8D, 0x75, 0xB8]);                 // lea rsi, [rbp-0x48]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);           // mov edx, 8
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                 // call [rip+memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x48, 0x8B, 0x75, 0xC8]);                 // mov rsi, [rbp-0x38]
        b.AddRange([0xE9, 0, 0, 0, 0]);                       // jmp .Lrela_next
        int poRelaNextJump3 = b.Count - 4;
        // .Ld64_miss: (same weak check as glob_dat, but reached from here)
        int poD64Miss = b.Count;
        b[poD64MissJump1] = (byte)(poD64Miss - (poD64MissJump1 + 1));
        b[poD64MissJump2] = (byte)(poD64Miss - (poD64MissJump2 + 1));
        b.AddRange([0x48, 0x8B, 0x75, 0xC8]);                 // mov rsi, [rbp-0x38]
        // jump back to the glob_dat miss handler (reuse code)
        b.AddRange([0xE9, 0, 0, 0, 0]);
        WriteRel32InBLocal(b.Count - 4, poGlobDatMiss);

        // .Lr_relative: mapbase + r_addend -> write to mapbase + r_offset
        int poRelative = b.Count;
        WriteRel32InBLocal(poRelativeJump, poRelative);
        // loc = mapbase + r_offset
        b.AddRange([0x48, 0x8B, 0xBB, 0x38, 0x04, 0x00, 0x00]); // mov rdi, [rbx+0x438]
        b.AddRange([0x48, 0x03, 0x3E]);                       // add rdi, [rsi]
        // val = mapbase + r_addend
        b.AddRange([0x48, 0x8B, 0x83, 0x38, 0x04, 0x00, 0x00]); // mov rax, [rbx+0x438]
        b.AddRange([0x48, 0x03, 0x46, 0x10]);                 // add rax, [rsi+0x10]
        b.AddRange([0x48, 0x89, 0x45, 0xB8]);                 // mov [rbp-0x48], rax
        // memcpy(loc, &val, 8)
        b.AddRange([0x48, 0x8D, 0x75, 0xB8]);                 // lea rsi, [rbp-0x48]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);           // mov edx, 8
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                 // call [rip+memcpy]
        AddRel(RelocSymbol.RtldMemcpy, b.Count - 4);
        b.AddRange([0x48, 0x8B, 0x75, 0xC8]);                 // mov rsi, [rbp-0x38] (restore rela ptr)
        // fall through to .Lrela_next

        // .Lrela_next: i++, check i < count
        int poRelaNext = b.Count;
        WriteRel32InBLocal(poRelaNextJump1, poRelaNext);
        WriteRel32InBLocal(poRelaNextJump2, poRelaNext);
        WriteRel32InBLocal(poRelaNextJump3, poRelaNext);
        WriteRel32InBLocal(poAppendDepFailJump, poRelaNext); // append_dep failure skips rest (non-fatal for now)
        b.AddRange([0x49, 0xFF, 0xC4]);                       // inc r12
        // .Lrela_check:
        int poRelaCheck = b.Count;
        WriteRel32InBLocal(poRelaCheckJump, poRelaCheck);
        b.AddRange([0x4C, 0x3B, 0x65, 0xA8]);                 // cmp r12, [rbp-0x58] (count)
        b.AddRange([0x0F, 0x82, 0, 0, 0, 0]);                 // jb .Lrela_loop
        WriteRel32InBLocal(b.Count - 4, poRelaLoop);

        // ---- Phase 4: Apply rela.plt relocations ----
        // r14 = plt, [rbp-0x50] = pltsz
        b.AddRange([0x4C, 0x89, 0xF6]);                       // mov rsi, r14
        b.AddRange([0x48, 0x89, 0x75, 0xA0]);                 // mov [rbp-0x60], rsi (plt base)
        b.AddRange([0x48, 0x8B, 0x45, 0xB0]);                 // mov rax, [rbp-0x50] (pltsz)
        b.AddRange([0x48, 0xB9, 0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        b.AddRange([0x48, 0xF7, 0xE1]);
        b.AddRange([0x48, 0xC1, 0xEA, 0x04]);
        b.AddRange([0x48, 0x89, 0x55, 0xA8]);                 // mov [rbp-0x58], rdx (plt count)
        b.AddRange([0x45, 0x31, 0xE4]);
        // .Lplt_check:
        int poPltCheck = b.Count;
        b.AddRange([0x4C, 0x3B, 0x65, 0xA8]);                 // cmp r12, [rbp-0x58] (plt count)
        b.AddRange([0x73, 0x00]);                             // jae .Lplt_done
        int poPltDoneJump = b.Count - 1;
        // Load entry
        b.AddRange([0x48, 0x8B, 0x75, 0xA0]);                 // mov rsi, [rbp-0x60] (plt base)
        b.AddRange([0x4B, 0x8D, 0x04, 0x64]);
        b.AddRange([0x48, 0xC1, 0xE0, 0x03]);
        b.AddRange([0x48, 0x01, 0xC6]);
        // r_info type
        b.AddRange([0x8B, 0x46, 0x08]);
        b.AddRange([0x83, 0xF8, 0x07]);                       // cmp eax, 7 (JMP_SLOT)
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                 // je .Lr_glob_dat (reuse GLOB_DAT handler)
        int poPltGlobDatJump = b.Count - 4;
        // Not JMP_SLOT: skip (log is optional, just continue)
        b.AddRange([0x49, 0xFF, 0xC4]);                       // inc r12
        b.AddRange([0xEB, (byte)(poPltCheck - (b.Count + 2))]); // jmp .Lplt_check
        // .Lplt_done:
        int poPltDone = b.Count;
        b[poPltDoneJump] = (byte)(poPltDone - (poPltDoneJump + 1));
        // Wire plt JMP_SLOT back to glob_dat handler
        WriteRel32InBLocal(poPltGlobDatJump, poRGlobDat);

        // Success: return 0
        b.AddRange([0x31, 0xC0]);                             // xor eax, eax
        // .Lexit:
        int poExit = b.Count;
        WriteRel32InBLocal(poFailExitJump1, poExit);
        WriteRel32InBLocal(poFailExitJump2, poExit);
        WriteRel32InBLocal(poFailExitJump3, poExit);
        b.AddRange([0x48, 0x83, 0xC4, 0x38]);                 // add rsp, 0x38
        b.AddRange([0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        int payloadOpenBytes = b.Count - payloadOpenOff;

        // ============================================================================
        // __rtld_payload_new(rdi = soname)
        //
        // calloc(1, 0x480), set vtable, mapbase/mapsize, strcpy soname,
        // SYS_getpid, SYS_thr_set_name.
        // ============================================================================
        int payloadNewOff = b.Count;
        // push rbp; mov rbp, rsp; push r15; push r14; push r13; push r12; push rbx; push rax
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x50]);
        // mov r14, rdi (save soname)
        b.AddRange([0x49, 0x89, 0xFE]);
        // calloc(1, 0x480) via [rip+calloc]
        b.AddRange([0xBF, 0x01, 0x00, 0x00, 0x00]);           // mov edi, 1
        b.AddRange([0xBE, 0x80, 0x04, 0x00, 0x00]);           // mov esi, 0x480
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                 // call [rip+calloc]
        AddRel(RelocSymbol.RtldCalloc, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xC3]);                       // mov rbx, rax

        // Get __crt_syscall address via lea for SYS_getpid call
        b.AddRange([0x4C, 0x8D, 0x2D, 0, 0, 0, 0]);          // lea r13, [rip+__crt_syscall]
        int pnCrtSyscallLeaAt = b.Count - 4;
        // SYS_getpid (20)
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]);           // mov edi, 20
        b.AddRange([0x31, 0xC0]);                             // xor eax, eax
        b.AddRange([0x41, 0xFF, 0xD5]);                       // call r13
        b.AddRange([0x49, 0x89, 0xC7]);                       // mov r15, rax (pid)

        // Set vtable
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_open]
        int pnOpenLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x03]);                       // mov [rbx], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_init_vtable]
        int pnInitVtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x08]);                 // mov [rbx+8], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_sym2addr]
        int pnSym2addrVtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x10]);                 // mov [rbx+0x10], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_addr2sym]
        int pnAddr2symVtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x18]);                 // mov [rbx+0x18], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_fini_vtable]
        int pnFiniVtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x20]);                 // mov [rbx+0x20], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_close]
        int pnCloseVtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x28]);                 // mov [rbx+0x28], rax
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+payload_destroy]
        int pnDestroyVtLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x43, 0x30]);                 // mov [rbx+0x30], rax

        // refcnt = 0
        b.AddRange([0xC7, 0x83, 0x48, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // mapbase = __image_start
        b.AddRange([0x48, 0x8D, 0x05, 0, 0, 0, 0]);          // lea rax, [rip+__image_start]
        int pnImageStartLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x83, 0x38, 0x04, 0x00, 0x00]); // mov [rbx+0x438], rax
        // mapsize = __image_end - __image_start
        b.AddRange([0x48, 0x8D, 0x0D, 0, 0, 0, 0]);          // lea rcx, [rip+__bss_end] (image_end approx)
        int pnImageEndLeaAt = b.Count - 4;
        b.AddRange([0x48, 0x29, 0xC1]);                       // sub rcx, rax
        b.AddRange([0x48, 0x89, 0x8B, 0x40, 0x04, 0x00, 0x00]); // mov [rbx+0x440], rcx
        // strcpy(lib->soname, soname)
        b.AddRange([0x4C, 0x8D, 0x63, 0x38]);                 // lea r12, [rbx+0x38]
        b.AddRange([0x4C, 0x89, 0xE7]);                       // mov rdi, r12
        b.AddRange([0x4C, 0x89, 0xF6]);                       // mov rsi, r14
        b.AddRange([0xFF, 0x15, 0, 0, 0, 0]);                 // call [rip+strcpy]
        AddRel(RelocSymbol.RtldStrcpy, b.Count - 4);
        // SYS_thr_set_name(pid, soname, 1024) = syscall 0x268
        b.AddRange([0xBF, 0x68, 0x02, 0x00, 0x00]);           // mov edi, 0x268
        b.AddRange([0x44, 0x89, 0xFE]);                       // mov esi, r15d (pid)
        b.AddRange([0x4C, 0x89, 0xE2]);                       // mov rdx, r12 (soname buf)
        b.AddRange([0xB9, 0x00, 0x04, 0x00, 0x00]);           // mov ecx, 1024
        b.AddRange([0x31, 0xC0]);                             // xor eax, eax
        b.AddRange([0x41, 0xFF, 0xD5]);                       // call r13
        // return lib
        b.AddRange([0x48, 0x89, 0xD8]);                       // mov rax, rbx
        // epilogue
        b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);
        _payloadNewBytes = b.Count - payloadNewOff;

        // Store payload vtable function offsets for the patching section
        _payloadCloseOff = payloadCloseOff; _payloadDestroyOff = payloadDestroyOff;
        _payloadInitVtableOff = payloadInitVtableOff; _payloadFiniVtableOff = payloadFiniVtableOff;
        _payloadSym2addrOff = payloadSym2addrOff; _payloadAddr2symOff = payloadAddr2symOff;
        _payloadOpenOff = payloadOpenOff; _payloadNewOff = payloadNewOff;

        _dlerrorOff = dlerrorOff; _dlfcnSetrootOff = dlfcnSetrootOff;
        _libDestroyOff = libDestroyOff; _libSym2addrOff = libSym2addrOff;
        _libOpenOff = libOpenOff; _libFiniOff = libFiniOff;
        _libSym2libOff = libSym2libOff; _libAppendDepOff = libAppendDepOff;
        _libSoname2libOff = libSoname2libOff; _libInitOff = libInitOff;
        _libAddr2symOff = libAddr2symOff; _libAddr2libOff = libAddr2libOff;
        _libRemoveDepOff = libRemoveDepOff; _findFileOff = findFileOff;
        _libCloseOff = libCloseOff; _libNewOff = libNewOff;
        _sprxInitOff = sprxInitOff; _dlfcnInitOff = dlfcnInitOff;
        _sprxNewOff = sprxNewOff; _soNewOff = soNewOff; _dynlibHandleOff = dynlibHandleOff;
        _soInitOff = soInitOff; _soRGlobDatOff = soRGlobDatOff;
        _payloadInitFnOff = payloadInitOff;
        _dlsymOff = dlsymOff; _dlcloseOff = dlcloseOff; _dlopenOff = dlopenOff;

        // ============================================================================
        // Patch every intra-section disp32 (calls between CRT routines).
        // ============================================================================
        void WriteDispFrom(int at, int target)
        {
            int disp = target - (at + 4);
            b[at + 0] = (byte)(disp & 0xFF);
            b[at + 1] = (byte)((disp >> 8) & 0xFF);
            b[at + 2] = (byte)((disp >> 16) & 0xFF);
            b[at + 3] = (byte)((disp >> 24) & 0xFF);
        }
        // _start intra-section calls (CRT orchestrator)
        WriteDispFrom(startCallSyscallInitDisp, crtSyscallInitOff);
        WriteDispFrom(saveFsbaseSyscallCallDisp, crtSyscallOff);
        WriteDispFrom(tcbSetSyscallCallDisp, crtSyscallOff);
        WriteDispFrom(restoreFsbaseSyscallCallDisp, crtSyscallOff);
        WriteDispFrom(thrExitSyscallCallDisp, crtSyscallOff);
        WriteDispFrom(startCallKernelInitDisp, kernelInitOff);
        WriteDispFrom(startCallKlogInitDisp, klogInitOff);
        WriteDispFrom(isthreadedDlsymDisp, kernelDynlibDlsymOff);
        WriteDispFrom(isthreadedFailKlogDisp, klogOff);
        WriteDispFrom(startPthreadSelfDlsym1Disp, kernelDynlibDlsymOff);
        WriteDispFrom(startPthreadSelfDlsym2Disp, kernelDynlibDlsymOff);
        // WriteDispTo(startPthreadSelfNameLea{1,2}At, pthreadSelfOff) deferred: pthreadSelfOff is
        // emitted later in the rodata block; the pair is patched immediately after.
        WriteDispFrom(startCallPatchInitDisp, patchInitOff);
        WriteDispFrom(patchFailKlogDisp, klogOff);
        WriteDispFrom(startCallRtldInitDisp, rtldInitOff);
        WriteDispFrom(rtldFailKlogDisp, klogOff);
        // _start diagnostic breadcrumb klog calls
        if (EmitDiagnosticBreadcrumbs)
        {
            WriteDispFrom(bcTcbSetCallDisp, klogOff);
            WriteDispFrom(bcCrtEnterCallDisp, klogOff);
            WriteDispFrom(bcInitSyscallCallDisp, klogOff);
            WriteDispFrom(bcInitKernelCallDisp, klogOff);
            WriteDispFrom(bcKernelInitOkCallDisp, klogOff);
            WriteDispFrom(bcInitKlogCallDisp, klogOff);
            WriteDispFrom(bcInitPatchCallDisp, klogOff);
            WriteDispFrom(bcInitRtldCallDisp, klogOff);
            WriteDispFrom(bcInitDoneCallDisp, klogOff);
            WriteDispFrom(bcMainEnterCallDisp, klogOff);
            // CRT orchestrator checkpoint klog calls
            WriteDispFrom(bcIsthreadedOkCallDisp, klogOff);
            WriteDispFrom(bcIsthreadedFailCallDisp, klogOff);
            WriteDispFrom(bcPayloadRunEnterCallDisp, klogOff);
            WriteDispFrom(bcMainExitCallDisp, klogOff);
            WriteDispFrom(bcPayloadTerminateCallDisp, klogOff);
            // RTLD subsystem init checkpoint klog calls
            WriteDispFrom(bcRtldSprxInitCallDisp, klogOff);
            WriteDispFrom(bcRtldSoInitCallDisp, klogOff);
            WriteDispFrom(bcRtldPayloadInitStartCallDisp, klogOff);
            WriteDispFrom(bcRtldPayloadInitDoneCallDisp, klogOff);
            WriteDispFrom(bcRtldDlfcnInitCallDisp, klogOff);
            // fixup_got sp:fixup:done klog call
            WriteDispFrom(fxKlogDoneCallDisp, klogOff);
        }
        WriteDispFrom(getargcDlsymDisp1, kernelDynlibDlsymOff);
        WriteDispFrom(getargcDlsymDisp2, kernelDynlibDlsymOff);
        WriteDispFrom(getargvDlsymDisp1, kernelDynlibDlsymOff);
        WriteDispFrom(getargvDlsymDisp2, kernelDynlibDlsymOff);
        WriteDispFrom(environDlsymDisp1, kernelDynlibDlsymOff);
        WriteDispFrom(environDlsymDisp2, kernelDynlibDlsymOff);
        WriteDispFrom(prognameDlsymDisp1, kernelDynlibDlsymOff);
        WriteDispFrom(prognameDlsymDisp2, kernelDynlibDlsymOff);
        WriteDispFrom(payloadNewCallDisp, payloadNewOff);
        WriteDispFrom(dlfcnSetrootCallDisp, dlfcnSetrootOff);
        WriteDispFrom(libOpenCallDisp, libOpenOff);
        WriteDispFrom(libInitCallDisp, libInitOff);
        WriteDispFrom(libFiniCallDisp, libFiniOff);
        WriteDispFrom(libCloseCallDisp, libCloseOff);
        WriteDispFrom(libCloseCallDisp2, libCloseOff);
        WriteDispFrom(libDestroyCallDisp, libDestroyOff);
        WriteDispFrom(libDestroyCallDisp2, libDestroyOff);
        // fixup_got intra-section calls
        WriteDispFrom(fxKlogMissCallDisp, klogOff);
        if (EmitDiagnosticBreadcrumbs)
        {
            WriteDispFrom(fxKlogStartCallDisp, klogOff);
            WriteDispFrom(fxKlogNameCallDisp, klogOff);
            WriteDispFrom(fxKlogResolvedCallDisp, klogOff);
        }
        // kernel_write calls __sp_crt_syscall
        WriteDispFrom(kwCall1Disp, crtSyscallOff);
        WriteDispFrom(kwCall2Disp, crtSyscallOff);
        // kernel_copyin calls __sp_kernel_write and __sp_crt_syscall
        WriteDispFrom(ciKw1Disp, kernelWriteOff);
        WriteDispFrom(ciKw2Disp, kernelWriteOff);
        WriteDispFrom(ciSyscallDisp, crtSyscallOff);
        // kernel_copyout calls __sp_kernel_write and __sp_crt_syscall
        WriteDispFrom(coKw1Disp, kernelWriteOff);
        WriteDispFrom(coKw2Disp, kernelWriteOff);
        WriteDispFrom(coSyscallDisp, crtSyscallOff);
        // nid_encode calls sha1_transform
        WriteDispFrom(nidCallTransform1, sha1TransformOff);
        WriteDispFrom(nidCallTransform2, sha1TransformOff);
        WriteDispFrom(nidCallTransform3, sha1TransformOff);
        WriteDispFrom(nidCallTransform4, sha1TransformOff);
        // kernel_get_proc calls crt_syscall and kernel_copyout
        WriteDispFrom(gprSyscallCall, crtSyscallOff);
        WriteDispFrom(gprCopyout1, kernelCopyoutOff);
        WriteDispFrom(gprCopyout2, kernelCopyoutOff);
        WriteDispFrom(gprCopyout3, kernelCopyoutOff);
        // kernel_find_proc_by_comm calls kernel_copyout
        WriteDispFrom(fpbcCopyout1, kernelCopyoutOff);
        WriteDispFrom(fpbcCopyout2, kernelCopyoutOff);
        WriteDispFrom(fpbcCopyout3, kernelCopyoutOff);
        // kernel_dynlib_obj calls kernel_get_proc and kernel_copyout
        WriteDispFrom(dobjGetProc, kernelGetProcOff);
        WriteDispFrom(dobjCopyout1, kernelCopyoutOff);
        WriteDispFrom(dobjCopyout2, kernelCopyoutOff);
        WriteDispFrom(dobjCopyout3, kernelCopyoutOff);
        WriteDispFrom(dobjCopyout4, kernelCopyoutOff);
        // kernel_dynlib_resolve calls kernel_dynlib_obj, kernel_copyout, crt_syscall
        WriteDispFrom(drsvDynlibObj, kernelDynlibObjOff);
        WriteDispFrom(drsvCopyoutMeta, kernelCopyoutOff);
        WriteDispFrom(drsvCopyoutSym, kernelCopyoutOff);
        WriteDispFrom(drsvCopyoutStr, kernelCopyoutOff);
        WriteDispFrom(drsvMmapCall, crtSyscallOff);
        WriteDispFrom(drsvMunmapCall, crtSyscallOff);
        // kernel_dynlib_dlsym calls nid_encode (with addr32 prefix) and kernel_dynlib_resolve
        WriteDispFrom(ddlsymNidCall, nidEncodeOff);
        WriteDispFrom(ddlsymResolveCall, kernelDynlibResolveOff);
        // kernel_dynlib_resolve breadcrumb klog calls
        if (EmitDiagnosticBreadcrumbs)
            WriteDispFrom(drsvObjOkKlogCall, klogOff);
        WriteDispFrom(drsvSymMissKlogCall, klogOff);
        WriteDispFrom(drsvCopyFailKlogCall, klogOff);
        WriteDispFrom(drsvObjFailKlogCall, klogOff);
        WriteDispFrom(drsvMetaFailKlogCall, klogOff);
        WriteDispFrom(drsvMmapFailKlogCall, klogOff);
        // kernel_dynlib_obj: SDK-exact version uses __error BSS, no klog calls
        // kernel_get_proc breadcrumb klog calls
        WriteDispFrom(gprPidMissKlogCall, klogOff);
        WriteDispFrom(gprAllprocFailKlogCall, klogOff);
        // kernel_init FW detection calls crt_syscall, R/W probe calls kernel_copyout
        WriteDispFrom(kiFwSyscallDisp, crtSyscallOff);
        WriteDispFrom(kiProbeCallDisp, kernelCopyoutOff);
        // patch_init calls crt_syscall, kernel_get_proc, kernel_copyout, kernel_copyin
        WriteDispFrom(piGetpidDisp, crtSyscallOff);
        WriteDispFrom(piGetProcDisp, kernelGetProcOff);
        WriteDispFrom(piCopyout1Disp, kernelCopyoutOff);
        WriteDispFrom(piCopyout2Disp, kernelCopyoutOff);
        WriteDispFrom(piCopyout3Disp, kernelCopyoutOff);
        WriteDispFrom(piCopyout4Disp, kernelCopyoutOff);
        WriteDispFrom(piCopyin1Disp, kernelCopyinOff);
        WriteDispFrom(piCopyin2Disp, kernelCopyinOff);
        WriteDispFrom(piCopyin3Disp, kernelCopyinOff);
        WriteDispFrom(piCopyin4Disp, kernelCopyinOff);
        // klog_init calls kernel_dynlib_dlsym
        WriteDispFrom(klSnprintfCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(klStrerrorCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(klVsnprintfCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(klErrorCallDisp1, kernelDynlibDlsymOff);
        WriteDispFrom(klErrorCallDisp2, kernelDynlibDlsymOff);
        // klog_puts calls crt_syscall
        WriteDispFrom(kpGetpidDisp, crtSyscallOff);
        WriteDispFrom(kpThrNameDisp, crtSyscallOff);
        WriteDispFrom(kpKexecDisp, crtSyscallOff);
        // klog_perror calls crt_syscall
        WriteDispFrom(keGetpidDisp, crtSyscallOff);
        WriteDispFrom(keThrNameDisp, crtSyscallOff);
        WriteDispFrom(keKexecDisp, crtSyscallOff);
        // klog_printf calls crt_syscall
        WriteDispFrom(kfGetpidDisp, crtSyscallOff);
        WriteDispFrom(kfThrNameDisp, crtSyscallOff);
        WriteDispFrom(kfKexecDisp, crtSyscallOff);
        // rtld_init calls kernel_dynlib_dlsym
        foreach (int cd in rtldCallDisps) WriteDispFrom(cd, kernelDynlibDlsymOff);
        // fixup_got calls kernel_dynlib_dlsym
        WriteDispFrom(fxDlsymCall1, kernelDynlibDlsymOff);
        WriteDispFrom(fxDlsymCall2, kernelDynlibDlsymOff);
        WriteDispFrom(fxDlsymCall3, kernelDynlibDlsymOff);
        // dlfcn intra-section call patches
        WriteDispFrom(libFiniSelfCallDisp, libFiniOff);
        WriteDispFrom(libSym2libSelfCallDisp, libSym2libOff);
        WriteDispFrom(libAddr2libSelfCallDisp, libAddr2libOff);
        WriteDispFrom(libSoname2libSelfCallDisp, libSoname2libOff);
        WriteDispFrom(libInitSelfCallDisp, libInitOff);
        WriteDispFrom(libCloseSelfCallDisp, libCloseOff);
        WriteDispFrom(refCloseJmpDisp, libCloseOff);
        // lib_new intra-section calls
        WriteDispFrom(libNewFindFileDisp, findFileOff);
        WriteDispFrom(libNewSoname2libDisp, libSoname2libOff);
        WriteDispFrom(libNewSoNewDisp, soNewOff);
        WriteDispFrom(libNewSprxNewDisp, sprxNewOff);
        // find_file calls crt_syscall
        WriteDispFrom(ffStatCall1, crtSyscallOff);
        WriteDispFrom(ffRandpathCall, crtSyscallOff);
        WriteDispFrom(ffGetcwdCall, crtSyscallOff);
        foreach (int d in ffStatDisps) WriteDispFrom(d, crtSyscallOff);
        foreach (int d in ffRandStatDisps) WriteDispFrom(d, crtSyscallOff);
        WriteDispFrom(ffHomebrewStatDisp, crtSyscallOff);
        WriteDispFrom(ffCwdStatDisp, crtSyscallOff);
        // sprx_init intra-section calls
        WriteDispFrom(siProbeCallDisp, kernelDynlibDlsymOff);
        foreach (int cd in siCallDisps) WriteDispFrom(cd, kernelDynlibDlsymOff);
        WriteDispFrom(siDynlibHandleCallDisp, dynlibHandleOff);
        // kernel_dynlib_handle calls kernel_get_proc and kernel_copyout (6x)
        WriteDispFrom(dhGetProcCallDisp, kernelGetProcOff);
        WriteDispFrom(dhCopyout1Disp, kernelCopyoutOff);
        WriteDispFrom(dhCopyout2Disp, kernelCopyoutOff);
        WriteDispFrom(dhCopyout3Disp, kernelCopyoutOff);
        WriteDispFrom(dhCopyout4Disp, kernelCopyoutOff);
        WriteDispFrom(dhCopyout5Disp, kernelCopyoutOff);
        WriteDispFrom(dhCopyout6Disp, kernelCopyoutOff);
        WriteDispFrom(siSysmodResolveCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diCallocCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diFreeCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diStrerrorCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diGetargcCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diGetargcFbCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diGetargvCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diGetargvFbCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diEnvironCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(diEnvironFbCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(dlsymSym2libCallDisp, libSym2libOff);
        WriteDispFrom(dlsymSym2addrCallDisp, libSym2addrOff);
        WriteDispFrom(dlcloseFiniCallDisp, libFiniOff);
        WriteDispFrom(dlcloseCloseCallDisp, libCloseOff);
        WriteDispFrom(dlcloseDestroyCallDisp, libDestroyOff);
        WriteDispFrom(dlopenLibNewCallDisp, libNewOff);
        WriteDispFrom(dlopenLibOpenCallDisp, libOpenOff);
        WriteDispFrom(dlopenDestroyCallDisp, libDestroyOff);
        WriteDispFrom(dlopenAppendDepCallDisp, libAppendDepOff);
        WriteDispFrom(dlopenInitCallDisp, libInitOff);
        // addr2lib self-recursive call
        WriteDispFrom(libAddr2libSelfCallDisp, libAddr2libOff);
        // payload_open intra-section calls
        WriteDispFrom(poLibNewCallDisp, libNewOff);
        WriteDispFrom(poLibOpenCallDisp, libOpenOff);
        WriteDispFrom(poAppendDepCallDisp, libAppendDepOff);
        WriteDispFrom(poDestroyCallDisp, libDestroyOff);
        WriteDispFrom(poSym2libCallDisp, libSym2libOff);
        WriteDispFrom(poSym2addrCallDisp, libSym2addrOff);
        WriteDispFrom(poD64Sym2libCallDisp, libSym2libOff);
        WriteDispFrom(poD64Sym2addrCallDisp, libSym2addrOff);
        WriteDispFrom(poLoadFailKlogDisp, klogOff);
        WriteDispFrom(poRelocUnsupKlogDisp, klogOff);
        WriteDispFrom(poUnresolvedNameKlogDisp, klogOff);
        WriteDispFrom(poResolveMissKlogDisp, klogOff);
        // The fallback cascade is no longer needed because rtld_sprx_new +
        // sprx_open + sprx_sym2addr now populate every SPRX lib node with a
        // functional sym2addr that walks the kernel-copyout'd symtab/strtab.
        // sprx_sym2addr calls nid_encode (direct)
        WriteDispFrom(s2aNidEncodeCallDisp, nidEncodeOff);
        // sprx_open calls (direct): kernel_dynlib_handle, __rtld_find_file,
        // klog_printf, kernel_dynlib_dlsym, kernel_dynlib_obj,
        // kernel_copyout x4, klog_puts, klog_perror
        WriteDispFrom(sprxoDynlibHandleCallDisp, dynlibHandleOff);
        WriteDispFrom(sprxoFindFileCallDisp, findFileOff);
        WriteDispFrom(sprxoKlogPrintfCallDisp, klogPrintfOff);
        WriteDispFrom(sprxoDlsymCallDisp, kernelDynlibDlsymOff);
        WriteDispFrom(soKernelDynlibObjCallDisp, kernelDynlibObjOff);
        WriteDispFrom(soCopyoutPathCallDisp, kernelCopyoutOff);
        WriteDispFrom(soCopyoutMetaCallDisp, kernelCopyoutOff);
        WriteDispFrom(soCopyoutStrtabCallDisp, kernelCopyoutOff);
        WriteDispFrom(soCopyoutSymtabCallDisp, kernelCopyoutOff);
        WriteDispFrom(sprxoKlogPutsCallDisp, klogPutsOff);
        WriteDispFrom(sprxoKlogPerrorCallDisp, klogPerrorOff);
        // __dladdr intra-section calls
        WriteDispFrom(dladdrAddr2libDisp, libAddr2libOff);
        WriteDispFrom(dladdrAddr2symDisp, libAddr2symOff);
        WriteDispFrom(dladdrSym2addrDisp, libSym2addrOff);
        // __rtld_so_init calls kernel_dynlib_dlsym
        foreach (int cd in soCallDisps) WriteDispFrom(cd, kernelDynlibDlsymOff);
        // so_r_glob_dat calls sym2lib, sym2addr, klog
        WriteDispFrom(sgSym2libCall1, libSym2libOff);
        WriteDispFrom(sgSym2addrCall1, libSym2addrOff);
        WriteDispFrom(sgSym2libCall2, libSym2libOff);
        WriteDispFrom(sgSym2addrCall2, libSym2addrOff);
        WriteDispFrom(sgKlogNameCall, klogOff);
        WriteDispFrom(sgKlogMsgCall, klogOff);
        // so_open cross-call dispatches
        WriteDispFrom(soOpenFindFileDisp, findFileOff);
        WriteDispFrom(soOpenKlogPerror1, klogPerrorOff);
        WriteDispFrom(soOpenKlogPerror2, klogPerrorOff);
        WriteDispFrom(soOpenKlogPerror3, klogPerrorOff);
        WriteDispFrom(soOpenKlogPerror4, klogPerrorOff);
        WriteDispFrom(soOpenKlogPerror5, klogPerrorOff);
        WriteDispFrom(soOpenKlogPrintf1, klogPrintfOff);
        WriteDispFrom(soOpenKlogPrintf2, klogPrintfOff);
        WriteDispFrom(soOpenKlogPrintf3, klogPrintfOff);
        WriteDispFrom(soOpenKlogPrintf4, klogPrintfOff);
        WriteDispFrom(soOpenLibDestroy1, libDestroyOff);
        WriteDispFrom(soOpenLibNew1, libNewOff);
        WriteDispFrom(soOpenLibOpen1, libOpenOff);
        WriteDispFrom(soOpenLibAppendDep1, libAppendDepOff);
        WriteDispFrom(soOpenSym2lib1, libSym2libOff);
        WriteDispFrom(soOpenSym2addr1, libSym2addrOff);
        WriteDispFrom(soOpenSym2lib2, libSym2libOff);
        WriteDispFrom(soOpenSym2addr2, libSym2addrOff);
        WriteDispFrom(soOpenRGlobDat1, soRGlobDatOff);
        WriteDispFrom(soOpenRGlobDat2, soRGlobDatOff);
        // Note: soOpenKernelMprotect1 wired below after mprotectOff is declared
        // __rtld_payload_init calls kernel_dynlib_dlsym
        foreach (int cd in piCallDisps) WriteDispFrom(cd, kernelDynlibDlsymOff);
        // __rtld_init orchestration calls: sprx_init, so_init, payload_init, tail-jmp dlfcn_init
        WriteDispFrom(rtCallSprxInitDisp, sprxInitOff);
        WriteDispFrom(rtCallSoInitDisp, soInitOff);
        WriteDispFrom(rtCallPayloadInitDisp, payloadInitOff);
        WriteDispFrom(rtTailJmpDlfcnInitDisp, dlfcnInitOff);

        // ============================================================================
        // __sp_nop_stub — 3-byte identity stub: push rdi ; pop rax ; ret
        //
        // The GOT fixup installs its runtime address for any GLOB_DAT whose plain name
        // starts with "Rh" (NativeAOT internal helpers like RhpReversePInvoke,
        // RhAllocateNewObject, RhNewString, RhYield). The prefix is two characters:
        // NativeAOT emits both Rhp-prefixed and Rh-only helpers. These symbols exist
        // in the payload .dynsym but no dynamic library exports them; without this
        // fallback every call through the corresponding PLT stub would crash. The stub
        // returns rdi (the first argument) so callers that treat the return value as a
        // callable or a pointer receive a non-zero address instead of 0 — preventing
        // the rip=0 SIGSEGV the old xor-eax stub caused when a NativeAOT helper's
        // return was used as a function pointer.
        // ============================================================================
        int nopStubOff = b.Count;
        b.AddRange([0x57, 0x58, 0xC3]);    // push rdi ; pop rax ; ret
        _nopStubBytes = b.Count - nopStubOff;

        // ============================================================================
        // payload_exit(int code)
        //
        // Stores the exit code in *payloadout, then transfers control back to _start's
        // setjmp point via __builtin_longjmp. The longjmp causes __builtin_setjmp to
        // return 1, which triggers payload_terminate.
        //
        //   mov rax, [rip+payload_args]       // rax = &payload_args
        //   mov rax, [rax+0x28]               // rax = payloadout ptr
        //   mov [rax], edi                    // *payloadout = code
        //   mov rbp, [rip+jmpbuf+0]           // restore rbp
        //   mov rsp, [rip+jmpbuf+16]          // restore rsp
        //   jmp qword [rip+jmpbuf+8]          // jump to longjmp_return
        // ============================================================================
        int payloadExitOff = b.Count;
        _currentRelocs = _startRelocs;
        // mov rax, [rip+payload_args]
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.PayloadArgs, b.Count - 4);
        // mov rax, [rax+0x28]
        b.AddRange([0x48, 0x8B, 0x40, 0x28]);
        // mov [rax], edi
        b.AddRange([0x89, 0x38]);
        // mov rbp, [rip+jmpbuf+0]
        b.AddRange([0x48, 0x8B, 0x2D, 0, 0, 0, 0]);
        _currentRelocs.Add(new Reloc(b.Count - 4, RelocSymbol.Jmpbuf, RPc32, -4));
        // mov rsp, [rip+jmpbuf+16]
        b.AddRange([0x48, 0x8B, 0x25, 0, 0, 0, 0]);
        _currentRelocs.Add(new Reloc(b.Count - 4, RelocSymbol.Jmpbuf, RPc32, 12));
        // jmp qword [rip+jmpbuf+8]
        b.AddRange([0xFF, 0x25, 0, 0, 0, 0]);
        _currentRelocs.Add(new Reloc(b.Count - 4, RelocSymbol.Jmpbuf, RPc32, 4));
        _payloadExitBytes = b.Count - payloadExitOff;

        // ============================================================================
        // kernel.c remaining functions (item 5 port)
        //
        // All functions use the _ucredRelocs list and share a common call pattern:
        //   - Intra-section calls via E8 rel32 (patched by WriteDispFrom at end)
        //   - BSS access via RIP-relative MOV with AddRel()
        //   - ABI: rdi=pid/addr, rsi=val/buf, rdx=len, return in rax
        // ============================================================================
        _currentRelocs = _ucredRelocs;

        // Collect call displacement positions for all kernel.c functions
        var kernelCallDisps = new List<(int at, string target)>();
        void EmitCallGetProc() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "get_proc")); }
        void EmitCallCopyout() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "copyout")); }
        void EmitCallCopyin() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "copyin")); }
        void EmitCallDynlibObj() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "dynlib_obj")); }
        void EmitCallGetProcUcred() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "get_proc_ucred")); }
        void EmitCallGetProcFiledesc() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "get_proc_filedesc")); }
        void EmitCallGetVmemEntry() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "get_vmem_entry")); }
        void EmitCallCrtSyscall() { b.AddRange([0xE8, 0, 0, 0, 0]); kernelCallDisps.Add((b.Count - 4, "crt_syscall")); }

        // ---- kernel_get_proc_ucred (65 bytes) ----
        // unsigned long kernel_get_proc_ucred(int pid)
        // Returns ucred pointer or 0 on failure.
        int getProcUcredOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                   // sub rsp, 0x10
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);      // movq [rbp-8], 0
        EmitCallGetProc();                                        // call kernel_get_proc (rdi = pid)
        b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
        b.AddRange([0x74, 0x00]);                                // je .Lfail
        int gpuFailJump = b.Count - 1;
        b.AddRange([0x48, 0x83, 0xC0, 0x40]);                   // add rax, 0x40 (PROC_P_UCRED)
        b.AddRange([0x48, 0x8D, 0x75, 0xF8]);                   // lea rsi, [rbp-8]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                      // mov edx, 8
        b.AddRange([0x48, 0x89, 0xC7]);                          // mov rdi, rax
        EmitCallCopyout();                                        // call kernel_copyout
        b.AddRange([0x85, 0xC0]);                                // test eax, eax
        b.AddRange([0x75, 0x06]);                                // jne .Lfail
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);                   // mov rax, [rbp-8]
        b.AddRange([0xEB, 0x02]);                                // jmp .Lret
        int gpuFail = b.Count;
        b[gpuFailJump] = (byte)(gpuFail - (gpuFailJump + 1));
        b.AddRange([0x31, 0xC0]);                                // xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);       // add rsp, 0x10 ; pop rbp ; ret
        _kernelGetProcUcredBytes = b.Count - getProcUcredOff;

        // ---- Helper: emit a ucred getter pattern ----
        // Pattern: get_proc_ucred(pid), if 0 fail, add offset, copyout, return value or 0.
        // For 8-byte values (authid, prison): returns unsigned long.
        // For N-byte buffers (caps=16, attrs=32): rsi=output buffer, returns int (0/-1).
        int EmitUcredGetter8(byte ucredOffset)
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x48, 0x83, 0xEC, 0x10]);                   // sub rsp, 0x10
            b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);      // movq [rbp-8], 0
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            b.AddRange([0x48, 0x83, 0xC0, ucredOffset]);            // add rax, ucredOffset
            b.AddRange([0x48, 0x8D, 0x75, 0xF8]);                   // lea rsi, [rbp-8]
            b.AddRange([0xBA, 0x08, 0, 0, 0]);                      // mov edx, 8
            b.AddRange([0x48, 0x89, 0xC7]);                          // mov rdi, rax
            EmitCallCopyout();                                        // call kernel_copyout
            b.AddRange([0x85, 0xC0]);                                // test eax, eax
            b.AddRange([0x75, 0x06]);                                // jne .Lfail
            b.AddRange([0x48, 0x8B, 0x45, 0xF8]);                   // mov rax, [rbp-8]
            b.AddRange([0xEB, 0x02]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0x31, 0xC0]);                                // xor eax, eax
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);       // add rsp, 0x10 ; pop rbp ; ret
            return off;
        }

        // Helper: emit a ucred setter for 8-byte value.
        // int kernel_set_ucred_X(int pid, unsigned long val) -> copyin(&val, ucred+offset, 8)
        int EmitUcredSetter8(byte ucredOffset)
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x48, 0x83, 0xEC, 0x10]);                   // sub rsp, 0x10
            b.AddRange([0x48, 0x89, 0x75, 0xF0]);                   // mov [rbp-0x10], rsi (save val)
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            b.AddRange([0x48, 0x83, 0xC0, ucredOffset]);            // add rax, ucredOffset
            b.AddRange([0x48, 0x89, 0xC6]);                          // mov rsi, rax (kaddr)
            b.AddRange([0x48, 0x8D, 0x7D, 0xF0]);                   // lea rdi, [rbp-0x10] (uaddr = &val)
            b.AddRange([0xBA, 0x08, 0, 0, 0]);                      // mov edx, 8
            EmitCallCopyin();                                         // call kernel_copyin
            b.AddRange([0xF7, 0xD8]);                                // neg eax
            b.AddRange([0x19, 0xC0]);                                // sbb eax, eax
            b.AddRange([0xEB, 0x05]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);             // mov eax, -1
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);       // add rsp, 0x10 ; pop rbp ; ret
            return off;
        }

        // Helper: emit a ucred getter for N-byte buffer.
        // int kernel_get_ucred_X(int pid, void* buf) -> copyout(ucred+offset, buf, size)
        int EmitUcredGetterBuf(byte ucredOffset, byte size)
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x53]);                                      // push rbx
            b.AddRange([0x48, 0x83, 0xEC, 0x08]);                   // sub rsp, 8
            b.AddRange([0x48, 0x89, 0xF3]);                          // mov rbx, rsi (save buf)
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            if (ucredOffset >= 0x80)
                b.AddRange([0x48, 0x05, ucredOffset, 0x00, 0x00, 0x00]); // add rax, ucredOffset (imm32)
            else
                b.AddRange([0x48, 0x83, 0xC0, ucredOffset]);             // add rax, ucredOffset (imm8)
            b.AddRange([0x48, 0x89, 0xDE]);                          // mov rsi, rbx (buf)
            b.AddRange([0xBA, size, 0, 0, 0]);                      // mov edx, size
            b.AddRange([0x48, 0x89, 0xC7]);                          // mov rdi, rax
            EmitCallCopyout();                                        // call kernel_copyout
            b.AddRange([0xF7, 0xD8]);                                // neg eax
            b.AddRange([0x19, 0xC0]);                                // sbb eax, eax
            b.AddRange([0xEB, 0x05]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);             // mov eax, -1
            b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]); // add rsp,8 ; pop rbx ; pop rbp ; ret
            return off;
        }

        // Helper: emit a ucred setter for N-byte buffer.
        // int kernel_set_ucred_X(int pid, const void* buf) -> copyin(buf, ucred+offset, size)
        int EmitUcredSetterBuf(byte ucredOffset, byte size)
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x53]);                                      // push rbx
            b.AddRange([0x48, 0x83, 0xEC, 0x08]);                   // sub rsp, 8
            b.AddRange([0x48, 0x89, 0xF3]);                          // mov rbx, rsi (save buf)
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            if (ucredOffset >= 0x80)
                b.AddRange([0x48, 0x05, ucredOffset, 0x00, 0x00, 0x00]); // add rax, ucredOffset (imm32)
            else
                b.AddRange([0x48, 0x83, 0xC0, ucredOffset]);             // add rax, ucredOffset (imm8)
            b.AddRange([0x48, 0x89, 0xC6]);                          // mov rsi, rax (kaddr)
            b.AddRange([0x48, 0x89, 0xDF]);                          // mov rdi, rbx (uaddr = buf)
            b.AddRange([0xBA, size, 0, 0, 0]);                      // mov edx, size
            EmitCallCopyin();                                         // call kernel_copyin
            b.AddRange([0xF7, 0xD8]);                                // neg eax
            b.AddRange([0x19, 0xC0]);                                // sbb eax, eax
            b.AddRange([0xEB, 0x05]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);             // mov eax, -1
            b.AddRange([0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]); // add rsp,8 ; pop rbx ; pop rbp ; ret
            return off;
        }

        // ---- kernel_get_ucred_authid ----
        int getUcredAuthidOff = EmitUcredGetter8(0x58);
        _kernelGetUcredAuthidBytes = b.Count - getUcredAuthidOff;

        // ---- kernel_set_ucred_authid ----
        int setUcredAuthidOff = EmitUcredSetter8(0x58);
        _kernelSetUcredAuthidBytes = b.Count - setUcredAuthidOff;

        // ---- kernel_get_ucred_caps ----
        int getUcredCapsOff = EmitUcredGetterBuf(0x60, 16);
        _kernelGetUcredCapsBytes = b.Count - getUcredCapsOff;

        // ---- kernel_set_ucred_caps ----
        int setUcredCapsOff = EmitUcredSetterBuf(0x60, 16);
        _kernelSetUcredCapsBytes = b.Count - setUcredCapsOff;

        // ---- kernel_get_ucred_attrs ----
        // SDK source: offset 0x80, size 32 bytes
        int getUcredAttrsOff = EmitUcredGetterBuf(0x80, 32);
        _kernelGetUcredAttrsBytes = b.Count - getUcredAttrsOff;

        // ---- kernel_set_ucred_attrs ----
        int setUcredAttrsOff = EmitUcredSetterBuf(0x80, 32);
        _kernelSetUcredAttrsBytes = b.Count - setUcredAttrsOff;

        // ---- kernel_get_ucred_prison (SDK kernel.c, offset 0x30) ----
        int getUcredPrisonOff = EmitUcredGetter8(0x30);
        _kernelGetUcredPrisonBytes = b.Count - getUcredPrisonOff;

        // ---- kernel_set_ucred_prison (SDK kernel.c, offset 0x30) ----
        int setUcredPrisonOff = EmitUcredSetter8(0x30);
        _kernelSetUcredPrisonBytes = b.Count - setUcredPrisonOff;

        // ---- kernel_get_root_vnode ----
        // unsigned long kernel_get_root_vnode(void) -> copyout(KERNEL_ADDRESS_ROOTVNODE, &vnode, 8)
        int getRootVnodeOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);          // movq [rbp-8], 0
        // mov rdi, [rip+kernel_rootvnode]
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.KernelRootvnode, b.Count - 4);
        b.AddRange([0x48, 0x8D, 0x75, 0xF8]);                       // lea rsi, [rbp-8]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        EmitCallCopyout();                                            // call kernel_copyout
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x75, 0x06]);                                    // jne .Lfail
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);                       // mov rax, [rbp-8]
        b.AddRange([0xEB, 0x02]);                                    // jmp .Lret
        b.AddRange([0x31, 0xC0]);                                    // .Lfail: xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);           // add rsp, 0x10 ; pop rbp ; ret
        _kernelGetRootVnodeBytes = b.Count - getRootVnodeOff;

        // ---- kernel_get_proc_filedesc ----
        // unsigned long kernel_get_proc_filedesc(int pid)
        // Same pattern as kernel_get_proc_ucred but offset 0x48 instead of 0x40.
        int getProcFiledescOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);          // movq [rbp-8], 0
        EmitCallGetProc();                                            // call kernel_get_proc (rdi = pid)
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x00]);                                    // je .Lfail
        int gfdFailJump = b.Count - 1;
        b.AddRange([0x48, 0x83, 0xC0, 0x48]);                       // add rax, 0x48 (PROC_P_FD)
        b.AddRange([0x48, 0x8D, 0x75, 0xF8]);                       // lea rsi, [rbp-8]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax
        EmitCallCopyout();                                            // call kernel_copyout
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x75, 0x06]);                                    // jne .Lfail
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);                       // mov rax, [rbp-8]
        b.AddRange([0xEB, 0x02]);                                    // jmp .Lret
        int gfdFail = b.Count;
        b[gfdFailJump] = (byte)(gfdFail - (gfdFailJump + 1));
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);           // add rsp, 0x10 ; pop rbp ; ret
        _kernelGetProcFiledescBytes = b.Count - getProcFiledescOff;

        // ---- kernel_get_proc_rootdir ----
        // unsigned long kernel_get_proc_rootdir(int pid)
        // Pattern: get_proc_filedesc -> copyout(filedesc+0x10, &vnode, 8)
        int getProcRootdirOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);
        EmitCallGetProcFiledesc();
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int grdFailJump = b.Count - 1;
        b.AddRange([0x48, 0x83, 0xC0, 0x10]);                       // add rax, 0x10 (FD_RDIR)
        b.AddRange([0x48, 0x8D, 0x75, 0xF8]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        b.AddRange([0x48, 0x89, 0xC7]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x06]);
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);
        b.AddRange([0xEB, 0x02]);
        int grdFail = b.Count;
        b[grdFailJump] = (byte)(grdFail - (grdFailJump + 1));
        b.AddRange([0x31, 0xC0]);
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetProcRootdirBytes = b.Count - getProcRootdirOff;

        // ---- kernel_set_proc_rootdir ----
        // int kernel_set_proc_rootdir(int pid, unsigned long vnode)
        int setProcRootdirOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0x89, 0x75, 0xF0]);                       // mov [rbp-0x10], rsi (save vnode)
        EmitCallGetProcFiledesc();
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int srdFailJump = b.Count - 1;
        b.AddRange([0x48, 0x83, 0xC0, 0x10]);                       // add rax, 0x10 (FD_RDIR)
        b.AddRange([0x48, 0x89, 0xC6]);                              // mov rsi, rax (kaddr)
        b.AddRange([0x48, 0x8D, 0x7D, 0xF0]);                       // lea rdi, [rbp-0x10] (uaddr)
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyin();
        b.AddRange([0xF7, 0xD8]);                                    // neg eax
        b.AddRange([0x19, 0xC0]);                                    // sbb eax, eax
        b.AddRange([0xEB, 0x05]);
        int srdFail = b.Count;
        b[srdFailJump] = (byte)(srdFail - (srdFailJump + 1));
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetProcRootdirBytes = b.Count - setProcRootdirOff;

        // ---- kernel_get_proc_jaildir (same pattern, offset 0x18) ----
        int getProcJaildirOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);
        EmitCallGetProcFiledesc();
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int gjdFailJump = b.Count - 1;
        b.AddRange([0x48, 0x83, 0xC0, 0x18]);                       // add rax, 0x18 (FD_JDIR)
        b.AddRange([0x48, 0x8D, 0x75, 0xF8]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        b.AddRange([0x48, 0x89, 0xC7]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x06]);
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);
        b.AddRange([0xEB, 0x02]);
        int gjdFail = b.Count;
        b[gjdFailJump] = (byte)(gjdFail - (gjdFailJump + 1));
        b.AddRange([0x31, 0xC0]);
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetProcJaildirBytes = b.Count - getProcJaildirOff;

        // ---- kernel_set_proc_jaildir (same pattern, offset 0x18) ----
        int setProcJaildirOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0x89, 0x75, 0xF0]);
        EmitCallGetProcFiledesc();
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);
        int sjdFailJump = b.Count - 1;
        b.AddRange([0x48, 0x83, 0xC0, 0x18]);                       // add rax, 0x18 (FD_JDIR)
        b.AddRange([0x48, 0x89, 0xC6]);
        b.AddRange([0x48, 0x8D, 0x7D, 0xF0]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyin();
        b.AddRange([0xF7, 0xD8]);
        b.AddRange([0x19, 0xC0]);
        b.AddRange([0xEB, 0x05]);
        int sjdFail = b.Count;
        b[sjdFailJump] = (byte)(sjdFail - (sjdFailJump + 1));
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetProcJaildirBytes = b.Count - setProcJaildirOff;

        // ---- kernel_dynlib_find_handle (302 bytes, SDK-exact) ----
        // int kernel_dynlib_find_handle(int pid, unsigned long addr, int *handle_out)
        // Walks the kernel dynlib linked list for the process to find which loaded
        // module contains the given address.  For each module entry it reads
        // mapbase (+0x30) and mapsize (+0x38); when addr falls in [mapbase, mapbase+mapsize)
        // it reads the handle at +0x28 and stores it through handle_out.
        // Returns 0 on match, -1 on failure/not-found (with errno = EINVAL on list exhaustion).
        int dynlibFindHandleOff = b.Count;
        // Prologue
        b.AddRange([0x55]);                                          // push rbp
        b.AddRange([0x48, 0x89, 0xE5]);                              // mov rbp, rsp
        b.AddRange([0x41, 0x57]);                                    // push r15
        b.AddRange([0x41, 0x56]);                                    // push r14
        b.AddRange([0x41, 0x55]);                                    // push r13
        b.AddRange([0x41, 0x54]);                                    // push r12
        b.AddRange([0x53]);                                          // push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x28]);                        // sub rsp, 0x28
        // Save args: r14 = handle_out, r15 = target addr
        b.AddRange([0x49, 0x89, 0xD6]);                              // mov r14, rdx
        b.AddRange([0x49, 0x89, 0xF7]);                              // mov r15, rsi
        // kernel_get_proc(pid) -- rdi already has pid
        EmitCallGetProc();                                            // call kernel_get_proc
        b.AddRange([0xBB, 0xFF, 0xFF, 0xFF, 0xFF]);                  // mov ebx, 0xFFFFFFFF (-1)
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x0F, 0x84, 0xF3, 0x00, 0x00, 0x00]);            // je exit (+0xF3)
        // proc + PROC_DYNLIB_HEAD offset (0x3e8) -> head pointer
        b.AddRange([0x48, 0x05, 0xE8, 0x03, 0x00, 0x00]);            // add rax, 0x3e8
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                        // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax
        EmitCallCopyout();                                            // call kernel_copyout (head ptr)
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x0F, 0x88, 0xD4, 0x00, 0x00, 0x00]);            // js exit (+0xD4)
        // Read first entry from head
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                        // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                        // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        EmitCallCopyout();                                            // call kernel_copyout (first entry)
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x0F, 0x88, 0xBA, 0x00, 0x00, 0x00]);            // js exit (+0xBA)
        // Save handle_out to stack, set up loop register pointers
        b.AddRange([0x4C, 0x89, 0x75, 0xC8]);                        // mov [rbp-0x38], r14
        b.AddRange([0x4C, 0x8D, 0x65, 0xB0]);                        // lea r12, [rbp-0x50]
        b.AddRange([0x4C, 0x8D, 0x6D, 0xB8]);                        // lea r13, [rbp-0x48]
        b.AddRange([0x4C, 0x8D, 0x75, 0xD0]);                        // lea r14, [rbp-0x30]
        b.AddRange([0xEB, 0x24]);                                    // jmp loopCondition (+0x24)
        // NOP alignment padding (11 bytes)
        b.AddRange([0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00,
                     0x00, 0x00, 0x00, 0x00]);
        // loopNext: follow linked list to next entry
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                        // mov rdi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        b.AddRange([0x4C, 0x89, 0xF6]);                              // mov rsi, r14
        EmitCallCopyout();                                            // call kernel_copyout (next entry)
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x0F, 0x88, 0x84, 0x00, 0x00, 0x00]);            // js exit (+0x84)
        // loopCondition: check if current entry is NULL
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                        // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x85, 0xFF]);                              // test rdi, rdi
        b.AddRange([0x74, 0x67]);                                    // je errnoPath (+0x67)
        // Read mapbase at entry + 0x30
        b.AddRange([0x48, 0x83, 0xC7, 0x30]);                        // add rdi, 0x30
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        b.AddRange([0x4C, 0x89, 0xE6]);                              // mov rsi, r12
        EmitCallCopyout();                                            // call kernel_copyout (mapbase)
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x78, 0x66]);                                    // js exit (+0x66)
        // Read mapsize at entry + 0x38
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                        // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x83, 0xC7, 0x38]);                        // add rdi, 0x38
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        b.AddRange([0x4C, 0x89, 0xEE]);                              // mov rsi, r13
        EmitCallCopyout();                                            // call kernel_copyout (mapsize)
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x78, 0x4D]);                                    // js exit (+0x4D)
        // Check if addr falls in [mapbase, mapbase+mapsize)
        b.AddRange([0x48, 0x8B, 0x45, 0xB0]);                        // mov rax, [rbp-0x50] (mapbase)
        b.AddRange([0x4C, 0x39, 0xF8]);                              // cmp rax, r15
        b.AddRange([0x77, 0xA7]);                                    // ja loopNext (-0x59)
        b.AddRange([0x48, 0x03, 0x45, 0xB8]);                        // add rax, [rbp-0x48] (mapsize)
        b.AddRange([0x4C, 0x39, 0xF8]);                              // cmp rax, r15
        b.AddRange([0x72, 0x9E]);                                    // jb loopNext (-0x62)
        // Found: read handle at entry + 0x28
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0]);                        // mov rdi, [rbp-0x30]
        b.AddRange([0x48, 0x83, 0xC7, 0x28]);                        // add rdi, 0x28
        b.AddRange([0x48, 0x8D, 0x75, 0xC0]);                        // lea rsi, [rbp-0x40]
        b.AddRange([0xBA, 0x08, 0x00, 0x00, 0x00]);                  // mov edx, 8
        EmitCallCopyout();                                            // call kernel_copyout (handle)
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x78, 0x21]);                                    // js exit (+0x21)
        // Store handle to *handle_out
        b.AddRange([0x8B, 0x45, 0xC0]);                              // mov eax, [rbp-0x40]
        b.AddRange([0x48, 0x8B, 0x4D, 0xC8]);                        // mov rcx, [rbp-0x38]
        b.AddRange([0x89, 0x01]);                                    // mov [rcx], eax
        b.AddRange([0x31, 0xDB]);                                    // xor ebx, ebx (return 0)
        b.AddRange([0xEB, 0x14]);                                    // jmp exit (+0x14)
        // errnoPath: list exhausted, set errno = EINVAL (0x16)
        b.AddRange([0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00]);      // mov rax, [rip+__error]
        AddRel(RelocSymbol.KlogError, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x08]);                                    // je exit (+0x08)
        b.AddRange([0xFF, 0xD0]);                                    // call *rax
        b.AddRange([0xC7, 0x00, 0x16, 0x00, 0x00, 0x00]);            // movl $0x16, (%rax) (EINVAL)
        // exit:
        b.AddRange([0x89, 0xD8]);                                    // mov eax, ebx
        b.AddRange([0x48, 0x83, 0xC4, 0x28]);                        // add rsp, 0x28
        b.AddRange([0x5B]);                                          // pop rbx
        b.AddRange([0x41, 0x5C]);                                    // pop r12
        b.AddRange([0x41, 0x5D]);                                    // pop r13
        b.AddRange([0x41, 0x5E]);                                    // pop r14
        b.AddRange([0x41, 0x5F]);                                    // pop r15
        b.AddRange([0x5D]);                                          // pop rbp
        b.AddRange([0xC3]);                                          // ret
        _kernelDynlibFindHandleBytes = b.Count - dynlibFindHandleOff;

        // ---- kernel_dynlib_mapbase_addr (SDK-exact 47 bytes / 0x2F) ----
        // unsigned long kernel_dynlib_mapbase_addr(int pid, unsigned int handle)
        // Pattern: push rbp; sub rsp,0x180; call dynlib_obj; extract field; ret.
        // Field offset: mapbase is at dynlib_obj+0x30 → rbp-0x180+0x30 = rbp-0x150.
        int dynlibMapbaseOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x81, 0xEC, 0x80, 0x01, 0x00, 0x00]);            // sub rsp, 0x180
        b.AddRange([0x48, 0x8D, 0x95, 0x80, 0xFE, 0xFF, 0xFF]);            // lea rdx, [rbp-0x180]
        EmitCallDynlibObj();                                                 // call kernel_dynlib_obj
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x75, 0x09]);                                           // jne .Lzero (+9)
        b.AddRange([0x48, 0x8B, 0x85, 0xB0, 0xFE, 0xFF, 0xFF]);            // mov rax, [rbp-0x150]
        b.AddRange([0xEB, 0x02]);                                           // jmp .Lret (+2)
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x48, 0x81, 0xC4, 0x80, 0x01, 0x00, 0x00]);            // add rsp, 0x180
        b.AddRange([0x5D, 0xC3]);                                           // pop rbp ; ret
        _kernelDynlibMapbaseBytes = b.Count - dynlibMapbaseOff;

        // ---- kernel_dynlib_fini_addr (SDK-exact 47 bytes / 0x2F) ----
        // Field offset: fini is at dynlib_obj+0xF0 → rbp-0x180+0xF0 = rbp-0x90.
        int dynlibFiniAddrOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x81, 0xEC, 0x80, 0x01, 0x00, 0x00]);            // sub rsp, 0x180
        b.AddRange([0x48, 0x8D, 0x95, 0x80, 0xFE, 0xFF, 0xFF]);            // lea rdx, [rbp-0x180]
        EmitCallDynlibObj();                                                 // call kernel_dynlib_obj
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x75, 0x09]);                                           // jne .Lzero (+9)
        b.AddRange([0x48, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF]);            // mov rax, [rbp-0x90]
        b.AddRange([0xEB, 0x02]);                                           // jmp .Lret (+2)
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x48, 0x81, 0xC4, 0x80, 0x01, 0x00, 0x00]);            // add rsp, 0x180
        b.AddRange([0x5D, 0xC3]);                                           // pop rbp ; ret
        _kernelDynlibFiniAddrBytes = b.Count - dynlibFiniAddrOff;

        // ---- kernel_dynlib_init_addr (SDK-exact 47 bytes / 0x2F) ----
        // Field offset: init is at dynlib_obj+0xE8 → rbp-0x180+0xE8 = rbp-0x98.
        int dynlibInitAddrOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x81, 0xEC, 0x80, 0x01, 0x00, 0x00]);            // sub rsp, 0x180
        b.AddRange([0x48, 0x8D, 0x95, 0x80, 0xFE, 0xFF, 0xFF]);            // lea rdx, [rbp-0x180]
        EmitCallDynlibObj();                                                 // call kernel_dynlib_obj
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x75, 0x09]);                                           // jne .Lzero (+9)
        b.AddRange([0x48, 0x8B, 0x85, 0x68, 0xFF, 0xFF, 0xFF]);            // mov rax, [rbp-0x98]
        b.AddRange([0xEB, 0x02]);                                           // jmp .Lret (+2)
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x48, 0x81, 0xC4, 0x80, 0x01, 0x00, 0x00]);            // add rsp, 0x180
        b.AddRange([0x5D, 0xC3]);                                           // pop rbp ; ret
        _kernelDynlibInitAddrBytes = b.Count - dynlibInitAddrOff;

        // ---- kernel_dynlib_entry_addr (SDK-exact 47 bytes / 0x2F) ----
        // Field offset: entry is at dynlib_obj+0x68 → rbp-0x180+0x68 = rbp-0x118.
        int dynlibEntryAddrOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x81, 0xEC, 0x80, 0x01, 0x00, 0x00]);            // sub rsp, 0x180
        b.AddRange([0x48, 0x8D, 0x95, 0x80, 0xFE, 0xFF, 0xFF]);            // lea rdx, [rbp-0x180]
        EmitCallDynlibObj();                                                 // call kernel_dynlib_obj
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x75, 0x09]);                                           // jne .Lzero (+9)
        b.AddRange([0x48, 0x8B, 0x85, 0xE8, 0xFE, 0xFF, 0xFF]);            // mov rax, [rbp-0x118]
        b.AddRange([0xEB, 0x02]);                                           // jmp .Lret (+2)
        b.AddRange([0x31, 0xC0]);                                           // xor eax, eax
        b.AddRange([0x48, 0x81, 0xC4, 0x80, 0x01, 0x00, 0x00]);            // add rsp, 0x180
        b.AddRange([0x5D, 0xC3]);                                           // pop rbp ; ret
        _kernelDynlibEntryAddrBytes = b.Count - dynlibEntryAddrOff;

        // ---- kernel_dynlib_path (SDK-exact 106 bytes / 0x6A) ----
        // int kernel_dynlib_path(int pid, unsigned int handle, char* path, unsigned long size)
        // SDK layout: push rbp..push rbx, sub rsp 0x188, clamp size via cmovb,
        //   call dynlib_obj, copyout path, NUL-terminate, return 0/-1.
        //   path_kaddr is at dynlib_obj+0x08 → rbp-0x198+0x08 = rbp-0x190.
        int dynlibPathOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                              // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x53]);                        // push r15 ; push r14 ; push rbx
        b.AddRange([0x48, 0x81, 0xEC, 0x88, 0x01, 0x00, 0x00]);            // sub rsp, 0x188
        b.AddRange([0x48, 0x89, 0xD3]);                                    // mov rbx, rdx (path buf)
        // Clamp: r14 = min(rcx, 0x400) via cmovb
        b.AddRange([0x48, 0x81, 0xF9, 0x00, 0x04, 0x00, 0x00]);            // cmp rcx, 0x400
        b.AddRange([0x41, 0xBE, 0x00, 0x04, 0x00, 0x00]);                  // mov r14d, 0x400
        b.AddRange([0x4C, 0x0F, 0x42, 0xF1]);                              // cmovb r14, rcx
        // Buffer at rbp-0x198 (stack after 3 pushes + 0x188 sub)
        b.AddRange([0x48, 0x8D, 0x95, 0x68, 0xFE, 0xFF, 0xFF]);            // lea rdx, [rbp-0x198]
        EmitCallDynlibObj();                                                 // call kernel_dynlib_obj
        b.AddRange([0x41, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF]);                  // mov r15d, -1
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x75, 0x1F]);                                           // jne .Lret (+31)
        // path_kaddr at dynlib_obj+0x08 → rbp-0x198+0x08 = rbp-0x190
        b.AddRange([0x48, 0x8B, 0xBD, 0x70, 0xFE, 0xFF, 0xFF]);            // mov rdi, [rbp-0x190]
        b.AddRange([0x48, 0x89, 0xDE]);                                    // mov rsi, rbx
        b.AddRange([0x4C, 0x89, 0xF2]);                                    // mov rdx, r14
        EmitCallCopyout();                                                   // call kernel_copyout
        b.AddRange([0x85, 0xC0]);                                           // test eax, eax
        b.AddRange([0x78, 0x09]);                                           // js .Lret (+9)
        b.AddRange([0x42, 0xC6, 0x44, 0x33, 0xFF, 0x00]);                  // movb $0, -1(%rbx,%r14,1)
        b.AddRange([0x45, 0x31, 0xFF]);                                    // xor r15d, r15d
        // .Lret:
        b.AddRange([0x44, 0x89, 0xF8]);                                    // mov eax, r15d
        b.AddRange([0x48, 0x81, 0xC4, 0x88, 0x01, 0x00, 0x00]);            // add rsp, 0x188
        b.AddRange([0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);            // pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
        _kernelDynlibPathBytes = b.Count - dynlibPathOff;

        // ---- kernel_mprotect ----
        // int kernel_mprotect(int pid, unsigned long addr, unsigned long len, int prot)
        // Tail-call to kernel_set_vmem_protection.
        int mprotectOff = b.Count;
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp kernel_set_vmem_protection
        kernelCallDisps.Add((b.Count - 4, "set_vmem_protection"));
        _kernelMprotectBytes = b.Count - mprotectOff;
        // Deferred so_open wiring (mprotectOff now available)
        WriteDispFrom(soOpenKernelMprotect1, mprotectOff);

        // ---- kernel_get_vmem_entry ----
        // unsigned long kernel_get_vmem_entry(int pid, unsigned long addr)
        // Binary tree walk: left at +0x10, right at +0x18, start at +0x20, end at +0x28
        int getVmemEntryOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x53]);                 // push r15 ; push r14 ; push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x38]);                       // sub rsp, 0x38
        b.AddRange([0x49, 0x89, 0xF7]);                              // mov r15, rsi (addr)
        // Get proc
        EmitCallGetProc();                                            // call kernel_get_proc(pid)
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lfail
        int gveFailJump1 = b.Count - 4;
        // copyout(proc + PROC_P_VMSPACE, &vmspace, 8)
        b.AddRange([0x48, 0x05, 0x00, 0x02, 0x00, 0x00]);           // add rax, 0x200 (PROC_P_VMSPACE)
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax
        b.AddRange([0x48, 0x8D, 0x75, 0xD8]);                       // lea rsi, [rbp-0x28]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int gveFailJump2 = b.Count - 4;
        // copyout(vmspace + VMSPACE_P_ROOT, &vm_map_entry, 8)
        b.AddRange([0x48, 0x8B, 0x45, 0xD8]);                       // mov rax, [rbp-0x28] (vmspace)
        // add rax, [rip+vmspace_p_root]
        b.AddRange([0x48, 0x03, 0x05, 0, 0, 0, 0]);
        AddRel(RelocSymbol.KernelVmspacePRoot, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);                       // lea rsi, [rbp-0x20]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int gveFailJump3 = b.Count - 4;
        // BSR tree walk loop
        int gveLoop = b.Count;
        b.AddRange([0x48, 0x8B, 0x5D, 0xE0]);                       // mov rbx, [rbp-0x20] (vm_map_entry)
        b.AddRange([0x48, 0x85, 0xDB]);                              // test rbx, rbx
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lfail_efault
        int gveFailJump4 = b.Count - 4;
        // copyout(entry + 0x20, &start, 8)
        b.AddRange([0x48, 0x8D, 0x7B, 0x20]);                       // lea rdi, [rbx+0x20]
        b.AddRange([0x48, 0x8D, 0x75, 0xD8]);                       // lea rsi, [rbp-0x28]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int gveFailJump5 = b.Count - 4;
        // copyout(entry + 0x28, &end, 8)
        b.AddRange([0x48, 0x8D, 0x7B, 0x28]);                       // lea rdi, [rbx+0x28]
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);                       // lea rsi, [rbp-0x20]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int gveFailJump6 = b.Count - 4;
        // if addr < start -> go left (entry+0x10)
        b.AddRange([0x4C, 0x3B, 0x7D, 0xD8]);                       // cmp r15, [rbp-0x28] (addr vs start)
        b.AddRange([0x73, 0x00]);                                    // jae .Lnot_left
        int gveNotLeftJump = b.Count - 1;
        // left: copyout(entry+0x10, &entry, 8)
        b.AddRange([0x48, 0x8D, 0x7B, 0x10]);                       // lea rdi, [rbx+0x10]
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);                       // lea rsi, [rbp-0x20]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int gveFailJump7 = b.Count - 4;
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lloop
        int gveLoopJump1 = b.Count - 4;
        // .Lnot_left:
        int gveNotLeft = b.Count;
        b[gveNotLeftJump] = (byte)(gveNotLeft - (gveNotLeftJump + 1));
        // if addr >= end -> go right (entry+0x18)
        b.AddRange([0x4C, 0x3B, 0x7D, 0xE0]);                       // cmp r15, [rbp-0x20] (addr vs end)
        b.AddRange([0x72, 0x00]);                                    // jb .Lfound
        int gveFoundJump = b.Count - 1;
        // right: copyout(entry+0x18, &entry, 8)
        b.AddRange([0x48, 0x8D, 0x7B, 0x18]);                       // lea rdi, [rbx+0x18]
        b.AddRange([0x48, 0x8D, 0x75, 0xE0]);                       // lea rsi, [rbp-0x20]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int gveFailJump8 = b.Count - 4;
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lloop
        int gveLoopJump2 = b.Count - 4;
        // .Lfound: return rbx (the entry address)
        int gveFound = b.Count;
        b[gveFoundJump] = (byte)(gveFound - (gveFoundJump + 1));
        b.AddRange([0x48, 0x89, 0xD8]);                              // mov rax, rbx
        b.AddRange([0xEB, 0x02]);                                    // jmp .Lret
        // .Lfail: return 0
        int gveFail = b.Count;
        WriteRel32InBLocal(gveFailJump1, gveFail);
        WriteRel32InBLocal(gveFailJump2, gveFail);
        WriteRel32InBLocal(gveFailJump3, gveFail);
        WriteRel32InBLocal(gveFailJump4, gveFail);
        WriteRel32InBLocal(gveFailJump5, gveFail);
        WriteRel32InBLocal(gveFailJump6, gveFail);
        WriteRel32InBLocal(gveFailJump7, gveFail);
        WriteRel32InBLocal(gveFailJump8, gveFail);
        WriteRel32InBLocal(gveLoopJump1, gveLoop);
        WriteRel32InBLocal(gveLoopJump2, gveLoop);
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x38]);                       // add rsp, 0x38
        b.AddRange([0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]);     // pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
        _kernelGetVmemEntryBytes = b.Count - getVmemEntryOff;

        // ---- kernel_set_vmem_protection ----
        // int kernel_set_vmem_protection(int pid, unsigned long addr, unsigned long len, int prot)
        int setVmemProtOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x53]);     // push r15 ; push r14 ; push r13 ; push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x20]);                       // sub rsp, 0x20
        b.AddRange([0x49, 0x89, 0xF7]);                              // mov r15, rsi (addr)
        b.AddRange([0x49, 0x89, 0xD6]);                              // mov r14, rdx (len)
        b.AddRange([0x41, 0x89, 0xCD]);                              // mov r13d, ecx (prot)
        // prot < 0 -> return -1
        b.AddRange([0x85, 0xC9]);                                    // test ecx, ecx
        b.AddRange([0x78, 0x00]);                                    // js .Lfail_einval
        int svpEinvalJump = b.Count - 1;
        // Save prot byte on stack for copyin
        b.AddRange([0x44, 0x88, 0x6D, 0xD8]);                       // mov [rbp-0x28], r13b
        // get_vmem_entry(pid, addr)
        b.AddRange([0x4C, 0x89, 0xFE]);                              // mov rsi, r15 (addr)
        EmitCallGetVmemEntry();
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x74, 0x00]);                                    // jz .Lfail
        int svpFailJump1 = b.Count - 1;
        b.AddRange([0x48, 0x89, 0xC3]);                              // mov rbx, rax (vm_entry)
        b.AddRange([0xBB, 0x01, 0x00, 0x00, 0x00]);                 // mov ebx, 1 (rbx overwritten; reset below)
        // Simplified loop: while entry != 0, walk the vm_entry chain and
        // apply the protection byte. Reset and re-emit with correct register usage.
        b.RemoveRange(setVmemProtOff, b.Count - setVmemProtOff);

        // ---- kernel_set_vmem_protection (simplified, matches SDK behavior) ----
        int setVmemProtOff2 = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53]); // push r15-r12, rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x28]);                       // sub rsp, 0x28
        b.AddRange([0x49, 0x89, 0xF7]);                              // mov r15, rsi (addr)
        b.AddRange([0x49, 0x89, 0xD6]);                              // mov r14, rdx (len)
        b.AddRange([0x41, 0x89, 0xCD]);                              // mov r13d, ecx (prot)
        b.AddRange([0x41, 0xBC, 0x01, 0x00, 0x00, 0x00]);           // mov r12d, 1 (first=1)
        // prot < 0 -> return -1
        b.AddRange([0x41, 0x85, 0xED]);                              // test r13d, r13d
        b.AddRange([0x0F, 0x88, 0, 0, 0, 0]);                       // js .Lfail
        int svpFailJumpNeg = b.Count - 4;
        // Save prot byte on stack (local area below callee-saved zone)
        b.AddRange([0x44, 0x88, 0x6D, 0xD0]);                       // mov [rbp-0x30], r13b
        // get_vmem_entry(pid, addr)
        b.AddRange([0x4C, 0x89, 0xFE]);                              // mov rsi, r15
        EmitCallGetVmemEntry();
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0, 0, 0, 0]);                       // jz .Lfail
        int svpFailJump1a = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC3]);                              // mov rbx, rax (vm_entry)
        // Loop:
        int svpLoop = b.Count;
        b.AddRange([0x48, 0x85, 0xDB]);                              // test rbx, rbx
        b.AddRange([0x74, 0x00]);                                    // jz .Ldone
        int svpDoneJump = b.Count - 1;
        // copyout(entry+0x20, &start, 8)
        b.AddRange([0x48, 0x8D, 0x7B, 0x20]);
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);                       // lea rsi, [rbp-0x38]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int svpFailJump2a = b.Count - 4;
        // Check: if start >= addr+len -> break
        b.AddRange([0x4C, 0x89, 0xF8]);                              // mov rax, r15 (addr)
        b.AddRange([0x4C, 0x01, 0xF0]);                              // add rax, r14 (addr+len)
        b.AddRange([0x48, 0x3B, 0x45, 0xC8]);                       // cmp rax, [rbp-0x38] (addr+len vs start)
        b.AddRange([0x76, 0x00]);                                    // jbe .Ldone
        int svpDoneJump2 = b.Count - 1;
        // Check: if start < addr && !first -> break
        b.AddRange([0x4C, 0x3B, 0x7D, 0xC8]);                       // cmp r15, [rbp-0x38]
        b.AddRange([0x76, 0x06]);                                    // jbe .Lno_break (if addr <= start, skip)
        b.AddRange([0x45, 0x85, 0xE4]);                              // test r12d, r12d
        b.AddRange([0x74, 0x00]);                                    // jz .Ldone
        int svpDoneJump3 = b.Count - 1;
        // .Lno_break:
        b.AddRange([0x45, 0x31, 0xE4]);                              // xor r12d, r12d (first=0)
        // copyin(&prot_byte, entry+0x64, 1)
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);                       // lea rdi, [rbp-0x30] (uaddr)
        b.AddRange([0x48, 0x8D, 0x73, 0x64]);                       // lea rsi, [rbx+0x64] (kaddr)
        b.AddRange([0xBA, 0x01, 0, 0, 0]);                          // mov edx, 1
        EmitCallCopyin();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int svpFailJump3a = b.Count - 4;
        // copyout(entry+0x08, &entry, 8) (follow next pointer)
        b.AddRange([0x48, 0x8D, 0x7B, 0x08]);                       // lea rdi, [rbx+0x08]
        b.AddRange([0x48, 0x8D, 0x75, 0xC0]);                       // lea rsi, [rbp-0x40]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jnz .Lfail
        int svpFailJump4a = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x5D, 0xC0]);                       // mov rbx, [rbp-0x40]
        b.AddRange([0xE9, 0, 0, 0, 0]);                             // jmp .Lloop
        int svpLoopJump = b.Count - 4;
        WriteRel32InBLocal(svpLoopJump, svpLoop);
        // .Ldone: return 0
        int svpDone = b.Count;
        b[svpDoneJump] = (byte)(svpDone - (svpDoneJump + 1));
        b[svpDoneJump2] = (byte)(svpDone - (svpDoneJump2 + 1));
        b[svpDoneJump3] = (byte)(svpDone - (svpDoneJump3 + 1));
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax
        b.AddRange([0xEB, 0x05]);                                    // jmp .Lret
        // .Lfail:
        int svpFail = b.Count;
        WriteRel32InBLocal(svpFailJumpNeg, svpFail);
        WriteRel32InBLocal(svpFailJump1a, svpFail);
        WriteRel32InBLocal(svpFailJump2a, svpFail);
        WriteRel32InBLocal(svpFailJump3a, svpFail);
        WriteRel32InBLocal(svpFailJump4a, svpFail);
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        b.AddRange([0x48, 0x83, 0xC4, 0x28]);                       // add rsp, 0x28
        b.AddRange([0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3]); // pop rbx-r15 ; pop rbp ; ret
        _kernelSetVmemProtBytes = b.Count - setVmemProtOff2;

        // ---- kernel_get_qaflags ----
        // int kernel_get_qaflags(unsigned char qaflags[16])
        int getQaflagsOff = b.Count;
        // mov rsi, rdi (qaflags buffer -> uaddr)
        b.AddRange([0x48, 0x89, 0xFE]);
        // mov rdi, [rip+kernel_qa_flags]
        b.AddRange([0x48, 0x8B, 0x3D, 0, 0, 0, 0]);
        AddRel(RelocSymbol.KernelQaFlags, b.Count - 4);
        b.AddRange([0xBA, 0x10, 0, 0, 0]);                          // mov edx, 16
        EmitCallCopyout();                                            // tail-call optimizable but keep simple
        b.AddRange([0xC3]);                                          // ret
        _kernelGetQaflagsBytes = b.Count - getQaflagsOff;

        // ---- kernel_setlong ----
        // int kernel_setlong(unsigned long addr, unsigned long val)
        int setlongOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x48, 0x89, 0xF8]);                              // mov rax, rdi (addr)
        b.AddRange([0x48, 0x89, 0x75, 0xF8]);                       // mov [rbp-8], rsi (val)
        b.AddRange([0x48, 0x8D, 0x7D, 0xF8]);                       // lea rdi, [rbp-8] (uaddr)
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        b.AddRange([0x48, 0x89, 0xC6]);                              // mov rsi, rax (kaddr)
        EmitCallCopyin();
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetlongBytes = b.Count - setlongOff;

        // ---- kernel_getlong ----
        // unsigned long kernel_getlong(unsigned long addr)
        int getlongOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);          // movq [rbp-8], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xF8]);                       // lea rsi, [rbp-8]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        EmitCallCopyout();
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);                       // mov rax, [rbp-8]
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetlongBytes = b.Count - getlongOff;

        // ---- kernel_setint ----
        int setintOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0x89, 0xF8]);                              // mov rax, rdi
        b.AddRange([0x89, 0x75, 0xFC]);                              // mov [rbp-4], esi
        b.AddRange([0x48, 0x8D, 0x7D, 0xFC]);                       // lea rdi, [rbp-4]
        b.AddRange([0xBA, 0x04, 0, 0, 0]);                          // mov edx, 4
        b.AddRange([0x48, 0x89, 0xC6]);
        EmitCallCopyin();
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetintBytes = b.Count - setintOff;

        // ---- kernel_getint ----
        int getintOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0xC7, 0x45, 0xFC, 0, 0, 0, 0]);                // mov dword [rbp-4], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xFC]);
        b.AddRange([0xBA, 0x04, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x8B, 0x45, 0xFC]);                              // mov eax, [rbp-4]
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetintBytes = b.Count - getintOff;

        // Record offsets for all new kernel functions
        _kernelGetProcUcredOff = getProcUcredOff;
        _kernelGetUcredAuthidOff = getUcredAuthidOff;
        _kernelSetUcredAuthidOff = setUcredAuthidOff;
        _kernelGetUcredCapsOff = getUcredCapsOff;
        _kernelSetUcredCapsOff = setUcredCapsOff;
        _kernelGetUcredAttrsOff = getUcredAttrsOff;
        _kernelSetUcredAttrsOff = setUcredAttrsOff;
        _kernelGetUcredPrisonOff = getUcredPrisonOff;
        _kernelSetUcredPrisonOff = setUcredPrisonOff;
        _kernelGetRootVnodeOff = getRootVnodeOff;
        _kernelGetProcFiledescOff = getProcFiledescOff;
        _kernelGetProcRootdirOff = getProcRootdirOff;
        _kernelSetProcRootdirOff = setProcRootdirOff;
        _kernelGetProcJaildirOff = getProcJaildirOff;
        _kernelSetProcJaildirOff = setProcJaildirOff;
        _kernelDynlibFindHandleOff = dynlibFindHandleOff;
        _kernelDynlibMapbaseOff = dynlibMapbaseOff;
        _kernelDynlibFiniAddrOff = dynlibFiniAddrOff;
        _kernelDynlibInitAddrOff = dynlibInitAddrOff;
        _kernelDynlibEntryAddrOff = dynlibEntryAddrOff;
        _kernelDynlibPathOff = dynlibPathOff;
        _kernelMprotectOff = mprotectOff;
        _kernelGetVmemEntryOff = getVmemEntryOff;
        _kernelSetVmemProtOff = setVmemProtOff2;
        _kernelGetQaflagsOff = getQaflagsOff;
        _kernelSetlongOff = setlongOff;
        _kernelGetlongOff = getlongOff;
        _kernelSetintOff = setintOff;
        _kernelGetintOff = getintOff;

        // ---- kernel_setshort (SDK kernel.c, 2-byte copyin) ----
        // int kernel_setshort(unsigned long addr, unsigned short val)
        int setshortOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x48, 0x89, 0xF8]);                              // mov rax, rdi (addr)
        b.AddRange([0x66, 0x89, 0x75, 0xFE]);                       // mov [rbp-2], si
        b.AddRange([0x48, 0x8D, 0x7D, 0xFE]);                       // lea rdi, [rbp-2] (uaddr)
        b.AddRange([0xBA, 0x02, 0, 0, 0]);                          // mov edx, 2
        b.AddRange([0x48, 0x89, 0xC6]);                              // mov rsi, rax (kaddr)
        EmitCallCopyin();
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetshortBytes = b.Count - setshortOff;

        // ---- kernel_setchar (SDK kernel.c, 1-byte copyin) ----
        // int kernel_setchar(unsigned long addr, unsigned char val)
        int setcharOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x48, 0x89, 0xF8]);                              // mov rax, rdi
        b.AddRange([0x40, 0x88, 0x75, 0xFF]);                       // mov [rbp-1], sil
        b.AddRange([0x48, 0x8D, 0x7D, 0xFF]);                       // lea rdi, [rbp-1]
        b.AddRange([0xBA, 0x01, 0, 0, 0]);                          // mov edx, 1
        b.AddRange([0x48, 0x89, 0xC6]);
        EmitCallCopyin();
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetcharBytes = b.Count - setcharOff;

        // ---- kernel_getshort (SDK kernel.c, 2-byte copyout) ----
        // unsigned short kernel_getshort(unsigned long addr)
        int getshortOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0x66, 0xC7, 0x45, 0xFE, 0, 0]);                // mov word [rbp-2], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xFE]);                       // lea rsi, [rbp-2]
        b.AddRange([0xBA, 0x02, 0, 0, 0]);                          // mov edx, 2
        EmitCallCopyout();
        b.AddRange([0x0F, 0xB7, 0x45, 0xFE]);                       // movzx eax, word [rbp-2]
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetshortBytes = b.Count - getshortOff;

        // ---- kernel_getchar (SDK kernel.c, 1-byte copyout) ----
        // unsigned char kernel_getchar(unsigned long addr)
        int getcharOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0xC6, 0x45, 0xFF, 0]);                          // mov byte [rbp-1], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xFF]);                       // lea rsi, [rbp-1]
        b.AddRange([0xBA, 0x01, 0, 0, 0]);                          // mov edx, 1
        EmitCallCopyout();
        b.AddRange([0x0F, 0xB6, 0x45, 0xFF]);                       // movzx eax, byte [rbp-1]
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetcharBytes = b.Count - getcharOff;

        // ---- kernel_set_qaflags (SDK kernel.c) ----
        // int kernel_set_qaflags(const unsigned char qaflags[16])
        // On FW >= 7.x, returns -1 with ENOSYS. Otherwise copyin(qaflags, QA_FLAGS, 16).
        int setQaflagsOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x48, 0x89, 0xFB]);                              // mov rbx, rdi (save qaflags ptr)
        // Load QA_FLAGS address from BSS
        b.AddRange([0x48, 0x8B, 0x35, 0, 0, 0, 0]);                 // mov rsi, [rip+qa_flags_slot]
        AddRel(RelocSymbol.KernelQaFlags, b.Count - 4);
        b.AddRange([0x48, 0x89, 0xDF]);                              // mov rdi, rbx (uaddr = qaflags)
        b.AddRange([0xBA, 0x10, 0, 0, 0]);                          // mov edx, 16
        EmitCallCopyin();
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);           // add rsp, 0x10 ; pop rbp ; ret
        _kernelSetQaflagsBytes = b.Count - setQaflagsOff;

        // ---- kernel_get_fw_version (SDK kernel.c) ----
        // unsigned int kernel_get_fw_version(void)
        // Calls SYS_dynlib_get_obj_member(0x2, 8, &sce_proc_param), returns sce_proc_param->sdk_ps5_ver
        int getFwVersionOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x48, 0x83, 0xEC, 0x20]);                       // sub rsp, 0x20
        b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);          // mov qword [rbp-8], 0 (sce_proc_param = 0)
        // __sp_crt_syscall(SYS_dynlib_get_obj_member=649, handle=0x2, member=8, &out)
        b.AddRange([0xBF]); b.AddRange(BitConverter.GetBytes(649));  // mov edi, 649
        b.AddRange([0xBE, 0x02, 0, 0, 0]);                          // mov esi, 0x2
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        b.AddRange([0x48, 0x8D, 0x4D, 0xF8]);                       // lea rcx, [rbp-8]
        EmitCallCrtSyscall();
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x75, 0x0C]);                                    // jne .ret0
        b.AddRange([0x48, 0x8B, 0x45, 0xF8]);                       // mov rax, [rbp-8]
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x04]);                                    // je .ret0
        b.AddRange([0x8B, 0x40, 0x10]);                              // mov eax, [rax+0x10] (sdk_ps5_ver)
        b.AddRange([0xEB, 0x02]);                                    // jmp .ret
        b.AddRange([0x31, 0xC0]);                                    // .ret0: xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3]);           // .ret: add rsp, 0x20 ; pop rbp ; ret
        _kernelGetFwVersionBytes = b.Count - getFwVersionOff;

        // ---- kernel_get_proc_thread (SDK kernel.c) ----
        // unsigned long kernel_get_proc_thread(int pid, int tid)
        // Gets proc via kernel_get_proc, if tid<0 calls SYS_thr_self(0x1b0) to get own tid,
        // then walks thread list at proc+0x10 checking thr+0x9c == tid.
        int getProcThreadOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x54]);                                    // push r12
        b.AddRange([0x53]);                                          // push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x89, 0xF3]);                                    // mov ebx, esi (tid)
        EmitCallGetProc();                                            // call kernel_get_proc (rdi=pid)
        b.AddRange([0x49, 0x89, 0xC4]);                              // mov r12, rax (proc)
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x00]);                                    // je .Lret0
        int ptFailJump = b.Count - 1;
        // if (tid < 0) { __crt_syscall(0x1b0, &tid); }
        b.AddRange([0x85, 0xDB]);                                    // test ebx, ebx
        b.AddRange([0x79, 0x00]);                                    // jns .Lskip_thr_self
        int ptSkipThrSelf = b.Count - 1;
        b.AddRange([0x89, 0x5D, 0xEC]);                              // mov [rbp-0x14], ebx
        b.AddRange([0xBF]); b.AddRange(BitConverter.GetBytes(0x1b0)); // mov edi, 0x1b0 (SYS_thr_self)
        b.AddRange([0x48, 0x8D, 0x75, 0xEC]);                       // lea rsi, [rbp-0x14]
        EmitCallCrtSyscall();
        b.AddRange([0x8B, 0x5D, 0xEC]);                              // mov ebx, [rbp-0x14] (tid)
        b[ptSkipThrSelf] = (byte)(b.Count - (ptSkipThrSelf + 1));
        // for (thr = getlong(proc+0x10); thr; thr = getlong(thr+0x10))
        //   if ((int)getlong(thr+0x9c) == (int)tid) return thr;
        b.AddRange([0x49, 0x8D, 0x7C, 0x24, 0x10]);                 // lea rdi, [r12+0x10]
        kernelCallDisps.Add((b.Count + 2, "getlong_inline"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // call kernel_getlong
        b.AddRange([0x49, 0x89, 0xC4]);                              // mov r12, rax (thr)
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x00]);                                    // je .Lret0
        int ptLoopExit = b.Count - 1;
        // .Lloop:
        int ptLoopTop = b.Count;
        b.AddRange([0x49, 0x8D, 0xBC, 0x24, 0x9C, 0, 0, 0]);       // lea rdi, [r12+0x9c]
        kernelCallDisps.Add((b.Count + 2, "getlong_inline"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // call kernel_getlong
        b.AddRange([0x39, 0xD8]);                                    // cmp eax, ebx
        b.AddRange([0x74, 0x00]);                                    // je .Lfound
        int ptFoundJump = b.Count - 1;
        b.AddRange([0x49, 0x8D, 0x7C, 0x24, 0x10]);                 // lea rdi, [r12+0x10]
        kernelCallDisps.Add((b.Count + 2, "getlong_inline"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // call kernel_getlong
        b.AddRange([0x49, 0x89, 0xC4]);                              // mov r12, rax
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        int ptLoopDisp = b.Count + 2;
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jne .Lloop
        int ptLoopRel = ptLoopTop - (b.Count);
        b[ptLoopDisp] = (byte)(ptLoopRel & 0xFF);
        b[ptLoopDisp + 1] = (byte)((ptLoopRel >> 8) & 0xFF);
        b[ptLoopDisp + 2] = (byte)((ptLoopRel >> 16) & 0xFF);
        b[ptLoopDisp + 3] = (byte)((ptLoopRel >> 24) & 0xFF);
        // .Lret0:
        int ptRet0 = b.Count;
        b[ptFailJump] = (byte)(ptRet0 - (ptFailJump + 1));
        b[ptLoopExit] = (byte)(ptRet0 - (ptLoopExit + 1));
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax
        b.AddRange([0xEB, 0x03]);                                    // jmp .Lret
        // .Lfound:
        b[ptFoundJump] = (byte)(b.Count - (ptFoundJump + 1));
        b.AddRange([0x4C, 0x89, 0xE0]);                              // mov rax, r12
        // .Lret:
        b.AddRange([0x48, 0x83, 0xC4, 0x10]);                       // add rsp, 0x10
        b.AddRange([0x5B]);                                          // pop rbx
        b.AddRange([0x41, 0x5C]);                                    // pop r12
        b.AddRange([0x5D, 0xC3]);                                    // pop rbp ; ret
        _kernelGetProcThreadBytes = b.Count - getProcThreadOff;

        // ---- kernel_get_proc_file (SDK kernel.c) ----
        // unsigned long kernel_get_proc_file(int pid, int fd)
        // Gets proc, reads p_fd (proc+0x48), reads fd_files (p_fd+0x00),
        // reads fde_file (fd_files+8+0x30*fd), reads file (fde_file+0x00)
        int getProcFileOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x54]);                                    // push r12
        b.AddRange([0x53]);                                          // push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x10]);                       // sub rsp, 0x10
        b.AddRange([0x89, 0xF3]);                                    // mov ebx, esi (fd)
        b.AddRange([0x48, 0xC7, 0x45, 0xE8, 0, 0, 0, 0]);          // mov qword [rbp-0x18], 0
        EmitCallGetProc();                                            // kernel_get_proc(pid)
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x00]);                                    // je .Lret0
        int pfFailJump1 = b.Count - 1;
        // read p_fd = proc+0x48
        b.AddRange([0x48, 0x83, 0xC0, 0x48]);                       // add rax, 0x48
        b.AddRange([0x48, 0x8D, 0x75, 0xE8]);                       // lea rsi, [rbp-0x18]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x75, 0x00]);                                    // jne .Lret0
        int pfFailJump2 = b.Count - 1;
        // read fd_files = [p_fd+0x00]
        b.AddRange([0x48, 0x8B, 0x7D, 0xE8]);                       // mov rdi, [rbp-0x18]
        b.AddRange([0x48, 0xC7, 0x45, 0xE8, 0, 0, 0, 0]);          // mov qword [rbp-0x18], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xE8]);                       // lea rsi, [rbp-0x18]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x00]);
        int pfFailJump3 = b.Count - 1;
        // compute fde_file = fd_files + 8 + 0x30 * fd
        b.AddRange([0x48, 0x8B, 0x45, 0xE8]);                       // mov rax, [rbp-0x18]
        b.AddRange([0x48, 0x63, 0xDB]);                              // movsxd rbx, ebx
        b.AddRange([0x48, 0x6B, 0xDB, 0x30]);                       // imul rbx, rbx, 0x30
        b.AddRange([0x48, 0x8D, 0x7C, 0x18, 0x08]);                 // lea rdi, [rax+rbx+8]
        b.AddRange([0x48, 0xC7, 0x45, 0xE8, 0, 0, 0, 0]);          // mov qword [rbp-0x18], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xE8]);                       // lea rsi, [rbp-0x18]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x00]);
        int pfFailJump4 = b.Count - 1;
        // read file = [fde_file+0x00]
        b.AddRange([0x48, 0x8B, 0x7D, 0xE8]);                       // mov rdi, [rbp-0x18]
        b.AddRange([0x48, 0xC7, 0x45, 0xE8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x8D, 0x75, 0xE8]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x06]);
        b.AddRange([0x48, 0x8B, 0x45, 0xE8]);                       // mov rax, [rbp-0x18]
        b.AddRange([0xEB, 0x02]);                                    // jmp .Lret
        // .Lret0:
        int pfRet0 = b.Count;
        b[pfFailJump1] = (byte)(pfRet0 - (pfFailJump1 + 1));
        b[pfFailJump2] = (byte)(pfRet0 - (pfFailJump2 + 1));
        b[pfFailJump3] = (byte)(pfRet0 - (pfFailJump3 + 1));
        b[pfFailJump4] = (byte)(pfRet0 - (pfFailJump4 + 1));
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax
        b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5B, 0x41, 0x5C, 0x5D, 0xC3]);
        _kernelGetProcFileBytes = b.Count - getProcFileOff;

        // ---- kernel_get_vmem_protection (SDK kernel.c) ----
        // int kernel_get_vmem_protection(int pid, unsigned long addr, unsigned long len)
        // Walks VM entries starting from kernel_get_vmem_entry, accumulates intersection of prot bits.
        int getVmemProtectionOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x57]);                                    // push r15
        b.AddRange([0x41, 0x56]);                                    // push r14
        b.AddRange([0x41, 0x55]);                                    // push r13
        b.AddRange([0x41, 0x54]);                                    // push r12
        b.AddRange([0x53]);                                          // push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x18]);                       // sub rsp, 0x18
        b.AddRange([0x49, 0x89, 0xD6]);                              // mov r14, rdx (len)
        b.AddRange([0x49, 0x89, 0xF5]);                              // mov r13, rsi (addr)
        b.AddRange([0x49, 0x01, 0xF6]);                              // add r14, rsi (end = addr + len)
        b.AddRange([0x41, 0xBC, 0xFF, 0xFF, 0xFF, 0xFF]);            // mov r12d, -1 (prot = -1)
        b.AddRange([0xBB, 0x01, 0, 0, 0]);                          // mov ebx, 1 (first = 1)
        // rdi = pid, rsi = addr -> call kernel_get_vmem_entry
        b.AddRange([0x4C, 0x89, 0xEE]);                              // mov rsi, r13
        EmitCallGetVmemEntry();
        b.AddRange([0x49, 0x89, 0xC7]);                              // mov r15, rax (vm_entry)
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x74, 0x00]);                                    // je .Lret_neg1
        int vpFailJump = b.Count - 1;
        // .Lloop:
        int vpLoopTop = b.Count;
        // read start = [vm_entry + 0x20] into safe local at [rbp-0x30]
        b.AddRange([0x48, 0xC7, 0x45, 0xD0, 0, 0, 0, 0]);          // mov qword [rbp-0x30], 0
        b.AddRange([0x49, 0x8D, 0x7F, 0x20]);                       // lea rdi, [r15+0x20]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                       // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);                                    // test eax, eax
        b.AddRange([0x75, 0x00]);                                    // jne .Lret_neg1
        int vpCopyoutFail1 = b.Count - 1;
        b.AddRange([0x48, 0x8B, 0x45, 0xD0]);                       // mov rax, [rbp-0x30] (start)
        // if (start >= end) break
        b.AddRange([0x4C, 0x39, 0xF0]);                              // cmp rax, r14
        b.AddRange([0x73, 0x00]);                                    // jae .Ldone
        int vpDoneJump1 = b.Count - 1;
        // if (start < addr && !first) break
        b.AddRange([0x4C, 0x39, 0xE8]);                              // cmp rax, r13
        b.AddRange([0x73, 0x04]);                                    // jae .Lskip_first_check
        b.AddRange([0x85, 0xDB]);                                    // test ebx, ebx
        b.AddRange([0x74, 0x00]);                                    // je .Ldone
        int vpDoneJump2 = b.Count - 1;
        // .Lskip_first_check:
        b.AddRange([0x31, 0xDB]);                                    // xor ebx, ebx (first = 0)
        // read vm_prot = byte [vm_entry + 0x64] into safe local at [rbp-0x31]
        b.AddRange([0xC6, 0x45, 0xCF, 0]);                          // mov byte [rbp-0x31], 0
        b.AddRange([0x49, 0x8D, 0x7F, 0x64]);                       // lea rdi, [r15+0x64]
        b.AddRange([0x48, 0x8D, 0x75, 0xCF]);                       // lea rsi, [rbp-0x31]
        b.AddRange([0xBA, 0x01, 0, 0, 0]);                          // mov edx, 1
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x00]);                                    // jne .Lret_neg1
        int vpCopyoutFail2 = b.Count - 1;
        b.AddRange([0x0F, 0xB6, 0x45, 0xCF]);                       // movzx eax, byte [rbp-0x31]
        // if (prot < 0) prot = vm_prot
        b.AddRange([0x45, 0x85, 0xE4]);                              // test r12d, r12d
        b.AddRange([0x79, 0x03]);                                    // jns .Lhas_prot
        b.AddRange([0x41, 0x89, 0xC4]);                              // mov r12d, eax
        // else if ((prot & vm_prot) != prot) return -1
        // .Lhas_prot:
        b.AddRange([0x44, 0x21, 0xE0]);                              // and eax, r12d
        b.AddRange([0x44, 0x39, 0xE0]);                              // cmp eax, r12d
        b.AddRange([0x75, 0x00]);                                    // jne .Lret_neg1
        int vpProtFail = b.Count - 1;
        // read next vm_entry = [vm_entry + 0x08] into safe local at [rbp-0x30]
        b.AddRange([0x49, 0x8D, 0x7F, 0x08]);                       // lea rdi, [r15+0x08]
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                       // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);                          // mov edx, 8
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x00]);                                    // jne .Lret_neg1
        int vpCopyoutFail3 = b.Count - 1;
        b.AddRange([0x4C, 0x8B, 0x7D, 0xD0]);                       // mov r15, [rbp-0x30]
        b.AddRange([0x4D, 0x85, 0xFF]);                              // test r15, r15
        int vpLoopDisp = b.Count + 2;
        b.AddRange([0x0F, 0x85, 0, 0, 0, 0]);                       // jne .Lloop
        {
            int rel = vpLoopTop - b.Count;
            b[vpLoopDisp] = (byte)(rel & 0xFF);
            b[vpLoopDisp + 1] = (byte)((rel >> 8) & 0xFF);
            b[vpLoopDisp + 2] = (byte)((rel >> 16) & 0xFF);
            b[vpLoopDisp + 3] = (byte)((rel >> 24) & 0xFF);
        }
        // .Ldone: return prot (may still be -1 if no entries matched)
        int vpDone = b.Count;
        b[vpDoneJump1] = (byte)(vpDone - (vpDoneJump1 + 1));
        b[vpDoneJump2] = (byte)(vpDone - (vpDoneJump2 + 1));
        b.AddRange([0x44, 0x89, 0xE0]);                              // mov eax, r12d
        b.AddRange([0xEB, 0x05]);                                    // jmp .Lret
        // .Lret_neg1:
        int vpRetNeg1 = b.Count;
        b[vpFailJump] = (byte)(vpRetNeg1 - (vpFailJump + 1));
        b[vpCopyoutFail1] = (byte)(vpRetNeg1 - (vpCopyoutFail1 + 1));
        b[vpCopyoutFail2] = (byte)(vpRetNeg1 - (vpCopyoutFail2 + 1));
        b[vpCopyoutFail3] = (byte)(vpRetNeg1 - (vpCopyoutFail3 + 1));
        b[vpProtFail] = (byte)(vpRetNeg1 - (vpProtFail + 1));
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        // .Lret:
        b.AddRange([0x48, 0x83, 0xC4, 0x18]);                       // add rsp, 0x18
        b.AddRange([0x5B]);                                          // pop rbx
        b.AddRange([0x41, 0x5C]);                                    // pop r12
        b.AddRange([0x41, 0x5D]);                                    // pop r13
        b.AddRange([0x41, 0x5E]);                                    // pop r14
        b.AddRange([0x41, 0x5F]);                                    // pop r15
        b.AddRange([0x5D, 0xC3]);                                    // pop rbp ; ret
        _kernelGetVmemProtectionBytes = b.Count - getVmemProtectionOff;

        // ---- kernel_overlap_sockets (SDK kernel.c) ----
        // int kernel_overlap_sockets(int pid, int master_sock, int victim_sock)
        // Steps: inc_so_count(master), get_inp6_outputopts(master),
        //        inc_so_count(victim), get_inp6_outputopts(victim),
        //        copyin victim+0x10 -> master+0x10, copyin tclass 0x13370000 -> master+0xc0
        int overlapSocketsOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5]);                       // push rbp ; mov rbp, rsp
        b.AddRange([0x41, 0x57]);                                    // push r15
        b.AddRange([0x41, 0x56]);                                    // push r14
        b.AddRange([0x41, 0x55]);                                    // push r13
        b.AddRange([0x41, 0x54]);                                    // push r12
        b.AddRange([0x53]);                                          // push rbx
        b.AddRange([0x48, 0x83, 0xEC, 0x28]);                       // sub rsp, 0x28
        b.AddRange([0x89, 0xFB]);                                    // mov ebx, edi (pid)
        b.AddRange([0x41, 0x89, 0xF4]);                              // mov r12d, esi (master_sock)
        b.AddRange([0x41, 0x89, 0xD5]);                              // mov r13d, edx (victim_sock)

        // Helper: inline get_proc_file(pid, fd) -> file pointer
        // Helper: inline get_inp6_outputopts(pid, fd) -> outputopts pointer
        // Helper: inline inc_so_count(pid, fd)
        // The helper calls are inlined as calls to get_proc_file + kernel_copyout + kernel_copyin

        // --- inc_so_count(pid, master_sock) ---
        b.AddRange([0x89, 0xDF]);                                    // mov edi, ebx (pid)
        b.AddRange([0x44, 0x89, 0xE6]);                              // mov esi, r12d (master_sock)
        kernelCallDisps.Add((b.Count + 2, "get_proc_file"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // call kernel_get_proc_file
        b.AddRange([0x48, 0x85, 0xC0]);                              // test rax, rax
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);           // je rel32 .Lfail
        int osFailJump1 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax (file)
        b.AddRange([0xC7, 0x45, 0xD0, 0, 0, 0, 0]);                 // mov dword [rbp-0x30], 0
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);                       // lea rsi, [rbp-0x30]
        b.AddRange([0xBA, 0x04, 0, 0, 0]);                          // mov edx, 4
        EmitCallCopyout();                                            // read so_count
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump2 = b.Count - 4;
        b.AddRange([0xFF, 0x45, 0xD0]);                              // inc dword [rbp-0x30]
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);                       // lea rdi, [rbp-0x30] (uaddr)
        // The file pointer is needed again - recalculate
        b.AddRange([0x89, 0xDF]);                                    // mov edi, ebx
        b.AddRange([0x44, 0x89, 0xE6]);                              // mov esi, r12d
        kernelCallDisps.Add((b.Count + 2, "get_proc_file"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // call kernel_get_proc_file
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);           // je rel32 .Lfail
        int osFailJump3 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC6]);                              // mov rsi, rax (kaddr = file)
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);                       // lea rdi, [rbp-0x30]
        b.AddRange([0xBA, 0x04, 0, 0, 0]);                          // mov edx, 4
        EmitCallCopyin();                                             // write so_count

        // --- get_inp6_outputopts(pid, master_sock) -> r14 ---
        b.AddRange([0x89, 0xDF]);                                    // mov edi, ebx
        b.AddRange([0x44, 0x89, 0xE6]);                              // mov esi, r12d
        kernelCallDisps.Add((b.Count + 2, "get_proc_file"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);                       // call kernel_get_proc_file
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);           // je rel32 .Lfail
        int osFailJump4 = b.Count - 4;
        // file+0x18 -> so_pcb
        b.AddRange([0x48, 0x83, 0xC0, 0x18]);                       // add rax, 0x18
        b.AddRange([0x48, 0xC7, 0x45, 0xC8, 0, 0, 0, 0]);          // mov qword [rbp-0x38], 0
        b.AddRange([0x48, 0x89, 0xC7]);                              // mov rdi, rax
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);                       // lea rsi, [rbp-0x38]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump5 = b.Count - 4;
        // so_pcb+0x120 -> inp6_outputopts
        b.AddRange([0x48, 0x8B, 0x45, 0xC8]);                       // mov rax, [rbp-0x38]
        b.AddRange([0x48, 0x05, 0x20, 0x01, 0, 0]);                 // add rax, 0x120
        b.AddRange([0x48, 0xC7, 0x45, 0xC8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x89, 0xC7]);
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump6 = b.Count - 4;
        b.AddRange([0x4C, 0x8B, 0x75, 0xC8]);                       // mov r14, [rbp-0x38] (master_inp6_outputopts)

        // --- inc_so_count(pid, victim_sock) ---
        b.AddRange([0x89, 0xDF]);
        b.AddRange([0x44, 0x89, 0xEE]);                              // mov esi, r13d
        kernelCallDisps.Add((b.Count + 2, "get_proc_file"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);           // je rel32 .Lfail
        int osFailJump7 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC7]);
        b.AddRange([0xC7, 0x45, 0xD0, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x8D, 0x75, 0xD0]);
        b.AddRange([0xBA, 0x04, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump8 = b.Count - 4;
        b.AddRange([0xFF, 0x45, 0xD0]);
        b.AddRange([0x89, 0xDF]);
        b.AddRange([0x44, 0x89, 0xEE]);
        kernelCallDisps.Add((b.Count + 2, "get_proc_file"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);           // je rel32 .Lfail
        int osFailJump9 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0xC6]);
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);
        b.AddRange([0xBA, 0x04, 0, 0, 0]);
        EmitCallCopyin();

        // --- get_inp6_outputopts(pid, victim_sock) -> r15 ---
        b.AddRange([0x89, 0xDF]);
        b.AddRange([0x44, 0x89, 0xEE]);
        kernelCallDisps.Add((b.Count + 2, "get_proc_file"));
        b.AddRange([0x67, 0xE8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x85, 0xC0]);
        b.AddRange([0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);           // je rel32 .Lfail
        int osFailJump10 = b.Count - 4;
        b.AddRange([0x48, 0x83, 0xC0, 0x18]);
        b.AddRange([0x48, 0xC7, 0x45, 0xC8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x89, 0xC7]);
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump11 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x45, 0xC8]);
        b.AddRange([0x48, 0x05, 0x20, 0x01, 0, 0]);
        b.AddRange([0x48, 0xC7, 0x45, 0xC8, 0, 0, 0, 0]);
        b.AddRange([0x48, 0x89, 0xC7]);
        b.AddRange([0x48, 0x8D, 0x75, 0xC8]);
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyout();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump12 = b.Count - 4;
        b.AddRange([0x4C, 0x8B, 0x7D, 0xC8]);                       // mov r15, [rbp-0x38] (victim_inp6_outputopts)

        // pktinfo = victim_inp6_outputopts + 0x10
        // copyin(&pktinfo, master_inp6_outputopts + 0x10, 8)
        b.AddRange([0x4D, 0x8D, 0x47, 0x10]);                       // lea r8, [r15+0x10]
        b.AddRange([0x4C, 0x89, 0x45, 0xC8]);                       // mov [rbp-0x38], r8
        b.AddRange([0x48, 0x8D, 0x7D, 0xC8]);                       // lea rdi, [rbp-0x38]
        b.AddRange([0x49, 0x8D, 0x76, 0x10]);                       // lea rsi, [r14+0x10]
        b.AddRange([0xBA, 0x08, 0, 0, 0]);
        EmitCallCopyin();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]);           // jne rel32 .Lfail
        int osFailJump13 = b.Count - 4;

        // tclass = 0x13370000
        // copyin(&tclass, master_inp6_outputopts + 0xc0, 4)
        b.AddRange([0xC7, 0x45, 0xD0, 0x00, 0x00, 0x37, 0x13]);     // mov dword [rbp-0x30], 0x13370000
        b.AddRange([0x48, 0x8D, 0x7D, 0xD0]);                       // lea rdi, [rbp-0x30]
        b.AddRange([0x49, 0x8D, 0xB6, 0xC0, 0, 0, 0]);              // lea rsi, [r14+0xc0]
        b.AddRange([0xBA, 0x04, 0, 0, 0]);
        EmitCallCopyin();
        b.AddRange([0x85, 0xC0]);
        b.AddRange([0x75, 0x05]);
        b.AddRange([0x31, 0xC0]);                                    // xor eax, eax (success)
        b.AddRange([0xEB, 0x05]);                                    // jmp .Lret

        // .Lfail:
        int osFail = b.Count;
        foreach (int j in new[] { osFailJump1, osFailJump2, osFailJump3, osFailJump4, osFailJump5,
                                  osFailJump6, osFailJump7, osFailJump8, osFailJump9, osFailJump10,
                                  osFailJump11, osFailJump12, osFailJump13 })
        {
            // All failure jumps use rel32 form (0F 84/85 + 4-byte displacement).
            // j points to the first byte of the 4-byte displacement field.
            int disp = osFail - (j + 4);
            b[j] = (byte)(disp & 0xFF);
            b[j + 1] = (byte)((disp >> 8) & 0xFF);
            b[j + 2] = (byte)((disp >> 16) & 0xFF);
            b[j + 3] = (byte)((disp >> 24) & 0xFF);
        }
        b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);                 // mov eax, -1
        // .Lret:
        b.AddRange([0x48, 0x83, 0xC4, 0x28]);                       // add rsp, 0x28
        b.AddRange([0x5B]);                                          // pop rbx
        b.AddRange([0x41, 0x5C]);                                    // pop r12
        b.AddRange([0x41, 0x5D]);                                    // pop r13
        b.AddRange([0x41, 0x5E]);                                    // pop r14
        b.AddRange([0x41, 0x5F]);                                    // pop r15
        b.AddRange([0x5D, 0xC3]);                                    // pop rbp ; ret
        _kernelOverlapSocketsBytes = b.Count - overlapSocketsOff;

        // ---- ucred uid/gid accessors (SDK kernel.c) ----
        // These all follow the same pattern as the existing ucred getter/setter helpers
        // but read/write 4-byte values at specific ucred offsets.

        // Helper: emit a ucred getter for 4-byte int value (returns int, -1 on failure).
        int EmitUcredGetter4(byte ucredOffset)
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x48, 0x83, 0xEC, 0x10]);                   // sub rsp, 0x10
            b.AddRange([0xC7, 0x45, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF]); // mov dword [rbp-4], -1
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            b.AddRange([0x48, 0x83, 0xC0, ucredOffset]);            // add rax, ucredOffset
            b.AddRange([0x48, 0x8D, 0x75, 0xFC]);                   // lea rsi, [rbp-4]
            b.AddRange([0xBA, 0x04, 0, 0, 0]);                      // mov edx, 4
            b.AddRange([0x48, 0x89, 0xC7]);                          // mov rdi, rax
            EmitCallCopyout();                                        // call kernel_copyout
            b.AddRange([0x85, 0xC0]);                                // test eax, eax
            b.AddRange([0x75, 0x05]);                                // jne .Lfail
            b.AddRange([0x8B, 0x45, 0xFC]);                          // mov eax, [rbp-4]
            b.AddRange([0xEB, 0x02]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0x31, 0xC0]);                                // xor eax, eax
            // SDK initializes val=-1 and returns val, so on proc_ucred or copyout
            // failure the dword is still -1. On success, return the read value.
            // On ucred fail, return -1 directly.
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);       // add rsp, 0x10 ; pop rbp ; ret
            return off;
        }

        // Helper: emit a ucred setter for 4-byte int value (returns 0 on success, -1 on failure).
        int EmitUcredSetter4(byte ucredOffset)
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x48, 0x83, 0xEC, 0x10]);                   // sub rsp, 0x10
            b.AddRange([0x89, 0x75, 0xFC]);                          // mov [rbp-4], esi (save val)
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            b.AddRange([0x48, 0x83, 0xC0, ucredOffset]);            // add rax, ucredOffset
            b.AddRange([0x48, 0x89, 0xC6]);                          // mov rsi, rax (kaddr)
            b.AddRange([0x48, 0x8D, 0x7D, 0xFC]);                   // lea rdi, [rbp-4] (uaddr = &val)
            b.AddRange([0xBA, 0x04, 0, 0, 0]);                      // mov edx, 4
            EmitCallCopyin();                                         // call kernel_copyin
            b.AddRange([0xF7, 0xD8]);                                // neg eax
            b.AddRange([0x19, 0xC0]);                                // sbb eax, eax
            b.AddRange([0xEB, 0x05]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);             // mov eax, -1
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);       // add rsp, 0x10 ; pop rbp ; ret
            return off;
        }

        // kernel_get_ucred_uid (offset 0x04)
        int getUcredUidOff = EmitUcredGetter4(0x04);
        _kernelGetUcredUidBytes = b.Count - getUcredUidOff;

        // kernel_set_ucred_uid (offset 0x04)
        int setUcredUidOff = EmitUcredSetter4(0x04);
        _kernelSetUcredUidBytes = b.Count - setUcredUidOff;

        // kernel_get_ucred_ruid (offset 0x08)
        int getUcredRuidOff = EmitUcredGetter4(0x08);
        _kernelGetUcredRuidBytes = b.Count - getUcredRuidOff;

        // kernel_set_ucred_ruid (offset 0x08)
        int setUcredRuidOff = EmitUcredSetter4(0x08);
        _kernelSetUcredRuidBytes = b.Count - setUcredRuidOff;

        // kernel_get_ucred_svuid (offset 0x0C)
        int getUcredSvuidOff = EmitUcredGetter4(0x0C);
        _kernelGetUcredSvuidBytes = b.Count - getUcredSvuidOff;

        // kernel_set_ucred_svuid (offset 0x0C)
        int setUcredSvuidOff = EmitUcredSetter4(0x0C);
        _kernelSetUcredSvuidBytes = b.Count - setUcredSvuidOff;

        // kernel_get_ucred_rgid (offset 0x14)
        int getUcredRgidOff = EmitUcredGetter4(0x14);
        _kernelGetUcredRgidBytes = b.Count - getUcredRgidOff;

        // kernel_set_ucred_rgid (offset 0x14)
        int setUcredRgidOff = EmitUcredSetter4(0x14);
        _kernelSetUcredRgidBytes = b.Count - setUcredRgidOff;

        // kernel_get_ucred_svgid (offset 0x18)
        int getUcredSvgidOff = EmitUcredGetter4(0x18);
        _kernelGetUcredSvgidBytes = b.Count - getUcredSvgidOff;

        // kernel_set_ucred_svgid (offset 0x18)
        int setUcredSvgidOff = EmitUcredSetter4(0x18);
        _kernelSetUcredSvgidBytes = b.Count - setUcredSvgidOff;

        // kernel_get_ucred_ngroups (offset 0x10)
        int getUcredNgroupsOff = EmitUcredGetter4(0x10);
        _kernelGetUcredNgroupsBytes = b.Count - getUcredNgroupsOff;

        // kernel_set_ucred_ngroups (offset 0x10)
        int setUcredNgroupsOff = EmitUcredSetter4(0x10);
        _kernelSetUcredNgroupsBytes = b.Count - setUcredNgroupsOff;

        // kernel_set_ucred_sce_attr0 (single byte at offset 0x83)
        // Stores the low byte of the int argument (sil) and performs a 1-byte copyin.
        // Uses the imm32 form of ADD for the ucred offset because 0x83 exceeds the
        // signed byte range and would be sign-extended to a negative value in the
        // imm8 encoding.
        int setUcredSceAttr0Off;
        {
            int off = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5]);                   // push rbp ; mov rbp, rsp
            b.AddRange([0x48, 0x83, 0xEC, 0x10]);                   // sub rsp, 0x10
            b.AddRange([0x40, 0x88, 0x75, 0xFC]);                   // mov [rbp-4], sil (save low byte)
            EmitCallGetProcUcred();                                   // call kernel_get_proc_ucred (rdi = pid)
            b.AddRange([0x48, 0x85, 0xC0]);                          // test rax, rax
            b.AddRange([0x74, 0x00]);                                // je .Lfail
            int failJump = b.Count - 1;
            b.AddRange([0x48, 0x05, 0x83, 0x00, 0x00, 0x00]);       // add rax, 0x83 (imm32)
            b.AddRange([0x48, 0x89, 0xC6]);                          // mov rsi, rax (kaddr)
            b.AddRange([0x48, 0x8D, 0x7D, 0xFC]);                   // lea rdi, [rbp-4] (uaddr = &val)
            b.AddRange([0xBA, 0x01, 0, 0, 0]);                      // mov edx, 1
            EmitCallCopyin();                                         // call kernel_copyin
            b.AddRange([0xF7, 0xD8]);                                // neg eax
            b.AddRange([0x19, 0xC0]);                                // sbb eax, eax
            b.AddRange([0xEB, 0x05]);                                // jmp .Lret
            int fail = b.Count;
            b[failJump] = (byte)(fail - (failJump + 1));
            b.AddRange([0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);             // mov eax, -1
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);       // add rsp, 0x10 ; pop rbp ; ret
            setUcredSceAttr0Off = off;
        }
        _kernelSetUcredSceAttr0Bytes = b.Count - setUcredSceAttr0Off;

        // Record offsets for new functions
        _kernelSetshortOff = setshortOff;
        _kernelSetcharOff = setcharOff;
        _kernelGetshortOff = getshortOff;
        _kernelGetcharOff = getcharOff;
        _kernelSetQaflagsOff = setQaflagsOff;
        _kernelGetFwVersionOff = getFwVersionOff;
        _kernelGetProcThreadOff = getProcThreadOff;
        _kernelGetProcFileOff = getProcFileOff;
        _kernelGetVmemProtectionOff = getVmemProtectionOff;
        _kernelOverlapSocketsOff = overlapSocketsOff;
        _kernelGetUcredUidOff = getUcredUidOff;
        _kernelSetUcredUidOff = setUcredUidOff;
        _kernelGetUcredRuidOff = getUcredRuidOff;
        _kernelSetUcredRuidOff = setUcredRuidOff;
        _kernelGetUcredSvuidOff = getUcredSvuidOff;
        _kernelSetUcredSvuidOff = setUcredSvuidOff;
        _kernelGetUcredRgidOff = getUcredRgidOff;
        _kernelSetUcredRgidOff = setUcredRgidOff;
        _kernelGetUcredSvgidOff = getUcredSvgidOff;
        _kernelSetUcredSvgidOff = setUcredSvgidOff;
        _kernelGetUcredNgroupsOff = getUcredNgroupsOff;
        _kernelSetUcredNgroupsOff = setUcredNgroupsOff;
        _kernelSetUcredSceAttr0Off = setUcredSceAttr0Off;

        // ---- Patch intra-section calls for kernel.c functions ----
        foreach (var (at, target) in kernelCallDisps)
        {
            int off = target switch
            {
                "get_proc" => kernelGetProcOff,
                "copyout" => kernelCopyoutOff,
                "copyin" => kernelCopyinOff,
                "dynlib_obj" => kernelDynlibObjOff,
                "get_proc_ucred" => getProcUcredOff,
                "get_proc_filedesc" => getProcFiledescOff,
                "get_vmem_entry" => getVmemEntryOff,
                "set_vmem_protection" => setVmemProtOff2,
                "crt_syscall" => crtSyscallOff,
                "kernel_write" => kernelWriteOff,
                "getlong_inline" => getlongOff,
                "get_proc_file" => getProcFileOff,
                _ => throw new InvalidOperationException($"Unknown kernel call target: {target}"),
            };
            WriteDispFrom(at, off);
        }

        // ============================================================================
        // __sp_klog_copyout_err(edi = copyout return code)
        //
        // Diagnostic-only helper that formats the copyout error code as two hex
        // digits and logs "sp:copyout:err=0xNN\n" through __prospero_klog. The
        // string is built entirely on the stack from immediate constants so no
        // rodata reference is needed.
        // ============================================================================
        int klogCopyoutErrOff = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            klogCopyoutErrOff = b.Count;
            b.AddRange([0x55]);                                          // push rbp
            b.AddRange([0x48, 0x89, 0xE5]);                              // mov rbp, rsp
            b.AddRange([0x48, 0x83, 0xEC, 0x20]);                        // sub rsp, 0x20
            b.AddRange([0x89, 0xFA]);                                    // mov edx, edi (save err code)
            // "sp:copyo" as imm64 (little-endian: s=73 p=70 :=3A c=63 o=6F p=70 y=79 o=6F)
            b.AddRange([0x48, 0xB8, 0x73, 0x70, 0x3A, 0x63, 0x6F, 0x70, 0x79, 0x6F]);
            b.AddRange([0x48, 0x89, 0x45, 0xE0]);                        // mov [rbp-0x20], rax
            // "ut:err=0" as imm64 (little-endian: u=75 t=74 :=3A e=65 r=72 r=72 ==3D 0=30)
            b.AddRange([0x48, 0xB8, 0x75, 0x74, 0x3A, 0x65, 0x72, 0x72, 0x3D, 0x30]);
            b.AddRange([0x48, 0x89, 0x45, 0xE8]);                        // mov [rbp-0x18], rax
            b.AddRange([0xC6, 0x45, 0xF0, 0x78]);                        // mov byte [rbp-0x10], 'x' (0x78)
            // High nibble: negate, shift right 4, convert to hex ASCII
            b.AddRange([0x89, 0xD0]);                                    // mov eax, edx
            b.AddRange([0xF7, 0xD8]);                                    // neg eax
            b.AddRange([0xC0, 0xE8, 0x04]);                              // shr al, 4
            b.AddRange([0x04, 0x30]);                                    // add al, '0'
            b.AddRange([0x3C, 0x3A]);                                    // cmp al, '0'+10
            b.AddRange([0x72, 0x02]);                                    // jb .Lok_hi
            b.AddRange([0x04, 0x27]);                                    // add al, 'a'-'0'-10
            // .Lok_hi:
            b.AddRange([0x88, 0x45, 0xF1]);                              // mov [rbp-0x0F], al
            // Low nibble: negate, mask, convert to hex ASCII
            b.AddRange([0x89, 0xD0]);                                    // mov eax, edx
            b.AddRange([0xF7, 0xD8]);                                    // neg eax
            b.AddRange([0x24, 0x0F]);                                    // and al, 0x0F
            b.AddRange([0x04, 0x30]);                                    // add al, '0'
            b.AddRange([0x3C, 0x3A]);                                    // cmp al, '0'+10
            b.AddRange([0x72, 0x02]);                                    // jb .Lok_lo
            b.AddRange([0x04, 0x27]);                                    // add al, 'a'-'0'-10
            // .Lok_lo:
            b.AddRange([0x88, 0x45, 0xF2]);                              // mov [rbp-0x0E], al
            // Append "\n\0"
            b.AddRange([0xC6, 0x45, 0xF3, 0x0A]);                        // mov byte [rbp-0x0D], '\n'
            b.AddRange([0xC6, 0x45, 0xF4, 0x00]);                        // mov byte [rbp-0x0C], 0
            // Call klog with the formatted string
            b.AddRange([0x48, 0x8D, 0x7D, 0xE0]);                        // lea rdi, [rbp-0x20]
            b.AddRange([0xE8, 0x00, 0x00, 0x00, 0x00]);                  // call __prospero_klog
            int klogCopyoutErrKlogDisp = b.Count - 4;
            b.AddRange([0x48, 0x83, 0xC4, 0x20]);                        // add rsp, 0x20
            b.AddRange([0x5D]);                                          // pop rbp
            b.AddRange([0xC3]);                                          // ret

            // Wire the helper's internal klog call
            WriteDispFrom(klogCopyoutErrKlogDisp, klogOff);
            // Wire each call-site's call to this helper
            foreach (int disp in copyoutErrCallDisps)
                WriteDispFrom(disp, klogCopyoutErrOff);
        }

        // ============================================================================
        // rodata pool at end of text (all NUL-terminated).
        // ============================================================================
        int pthreadSelfOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(PthreadSelfName));
        b.Add(0);
        // Patch the _start pthread_self priming LEAs now that the rodata offset is known.
        WriteDispTo(startPthreadSelfNameLea1At, pthreadSelfOff);
        WriteDispTo(startPthreadSelfNameLea2At, pthreadSelfOff);
        int sceKernelDlsymOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SceKernelDlsymName));
        b.Add(0);
        int getpidOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(GetpidName));
        b.Add(0);
        int spFixupStartOff = -1, spFixupDoneOff = -1, spKernelInitOkOff = -1, spCrtEnterOff = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            spFixupStartOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpFixupStartName));
            b.Add(0);
            spFixupDoneOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpFixupDoneName));
            b.Add(0);
            spKernelInitOkOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpKernelInitOkName));
            b.Add(0);
            spCrtEnterOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpCrtEnterName));
            b.Add(0);
        }
        int spTcbSetRodataOff = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            spTcbSetRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpTcbSetName));
            b.Add(0);
        }
        int spKernelInitDegenOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpKernelInitDegenName));
        b.Add(0);
        int seedOff = b.Count;
        b.AddRange(tcbSeed);
        int nidSaltRodataOff = b.Count;
        b.AddRange([0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1,
                    0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30]); // 16-byte SHA-1 salt
        int nidB64CharsetRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"));
        int spPatchOkRodataOff = -1, spKlogOkRodataOff = -1, spRtldOkRodataOff = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            // RTLD orchestration success-path rodata strings
            spPatchOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpPatchOkName)); b.Add(0);
            spKlogOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpKlogOkName)); b.Add(0);
            spRtldOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpRtldOkName)); b.Add(0);
        }
        int snprintfRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SnprintfName)); b.Add(0);
        int vsnprintfRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(VsnprintfName)); b.Add(0);
        int strerrorRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrerrorName)); b.Add(0);
        int errorRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(ErrorName)); b.Add(0);
        int strcpyRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrcpyName)); b.Add(0);
        int strcatRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrcatName)); b.Add(0);
        int strcmpRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrcmpName)); b.Add(0);
        int strncmpRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrncmpName)); b.Add(0);
        int strlenRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrlenName)); b.Add(0);
        int sprintfRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SprintfName)); b.Add(0);
        int callocRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(CallocName)); b.Add(0);
        int freeRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FreeName)); b.Add(0);
        int getenvRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(GetenvName)); b.Add(0);
        int strerrorUnderscoreRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(StrerrorUnderscoreName)); b.Add(0);
        int memcpyRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(MemcpyName)); b.Add(0);
        int mallocRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(MallocName)); b.Add(0);
        // _start breadcrumbs (error-path)
        int spCrtSyscallInitFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpCrtSyscallInitFailName)); b.Add(0);
        int spMainEnterRodataOff = -1, spExitRodataOff = -1;
        int spInitSyscallRodataOff = -1, spInitKernelRodataOff = -1;
        int spInitKlogRodataOff = -1, spInitPatchRodataOff = -1;
        int spInitRtldRodataOff = -1, spInitDoneRodataOff = -1;
        int spResolveOkRodataOff = -1;
        int spIsthreadedOkRodataOff = -1, spIsthreadedFailRodataOff = -1;
        int spPayloadRunEnterRodataOff = -1, spMainExitRodataOff = -1;
        int spPayloadTerminateRodataOff = -1;
        int spRtldSprxInitRodataOff = -1, spRtldSoInitRodataOff = -1;
        int spRtldPayloadInitStartRodataOff = -1, spRtldPayloadInitDoneRodataOff = -1;
        int spRtldDlfcnInitRodataOff = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            spMainEnterRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpMainEnterName)); b.Add(0);
            spExitRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpExitName)); b.Add(0);
            // init-step success-path breadcrumbs
            spInitSyscallRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpInitSyscallName)); b.Add(0);
            spInitKernelRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpInitKernelName)); b.Add(0);
        }
        int spInitKernelFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpInitKernelFailName)); b.Add(0);
        if (EmitDiagnosticBreadcrumbs)
        {
            spInitKlogRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpInitKlogName)); b.Add(0);
            spInitPatchRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpInitPatchName)); b.Add(0);
            spInitRtldRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpInitRtldName)); b.Add(0);
            spInitDoneRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpInitDoneName)); b.Add(0);
            // Per-symbol resolve success-path breadcrumbs
            spResolveOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpResolveOkName)); b.Add(0);
            // CRT orchestrator checkpoint breadcrumbs
            spIsthreadedOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpIsthreadedOkName)); b.Add(0);
            spIsthreadedFailRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpIsthreadedFailName)); b.Add(0);
            spPayloadRunEnterRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpPayloadRunEnterName)); b.Add(0);
            spMainExitRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpMainExitName)); b.Add(0);
            spPayloadTerminateRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpPayloadTerminateName)); b.Add(0);
            // RTLD subsystem init checkpoint breadcrumbs
            spRtldSprxInitRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpRtldSprxInitName)); b.Add(0);
            spRtldSoInitRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpRtldSoInitName)); b.Add(0);
            spRtldPayloadInitStartRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpRtldPayloadInitStartName)); b.Add(0);
            spRtldPayloadInitDoneRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpRtldPayloadInitDoneName)); b.Add(0);
            spRtldDlfcnInitRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpRtldDlfcnInitName)); b.Add(0);
        }
        int spResolveMissRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpResolveMissName)); b.Add(0);
        // Resolver walk breadcrumbs (error-path unconditional)
        int spDlWalkMissRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkMissName)); b.Add(0);
        int spDlFbMissRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlFbMissName)); b.Add(0);
        int spDlWalkObjOkRodataOff = -1;
        var siResolveRodataOffs = new List<int>();
        if (EmitDiagnosticBreadcrumbs)
        {
            spDlWalkObjOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkObjOkName)); b.Add(0);
            // Per-resolve breadcrumbs for sprx_init (sp:si:1 through sp:si:N)
            for (int ri = 0; ri < siResolveLeaAts.Count; ri++)
            {
                siResolveRodataOffs.Add(b.Count);
                b.AddRange(Encoding.ASCII.GetBytes($"sp:si:{ri + 1}\n")); b.Add(0);
            }
        }
        int spDlWalkObjFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkObjFailName)); b.Add(0);
        int spDlWalkMetaFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkMetaFailName)); b.Add(0);
        int spDlWalkMmapFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkMmapFailName)); b.Add(0);
        int spDlWalkCopyFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkCopyFailName)); b.Add(0);
        int spDlWalkSymMissRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkSymMissName)); b.Add(0);
        int spDlWalkProcZeroRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkProcZeroName)); b.Add(0);
        int spDlWalkHandleMissRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkHandleMissName)); b.Add(0);
        int spDlWalkAllprocFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkAllprocFailName)); b.Add(0);
        int spDlWalkPidMissRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpDlWalkPidMissName)); b.Add(0);
        // dlfcn name strings
        int sceKernelLoadStartModuleRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SceKernelLoadStartModuleName)); b.Add(0);
        int sceKernelStopUnloadModuleRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SceKernelStopUnloadModuleName)); b.Add(0);
        int dlfcnGetargcRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("getargc")); b.Add(0);
        int dlfcnGetargvRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("getargv")); b.Add(0);
        int dlfcnEnvironRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("environ")); b.Add(0);
        // Payload rodata strings
        int payloadSonameRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(PayloadSoname)); b.Add(0);
        int spPayloadLoadFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpPayloadLoadFailName)); b.Add(0);
        int spPayloadRelocUnsupRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SpPayloadRelocUnsupName)); b.Add(0);
        int spPayloadOpenOkRodataOff = -1;
        if (EmitDiagnosticBreadcrumbs)
        {
            spPayloadOpenOkRodataOff = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SpPayloadOpenOkName)); b.Add(0);
        }
        // sprx_init rodata strings
        int libSceSysmoduleSprxRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(LibSceSysmoduleSprxName)); b.Add(0);
        int libSceSysmodulePathRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(LibSceSysmodulePathName)); b.Add(0);
        int sceSysmodLoadModInternalRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SceSysmoduleLoadModuleInternalName)); b.Add(0);
        int soResolveFailRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SoResolveFailName)); b.Add(0);
        // so_open rodata: error/diagnostic strings
        int soOpenStrCloseRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("close")); b.Add(0);
        int soOpenStrLseekRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("lseek")); b.Add(0);
        int soOpenStrOpenRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("open")); b.Add(0);
        int soOpenStrMallocRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("malloc")); b.Add(0);
        int soOpenStrReadRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("read")); b.Add(0);
        int soOpenStrMprotectRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("mprotect")); b.Add(0);
        int soOpenStrNotSharedRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("%s: Not a shared object\n")); b.Add(0);
        int soOpenStrUnsupRelaRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("Unsupported relocation type %x\n")); b.Add(0);
        int soOpenStrUnsupPltRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("Unsupported plt relocation type %x\n")); b.Add(0);
        int soOpenStrUnableLoadRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("%s: unable to load '%s'\n")); b.Add(0);
        int soOpenStrUnableResolveRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("%s: unable to resolve '%s'\n")); b.Add(0);

        // so_open rodata: jump table 1 (DT_ tag switch, 29 entries = 0x74 bytes)
        // Each entry is a 4-byte relative offset from the table base to the target
        // code location within so_open. Filled in by WriteDispTo wiring below.
        int soOpenJmpTbl1RodataOff = b.Count;
        for (int i = 0; i < 29; i++) b.AddRange([0x00, 0x00, 0x00, 0x00]);

        // so_open rodata: jump table 2 (relocation type switch, 9 entries = 0x24 bytes)
        int soOpenJmpTbl2RodataOff = b.Count;
        for (int i = 0; i < 9; i++) b.AddRange([0x00, 0x00, 0x00, 0x00]);

        // find_file format strings
        int ffSysPrivLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfSysPrivLib)); b.Add(0);
        int ffSysCommonLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfSysCommonLib)); b.Add(0);
        int ffSysExPrivExLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfSysExPrivExLib)); b.Add(0);
        int ffSysExCommonExLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfSysExCommonExLib)); b.Add(0);
        int ffRandPrivLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfRandPrivLib)); b.Add(0);
        int ffRandCommonLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfRandCommonLib)); b.Add(0);
        int ffRandPrivExLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfRandPrivExLib)); b.Add(0);
        int ffRandCommonExLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfRandCommonExLib)); b.Add(0);
        int ffLdLibraryPathRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfLdLibraryPath)); b.Add(0);
        int ffHomebrewLibRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfHomebrewLib)); b.Add(0);
        int ffCwdFmtRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(FfCwdFmt)); b.Add(0);
        int sprxSuffixRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(SprxSuffix)); b.Add(0);
        // CRT orchestrator rodata (payload_init / payload_run / payload_terminate)
        int isthreadedNameRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(IsthreadedName)); b.Add(0);
        int isthreadedFailMsgRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(IsthreadedFailMsg)); b.Add(0);
        int patchFailMsgRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(PatchFailMsg)); b.Add(0);
        int rtldFailMsgRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(RtldFailMsg)); b.Add(0);
        int prognameRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(PrognameName)); b.Add(0);
        int exitNameRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(ExitName)); b.Add(0);
        int emptyStringRodataOff = b.Count;
        b.Add(0); // empty string for progname fallback
        // klog consumer format strings
        int klogPidFmtRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(KlogPidFmt)); b.Add(0);
        int klogPutsFmtRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(KlogPutsFmt)); b.Add(0);
        int klogPrintfFmtRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(KlogPrintfFmt)); b.Add(0);
        int klogPerrorFmtRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes(KlogPerrorFmt)); b.Add(0);
        // sysmodtab name strings (137 NUL-terminated names for the sysmod lookup table)
        _sysmodtabStringOffs = new int[SysmodEntries.Length];
        for (int si = 0; si < SysmodEntries.Length; si++)
        {
            _sysmodtabStringOffs[si] = b.Count;
            b.AddRange(Encoding.ASCII.GetBytes(SysmodEntries[si].Name));
            b.Add(0);
        }
        // sprx_open rodata strings (kernel library names, error messages)
        int libkernelSprxRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("libkernel.sprx")); b.Add(0);
        int libkernelWebSprxRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("libkernel_web.sprx")); b.Add(0);
        int libkernelSysSprxRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("libkernel_sys.sprx")); b.Add(0);
        int sprxoSysmodFmtRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("sceSysmoduleLoadModuleInternal: 0x%x\n")); b.Add(0);
        int sprxoUnknownErrRodataOff = b.Count;
        b.AddRange(Encoding.ASCII.GetBytes("Unknown kernel I/O error")); b.Add(0);

        void WriteDispTo(int at, int target)
        {
            int disp = target - (at + 4);
            b[at + 0] = (byte)(disp & 0xFF);
            b[at + 1] = (byte)((disp >> 8) & 0xFF);
            b[at + 2] = (byte)((disp >> 16) & 0xFF);
            b[at + 3] = (byte)((disp >> 24) & 0xFF);
        }
        // (TCB canary/seed slots are now forwarded from the host's live fs:0x28/fs:0x30
        // at TCB setup time, so no __sp_tcb_seed LEA fixup is needed here.)
        // _start CRT orchestrator rodata LEAs
        WriteDispTo(isthreadedLeaAt, isthreadedNameRodataOff);
        WriteDispTo(isthreadedFailMsgLeaAt, isthreadedFailMsgRodataOff);
        WriteDispTo(patchFailMsgLeaAt, patchFailMsgRodataOff);
        WriteDispTo(rtldFailMsgLeaAt, rtldFailMsgRodataOff);
        WriteDispTo(getargcLeaAt1, dlfcnGetargcRodataOff);
        WriteDispTo(getargcLeaAt2, dlfcnGetargcRodataOff);
        WriteDispTo(getargvLeaAt1, dlfcnGetargvRodataOff);
        WriteDispTo(getargvLeaAt2, dlfcnGetargvRodataOff);
        WriteDispTo(environLeaAt1, dlfcnEnvironRodataOff);
        WriteDispTo(environLeaAt2, dlfcnEnvironRodataOff);
        WriteDispTo(prognameLeaAt1, prognameRodataOff);
        WriteDispTo(prognameLeaAt2, prognameRodataOff);
        WriteDispTo(emptyStringLeaAt, emptyStringRodataOff);
        // _start diagnostic breadcrumb rodata LEAs
        if (EmitDiagnosticBreadcrumbs)
        {
            WriteDispTo(bcTcbSetLeaAt, spTcbSetRodataOff);
            WriteDispTo(bcCrtEnterLeaAt, spCrtEnterOff);
            WriteDispTo(bcInitSyscallLeaAt, spInitSyscallRodataOff);
            WriteDispTo(bcInitKernelLeaAt, spInitKernelRodataOff);
            WriteDispTo(bcKernelInitOkLeaAt, spKernelInitOkOff);
            WriteDispTo(bcInitKlogLeaAt, spInitKlogRodataOff);
            WriteDispTo(bcInitPatchLeaAt, spInitPatchRodataOff);
            WriteDispTo(bcInitRtldLeaAt, spInitRtldRodataOff);
            WriteDispTo(bcInitDoneLeaAt, spInitDoneRodataOff);
            WriteDispTo(bcMainEnterLeaAt, spMainEnterRodataOff);
            // CRT orchestrator checkpoint LEAs
            WriteDispTo(bcIsthreadedOkLeaAt, spIsthreadedOkRodataOff);
            WriteDispTo(bcIsthreadedFailLeaAt, spIsthreadedFailRodataOff);
            WriteDispTo(bcPayloadRunEnterLeaAt, spPayloadRunEnterRodataOff);
            WriteDispTo(bcMainExitLeaAt, spMainExitRodataOff);
            WriteDispTo(bcPayloadTerminateLeaAt, spPayloadTerminateRodataOff);
            // RTLD subsystem init checkpoint LEAs
            WriteDispTo(bcRtldSprxInitLeaAt, spRtldSprxInitRodataOff);
            WriteDispTo(bcRtldSoInitLeaAt, spRtldSoInitRodataOff);
            WriteDispTo(bcRtldPayloadInitStartLeaAt, spRtldPayloadInitStartRodataOff);
            WriteDispTo(bcRtldPayloadInitDoneLeaAt, spRtldPayloadInitDoneRodataOff);
            WriteDispTo(bcRtldDlfcnInitLeaAt, spRtldDlfcnInitRodataOff);
            // fixup_got sp:fixup:done LEA
            WriteDispTo(fxDoneLeaAt, spFixupDoneOff);
        }
        // fixup_got LEAs (kept for backward compat function)
        WriteDispTo(probeNameLeaAt, sceKernelDlsymOff);
        if (EmitDiagnosticBreadcrumbs)
            WriteDispTo(fxStartLeaAt, spFixupStartOff);
        // fixup_got nop stub LEA
        WriteDispTo(fxNopStubLeaAt, nopStubOff);
        // fixup_got per-symbol resolve breadcrumb LEAs
        if (EmitDiagnosticBreadcrumbs)
            WriteDispTo(fxResolvedOkLeaAt, spResolveOkRodataOff);
        WriteDispTo(fxMissLeaAt, spResolveMissRodataOff);
        // __sp_crt_syscall_init rodata LEAs
        WriteDispTo(sciProbeNameLeaAt, sceKernelDlsymOff);
        WriteDispTo(sciFallbackNameLeaAt, sceKernelDlsymOff);
        WriteDispTo(sciGetpidLeaAt, getpidOff);
        WriteDispTo(sciGetpidFallbackLeaAt, getpidOff);
        // nid_encode rodata LEAs
        WriteDispTo(nidSaltLeaAt, nidSaltRodataOff);
        WriteDispTo(nidB64LeaAt, nidB64CharsetRodataOff);
        // klog_init rodata LEAs
        WriteDispTo(klSnprintfLeaAt, snprintfRodataOff);
        WriteDispTo(klStrerrorLeaAt, strerrorRodataOff);
        WriteDispTo(klVsnprintfLeaAt, vsnprintfRodataOff);
        WriteDispTo(klErrorLeaAt1, errorRodataOff);
        WriteDispTo(klErrorLeaAt2, errorRodataOff);
        // klog_puts rodata LEAs
        WriteDispTo(kpPidFmtLeaAt, klogPidFmtRodataOff);
        WriteDispTo(kpPutsFmtLeaAt, klogPutsFmtRodataOff);
        // klog_perror rodata LEAs
        WriteDispTo(kePidFmtLeaAt, klogPidFmtRodataOff);
        WriteDispTo(kePerrorFmtLeaAt, klogPerrorFmtRodataOff);
        // klog_printf rodata LEAs
        WriteDispTo(kfPidFmtLeaAt, klogPidFmtRodataOff);
        WriteDispTo(kfPrintfFmtLeaAt, klogPrintfFmtRodataOff);
        // rtld_init rodata LEAs
        int[] rtldRodataOffs = [strcpyRodataOff, strcatRodataOff, strcmpRodataOff,
            strncmpRodataOff, strlenRodataOff, sprintfRodataOff, callocRodataOff,
            freeRodataOff, getenvRodataOff];
        for (int ri = 0; ri < rtldLeaAts.Count; ri++) WriteDispTo(rtldLeaAts[ri], rtldRodataOffs[ri]);
        // (kernel_dynlib_dlsym omits breadcrumb LEAs)
        if (EmitDiagnosticBreadcrumbs)
            WriteDispTo(drsvObjOkLeaAt, spDlWalkObjOkRodataOff);
        WriteDispTo(drsvObjFailLeaAt, spDlWalkObjFailRodataOff);
        WriteDispTo(drsvMetaFailLeaAt, spDlWalkMetaFailRodataOff);
        WriteDispTo(drsvMmapFailLeaAt, spDlWalkMmapFailRodataOff);
        WriteDispTo(drsvCopyFailLeaAt, spDlWalkCopyFailRodataOff);
        WriteDispTo(drsvSymMissLeaAt, spDlWalkSymMissRodataOff);
        // kernel_dynlib_obj: SDK-exact version uses __error BSS, no rodata LEAs
        WriteDispTo(gprPidMissLeaAt, spDlWalkPidMissRodataOff);
        WriteDispTo(gprAllprocFailLeaAt, spDlWalkAllprocFailRodataOff);
        // dlfcn rodata LEAs
        // (sprx_init LEA patches moved to the sprx_init rodata LEAs block below)
        WriteDispTo(diCallocLeaAt, callocRodataOff);
        WriteDispTo(diFreeLeaAt, freeRodataOff);
        WriteDispTo(diStrerrorLeaAt, strerrorUnderscoreRodataOff);
        WriteDispTo(diGetargcLeaAt, dlfcnGetargcRodataOff);
        WriteDispTo(diGetargcFbLeaAt, dlfcnGetargcRodataOff);
        WriteDispTo(diGetargvLeaAt, dlfcnGetargvRodataOff);
        WriteDispTo(diGetargvFbLeaAt, dlfcnGetargvRodataOff);
        WriteDispTo(diEnvironLeaAt, dlfcnEnvironRodataOff);
        WriteDispTo(diEnvironFbLeaAt, dlfcnEnvironRodataOff);
        // lib_new ref vtable LEAs
        WriteDispTo(libNewRefOpenLeaAt, refOpenOff);
        WriteDispTo(libNewRefInitLeaAt, refInitOff);
        WriteDispTo(libNewRefSym2addrLeaAt, refSym2addrOff);
        WriteDispTo(libNewRefAddr2symLeaAt, refAddr2symOff);
        WriteDispTo(libNewRefFiniLeaAt, refFiniOff);
        WriteDispTo(libNewRefCloseLeaAt, refCloseOff);
        WriteDispTo(libNewRefDestroyLeaAt, refDestroyOff);
        // lib_new endswith(".sprx") LEAs
        WriteDispTo(libNewSprxSuffixLeaAt, sprxSuffixRodataOff);
        WriteDispTo(libNewSprxSuffixLeaAt2, sprxSuffixRodataOff);
        // find_file rodata LEAs
        {
            int[] ffFmtOffs = [ffSysPrivLibRodataOff, ffSysCommonLibRodataOff, ffSysExPrivExLibRodataOff, ffSysExCommonExLibRodataOff];
            for (int i = 0; i < ffFmtLeaAts.Count; i++) WriteDispTo(ffFmtLeaAts[i], ffFmtOffs[i]);
        }
        {
            int[] ffRandOffs = [ffRandPrivLibRodataOff, ffRandCommonLibRodataOff, ffRandPrivExLibRodataOff, ffRandCommonExLibRodataOff];
            for (int i = 0; i < ffRandFmtLeaAts.Count; i++) WriteDispTo(ffRandFmtLeaAts[i], ffRandOffs[i]);
        }
        WriteDispTo(ffLdLibPathLeaAt, ffLdLibraryPathRodataOff);
        WriteDispTo(ffHomebrewLeaAt, ffHomebrewLibRodataOff);
        WriteDispTo(ffCwdFmtLeaAt, ffCwdFmtRodataOff);
        WriteDispTo(ffCrtSyscallLeaAt, crtSyscallOff);
        // Payload rodata LEAs
        WriteDispTo(poLoadFailLeaAt, spPayloadLoadFailRodataOff);
        WriteDispTo(poRelocUnsupLeaAt, spPayloadRelocUnsupRodataOff);
        WriteDispTo(poResolveMissLeaAt, spResolveMissRodataOff);
        // payload_open _DYNAMIC LEAs (uses linker-provided _DYNAMIC)
        // The disp32 LEAs in _payloadRelocs target rodata, patched here.
        // AddRel(RelocSymbol.Dynamic) entries are linker relocs, not intra-section patches.
        // payload_open lea rsi, [rip+_DYNAMIC] requires a linker reloc, not intra-section patching.
        // Placeholder zeros were emitted above; proper reloc entries are added below.
        // _DYNAMIC is a linker-provided symbol requiring reloc entries in _payloadRelocs.
        // The lea [rip+_DYNAMIC] at poOpenDynamicLeaAt and poNeededDynamicLeaAt need
        // linker relocs, not intra-section patches. Placeholder zeros were emitted; relocs follow.
        _payloadRelocs.Add(new Reloc(poOpenDynamicLeaAt, RelocSymbol.Dynamic, RPc32, -4));
        _payloadRelocs.Add(new Reloc(poNeededDynamicLeaAt, RelocSymbol.Dynamic, RPc32, -4));
        // __rtld_payload_new LEAs for vtable slots and linker symbols
        WriteDispTo(pnCrtSyscallLeaAt, crtSyscallOff);
        WriteDispTo(pnOpenLeaAt, payloadOpenOff);
        WriteDispTo(pnInitVtLeaAt, payloadInitVtableOff);
        WriteDispTo(pnSym2addrVtLeaAt, payloadSym2addrOff);
        WriteDispTo(pnAddr2symVtLeaAt, payloadAddr2symOff);
        WriteDispTo(pnFiniVtLeaAt, payloadFiniVtableOff);
        WriteDispTo(pnCloseVtLeaAt, payloadCloseOff);
        WriteDispTo(pnDestroyVtLeaAt, payloadDestroyOff);
        // __rtld_payload_new linker symbol LEAs
        _payloadRelocs.Add(new Reloc(pnImageStartLeaAt, RelocSymbol.ImageStart, RPc32, -4));
        _payloadRelocs.Add(new Reloc(pnImageEndLeaAt, RelocSymbol.BssEnd, RPc32, -4));
        // __rtld_so_init rodata LEAs
        int[] soRodataOffs = [strcmpRodataOff, strcpyRodataOff, mallocRodataOff, callocRodataOff, memcpyRodataOff, freeRodataOff];
        for (int si = 0; si < soLeaAts.Count; si++) WriteDispTo(soLeaAts[si], soRodataOffs[si]);
        // so_r_glob_dat rodata LEA
        WriteDispTo(sgResolveFailLeaAt, soResolveFailRodataOff);
        // so_open rodata LEAs (string references)
        WriteDispTo(soOpenStrCloseLeaAt, soOpenStrCloseRodataOff);
        WriteDispTo(soOpenStrLseekLeaAt, soOpenStrLseekRodataOff);
        WriteDispTo(soOpenStrOpenLeaAt, soOpenStrOpenRodataOff);
        WriteDispTo(soOpenStrMallocLeaAt, soOpenStrMallocRodataOff);
        WriteDispTo(soOpenStrReadLeaAt, soOpenStrReadRodataOff);
        WriteDispTo(soOpenStrMprotectLeaAt, soOpenStrMprotectRodataOff);
        WriteDispTo(soOpenStrNotSharedLeaAt, soOpenStrNotSharedRodataOff);
        WriteDispTo(soOpenStrUnsupRelaLeaAt, soOpenStrUnsupRelaRodataOff);
        WriteDispTo(soOpenStrUnsupPltLeaAt, soOpenStrUnsupPltRodataOff);
        WriteDispTo(soOpenStrUnableLoadLeaAt, soOpenStrUnableLoadRodataOff);
        WriteDispTo(soOpenStrUnableResolveLeaAt, soOpenStrUnableResolveRodataOff);
        // so_open rodata LEAs (jump table pointers)
        WriteDispTo(soOpenJmpTbl1LeaAt, soOpenJmpTbl1RodataOff);
        WriteDispTo(soOpenJmpTbl2LeaAt1, soOpenJmpTbl2RodataOff);
        WriteDispTo(soOpenJmpTbl2LeaAt2, soOpenJmpTbl2RodataOff);
        WriteDispTo(soOpenKlogPrintfLeaAt, klogPrintfOff);
        // so_open jump table 1 entries (DT_ tag dispatch at so_open+0x2d3)
        // Maps DT_ tag values 0..0x1c to code offsets within so_open.
        // Each entry = target_code_offset - jump_table_base_offset (4-byte signed).
        // SDK mapping from .rodata.so_open relocations:
        //  [0]=0x3a0 (DT_NULL→gnu_hash_size), [1]=0x2d3 (default→loop), [2]=0x2ee (DT_PLTRELSZ→skip),
        //  [3]=0x2db (DT_HASH→skip), [4]=0x2df (→skip), [5]=0x395 (DT_STRTAB→store),
        //  [6]=0x37f (DT_SYMTAB→store), [7]=0x2eb (DT_RELA→store), [8]=0x2ef (DT_RELASZ→store),
        //  [9]=0x2f3 (→skip), [10]=0x2f7 (DT_STRSZ→store), [11]=0x2fb (DT_SYMENT→skip),
        //  [12]=0x2ff (DT_INIT→skip), [13]=0x303 (DT_FINI→skip), [14]=0x307 (DT_SONAME→skip),
        //  [15]=0x30b (→skip), [16]=0x30f (→skip), [17]=0x313 (→skip), [18]=0x317 (→skip),
        //  [19]=0x31b (→skip), [20]=0x31f (DT_JMPREL→skip), [21]=0x323 (→skip),
        //  [22]=0x327 (→skip), [23]=0x392 (DT_JMPREL→store), [24]=0x32f (→skip),
        //  [25]=0x373 (DT_INIT_ARRAY→store), [26]=0x3b5 (DT_INIT_ARRAYSZ→skip),
        //  [27]=0x392 (→skip), [28]=0x335 (DT_FINI_ARRAY→skip)
        {
            // Map of DT_ tag index → SDK code offset within so_open
            int[] jt1SdkTargets = [
                0x3a0, 0x2d3, 0x2ee, 0x2db, 0x2df, 0x395, 0x37f, 0x2eb,
                0x2ef, 0x2f3, 0x2f7, 0x2fb, 0x2ff, 0x303, 0x307, 0x30b,
                0x30f, 0x313, 0x317, 0x31b, 0x31f, 0x323, 0x327, 0x392,
                0x32f, 0x373, 0x3b5, 0x392, 0x335,
            ];
            for (int i = 0; i < 29; i++)
            {
                int codeOff = soOpenOff + jt1SdkTargets[i]; // absolute position in b
                int tableEntry = soOpenJmpTbl1RodataOff + i * 4; // absolute position of entry in b
                int disp = codeOff - soOpenJmpTbl1RodataOff; // relative to table base
                b[tableEntry + 0] = (byte)(disp & 0xFF);
                b[tableEntry + 1] = (byte)((disp >> 8) & 0xFF);
                b[tableEntry + 2] = (byte)((disp >> 16) & 0xFF);
                b[tableEntry + 3] = (byte)((disp >> 24) & 0xFF);
            }
        }
        // so_open jump table 2 entries (relocation type switch at so_open+0x511)
        // Maps (rela_type - 1) values 0..8 to code offsets within so_open.
        // SDK mapping from .rodata.so_open+0x70 relocations:
        //  [0]=0x335 (R_X86_64_64→direct), [1]=0x5d0 (R_X86_64_GLOB_DAT→resolve),
        //  [2]=0x783 (→unsup), [3]=0x787 (→unsup), [4]=0x78b (→unsup),
        //  [5]=0x78f (→unsup), [6]=0x5c7 (→relative?), [7]=0x5cb (→relative?),
        //  [8]=0x6bc (→64_handler)
        {
            int[] jt2SdkTargets = [
                0x335, 0x5d0, 0x783, 0x787, 0x78b, 0x78f, 0x5c7, 0x5cb, 0x6bc,
            ];
            for (int i = 0; i < 9; i++)
            {
                int codeOff = soOpenOff + jt2SdkTargets[i];
                int tableEntry = soOpenJmpTbl2RodataOff + i * 4;
                int disp = codeOff - soOpenJmpTbl2RodataOff;
                b[tableEntry + 0] = (byte)(disp & 0xFF);
                b[tableEntry + 1] = (byte)((disp >> 8) & 0xFF);
                b[tableEntry + 2] = (byte)((disp >> 16) & 0xFF);
                b[tableEntry + 3] = (byte)((disp >> 24) & 0xFF);
            }
        }
        // __rtld_payload_init rodata LEAs
        int[] piRodataOffs = [callocRodataOff, memcpyRodataOff, freeRodataOff, strcpyRodataOff, strcmpRodataOff];
        for (int pi = 0; pi < piLeaAts.Count; pi++) WriteDispTo(piLeaAts[pi], piRodataOffs[pi]);
        // __rtld_sprx_init rodata LEAs and intra-section calls
        WriteDispTo(siProbeLeaAt, sceKernelDlsymOff);
        // sprx_init resolves: sceKernelLoadStartModule, sceKernelStopUnloadModule, strcpy, strcmp, strncmp, calloc, malloc, free
        int[] siRodataOffs = [sceKernelLoadStartModuleRodataOff, sceKernelStopUnloadModuleRodataOff,
            strcpyRodataOff, strcmpRodataOff, strncmpRodataOff, callocRodataOff, mallocRodataOff, freeRodataOff];
        for (int si = 0; si < siLeaAts.Count; si++) WriteDispTo(siLeaAts[si], siRodataOffs[si]);
        // Per-resolve diagnostic breadcrumb LEA + klog call patches
        if (EmitDiagnosticBreadcrumbs)
        {
            for (int si = 0; si < siResolveLeaAts.Count; si++)
            {
                WriteDispTo(siResolveLeaAts[si], siResolveRodataOffs[si]);
                WriteDispFrom(siResolveKlogCallDisps[si], klogPutsOff);
            }
        }
        WriteDispTo(siSysmodNameLeaAt, libSceSysmoduleSprxRodataOff);
        WriteDispTo(siSysmodPathLeaAt, libSceSysmodulePathRodataOff);
        WriteDispTo(siSysmodResolveLeaAt, sceSysmodLoadModInternalRodataOff);
        // __rtld_sprx_new vtable LEAs
        WriteDispTo(snVtOpenLeaAt, sprxOpenOff);
        WriteDispTo(snVtInitLeaAt, sprxInitStubOff);     // init (xor eax; ret)
        WriteDispTo(snVtSym2addrLeaAt, sprxSym2addrOff); // sym2addr (full NID-walk)
        WriteDispTo(snVtAddr2symLeaAt, sprxAddr2symOff); // addr2sym (full address scan)
        WriteDispTo(snVtFiniLeaAt, sprxFiniStubOff);     // fini (xor eax; ret)
        WriteDispTo(snVtCloseLeaAt, sprxCloseOff);
        WriteDispTo(snVtDestroyLeaAt, sprxDestroyOff);
        // sprx_open rodata LEAs (kernel library names, format strings, error messages)
        WriteDispTo(sprxoLibkernelLeaAt, libkernelSprxRodataOff);
        WriteDispTo(sprxoLibkernelWebLeaAt, libkernelWebSprxRodataOff);
        WriteDispTo(sprxoLibkernelSysLeaAt, libkernelSysSprxRodataOff);
        WriteDispTo(sprxoSysmodFmtLeaAt, sprxoSysmodFmtRodataOff);
        WriteDispTo(sprxoSceKernelDlsymLeaAt, sceKernelDlsymOff);
        WriteDispTo(sprxoUnknownErrLeaAt, sprxoUnknownErrRodataOff);
        WriteDispTo(sprxoMallocErrLeaAt, mallocRodataOff);
        // __rtld_so_new vtable LEAs (SDK-matching implementations)
        WriteDispTo(soNVtOpenLeaAt, soOpenOff);
        WriteDispTo(soNVtInitLeaAt, soInitVtOff);
        WriteDispTo(soNVtSym2addrLeaAt, soSym2addrOff);
        WriteDispTo(soNVtAddr2symLeaAt, soAddr2symOff);
        WriteDispTo(soNVtFiniLeaAt, soFiniOff);
        WriteDispTo(soNVtCloseLeaAt, soCloseOff);
        WriteDispTo(soNVtDestroyLeaAt, soDestroyOff);

        // ============================================================================
        // kernel_get_proc_ucred + ucred get/set + mdbg + kernel_procio subsystems
        // ============================================================================
        int kernelGetProcUcredOff = b.Count;
        _currentRelocs = _ucredRelocs;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int gpuGetProcCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]); int ucredProcFailJ1 = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x78, 0x40, 0x48, 0x8D, 0x75, 0xF8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int gpuCopyoutCall = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x00]); int ucredProcFailJ2 = b.Count - 1;
        b.AddRange([0x48, 0x8B, 0x45, 0xF8, 0xEB, 0x02]);
        int ucredProcFail = b.Count; b[ucredProcFailJ1] = (byte)(ucredProcFail - (ucredProcFailJ1 + 1)); b[ucredProcFailJ2] = (byte)(ucredProcFail - (ucredProcFailJ2 + 1));
        b.AddRange([0x31, 0xC0, 0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetProcUcredBytes = b.Count - kernelGetProcUcredOff;

        int kernelGetUcredAuthidOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int guaCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]); int guaFJ1 = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x78, 0x58, 0x48, 0x8D, 0x75, 0xF8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int guaCO = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x00]); int guaFJ2 = b.Count - 1;
        b.AddRange([0x48, 0x8B, 0x45, 0xF8, 0xEB, 0x02]);
        int guaF = b.Count; b[guaFJ1] = (byte)(guaF - (guaFJ1 + 1)); b[guaFJ2] = (byte)(guaF - (guaFJ2 + 1));
        b.AddRange([0x31, 0xC0, 0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelGetUcredAuthidBytes = b.Count - kernelGetUcredAuthidOff;

        int kernelSetUcredAuthidOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0x48, 0x89, 0x75, 0xF8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int suaCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]); int suaFJ1 = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x7D, 0xF8, 0x48, 0x8D, 0x70, 0x58, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int suaCI = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x00]); int suaFJ2 = b.Count - 1;
        b.AddRange([0x31, 0xC0, 0xEB, 0x03]);
        int suaF = b.Count; b[suaFJ1] = (byte)(suaF - (suaFJ1 + 1)); b[suaFJ2] = (byte)(suaF - (suaFJ2 + 1));
        b.AddRange([0x83, 0xC8, 0xFF, 0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
        _kernelSetUcredAuthidBytes = b.Count - kernelSetUcredAuthidOff;

        int kernelGetUcredCapsOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x89, 0xF3]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int gucCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]); int gucFJ1 = b.Count - 1;
        b.AddRange([0x48, 0x8D, 0x78, 0x60, 0x48, 0x89, 0xDE, 0xBA, 0x10, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int gucCO = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x00]); int gucFJ2 = b.Count - 1;
        b.AddRange([0x31, 0xC0, 0xEB, 0x03]);
        int gucF = b.Count; b[gucFJ1] = (byte)(gucF - (gucFJ1 + 1)); b[gucFJ2] = (byte)(gucF - (gucFJ2 + 1));
        b.AddRange([0x83, 0xC8, 0xFF, 0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        _kernelGetUcredCapsBytes = b.Count - kernelGetUcredCapsOff;

        int kernelSetUcredCapsOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x89, 0xF3]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int sucCall = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x74, 0x00]); int sucFJ1 = b.Count - 1;
        b.AddRange([0x48, 0x89, 0xDF, 0x48, 0x8D, 0x70, 0x60, 0xBA, 0x10, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int sucCI = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x75, 0x00]); int sucFJ2 = b.Count - 1;
        b.AddRange([0x31, 0xC0, 0xEB, 0x03]);
        int sucF = b.Count; b[sucFJ1] = (byte)(sucF - (sucFJ1 + 1)); b[sucFJ2] = (byte)(sucF - (sucFJ2 + 1));
        b.AddRange([0x83, 0xC8, 0xFF, 0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3]);
        _kernelSetUcredCapsBytes = b.Count - kernelSetUcredCapsOff;

        // privcaps rodata (16 x 0xFF)
        int mdbgPrivcapsOff = b.Count;
        for (int pc = 0; pc < 16; pc++) b.Add(0xFF);

        // mdbg_memop(edi=memop, rsi=args) -> eax
        int mdbgMemopOff = b.Count;
        _currentRelocs = _mdbgRelocs;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x40]);
        b.AddRange([0x48, 0x89, 0xF3, 0x41, 0x89, 0xFE]);
        b.AddRange([0x48, 0xC7, 0x45, 0xB8, 0x01, 0x00, 0x00, 0x00]);
        b.AddRange([0x4C, 0x89, 0x75, 0xC0]);
        b.AddRange([0xBF, 0x14, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmSC1 = b.Count - 4;
        b.AddRange([0x41, 0x89, 0xC4]);
        b.AddRange([0x83, 0x3B, 0x00, 0x79, 0x03, 0x44, 0x89, 0x23]);
        b.AddRange([0x44, 0x89, 0xE7, 0x48, 0x8D, 0x75, 0xC8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmGC = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int mmF1 = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xE7]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmGA = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int mmF2 = b.Count - 4;
        b.AddRange([0x48, 0x89, 0x45, 0xD8]);
        b.AddRange([0x44, 0x89, 0xE7]);
        b.AddRange([0x48, 0xBE, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmSA1 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int mmF3 = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xE7, 0x48, 0x8D, 0x35, 0, 0, 0, 0]); int mmPCLea = b.Count - 4;
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmSC1b = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int mmF4 = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xED]);
        int mmLoop = b.Count;
        b.AddRange([0x48, 0xC7, 0x45, 0xA8, 0, 0, 0, 0, 0x48, 0xC7, 0x45, 0xB0, 0, 0, 0, 0]);
        b.AddRange([0xBF, 0x3D, 0x02, 0x00, 0x00, 0x48, 0x8D, 0x75, 0xB8, 0x48, 0x89, 0xDA, 0x48, 0x8D, 0x4D, 0xA8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmSC2 = b.Count - 4;
        b.AddRange([0x49, 0x89, 0xC5, 0x48, 0x83, 0xF8, 0xFF, 0x74, 0x00]); int mmBrk = b.Count - 1;
        b.AddRange([0x48, 0x8B, 0x45, 0xB0, 0x48, 0x01, 0x43, 0x08, 0x48, 0x01, 0x43, 0x10, 0x48, 0x29, 0x43, 0x18]);
        b.AddRange([0x83, 0x7D, 0xA8, 0x00, 0x74, 0x00]); int mmLE1 = b.Count - 1;
        b.AddRange([0x48, 0x83, 0x7B, 0x18, 0x00, 0x74, 0x00]); int mmLE2 = b.Count - 1;
        b.AddRange([0x48, 0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int mmLB = b.Count - 4;
        WriteRel32InBLocal(mmLB, mmLoop);
        int mmLD = b.Count;
        b[mmBrk] = (byte)(mmLD - (mmBrk + 1)); b[mmLE1] = (byte)(mmLD - (mmLE1 + 1)); b[mmLE2] = (byte)(mmLD - (mmLE2 + 1));
        b.AddRange([0x44, 0x89, 0xE7, 0x48, 0x8B, 0x75, 0xD8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmSA2 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int mmF5 = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xE7, 0x48, 0x8D, 0x75, 0xC8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mmSC2b = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int mmF6 = b.Count - 4;
        b.AddRange([0x4C, 0x89, 0xE8, 0xEB, 0x00]); int mmRJ = b.Count - 1;
        int mmFail = b.Count;
        WriteRel32InBLocal(mmF1, mmFail); WriteRel32InBLocal(mmF2, mmFail);
        WriteRel32InBLocal(mmF3, mmFail); WriteRel32InBLocal(mmF4, mmFail);
        WriteRel32InBLocal(mmF5, mmFail); WriteRel32InBLocal(mmF6, mmFail);
        b.AddRange([0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF]);
        int mmRet = b.Count; b[mmRJ] = (byte)(mmRet - (mmRJ + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x40, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _mdbgMemopBytes = b.Count - mdbgMemopOff;

        // mdbg_copyout(edi=pid, rsi=addr, rdx=buf, rcx=len)
        int mdbgCopyoutOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]);
        b.AddRange([0x89, 0x7D, 0xE0, 0x48, 0x89, 0x75, 0xE8, 0x48, 0x89, 0x55, 0xF0, 0x48, 0x89, 0x4D, 0xF8]);
        b.AddRange([0xBF, 0x12, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x75, 0xE0]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mcoCall = b.Count - 4;
        b.AddRange([0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3]);
        _mdbgCopyoutBytes = b.Count - mdbgCopyoutOff;

        // mdbg_copyin(edi=pid, rsi=buf, rdx=addr, rcx=len)
        int mdbgCopyinOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20]);
        b.AddRange([0x89, 0x7D, 0xE0, 0x48, 0x89, 0x55, 0xE8, 0x48, 0x89, 0x75, 0xF0, 0x48, 0x89, 0x4D, 0xF8]);
        b.AddRange([0xBF, 0x13, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x75, 0xE0]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int mciCall = b.Count - 4;
        b.AddRange([0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3]);
        _mdbgCopyinBytes = b.Count - mdbgCopyinOff;

        // mdbg_set{char,short,int,long}
        void EmitMdbgSet(int sz, out int setOff, out int setBytes)
        {
            setOff = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);
            if (sz == 1) b.AddRange([0x88, 0x55, 0xF8]);
            else if (sz == 2) b.AddRange([0x66, 0x89, 0x55, 0xF8]);
            else if (sz == 4) b.AddRange([0x89, 0x55, 0xF8]);
            else b.AddRange([0x48, 0x89, 0x55, 0xF8]);
            b.AddRange([0x48, 0x89, 0xF2, 0x48, 0x8D, 0x75, 0xF8]);
            b.AddRange([(byte)0xB9, (byte)sz, 0, 0, 0]);
            b.AddRange([0xE8, 0, 0, 0, 0]); int ca = b.Count - 4;
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
            setBytes = b.Count - setOff;
            WriteRel32InBLocal(ca, mdbgCopyinOff);
        }
        EmitMdbgSet(1, out int msco, out int mscb); _mdbgSetcharOff = msco; _mdbgSetcharBytes = mscb;
        EmitMdbgSet(2, out int msso, out int mssb); _mdbgSetshortOff = msso; _mdbgSetshortBytes = mssb;
        EmitMdbgSet(4, out int msio, out int msib); _mdbgSetintOff = msio; _mdbgSetintBytes = msib;
        EmitMdbgSet(8, out int mslo, out int mslb); _mdbgSetlongOff = mslo; _mdbgSetlongBytes = mslb;

        // mdbg_get{long,int,short,char}
        void EmitMdbgGet(int sz, out int getOff, out int getBytes)
        {
            getOff = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);
            b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);
            b.AddRange([0x48, 0x8D, 0x55, 0xF8]);
            b.AddRange([(byte)0xB9, (byte)sz, 0, 0, 0]);
            b.AddRange([0xE8, 0, 0, 0, 0]); int ca = b.Count - 4;
            if (sz == 1) b.AddRange([0x0F, 0xBE, 0x45, 0xF8]);
            else if (sz == 2) b.AddRange([0x0F, 0xBF, 0x45, 0xF8]);
            else if (sz == 4) b.AddRange([0x8B, 0x45, 0xF8]);
            else b.AddRange([0x48, 0x8B, 0x45, 0xF8]);
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
            getBytes = b.Count - getOff;
            WriteRel32InBLocal(ca, mdbgCopyoutOff);
        }
        EmitMdbgGet(8, out int mglo, out int mglb); _mdbgGetlongOff = mglo; _mdbgGetlongBytes = mglb;
        EmitMdbgGet(4, out int mgio, out int mgib); _mdbgGetintOff = mgio; _mdbgGetintBytes = mgib;
        EmitMdbgGet(2, out int mgso, out int mgsb); _mdbgGetshortOff = mgso; _mdbgGetshortBytes = mgsb;
        EmitMdbgGet(1, out int mgco, out int mgcb); _mdbgGetcharOff = mgco; _mdbgGetcharBytes = mgcb;

        // kernel_virt2phys(rdi=pml4u, rsi=cr3, rdx=vaddr, rcx=paddr, r8=plen)
        int kernelVirt2PhysOff = b.Count;
        _currentRelocs = _procioRelocs;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x18]);
        b.AddRange([0x48, 0x89, 0xFB, 0x48, 0x29, 0xF3]); // rbx = pml4u - cr3 (dmap)
        b.AddRange([0x49, 0x89, 0xD4]); // r12 = vaddr
        b.AddRange([0x49, 0x89, 0xCE]); // r14 = paddr ptr
        b.AddRange([0x4D, 0x89, 0xC7]); // r15 = plen ptr
        b.AddRange([0x48, 0x89, 0x75, 0xC8]); // [rbp-0x38] = pte = cr3
        b.AddRange([0xB9, 0x27, 0x00, 0x00, 0x00]);
        int v2pLoop = b.Count;
        b.AddRange([0x89, 0x4D, 0xD0]); // save bitpos
        b.AddRange([0x4C, 0x89, 0xE0, 0x48, 0xD3, 0xE8, 0x25, 0xFF, 0x01, 0x00, 0x00, 0x48, 0xC1, 0xE0, 0x03]);
        // pte &= PG_FRAME using rdi as temp
        b.AddRange([0x48, 0xBF]);
        { ulong pgf = 0xffffffffff000UL; for (int bi = 0; bi < 8; bi++) b.Add((byte)(pgf >> (bi * 8))); }
        b.AddRange([0x48, 0x8B, 0x4D, 0xC8, 0x48, 0x21, 0xF9, 0x48, 0x8D, 0x3C, 0x01, 0x48, 0x01, 0xDF]);
        b.AddRange([0x48, 0x8D, 0x75, 0xC8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int v2pCO = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int v2pFJ1 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x45, 0xC8, 0xA8, 0x01, 0x0F, 0x84, 0, 0, 0, 0]); int v2pFJ2 = b.Count - 4;
        b.AddRange([0x8B, 0x4D, 0xD0, 0xA8, 0x80, 0x75, 0x00]); int v2pFndJ1 = b.Count - 1;
        b.AddRange([0x83, 0xF9, 0x0C, 0x74, 0x00]); int v2pFndJ2 = b.Count - 1;
        b.AddRange([0x83, 0xE9, 0x09, 0x83, 0xF9, 0x0C, 0x0F, 0x8D, 0, 0, 0, 0]); int v2pLB = b.Count - 4;
        WriteRel32InBLocal(v2pLB, v2pLoop);
        b.AddRange([0xE9, 0, 0, 0, 0]); int v2pFJF = b.Count - 4;
        int v2pFound = b.Count; b[v2pFndJ1] = (byte)(v2pFound - (v2pFndJ1 + 1)); b[v2pFndJ2] = (byte)(v2pFound - (v2pFndJ2 + 1));
        b.AddRange([0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x48, 0xD3, 0xE7]);
        b.AddRange([0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, 0x48, 0xC1, 0xE6, 0x34, 0x48, 0x29, 0xFE, 0x48, 0x21, 0xC6]);
        b.AddRange([0x48, 0xFF, 0xCF, 0x4C, 0x89, 0xE2, 0x48, 0x21, 0xFA, 0x48, 0x09, 0xD6, 0x49, 0x89, 0x36]);
        b.AddRange([0x48, 0x89, 0xF0, 0x48, 0x09, 0xF8, 0x48, 0xFF, 0xC0, 0x48, 0x29, 0xF0, 0x49, 0x89, 0x07]);
        b.AddRange([0x31, 0xC0, 0xEB, 0x00]); int v2pRJ = b.Count - 1;
        int v2pFail = b.Count;
        WriteRel32InBLocal(v2pFJ1, v2pFail); WriteRel32InBLocal(v2pFJ2, v2pFail); WriteRel32InBLocal(v2pFJF, v2pFail);
        b.AddRange([0x83, 0xC8, 0xFF]);
        int v2pRet = b.Count; b[v2pRJ] = (byte)(v2pRet - (v2pRJ + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x18, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelVirt2PhysBytes = b.Count - kernelVirt2PhysOff;

        // kernel_proc_copyin(edi=pid, rsi=buf, rdx=addr, rcx=len)
        int kernelProcCopyinOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x38]);
        b.AddRange([0x48, 0x89, 0xF3, 0x49, 0x89, 0xD4, 0x49, 0x89, 0xCD, 0x41, 0x89, 0xFE]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcMC = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int kpcFOJ = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xF7]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcGP = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int kpcFJ1 = b.Count - 4;
        b.AddRange([0x48, 0x05, 0x00, 0x02, 0x00, 0x00, 0x48, 0x89, 0xC7, 0x48, 0x8D, 0x75, 0xC8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcCO1 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpcFJ2 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]); AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int kpcFJ3 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x4D, 0xC8, 0x48, 0x01, 0xC1]);
        b.AddRange([0x48, 0x8D, 0x79, 0x20, 0x48, 0x8D, 0x75, 0xD0, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcCO2 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpcFJ4 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]); AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4);
        b.AddRange([0x48, 0x03, 0x45, 0xC8, 0x48, 0x8D, 0x78, 0x28, 0x48, 0x8D, 0x75, 0xD8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcCO3 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpcFJ5 = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xFF]);
        int kpcLT = b.Count;
        b.AddRange([0x4D, 0x39, 0xEF, 0x0F, 0x83, 0, 0, 0, 0]); int kpcLDJ = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0, 0x48, 0x8B, 0x75, 0xD8, 0x4C, 0x89, 0xE2, 0x4C, 0x01, 0xFA]);
        b.AddRange([0x48, 0x8D, 0x4D, 0xE0, 0x4C, 0x8D, 0x45, 0xE8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcV2P = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpcFJ6 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x45, 0xE8, 0x4C, 0x39, 0xE8, 0x76, 0x03, 0x4C, 0x89, 0xE8]);
        b.AddRange([0x48, 0x89, 0xDF, 0x4C, 0x01, 0xFF]);
        b.AddRange([0x48, 0x8B, 0x75, 0xD0, 0x48, 0x2B, 0x75, 0xD8, 0x48, 0x03, 0x75, 0xE0]);
        b.AddRange([0x48, 0x89, 0xC2, 0x48, 0x89, 0x45, 0xE8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpcCI = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpcFJ7 = b.Count - 4;
        b.AddRange([0x4C, 0x03, 0x7D, 0xE8, 0xE9, 0, 0, 0, 0]); int kpcLBack = b.Count - 4;
        WriteRel32InBLocal(kpcLBack, kpcLT);
        int kpcOk = b.Count; WriteRel32InBLocal(kpcLDJ, kpcOk); WriteRel32InBLocal(kpcFOJ, kpcOk);
        b.AddRange([0x31, 0xC0, 0xEB, 0x00]); int kpcRJ = b.Count - 1;
        int kpcFail = b.Count;
        WriteRel32InBLocal(kpcFJ1, kpcFail); WriteRel32InBLocal(kpcFJ2, kpcFail);
        WriteRel32InBLocal(kpcFJ3, kpcFail); WriteRel32InBLocal(kpcFJ4, kpcFail);
        WriteRel32InBLocal(kpcFJ5, kpcFail); WriteRel32InBLocal(kpcFJ6, kpcFail);
        WriteRel32InBLocal(kpcFJ7, kpcFail);
        b.AddRange([0x83, 0xC8, 0xFF]); b[kpcRJ] = (byte)(b.Count - (kpcRJ + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x38, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelProcCopyinBytes = b.Count - kernelProcCopyinOff;

        // kernel_proc_copyout(edi=pid, rsi=addr, rdx=buf, rcx=len)
        int kernelProcCopyoutOff = b.Count;
        b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x38]);
        b.AddRange([0x48, 0x89, 0xD3, 0x49, 0x89, 0xF4, 0x49, 0x89, 0xCD, 0x41, 0x89, 0xFE]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoMC = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int kpoFOJ = b.Count - 4;
        b.AddRange([0x44, 0x89, 0xF7]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoGP = b.Count - 4;
        b.AddRange([0x48, 0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int kpoFJ1 = b.Count - 4;
        b.AddRange([0x48, 0x05, 0x00, 0x02, 0x00, 0x00, 0x48, 0x89, 0xC7, 0x48, 0x8D, 0x75, 0xC8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoCO1 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpoFJ2 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]); AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4);
        b.AddRange([0x48, 0x85, 0xC0, 0x0F, 0x84, 0, 0, 0, 0]); int kpoFJ3 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x4D, 0xC8, 0x48, 0x01, 0xC1]);
        b.AddRange([0x48, 0x8D, 0x79, 0x20, 0x48, 0x8D, 0x75, 0xD0, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoCO2 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpoFJ4 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x05, 0, 0, 0, 0]); AddRel(RelocSymbol.VmspaceVmPmap, b.Count - 4);
        b.AddRange([0x48, 0x03, 0x45, 0xC8, 0x48, 0x8D, 0x78, 0x28, 0x48, 0x8D, 0x75, 0xD8, 0xBA, 0x08, 0x00, 0x00, 0x00]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoCO3 = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpoFJ5 = b.Count - 4;
        b.AddRange([0x45, 0x31, 0xFF]);
        int kpoLT = b.Count;
        b.AddRange([0x4D, 0x39, 0xEF, 0x0F, 0x83, 0, 0, 0, 0]); int kpoLDJ = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0, 0x48, 0x8B, 0x75, 0xD8, 0x4C, 0x89, 0xE2, 0x4C, 0x01, 0xFA]);
        b.AddRange([0x48, 0x8D, 0x4D, 0xE0, 0x4C, 0x8D, 0x45, 0xE8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoV2P = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpoFJ6 = b.Count - 4;
        b.AddRange([0x48, 0x8B, 0x45, 0xE8, 0x4C, 0x39, 0xE8, 0x76, 0x03, 0x4C, 0x89, 0xE8]);
        b.AddRange([0x48, 0x8B, 0x7D, 0xD0, 0x48, 0x2B, 0x7D, 0xD8, 0x48, 0x03, 0x7D, 0xE0]);
        b.AddRange([0x48, 0x89, 0xDE, 0x4C, 0x01, 0xFE]);
        b.AddRange([0x48, 0x89, 0xC2, 0x48, 0x89, 0x45, 0xE8]);
        b.AddRange([0xE8, 0, 0, 0, 0]); int kpoCOD = b.Count - 4;
        b.AddRange([0x85, 0xC0, 0x0F, 0x85, 0, 0, 0, 0]); int kpoFJ7 = b.Count - 4;
        b.AddRange([0x4C, 0x03, 0x7D, 0xE8, 0xE9, 0, 0, 0, 0]); int kpoLBack = b.Count - 4;
        WriteRel32InBLocal(kpoLBack, kpoLT);
        int kpoOk = b.Count; WriteRel32InBLocal(kpoLDJ, kpoOk); WriteRel32InBLocal(kpoFOJ, kpoOk);
        b.AddRange([0x31, 0xC0, 0xEB, 0x00]); int kpoRJ = b.Count - 1;
        int kpoFail = b.Count;
        WriteRel32InBLocal(kpoFJ1, kpoFail); WriteRel32InBLocal(kpoFJ2, kpoFail);
        WriteRel32InBLocal(kpoFJ3, kpoFail); WriteRel32InBLocal(kpoFJ4, kpoFail);
        WriteRel32InBLocal(kpoFJ5, kpoFail); WriteRel32InBLocal(kpoFJ6, kpoFail);
        WriteRel32InBLocal(kpoFJ7, kpoFail);
        b.AddRange([0x83, 0xC8, 0xFF]); b[kpoRJ] = (byte)(b.Count - (kpoRJ + 1));
        b.AddRange([0x48, 0x83, 0xC4, 0x38, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3]);
        _kernelProcCopyoutBytes = b.Count - kernelProcCopyoutOff;

        // kernel_proc_set{char,short,int,long}
        void EmitKernelProcSet(int sz, out int kpsOff, out int kpsBytes)
        {
            kpsOff = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);
            if (sz == 1) b.AddRange([0x88, 0x4D, 0xF8]);
            else if (sz == 2) b.AddRange([0x66, 0x89, 0x4D, 0xF8]);
            else if (sz == 4) b.AddRange([0x89, 0x4D, 0xF8]);
            else b.AddRange([0x48, 0x89, 0x4D, 0xF8]);
            b.AddRange([0x48, 0x89, 0xF2, 0x48, 0x8D, 0x75, 0xF8]);
            b.AddRange([(byte)0xB9, (byte)sz, 0, 0, 0]);
            b.AddRange([0xE8, 0, 0, 0, 0]); int ca = b.Count - 4;
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
            kpsBytes = b.Count - kpsOff;
            WriteRel32InBLocal(ca, kernelProcCopyinOff);
        }
        EmitKernelProcSet(1, out int ksco, out int kscb); _kernelProcSetcharOff = ksco; _kernelProcSetcharBytes = kscb;
        EmitKernelProcSet(2, out int ksso, out int kssb); _kernelProcSetshortOff = ksso; _kernelProcSetshortBytes = kssb;
        EmitKernelProcSet(4, out int ksio, out int ksib); _kernelProcSetintOff = ksio; _kernelProcSetintBytes = ksib;
        EmitKernelProcSet(8, out int ksLo, out int ksLb); _kernelProcSetlongOff = ksLo; _kernelProcSetlongBytes = ksLb;

        // kernel_proc_get{char,short,int,long}
        void EmitKernelProcGet(int sz, out int kpgOff, out int kpgBytes)
        {
            kpgOff = b.Count;
            b.AddRange([0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10]);
            b.AddRange([0x48, 0xC7, 0x45, 0xF8, 0, 0, 0, 0]);
            b.AddRange([0x48, 0x8D, 0x55, 0xF8]);
            b.AddRange([(byte)0xB9, (byte)sz, 0, 0, 0]);
            b.AddRange([0xE8, 0, 0, 0, 0]); int ca = b.Count - 4;
            if (sz == 1) b.AddRange([0x0F, 0xBE, 0x45, 0xF8]);
            else if (sz == 2) b.AddRange([0x0F, 0xBF, 0x45, 0xF8]);
            else if (sz == 4) b.AddRange([0x8B, 0x45, 0xF8]);
            else b.AddRange([0x48, 0x8B, 0x45, 0xF8]);
            b.AddRange([0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3]);
            kpgBytes = b.Count - kpgOff;
            WriteRel32InBLocal(ca, kernelProcCopyoutOff);
        }
        EmitKernelProcGet(1, out int kgco, out int kgcb); _kernelProcGetcharOff = kgco; _kernelProcGetcharBytes = kgcb;
        EmitKernelProcGet(2, out int kgso, out int kgsb); _kernelProcGetshortOff = kgso; _kernelProcGetshortBytes = kgsb;
        EmitKernelProcGet(4, out int kgio, out int kgib); _kernelProcGetintOff = kgio; _kernelProcGetintBytes = kgib;
        EmitKernelProcGet(8, out int kgLo, out int kgLb); _kernelProcGetlongOff = kgLo; _kernelProcGetlongBytes = kgLb;

        // Wire ucred helpers
        WriteRel32InBLocal(gpuGetProcCall, kernelGetProcOff);
        WriteRel32InBLocal(gpuCopyoutCall, kernelCopyoutOff);
        WriteRel32InBLocal(guaCall, kernelGetProcUcredOff);
        WriteRel32InBLocal(guaCO, kernelCopyoutOff);
        WriteRel32InBLocal(suaCall, kernelGetProcUcredOff);
        WriteRel32InBLocal(suaCI, kernelCopyinOff);
        WriteRel32InBLocal(gucCall, kernelGetProcUcredOff);
        WriteRel32InBLocal(gucCO, kernelCopyoutOff);
        WriteRel32InBLocal(sucCall, kernelGetProcUcredOff);
        WriteRel32InBLocal(sucCI, kernelCopyinOff);
        // Wire mdbg
        WriteRel32InBLocal(mmSC1, crtSyscallOff); WriteRel32InBLocal(mmSC2, crtSyscallOff);
        WriteRel32InBLocal(mmGC, kernelGetUcredCapsOff); WriteRel32InBLocal(mmGA, kernelGetUcredAuthidOff);
        WriteRel32InBLocal(mmSA1, kernelSetUcredAuthidOff); WriteRel32InBLocal(mmSA2, kernelSetUcredAuthidOff);
        WriteRel32InBLocal(mmSC1b, kernelSetUcredCapsOff); WriteRel32InBLocal(mmSC2b, kernelSetUcredCapsOff);
        WriteDispTo(mmPCLea, mdbgPrivcapsOff);
        WriteRel32InBLocal(mcoCall, mdbgMemopOff);
        WriteRel32InBLocal(mciCall, mdbgMemopOff);
        // Wire kernel_virt2phys
        WriteRel32InBLocal(v2pCO, kernelCopyoutOff);
        // Wire kernel_proc_copyin
        WriteRel32InBLocal(kpcMC, mdbgCopyinOff); WriteRel32InBLocal(kpcGP, kernelGetProcOff);
        WriteRel32InBLocal(kpcCO1, kernelCopyoutOff); WriteRel32InBLocal(kpcCO2, kernelCopyoutOff);
        WriteRel32InBLocal(kpcCO3, kernelCopyoutOff); WriteRel32InBLocal(kpcV2P, kernelVirt2PhysOff);
        WriteRel32InBLocal(kpcCI, kernelCopyinOff);
        // Wire kernel_proc_copyout
        WriteRel32InBLocal(kpoMC, mdbgCopyoutOff); WriteRel32InBLocal(kpoGP, kernelGetProcOff);
        WriteRel32InBLocal(kpoCO1, kernelCopyoutOff); WriteRel32InBLocal(kpoCO2, kernelCopyoutOff);
        WriteRel32InBLocal(kpoCO3, kernelCopyoutOff); WriteRel32InBLocal(kpoV2P, kernelVirt2PhysOff);
        WriteRel32InBLocal(kpoCOD, kernelCopyoutOff);

        // ============================================================================
        // Reloc list - every field that needs a linker-provided address.
        // ============================================================================
        _relocations = [.. _startRelocs, .. _klogRelocs, .. _dlsymInitRelocs, .. _fixupRelocs,
                        .. _crtSyscallRelocs, .. _crtKekcallRelocs, .. _crtMdbgCallRelocs,
                        .. _crtSyscallInitRelocs,
                        .. _kernelWriteRelocs, .. _kernelCopyinRelocs,
                        .. _kernelCopyoutRelocs, .. _kernelInitRelocs,
                        .. _sha1TransformRelocs, .. _nidEncodeRelocs,
                        .. _kernelGetProcRelocs, .. _kernelFindProcByCommRelocs,
                        .. _kernelDynlibObjRelocs,
                        .. _kernelDynlibResolveRelocs, .. _kernelDynlibDlsymRelocs,
                        .. _patchInitRelocs, .. _klogInitRelocs, .. _klogFuncsRelocs, .. _rtldInitRelocs,
                        .. _dlfcnRelocs, .. _payloadRelocs,
                        .. _soOpenRelocs,
                        .. _soInitRelocs, .. _soRGlobDatRelocs, .. _soSym2addrRelocs,
                        .. _soCloseRelocs, .. _soDestroyRelocs,
                        .. _sprxSym2addrRelocs, .. _sprxOpenRelocs,
                        .. _sprxCloseRelocs, .. _sprxDestroyRelocs,
                        .. _dynlibHandleRelocs,
                        .. _payloadInitRelocs,
                        .. _ucredRelocs, .. _mdbgRelocs, .. _procioRelocs];

        _startOff = startOff;
        _getArgsOff = getArgsOff;
        _klogOff = klogOff;
        _dlsymInitOff = dlsymInitOff;
        _fixupOff = fixupOff;
        _bootcheckOff = bootcheckOff;
        _tcbSeedOff = seedOff;
        _crtSyscallOff = crtSyscallOff;
        _crtKekcallOff = crtKekcallOff;
        _crtMdbgCallOff = crtMdbgCallOff;
        _crtSyscallInitOff = crtSyscallInitOff;
        _kernelWriteOff = kernelWriteOff;
        _kernelCopyinOff = kernelCopyinOff;
        _kernelCopyoutOff = kernelCopyoutOff;
        _kernelInitOff = kernelInitOff;
        _sha1TransformOff = sha1TransformOff;
        _nidEncodeOff = nidEncodeOff;
        _kernelGetProcOff = kernelGetProcOff;
        _kernelFindProcByCommOff = findProcByCommOff;
        _kernelDynlibObjOff = kernelDynlibObjOff;
        _kernelDynlibResolveOff = kernelDynlibResolveOff;
        _kernelDynlibDlsymOff = kernelDynlibDlsymOff;
        _patchInitOff = patchInitOff;
        _klogInitOff = klogInitOff;
        _klogPutsOff = klogPutsOff;
        _klogPerrorOff = klogPerrorOff;
        _klogPrintfOff = klogPrintfOff;
        _rtldInitOff = rtldInitOff;
        _nopStubOff = nopStubOff;
        _payloadExitOff = payloadExitOff;
        _kernelGetProcUcredOff = kernelGetProcUcredOff;
        _kernelGetUcredAuthidOff = kernelGetUcredAuthidOff;
        _kernelSetUcredAuthidOff = kernelSetUcredAuthidOff;
        _kernelGetUcredCapsOff = kernelGetUcredCapsOff;
        _kernelSetUcredCapsOff = kernelSetUcredCapsOff;
        _mdbgMemopOff = mdbgMemopOff;
        _mdbgCopyoutOff = mdbgCopyoutOff;
        _mdbgCopyinOff = mdbgCopyinOff;
        _kernelVirt2PhysOff = kernelVirt2PhysOff;
        _kernelProcCopyinOff = kernelProcCopyinOff;
        _kernelProcCopyoutOff = kernelProcCopyoutOff;
        return [.. b];
    }

    // Runtime-recorded layout for the assembler pass (populated by BuildCode()).
    private static int _startOff, _getArgsOff, _klogOff, _dlsymInitOff, _fixupOff, _bootcheckOff, _tcbSeedOff;
    private static int _crtSyscallOff, _crtKekcallOff, _crtMdbgCallOff, _crtSyscallInitOff, _kernelWriteOff, _kernelCopyinOff, _kernelCopyoutOff, _kernelInitOff;
    private static int _sha1TransformOff, _nidEncodeOff, _kernelGetProcOff, _kernelFindProcByCommOff, _kernelDynlibObjOff, _kernelDynlibResolveOff, _kernelDynlibDlsymOff;
    private static int _patchInitOff, _klogInitOff, _rtldInitOff, _nopStubOff;
    private static int _dlerrorOff, _dlfcnSetrootOff, _libDestroyOff, _libSym2addrOff;
    private static int _libOpenOff, _libFiniOff, _libSym2libOff, _libAppendDepOff;
    private static int _libSoname2libOff, _libInitOff, _libCloseOff, _libNewOff;
    private static int _libAddr2symOff, _libAddr2libOff, _libRemoveDepOff, _findFileOff;
    private static int _sprxInitOff, _dlfcnInitOff, _dlsymOff, _dlcloseOff, _dlopenOff;
    private static int _payloadNewOff, _payloadOpenOff, _payloadInitFnOff;
    private static int _payloadInitVtableOff, _payloadFiniVtableOff;
    private static int _payloadSym2addrOff, _payloadAddr2symOff, _payloadCloseOff, _payloadDestroyOff;
    private static int _sprxNewOff, _soNewOff, _soInitOff, _soRGlobDatOff, _dynlibHandleOff;
    private static int _startBytes, _getArgsBytes, _klogBytes, _dlsymInitBytes, _fixupBytes, _bootcheckBytes;
    private static int _crtSyscallBytes, _crtKekcallBytes, _crtMdbgCallBytes, _crtSyscallInitBytes, _kernelWriteBytes, _kernelCopyinBytes, _kernelCopyoutBytes, _kernelInitBytes;
    private static int _sha1TransformBytes, _nidEncodeBytes, _kernelGetProcBytes, _kernelFindProcByCommBytes, _kernelDynlibObjBytes, _kernelDynlibResolveBytes, _kernelDynlibDlsymBytes;
    private static int _patchInitBytes, _klogInitBytes, _rtldInitBytes, _nopStubBytes;
    private static int _klogPutsOff, _klogPutsBytes, _klogPerrorOff, _klogPerrorBytes, _klogPrintfOff, _klogPrintfBytes;
    private static int _dlerrorBytes, _dlfcnSetrootBytes, _libDestroyBytes, _libSym2addrBytes;
    private static int _libOpenBytes, _libFiniBytes, _libSym2libBytes, _libAppendDepBytes;
    private static int _libSoname2libBytes, _libInitBytes, _libCloseBytes, _libNewBytes;
    private static int _libAddr2symBytes, _libAddr2libBytes, _libRemoveDepBytes, _findFileBytes;
    private static int _sprxInitBytes, _dlfcnInitBytes, _dlsymBytes, _dlcloseBytes, _dlopenBytes;
    private static int _payloadNewBytes, _payloadInitBytes;
    private static int _sprxNewBytes, _soNewBytes, _soInitBytes, _soRGlobDatBytes, _dynlibHandleBytes;
    private static int _payloadExitOff, _payloadExitBytes;
    private static int _kernelGetProcUcredOff, _kernelGetProcUcredBytes;
    private static int _kernelGetUcredAuthidOff, _kernelGetUcredAuthidBytes;
    private static int _kernelSetUcredAuthidOff, _kernelSetUcredAuthidBytes;
    private static int _kernelGetUcredCapsOff, _kernelGetUcredCapsBytes;
    private static int _kernelSetUcredCapsOff, _kernelSetUcredCapsBytes;
    private static int _kernelGetUcredAttrsOff, _kernelGetUcredAttrsBytes;
    private static int _kernelSetUcredAttrsOff, _kernelSetUcredAttrsBytes;
    private static int _kernelGetUcredPrisonOff, _kernelGetUcredPrisonBytes;
    private static int _kernelSetUcredPrisonOff, _kernelSetUcredPrisonBytes;
    private static int _kernelGetRootVnodeOff, _kernelGetRootVnodeBytes;
    private static int _kernelGetProcFiledescOff, _kernelGetProcFiledescBytes;
    private static int _kernelGetProcRootdirOff, _kernelGetProcRootdirBytes;
    private static int _kernelSetProcRootdirOff, _kernelSetProcRootdirBytes;
    private static int _kernelGetProcJaildirOff, _kernelGetProcJaildirBytes;
    private static int _kernelSetProcJaildirOff, _kernelSetProcJaildirBytes;
    private static int _kernelDynlibFindHandleOff, _kernelDynlibFindHandleBytes;
    private static int _kernelDynlibMapbaseOff, _kernelDynlibMapbaseBytes;
    private static int _kernelDynlibFiniAddrOff, _kernelDynlibFiniAddrBytes;
    private static int _kernelDynlibInitAddrOff, _kernelDynlibInitAddrBytes;
    private static int _kernelDynlibEntryAddrOff, _kernelDynlibEntryAddrBytes;
    private static int _kernelDynlibPathOff, _kernelDynlibPathBytes;
    private static int _kernelMprotectOff, _kernelMprotectBytes;
    private static int _kernelGetVmemEntryOff, _kernelGetVmemEntryBytes;
    private static int _kernelSetVmemProtOff, _kernelSetVmemProtBytes;
    private static int _kernelGetQaflagsOff, _kernelGetQaflagsBytes;
    private static int _kernelSetlongOff, _kernelSetlongBytes;
    private static int _kernelGetlongOff, _kernelGetlongBytes;
    private static int _kernelSetintOff, _kernelSetintBytes;
    private static int _kernelGetintOff, _kernelGetintBytes;
    private static int _kernelSetcharOff, _kernelSetcharBytes;
    private static int _kernelGetcharOff, _kernelGetcharBytes;
    private static int _kernelSetshortOff, _kernelSetshortBytes;
    private static int _kernelGetshortOff, _kernelGetshortBytes;
    private static int _kernelSetQaflagsOff, _kernelSetQaflagsBytes;
    private static int _kernelGetFwVersionOff, _kernelGetFwVersionBytes;
    private static int _kernelGetProcThreadOff, _kernelGetProcThreadBytes;
    private static int _kernelGetProcFileOff, _kernelGetProcFileBytes;
    private static int _kernelGetVmemProtectionOff, _kernelGetVmemProtectionBytes;
    private static int _kernelOverlapSocketsOff, _kernelOverlapSocketsBytes;
    private static int _kernelGetUcredUidOff, _kernelGetUcredUidBytes;
    private static int _kernelSetUcredUidOff, _kernelSetUcredUidBytes;
    private static int _kernelGetUcredRuidOff, _kernelGetUcredRuidBytes;
    private static int _kernelSetUcredRuidOff, _kernelSetUcredRuidBytes;
    private static int _kernelGetUcredSvuidOff, _kernelGetUcredSvuidBytes;
    private static int _kernelSetUcredSvuidOff, _kernelSetUcredSvuidBytes;
    private static int _kernelGetUcredRgidOff, _kernelGetUcredRgidBytes;
    private static int _kernelSetUcredRgidOff, _kernelSetUcredRgidBytes;
    private static int _kernelGetUcredSvgidOff, _kernelGetUcredSvgidBytes;
    private static int _kernelSetUcredSvgidOff, _kernelSetUcredSvgidBytes;
    private static int _kernelGetUcredNgroupsOff, _kernelGetUcredNgroupsBytes;
    private static int _kernelSetUcredNgroupsOff, _kernelSetUcredNgroupsBytes;
    private static int _kernelSetUcredSceAttr0Off, _kernelSetUcredSceAttr0Bytes;
    private static int _dladdrOff, _dladdrBytes;
    private static int _mdbgMemopOff, _mdbgMemopBytes;
    private static int _mdbgCopyoutOff, _mdbgCopyoutBytes;
    private static int _mdbgCopyinOff, _mdbgCopyinBytes;
    private static int _mdbgSetcharOff, _mdbgSetcharBytes, _mdbgSetshortOff, _mdbgSetshortBytes;
    private static int _mdbgSetintOff, _mdbgSetintBytes, _mdbgSetlongOff, _mdbgSetlongBytes;
    private static int _mdbgGetlongOff, _mdbgGetlongBytes, _mdbgGetintOff, _mdbgGetintBytes;
    private static int _mdbgGetshortOff, _mdbgGetshortBytes, _mdbgGetcharOff, _mdbgGetcharBytes;
    private static int _kernelVirt2PhysOff, _kernelVirt2PhysBytes;
    private static int _kernelProcCopyinOff, _kernelProcCopyinBytes;
    private static int _kernelProcCopyoutOff, _kernelProcCopyoutBytes;
    private static int _kernelProcSetcharOff, _kernelProcSetcharBytes;
    private static int _kernelProcSetshortOff, _kernelProcSetshortBytes;
    private static int _kernelProcSetintOff, _kernelProcSetintBytes;
    private static int _kernelProcSetlongOff, _kernelProcSetlongBytes;
    private static int _kernelProcGetcharOff, _kernelProcGetcharBytes;
    private static int _kernelProcGetshortOff, _kernelProcGetshortBytes;
    private static int _kernelProcGetintOff, _kernelProcGetintBytes;
    private static int _kernelProcGetlongOff, _kernelProcGetlongBytes;
    private static int[] _sysmodtabStringOffs = [];
    private static IReadOnlyList<Reloc>? _relocations;
    private static List<Reloc> _startRelocs = [];
    private static List<Reloc> _klogRelocs = [];
    private static List<Reloc> _dlsymInitRelocs = [];
    private static List<Reloc> _fixupRelocs = [];
    private static List<Reloc> _crtSyscallRelocs = [];
    private static List<Reloc> _crtKekcallRelocs = [];
    private static List<Reloc> _crtMdbgCallRelocs = [];
    private static List<Reloc> _crtSyscallInitRelocs = [];
    private static List<Reloc> _kernelWriteRelocs = [];
    private static List<Reloc> _kernelCopyinRelocs = [];
    private static List<Reloc> _kernelCopyoutRelocs = [];
    private static List<Reloc> _kernelInitRelocs = [];
    private static List<Reloc> _sha1TransformRelocs = [];
    private static List<Reloc> _nidEncodeRelocs = [];
    private static List<Reloc> _kernelGetProcRelocs = [];
    private static List<Reloc> _kernelFindProcByCommRelocs = [];
    private static List<Reloc> _kernelDynlibObjRelocs = [];
    private static List<Reloc> _kernelDynlibResolveRelocs = [];
    private static List<Reloc> _kernelDynlibDlsymRelocs = [];
    private static List<Reloc> _patchInitRelocs = [];
    private static List<Reloc> _dlfcnRelocs = [];
    private static List<Reloc> _payloadRelocs = [];
    private static List<Reloc> _klogInitRelocs = [];
    private static List<Reloc> _klogFuncsRelocs = [];
    private static List<Reloc> _rtldInitRelocs = [];
    private static List<Reloc> _soInitRelocs = [];
    private static List<Reloc> _soOpenRelocs = [];
    private static List<Reloc> _soRGlobDatRelocs = [];
    private static List<Reloc> _soSym2addrRelocs = [];
    private static List<Reloc> _soCloseRelocs = [];
    private static List<Reloc> _soDestroyRelocs = [];
    private static List<Reloc> _sprxSym2addrRelocs = [];
    private static List<Reloc> _sprxOpenRelocs = [];
    private static List<Reloc> _sprxCloseRelocs = [];
    private static List<Reloc> _sprxDestroyRelocs = [];
    private static List<Reloc> _dynlibHandleRelocs = [];
    private static List<Reloc> _payloadInitRelocs = [];
    private static List<Reloc> _ucredRelocs = [];
    private static List<Reloc> _mdbgRelocs = [];
    private static List<Reloc> _procioRelocs = [];
    private static List<Reloc> _currentRelocs = [];

    private enum RelocSymbol
    {
        PayloadArgs, BssStart, BssEnd, InitArrayStart, InitArrayEnd, Main,
        FiniArrayStart, FiniArrayEnd, KlogSlot,
        GotScratch, PtrSyscall, ImageStart, Dynamic,
        DlsymFn, DlsymOk,
        PipeAddr, RwPipe0, RwPipe1, RwPair0, RwPair1, KdataBase,
        Allproc,
        KlogSnprintf, KlogVsnprintf, KlogStrerror, KlogError,
        RtldStrcpy, RtldStrcat, RtldStrcmp, RtldStrncmp, RtldStrlen,
        RtldSprintf, RtldCalloc, RtldFree, RtldGetenv,
        DlfcnDlerrno, DlfcnRoot, DlfcnGetargc, DlfcnGetargv, DlfcnEnviron,
        DlfcnStrerror, DlfcnSceLoadMod, DlfcnSceUnloadMod, DlfcnSceSysmodLoad,
        DlfcnMalloc, DlfcnCalloc, DlfcnFree, RtldMemcpy, Jmpbuf,
        VmspaceVmPmap,
        KernelRootvnode, KernelSecurityFlags, KernelQaFlags,
        KernelPrison0, KernelVmspacePRoot,
        KernelFwVersion,
        KernelTextBase, KernelBusDataDevices, KernelTargetid, KernelUtokenFlags,
        SysmodTab,
        NataotTcb,
        SavedFsbase,
        SavedRetaddr,
    }

    private readonly record struct Reloc(int Offset, RelocSymbol Sym, uint Type, long Addend);

    /// <summary>Builds the payload start-object bytes.</summary>
    public static byte[] BuildStartObject()
    {
        lock (_buildLock)
        {
            byte[] tcbSeed = RandomNumberGenerator.GetBytes(TcbSeedSize);
            byte[] text = BuildCode(tcbSeed);

            var strtab = new StringTable();
            int nStart = strtab.Add(StartSymbol);
            int nGetArgs = strtab.Add(GetArgsSymbol);
            int nKlog = strtab.Add(KlogSymbol);
            int nFixup = strtab.Add(FixupGotSymbol);
            int nDlsymInit = strtab.Add(DlsymInitSymbol);
            int nBootcheck = strtab.Add(BootcheckSymbol);
            int nPayloadArgs = strtab.Add(PayloadArgsDataSymbol);
            int nKlogSlot = strtab.Add(KlogSlotSymbol);
            int nGotScratch = strtab.Add(GotScratchSymbol);
            int nPtrSyscall = strtab.Add(PtrSyscallSymbol);
            int nDlsymFn = strtab.Add(DlsymFnSymbol);
            int nDlsymOk = strtab.Add(DlsymOkSymbol);
            int nTcbSeed = strtab.Add(TcbSeedSymbol);
            int nCrtSyscall = strtab.Add(CrtSyscallSymbol);
            int nCrtKekcall = strtab.Add(CrtKekcallSymbol);
            int nCrtMdbgCall = strtab.Add(CrtMdbgCallSymbol);
            int nCrtSyscallInit = strtab.Add(CrtSyscallInitSymbol);
            int nKernelWrite = strtab.Add(KernelWriteSymbol);
            int nKernelCopyin = strtab.Add(KernelCopyinSymbol);
            int nKernelCopyout = strtab.Add(KernelCopyoutSymbol);
            int nKernelInit = strtab.Add(KernelInitSymbol);
            int nPipeAddr = strtab.Add(PipeAddrSymbol);
            int nRwPipe0 = strtab.Add(RwPipe0Symbol);
            int nRwPipe1 = strtab.Add(RwPipe1Symbol);
            int nRwPair0 = strtab.Add(RwPair0Symbol);
            int nRwPair1 = strtab.Add(RwPair1Symbol);
            int nKdataBase = strtab.Add(KdataBaseSymbol);
            int nAllproc = strtab.Add(AllprocSymbol);
            int nSha1Transform = strtab.Add(Sha1TransformSymbol);
            int nNidEncode = strtab.Add(NidEncodeSymbol);
            int nKernelGetProc = strtab.Add(KernelGetProcSymbol);
            int nKernelFindProcByComm = strtab.Add(KernelFindProcByCommSymbol);
            int nKernelDynlibObj = strtab.Add(KernelDynlibObjSymbol);
            int nKernelDynlibResolve = strtab.Add(KernelDynlibResolveSymbol);
            int nKernelDynlibDlsym = strtab.Add(KernelDynlibDlsymSymbol);
            int nPatchInit = strtab.Add(PatchInitSymbol);
            int nKlogInit = strtab.Add(KlogInitSymbol);
            int nKlogPuts = strtab.Add(KlogPutsSymbol);
            int nKlogPrintf = strtab.Add(KlogPrintfSymbol);
            int nKlogPerror = strtab.Add(KlogPerrorSymbol);
            int nRtldInit = strtab.Add(RtldInitSymbol);
            int nKlogSnprintf = strtab.Add(KlogSnprintfSymbol);
            int nKlogVsnprintf = strtab.Add(KlogVsnprintfSymbol);
            int nKlogStrerror = strtab.Add(KlogStrerrorSymbol);
            int nKlogError = strtab.Add(KlogErrorSymbol);
            int nRtldStrcpy = strtab.Add(RtldStrcpySymbol);
            int nRtldStrcat = strtab.Add(RtldStrcatSymbol);
            int nRtldStrcmp = strtab.Add(RtldStrcmpSymbol);
            int nRtldStrncmp = strtab.Add(RtldStrncmpSymbol);
            int nRtldStrlen = strtab.Add(RtldStrlenSymbol);
            int nRtldSprintf = strtab.Add(RtldSprintfSymbol);
            int nRtldCalloc = strtab.Add(RtldCallocSymbol);
            int nRtldFree = strtab.Add(RtldFreeSymbol);
            int nRtldGetenv = strtab.Add(RtldGetenvSymbol);
            int nNopStub = strtab.Add(NopStubSymbol);
            int nDlopen = strtab.Add(DlopenSymbol);
            int nDlsymApi = strtab.Add(DlsymSymbol);
            int nDlclose = strtab.Add(DlcloseSymbol);
            int nDlerror = strtab.Add(DlerrorSymbol);
            int nDlfcnInit = strtab.Add(RtldDlfcnInitSymbol);
            int nDlfcnSetroot = strtab.Add(RtldDlfcnSetrootSymbol);
            int nSprxInit = strtab.Add(RtldSprxInitSymbol);
            int nLibNew = strtab.Add(RtldLibNewSymbol);
            int nLibOpen = strtab.Add(RtldLibOpenSymbol);
            int nLibClose = strtab.Add(RtldLibCloseSymbol);
            int nLibDestroy = strtab.Add(RtldLibDestroySymbol);
            int nLibInit = strtab.Add(RtldLibInitSymbol);
            int nLibFini = strtab.Add(RtldLibFiniSymbol);
            int nLibSym2lib = strtab.Add(RtldLibSym2libSymbol);
            int nLibSym2addr = strtab.Add(RtldLibSym2addrSymbol);
            int nLibAppendDep = strtab.Add(RtldLibAppendDepSymbol);
            int nLibSoname2lib = strtab.Add(RtldLibSoname2libSymbol);
            int nDlfcnDlerrno = strtab.Add(DlfcnDlerrnoSymbol);
            int nDlfcnRoot = strtab.Add(DlfcnRootSymbol);
            int nDlfcnGetargc = strtab.Add(DlfcnGetargcSymbol);
            int nDlfcnGetargv = strtab.Add(DlfcnGetargvSymbol);
            int nDlfcnEnviron = strtab.Add(DlfcnEnvironSymbol);
            int nDlfcnStrerror = strtab.Add(DlfcnStrerrorSymbol);
            int nDlfcnSceLoadMod = strtab.Add(DlfcnSceLoadModSymbol);
            int nDlfcnSceUnloadMod = strtab.Add(DlfcnSceUnloadModSymbol);
            int nDlfcnSceSysmodLoad = strtab.Add(DlfcnSceSysmodLoadSymbol);
            int nDlfcnMalloc = strtab.Add(DlfcnMallocSymbol);
            int nDlfcnCalloc = strtab.Add(DlfcnCallocSymbol);
            int nDlfcnFree = strtab.Add(DlfcnFreeSymbol);
            int nRtldMemcpy = strtab.Add(RtldMemcpySymbol);
            int nPayloadInit = strtab.Add(RtldPayloadInitSymbol);
            int nPayloadNew = strtab.Add(RtldPayloadNewSymbol);
            int nLibRemoveDep = strtab.Add(RtldLibRemoveDepSymbol);
            int nLibAddr2sym = strtab.Add(RtldLibAddr2symSymbol);
            int nLibAddr2lib = strtab.Add(RtldLibAddr2libSymbol);
            int nFindFile = strtab.Add(RtldFindFileSymbol);
            int nSoInit = strtab.Add(RtldSoInitSymbol);
            int nSoRGlobDat = strtab.Add(SoRGlobDatSymbol);
            int nSprxNew = strtab.Add(RtldSprxNewSymbol);
            int nSoNew = strtab.Add(RtldSoNewSymbol);
            int nDynlibHandle = strtab.Add(KernelDynlibHandleSymbol);
            int nPayloadExit = strtab.Add(PayloadExitSymbol);
            int nPayloadGetArgsSdk = strtab.Add(PayloadGetArgsSdkSymbol);
            int nJmpbuf = strtab.Add(JmpbufSymbol);
            int nVmspaceVmPmap = strtab.Add(VmspaceVmPmapSymbol);
            int nKernelRootvnode = strtab.Add(KernelRootvnodeSymbol);
            int nKernelSecurityFlags = strtab.Add(KernelSecurityFlagsSymbol);
            int nKernelQaFlags = strtab.Add(KernelQaFlagsSymbol);
            int nKernelPrison0 = strtab.Add(KernelPrison0Symbol);
            int nKernelVmspacePRoot = strtab.Add(KernelVmspacePRootSymbol);
            int nMdbgCopyout = strtab.Add(MdbgCopyoutSymbol);
            int nMdbgCopyin = strtab.Add(MdbgCopyinSymbol);
            int nMdbgSetchar = strtab.Add(MdbgSetcharSymbol);
            int nMdbgSetshort = strtab.Add(MdbgSetshortSymbol);
            int nMdbgSetint = strtab.Add(MdbgSetintSymbol);
            int nMdbgSetlong = strtab.Add(MdbgSetlongSymbol);
            int nMdbgGetlong = strtab.Add(MdbgGetlongSymbol);
            int nMdbgGetint = strtab.Add(MdbgGetintSymbol);
            int nMdbgGetshort = strtab.Add(MdbgGetshortSymbol);
            int nMdbgGetchar = strtab.Add(MdbgGetcharSymbol);
            int nKernelProcCopyin = strtab.Add(KernelProcCopyinSymbol);
            int nKernelProcCopyout = strtab.Add(KernelProcCopyoutSymbol);
            int nKernelProcSetchar = strtab.Add(KernelProcSetcharSymbol);
            int nKernelProcSetshort = strtab.Add(KernelProcSetshortSymbol);
            int nKernelProcSetint = strtab.Add(KernelProcSetintSymbol);
            int nKernelProcSetlong = strtab.Add(KernelProcSetlongSymbol);
            int nKernelProcGetchar = strtab.Add(KernelProcGetcharSymbol);
            int nKernelProcGetshort = strtab.Add(KernelProcGetshortSymbol);
            int nKernelProcGetint = strtab.Add(KernelProcGetintSymbol);
            int nKernelProcGetlong = strtab.Add(KernelProcGetlongSymbol);
            int nKernelGetProcUcred = strtab.Add(KernelGetProcUcredSymbol);
            int nKernelGetUcredAuthid = strtab.Add(KernelGetUcredAuthidSymbol);
            int nKernelSetUcredAuthid = strtab.Add(KernelSetUcredAuthidSymbol);
            int nKernelGetUcredCaps = strtab.Add(KernelGetUcredCapsSymbol);
            int nKernelSetUcredCaps = strtab.Add(KernelSetUcredCapsSymbol);
            int nKernelGetUcredAttrs = strtab.Add(KernelGetUcredAttrsSymbol);
            int nKernelSetUcredAttrs = strtab.Add(KernelSetUcredAttrsSymbol);
            int nKernelGetUcredPrison = strtab.Add(KernelGetUcredPrisonSymbol);
            int nKernelSetUcredPrison = strtab.Add(KernelSetUcredPrisonSymbol);
            int nKernelGetRootVnode = strtab.Add(KernelGetRootVnodeSymbol);
            int nKernelGetProcFiledesc = strtab.Add(KernelGetProcFiledescSymbol);
            int nKernelGetProcRootdir = strtab.Add(KernelGetProcRootdirSymbol);
            int nKernelSetProcRootdir = strtab.Add(KernelSetProcRootdirSymbol);
            int nKernelGetProcJaildir = strtab.Add(KernelGetProcJaildirSymbol);
            int nKernelSetProcJaildir = strtab.Add(KernelSetProcJaildirSymbol);
            int nKernelDynlibFindHandle = strtab.Add(KernelDynlibFindHandleSymbol);
            int nKernelDynlibMapbase = strtab.Add(KernelDynlibMapbaseAddrSymbol);
            int nKernelDynlibPath = strtab.Add(KernelDynlibPathSymbol);
            int nKernelDynlibFiniAddr = strtab.Add(KernelDynlibFiniAddrSymbol);
            int nKernelDynlibInitAddr = strtab.Add(KernelDynlibInitAddrSymbol);
            int nKernelDynlibEntryAddr = strtab.Add(KernelDynlibEntryAddrSymbol);
            int nKernelGetVmemEntry = strtab.Add(KernelGetVmemEntrySymbol);
            int nKernelSetVmemProt = strtab.Add(KernelSetVmemProtectionSymbol);
            int nKernelMprotect = strtab.Add(KernelMprotectSymbol);
            int nKernelGetlong = strtab.Add(KernelGetlongSymbol);
            int nKernelSetlong = strtab.Add(KernelSetlongSymbol);
            int nKernelGetint = strtab.Add(KernelGetintSymbol);
            int nKernelSetint = strtab.Add(KernelSetintSymbol);
            int nKernelGetQaflags = strtab.Add(KernelGetQaflagsSymbol);
            int nKernelGetchar = strtab.Add(KernelGetcharSymbol);
            int nKernelSetchar = strtab.Add(KernelSetcharSymbol);
            int nKernelGetshort = strtab.Add(KernelGetshortSymbol);
            int nKernelSetshort = strtab.Add(KernelSetshortSymbol);
            int nKernelSetQaflags = strtab.Add(KernelSetQaflagsSymbol);
            int nKernelGetFwVersion = strtab.Add(KernelGetFwVersionSymbol);
            int nKernelGetProcThread = strtab.Add(KernelGetProcThreadSymbol);
            int nKernelGetProcFile = strtab.Add(KernelGetProcFileSymbol);
            int nKernelGetVmemProtection = strtab.Add(KernelGetVmemProtectionSymbol);
            int nKernelOverlapSockets = strtab.Add(KernelOverlapSocketsSymbol);
            int nKernelGetUcredUid = strtab.Add(KernelGetUcredUidSymbol);
            int nKernelSetUcredUid = strtab.Add(KernelSetUcredUidSymbol);
            int nKernelGetUcredRuid = strtab.Add(KernelGetUcredRuidSymbol);
            int nKernelSetUcredRuid = strtab.Add(KernelSetUcredRuidSymbol);
            int nKernelGetUcredSvuid = strtab.Add(KernelGetUcredSvuidSymbol);
            int nKernelSetUcredSvuid = strtab.Add(KernelSetUcredSvuidSymbol);
            int nKernelGetUcredRgid = strtab.Add(KernelGetUcredRgidSymbol);
            int nKernelSetUcredRgid = strtab.Add(KernelSetUcredRgidSymbol);
            int nKernelGetUcredSvgid = strtab.Add(KernelGetUcredSvgidSymbol);
            int nKernelSetUcredSvgid = strtab.Add(KernelSetUcredSvgidSymbol);
            int nKernelGetUcredNgroups = strtab.Add(KernelGetUcredNgroupsSymbol);
            int nKernelSetUcredNgroups = strtab.Add(KernelSetUcredNgroupsSymbol);
            int nKernelSetUcredSceAttr0 = strtab.Add(KernelSetUcredSceAttr0Symbol);
            int nDladdr = strtab.Add(DladdrSymbol);
            int nKernelFwVersion = strtab.Add("__sp_kernel_fw_version");
            int nKernelTextBase = strtab.Add(KernelTextBaseSymbol);
            int nKernelBusDataDevices = strtab.Add(KernelBusDataDevicesSymbol);
            int nKernelTargetid = strtab.Add(KernelTargetidSymbol);
            int nKernelUtokenFlags = strtab.Add(KernelUtokenFlagsSymbol);
            int nBssStart = strtab.Add("__bss_start");
            int nBssEnd = strtab.Add("__bss_end");
            int nInitStart = strtab.Add("__init_array_start");
            int nInitEnd = strtab.Add("__init_array_end");
            int nFiniStart = strtab.Add("__fini_array_start");
            int nFiniEnd = strtab.Add("__fini_array_end");
            int nMain = strtab.Add("main");
            int nImageStart = strtab.Add("__image_start");
            int nDynamic = strtab.Add("_DYNAMIC");
            int nSysmodtab = strtab.Add("sysmodtab");
            int nNataotTcb = strtab.Add(NataotTcbSymbol);
            int nSavedFsbase = strtab.Add(SavedFsbaseSymbol);
            int nSavedRetaddr = strtab.Add(SavedRetaddrSymbol);
            byte[] strtabBytes = strtab.ToBytes();

            const int shText = 1, shRelaText = 2, shBss = 3;
            const int shSysmodtab = 4, shRelaSysmodtab = 5;
            const int shSym = 6, shStr = 7, shShStr = 8;
            const int symStart = 1, symGetArgs = 2, symKlog = 3, symFixup = 4, symDlsymInit = 5, symBootcheck = 6;
            const int symPayloadArgs = 7, symKlogSlot = 8, symGotScratch = 9, symPtrSyscall = 10;
            const int symDlsymFn = 11, symDlsymOk = 12, symTcbSeed = 13;
            const int symCrtSyscall = 14, symCrtSyscallInit = 15, symKernelWrite = 16;
            const int symKernelCopyin = 17, symKernelCopyout = 18, symKernelInit = 19;
            const int symPipeAddr = 20, symRwPipe0 = 21, symRwPipe1 = 22, symRwPair0 = 23, symRwPair1 = 24, symKdataBase = 25;
            const int symAllproc = 26;
            const int symSha1Transform = 27, symNidEncode = 28, symKernelGetProc = 29;
            const int symKernelDynlibObj = 30, symKernelDynlibResolve = 31, symKernelDynlibDlsym = 32;
            const int symPatchInit = 33, symKlogInit = 34, symRtldInit = 35;
            const int symKlogSnprintf = 36, symKlogVsnprintf = 37, symKlogStrerror = 38, symKlogError = 39;
            const int symRtldStrcpy = 40, symRtldStrcat = 41, symRtldStrcmp = 42, symRtldStrncmp = 43;
            const int symRtldStrlen = 44, symRtldSprintf = 45, symRtldCalloc = 46, symRtldFree = 47, symRtldGetenv = 48;
            const int symNopStub = 49;
            const int symDlopenApi = 50, symDlsymApi = 51, symDlcloseApi = 52, symDlerrorApi = 53;
            const int symDlfcnInitApi = 54, symDlfcnSetrootApi = 55, symSprxInitApi = 56;
            const int symLibNew = 57, symLibOpen = 58, symLibClose = 59, symLibDestroy = 60;
            const int symLibInit = 61, symLibFini = 62, symLibSym2lib = 63, symLibSym2addr = 64;
            const int symLibAppendDep = 65, symLibSoname2lib = 66;
            const int symDlfcnDlerrno = 67, symDlfcnRoot = 68, symDlfcnGetargc = 69;
            const int symDlfcnGetargv = 70, symDlfcnEnviron = 71, symDlfcnStrerror = 72;
            const int symDlfcnSceLoadMod = 73, symDlfcnSceUnloadMod = 74;
            const int symDlfcnSceSysmodLoad = 75, symDlfcnMalloc = 76;
            const int symDlfcnCalloc = 77, symDlfcnFree = 78;
            const int symRtldMemcpy = 79;
            const int symPayloadInitFn = 80, symPayloadNewFn = 81;
            const int symLibRemoveDep = 82, symLibAddr2sym = 83, symLibAddr2lib = 84;
            const int symBssStart = 85, symBssEnd = 86, symInitStart = 87, symInitEnd = 88;
            const int symFiniStart = 89, symFiniEnd = 90, symMain = 91, symImageStart = 92, symDynamic = 93;
            const int symSoInitApi = 94;
            const int symFindFile = 95;
            const int symSoRGlobDat = 96;
            const int symSprxNew = 97;
            const int symSoNew = 98;
            const int symDynlibHandle = 99;
            const int symPayloadExit = 100;
            const int symPayloadGetArgsSdk = 101;
            const int symJmpbuf = 102;
            const int symKlogPuts = 103;
            const int symKlogPrintf = 104;
            const int symKlogPerror = 105;
            const int symVmspaceVmPmap = 106;
            const int symKernelRootvnode = 107;
            const int symKernelSecurityFlags = 108;
            const int symKernelQaFlags = 109;
            const int symKernelPrison0 = 110;
            const int symKernelVmspacePRoot = 111;
            const int symMdbgCopyout = 112, symMdbgCopyin = 113;
            const int symMdbgSetchar = 114, symMdbgSetshort = 115, symMdbgSetint = 116, symMdbgSetlong = 117;
            const int symMdbgGetlong = 118, symMdbgGetint = 119, symMdbgGetshort = 120, symMdbgGetchar = 121;
            const int symKernelProcCopyin = 122, symKernelProcCopyout = 123;
            const int symKernelProcSetchar = 124, symKernelProcSetshort = 125;
            const int symKernelProcSetint = 126, symKernelProcSetlong = 127;
            const int symKernelProcGetchar = 128, symKernelProcGetshort = 129;
            const int symKernelProcGetint = 130, symKernelProcGetlong = 131;
            const int symKernelGetProcUcred = 132, symKernelGetUcredAuthid = 133;
            const int symKernelSetUcredAuthid = 134, symKernelGetUcredCaps = 135;
            const int symKernelSetUcredCaps = 136;
            const int symKernelGetUcredAttrs = 137, symKernelSetUcredAttrs = 138;
            const int symKernelGetUcredPrison = 139, symKernelSetUcredPrison = 140;
            const int symKernelGetRootVnode = 141, symKernelGetProcFiledesc = 142;
            const int symKernelGetProcRootdir = 143, symKernelSetProcRootdir = 144;
            const int symKernelGetProcJaildir = 145, symKernelSetProcJaildir = 146;
            const int symKernelDynlibFindHandle = 147, symKernelDynlibMapbase = 148;
            const int symKernelDynlibPath = 149, symKernelDynlibFiniAddr = 150;
            const int symKernelDynlibInitAddr = 151, symKernelDynlibEntryAddr = 152;
            const int symKernelGetVmemEntry = 153, symKernelSetVmemProt = 154;
            const int symKernelMprotect = 155, symKernelGetlong = 156;
            const int symKernelSetlong = 157, symKernelGetint = 158;
            const int symKernelSetint = 159, symKernelGetQaflags = 160;
            const int symKernelGetchar = 161, symKernelSetchar = 162;
            const int symKernelGetshort = 163, symKernelSetshort = 164;
            const int symKernelSetQaflags = 165, symKernelGetFwVersion = 166;
            const int symKernelGetProcThread = 167, symKernelGetProcFile = 168;
            const int symKernelGetVmemProtection = 169, symKernelOverlapSockets = 170;
            const int symKernelGetUcredUid = 171, symKernelSetUcredUid = 172;
            const int symKernelGetUcredRuid = 173, symKernelSetUcredRuid = 174;
            const int symKernelGetUcredSvuid = 175, symKernelSetUcredSvuid = 176;
            const int symKernelGetUcredRgid = 177, symKernelSetUcredRgid = 178;
            const int symKernelGetUcredSvgid = 179, symKernelSetUcredSvgid = 180;
            const int symDladdr = 181;
            const int symKernelFwVersion = 182;
            const int symKernelTextBase = 183;
            const int symKernelBusDataDevices = 184;
            const int symKernelTargetid = 185;
            const int symKernelUtokenFlags = 186;
            const int symSysmodtab = 187;
            const int symNataotTcb = 188;
            const int symSavedFsbase = 189;
            const int symSavedRetaddr = 190;
            const int symKernelFindProcByComm = 191;
            const int symKernelGetUcredNgroups = 192;
            const int symKernelSetUcredNgroups = 193;
            const int symKernelSetUcredSceAttr0 = 194;
            const int symCrtKekcall = 195;
            const int symCrtMdbgCall = 196;
            const int symCount = 197;

            byte[] symtab = new byte[24 * symCount];
            WriteSym(symtab, symStart, nStart, GlobalFunc, shText, (ulong)_startOff, (ulong)_startBytes);
            WriteSym(symtab, symGetArgs, nGetArgs, GlobalFunc, shText, (ulong)_getArgsOff, (ulong)_getArgsBytes);
            WriteSym(symtab, symKlog, nKlog, GlobalFunc, shText, (ulong)_klogOff, (ulong)_klogBytes);
            WriteSym(symtab, symFixup, nFixup, GlobalFunc, shText, (ulong)_fixupOff, (ulong)_fixupBytes);
            WriteSym(symtab, symDlsymInit, nDlsymInit, GlobalFunc, shText, (ulong)_dlsymInitOff, (ulong)_dlsymInitBytes);
            WriteSym(symtab, symBootcheck, nBootcheck, GlobalFunc, shText, (ulong)_bootcheckOff, (ulong)_bootcheckBytes);
            WriteSym(symtab, symPayloadArgs, nPayloadArgs, GlobalObject, shBss, BssOffArgs, 8);
            WriteSym(symtab, symKlogSlot, nKlogSlot, GlobalObject, shBss, BssOffKlogSlot, 8);
            WriteSym(symtab, symGotScratch, nGotScratch, GlobalObject, shBss, BssOffGotScratch, 8);
            WriteSym(symtab, symPtrSyscall, nPtrSyscall, GlobalObject, shBss, BssOffPtrSyscall, 8);
            WriteSym(symtab, symDlsymFn, nDlsymFn, GlobalObject, shBss, BssOffDlsymFn, 8);
            WriteSym(symtab, symDlsymOk, nDlsymOk, GlobalObject, shBss, BssOffDlsymOk, 1);
            WriteSym(symtab, symTcbSeed, nTcbSeed, GlobalObject, shText, (ulong)_tcbSeedOff, TcbSeedSize);
            WriteSym(symtab, symCrtSyscall, nCrtSyscall, GlobalFunc, shText, (ulong)_crtSyscallOff, (ulong)_crtSyscallBytes);
            WriteSym(symtab, symCrtKekcall, nCrtKekcall, GlobalFunc, shText, (ulong)_crtKekcallOff, (ulong)_crtKekcallBytes);
            WriteSym(symtab, symCrtMdbgCall, nCrtMdbgCall, GlobalFunc, shText, (ulong)_crtMdbgCallOff, (ulong)_crtMdbgCallBytes);
            WriteSym(symtab, symCrtSyscallInit, nCrtSyscallInit, GlobalFunc, shText, (ulong)_crtSyscallInitOff, (ulong)_crtSyscallInitBytes);
            WriteSym(symtab, symKernelWrite, nKernelWrite, GlobalFunc, shText, (ulong)_kernelWriteOff, (ulong)_kernelWriteBytes);
            WriteSym(symtab, symKernelCopyin, nKernelCopyin, GlobalFunc, shText, (ulong)_kernelCopyinOff, (ulong)_kernelCopyinBytes);
            WriteSym(symtab, symKernelCopyout, nKernelCopyout, GlobalFunc, shText, (ulong)_kernelCopyoutOff, (ulong)_kernelCopyoutBytes);
            WriteSym(symtab, symKernelInit, nKernelInit, GlobalFunc, shText, (ulong)_kernelInitOff, (ulong)_kernelInitBytes);
            WriteSym(symtab, symPipeAddr, nPipeAddr, GlobalObject, shBss, BssOffPipeAddr, 8);
            WriteSym(symtab, symRwPipe0, nRwPipe0, GlobalObject, shBss, BssOffRwPipe0, 4);
            WriteSym(symtab, symRwPipe1, nRwPipe1, GlobalObject, shBss, BssOffRwPipe1, 4);
            WriteSym(symtab, symRwPair0, nRwPair0, GlobalObject, shBss, BssOffRwPair0, 4);
            WriteSym(symtab, symRwPair1, nRwPair1, GlobalObject, shBss, BssOffRwPair1, 4);
            WriteSym(symtab, symKdataBase, nKdataBase, GlobalObject, shBss, BssOffKdataBase, 8);
            WriteSym(symtab, symAllproc, nAllproc, GlobalObject, shBss, BssOffAllproc, 8);
            WriteSym(symtab, symSha1Transform, nSha1Transform, GlobalFunc, shText, (ulong)_sha1TransformOff, (ulong)_sha1TransformBytes);
            WriteSym(symtab, symNidEncode, nNidEncode, GlobalFunc, shText, (ulong)_nidEncodeOff, (ulong)_nidEncodeBytes);
            WriteSym(symtab, symKernelGetProc, nKernelGetProc, GlobalFunc, shText, (ulong)_kernelGetProcOff, (ulong)_kernelGetProcBytes);
            WriteSym(symtab, symKernelFindProcByComm, nKernelFindProcByComm, GlobalFunc, shText, (ulong)_kernelFindProcByCommOff, (ulong)_kernelFindProcByCommBytes);
            WriteSym(symtab, symKernelDynlibObj, nKernelDynlibObj, GlobalFunc, shText, (ulong)_kernelDynlibObjOff, (ulong)_kernelDynlibObjBytes);
            WriteSym(symtab, symKernelDynlibResolve, nKernelDynlibResolve, GlobalFunc, shText, (ulong)_kernelDynlibResolveOff, (ulong)_kernelDynlibResolveBytes);
            WriteSym(symtab, symKernelDynlibDlsym, nKernelDynlibDlsym, GlobalFunc, shText, (ulong)_kernelDynlibDlsymOff, (ulong)_kernelDynlibDlsymBytes);
            WriteSym(symtab, symPatchInit, nPatchInit, GlobalFunc, shText, (ulong)_patchInitOff, (ulong)_patchInitBytes);
            WriteSym(symtab, symKlogInit, nKlogInit, GlobalFunc, shText, (ulong)_klogInitOff, (ulong)_klogInitBytes);
            WriteSym(symtab, symKlogPuts, nKlogPuts, GlobalFunc, shText, (ulong)_klogPutsOff, (ulong)_klogPutsBytes);
            WriteSym(symtab, symKlogPrintf, nKlogPrintf, GlobalFunc, shText, (ulong)_klogPrintfOff, (ulong)_klogPrintfBytes);
            WriteSym(symtab, symKlogPerror, nKlogPerror, GlobalFunc, shText, (ulong)_klogPerrorOff, (ulong)_klogPerrorBytes);
            WriteSym(symtab, symRtldInit, nRtldInit, GlobalFunc, shText, (ulong)_rtldInitOff, (ulong)_rtldInitBytes);
            WriteSym(symtab, symKlogSnprintf, nKlogSnprintf, GlobalObject, shBss, BssOffKlogSnprintf, 8);
            WriteSym(symtab, symKlogVsnprintf, nKlogVsnprintf, GlobalObject, shBss, BssOffKlogVsnprintf, 8);
            WriteSym(symtab, symKlogStrerror, nKlogStrerror, GlobalObject, shBss, BssOffKlogStrerror, 8);
            WriteSym(symtab, symKlogError, nKlogError, GlobalObject, shBss, BssOffKlogError, 8);
            WriteSym(symtab, symRtldStrcpy, nRtldStrcpy, GlobalObject, shBss, BssOffRtldStrcpy, 8);
            WriteSym(symtab, symRtldStrcat, nRtldStrcat, GlobalObject, shBss, BssOffRtldStrcat, 8);
            WriteSym(symtab, symRtldStrcmp, nRtldStrcmp, GlobalObject, shBss, BssOffRtldStrcmp, 8);
            WriteSym(symtab, symRtldStrncmp, nRtldStrncmp, GlobalObject, shBss, BssOffRtldStrncmp, 8);
            WriteSym(symtab, symRtldStrlen, nRtldStrlen, GlobalObject, shBss, BssOffRtldStrlen, 8);
            WriteSym(symtab, symRtldSprintf, nRtldSprintf, GlobalObject, shBss, BssOffRtldSprintf, 8);
            WriteSym(symtab, symRtldCalloc, nRtldCalloc, GlobalObject, shBss, BssOffRtldCalloc, 8);
            WriteSym(symtab, symRtldFree, nRtldFree, GlobalObject, shBss, BssOffRtldFree, 8);
            WriteSym(symtab, symRtldGetenv, nRtldGetenv, GlobalObject, shBss, BssOffRtldGetenv, 8);
            WriteSym(symtab, symNopStub, nNopStub, GlobalFunc, shText, (ulong)_nopStubOff, (ulong)_nopStubBytes);
            WriteSym(symtab, symDlopenApi, nDlopen, GlobalFunc, shText, (ulong)_dlopenOff, (ulong)_dlopenBytes);
            WriteSym(symtab, symDlsymApi, nDlsymApi, GlobalFunc, shText, (ulong)_dlsymOff, (ulong)_dlsymBytes);
            WriteSym(symtab, symDlcloseApi, nDlclose, GlobalFunc, shText, (ulong)_dlcloseOff, (ulong)_dlcloseBytes);
            WriteSym(symtab, symDlerrorApi, nDlerror, GlobalFunc, shText, (ulong)_dlerrorOff, (ulong)_dlerrorBytes);
            WriteSym(symtab, symDlfcnInitApi, nDlfcnInit, GlobalFunc, shText, (ulong)_dlfcnInitOff, (ulong)_dlfcnInitBytes);
            WriteSym(symtab, symDlfcnSetrootApi, nDlfcnSetroot, GlobalFunc, shText, (ulong)_dlfcnSetrootOff, (ulong)_dlfcnSetrootBytes);
            WriteSym(symtab, symSprxInitApi, nSprxInit, GlobalFunc, shText, (ulong)_sprxInitOff, (ulong)_sprxInitBytes);
            WriteSym(symtab, symLibNew, nLibNew, GlobalFunc, shText, (ulong)_libNewOff, (ulong)_libNewBytes);
            WriteSym(symtab, symLibOpen, nLibOpen, GlobalFunc, shText, (ulong)_libOpenOff, (ulong)_libOpenBytes);
            WriteSym(symtab, symLibClose, nLibClose, GlobalFunc, shText, (ulong)_libCloseOff, (ulong)_libCloseBytes);
            WriteSym(symtab, symLibDestroy, nLibDestroy, GlobalFunc, shText, (ulong)_libDestroyOff, (ulong)_libDestroyBytes);
            WriteSym(symtab, symLibInit, nLibInit, GlobalFunc, shText, (ulong)_libInitOff, (ulong)_libInitBytes);
            WriteSym(symtab, symLibFini, nLibFini, GlobalFunc, shText, (ulong)_libFiniOff, (ulong)_libFiniBytes);
            WriteSym(symtab, symLibSym2lib, nLibSym2lib, GlobalFunc, shText, (ulong)_libSym2libOff, (ulong)_libSym2libBytes);
            WriteSym(symtab, symLibSym2addr, nLibSym2addr, GlobalFunc, shText, (ulong)_libSym2addrOff, (ulong)_libSym2addrBytes);
            WriteSym(symtab, symLibAppendDep, nLibAppendDep, GlobalFunc, shText, (ulong)_libAppendDepOff, (ulong)_libAppendDepBytes);
            WriteSym(symtab, symLibSoname2lib, nLibSoname2lib, GlobalFunc, shText, (ulong)_libSoname2libOff, (ulong)_libSoname2libBytes);
            WriteSym(symtab, symDlfcnDlerrno, nDlfcnDlerrno, GlobalObject, shBss, BssOffDlfcnDlerrno, 4);
            WriteSym(symtab, symDlfcnRoot, nDlfcnRoot, GlobalObject, shBss, BssOffDlfcnRoot, 8);
            WriteSym(symtab, symDlfcnGetargc, nDlfcnGetargc, GlobalObject, shBss, BssOffDlfcnGetargc, 8);
            WriteSym(symtab, symDlfcnGetargv, nDlfcnGetargv, GlobalObject, shBss, BssOffDlfcnGetargv, 8);
            WriteSym(symtab, symDlfcnEnviron, nDlfcnEnviron, GlobalObject, shBss, BssOffDlfcnEnviron, 8);
            WriteSym(symtab, symDlfcnStrerror, nDlfcnStrerror, GlobalObject, shBss, BssOffDlfcnStrerror, 8);
            WriteSym(symtab, symDlfcnSceLoadMod, nDlfcnSceLoadMod, GlobalObject, shBss, BssOffDlfcnSceLoadMod, 8);
            WriteSym(symtab, symDlfcnSceUnloadMod, nDlfcnSceUnloadMod, GlobalObject, shBss, BssOffDlfcnSceUnloadMod, 8);
            WriteSym(symtab, symDlfcnSceSysmodLoad, nDlfcnSceSysmodLoad, GlobalObject, shBss, BssOffDlfcnSceSysmodLoad, 8);
            WriteSym(symtab, symDlfcnMalloc, nDlfcnMalloc, GlobalObject, shBss, BssOffDlfcnMalloc, 8);
            WriteSym(symtab, symDlfcnCalloc, nDlfcnCalloc, GlobalObject, shBss, BssOffDlfcnCalloc, 8);
            WriteSym(symtab, symDlfcnFree, nDlfcnFree, GlobalObject, shBss, BssOffDlfcnFree, 8);
            WriteSym(symtab, symRtldMemcpy, nRtldMemcpy, GlobalObject, shBss, BssOffRtldMemcpy, 8);
            WriteSym(symtab, symPayloadInitFn, nPayloadInit, GlobalFunc, shText, (ulong)_payloadInitFnOff, (ulong)_payloadInitBytes);
            WriteSym(symtab, symPayloadNewFn, nPayloadNew, GlobalFunc, shText, (ulong)_payloadNewOff, (ulong)_payloadNewBytes);
            WriteSym(symtab, symLibRemoveDep, nLibRemoveDep, GlobalFunc, shText, (ulong)_libRemoveDepOff, (ulong)_libRemoveDepBytes);
            WriteSym(symtab, symLibAddr2sym, nLibAddr2sym, GlobalFunc, shText, (ulong)_libAddr2symOff, (ulong)_libAddr2symBytes);
            WriteSym(symtab, symLibAddr2lib, nLibAddr2lib, GlobalFunc, shText, (ulong)_libAddr2libOff, (ulong)_libAddr2libBytes);
            WriteSym(symtab, symFindFile, nFindFile, GlobalFunc, shText, (ulong)_findFileOff, (ulong)_findFileBytes);
            WriteSym(symtab, symSoInitApi, nSoInit, GlobalFunc, shText, (ulong)_soInitOff, (ulong)_soInitBytes);
            WriteSym(symtab, symSoRGlobDat, nSoRGlobDat, GlobalFunc, shText, (ulong)_soRGlobDatOff, (ulong)_soRGlobDatBytes);
            WriteSym(symtab, symSprxNew, nSprxNew, GlobalFunc, shText, (ulong)_sprxNewOff, (ulong)_sprxNewBytes);
            WriteSym(symtab, symSoNew, nSoNew, GlobalFunc, shText, (ulong)_soNewOff, (ulong)_soNewBytes);
            WriteSym(symtab, symDynlibHandle, nDynlibHandle, GlobalFunc, shText, (ulong)_dynlibHandleOff, (ulong)_dynlibHandleBytes);
            WriteSym(symtab, symPayloadExit, nPayloadExit, GlobalFunc, shText, (ulong)_payloadExitOff, (ulong)_payloadExitBytes);
            WriteSym(symtab, symPayloadGetArgsSdk, nPayloadGetArgsSdk, GlobalFunc, shText, (ulong)_getArgsOff, (ulong)_getArgsBytes);
            WriteSym(symtab, symJmpbuf, nJmpbuf, GlobalObject, shBss, BssOffJmpbuf, 256);
            WriteSym(symtab, symVmspaceVmPmap, nVmspaceVmPmap, GlobalObject, shBss, BssOffVmspaceVmPmap, 8);
            WriteSym(symtab, symKernelRootvnode, nKernelRootvnode, GlobalObject, shBss, BssOffKernelRootvnode, 8);
            WriteSym(symtab, symKernelSecurityFlags, nKernelSecurityFlags, GlobalObject, shBss, BssOffKernelSecurityFlags, 8);
            WriteSym(symtab, symKernelQaFlags, nKernelQaFlags, GlobalObject, shBss, BssOffKernelQaFlags, 8);
            WriteSym(symtab, symKernelPrison0, nKernelPrison0, GlobalObject, shBss, BssOffKernelPrison0, 8);
            WriteSym(symtab, symKernelVmspacePRoot, nKernelVmspacePRoot, GlobalObject, shBss, BssOffKernelVmspacePRoot, 8);
            WriteSym(symtab, symMdbgCopyout, nMdbgCopyout, GlobalFunc, shText, (ulong)_mdbgCopyoutOff, (ulong)_mdbgCopyoutBytes);
            WriteSym(symtab, symMdbgCopyin, nMdbgCopyin, GlobalFunc, shText, (ulong)_mdbgCopyinOff, (ulong)_mdbgCopyinBytes);
            WriteSym(symtab, symMdbgSetchar, nMdbgSetchar, GlobalFunc, shText, (ulong)_mdbgSetcharOff, (ulong)_mdbgSetcharBytes);
            WriteSym(symtab, symMdbgSetshort, nMdbgSetshort, GlobalFunc, shText, (ulong)_mdbgSetshortOff, (ulong)_mdbgSetshortBytes);
            WriteSym(symtab, symMdbgSetint, nMdbgSetint, GlobalFunc, shText, (ulong)_mdbgSetintOff, (ulong)_mdbgSetintBytes);
            WriteSym(symtab, symMdbgSetlong, nMdbgSetlong, GlobalFunc, shText, (ulong)_mdbgSetlongOff, (ulong)_mdbgSetlongBytes);
            WriteSym(symtab, symMdbgGetlong, nMdbgGetlong, GlobalFunc, shText, (ulong)_mdbgGetlongOff, (ulong)_mdbgGetlongBytes);
            WriteSym(symtab, symMdbgGetint, nMdbgGetint, GlobalFunc, shText, (ulong)_mdbgGetintOff, (ulong)_mdbgGetintBytes);
            WriteSym(symtab, symMdbgGetshort, nMdbgGetshort, GlobalFunc, shText, (ulong)_mdbgGetshortOff, (ulong)_mdbgGetshortBytes);
            WriteSym(symtab, symMdbgGetchar, nMdbgGetchar, GlobalFunc, shText, (ulong)_mdbgGetcharOff, (ulong)_mdbgGetcharBytes);
            WriteSym(symtab, symKernelProcCopyin, nKernelProcCopyin, GlobalFunc, shText, (ulong)_kernelProcCopyinOff, (ulong)_kernelProcCopyinBytes);
            WriteSym(symtab, symKernelProcCopyout, nKernelProcCopyout, GlobalFunc, shText, (ulong)_kernelProcCopyoutOff, (ulong)_kernelProcCopyoutBytes);
            WriteSym(symtab, symKernelProcSetchar, nKernelProcSetchar, GlobalFunc, shText, (ulong)_kernelProcSetcharOff, (ulong)_kernelProcSetcharBytes);
            WriteSym(symtab, symKernelProcSetshort, nKernelProcSetshort, GlobalFunc, shText, (ulong)_kernelProcSetshortOff, (ulong)_kernelProcSetshortBytes);
            WriteSym(symtab, symKernelProcSetint, nKernelProcSetint, GlobalFunc, shText, (ulong)_kernelProcSetintOff, (ulong)_kernelProcSetintBytes);
            WriteSym(symtab, symKernelProcSetlong, nKernelProcSetlong, GlobalFunc, shText, (ulong)_kernelProcSetlongOff, (ulong)_kernelProcSetlongBytes);
            WriteSym(symtab, symKernelProcGetchar, nKernelProcGetchar, GlobalFunc, shText, (ulong)_kernelProcGetcharOff, (ulong)_kernelProcGetcharBytes);
            WriteSym(symtab, symKernelProcGetshort, nKernelProcGetshort, GlobalFunc, shText, (ulong)_kernelProcGetshortOff, (ulong)_kernelProcGetshortBytes);
            WriteSym(symtab, symKernelProcGetint, nKernelProcGetint, GlobalFunc, shText, (ulong)_kernelProcGetintOff, (ulong)_kernelProcGetintBytes);
            WriteSym(symtab, symKernelProcGetlong, nKernelProcGetlong, GlobalFunc, shText, (ulong)_kernelProcGetlongOff, (ulong)_kernelProcGetlongBytes);
            WriteSym(symtab, symKernelGetProcUcred, nKernelGetProcUcred, GlobalFunc, shText, (ulong)_kernelGetProcUcredOff, (ulong)_kernelGetProcUcredBytes);
            WriteSym(symtab, symKernelGetUcredAuthid, nKernelGetUcredAuthid, GlobalFunc, shText, (ulong)_kernelGetUcredAuthidOff, (ulong)_kernelGetUcredAuthidBytes);
            WriteSym(symtab, symKernelSetUcredAuthid, nKernelSetUcredAuthid, GlobalFunc, shText, (ulong)_kernelSetUcredAuthidOff, (ulong)_kernelSetUcredAuthidBytes);
            WriteSym(symtab, symKernelGetUcredCaps, nKernelGetUcredCaps, GlobalFunc, shText, (ulong)_kernelGetUcredCapsOff, (ulong)_kernelGetUcredCapsBytes);
            WriteSym(symtab, symKernelSetUcredCaps, nKernelSetUcredCaps, GlobalFunc, shText, (ulong)_kernelSetUcredCapsOff, (ulong)_kernelSetUcredCapsBytes);
            WriteSym(symtab, symKernelGetUcredAttrs, nKernelGetUcredAttrs, GlobalFunc, shText, (ulong)_kernelGetUcredAttrsOff, (ulong)_kernelGetUcredAttrsBytes);
            WriteSym(symtab, symKernelSetUcredAttrs, nKernelSetUcredAttrs, GlobalFunc, shText, (ulong)_kernelSetUcredAttrsOff, (ulong)_kernelSetUcredAttrsBytes);
            WriteSym(symtab, symKernelGetUcredPrison, nKernelGetUcredPrison, GlobalFunc, shText, (ulong)_kernelGetUcredPrisonOff, (ulong)_kernelGetUcredPrisonBytes);
            WriteSym(symtab, symKernelSetUcredPrison, nKernelSetUcredPrison, GlobalFunc, shText, (ulong)_kernelSetUcredPrisonOff, (ulong)_kernelSetUcredPrisonBytes);
            WriteSym(symtab, symKernelGetRootVnode, nKernelGetRootVnode, GlobalFunc, shText, (ulong)_kernelGetRootVnodeOff, (ulong)_kernelGetRootVnodeBytes);
            WriteSym(symtab, symKernelGetProcFiledesc, nKernelGetProcFiledesc, GlobalFunc, shText, (ulong)_kernelGetProcFiledescOff, (ulong)_kernelGetProcFiledescBytes);
            WriteSym(symtab, symKernelGetProcRootdir, nKernelGetProcRootdir, GlobalFunc, shText, (ulong)_kernelGetProcRootdirOff, (ulong)_kernelGetProcRootdirBytes);
            WriteSym(symtab, symKernelSetProcRootdir, nKernelSetProcRootdir, GlobalFunc, shText, (ulong)_kernelSetProcRootdirOff, (ulong)_kernelSetProcRootdirBytes);
            WriteSym(symtab, symKernelGetProcJaildir, nKernelGetProcJaildir, GlobalFunc, shText, (ulong)_kernelGetProcJaildirOff, (ulong)_kernelGetProcJaildirBytes);
            WriteSym(symtab, symKernelSetProcJaildir, nKernelSetProcJaildir, GlobalFunc, shText, (ulong)_kernelSetProcJaildirOff, (ulong)_kernelSetProcJaildirBytes);
            WriteSym(symtab, symKernelDynlibFindHandle, nKernelDynlibFindHandle, GlobalFunc, shText, (ulong)_kernelDynlibFindHandleOff, (ulong)_kernelDynlibFindHandleBytes);
            WriteSym(symtab, symKernelDynlibMapbase, nKernelDynlibMapbase, GlobalFunc, shText, (ulong)_kernelDynlibMapbaseOff, (ulong)_kernelDynlibMapbaseBytes);
            WriteSym(symtab, symKernelDynlibPath, nKernelDynlibPath, GlobalFunc, shText, (ulong)_kernelDynlibPathOff, (ulong)_kernelDynlibPathBytes);
            WriteSym(symtab, symKernelDynlibFiniAddr, nKernelDynlibFiniAddr, GlobalFunc, shText, (ulong)_kernelDynlibFiniAddrOff, (ulong)_kernelDynlibFiniAddrBytes);
            WriteSym(symtab, symKernelDynlibInitAddr, nKernelDynlibInitAddr, GlobalFunc, shText, (ulong)_kernelDynlibInitAddrOff, (ulong)_kernelDynlibInitAddrBytes);
            WriteSym(symtab, symKernelDynlibEntryAddr, nKernelDynlibEntryAddr, GlobalFunc, shText, (ulong)_kernelDynlibEntryAddrOff, (ulong)_kernelDynlibEntryAddrBytes);
            WriteSym(symtab, symKernelGetVmemEntry, nKernelGetVmemEntry, GlobalFunc, shText, (ulong)_kernelGetVmemEntryOff, (ulong)_kernelGetVmemEntryBytes);
            WriteSym(symtab, symKernelSetVmemProt, nKernelSetVmemProt, GlobalFunc, shText, (ulong)_kernelSetVmemProtOff, (ulong)_kernelSetVmemProtBytes);
            WriteSym(symtab, symKernelMprotect, nKernelMprotect, GlobalFunc, shText, (ulong)_kernelMprotectOff, (ulong)_kernelMprotectBytes);
            WriteSym(symtab, symKernelGetlong, nKernelGetlong, GlobalFunc, shText, (ulong)_kernelGetlongOff, (ulong)_kernelGetlongBytes);
            WriteSym(symtab, symKernelSetlong, nKernelSetlong, GlobalFunc, shText, (ulong)_kernelSetlongOff, (ulong)_kernelSetlongBytes);
            WriteSym(symtab, symKernelGetint, nKernelGetint, GlobalFunc, shText, (ulong)_kernelGetintOff, (ulong)_kernelGetintBytes);
            WriteSym(symtab, symKernelSetint, nKernelSetint, GlobalFunc, shText, (ulong)_kernelSetintOff, (ulong)_kernelSetintBytes);
            WriteSym(symtab, symKernelGetQaflags, nKernelGetQaflags, GlobalFunc, shText, (ulong)_kernelGetQaflagsOff, (ulong)_kernelGetQaflagsBytes);
            WriteSym(symtab, symKernelGetchar, nKernelGetchar, GlobalFunc, shText, (ulong)_kernelGetcharOff, (ulong)_kernelGetcharBytes);
            WriteSym(symtab, symKernelSetchar, nKernelSetchar, GlobalFunc, shText, (ulong)_kernelSetcharOff, (ulong)_kernelSetcharBytes);
            WriteSym(symtab, symKernelGetshort, nKernelGetshort, GlobalFunc, shText, (ulong)_kernelGetshortOff, (ulong)_kernelGetshortBytes);
            WriteSym(symtab, symKernelSetshort, nKernelSetshort, GlobalFunc, shText, (ulong)_kernelSetshortOff, (ulong)_kernelSetshortBytes);
            WriteSym(symtab, symKernelSetQaflags, nKernelSetQaflags, GlobalFunc, shText, (ulong)_kernelSetQaflagsOff, (ulong)_kernelSetQaflagsBytes);
            WriteSym(symtab, symKernelGetFwVersion, nKernelGetFwVersion, GlobalFunc, shText, (ulong)_kernelGetFwVersionOff, (ulong)_kernelGetFwVersionBytes);
            WriteSym(symtab, symKernelGetProcThread, nKernelGetProcThread, GlobalFunc, shText, (ulong)_kernelGetProcThreadOff, (ulong)_kernelGetProcThreadBytes);
            WriteSym(symtab, symKernelGetProcFile, nKernelGetProcFile, GlobalFunc, shText, (ulong)_kernelGetProcFileOff, (ulong)_kernelGetProcFileBytes);
            WriteSym(symtab, symKernelGetVmemProtection, nKernelGetVmemProtection, GlobalFunc, shText, (ulong)_kernelGetVmemProtectionOff, (ulong)_kernelGetVmemProtectionBytes);
            WriteSym(symtab, symKernelOverlapSockets, nKernelOverlapSockets, GlobalFunc, shText, (ulong)_kernelOverlapSocketsOff, (ulong)_kernelOverlapSocketsBytes);
            WriteSym(symtab, symKernelGetUcredUid, nKernelGetUcredUid, GlobalFunc, shText, (ulong)_kernelGetUcredUidOff, (ulong)_kernelGetUcredUidBytes);
            WriteSym(symtab, symKernelSetUcredUid, nKernelSetUcredUid, GlobalFunc, shText, (ulong)_kernelSetUcredUidOff, (ulong)_kernelSetUcredUidBytes);
            WriteSym(symtab, symKernelGetUcredRuid, nKernelGetUcredRuid, GlobalFunc, shText, (ulong)_kernelGetUcredRuidOff, (ulong)_kernelGetUcredRuidBytes);
            WriteSym(symtab, symKernelSetUcredRuid, nKernelSetUcredRuid, GlobalFunc, shText, (ulong)_kernelSetUcredRuidOff, (ulong)_kernelSetUcredRuidBytes);
            WriteSym(symtab, symKernelGetUcredSvuid, nKernelGetUcredSvuid, GlobalFunc, shText, (ulong)_kernelGetUcredSvuidOff, (ulong)_kernelGetUcredSvuidBytes);
            WriteSym(symtab, symKernelSetUcredSvuid, nKernelSetUcredSvuid, GlobalFunc, shText, (ulong)_kernelSetUcredSvuidOff, (ulong)_kernelSetUcredSvuidBytes);
            WriteSym(symtab, symKernelGetUcredRgid, nKernelGetUcredRgid, GlobalFunc, shText, (ulong)_kernelGetUcredRgidOff, (ulong)_kernelGetUcredRgidBytes);
            WriteSym(symtab, symKernelSetUcredRgid, nKernelSetUcredRgid, GlobalFunc, shText, (ulong)_kernelSetUcredRgidOff, (ulong)_kernelSetUcredRgidBytes);
            WriteSym(symtab, symKernelGetUcredSvgid, nKernelGetUcredSvgid, GlobalFunc, shText, (ulong)_kernelGetUcredSvgidOff, (ulong)_kernelGetUcredSvgidBytes);
            WriteSym(symtab, symKernelSetUcredSvgid, nKernelSetUcredSvgid, GlobalFunc, shText, (ulong)_kernelSetUcredSvgidOff, (ulong)_kernelSetUcredSvgidBytes);
            WriteSym(symtab, symKernelGetUcredNgroups, nKernelGetUcredNgroups, GlobalFunc, shText, (ulong)_kernelGetUcredNgroupsOff, (ulong)_kernelGetUcredNgroupsBytes);
            WriteSym(symtab, symKernelSetUcredNgroups, nKernelSetUcredNgroups, GlobalFunc, shText, (ulong)_kernelSetUcredNgroupsOff, (ulong)_kernelSetUcredNgroupsBytes);
            WriteSym(symtab, symKernelSetUcredSceAttr0, nKernelSetUcredSceAttr0, GlobalFunc, shText, (ulong)_kernelSetUcredSceAttr0Off, (ulong)_kernelSetUcredSceAttr0Bytes);
            WriteSym(symtab, symDladdr, nDladdr, GlobalFunc, shText, (ulong)_dladdrOff, (ulong)_dladdrBytes);
            WriteSym(symtab, symKernelFwVersion, nKernelFwVersion, GlobalObject, shBss, BssOffKernelFwVersion, 4);
            WriteSym(symtab, symKernelTextBase, nKernelTextBase, GlobalObject, shBss, BssOffKernelTextBase, 8);
            WriteSym(symtab, symKernelBusDataDevices, nKernelBusDataDevices, GlobalObject, shBss, BssOffKernelBusDataDevices, 8);
            WriteSym(symtab, symKernelTargetid, nKernelTargetid, GlobalObject, shBss, BssOffKernelTargetid, 8);
            WriteSym(symtab, symKernelUtokenFlags, nKernelUtokenFlags, GlobalObject, shBss, BssOffKernelUtokenFlags, 8);
            WriteSym(symtab, symBssStart, nBssStart, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symBssEnd, nBssEnd, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symInitStart, nInitStart, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symInitEnd, nInitEnd, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symFiniStart, nFiniStart, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symFiniEnd, nFiniEnd, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symMain, nMain, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symImageStart, nImageStart, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symDynamic, nDynamic, GlobalNoType, 0, 0, 0);
            WriteSym(symtab, symSysmodtab, nSysmodtab, GlobalObject, shSysmodtab, 0, SysmodTabSize);
            WriteSym(symtab, symNataotTcb, nNataotTcb, GlobalObject, shBss, BssOffNataotTcb, 0x300);
            WriteSym(symtab, symSavedFsbase, nSavedFsbase, GlobalObject, shBss, BssOffSavedFsbase, 8);
            WriteSym(symtab, symSavedRetaddr, nSavedRetaddr, GlobalObject, shBss, BssOffSavedRetaddr, 8);

            IReadOnlyList<Reloc> relocations = _relocations ?? [];
            byte[] relaText = new byte[24 * relocations.Count];
            int Symbol(RelocSymbol s) => s switch
            {
                RelocSymbol.PayloadArgs => symPayloadArgs,
                RelocSymbol.BssStart => symBssStart,
                RelocSymbol.BssEnd => symBssEnd,
                RelocSymbol.InitArrayStart => symInitStart,
                RelocSymbol.InitArrayEnd => symInitEnd,
                RelocSymbol.Main => symMain,
                RelocSymbol.FiniArrayStart => symFiniStart,
                RelocSymbol.FiniArrayEnd => symFiniEnd,
                RelocSymbol.KlogSlot => symKlogSlot,
                RelocSymbol.GotScratch => symGotScratch,
                RelocSymbol.PtrSyscall => symPtrSyscall,
                RelocSymbol.ImageStart => symImageStart,
                RelocSymbol.Dynamic => symDynamic,
                RelocSymbol.DlsymFn => symDlsymFn,
                RelocSymbol.DlsymOk => symDlsymOk,
                RelocSymbol.PipeAddr => symPipeAddr,
                RelocSymbol.RwPipe0 => symRwPipe0,
                RelocSymbol.RwPipe1 => symRwPipe1,
                RelocSymbol.RwPair0 => symRwPair0,
                RelocSymbol.RwPair1 => symRwPair1,
                RelocSymbol.KdataBase => symKdataBase,
                RelocSymbol.Allproc => symAllproc,
                RelocSymbol.KlogSnprintf => symKlogSnprintf,
                RelocSymbol.KlogVsnprintf => symKlogVsnprintf,
                RelocSymbol.KlogStrerror => symKlogStrerror,
                RelocSymbol.KlogError => symKlogError,
                RelocSymbol.RtldStrcpy => symRtldStrcpy,
                RelocSymbol.RtldStrcat => symRtldStrcat,
                RelocSymbol.RtldStrcmp => symRtldStrcmp,
                RelocSymbol.RtldStrncmp => symRtldStrncmp,
                RelocSymbol.RtldStrlen => symRtldStrlen,
                RelocSymbol.RtldSprintf => symRtldSprintf,
                RelocSymbol.RtldCalloc => symRtldCalloc,
                RelocSymbol.RtldFree => symRtldFree,
                RelocSymbol.RtldGetenv => symRtldGetenv,
                RelocSymbol.DlfcnDlerrno => symDlfcnDlerrno,
                RelocSymbol.DlfcnRoot => symDlfcnRoot,
                RelocSymbol.DlfcnGetargc => symDlfcnGetargc,
                RelocSymbol.DlfcnGetargv => symDlfcnGetargv,
                RelocSymbol.DlfcnEnviron => symDlfcnEnviron,
                RelocSymbol.DlfcnStrerror => symDlfcnStrerror,
                RelocSymbol.DlfcnSceLoadMod => symDlfcnSceLoadMod,
                RelocSymbol.DlfcnSceUnloadMod => symDlfcnSceUnloadMod,
                RelocSymbol.DlfcnSceSysmodLoad => symDlfcnSceSysmodLoad,
                RelocSymbol.DlfcnMalloc => symDlfcnMalloc,
                RelocSymbol.DlfcnCalloc => symDlfcnCalloc,
                RelocSymbol.DlfcnFree => symDlfcnFree,
                RelocSymbol.RtldMemcpy => symRtldMemcpy,
                RelocSymbol.Jmpbuf => symJmpbuf,
                RelocSymbol.VmspaceVmPmap => symVmspaceVmPmap,
                RelocSymbol.KernelRootvnode => symKernelRootvnode,
                RelocSymbol.KernelSecurityFlags => symKernelSecurityFlags,
                RelocSymbol.KernelQaFlags => symKernelQaFlags,
                RelocSymbol.KernelPrison0 => symKernelPrison0,
                RelocSymbol.KernelVmspacePRoot => symKernelVmspacePRoot,
                RelocSymbol.KernelFwVersion => symKernelFwVersion,
                RelocSymbol.KernelTextBase => symKernelTextBase,
                RelocSymbol.KernelBusDataDevices => symKernelBusDataDevices,
                RelocSymbol.KernelTargetid => symKernelTargetid,
                RelocSymbol.KernelUtokenFlags => symKernelUtokenFlags,
                RelocSymbol.SysmodTab => symSysmodtab,
                RelocSymbol.NataotTcb => symNataotTcb,
                RelocSymbol.SavedFsbase => symSavedFsbase,
                RelocSymbol.SavedRetaddr => symSavedRetaddr,
                _ => throw new InvalidOperationException(),
            };
            for (int i = 0; i < relocations.Count; i++)
                WriteRela(relaText, i, relocations[i].Offset, Symbol(relocations[i].Sym), relocations[i].Type, relocations[i].Addend);

            // Build the sysmodtab section data (137 entries * 16 bytes = 2192 bytes).
            // Each entry: 8-byte pointer (zero, patched by R_X86_64_64 relocation) + uint32 sysmod_id + 4-byte pad.
            byte[] sysmodtabData = new byte[SysmodTabSize];
            for (int si = 0; si < SysmodEntries.Length; si++)
            {
                int off = si * SysmodEntrySize;
                // bytes 0-7: zero (pointer filled by R_X86_64_64 -> R_X86_64_RELATIVE at link/load time)
                BinaryPrimitives.WriteUInt32LittleEndian(sysmodtabData.AsSpan(off + 8), SysmodEntries[si].Id);
                // bytes 12-15: zero padding
            }

            // Build .rela.data.rel.ro.sysmodtab: one R_X86_64_64 per entry, targeting symStart (value=0 in .text)
            // with addend = string offset in .text. The linker resolves this to an absolute address and
            // emits R_X86_64_RELATIVE in the output .rela.dyn; rtld_payload_init fixes up at load time.
            byte[] relaSysmodtab = new byte[24 * SysmodEntries.Length];
            for (int si = 0; si < SysmodEntries.Length; si++)
                WriteRela(relaSysmodtab, si, si * SysmodEntrySize, symStart, R64, _sysmodtabStringOffs[si]);

            var shstr = new StringTable();
            int nTextS = shstr.Add(".text");
            int nRelaTextS = shstr.Add(".rela.text");
            int nBssS = shstr.Add(".bss");
            int nSysmodtabS = shstr.Add(".data.rel.ro.sysmodtab");
            int nRelaSysmodtabS = shstr.Add(".rela.data.rel.ro.sysmodtab");
            int nSymS = shstr.Add(".symtab");
            int nStrS = shstr.Add(".strtab");
            int nShStrS = shstr.Add(".shstrtab");
            byte[] shstrBytes = shstr.ToBytes();

            var body = new List<byte>();
            long textOff = Place(body, text);
            long relaTextOff = Place(body, relaText);
            long bssOff = 64 + body.Count;
            long sysmodtabOff = Place(body, sysmodtabData);
            long relaSysmodtabOff = Place(body, relaSysmodtab);
            long symOff = Place(body, symtab);
            long strOff = Place(body, strtabBytes);
            long shstrOff = Place(body, shstrBytes);
            Align(body, 8);
            long shdrOff = 64 + body.Count;

            const int sectionCount = 9;
            byte[] shdr = new byte[64 * sectionCount];
            WriteShdr(shdr, shText, nTextS, ShtProgBits, ShfAlloc | ShfExec, textOff, text.Length, 0, 0, 16, 0);
            WriteShdr(shdr, shRelaText, nRelaTextS, ShtRela, 0, relaTextOff, relaText.Length, shSym, shText, 8, 24);
            WriteShdr(shdr, shBss, nBssS, ShtNoBits, ShfAlloc | ShfWrite, bssOff, BssTotalSize, 0, 0, 16, 0);
            WriteShdr(shdr, shSysmodtab, nSysmodtabS, ShtProgBits, ShfAlloc | ShfWrite, sysmodtabOff, sysmodtabData.Length, 0, 0, 16, 0);
            WriteShdr(shdr, shRelaSysmodtab, nRelaSysmodtabS, ShtRela, 0, relaSysmodtabOff, relaSysmodtab.Length, shSym, shSysmodtab, 8, 24);
            WriteShdr(shdr, shSym, nSymS, ShtSymTab, 0, symOff, symtab.Length, shStr, 1, 8, 24);
            WriteShdr(shdr, shStr, nStrS, ShtStrTab, 0, strOff, strtabBytes.Length, 0, 0, 1, 0);
            WriteShdr(shdr, shShStr, nShStrS, ShtStrTab, 0, shstrOff, shstrBytes.Length, 0, 0, 1, 0);

            var output = new List<byte>(64 + body.Count + shdr.Length);
            output.AddRange(BuildHeader(shdrOff, shShStr, sectionCount));
            output.AddRange(body);
            output.AddRange(shdr);
            return [.. output];
        } // lock
    }

    private static long Place(List<byte> body, byte[] data)
    {
        Align(body, 8);
        long offset = 64 + body.Count;
        body.AddRange(data);
        return offset;
    }

    private static void Align(List<byte> body, int alignment)
    {
        while ((64 + body.Count) % alignment != 0) body.Add(0);
    }

    private static byte[] BuildHeader(long shoff, int shstrndx, int sectionCount)
    {
        byte[] e = new byte[64];
        e[0] = 0x7F; e[1] = (byte)'E'; e[2] = (byte)'L'; e[3] = (byte)'F';
        e[4] = 2; e[5] = 1; e[6] = 1; e[7] = 9;
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(0x10), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(0x12), 0x3E);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(0x14), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(e.AsSpan(0x28), (ulong)shoff);
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(0x34), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(0x3A), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(0x3C), (ushort)sectionCount);
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(0x3E), (ushort)shstrndx);
        return e;
    }

    private static void WriteSym(byte[] table, int index, int nameOff, byte info, int sectionIndex, ulong value, ulong size)
    {
        int b = index * 24;
        BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(b), (uint)nameOff);
        table[b + 4] = info;
        BinaryPrimitives.WriteUInt16LittleEndian(table.AsSpan(b + 6), (ushort)sectionIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(table.AsSpan(b + 8), value);
        BinaryPrimitives.WriteUInt64LittleEndian(table.AsSpan(b + 16), size);
    }

    private static void WriteRela(byte[] table, int index, int offset, int symbol, uint type, long addend)
    {
        int b = index * 24;
        BinaryPrimitives.WriteUInt64LittleEndian(table.AsSpan(b), (ulong)offset);
        BinaryPrimitives.WriteUInt64LittleEndian(table.AsSpan(b + 8), ((ulong)(uint)symbol << 32) | type);
        BinaryPrimitives.WriteInt64LittleEndian(table.AsSpan(b + 16), addend);
    }

    private static void WriteShdr(byte[] shdr, int index, int nameOff, uint type, ulong flags, long offset, long size,
        int link, int info, int align, int entsize)
    {
        int b = index * 64;
        BinaryPrimitives.WriteUInt32LittleEndian(shdr.AsSpan(b), (uint)nameOff);
        BinaryPrimitives.WriteUInt32LittleEndian(shdr.AsSpan(b + 4), type);
        BinaryPrimitives.WriteUInt64LittleEndian(shdr.AsSpan(b + 8), flags);
        BinaryPrimitives.WriteUInt64LittleEndian(shdr.AsSpan(b + 24), (ulong)offset);
        BinaryPrimitives.WriteUInt64LittleEndian(shdr.AsSpan(b + 32), (ulong)size);
        BinaryPrimitives.WriteUInt32LittleEndian(shdr.AsSpan(b + 40), (uint)link);
        BinaryPrimitives.WriteUInt32LittleEndian(shdr.AsSpan(b + 44), (uint)info);
        BinaryPrimitives.WriteUInt64LittleEndian(shdr.AsSpan(b + 48), (ulong)align);
        BinaryPrimitives.WriteUInt64LittleEndian(shdr.AsSpan(b + 56), (ulong)entsize);
    }

    private sealed class StringTable
    {
        private readonly List<byte> _bytes = [0];
        private readonly Dictionary<string, int> _off = new(StringComparer.Ordinal);
        public int Add(string value)
        {
            if (_off.TryGetValue(value, out int existing)) return existing;
            int offset = _bytes.Count;
            _bytes.AddRange(Encoding.ASCII.GetBytes(value));
            _bytes.Add(0);
            _off[value] = offset;
            return offset;
        }
        public byte[] ToBytes() => [.. _bytes];
    }
}
