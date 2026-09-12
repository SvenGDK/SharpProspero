// SharpProspero.Link - a linker for module output.
// Copyright (C) 2026 SvenGDK

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpProspero.Link;

/// <summary>
/// Writes the runtime-support compat object: a relocatable object that defines the small set of C-library
/// names the ahead-of-time runtime imports which the device modules do not publish directly. Each is a
/// thin definition — a tail call to the name the device does publish, a fixed result, or a clean refusal —
/// so the linked module needs no outside object for them. It is included alongside the compiled object and
/// the runtime archives.
/// </summary>
/// <remarks>
/// The set is the difference between what a compiled module imports and what the C and kernel modules
/// export (see <c>runtime/imports/compat.txt</c>). The large-file variants forward to the base name; a few
/// names map to a kernel entry; the rest return a fixed value an application module can accept (it does not
/// fork, is not a terminal, and does not walk its own program headers).
/// </remarks>
public static class CompatEmitter
{
    private const int ShtProgBits = 1;
    private const int ShtSymTab = 2;
    private const int ShtStrTab = 3;
    private const int ShtRela = 4;
    private const int ShtNoBits = 8;

    private const ulong ShfWrite = 0x1;
    private const ulong ShfAlloc = 0x2;
    private const ulong ShfExec = 0x4;
    private const ulong ShfTls = 0x400;

    private const uint RPlt32 = 4;     // R_X86_64_PLT32
    private const uint RTpOff32 = 23;  // R_X86_64_TPOFF32 (local-exec thread-local offset)
    private const uint RTlsGd = 19;    // R_X86_64_TLSGD (a pair of table slots, resolved as the module loads)
    private const uint RAbs64 = 1;     // R_X86_64_64 (a variable holding an address)

    private const byte TypeFunc = 2;
    private const byte TypeObject = 1;
    private const byte TypeTls = 6;
    private const byte BindLocal = 0;
    private const byte BindGlobal = 1;
    private const byte BindWeak = 2;

    // The per-thread scratch that readdir64 translates into. It lives in the object's own thread-local
    // block so concurrent directory reads on different threads never share it. Its name is object-local.
    private const string ReaddirBufSymbol = "__sp_readdir64_buf";
    private const int ReaddirBufSize = 288;   // a directory entry the runtime reads (280), rounded up to 8
    // The per-thread block holds the directory entry first and the error number after it.
    private const int ErrnoShadowOffset = ReaddirBufSize, ErrnoShadowSize = 4;
    private const int ThreadBlockSize = ErrnoShadowOffset + ErrnoShadowSize;

    // ---------------------------------------------------------------------------
    // Per-thread storage without local-exec TLS.
    //
    // A payload is not a module the runtime loader wires up; it is mapped by an out-of-process loader
    // that applies only base-relative fix-ups. A local-exec TLS load (mov fs:[0]; lea reg, [rax +
    // TPOFF32]) needs the host to have laid out a thread-local segment whose distance from the thread
    // pointer is what the R_X86_64_TPOFF32 relocation names, and the payload's host does neither. The
    // load reads garbage from fs:[0], the linker has nowhere to write the distance, and the payload
    // reads through a wild pointer the first time either accessor is called.
    //
    // For payload builds every reference to the per-thread block goes through pthread-key storage
    // instead: a shared init routine that races once to create a key with free() as the destructor,
    // and pthread_getspecific / pthread_setspecific with a calloc() on first touch per thread. The
    // errno slot and the readdir entry share one block, at the same offsets the TLS layout used, so
    // the payload sees the same memory shape a standalone module would.
    // ---------------------------------------------------------------------------

    /// <summary>The pthread_key_t slot (four bytes on this platform - FreeBSD lineage: pthread_key_t
    /// is a plain int) the shared init routine writes and every per-thread accessor reads.</summary>
    private const string PayloadKeySlotSymbol = "__sp_thread_block_key";

    /// <summary>The guard word the shared init routine sequences on. Three states: 0 = uninitialised;
    /// 1 = a thread is calling pthread_key_create right now; 2 = the key is ready. Reads and writes
    /// are ordered so a thread that lost the init race spins on the guard rather than proceeding
    /// with a key that has not been written.</summary>
    private const string PayloadKeyStateSymbol = "__sp_thread_block_state";

    /// <summary>The shared init routine, called from every per-thread accessor. Takes the key slot in
    /// rdi and the state word in rsi. Returns nothing. Runs pthread_key_create exactly once across
    /// the process, whichever thread wins the race, and blocks every other thread until that call
    /// returns. Every accessor gets a key it can read past this point.</summary>
    private const string PayloadKeyInitSymbol = "__sp_thread_block_key_init";

    /// <summary>The per-thread block accessor. Returns a pointer to the block in rax, or null on an
    /// allocation failure. Callers use offset zero for the readdir entry and
    /// <see cref="ErrnoShadowOffset"/> for the errno word - the same layout the TLS variant had.</summary>
    private const string PayloadThreadBlockSymbol = "__sp_thread_block";

    /// <summary>The pthread_create wrapper the payload build emits under the plain C name. Every
    /// pthread_create call the runtime issues reaches this instead of the device entry, and this
    /// forwards to the device call with a trampoline in place of the user start routine. The
    /// trampoline installs the per-thread TCB template <see cref="TcbSeedSymbol"/> on entry to the
    /// new thread and then jumps to the user start routine.</summary>
    private const string PayloadThreadTrampolineSymbol = "__sp_thread_trampoline";

    /// <summary>The 16-byte random seed the payload start object bakes into read-only text (published
    /// as <see cref="PayloadCrtEmitter.TcbSeedSymbol"/>). Payload builds reference it externally;
    /// standalone module builds define nothing under that name and do not emit the trampoline.</summary>
    public const string TcbSeedSymbol = "__sp_tcb_seed";

    /// <summary>The baked-in environment table the payload getenv searches. Each entry is a
    /// NUL-terminated "KEY=VALUE" string; an empty entry (a lone NUL) ends the table. The table
    /// lives in .data so the execute-only .text can reach it instruction-relative.</summary>
    private const string EnvTableSymbol = "__sp_env_table";

    /// <summary>Builds the NUL-separated environment table that getenv walks. The entries configure
    /// the NativeAOT GC to a bounded heap that fits inside the hijacked host process's remaining
    /// flexible-memory budget. Without a hard limit the GC auto-computes a regions_range from
    /// <c>total_physical_mem * 2</c>, whose bookkeeping block is only partially committed, and
    /// <c>initial_make_soh_regions</c> writes past the committed range into PROT_NONE pages.
    ///
    /// Only <c>GCHeapHardLimit</c> is set here. The other two sizing knobs that were here before
    /// (<c>GCTotalPhysicalMemory</c>, <c>GCRegionRange</c>) are deliberately absent:
    /// <list type="bullet">
    ///   <item><c>GCTotalPhysicalMemory</c> --- removing it lets the GC fall through to
    ///     <c>sysconf(_SC_PHYS_PAGES)</c>, which queries the host process's actual configured
    ///     flexible-memory budget via <c>sceKernelConfiguredFlexibleMemorySize</c>. A hardcoded
    ///     value cannot track the real budget of a hijacked host, and an inflated figure causes the
    ///     GC to size internal bookkeeping for memory the host does not have.</item>
    ///   <item><c>GCRegionRange</c> --- removing it lets the GC compute <c>5 * hard_limit</c>
    ///     (80 MB for a 16 MB ceiling). That range is virtual address space only, reserved via
    ///     <c>sceKernelReserveVirtualRange</c> with no flexible-memory cost. Its bookkeeping table
    ///     is 40 entries of 0xa8 bytes (~7 KB), trivially committed.</item>
    /// </list>
    ///
    /// Every memory-size knob is parsed as hexadecimal by the GC config reader
    /// (<c>ReadConfigValue</c> with <c>ecx=0</c> maps to the shl-4 hex loop). A decimal string
    /// read as hex reads orders of magnitude larger than intended: 16777216 (16 MB in decimal)
    /// reads as 0x16777216 (377 MB), which would oversize regions_range and overflow the
    /// seg_mapping_table. The HeapHardLimit value below is a hex string: 0x1000000 = 16 MB.
    /// Scalar knobs (gcServer, GCHeapCount, GCRetainVM) are also parsed through the same hex
    /// path but their values (0, 1) read identically in either base.</summary>
    private static byte[] BuildEnvTable()
    {
        var table = new List<byte>();
        void Entry(string kv) { table.AddRange(Encoding.ASCII.GetBytes(kv)); table.Add(0); }
        Entry("DOTNET_GCHeapHardLimit=1000000");            // 16 MB hard ceiling on GC heap (hex)
        Entry("DOTNET_gcServer=0");                         // workstation GC, single heap
        Entry("DOTNET_GCHeapCount=1");                      // one GC heap
        Entry("DOTNET_GCRetainVM=0");                       // release virtual memory
        table.Add(0);                                       // empty-string sentinel
        return [.. table];
    }

    /// <summary>Where the seed's two words land relative to the thread pointer. The runtime the
    /// payload carries reads its stack canary from <c>fs:[0x28]</c> and its pointer-guard cookie
    /// from <c>fs:[0x30]</c> - the offsets a glibc-derived runtime writes on thread bring-up and
    /// then hashes every callee-saved pointer against. Writing zero into either slot would make
    /// every guarded return abort the process on the first return that checks its canary, which is
    /// the second frame in any GC callback the runtime installs. The seed is 16 bytes on purpose:
    /// eight bytes at each offset, laid down in one pair of writes per thread.</summary>
    private const int TcbCanaryOffset = 0x28;
    private const int TcbGuardOffset = 0x30;

    /// <summary>External names the payload variant imports from libSceLibcInternal (handle 0x2) and
    /// libkernel_web (handle 0x2001). The kernel resolver accepts plain C names, so these are the
    /// names the fixup shim asks for by string.</summary>
    private const string ImportPthreadKeyCreate = "pthread_key_create";
    private const string ImportPthreadGetspecific = "pthread_getspecific";
    private const string ImportPthreadSetspecific = "pthread_setspecific";
    private const string ImportCalloc = "calloc";
    private const string ImportFree = "free";

    /// <summary>
    /// One defined function: its name, binding, code bytes, tail-call relocations, and an optional
    /// thread-local reference (where its address load starts, which register the address lands in, and
    /// the thread-local it names).
    /// </summary>
    private readonly record struct CompatFunc(
        string Name, bool Weak, byte[] Code, (int Offset, string Target)[] Relocs,
        (int Offset, int Register, string Symbol)? Tls = null,
        bool Hidden = false);

    // Register numbers, for the address loads below.
    private const int RegRax = 0, RegRdx = 2, RegRbx = 3, RegRdi = 7;

    /// <summary>The helper a library asks where one of its thread-locals ended up.</summary>
    public const string TlsGetAddrSymbol = "__tls_get_addr";

    // How many bytes an address load takes, and where in it the distance sits. The two forms below are
    // the same length on purpose: which one is written is settled after the code around it is laid out,
    // so a difference in length would move everything after it.
    private const int TlsLoadSize = 19;
    private const int TlsLoadDisp = 15;

    // Loading the address of a thread-local, the way an application does it: read the thread pointer,
    // then add a distance settled when the module was linked. The three leading bytes do nothing and
    // are there to make this the same length as the other form.
    private static byte[] TlsLoad(int register) =>
    [
        0x0F, 0x1F, 0x00,                                 // nop
        0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0,         // mov rax, fs:[0]        (this thread)
        0x48, 0x8D, (byte)(0x80 | (register << 3)), 0, 0, 0, 0,  // lea reg, [rax + this thread's word]
    ];

    // The same, the way a library does it: hand the helper a pair of table slots saying which module
    // owns the block and where in it the variable sits, and take the answer. Where the block ends up is
    // only settled once the module is loaded, so a library cannot write a distance in advance.
    private static byte[] TlsLoadThroughHelper(int register) =>
    [
        0x66, 0x48, 0x8D, 0x3D, 0, 0, 0, 0,               // lea rdi, [rip + the pair]
        0x66, 0x66, 0x48, 0xE8, 0, 0, 0, 0,               // call the helper
        0x48, 0x89, (byte)(0xC0 | register),              // mov reg, rax
    ];

    /// <summary>
    /// One defined pointer-sized variable: its name and the name whose address it holds, or null for a
    /// variable that starts out empty.
    /// </summary>
    private readonly record struct CompatData(string Name, string? PointsAt);

    // Code fragments.
    private static byte[] RetZero() => [0x31, 0xC0, 0xC3];                       // xor eax,eax ; ret
    private static byte[] RetImm(int value)                                     // mov eax, imm32 ; ret
    {
        byte[] c = [0xB8, 0, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteInt32LittleEndian(c.AsSpan(1), value);
        return c;
    }
    private static byte[] JmpTail() => [0xE9, 0, 0, 0, 0];                       // jmp rel32 (target patched by reloc)

    // Forward the current call unchanged to another name (same arguments, its result becomes ours).
    private static CompatFunc Forward(string name, string target) =>
        new(name, false, JmpTail(), [(1, target)]);

    // Forward to a name using the 3rd and 4th argument registers as the 1st and 2nd.
    // Used by clock_nanosleep(clockid, flags, req, rem) -> nanosleep(req, rem).
    private static CompatFunc ForwardShiftTwo(string name, string target)
    {
        // mov rdi, rdx ; mov rsi, rcx ; jmp target
        byte[] code = [0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0xE9, 0, 0, 0, 0];
        return new(name, false, code, [(7, target)]);
    }

    private static CompatFunc Value(string name, int value) => new(name, false, RetImm(value), []);
    private static CompatFunc Zero(string name) => new(name, false, RetZero(), []);
    private static CompatFunc WeakZero(string name) => new(name, true, RetZero(), []);

    // getrlimit(resource, rlim): report that no resource has a limit.
    //
    // A refusal here (returning -1 and leaving the output structure uninitialised) was safe as
    // long as every caller checked the return code first: the collector's measure of how much
    // address space the process may hold does check, and falls back to an internal ceiling that
    // happens to work. But the refusal writes a reason into the error place, and the error place
    // is the same word the next kernel call reads back when it needs to report its own failure:
    // the code left behind by the refusal can leak across into a later read that has nothing to
    // do with limits, and the later read is done from a path whose failure is not logged. On this
    // platform no process-wide limit constrains the module, so both halves of the output are set
    // to no-limit and the call succeeds, which is the truth rather than a guess, and leaves the
    // error place alone.
    private static CompatFunc GetRlimit()
    {
        byte[] code =
        [
            0x48, 0xC7, 0x06, 0xFF, 0xFF, 0xFF, 0xFF,        // mov qword [rsi], -1      (rlim_cur = no limit)
            0x48, 0xC7, 0x46, 0x08, 0xFF, 0xFF, 0xFF, 0xFF,   // mov qword [rsi+8], -1    (rlim_max = no limit)
            0x31, 0xC0,                                       // xor eax, eax             (success)
            0xC3,                                             // ret
        ];
        return new("getrlimit", false, code, []);
    }

    /// <summary>
    /// The number a routine with no counterpart here answers with, as the runtime counts them.
    /// </summary>
    private const byte NoSuchRoutine = 38;              // "not implemented", in the runtime's numbering

    /// <summary>
    /// The number for an argument the platform will not accept, as the runtime counts them. Both sides
    /// happen to agree on it, but it is written the runtime's way because that is what reads it.
    /// </summary>
    private const byte InvalidArgument = 22;

    /// <summary>
    /// A refusal says why it refused. Callers do not merely test the result: many wrap the call in a
    /// loop that retries for as long as the number says the call was interrupted, and a refusal that
    /// leaves that number alone inherits whatever the last call to anything left there. If that
    /// happened to be the interrupted one, the loop retries a call whose answer can never change, and
    /// does so without a system call to slow it down - a module that started, stopped responding, and
    /// burns a processor doing it. Saying "there is no such routine" ends every one of those loops.
    /// </summary>
    private static CompatFunc Refuse(string name) => Refusal(name, [0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);

    // A refusal that fills the whole register rather than its lower half. An entry declared to return a
    // pointer or a 64-bit count is compared over all 64 bits by its caller, and writing only the lower
    // half leaves the upper half as it was - zero, on the path that reaches these - so the result reads
    // as 0x00000000FFFFFFFF, a large positive number, and the caller takes the refusal for a success.
    private static CompatFunc RefuseWide(string name) =>
        Refusal(name, [0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF]);   // mov rax, -1

    /// <summary>
    /// A refusal that answers nothing rather than -1, and still says why. An entry declared to return
    /// a pointer reports failure by answering none, so it needs the same reason behind it: a caller
    /// that tells "there is nothing" from "something went wrong" tells them apart by that number, and
    /// one of these sits inside a retry loop like the rest.
    /// </summary>
    private static CompatFunc RefuseNull(string name) => Refusal(name, [0x31, 0xC0]);   // xor eax, eax

    private static CompatFunc Refusal(string name, byte[] answer)
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0xBF, NoSuchRoutine, 0x00, 0x00, 0x00);      // mov edi, there is no such routine
        a.Call(SetErrnoSymbol);
        a.Emit(answer);
        a.Emit(0x5D, 0xC3);                                 // pop rbp ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new(name, false, code, relocs);
    }

    /// <summary>
    /// Records why a call refused, taken from the coded failure it answered with, and leaves the code
    /// in place for the caller to load afterwards.
    ///
    /// The memory and affinity entry points do not put the reason where the runtime reads it. They
    /// answer a single code built as a fixed high half plus the platform's own number for what went
    /// wrong, and on the paths that refuse before reaching a system call there is no system call to
    /// leave that number anywhere. So the low half is taken out of the code, put through the same
    /// numbering every other error goes through - which is not the identity, since two of the low
    /// numbers trade places - and written where the runtime looks. Without this the caller reads
    /// whatever the last call to anything left there and reports an unrelated failure.
    ///
    /// It marks "unnamed" and "tell", so a caller with a reason of its own can jump to "tell" with the
    /// number already in edi. It ends in a call, so every register a call may clobber is gone - the
    /// answer has to be loaded after it, not before.
    /// </summary>
    private static void EmitCodedErrno(Asm a)
    {
        a.Emit(0x0F, 0xB7, 0xF8);                           // movzx edi, ax   (the platform's number)
        a.Emit(0x81, 0xFF); a.Emit32(ErrorTableSize);       // cmp edi, the numbering's reach
        a.JumpIfAtOrAbove("unnamed");
        int at = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the numbering]
        a.Emit(0x0F, 0xB6, 0x3C, 0x38);                     // movzx edi, byte [rax + rdi]
        a.JumpIfAlways("tell");
        a.Mark("unnamed");
        a.Emit(0xBF, UnnamedError, 0x00, 0x00, 0x00);       // mov edi, no name for it
        a.Mark("tell");
        a.Note(at, ErrorTableSymbol);
        a.Call(SetErrnoSymbol);
    }

    /// <summary>
    /// The start of the image, at link-time address zero. Reached instruction-relative it reads back
    /// as the address the module was loaded at. Every linker defines this name, so an object using it
    /// links the same way whichever one builds the module.
    /// </summary>
    public const string ModuleBaseSymbol = "__executable_start";

    /// <summary>
    /// The end of the code group, at its link-time address. With the image start it gives the extent
    /// the unwinder matches a program counter against.
    /// </summary>
    public const string TextEndSymbol = "_etext";

    /// <summary>
    /// The frame-lookup index, at its link-time address, or the image start when the module carries
    /// none. The unwinder finds it through the header this name stands for.
    /// </summary>
    public const string FrameIndexSymbol = "__GNU_EH_FRAME_HDR";

    /// <summary>
    /// The end of that index. The unwinder is handed the index as a range, and measures it by the
    /// length in the header rather than by reading a length out of the index itself, so a header that
    /// names the start and leaves the length at zero describes an empty range and is refused.
    /// </summary>
    public const string FrameIndexEndSymbol = "__GNU_EH_FRAME_HDR_END";

    /// <summary>
    /// The marker the C module publishes to record that a module was linked against it. The
    /// process parameters name it, so the linker has to be able to find it among the imports.
    /// </summary>
    public const string LibcMarkerName = "Need_sceLibc";

    // The name dladdr reports for the module. The one caller that reads it hands the pointer straight to
    // a string length, so it cannot be null - a name that is merely approximate costs nothing, a null one
    // faults. It lives among the variables rather than in the code, which is mapped execute-only and
    // cannot be read.
    private const string ModuleNameSymbol = "__sp_module_name";
    private static readonly byte[] ModuleNameText = "/app0/eboot.bin\0"u8.ToArray();

    // dladdr(address, info): fills in what the runtime reads out of it, which is the address the
    // module holding that address was loaded at. Nothing published here reports that for an arbitrary
    // address, but the one caller asks about a pointer inside this module, and this module's own base
    // is reachable: the linker puts a symbol at link-time address zero, so reaching it
    // instruction-relative gives the address the module was placed at.
    //
    // A stub reporting failure here is not a small thing. The runtime treats the answer as the handle
    // that identifies the module, and a module registered under a null handle is one the runtime
    // cannot match an address back to.
    private static CompatFunc DlAddr()
    {
        byte[] code =
        [
            0x48, 0x8D, 0x05, 0, 0, 0, 0,       // 0x00 lea rax, [rip + the image start]  (rel32 at 3)
            0x48, 0x89, 0x46, 0x08,             // 0x07 mov [rsi + 8], rax   (where it was loaded)
            0x48, 0x8D, 0x05, 0, 0, 0, 0,       // 0x0B lea rax, [rip + the name]  (rel32 at 0x0E)
            0x48, 0x89, 0x06,                   // 0x12 mov [rsi], rax      (the file it came from)
            0x48, 0xC7, 0x46, 0x10, 0, 0, 0, 0, // 0x15 mov qword [rsi+16], 0 (no symbol name)
            0x48, 0xC7, 0x46, 0x18, 0, 0, 0, 0, // 0x1D mov qword [rsi+24], 0 (no symbol address)
            0xB8, 0x01, 0x00, 0x00, 0x00,       // 0x25 mov eax, 1           (found)
            0xC3,                               // 0x2A ret
        ];
        return new("dladdr", false, code, [(3, ModuleBaseSymbol), (0x0E, ModuleNameSymbol)]);
    }

    // dl_iterate_phdr(callback, argument): describe each loaded module to the callback.
    //
    // One module is one description. What reads it is the unwinder, and what it needs from the
    // description is where the module was placed, how far its code reaches, and where its frame index
    // is - the index the linker already builds and already declares a header for. Answering nothing,
    // which is what this did, tells the unwinder there is no frame information anywhere in the process:
    // every walk up the stack stops at the first frame, so an exception thrown through a frame that has
    // to be unwound ends the module instead of reaching the handler that would have caught it, and
    // nothing says why.
    //
    // The two headers are built here rather than read out of the image. A module's own header table
    // lies in the head of the code group, and that group is mapped to execute without read - reading it
    // faults - so both addresses are reached instruction-relative from names the linker places instead.
    // The description and the headers live on this frame and are only read while the callback runs.
    private const uint PtLoad = 1, PtGnuEhFrame = 0x6474E550;
    private const int PhdrSize = 56, PhdrInfoSize = 64, DlFrame = 2 * PhdrSize + PhdrInfoSize;
    private const int InfoAt = 2 * PhdrSize;

    private static CompatFunc DlIteratePhdr()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x48, 0x81, 0xEC); a.Emit32(DlFrame);        // sub rsp, the frame
        a.Emit(0x49, 0x89, 0xFA);                           // mov r10, rdi   (the callback)
        a.Emit(0x49, 0x89, 0xF3);                           // mov r11, rsi   (its argument)
        // Everything not written below reads as zero, which is what each of those fields means here.
        a.Emit(0x48, 0x89, 0xE7);                           // mov rdi, rsp
        a.Emit(0xB9); a.Emit32(DlFrame);                    // mov ecx, the frame
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.Emit(0xF3, 0xAA);                                 // rep stosb

        // The first header covers the code, from the image start to the end of the group. Its address
        // is zero because the image starts there, and the reader adds where the module was placed.
        a.Emit(0xC7, 0x04, 0x24); a.Emit32((int)PtLoad);            // mov dword [rsp], loadable
        a.Emit(0xC7, 0x44, 0x24, 0x04); a.Emit32(5);               // mov dword [rsp+4], read|execute
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the end of the code]
        a.Emit(0x48, 0x8D, 0x0D, 0, 0, 0, 0);               // lea rcx, [rip + the image start]
        a.Emit(0x48, 0x29, 0xC8);                           // sub rax, rcx
        a.Emit(0x48, 0x89, 0x44, 0x24, 0x20);               // mov [rsp+32], rax   (stored length)
        a.Emit(0x48, 0x89, 0x44, 0x24, 0x28);               // mov [rsp+40], rax   (length in memory)

        // The second covers the frame index. A module built without one names the image start for it,
        // and there is then nothing to describe, so only the first header is offered.
        //
        // Its length matters as much as its address. The reader is handed the index as a range - it
        // takes the start from this header and the end from the start plus the length in this same
        // header, because the index does not record its own size - and a range whose two ends meet is
        // refused before a byte of it is read. Leaving the length at zero therefore reported an index
        // that exists and is empty, which is worse than reporting none at all: the reader stopped at
        // the refusal without recording where the frame information was, so every later walk up the
        // stack found no method for the address it was standing on and ended the module. Both lengths
        // are written, though only the one in memory is read, so the header does not contradict itself.
        a.Emit(0xC7, 0x44, 0x24, PhdrSize); a.Emit32(unchecked((int)PtGnuEhFrame));
        a.Emit(0xC7, 0x44, 0x24, PhdrSize + 4); a.Emit32(4);        // read
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the frame index]
        a.Emit(0x48, 0x29, 0xC8);                           // sub rax, rcx
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfEqual("codeonly"); // test rax, rax
        a.Emit(0x48, 0x89, 0x44, 0x24, PhdrSize + 16);      // mov [rsp+.. +16], rax  (its address)
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the end of the index]
        a.Emit(0x48, 0x29, 0xC8);                           // sub rax, rcx   (measured from the image)
        a.Emit(0x48, 0x2B, 0x44, 0x24, PhdrSize + 16);      // sub rax, its address (how far it reaches)
        a.Emit(0x48, 0x89, 0x44, 0x24, PhdrSize + 32);      // mov [rsp+.. +32], rax  (stored length)
        a.Emit(0x48, 0x89, 0x44, 0x24, PhdrSize + 40);      // mov [rsp+.. +40], rax  (length in memory)
        a.Emit(0x66, 0xC7, 0x84, 0x24); a.Emit32(InfoAt + 24); a.Emit(0x02, 0x00);   // two headers
        a.JumpIfAlways("described");
        a.Mark("codeonly");
        a.Emit(0x66, 0xC7, 0x84, 0x24); a.Emit32(InfoAt + 24); a.Emit(0x01, 0x00);   // one header

        a.Mark("described");
        a.Emit(0x48, 0x89, 0x8C, 0x24); a.Emit32(InfoAt);   // mov [info+0], rcx   (where it was placed)
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the name]
        a.Emit(0x48, 0x89, 0x84, 0x24); a.Emit32(InfoAt + 8);   // mov [info+8], rax
        a.Emit(0x48, 0x89, 0xE0);                           // mov rax, rsp
        a.Emit(0x48, 0x89, 0x84, 0x24); a.Emit32(InfoAt + 16);  // mov [info+16], rax  (the headers)
        // One module, and it is never unloaded: the count of modules added is one, of modules removed
        // zero. A reader that caches what it is told uses these to notice the set has changed.
        a.Emit(0x48, 0xC7, 0x84, 0x24); a.Emit32(InfoAt + 32); a.Emit32(1);

        a.Emit(0x48, 0x8D, 0xBC, 0x24); a.Emit32(InfoAt);   // lea rdi, [the description]
        a.Emit(0xBE); a.Emit32(PhdrInfoSize);               // mov esi, how big it is
        a.Emit(0x4C, 0x89, 0xDA);                           // mov rdx, r11
        a.Emit(0x41, 0xFF, 0xD2);                           // call r10
        a.Emit(0xC9, 0xC3);                                 // leave ; ret

        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        // The four instruction-relative addresses, found by their position rather than counted by hand.
        int[] leas = [.. Enumerable.Range(0, code.Length - 6)
            .Where(i => code[i] == 0x48 && code[i + 1] == 0x8D
                     && (code[i + 2] == 0x05 || code[i + 2] == 0x0D)
                     && code[i + 3] == 0 && code[i + 4] == 0 && code[i + 5] == 0 && code[i + 6] == 0)];
        if (leas.Length != 5)
            throw new ElfLinkException("The module description does not name five addresses.");
        return new("dl_iterate_phdr", false, code,
        [
            .. relocs,
            (leas[0] + 3, TextEndSymbol),
            (leas[1] + 3, ModuleBaseSymbol),
            (leas[2] + 3, FrameIndexSymbol),
            (leas[3] + 3, FrameIndexEndSymbol),
            (leas[4] + 3, ModuleNameSymbol),
        ]);
    }

    // mmap(addr, len, prot, flags, fd, offset): the anonymous private mapping the runtime reserves its
    // heap with. This platform has no mmap of its own - a range is asked for by handing an address slot
    // in and reading back where it was placed. The slot starts as the address the caller named, or zero
    // to let the system choose.
    //
    // Which call answers depends on what was asked for. A request for no access wants addresses and
    // nothing behind them, and there is a call that does exactly that; a request for access wants
    // memory out of the flexible budget, which is another. Both take the same slot.
    //
    // Pinning a range to a named address, and the protection bits: read-and-write is a single bit here
    // rather than read plus write, so a request for both folds onto it, and none, read, read-execute
    // and all already line up.
    private const byte MapFixed = 0x10, ProtReadWrite = 0x02, PosixReadWrite = 0x03;
    // The kinds of range that already have something behind them: memory taken from the flexible
    // budget, memory taken from the machine directly, a thread stack, and pool room. A range that is
    // none of these and carries no protection at all is one whose addresses are held and nothing more.
    private const byte RangeIsBacked = 0x0F;

    private static CompatFunc Mmap()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x48, 0x83, 0xEC, 0x10);                     // sub rsp, 16   (the address slot)
        // A length is rounded up to a whole page. Asking for memory hands back whole pages anyway, and
        // both of the platform's calls refuse a length that is not a multiple of one - so a request for
        // a few hundred bytes, which the ordinary call answers with a page, would be refused outright.
        a.Emit(0x48, 0x81, 0xC6, 0xFF, 0x3F, 0x00, 0x00);   // add rsi, page - 1
        a.Emit(0x48, 0x81, 0xE6, 0x00, 0xC0, 0xFF, 0xFF);   // and rsi, -page
        a.Emit(0x48, 0x89, 0x3C, 0x24);                     // mov [rsp], rdi
        // Of the caller's flags only the pinning bit carries over, and both sides spell it the same. An
        // address handed in without it is a suggestion on either side - the platform reads it as where
        // to start looking for room - so passing it through unchanged keeps a suggestion from hardening
        // into a demand that fails when those addresses are taken.
        a.Emit(0x83, 0xE1, MapFixed);                       // and ecx, pinned

        // Asking for no access is asking for room, not for memory: putting memory behind the whole of
        // it would spend the budget on a range nothing has written to yet. The platform holds addresses
        // and nothing else for exactly this, and a range held that way is filled afterwards by mapping
        // over it pinned, which is what the protection change below does the first time the range is
        // written to. The same call also answers the opposite request - a range pinned to addresses the
        // caller already holds is memory being given back - because mapping room over it pinned
        // replaces what was there, releasing the memory and leaving the addresses held.
        a.Emit(0x85, 0xD2); a.JumpIfNotEqual("access");      // test edx, edx
        a.Emit(0x48, 0x89, 0xE7);                           // mov rdi, rsp  (the address slot)
        a.Emit(0x89, 0xCA);                                 // mov edx, ecx  (pinned, or not)
        a.Emit(0x31, 0xC9);                                 // xor ecx, ecx  (any alignment)
        a.Call("sceKernelReserveVirtualRange");
        a.JumpIfAlways("settle");

        a.Mark("access");
        a.Emit(0x48, 0x89, 0xE7);                           // mov rdi, rsp  (the address slot)
        a.Emit(0x83, 0xFA, PosixReadWrite);                 // cmp edx, read|write
        a.JumpIfNotEqual("mapit");
        a.Emit(0xBA, ProtReadWrite, 0x00, 0x00, 0x00);      // mov edx, read-write
        a.Mark("mapit");
        // The mapping call reads two registers past the ones it documents, and coming from the ordinary
        // call both still hold that call's own arguments. The first decides whether the request is
        // refused outright: anything above three and it is, and what sits there is the caller's file,
        // which is -1 for a mapping backed by no file at all - so every request for memory was turned
        // away before it reached the platform, and nothing said so. The second is read whenever no
        // address was named, and a value in one particular range moves the mapping to a region kept for
        // the system; what sits there is the caller's offset, which is zero for these mappings, but
        // that is the caller's business to get right and not something to lean on. Both are cleared.
        a.Emit(0x45, 0x31, 0xC0);                           // xor r8d, r8d
        a.Emit(0x45, 0x31, 0xC9);                           // xor r9d, r9d
        a.Call("sceKernelMapFlexibleMemory");

        a.Mark("settle");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("refuse");     // test eax, eax
        a.Emit(0x48, 0x8B, 0x04, 0x24);                     // mov rax, [rsp]  (where it landed)
        a.Emit(0xC9, 0xC3);                                 // leave ; ret
        // Both calls this reaches report a refusal the same way, so the reason is recovered from the
        // code either of them answered with. Two of the refusals never reach a system call at all - a
        // length of nothing, and pinning to no address - so there is no other place it could come from.
        a.Mark("refuse");
        EmitCodedErrno(a);
        a.Emit(0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0xC3); // mov rax,-1 ; leave ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("mmap", false, code, relocs);
    }

    // mprotect(addr, len, prot): a protection change on memory that is already there, or the moment a
    // reserved range is first written to.
    //
    // The two cases need opposite calls and cannot be told apart by trying one and watching it fail, so
    // the range is asked about first.
    //
    // A protection change over a range that is held but empty **succeeds** and attaches nothing, so
    // going to it first leaves the memory untaken, tells the caller the range is his, and faults on the
    // first write. Going to the mapping call first does not separate them either: a held range already
    // occupies the address space, so a mapping that refuses to overwrite is turned away and lands right
    // back on the protection change. What distinguishes them is not the outcome of either call but
    // whether anything is behind the address, and the range report says so directly.
    private static CompatFunc MProtect(bool extraPage = false)
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x48, 0x83, 0xEC, 0x70);                     // sub rsp, 112
        // The frame holds the three arguments at [rbp-8], [rbp-16] and [rbp-24], and the range report
        // from [rbp-0x60] up to where the arguments start.
        // A protection change covers whole pages: the address moves back to the start of its page and
        // the length grows by as much, then rounds up. The platform's call refuses anything else, and
        // the runtime changes protection on ranges it sized in objects rather than in pages.
        a.Emit(0x48, 0x89, 0xF8);                           // mov rax, rdi
        a.Emit(0x25, 0xFF, 0x3F, 0x00, 0x00);               // and eax, page - 1
        a.Emit(0x48, 0x01, 0xC6);                           // add rsi, rax
        a.Emit(0x48, 0x81, 0xE7, 0x00, 0xC0, 0xFF, 0xFF);   // and rdi, -page
        a.Emit(0x48, 0x81, 0xC6, 0xFF, 0x3F, 0x00, 0x00);   // add rsi, page - 1
        a.Emit(0x48, 0x81, 0xE6, 0x00, 0xC0, 0xFF, 0xFF);   // and rsi, -page
        if (extraPage)
        {
            // The collector sizes its commit calls in objects and reads across the tail into the next
            // page: a range whose bookkeeping is one entry sits at some byte offset in the page it starts
            // on, and the entry itself is 168 bytes, so its last field lands past the first page. The
            // collector does not commit the second page from a separate call -- it assumes the first
            // commit's rounding covered it -- and if the first commit's size falls short of the second
            // page's beginning, that page is never taken from the flexible pool and the first field read
            // from it faults. One extra page beyond the rounded end fills that gap. This extension is for
            // the standalone environment where the host process's address space is tighter; an application
            // module's own collector sizes its commits in pages and the round-up is enough.
            a.Emit(0x48, 0x81, 0xC6, 0x00, 0x40, 0x00, 0x00); // add rsi, page
        }
        a.Emit(0x48, 0x89, 0x7D, 0xF8);                     // mov [rbp-8], rdi   (addr)
        a.Emit(0x48, 0x89, 0x75, 0xF0);                     // mov [rbp-16], rsi  (len)

        a.Emit(0x83, 0xFA, PosixReadWrite);                 // cmp edx, read|write
        a.JumpIfNotEqual("kept");
        a.Emit(0xBA, ProtReadWrite, 0x00, 0x00, 0x00);      // mov edx, read-write
        a.Mark("kept");
        a.Emit(0x89, 0x55, 0xE8);                           // mov [rbp-24], edx  (prot)

        // Ask what is at that address rather than guess. A range can be held without memory behind it,
        // and the two cases need opposite calls, so the report is what decides. Its protection sits at
        // offset 0x18 and the word saying what kind of range it is at 0x20; the whole report is 0x48
        // bytes, which is what the call is told so it fills all of it.
        a.Emit(0x48, 0x8B, 0x7D, 0xF8);                     // mov rdi, [rbp-8]
        a.Emit(0x31, 0xF6);                                 // xor esi, esi   (no search)
        a.Emit(0x48, 0x8D, 0x55, 0xA0);                     // lea rdx, [rbp-96]
        a.Emit(0xB9, 0x48, 0x00, 0x00, 0x00);               // mov ecx, 0x48
        a.Call("sceKernelVirtualQuery");
        // No report came back, so nothing here knows what that range is. The one thing that must not
        // happen then is placing memory over it: a mapping pinned to an address replaces whatever was
        // there, and if the range did hold something - this module's own image, say - it is gone and
        // the fault lands somewhere else entirely. Ask for the protection change instead and let the
        // platform refuse it if the range is not real.
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("keepit");
        // Two things have to agree before fresh memory is placed over a range, because placing it is
        // destructive: a mapping pinned to an address replaces whatever was there, so misreading a live
        // range as empty would throw away what it held - this module's own data, say, whose protection
        // the runtime changes while it starts. A range whose addresses are merely held carries no
        // protection at all *and* is none of the kinds that have something behind them. Anything else
        // is left to the protection change, which is harmless when the guess is wrong either way.
        a.Emit(0x8B, 0x45, 0xB8);                           // mov eax, [rbp-72]   (protection)
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("keepit");     // test eax, eax
        a.Emit(0x0F, 0xB6, 0x45, 0xC0);                     // movzbl [rbp-64], eax
        a.Emit(0xA8, RangeIsBacked);                        // test al, backed
        a.JumpIfNotEqual("keepit");

        // Nothing behind that range yet, so put memory behind it, pinned to the addresses that are
        // already held. This is the step the protection call cannot do: that one reports success over a
        // range that holds nothing and leaves it as empty as it found it, so the runtime believes it
        // owns memory it has not been given and faults on the first write.
        a.Emit(0x48, 0x8D, 0x7D, 0xF8);                     // lea rdi, [rbp-8]
        a.Emit(0x48, 0x8B, 0x75, 0xF0);                     // mov rsi, [rbp-16]
        a.Emit(0x8B, 0x55, 0xE8);                           // mov edx, [rbp-24]
        a.Emit(0xB9, MapFixed, 0x00, 0x00, 0x00);           // mov ecx, pinned
        a.Emit(0x45, 0x31, 0xC0);                           // xor r8d, r8d  (read past the arguments)
        a.Call("sceKernelMapFlexibleMemory");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("done");          // test eax, eax
        a.JumpIfAlways("refuse");

        // Memory is already there, so this is a protection change on what it holds and nothing moves.
        a.Mark("keepit");
        a.Emit(0x48, 0x8B, 0x7D, 0xF8);                     // mov rdi, [rbp-8]
        a.Emit(0x48, 0x8B, 0x75, 0xF0);                     // mov rsi, [rbp-16]
        a.Emit(0x8B, 0x55, 0xE8);                           // mov edx, [rbp-24]
        a.Call("sceKernelMprotect");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("refuse");     // test eax, eax
        a.Mark("done");
        a.Emit(0x31, 0xC0, 0xC9, 0xC3);                     // xor eax, eax ; leave ; ret
        // Whichever of the two calls refused, it answered a code carrying the reason, and neither
        // leaves that reason where the runtime reads it.
        a.Mark("refuse");
        EmitCodedErrno(a);
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0xC3);   // mov eax, -1 ; leave ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("mprotect", false, code, relocs);
    }

    // sysconf(name): the two answers the runtime acts on. The page size decides how the collector
    // reserves memory and the processor count how many threads it starts, so both are answered
    // properly; anything else reports that the value is not available, which every caller handles.
    // Branch displacements are worked out from where the labels land rather than written by hand. A
    // displacement counted by hand once sent the memory-size question to the processor-count answer,
    // which reported 128 KB of memory and was invisible until the module was on a console.
    private sealed class Asm
    {
        private readonly List<byte> _code = [];
        private readonly List<(int At, string Label)> _fixups = [];
        private readonly Dictionary<string, int> _labels = new(StringComparer.Ordinal);
        private readonly List<(int Offset, string Target)> _calls = [];

        public int Length => _code.Count;
        public void Emit(params byte[] bytes) => _code.AddRange(bytes);
        public void Mark(string label) => _labels[label] = _code.Count;

        /// <summary>Appends a four-byte immediate, so a constant is never split by hand.</summary>
        public void Emit32(int value) =>
            _code.AddRange([(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)]);

        // Every branch carries a full-width displacement rather than the short one. A short branch
        // reaches 127 bytes, and a routine that grows past that turns a correct jump into one that does
        // not reach - which is a build failure at best and, if the width were chosen by hand, a jump
        // into the middle of an instruction at worst. The wide form always reaches, and four bytes of
        // displacement in a handful of branches costs nothing.
        /// <summary>A conditional jump to a label placed later, taken when the last compare was equal.</summary>
        public void JumpIfEqual(string label)
        {
            _code.AddRange([0x0F, 0x84]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        public void JumpIfAlways(string label)
        {
            _code.Add(0xE9);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        public void JumpIfNotEqual(string label)
        {
            _code.AddRange([0x0F, 0x85]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A jump taken when the last result was zero or above.</summary>
        public void JumpIfNotNegative(string label)
        {
            _code.AddRange([0x0F, 0x89]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A jump taken when the last compare was at or above, counting without a sign.</summary>
        public void JumpIfAtOrAbove(string label)
        {
            _code.AddRange([0x0F, 0x83]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A jump taken when the last compare was below, counting without a sign.</summary>
        public void JumpIfBelow(string label)
        {
            _code.AddRange([0x0F, 0x82]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A jump taken when the last result was zero or below, counting with a sign.</summary>
        public void JumpIfNotPositive(string label)
        {
            _code.AddRange([0x0F, 0x8E]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A jump taken when the last compare was above, counting without a sign.</summary>
        public void JumpIfAbove(string label)
        {
            _code.AddRange([0x0F, 0x87]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A jump taken when the last result was below zero.</summary>
        public void JumpIfNegative(string label)
        {
            _code.AddRange([0x0F, 0x88]);
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>
        /// Records a name reached by an instruction that is not a call - an address load, say - so the
        /// linker fills its displacement the same way.
        /// </summary>
        public void Note(int offset, string target) => _calls.Add((offset, target));

        /// <summary>Appends a four-byte RIP-relative displacement to an internal label. The caller
        /// emits the opcode before this (a LEA, MOV, or any instruction whose displacement follows
        /// the opcode bytes). The displacement is resolved in <see cref="Build"/> the same way a
        /// branch displacement is: <c>target - (at + 4)</c>.</summary>
        public void Disp32(string label)
        {
            _fixups.Add((_code.Count, label));
            _code.AddRange([0, 0, 0, 0]);
        }

        /// <summary>A call to a name the linker binds, recording where its displacement sits.</summary>
        public void Call(string target)
        {
            _code.Add(0xE8);
            _calls.Add((_code.Count, target));
            _code.AddRange([0, 0, 0, 0]);
        }

        public (byte[] Code, (int Offset, string Target)[] Relocs) Build()
        {
            byte[] code = [.. _code];
            foreach ((int at, string label) in _fixups)
            {
                if (!_labels.TryGetValue(label, out int target))
                    throw new ElfLinkException($"A branch names '{label}', which is never placed.");
                BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(at), target - (at + 4));
            }
            return (code, [.. _calls]);
        }
    }

    // clock_nanosleep(clock, flags, request, remainder): sleep until a moment, or for a length of time.
    //
    // The device publishes only the call that sleeps for a length, so the two have to be bridged here,
    // and the bridge is the whole point. With the deadline flag set, the request is the moment to wake
    // at, not how long to wait: handing it to the length-based call unchanged asks for a sleep of
    // however long the clock has been running, which is the difference between a millisecond and hours.
    // The moment is turned into a length by reading the same clock the caller built it from and
    // subtracting - reading the same clock is what makes this right whatever that clock counts. A
    // moment already past becomes no wait at all rather than an enormous one.
    //
    // The result convention differs too: the length-based call answers -1 and leaves the reason
    // elsewhere, while this one answers the reason itself, so a refusal is fetched and returned.
    private const byte DeadlineFlag = 0x01;

    private static CompatFunc ClockNanosleep()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx        (keeps the stack aligned)
        a.Emit(0x48, 0x83, 0xEC, 0x28);                     // sub rsp, 40     (two moments)
        a.Emit(0x40, 0xF6, 0xC6, DeadlineFlag);             // test sil, deadline
        a.JumpIfNotEqual("deadline");

        // A length was asked for, which is what the device's call already takes.
        a.Emit(0x48, 0x89, 0xD7);                           // mov rdi, rdx
        a.Emit(0x48, 0x89, 0xCE);                           // mov rsi, rcx
        a.Call("nanosleep");
        a.JumpIfAlways("settle");

        // A moment was asked for. Read the same clock it was measured against, take the difference,
        // and wait that long.
        a.Mark("deadline");
        a.Emit(0x48, 0x89, 0xD3);                           // mov rbx, rdx    (the moment)
        a.Emit(0x48, 0x8D, 0x75, 0xD0);                     // lea rsi, [rbp-48] -> now
        a.Call("clock_gettime");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("settle");     // test eax, eax
        a.Emit(0x48, 0x8B, 0x03);                           // mov rax, [rbx]      seconds asked for
        a.Emit(0x48, 0x2B, 0x45, 0xD0);                     // sub rax, [rbp-48]   less seconds now
        a.Emit(0x48, 0x8B, 0x4B, 0x08);                     // mov rcx, [rbx+8]    nanoseconds asked for
        a.Emit(0x48, 0x2B, 0x4D, 0xD8);                     // sub rcx, [rbp-40]   less nanoseconds now
        // A negative nanosecond part borrows a whole second from the seconds part.
        a.Emit(0x48, 0x85, 0xC9); a.JumpIfNotNegative("whole"); // test rcx, rcx
        a.Emit(0x48, 0x81, 0xC1, 0x00, 0xCA, 0x9A, 0x3B);   // add rcx, 1000000000
        a.Emit(0x48, 0x83, 0xE8, 0x01);                     // sub rax, 1
        a.Mark("whole");
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfNotNegative("ahead"); // test rax, rax
        a.Emit(0x31, 0xC0);                                 // xor eax, eax          already past
        a.JumpIfAlways("done");
        a.Mark("ahead");
        a.Emit(0x48, 0x89, 0x45, 0xE0);                     // mov [rbp-32], rax     seconds to wait
        a.Emit(0x48, 0x89, 0x4D, 0xE8);                     // mov [rbp-24], rcx     nanoseconds to wait
        a.Emit(0x48, 0x8D, 0x7D, 0xE0);                     // lea rdi, [rbp-32]
        a.Emit(0x31, 0xF6);                                 // xor esi, esi          no remainder
        a.Call("nanosleep");

        // The device's call answers -1 and leaves the reason elsewhere; this one answers the reason
        // itself. It is read through the translating thunk rather than the device's own place, so what
        // comes back is the number the caller was compiled to compare against - and the place is left
        // as it was, which is what the call this stands in for does.
        a.Mark("settle");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("done");          // test eax, eax
        a.Call("__errno_location");
        a.Emit(0x8B, 0x00);                                 // mov eax, [rax]
        a.Mark("done");
        a.Emit(0x48, 0x83, 0xC4, 0x28, 0x5B, 0x5D, 0xC3);   // add rsp,40; pop rbx; pop rbp; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("clock_nanosleep", false, code, relocs);
    }

    // A signal set on this platform is four 32-bit words, one bit per signal, numbered from one: the
    // word is (signal - 1) / 32 and the bit is (signal - 1) % 32, for signals 1 to 128. Emptying and
    // adding are a few instructions each, and reporting success without doing either is the worst of
    // both: the caller reads back whatever was on the stack and hands that to the device as a set of
    // signals to act on.
    private const int SignalWords = 4, MaxSignal = 128;

    /// <summary>What the platform answers for a thread that is not there.</summary>
    private const int NoSuchThread = 3;

    /// <summary>
    /// What the collector says when it cannot start. The routine it would reach is empty in the build
    /// linked here, so every reason it gives for refusing is discarded - and a collector that will not
    /// start is the failure hardest to place from the outside, because nothing else reports it either.
    /// This writes it where anything else fatal goes, using only names the catalog already resolves.
    /// </summary>
    private const string GcLogSymbol = "_ZN15GCToEEInterface14LogErrorToHostEPKc";

    /// <summary>
    /// The names this object defines on purpose over a definition the runtime archives also carry. A
    /// link refuses two full definitions of one name, so the ones meant to stand in front of another
    /// are listed here rather than being told apart by luck of ordering.
    /// </summary>
    public static IReadOnlySet<string> DeliberateOverrides { get; } =
        new HashSet<string>(StringComparer.Ordinal) { GcLogSymbol };
    private const byte ErrorStream = 2;

    private static CompatFunc GcLog()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        a.Emit(0x48, 0x85, 0xFF); a.JumpIfEqual("out");     // test rdi, rdi
        a.Emit(0x48, 0x89, 0xFB);                           // mov rbx, rdi
        a.Call("strlen");
        a.Emit(0x48, 0x89, 0xC2);                           // mov rdx, rax   (how much)
        a.Emit(0x48, 0x89, 0xDE);                           // mov rsi, rbx   (what)
        a.Emit(0xBF, ErrorStream, 0x00, 0x00, 0x00);        // mov edi, where anything fatal goes
        a.Call("write");
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new(GcLogSymbol, false, code, relocs);
    }

    // sigemptyset(set): clear the four words and report success.
    private static CompatFunc SigEmptySet()
    {
        var a = new Asm();
        a.Emit(0x48, 0x85, 0xFF); a.JumpIfEqual("refuse");  // test rdi, rdi
        a.Emit(0x48, 0xC7, 0x07, 0x00, 0x00, 0x00, 0x00);   // mov qword [rdi], 0
        a.Emit(0x48, 0xC7, 0x47, 0x08, 0x00, 0x00, 0x00, 0x00); // mov qword [rdi+8], 0
        a.Emit(0x31, 0xC0, 0xC3);                           // xor eax, eax ; ret
        a.Mark("refuse");
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3);         // mov eax, -1 ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("sigemptyset", false, code, relocs);
    }

    // sigfillset(set): name every signal there is and report success.
    //
    // Four words hold a hundred and twenty-eight bits, and a hundred and twenty-eight is exactly how
    // many signals this platform numbers, so all-ones names every one of them and nothing beyond. The
    // caller's set is the wider one the runtime was built against, which is why only the four words
    // this platform reads are written - the rest of it is never looked at on this side.
    private static CompatFunc SigFillSet()
    {
        var a = new Asm();
        a.Emit(0x48, 0x85, 0xFF); a.JumpIfEqual("refuse");  // test rdi, rdi
        a.Emit(0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF);   // mov rax, -1
        a.Emit(0x48, 0x89, 0x07);                           // mov [rdi], rax
        a.Emit(0x48, 0x89, 0x47, 0x08);                     // mov [rdi+8], rax
        a.Emit(0x31, 0xC0, 0xC3);                           // xor eax, eax ; ret
        a.Mark("refuse");
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3);         // mov eax, -1 ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("sigfillset", false, code, relocs);
    }

    // sigaddset(set, signal): set the one bit, or refuse a signal outside the range.
    private static CompatFunc SigAddSet()
    {
        var a = new Asm();
        a.Emit(0x48, 0x85, 0xFF); a.JumpIfEqual("refuse");  // test rdi, rdi
        a.Emit(0xFF, 0xCE);                                 // dec esi          (signal - 1)
        a.Emit(0x81, 0xFE, MaxSignal, 0x00, 0x00, 0x00);    // cmp esi, 128
        a.JumpIfAtOrAbove("refuse");
        a.Emit(0x89, 0xF0);                                 // mov eax, esi
        a.Emit(0xC1, 0xE8, 0x05);                           // shr eax, 5       (which word)
        a.Emit(0x89, 0xF1);                                 // mov ecx, esi
        a.Emit(0x83, 0xE1, 0x1F);                           // and ecx, 31      (which bit)
        a.Emit(0xBA, 0x01, 0x00, 0x00, 0x00);               // mov edx, 1
        a.Emit(0xD3, 0xE2);                                 // shl edx, cl
        a.Emit(0x09, 0x14, 0x87);                           // or [rdi + rax*4], edx
        a.Emit(0x31, 0xC0, 0xC3);                           // xor eax, eax ; ret
        a.Mark("refuse");
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3);         // mov eax, -1 ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("sigaddset", false, code, relocs);
    }

    // open(path, flags, mode): the flags word does not mean the same thing on both sides.
    //
    // The compiled runtime was built against a library whose open flags carry one set of values, and
    // the device reads another - they agree only on the three access-mode bits at the bottom. Handing
    // the word over unchanged is not a near miss: the bit that asks for a file to be created reads as
    // the one that asks for signal-driven input, so creating a file quietly fails; the bit that asks
    // for an existing file to be emptied reads as the create bit; and the bit that refuses to follow a
    // link reads as the one that demands a directory, so opening an ordinary file fails outright.
    //
    // Each bit is moved to where the device expects it. Everything is a shift of a masked bit, so there
    // are no branches, and the access mode at the bottom is carried across untouched. The accumulator
    // avoids the first argument, the third, and the byte that counts vector registers for a call taking
    // a variable argument, all of which have to reach the device exactly as the caller left them.
    private static readonly (uint Ours, uint Theirs)[] OpenFlagMap =
    [
        (0x000040, 0x000200),   // create if it is not there
        (0x000080, 0x000800),   // fail if it is
        (0x000100, 0x008000),   // do not make it the controlling terminal
        (0x000200, 0x000400),   // empty it
        (0x000400, 0x000008),   // append
        (0x000800, 0x000004),   // do not wait
        (0x001000, 0x001000),   // write data through
        (0x002000, 0x000040),   // signal when ready
        (0x004000, 0x010000),   // bypass the cache
        (0x010000, 0x020000),   // it must be a directory
        (0x020000, 0x000100),   // do not follow a link
        (0x080000, 0x100000),   // close it when the module is replaced
        (0x100000, 0x000080),   // write everything through
        // The bit asking for large files is dropped: the device is already counting in 64 bits, and
        // left in place it would read as the controlling-terminal bit.
    ];

    /// <summary>
    /// Rewrites a word of open flags in place, in either direction. The three bytes name the register
    /// being rewritten: how to copy it out, how to copy it out again, and how to copy the result back.
    /// </summary>
    private static void TranslateOpenFlags(Asm a, bool toDevice, byte outA, byte outB, byte back)
    {
        a.Emit(0x41, 0x89, outA);                           // mov r8d, <reg>
        a.Emit(0x41, 0x81, 0xE0, 0x03, 0x00, 0x00, 0x00);   // and r8d, access mode
        foreach ((uint ours, uint theirs) in OpenFlagMap)
        {
            uint from = toDevice ? ours : theirs, to = toDevice ? theirs : ours;
            a.Emit(0x41, 0x89, outB);                       // mov r9d, <reg>
            a.Emit(0x41, 0x81, 0xE1);                       // and r9d, the bit as it arrives
            a.Emit32(unchecked((int)from));
            int fromBit = System.Numerics.BitOperations.TrailingZeroCount(from);
            int toBit = System.Numerics.BitOperations.TrailingZeroCount(to);
            if (toBit > fromBit)
                a.Emit(0x41, 0xC1, 0xE1, (byte)(toBit - fromBit));     // shl r9d, n
            else if (toBit < fromBit)
                a.Emit(0x41, 0xC1, 0xE9, (byte)(fromBit - toBit));     // shr r9d, n
            a.Emit(0x45, 0x09, 0xC8);                       // or r8d, r9d
        }
        a.Emit(0x44, 0x89, back);                           // mov <reg>, r8d
    }

    private static CompatFunc Open64()
    {
        var a = new Asm();
        TranslateOpenFlags(a, toDevice: true, 0xF0, 0xF1, 0xC6);       // the word arrives in esi
        a.Emit(0xE9, 0x00, 0x00, 0x00, 0x00);               // jmp open
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("open64", false, code, [.. relocs, (code.Length - 4, "open")]);
    }

    // ---------------------------------------------------------------------------
    // Two more calls whose arguments are numbers meaning something else on each side.
    // ---------------------------------------------------------------------------

    // pthread_sigmask(how, set, previous): whether to add to the set of blocked signals, remove from
    // it, or replace it. The runtime was built where those three are nought, one and two; here they are
    // one, two and three, so every request lands one place along. The runtime asks to **remove** the
    // signal it interrupts a thread with - one place along from remove is add - so every thread it made
    // had that signal blocked, which is the opposite of what it asked for, on every thread it owns.
    private static CompatFunc PthreadSigmask()
    {
        var a = new Asm();
        a.Emit(0x83, 0xFF, 0x03); a.JumpIfAtOrAbove("asis"); // cmp edi, how many we know
        a.Emit(0xFF, 0xC7);                                 // inc edi
        a.Mark("asis");
        a.Emit(0xE9, 0x00, 0x00, 0x00, 0x00);               // jmp the platform's own
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("pthread_sigmask", false, code,
            [.. relocs, (code.Length - 4, Linker.DeviceAliasPrefix + "pthread_sigmask")]);
    }

    // fcntl(descriptor, command, argument): the commands are numbered differently, and two of them
    // carry a word of open flags that needs the same translation an open's does. Left alone, asking a
    // descriptor to stop waiting set a wholly different flag, and asking to take a lock ran the command
    // that sets which process receives a signal - with the lock's address standing in for the process.
    private static readonly (int Runtime, int Device, string What)[] FcntlCommands =
    [
        (0, 0,  "duplicate it"),
        (1, 1,  "read whether it closes when the module is replaced"),
        (2, 2,  "set whether it closes when the module is replaced"),
        (3, 3,  "read the open flags"),
        (4, 4,  "set the open flags"),
        (5, 11, "read a lock"),
        (6, 12, "take a lock"),
        (7, 13, "take a lock, waiting for it"),
        (8, 6,  "set which process is signalled"),
        (9, 5,  "read which process is signalled"),
    ];
    private const string FcntlTableSymbol = "__sp_fcntl_commands";
    private const int FcntlTableSize = 10;
    private const int FcntlDuplicateClosing = 1030, FcntlDeviceDuplicateClosing = 19;
    private const int FcntlReadFlags = 3, FcntlSetFlags = 4;

    // The three commands that carry a lock, counted the runtime's way, and the first of them - the one
    // that reads a lock back rather than taking one, which is also the only one that answers in the
    // structure it was handed.
    private const byte FcntlReadLock = 5, FcntlLockCommands = 3;

    // Where the fields of a lock sit, and how the two sides number the kinds of lock.
    //
    // Same size on both sides, so nothing overruns - the failure is pure misreading. The runtime puts
    // the kind first and the offset eight bytes in; this platform puts the offset first and the kind
    // twenty bytes in. Handed over unchanged, the kind is read out of the offset, the offset out of the
    // length, and the kind field takes the top half of the length - which is nought for any lock
    // shorter than four gigabytes, and nought is not a kind of lock, so every request is refused.
    //
    // The kinds are numbered from one here - shared one, unlocked two, exclusive three - against the
    // runtime's from nought - shared nought, exclusive one, unlocked two. Three kinds each way is a
    // short enough run to carry as one nibble per kind in an immediate rather than as another table in
    // the data section.
    private const int LockKindsToDevice = 0x231, LockKindsFromDevice = 0x1200;

    /// <summary>
    /// Rewrites a kind of lock, arriving in ecx and answered in eax, through one of the two pairings.
    /// The kind is masked into the run the pairing covers so the shift cannot run off the end. Only
    /// three of the four places in a pairing name a kind, and the fourth reads back as nought, which
    /// the platform does not accept - so a kind neither side names is refused rather than guessed at.
    /// </summary>
    private static void EmitLockKind(Asm a, int pairing)
    {
        a.Emit(0x83, 0xE1, 0x03);                           // and ecx, 3
        a.Emit(0xC1, 0xE1, 0x02);                           // shl ecx, 2      (a nibble per kind)
        a.Emit(0xB8); a.Emit32(pairing);                    // mov eax, the pairing
        a.Emit(0xD3, 0xE8);                                 // shr eax, cl
        a.Emit(0x83, 0xE0, 0x0F);                           // and eax, 15
    }

    /// <summary>
    /// Builds this platform's lock on the frame from the caller's, for the three commands that carry
    /// one, and points the third argument at it. The caller's is kept so a read-a-lock answer can go
    /// back into it. Everything else passes straight through.
    /// </summary>
    private static void EmitLockToDevice(Asm a)
    {
        a.Emit(0x89, 0xD8);                                 // mov eax, ebx
        a.Emit(0x83, 0xE8, FcntlReadLock);                  // sub eax, the first of the three
        a.Emit(0x83, 0xF8, FcntlLockCommands);              // cmp eax, how many carry a lock
        a.JumpIfAtOrAbove("nolock");
        a.Emit(0x48, 0x85, 0xD2); a.JumpIfEqual("nolock");  // test rdx, rdx  (nothing to read)
        a.Emit(0x48, 0x89, 0x55, 0xE8);                     // mov [rbp-24], rdx  (to answer into)
        a.Emit(0x48, 0x8B, 0x42, 0x08);                     // mov rax, [rdx+8]
        a.Emit(0x48, 0x89, 0x45, 0xC0);                     // mov [rbp-64], rax    where it starts
        a.Emit(0x48, 0x8B, 0x42, 0x10);                     // mov rax, [rdx+16]
        a.Emit(0x48, 0x89, 0x45, 0xC8);                     // mov [rbp-56], rax    how far it reaches
        a.Emit(0x8B, 0x42, 0x18);                           // mov eax, [rdx+24]
        a.Emit(0x89, 0x45, 0xD0);                           // mov [rbp-48], eax    whose it is
        a.Emit(0x0F, 0xB7, 0x0A);                           // movzx ecx, word [rdx]
        EmitLockKind(a, LockKindsToDevice);
        a.Emit(0x66, 0x89, 0x45, 0xD4);                     // mov [rbp-44], ax     what kind
        a.Emit(0x0F, 0xB7, 0x42, 0x02);                     // movzx eax, word [rdx+2]
        a.Emit(0x66, 0x89, 0x45, 0xD6);                     // mov [rbp-42], ax     what it counts from
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.Emit(0x89, 0x45, 0xD8);                           // mov [rbp-40], eax    this machine's own
        a.Emit(0x48, 0x8D, 0x55, 0xC0);                     // lea rdx, [rbp-64]
        a.Mark("nolock");
    }

    /// <summary>
    /// Copies the answer to a read-a-lock request back into the caller's own structure, the other way
    /// through the same field placing and the same pairing of kinds.
    /// </summary>
    private static void EmitLockFromDevice(Asm a)
    {
        a.Emit(0x48, 0x8B, 0x55, 0xE8);                     // mov rdx, [rbp-24]
        a.Emit(0x48, 0x85, 0xD2); a.JumpIfEqual("out");     // test rdx, rdx  (never built one)
        a.Emit(0x0F, 0xB7, 0x4D, 0xD4);                     // movzx ecx, word [rbp-44]
        EmitLockKind(a, LockKindsFromDevice);
        a.Emit(0x66, 0x89, 0x02);                           // mov [rdx], ax
        a.Emit(0x0F, 0xB7, 0x45, 0xD6);                     // movzx eax, word [rbp-42]
        a.Emit(0x66, 0x89, 0x42, 0x02);                     // mov [rdx+2], ax
        a.Emit(0x48, 0x8B, 0x45, 0xC0);                     // mov rax, [rbp-64]
        a.Emit(0x48, 0x89, 0x42, 0x08);                     // mov [rdx+8], rax
        a.Emit(0x48, 0x8B, 0x45, 0xC8);                     // mov rax, [rbp-56]
        a.Emit(0x48, 0x89, 0x42, 0x10);                     // mov [rdx+16], rax
        a.Emit(0x8B, 0x45, 0xD0);                           // mov eax, [rbp-48]
        a.Emit(0x89, 0x42, 0x18);                           // mov [rdx+24], eax
        a.Emit(0x31, 0xC0);                                 // xor eax, eax   (the request succeeded)
    }

    private static byte[] BuildFcntlTable()
    {
        byte[] t = new byte[FcntlTableSize];
        foreach ((int runtime, int device, string _) in FcntlCommands)
            t[runtime] = (byte)device;
        return t;
    }

    private static CompatFunc Fcntl()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        // The frame carries this platform's lock at [rbp-64], which is thirty-two bytes, and the
        // caller's own at [rbp-24] so a read-a-lock answer knows where to go back.
        a.Emit(0x48, 0x83, 0xEC, 0x38);                     // sub rsp, 56
        a.Emit(0x48, 0xC7, 0x45, 0xE8, 0x00, 0x00, 0x00, 0x00);  // mov qword [rbp-24], 0
        a.Emit(0x89, 0xF3);                                 // mov ebx, esi  (what was asked for)

        // The word an open-flags request carries is translated the way an open's is.
        a.Emit(0x81, 0xFB); a.Emit32(FcntlSetFlags); a.JumpIfNotEqual("notflags");
        TranslateOpenFlags(a, toDevice: true, 0xD0, 0xD1, 0xC2);       // the word arrives in edx
        a.Mark("notflags");

        a.Emit(0x81, 0xFB); a.Emit32(FcntlTableSize); a.JumpIfAtOrAbove("wider");
        a.Emit(0x89, 0xF6);                                 // mov esi, esi
        int at = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the numbering]
        a.Emit(0x0F, 0xB6, 0x34, 0x30);                     // movzx esi, byte [rax + rsi]
        a.JumpIfAlways("ready");

        // One command sits far outside the run the numbering covers.
        a.Mark("wider");
        a.Emit(0x81, 0xFB); a.Emit32(FcntlDuplicateClosing); a.JumpIfNotEqual("ready");
        a.Emit(0xBE); a.Emit32(FcntlDeviceDuplicateClosing);

        a.Mark("ready");
        // The three lock commands carry a structure whose fields this platform reads elsewhere, so it
        // is rebuilt on the frame before the call rather than handed over as it arrived.
        EmitLockToDevice(a);
        a.Emit(0x31, 0xC0);                                 // xor eax, eax  (no vector arguments)
        a.Call(Linker.DeviceAliasPrefix + "fcntl");

        // Two kinds of request answer with something needing translation back: one with a word of open
        // flags, and one with the lock it was asked about.
        a.Emit(0x85, 0xC0); a.JumpIfNegative("out");        // test eax, eax  (a refusal passes through)
        a.Emit(0x81, 0xFB); a.Emit32(FcntlReadLock); a.JumpIfEqual("readlock");
        a.Emit(0x81, 0xFB); a.Emit32(FcntlReadFlags); a.JumpIfNotEqual("out");
        TranslateOpenFlags(a, toDevice: false, 0xC0, 0xC1, 0xC0);      // the word came back in eax
        a.JumpIfAlways("out");
        a.Mark("readlock");
        EmitLockFromDevice(a);
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x38, 0x5B, 0x5D, 0xC3);   // add rsp,56 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("fcntl", false, code, [.. relocs, (at, FcntlTableSymbol)]);
    }

    // The count answered when the pool cannot say how much memory this module has. Sixteen thousand
    // pages is a quarter of a gigabyte, which is under the pool a module of this kind is given and well
    // over what the collector needs to start - cautious in the direction that fails safely.
    private const int AssumedPages = 16384;

    // The count answered when the set of processors this thread may run on cannot be read. It is well
    // under the widest set the toolchain names, so a module sized against it starts with fewer threads
    // than the machine could carry rather than more than it can.
    private const byte AssumedProcessors = 8;

    private static CompatFunc SysConf()
    {
        const byte ScPageSize = 30, ScProcessorsConf = 83, ScProcessorsOnline = 84,
                   ScPhysPages = 85, ScAvailPages = 86;
        var a = new Asm();
        a.Emit(0x83, 0xFF, ScPageSize); a.JumpIfEqual("page");              // cmp edi, _SC_PAGESIZE
        a.Emit(0x83, 0xFF, ScProcessorsConf); a.JumpIfEqual("cpus");
        a.Emit(0x83, 0xFF, ScProcessorsOnline); a.JumpIfEqual("cpus");
        a.Emit(0x83, 0xFF, ScPhysPages); a.JumpIfEqual("pages");
        a.Emit(0x83, 0xFF, ScAvailPages); a.JumpIfEqual("avail");
        a.Emit(0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3);             // mov rax, -1 ; ret

        a.Mark("page");
        a.Emit(0xB8, 0x00, 0x40, 0x00, 0x00, 0xC3);                         // mov eax, 16384 ; ret

        // How many processors there are. **This may not refuse either**: the collector compares the
        // answer against -1 and gives up on its whole start-up when it matches, which surfaces as the
        // module reporting a non-zero result from its entry and nothing else.
        //
        // The figure is asked of the platform rather than written down here, because a number written
        // down here is a number the platform never states - and it is the same question the set of
        // processors this thread may run on already answers, which is where the runtime's own count
        // comes from. Taking both from one source is the point: two answers describing two different
        // machines is worse than either being a little off, since the collector sizes its heaps
        // against one and the thread pool against the other.
        a.Mark("cpus");
        a.Emit(0x55, 0x48, 0x89, 0xE5);                                     // push rbp ; mov rbp, rsp
        a.Emit(0x48, 0x83, 0xEC, 0x10);                                     // sub rsp, 16  (the set)
        a.Emit(0x48, 0xC7, 0x04, 0x24, 0, 0, 0, 0);                         // mov qword [rsp], 0
        a.Call("scePthreadSelf");
        a.Emit(0x48, 0x89, 0xC7);                                           // mov rdi, rax
        a.Emit(0x48, 0x89, 0xE6);                                           // mov rsi, rsp
        a.Call("scePthreadGetaffinity");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("assumecpus");                 // test eax, eax
        a.Emit(0xF3, 0x48, 0x0F, 0xB8, 0x04, 0x24);                         // popcnt rax, [rsp]
        // An empty set is the question going unanswered rather than a machine with no processors, and
        // passing nought on divides by it further up.
        a.Emit(0x85, 0xC0); a.JumpIfEqual("assumecpus");                    // test eax, eax
        a.Emit(0xC9, 0xC3);                                                 // leave ; ret
        a.Mark("assumecpus");
        a.Emit(0xB8, AssumedProcessors, 0x00, 0x00, 0x00);                  // mov eax, a cautious count
        a.Emit(0xC9, 0xC3);                                                 // leave ; ret

        // How much memory this module can have, in pages, and how much of it is still free.
        //
        // **Neither may refuse.** The caller that asks how much memory there is refuses to start the
        // runtime at all when this answers -1 - it compares the result against -1 and returns failure
        // for its whole initialisation, which surfaces as the module reporting a non-zero result from
        // its entry and nothing else. The caller that asks how much is free does not check at all, and
        // reads -1 as sixteen million million pages. So the two want opposite wrong answers, and the
        // way out of that is to give neither a wrong answer: when the question the pool answers fails,
        // ask the machine how much memory it has instead. That is a real figure from the device rather
        // than a number invented here, and it is the same order as the pool's own.
        a.Mark("pages");
        a.Emit(0x55, 0x48, 0x89, 0xE5);                                     // push rbp ; mov rbp, rsp
        a.Emit(0x48, 0x83, 0xEC, 0x10);                                     // sub rsp, 16
        a.Emit(0x48, 0xC7, 0x04, 0x24, 0, 0, 0, 0);                         // mov qword [rsp], 0
        a.Emit(0x48, 0x89, 0xE7);                                           // mov rdi, rsp
        a.Call("sceKernelConfiguredFlexibleMemorySize");
        a.JumpIfAlways("settle");

        a.Mark("avail");
        a.Emit(0x55, 0x48, 0x89, 0xE5);                                     // push rbp ; mov rbp, rsp
        a.Emit(0x48, 0x83, 0xEC, 0x10);                                     // sub rsp, 16
        a.Emit(0x48, 0xC7, 0x04, 0x24, 0, 0, 0, 0);                         // mov qword [rsp], 0
        a.Emit(0x48, 0x89, 0xE7);                                           // mov rdi, rsp
        a.Call("sceKernelAvailableFlexibleMemorySize");

        a.Mark("settle");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("assume");                     // test eax, eax
        a.Emit(0x48, 0x8B, 0x04, 0x24);                                     // mov rax, [rsp]
        // A byte count of nothing is not an answer of "no memory" - it is the question going
        // unanswered. Passed on it stamps the collector's idea of how much memory exists with zero,
        // which satisfies the caller's check and starves everything above it instead.
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfEqual("assume");                  // test rax, rax
        a.Emit(0x48, 0xC1, 0xE8, 0x0E);                                     // shr rax, 14 (16 KB pages)
        a.Emit(0xC9, 0xC3);                                                 // leave ; ret

        // Nothing came back, so a figure is used instead of a refusal. It is a fixed, cautious one in
        // the same spirit as the fall-back count above, and deliberately **not** the
        // machine's own memory size: the collector's pages come from the pool this module maps out of,
        // which is a small fraction of what the machine has, and answering with the larger figure would
        // size every decision above it against memory this module can never reach - trading a refusal
        // that stops the module cleanly for an exhaustion much further on that reads as nothing at all.
        a.Mark("assume");
        a.Emit(0xB8); a.Emit32(AssumedPages);                               // mov eax, a cautious count
        a.Emit(0xC9, 0xC3);                                                 // leave ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("sysconf", false, code, relocs);
    }

    // ---------------------------------------------------------------------------
    // struct stat translation.
    //
    // The runtime's operating-system layer reads a file's status through a struct whose fields sit at
    // one set of offsets; the device's own status call writes a struct with different field types and
    // offsets. A large-file status entry therefore calls the device's status call into a scratch buffer
    // and copies each field across, so the runtime reads the right value at the right place. The offsets
    // are taken from both headers for the x86-64 target and locked by a test.
    // ---------------------------------------------------------------------------

    private const int Rax = 0, Rbx = 3, Rsp = 4, Rsi = 6, Rdi = 7;

    // Device struct size (rounded up to a 16-byte scratch); the runtime struct's field offsets follow.
    private const int DeviceStatSize = 128;

    // (runtime offset, device offset, load-size in bytes). A load-size < 8 zero-extends into a 64-bit
    // field; the mode field is the one 4-byte destination.
    private static readonly (int To, int From, int Size)[] StatFields =
    [
        (0, 0, 4),     // st_dev
        (8, 4, 4),     // st_ino
        (16, 10, 2),   // st_nlink
        (24, 8, 2),    // st_mode  (4-byte destination)
        (28, 12, 4),   // st_uid
        (32, 16, 4),   // st_gid
        (40, 20, 4),   // st_rdev
        (48, 72, 8),   // st_size
        (56, 88, 4),   // st_blksize
        (64, 80, 8),   // st_blocks
        (72, 24, 8),   // st_atim.tv_sec
        (80, 32, 8),   // st_atim.tv_nsec
        (88, 40, 8),   // st_mtim.tv_sec
        (96, 48, 8),   // st_mtim.tv_nsec
        (104, 56, 8),  // st_ctim.tv_sec
        (112, 64, 8),  // st_ctim.tv_nsec
    ];

    // Runtime-struct bytes not written by a field copy, zeroed so no stale value is read.
    private static readonly int[] StatZeroGaps = [36, 120, 128, 136];

    // Builds `name(version, target-arg, out-buf)`: call the device status function into a scratch, then
    // translate into the runtime struct at the caller's buffer. `byFd` passes the second argument as a
    // 32-bit file descriptor rather than a pointer.
    private static CompatFunc StatThunk(string name, string target, bool byFd)
    {
        var c = new List<byte>
        {
            0x53                                        // push rbx
        };
        c.AddRange([0x48, 0x89, 0xD3]);                     // mov rbx, rdx    (save out-buf)
        c.AddRange([0x48, 0x81, 0xEC, DeviceStatSize, 0x00, 0x00, 0x00]); // sub rsp, DeviceStatSize
        c.AddRange(byFd ? [0x89, 0xF7] : new byte[] { 0x48, 0x89, 0xF7 }); // mov edi,esi / mov rdi,rsi
        c.AddRange([0x48, 0x89, 0xE6]);                     // mov rsi, rsp    (&scratch)
        int callRel = c.Count + 1;
        c.AddRange([0xE8, 0, 0, 0, 0]);                     // call target
        c.AddRange([0x85, 0xC0]);                           // test eax, eax
        int jnz = c.Count;
        c.AddRange([0x0F, 0x85, 0, 0, 0, 0]);               // jnz done (patched)
        int bodyStart = c.Count;

        c.AddRange([0x31, 0xC0]);                           // xor eax, eax
        foreach (int gap in StatZeroGaps)
            Store64(c, Rbx, gap);                           // zero the runtime-struct gaps
        foreach ((int to, int from, int size) in StatFields)
        {
            LoadScratch(c, from, size);
            if (to == 24) Store32(c, Rbx, to);              // st_mode is a 4-byte field
            else Store64(c, Rbx, to);
        }
        c.AddRange([0x31, 0xC0]);                           // xor eax, eax   (return 0)

        int done = c.Count;
        int disp = done - bodyStart;
        c[jnz + 2] = (byte)disp; c[jnz + 3] = (byte)(disp >> 8);
        c[jnz + 4] = (byte)(disp >> 16); c[jnz + 5] = (byte)(disp >> 24);
        c.AddRange([0x48, 0x81, 0xC4, DeviceStatSize, 0x00, 0x00, 0x00]); // add rsp, DeviceStatSize
        c.Add(0x5B);                                        // pop rbx
        c.Add(0xC3);                                        // ret
        return new CompatFunc(name, false, [.. c], [(callRel, target)]);
    }

    // Loads a value of the given size from [rsp+off] into eax/rax, zero-extending a short field.
    private static void LoadScratch(List<byte> c, int off, int size)
    {
        if (size == 8) { c.AddRange([0x48, 0x8B]); ModRm(c, Rax, Rsp, off); }        // mov rax, [rsp+off]
        else if (size == 4) { c.Add(0x8B); ModRm(c, Rax, Rsp, off); }                // mov eax, [rsp+off]
        else { c.AddRange([0x0F, 0xB7]); ModRm(c, Rax, Rsp, off); }                  // movzx eax, word [rsp+off]
    }

    private static void Store64(List<byte> c, int baseReg, int off) { c.AddRange([0x48, 0x89]); ModRm(c, Rax, baseReg, off); }
    private static void Store32(List<byte> c, int baseReg, int off) { c.Add(0x89); ModRm(c, Rax, baseReg, off); }

    // Appends the ModRM (and SIB/displacement) for `reg`-with-[base+disp]. Handles rsp (needs a SIB) and
    // a disp of zero, one byte, or four bytes.
    private static void ModRm(List<byte> c, int reg, int baseReg, int disp)
    {
        int mod = disp == 0 ? 0 : (disp >= -128 && disp <= 127 ? 1 : 2);
        bool sib = baseReg == Rsp;
        c.Add((byte)((mod << 6) | ((reg & 7) << 3) | (sib ? 4 : baseReg & 7)));
        if (sib) c.Add(0x24);
        if (mod == 1) c.Add((byte)disp);
        else if (mod == 2) { c.Add((byte)disp); c.Add((byte)(disp >> 8)); c.Add((byte)(disp >> 16)); c.Add((byte)(disp >> 24)); }
    }

    // ---------------------------------------------------------------------------
    // struct dirent translation.
    //
    // The device's directory read returns a pointer to an entry whose fields sit at one set of offsets;
    // the runtime reads the returned pointer as an entry with a wider inode and different offsets. readdir64
    // therefore calls the device's readdir, copies the entry into a per-thread block laid out the way the
    // runtime expects, and returns a pointer to that. A null result (end of directory) passes straight
    // through. Offsets are from both headers for the x86-64 target and locked by a test.
    //
    //   device entry:  d_fileno @0 (4)  d_reclen @4 (2)  d_type @6 (1)  d_namlen @7 (1)  d_name @8
    //   runtime entry: d_ino    @0 (8)  d_off    @8 (8)  d_reclen @16 (2) d_type @18 (1) d_name @19
    // ---------------------------------------------------------------------------

    private static CompatFunc Readdir64()
    {
        // Two references are patched by relocations: the call to the device readdir (PLT32, +1 in its
        // instruction) and the address load of the per-thread block, whose form and whose relocation
        // depend on which kind of module is being built.
        const int callSite = 2;      // operand of `call readdir`
        const int tlsSite = 16;      // where the address load of the per-thread block starts
        byte[] code =
        [
            0x53,                                           // 0   push rbx
            0xE8, 0x00, 0x00, 0x00, 0x00,                   // 1   call readdir            (rdi already holds DIR*)
            0x48, 0x85, 0xC0,                               // 6   test rax, rax
            0x75, 0x02,                                     // 9   jnz +2  -> 13
            0x5B,                                           // 11  pop rbx
            0xC3,                                           // 12  ret                     (null: end of directory)
            0x48, 0x89, 0xC3,                               // 13  mov rbx, rax            (device entry)
            .. TlsLoad(RegRdi),                             // 16  rdi = the per-thread block
            0x8B, 0x03,                                     // 35  mov eax, [rbx]          (d_fileno, zero-extended)
            0x48, 0x89, 0x07,                               // 37  mov [rdi], rax          (d_ino)
            0x31, 0xC0,                                     // 40  xor eax, eax
            0x48, 0x89, 0x47, 0x08,                         // 42  mov [rdi+8], rax        (d_off = 0)
            0x8A, 0x43, 0x06,                               // 46  mov al, [rbx+6]         (d_type)
            0x88, 0x47, 0x12,                               // 49  mov [rdi+18], al        (d_type)
            0x0F, 0xB6, 0x4B, 0x07,                         // 52  movzx ecx, byte [rbx+7] (d_namlen)
            0x8D, 0x41, 0x14,                               // 56  lea eax, [rcx+20]       (record length)
            0x66, 0x89, 0x47, 0x10,                         // 59  mov [rdi+16], ax        (d_reclen)
            0x48, 0x89, 0xF8,                               // 63  mov rax, rdi            (return value: block base)
            0x48, 0x8D, 0x73, 0x08,                         // 66  lea rsi, [rbx+8]        (source name)
            0x48, 0x83, 0xC7, 0x13,                         // 70  add rdi, 19             (dest name)
            0xFF, 0xC1,                                     // 74  inc ecx                 (copy the terminating null too)
            0xF3, 0xA4,                                     // 76  rep movsb
            0x5B,                                           // 78  pop rbx
            0xC3,                                           // 79  ret
        ];
        return new("readdir64", false, code, [(callSite, "readdir")], Tls: (tlsSite, RegRdi, ReaddirBufSymbol));
    }

    // ---------------------------------------------------------------------------
    // Directory streams.
    //
    // Nothing the toolchain lets a module link against offers one: opening a directory, reading the
    // next entry and closing it are absent from every library, and each was left reporting nothing.
    // Reporting nothing is not a refusal - an empty answer is exactly what an empty directory gives -
    // so every enumeration in the runtime succeeded and found no files, which is worse than failing.
    //
    // What is published is the call the three are built on. It fills a caller's buffer with as many
    // whole entries as fit, answers how many bytes it wrote, and moves the descriptor on by itself, so
    // a second call continues where the first stopped and no seeking is needed. A stream is that call
    // plus the bookkeeping its caller would otherwise repeat.
    //
    // The whole stream is one allocation, so closing it frees one thing:
    //   +0 the descriptor   +8 how far the reader has got   +16 how much was read   +24 the buffer
    // ---------------------------------------------------------------------------

    private const byte DirFd = 0, DirLoc = 8, DirSize = 16, DirBuf = 24;
    // The buffer the platform's own library gives a stream that is read straight through.
    private const int DirBufSize = 0x10000;
    private const int DirBlockSize = DirBuf + DirBufSize;
    // Read only, do not wait, it must be a directory, and drop it if the module is replaced - the
    // four the platform's own library asks for.
    private const int DirOpenFlags = 0x120004;

    // opendir(path): open the directory, take the block, and hand back a stream positioned at its start.
    private static CompatFunc OpenDir()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8   (keeps the stack aligned)
        a.Emit(0xBE); a.Emit32(DirOpenFlags);               // mov esi, the four flags
        a.Emit(0x31, 0xC0);                                 // xor eax, eax (no vector arguments follow)
        a.Call("open");
        a.Emit(0x85, 0xC0); a.JumpIfNegative("none");       // test eax, eax
        a.Emit(0x89, 0xC3);                                 // mov ebx, eax  (the descriptor)
        a.Emit(0xBF); a.Emit32(DirBlockSize);               // mov edi, the whole block
        a.Call("malloc");
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfEqual("giveback"); // test rax, rax
        a.Emit(0x89, 0x18);                                 // mov [rax], ebx
        a.Emit(0x48, 0xC7, 0x40, DirLoc, 0x00, 0x00, 0x00, 0x00);   // mov qword [rax+8], 0
        a.Emit(0x48, 0xC7, 0x40, DirSize, 0x00, 0x00, 0x00, 0x00);  // mov qword [rax+16], 0
        a.JumpIfAlways("out");

        // No room for the bookkeeping, so the descriptor goes back rather than being leaked.
        a.Mark("giveback");
        a.Emit(0x89, 0xDF);                                 // mov edi, ebx
        a.Call("close");
        a.Mark("none");
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("opendir", false, code, relocs);
    }

    // readdir(stream): the next entry, or nothing at the end of the directory.
    private static CompatFunc ReadDir()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        a.Emit(0x48, 0x85, 0xFF); a.JumpIfEqual("none");    // test rdi, rdi
        a.Emit(0x48, 0x89, 0xFB);                           // mov rbx, rdi

        a.Mark("next");
        a.Emit(0x48, 0x8B, 0x43, DirLoc);                   // mov rax, [rbx+8]   how far it has got
        a.Emit(0x48, 0x3B, 0x43, DirSize);                  // cmp rax, [rbx+16]  against how much was read
        a.JumpIfBelow("have");

        // Nothing of what was read is left, so read more from where the descriptor now stands.
        a.Emit(0x8B, 0x3B);                                 // mov edi, [rbx]
        a.Emit(0x48, 0x8D, 0x73, DirBuf);                   // lea rsi, [rbx+24]
        a.Emit(0xBA); a.Emit32(DirBufSize);                 // mov edx, the buffer
        a.Call("getdents");
        a.Emit(0x85, 0xC0); a.JumpIfNotPositive("none");    // test eax, eax  (nothing more, or refused)
        a.Emit(0x48, 0x63, 0xC0);                           // movsxd rax, eax
        a.Emit(0x48, 0x89, 0x43, DirSize);                  // mov [rbx+16], rax
        a.Emit(0x48, 0xC7, 0x43, DirLoc, 0x00, 0x00, 0x00, 0x00);   // mov qword [rbx+8], 0
        a.Emit(0x31, 0xC0);                                 // xor eax, eax   (back at the start of it)

        // One entry. Its own recorded length is what moves the reader on, so a length of zero would
        // never move and a length running past what was read would read beyond it: both are treated as
        // the end of the directory rather than trusted.
        a.Mark("have");
        a.Emit(0x48, 0x8D, 0x53, DirBuf);                   // lea rdx, [rbx+24]
        a.Emit(0x48, 0x01, 0xC2);                           // add rdx, rax    (this entry)
        a.Emit(0x0F, 0xB7, 0x4A, 0x04);                     // movzx ecx, word [rdx+4]  (its length)
        a.Emit(0x48, 0x85, 0xC9); a.JumpIfEqual("none");    // test rcx, rcx
        a.Emit(0x48, 0x01, 0xC8);                           // add rax, rcx
        a.Emit(0x48, 0x3B, 0x43, DirSize);                  // cmp rax, [rbx+16]
        a.JumpIfAbove("none");
        a.Emit(0x48, 0x89, 0x43, DirLoc);                   // mov [rbx+8], rax
        // An entry whose file number is zero is one that has been removed; it is skipped, not reported.
        a.Emit(0x83, 0x3A, 0x00); a.JumpIfEqual("next");    // cmp dword [rdx], 0
        a.Emit(0x48, 0x89, 0xD0);                           // mov rax, rdx
        a.JumpIfAlways("out");

        a.Mark("none");
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("readdir", false, code, relocs);
    }

    // closedir(stream): give back the descriptor and the block.
    private static CompatFunc CloseDir()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        a.Emit(0x48, 0x85, 0xFF); a.JumpIfEqual("out");     // test rdi, rdi
        a.Emit(0x48, 0x89, 0xFB);                           // mov rbx, rdi
        a.Emit(0x8B, 0x3B);                                 // mov edi, [rbx]
        a.Call("close");
        a.Emit(0x48, 0x89, 0xDF);                           // mov rdi, rbx
        a.Call("free");
        a.Mark("out");
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("closedir", false, code, relocs);
    }

    // sched_getaffinity(process, set size, set): which processors this thread may run on.
    //
    // The platform publishes the same question asked of a thread rather than a process, and a module is
    // one process, so the running thread's answer is the module's. The mask is a single 64-bit word
    // there and a byte array of the caller's size here, so the caller's is cleared first and the word
    // written into its bottom - a set left holding whatever was on the stack would report processors
    // that are not there.
    //
    // Refusing instead was not free: the count the caller derives from this is how many threads the
    // runtime starts with, and the answer it falls back to is a different call that need not agree.
    private static CompatFunc SchedGetAffinity()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x18);                     // sub rsp, 24  (the word, and alignment)
        a.Emit(0x48, 0x85, 0xD2); a.JumpIfEqual("refuse");  // test rdx, rdx   (nowhere to put it)
        a.Emit(0x48, 0x83, 0xFE, 0x08); a.JumpIfBelow("refuse");  // cmp rsi, 8  (too small to hold it)
        a.Emit(0x48, 0x89, 0xD3);                           // mov rbx, rdx
        a.Emit(0x48, 0x89, 0xD7);                           // mov rdi, rdx
        a.Emit(0x48, 0x89, 0xF1);                           // mov rcx, rsi
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.Emit(0xF3, 0xAA);                                 // rep stosb    (clear the caller's set)
        a.Call("scePthreadSelf");
        a.Emit(0x48, 0x89, 0xC7);                           // mov rdi, rax
        a.Emit(0x48, 0x8D, 0x75, 0xE0);                     // lea rsi, [rbp-32]
        a.Call("scePthreadGetaffinity");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("refuse");     // test eax, eax
        a.Emit(0x48, 0x8B, 0x45, 0xE0);                     // mov rax, [rbp-32]
        a.Emit(0x48, 0x89, 0x03);                           // mov [rbx], rax
        a.Emit(0x31, 0xC0);                                 // xor eax, eax
        a.JumpIfAlways("out");
        a.Mark("refuse");
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF);               // mov eax, -1
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x18, 0x5B, 0x5D, 0xC3);   // add rsp,24 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("sched_getaffinity", false, code, relocs);
    }

    // sched_setaffinity(process, set size, set): which processors this thread may run on from now on.
    //
    // The mirror of the question above, and the platform publishes it in the same shape: the same
    // question asked of a thread, taking a single word rather than a byte array, and a module is one
    // process. Only the bottom word of the caller's set is read, which is where every processor this
    // platform has fits; the caller that reaches this builds its set into that word.
    //
    // Reporting success and doing nothing, which is what this did, is the worst answer available. The
    // caller does not ask afterwards whether the pinning took - it reports to the application that the
    // threads are pinned - so a thread that was never moved is one nothing will ever notice.
    private static CompatFunc SchedSetAffinity()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        a.Emit(0x48, 0x85, 0xD2); a.JumpIfEqual("invalid"); // test rdx, rdx   (no set to read)
        a.Emit(0x48, 0x83, 0xFE, 0x08); a.JumpIfBelow("invalid");  // cmp rsi, 8  (too small to hold it)
        a.Emit(0x48, 0x89, 0xD3);                           // mov rbx, rdx
        a.Call("scePthreadSelf");
        a.Emit(0x48, 0x89, 0xC7);                           // mov rdi, rax
        a.Emit(0x48, 0x8B, 0x33);                           // mov rsi, [rbx]  (the bottom of the set)
        a.Call("scePthreadSetaffinity");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("coded");      // test eax, eax
        a.JumpIfAlways("out");                              // nothing refused, so eax is already nought
        a.Mark("invalid");
        a.Emit(0xBF, InvalidArgument, 0x00, 0x00, 0x00);    // mov edi, that argument is not valid
        a.JumpIfAlways("tell");
        a.Mark("coded");
        EmitCodedErrno(a);
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF);               // mov eax, -1
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("sched_setaffinity", false, code, relocs);
    }

    // __sched_cpucount(set size, set): how many processors are in the set. Answering a fixed one left
    // the runtime sizing its thread pool for a single processor while the count it asks for separately
    // described a much larger machine, so the two answers described different machines.
    private static CompatFunc SchedCpuCount()
    {
        var a = new Asm();
        a.Emit(0x31, 0xC0);                                 // xor eax, eax    (none counted yet)
        a.Emit(0x48, 0x85, 0xF6); a.JumpIfEqual("done");    // test rsi, rsi
        a.Emit(0x31, 0xC9);                                 // xor ecx, ecx
        a.Mark("byte");
        a.Emit(0x48, 0x39, 0xF9); a.JumpIfAtOrAbove("done"); // cmp rcx, rdi
        a.Emit(0x0F, 0xB6, 0x14, 0x0E);                     // movzx edx, byte [rsi + rcx]
        a.Emit(0xF3, 0x0F, 0xB8, 0xD2);                     // popcnt edx, edx
        a.Emit(0x01, 0xD0);                                 // add eax, edx
        a.Emit(0x48, 0xFF, 0xC1);                           // inc rcx
        a.JumpIfAlways("byte");
        a.Mark("done");
        a.Emit(0xC3);                                       // ret

        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("__sched_cpucount", false, code, relocs);
    }

    // ---------------------------------------------------------------------------
    // Error numbers.
    //
    // Both sides count their errors from one, and they stop agreeing at eleven: there it means a
    // deadlock would occur on one side and try-again on the other, and the two swap places. From
    // thirty-five on they diverge wholesale. The numbers are exactly what the runtime compares against,
    // so handing its own place over unchanged - which is what a plain forward did - makes every one of
    // those comparisons a comparison against a different error.
    //
    // It is not a quiet difference. The number the device writes for a call it does not implement is
    // the number the runtime reads as "that is not a socket", so a runtime that probes for a missing
    // call by testing for the first concludes the call is there, caches that, and never takes the way
    // that works. The same trade in reverse marks a working feature unsupported.
    //
    // Translating the value alone will not do, because what is handed over is a **place**, and the
    // runtime writes to it as well as reading it. Two places will not do either: the runtime saves the
    // number, does something, and puts it back, and it also reads it inside a signal handler - so a
    // copy kept beside the device's own goes stale the moment anything writes the other one, and the
    // put-back lands in the copy while the device's wins the next read.
    //
    // So there is one place, the device's, and the number in it is translated where it lies. What that
    // needs is a way to tell a number this already translated from one the device has just written,
    // because the numbering is not its own inverse - two codes trade places, so translating twice puts
    // them back. A word per thread remembers what was last written; a value equal to it is left alone.
    //
    // Both columns below are read off their own side rather than derived from one another - the
    // device's from the platform headers, the runtime's from the numbering it was compiled with - so a
    // wrong pairing takes two independent mistakes. A device number with no counterpart the runtime
    // names is reported as a number above everything it knows, which it reads as an error it has no
    // name for. That is better than passing it through to be read as some unrelated error that happens
    // to share the number.
    // ---------------------------------------------------------------------------

    private const string ErrnoShadowSymbol = "__sp_errno_written";
    private const string ErrorTableSymbol = "__sp_error_numbers";
    private const byte UnnamedError = 132;      // above every number the runtime has a name for
    private const int ErrorTableSize = 256;

    private static readonly (string Name, byte Device, byte Runtime)[] ErrorNumbers =
    [
        ("EPERM", 1, 1), ("ENOENT", 2, 2), ("ESRCH", 3, 3), ("EINTR", 4, 4), ("EIO", 5, 5),
        ("ENXIO", 6, 6), ("E2BIG", 7, 7), ("ENOEXEC", 8, 8), ("EBADF", 9, 9), ("ECHILD", 10, 10),
        // The one that trips a reader who assumes the low numbers agree: these two are swapped.
        ("EDEADLK", 11, 35), ("EAGAIN", 35, 11),
        ("ENOMEM", 12, 12), ("EACCES", 13, 13), ("EFAULT", 14, 14), ("ENOTBLK", 15, 15),
        ("EBUSY", 16, 16), ("EEXIST", 17, 17), ("EXDEV", 18, 18), ("ENODEV", 19, 19),
        ("ENOTDIR", 20, 20), ("EISDIR", 21, 21), ("EINVAL", 22, 22), ("ENFILE", 23, 23),
        ("EMFILE", 24, 24), ("ENOTTY", 25, 25), ("ETXTBSY", 26, 26), ("EFBIG", 27, 27),
        ("ENOSPC", 28, 28), ("ESPIPE", 29, 29), ("EROFS", 30, 30), ("EMLINK", 31, 31),
        ("EPIPE", 32, 32), ("EDOM", 33, 33), ("ERANGE", 34, 34),
        ("EINPROGRESS", 36, 115), ("EALREADY", 37, 114), ("ENOTSOCK", 38, 88),
        ("EDESTADDRREQ", 39, 89), ("EMSGSIZE", 40, 90), ("EPROTOTYPE", 41, 91),
        ("ENOPROTOOPT", 42, 92), ("EPROTONOSUPPORT", 43, 93), ("ESOCKTNOSUPPORT", 44, 94),
        ("EOPNOTSUPP", 45, 95), ("EPFNOSUPPORT", 46, 96), ("EAFNOSUPPORT", 47, 97),
        ("EADDRINUSE", 48, 98), ("EADDRNOTAVAIL", 49, 99), ("ENETDOWN", 50, 100),
        ("ENETUNREACH", 51, 101), ("ENETRESET", 52, 102), ("ECONNABORTED", 53, 103),
        ("ECONNRESET", 54, 104), ("ENOBUFS", 55, 105), ("EISCONN", 56, 106), ("ENOTCONN", 57, 107),
        ("ESHUTDOWN", 58, 108), ("ETOOMANYREFS", 59, 109), ("ETIMEDOUT", 60, 110),
        ("ECONNREFUSED", 61, 111), ("ELOOP", 62, 40), ("ENAMETOOLONG", 63, 36),
        ("EHOSTDOWN", 64, 112), ("EHOSTUNREACH", 65, 113), ("ENOTEMPTY", 66, 39),
        ("EUSERS", 68, 87), ("EDQUOT", 69, 122), ("ESTALE", 70, 116), ("EREMOTE", 71, 66),
        ("ENOLCK", 77, 37), ("ENOSYS", 78, 38), ("EIDRM", 82, 43), ("ENOMSG", 83, 42),
        ("EOVERFLOW", 84, 75), ("ECANCELED", 85, 125), ("EILSEQ", 86, 84),
        // The runtime carries no name of its own for an absent attribute; the one it reads for absent
        // data is the same number and the same meaning to every caller that tests it.
        ("ENOATTR", 87, 61),
        ("EBADMSG", 89, 74), ("EMULTIHOP", 90, 72), ("ENOLINK", 91, 67), ("EPROTO", 92, 71),
        ("ENOTRECOVERABLE", 107, 131), ("EOWNERDEAD", 108, 130),
    ];

    /// <summary>The device's numbering indexed straight, holding the runtime's number for each.</summary>
    private static byte[] BuildErrorTable()
    {
        byte[] table = new byte[ErrorTableSize];
        Array.Fill(table, UnnamedError);
        table[0] = 0;                            // no error stays no error
        foreach ((string _, byte device, byte runtime) in ErrorNumbers)
            table[device] = runtime;
        return table;
    }

    /// <summary>The same pairing read the other way, for a number going back to the platform.</summary>
    private const string ReverseErrorTableSymbol = "__sp_platform_error_numbers";

    private static byte[] BuildReverseErrorTable()
    {
        byte[] table = new byte[ErrorTableSize];
        Array.Fill(table, UnnamedError);
        table[0] = 0;
        foreach ((string _, byte device, byte runtime) in ErrorNumbers)
            table[runtime] = device;
        return table;
    }

    // strerror(number): the message for an error, as text the caller does not own.
    //
    // The platform publishes this and it can be reached straight through, which is what left it wrong:
    // the number arriving here is counted the runtime's way, and the platform counts errors its own
    // way, so every number the two sides disagree about asked for the message belonging to a different
    // error. Two callers reach it - the compressor, when it reports why a stream could not be written
    // or read, and the runtime, when it writes out what a fault was - and both hand what comes back
    // straight to whoever is reading the report. The number is put back the way the platform counts
    // before the call, and nothing else changes, so the answer is still the platform's own text.
    private static CompatFunc StrError()
    {
        var a = new Asm();
        a.Emit(0x81, 0xFF); a.Emit32(ErrorTableSize);       // cmp edi, the numbering's reach
        a.JumpIfAtOrAbove("asis");
        a.Emit(0x89, 0xFF);                                 // mov edi, edi
        int tableAt = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the numbering, reversed]
        a.Emit(0x0F, 0xB6, 0x3C, 0x38);                     // movzx edi, byte [rax + rdi]
        a.Mark("asis");
        // A tail jump, so what the platform answers is what the caller gets and no frame is built.
        a.Emit(0xE9); a.Note(a.Length, Linker.DeviceAliasPrefix + "strerror"); a.Emit(0, 0, 0, 0);
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("strerror", false, code, [.. relocs, (tableAt, ReverseErrorTableSymbol)]);
    }

    // strerror_r(number, buffer, size): the message for an error.
    //
    // Both sides publish this name and they do not agree on what it answers. The runtime expects the
    // message itself back - it hands the answer straight on as text - while this platform answers zero
    // when it filled the buffer and an error number when it could not, which is what it does for any
    // buffer of twenty-two bytes or fewer. So a caller with a small buffer was handed the number
    // thirty-four and read it as an address. Nothing caught it because the one caller in the runtime
    // always passes a thousand bytes, and a thousand bytes always succeeds and always answers zero,
    // which reads as "no message" and is quietly handled.
    //
    // The number also has to go back the way it came: the runtime counts errors its own way, so asking
    // the platform for the message belonging to the runtime's number describes a different error.
    private static CompatFunc StrErrorR()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        a.Emit(0x48, 0x89, 0xF3);                           // mov rbx, rsi   (the buffer)
        a.Emit(0x48, 0x85, 0xD2); a.JumpIfEqual("nowhere"); // test rdx, rdx
        a.Emit(0x81, 0xFF); a.Emit32(ErrorTableSize);       // cmp edi, the numbering's reach
        a.JumpIfAtOrAbove("asis");
        a.Emit(0x89, 0xFF);                                 // mov edi, edi
        int tableAt = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the numbering, reversed]
        a.Emit(0x0F, 0xB6, 0x3C, 0x38);                     // movzx edi, byte [rax + rdi]
        a.Mark("asis");
        a.Call(Linker.DeviceAliasPrefix + "strerror_r");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("filled");        // test eax, eax
        a.Emit(0xC6, 0x03, 0x00);                           // mov byte [rbx], 0   (nothing to say)
        a.Mark("filled");
        a.Emit(0x48, 0x89, 0xD8);                           // mov rax, rbx   (the message, as text)
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret
        a.Mark("nowhere");
        a.Emit(0x31, 0xC0);                                 // xor eax, eax   (nowhere to put it)
        a.JumpIfAlways("out");
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("strerror_r", false, code, [.. relocs, (tableAt, ReverseErrorTableSymbol)]);
    }

    // pthread_cond_timedwait: wait on a condition until a deadline.
    //
    // A thread call answers its error by value rather than through the per-thread word, so the
    // translation the per-thread word gets does not reach it. The two sides number a timeout
    // differently, and the collector's own wait compares what comes back against the runtime's number
    // for it - so a wait that timed out read as a wait that failed, and the collector treated a
    // deadline it set itself as an error. This stands in front of the platform's and puts the answer
    // through the same numbering everything else goes through.
    private static CompatFunc PthreadCondTimedWait()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Call(Linker.DeviceAliasPrefix + "pthread_cond_timedwait");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("done");          // test eax, eax   (no error stays none)
        a.Emit(0x3D); a.Emit32(ErrorTableSize);             // cmp eax, the numbering's reach
        a.JumpIfAtOrAbove("unnamed");
        a.Emit(0x89, 0xC0);                                 // mov eax, eax    (clear the upper half)
        int tableAt = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x15, 0, 0, 0, 0);               // lea rdx, [rip + the numbering]
        a.Emit(0x0F, 0xB6, 0x04, 0x02);                     // movzx eax, byte [rdx + rax]
        a.JumpIfAlways("done");
        a.Mark("unnamed");
        a.Emit(0xB8, UnnamedError, 0x00, 0x00, 0x00);       // mov eax, no name for it
        a.Mark("done");
        a.Emit(0x5D, 0xC3);                                 // pop rbp ; ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("pthread_cond_timedwait", false, code, [.. relocs, (tableAt, ErrorTableSymbol)]);
    }

    // ---------------------------------------------------------------------------
    // File timestamps.
    //
    // The runtime sets a file's times through a pair of routines this platform does not publish, and
    // it does publish the older pair that differ only in how fine the time is: microseconds rather
    // than nanoseconds. So each of these divides the fractional part down and hands the older routine
    // the result.
    //
    // Two things they cannot carry across. A time given as "leave this one alone" needs the file's
    // current time read back first, and one given as "set it to now" only works when both are, so
    // anything else in that shape is refused rather than written wrong; the runtime asks for neither.
    // And the newer routine is asked not to follow a link, which the older one always does - the
    // platform publishes nothing that does not, so setting the times of a link sets its target's.
    // ---------------------------------------------------------------------------

    private const int UtimeNow = 0x3FFFFFFF, UtimeOmit = 0x3FFFFFFE;

    // Fills two microsecond times at [rsp] from the two nanosecond times rsi points at, or jumps to
    // "now" for a null pointer or a pair both meaning now, or to "refuse" for anything else in that
    // shape. Leaves rsi pointing at the pair it filled.
    private static void EmitTimeConversion(Asm a)
    {
        a.Emit(0x48, 0x85, 0xF6); a.JumpIfEqual("now");     // test rsi, rsi
        a.Emit(0x48, 0x8B, 0x46, 0x08);                     // mov rax, [rsi+8]    first nanoseconds
        a.Emit(0x4C, 0x8B, 0x46, 0x18);                     // mov r8, [rsi+24]    second nanoseconds
        a.Emit(0x48, 0x3D); a.Emit32(UtimeNow);             // cmp rax, set it to now
        a.JumpIfNotEqual("settled");
        a.Emit(0x49, 0x81, 0xF8); a.Emit32(UtimeNow);       // cmp r8, set it to now
        a.JumpIfEqual("now");
        a.Mark("settled");
        a.Emit(0x48, 0x3D); a.Emit32(UtimeOmit);            // cmp rax, leave it alone
        a.JumpIfAtOrAbove("refuse");
        a.Emit(0x49, 0x81, 0xF8); a.Emit32(UtimeOmit);      // cmp r8, leave it alone
        a.JumpIfAtOrAbove("refuse");

        a.Emit(0x4C, 0x8B, 0x0E);                           // mov r9, [rsi]       first seconds
        a.Emit(0x4C, 0x89, 0x0C, 0x24);                     // mov [rsp], r9
        a.Emit(0x4C, 0x8B, 0x4E, 0x10);                     // mov r9, [rsi+16]    second seconds
        a.Emit(0x4C, 0x89, 0x4C, 0x24, 0x10);               // mov [rsp+16], r9
        a.Emit(0x41, 0xB9, 0xE8, 0x03, 0x00, 0x00);         // mov r9d, 1000
        a.Emit(0x31, 0xD2);                                 // xor edx, edx
        a.Emit(0x49, 0xF7, 0xF1);                           // div r9              first microseconds
        a.Emit(0x48, 0x89, 0x44, 0x24, 0x08);               // mov [rsp+8], rax
        a.Emit(0x4C, 0x89, 0xC0);                           // mov rax, r8
        a.Emit(0x31, 0xD2);                                 // xor edx, edx
        a.Emit(0x49, 0xF7, 0xF1);                           // div r9              second microseconds
        a.Emit(0x48, 0x89, 0x44, 0x24, 0x18);               // mov [rsp+24], rax
        a.Emit(0x48, 0x89, 0xE6);                           // mov rsi, rsp
        a.JumpIfAlways("hand over");
        a.Mark("now");
        a.Emit(0x31, 0xF6);                                 // xor esi, esi        both to now
        a.Mark("hand over");
    }

    // The tail of one of these: hand over, or refuse and say why.
    private static void EmitTimeTail(Asm a, string target, out int callSite)
    {
        a.Call(target);
        a.JumpIfAlways("out");
        a.Mark("refuse");
        a.Emit(0xBF, NoSuchRoutine, 0x00, 0x00, 0x00);      // mov edi, there is no such routine
        a.Call(SetErrnoSymbol);
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF);               // mov eax, -1
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x28, 0x5B, 0x5D, 0xC3);   // add rsp,40 ; pop rbx ; pop rbp ; ret
        callSite = 0;
    }

    // futimens(fd, times[2]): set an open file's times.
    private static CompatFunc Futimens()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x28);                     // sub rsp, 40   (two times, and alignment)
        EmitTimeConversion(a);
        EmitTimeTail(a, "futimes", out _);
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("futimens", false, code, relocs);
    }

    // utimensat(dirfd, path, times[2], flags): set a named file's times. The directory the name is
    // relative to is always the working directory here and the flag is always "do not follow a link",
    // which is what the runtime passes and what the older routine cannot honour.
    private static CompatFunc Utimensat()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x28);                     // sub rsp, 40   (two times, and alignment)
        a.Emit(0x48, 0x89, 0xF7);                           // mov rdi, rsi  (the name)
        a.Emit(0x48, 0x89, 0xD6);                           // mov rsi, rdx  (the times)
        EmitTimeConversion(a);
        EmitTimeTail(a, "utimes", out _);
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("utimensat", false, code, relocs);
    }

    // madvise(address, length, advice): a hint about how a range will be used.
    //
    // The two sides agree on the first five hints and part company immediately after. The one the
    // collector leans on - "I am done with these pages, the contents are junk, take them back" - is
    // the eighth number to the runtime and the fifth here; the eighth here means something else
    // entirely, and something actively unhelpful: keep these pages out of the record written when the
    // module dies. Passing the number through therefore did two wrong things at once. The collector
    // asked for memory back, was told yes, and got nothing back - so a heap that should have shrunk
    // after every collection only ever grew. And every range it asked about was quietly struck from
    // the record the machine writes when a module fails, which is the one place the answers to
    // questions like this one come from.
    //
    // Hints with no counterpart here are answered without being passed on. A hint is advisory - every
    // caller in the runtime either ignores the answer or treats it as advice - so answering "done"
    // and doing nothing is correct, where forwarding a number this platform reads as a different hint
    // is not.
    private const string AdviceTableSymbol = "__sp_memory_advice";
    private const int AdviceTableSize = 9;
    private const byte AdviceNoCounterpart = 0xFF;

    /// <summary>Hints the runtime names, indexed straight, holding this platform's number for each.</summary>
    private static byte[] BuildAdviceTable()
    {
        byte[] t = new byte[AdviceTableSize];
        Array.Fill(t, AdviceNoCounterpart);
        for (byte i = 0; i <= 4; i++) t[i] = i;         // ordinary, random, sequential, will need, done
        t[8] = 5;                                       // done with these, and their contents are junk
        return t;
    }

    private static CompatFunc MAdvise()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x83, 0xFA, AdviceTableSize);                // cmp edx, how many the runtime names
        a.JumpIfAtOrAbove("nohint");
        a.Emit(0x89, 0xD2);                                 // mov edx, edx  (clear the top before indexing)
        int tableAt = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the hints]
        a.Emit(0x0F, 0xB6, 0x14, 0x10);                     // movzx edx, byte [rax + rdx]
        a.Emit(0x80, 0xFA, AdviceNoCounterpart);            // cmp dl, no counterpart
        a.JumpIfEqual("nohint");
        a.Emit(0x5D);                                       // pop rbp
        int tailAt = a.Length + 1;
        a.Emit(0xE9, 0, 0, 0, 0);                           // jmp the platform's own
        a.Mark("nohint");
        a.Emit(0x31, 0xC0, 0x5D, 0xC3);                     // xor eax, eax ; pop rbp ; ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("madvise", false, code,
            [.. relocs, (tableAt, AdviceTableSymbol), (tailAt, Linker.DeviceAliasPrefix + "madvise")]);
    }

    // syscall(number, ...): the runtime asks for a handful of things this way, all but one of which
    // this platform does not have. The one it does have is the caller's own thread number, which the
    // runtime reads once, keeps, and uses to tell its threads apart: it records each thread under that
    // number and looks threads up by it later. A blanket refusal gave every thread the same number, so
    // every later lookup answered with whichever thread had been recorded first - and what is done
    // with the answer is to note where a thread was interrupted and to walk its memory looking for
    // what is still in use, both against the wrong thread.
    //
    // The rest must keep being refused. One of them is how the runtime asks whether the machine offers
    // a cheaper way to make one thread's writes visible to the others; a refusal is the answer that
    // makes it choose the way that works here, and answering anything else would have it choose one
    // that does not.
    private const byte AskingForThreadNumber = 186;

    private static CompatFunc SysCall()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x81, 0xFF); a.Emit32(AskingForThreadNumber);
        a.JumpIfNotEqual("norest");
        a.Emit(0x5D);                                       // pop rbp
        int tailAt = a.Length + 1;
        a.Emit(0xE9, 0, 0, 0, 0);                           // jmp the platform's own
        a.Mark("norest");
        a.Emit(0xBF, NoSuchRoutine, 0x00, 0x00, 0x00);      // mov edi, there is no such routine
        a.Call(SetErrnoSymbol);
        a.Emit(0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF);   // mov rax, -1
        a.Emit(0x5D, 0xC3);                                 // pop rbp ; ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("syscall", false, code, [.. relocs, (tailAt, "scePthreadGetthreadid")]);
    }

    private const string SetErrnoSymbol = "__sp_set_errno";

    // __sp_set_errno(number): put a number, counted the way the runtime counts them, where the runtime
    // reads its last error from.
    //
    // It writes the word the runtime owns, and clears the platform's place on the way. Without the
    // clearing, a failure the platform recorded earlier and nobody read would be taken as news on the
    // next read and translated over the number just written.
    private static CompatFunc SetErrno()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        a.Emit(0x89, 0xFB);                                 // mov ebx, edi   (the number)
        a.Call("__error");
        a.Emit(0xC7, 0x00, 0x00, 0x00, 0x00, 0x00);         // mov dword [rax], 0   (nothing pending)
        int tlsAt = a.Length;
        a.Emit(TlsLoad(RegRdx));                            // rdx = this thread's word
        a.Emit(0x89, 0x1A);                                 // mov [rdx], ebx  (the runtime's own word)
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new(SetErrnoSymbol, false, code, relocs, Tls: (tlsAt, RegRdx, ErrnoShadowSymbol));
    }

    // __errno_location(): the place the runtime reads its last error from, and writes to.
    //
    // It is a place of this object's own, per thread, not the platform's. Translating the platform's
    // place where it lies looked simpler and is wrong, because the runtime does not only read that
    // place: it writes numbers of its own into it, at fourteen points in what gets linked. A number
    // the runtime writes is already counted the way the runtime counts, and translating it again takes
    // it somewhere else - two of the codes trade places, so each becomes the other, and one the
    // runtime writes has no counterpart at all and comes back as the number for an error with no name.
    // Remembering the last number written does not tell the two apart either, since it cannot say who
    // wrote it.
    //
    // What separates them is that the platform only ever writes that place to report a failure, and a
    // failure is never numbered zero. So a number sitting there is news, and it is taken once: read,
    // translated into the runtime's word, and cleared. After that the runtime's word is the runtime's
    // to keep, and saving it, calling something, and putting it back all work - the reading happens
    // before the writing, so a failure in between is taken first and then written over, which is the
    // order the caller asked for. Clearing is what makes the same failure twice in a row readable as
    // two failures rather than one.
    private static CompatFunc ErrnoLocation()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        int tlsAt = a.Length;
        a.Emit(TlsLoad(RegRbx));                            // rbx = this thread's word
        a.Call("__error");
        a.Emit(0x8B, 0x08);                                 // mov ecx, [rax]   (the platform's number)
        // Nothing there, so nothing has failed since it was last taken and the runtime's word stands.
        a.Emit(0x85, 0xC9); a.JumpIfEqual("keep");          // test ecx, ecx
        a.Emit(0xC7, 0x00, 0x00, 0x00, 0x00, 0x00);         // mov dword [rax], 0   (taken)
        a.Emit(0x81, 0xF9); a.Emit32(ErrorTableSize);       // cmp ecx, the numbering's reach
        a.JumpIfAtOrAbove("unnamed");
        int tableAt = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x15, 0, 0, 0, 0);               // lea rdx, [rip + the numbering]
        a.Emit(0x0F, 0xB6, 0x0C, 0x0A);                     // movzx ecx, byte [rdx + rcx]
        a.JumpIfAlways("store");
        a.Mark("unnamed");
        a.Emit(0xB9, UnnamedError, 0x00, 0x00, 0x00);       // mov ecx, no name for it
        a.Mark("store");
        a.Emit(0x89, 0x0B);                                 // mov [rbx], ecx   (the runtime's own word)
        a.Mark("keep");
        a.Emit(0x48, 0x89, 0xD8);                           // mov rax, rbx     (hand back our word)
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret

        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("__errno_location", false, code, [.. relocs, (tableAt, ErrorTableSymbol)],
            Tls: (tlsAt, RegRbx, ErrnoShadowSymbol));
    }

    // ---------------------------------------------------------------------------
    // Clocks.
    //
    // The two sides number their clocks differently, and the one the runtime asks for most is the one
    // that differs. It asks for clock one meaning "counts steadily and never jumps"; here clock one
    // counts only the time this process spent on a processor, and the steady one is four. Every waiting
    // deadline, every measured interval and every pause the collector times is taken against it, so the
    // module is not broken by this so much as quietly wrong about how much time has passed - and the
    // condition variables are told to wait on one clock while their deadlines are computed against
    // another, which is worse than either alone.
    //
    // The names this reaches are deliberately the platform's own rather than the portable ones. A
    // definition here shadows the portable name for every reference in the module including its own, so
    // a translating clock_gettime that called clock_gettime would call itself for ever.
    //
    // (what the runtime asks for, what it means here)
    private static readonly (byte Runtime, byte Device, string What)[] ClockIds =
    [
        (0, 0,  "wall clock"),                   // asked for
        (1, 4,  "steady, never jumps"),          // asked for; the one that matters, since here 1 is
                                                 // processor time and the steady one is four
        // Nothing links a request for either of these two. The first reaches this platform's own
        // process clock rather than the one that carries the same name as what was asked for, which
        // is numbered twenty-one here; settle which is meant before relying on it.
        (2, 15, "processor time for this module"),
        (3, 14, "processor time for this thread"),
        (4, 4,  "steady and unadjusted"),        // not asked for
        (5, 10, "wall clock, cheap and coarse"), // asked for
        (6, 12, "steady, cheap and coarse"),     // asked for
        (7, 20, "counts since the machine started"),  // asked for
    ];
    private const string ClockTableSymbol = "__sp_clock_ids";
    private const int ClockTableSize = 8;

    private static byte[] BuildClockTable()
    {
        byte[] t = new byte[ClockTableSize];
        foreach ((byte runtime, byte device, string _) in ClockIds)
            t[runtime] = device;
        return t;
    }

    /// <summary>Rewrites the clock in a register to the one this platform numbers it as.</summary>
    private static void TranslateClock(Asm a, byte[] compare, byte[] widen, byte[] load, string past)
    {
        a.Emit(compare);                                    // cmp <reg>, how many we know
        a.JumpIfAtOrAbove(past);
        a.Emit(widen);                                      // clear the top half before indexing
        int at = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x05, 0, 0, 0, 0);               // lea rax, [rip + the numbering]
        a.Emit(load);                                       // movzx <reg>, byte [rax + <reg>]
        a.Mark(past);
        a.Note(at, ClockTableSymbol);
    }

    // clock_gettime(clock, out time): the platform's own call, with the clock and the result convention
    // translated. It answers zero or a coded failure rather than -1 and an error left elsewhere.
    private static CompatFunc ClockGettime()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8
        TranslateClock(a, [0x83, 0xFF, ClockTableSize], [0x89, 0xFF], [0x0F, 0xB6, 0x3C, 0x38], "asis");
        a.Call("sceKernelClockGettime");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("out");           // test eax, eax
        a.Emit(0x89, 0xC3);                                 // mov ebx, eax   (keep the coded failure)
        a.Call("__error");
        a.Emit(0x81, 0xE3, 0xFF, 0xFF, 0x00, 0x00);         // and ebx, the error itself
        a.Emit(0x89, 0x18);                                 // mov [rax], ebx
        a.Emit(0xB8, 0xFF, 0xFF, 0xFF, 0xFF);               // mov eax, -1
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08, 0x5B, 0x5D, 0xC3);   // add rsp,8 ; pop rbx ; pop rbp ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("clock_gettime", false, code, relocs);
    }

    // The attribute objects a thread is configured through are the one place where this platform's
    // type is LARGER than the one the runtime reserves room for. An attribute object is a single
    // word here - the platform keeps the object and hands back a reference to it - while the runtime
    // sets aside four bytes, which is all its own library needs. So the platform's own routine, asked
    // to fill four bytes, writes eight, and the other four land on whatever the compiler placed next.
    //
    // What it placed next was the value guarding the return address, so the routine ran to completion
    // and died on the way out reporting a damaged frame, several calls away from the write that did
    // it. Nothing about that failure points back here, which is worth saying plainly: this was found
    // by reading the four bytes out of a machine's own record of the crash and recognising the top
    // half of an address that belongs to the platform.
    //
    // Every other object of this shape is safe, and for the same reason read the other way: a mutex,
    // a condition, a lock and a thread are each one word here against the forty, forty-eight, fifty-
    // six and eight reserved for them, so the platform writes well inside what it was given.
    //
    // The answer is that attribute objects never reach the platform at all. The four bytes the caller
    // owns hold the setting itself - a clock, or a kind of mutex - and the routine that consumes the
    // attributes builds a real one on its own frame, applies the setting, uses it, and releases it
    // before returning. Nothing belonging to the platform is ever written into the caller's four
    // bytes, and the setting still arrives where it was meant to go.

    // The settings an attribute object carries before anything is asked of it, in the caller's own
    // numbering: the wall clock, and an ordinary mutex.
    private const byte AttrStartingClock = 0, AttrStartingKind = 0;
    // The kinds of mutex run the other way round here: what the caller numbers 0, 1, 2 - ordinary,
    // re-entrant, checked - this platform numbers 3, 2, 1, so one is the other subtracted from three.
    // Anything outside that range asks for a kind this platform does not have, and gets the one it
    // uses when none is named.
    private const byte MutexKindsKnown = 3, MutexKindsMirror = 3, MutexKindWhenUnknown = 1;

    /// <summary>An attribute object starts holding one setting, in the four bytes the caller owns.</summary>
    private static CompatFunc AttrStart(string name, byte setting)
    {
        var a = new Asm();
        a.Emit(0xC7, 0x07);                                 // mov dword [rdi], setting
        a.Emit32(setting);
        a.Emit(0x31, 0xC0, 0xC3);                           // xor eax, eax ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new(name, false, code, relocs);
    }

    /// <summary>Changing a setting keeps it in those same four bytes, and writes no more than four.</summary>
    private static CompatFunc AttrKeep(string name)
    {
        var a = new Asm();
        a.Emit(0x89, 0x37);                                 // mov [rdi], esi
        a.Emit(0x31, 0xC0, 0xC3);                           // xor eax, eax ; ret
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new(name, false, code, relocs);
    }

    /// <summary>The frame the two consuming routines share: the platform's own attributes at [rbp-24].</summary>
    private static void AttrFrameStart(Asm a)
    {
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53, 0x41, 0x54);                           // push rbx ; push r12
        a.Emit(0x48, 0x83, 0xEC, 0x10);                     // sub rsp, 16
        a.Emit(0x48, 0x89, 0xFB);                           // mov rbx, rdi   (what is being set up)
        a.Emit(0x45, 0x31, 0xE4);                           // xor r12d, r12d (the setting, if none named)
        a.Emit(0x48, 0x85, 0xF6); a.JumpIfEqual("plain");    // test rsi, rsi
        a.Emit(0x44, 0x8B, 0x26);                           // mov r12d, [rsi]  (four bytes, no more)
        a.Mark("plain");
    }

    /// <summary>Answer zero, or the error itself rather than the platform's coded form.</summary>
    private static void AttrFrameEnd(Asm a)
    {
        a.Mark("coded");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("out");           // test eax, eax
        a.Emit(0x25, 0xFF, 0xFF, 0x00, 0x00);               // and eax, the error itself
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x10);                     // add rsp, 16
        a.Emit(0x41, 0x5C, 0x5B, 0x5D, 0xC3);               // pop r12 ; pop rbx ; pop rbp ; ret
    }

    // pthread_cond_init(condition, attributes): the platform's attributes are built here, given the
    // clock the caller asked for, and released again. The clock is translated on the way, so a wait
    // and the deadline it is measured against are on the same one.
    private static CompatFunc CondInit()
    {
        var a = new Asm();
        AttrFrameStart(a);
        a.Emit(0x48, 0x8D, 0x7D, 0xE8);                     // lea rdi, [rbp-24]
        a.Call("scePthreadCondattrInit");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("coded");      // test eax, eax
        a.Emit(0x44, 0x89, 0xE6);                           // mov esi, r12d
        TranslateClock(a, [0x83, 0xFE, ClockTableSize], [0x89, 0xF6], [0x0F, 0xB6, 0x34, 0x30], "asis");
        a.Emit(0x48, 0x8D, 0x7D, 0xE8);                     // lea rdi, [rbp-24]
        a.Call("scePthreadCondattrSetclock");
        a.Emit(0x48, 0x89, 0xDF);                           // mov rdi, rbx
        a.Emit(0x48, 0x8D, 0x75, 0xE8);                     // lea rsi, [rbp-24]
        a.Emit(0x31, 0xD2);                                 // xor edx, edx  (unnamed; the platform allows it)
        a.Call("scePthreadCondInit");
        a.Emit(0x41, 0x89, 0xC4);                           // mov r12d, eax  (keep it across the release)
        a.Emit(0x48, 0x8D, 0x7D, 0xE8);                     // lea rdi, [rbp-24]
        a.Call("scePthreadCondattrDestroy");
        a.Emit(0x44, 0x89, 0xE0);                           // mov eax, r12d
        AttrFrameEnd(a);
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("pthread_cond_init", false, code, relocs);
    }

    // pthread_mutex_init(mutex, attributes): the same shape, with the kind of mutex translated rather
    // than a clock.
    private static CompatFunc MutexInit()
    {
        var a = new Asm();
        AttrFrameStart(a);
        a.Emit(0x48, 0x8D, 0x7D, 0xE8);                     // lea rdi, [rbp-24]
        a.Call("scePthreadMutexattrInit");
        a.Emit(0x85, 0xC0); a.JumpIfNotEqual("coded");      // test eax, eax
        a.Emit(0x41, 0x83, 0xFC, MutexKindsKnown);          // cmp r12d, how many we know
        a.JumpIfAtOrAbove("theirs");
        a.Emit(0xBE, MutexKindsMirror, 0x00, 0x00, 0x00);   // mov esi, the mirror
        a.Emit(0x44, 0x29, 0xE6);                           // sub esi, r12d
        a.JumpIfAlways("settle");
        a.Mark("theirs");
        a.Emit(0xBE, MutexKindWhenUnknown, 0x00, 0x00, 0x00);
        a.Mark("settle");
        a.Emit(0x48, 0x8D, 0x7D, 0xE8);                     // lea rdi, [rbp-24]
        a.Call("scePthreadMutexattrSettype");
        a.Emit(0x48, 0x89, 0xDF);                           // mov rdi, rbx
        a.Emit(0x48, 0x8D, 0x75, 0xE8);                     // lea rsi, [rbp-24]
        a.Emit(0x31, 0xD2);                                 // xor edx, edx  (unnamed)
        a.Call("scePthreadMutexInit");
        a.Emit(0x41, 0x89, 0xC4);                           // mov r12d, eax
        a.Emit(0x48, 0x8D, 0x7D, 0xE8);                     // lea rdi, [rbp-24]
        a.Call("scePthreadMutexattrDestroy");
        a.Emit(0x44, 0x89, 0xE0);                           // mov eax, r12d
        AttrFrameEnd(a);
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("pthread_mutex_init", false, code, relocs);
    }

    // ---------------------------------------------------------------------------
    // Payload-only per-thread block: shared init, accessor, and the three consumers.
    //
    // The three consumers below (SetErrno / ErrnoLocation / Readdir64 payload variants) each replace
    // their non-payload TLS load with a single call to <see cref="ThreadBlockAccessor"/>. The block
    // layout is identical to the TLS one - offset zero holds the readdir entry, offset
    // <see cref="ErrnoShadowOffset"/> holds the errno word - so nothing else in the code changes.
    //
    // The shared init routine sequences on a state word: 0 = uninitialised, 1 = one thread is inside
    // pthread_key_create right now, 2 = the key slot has been written. A caller uses cmpxchg to move
    // 0 -> 1 (announcing it will do the create) and a plain store to move 1 -> 2 (releasing the
    // completed create). A caller that finds the state at 1 spins on `pause` until it reads 2. The
    // fast path - state already at 2 - is a single load and compare with no fence, since a subsequent
    // load of the key slot is data-dependent on the state read that saw 2, and the kernel does not
    // fold that dependency.
    // ---------------------------------------------------------------------------

    private static CompatFunc ThreadBlockKeyInit()
    {
        // void __sp_thread_block_key_init(pthread_key_t *keyPtr, uint32_t *statePtr):
        //   if (*statePtr == 2) return;
        //   if (cmpxchg(statePtr, 0, 1) == 0) {           // we won the race
        //       pthread_key_create(keyPtr, free);
        //       *statePtr = 2;                            // release
        //       return;
        //   }
        //   while (*statePtr != 2) pause();               // lost the race, wait for the winner
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                               // push rbx
        a.Emit(0x41, 0x54);                                         // push r12
        // Three pushes (odd) after the call-pushed return address leave rsp at 0 mod 16.
        a.Emit(0x48, 0x89, 0xFB);                                   // mov rbx, rdi (key slot)
        a.Emit(0x49, 0x89, 0xF4);                                   // mov r12, rsi (state slot)

        // Fast path: state already 2?
        a.Emit(0x41, 0x8B, 0x04, 0x24);                             // mov eax, [r12]
        a.Emit(0x83, 0xF8, 0x02);                                   // cmp eax, 2
        a.JumpIfEqual("done");

        // cmpxchg with 0 -> 1. lock cmpxchg dword [r12], ecx sets ZF iff [r12] was eax before.
        a.Emit(0x31, 0xC0);                                         // xor eax, eax
        a.Emit(0xB9, 0x01, 0x00, 0x00, 0x00);                       // mov ecx, 1
        a.Emit(0xF0, 0x41, 0x0F, 0xB1, 0x0C, 0x24);                 // lock cmpxchg [r12], ecx
        a.JumpIfNotEqual("spin");                                   // lost the race

        // We won: pthread_key_create(&key, free).
        a.Emit(0x48, 0x89, 0xDF);                                   // mov rdi, rbx
        a.Emit(0x48, 0x8D, 0x35, 0, 0, 0, 0);                       // lea rsi, [rip + free]
        a.Note(a.Length - 4, ImportFree);
        a.Call(ImportPthreadKeyCreate);
        // Release: state = 2. A plain store is sufficient because every reader that observes 2 will
        // observe the pthread_key_create's write to *keyPtr - the create call itself is a full
        // barrier on this platform (it enters the kernel), so the store to state cannot be reordered
        // above the create's own writes.
        a.Emit(0x41, 0xC7, 0x04, 0x24, 0x02, 0x00, 0x00, 0x00);     // mov dword [r12], 2
        a.JumpIfAlways("done");

        // Lost the race: spin until state == 2.
        a.Mark("spin");
        a.Emit(0xF3, 0x90);                                         // pause
        a.Emit(0x41, 0x8B, 0x04, 0x24);                             // mov eax, [r12]
        a.Emit(0x83, 0xF8, 0x02);                                   // cmp eax, 2
        a.JumpIfNotEqual("spin");

        a.Mark("done");
        a.Emit(0x41, 0x5C);                                         // pop r12
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new(PayloadKeyInitSymbol, false, code, relocs);
    }

    private static CompatFunc ThreadBlockAccessor()
    {
        // void *__sp_thread_block(void):
        //   if (state != 2) __sp_thread_block_key_init(&key, &state);
        //   void *p = pthread_getspecific(key);
        //   if (p) return p;
        //   p = calloc(1, ThreadBlockSize);
        //   if (!p) return NULL;
        //   pthread_setspecific(key, p);
        //   return p;
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                               // push rbx  (holds the block ptr)
        a.Emit(0x48, 0x83, 0xEC, 0x08);                             // sub rsp, 8  (align)

        // Fast path: state already 2?
        a.Emit(0x8B, 0x05, 0, 0, 0, 0);                             // mov eax, [rip + state]
        a.Note(a.Length - 4, PayloadKeyStateSymbol);
        a.Emit(0x83, 0xF8, 0x02);                                   // cmp eax, 2
        a.JumpIfEqual("have_key");

        // Slow path: run the init.
        a.Emit(0x48, 0x8D, 0x3D, 0, 0, 0, 0);                       // lea rdi, [rip + key]
        a.Note(a.Length - 4, PayloadKeySlotSymbol);
        a.Emit(0x48, 0x8D, 0x35, 0, 0, 0, 0);                       // lea rsi, [rip + state]
        a.Note(a.Length - 4, PayloadKeyStateSymbol);
        a.Call(PayloadKeyInitSymbol);

        a.Mark("have_key");
        a.Emit(0x8B, 0x3D, 0, 0, 0, 0);                             // mov edi, [rip + key]  (pthread_key_t = int)
        a.Note(a.Length - 4, PayloadKeySlotSymbol);
        a.Call(ImportPthreadGetspecific);
        a.Emit(0x48, 0x85, 0xC0);                                   // test rax, rax
        a.JumpIfNotEqual("done");

        // First touch on this thread: calloc(1, ThreadBlockSize).
        a.Emit(0xBF, 0x01, 0x00, 0x00, 0x00);                       // mov edi, 1
        a.Emit(0xBE); a.Emit32(ThreadBlockSize);                    // mov esi, ThreadBlockSize
        a.Call(ImportCalloc);
        a.Emit(0x48, 0x85, 0xC0);                                   // test rax, rax
        a.JumpIfEqual("done");                                      // fail: return NULL

        // Publish the block into this thread's slot.
        a.Emit(0x48, 0x89, 0xC3);                                   // mov rbx, rax
        a.Emit(0x8B, 0x3D, 0, 0, 0, 0);                             // mov edi, [rip + key]
        a.Note(a.Length - 4, PayloadKeySlotSymbol);
        a.Emit(0x48, 0x89, 0xDE);                                   // mov rsi, rbx
        a.Call(ImportPthreadSetspecific);
        a.Emit(0x48, 0x89, 0xD8);                                   // mov rax, rbx

        a.Mark("done");
        a.Emit(0x48, 0x83, 0xC4, 0x08);                             // add rsp, 8
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new(PayloadThreadBlockSymbol, false, code, relocs);
    }

    // Payload variant of __sp_set_errno: same shape as the TLS variant, but the per-thread errno word
    // is reached through the pthread-key accessor instead of a fs:[TPOFF32] load. The write to the
    // platform's own errno (via __error) is unchanged - the whole point of __sp_set_errno is to clear
    // it, so a stale interrupted-number from the previous syscall does not leak into the next retry.
    private static CompatFunc SetErrnoPayload()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                               // push rbx  (saves the number)
        a.Emit(0x48, 0x83, 0xEC, 0x08);                             // sub rsp, 8
        a.Emit(0x89, 0xFB);                                         // mov ebx, edi   (the number)
        a.Call("__error");
        a.Emit(0xC7, 0x00, 0x00, 0x00, 0x00, 0x00);                 // mov dword [rax], 0  (nothing pending)
        a.Call(PayloadThreadBlockSymbol);
        a.Emit(0x48, 0x85, 0xC0);                                   // test rax, rax
        a.JumpIfEqual("done");                                      // allocation failed: nothing to record
        // *(int *)(block + ErrnoShadowOffset) = ebx
        a.Emit(0x89, 0x98); a.Emit32(ErrnoShadowOffset);            // mov [rax + ErrnoShadowOffset], ebx
        a.Mark("done");
        a.Emit(0x48, 0x83, 0xC4, 0x08);                             // add rsp, 8
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new(SetErrnoSymbol, false, code, relocs);
    }

    // Payload variant of __errno_location: reads the per-thread errno word from the pthread-key
    // accessor and returns its address. The translation of the platform's own errno (through the
    // error-number table) happens on the way out, so a caller that reads *__errno_location() sees the
    // runtime's numbering rather than the platform's.
    private static CompatFunc ErrnoLocationPayload()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                               // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                             // sub rsp, 8
        a.Call(PayloadThreadBlockSymbol);
        a.Emit(0x48, 0x85, 0xC0);                                   // test rax, rax
        a.JumpIfEqual("fail");
        // rbx = &per_thread_errno_word
        a.Emit(0x48, 0x8D, 0x98); a.Emit32(ErrnoShadowOffset);      // lea rbx, [rax + ErrnoShadowOffset]
        a.Call("__error");
        a.Emit(0x8B, 0x08);                                         // mov ecx, [rax]  (platform's number)
        a.Emit(0x85, 0xC9); a.JumpIfEqual("keep");                  // test ecx, ecx
        a.Emit(0xC7, 0x00, 0x00, 0x00, 0x00, 0x00);                 // mov dword [rax], 0  (taken)
        a.Emit(0x81, 0xF9); a.Emit32(ErrorTableSize);               // cmp ecx, the numbering's reach
        a.JumpIfAtOrAbove("unnamed");
        int tableAt = a.Length + 3;
        a.Emit(0x48, 0x8D, 0x15, 0, 0, 0, 0);                       // lea rdx, [rip + the numbering]
        a.Emit(0x0F, 0xB6, 0x0C, 0x0A);                             // movzx ecx, byte [rdx + rcx]
        a.JumpIfAlways("store");
        a.Mark("unnamed");
        a.Emit(0xB9, UnnamedError, 0x00, 0x00, 0x00);               // mov ecx, no name for it
        a.Mark("store");
        a.Emit(0x89, 0x0B);                                         // mov [rbx], ecx  (runtime's own word)
        a.Mark("keep");
        a.Emit(0x48, 0x89, 0xD8);                                   // mov rax, rbx
        a.JumpIfAlways("epilogue");
        a.Mark("fail");
        a.Emit(0x31, 0xC0);                                         // xor eax, eax  (no per-thread slot yet)
        a.Mark("epilogue");
        a.Emit(0x48, 0x83, 0xC4, 0x08);                             // add rsp, 8
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("__errno_location", false, code, [.. relocs, (tableAt, ErrorTableSymbol)]);
    }

    // mmap for payloads: uses calloc from libSceLibcInternal instead of SYS_mmap.
    // SYS_mmap (477) is not available to unprivileged PS5 processes. C payloads resolve
    // malloc/calloc/free from libSceLibcInternal.sprx which has its own kernel-managed memory
    // pool. The NativeAOT GC calls mmap for heap allocation; this shim redirects to
    // calloc with manual 16KB page alignment.
    private static CompatFunc MmapPayload()
    {
        // mmap(addr, len, prot, flags, fd, offset) → calloc(1, rounded + page + 8) + manual align
        // Ignores addr/prot/flags/fd/offset — all mmap requests become aligned heap allocations.
        // C args: rdi=addr(ignored), rsi=len, edx=prot(ignored), ecx=flags(ignored),
        //         r8d=fd(ignored), r9=offset(ignored)
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                       // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                     // sub rsp, 8 (16-byte align)
        a.Emit(0x48, 0x89, 0xF3);                           // mov rbx, rsi (save len)
        // Breadcrumb: sp:mmap
        a.Emit(0x48, 0x8D, 0x3D);                           // lea rdi, [rip+str_mmap]
        a.Disp32("str_mmap");
        a.Call("__prospero_klog");
        // Round len up to 16KB page
        a.Emit(0x48, 0x81, 0xC3, 0xFF, 0x3F, 0x00, 0x00);   // add rbx, 0x3FFF
        a.Emit(0x48, 0x81, 0xE3, 0x00, 0xC0, 0xFF, 0xFF);   // and rbx, ~0x3FFF
        // Over-allocate: calloc(1, rounded_len + page + 8) for manual page alignment.
        // Store the raw pointer at (aligned - 8) so munmap can free it.
        a.Emit(0x48, 0x8D, 0xB3, 0x08, 0x40, 0x00, 0x00);   // lea rsi, [rbx + 0x4008] (len + page + 8)
        a.Emit(0xBF, 0x01, 0x00, 0x00, 0x00);               // mov edi, 1
        a.Call("calloc");
        a.Emit(0x48, 0x85, 0xC0);                           // test rax, rax
        a.JumpIfEqual("fail");
        // Manually align to 16KB page: aligned = (raw + 0x3FFF + 8) & ~0x3FFF
        a.Emit(0x48, 0x89, 0xC1);                           // mov rcx, rax (save raw)
        a.Emit(0x48, 0x05, 0x07, 0x40, 0x00, 0x00);         // add rax, 0x4007 (0x3FFF + 8)
        a.Emit(0x48, 0x25, 0x00, 0xC0, 0xFF, 0xFF);         // and rax, ~0x3FFF
        // Store raw pointer at aligned[-8] for munmap/free
        a.Emit(0x48, 0x89, 0x48, 0xF8);                     // mov [rax - 8], rcx
        // Breadcrumb: sp:mmap:ok — save result in rbx (len no longer needed)
        a.Emit(0x48, 0x89, 0xC3);                           // mov rbx, rax
        a.Emit(0x48, 0x8D, 0x3D);                           // lea rdi, [rip+str_ok]
        a.Disp32("str_ok");
        a.Call("__prospero_klog");
        a.Emit(0x48, 0x89, 0xD8);                           // mov rax, rbx (restore result)
        a.JumpIfAlways("done");
        a.Mark("fail");
        // Breadcrumb: sp:mmap:fail
        a.Emit(0x48, 0x8D, 0x3D);                           // lea rdi, [rip+str_fail]
        a.Disp32("str_fail");
        a.Call("__prospero_klog");
        a.Emit(0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF);   // mov rax, -1 (MAP_FAILED)
        a.Mark("done");
        // Epilog: matches prolog exactly (sub rsp 8 → add rsp 8, push rbx → pop rbx)
        a.Emit(0x48, 0x83, 0xC4, 0x08);                     // add rsp, 8
        a.Emit(0x5B);                                       // pop rbx
        a.Emit(0x5D, 0xC3);                                 // pop rbp ; ret
        // String data (after ret, never executed — referenced via RIP-relative LEA)
        a.Mark("str_mmap");
        a.Emit(0x73, 0x70, 0x3A, 0x6D, 0x6D, 0x61, 0x70, 0x0A, 0x00); // "sp:mmap\n\0"
        a.Mark("str_ok");
        a.Emit(0x73, 0x70, 0x3A, 0x6D, 0x6D, 0x61, 0x70, 0x3A, 0x6F, 0x6B, 0x0A, 0x00); // "sp:mmap:ok\n\0"
        a.Mark("str_fail");
        a.Emit(0x73, 0x70, 0x3A, 0x6D, 0x6D, 0x61, 0x70, 0x3A, 0x66, 0x61, 0x69, 0x6C, 0x0A, 0x00); // "sp:mmap:fail\n\0"
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("mmap", false, code, relocs);
    }

    // mprotect for payloads: no-op returning success. Memory from calloc is already
    // PROT_READ|PROT_WRITE. The NativeAOT GC's mprotect "commit" calls are harmless no-ops.
    private static CompatFunc MProtectPayload()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                     // push rbp ; mov rbp, rsp
        // Breadcrumb: sp:mprot
        a.Emit(0x48, 0x8D, 0x3D);                           // lea rdi, [rip+str_mprot]
        a.Disp32("str_mprot");
        a.Call("__prospero_klog");
        a.Emit(0x31, 0xC0);                                 // xor eax, eax (return 0 = success)
        a.Emit(0x5D, 0xC3);                                 // pop rbp ; ret
        a.Mark("str_mprot");
        a.Emit(0x73, 0x70, 0x3A, 0x6D, 0x70, 0x72, 0x6F, 0x74, 0x0A, 0x00); // "sp:mprot\n\0"
        (byte[] code, (int, string)[] relocs) = a.Build();
        return new("mprotect", false, code, relocs);
    }

    // buffer the device entry is copied into comes from the pthread-key accessor. The layout is
    // identical (readdir entry at offset 0, errno word past it) so every offset below matches the
    // TLS variant byte for byte.
    private static CompatFunc Readdir64Payload()
    {
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                               // push rbx
        a.Emit(0x48, 0x83, 0xEC, 0x08);                             // sub rsp, 8
        // The device readdir takes the DIR* in rdi, which is what the runtime handed us.
        a.Call("readdir");
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfEqual("end");             // test rax, rax; jz end  (empty)
        a.Emit(0x48, 0x89, 0xC3);                                   // mov rbx, rax  (device entry)
        a.Call(PayloadThreadBlockSymbol);
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfEqual("end");             // no block: caller sees nothing
        a.Emit(0x48, 0x89, 0xC7);                                   // mov rdi, rax  (per-thread block)
        // Same field layout as the TLS variant. Offsets are into the entry rbx / the block rdi.
        a.Emit(0x8B, 0x03);                                         // mov eax, [rbx]      (d_fileno)
        a.Emit(0x48, 0x89, 0x07);                                   // mov [rdi], rax      (d_ino)
        a.Emit(0x31, 0xC0);                                         // xor eax, eax
        a.Emit(0x48, 0x89, 0x47, 0x08);                             // mov [rdi+8], rax    (d_off = 0)
        a.Emit(0x8A, 0x43, 0x06);                                   // mov al, [rbx+6]     (d_type)
        a.Emit(0x88, 0x47, 0x12);                                   // mov [rdi+18], al    (d_type)
        a.Emit(0x0F, 0xB6, 0x4B, 0x07);                             // movzx ecx, byte [rbx+7] (d_namlen)
        a.Emit(0x8D, 0x41, 0x14);                                   // lea eax, [rcx+20]   (record length)
        a.Emit(0x66, 0x89, 0x47, 0x10);                             // mov [rdi+16], ax    (d_reclen)
        a.Emit(0x48, 0x89, 0xF8);                                   // mov rax, rdi        (return value)
        a.Emit(0x48, 0x8D, 0x73, 0x08);                             // lea rsi, [rbx+8]    (source name)
        a.Emit(0x48, 0x83, 0xC7, 0x13);                             // add rdi, 19         (dest name)
        a.Emit(0xFF, 0xC1);                                         // inc ecx             (copy the terminator too)
        a.Emit(0xF3, 0xA4);                                         // rep movsb
        a.JumpIfAlways("out");
        a.Mark("end");
        a.Emit(0x31, 0xC0);                                         // xor eax, eax  (null return)
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08);                             // add rsp, 8
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("readdir64", false, code, relocs);
    }

    // ---------------------------------------------------------------------------
    // pthread_create wrapper (payload only): the TCB template is planted on entry to the new thread.
    //
    // The runtime the payload carries reads its stack canary from fs:[0x28] and its pointer-guard
    // cookie from fs:[0x30]. On the payload's initial thread, __prospero_pthread_fallback stands in
    // when fs:[0x10] is null and the two slots read zero - which is a canary the runtime immediately
    // recognises as unset and works around. But every subsequent thread the runtime creates gets a
    // fresh TCB written by the platform's pthread_create, and the two guard slots come back to zero
    // there too - so the first GC callback the new thread runs aborts on its first canary check.
    //
    // The wrapper below intercepts pthread_create: it packs the caller's start routine and argument
    // into a heap struct, calls the device pthread_create with the trampoline as the start routine,
    // and lets the trampoline install the seed on entry to the new thread before jumping to the
    // caller's routine. The seed is baked into read-only text at build time and every thread reads
    // the same 16 bytes, which is the same shape a static-linked application ships.
    // ---------------------------------------------------------------------------

    private static CompatFunc PthreadCreateWrapper()
    {
        // int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
        //                    void *(*start)(void *), void *arg):
        //   void **ctx = calloc(1, 16);
        //   if (!ctx) return EAGAIN;               // 11 in the runtime's numbering
        //   ctx[0] = start;
        //   ctx[1] = arg;
        //   int rc = device_pthread_create(thread, attr, __sp_thread_trampoline, ctx);
        //   if (rc != 0) { free(ctx); return rc; }
        //   return 0;
        var a = new Asm();
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57);     // push r12/r13/r14/r15
        a.Emit(0x53);                                               // push rbx
        // We have pushed 6 GP regs plus rbp plus the return address = 8 pushes = 64 bytes. Sub 8 to
        // realign to 16 for the calls below.
        a.Emit(0x48, 0x83, 0xEC, 0x08);                             // sub rsp, 8
        a.Emit(0x49, 0x89, 0xFC);                                   // mov r12, rdi (thread)
        a.Emit(0x49, 0x89, 0xF5);                                   // mov r13, rsi (attr)
        a.Emit(0x49, 0x89, 0xD6);                                   // mov r14, rdx (start)
        a.Emit(0x49, 0x89, 0xCF);                                   // mov r15, rcx (arg)
        // calloc(1, 16)
        a.Emit(0xBF, 0x01, 0x00, 0x00, 0x00);                       // mov edi, 1
        a.Emit(0xBE, 0x10, 0x00, 0x00, 0x00);                       // mov esi, 16
        a.Call(ImportCalloc);
        a.Emit(0x48, 0x85, 0xC0); a.JumpIfEqual("nomem");           // test rax, rax; jz nomem
        a.Emit(0x48, 0x89, 0xC3);                                   // mov rbx, rax (ctx)
        // ctx[0] = start ; ctx[1] = arg
        a.Emit(0x4C, 0x89, 0x33);                                   // mov [rbx], r14
        a.Emit(0x4C, 0x89, 0x7B, 0x08);                             // mov [rbx+8], r15
        // pthread_create(thread, attr, trampoline, ctx)
        a.Emit(0x4C, 0x89, 0xE7);                                   // mov rdi, r12
        a.Emit(0x4C, 0x89, 0xEE);                                   // mov rsi, r13
        a.Emit(0x48, 0x8D, 0x15, 0, 0, 0, 0);                       // lea rdx, [rip + trampoline]
        a.Note(a.Length - 4, PayloadThreadTrampolineSymbol);
        a.Emit(0x48, 0x89, 0xD9);                                   // mov rcx, rbx
        a.Call(Linker.DeviceAliasPrefix + "pthread_create");
        a.Emit(0x85, 0xC0); a.JumpIfEqual("ok");                    // test eax, eax; jz ok
        // Non-zero result: free the ctx (the trampoline will never run) and return the error.
        a.Emit(0x41, 0x89, 0xC4);                                   // mov r12d, eax  (save rc)
        a.Emit(0x48, 0x89, 0xDF);                                   // mov rdi, rbx
        a.Call(ImportFree);
        a.Emit(0x44, 0x89, 0xE0);                                   // mov eax, r12d
        a.JumpIfAlways("out");
        a.Mark("nomem");
        a.Emit(0xB8, 0x0B, 0x00, 0x00, 0x00);                       // mov eax, 11 (EAGAIN)
        a.JumpIfAlways("out");
        a.Mark("ok");
        a.Emit(0x31, 0xC0);                                         // xor eax, eax
        a.Mark("out");
        a.Emit(0x48, 0x83, 0xC4, 0x08);                             // add rsp, 8
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C);     // pop r15/r14/r13/r12
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("pthread_create", false, code, relocs);
    }

    private static CompatFunc ThreadTrampoline()
    {
        // void *__sp_thread_trampoline(void *ctx):
        //   Allocate a per-thread 4KB TCB page via mmap, write the self-pointer at
        //   mmap_base+0x260, forward the host's fs:0x10 (pthread), fs:0x28 (canary),
        //   fs:0x30 (guard), and switch FSBASE via sysarch(AMD64_SET_FSBASE=129).
        //   Then extract start_routine and arg from ctx, free ctx, and call through.
        var a = new Asm();
        // Prologue: 6 callee-saved pushes + sub 8 -> rsp 16-aligned
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x53);                                               // push rbx
        a.Emit(0x41, 0x54);                                         // push r12
        a.Emit(0x41, 0x55);                                         // push r13
        a.Emit(0x41, 0x56);                                         // push r14
        a.Emit(0x41, 0x57);                                         // push r15
        a.Emit(0x48, 0x83, 0xEC, 0x08);                             // sub rsp, 8
        a.Emit(0x48, 0x89, 0xFB);                                   // mov rbx, rdi  (ctx)
        // Read host TCB fields BEFORE FSBASE change
        a.Emit(0x64, 0x4C, 0x8B, 0x3C, 0x25, 0x10, 0x00, 0x00, 0x00); // mov r15, fs:[0x10]
        a.Emit(0x64, 0x4C, 0x8B, 0x34, 0x25, 0x28, 0x00, 0x00, 0x00); // mov r14, fs:[0x28]
        a.Emit(0x64, 0x4C, 0x8B, 0x2C, 0x25, 0x30, 0x00, 0x00, 0x00); // mov r13, fs:[0x30]
        // mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0)
        // via __sp_crt_syscall(477, 0, 0x1000, 3, 0x1002, -1, [stack]=0)
        a.Emit(0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00);   // mov qword [rsp], 0  (offset)
        a.Emit(0xBF, 0xDD, 0x01, 0x00, 0x00);                       // mov edi, 477  (SYS_mmap)
        a.Emit(0x31, 0xF6);                                         // xor esi, esi  (addr=NULL)
        a.Emit(0xBA, 0x00, 0x10, 0x00, 0x00);                       // mov edx, 0x1000 (len)
        a.Emit(0xB9, 0x03, 0x00, 0x00, 0x00);                       // mov ecx, 3  (PROT_READ|PROT_WRITE)
        a.Emit(0x41, 0xB8, 0x02, 0x10, 0x00, 0x00);                 // mov r8d, 0x1002 (MAP_PRIVATE|MAP_ANON)
        a.Emit(0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF);                 // mov r9d, -1  (fd)
        a.Call(PayloadCrtEmitter.CrtSyscallSymbol);                 // call __sp_crt_syscall
        a.Emit(0x48, 0x83, 0xF8, 0xFF);                             // cmp rax, -1
        a.JumpIfEqual("skip_tcb");                                   // je skip_tcb
        // Compute TCB self-pointer
        a.Emit(0x4C, 0x8D, 0xA0, 0x60, 0x02, 0x00, 0x00);         // lea r12, [rax+0x260]
        // Write TCB fields
        a.Emit(0x4D, 0x89, 0x24, 0x24);                             // mov [r12], r12       (self-ptr)
        a.Emit(0x4D, 0x89, 0x7C, 0x24, 0x10);                       // mov [r12+0x10], r15  (pthread)
        a.Emit(0x4D, 0x89, 0x74, 0x24, 0x28);                       // mov [r12+0x28], r14  (canary)
        a.Emit(0x4D, 0x89, 0x6C, 0x24, 0x30);                       // mov [r12+0x30], r13  (guard)
        // sysarch(AMD64_SET_FSBASE=129, &tcb_addr)
        a.Emit(0x4C, 0x89, 0x24, 0x24);                             // mov [rsp], r12  (stash TCB addr)
        a.Emit(0x48, 0x8D, 0x14, 0x24);                             // lea rdx, [rsp]  (parms=&tcb_addr)
        a.Emit(0xBE, 0x81, 0x00, 0x00, 0x00);                       // mov esi, 129 (AMD64_SET_FSBASE)
        a.Emit(0xBF, 0xA5, 0x00, 0x00, 0x00);                       // mov edi, 165 (SYS_sysarch)
        a.Call(PayloadCrtEmitter.CrtSyscallSymbol);                 // call __sp_crt_syscall
        a.Mark("skip_tcb");
        // Extract start and arg from ctx, free ctx, call through
        a.Emit(0x4C, 0x8B, 0x23);                                   // mov r12, [rbx]     (start)
        a.Emit(0x48, 0x8B, 0x43, 0x08);                             // mov rax, [rbx+8]   (arg)
        a.Emit(0x48, 0x89, 0x04, 0x24);                             // mov [rsp], rax     (spill arg)
        a.Emit(0x48, 0x89, 0xDF);                                   // mov rdi, rbx
        a.Call(ImportFree);                                         // call free
        a.Emit(0x48, 0x8B, 0x3C, 0x24);                             // mov rdi, [rsp]     (reload arg)
        a.Emit(0x41, 0xFF, 0xD4);                                   // call r12
        // Epilogue
        a.Emit(0x48, 0x83, 0xC4, 0x08);                             // add rsp, 8
        a.Emit(0x41, 0x5F);                                         // pop r15
        a.Emit(0x41, 0x5E);                                         // pop r14
        a.Emit(0x41, 0x5D);                                         // pop r13
        a.Emit(0x41, 0x5C);                                         // pop r12
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret
        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new(PayloadThreadTrampolineSymbol, false, code, relocs);
    }

    // __sp_kfncall(fn, a1, a2, a3, a4, a5, a6, kframeKva, uretframeKva, kstackKva)
    //
    // Calls a kernel function by entering kernel mode via INT 9 and returning via INT 1.
    // The IDT and TSS must be patched beforehand by the managed KernelKfncallSetup class.
    // Arguments are passed through registers directly — the INT 9 → iret chain preserves
    // all GPRs, so the kernel function receives them in the standard AMD64 convention.
    // The return value in RAX is preserved through the INT 1 → iret return chain.
    //
    // 10 args: rdi=fn, rsi=a1, rdx=a2, rcx=a3, r8=a4, r9=a5,
    //          [rsp+8]=a6, [rsp+16]=kframeKva, [rsp+24]=uretframeKva, [rsp+32]=kstackKva
    private const string KfncallInt9Symbol = "__sp_kfncall";

    private static CompatFunc KfncallInt9()
    {
        var a = new Asm();
        // Prolog: save callee-saved + allocate local frame
        a.Emit(0x55, 0x48, 0x89, 0xE5);                             // push rbp ; mov rbp, rsp
        a.Emit(0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54);     // push r15/r14/r13/r12
        a.Emit(0x53);                                               // push rbx
        a.Emit(0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00);           // sub rsp, 0x90

        // Save all 10 arguments to stack
        a.Emit(0x48, 0x89, 0x7D, 0xC8);                             // mov [rbp-0x38], rdi (fn)
        a.Emit(0x48, 0x89, 0x75, 0xC0);                             // mov [rbp-0x40], rsi (a1)
        a.Emit(0x48, 0x89, 0x55, 0xB8);                             // mov [rbp-0x48], rdx (a2)
        a.Emit(0x48, 0x89, 0x4D, 0xB0);                             // mov [rbp-0x50], rcx (a3)
        a.Emit(0x4C, 0x89, 0x45, 0xA8);                             // mov [rbp-0x58], r8  (a4)
        a.Emit(0x4C, 0x89, 0x4D, 0xA0);                             // mov [rbp-0x60], r9  (a5)
        a.Emit(0x48, 0x8B, 0x45, 0x10);                             // mov rax, [rbp+0x10] (a6)
        a.Emit(0x48, 0x89, 0x45, 0x98);                             // mov [rbp-0x68], rax
        a.Emit(0x48, 0x8B, 0x45, 0x18);                             // mov rax, [rbp+0x18] (kframeKva)
        a.Emit(0x49, 0x89, 0xC4);                                   // mov r12, rax
        a.Emit(0x48, 0x8B, 0x45, 0x20);                             // mov rax, [rbp+0x20] (uretframeKva)
        a.Emit(0x49, 0x89, 0xC5);                                   // mov r13, rax
        a.Emit(0x48, 0x8B, 0x45, 0x28);                             // mov rax, [rbp+0x28] (kstackKva)
        a.Emit(0x49, 0x89, 0xC6);                                   // mov r14, rax

        // Save RSP for uretframe (will be restored by INT 1 return)
        a.Emit(0x49, 0x89, 0xE7);                                   // mov r15, rsp

        // Build kframe (40 bytes) at [rsp]: {fn, 0x20, 0x02, kstackKva, 0x00}
        a.Emit(0x48, 0x8B, 0x45, 0xC8);                             // mov rax, [rbp-0x38] (fn)
        a.Emit(0x48, 0x89, 0x04, 0x24);                             // mov [rsp], rax       (kframe.RIP)
        a.Emit(0x48, 0xC7, 0x44, 0x24, 0x08, 0x20, 0x00, 0x00, 0x00); // mov qword [rsp+8], 0x20 (CS)
        a.Emit(0x48, 0xC7, 0x44, 0x24, 0x10, 0x02, 0x00, 0x00, 0x00); // mov qword [rsp+16], 0x02 (RFLAGS)
        a.Emit(0x4C, 0x89, 0x74, 0x24, 0x18);                       // mov [rsp+24], r14    (kframe.RSP = kstackKva)
        a.Emit(0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00); // mov qword [rsp+32], 0x00 (SS)

        // Copyin kframe: __sp_kernel_copyin(kframeKva, &kframe_on_stack, 40)
        a.Emit(0x4C, 0x89, 0xE7);                                   // mov rdi, r12 (kframeKva)
        a.Emit(0x48, 0x89, 0xE6);                                   // mov rsi, rsp (kframe on stack)
        a.Emit(0xBA, 0x28, 0x00, 0x00, 0x00);                       // mov edx, 40
        a.Call("__sp_kernel_copyin");

        // Build uretframe (40 bytes) at [rsp]: {.Lint1_return, 0x43, 0x10202, saved_rsp, 0x3B}
        a.Emit(0x48, 0x8D, 0x05);                                   // lea rax, [rip+.Lint1_return]
        a.Disp32("int1_return");
        a.Emit(0x48, 0x89, 0x04, 0x24);                             // mov [rsp], rax       (uretframe.RIP)
        a.Emit(0x48, 0xC7, 0x44, 0x24, 0x08, 0x43, 0x00, 0x00, 0x00); // mov qword [rsp+8], 0x43 (CS)
        a.Emit(0xC7, 0x44, 0x24, 0x10, 0x02, 0x02, 0x01, 0x00);     // mov dword [rsp+16], 0x10202 (RFLAGS low)
        a.Emit(0xC7, 0x44, 0x24, 0x14, 0x00, 0x00, 0x00, 0x00);     // mov dword [rsp+20], 0       (RFLAGS high)
        a.Emit(0x4C, 0x89, 0x7C, 0x24, 0x18);                       // mov [rsp+24], r15    (uretframe.RSP = saved rsp)
        a.Emit(0x48, 0xC7, 0x44, 0x24, 0x20, 0x3B, 0x00, 0x00, 0x00); // mov qword [rsp+32], 0x3B (SS)

        // Copyin uretframe: __sp_kernel_copyin(uretframeKva, &uretframe_on_stack, 40)
        a.Emit(0x4C, 0x89, 0xEF);                                   // mov rdi, r13 (uretframeKva)
        a.Emit(0x48, 0x89, 0xE6);                                   // mov rsi, rsp
        a.Emit(0xBA, 0x28, 0x00, 0x00, 0x00);                       // mov edx, 40
        a.Call("__sp_kernel_copyin");

        // Load kernel function arguments into registers
        a.Emit(0x48, 0x8B, 0x7D, 0xC0);                             // mov rdi, [rbp-0x40] (a1)
        a.Emit(0x48, 0x8B, 0x75, 0xB8);                             // mov rsi, [rbp-0x48] (a2)
        a.Emit(0x48, 0x8B, 0x55, 0xB0);                             // mov rdx, [rbp-0x50] (a3)
        a.Emit(0x48, 0x8B, 0x4D, 0xA8);                             // mov rcx, [rbp-0x58] (a4)
        a.Emit(0x4C, 0x8B, 0x45, 0xA0);                             // mov r8,  [rbp-0x60] (a5)
        a.Emit(0x4C, 0x8B, 0x4D, 0x98);                             // mov r9,  [rbp-0x68] (a6)

        // INT 9 placeholder — replaced with NOPs for crash isolation testing.
        a.Emit(0x90, 0x90);                                         // nop; nop (was: int 9)

        // INT 1 returns here via uretframe with RSP = r15 (saved before copyin)
        a.Mark("int1_return");
        // RAX = kernel function return value (preserved through the iret chain)

        // Epilog
        a.Emit(0x48, 0x81, 0xC4, 0x90, 0x00, 0x00, 0x00);           // add rsp, 0x90
        a.Emit(0x5B);                                               // pop rbx
        a.Emit(0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F);     // pop r12/r13/r14/r15
        a.Emit(0x5D);                                               // pop rbp
        a.Emit(0xC3);                                               // ret

        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new(KfncallInt9Symbol, false, code, relocs, Hidden: true);
    }

    /// <summary>A getenv that walks a baked-in NUL-separated table of "KEY=VALUE" entries in .data.
    /// The standalone build's <c>Zero("getenv")</c> returns NULL for every lookup, which is fine when
    /// libSceLibcInternal publishes a real getenv. In a payload there is no libc to import from, and
    /// the NativeAOT GC reads <c>DOTNET_GCHeapHardLimit</c> through
    /// <c>PalGetEnvironmentVariable -&gt; getenv</c>. A NULL answer for the hard limit leaves the GC
    /// without a ceiling, and it auto-computes a regions_range of <c>total_physical_mem * 2</c> whose
    /// bookkeeping block is only partially committed. This body answers the hard limit from the baked
    /// table; knobs not in the table (GCRegionRange, GCTotalPhysicalMemory) return NULL and the GC
    /// falls through to its own defaults --- <c>5 * hard_limit</c> for the range and
    /// <c>sysconf(_SC_PHYS_PAGES)</c> for physical memory.</summary>
    private static CompatFunc GetenvPayload()
    {
        // char *getenv(const char *name):
        //   lea rsi, [rip + __sp_env_table]
        // .entry:
        //   if *rsi == 0 -> miss (end of table)
        //   compare name bytes against entry prefix until name byte == 0
        //   if entry byte at that position == '=' -> return entry + offset + 1
        //   otherwise skip to next NUL, advance past it, repeat
        // .miss:
        //   return NULL
        var a = new Asm();
        a.Emit(0x48, 0x8D, 0x35, 0, 0, 0, 0);              // lea rsi, [rip + __sp_env_table]
        a.Note(a.Length - 4, EnvTableSymbol);

        a.Mark("entry");
        a.Emit(0x80, 0x3E, 0x00);                           // cmp byte [rsi], 0
        a.JumpIfEqual("miss");                               // je miss  (empty string = end)
        a.Emit(0x31, 0xC9);                                  // xor ecx, ecx

        a.Mark("cmp");
        a.Emit(0x0F, 0xB6, 0x04, 0x0F);                     // movzx eax, byte [rdi + rcx]
        a.Emit(0x84, 0xC0);                                  // test al, al
        a.JumpIfEqual("key_end");                            // jz key_end  (name exhausted)
        a.Emit(0x3A, 0x04, 0x0E);                            // cmp al, byte [rsi + rcx]
        a.JumpIfNotEqual("skip");                            // jne skip  (mismatch)
        a.Emit(0xFF, 0xC1);                                  // inc ecx
        a.JumpIfAlways("cmp");                               // jmp cmp

        a.Mark("key_end");
        a.Emit(0x80, 0x3C, 0x0E, 0x3D);                     // cmp byte [rsi + rcx], '='
        a.JumpIfNotEqual("skip");                            // jne skip  (not at separator)
        a.Emit(0x48, 0x8D, 0x44, 0x0E, 0x01);               // lea rax, [rsi + rcx + 1]
        a.Emit(0xC3);                                        // ret  (rax -> value string)

        a.Mark("skip");
        a.Emit(0x80, 0x3E, 0x00);                           // cmp byte [rsi], 0
        a.Emit(0x48, 0x8D, 0x76, 0x01);                     // lea rsi, [rsi + 1]
        a.JumpIfNotEqual("skip");                            // jne skip  (scan to NUL)
        a.JumpIfAlways("entry");                             // jmp entry  (try next entry)

        a.Mark("miss");
        a.Emit(0x31, 0xC0);                                  // xor eax, eax
        a.Emit(0xC3);                                        // ret  (NULL)

        (byte[] code, (int Offset, string Target)[] relocs) = a.Build();
        return new("getenv", false, code, relocs);
    }

    /// <summary>The compat functions the link consumes. Every build shares the same set; the payload
    /// build swaps the three per-thread-storage bodies for pthread-key variants (see
    /// <see cref="BuildFunctions"/>) and appends the pthread_create wrapper plus its trampoline.</summary>
    private static IReadOnlyList<CompatFunc> Functions =>
    [
        // Large-file variants: the device publishes the base name with a 64-bit offset already.
        Open64(),
        Forward("lseek64", "lseek"),
        Forward("mmap64", "mmap"),
        Forward("pread64", "pread"),
        Forward("fopen64", "fopen"),
        Readdir64(),
        Forward("getrlimit64", "getrlimit"),
        StatThunk("__fxstat64", "fstat", byFd: true),
        StatThunk("__xstat64", "stat", byFd: false),

        // The clock the runtime asks for is numbered differently here, and the one it asks for most is
        // the one that differs; both routines that take a clock translate it.
        ClockGettime(),
        PthreadSigmask(),
        Fcntl(),

        // Thread attributes are held as a setting in the four bytes the caller reserved, never as
        // something belonging to the platform, which needs eight and would write past them.
        AttrStart("pthread_condattr_init", AttrStartingClock),
        AttrKeep("pthread_condattr_setclock"),
        Zero("pthread_condattr_destroy"),
        CondInit(),
        AttrStart("pthread_mutexattr_init", AttrStartingKind),
        AttrKeep("pthread_mutexattr_settype"),
        Zero("pthread_mutexattr_destroy"),
        MutexInit(),

        // Mapped to a device entry, or refused where there is no counterpart.
        SetErrno(),
        ErrnoLocation(),
        StrError(),
        StrErrorR(),
        // Naming a thread. Two names reach the same work here, and only one of them answers the way
        // the runtime was built to read: the one this forwards to hands back nought or a plain error
        // number, while the other wraps that number into a code of its own, so a caller testing for a
        // thread that is gone compares against a number it never sees.
        Forward("pthread_setname_np", "pthread_rename_np"),
        // Reading a thread's own attributes. The device publishes the same call under the name the
        // system it descends from uses, and the arguments and the result line up - a thread handle
        // first, a place to put the attributes second, zero or an error number back - so both pass
        // straight through. Refusing instead left the attributes at the defaults that were put there
        // before the call, so the caller read the template's stack address and size rather than the
        // running thread's, and every later check against those bounds asked about the wrong range.
        //
        // Two things about the platform's version are worth writing down, because they are not true of
        // the one the runtime was built against. It refuses a place that has not already been made
        // ready, answering "not valid" rather than filling it in, and what it fills in it also
        // allocates, which only the matching release call frees. The runtime happens to do both -
        // it makes the place ready, reads, takes the stack out of it, and releases - so this holds
        // today; a caller that skipped either step would get nothing and leak on every call.
        Forward("pthread_getattr_np", "pthread_attr_get_np"),
        ClockNanosleep(),
        Forward("pipe2", "pipe"),                   // the extra flags argument is dropped
        Refuse("statfs64"),
        RefuseWide("__getdelim"),                   // a count, so the whole register has to say -1

        // Realtime-signal bounds the runtime asks for when it picks a signal.
        Value("__libc_current_sigrtmin", 65),
        Value("__libc_current_sigrtmax", 126),

        // Weak no-ops the toolchain overrides: the SDK supplies its own start object and no profiler.
        WeakZero("__libc_start_main"),
        WeakZero("__gmon_start__"),
        WeakZero("_ITM_registerTMCloneTable"),
        WeakZero("_ITM_deregisterTMCloneTable"),

        // Fixed results an application module accepts.
        Refuse("fork"),                             // a module does not fork
        Zero("isatty"),                             // not a terminal
        Value("getpwuid_r", 2),                     // no such user
        DlIteratePhdr(),
        DlAddr(),
        Zero("gai_strerror"),                       // no message
        Refuse("sysinfo"),
        Zero("prctl"),                              // process controls are no-ops
        SysCall(),                                  // one of the numbers asked for does exist here
        MAdvise(),                                  // the hints are numbered differently past the fifth
        PthreadCondTimedWait(),                     // the answer is by value, so it needs its own translation
        Futimens(),                                 // the finer pair is not published; the older one is
        Utimensat(),
        // Which processor this thread is on. The platform publishes exactly that question.
        Forward("sched_getcpu", "sceKernelGetCurrentCpu"),
        SchedGetAffinity(),
        SchedSetAffinity(),
        SchedCpuCount(),

        // Further large-file variants that forward to a base name the device publishes.
        Forward("ftruncate64", "ftruncate"),
        Forward("pwrite64", "pwrite"),
        Forward("pwritev64", "pwritev"),
        Forward("preadv64", "preadv"),
        Forward("setrlimit64", "setrlimit"),
        StatThunk("__lxstat64", "lstat", byFd: false),

        // Advisory or best-effort calls that succeed as no-ops, and lookups with no counterpart.
        Zero("posix_fadvise64"),                    // advice is optional
        Zero("getauxval"),                          // no auxiliary value
        RefuseNull("mkdtemp"),                      // no temporary directory, and it says why
        Value("getgrgid_r", 2),                     // no such group
        Value("getpwnam_r", 2),                     // no such user

        // Calls an application module has no counterpart for; refused so the caller falls back.
        Refuse("__xmknod"),
        Refuse("fallocate64"),
        Refuse("fstatfs64"),
        Refuse("getgrouplist"),
        Refuse("inotify_add_watch"),
        Refuse("inotify_init1"),
        Refuse("inotify_rm_watch"),
        Refuse("link"),
        Refuse("symlink"),
        RefuseWide("readlink"),                     // a count, declared as a machine word
        Refuse("mkfifo"),
        Refuse("mkstemps64"),
        RefuseWide("pathconf"),                     // a limit, declared as a machine word
        RefuseWide("sendfile64"),                   // a count, declared as a machine word
        Refuse("setgid"),
        Refuse("uname"),
        Refuse("vfork"),                            // a module does not fork
        Refuse("waitid"),

        // System queries the platform does not offer an application module. The bindings for these
        // exist because the query is a reasonable thing to want, but nothing publishes an entry point
        // for them, so each reports failure rather than binding to nothing.

        // Taking a compute queue directly from the graphics driver. The toolchain offers both of these
        // and the module that would answer them carries neither, which is a difference worth being
        // careful about: an import of a name the module does not carry cannot bind, and a module whose
        // imports do not all bind never reaches its first instruction - so naming them would cost far
        // more than the two calls are worth. Refused here instead, which the caller already handles by
        // going without a compute queue.
        Refuse("sceAgcDriverAcquireComputeQueue"),
        Refuse("sceAgcDriverReleaseComputeQueue"),

        // Entry points no module publishes. The runtime archives reach them from paths an application
        // module does not take - starting other processes, reading a terminal, handling signals the
        // platform owns - so each reports the failure its caller already handles rather than being left
        // as an import nothing can bind.
        SysConf(),
        Refuse("access"),
        Refuse("chdir"),
        Refuse("dup2"),
        Refuse("execv"),                            // a module does not start another program
        GetRlimit(),
        Refuse("getrusage"),
        Refuse("ioctl"),
        // Asking about a name without following a link where it leads. The toolchain publishes no such
        // call, and refusing it failed every check of whether a file exists, because the large-file
        // variant below is what those checks reach and it forwards here. The call that does follow a
        // link is published and answers the same question about the same name; the two differ only
        // where a name is a link, and the difference is worth far less than the answer.
        Forward("lstat", "stat"),
        Refuse("pipe"),
        Refuse("poll"),
        Zero("setrlimit"),                          // no limit to change; succeed as a no-op
        Refuse("shm_open"),
        Refuse("shm_unlink"),
        // waitpid is left unresolved here so the load-time cascade can bind it to the kernel
        // library that publishes it (handle 0x2001). Defining a local refusal instead hid the
        // export behind an errno-forty-five stub, and every ptrace-based unjail path folded
        // into a "child did not stop" failure the moment the payload waited on a stopped child.
        // The device publishes the counterparts that change protection and release memory, but not the
        // one that takes it: no library the toolchain links against carries that name, so a module has
        // to bring its own. The protection change is defined here too, because the two have to agree -
        // this one hands back address space with no memory behind it, so the change that grants access
        // is what takes the memory.
        Mmap(),
        MProtect(),
        // Keeping a page resident. The collector asks for this on one page it then changes protection
        // on twice, so that the change is seen by every processor; the lock is there only to keep that
        // page from being paged out in between, and nothing afterwards depends on it having happened.
        // The call it would otherwise reach is a bare system call the kernel guards with a privilege
        // an application is not given, and refuses outright when a limit it never raises is exceeded -
        // and the collector treats a refusal as fatal, so a hint it can do without would stop the
        // runtime from starting. Of every module that launches on this platform, not one asks for it.
        Zero("mlock"),
        Zero("munlock"),
        // Installing a signal handler reports success and changes nothing. **This must not be made to
        // fail.** Of the 119 libraries the toolchain lets an application link, not one publishes any
        // real signal call, so this object has to define the name and there is no better body for it -
        // and the caller treats a refusal as fatal: it gives up on installing its handlers, which makes
        // the platform layer refuse, which makes the runtime refuse, which is the module reaching its
        // entry and reporting a non-zero result with nothing said anywhere. Reporting success leaves
        // the runtime's hardware-exception path inert, which costs nothing until something faults.
        Zero("sigaction"),
        SigEmptySet(),
        SigFillSet(),
        SigAddSet(),
        Zero("signal"),                             // the previous handler, which is the default one
        // Sending a signal to a process. Nothing published delivers one, and the shape of the refusal
        // matters: this answers -1 and leaves the reason behind it, so a caller testing the result for
        // a negative number reads a refusal as a refusal. Answering the reason itself, the way the
        // thread-directed call below does, would read as a success to that same test.
        Refuse("kill"),
        // Sending a signal to a thread. Nothing published delivers one, so the collector's way of
        // interrupting a thread to take control of it cannot work whatever this answers. It answers
        // "there is no such thread", which is the one refusal the caller already has a path for: it
        // leaves the thread unmarked, where reporting success leaves it marked as interrupted for ever
        // and the collector waits on something that will never happen.
        Value("pthread_kill", NoSuchThread),
        GcLog(),
        // Directory streams, which nothing published offers, built on the call underneath them.
        OpenDir(),
        ReadDir(),
        CloseDir(),
        // Nothing found, reported the way each caller expects. Asking for a name that is not set is
        // an ordinary answer rather than a failure, and the ones that load code report why through a
        // call of their own, so those four answer nothing and leave the number alone. Resolving a
        // path is a failure when it answers nothing, so that one says why.
        //
        // The four that load code go together. Nothing in the toolchain declares or publishes any of
        // them, so all four have to be defined here or none of the five entry points the runtime
        // builds on them can be linked at all - and three of those five are reached by asking for the
        // module's own path or its identifier, which an ordinary application does. Releasing what was
        // loaded succeeds because nothing was ever handed out to release, and asking why the load
        // failed answers nothing, which is what that call answers when there is nothing to say and
        // therefore what every caller of it already handles.
        Zero("dlopen"),
        Zero("dlsym"),
        Zero("dlclose"),
        Zero("dlerror"),
        Zero("getenv"),
        RefuseNull("realpath"),
    ];

    /// <summary>The functions this object defines for a given target. Payload builds substitute the
    /// three per-thread-storage bodies for pthread-key variants (which the payload loader can honour;
    /// a local-exec TLS load cannot be applied by a base-relative-only fix-up pass) and append the
    /// pthread_create wrapper plus its trampoline so every thread the runtime creates carries the
    /// same stack-canary and pointer-guard seed the initial thread does.</summary>
    private static IReadOnlyList<CompatFunc> BuildFunctions(bool payload)
    {
        if (!payload)
            return Functions;
        // Substitute the three TLS bodies and the getenv zero-stub, then append the pthread-key
        // helpers plus the pthread_create wrapper and its trampoline. The names are what the linker
        // resolves against, so the swap is symmetric: the payload build sees exactly one definition
        // of readdir64, __errno_location, __sp_set_errno and getenv, each with a body suited to the
        // payload environment where no libc import is available.
        var swapped = new List<CompatFunc>(Functions.Count + 5);
        foreach (CompatFunc f in Functions)
        {
            swapped.Add(f.Name switch
            {
                "readdir64" => Readdir64Payload(),
                "__errno_location" => ErrnoLocationPayload(),
                SetErrnoSymbol => SetErrnoPayload(),
                "getenv" => GetenvPayload(),
                "mmap" => MmapPayload(),
                "mprotect" => MProtectPayload(),
                _ => f,
            });
        }
        // The pthread_create wrapper has to arrive last: on the standalone side pthread_create is
        // imported from libkernel_web directly, so nothing in Functions defines it. The wrapper
        // shadows that import - the linker binds every pthread_create reference in the compiled
        // module to this definition instead - and its trampoline is what runs on each new thread.
        swapped.Add(ThreadBlockKeyInit());
        swapped.Add(ThreadBlockAccessor());
        swapped.Add(PthreadCreateWrapper());
        swapped.Add(ThreadTrampoline());
        return swapped;
    }

    /// <summary>
    /// The data objects this object defines: a pointer each, either left null or pointing at a name the
    /// C module publishes. The runtime reads these as variables rather than calling them.
    /// </summary>
    private static IReadOnlyList<CompatData> DataObjects =>
    [
        // The standard streams are published under their own names; the variables hold their addresses.
        new("stdin", "__stdinp"),
        new("stdout", "__stdoutp"),
        new("stderr", "__stderrp"),
        // A module is started with no environment, so the list is empty.
        new("environ", null),
        // The marker the C module publishes to record that a module was linked against it. It carries
        // no behaviour; holding its address is what puts the name in the import table, which is what a
        // module built against the same library carries.
        new("__sce_libc_marker", LibcMarkerName),
    ];

    /// <summary>
    /// The names this object defines. A link resolves an imported name through the stub catalog first
    /// and falls back to these, so between them they have to cover everything the compiled image
    /// reaches.
    /// </summary>
    public static IReadOnlyList<string> DefinedNames =>
        [.. Functions.Select(f => f.Name), .. DataObjects.Select(d => d.Name)];

    /// <summary>
    /// Builds the compat object bytes for the kind of module being linked. The kind settles how the
    /// object reaches its own per-thread storage, which is the one thing it cannot do the same way in
    /// both: an application knows the distance from the thread pointer when it is linked, a library
    /// does not. When the object is destined for a payload rather than a standalone module the C
    /// library marker is omitted: the marker names an imported symbol nothing on the target publishes
    /// under that name, and the payload writer has no dependency table to feed it into anyway.
    /// </summary>
    public static byte[] BuildObject(ModuleKind kind = ModuleKind.Executable, bool payload = false)
    {
        IReadOnlyList<CompatFunc> funcs = BuildFunctions(payload);
        bool library = kind == ModuleKind.Library;

        // Lay out .text: each function on a 16-byte boundary. Record each function's offset.
        var text = new List<byte>();
        var textOffsets = new int[funcs.Count];
        for (int i = 0; i < funcs.Count; i++)
        {
            while (text.Count % 16 != 0)
                text.Add(0x90);   // nop padding
            textOffsets[i] = text.Count;
            text.AddRange(funcs[i].Code);
            // A library asks the helper where its block ended up rather than adding a distance settled
            // here. The two forms are the same length, so this replaces the one written into the code
            // above and nothing after it moves.
            if (library && funcs[i].Tls is var (site, register, _))
                for (int b = 0; b < TlsLoadSize; b++)
                    text[textOffsets[i] + site + b] = TlsLoadThroughHelper(register)[b];
        }
        byte[] textBytes = [.. text];

        // The variables: one pointer each, in declaration order, then the module name dladdr reports,
        // then the error numbering, which is read like any other constant. A payload leaves out the
        // C-library marker: nothing on the target publishes a symbol under the marker's name, so a
        // payload that carried it would end its start-up on a null resolver slot the first time
        // something reached for the marker's address.
        IReadOnlyList<CompatData> data = payload
            ? [.. DataObjects.Where(d => d.Name != "__sce_libc_marker")]
            : DataObjects;
        int moduleNameOffset = data.Count * 8;
        int errorTableOffset = moduleNameOffset + ModuleNameText.Length;
        int clockTableOffset = errorTableOffset + ErrorTableSize;
        int fcntlTableOffset = clockTableOffset + ClockTableSize;
        int adviceTableOffset = fcntlTableOffset + FcntlTableSize;
        int reverseErrorTableOffset = adviceTableOffset + AdviceTableSize;
        // A payload build tacks the pthread-key slot, its init-state guard, and the baked-in
        // environment table onto the end of .data. The key slot and state start at zero; the shared
        // init routine writes the slot from pthread_key_create's out pointer, and the state word
        // walks 0 -> 1 (in-progress) -> 2 (ready) as it does. The environment table holds the
        // NUL-separated KEY=VALUE entries that getenv searches. Placing them all in .data rather
        // than a fresh .bss keeps the section count stable at nine.
        int keySlotOffset = -1, keyStateOffset = -1, envTableOffset = -1, dataLength;
        byte[]? envTableBytes = null;
        if (payload)
        {
            keySlotOffset = (reverseErrorTableOffset + ErrorTableSize + 3) & ~3;   // align 4
            keyStateOffset = keySlotOffset + 4;
            envTableBytes = BuildEnvTable();
            envTableOffset = keyStateOffset + 4;
            dataLength = envTableOffset + envTableBytes.Length;
        }
        else
        {
            dataLength = reverseErrorTableOffset + ErrorTableSize;
        }
        byte[] dataBytes = new byte[dataLength];
        ModuleNameText.CopyTo(dataBytes, moduleNameOffset);
        BuildErrorTable().CopyTo(dataBytes, errorTableOffset);
        BuildClockTable().CopyTo(dataBytes, clockTableOffset);
        BuildFcntlTable().CopyTo(dataBytes, fcntlTableOffset);
        BuildAdviceTable().CopyTo(dataBytes, adviceTableOffset);
        BuildReverseErrorTable().CopyTo(dataBytes, reverseErrorTableOffset);
        if (envTableBytes is not null)
            envTableBytes.CopyTo(dataBytes, envTableOffset);

        // Section header indices.
        const int shText = 1, shTbss = 2, shRela = 3, shData = 4, shRelaData = 5, shSym = 6, shStr = 7, shShStr = 8;
        const int sectionCount = 9;

        // Symbols: the local symbols come first (ELF requires it) — [0] null, [1] the thread-local buffer
        // readdir64 translates into, and [2] the module name — then every defined function, then every
        // external target. sh_info is the count of leading locals.
        var strtab = new StringTable();
        var symIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        var symbols = new List<(int NameOff, byte Info, int Shndx, ulong Value, ulong Size, byte Other)>
        {
            (0, 0, 0, 0, 0, 0),                                                                       // [0] null
            (strtab.Add(ReaddirBufSymbol), (BindLocal << 4) | TypeTls, shTbss, 0, ReaddirBufSize, 0), // [1] tls buffer
            (strtab.Add(ErrnoShadowSymbol), (BindLocal << 4) | TypeTls, shTbss,                    // [2] error number
                ErrnoShadowOffset, ErrnoShadowSize, 0),
            (strtab.Add(ModuleNameSymbol), (BindLocal << 4) | TypeObject, shData,                  // [3] module name
                (ulong)moduleNameOffset, (ulong)ModuleNameText.Length, 0),
            (strtab.Add(ErrorTableSymbol), (BindLocal << 4) | TypeObject, shData,                  // [4] the numbering
                (ulong)errorTableOffset, ErrorTableSize, 0),
            (strtab.Add(ClockTableSymbol), (BindLocal << 4) | TypeObject, shData,                  // [5] the clocks
                (ulong)clockTableOffset, ClockTableSize, 0),
            (strtab.Add(FcntlTableSymbol), (BindLocal << 4) | TypeObject, shData,                  // [6] the commands
                (ulong)fcntlTableOffset, FcntlTableSize, 0),
            (strtab.Add(AdviceTableSymbol), (BindLocal << 4) | TypeObject, shData,                 // [7] the hints
                (ulong)adviceTableOffset, AdviceTableSize, 0),
            (strtab.Add(ReverseErrorTableSymbol), (BindLocal << 4) | TypeObject, shData,           // [8] read back
                (ulong)reverseErrorTableOffset, ErrorTableSize, 0),
        };
        symIndex[ReaddirBufSymbol] = 1;
        symIndex[ErrnoShadowSymbol] = 2;
        symIndex[ModuleNameSymbol] = 3;
        symIndex[ErrorTableSymbol] = 4;
        symIndex[ClockTableSymbol] = 5;
        symIndex[FcntlTableSymbol] = 6;
        symIndex[AdviceTableSymbol] = 7;
        symIndex[ReverseErrorTableSymbol] = 8;

        // Payload-only locals: the four-byte pthread_key_t slot, the four-byte init-state guard
        // used by the shared accessor, and the baked-in environment table that getenv searches.
        // All three live at the tail of .data so their positions are known once the tables above
        // are laid down. Local symbols must precede globals in the symbol table (an ELF invariant),
        // so they are added here before the function symbols below.
        if (payload)
        {
            symIndex[PayloadKeySlotSymbol] = symbols.Count;
            symbols.Add((strtab.Add(PayloadKeySlotSymbol), (BindLocal << 4) | TypeObject, shData,
                (ulong)keySlotOffset, 4, 0));
            symIndex[PayloadKeyStateSymbol] = symbols.Count;
            symbols.Add((strtab.Add(PayloadKeyStateSymbol), (BindLocal << 4) | TypeObject, shData,
                (ulong)keyStateOffset, 4, 0));
            symIndex[EnvTableSymbol] = symbols.Count;
            symbols.Add((strtab.Add(EnvTableSymbol), (BindLocal << 4) | TypeObject, shData,
                (ulong)envTableOffset, (ulong)envTableBytes!.Length, 0));
        }
        int LocalSymbolCount = payload ? 12 : 9;

        for (int i = 0; i < funcs.Count; i++)
        {
            CompatFunc f = funcs[i];
            byte bind = f.Weak ? BindWeak : BindGlobal;
            symIndex[f.Name] = symbols.Count;
            symbols.Add((strtab.Add(f.Name), (byte)((bind << 4) | TypeFunc), shText, (ulong)textOffsets[i], (ulong)f.Code.Length, f.Hidden ? (byte)2 : (byte)0));
        }

        for (int i = 0; i < data.Count; i++)
        {
            symIndex[data[i].Name] = symbols.Count;
            symbols.Add((strtab.Add(data[i].Name), (BindGlobal << 4) | TypeObject, shData, (ulong)(i * 8), 8, 0));
        }

        var externals = new List<string>();
        void AddExternal(string target, byte type)
        {
            if (symIndex.ContainsKey(target))
                return;
            symIndex[target] = symbols.Count;
            externals.Add(target);
            symbols.Add((strtab.Add(target), (byte)((BindGlobal << 4) | type), 0, 0, 0, 0));
        }
        foreach (CompatFunc f in funcs)
            foreach ((int _, string target) in f.Relocs)
                AddExternal(target, TypeFunc);
        // The helper a library's address loads call. An application resolves the same loads itself and
        // so names nothing.
        if (library && funcs.Any(f => f.Tls is not null))
            AddExternal(TlsGetAddrSymbol, TypeFunc);
        // A name whose address a variable holds is data, and has to say so: a module that calls it a
        // function invites the loader to bind it the way a function is bound.
        foreach (CompatData d in data)
            if (d.PointsAt is not null)
                AddExternal(d.PointsAt, TypeObject);

        // Relocations: a PLT32 per tail call, plus what each address load of a thread-local needs. An
        // application takes one record for the distance it adds to the thread pointer; a library takes
        // two, one naming the pair of table slots and one for the call to the helper that reads them.
        var relocs = new List<(int Offset, int Symbol, uint Type, long Addend)>();
        for (int i = 0; i < funcs.Count; i++)
        {
            foreach ((int off, string target) in funcs[i].Relocs)
                relocs.Add((textOffsets[i] + off, symIndex[target], RPlt32, -4));
            if (funcs[i].Tls is not var (tlsSite, _, tlsName))
                continue;
            if (library)
            {
                relocs.Add((textOffsets[i] + tlsSite + 4, symIndex[tlsName], RTlsGd, -4));
                relocs.Add((textOffsets[i] + tlsSite + 12, symIndex[TlsGetAddrSymbol], RPlt32, -4));
            }
            else
            {
                relocs.Add((textOffsets[i] + tlsSite + TlsLoadDisp, symIndex[tlsName], RTpOff32, 0));
            }
        }

        // A variable holding an address needs a load-time fixup, the same as any other absolute
        // reference; one left empty needs none.
        var dataRelocs = new List<(int Offset, int Symbol, uint Type, long Addend)>();
        for (int i = 0; i < data.Count; i++)
            if (data[i].PointsAt is string target)
                dataRelocs.Add((i * 8, symIndex[target], RAbs64, 0));

        byte[] strtabBytes = strtab.ToBytes();

        byte[] symtab = new byte[24 * symbols.Count];
        for (int i = 0; i < symbols.Count; i++)
            WriteSym(symtab, i, symbols[i].NameOff, symbols[i].Info, symbols[i].Other, symbols[i].Shndx, symbols[i].Value, symbols[i].Size);

        byte[] rela = new byte[24 * relocs.Count];
        for (int i = 0; i < relocs.Count; i++)
            WriteRela(rela, i, relocs[i].Offset, relocs[i].Symbol, relocs[i].Type, relocs[i].Addend);

        byte[] relaData = new byte[24 * dataRelocs.Count];
        for (int i = 0; i < dataRelocs.Count; i++)
            WriteRela(relaData, i, dataRelocs[i].Offset, dataRelocs[i].Symbol, dataRelocs[i].Type, dataRelocs[i].Addend);

        var shstr = new StringTable();
        int nText = shstr.Add(".text");
        int nTbss = shstr.Add(".tbss");
        int nRela = shstr.Add(".rela.text");
        int nData = shstr.Add(".data");
        int nRelaData = shstr.Add(".rela.data");
        int nSym = shstr.Add(".symtab");
        int nStr = shstr.Add(".strtab");
        int nShStr = shstr.Add(".shstrtab");
        byte[] shstrBytes = shstr.ToBytes();

        var body = new List<byte>();
        long textOff = Place(body, textBytes);
        long relaOff = Place(body, rela);
        long dataOff = Place(body, dataBytes);
        long relaDataOff = Place(body, relaData);
        long symOff = Place(body, symtab);
        long strOff = Place(body, strtabBytes);
        long shstrOff = Place(body, shstrBytes);
        Align(body, 8);
        // A no-bits section carries no file data; its offset just marks where it would sit.
        long tbssOff = 64 + body.Count;
        long shdrOff = 64 + body.Count;

        byte[] shdr = new byte[64 * sectionCount];
        WriteShdr(shdr, shText, nText, ShtProgBits, ShfAlloc | ShfExec, textOff, textBytes.Length, 0, 0, 16, 0);
        WriteShdr(shdr, shTbss, nTbss, ShtNoBits, ShfWrite | ShfAlloc | ShfTls, tbssOff, ThreadBlockSize, 0, 0, 8, 0);
        WriteShdr(shdr, shRela, nRela, ShtRela, 0, relaOff, rela.Length, shSym, shText, 8, 24);
        WriteShdr(shdr, shData, nData, ShtProgBits, ShfAlloc | ShfWrite, dataOff, dataBytes.Length, 0, 0, 8, 0);
        WriteShdr(shdr, shRelaData, nRelaData, ShtRela, 0, relaDataOff, relaData.Length, shSym, shData, 8, 24);
        WriteShdr(shdr, shSym, nSym, ShtSymTab, 0, symOff, symtab.Length, shStr, LocalSymbolCount, 8, 24);
        WriteShdr(shdr, shStr, nStr, ShtStrTab, 0, strOff, strtabBytes.Length, 0, 0, 1, 0);
        WriteShdr(shdr, shShStr, nShStr, ShtStrTab, 0, shstrOff, shstrBytes.Length, 0, 0, 1, 0);

        var output = new List<byte>(64 + body.Count + shdr.Length);
        output.AddRange(BuildHeader(shdrOff, shShStr, sectionCount));
        output.AddRange(body);
        output.AddRange(shdr);
        return [.. output];
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
        while ((64 + body.Count) % alignment != 0)
            body.Add(0);
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

    private static void WriteSym(byte[] table, int index, int nameOff, byte info, byte other, int sectionIndex, ulong value, ulong size)
    {
        int b = index * 24;
        BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(b), (uint)nameOff);
        table[b + 4] = info;
        table[b + 5] = other;
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
        BinaryPrimitives.WriteUInt64LittleEndian(shdr.AsSpan(b + 16), 0);
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
            if (_off.TryGetValue(value, out int existing))
                return existing;
            int offset = _bytes.Count;
            _bytes.AddRange(Encoding.ASCII.GetBytes(value));
            _bytes.Add(0);
            _off[value] = offset;
            return offset;
        }

        public byte[] ToBytes() => [.. _bytes];
    }
}
