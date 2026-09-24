// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// The system software version, as the kernel reports it. The caller sets <see cref="Size"/> to the
/// size of this block; the kernel fills the printable string and the packed value.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceKernelSwVersion
{
    /// <summary>The size of this block, in bytes. Set before the call.</summary>
    public ulong Size;

    /// <summary>The version as text, for example "11.020.000". NUL-terminated ASCII.</summary>
    public fixed byte VersionString[28];

    /// <summary>
    /// The version packed into a word: the major byte, the minor byte, then the rest. The high half
    /// carries the major and minor a requirement compares against.
    /// </summary>
    public uint Version;
}

/// <summary>Kernel queries about the system itself.</summary>
public static unsafe partial class KernelSystem
{
    private const string Lib = "libkernel";

    // The library the console identifier is published under, which is not the one above.
    private const string OpenPsIdLib = "libSceOpenPsId";

    /// <summary>
    /// Reads the system software version. Set <see cref="SceKernelSwVersion.Size"/> to the block size
    /// first. Zero on success, or a negative error code.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetProsperoSystemSwVersion(SceKernelSwVersion* version);

    /// <summary>
    /// Reads the highest SDK version the system will accept a module built against, into
    /// <paramref name="version"/>. The value is packed like a module's own requirement (the major and
    /// minor in the high half); the low bits are set to the maximum patch. A module built against more
    /// than this is rejected at load, so this is the ceiling a build can safely target for the running
    /// system. Zero on success, or a negative error code; <paramref name="version"/> must not be null.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetAllowedSdkVersionOnSystem(uint* version);

    /// <summary>
    /// Reads the console's 16-byte open identifier into <paramref name="openId"/>. Zero on success.
    /// </summary>
    /// <remarks>
    /// The same module carries this one, but publishes it under a library of its own rather than the
    /// one every other call here belongs to, so it is asked for by that name. Naming the usual library
    /// asks for something nothing publishes, and a module whose imports do not all bind never reaches
    /// its first instruction.
    /// </remarks>
    [LibraryImport(OpenPsIdLib)]
    public static partial int sceKernelGetOpenPsId(byte* openId);

    /// <summary>
    /// Reads a system value identified by a numeric MIB (management information base) path into
    /// <paramref name="oldp"/>. <paramref name="name"/> is an array of <paramref name="namelen"/>
    /// integers that address the value in the tree. Returns -1 and sets errno on failure. The size in
    /// and out is <paramref name="oldlenp"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sysctl(int* name, uint namelen, void* oldp, nuint* oldlenp, void* newp, nuint newlen);

    /// <summary>
    /// Reads a system value named by a dotted string (for example <c>hw.ncpu</c>) into
    /// <paramref name="oldp"/>. This is the libc-style call: it returns -1 and sets errno on failure,
    /// unlike the sce* calls. The size in and out is <paramref name="oldlenp"/>.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sysctlbyname(string name, void* oldp, nuint* oldlenp, void* newp, nuint newlen);

    /// <summary>
    /// Returns the address of the calling thread's error number. The libc-style calls report failure
    /// with -1 and leave the reason here, so a caller reads it immediately after the call it belongs to
    /// and before anything else on the same thread can overwrite it.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int* __error();

    /// <summary>
    /// Drives the debug output pins: the low bits of <paramref name="bits"/> reach the general-purpose
    /// output on a devkit and are ignored elsewhere.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial void sceKernelSetGPO(uint bits);

    /// <summary>Reads the debug input pins.</summary>
    [LibraryImport(Lib)]
    public static partial ulong sceKernelGetGPI();
}

/// <summary>Which thread the process stopped on, and why.</summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SceCoredumpStopInfoCpu
{
    /// <summary>The thread handle. <c>-1</c> means no thread; <c>-2</c> means the dump was asked for.</summary>
    public nint Thread;

    public int ReasonCode;
    private int _pad0;
}

/// <summary>When the graphics side stopped.</summary>
[StructLayout(LayoutKind.Sequential, Size = 8)]
public struct SceCoredumpStopInfoGpu
{
    public ulong Timestamp;
}

/// <summary>The register file of the thread the process stopped on.</summary>
[StructLayout(LayoutKind.Sequential, Size = 144)]
public struct SceCoredumpThreadContextInfo
{
    public ulong Rdi;
    public ulong Rsi;
    public ulong Rdx;
    public ulong Rcx;
    public ulong R8;
    public ulong R9;
    public ulong Rax;
    public ulong Rbx;
    public ulong Rbp;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;
    public ulong Rip;
    public ulong Rflags;
    public ulong Rsp;
}

/// <summary>
/// Crash-report bindings. The application registers one handler; the system runs it on its own thread
/// after the process stops, and everything the handler attaches or writes lands in the report alongside
/// the register state. The attach, write and read calls belong inside the handler, and the service has
/// an error code of its own for reaching them from anywhere else.
/// </summary>
/// <remarks>
/// The same module carries these as the kernel calls above, but publishes them under a library of their
/// own, so they are asked for by that name. Naming the usual library asks for something nothing
/// publishes, and a module whose imports do not all bind never reaches its first instruction.
/// </remarks>
public static unsafe partial class KernelCoredump
{
    private const string Lib = "libSceCoredump";

    /// <summary>Attach the region but cut it short rather than fail when it exceeds the report limit.</summary>
    public const uint UserFileTruncateIfExceedLimit = 0x80000000;

    /// <summary>Cut from the end rather than the start when truncating.</summary>
    public const uint UserFileTruncateFromEnd = 0x40000000;

    /// <summary>Write every mapped page into the report rather than the default subset.</summary>
    public const uint ConfigModeFull = 1;

    /// <summary>The thread handle reported when no thread was responsible.</summary>
    public static readonly nint ThreadNotApplicable = -1;

    /// <summary>The thread handle reported when the dump was asked for rather than caused by a fault.</summary>
    public static readonly nint ThreadTriggered = -2;

    /// <summary>
    /// Installs <paramref name="handler"/> as the crash handler and gives it a stack of
    /// <paramref name="stackSize"/> bytes; <paramref name="pCommon"/> is handed back to it unchanged. The
    /// system creates the handler thread here, so the stack size is checked at registration rather than
    /// at crash time: 16 KiB is the floor and 512 MiB the ceiling, and a size outside that is refused.
    /// Only one handler may be installed at a time.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpRegisterCoredumpHandler(
        delegate* unmanaged[Cdecl]<void*, int> handler, nuint stackSize, void* pCommon);

    /// <summary>Removes the installed handler.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpUnregisterCoredumpHandler();

    /// <summary>
    /// Streams <paramref name="size"/> bytes into the report. Repeated calls append, which makes this the
    /// route for a log the application kept in memory.
    /// </summary>
    /// <returns>The bytes written, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial nint sceCoredumpWriteUserData(void* data, nuint size);

    /// <summary>Writes <paramref name="len"/> bytes of <paramref name="str"/> into the report as text.</summary>
    [LibraryImport(Lib)]
    public static partial void sceCoredumpDebugTextOut(byte* str, int len);

    /// <summary>
    /// Attaches the file at <paramref name="path"/> to the report under the tag
    /// <paramref name="userValue"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpAttachUserFile(uint userValue, byte* path);

    /// <summary>Attaches <paramref name="size"/> bytes at <paramref name="mem"/> as a file called <paramref name="name"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpAttachMemoryRegionAsUserFile(uint userValue, void* mem, nuint size, byte* name);

    /// <summary>Attaches <paramref name="size"/> bytes at <paramref name="mem"/> to the report.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpAttachMemoryRegion(uint userValue, void* mem, nuint size);

    /// <summary>Attaches <paramref name="size"/> bytes at <paramref name="mem"/> as an unnamed file.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpAttachUserMemoryFile(uint userValue, void* mem, nuint size);

    /// <summary>Chooses how much of the process the report covers.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpConfigDumpMode(uint mode);

    /// <summary>Reads which thread stopped. <paramref name="size"/> is the size of the block.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpGetStopInfoCpu(SceCoredumpStopInfoCpu* info, nuint size);

    /// <summary>Reads when the graphics side stopped. <paramref name="size"/> is the size of the block.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpGetStopInfoGpu(SceCoredumpStopInfoGpu* info, nuint size);

    /// <summary>Reads the stopped thread's registers.</summary>
    [LibraryImport(Lib)]
    public static partial int sceCoredumpGetThreadContextInfo(
        SceCoredumpThreadContextInfo* threadContextInfo, nuint threadContextInfoSize);
}
