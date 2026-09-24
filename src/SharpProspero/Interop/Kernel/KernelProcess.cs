// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// A 128-bit identifier in its field form: the fields are stored in the order below, each in the
/// processor's own byte order, which is not the order the printed form reads in.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceKernelUuid
{
    /// <summary>The low field of the timestamp.</summary>
    public uint TimeLow;

    /// <summary>The middle field of the timestamp.</summary>
    public ushort TimeMid;

    /// <summary>The high field of the timestamp with the version in its top four bits.</summary>
    public ushort TimeHighAndVersion;

    /// <summary>The high field of the sequence with the variant in its top bits.</summary>
    public byte ClockSequenceHighAndReserved;

    /// <summary>The low field of the sequence.</summary>
    public byte ClockSequenceLow;

    /// <summary>The six-byte node field.</summary>
    public fixed byte Node[6];
}

/// <summary>
/// Process-level bindings: what the process is, what it was started with, and the sizes the system
/// imposes on it.
/// </summary>
public static unsafe partial class KernelProcess
{
    private const string Lib = "libkernel";

    /// <summary>The process identifier.</summary>
    [LibraryImport(Lib)]
    public static partial int getpid();

    /// <summary>
    /// Sends signal <paramref name="signal"/> to process <paramref name="pid"/>. A pid of zero
    /// sends the signal to every process in the calling process's own group. The signal number
    /// follows the FreeBSD numbering the kernel uses (SIGKILL is 9).
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int kill(int pid, int signal);

    /// <summary>SIGKILL: an uncatchable signal that ends the receiving process immediately.</summary>
    public const int SIGKILL = 9;

    /// <summary>
    /// The size of a memory page, which is also the alignment a mapping is made on. Matches
    /// <see cref="KernelMemory.PageSize"/>; read it here when the running system is the authority
    /// rather than the build.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int getpagesize();

    /// <summary>
    /// How many file descriptors the process may hold open at once. A build that opens many files at
    /// once reads this before it decides how many to keep.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int getdtablesize();

    /// <summary>How many arguments the process was started with.</summary>
    [LibraryImport(Lib)]
    public static partial int getargc();

    /// <summary>
    /// The arguments the process was started with: an array of <see cref="getargc"/> pointers to
    /// null-terminated UTF-8 strings.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial byte** getargv();

    /// <summary>
    /// Fills <paramref name="uuid"/> with a fresh identifier. The system draws it, so two processes
    /// never produce the same one.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelUuidCreate(SceKernelUuid* uuid);

    /// <summary>
    /// Queries application information for the process with the given <paramref name="pid"/>.
    /// </summary>
    /// <param name="pid">The process identifier.</param>
    /// <param name="info">On success, receives the application information.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetAppInfo(int pid, SceKernelAppInfo* info);
}

/// <summary>
/// Application information for a running process, as returned by
/// <see cref="KernelProcess.sceKernelGetAppInfo"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceKernelAppInfo
{
    /// <summary>The application id assigned by the system.</summary>
    public uint AppId;

    /// <summary>An undocumented eight-byte field following the app id.</summary>
    public ulong Unknown1;

    /// <summary>The application type code.</summary>
    public uint AppType;

    /// <summary>The title identifier, a ten-character ASCII string (e.g. "PPSA01234").</summary>
    public fixed byte TitleId[10];

    /// <summary>Undocumented trailing data.</summary>
    public fixed byte Unknown2[0x3C];
}
