// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// The status of one file, as a status call fills it in.
/// </summary>
/// <remarks>
/// The offsets are the console's own and most of them sit elsewhere in the shape the run time was
/// compiled against: the mode is a 16-bit field eight bytes in and the size a 64-bit field
/// seventy-two bytes in. A field read at any other offset returns an unrelated value, and no call
/// reports that it did. The reservation runs past the last field so a status call cannot write beyond
/// the structure.
/// </remarks>
[StructLayout(LayoutKind.Explicit, Size = 128)]
public struct SceKernelStat
{
    /// <summary>The device the file lives on.</summary>
    [FieldOffset(0)] public uint Device;

    /// <summary>The file serial number within its device.</summary>
    [FieldOffset(4)] public uint Inode;

    /// <summary>The file kind and the permission bits. Mask with <see cref="KernelFile.FileTypeMask"/> for the kind.</summary>
    [FieldOffset(8)] public ushort Mode;

    /// <summary>How many directory entries name this file.</summary>
    [FieldOffset(10)] public ushort LinkCount;

    /// <summary>The owning user.</summary>
    [FieldOffset(12)] public uint UserId;

    /// <summary>The owning group.</summary>
    [FieldOffset(16)] public uint GroupId;

    /// <summary>The device this file is, when it is a device.</summary>
    [FieldOffset(20)] public uint DeviceType;

    /// <summary>Seconds of the last read.</summary>
    [FieldOffset(24)] public long AccessSeconds;

    /// <summary>Nanoseconds of the last read.</summary>
    [FieldOffset(32)] public long AccessNanoseconds;

    /// <summary>Seconds of the last write.</summary>
    [FieldOffset(40)] public long ModifySeconds;

    /// <summary>Nanoseconds of the last write.</summary>
    [FieldOffset(48)] public long ModifyNanoseconds;

    /// <summary>Seconds of the last status change.</summary>
    [FieldOffset(56)] public long ChangeSeconds;

    /// <summary>Nanoseconds of the last status change.</summary>
    [FieldOffset(64)] public long ChangeNanoseconds;

    /// <summary>The file length in bytes.</summary>
    [FieldOffset(72)] public long Size;

    /// <summary>The blocks the file occupies.</summary>
    [FieldOffset(80)] public long Blocks;

    /// <summary>The block size the file system prefers for reads and writes.</summary>
    [FieldOffset(88)] public int BlockSize;

    /// <summary>The user-defined flags on the file.</summary>
    [FieldOffset(92)] public uint Flags;

    /// <summary>The file generation number.</summary>
    [FieldOffset(96)] public uint Generation;

    /// <summary>Seconds of creation.</summary>
    [FieldOffset(104)] public long CreateSeconds;

    /// <summary>Nanoseconds of creation.</summary>
    [FieldOffset(112)] public long CreateNanoseconds;
}

/// <summary>
/// File bindings. A module opens a path with a set of flags, reads or writes at the current offset,
/// seeks, and closes the descriptor. Paths are the mounted package roots, for example
/// <c>/app0/assets/level.bin</c> for a packaged asset. Byte counts and offsets are signed 64-bit.
/// </summary>
public static unsafe partial class KernelFile
{
    private const string Lib = "libkernel";

    /// <summary>Open for reading only.</summary>
    public const int ReadOnly = 0x0000;

    /// <summary>Open for writing only.</summary>
    public const int WriteOnly = 0x0001;

    /// <summary>Open for reading and writing.</summary>
    public const int ReadWrite = 0x0002;

    /// <summary>Append writes to the end of the file.</summary>
    public const int Append = 0x0008;

    /// <summary>Create the file if it does not exist.</summary>
    public const int Create = 0x0200;

    /// <summary>Truncate the file to empty on open.</summary>
    public const int Truncate = 0x0400;

    /// <summary>Fail if the path already exists (with <see cref="Create"/>).</summary>
    public const int Exclusive = 0x0800;

    /// <summary>Fail if the path is not a directory. Required to list a directory.</summary>
    public const int Directory = 0x00020000;

    /// <summary>Do not block; report right away when the read or open would wait.</summary>
    public const int NonBlock = 0x0004;

    /// <summary>Close the descriptor across an exec, so it does not leak into a spawned process.</summary>
    public const int CloseOnExec = 0x00100000;

    /// <summary>
    /// The flag word the platform's own opendir passes to _open when it opens a directory. Any
    /// caller that wants to walk a directory should use this word instead of composing the bits
    /// itself, so the kernel path-resolution layer sees exactly what a system-issued opendir sends.
    /// Equal to <see cref="ReadOnly"/> | <see cref="NonBlock"/> | <see cref="Directory"/>
    /// | <see cref="CloseOnExec"/>, which is <c>0x00120004</c>.
    /// </summary>
    public const int OpenDirectory = ReadOnly | NonBlock | Directory | CloseOnExec;

    /// <summary>Seek relative to the start of the file.</summary>
    public const int SeekSet = 0;

    /// <summary>Seek relative to the current offset.</summary>
    public const int SeekCurrent = 1;

    /// <summary>Seek relative to the end of the file.</summary>
    public const int SeekEnd = 2;

    /// <summary>Opens <paramref name="path"/> (a null-terminated UTF-8 string) with <paramref name="flags"/>.</summary>
    /// <returns>A non-negative descriptor on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelOpen(byte* path, int flags, ushort mode);

    /// <summary>Closes a descriptor.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelClose(int descriptor);

    /// <summary>Reads up to <paramref name="length"/> bytes into <paramref name="buffer"/>.</summary>
    /// <returns>The number of bytes read (zero at end of file), or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial long sceKernelRead(int descriptor, void* buffer, nuint length);

    /// <summary>Writes up to <paramref name="length"/> bytes from <paramref name="buffer"/>.</summary>
    /// <returns>The number of bytes written, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial long sceKernelWrite(int descriptor, void* buffer, nuint length);

    /// <summary>Moves the file offset and returns the new offset, or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial long sceKernelLseek(int descriptor, long offset, int whence);

    /// <summary>
    /// Reads directory entries from a descriptor opened with <see cref="Directory"/> into
    /// <paramref name="buffer"/>, as a packed run of variable-length records.
    /// </summary>
    /// <returns>Bytes written (zero at the end of the directory), or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetdents(int descriptor, byte* buffer, int length);

    /// <summary>
    /// Reads directory entries the same way <see cref="sceKernelGetdents"/> does, and additionally
    /// writes to <paramref name="position"/> the offset within the directory the returned run began at.
    /// </summary>
    /// <param name="descriptor">A descriptor opened with <see cref="Directory"/>.</param>
    /// <param name="buffer">Where the packed run of records is written.</param>
    /// <param name="length">How many bytes <paramref name="buffer"/> can take.</param>
    /// <param name="position">
    /// Receives the directory offset the run started at, so a later seek can resume there. May be null,
    /// in which case this behaves exactly as <see cref="sceKernelGetdents"/>.
    /// </param>
    /// <returns>Bytes written (zero at the end of the directory), or a negative error code.</returns>
    /// <remarks>
    /// This is the form the system's own directory walks use. Both calls reach one routine inside the
    /// kernel; the plain form is a wrapper that passes no position pointer.
    /// </remarks>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetdirentries(int descriptor, byte* buffer, int length, long* position);

    /// <summary>Creates the directory at <paramref name="path"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelMkdir(byte* path, ushort mode);

    /// <summary>Removes the empty directory at <paramref name="path"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelRmdir(byte* path);

    /// <summary>Removes the file at <paramref name="path"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelUnlink(byte* path);

    /// <summary>Renames or moves <paramref name="from"/> to <paramref name="to"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelRename(byte* from, byte* to);

    /// <summary>Sets the length of the file at <paramref name="path"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelTruncate(byte* path, long length);

    /// <summary>Reports whether <paramref name="path"/> can be reached.</summary>
    /// <returns>Zero when it is reachable, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelCheckReachability(byte* path);

    /// <summary>The bits of <see cref="SceKernelStat.Mode"/> that hold the file kind.</summary>
    /// <remarks>
    /// Shifting the masked value down twelve bits gives the same number a directory record carries in
    /// its kind byte, so one mapping serves both.
    /// </remarks>
    public const ushort FileTypeMask = 0xF000;

    // The five below carry the names the module publishes them under. The same module file publishes
    // them in a library of its own rather than in the kernel's, which the link settles from the name;
    // the module named here is the file both libraries come out of, and it is what makes these bind
    // directly rather than through a lookup at run time. The kernel-prefixed spellings of the same
    // calls only wrap these and translate the failure into a service code.

    /// <summary>
    /// Fills <paramref name="status"/> with the status of the file at <paramref name="path"/>,
    /// following a symbolic link to what it names.
    /// </summary>
    /// <returns>Zero on success, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial int stat(byte* path, SceKernelStat* status);

    /// <summary>Fills <paramref name="status"/> with the status of an open descriptor.</summary>
    /// <returns>Zero on success, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial int fstat(int descriptor, SceKernelStat* status);

    /// <summary>Writes everything buffered for <paramref name="descriptor"/> out to its device.</summary>
    /// <returns>Zero on success, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial int fsync(int descriptor);

    /// <summary>
    /// Reads at <paramref name="offset"/> without moving the descriptor's own offset, so readers
    /// sharing one descriptor do not disturb each other.
    /// </summary>
    /// <returns>The number of bytes read (zero at end of file), or -1.</returns>
    [LibraryImport(Lib)]
    public static partial long pread(int descriptor, void* buffer, nuint length, long offset);

    /// <summary>Writes at <paramref name="offset"/> without moving the descriptor's own offset.</summary>
    /// <returns>The number of bytes written, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial long pwrite(int descriptor, void* buffer, nuint length, long offset);

    /// <summary>
    /// Sets the length of an open file. Growing a file this way leaves the added bytes reading as zero
    /// without writing them, which is how a large output file is sized up front.
    /// </summary>
    /// <returns>Zero on success, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial int ftruncate(int descriptor, long length);

    /// <summary>Sets the permission bits of the file at <paramref name="path"/>.</summary>
    /// <remarks>
    /// The <paramref name="mode"/> argument follows POSIX conventions - 0x1ED = 0755 marks the file as
    /// executable by everyone, 0x1B6 = 0666 as readable and writable by everyone. Executable bits are
    /// what the platform loader tests before it maps an <c>eboot.bin</c> or a shared module for
    /// execution, so a launcher that copies binaries into place first has to set them here.
    /// </remarks>
    /// <returns>Zero on success, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial int chmod(byte* path, ushort mode);

    /// <summary>Sets the permission bits of an open descriptor.</summary>
    /// <returns>Zero on success, or -1.</returns>
    [LibraryImport(Lib)]
    public static partial int fchmod(int descriptor, ushort mode);

    /// <summary>
    /// Reads a batch of directory entries from an open descriptor into the caller's buffer, walking
    /// forward from the descriptor's current offset. Every entry is a FreeBSD <c>struct dirent</c>
    /// with fields at offsets 0 (fileno u32), 4 (reclen u16), 6 (type u8), 7 (namlen u8), 8 (name).
    /// </summary>
    /// <returns>
    /// The number of bytes packed into <paramref name="buffer"/>, zero at end of directory, or -1.
    /// </returns>
    [LibraryImport(Lib)]
    public static partial int getdents(int descriptor, byte* buffer, nuint length);

    /// <summary>Fetches or sets a descriptor attribute. Value 3.</summary>
    /// <remarks>The paired <c>F_GETFL</c>/<c>F_SETFL</c> pair reads and writes the open-time flags.</remarks>
    public const int FcntlGetFlags = 3;

    /// <summary>Sets the descriptor's open-time flags to the third argument.</summary>
    public const int FcntlSetFlags = 4;

    /// <summary>Ask a light-weight file system to work in cooperation mode. Value 0.</summary>
    public const int LwfsDisable = 0;

    /// <summary>Ask a light-weight file system to work in its exclusive mode. Value 1.</summary>
    public const int LwfsEnable = 1;

    /// <summary>Seek relative to the start of the file, for a light-weight file system. Value 0.</summary>
    public const int LwfsSeekSet = 0;

    /// <summary>Seek relative to the current offset, for a light-weight file system. Value 1.</summary>
    public const int LwfsSeekCurrent = 1;

    /// <summary>Seek relative to the end of the file, for a light-weight file system. Value 2.</summary>
    public const int LwfsSeekEnd = 2;

    /// <summary>
    /// Seek to the last byte of the file where data has been written, for a light-weight file system.
    /// Value 3.
    /// </summary>
    public const int LwfsSeekDataEnd = 3;

    /// <summary>
    /// Sets or reads a per-descriptor attribute. The third argument depends on <paramref name="cmd"/>:
    /// <see cref="FcntlSetFlags"/> takes an int, <see cref="FcntlGetFlags"/> ignores it.
    /// </summary>
    /// <returns>The command's own return, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelFcntl(int descriptor, int cmd, int arg);

    /// <summary>
    /// Fills <paramref name="status"/> with the file status of <paramref name="path"/> (following a
    /// symbolic link to what it names).
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelStat(byte* path, SceKernelStat* status);

    /// <summary>Sets the permission bits of the file at <paramref name="path"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelChmod(byte* path, ushort mode);

    /// <summary>Writes everything buffered for <paramref name="descriptor"/> out to its device.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelFsync(int descriptor);

    /// <summary>Sets the length of an open file. Reports a negative error code on failure.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelFtruncate(int descriptor, long length);

    /// <summary>
    /// Reads into a scatter list of <paramref name="iovcnt"/> buffers, filling them in order until the
    /// count is exhausted or the file ends.
    /// </summary>
    /// <returns>The total byte count read (zero at end of file), or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial long sceKernelReadv(int descriptor, SceKernelIovec* iov, int iovcnt);

    /// <summary>Writes from a gather list of <paramref name="iovcnt"/> buffers, in order.</summary>
    /// <returns>The total byte count written, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial long sceKernelWritev(int descriptor, SceKernelIovec* iov, int iovcnt);

    /// <summary>
    /// Reads into a scatter list of <paramref name="iovcnt"/> buffers at <paramref name="offset"/>
    /// without moving the descriptor's own offset.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial long sceKernelPreadv(int descriptor, SceKernelIovec* iov, int iovcnt, long offset);

    /// <summary>
    /// Writes from a gather list of <paramref name="iovcnt"/> buffers at <paramref name="offset"/>
    /// without moving the descriptor's own offset.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial long sceKernelPwritev(int descriptor, SceKernelIovec* iov, int iovcnt, long offset);

    /// <summary>
    /// Turns a light-weight file-system descriptor into its exclusive mode (<see cref="LwfsEnable"/>) or
    /// back to cooperative (<see cref="LwfsDisable"/>).
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelLwfsSetAttribute(int descriptor, int flags);

    /// <summary>Reserves <paramref name="size"/> bytes of contiguous storage for later writes on <paramref name="descriptor"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelLwfsAllocateBlock(int descriptor, long size);

    /// <summary>Releases <paramref name="size"/> bytes of the reservation that no writer has claimed.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelLwfsTrimBlock(int descriptor, long size);

    /// <summary>Moves the file offset within a light-weight file system, taking a <c>LwfsSeek*</c> whence.</summary>
    /// <returns>The new offset, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial long sceKernelLwfsLseek(int descriptor, long offset, int whence);

    /// <summary>Writes <paramref name="nbytes"/> from <paramref name="buffer"/> to <paramref name="descriptor"/>.</summary>
    /// <returns>The byte count written, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial long sceKernelLwfsWrite(int descriptor, void* buffer, nuint nbytes);
}

/// <summary>
/// One entry of a scatter or gather buffer list. The kernel's own name for this structure is
/// <c>iovec</c>; the scatter and gather read and write calls each take an array of these.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public unsafe struct SceKernelIovec
{
    /// <summary>The address of the buffer.</summary>
    public void* Base;

    /// <summary>The byte count of the buffer.</summary>
    public nuint Length;
}
