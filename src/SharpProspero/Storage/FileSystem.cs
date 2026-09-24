// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Kernel;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace SharpProspero.Storage;

/// <summary>What a directory entry refers to.</summary>
public enum FileEntryType
{
    /// <summary>
    /// The listing did not report a kind. Ask <see cref="FileSystem.GetEntryType"/> for the path to
    /// find out; treating it as a file is wrong for any file system that leaves the kind out.
    /// </summary>
    Unknown = 0,

    /// <summary>A named pipe.</summary>
    Fifo = 1,

    /// <summary>A character device.</summary>
    Character = 2,

    /// <summary>A directory.</summary>
    Directory = 4,

    /// <summary>A block device.</summary>
    Block = 6,

    /// <summary>A regular file.</summary>
    File = 8,

    /// <summary>A symbolic link.</summary>
    SymbolicLink = 10,

    /// <summary>A socket.</summary>
    Socket = 12,
}

/// <summary>One entry in a directory: its name and what it refers to.</summary>
public readonly struct DirectoryEntry
{
    /// <summary>The entry name, without a path.</summary>
    public string Name { get; init; }

    /// <summary>What the entry refers to.</summary>
    public FileEntryType Type { get; init; }

    /// <summary>True when the entry is a directory.</summary>
    public bool IsDirectory => Type == FileEntryType.Directory;

    /// <summary>True when the entry is a regular file.</summary>
    public bool IsFile => Type == FileEntryType.File;

    /// <summary>The entry name.</summary>
    public override string ToString() => Name;
}

/// <summary>
/// Browses and changes files and directories by path. Paths are the mounted roots, for example
/// <c>/app0</c> for a module's own read-only files. Use <see cref="PackageFile"/> for the simple case
/// of reading a bundled asset; use this to list a directory or to write to a writable mount.
/// </summary>
public static unsafe class FileSystem
{
    // A directory read returns a packed run of variable-length records. Each record starts with a
    // 4-byte file number, a 2-byte record length, a 1-byte type and a 1-byte name length, then the
    // name; the record length steps to the next entry.
    private const int RecordHeaderSize = 8;

    // The kernel re-reads a directory into a buffer of its own when a caller's is too small to hold one
    // record, but only for a request between 512 bytes and 64 kilobytes. Staying inside that band keeps
    // that second chance available.
    private const int ReadBufferSize = 8192;

    // What a failed listing is reported as. The open, the read and the retry are one operation as far as
    // a caller is concerned, and naming the individual call would say more about the SDK than the fault.
    private const string ListOperation = nameof(EnumerateDirectory);

    /// <summary>Lists the entries of the directory at <paramref name="path"/>, excluding . and .. .</summary>
    /// <exception cref="ProsperoException">The directory could not be opened or read.</exception>
    /// <remarks>
    /// Prefer <see cref="TryEnumerateDirectory"/> where a directory may not be there: a module sees only
    /// the part of the file system its own start-up left it, so a path that answers on one console or in
    /// one process is absent in the next, and that is expected rather than exceptional.
    /// </remarks>
    public static IReadOnlyList<DirectoryEntry> EnumerateDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        int code = Read(path, out List<DirectoryEntry> entries);
        return code < 0 ? throw new ProsperoException(ListOperation, code) : entries;
    }

    /// <summary>
    /// Lists the entries of the directory at <paramref name="path"/> and reports why when it cannot,
    /// instead of only that it could not.
    /// </summary>
    /// <param name="path">The directory to list.</param>
    /// <param name="entries">The entries, excluding . and .. . Empty when the listing failed.</param>
    /// <param name="errorCode">
    /// Zero on success, otherwise the code the failing call returned. Pass it to
    /// <see cref="SceResult.Describe"/> for a reason worth showing, or to
    /// <see cref="SceResult.ErrorNumber"/> to branch on it.
    /// </param>
    /// <returns>True when the directory was listed.</returns>
    public static bool TryEnumerateDirectory(string path, out IReadOnlyList<DirectoryEntry> entries, out int errorCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        errorCode = Read(path, out List<DirectoryEntry> found);
        entries = found;
        return errorCode == 0;
    }

    // Opens the directory and reads it, first with the plain call and then, if that refuses, once more
    // with the form that also reports the directory offset. Both reach one routine inside the kernel, so
    // the retry is insurance rather than a known cure; it costs one call on a path that already failed
    // and it is the form the system's own directory walks use. Returns zero, or the code that failed.
    private static int Read(string path, out List<DirectoryEntry> entries)
    {
        entries = [];
        int fd = OpenDirectoryDescriptor(path);
        if (fd < 0)
            return fd;
        try
        {
            int code = ReadInto(fd, entries, reportPosition: false);
            if (code == 0)
                return 0;

            // The first attempt consumed part of the directory before it failed, so the retry has to
            // start over. Rewinding the descriptor is what the kernel itself does when it re-reads a
            // directory on a caller's behalf; if it will not rewind, the first reason still stands.
            if (KernelFile.sceKernelLseek(fd, 0, KernelFile.SeekSet) >= 0)
            {
                entries.Clear();
                if (ReadInto(fd, entries, reportPosition: true) == 0)
                    return 0;
            }

            // A half-read directory is worse than none: a caller shown four of nine names has no way to
            // tell that from a directory holding four. The reason reported is the one the plain call
            // gave, which is why the listing was refused; the retry only ever adds a second chance.
            entries.Clear();
            return code;
        }
        finally
        {
            KernelFile.sceKernelClose(fd);
        }
    }

    // Reads one directory to its end. Returns zero, or the negative code the read returned.
    private static int ReadInto(int fd, List<DirectoryEntry> entries, bool reportPosition)
    {
        byte[] buffer = new byte[ReadBufferSize];
        long position = 0;
        fixed (byte* p = buffer)
        {
            while (true)
            {
                int read = reportPosition
                    ? KernelFile.sceKernelGetdirentries(fd, p, buffer.Length, &position)
                    : KernelFile.sceKernelGetdents(fd, p, buffer.Length);
                if (read < 0)
                    return read;
                if (read == 0)
                    return 0;
                DecodeEntries(buffer.AsSpan(0, read), entries);
            }
        }
    }

    /// <summary>
    /// Decodes a run of directory records into <paramref name="entries"/>, skipping the . and ..
    /// entries. Stops at the first record that does not fit the buffer.
    /// </summary>
    public static void DecodeEntries(ReadOnlySpan<byte> buffer, List<DirectoryEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        int offset = 0;
        while (offset + RecordHeaderSize <= buffer.Length)
        {
            int recordLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer[(offset + 4)..]);
            // A record shorter than its header, or one that runs past the buffer, ends the run; without
            // this the zero-length case would never advance.
            if (recordLength < RecordHeaderSize || offset + recordLength > buffer.Length)
                return;

            var type = (FileEntryType)buffer[offset + 6];
            int nameLength = Math.Min(buffer[offset + 7], recordLength - RecordHeaderSize);
            ReadOnlySpan<byte> nameBytes = buffer.Slice(offset + RecordHeaderSize, nameLength);

            // The name is padded to a four-byte boundary with zero bytes and the record can be longer
            // still, because a listing that had to be split reports the remainder of the buffer as part
            // of the last record. The length byte says where the name ends, but a name carried past a
            // zero byte would go on to build a path no call could open, so the first zero wins.
            int terminator = nameBytes.IndexOf((byte)0);
            if (terminator >= 0)
                nameBytes = nameBytes[..terminator];

            string name = Encoding.UTF8.GetString(nameBytes);
            if (name.Length > 0 && name != "." && name != "..")
                entries.Add(new DirectoryEntry { Name = name, Type = type });
            offset += recordLength;
        }
    }

    /// <summary>
    /// What <paramref name="path"/> refers to, asking the file system directly rather than relying on
    /// a directory listing to report it.
    /// </summary>
    /// <returns>
    /// The kind, or <see cref="FileEntryType.Unknown"/> when the path cannot be reached or its status
    /// cannot be read.
    /// </returns>
    /// <remarks>
    /// A symbolic link is reported as whatever it names, matching how the system's own directory walks
    /// decide whether to descend.
    /// </remarks>
    public static FileEntryType GetEntryType(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        byte[] owned = ToNullTerminated(path);
        SceKernelStat status = default;
        int result;
        fixed (byte* p = owned)
            result = KernelFile.stat(p, &status);
        return result == 0
            ? (FileEntryType)((status.Mode & KernelFile.FileTypeMask) >> 12)
            : FileEntryType.Unknown;
    }

    /// <summary>True when <paramref name="path"/> is a directory.</summary>
    public static bool IsDirectory(string path) => GetEntryType(path) == FileEntryType.Directory;

    /// <summary>The size in bytes of the file at <paramref name="path"/>.</summary>
    public static long GetFileSize(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        int fd = OpenPath(path, KernelFile.ReadOnly, 0);
        try
        {
            long size = KernelFile.sceKernelLseek(fd, 0, KernelFile.SeekEnd);
            if (size < 0)
                throw new ProsperoException(nameof(KernelFile.sceKernelLseek), (int)size);
            return size;
        }
        finally
        {
            KernelFile.sceKernelClose(fd);
        }
    }

    /// <summary>True when <paramref name="path"/> can be reached.</summary>
    public static bool Exists(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        byte[] owned = ToNullTerminated(path);
        fixed (byte* p = owned)
            return SceResult.Succeeded(KernelFile.sceKernelCheckReachability(p));
    }

    /// <summary>Creates the directory at <paramref name="path"/>.</summary>
    public static void CreateDirectory(string path, ushort mode = 0x1FF)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        byte[] owned = ToNullTerminated(path);
        fixed (byte* p = owned)
            SceResult.ThrowIfFailed(KernelFile.sceKernelMkdir(p, mode), nameof(KernelFile.sceKernelMkdir));
    }

    /// <summary>Removes the empty directory at <paramref name="path"/>.</summary>
    public static void DeleteDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        byte[] owned = ToNullTerminated(path);
        fixed (byte* p = owned)
            SceResult.ThrowIfFailed(KernelFile.sceKernelRmdir(p), nameof(KernelFile.sceKernelRmdir));
    }

    /// <summary>Removes the file at <paramref name="path"/>.</summary>
    public static void DeleteFile(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        byte[] owned = ToNullTerminated(path);
        fixed (byte* p = owned)
            SceResult.ThrowIfFailed(KernelFile.sceKernelUnlink(p), nameof(KernelFile.sceKernelUnlink));
    }

    /// <summary>Renames or moves <paramref name="from"/> to <paramref name="to"/>.</summary>
    public static void Move(string from, string to)
    {
        ArgumentException.ThrowIfNullOrEmpty(from);
        ArgumentException.ThrowIfNullOrEmpty(to);
        byte[] a = ToNullTerminated(from);
        byte[] b = ToNullTerminated(to);
        fixed (byte* pa = a)
        fixed (byte* pb = b)
            SceResult.ThrowIfFailed(KernelFile.sceKernelRename(pa, pb), nameof(KernelFile.sceKernelRename));
    }

    /// <summary>Reads the whole file at <paramref name="path"/>.</summary>
    /// <remarks>
    /// The whole file goes into one array, so this can only serve a file the heap can hold. Use
    /// <see cref="OpenRead"/> for anything larger, or for anything whose size is not known in advance.
    /// </remarks>
    public static byte[] ReadAllBytes(string path) => PackageFile.ReadAllBytes(path);

    /// <summary>Opens the file at <paramref name="path"/> for reading in pieces.</summary>
    /// <exception cref="ProsperoException">The file could not be opened.</exception>
    public static DeviceFileStream OpenRead(string path) => DeviceFileStream.OpenRead(path);

    /// <summary>
    /// Creates the file at <paramref name="path"/>, or empties it when it is already there, and opens it
    /// for writing in pieces.
    /// </summary>
    /// <exception cref="ProsperoException">The file could not be opened.</exception>
    public static DeviceFileStream Create(string path) => DeviceFileStream.Create(path);

    /// <summary>
    /// Opens the file at <paramref name="path"/> for writing at its end, creating it when it is not
    /// there.
    /// </summary>
    /// <exception cref="ProsperoException">The file could not be opened.</exception>
    public static DeviceFileStream OpenAppend(string path) => DeviceFileStream.OpenAppend(path);

    /// <summary>Writes <paramref name="data"/> to <paramref name="path"/>, replacing any existing file.</summary>
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> data)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        int fd = OpenPath(path, KernelFile.WriteOnly | KernelFile.Create | KernelFile.Truncate, 0x1B6);
        try
        {
            int written = 0;
            fixed (byte* p = data)
            {
                while (written < data.Length)
                {
                    long n = KernelFile.sceKernelWrite(fd, p + written, (nuint)(data.Length - written));
                    if (n < 0)
                        throw new ProsperoException(nameof(KernelFile.sceKernelWrite), (int)n);
                    if (n == 0)
                        break;
                    written += (int)n;
                }
            }
        }
        finally
        {
            KernelFile.sceKernelClose(fd);
        }
    }

    /// <summary>Writes <paramref name="text"/> to <paramref name="path"/> as UTF-8.</summary>
    public static void WriteAllText(string path, string text)
        => WriteAllBytes(path, Encoding.UTF8.GetBytes(text ?? string.Empty));

    /// <summary>Reads the file at <paramref name="path"/> and decodes it as UTF-8 text.</summary>
    /// <exception cref="ProsperoException">Opening or reading the file failed.</exception>
    public static string ReadAllText(string path) => Encoding.UTF8.GetString(ReadAllBytes(path));

    /// <summary>Creates the directory at <paramref name="path"/> and any missing parent directories.</summary>
    /// <exception cref="ProsperoException">A directory could not be created.</exception>
    public static void CreateDirectoryRecursive(string path, ushort mode = 0x1FF)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        bool absolute = path[0] == '/';
        var builder = new StringBuilder(path.Length);
        string[] segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < segments.Length; i++)
        {
            if (i > 0 || absolute)
                builder.Append('/');
            builder.Append(segments[i]);
            string directory = builder.ToString();
            if (!Exists(directory))
                CreateDirectory(directory, mode);
        }
    }

    /// <summary>Lists every file beneath <paramref name="path"/>, walking into sub-directories, as full paths.</summary>
    /// <exception cref="ProsperoException">A directory could not be read.</exception>
    public static List<string> EnumerateRecursive(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var files = new List<string>();
        CollectFiles(path, files);
        return files;
    }

    /// <summary>
    /// Copies the file at <paramref name="source"/> to <paramref name="destination"/>, overwriting it.
    /// The copy runs through a buffer of <paramref name="bufferSize"/> bytes, so a file larger than the
    /// heap copies as readily as a small one.
    /// </summary>
    /// <exception cref="ProsperoException">The read or write failed.</exception>
    public static void CopyFile(string source, string destination, int bufferSize = 1 << 20)
    {
        ArgumentException.ThrowIfNullOrEmpty(source);
        ArgumentException.ThrowIfNullOrEmpty(destination);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bufferSize);

        using DeviceFileStream from = DeviceFileStream.OpenRead(source);
        using DeviceFileStream to = DeviceFileStream.Create(destination);
        byte[] buffer = new byte[bufferSize];
        while (true)
        {
            int read = from.Read(buffer);
            if (read == 0)
                break;
            to.Write(buffer.AsSpan(0, read));
        }
    }

    /// <summary>Copies the directory tree at <paramref name="source"/> to <paramref name="destination"/>, creating it.</summary>
    /// <exception cref="ProsperoException">A read, write, or directory creation failed.</exception>
    public static void CopyDirectory(string source, string destination)
    {
        ArgumentException.ThrowIfNullOrEmpty(source);
        ArgumentException.ThrowIfNullOrEmpty(destination);

        // Refuse to copy a tree into itself or into one of its own sub-directories. Otherwise creating the
        // destination first would add an entry the walk then descends into, recursing without end.
        string normalizedSource = source.TrimEnd('/');
        string normalizedDestination = destination.TrimEnd('/');
        if (normalizedDestination == normalizedSource ||
            normalizedDestination.StartsWith(normalizedSource + "/", StringComparison.Ordinal))
        {
            throw new ProsperoException("The destination is the source directory or is inside it.", -1);
        }

        CreateDirectoryRecursive(destination);
        foreach (DirectoryEntry entry in EnumerateDirectory(source))
        {
            if (entry.Name is "." or "..")
                continue;
            string from = source.TrimEnd('/') + "/" + entry.Name;
            string to = destination.TrimEnd('/') + "/" + entry.Name;
            if (DescendsInto(entry, from))
                CopyDirectory(from, to);
            else
                CopyFile(from, to);
        }
    }

    private static void CollectFiles(string directory, List<string> files)
    {
        foreach (DirectoryEntry entry in EnumerateDirectory(directory))
        {
            if (entry.Name is "." or "..")
                continue;
            string child = directory.TrimEnd('/') + "/" + entry.Name;
            if (DescendsInto(entry, child))
                CollectFiles(child, files);
            else
                files.Add(child);
        }
    }

    // A file system is free to leave the kind out of a directory record, and a walk that reads an
    // unreported kind as a file would copy a directory as a byte stream and never enter it. Only the
    // unreported case costs a second call; a record that names its kind is taken at its word.
    private static bool DescendsInto(DirectoryEntry entry, string path)
        => entry.Type == FileEntryType.Unknown
            ? GetEntryType(path) == FileEntryType.Directory
            : entry.IsDirectory;

    private static int OpenPath(string path, int flags, ushort mode)
    {
        byte[] owned = ToNullTerminated(path);
        int fd;
        fixed (byte* p = owned)
            fd = KernelFile.sceKernelOpen(p, flags, mode);
        return SceResult.ThrowIfFailed(fd, nameof(KernelFile.sceKernelOpen));
    }

    // Opens a directory. The one call the platform's own opendir issues is what the kernel's own
    // path-resolution layer is prepared for; no other flag combination changes what happens after
    // the syscall reaches namei, and layering retries on top only hides the real reason behind an
    // accidental cascade. The mount-namespace side of "why /data answers and /mnt/usb0 does" lives
    // outside this call and is settled by the caller's own credentials and root-directory vnode.
    private static int OpenDirectoryDescriptor(string path)
    {
        byte[] owned = ToNullTerminated(path);
        fixed (byte* p = owned)
            return KernelFile.sceKernelOpen(p, KernelFile.OpenDirectory, 0);
    }

    private static byte[] ToNullTerminated(string path)
    {
        int count = Encoding.UTF8.GetByteCount(path);
        byte[] buffer = new byte[count + 1];
        Encoding.UTF8.GetBytes(path, buffer);
        return buffer;
    }
}
