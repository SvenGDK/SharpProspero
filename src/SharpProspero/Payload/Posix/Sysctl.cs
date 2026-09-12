// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Posix;

/// <summary>
/// FreeBSD <c>sysctl</c> interface for a payload context. <c>sysctl(KERN_PROC)</c> enumerates
/// running processes, and <c>getmntinfo</c> (which internally calls <c>getvfsstat</c>, a
/// sysctl variant) enumerates mount points. These wrappers provide direct access to the
/// sysctl mechanism through <c>libc</c>.
/// </summary>
/// <remarks>
/// <para>FreeBSD sysctl MIB values for process enumeration:</para>
/// <list type="bullet">
/// <item><description><c>CTL_KERN = 1</c></description></item>
/// <item><description><c>KERN_PROC = 14</c></description></item>
/// <item><description><c>KERN_PROC_PID = 1</c> (single process by PID)</description></item>
/// </list>
/// </remarks>
public static unsafe partial class PayloadSysctl
{
    private const string LibKernel = "libkernel";

    /// <summary>Top-level MIB: kernel parameters.</summary>
    public const int CtlKern = 1;

    /// <summary>Second-level MIB: process information.</summary>
    public const int KernProc = 14;

    /// <summary>Third-level MIB: single process by PID.</summary>
    public const int KernProcPid = 1;

    /// <summary>Third-level MIB: all processes.</summary>
    public const int KernProcProc = 8;

    /// <summary>Mount wait flag for <see cref="getmntinfo"/>.</summary>
    public const int MntWait = 1;

    /// <summary>Mount no-wait flag for <see cref="getmntinfo"/>.</summary>
    public const int MntNowait = 2;

    /// <summary>
    /// Reads or writes a kernel parameter identified by <paramref name="name"/> (a MIB array).
    /// </summary>
    /// <param name="name">An array of MIB integers identifying the parameter.</param>
    /// <param name="namelen">The number of integers in <paramref name="name"/>.</param>
    /// <param name="oldp">Buffer to receive the current value, or null to query the size.</param>
    /// <param name="oldlenp">On entry, the buffer size; on exit, the actual size.</param>
    /// <param name="newp">New value to set, or null for a read-only query.</param>
    /// <param name="newlen">Size of <paramref name="newp"/>.</param>
    /// <returns>Zero on success, or -1 on error (sets errno).</returns>
    [LibraryImport(LibKernel)]
    public static partial int sysctl(int* name, uint namelen, void* oldp, nuint* oldlenp,
        void* newp, nuint newlen);

    /// <summary>
    /// Returns the list of mounted filesystems.
    /// </summary>
    /// <param name="bufp">On success, points to an array of <c>statfs</c> structures.</param>
    /// <param name="mode">Either <see cref="MntWait"/> or <see cref="MntNowait"/>.</param>
    /// <returns>The number of mounted filesystems, or -1 on error.</returns>
    /// <remarks>
    /// <c>getmntinfo</c> is not exported by any SPRX module on the target platform (it exists
    /// only in static <c>libc.a</c>). This method throws at runtime. Replace callers with a
    /// managed wrapper that invokes <c>getvfsstat</c> via <see cref="sysctl"/>.
    /// </remarks>
    /// <exception cref="System.PlatformNotSupportedException">Always thrown.</exception>
    public static int getmntinfo(void** bufp, int mode) =>
        throw new System.PlatformNotSupportedException(
            "getmntinfo is not exported by any SPRX module. Use sysctl or getvfsstat instead.");

    /// <summary>
    /// Finds the process identifier of a running process by its thread name. Queries all
    /// processes via <c>KERN_PROC_PROC</c> in a single sysctl call and walks the result,
    /// returning the last match (excluding the caller's own PID).
    /// </summary>
    /// <param name="name">The NUL-terminated thread name to search for.</param>
    /// <returns>The PID of the last matching process, or -1 if not found.</returns>
    public static int FindPidByName(byte* name)
    {
        const int KiStructSizeOffset = 0;
        const int KiPidOffset = 72;
        const int KiTdnameOffset = 447;
        const int KiTdnameMax = 16;

        int nameLen = 0;
        while (nameLen < KiTdnameMax && name[nameLen] != 0) nameLen++;

        int myPid = (int)PayloadCrt.Syscall(20, 0);

        int* mib = stackalloc int[4];
        mib[0] = CtlKern;
        mib[1] = KernProc;
        mib[2] = KernProcProc;
        mib[3] = 0;

        nuint totalSize = 0;
        if (sysctl(mib, 4, null, &totalSize, null, 0) != 0)
            return -1;

        totalSize += 4096;
        long mapResult = PayloadCrt.Syscall(477, 0, (long)totalSize, 3, 0x1002, -1, 0);
        if (mapResult == -1) return -1;
        byte* buf = (byte*)(ulong)mapResult;

        nuint actualSize = totalSize;
        if (sysctl(mib, 4, buf, &actualSize, null, 0) != 0)
        {
            PayloadCrt.Syscall(73, mapResult, (long)totalSize);
            return -1;
        }

        int matched = -1;
        nuint offset = 0;
        while (offset < actualSize)
        {
            byte* entry = buf + offset;
            int structSize = *(int*)(entry + KiStructSizeOffset);
            if (structSize <= 0) break;

            int pid = *(int*)(entry + KiPidOffset);
            if (pid != myPid)
            {
                byte* tdname = entry + KiTdnameOffset;
                bool match = true;
                for (int j = 0; j < nameLen; j++)
                {
                    if (tdname[j] != name[j]) { match = false; break; }
                }
                if (match && (nameLen >= KiTdnameMax || tdname[nameLen] == 0))
                    matched = pid;
            }

            offset += (nuint)structSize;
        }

        PayloadCrt.Syscall(73, mapResult, (long)totalSize);
        return matched;
    }
}
