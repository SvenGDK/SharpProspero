// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Process;

/// <summary>
/// Application information for a running process, as returned by
/// <see cref="PayloadProcess.sceKernelGetAppInfo"/>. The structure layout matches the
/// <c>app_info_t</c> typedef.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct PayloadAppInfo
{
    /// <summary>The application id assigned by the system.</summary>
    public uint AppId;

    /// <summary>An undocumented eight-byte field following the app id.</summary>
    public ulong Unknown1;

    /// <summary>The title identifier (offset +16, 14 bytes, NUL-padded).</summary>
    public fixed byte TitleId[14];

    /// <summary>Undocumented trailing data.</summary>
    public fixed byte Unknown2[0x3C];
}

/// <summary>
/// Queries the system for application information about a running process from a payload
/// context. Wraps <c>sceKernelGetAppInfo</c> from <c>libkernel</c>, which reads the app id
/// and title id of a running process.
/// </summary>
public static unsafe partial class PayloadProcess
{
    private const string Lib = "libkernel";

    /// <summary>
    /// Queries application information for the process with the given <paramref name="pid"/>.
    /// </summary>
    /// <param name="pid">The process identifier.</param>
    /// <param name="info">On success, receives the application information.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelGetAppInfo(int pid, PayloadAppInfo* info);

    /// <summary>
    /// Queries application information for the process with the given <paramref name="pid"/>,
    /// returning the result by value.
    /// </summary>
    /// <param name="pid">The process identifier.</param>
    /// <param name="info">On success, receives the application information.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    public static int GetAppInfo(int pid, out PayloadAppInfo info)
    {
        PayloadAppInfo local;
        int result = sceKernelGetAppInfo(pid, &local);
        info = result == 0 ? local : default;
        return result;
    }
}
