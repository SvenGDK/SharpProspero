// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Debug;

/// <summary>
/// CPU profiler capture-control bindings. Two entries let the running module start or stop a host
/// capture from its own code, provided the host is currently listening for the command; both return
/// <see cref="RazorCpuDebug.ErrorHostNotListening"/> when it is not.
/// </summary>
public static unsafe partial class RazorCpuDebug
{
    private const string Lib = "libSceRazorCpu_debug";

    /// <summary>The host is not listening for a start or stop request from the running module.</summary>
    public const int ErrorHostNotListening = unchecked((int)0x8058000C);

    /// <summary>Requests a capture start; returns zero on success or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuStartCapture();

    /// <summary>Requests a capture stop; returns zero on success or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceRazorCpuStopCapture();
}
