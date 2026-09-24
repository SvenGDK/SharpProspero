// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Services;

/// <summary>
/// Launches the system web browser from a payload context. Wraps
/// <c>sceSystemServiceLaunchWebBrowser</c> from <c>libSceSystemService</c>.
/// </summary>
/// <remarks>
/// <para>The browser launch requires an active user-service session. The user service must be
/// initialised before calling <c>sceSystemServiceLaunchWebBrowser</c>. A payload should call
/// <see cref="PayloadUserService.Initialize"/> before calling <see cref="LaunchWebBrowser"/>.
/// </para>
/// <para>Requires <c>libSceSystemService</c> and <c>libSceUserService</c> in the payload's
/// DT_NEEDED list.</para>
/// </remarks>
public static unsafe partial class PayloadBrowser
{
    private const string Lib = "libSceSystemService";

    /// <summary>
    /// Launches the system web browser and navigates it to the given URI.
    /// The URI must use the <c>http:</c>, <c>https:</c>, or <c>psno:</c> scheme and
    /// be shorter than 6016 bytes (0x1780).
    /// </summary>
    /// <param name="uri">A NUL-terminated UTF-8 URI string (e.g. "http://192.168.1.1\0").</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceLaunchWebBrowser(byte* uri);

    /// <summary>
    /// Launches the system web browser with a managed-friendly URI span.
    /// </summary>
    /// <param name="uri">A NUL-terminated UTF-8 URI.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    public static int LaunchWebBrowser(ReadOnlySpan<byte> uri)
    {
        fixed (byte* p = uri)
            return sceSystemServiceLaunchWebBrowser(p);
    }
}
