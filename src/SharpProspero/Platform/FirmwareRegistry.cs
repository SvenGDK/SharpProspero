// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Collections.Generic;

namespace SharpProspero.Platform;

/// <summary>
/// One system library the SDK resolves at run time, the exports it needs, and where those facts were
/// confirmed. The <see cref="FirmwareRegistry"/> holds one of these per dynamically-loaded service so
/// there is a single place that says what each depends on and on which system it was checked.
/// </summary>
/// <param name="Name">A short name for the service (the wrapper that uses it).</param>
/// <param name="Path">The absolute path the library loads from.</param>
/// <param name="RequiredExports">
/// The exports the wrapper resolves. If a system version drops or renames one, the wrapper's own
/// resolution fails with a clear message, and <see cref="FirmwareSupport.Validate(SystemLibraryDescriptor)"/>
/// reports exactly which are missing before the service is used.
/// </param>
/// <param name="TestedOn">The system version the exports were confirmed present on.</param>
/// <param name="Notes">What the service is used for, and anything worth recording about it.</param>
public sealed record SystemLibraryDescriptor(
    string Name,
    string Path,
    IReadOnlyList<string> RequiredExports,
    FirmwareVersion TestedOn,
    string Notes);

/// <summary>
/// The single source of truth for what the SDK expects of the system it runs on: the range of system
/// versions it supports, the version its run-time surfaces were last confirmed on, and the libraries it
/// resolves by name at run time.
/// </summary>
/// <remarks>
/// <para>
/// The SDK's linked bindings are generated against the lowest supported version's export surface, which
/// later systems keep (an export is added across versions, not removed), so a module linked once loads
/// across the whole range. The libraries a title does not link against are resolved by name at run
/// time instead, which adapts to whatever the running system exports; those are the ones listed here,
/// because a name that moved between versions shows up there first.
/// </para>
/// <para>
/// This registry deliberately holds no absolute addresses. The SDK builds userland application modules
/// and reaches the system only through its exported functions and loadable modules, so there is nothing
/// here to pin to a version-specific offset. If a future feature ever needed one, it would be added
/// here with the same provenance the library entries carry, and validated the same way — but none is
/// needed today, and none is invented.
/// </para>
/// </remarks>
public static class FirmwareRegistry
{
    /// <summary>
    /// The range of system versions the SDK supports. Open-ended above the minimum: the export surface
    /// is confirmed backward-compatible, so a module built against the minimum runs on later systems.
    /// </summary>
    public static FirmwareRange SupportedRange { get; } =
        new(FirmwareVersion.FromMajorMinor(2, 0), FirmwareVersion.None);

    /// <summary>
    /// The most recent system version the run-time surfaces were confirmed against. Newer systems are
    /// expected to work by the backward-compatibility rule above; this is the last one actually checked.
    /// </summary>
    /// <remarks>
    /// The application-module surface (system libraries loaded by name) was last checked on 10.01.
    /// The payload-side kernel offset tables in <c>SharpProspero.Payload.Kernel.KernelOffsets</c>
    /// carry confirmed values for <c>allproc</c>, <c>kernel_pmap_store</c>, <c>security_flags</c>,
    /// <c>sysents</c>, <c>sysentvec</c> and the invariant structure field offsets through 12.70;
    /// the unjail-payload boot path (<c>KernelOffsets.IsSupportedForUnjail</c>) accepts every
    /// firmware in that range because it derives the root vnode at run time from init instead of
    /// consulting the <c>rootvnode</c> kdata offset, which is unverified for 11.xx and 12.xx.
    /// </remarks>
    public static FirmwareVersion LastValidatedOn { get; } = FirmwareVersion.FromMajorMinor(10, 1);

    /// <summary>
    /// The libraries the SDK loads and resolves by name at run time, each with the exports it needs and
    /// the system version they were confirmed on.
    /// </summary>
    public static IReadOnlyList<SystemLibraryDescriptor> DynamicLibraries { get; } =
    [
        new SystemLibraryDescriptor(
            Name: "Package installer",
            Path: PackageInstaller.ModulePath,
            // The exports the installer needs on every supported system. The option-taking uninstall
            // (sceAppInstUtilAppUnInstall2) is deliberately not here: it appears from firmware 3.00, so
            // requiring it would fail validation on 2.00-2.50 where the installer otherwise works. The
            // wrapper resolves it optionally and reports it only when its option is actually used.
            RequiredExports:
            [
                "sceAppInstUtilInitialize",
                "sceAppInstUtilTerminate",
                "sceAppInstUtilAppInstallPkg",
                "sceAppInstUtilAppExists",
                "sceAppInstUtilAppGetSize",
                "sceAppInstUtilAppUnInstall",
            ],
            TestedOn: FirmwareVersion.FromMajorMinor(10, 1),
            Notes: "Install, remove and query installed applications. Reached through the shell, not a public API. "
                + "The option-taking uninstall needs firmware 3.00 or later."),

        new SystemLibraryDescriptor(
            Name: "USB mass storage",
            Path: UsbStorage.ModulePath,
            RequiredExports:
            [
                "sceUsbStorageInit",
                "sceUsbStorageTerm",
                "sceUsbStorageGetDeviceList",
                "sceUsbStorageGetMountPointOfShellCore",
                "sceUsbStorageRequestMap",
                "sceUsbStorageRequestUnmap",
            ],
            TestedOn: FirmwareVersion.FromMajorMinor(10, 1),
            Notes: "Enumerate connected USB drives, read their mount paths, and map or unmap one on request."),
    ];

    /// <summary>Finds the descriptor for a service by <paramref name="name"/>, or null when there is none.</summary>
    public static SystemLibraryDescriptor? FindLibrary(string name)
    {
        foreach (SystemLibraryDescriptor descriptor in DynamicLibraries)
        {
            if (string.Equals(descriptor.Name, name, System.StringComparison.Ordinal))
                return descriptor;
        }
        return null;
    }
}
