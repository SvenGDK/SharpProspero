// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpProspero.Payload.Services;

/// <summary>
/// Installs an application from a local directory in a payload context. Wraps
/// <c>sceAppInstUtilInitialize</c> and <c>sceAppInstUtilAppInstallTitleDir</c> from
/// <c>libSceAppInstUtil</c>.
/// </summary>
/// <remarks>
/// Requires <c>libSceAppInstUtil</c> and <c>libSceIpmi</c> in the payload's DT_NEEDED list.
/// The install operation reads a previously unpacked application directory at a path like
/// <c>/user/app/</c> and registers it with the system using the given title identifier.
/// </remarks>
public static unsafe partial class PayloadAppInstaller
{
    private const string Lib = "libSceAppInstUtil";

    /// <summary>
    /// Initialises the application install utility service.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilInitialize();

    /// <summary>
    /// Installs an application from <paramref name="path"/> with the given
    /// <paramref name="titleId"/>. The path should be a directory containing the unpacked
    /// application files.
    /// </summary>
    /// <param name="titleId">A NUL-terminated UTF-8 title identifier (e.g. "FAKE02932\0").</param>
    /// <param name="path">A NUL-terminated UTF-8 filesystem path (e.g. "/user/app/\0").</param>
    /// <param name="param">Reserved parameter, pass null.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppInstallTitleDir(byte* titleId, byte* path, void* param);

    /// <summary>
    /// Initialises the install utility and installs an application in a single call.
    /// </summary>
    /// <param name="titleId">A NUL-terminated UTF-8 title identifier.</param>
    /// <param name="path">A NUL-terminated UTF-8 filesystem path.</param>
    /// <returns>Zero on success, or the first non-zero error code.</returns>
    public static int InstallFromDirectory(ReadOnlySpan<byte> titleId, ReadOnlySpan<byte> path)
    {
        int result = sceAppInstUtilInitialize();
        if (result != 0) return result;

        fixed (byte* pTitle = titleId)
        fixed (byte* pPath = path)
            return sceAppInstUtilAppInstallTitleDir(pTitle, pPath, null);
    }

    /// <summary>
    /// Uninstalls the application with the given <paramref name="titleId"/>.
    /// </summary>
    /// <param name="titleId">A NUL-terminated UTF-8 title identifier.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppUnInstall(byte* titleId);

    /// <summary>
    /// Installs all pending applications. On firmware 12.00 and later this is the required
    /// entry point; the per-directory variant may not be available.
    /// </summary>
    /// <param name="param">Reserved parameter, pass null.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilAppInstallAll(void* param);

    /// <summary>
    /// Convenience wrapper for <see cref="sceAppInstUtilAppUnInstall"/> that accepts a span.
    /// </summary>
    public static int Uninstall(ReadOnlySpan<byte> titleId)
    {
        fixed (byte* p = titleId)
            return sceAppInstUtilAppUnInstall(p);
    }

    /// <summary>
    /// Initialises the install utility and installs all pending applications in a single call.
    /// </summary>
    /// <returns>Zero on success, or the first non-zero error code.</returns>
    public static int InstallAll()
    {
        int result = sceAppInstUtilInitialize();
        if (result != 0) return result;
        return sceAppInstUtilAppInstallAll(null);
    }

    /// <summary>
    /// Installs an application from a package file (.pkg) using a descriptor that carries the
    /// package path and optional metadata. On success the service writes the content information
    /// into <paramref name="outContentInfo"/> and the package identifier into
    /// <paramref name="outPkgInfo"/>.
    /// </summary>
    /// <param name="descriptor">
    /// A pointer to a 0x38-byte <see cref="InstallByPackageDescriptor"/> containing the package
    /// path and optional fields.
    /// </param>
    /// <param name="outContentInfo">
    /// A pointer to a 0x38-byte <see cref="InstallByPackageResult"/> that receives the content
    /// id, content type, and content platform of the installed package.
    /// </param>
    /// <param name="outPkgInfo">
    /// A pointer to a buffer that receives the package identifier from the service.
    /// </param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAppInstUtilInstallByPackage(
        InstallByPackageDescriptor* descriptor,
        InstallByPackageResult* outContentInfo,
        void* outPkgInfo);

    /// <summary>
    /// Initialises the install utility and installs a package file in a single call.
    /// On success <paramref name="result"/> receives the content information, and
    /// <paramref name="contentId"/> and <paramref name="pkgId"/> receive the NUL-terminated
    /// UTF-8 strings the service wrote into its output buffers.
    /// </summary>
    /// <param name="pkgPath">
    /// A NUL-terminated UTF-8 absolute path to the .pkg file on the filesystem.
    /// </param>
    /// <param name="result">
    /// Receives the content id, content type, and content platform of the installed package.
    /// </param>
    /// <param name="contentId">
    /// On success, the content id string decoded from the result structure (up to 47 characters).
    /// Empty when the call fails or the field is blank.
    /// </param>
    /// <param name="pkgId">
    /// On success, the package identifier string decoded from the service output buffer.
    /// Empty when the call fails or the field is blank.
    /// </param>
    /// <returns>Zero on success, or the first non-zero error code.</returns>
    public static int InstallByPackage(ReadOnlySpan<byte> pkgPath, out InstallByPackageResult result,
        out string contentId, out string pkgId)
    {
        result = default;
        contentId = string.Empty;
        pkgId = string.Empty;

        int rc = sceAppInstUtilInitialize();
        if (rc != 0) return rc;

        InstallByPackageDescriptor desc = default;
        InstallByPackageResult localResult = default;

        // The service writes a NUL-terminated package identifier into the third output buffer.
        // Use 0x100 bytes as a safe upper bound for the descriptor id.
        byte* pkgIdBuf = stackalloc byte[0x100];
        new Span<byte>(pkgIdBuf, 0x100).Clear();

        fixed (byte* pPath = pkgPath)
        {
            desc.PkgPath = pPath;
            rc = sceAppInstUtilInstallByPackage(&desc, &localResult, pkgIdBuf);
        }

        result = localResult;

        if (rc == 0)
        {
            // Decode content id from the result structure (0x30 bytes, NUL-terminated UTF-8).
            InstallByPackageResult* pRes = &localResult;
            int cidLen = 0;
            while (cidLen < 0x30 && pRes->ContentId[cidLen] != 0)
                cidLen++;
            if (cidLen > 0)
                contentId = Encoding.UTF8.GetString(pRes->ContentId, cidLen);

            // Decode package id from the output buffer (up to 0x100 bytes, NUL-terminated UTF-8).
            int pidLen = 0;
            while (pidLen < 0x100 && pkgIdBuf[pidLen] != 0)
                pidLen++;
            if (pidLen > 0)
                pkgId = Encoding.UTF8.GetString(pkgIdBuf, pidLen);
        }

        return rc;
    }
}

/// <summary>
/// Descriptor for <see cref="PayloadAppInstaller.sceAppInstUtilInstallByPackage"/>. Contains a
/// required package path and optional metadata fields. All string fields must be NUL-terminated
/// UTF-8 or null when not provided.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 0x38)]
public unsafe struct InstallByPackageDescriptor
{
    /// <summary>Required. Absolute path to the .pkg file (max 16383 characters).</summary>
    [FieldOffset(0x00)] public byte* PkgPath;

    /// <summary>Optional. An install option string (max 16383 characters).</summary>
    [FieldOffset(0x08)] public byte* Option;

    /// <summary>Optional. Content type code (max 2 characters).</summary>
    [FieldOffset(0x10)] public byte* TypeCode;

    /// <summary>Optional. Content id (max 47 characters).</summary>
    [FieldOffset(0x18)] public byte* ContentId;

    /// <summary>Optional. Additional parameter (max 127 characters).</summary>
    [FieldOffset(0x20)] public byte* Param;

    /// <summary>Optional. An extra filesystem path (max 16383 characters).</summary>
    [FieldOffset(0x28)] public byte* ExtraPath;

    /// <summary>Flags passed through to the install service.</summary>
    [FieldOffset(0x30)] public uint Flags;

    /// <summary>Target platform value passed through to the install service.</summary>
    [FieldOffset(0x34)] public byte Platform;
}

/// <summary>
/// Output from <see cref="PayloadAppInstaller.sceAppInstUtilInstallByPackage"/>. The service fills
/// in the content id of the installed package along with its content type and platform.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 0x38)]
public unsafe struct InstallByPackageResult
{
    /// <summary>The content id string written by the service (up to 47 characters + NUL).</summary>
    [FieldOffset(0x00)] public fixed byte ContentId[0x30];

    /// <summary>Content type identifier written by the service.</summary>
    [FieldOffset(0x30)] public uint ContentType;

    /// <summary>Content platform identifier written by the service.</summary>
    [FieldOffset(0x34)] public uint ContentPlatform;
}
