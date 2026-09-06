// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.IO;
using System;

namespace SharpProspero.Payload.Orchestration;

/// <summary>
/// Scans <c>/user/app</c> directories for <c>mount.lnk</c> files, reads each link
/// target, detects and mounts images at the source path, then bind-mounts the result
/// to <c>/system_ex/app/&lt;titleid&gt;</c>. Handles UFS, PFS, PFSC, and exFAT images
/// with nested image support inside PFSC containers.
/// </summary>
public static unsafe class PayloadTitleAutoMount
{
    /// <summary>
    /// Scans for titles with <c>mount.lnk</c> files and mounts their content.
    /// Creates the base mount directories upfront, checks the automount sentinel,
    /// filters by 9-character title ID, guards against already-mounted titles,
    /// and cleans stale mounts before fresh mounting.
    /// </summary>
    /// <returns>Number of titles successfully mounted.</returns>
    public static int ScanAndMountTitles()
    {
        EnsureBaseDirectories();

        byte* userAppPath = stackalloc byte[] {
            (byte)'/', (byte)'u', (byte)'s', (byte)'e', (byte)'r',
            (byte)'/', (byte)'a', (byte)'p', (byte)'p', 0 };

        void* dir = PayloadFileSystem.opendir(userAppPath);
        if (dir == null) return 0;

        int mounted = 0;
        byte* linkPath = stackalloc byte[512];
        byte* targetPath = stackalloc byte[512];
        byte* mountedSrc = stackalloc byte[512];
        byte* dstPath = stackalloc byte[512];
        byte* imagePath = stackalloc byte[512];
        byte* sceSysCheck = stackalloc byte[512];

        while (true)
        {
            FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
            if (entry == null) break;
            if (entry->d_type != PayloadFileSystem.DT_DIR) continue;
            if (entry->d_name[0] == (byte)'.') continue;

            int nameLen = StringLength(entry->d_name);
            if (nameLen != 9) continue;

            BuildPath(linkPath, userAppPath, entry->d_name, "mount.lnk\0"u8);

            if (PayloadFileSystem.access(linkPath, PayloadFileSystem.F_OK) != 0)
                continue;

            if (ReadMountLink(linkPath, targetPath, 511) <= 0)
                continue;

            BuildSystemExPath(dstPath, entry->d_name);

            AppendSlash(sceSysCheck, dstPath, "sce_sys\0"u8);
            FreeBsdStat sceSt = default;
            if (PayloadFileSystem.stat(sceSysCheck, &sceSt) == 0)
                continue;

            // Clear any stale mount before fresh mount.
            PayloadMount.unmount(dstPath, 0);

            PayloadImageMount.ImageType imgType = PayloadImageMount.FindImageInDirectory(
                targetPath, imagePath, 512);

            if (imgType == PayloadImageMount.ImageType.Unknown)
            {
                PayloadFileSystem.mkdir(dstPath, 0x1FF);
                if (PayloadMount.MountNullfs(targetPath, dstPath) == 0)
                    mounted++;
                continue;
            }

            bool mountOk = MountSource(imgType, imagePath, mountedSrc);
            if (!mountOk) continue;

            PayloadFileSystem.mkdir(dstPath, 0x1FF);
            if (PayloadMount.MountNullfs(mountedSrc, dstPath) == 0)
            {
                mounted++;
            }
            else
            {
                PayloadMount.unmount(mountedSrc, PayloadMount.MntForce);
                PayloadFileSystem.rmdir(mountedSrc);
            }
        }

        PayloadFileSystem.closedir(dir);
        return mounted;
    }

    private static bool MountSource(PayloadImageMount.ImageType imgType, byte* imagePath,
        byte* outMountedPath)
    {
        switch (imgType)
        {
            case PayloadImageMount.ImageType.Pfs:
                return MountPfs(imagePath, outMountedPath);
            case PayloadImageMount.ImageType.Ufs:
                return MountUfs(imagePath, outMountedPath);
            case PayloadImageMount.ImageType.Pfsc:
                return MountPfsc(imagePath, outMountedPath);
            case PayloadImageMount.ImageType.ExFat:
                return MountExfat(imagePath, outMountedPath);
            default:
                return false;
        }
    }

    private static bool MountPfs(byte* imagePath, byte* outMountPoint)
    {
        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int pos = 0;
        AppendLiteral(outMountPoint, ref pos, "/data/imgmnt/pfsmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref pos, mountName, mnLen);
        outMountPoint[pos] = 0;

        PayloadFileSystem.mkdir(outMountPoint, 0x1FF);

        MountSaveDataOpt opt = default;
        PayloadPfsMount.sceFsInitMountSaveDataOpt(&opt);
        byte* zeroKey = stackalloc byte[32];
        new Span<byte>(zeroKey, 32).Clear();

        return PayloadPfsMount.sceFsMountSaveData(&opt, imagePath, outMountPoint, zeroKey) == 0;
    }

    private static bool MountUfs(byte* imagePath, byte* outMountPoint)
    {
        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(imagePath, &st) != 0) return false;

        // Time-freshness: skip images modified less than 12 seconds ago.
        long* ts = stackalloc long[2];
        ts[0] = 0; ts[1] = 0;
        if (PayloadCrt.Syscall(232, 0, (long)ts) == 0 && ts[0] > 0 && (ts[0] - st.st_mtim_sec) < 12)
            return false;

        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int pos = 0;
        AppendLiteral(outMountPoint, ref pos, "/data/imgmnt/ufsmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref pos, mountName, mnLen);
        outMountPoint[pos] = 0;

        // Check if already mounted as UFS.
        FreeBsdStatfs sfs = default;
        if (PayloadMount.statfs(outMountPoint, &sfs) == 0)
        {
            byte* ufsName = stackalloc byte[] { (byte)'u', (byte)'f', (byte)'s', 0 };
            if (FixedBytesEqual(sfs.f_fstypename, ufsName, 3))
                return true;
        }

        PayloadFileSystem.mkdir(outMountPoint, 0x1FF);

        int unit = PayloadImageMount.MdAttach(imagePath, 512, true, (ulong)st.st_size);
        if (unit < 0)
        {
            unit = PayloadImageMount.MdAttach(imagePath, 512, false, (ulong)st.st_size);
            if (unit < 0) return false;
        }

        byte* devPath = stackalloc byte[32];
        int dpos = 0;
        AppendLiteral(devPath, ref dpos, "/dev/md"u8);
        WriteInt(devPath, ref dpos, unit);
        devPath[dpos] = 0;

        if (PayloadMount.NmountUfs(devPath, outMountPoint) == 0)
            return true;

        if (PayloadMount.NmountUfs(devPath, outMountPoint, readOnly: true) == 0)
            return true;

        PayloadImageMount.MdDetach(unit);
        return false;
    }

    private static bool MountPfsc(byte* imagePath, byte* outMountPoint)
    {
        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int pos = 0;
        AppendLiteral(outMountPoint, ref pos, "/data/imgmnt/pfscmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref pos, mountName, mnLen);
        outMountPoint[pos] = 0;

        PayloadFileSystem.mkdir(outMountPoint, 0x1FF);

        // PFSC: lvd attach + PFS nmount with sigverify=0
        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(imagePath, &st) != 0) return false;

        int devId = PayloadImageMount.LvdAttach(2048, 7, (ulong)st.st_size);
        if (devId < 0) return false;

        byte* devPath = stackalloc byte[32];
        int dpos = 0;
        AppendLiteral(devPath, ref dpos, "/dev/lvd"u8);
        WriteInt(devPath, ref dpos, devId);
        devPath[dpos] = 0;

        MountSaveDataOpt opt = default;
        PayloadPfsMount.sceFsInitMountSaveDataOpt(&opt);
        byte* zeroKey = stackalloc byte[32];
        new Span<byte>(zeroKey, 32).Clear();

        if (PayloadPfsMount.sceFsMountSaveData(&opt, devPath, outMountPoint, zeroKey) != 0)
        {
            PayloadImageMount.LvdDetach(devId);
            return false;
        }

        // Check for nested image inside the PFSC container.
        byte* nestedImagePath = stackalloc byte[512];
        PayloadImageMount.ImageType nestedType = PayloadImageMount.FindImageInDirectory(
            outMountPoint, nestedImagePath, 512);

        if (nestedType != PayloadImageMount.ImageType.Unknown)
        {
            byte* nestedMountPoint = stackalloc byte[512];
            bool nestedOk = MountSource(nestedType, nestedImagePath, nestedMountPoint);
            if (nestedOk)
            {
                CopyString(outMountPoint, nestedMountPoint);
                return true;
            }
        }

        return true;
    }

    private static bool MountExfat(byte* imagePath, byte* outMountPoint)
    {
        FreeBsdStat st = default;
        if (PayloadFileSystem.stat(imagePath, &st) != 0) return false;

        byte* filename = GetFilenamePointer(imagePath);
        byte* mountName = stackalloc byte[256];
        CopyFilenameNoExt(mountName, 256, filename);

        int pos = 0;
        AppendLiteral(outMountPoint, ref pos, "/data/imgmnt/exfatmnt/"u8);
        int mnLen = StringLength(mountName);
        CopyBytes(outMountPoint, ref pos, mountName, mnLen);
        outMountPoint[pos] = 0;

        // Check if already mounted.
        FreeBsdStatfs sfs = default;
        if (PayloadMount.statfs(outMountPoint, &sfs) == 0)
        {
            byte* exfatName = stackalloc byte[] {
                (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
            if (FixedBytesEqual(sfs.f_fstypename, exfatName, 7))
                return true;
        }

        PayloadFileSystem.mkdir(outMountPoint, 0x1FF);

        // Path A: md(4)
        int unit = PayloadImageMount.MdAttach(imagePath, 512, true, (ulong)st.st_size);
        if (unit >= 0)
        {
            byte* devPath = stackalloc byte[32];
            int dpos = 0;
            AppendLiteral(devPath, ref dpos, "/dev/md"u8);
            WriteInt(devPath, ref dpos, unit);
            devPath[dpos] = 0;

            if (PayloadMount.NmountExfat(devPath, outMountPoint) == 0)
                return true;

            PayloadImageMount.MdDetach(unit);
        }

        // Path B: LVD fallback
        int devId = PayloadImageMount.LvdAttach(512, 7, (ulong)st.st_size);
        if (devId >= 0)
        {
            byte* devPath = stackalloc byte[32];
            int dpos = 0;
            AppendLiteral(devPath, ref dpos, "/dev/lvd"u8);
            WriteInt(devPath, ref dpos, devId);
            devPath[dpos] = 0;

            if (PayloadMount.NmountExfat(devPath, outMountPoint) == 0)
                return true;

            PayloadImageMount.LvdDetach(devId);
        }

        return false;
    }

    // ---- Helpers ----

    private static void EnsureBaseDirectories()
    {
        byte* d1 = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'a', (byte)'t', (byte)'a',
            (byte)'/', (byte)'i', (byte)'m', (byte)'g', (byte)'m', (byte)'n', (byte)'t', 0 };
        PayloadFileSystem.mkdir(d1, 0x1FF);

        byte* d2 = stackalloc byte[32]; int p2 = 0;
        AppendLiteral(d2, ref p2, "/data/imgmnt/ufsmnt"u8); d2[p2] = 0;
        PayloadFileSystem.mkdir(d2, 0x1FF);

        byte* d3 = stackalloc byte[32]; int p3 = 0;
        AppendLiteral(d3, ref p3, "/data/imgmnt/pfsmnt"u8); d3[p3] = 0;
        PayloadFileSystem.mkdir(d3, 0x1FF);

        byte* d4 = stackalloc byte[32]; int p4 = 0;
        AppendLiteral(d4, ref p4, "/data/imgmnt/pfscmnt"u8); d4[p4] = 0;
        PayloadFileSystem.mkdir(d4, 0x1FF);

        byte* d5 = stackalloc byte[32]; int p5 = 0;
        AppendLiteral(d5, ref p5, "/data/imgmnt/exfatmnt"u8); d5[p5] = 0;
        PayloadFileSystem.mkdir(d5, 0x1FF);
    }

    private static int ReadMountLink(byte* path, byte* outBuf, int outSize)
    {
        int fd = PayloadIo.open(path, PayloadFileSystem.O_RDONLY);
        if (fd < 0) return 0;
        long n = PayloadIo.read(fd, outBuf, (nuint)outSize);
        PayloadIo.close(fd);
        if (n <= 0) return 0;
        outBuf[n] = 0;
        return (int)n;
    }

    private static void BuildSystemExPath(byte* buf, byte* titleId)
    {
        int i = 0;
        AppendLiteral(buf, ref i, "/system_ex/app/"u8);
        while (*titleId != 0) buf[i++] = *titleId++;
        buf[i] = 0;
    }

    private static void BuildPath(byte* buf, byte* dir, byte* name, ReadOnlySpan<byte> file)
    {
        int i = 0;
        byte* p = dir;
        while (*p != 0) buf[i++] = *p++;
        buf[i++] = (byte)'/';
        p = name;
        while (*p != 0) buf[i++] = *p++;
        buf[i++] = (byte)'/';
        for (int j = 0; j < file.Length; j++) buf[i++] = file[j];
    }

    private static void AppendSlash(byte* buf, byte* base_, ReadOnlySpan<byte> suffix)
    {
        int i = 0;
        byte* p = base_;
        while (*p != 0) buf[i++] = *p++;
        buf[i++] = (byte)'/';
        for (int j = 0; j < suffix.Length; j++) buf[i++] = suffix[j];
    }

    private static void AppendLiteral(byte* buf, ref int pos, ReadOnlySpan<byte> text)
    {
        for (int i = 0; i < text.Length; i++) buf[pos++] = text[i];
    }

    private static void CopyBytes(byte* buf, ref int pos, byte* src, int len)
    {
        for (int i = 0; i < len; i++) buf[pos++] = src[i];
    }

    private static void WriteInt(byte* buf, ref int pos, int value)
    {
        if (value >= 10) WriteInt(buf, ref pos, value / 10);
        buf[pos++] = (byte)('0' + value % 10);
    }

    private static int StringLength(byte* s)
    {
        int len = 0;
        while (s[len] != 0) len++;
        return len;
    }

    private static byte* GetFilenamePointer(byte* path)
    {
        byte* last = path;
        byte* p = path;
        while (*p != 0) { if (*p == (byte)'/') last = p + 1; p++; }
        return last;
    }

    private static void CopyFilenameNoExt(byte* dst, int dstSize, byte* filename)
    {
        int len = StringLength(filename);
        int dotPos = len;
        for (int i = len - 1; i >= 0; i--)
        {
            if (filename[i] == (byte)'.') { dotPos = i; break; }
        }
        int copyLen = dotPos < dstSize - 1 ? dotPos : dstSize - 1;
        for (int i = 0; i < copyLen; i++) dst[i] = filename[i];
        dst[copyLen] = 0;
    }

    private static void CopyString(byte* dst, byte* src)
    {
        while (*src != 0) *dst++ = *src++;
        *dst = 0;
    }

    private static bool FixedBytesEqual(byte* a, byte* b, int len)
    {
        for (int i = 0; i < len; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
