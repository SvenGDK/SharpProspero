// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Elf;
using System;

namespace SharpProspero.Payload.IO;

/// <summary>
/// Detects image file types by extension and dispatches to the correct mount path:
/// <c>md(4)</c> + <c>nmount</c> for UFS and exFAT, <c>sceFsMountSaveData</c> for PFS,
/// <c>lvdctl</c> + <c>nmount</c> for PFSC.
/// </summary>
public static unsafe class PayloadImageMount
{
    /// <summary>Detected image type.</summary>
    public enum ImageType { Unknown, Ufs, Pfs, Pfsc, ExFat }

    /// <summary>
    /// Detects the image type from a file path by extension.
    /// </summary>
    public static ImageType DetectType(byte* path)
    {
        int len = 0;
        while (path[len] != 0) len++;
        if (len < 4) return ImageType.Unknown;

        if (EndsWith(path, len, ".pfs"u8)) return ImageType.Pfs;
        if (EndsWith(path, len, ".ufs"u8)) return ImageType.Ufs;
        if (EndsWith(path, len, ".ffpkg"u8)) return ImageType.Ufs;
        if (EndsWith(path, len, ".ffpfsc"u8)) return ImageType.Pfsc;
        if (EndsWith(path, len, ".exfat"u8)) return ImageType.ExFat;
        if (EndsWith(path, len, ".img"u8)) return ImageType.ExFat;

        return ImageType.Unknown;
    }

    /// <summary>
    /// Attaches a file as a memory disk via <c>/dev/mdctl</c> and returns the unit number.
    /// Used for UFS and exFAT images.
    /// </summary>
    /// <returns>The assigned unit number on success, or -1 on error.</returns>
    public static int MdAttach(byte* imagePath, uint sectorSize, bool readOnly, ulong mediaSize)
    {
        byte* devPath = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'m', (byte)'d', (byte)'c', (byte)'t', (byte)'l', 0 };

        int fd = PayloadIo.open(devPath, PayloadFileSystem.O_RDWR);
        if (fd < 0) return -1;

        MdIoctl md = default;
        md.Version = 0;
        md.Type = DeviceControl.MdVnode;
        md.File = imagePath;
        md.Mediasize = mediaSize;
        md.Sectorsize = sectorSize;
        md.Options = DeviceControl.MdAutounit | (readOnly ? DeviceControl.MdReadonly : 0u);

        int rc = PayloadIo.ioctl(fd, DeviceControl.MdiocAttach, &md);
        PayloadIo.close(fd);

        return rc == 0 ? (int)md.Unit : -1;
    }

    /// <summary>
    /// Detaches a memory disk unit.
    /// </summary>
    public static int MdDetach(int unit)
    {
        byte* devPath = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'m', (byte)'d', (byte)'c', (byte)'t', (byte)'l', 0 };

        int fd = PayloadIo.open(devPath, PayloadFileSystem.O_RDWR);
        if (fd < 0) return -1;

        MdIoctl md = default;
        md.Unit = (uint)unit;

        int rc = PayloadIo.ioctl(fd, DeviceControl.MdiocDetach, &md);
        PayloadIo.close(fd);
        return rc;
    }

    /// <summary>
    /// Attaches a file as an LVD virtual disk via <c>/dev/lvdctl</c> and returns the
    /// device identifier.
    /// </summary>
    /// <returns>The assigned device identifier on success, or -1 on error.</returns>
    public static int LvdAttach(uint sectorSize, uint imageType, ulong deviceSize)
    {
        byte* devPath = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'l', (byte)'v', (byte)'d', (byte)'c', (byte)'t', (byte)'l', 0 };

        int fd = PayloadIo.open(devPath, PayloadFileSystem.O_RDWR);
        if (fd < 0) return -1;

        LvdIoctlAttach attach = default;
        attach.SectorSize = sectorSize;
        attach.ImageType = imageType;
        attach.DeviceSize = deviceSize;
        attach.LayerCount = 1;

        int rc = PayloadIo.ioctl(fd, DeviceControl.SceLvdIocAttach, &attach);
        PayloadIo.close(fd);

        return rc == 0 ? (int)attach.DeviceId : -1;
    }

    /// <summary>
    /// Detaches an LVD virtual disk.
    /// </summary>
    public static int LvdDetach(int deviceId)
    {
        byte* devPath = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'l', (byte)'v', (byte)'d', (byte)'c', (byte)'t', (byte)'l', 0 };

        int fd = PayloadIo.open(devPath, PayloadFileSystem.O_RDWR);
        if (fd < 0) return -1;

        LvdIoctlDetach detach = default;
        detach.DeviceId = (uint)deviceId;

        int rc = PayloadIo.ioctl(fd, DeviceControl.SceLvdIocDetach, &detach);
        PayloadIo.close(fd);
        return rc;
    }

    /// <summary>
    /// Scans a directory for image files and returns the first one found, or null.
    /// </summary>
    public static ImageType FindImageInDirectory(byte* dirPath, byte* outPath, int outPathSize)
    {
        void* dir = PayloadFileSystem.opendir(dirPath);
        if (dir == null) return ImageType.Unknown;

        ImageType found = ImageType.Unknown;
        while (true)
        {
            FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
            if (entry == null) break;
            if (entry->d_type != PayloadFileSystem.DT_REG) continue;

            ImageType t = DetectType(entry->d_name);
            if (t != ImageType.Unknown)
            {
                int i = 0;
                byte* dp = dirPath;
                while (*dp != 0 && i < outPathSize - 2) { outPath[i++] = *dp; dp++; }
                outPath[i++] = (byte)'/';
                byte* np = entry->d_name;
                while (*np != 0 && i < outPathSize - 1) { outPath[i++] = *np; np++; }
                outPath[i] = 0;
                found = t;
                break;
            }
        }

        PayloadFileSystem.closedir(dir);
        return found;
    }

    /// <summary>
    /// Force-unmounts a UFS mount point and detaches all /dev/md devices (0-15).
    /// </summary>
    public static void UnmountUfs(byte* mountPoint)
    {
        if (mountPoint == null || *mountPoint == 0) return;

        FreeBsdStatfs sfs = default;
        if (PayloadMount.statfs(mountPoint, &sfs) == 0)
        {
            byte* ufsName = stackalloc byte[] { (byte)'u', (byte)'f', (byte)'s', 0 };
            if (FixedBytesEqual(sfs.f_fstypename, ufsName, 3))
                PayloadMount.unmount(mountPoint, PayloadMount.MntForce);
        }

        byte* devBuf = stackalloc byte[32];
        byte* mdPrefix = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'m', (byte)'d', 0 };
        for (int i = 0; i < 16; i++)
        {
            int pos = 0;
            byte* p = mdPrefix;
            while (*p != 0) devBuf[pos++] = *p++;
            WriteInt(devBuf, ref pos, i);
            devBuf[pos] = 0;

            if (PayloadFileSystem.access(devBuf, PayloadFileSystem.F_OK) == 0)
                MdDetach(i);
        }

        PayloadFileSystem.rmdir(mountPoint);
    }

    /// <summary>
    /// Force-unmounts an exFAT mount point and detaches all /dev/lvd (0-15) and
    /// /dev/md (0-15) devices.
    /// </summary>
    public static void UnmountExfat(byte* mountPoint)
    {
        if (mountPoint == null || *mountPoint == 0) return;

        FreeBsdStatfs sfs = default;
        if (PayloadMount.statfs(mountPoint, &sfs) == 0)
        {
            byte* exfatName = stackalloc byte[] {
                (byte)'e', (byte)'x', (byte)'f', (byte)'a', (byte)'t', (byte)'f', (byte)'s', 0 };
            if (FixedBytesEqual(sfs.f_fstypename, exfatName, 7))
                PayloadMount.unmount(mountPoint, PayloadMount.MntForce);
        }

        byte* devBuf = stackalloc byte[32];
        byte* lvdPrefix = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'l', (byte)'v', (byte)'d', 0 };
        for (int i = 0; i < 16; i++)
        {
            int pos = 0;
            byte* p = lvdPrefix;
            while (*p != 0) devBuf[pos++] = *p++;
            WriteInt(devBuf, ref pos, i);
            devBuf[pos] = 0;

            if (PayloadFileSystem.access(devBuf, PayloadFileSystem.F_OK) == 0)
                LvdDetach(i);
        }

        byte* mdPrefix = stackalloc byte[] {
            (byte)'/', (byte)'d', (byte)'e', (byte)'v', (byte)'/',
            (byte)'m', (byte)'d', 0 };
        for (int i = 0; i < 16; i++)
        {
            int pos = 0;
            byte* p = mdPrefix;
            while (*p != 0) devBuf[pos++] = *p++;
            WriteInt(devBuf, ref pos, i);
            devBuf[pos] = 0;

            if (PayloadFileSystem.access(devBuf, PayloadFileSystem.F_OK) == 0)
                MdDetach(i);
        }

        PayloadFileSystem.rmdir(mountPoint);
    }

    private static bool FixedBytesEqual(byte* a, byte* b, int len)
    {
        for (int i = 0; i < len; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    private static void WriteInt(byte* buf, ref int pos, int value)
    {
        if (value >= 10) WriteInt(buf, ref pos, value / 10);
        buf[pos++] = (byte)('0' + value % 10);
    }

    private static bool EndsWith(byte* str, int len, ReadOnlySpan<byte> suffix)
    {
        if (len < suffix.Length) return false;
        for (int i = 0; i < suffix.Length; i++)
        {
            byte c = str[len - suffix.Length + i];
            byte s = suffix[i];
            if (c >= (byte)'A' && c <= (byte)'Z') c += 32;
            if (s >= (byte)'A' && s <= (byte)'Z') s += 32;
            if (c != s) return false;
        }
        return true;
    }
}
