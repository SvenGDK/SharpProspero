// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Elf;

/// <summary>
/// Device control structures for md(4) memory disk and LVD virtual disk management.
/// </summary>
public static class DeviceControl
{
    /// <summary>md(4) MDIOCATTACH ioctl number (_IOWR('m', 0, struct md_ioctl), sizeof=444).</summary>
    public const ulong MdiocAttach = 0xC1BC6D00;

    /// <summary>md(4) MDIOCDETACH ioctl number (_IOWR('m', 1, struct md_ioctl), sizeof=444).</summary>
    public const ulong MdiocDetach = 0xC1BC6D01;

    /// <summary>LVD attach ioctl number.</summary>
    public const ulong SceLvdIocAttach = 0xC0286D00;

    /// <summary>LVD detach ioctl number.</summary>
    public const ulong SceLvdIocDetach = 0xC0286D01;

    /// <summary>md type: vnode-backed.</summary>
    public const int MdVnode = 2;

    /// <summary>md option: auto-assign unit number.</summary>
    public const int MdAutounit = 0x0004;

    /// <summary>md option: read-only.</summary>
    public const int MdReadonly = 0x0008;
}

/// <summary>
/// FreeBSD md(4) memory disk ioctl control structure (444 bytes, MDNPAD=97).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct MdIoctl
{
    /// <summary>Structure version (MDIOVERSION=0).</summary>
    public uint Version;

    /// <summary>Unit number (set by MDIOCATTACH when MdAutounit is used).</summary>
    public uint Unit;

    /// <summary>Disk type (<see cref="DeviceControl.MdVnode"/>).</summary>
    public int Type;

    private uint _alignPad;

    /// <summary>Path to the backing file (NUL-terminated).</summary>
    public byte* File;

    /// <summary>Total media size in bytes.</summary>
    public ulong Mediasize;

    /// <summary>Sector size in bytes (typically 512 or 2048).</summary>
    public uint Sectorsize;

    /// <summary>Option flags (<see cref="DeviceControl.MdAutounit"/> | <see cref="DeviceControl.MdReadonly"/>).</summary>
    public uint Options;

    /// <summary>Base address for preloaded disks.</summary>
    public ulong Base;

    /// <summary>Firmware-reported heads.</summary>
    public int FwHeads;

    /// <summary>Firmware-reported sectors.</summary>
    public int FwSectors;

    /// <summary>Padding for future extensions (MDNPAD=97).</summary>
    public fixed int Pad[97];
}

/// <summary>
/// LVD (logical volume device) attach parameters.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct LvdIoctlAttach
{
    /// <summary>Structure version.</summary>
    public uint IoVersion;

    /// <summary>Device identifier (output on attach).</summary>
    public uint DeviceId;

    /// <summary>Sector size.</summary>
    public uint SectorSize;

    /// <summary>Image type.</summary>
    public uint ImageType;

    /// <summary>Number of layers.</summary>
    public uint LayerCount;

    /// <summary>Total device size.</summary>
    public ulong DeviceSize;

    /// <summary>Layer descriptors.</summary>
    public fixed byte Layers[128];
}

/// <summary>
/// LVD detach parameters.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct LvdIoctlDetach
{
    /// <summary>Device identifier to detach.</summary>
    public uint DeviceId;
}
