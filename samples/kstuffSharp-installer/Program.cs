// Kernel module installer payload. Receives PayloadArgs, sets up the trace-based
// kernel function-call mechanism, and installs the kernel module (kelf + uelf)
// into kernel memory. This binary runs as a separately mapped ELF inside the
// loader process; the loader mmaps it at hint 0x926100000, copies its PT_LOAD
// segments, and calls the entry point.

using System;
using System.Runtime.InteropServices;

using SharpProspero.Payload;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Services;

namespace InstallerApp;

internal static unsafe class Program
{
    [UnmanagedCallersOnly(EntryPoint = "__managed__Main")]
    public static int Main(void* args)
    {
        PayloadCrt.Klog("installer: start\n\0"u8);

        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null)
        {
            PayloadCrt.Klog("installer: no args\n\0"u8);
            return -1;
        }

        long kekcallResult = PayloadKekcall.Invoke(-1);
        if (kekcallResult == 0)
        {
            PayloadCrt.Klog("installer: already loaded\n\0"u8);
            PayloadNotification.SendKernelNotification("kstuff: already loaded"u8);
            return 1;
        }

        PayloadKernelIo io = new(pargs);

        uint fw = PayloadKernel.GetFirmwareVersion(io);
        if (fw == 0)
        {
            PayloadCrt.Klog("installer: fw fail\n\0"u8);
            return -1;
        }
        PayloadCrt.Klog("installer: fw ok\n\0"u8);

        ReadOnlySpan<byte> kelfBlob = KernelModuleData.Kelf;
        ReadOnlySpan<byte> uelfBlob = KernelModuleData.Uelf;

        if (kelfBlob.Length == 0 || uelfBlob.Length == 0)
        {
            PayloadCrt.Klog("installer: blobs missing\n\0"u8);
            return -1;
        }

        PayloadCrt.Klog("installer: installing\n\0"u8);

        bool ok = KernelModuleInstaller.Install(io, kelfBlob, uelfBlob, fw);
        if (ok)
            PayloadCrt.Klog("installer: done\n\0"u8);
        else
            PayloadCrt.Klog("installer: failed\n\0"u8);

        return ok ? 0 : -1;
    }
}

internal static class KernelModuleData
{
    public static ReadOnlySpan<byte> Kelf => KernelModuleBlobs.Kelf;
    public static ReadOnlySpan<byte> Uelf => KernelModuleBlobs.Uelf;
}
