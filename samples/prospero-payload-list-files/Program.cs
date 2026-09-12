// Escapes the sandbox jail by rewriting the process
// rootdir vnode to the kernel's real root, then recursively enumerates "/" with opendir/
// readdir and outputs the listing via klog. Restores the original rootdir when done.

using System;
using System.Runtime.InteropServices;
using SharpProspero.Payload;
using SharpProspero.Payload.IO;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Process;

namespace SampleApp;

internal static unsafe class Program
{
    [UnmanagedCallersOnly(EntryPoint = "__managed__Main")]
    public static int Main(void* args)
    {
        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null)
            return -1;

        var io = new PayloadKernelIo(pargs);

        // Save the current rootdir, then set it to the kernel root vnode.
        ulong rootvnode = PayloadKernel.GetRootVnode(io);
        int pid = PayloadProcessControl.getpid();
        ulong proc = PayloadKernel.FindProcessByPid(io, pid);
        if (proc == 0)
            return -2;

        ulong filedesc = io.ReadU64(proc + (ulong)KernelOffsets.ProcFd);
        ulong savedRootdir = io.ReadU64(filedesc + (ulong)KernelOffsets.FdRdir);

        // Escape jail: set rootdir to kernel's root vnode.
        io.WriteU64(filedesc + (ulong)KernelOffsets.FdRdir, rootvnode);

        // Enumerate root directory.
        fixed (byte* root = "/\0"u8)
        {
            ListDir(root);
        }

        // Restore the original rootdir.
        io.WriteU64(filedesc + (ulong)KernelOffsets.FdRdir, savedRootdir);

        return 0;
    }

    private static void ListDir(byte* basePath)
    {
        void* dir = PayloadFileSystem.opendir(basePath);
        if (dir == null)
            return;

        FreeBsdDirent* entry;
        while ((entry = PayloadFileSystem.readdir(dir)) != null)
        {
            byte* name = entry->d_name;

            // Skip "." and ".."
            if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
                continue;

            // Build full path and log it.
            byte* fullPath = stackalloc byte[1024];
            int pos = 0;
            for (int i = 0; basePath[i] != 0 && pos < 1000; i++)
                fullPath[pos++] = basePath[i];
            if (pos > 1 && fullPath[pos - 1] != '/')
                fullPath[pos++] = (byte)'/';
            for (int i = 0; name[i] != 0 && pos < 1020; i++)
                fullPath[pos++] = name[i];
            fullPath[pos++] = (byte)'\n';
            fullPath[pos] = 0;
            PayloadCrt.Klog(fullPath);
        }

        PayloadFileSystem.closedir(dir);
    }
}
