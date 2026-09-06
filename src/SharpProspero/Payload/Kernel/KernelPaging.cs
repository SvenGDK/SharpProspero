// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Kernel virtual-to-physical address translation. Walks the 4-level x86-64 page table
/// structure (PML4 -> PDPT -> PD -> PT) using kernel memory reads to resolve a kernel
/// virtual address to its physical address.
/// </summary>
public static unsafe class KernelPaging
{
    /// <summary>Page size (4 KB).</summary>
    public const ulong PageSize = 0x1000;

    /// <summary>Large page size (2 MB).</summary>
    public const ulong LargePageSize = 0x200000;

    /// <summary>
    /// Translates a kernel virtual address to a physical address by walking the page
    /// tables. Returns zero if the mapping is not present.
    /// </summary>
    /// <param name="io">Kernel I/O for reading page table entries.</param>
    /// <param name="cr3">The kernel CR3 value (physical address of PML4).</param>
    /// <param name="dmapBase">The direct physical memory map base
    /// (<c>DMAP_BASE</c>, typically <c>0xFFFF800000000000</c>).</param>
    /// <param name="va">The virtual address to translate.</param>
    public static ulong VirtToPhys(PayloadKernelIo io, ulong cr3, ulong dmapBase, ulong va)
    {
        ulong pml4i = (va >> 39) & 0x1FF;
        ulong pdpti = (va >> 30) & 0x1FF;
        ulong pdi = (va >> 21) & 0x1FF;
        ulong pti = (va >> 12) & 0x1FF;

        ulong pml4e = io.ReadU64(dmapBase + (cr3 & 0x000FFFFFFFFFF000UL) + pml4i * 8);
        if ((pml4e & 1) == 0) return 0;

        ulong pdpte = io.ReadU64(dmapBase + (pml4e & 0x000FFFFFFFFFF000UL) + pdpti * 8);
        if ((pdpte & 1) == 0) return 0;
        if ((pdpte & 0x80) != 0) return (pdpte & 0x000FFFFFC0000000UL) | (va & 0x3FFFFFFFUL); // 1 GB page

        ulong pde = io.ReadU64(dmapBase + (pdpte & 0x000FFFFFFFFFF000UL) + pdi * 8);
        if ((pde & 1) == 0) return 0;
        if ((pde & 0x80) != 0) return (pde & 0x000FFFFFFFE00000UL) | (va & 0x1FFFFFUL); // 2 MB page

        ulong pte = io.ReadU64(dmapBase + (pde & 0x000FFFFFFFFFF000UL) + pti * 8);
        if ((pte & 1) == 0) return 0;

        return (pte & 0x000FFFFFFFFFF000UL) | (va & 0xFFF);
    }

    /// <summary>
    /// Copies data to a kernel virtual address through the direct physical memory map.
    /// Loops over page-sized chunks, calling <see cref="VirtToPhys"/> for each chunk so
    /// that cross-page copies succeed even when the pages are not physically contiguous.
    /// </summary>
    public static bool PhysCopyin(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong kva, void* src, int len)
    {
        byte* s = (byte*)src;
        while (len > 0)
        {
            ulong pa = VirtToPhys(io, cr3, dmapBase, kva);
            if (pa == 0) return false;
            int pageRemaining = (int)(0x1000 - (kva & 0xFFF));
            int chunk = Math.Min(pageRemaining, len);
            io.Write(dmapBase + pa, s, chunk);
            kva += (ulong)chunk;
            s += chunk;
            len -= chunk;
        }
        return true;
    }

    /// <summary>
    /// Copies data from a kernel virtual address through the direct physical memory map.
    /// Loops over page-sized chunks, calling <see cref="VirtToPhys"/> for each chunk so
    /// that cross-page copies succeed even when the pages are not physically contiguous.
    /// </summary>
    public static bool PhysCopyout(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong kva, void* dst, int len)
    {
        byte* d = (byte*)dst;
        while (len > 0)
        {
            ulong pa = VirtToPhys(io, cr3, dmapBase, kva);
            if (pa == 0) return false;
            int pageRemaining = (int)(0x1000 - (kva & 0xFFF));
            int chunk = Math.Min(pageRemaining, len);
            io.Read(dmapBase + pa, d, chunk);
            kva += (ulong)chunk;
            d += chunk;
            len -= chunk;
        }
        return true;
    }

    /// <summary>
    /// Derives the CR3 page-table root for a process identified by PID.
    /// Walks the allproc list, reads <c>proc->p_vmspace->vm_pmap.pm_cr3</c>.
    /// </summary>
    /// <param name="io">Kernel I/O for reading process structures.</param>
    /// <param name="pid">The target process identifier.</param>
    /// <param name="fwMajorMinor">Firmware major.minor (e.g. 0x1001 for FW 10.01).</param>
    /// <returns>The process CR3, or zero if the process cannot be found.</returns>
    public static ulong GetProcessCr3(PayloadKernelIo io, int pid, uint fwMajorMinor)
    {
        ulong proc = PayloadKernel.WalkAllprocForPid(io, pid);
        if (proc == 0) return 0;

        ulong vmspace = io.ReadU64(proc + (ulong)KernelOffsets.ProcVmspace);
        if (vmspace == 0) return 0;

        int pmapOff = KernelOffsets.VmspacePmapOffset(fwMajorMinor);
        ulong pmCr3 = io.ReadU64(vmspace + (ulong)pmapOff + 40);
        return pmCr3;
    }
}
