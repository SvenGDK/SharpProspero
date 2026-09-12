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
    /// tables. Returns <c>ulong.MaxValue</c> if the mapping is not present.
    /// </summary>
    /// <param name="io">Kernel I/O for reading page table entries.</param>
    /// <param name="cr3">The kernel CR3 value (physical address of PML4).</param>
    /// <param name="dmapBase">The direct physical memory map base
    /// (<c>DMAP_BASE</c>, typically <c>0xFFFF800000000000</c>).</param>
    /// <param name="va">The virtual address to translate.</param>
    /// <summary>Upper bound on physical addresses the on-device DMAP maps. The DMAP is
    /// a linear image of physical RAM, so a translation that resolves to an address
    /// beyond this bound points at MMIO or off-map space and cannot be dereferenced
    /// through the DMAP. Callers use this to reject bogus translations that would
    /// otherwise page-fault in the pipe primitive.</summary>
    public const ulong DmemMaxPhys = 0x1_0000_0000_0000UL;

    public static ulong VirtToPhys(PayloadKernelIo io, ulong cr3, ulong dmapBase, ulong va)
    {
        ulong pml4i = (va >> 39) & 0x1FF;
        ulong pdpti = (va >> 30) & 0x1FF;
        ulong pdi = (va >> 21) & 0x1FF;
        ulong pti = (va >> 12) & 0x1FF;

        ulong pml4e = io.ReadU64(dmapBase + (cr3 & 0x000FFFFFFFFFF000UL) + pml4i * 8);
        if ((pml4e & 1) == 0) return ulong.MaxValue;

        ulong pdpte = io.ReadU64(dmapBase + (pml4e & 0x000FFFFFFFFFF000UL) + pdpti * 8);
        if ((pdpte & 1) == 0) return ulong.MaxValue;
        if ((pdpte & 0x80) != 0)
        {
            ulong pa1 = (pdpte & 0x000FFFFFC0000000UL) | (va & 0x3FFFFFFFUL);
            return pa1 < DmemMaxPhys ? pa1 : ulong.MaxValue;
        }

        ulong pde = io.ReadU64(dmapBase + (pdpte & 0x000FFFFFFFFFF000UL) + pdi * 8);
        if ((pde & 1) == 0) return ulong.MaxValue;
        if ((pde & 0x80) != 0)
        {
            ulong pa2 = (pde & 0x000FFFFFFFE00000UL) | (va & 0x1FFFFFUL);
            return pa2 < DmemMaxPhys ? pa2 : ulong.MaxValue;
        }

        ulong pte = io.ReadU64(dmapBase + (pde & 0x000FFFFFFFFFF000UL) + pti * 8);
        if ((pte & 1) == 0) return ulong.MaxValue;

        ulong pa = (pte & 0x000FFFFFFFFFF000UL) | (va & 0xFFF);
        return pa < DmemMaxPhys ? pa : ulong.MaxValue;
    }

    /// <summary>
    /// Reloads CR3 through a kernel function call, flushing every non-global TLB
    /// entry. Callers must invoke this immediately after mutating a page table
    /// entry that may be cached by the CPU MMU; without the reload, executions
    /// on the modified virtual addresses can hit stale physical mappings until
    /// the TLB naturally evicts them.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="sysentsAddr">Address of the sysent table used by the trace kfncall.</param>
    /// <param name="kdataBase">Kernel data-section base address (from <c>PayloadArgs</c>).</param>
    public static void InvalidateTlb(PayloadKernelIo io, ulong sysentsAddr, ulong kdataBase)
    {
        // Both CR3 gadgets consume/produce their operand in RAX, so both hops
        // go through the single-step dispatch path that offers RAX control.
        // The standard kfncall path routes arguments through RDI/RSI/... and
        // never touches RAX, which would drive an uncontrolled kernel-residual
        // value into CR3 and triple-fault the CPU on the next instruction fetch.
        ulong readCr3Gadget = (ulong)((long)kdataBase + KernelOffsets.MovRaxCr3_1001);
        ulong cr3 = PayloadKfncall.RunGadgetWithRax(io, readCr3Gadget, 0);
        if (cr3 == 0) return;
        ulong writeCr3Gadget = (ulong)((long)kdataBase + KernelOffsets.MovCr3RaxMovDs_1001);
        PayloadKfncall.RunGadgetWithRax(io, writeCr3Gadget, cr3);
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
            if (pa == ulong.MaxValue) return false;
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
            if (pa == ulong.MaxValue) return false;
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
