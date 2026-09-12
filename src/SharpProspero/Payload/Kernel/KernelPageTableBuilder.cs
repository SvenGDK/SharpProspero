// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// CR3/page table construction for mapping custom kernel code. Builds a private PML4
/// with mappings for a user-provided code region alongside the existing kernel mappings.
/// </summary>
public static unsafe class KernelPageTableBuilder
{
    /// <summary>
    /// Allocates and populates a new PML4 that mirrors the kernel's own mappings plus
    /// an additional mapping for custom code at the specified virtual address.
    /// </summary>
    /// <param name="io">Kernel I/O for reading the existing page tables.</param>
    /// <param name="kernelCr3">The kernel's current CR3 value.</param>
    /// <param name="dmapBase">Direct physical memory map base.</param>
    /// <param name="codePhys">Physical address of the custom code region.</param>
    /// <param name="codeVirt">Virtual address where the code should appear.</param>
    /// <param name="codeSize">Size of the code region in bytes.</param>
    /// <param name="mallocFn">Kernel address of <c>malloc</c> for allocating page tables.</param>
    /// <param name="sysentsAddr">Address of the sysent table for kfncall.</param>
    /// <returns>The physical address of the new PML4, or zero on failure.</returns>
    public static ulong Build(PayloadKernelIo io, ulong kernelCr3, ulong dmapBase,
        ulong codePhys, ulong codeVirt, ulong codeSize,
        ulong mallocFn, ulong sysentsAddr)
    {
        // Kernel malloc returns KERNEL VIRTUAL addresses, not physical ones.
        // Page table entries take physical addresses; the CPU MMU walks them
        // as physical bases when translating virtual accesses. Every malloc
        // result therefore needs a virt->phys pass before it can be stored
        // in a PML4E / PDPTE / PDE / PTE, or dereferenced via the DMAP.

        // Allocate a new PML4 page.
        ulong pml4Kva = PayloadKfncall.Call(io, sysentsAddr, mallocFn, 4096, 0);
        if (pml4Kva == 0) return 0;
        ulong pml4Phys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, pml4Kva);
        if (pml4Phys == ulong.MaxValue) return 0;

        ulong pml4Virt = dmapBase + pml4Phys;

        // Copy the kernel's PML4 entries.
        ulong kernelPml4 = dmapBase + (kernelCr3 & ~0xFFFUL);
        for (int i = 0; i < 512; i++)
        {
            ulong entry = io.ReadU64(kernelPml4 + (ulong)(i * 8));
            io.WriteU64(pml4Virt + (ulong)(i * 8), entry);
        }

        // Map the code region with 2 MB large pages.
        ulong pml4i = (codeVirt >> 39) & 0x1FF;
        ulong pdpti = (codeVirt >> 30) & 0x1FF;
        ulong pdi = (codeVirt >> 21) & 0x1FF;

        // Allocate PDPT and PD, translate each to physical for PTE storage.
        ulong pdptKva = PayloadKfncall.Call(io, sysentsAddr, mallocFn, 4096, 0);
        if (pdptKva == 0) return 0;
        ulong pdptPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, pdptKva);
        if (pdptPhys == ulong.MaxValue) return 0;

        ulong pdKva = PayloadKfncall.Call(io, sysentsAddr, mallocFn, 4096, 0);
        if (pdKva == 0) return 0;
        ulong pdPhys = KernelPaging.VirtToPhys(io, kernelCr3, dmapBase, pdKva);
        if (pdPhys == ulong.MaxValue) return 0;

        // Clear new tables via DMAP virtual addresses.
        for (int i = 0; i < 512; i++)
        {
            io.WriteU64(dmapBase + pdptPhys + (ulong)(i * 8), 0);
            io.WriteU64(dmapBase + pdPhys + (ulong)(i * 8), 0);
        }

        // Wire: PML4 -> PDPT -> PD -> 2MB pages (all PTE values are physical)
        io.WriteU64(pml4Virt + pml4i * 8, pdptPhys | 0x67); // Present + RW + User + Accessed + Dirty
        io.WriteU64(dmapBase + pdptPhys + pdpti * 8, pdPhys | 0x67);

        ulong pages = (codeSize + KernelPaging.LargePageSize - 1) / KernelPaging.LargePageSize;
        for (ulong p = 0; p < pages; p++)
        {
            ulong phys = codePhys + p * KernelPaging.LargePageSize;
            io.WriteU64(dmapBase + pdPhys + (pdi + p) * 8, phys | 0xE7); // PS=1 (2MB) + Present + RW + User + Accessed + Dirty
        }

        // Flush the TLB so the CPU picks up the fresh mappings on next access.
        // A same-CR3 reload evicts every non-global entry, which is what we want
        // after writing PML4 / PDPT / PD / PT entries in the new hierarchy.
        KernelPaging.InvalidateTlb(io, sysentsAddr, PayloadEntryPoint.Args->KernelDataBase);

        return pml4Phys;
    }
}
