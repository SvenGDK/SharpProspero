// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.IO;
using System;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// Advanced kernel page table operations: superpage splitting, page remapping, and
/// kernel-to-userspace page mirroring. Extends <see cref="KernelPaging"/> with write
/// operations on page table entries.
/// </summary>
public static unsafe class PayloadKernelPagingAdvanced
{
    /// <summary>PDE PS (Page Size) bit — set for 2 MB large pages.</summary>
    public const ulong PdePsBit = 0x80;

    /// <summary>Maximum number of tracked mirrors.</summary>
    public const int MaxMirrors = 256;

    private static readonly ulong[] MirrorOrigPte = new ulong[MaxMirrors];
    private static readonly ulong[] MirrorPteAddr = new ulong[MaxMirrors];
    private static int _mirrorCount;

    /// <summary>
    /// Splits a 2 MB kernel superpage into 512 individual 4 KB page table entries so
    /// that per-page PTE flags (RW, NX) can be set independently. Allocates a new PT
    /// page and populates it with 512 entries pointing at the same physical region.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="cr3">Kernel CR3.</param>
    /// <param name="dmapBase">Direct physical memory map base.</param>
    /// <param name="va">A virtual address within the 2 MB page to split.</param>
    /// <param name="mallocFn">Kernel address of <c>malloc</c>.</param>
    /// <param name="sysentsAddr">Sysent table address for kfncall.</param>
    /// <returns><see langword="true"/> if the superpage was split.</returns>
    public static bool DowngradeSuperpage(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong va, ulong mallocFn, ulong sysentsAddr)
    {
        ulong pml4i = (va >> 39) & 0x1FF;
        ulong pdpti = (va >> 30) & 0x1FF;
        ulong pdi = (va >> 21) & 0x1FF;

        ulong pml4e = io.ReadU64(dmapBase + (cr3 & 0x000FFFFFFFFFF000UL) + pml4i * 8);
        if ((pml4e & 1) == 0) return false;

        ulong pdpte = io.ReadU64(dmapBase + (pml4e & 0x000FFFFFFFFFF000UL) + pdpti * 8);
        if ((pdpte & 1) == 0) return false;

        ulong pdeAddr = dmapBase + (pdpte & 0x000FFFFFFFFFF000UL) + pdi * 8;
        ulong pde = io.ReadU64(pdeAddr);
        if ((pde & 1) == 0 || (pde & PdePsBit) == 0) return false; // Not a superpage

        ulong basePhys = pde & 0x000FFFFFFFE00000UL;
        ulong flags = (pde & 0xFFF) | (pde & 0x8000000000000000UL); // Preserve flags + NX bit
        flags &= ~PdePsBit; // Clear PS bit

        // Allocate a new 4 KB page table page. Kernel malloc returns a KERNEL
        // VIRTUAL address; a PDE entry takes the PT's physical base, so the
        // malloc result must be translated via VirtToPhys before it can be
        // stored in pdeAddr or used to reach the PT through the DMAP.
        ulong ptKva = PayloadKfncall.Call(io, sysentsAddr, mallocFn, 4096, 0);
        if (ptKva == 0) return false;
        ulong ptPhys = KernelPaging.VirtToPhys(io, cr3, dmapBase, ptKva);
        if (ptPhys == ulong.MaxValue) return false;

        // Fill 512 PTEs pointing at consecutive 4 KB pages within the 2 MB region.
        ulong ptVirt = dmapBase + ptPhys;
        for (int i = 0; i < 512; i++)
        {
            ulong pte = basePhys + (ulong)(i * 4096) | (flags & ~PdePsBit) | 1;
            io.WriteU64(ptVirt + (ulong)(i * 8), pte);
        }

        // Replace the 2 MB PDE with a pointer to the new PT page.
        io.WriteU64(pdeAddr, ptPhys | (flags & 0x67)); // Present + RW + User + Accessed

        // Flush the TLB so subsequent accesses to the split range use the new
        // 4 KB PTEs instead of the cached 2 MB superpage mapping.
        KernelPaging.InvalidateTlb(io, sysentsAddr, PayloadEntryPoint.Args->KernelDataBase);

        return true;
    }

    /// <summary>
    /// Changes the physical address backing a virtual page by rewriting the PTE.
    /// Returns the original physical address for later restoration.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="cr3">Kernel CR3.</param>
    /// <param name="dmapBase">Direct physical memory map base.</param>
    /// <param name="va">The virtual address whose mapping to change.</param>
    /// <param name="newPhys">The new physical address to map.</param>
    /// <returns>The original physical address, or zero on failure.</returns>
    public static ulong RemapPage(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong va, ulong newPhys)
    {
        ulong pteAddr = FindPteAddr(io, cr3, dmapBase, va);
        if (pteAddr == 0) return 0;

        ulong oldPte = io.ReadU64(pteAddr);
        ulong oldPhys = oldPte & 0x000FFFFFFFFFF000UL;
        ulong flags = (oldPte & 0xFFF) | (oldPte & 0x8000000000000000UL); // Preserve NX

        io.WriteU64(pteAddr, (newPhys & 0x000FFFFFFFFFF000UL) | flags);
        return oldPhys;
    }

    /// <summary>
    /// Maps a kernel physical page into the calling process's address space by replacing
    /// an anonymous user page's PTE with the kernel page's physical address. Tracks the
    /// original PTE for restoration via <see cref="ResetMirrors"/>.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="cr3">Kernel CR3.</param>
    /// <param name="dmapBase">Direct physical memory map base.</param>
    /// <param name="userVa">A user-space virtual address backed by an anonymous page.</param>
    /// <param name="kernelPhys">The kernel physical address to mirror.</param>
    /// <returns><see langword="true"/> if the mirror was installed.</returns>
    public static bool MirrorPage(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong userVa, ulong kernelPhys)
    {
        if (_mirrorCount >= MaxMirrors) return false;

        ulong pteAddr = FindPteAddr(io, cr3, dmapBase, userVa);
        if (pteAddr == 0) return false;

        ulong origPte = io.ReadU64(pteAddr);
        MirrorOrigPte[_mirrorCount] = origPte;
        MirrorPteAddr[_mirrorCount] = pteAddr;
        _mirrorCount++;

        ulong flags = (origPte & 0xFFF) | (origPte & 0x8000000000000000UL); // Preserve NX
        io.WriteU64(pteAddr, (kernelPhys & 0x000FFFFFFFFFF000UL) | flags);
        return true;
    }

    /// <summary>
    /// Mirrors a contiguous range of kernel physical pages into user address space.
    /// </summary>
    public static bool MirrorPageRange(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong userVa, ulong kernelPhys, int pageCount)
    {
        for (int i = 0; i < pageCount; i++)
        {
            if (!MirrorPage(io, cr3, dmapBase,
                userVa + (ulong)(i * 4096), kernelPhys + (ulong)(i * 4096)))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Restores all mirrored pages to their original physical addresses.
    /// </summary>
    public static void ResetMirrors(PayloadKernelIo io)
    {
        for (int i = _mirrorCount - 1; i >= 0; i--)
            io.WriteU64(MirrorPteAddr[i], MirrorOrigPte[i]);
        _mirrorCount = 0;
    }

    /// <summary>
    /// Scans a kernel text region through the DMAP for x86 E8 CALL opcodes whose rel32
    /// target matches the given function address. Returns matching call-site addresses.
    /// </summary>
    /// <param name="io">Kernel I/O.</param>
    /// <param name="dmapBase">Direct physical memory map base.</param>
    /// <param name="cr3">Kernel CR3 for address translation.</param>
    /// <param name="textStart">Start of the kernel text section.</param>
    /// <param name="textSize">Size of the kernel text section.</param>
    /// <param name="targetFunc">The function address that calls should target.</param>
    /// <param name="results">Buffer to receive matching call-site addresses.</param>
    /// <param name="maxResults">Maximum number of results.</param>
    /// <returns>Number of matches found.</returns>
    public static int ScanKernelCalls(PayloadKernelIo io, ulong dmapBase, ulong cr3,
        ulong textStart, ulong textSize, ulong targetFunc,
        Span<ulong> results, int maxResults)
    {
        int count = 0;
        byte* buf = stackalloc byte[4100]; // 4096 + 4 overflow for boundary CALL detection

        for (ulong offset = 0; offset < textSize && count < maxResults; offset += 4096)
        {
            ulong va = textStart + offset;
            ulong pa = KernelPaging.VirtToPhys(io, cr3, dmapBase, va);
            if (pa == ulong.MaxValue) continue;

            int pageLen = (int)Math.Min(4096, textSize - offset);
            io.Read(dmapBase + pa, buf, pageLen);

            // Read up to 4 overflow bytes from the next page for boundary CALL detection.
            int overflowLen = 0;
            if (offset + 4096 < textSize)
            {
                ulong nextPa = KernelPaging.VirtToPhys(io, cr3, dmapBase, va + 4096);
                if (nextPa != ulong.MaxValue)
                {
                    overflowLen = (int)Math.Min(4, textSize - offset - 4096);
                    io.Read(dmapBase + nextPa, buf + 4096, overflowLen);
                }
            }

            int readable = pageLen + overflowLen;
            for (int i = 0; i < pageLen && count < maxResults; i++)
            {
                if (buf[i] == 0xE8 && i + 5 <= readable)
                {
                    int rel32 = *(int*)(buf + i + 1);
                    ulong callTarget = va + (ulong)i + 5 + (ulong)(long)rel32;
                    if (callTarget == targetFunc)
                        results[count++] = va + (ulong)i;
                }
            }
        }

        return count;
    }

    private static ulong FindPteAddr(PayloadKernelIo io, ulong cr3, ulong dmapBase, ulong va)
    {
        ulong pml4i = (va >> 39) & 0x1FF;
        ulong pdpti = (va >> 30) & 0x1FF;
        ulong pdi = (va >> 21) & 0x1FF;
        ulong pti = (va >> 12) & 0x1FF;

        ulong pml4e = io.ReadU64(dmapBase + (cr3 & 0x000FFFFFFFFFF000UL) + pml4i * 8);
        if ((pml4e & 1) == 0) return 0;

        ulong pdpte = io.ReadU64(dmapBase + (pml4e & 0x000FFFFFFFFFF000UL) + pdpti * 8);
        if ((pdpte & 1) == 0 || (pdpte & 0x80) != 0) return 0;

        ulong pde = io.ReadU64(dmapBase + (pdpte & 0x000FFFFFFFFFF000UL) + pdi * 8);
        if ((pde & 1) == 0 || (pde & 0x80) != 0) return 0;

        return dmapBase + (pde & 0x000FFFFFFFFFF000UL) + pti * 8;
    }
}

/// <summary>
/// SELF file enumeration. Scans a directory for files with the SELF magic value.
/// </summary>
public static unsafe class PayloadSelfEnumerator
{
    /// <summary>
    /// Scans a directory for SELF files by reading the first 4 bytes of each regular
    /// file and checking for the SELF magic.
    /// </summary>
    /// <param name="dirPath">NUL-terminated directory path.</param>
    /// <param name="results">Buffer to receive NUL-terminated filenames (packed).</param>
    /// <param name="resultSize">Size of the results buffer.</param>
    /// <returns>Number of SELF files found.</returns>
    public static int FindSelfFiles(byte* dirPath, byte* results, int resultSize)
    {
        void* dir = PayloadFileSystem.opendir(dirPath);
        if (dir == null) return 0;

        int count = 0;
        int pos = 0;

        byte* fullPath = stackalloc byte[1024];

        while (true)
        {
            FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
            if (entry == null) break;
            if (entry->d_type != PayloadFileSystem.DT_REG) continue;
            int i = 0;
            byte* dp = dirPath;
            while (*dp != 0) { if (i >= 1023) break; fullPath[i++] = *dp++; }
            if (i < 1023) fullPath[i++] = (byte)'/';
            byte* np = entry->d_name;
            while (*np != 0) { if (i >= 1023) break; fullPath[i++] = *np++; }
            fullPath[i] = 0;

            int fd = PayloadIo.open(fullPath, PayloadFileSystem.O_RDONLY);
            if (fd < 0) continue;

            uint magic = 0;
            PayloadIo.read(fd, &magic, 4);
            PayloadIo.close(fd);

            if (magic == PayloadSelfDecryptor.SelfMagicProspero ||
                magic == PayloadSelfDecryptor.SelfMagicOrbis)
            {
                int nameLen = 0;
                byte* n = entry->d_name;
                while (n[nameLen] != 0) nameLen++;

                if (pos + nameLen + 1 < resultSize)
                {
                    for (int j = 0; j < nameLen; j++) results[pos++] = n[j];
                    results[pos++] = 0;
                    count++;
                }
            }
        }

        PayloadFileSystem.closedir(dir);
        return count;
    }
}
