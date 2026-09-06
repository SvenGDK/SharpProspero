// SharpProspero.Link - a linker for module output.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpProspero.Link;

/// <summary>
/// Wraps emitted kernel module machine code into ELF64 binaries that the kernel module
/// installer loads into kernel memory via its <c>LoadKelf</c> function.
///
/// <para>Two binaries are produced:</para>
/// <list type="bullet">
///   <item><strong>kelf</strong>: Contains the IDT handler stubs (INT13, INT1, INT3) and
///         a 48-byte entry descriptor table at the entry point. The descriptor table
///         holds the handler code addresses and IST stack values that the installer reads
///         to patch the IDT and TSS.</item>
///   <item><strong>uelf</strong>: Contains the dispatcher and all subsystem handlers. Its
///         entry point is the dispatcher function.</item>
/// </list>
///
/// <para>Both are standard ELF64 with FreeBSD OS/ABI, position-independent (ET_DYN),
/// and use only program headers (no section headers). External patch targets are
/// undefined symbols resolved at load time from the installer's firmware offset table.
/// Internal function references within the same binary use R_X86_64_RELATIVE relocations
/// for base-relative address fixup.</para>
///
/// <para>The <c>LoadKelf</c> ELF loader reads PT_LOAD and PT_DYNAMIC program headers,
/// copies loadable segments to kernel memory, then processes relocations by resolving
/// symbol names against the installer's address table. R_X86_64_64 and R_X86_64_GLOB_DAT
/// relocations write <c>addend + resolved_value</c> at the patch site. R_X86_64_RELATIVE
/// relocations write <c>mapped_base + addend</c>.</para>
/// </summary>
public static class KernelModuleElfWriter
{
    // ---- ELF identification constants ----

    private const byte ElfClass64 = 2;
    private const byte ElfData2Lsb = 1;
    private const byte EvCurrent = 1;
    private const byte OsabiFreeBsd = 9;

    // ---- ELF header field values ----

    private const ushort EtDyn = 3;
    private const ushort EmX8664 = 62;

    // ---- Program header types ----

    private const uint PtLoad = 1;
    private const uint PtDynamic = 2;

    // ---- Segment permission flags ----

    private const uint PfR = 4;
    private const uint PfW = 2;
    private const uint PfX = 1;

    // ---- Dynamic section tags ----

    private const long DtNull = 0;
    private const long DtStrtab = 5;
    private const long DtSymtab = 6;
    private const long DtRela = 7;
    private const long DtRelasz = 8;

    // ---- Relocation types ----

    private const uint Rel64 = 1; // R_X86_64_64
    private const uint RelRelative = 8; // R_X86_64_RELATIVE

    // ---- Symbol table constants ----

    private const byte StbGlobal = 1;

    // ---- Structure sizes (bytes) ----

    private const int EhdrSize = 64;
    private const int PhdrSize = 56;
    private const int SymEntSize = 24;
    private const int RelaEntSize = 24;
    private const int DynEntSize = 16;
    private const int DynEntCount = 5; // DT_STRTAB + DT_SYMTAB + DT_RELA + DT_RELASZ + DT_NULL
    private const int HeadersSize = EhdrSize + 2 * PhdrSize; // 176

    /// <summary>
    /// Size of the kelf entry descriptor table. The installer reads handler addresses
    /// and IST stack values from this table at offsets +0, +8, +16, +24, +32, +40.
    /// </summary>
    private const int KelfEntryTableSize = 48;

    /// <summary>
    /// Maps emitter dispatch patch target names to the symbol names that the
    /// installer's <c>LoadKelf</c> resolves from the firmware offset table.
    /// Names absent from this map pass through unchanged.
    /// </summary>
    private static readonly Dictionary<string, string> SymbolNameMap = new()
    {
        // Kernel IDT handler addresses (re-injection targets)
        ["native_int1_handler"] = "int1_handler",
        ["native_int3_handler"] = "int3_handler",
        ["native_int13_handler"] = "int13_handler",

        // Data area base addresses
        ["dmem_base"] = "dmem",
        ["shared_area_base"] = "shared_area",

        // Sysent table base addresses
        ["sysent_table"] = "sysents",
        ["sysents_ps4_table"] = "sysents_ps4",

        // TSS base address (one-shot per-CPU symbol)
        ["tss_base"] = "tss",

        // Mailbox return address comparison targets (fpkg subsystem)
        ["mailbox_lr_verifySuperBlock"] = "sceSblServiceMailbox_lr_verifySuperBlock",
        ["mailbox_lr_clearKey_1"] = "sceSblServiceMailbox_lr_sceSblPfsClearKey_1",
        ["mailbox_lr_clearKey_2"] = "sceSblServiceMailbox_lr_sceSblPfsClearKey_2",

        // Mailbox return address comparison targets (fself subsystem)
        ["mailbox_lr_fself_verifyHeader"] = "sceSblServiceMailbox_lr_verifyHeader",
        ["mailbox_lr_fself_loadSelfSegment"] = "sceSblServiceMailbox_lr_loadSelfSegment",
        ["mailbox_lr_fself_decryptSelfBlock"] = "sceSblServiceMailbox_lr_decryptSelfBlock",
        ["mailbox_lr_fself_decryptMultipleSelfBlocks"] = "sceSblServiceMailbox_lr_decryptMultipleSelfBlocks",

        // Mailbox return address comparison targets (npdrm subsystem)
        ["mailbox_lr_npdrm_cmd_5"] = "sceSblServiceMailbox_lr_npdrm_cmd_5",
        ["mailbox_lr_npdrm_cmd_6"] = "sceSblServiceMailbox_lr_npdrm_cmd_6",
    };

    /// <summary>
    /// Translates a dispatch patch target name to the corresponding ELF symbol name.
    /// </summary>
    private static string MapSymbolName(string targetName)
    {
        return SymbolNameMap.TryGetValue(targetName, out string? mapped) ? mapped : targetName;
    }

    /// <summary>
    /// Wraps the kelf portion of the kernel module into an ELF64 binary. The kelf
    /// contains a 48-byte entry descriptor table followed by the IDT handler stubs
    /// (INT13, INT1, INT3).
    ///
    /// <para>The entry descriptor table at vaddr 0 has the following layout:</para>
    /// <list type="table">
    ///   <listheader><term>Offset</term><description>Content</description></listheader>
    ///   <item><term>+0x00</term><description>INT13 handler code address (R_X86_64_RELATIVE)</description></item>
    ///   <item><term>+0x08</term><description>IST3 stack value (<c>ist_errc</c> symbol)</description></item>
    ///   <item><term>+0x10</term><description>INT1 handler code address (R_X86_64_RELATIVE)</description></item>
    ///   <item><term>+0x18</term><description>IST4 stack value (<c>ist_noerrc</c> symbol)</description></item>
    ///   <item><term>+0x20</term><description>INT3 handler code address (R_X86_64_RELATIVE)</description></item>
    ///   <item><term>+0x28</term><description>IST7 stack value (<c>ist4</c> symbol)</description></item>
    /// </list>
    /// </summary>
    /// <param name="module">The kernel module output from the writer.</param>
    /// <returns>A complete ELF64 binary ready for the installer's <c>LoadKelf</c>.</returns>
    public static byte[] BuildKelf(KernelModuleOutput module)
    {
        int splitOffset = module.DispatcherOffset;

        // Mapped data: 48-byte entry descriptor followed by handler stub code
        byte[] codeData = new byte[KelfEntryTableSize + splitOffset];
        Array.Copy(module.Code, 0, codeData, KelfEntryTableSize, splitOffset);

        var symbolNames = new List<string>();
        var symbolIndex = new Dictionary<string, int>();
        var relocations = new List<ElfRelocation>();

        // ---- Entry descriptor table relocations ----

        // Handler addresses: R_X86_64_RELATIVE to handler code within the kelf
        relocations.Add(ElfRelocation.Relative(0,
            KelfEntryTableSize + module.Int13EntryOffset));
        relocations.Add(ElfRelocation.Relative(16,
            KelfEntryTableSize + module.Int1EntryOffset));
        relocations.Add(ElfRelocation.Relative(32,
            KelfEntryTableSize + module.Int3EntryOffset));

        // IST stack values: R_X86_64_64 to installer-resolved per-CPU symbols
        relocations.Add(ElfRelocation.Symbol(8,
            GetOrAddSymbol("ist_errc", symbolNames, symbolIndex)));
        relocations.Add(ElfRelocation.Symbol(24,
            GetOrAddSymbol("ist_noerrc", symbolNames, symbolIndex)));
        relocations.Add(ElfRelocation.Symbol(40,
            GetOrAddSymbol("ist4", symbolNames, symbolIndex)));

        // ---- CR3 page table address -> "uelf_cr3" symbol ----

        int uelfCr3Sym = GetOrAddSymbol("uelf_cr3", symbolNames, symbolIndex);
        foreach (int off in module.Cr3PatchOffsets)
        {
            if (off >= 0 && off + 8 <= splitOffset)
                relocations.Add(ElfRelocation.Symbol(KelfEntryTableSize + off, uelfCr3Sym));
        }

        // ---- Handle function address -> "uelf_entry" symbol ----

        int uelfEntrySym = GetOrAddSymbol("uelf_entry", symbolNames, symbolIndex);
        foreach (int off in module.HandleFnPatchOffsets)
        {
            if (off >= 0 && off + 8 <= splitOffset)
                relocations.Add(ElfRelocation.Symbol(KelfEntryTableSize + off, uelfEntrySym));
        }

        // ---- Dispatch patch sites within kelf code range ----

        foreach (var kvp in module.DispatchPatchSites)
        {
            string target = kvp.Key;
            bool isInternal = module.InternalTargets.ContainsKey(target);

            foreach (int off in kvp.Value)
            {
                if (off < 0 || off + 8 > splitOffset)
                    continue;

                int vaddr = KelfEntryTableSize + off;

                if (isInternal)
                {
                    int targetOff = module.InternalTargets[target];
                    if (targetOff < splitOffset)
                        relocations.Add(ElfRelocation.Relative(vaddr,
                            KelfEntryTableSize + targetOff));
                }
                else
                {
                    string symName = MapSymbolName(target);
                    int si = GetOrAddSymbol(symName, symbolNames, symbolIndex);
                    relocations.Add(ElfRelocation.Symbol(vaddr, si));
                }
            }
        }

        // e_entry = 0 (entry descriptor table at vaddr 0)
        return BuildElf(codeData, 0, symbolNames, relocations);
    }

    /// <summary>
    /// Wraps the uelf portion of the kernel module into an ELF64 binary. The uelf
    /// contains the dispatcher and all subsystem handlers. Its entry point is the
    /// dispatcher function at vaddr 0.
    /// </summary>
    /// <param name="module">The kernel module output from the writer.</param>
    /// <returns>A complete ELF64 binary ready for the installer's <c>LoadKelf</c>.</returns>
    public static byte[] BuildUelf(KernelModuleOutput module)
    {
        int splitOffset = module.DispatcherOffset;
        int uelfLen = module.Code.Length - splitOffset;

        byte[] codeData = new byte[uelfLen];
        Array.Copy(module.Code, splitOffset, codeData, 0, uelfLen);

        var symbolNames = new List<string>();
        var symbolIndex = new Dictionary<string, int>();
        var relocations = new List<ElfRelocation>();

        // ---- Dispatch patch sites within uelf code range ----

        foreach (var kvp in module.DispatchPatchSites)
        {
            string target = kvp.Key;
            bool isInternal = module.InternalTargets.ContainsKey(target);

            foreach (int off in kvp.Value)
            {
                if (off < splitOffset || off + 8 > module.Code.Length)
                    continue;

                int adjOff = off - splitOffset;

                if (isInternal)
                {
                    int targetOff = module.InternalTargets[target] - splitOffset;
                    relocations.Add(ElfRelocation.Relative(adjOff, targetOff));
                }
                else
                {
                    string symName = MapSymbolName(target);
                    int si = GetOrAddSymbol(symName, symbolNames, symbolIndex);
                    relocations.Add(ElfRelocation.Symbol(adjOff, si));
                }
            }
        }

        // e_entry = 0 (dispatcher at vaddr 0)
        return BuildElf(codeData, 0, symbolNames, relocations);
    }

    // ---- Symbol table helper ----

    /// <summary>
    /// Returns the 1-based symbol index for a name, adding it to the symbol list
    /// if not already present. Index 0 is reserved for the mandatory null entry.
    /// </summary>
    private static int GetOrAddSymbol(string name, List<string> names,
        Dictionary<string, int> index)
    {
        if (index.TryGetValue(name, out int idx))
            return idx;

        idx = names.Count + 1;
        names.Add(name);
        index[name] = idx;
        return idx;
    }

    // ---- ELF binary builder ----

    /// <summary>
    /// Builds a complete ELF64 binary from a code/data blob, a symbol list, and
    /// a set of relocations.
    ///
    /// <para>File layout:</para>
    /// <list type="number">
    ///   <item>ELF header (64 bytes)</item>
    ///   <item>Program header 0: PT_LOAD (56 bytes)</item>
    ///   <item>Program header 1: PT_DYNAMIC (56 bytes)</item>
    ///   <item>Mapped data (code/data blob + string table + symbol table +
    ///         relocation table + dynamic table)</item>
    /// </list>
    ///
    /// <para>The PT_LOAD segment maps from file offset <c>HeadersSize</c> to virtual
    /// address 0, covering all mapped data. This makes virtual address == position
    /// within the mapped region, so <c>virt2file(vaddr) = vaddr + HeadersSize</c>.</para>
    /// </summary>
    private static byte[] BuildElf(byte[] codeData, int entryOffset,
        List<string> symbolNames, List<ElfRelocation> relocations)
    {
        // ---- Build string table ----

        byte[] strtab;
        int[] nameOffsets;
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(0); // Leading NUL (null symbol name)
            nameOffsets = new int[symbolNames.Count];
            for (int i = 0; i < symbolNames.Count; i++)
            {
                nameOffsets[i] = (int)ms.Position;
                byte[] nameBytes = Encoding.UTF8.GetBytes(symbolNames[i]);
                ms.Write(nameBytes, 0, nameBytes.Length);
                ms.WriteByte(0); // NUL terminator
            }
            strtab = ms.ToArray();
        }

        // ---- Compute layout ----

        int codeDataSize = codeData.Length;
        int strtabSize = strtab.Length;
        int strtabVaddr = codeDataSize;

        // Symbol table must be 8-byte aligned (accessed as uint64_t* by the loader)
        int symtabPad = AlignPadding(codeDataSize + strtabSize, 8);
        int numSyms = symbolNames.Count + 1; // +1 null entry
        int symtabSize = numSyms * SymEntSize;
        int symtabVaddr = codeDataSize + strtabSize + symtabPad;

        int relaSize = relocations.Count * RelaEntSize;
        int relaVaddr = symtabVaddr + symtabSize;

        int dynSize = DynEntCount * DynEntSize;
        int dynVaddr = relaVaddr + relaSize;

        int mappedSize = dynVaddr + dynSize;
        int totalFileSize = HeadersSize + mappedSize;

        byte[] elf = new byte[totalFileSize];

        // ---- ELF header (64 bytes at offset 0) ----

        int p = 0;

        // e_ident[16]
        elf[p++] = 0x7F;
        elf[p++] = (byte)'E';
        elf[p++] = (byte)'L';
        elf[p++] = (byte)'F';
        elf[p++] = ElfClass64;
        elf[p++] = ElfData2Lsb;
        elf[p++] = EvCurrent;
        elf[p++] = OsabiFreeBsd;
        p += 8; // EI_ABIVERSION + padding

        WriteU16(elf, ref p, EtDyn);              // e_type
        WriteU16(elf, ref p, EmX8664);             // e_machine
        WriteU32(elf, ref p, 1);                   // e_version
        WriteU64(elf, ref p, (ulong)entryOffset);  // e_entry
        WriteU64(elf, ref p, EhdrSize);            // e_phoff
        WriteU64(elf, ref p, 0);                   // e_shoff (no sections)
        WriteU32(elf, ref p, 0);                   // e_flags
        WriteU16(elf, ref p, (ushort)EhdrSize);    // e_ehsize
        WriteU16(elf, ref p, (ushort)PhdrSize);    // e_phentsize
        WriteU16(elf, ref p, 2);                   // e_phnum
        WriteU16(elf, ref p, 0);                   // e_shentsize
        WriteU16(elf, ref p, 0);                   // e_shnum
        WriteU16(elf, ref p, 0);                   // e_shstrndx

        // ---- Program header 0: PT_LOAD (maps all data at vaddr 0) ----

        WriteU32(elf, ref p, PtLoad);                     // p_type
        WriteU32(elf, ref p, PfR | PfW | PfX);            // p_flags
        WriteU64(elf, ref p, (ulong)HeadersSize);          // p_offset
        WriteU64(elf, ref p, 0);                           // p_vaddr
        WriteU64(elf, ref p, 0);                           // p_paddr
        WriteU64(elf, ref p, (ulong)mappedSize);           // p_filesz
        WriteU64(elf, ref p, (ulong)mappedSize);           // p_memsz
        WriteU64(elf, ref p, 0x1000);                      // p_align

        // ---- Program header 1: PT_DYNAMIC ----

        WriteU32(elf, ref p, PtDynamic);                   // p_type
        WriteU32(elf, ref p, PfR);                         // p_flags
        WriteU64(elf, ref p, (ulong)(HeadersSize + dynVaddr)); // p_offset
        WriteU64(elf, ref p, (ulong)dynVaddr);             // p_vaddr
        WriteU64(elf, ref p, (ulong)dynVaddr);             // p_paddr
        WriteU64(elf, ref p, (ulong)dynSize);              // p_filesz
        WriteU64(elf, ref p, (ulong)dynSize);              // p_memsz
        WriteU64(elf, ref p, 8);                           // p_align

        // ---- Mapped data (starting at file offset HeadersSize) ----

        int dataBase = HeadersSize;

        // Code/data blob
        Array.Copy(codeData, 0, elf, dataBase, codeDataSize);

        // String table
        Array.Copy(strtab, 0, elf, dataBase + strtabVaddr, strtabSize);

        // Symbol table (index 0 = null entry, already zeroed)
        int symBase = dataBase + symtabVaddr;
        for (int i = 0; i < symbolNames.Count; i++)
        {
            int sp = symBase + (i + 1) * SymEntSize;
            WriteU32At(elf, sp, (uint)nameOffsets[i]); // st_name
            elf[sp + 4] = StbGlobal << 4;              // st_info (STB_GLOBAL | STT_NOTYPE)
            // st_other = 0 (default visibility)
            // st_shndx = SHN_UNDEF (0) -- external, resolved at load time
            // st_value = 0 -- undefined symbol
            // st_size  = 0
        }

        // Relocation table
        int relaBase = dataBase + relaVaddr;
        for (int i = 0; i < relocations.Count; i++)
        {
            ElfRelocation rel = relocations[i];
            int rp = relaBase + i * RelaEntSize;
            WriteU64At(elf, rp, (ulong)rel.Offset);                             // r_offset
            WriteU64At(elf, rp + 8, ((ulong)rel.SymbolIndex << 32) | rel.Type); // r_info
            WriteI64At(elf, rp + 16, rel.Addend);                               // r_addend
        }

        // Dynamic table
        int dynBase = dataBase + dynVaddr;
        WriteDynEntry(elf, dynBase, DtStrtab, (ulong)strtabVaddr);
        WriteDynEntry(elf, dynBase + 16, DtSymtab, (ulong)symtabVaddr);
        WriteDynEntry(elf, dynBase + 32, DtRela, (ulong)relaVaddr);
        WriteDynEntry(elf, dynBase + 48, DtRelasz, (ulong)relaSize);
        WriteDynEntry(elf, dynBase + 64, DtNull, 0);

        return elf;
    }

    // ---- Relocation descriptor ----

    /// <summary>
    /// Describes a single ELF relocation entry.
    /// </summary>
    private readonly struct ElfRelocation
    {
        /// <summary>Virtual address of the 64-bit slot to patch.</summary>
        public readonly int Offset;

        /// <summary>Symbol table index (0 for R_X86_64_RELATIVE, 1+ for named symbols).</summary>
        public readonly int SymbolIndex;

        /// <summary>Relocation type (R_X86_64_64 or R_X86_64_RELATIVE).</summary>
        public readonly uint Type;

        /// <summary>Addend. For R_X86_64_64: added to the resolved symbol value.
        /// For R_X86_64_RELATIVE: the target virtual address within the loaded image.</summary>
        public readonly long Addend;

        private ElfRelocation(int offset, int symbolIndex, uint type, long addend)
        {
            Offset = offset;
            SymbolIndex = symbolIndex;
            Type = type;
            Addend = addend;
        }

        /// <summary>Creates an R_X86_64_64 relocation to an undefined symbol.</summary>
        public static ElfRelocation Symbol(int offset, int symbolIndex) =>
            new(offset, symbolIndex, Rel64, 0);

        /// <summary>Creates an R_X86_64_RELATIVE relocation with the given addend.</summary>
        public static ElfRelocation Relative(int offset, long addend) =>
            new(offset, 0, RelRelative, addend);
    }

    // ---- Binary write helpers ----

    private static int AlignPadding(int value, int alignment)
    {
        int remainder = value % alignment;
        return remainder == 0 ? 0 : alignment - remainder;
    }

    /// <summary>Write a little-endian uint16 and advance the position.</summary>
    private static void WriteU16(byte[] buf, ref int pos, ushort value)
    {
        buf[pos] = (byte)value;
        buf[pos + 1] = (byte)(value >> 8);
        pos += 2;
    }

    /// <summary>Write a little-endian uint32 and advance the position.</summary>
    private static void WriteU32(byte[] buf, ref int pos, uint value)
    {
        buf[pos] = (byte)value;
        buf[pos + 1] = (byte)(value >> 8);
        buf[pos + 2] = (byte)(value >> 16);
        buf[pos + 3] = (byte)(value >> 24);
        pos += 4;
    }

    /// <summary>Write a little-endian uint64 and advance the position.</summary>
    private static void WriteU64(byte[] buf, ref int pos, ulong value)
    {
        WriteU64At(buf, pos, value);
        pos += 8;
    }

    /// <summary>Write a little-endian uint32 at a fixed offset.</summary>
    private static void WriteU32At(byte[] buf, int offset, uint value)
    {
        buf[offset] = (byte)value;
        buf[offset + 1] = (byte)(value >> 8);
        buf[offset + 2] = (byte)(value >> 16);
        buf[offset + 3] = (byte)(value >> 24);
    }

    /// <summary>Write a little-endian uint64 at a fixed offset.</summary>
    private static void WriteU64At(byte[] buf, int offset, ulong value)
    {
        buf[offset] = (byte)value;
        buf[offset + 1] = (byte)(value >> 8);
        buf[offset + 2] = (byte)(value >> 16);
        buf[offset + 3] = (byte)(value >> 24);
        buf[offset + 4] = (byte)(value >> 32);
        buf[offset + 5] = (byte)(value >> 40);
        buf[offset + 6] = (byte)(value >> 48);
        buf[offset + 7] = (byte)(value >> 56);
    }

    /// <summary>Write a little-endian int64 at a fixed offset.</summary>
    private static void WriteI64At(byte[] buf, int offset, long value) =>
        WriteU64At(buf, offset, unchecked((ulong)value));

    /// <summary>Write a dynamic section entry (d_tag + d_val, 16 bytes).</summary>
    private static void WriteDynEntry(byte[] buf, int offset, long tag, ulong val)
    {
        WriteI64At(buf, offset, tag);
        WriteU64At(buf, offset + 8, val);
    }
}
