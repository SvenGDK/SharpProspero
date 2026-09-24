// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Process;
using System;

namespace SharpProspero.Payload.Bypass;

/// <summary>
/// SceShellCore patch that unlocks the shell's own <c>/data</c> and <c>/user</c> mount code
/// path, applied by pattern-scanning the running shell's text section for firmware-specific
/// signatures and writing three replacement byte sequences through the direct physical map.
/// </summary>
/// <remarks>
/// <para>
/// The unlock replaces two permission-check call sites with an unconditional
/// <c>mov eax, 1</c> (permission granted) and one permission-check function's prologue with
/// an always-return-<c>0x80182614</c> stub. The two call-site rewrites make the callers stop
/// consulting the check; the function-body rewrite makes any other caller of the same check
/// receive an error code that its own error path treats as "the mount is not owned by me",
/// leaving the mount available for the caller's own use. Together the three writes allow the
/// <c>/data</c> and <c>/user</c> partitions to be mkdir'd, opened, and read from a title
/// whose sandbox namespace does not bind them.
/// </para>
/// <para>
/// Patterns are pattern-scan signatures (not fixed offsets): they hold across every point
/// release inside a firmware major/minor group, and each signature is checked for a unique
/// hit before the write goes out so a shifted layout on an unknown firmware refuses to write
/// rather than corrupting the process.
/// </para>
/// </remarks>
public static unsafe class PayloadShellCoreDataMountPatch
{
    // Replacement bytes are the same for every supported firmware.
    private static readonly byte[] s_replaceMovEax1 = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00 };
    private static readonly byte[] s_replaceCheckerStub = new byte[]
    {
        0x55,                                // push rbp
        0x48, 0x89, 0xE5,                    // mov rbp, rsp
        0xB8, 0x14, 0x26, 0x18, 0x80,        // mov eax, 0x80182614
        0x5D,                                // pop rbp
        0xC3,                                // ret
    };

    // Upper bound for the text-section scan. The eboot's segments[0].size is used as the
    // real span, and this cap keeps a corrupt-size read from asking the pattern scanner
    // for hundreds of megabytes. FW 10.01's executable segment is around 24 MiB, so 64 MiB
    // is comfortable headroom for any firmware that keeps the shell's shape.
    private const int MaxTextScanBytes = 64 * 1024 * 1024;
    private const int TextScanBytes = MaxTextScanBytes;

    /// <summary>
    /// The step the unlock stopped at when it did not run to completion.
    /// </summary>
    public enum Reason
    {
        /// <summary>The unlock completed - three writes applied.</summary>
        Success,

        /// <summary>No signatures are on file for the running firmware.</summary>
        UnsupportedFirmware,

        /// <summary>The kernel process list did not carry a SceShellCore entry.</summary>
        ShellCoreProcessNotFound,

        /// <summary>SceShellCore's CR3 could not be derived from its vmspace.</summary>
        ShellCoreCr3ReadFailed,

        /// <summary>SceShellCore's SharedObject list did not carry a SceShellCore entry.</summary>
        ShellCoreModuleBaseNotFound,

        /// <summary>SceShellCore's ELF header could not be read from its process memory.</summary>
        ShellCoreElfHeaderReadFailed,

        /// <summary>No executable PT_LOAD program header was found in SceShellCore's ELF.</summary>
        ShellCoreTextSegmentNotFound,

        /// <summary>SceShellCore's text section reported an implausibly large size.</summary>
        ShellCoreTextSegmentTooLarge,

        /// <summary>The scratch buffer could not be allocated with mmap.</summary>
        ScratchAllocFailed,

        /// <summary>mdbg_copyout of the text section into the scratch buffer failed.</summary>
        TextCopyoutFailed,

        /// <summary>Every signature pattern-scanned in the scratch buffer returned no match.</summary>
        NoSignaturesMatched,

        /// <summary>PhysCopyin refused every candidate write.</summary>
        PhysCopyinRejected,
    }

    /// <summary>
    /// The result of applying the <c>/data</c> and <c>/user</c> mount unlock.
    /// </summary>
    public readonly struct Result
    {
        /// <summary>How many of the three writes landed. Three is a full success.</summary>
        public readonly int Applied;

        /// <summary>True when the firmware is supported and every signature matched uniquely.</summary>
        public readonly bool FullSuccess;

        /// <summary>The step the unlock stopped at, or <see cref="Reason.Success"/>.</summary>
        public readonly Reason Stop;

        /// <summary>SceShellCore's text section virtual address at the time of the scan.</summary>
        public readonly ulong TextBase;

        /// <summary>SceShellCore's text section size at the time of the scan.</summary>
        public readonly ulong TextSize;

        internal Result(int applied, bool fullSuccess, Reason stop, ulong textBase, ulong textSize)
        {
            Applied = applied;
            FullSuccess = fullSuccess;
            Stop = stop;
            TextBase = textBase;
            TextSize = textSize;
        }
    }

    /// <summary>
    /// Applies the SceShellCore /data-mount unlock on the running shell. Returns a
    /// <see cref="Result"/> describing the outcome; a full success is three writes applied
    /// and every signature matching a unique text-section address.
    /// </summary>
    /// <param name="io">Kernel I/O primitive from the calling payload's args block.</param>
    /// <param name="dmapBase">Direct physical-memory map base for
    /// <see cref="KernelPaging.PhysCopyin"/>.</param>
    /// <param name="firmwareVersion">BCD firmware version (e.g. <c>0x10010000</c> for 10.01).</param>
    public static Result Apply(PayloadKernelIo io, ulong dmapBase, uint firmwareVersion)
    {
        Signatures? sigs = SignaturesFor(firmwareVersion);
        if (sigs is null)
            return new Result(0, false, Reason.UnsupportedFirmware, 0, 0);

        // 1. Find the SceShellCore process.
        byte* shellCoreName = stackalloc byte[] {
            (byte)'S', (byte)'c', (byte)'e', (byte)'S', (byte)'h', (byte)'e', (byte)'l',
            (byte)'l', (byte)'C', (byte)'o', (byte)'r', (byte)'e', 0 };
        ulong proc = PayloadKernel.FindProcessByName(io, shellCoreName, 12);
        if (proc == 0)
            return new Result(0, false, Reason.ShellCoreProcessNotFound, 0, 0);
        int shellCorePid = (int)io.ReadU32(proc + (ulong)KernelOffsets.ProcPid);

        // 2. Derive the SceShellCore CR3 through its p_vmspace->vm_pmap.pm_cr3.
        uint fwMajorMinor = (firmwareVersion >> 16) & 0xFFFF;
        ulong cr3 = KernelPaging.GetProcessCr3(io, shellCorePid, fwMajorMinor);
        if (cr3 == 0)
            return new Result(0, false, Reason.ShellCoreCr3ReadFailed, 0, 0);

        // 3. Resolve the shell's text-section start address and length through the
        //    process's own dynlib metadata. The path is:
        //
        //        p_dynlib  = *(proc + KernelOffsets.ProcDynlib(fw))
        //        dso_eboot = *(p_dynlib + 0x00)     // head SharedObject = the eboot
        //        segments  = *(dso_eboot + 0x40)    // segments array pointer
        //        textStart = *(segments + 0x08)     // segment[0].addr = text base VA
        //        textSize  = *(segments + 0x10)     // segment[0].size in bytes
        //
        //    This is the exact layout the loader source that ships with the payload SDK
        //    reads to widen the eboot segments for dlsym on 5.00+. Reading SharedObject
        //    directly at +0x10 was a PS4-era libhijacker shape that does not survive on
        //    the PS5 struct layout the loader itself uses.
        int dynlibOffset = KernelOffsets.ProcDynlib(firmwareVersion);
        if (dynlibOffset < 0)
            return new Result(0, false, Reason.ShellCoreModuleBaseNotFound, 0, 0);
        ulong pDynlib = io.ReadU64(proc + (ulong)dynlibOffset);
        if (pDynlib == 0)
            return new Result(0, false, Reason.ShellCoreModuleBaseNotFound, 0, 0);
        ulong dsoEboot = io.ReadU64(pDynlib);
        if (dsoEboot == 0)
            return new Result(0, false, Reason.ShellCoreModuleBaseNotFound, 0, 0);
        ulong segments = io.ReadU64(dsoEboot + 0x40);
        if (segments == 0)
            return new Result(0, false, Reason.ShellCoreModuleBaseNotFound, 0, 0);
        ulong textStart = io.ReadU64(segments + 0x08);
        ulong textSize = io.ReadU64(segments + 0x10);
        if (textStart == 0 || textSize == 0)
            return new Result(0, false, Reason.ShellCoreModuleBaseNotFound, 0, 0);
        if (textSize > (ulong)MaxTextScanBytes)
            textSize = (ulong)MaxTextScanBytes;

        int scanBytes = (int)Math.Min((ulong)TextScanBytes, textSize);

        // 4. Pattern-scan the shell process's executable segment directly. The scanner
        //    streams four-kilobyte chunks through mdbg_copyout and matches against each
        //    chunk with overlap, so no in-payload copy of the whole segment is needed and
        //    an unmapped tail page just gets skipped without failing the search.
        nint site1 = PayloadProcessMemory.PatternScan(
            shellCorePid, (nint)textStart, (nuint)scanBytes, sigs.Site1.Bytes, sigs.Site1.Mask);
        nint site2 = PayloadProcessMemory.PatternScan(
            shellCorePid, (nint)textStart, (nuint)scanBytes, sigs.Site2.Bytes, sigs.Site2.Mask);
        nint checker = PayloadProcessMemory.PatternScan(
            shellCorePid, (nint)textStart, (nuint)scanBytes, sigs.Checker.Bytes, sigs.Checker.Mask);

        if (site1 == 0 && site2 == 0 && checker == 0)
            return new Result(0, false, Reason.NoSignaturesMatched, textStart, textSize);

        // 6. Apply the writes for every signature that resolved. A signature that did not
        //    match is skipped so a partial unlock still lands the writes it can.
        int applied = 0;
        if (site1 != 0 && WriteBytes(io, cr3, dmapBase, (ulong)site1, s_replaceMovEax1))
            applied++;
        if (site2 != 0 && WriteBytes(io, cr3, dmapBase, (ulong)site2, s_replaceMovEax1))
            applied++;
        if (checker != 0 && WriteBytes(io, cr3, dmapBase, (ulong)checker, s_replaceCheckerStub))
            applied++;

        Reason stop = applied == 0 ? Reason.PhysCopyinRejected : Reason.Success;
        bool fullSuccess = applied == 3 && site1 != 0 && site2 != 0 && checker != 0;
        return new Result(applied, fullSuccess, stop, textStart, textSize);
    }

    private static bool WriteBytes(PayloadKernelIo io, ulong cr3, ulong dmapBase,
        ulong targetVaddr, byte[] data)
    {
        fixed (byte* p = data)
        {
            return KernelPaging.PhysCopyin(io, cr3, dmapBase, targetVaddr, p, data.Length);
        }
    }

    /// <summary>Signatures for one firmware group.</summary>
    private sealed class Signatures
    {
        public required Pattern Site1;
        public required Pattern Site2;
        public required Pattern Checker;
    }

    // The signature tables below are the on-device byte patterns used to locate the two
    // permission-check call sites and the permission-check function's prologue for every
    // supported firmware family. Empirically verified against the shell binaries the
    // firmware release ships (see /Reversed/etahen-shellcore-data-mount-patch.md).
    private static Signatures? SignaturesFor(uint firmwareVersion)
    {
        uint fw = firmwareVersion & KernelOffsets.VersionMask;
        return fw switch
        {
            // ---- 2.00 through 2.70 ----
            KernelOffsets.Fw200 or KernelOffsets.Fw220 or KernelOffsets.Fw225
                or KernelOffsets.Fw226 or KernelOffsets.Fw230 or KernelOffsets.Fw250
                or KernelOffsets.Fw270 => new Signatures
                {
                    Site1 = Pattern.Parse("e8 ?? ?? ec 00 48 89 9d"),
                    Site2 = Pattern.Parse("e8 ?? ?? b1 00 83 f8"),
                    Checker = Pattern.Parse(
                        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49"),
                },

            // ---- 3.00 through 3.21 ----
            KernelOffsets.Fw300 or KernelOffsets.Fw310 or KernelOffsets.Fw320
                or KernelOffsets.Fw321 => new Signatures
                {
                    Site1 = Pattern.Parse("e8 ?? ?? 00 01 ?? 89 ?? 40"),
                    Site2 = Pattern.Parse("e8 ?? ?? c5 00 83 f8 01 75 5f"),
                    Checker = Pattern.Parse(
                        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49"),
                },

            // ---- 4.00 through 4.51 ----
            KernelOffsets.Fw400 or KernelOffsets.Fw402 or KernelOffsets.Fw403
                or KernelOffsets.Fw450 or KernelOffsets.Fw451 => new Signatures
                {
                    Site1 = Pattern.Parse(
                        "e8 ?? ?? ?? ?? 4c 89 bd ?? ?? ?? ?? 48 89 9d ?? ?? ?? ??"),
                    Site2 = Pattern.Parse("e8 ?? ?? ?? ?? 83 f8 01 75 ?? 41 80 3c 24 00"),
                    Checker = Pattern.Parse(
                        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 00 02 00 00 49"),
                },

            // ---- 5.00 through 5.50 ----
            KernelOffsets.Fw500 or KernelOffsets.Fw502 or KernelOffsets.Fw510
                or KernelOffsets.Fw550 => new Signatures
                {
                    Site1 = Pattern.Parse(
                        "e8 ?? ?? fb 00 85 c0 75 0d e8 ?? ?? fb 00 85 c0 0f 84 47"),
                    Site2 = Pattern.Parse("e8 ?? ?? c7 00 83 f8 01 75 5e"),
                    Checker = Pattern.Parse(
                        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49"),
                },

            // ---- 6.00 through 6.50 ----
            KernelOffsets.Fw600 or KernelOffsets.Fw602 or KernelOffsets.Fw650
                => new Signatures
                {
                    Site1 = Pattern.Parse("e8 ?? ?? ?? 01 4c 89 a5 80"),
                    Site2 = Pattern.Parse("e8 ?? ?? ?? 00 83 f8 01 75 66"),
                    Checker = Pattern.Parse(
                        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49"),
                },

            // ---- 7.00 through 7.61 ----
            KernelOffsets.Fw700 or KernelOffsets.Fw701 or KernelOffsets.Fw720
                or KernelOffsets.Fw740 or KernelOffsets.Fw760 or KernelOffsets.Fw761
                => new Signatures
                {
                    Site1 = Pattern.Parse("e8 ?? ?? ?? 01 4c 89 b5 80"),
                    Site2 = Pattern.Parse("e8 ?? ?? d7 00 83 f8 01 0f 85 cd"),
                    Checker = Pattern.Parse(
                        "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec e0 01 00 00 49 89 cd"),
                },

            // ---- 8.00 through 8.20 ----
            KernelOffsets.Fw800 or KernelOffsets.Fw820 => new Signatures
            {
                Site1 = Pattern.Parse(
                    "e8 ?? ?? ?? 01 85 c0 75 0d e8 ?? ?? ?? 01 85 c0 0f 84 c1"),
                Site2 = Pattern.Parse("e8 ?? ?? dc 00 83 f8 01 0f"),
                Checker = Pattern.Parse(
                    "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec c8 01 00 00 49 89 cd"),
            },

            // ---- 10.01 ----
            //
            // The layout on 10.01 dropped the intermediate `mov [rbp-0x2c0], rbx` byte
            // sequence that anchored the older site-1 patterns and switched the check
            // function to a larger stack frame with no `and rsp, -0x20` alignment step,
            // which is why every 2.xx-through-8.xx signature above misses on this firmware.
            //
            // Site 1: the two-call permission gate inside the shell's own mount-root
            // initialiser. Both CALLs land in the same PLT thunk family (targets 0x10
            // apart), which the 22-byte signature encodes as `E8 rel32; test eax,eax; jne
            // +0x0D; E8 rel32; test eax,eax; jne_far 0x00000109`.
            //
            // Site 2: a later single-call check in the same function whose result is
            // compared against 1 and followed by a byte-load that gates the retail-mode
            // /data mount refusal. The 23-byte signature ties the CALL to the exact
            // `cmp eax,1; jne_far 0xCE; cmp byte [rbx],0; je_far 0x91` shape.
            //
            // Site 3 (checker): the retail patch-eligibility check's prologue, 20 bytes
            // through the `sub rsp, 0xD68` allocation plus the two RIP-relative reads and
            // the four `mov`s that store the caller's arguments into r15/r14/r12 and rbx.
            // The two `??` fields cover the shifting RIP-relative disp32 offsets to the
            // per-build data addresses.
            KernelOffsets.Fw1001 => new Signatures
            {
                Site1 = Pattern.Parse(
                    "E8 ?? ?? ?? ?? 85 C0 75 0D E8 ?? ?? ?? ?? 85 C0 0F 84 09 01 00 00"),
                Site2 = Pattern.Parse(
                    "E8 ?? ?? ?? ?? 83 F8 01 0F 85 CE 00 00 00 80 3B 00 0F 84 91 00 00 00"),
                Checker = Pattern.Parse(
                    "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC 68 0D 00 00 "
                    + "48 8B 05 ?? ?? ?? ?? 48 89 8D ?? ?? ?? ?? 48 8D 5F 30 49 89 "
                    + "FF 49 89 D6 49 89 F4"),
            },

            _ => null,
        };
    }
}
