// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Agc;

/// <summary>
/// A command buffer header for the async memory paging and remapping subsystem. The runtime
/// fills the buffer at <see cref="Buffer"/> with commands whose combined length is at most
/// <see cref="BufferSize"/>; the write cursor is <see cref="Offset"/>, the count of committed
/// commands is <see cref="NumCommands"/>, and <see cref="Type"/> selects which command builder
/// interprets the buffer.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAmprCommandBuffer
{
    /// <summary>Which command family the buffer holds.</summary>
    public int Type;

    /// <summary>Byte offset in <see cref="Buffer"/> at which the next command will be appended.</summary>
    public uint Offset;

    /// <summary>Number of committed commands. Written by the runtime after every successful append.</summary>
    public volatile int NumCommands;

    /// <summary>Byte size of the memory pointed to by <see cref="Buffer"/>.</summary>
    public uint BufferSize;

    /// <summary>The command bytes. Multiple of four bytes long, up to 64 MiB.</summary>
    public void* Buffer;
}

/// <summary>
/// The result written back by an AMM command buffer submission that requested a result. When the
/// buffer's commands all succeed <see cref="Result"/> is zero; on failure it carries a negative
/// error code and <see cref="ErrorOffset"/> is the offset in the command buffer at which the
/// failure was detected.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAmmResultBuffer
{
    /// <summary>Zero for normal termination, or a negative error code.</summary>
    public int Result;

    /// <summary>The byte offset in the command buffer at which the failure was detected.</summary>
    public uint ErrorOffset;
}

/// <summary>
/// The result written back by an APR command buffer submission that requested a result. When the
/// buffer's commands all succeed <see cref="Result"/> is zero; on failure it carries a negative
/// error code and <see cref="ErrorOffset"/> is the offset in the command buffer at which the
/// failure was detected.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAprResultBuffer
{
    /// <summary>Zero for normal termination, or a negative error code.</summary>
    public int Result;

    /// <summary>The byte offset in the command buffer at which the failure was detected.</summary>
    public uint ErrorOffset;
}

/// <summary>
/// Internal map-in-progress state kept inside an APR command buffer. A 64-bit field packing a
/// one-bit begin-marker, the count of 16 KiB pages that have been mapped so far, and the top
/// 34 bits of the virtual address being mapped. Applications treat this as opaque.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAprMapState
{
    /// <summary>The packed bitfield described in the type summary.</summary>
    public ulong AsU64;
}

/// <summary>
/// Internal scatter/gather state kept inside an APR command buffer. A 64-bit field packing the
/// end-of-output-buffer virtual address and a one-bit valid flag. Applications treat this as
/// opaque.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAprScatterGatherState
{
    /// <summary>The packed bitfield described in the type summary.</summary>
    public ulong AsU64;
}

/// <summary>
/// Async memory paging and remap surface: the command-buffer path the GPU drives to map, unmap and
/// remap direct and flexible memory, including partial-resident textures, together with the paired
/// file-read submission subsystem. The module's callable entry points are published only through a
/// C++ interface, with no C prototype for any of them, so none can be declared here. This class
/// therefore carries the constants, command-buffer layouts, wait comparisons, priority levels and
/// result codes that surface is defined in terms of.
/// </summary>
public static unsafe partial class SceAmpr
{
    private const string Lib = "libSceAmpr";

    /// <summary>Wait comparison: the watched value equals the reference.</summary>
    public const byte WaitCompareEqual = 0;

    /// <summary>Wait comparison: the watched value is greater than the reference.</summary>
    public const byte WaitCompareGreaterThan = 1;

    /// <summary>Wait comparison: the watched value is less than the reference.</summary>
    public const byte WaitCompareLessThan = 2;

    /// <summary>Wait comparison: the watched value differs from the reference.</summary>
    public const byte WaitCompareNotEqual = 3;

    /// <summary>Wait completion: keep the following prefetched commands in the buffer.</summary>
    public const byte WaitCommandFetchFlushDisable = 0;

    /// <summary>Wait completion: discard the following prefetched commands from the buffer.</summary>
    public const byte WaitCommandFetchFlushEnable = 1;

    /// <summary>APR command-buffer submission priority 0 (highest).</summary>
    public const int AprPriority0 = 0;

    /// <summary>APR command-buffer submission priority 1.</summary>
    public const int AprPriority1 = 1;

    /// <summary>APR command-buffer submission priority 2.</summary>
    public const int AprPriority2 = 2;

    /// <summary>APR command-buffer submission priority 3.</summary>
    public const int AprPriority3 = 3;

    /// <summary>APR command-buffer submission priority 4.</summary>
    public const int AprPriority4 = 4;

    /// <summary>APR command-buffer submission priority 5.</summary>
    public const int AprPriority5 = 5;

    /// <summary>APR command-buffer submission priority 6 (lowest).</summary>
    public const int AprPriority6 = 6;

    /// <summary>Sentinel meaning "no such APR file id".</summary>
    public const uint AprFileIdInvalid = 0xFFFFFFFFu;

    /// <summary>Largest permitted command-buffer size in bytes (64 MiB).</summary>
    public const int CommandBufferSizeMax = 64 * 1024 * 1024;

    /// <summary>Largest number of file paths a single resolve call takes.</summary>
    public const int AprResolveMax = 1024;

    /// <summary>Largest permitted APR command-buffer size in bytes (64 MiB).</summary>
    public const int AprBufferMax = 64 * 1024 * 1024;

    /// <summary>APR error: command runs past the end of the command buffer. Value 0x81912001.</summary>
    public const int ErrorAprCommandBufferOverrun = unchecked((int)0x81912001);

    /// <summary>APR error: invalid command opcode. Value 0x81912002.</summary>
    public const int ErrorAprInvalidOpcode = unchecked((int)0x81912002);

    /// <summary>APR error: invalid command element count. Value 0x81912003.</summary>
    public const int ErrorAprInvalidNumElem = unchecked((int)0x81912003);

    /// <summary>APR error: command fails basic format validation. Value 0x81912004.</summary>
    public const int ErrorAprInvalidCommandDataFormat = unchecked((int)0x81912004);

    /// <summary>APR error: invalid command-buffer address. Value 0x81912005.</summary>
    public const int ErrorAprInvalidCommandBufferAddress = unchecked((int)0x81912005);

    /// <summary>APR error: invalid waitOnAddress address. Value 0x81912006.</summary>
    public const int ErrorAprInvalidWaitOnAddressAddress = unchecked((int)0x81912006);

    /// <summary>APR error: invalid writeAddress source. Value 0x81912007.</summary>
    public const int ErrorAprInvalidWriteAddressSource = unchecked((int)0x81912007);

    /// <summary>APR error: memory fault reading the command buffer. Value 0x81912018.</summary>
    public const int ErrorAprMemoryFaultReadCommandBuffer = unchecked((int)0x81912018);

    /// <summary>APR error: memory fault reading the waitOnAddress target. Value 0x81912019.</summary>
    public const int ErrorAprMemoryFaultReadWaitOnAddress = unchecked((int)0x81912019);

    /// <summary>APR error: memory fault reading the buffer target. Value 0x81912020.</summary>
    public const int ErrorAprMemoryFaultReadBufferAddress = unchecked((int)0x81912020);

    /// <summary>APR error: memory fault writing the buffer target. Value 0x81912021.</summary>
    public const int ErrorAprMemoryFaultWriteBufferAddress = unchecked((int)0x81912021);

    /// <summary>APR error: address outside the application's valid range. Value 0x81912030.</summary>
    public const int ErrorAprOutOfRangeAddress = unchecked((int)0x81912030);

    /// <summary>APR error: tried to write a reserved system counter. Value 0x81912031.</summary>
    public const int ErrorAprIllegalCounterWrite = unchecked((int)0x81912031);

    /// <summary>APR error: writeOnCompletion aborted by a preceding command error. Value 0x81912032.</summary>
    public const int ErrorAprEopAbortByError = unchecked((int)0x81912032);

    /// <summary>APR error: invalid mount id. Value 0x81912038.</summary>
    public const int ErrorAprInvalidMountId = unchecked((int)0x81912038);

    /// <summary>APR error: invalid file id. Value 0x81912039.</summary>
    public const int ErrorAprInvalidFileId = unchecked((int)0x81912039);

    /// <summary>APR error: invalid file offset. Value 0x8191203A.</summary>
    public const int ErrorAprInvalidFileOffset = unchecked((int)0x8191203A);

    /// <summary>APR error: invalid gather/scatter state. Value 0x8191203B.</summary>
    public const int ErrorAprInvalidGatherScatterState = unchecked((int)0x8191203B);

    /// <summary>APR error: unavailable file id. Value 0x8191203C.</summary>
    public const int ErrorAprUnavailableFileId = unchecked((int)0x8191203C);

    /// <summary>Error: command runs past the end of the command buffer. Value 0x81912001.</summary>
    public const int ErrorCommandBufferOverrun = unchecked((int)0x81912001);

    /// <summary>Error: invalid command opcode. Value 0x81912002.</summary>
    public const int ErrorInvalidOpcode = unchecked((int)0x81912002);

    /// <summary>Error: invalid command element count. Value 0x81912003.</summary>
    public const int ErrorInvalidNumElem = unchecked((int)0x81912003);

    /// <summary>Error: command fails basic format validation. Value 0x81912004.</summary>
    public const int ErrorInvalidCommandDataFormat = unchecked((int)0x81912004);

    /// <summary>Error: invalid command-buffer address. Value 0x81912005.</summary>
    public const int ErrorInvalidCommandBufferAddress = unchecked((int)0x81912005);

    /// <summary>Error: invalid waitOnAddress address. Value 0x81912006.</summary>
    public const int ErrorInvalidWaitOnAddressAddress = unchecked((int)0x81912006);

    /// <summary>Error: invalid writeAddress source. Value 0x81912007.</summary>
    public const int ErrorInvalidWriteAddressSource = unchecked((int)0x81912007);

    /// <summary>Error: invalid VA address, size alignment, or VA range. Value 0x81912008.</summary>
    public const int ErrorMemoryInvalidVaRange = unchecked((int)0x81912008);

    /// <summary>Error: attempted to map a VA that is already mapped. Value 0x81912009.</summary>
    public const int ErrorMemoryVaAlreadyMapped = unchecked((int)0x81912009);

    /// <summary>Error: out of physical pages while trying to allocate. Value 0x8191200A.</summary>
    public const int ErrorMemoryOutOfPaPages = unchecked((int)0x8191200A);

    /// <summary>Error: out of memory for the page table. Value 0x8191200B.</summary>
    public const int ErrorMemoryOutOfPageTables = unchecked((int)0x8191200B);

    /// <summary>Error: exceeded the multimap count. Value 0x8191200C.</summary>
    public const int ErrorExceededMultimapCount = unchecked((int)0x8191200C);

    /// <summary>Error: invalid size, for example mapping zero bytes. Value 0x8191200D.</summary>
    public const int ErrorInvalidSize = unchecked((int)0x8191200D);

    /// <summary>Error: invalid kernel memory type. Value 0x8191200E.</summary>
    public const int ErrorMemoryInvalidMType = unchecked((int)0x8191200E);

    /// <summary>Error: invalid map attribute combination. Value 0x8191200F.</summary>
    public const int ErrorMemoryInvalidAttributes = unchecked((int)0x8191200F);

    /// <summary>Error: privilege violation, attempted to modify a privileged mapping. Value 0x81912010.</summary>
    public const int ErrorPrivilegeViolation = unchecked((int)0x81912010);

    /// <summary>Error: multimap alias or remap base region is not fully mapped. Value 0x81912011.</summary>
    public const int ErrorRegionNotFullyMapped = unchecked((int)0x81912011);

    /// <summary>Error: attempted to map physical memory that is already mapped. Value 0x81912012.</summary>
    public const int ErrorMemoryPaAlreadyMapped = unchecked((int)0x81912012);

    /// <summary>Error: invalid PA address, size alignment, or PA range. Value 0x81912013.</summary>
    public const int ErrorMemoryInvalidPaRange = unchecked((int)0x81912013);

    /// <summary>Error: attempted to change the VA attributes of a PRT-mapped area. Value 0x81912014.</summary>
    public const int ErrorMemoryPrtModifyViolation = unchecked((int)0x81912014);

    /// <summary>Error: memory fault reading the command buffer. Value 0x81912018.</summary>
    public const int ErrorMemoryFaultReadCommandBuffer = unchecked((int)0x81912018);

    /// <summary>Error: memory fault reading the waitOnAddress target. Value 0x81912019.</summary>
    public const int ErrorMemoryFaultReadWaitOnAddress = unchecked((int)0x81912019);

    /// <summary>Error: memory fault reading the buffer target. Value 0x81912020.</summary>
    public const int ErrorMemoryFaultReadBufferAddress = unchecked((int)0x81912020);

    /// <summary>Error: memory fault writing the buffer target. Value 0x81912021.</summary>
    public const int ErrorMemoryFaultWriteBufferAddress = unchecked((int)0x81912021);

    /// <summary>Error: address outside the application's valid range. Value 0x81912030.</summary>
    public const int ErrorOutOfRangeAddress = unchecked((int)0x81912030);

    /// <summary>Error: tried to write a reserved system counter. Value 0x81912031.</summary>
    public const int ErrorIllegalCounterWrite = unchecked((int)0x81912031);

    /// <summary>Error: invalid mount id. Value 0x81912038.</summary>
    public const int ErrorInvalidMountId = unchecked((int)0x81912038);

    /// <summary>Error: invalid file id. Value 0x81912039.</summary>
    public const int ErrorInvalidFileId = unchecked((int)0x81912039);

    /// <summary>Error: invalid file offset. Value 0x8191203A.</summary>
    public const int ErrorInvalidFileOffset = unchecked((int)0x8191203A);

    /// <summary>Error: invalid gather/scatter state. Value 0x8191203B.</summary>
    public const int ErrorInvalidGatherScatterState = unchecked((int)0x8191203B);

    /// <summary>Error: unavailable file id. Value 0x8191203C.</summary>
    public const int ErrorUnavailableFileId = unchecked((int)0x8191203C);

    /// <summary>Error: unavailable event queue id. Value 0x8191203D.</summary>
    public const int ErrorInvalidEventQueueId = unchecked((int)0x8191203D);

    /// <summary>Error: unavailable event id. Value 0x8191203E.</summary>
    public const int ErrorInvalidEventId = unchecked((int)0x8191203E);
}
