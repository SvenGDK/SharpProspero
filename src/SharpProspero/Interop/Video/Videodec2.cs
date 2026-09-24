// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.Kernel;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Video;

/// <summary>Which compressed form the video decoder reads.</summary>
public enum Videodec2CodecType : uint
{
    /// <summary>H.264 / MPEG-4 Part 10.</summary>
    Avc = 1,

    /// <summary>H.265 High Efficiency Video Coding.</summary>
    Hevc = 974921,

    /// <summary>VP9.</summary>
    Vp9 = 2382845,
}

/// <summary>The H.264 profile a stream is coded at.</summary>
public enum Videodec2AvcProfile : uint
{
    /// <summary>Main profile.</summary>
    Main = 77,

    /// <summary>High profile, the usual one for a recorded file.</summary>
    High = 100,
}

/// <summary>What the decoder is built on.</summary>
public enum Videodec2ResourceType : uint
{
    /// <summary>Decoding runs on a compute queue.</summary>
    Compute = 1,
}

/// <summary>How the decoder is set up: what it decodes and how large a picture it must handle.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideodec2DecoderConfigInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>What the decoder is built on, from <see cref="Videodec2ResourceType"/>.</summary>
    public uint ResourceType;

    /// <summary>Which compressed form to read, from <see cref="Videodec2CodecType"/>.</summary>
    public uint CodecType;

    /// <summary>The profile the stream is coded at.</summary>
    public uint Profile;

    /// <summary>The highest level the decoder must handle.</summary>
    public uint MaxLevel;

    /// <summary>The widest picture, or -1 to let the decoder decide.</summary>
    public int MaxFrameWidth;

    /// <summary>The tallest picture, or -1 to let the decoder decide.</summary>
    public int MaxFrameHeight;

    /// <summary>How many pictures the decoder may hold back, or -1 to let it decide.</summary>
    public int MaxDpbFrameCount;

    /// <summary>How many inputs may be queued before one is taken.</summary>
    public uint DecodeInputQueueDepth;

    /// <summary>The compute queue the decoder runs on.</summary>
    public void* ComputeQueue;

    /// <summary>Which processors the decoder's threads may run on, or 0 to inherit.</summary>
    public ulong CpuAffinityMask;

    /// <summary>The priority of the decoder's threads, or -1 to inherit.</summary>
    public int CpuThreadPriority;

    /// <summary>Whether to favour progressive video.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool OptimizeProgressiveVideo;

    /// <summary>Whether the decoder checks what backs the memory it is given.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool CheckMemoryType;

    private byte _reserved0;
    private byte _reserved1;

    /// <summary>Extra settings, or null.</summary>
    public void* ExtraConfigInfo;
}

/// <summary>How much memory of each kind the decoder needs, and where it has been put.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideodec2DecoderMemoryInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Bytes of ordinary memory the decoder needs.</summary>
    public nuint CpuMemorySize;

    /// <summary>Where that ordinary memory is.</summary>
    public void* CpuMemory;

    /// <summary>Bytes of graphics memory the decoder needs.</summary>
    public nuint GpuMemorySize;

    /// <summary>Where that graphics memory is.</summary>
    public void* GpuMemory;

    /// <summary>Bytes of memory both sides reach that the decoder needs.</summary>
    public nuint CpuGpuMemorySize;

    /// <summary>Where that shared memory is.</summary>
    public void* CpuGpuMemory;

    /// <summary>The largest picture buffer the decoder will ask for.</summary>
    public nuint MaxFrameBufferSize;

    /// <summary>The alignment a picture buffer must be made on.</summary>
    public uint FrameBufferAlignment;

    private uint _reserved0;
}

/// <summary>One compressed unit handed to the decoder.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideodec2InputData
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>The compressed bytes.</summary>
    public void* AuData;

    /// <summary>How many compressed bytes there are.</summary>
    public nuint AuSize;

    /// <summary>When the picture should be shown.</summary>
    public ulong PresentationTime;

    /// <summary>When the unit should be decoded.</summary>
    public ulong DecodeTime;

    /// <summary>A value of the caller's own, handed back with the picture.</summary>
    public ulong AttachedData;
}

/// <summary>What came out of a decode call.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideodec2OutputInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether a picture is present.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    /// <summary>Whether the picture was decoded from damaged input.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsErrorFrame;

    /// <summary>How many pictures this output carries.</summary>
    public byte PictureCount;

    /// <summary>Whether the picture was dropped rather than shown.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsDiscardedFrame;

    /// <summary>Which compressed form produced it.</summary>
    public uint CodecType;

    /// <summary>The picture's width in pixels.</summary>
    public uint FrameWidth;

    /// <summary>The picture's row stride in pixels.</summary>
    public uint FramePitch;

    /// <summary>The picture's height in pixels.</summary>
    public uint FrameHeight;

    /// <summary>Where the picture is.</summary>
    public void* FrameBuffer;

    /// <summary>How large the picture buffer is.</summary>
    public nuint FrameBufferSize;

    /// <summary>The picture's pixel arrangement.</summary>
    public uint FrameFormat;

    /// <summary>The picture's row stride in bytes.</summary>
    public uint FramePitchInBytes;
}

/// <summary>A buffer offered to the decoder to write a picture into.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideodec2FrameBuffer
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Where the buffer is.</summary>
    public void* FrameBuffer;

    /// <summary>How large the buffer is.</summary>
    public nuint FrameBufferSize;

    /// <summary>Whether the decoder took the buffer.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsAccepted;
}

/// <summary>How much memory a compute queue needs, and where it has been put.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVideodec2ComputeMemoryInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Bytes of memory both sides reach that the queue needs.</summary>
    public nuint CpuGpuMemorySize;

    /// <summary>Where that shared memory is.</summary>
    public void* CpuGpuMemory;
}

/// <summary>Which compute queue to take and whether its memory is checked.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVideodec2ComputeConfigInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Which pipe the queue is on.</summary>
    public ushort ComputePipeId;

    /// <summary>Which queue on that pipe.</summary>
    public ushort ComputeQueueId;

    /// <summary>Whether the service checks what backs the memory it is given.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool CheckMemoryType;

    private byte _reserved0;
    private ushort _reserved1;
}

/// <summary>Per-picture information for an H.264 stream, drawn from the decoded picture.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVideodec2AvcPictureInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether this picture-info entry carries a picture.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    /// <summary>When the picture should be shown.</summary>
    public ulong PresentationTime;

    /// <summary>When the unit was decoded.</summary>
    public ulong DecodeTime;

    /// <summary>The caller's value that came in with the access unit.</summary>
    public ulong AttachedData;

    /// <summary>Whether the picture is an IDR frame.</summary>
    public byte IdrPictureFlag;

    /// <summary>The profile id from the SPS.</summary>
    public byte ProfileIdc;

    /// <summary>The level id from the SPS.</summary>
    public byte LevelIdc;

    /// <summary>The stored picture width in macroblocks, minus one.</summary>
    public uint PicWidthInMbsMinus1;

    /// <summary>The stored picture height in map units, minus one.</summary>
    public uint PicHeightInMapUnitsMinus1;

    /// <summary>Whether the sequence is coded as frames only.</summary>
    public byte FrameMbsOnlyFlag;

    /// <summary>Whether the picture carries cropping offsets.</summary>
    public byte FrameCroppingFlag;

    /// <summary>The left crop offset from the SPS.</summary>
    public uint FrameCropLeftOffset;

    /// <summary>The right crop offset from the SPS.</summary>
    public uint FrameCropRightOffset;

    /// <summary>The top crop offset from the SPS.</summary>
    public uint FrameCropTopOffset;

    /// <summary>The bottom crop offset from the SPS.</summary>
    public uint FrameCropBottomOffset;

    /// <summary>Whether aspect-ratio information is signalled.</summary>
    public byte AspectRatioInfoPresentFlag;

    /// <summary>The aspect-ratio id from the SPS.</summary>
    public byte AspectRatioIdc;

    /// <summary>The sample aspect-ratio width.</summary>
    public ushort SarWidth;

    /// <summary>The sample aspect-ratio height.</summary>
    public ushort SarHeight;

    /// <summary>Whether video-signal-type information is signalled.</summary>
    public byte VideoSignalTypePresentFlag;

    /// <summary>The video format from the SPS.</summary>
    public byte VideoFormat;

    /// <summary>Whether the sample range is full.</summary>
    public byte VideoFullRangeFlag;

    /// <summary>Whether colour-description information is signalled.</summary>
    public byte ColourDescriptionPresentFlag;

    /// <summary>The colour-primaries id from the SPS.</summary>
    public byte ColourPrimaries;

    /// <summary>The transfer-characteristics id from the SPS.</summary>
    public byte TransferCharacteristics;

    /// <summary>The matrix-coefficients id from the SPS.</summary>
    public byte MatrixCoefficients;

    /// <summary>Whether timing information is signalled.</summary>
    public byte TimingInfoPresentFlag;

    /// <summary>The number of time units in one tick.</summary>
    public uint NumUnitsInTick;

    /// <summary>The number of ticks in one second.</summary>
    public uint TimeScale;

    /// <summary>Whether the frame rate is fixed.</summary>
    public byte FixedFrameRateFlag;

    /// <summary>Whether the SPS carries a bitstream-restriction section.</summary>
    public byte BitstreamRestrictionFlag;

    /// <summary>The largest DPB size the SPS says the decoder must hold.</summary>
    public byte MaxDecFrameBuffering;

    /// <summary>Whether picture-timing SEI is present.</summary>
    public byte PicStructPresentFlag;

    /// <summary>The pic_struct value from picture-timing SEI.</summary>
    public byte PicStruct;

    /// <summary>Whether the picture is a field, from the slice header.</summary>
    public byte FieldPicFlag;

    /// <summary>Whether a field picture is the bottom field.</summary>
    public byte BottomFieldFlag;

    /// <summary>Whether the picture carries a fresh SPS.</summary>
    public byte SequenceParameterSetPresentFlag;

    /// <summary>Whether the picture carries a fresh PPS.</summary>
    public byte PictureParameterSetPresentFlag;

    /// <summary>Whether an access-unit delimiter preceded the picture.</summary>
    public byte AuDelimiterPresentFlag;

    /// <summary>Whether an end-of-sequence NAL was seen.</summary>
    public byte EndOfSequencePresentFlag;

    /// <summary>Whether an end-of-stream NAL was seen.</summary>
    public byte EndOfStreamPresentFlag;

    /// <summary>Whether filler-data NALs were seen.</summary>
    public byte FillerDataPresentFlag;

    /// <summary>Whether picture-timing SEI was carried.</summary>
    public byte PictureTimingSeiPresentFlag;

    /// <summary>Whether buffering-period SEI was carried.</summary>
    public byte BufferingPeriodSeiPresentFlag;

    /// <summary>The constraint_set0 flag from the SPS.</summary>
    public byte ConstraintSet0Flag;

    /// <summary>The constraint_set1 flag from the SPS.</summary>
    public byte ConstraintSet1Flag;

    /// <summary>The constraint_set2 flag from the SPS.</summary>
    public byte ConstraintSet2Flag;

    /// <summary>The constraint_set3 flag from the SPS.</summary>
    public byte ConstraintSet3Flag;

    /// <summary>The constraint_set4 flag from the SPS.</summary>
    public byte ConstraintSet4Flag;

    /// <summary>The constraint_set5 flag from the SPS.</summary>
    public byte ConstraintSet5Flag;
}

/// <summary>Per-picture information for an HEVC stream, drawn from the decoded picture.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVideodec2HevcPictureInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether this picture-info entry carries a picture.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    /// <summary>When the picture should be shown.</summary>
    public ulong PresentationTime;

    /// <summary>When the unit was decoded.</summary>
    public ulong DecodeTime;

    /// <summary>The caller's value that came in with the access unit.</summary>
    public ulong AttachedData;

    /// <summary>The stored picture width in luma samples.</summary>
    public uint PicWidthInLumaSamples;

    /// <summary>The stored picture height in luma samples.</summary>
    public uint PicHeightInLumaSamples;

    /// <summary>Bit depth for the luma plane, minus 8.</summary>
    public byte BitDepthLumaMinus8;

    /// <summary>Bit depth for the chroma planes, minus 8.</summary>
    public byte BitDepthChromaMinus8;

    /// <summary>Whether timing information is signalled.</summary>
    public byte TimingInfoPresentFlag;

    /// <summary>The number of time units in one tick.</summary>
    public uint NumUnitsInTick;

    /// <summary>The number of ticks in one second.</summary>
    public uint TimeScale;

    /// <summary>Whether aspect-ratio information is signalled.</summary>
    public uint AspectRatioInfoPresentFlag;

    /// <summary>The aspect-ratio id from the VUI.</summary>
    public byte AspectRatioIdc;

    /// <summary>The sample aspect-ratio width.</summary>
    public ushort SarWidth;

    /// <summary>The sample aspect-ratio height.</summary>
    public ushort SarHeight;

    /// <summary>Whether video-signal-type information is signalled.</summary>
    public byte VideoSignalTypePresentFlag;

    /// <summary>The video format from the VUI.</summary>
    public byte VideoFormat;

    /// <summary>Whether the sample range is full.</summary>
    public byte VideoFullRangeFlag;

    /// <summary>Whether colour-description information is signalled.</summary>
    public byte ColourDescriptionPresentFlag;

    /// <summary>The colour-primaries id from the VUI.</summary>
    public byte ColourPrimaries;

    /// <summary>The transfer-characteristics id from the VUI.</summary>
    public byte TransferCharacteristics;

    /// <summary>The matrix-coefficients id from the VUI.</summary>
    public byte MatrixCoeffs;

    /// <summary>Whether frame-field information is signalled.</summary>
    public byte FrameFieldInfoPresentFlag;

    /// <summary>The pic_struct value from picture-timing SEI.</summary>
    public uint PicStruct;

    /// <summary>The source scan type reported by SEI.</summary>
    public uint SourceScanType;

    /// <summary>Whether the picture is marked duplicate.</summary>
    public uint DuplicateFlag;

    /// <summary>Whether the SPS carries a conformance window.</summary>
    public uint ConformanceWindowFlag;

    /// <summary>The conformance window left offset.</summary>
    public uint ConfWinLeftOffset;

    /// <summary>The conformance window right offset.</summary>
    public uint ConfWinRightOffset;

    /// <summary>The conformance window top offset.</summary>
    public uint ConfWinTopOffset;

    /// <summary>The conformance window bottom offset.</summary>
    public uint ConfWinBottomOffset;

    /// <summary>Whether the VUI carries a default display window.</summary>
    public uint DefaultDisplayWindowFlag;

    /// <summary>The default display window left offset.</summary>
    public uint DefDispWinLeftOffset;

    /// <summary>The default display window right offset.</summary>
    public uint DefDispWinRightOffset;

    /// <summary>The default display window top offset.</summary>
    public uint DefDispWinTopOffset;

    /// <summary>The default display window bottom offset.</summary>
    public uint DefDispWinBottomOffset;

    /// <summary>Whether chroma-sample-location information is signalled.</summary>
    public byte ChromaLocInfoPresentFlag;

    /// <summary>The chroma sample location type for the top field.</summary>
    public byte ChromaSampleLocTypeTopField;

    /// <summary>The chroma sample location type for the bottom field.</summary>
    public byte ChromaSampleLocTypeBottomField;

    /// <summary>Whether the sequence is a field sequence.</summary>
    public byte FieldSeqFlag;

    /// <summary>Whether the picture carries a fresh VPS.</summary>
    public byte VideoParameterSetPresentFlag;

    /// <summary>Whether the picture carries a fresh SPS.</summary>
    public byte SequenceParameterSetPresentFlag;

    /// <summary>Whether the picture carries a fresh PPS.</summary>
    public byte PictureParameterSetPresentFlag;

    /// <summary>Whether an access-unit delimiter preceded the picture.</summary>
    public byte AuDelimiterPresentFlag;

    /// <summary>Whether an end-of-sequence NAL was seen.</summary>
    public byte EndOfSequencePresentFlag;

    /// <summary>Whether an end-of-stream NAL was seen.</summary>
    public byte EndOfStreamPresentFlag;

    /// <summary>Whether filler-data NALs were seen.</summary>
    public byte FillerDataPresentFlag;

    /// <summary>Whether picture-timing SEI was carried.</summary>
    public byte PictureTimingSeiPresentFlag;

    /// <summary>Whether buffering-period SEI was carried.</summary>
    public byte BufferingPeriodSeiPresentFlag;

    /// <summary>Whether frame-packing arrangement SEI was carried.</summary>
    public byte FramePackingArrangementSeiPresentFlag;

    /// <summary>Whether alternative-transfer-characteristics SEI was carried.</summary>
    public byte AlternativeTransferCharacteristicsSeiPresentFlag;

    /// <summary>Whether the picture is an IDR frame.</summary>
    public byte IdrPictureFlag;

    /// <summary>Whether the picture is an IRAP frame.</summary>
    public byte IrapPictureFlag;

    /// <summary>The general_profile_space value from the PTL.</summary>
    public byte GeneralProfileSpace;

    /// <summary>The general_tier_flag value from the PTL.</summary>
    public byte GeneralTierFlag;

    /// <summary>The general_profile_idc value from the PTL.</summary>
    public byte GeneralProfileIdc;

    /// <summary>The general_progressive_source_flag value from the PTL.</summary>
    public byte GeneralProgressiveSourceFlag;

    /// <summary>The general_interlaced_source_flag value from the PTL.</summary>
    public byte GeneralInterlacedSourceFlag;

    /// <summary>The general_frame_only_constraint_flag value from the PTL.</summary>
    public byte GeneralFrameOnlyConstraintFlag;

    /// <summary>The general_level_idc value from the PTL.</summary>
    public byte GeneralLevelIdc;

    /// <summary>Whether the sub-layer profile is present.</summary>
    public byte SubLayerProfilePresentFlag;

    /// <summary>Whether the sub-layer level is present.</summary>
    public byte SubLayerLevelPresentFlag;

    /// <summary>The sub-layer profile-space value.</summary>
    public byte SubLayerProfileSpace;

    /// <summary>The sub-layer tier flag.</summary>
    public byte SubLayerTierFlag;

    /// <summary>The sub-layer profile id.</summary>
    public byte SubLayerProfileIdc;

    /// <summary>The sub-layer level id.</summary>
    public byte SubLayerLevelIdc;

    /// <summary>Whether the SPS carries sub-layer ordering information.</summary>
    public byte SubLayerOrderingInfoPresentFlag;

    /// <summary>The largest DPB size the SPS says the decoder must hold, minus one.</summary>
    public byte MaxDecPicBufferingMinus1;

    /// <summary>The preferred transfer characteristics from alternative-transfer-characteristics SEI.</summary>
    public byte PreferredTransferCharacteristics;

    /// <summary>Whether the picture carries a conformance/cropping window.</summary>
    public byte FrameCroppingFlag;

    /// <summary>The left crop offset.</summary>
    public uint FrameCropLeftOffset;

    /// <summary>The right crop offset.</summary>
    public uint FrameCropRightOffset;

    /// <summary>The top crop offset.</summary>
    public uint FrameCropTopOffset;

    /// <summary>The bottom crop offset.</summary>
    public uint FrameCropBottomOffset;
}

/// <summary>Per-picture information for a VP9 stream, drawn from the decoded picture.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVideodec2Vp9PictureInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether this picture-info entry carries a picture.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    /// <summary>When the picture should be shown.</summary>
    public ulong PresentationTime;

    /// <summary>When the unit was decoded.</summary>
    public ulong DecodeTime;

    /// <summary>The caller's value that came in with the access unit.</summary>
    public ulong AttachedData;

    /// <summary>The VP9 profile the stream is coded at.</summary>
    public uint Profile;

    /// <summary>The VP9 level the stream is coded at.</summary>
    public uint Level;

    /// <summary>1 for a key frame, 0 for a non-key frame.</summary>
    public uint KeyFrameFlag;

    /// <summary>1 when the frame is coded as intra-only.</summary>
    public uint IntraOnly;

    /// <summary>Bit depth of the picture, 8 or 10.</summary>
    public byte BitDepth;

    /// <summary>Sample range: 0 for studio swing, 1 for full swing.</summary>
    public byte ColorRange;

    /// <summary>The colour space the picture is in.</summary>
    public uint ColorSpace;

    /// <summary>How many frames are packed in this super-frame.</summary>
    public uint NumFrames;

    /// <summary>Coded frame width in pixels.</summary>
    public uint FrameWidth;

    /// <summary>Coded frame height in pixels.</summary>
    public uint FrameHeight;

    /// <summary>Render width in pixels.</summary>
    public uint RenderWidth;

    /// <summary>Render height in pixels.</summary>
    public uint RenderHeight;
}

/// <summary>
/// Compressed video decoding. The caller provides every piece of memory: it asks how much a compute
/// queue needs and creates one, asks how much a decoder needs and creates it, then offers a buffer per
/// picture and is handed back the decoded frame.
/// </summary>
public static unsafe partial class Videodec2
{
    private const string Lib = "libSceVideodec2";

    /// <summary>Let the decoder settle a frame or buffer count itself.</summary>
    public const int AutoFrameSetting = -1;

    /// <summary>Run the decoder's threads on whichever processors the caller uses.</summary>
    public const ulong InheritAffinityMask = 0;

    /// <summary>Run the decoder's threads at the caller's priority.</summary>
    public const int InheritThreadPriority = -1;

    /// <summary>The usual pixel arrangement for a decoded picture.</summary>
    public const uint FrameFormatDefault = 0;

    /// <summary>The alignment every memory region the decoder is given must be made on.</summary>
    public const nuint MemoryAlignment = KernelMemory.PageSize;

    /// <summary>Asks how much memory a compute queue needs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2QueryComputeMemoryInfo(SceVideodec2ComputeMemoryInfo* memoryInfo);

    /// <summary>Takes a compute queue using the memory named in <paramref name="memoryInfo"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2AllocateComputeQueue(
        SceVideodec2ComputeConfigInfo* configInfo, SceVideodec2ComputeMemoryInfo* memoryInfo, void** computeQueueOut);

    /// <summary>Gives a compute queue back.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2ReleaseComputeQueue(void* computeQueue);

    /// <summary>Asks how much memory a decoder with these settings needs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2QueryDecoderMemoryInfo(
        SceVideodec2DecoderConfigInfo* configInfo, SceVideodec2DecoderMemoryInfo* memoryInfo);

    /// <summary>Creates a decoder from the settings and the memory provided.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2CreateDecoder(
        SceVideodec2DecoderConfigInfo* configInfo, SceVideodec2DecoderMemoryInfo* memoryInfo, void** decoderOut);

    /// <summary>Destroys a decoder.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2DeleteDecoder(void* decoder);

    /// <summary>Decodes one compressed unit into the offered picture buffer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2Decode(
        void* decoder, SceVideodec2InputData* inputData, SceVideodec2FrameBuffer* frameBuffer,
        SceVideodec2OutputInfo* outputInfo);

    /// <summary>Pushes out any picture the decoder was still holding.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2Flush(
        void* decoder, SceVideodec2FrameBuffer* frameBuffer, SceVideodec2OutputInfo* outputInfo);

    /// <summary>Drops what the decoder was carrying, for a seek.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2Reset(void* decoder);

    /// <summary>Fills a codec-appropriate picture-info structure from an output-info result. H.264 fills up to two entries (one per field for an interlaced picture); the other codecs fill only the first.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2GetPictureInfo(
        SceVideodec2OutputInfo* outputInfo, void* firstPictureInfoOut, void* secondPictureInfoOut);

    /// <summary>Fills one or two H.264 picture-info entries from an output-info result. The two out-pointer arguments carry the top and bottom field pictures for an interlaced stream.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2GetAvcPictureInfo(
        SceVideodec2OutputInfo* outputInfo,
        SceVideodec2AvcPictureInfo* firstPictureInfoOut,
        SceVideodec2AvcPictureInfo* secondPictureInfoOut);

    /// <summary>Fills an HEVC picture-info entry from an output-info result.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2GetHevcPictureInfo(
        SceVideodec2OutputInfo* outputInfo, SceVideodec2HevcPictureInfo* pictureInfoOut);

    /// <summary>Fills a VP9 picture-info entry from an output-info result.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVideodec2GetVp9PictureInfo(
        SceVideodec2OutputInfo* outputInfo, SceVideodec2Vp9PictureInfo* pictureInfoOut);
}
