// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Video;

/// <summary>Which compressed form the compute-shader video decoder reads.</summary>
public enum VdecswCodecType : uint
{
    /// <summary>H.264 / MPEG-4 Part 10.</summary>
    Avc = 1,

    /// <summary>H.265 High Efficiency Video Coding.</summary>
    Hevc = 974921,

    /// <summary>VP9.</summary>
    Vp9 = 2382845,
}

/// <summary>What the decoder is built on.</summary>
public enum VdecswResourceType : uint
{
    /// <summary>Decoding runs on a compute queue.</summary>
    Compute = 1,
}

/// <summary>The H.264 profile a stream is coded at.</summary>
public enum VdecswAvcProfile : uint
{
    /// <summary>Baseline profile.</summary>
    Baseline = 66,

    /// <summary>Main profile.</summary>
    Main = 77,

    /// <summary>High profile, the usual one for a recorded file.</summary>
    High = 100,
}

/// <summary>The H.264 level a stream is coded at.</summary>
public enum VdecswAvcLevel : uint
{
    /// <summary>Level 1.</summary>
    Level1 = 10,
    /// <summary>Level 1b.</summary>
    Level1b = 111,
    /// <summary>Level 1.1.</summary>
    Level1_1 = 11,
    /// <summary>Level 1.2.</summary>
    Level1_2 = 12,
    /// <summary>Level 1.3.</summary>
    Level1_3 = 13,
    /// <summary>Level 2.</summary>
    Level2 = 20,
    /// <summary>Level 2.1.</summary>
    Level2_1 = 21,
    /// <summary>Level 2.2.</summary>
    Level2_2 = 22,
    /// <summary>Level 3.</summary>
    Level3 = 30,
    /// <summary>Level 3.1.</summary>
    Level3_1 = 31,
    /// <summary>Level 3.2.</summary>
    Level3_2 = 32,
    /// <summary>Level 4.</summary>
    Level4 = 40,
    /// <summary>Level 4.1.</summary>
    Level4_1 = 41,
    /// <summary>Level 4.2.</summary>
    Level4_2 = 42,
    /// <summary>Level 5.</summary>
    Level5 = 50,
    /// <summary>Level 5.1.</summary>
    Level5_1 = 51,
    /// <summary>Level 5.2.</summary>
    Level5_2 = 52,
    /// <summary>Level 6.</summary>
    Level6 = 60,
    /// <summary>Level 6.1.</summary>
    Level6_1 = 61,
    /// <summary>Level 6.2.</summary>
    Level6_2 = 62,
}

/// <summary>The HEVC profile a stream is coded at.</summary>
public enum VdecswHevcProfile : uint
{
    /// <summary>Main profile.</summary>
    Main = 1,

    /// <summary>Main10 profile.</summary>
    Main10 = 2,
}

/// <summary>The HEVC level a stream is coded at.</summary>
public enum VdecswHevcLevel : uint
{
    /// <summary>Level 1.</summary>
    Level1 = 30,
    /// <summary>Level 2.</summary>
    Level2 = 60,
    /// <summary>Level 2.1.</summary>
    Level2_1 = 63,
    /// <summary>Level 3.</summary>
    Level3 = 90,
    /// <summary>Level 3.1.</summary>
    Level3_1 = 93,
    /// <summary>Level 4.</summary>
    Level4 = 120,
    /// <summary>Level 4.1.</summary>
    Level4_1 = 123,
    /// <summary>Level 5.</summary>
    Level5 = 150,
    /// <summary>Level 5.1.</summary>
    Level5_1 = 153,
    /// <summary>Level 5.2.</summary>
    Level5_2 = 156,
    /// <summary>Level 6.</summary>
    Level6 = 180,
    /// <summary>Level 6.1.</summary>
    Level6_1 = 183,
    /// <summary>Level 6.2.</summary>
    Level6_2 = 186,
}

/// <summary>Which HEVC tier the decoder handles, matching general_tier_flag in the stream.</summary>
public enum VdecswHevcTierType : int
{
    /// <summary>Main tier (general_tier_flag == 0).</summary>
    Main = 0,

    /// <summary>High tier (general_tier_flag == 1).</summary>
    High = 1,
}

/// <summary>How hard the GPU is pushed while decoding HEVC.</summary>
public enum VdecswHevcGpuLoadLevel : uint
{
    /// <summary>The default level used for HEVC.</summary>
    Level1 = 1,
}

/// <summary>The VP9 profile a stream is coded at.</summary>
public enum VdecswVp9Profile : uint
{
    /// <summary>Profile 0 (8-bit 4:2:0).</summary>
    Profile0 = 0,

    /// <summary>Profile 2 (10-bit 4:2:0).</summary>
    Profile2 = 2,
}

/// <summary>The VP9 level a stream is coded at.</summary>
public enum VdecswVp9Level : uint
{
    /// <summary>Level 1.</summary>
    Level1 = 10,
    /// <summary>Level 1.1.</summary>
    Level1_1 = 11,
    /// <summary>Level 2.</summary>
    Level2 = 20,
    /// <summary>Level 2.1.</summary>
    Level2_1 = 21,
    /// <summary>Level 3.</summary>
    Level3 = 30,
    /// <summary>Level 3.1.</summary>
    Level3_1 = 31,
    /// <summary>Level 4.</summary>
    Level4 = 40,
    /// <summary>Level 4.1.</summary>
    Level4_1 = 41,
    /// <summary>Level 5.</summary>
    Level5 = 50,
    /// <summary>Level 5.1.</summary>
    Level5_1 = 51,
    /// <summary>Level 5.2.</summary>
    Level5_2 = 52,
    /// <summary>Level 6.</summary>
    Level6 = 60,
    /// <summary>Level 6.1.</summary>
    Level6_1 = 61,
    /// <summary>Level 6.2.</summary>
    Level6_2 = 62,
}

/// <summary>The color space signalled in a VP9 bitstream.</summary>
public enum VdecswVp9Color : uint
{
    /// <summary>Unknown color space.</summary>
    Unknown = 0,
    /// <summary>BT.601.</summary>
    Bt601 = 1,
    /// <summary>BT.709.</summary>
    Bt709 = 2,
    /// <summary>SMPTE 170.</summary>
    Smpte170 = 3,
    /// <summary>SMPTE 240.</summary>
    Smpte240 = 4,
    /// <summary>BT.2020.</summary>
    Bt2020 = 5,
    /// <summary>sRGB.</summary>
    Srgb = 7,
}

/// <summary>How the decoder is set up: what it decodes, how large a picture it must handle, and where its threads run.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswDecoderConfigInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>What the decoder is built on, from <see cref="VdecswResourceType"/>.</summary>
    public uint ResourceType;

    /// <summary>Which compressed form to read, from <see cref="VdecswCodecType"/>.</summary>
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

    /// <summary>Additional DPB frames to hold beyond the profile minimum, or -1 for automatic.</summary>
    public sbyte ExtraDpbFrameCount;

    /// <summary>Codec-specific extra settings, or null. Points to <see cref="SceVdecswHevcExtraConfigInfo"/> or <see cref="SceVdecswVp9ExtraConfigInfo"/> when the codec calls for one.</summary>
    public void* ExtraConfigInfo;

    /// <summary>Whether the caller drives the input side without waiting on the decoder's completion.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool DisableSyncDecodeInput;

    private byte _pad0;
    private ushort _pad1;

    /// <summary>How many decode requests may be in flight when the input side does not wait.</summary>
    public uint MaxPendingSyncCount;
}

/// <summary>How much memory of each kind the decoder needs, and where the caller has put it.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswDecoderMemoryInfo
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

/// <summary>One compressed access unit handed to the decoder.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswInputData
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>The compressed bytes.</summary>
    public void* AuData;

    /// <summary>How many compressed bytes there are.</summary>
    public nuint AuSize;

    /// <summary>When the picture should be shown, or 0xFFFFFFFFFFFFFFFF for unknown.</summary>
    public ulong PtsData;

    /// <summary>When the access unit should be decoded, or 0xFFFFFFFFFFFFFFFF for unknown.</summary>
    public ulong DtsData;

    /// <summary>A value of the caller's own, handed back with the picture.</summary>
    public ulong AttachedData;
}

/// <summary>What came back from the input side after the decoder took an access unit.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswInputResult
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>The access unit the decoder finished with.</summary>
    public void* DecodedAu;

    /// <summary>How many pictures the decoder produced from it.</summary>
    public uint OutputFrameCount;

    private uint _reserved0;
}

/// <summary>What came out of a decode call on the output side.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswOutputInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether a picture is present.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    /// <summary>Whether this is the last picture from the current sequence.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsLastFrame;

    /// <summary>Whether the picture was decoded from damaged input.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsErrorFrame;

    /// <summary>How many pictures this output carries.</summary>
    public byte PictureCount;

    /// <summary>Which compressed form produced it.</summary>
    public uint CodecType;

    /// <summary>The picture's width in pixels.</summary>
    public uint FrameWidth;

    /// <summary>The picture's row stride in pixels.</summary>
    public uint FramePitch;

    /// <summary>The picture's height in pixels.</summary>
    public uint FrameHeight;

    /// <summary>Whether the picture was dropped rather than shown.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsDiscardedFrame;

    private byte _pad0;
    private ushort _pad1;

    /// <summary>Where the picture is.</summary>
    public void* FrameBuffer;

    /// <summary>How large the picture buffer is.</summary>
    public nuint FrameBufferSize;

    /// <summary>The picture's pixel arrangement.</summary>
    public uint FrameFormat;

    /// <summary>The picture's row stride in bytes.</summary>
    public uint FramePitchInBytes;
}

/// <summary>A picture buffer offered to the decoder to write into.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswFrameBuffer
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Where the buffer is.</summary>
    public void* FrameBuffer;

    /// <summary>How large the buffer is.</summary>
    public nuint FrameBufferSize;
}

/// <summary>How much memory a compute queue needs, and where the caller has put it.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceVdecswComputeMemoryInfo
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
public struct SceVdecswComputeConfigInfo
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

/// <summary>Codec-specific extra settings for an HEVC decoder.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVdecswHevcExtraConfigInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Which HEVC tier the decoder handles, from <see cref="VdecswHevcTierType"/>.</summary>
    public int TierType;

    /// <summary>The largest bit depth the decoder accepts for the luma plane.</summary>
    public sbyte MaxBitDepthLuma;

    /// <summary>The largest bit depth the decoder accepts for the chroma planes.</summary>
    public sbyte MaxBitDepthChroma;

    private ushort _reserved0;

    /// <summary>The largest temporal id the decoder outputs, or -1 for every id.</summary>
    public int MaxTemporalIdToDecode;

    /// <summary>The pixel arrangement used for HDR frames.</summary>
    public uint HdrFrameFormat;

    /// <summary>How hard the GPU is pushed for HEVC, from <see cref="VdecswHevcGpuLoadLevel"/>.</summary>
    public uint GpuLoadLevel;
}

/// <summary>Codec-specific extra settings for a VP9 decoder.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVdecswVp9ExtraConfigInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>The largest bit depth the decoder accepts (8 or 10).</summary>
    public sbyte MaxBitDepth;

    private byte _pad0;
    private ushort _pad1;

    /// <summary>The pixel arrangement used for HDR frames.</summary>
    public uint HdrFrameFormat;
}

/// <summary>Per-picture information for an H.264 stream, taken from the decoded picture.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVdecswAvcPictureInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether the picture info is present.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    private byte _pad0;
    private ushort _pad1;
    private uint _pad2;

    /// <summary>When the picture should be shown.</summary>
    public ulong PtsData;

    /// <summary>When the picture was decoded.</summary>
    public ulong DtsData;

    /// <summary>The caller's value that came in with the access unit.</summary>
    public ulong AttachedData;

    /// <summary>Whether the picture is an IDR frame.</summary>
    public byte IdrPictureFlag;

    /// <summary>The profile id from the SPS.</summary>
    public byte ProfileIdc;

    /// <summary>The level id from the SPS.</summary>
    public byte LevelIdc;

    private byte _pad3;

    /// <summary>The stored picture width in macroblocks, minus one.</summary>
    public uint PicWidthInMbsMinus1;

    /// <summary>The stored picture height in map units, minus one.</summary>
    public uint PicHeightInMapUnitsMinus1;

    /// <summary>Whether the sequence is coded as frames only.</summary>
    public byte FrameMbsOnlyFlag;

    /// <summary>Whether the picture carries cropping offsets.</summary>
    public byte FrameCroppingFlag;

    private ushort _pad4;

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

/// <summary>Per-picture information for an HEVC stream, taken from the decoded picture.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVdecswHevcPictureInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether the picture info is present.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    private byte _pad0;
    private ushort _pad1;
    private uint _pad2;

    /// <summary>When the picture should be shown.</summary>
    public ulong PtsData;

    /// <summary>When the picture was decoded.</summary>
    public ulong DtsData;

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

    private byte _pad3;

    /// <summary>The number of time units in one tick.</summary>
    public uint NumUnitsInTick;

    /// <summary>The number of ticks in one second.</summary>
    public uint TimeScale;

    /// <summary>Whether aspect-ratio information is signalled.</summary>
    public uint AspectRatioInfoPresentFlag;

    /// <summary>The aspect-ratio id from the VUI.</summary>
    public byte AspectRatioIdc;

    private byte _pad4;

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

    private ushort _pad6;

    /// <summary>The left crop offset.</summary>
    public uint FrameCropLeftOffset;

    /// <summary>The right crop offset.</summary>
    public uint FrameCropRightOffset;

    /// <summary>The top crop offset.</summary>
    public uint FrameCropTopOffset;

    /// <summary>The bottom crop offset.</summary>
    public uint FrameCropBottomOffset;
}

/// <summary>Per-picture information for a VP9 stream, taken from the decoded picture.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceVdecswVp9PictureInfo
{
    /// <summary>The size of this structure in bytes.</summary>
    public nuint ThisSize;

    /// <summary>Whether the picture info is present.</summary>
    [MarshalAs(UnmanagedType.U1)] public bool IsValid;

    private byte _pad0;
    private ushort _pad1;
    private uint _pad2;

    /// <summary>When the picture should be shown.</summary>
    public ulong PtsData;

    /// <summary>When the picture was decoded.</summary>
    public ulong DtsData;

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

    /// <summary>Bit depth of the picture (8 or 10).</summary>
    public byte BitDepth;

    /// <summary>Sample range: 0 for studio, 1 for full.</summary>
    public byte ColorRange;

    private ushort _pad3;

    /// <summary>Color space, from <see cref="VdecswVp9Color"/>.</summary>
    public uint ColorSpace;

    /// <summary>How many frames are packed in this super-frame.</summary>
    public uint NumFrames;

    /// <summary>Coded frame width in pixels.</summary>
    public uint FrameWidth;

    /// <summary>Coded frame height in pixels.</summary>
    public uint FrameHeight;

    /// <summary>Render (display) width in pixels.</summary>
    public uint RenderWidth;

    /// <summary>Render (display) height in pixels.</summary>
    public uint RenderHeight;
}

/// <summary>
/// Compressed video decoding on a compute queue. The caller provides every piece of memory: it asks how
/// much a compute queue needs and creates one, asks how much a decoder needs and creates it, then feeds
/// access units in on the input side, offers picture buffers on the output side, and receives back
/// decoded frames along with codec-specific per-picture information.
/// </summary>
public static unsafe partial class Vdecsw
{
    private const string Lib = "libSceVdecsw";

    /// <summary>Value passed to a decoder or DPB size to let the decoder decide.</summary>
    public const int AutoFrameSetting = -1;

    /// <summary>Run the decoder's threads on whichever processors the caller uses.</summary>
    public const ulong InheritAffinityMask = 0;

    /// <summary>Run the decoder's threads at the caller's priority.</summary>
    public const int InheritThreadPriority = -1;

    /// <summary>Timestamp value that stands in for an unknown PTS or DTS.</summary>
    public const ulong TimestampInvalid = 0xFFFFFFFFFFFFFFFFUL;

    /// <summary>The usual pixel arrangement for a decoded picture (NV12 linear).</summary>
    public const uint FrameFormatDefault = 0;

    /// <summary>Pixel arrangement for HDR frames: three 10-bit samples packed to 32 bits.</summary>
    public const uint FrameFormat10_10_10_2 = 49738;

    /// <summary>Extra DPB frames count that lets the decoder decide.</summary>
    public const sbyte ExtraDpbFrameCountAuto = -1;

    /// <summary>Default extra DPB frames count.</summary>
    public const sbyte ExtraDpbFrameCountDefault = 1;

    /// <summary>Asks how much memory a compute queue needs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswQueryComputeMemoryInfo(SceVdecswComputeMemoryInfo* computeMemInfoOut);

    /// <summary>Takes a compute queue using the memory named in <paramref name="computeMemInfoIn"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswAllocateComputeQueue(
        SceVdecswComputeConfigInfo* computeCfgInfoIn,
        SceVdecswComputeMemoryInfo* computeMemInfoIn,
        void** computeQueueOut);

    /// <summary>Gives a compute queue back.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswReleaseComputeQueue(void* computeQueue);

    /// <summary>Asks how much memory a decoder with these settings needs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswQueryDecoderMemoryInfo(
        SceVdecswDecoderConfigInfo* decoderConfigInfoIn,
        SceVdecswDecoderMemoryInfo* decoderMemoryInfoOut);

    /// <summary>Creates a decoder from the settings and memory the caller has prepared.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswCreateDecoder(
        SceVdecswDecoderConfigInfo* decoderConfigInfoIn,
        SceVdecswDecoderMemoryInfo* decoderMemoryInfoIn,
        void** decoderInstanceOut);

    /// <summary>Destroys a decoder.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswDeleteDecoder(void* decoderInstance);

    /// <summary>Drops what the decoder was carrying, for a seek.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswResetDecoder(void* decoderInstance);

    /// <summary>Hands one compressed access unit to the input side of the decoder.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswSetDecodeInput(void* decoderInstance, SceVdecswInputData* inputDataIn);

    /// <summary>Waits for the input side to finish consuming an access unit and reports what came of it.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswSyncDecodeInput(void* decoderInstance, SceVdecswInputResult* inputResultOut);

    /// <summary>Non-blocking check for the input side; returns immediately when nothing has completed yet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswTrySyncDecodeInput(void* decoderInstance, SceVdecswInputResult* inputResultOut);

    /// <summary>Offers a picture buffer to the output side of the decoder.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswSetDecodeOutput(void* decoderInstance, SceVdecswFrameBuffer* frameBufferInOut);

    /// <summary>Waits for the output side to produce a picture and reports it.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswSyncDecodeOutput(void* decoderInstance, SceVdecswOutputInfo* outputInfoOut);

    /// <summary>Non-blocking check for the output side; returns immediately when no picture is ready yet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswTrySyncDecodeOutput(void* decoderInstance, SceVdecswOutputInfo* outputInfoOut);

    /// <summary>Closes out the current decode sequence, flushing whatever the decoder was still holding.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswFinalizeDecodeSequence(void* decoderInstance);

    /// <summary>Fills a codec-appropriate picture-info structure from an output-info result. The two out-pointer arguments carry one or two pictures depending on the codec.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswGetPictureInfo(
        SceVdecswOutputInfo* outputInfoIn,
        void* firstPictureInfoOut,
        void* secondPictureInfoOut);

    /// <summary>Fills an AVC picture-info pair from an output-info result (one entry per field for interlaced input).</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswGetAvcPictureInfo(
        SceVdecswOutputInfo* outputInfoIn,
        SceVdecswAvcPictureInfo* firstPictureInfoOut,
        SceVdecswAvcPictureInfo* secondPictureInfoOut);

    /// <summary>Fills an HEVC picture-info structure from an output-info result.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswGetHevcPictureInfo(
        SceVdecswOutputInfo* outputInfoIn,
        SceVdecswHevcPictureInfo* pictureInfoOut);

    /// <summary>Fills a VP9 picture-info structure from an output-info result.</summary>
    [LibraryImport(Lib)]
    public static partial int sceVdecswGetVp9PictureInfo(
        SceVdecswOutputInfo* outputInfoIn,
        SceVdecswVp9PictureInfo* pictureInfoOut);
}
