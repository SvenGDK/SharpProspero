// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Audio;

/// <summary>The kind of Original File Length metadata found in an MP3 bitstream.</summary>
public enum SceAjmDecMp3OflType : uint
{
    /// <summary>No OFL data.</summary>
    None = 0,
    /// <summary>LAME OFL data.</summary>
    Lame = 1,
    /// <summary>VBRI header.</summary>
    Vbri = 2,
    /// <summary>Fraunhofer OFL.</summary>
    Fgh = 3,
    /// <summary>VBRI header followed by Fraunhofer OFL.</summary>
    VbriAndFgh = 4,
}

/// <summary>ATRAC9 configuration information reported by <see cref="Ajm.sceAjmDecAt9ParseConfigData"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAjmDecAt9ConfigDataInfo
{
    /// <summary>Number of channels in the frame.</summary>
    public uint Channels;
    /// <summary>Sample rate of the frame in hertz.</summary>
    public uint SampleRate;
    /// <summary>Number of samples per channel in a frame.</summary>
    public uint FrameSamplesPerCh;
    /// <summary>Number of samples per channel in a super-frame.</summary>
    public uint SuperFrameSamplesPerCh;
    /// <summary>Size in bytes of a super-frame.</summary>
    public uint SuperFrameSize;
}

/// <summary>Information about an MP3 frame reported by <see cref="Ajm.sceAjmDecMp3ParseFrame"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAjmDecMp3ParseFrame
{
    /// <summary>Size of the parsed frame in bytes.</summary>
    public nuint FrameSize;
    /// <summary>Number of channels in the frame.</summary>
    public uint NumChannels;
    /// <summary>Number of samples per channel in the frame.</summary>
    public uint NumSamplesPerChannel;
    /// <summary>Frame bitrate in bits per second.</summary>
    public uint Bitrate;
    /// <summary>Sample rate of the frame in hertz.</summary>
    public uint SampleRate;
    /// <summary>Encoder delay recorded in the OFL data, or zero when the OFL was not parsed.</summary>
    public uint EncoderDelay;
    /// <summary>Total number of frames recorded in the OFL data, or zero when the OFL was not parsed.</summary>
    public uint NumFrames;
    /// <summary>Total number of samples recorded in the OFL data, or zero when the OFL was not parsed.</summary>
    public uint TotalSamples;
    /// <summary>The kind of OFL data that was found.</summary>
    public SceAjmDecMp3OflType OflType;
}

/// <summary>
/// The audio job manager: batched decode and encode for Opus, AAC, MP3, ATRAC9 and the other codecs. Signatures from ajm.h.
/// </summary>
public static unsafe partial class Ajm
{
    private const string Lib = "libSceAjm";

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmInitialize(long initializeFlag, void* pContext);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmFinalize(uint uiContext);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmMemoryRegister(uint uiContext, void* pRegion, nuint szNumPages);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmMemoryUnregister(uint uiContext, void* pRegion);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmModuleRegister(uint uiContext, uint uiCodec, long iReserved);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmModuleUnregister(uint uiContext, uint uiCodec);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmInstanceCreate(uint uiContext, uint uiCodec, ulong uiFlags, void* pInstance);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmInstanceExtend(uint uiContext, uint uiCodec, ulong uiFlags, uint uiInstance);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmInstanceSwitch(uint uiContext, uint uiCodec, ulong uiFlags, uint uiInstance);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmInstanceDestroy(uint uiContext, uint uiInstance);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchInitialize(void* pBuffer, nuint szBuffer, void* pInfo);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobInitialize(void* pInfo, uint uiInstance, void* pCodecParameters, nuint szCodecParametersSize, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobClearContext(void* pInfo, uint uiInstance, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobDecode(void* pInfo, uint uiInstance, void* pBitstreamInput, nuint szBitstreamInputSize, void* pPcmOutput, nuint szPcmOutputSize, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobDecodeSingle(void* pInfo, uint uiInstance, void* pBitstreamInput, nuint szBitstreamInputSize, void* pPcmOutput, nuint szPcmOutputSize, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobDecodeSplit(void* pInfo, uint uiInstance, void* pDataInputBuffers, nuint szNumDataInputBuffers, void* pDataOutputBuffers, nuint szNumDataOutputBuffers, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobEncode(void* pInfo, uint uiInstance, void* pPcmInput, nuint szPcmInputSize, void* pBitstreamOutput, nuint szBitstreamOutputSize, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobGetInfo(void* pInfo, uint uiInstance, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobGetCodecInfo(void* pInfo, uint uiInstance, void* pResult, nuint szResultSize);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobSetGaplessDecode(void* pInfo, uint uiInstance, void* pGaplessDecode, int iReset, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobGetGaplessDecode(void* pInfo, uint uiInstance, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobSetResampleParameters(void* pInfo, uint uiInstance, float fResampleRatio, uint uiFlags, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobSetResampleParametersEx(void* pInfo, uint uiInstance, float fRatioStart, float fRatioChangePerSample, uint uiFlags, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobGetResampleInfo(void* pInfo, uint uiInstance, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchStart(uint uiContext, void* pInfo, int iPriority, void* pBatchError, void* pBatch);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchWait(uint uiContext, uint uiBatch, uint uiTimeout, void* pBatchError);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchCancel(uint uiContext, uint uiBatch);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchErrorDump(void* pInfo, void* pBatchError);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobGetStatistics(void* pInfo, float fInterval, void* pResult);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobControl(void* pInfo, uint uiInstance, ulong uiFlags, void* pSidebandInput, nuint szSidebandInputSize, void* pSidebandOutput, nuint szSidebandOutputSize);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobRun(void* pInfo, uint uiInstance, ulong uiFlags, void* pDataInput, nuint szDataInputSize, void* pDataOutput, nuint szDataOutputSize, void* pSidebandOutput, nuint szSidebandOutputSize);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmBatchJobRunSplit(void* pInfo, uint uiInstance, ulong uiFlags, void* pDataInputBuffers, nuint szNumDataInputBuffers, void* pDataOutputBuffers, nuint szNumDataOutputBuffers, void* pSidebandOutput, nuint szSidebandOutputSize);

    /// <summary>Parses an ATRAC9 configuration data blob and fills <paramref name="pConfigDataInfo"/> with the described stream shape.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmDecAt9ParseConfigData(void* pConfigData, SceAjmDecAt9ConfigDataInfo* pConfigDataInfo);

    /// <summary>Parses an MP3 frame and reports its shape; pass a non-zero <paramref name="iParseOfl"/> to also read Original File Length data from the ancillary bytes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAjmDecMp3ParseFrame(void* pBitstream, nuint szBitstream, int iParseOfl, SceAjmDecMp3ParseFrame* pFrameInfo);

    /// <summary>Returns a static null-terminated text description of an AJM error code.</summary>
    [LibraryImport(Lib)]
    public static partial byte* sceAjmStrError(int iErrorCode);
}