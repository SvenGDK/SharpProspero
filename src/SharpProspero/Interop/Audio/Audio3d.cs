// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Audio;

/// <summary>A point in the listener's space, passed to the speaker-array mix query. Three floats.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudio3dPosition
{
    /// <summary>The x coordinate.</summary>
    public float X;
    /// <summary>The y coordinate.</summary>
    public float Y;
    /// <summary>The z coordinate.</summary>
    public float Z;
}

/// <summary>
/// Object-based spatial audio: reserve objects, set their position and attributes, and mix them to a port. Signatures from audio3d.h.
/// </summary>
public static unsafe partial class Audio3d
{
    private const string Lib = "libSceAudio3d";

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dInitialize(long iReserved);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dTerminate();

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortOpen(int iUserId, void* pParameters, void* pId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortClose(uint uiPortId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortSetAttribute(uint uiPortId, uint uiAttributeId, void* pAttribute, nuint szAttribute);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortAdvance(uint uiPortId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortPush(uint uiPortId, uint eBlocking);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortGetAttributesSupported(uint uiPortId, void* pCapabilities, void* pNumCapabilities);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortGetQueueLevel(uint uiPortId, void* pQueueLevel, void* pQueueAvailable);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dObjectReserve(uint uiPortId, void* pId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dObjectUnreserve(uint uiPortId, uint uiObjectId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dObjectSetAttributes(uint uiPortId, uint uiObjectId, nuint szNumAttributes, void* pAttributeArray);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dBedWrite(uint uiPortId, uint uiNumChannels, uint eFormat, void* pBuffer, uint uiNumSamples);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dBedWrite2(uint uiPortId, uint uiNumChannels, uint eFormat, void* pBuffer, uint uiNumSamples, uint eOutputRoute, byte bRestricted);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial nuint sceAudio3dGetSpeakerArrayMemorySize(uint uiNumSpeakers, byte bIs3d);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dCreateSpeakerArray(void** pHandle, void* pParameters);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dDeleteSpeakerArray(void* handle);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dGetSpeakerArrayMixCoefficients(void* handle, SceAudio3dPosition pos, float fSpread, void* pCoefficients, uint uiNumCoefficients);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dGetSpeakerArrayMixCoefficients2(void* handle, SceAudio3dPosition pos, float fSpread, void* pCoefficients, uint uiNumCoefficients, byte bHeightAware, float fDownmixSpreadRadius);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dAudioOutOpen(uint uiPortId, int userId, int type, int index, uint len, uint freq, uint param);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dAudioOutClose(int handle);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dAudioOutOutput(int handle, void* ptr);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dAudioOutOutputs(void* param, uint num);

    /// <summary>Fills <paramref name="pParameters"/> with the recommended defaults for opening a port.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dGetDefaultOpenParameters(void* pParameters);

    /// <summary>Reads the current runtime status of a port.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortGetStatus(uint uiPortId, void* pStatus);

    /// <summary>Returns a static UTF-8 error string for the given error code, or null when the code is unknown.</summary>
    [LibraryImport(Lib)]
    public static partial byte* sceAudio3dStrError(int iErrorCode);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortCreate(uint uiGranularity, uint eRate, long iReserved, void* pId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortDestroy(uint uiPortId);

    /// <summary>Imported from the module.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudio3dPortFlush(uint uiPortId);

}