// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Audio;

/// <summary>The sample form of an audio buffer passed to the library.</summary>
public enum AudioPropagationPcmType : uint
{
    /// <summary>32-bit floating-point samples.</summary>
    Float = 0,

    /// <summary>16-bit signed samples.</summary>
    Int16 = 1,
}

/// <summary>The output speaker layout used by a rendered source.</summary>
public enum AudioPropagationOutputFormat : uint
{
    /// <summary>First-order Ambisonics, deinterleaved, four contiguous channels.</summary>
    AmbisonicsFirstOrder = 0,

    /// <summary>Second-order Ambisonics, deinterleaved, nine contiguous channels.</summary>
    AmbisonicsSecondOrder = 1,

    /// <summary>Third-order Ambisonics, deinterleaved, sixteen contiguous channels.</summary>
    AmbisonicsThirdOrder = 2,

    /// <summary>Eight interleaved channels in the order L-R-C-LFE-Lsurround-Rsurround-Lextend-Rextend.</summary>
    ChannelFloat8Ch = 4,

    /// <summary>Eight interleaved channels in the order L-R-C-LFE-Lextend-Rextend-Lsurround-Rsurround.</summary>
    ChannelFloat8ChStd = 5,
}

/// <summary>The formula used to attenuate a source by distance.</summary>
public enum AudioPropagationRolloffModel : uint
{
    /// <summary>Inverse distance attenuation.</summary>
    Inverse = 0,

    /// <summary>Linear interpolation attenuation.</summary>
    Linear = 1,

    /// <summary>Exponential attenuation.</summary>
    Exponential = 2,

    /// <summary>Inverse distance attenuation, clamped to a maximum distance.</summary>
    ClampedInverse = 3,

    /// <summary>Linear interpolation, clamped to a maximum distance.</summary>
    ClampedLinear = 4,

    /// <summary>Exponential attenuation, clamped to a maximum distance.</summary>
    ClampedExponential = 5,
}

/// <summary>Flags carried by an audio path between a source and the listener.</summary>
[Flags]
public enum AudioPropagationPathFlags : uint
{
    /// <summary>No flags are set on the path.</summary>
    None = 0,

    /// <summary>The path is not a valid route between the source and the listener.</summary>
    Invalid = 1 << 0,

    /// <summary>The path travels through a portal.</summary>
    Portal = 1 << 1,
}

/// <summary>The kind of filter a source uses for material absorption.</summary>
public enum AudioPropagationFilterType : int
{
    /// <summary>Frequency-domain filters for material absorption.</summary>
    Frequency = 0,

    /// <summary>Time-domain filters for material absorption.</summary>
    Time = 1,
}

/// <summary>System-level option flags used when creating the propagation context.</summary>
[Flags]
public enum AudioPropagationOptionFlags : uint
{
    /// <summary>No options are set.</summary>
    None = 0,

    /// <summary>Use the Acm library to run the audio processing jobs.</summary>
    Acm = 1u << 0,
}

/// <summary>Attribute identifiers for a source. Each carries a payload of a specific type.</summary>
public enum AudioPropagationSourceAttribute : uint
{
    /// <summary>The source's position relative to the listener. Payload: <see cref="SceAudioPropagationVector3"/>.</summary>
    Position = 0x00000000,

    /// <summary>A vector describing the forward direction of the source. Payload: <see cref="SceAudioPropagationVector3"/>.</summary>
    Direction = 0x00000001,

    /// <summary>The distance-based attenuation settings. Payload: <see cref="SceAudioPropagationRolloff"/>.</summary>
    Rolloff = 0x00000002,

    /// <summary>The directional cone attenuation settings. Payload: <see cref="SceAudioPropagationCone"/>.</summary>
    Cone = 0x00000003,

    /// <summary>A buffer of audio data emitted by the source. Payload: <see cref="SceAudioPropagationPcm"/>.</summary>
    Pcm = 0x00000004,

    /// <summary>The DSP filter used by the source. Payload: <see cref="SceAudioPropagationFilter"/>.</summary>
    Filter = 0x00000005,

    /// <summary>The Acm batch used by the source. Payload: <see cref="SceAudioPropagationAcmBatch"/>.</summary>
    AcmBatch = 0x00000006,

    /// <summary>Handle of the room the source is inside. Payload: <c>ulong</c> room handle.</summary>
    Room = 0x00000007,
}

/// <summary>Attribute identifiers for a portal. Each carries a payload of a specific type.</summary>
public enum AudioPropagationPortalAttribute : uint
{
    /// <summary>The portal's position relative to the listener. Payload: <see cref="SceAudioPropagationVector3"/>.</summary>
    Position = 0x00010000,

    /// <summary>A room this portal connects. Payload: <see cref="SceAudioPropagationPortalRoom"/>.</summary>
    Room = 0x00010001,

    /// <summary>Extents of the portal. Payload: <see cref="SceAudioPropagationVector3"/>.</summary>
    Extents = 0x00010002,

    /// <summary>A vector describing the forward direction of the portal. Payload: <see cref="SceAudioPropagationVector3"/>.</summary>
    Forwards = 0x00010003,

    /// <summary>A vector describing the upward direction of the portal. Payload: <see cref="SceAudioPropagationVector3"/>.</summary>
    Upwards = 0x00010004,
}

/// <summary>Attribute identifiers for the system. Each carries a payload of a specific type.</summary>
public enum AudioPropagationSystemAttribute : uint
{
    /// <summary>Handle of the room the listener is inside. Payload: <c>ulong</c> room handle.</summary>
    Room = 0x00020000,
}

/// <summary>Structure identifiers written into the descriptor of every versioned API structure.</summary>
public enum AudioPropagationStructId : uint
{
    /// <summary>Identifier written into a <see cref="SceAudioPropagationMaterial"/> descriptor.</summary>
    Material = 0x010107D1,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationAudioPathPoint"/> descriptor.</summary>
    PathPoint = 0x010107D2,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationAudioPath"/> descriptor.</summary>
    Path = 0x010107D3,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationSystemMemory"/> descriptor.</summary>
    SystemMemory = 0x010107D4,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationSystemOption"/> descriptor.</summary>
    SystemOption = 0x010107D5,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationSourceRenderInfo"/> descriptor.</summary>
    SourceRenderInfo = 0x010107D6,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationRay"/> descriptor.</summary>
    Ray = 0x010107D7,

    /// <summary>Identifier written into a <see cref="SceAudioPropagationPortalSettings"/> descriptor.</summary>
    PortalSettings = 0x010107D8,
}

/// <summary>
/// Header carried by every versioned API structure. A caller sets <see cref="Id"/> to the matching
/// <see cref="AudioPropagationStructId"/> value and <see cref="Size"/> to <c>sizeof</c> of the outer
/// structure, which lets the library reject structures of the wrong shape.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationStructDescriptor
{
    /// <summary>The structure identifier. Set to one of the <see cref="AudioPropagationStructId"/> values.</summary>
    public uint Id;

    /// <summary>The size of the outer structure in bytes, including this header.</summary>
    public nuint Size;
}

/// <summary>A buffer of audio data emitted by a source.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationPcm
{
    /// <summary>The memory location of the audio data.</summary>
    public void* Data;

    /// <summary>The size of the data buffer in bytes.</summary>
    public uint DataSizeBytes;

    /// <summary>The sample format, from <see cref="AudioPropagationPcmType"/>.</summary>
    public uint DataType;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>A three-dimensional vector with a trailing pad word to align the structure to eight bytes.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationVector3
{
    /// <summary>The horizontal axis offset.</summary>
    public float X;

    /// <summary>The vertical axis offset.</summary>
    public float Y;

    /// <summary>The depth axis offset.</summary>
    public float Z;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>
/// The directionality of a sound source, modelled as a nested pair of coaxial cones with a gain that
/// interpolates between the inner level and the outer level as the listener leaves the inner cone and
/// enters the outer one.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationCone
{
    /// <summary>Gain inside the inner cone. Range 0.0 to 2.0.</summary>
    public float InnerLevel;

    /// <summary>The inner cone angle in degrees. Range 0.0 to 360.0.</summary>
    public float InnerAngle;

    /// <summary>Gain outside the outer cone. Range 0.0 to 2.0.</summary>
    public float OuterLevel;

    /// <summary>The outer cone angle in degrees. Range from <see cref="InnerAngle"/> up to 360.0.</summary>
    public float OuterAngle;
}

/// <summary>The parameters that describe how volume attenuates with distance from a source.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationRolloff
{
    /// <summary>The rolloff formula, from <see cref="AudioPropagationRolloffModel"/>.</summary>
    public uint Model;

    /// <summary>The distance past which no further rolloff occurs. Must be 0 or greater.</summary>
    public float MaxDistance;

    /// <summary>The rolloff factor. Must be 0 or greater.</summary>
    public float RolloffFactor;

    /// <summary>The reference distance. Range from 0 to <see cref="MaxDistance"/>.</summary>
    public float ReferenceDistance;
}

/// <summary>
/// A material with absorption coefficients at six frequency bands. When a material is assigned to a
/// reflection point on a path, audio that reflects at that point is altered by the coefficients.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationMaterial
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.Material"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The unique name of the material, up to fifteen bytes plus a trailing NUL.</summary>
    public fixed byte Name[16];

    /// <summary>The absorption coefficient at 125 Hz.</summary>
    public float Absorption125;

    /// <summary>The absorption coefficient at 250 Hz.</summary>
    public float Absorption250;

    /// <summary>The absorption coefficient at 500 Hz.</summary>
    public float Absorption500;

    /// <summary>The absorption coefficient at 1 kHz.</summary>
    public float Absorption1k;

    /// <summary>The absorption coefficient at 2 kHz.</summary>
    public float Absorption2k;

    /// <summary>The absorption coefficient at 4 kHz.</summary>
    public float Absorption4k;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>
/// A single point on an audio path. The material at the point specifies which surface the audio is
/// reflecting off, and the position places the point in listener-relative space.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationAudioPathPoint
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.PathPoint"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The handle of the material at the reflection point.</summary>
    public ulong Material;

    /// <summary>The volume multiplier applied at this point.</summary>
    public float Gain;

    /// <summary>The listener-relative position of the point.</summary>
    public SceAudioPropagationVector3 Pos;
}

/// <summary>
/// A route travelled by audio from a source to the listener. The first point is the source, the last
/// point is the listener at the origin, and intermediate points are reflections against surfaces. The
/// fixed-size point array holds up to <see cref="SceAudioPropagation.MaxPathPoints"/> entries; the
/// active count is written to <see cref="NumPoints"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationAudioPath
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.Path"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The first path point. Index 0 in the four-slot point array.</summary>
    public SceAudioPropagationAudioPathPoint Point0;

    /// <summary>The second path point. Index 1 in the four-slot point array.</summary>
    public SceAudioPropagationAudioPathPoint Point1;

    /// <summary>The third path point. Index 2 in the four-slot point array.</summary>
    public SceAudioPropagationAudioPathPoint Point2;

    /// <summary>The fourth path point. Index 3 in the four-slot point array.</summary>
    public SceAudioPropagationAudioPathPoint Point3;

    /// <summary>The number of active entries in the point array.</summary>
    public uint NumPoints;

    /// <summary>Flags describing the path, from <see cref="AudioPropagationPathFlags"/>.</summary>
    public uint Flags;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>
/// The two memory regions the library uses. The CPU region is always required. The GPU-mapped region
/// is only required when <see cref="AudioPropagationOptionFlags.Acm"/> is set.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationSystemMemory
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.SystemMemory"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>Pointer to the buffer used for CPU work.</summary>
    public void* PCpuMem;

    /// <summary>The size of the CPU buffer in bytes.</summary>
    public nuint SizeCpuMem;

    /// <summary>Pointer to a GPU-mapped buffer. May be null when the Acm option is not enabled.</summary>
    public void* PGpuMem;

    /// <summary>The size of the GPU buffer in bytes.</summary>
    public nuint SizeGpuMem;
}

/// <summary>The settings the library is initialized with. Fill in every field before the create call.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationSystemOption
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.SystemOption"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The maximum number of sources that can be handled at once.</summary>
    public uint MaxSources;

    /// <summary>The maximum number of materials that can be registered at once.</summary>
    public uint MaxMaterials;

    /// <summary>The maximum number of raycasts per source.</summary>
    public uint MaxRaycasts;

    /// <summary>The maximum number of reflections in any single path.</summary>
    public uint MaxBounces;

    /// <summary>The render grain per source, in samples per channel. Must be 512, 1024, 2048, or 4096.</summary>
    public uint UpdateGrain;

    /// <summary>The speed of sound in metres per second.</summary>
    public float SpeedOfSound;

    /// <summary>The maximum path distance between a source and the listener, in metres.</summary>
    public float MaxDistance;

    /// <summary>System option flags, from <see cref="AudioPropagationOptionFlags"/>.</summary>
    public uint Flags;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>Rendering information for one source in a batched render call.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationSourceRenderInfo
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.SourceRenderInfo"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The source to render.</summary>
    public ulong SourceHandle;

    /// <summary>The buffer that receives the rendered audio, mixed on top of existing content.</summary>
    public float* Buffer;

    /// <summary>The size of the buffer in bytes.</summary>
    public nuint BufferSize;

    /// <summary>The required output format, from <see cref="AudioPropagationOutputFormat"/>.</summary>
    public uint Format;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>
/// A raycast the library needs the caller to run against game geometry. The library fills in the
/// start position and direction; the caller writes back the collision position, normal and material
/// handle.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationRay
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.Ray"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The start position of the ray.</summary>
    public SceAudioPropagationVector3 Start;

    /// <summary>The direction of the ray.</summary>
    public SceAudioPropagationVector3 Dir;

    /// <summary>The position where the ray collided with geometry.</summary>
    public SceAudioPropagationVector3 CollisionPosition;

    /// <summary>The normal of the collision surface.</summary>
    public SceAudioPropagationVector3 CollisionNormal;

    /// <summary>The handle of the material at the collision point.</summary>
    public ulong CollisionMaterial;
}

/// <summary>The filter settings a source uses. Carried by <see cref="AudioPropagationSourceAttribute.Filter"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioPropagationFilter
{
    /// <summary>The filter kind, from <see cref="AudioPropagationFilterType"/>.</summary>
    public int Type;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>
/// The Acm batch a source's jobs are appended to. Carried by <see cref="AudioPropagationSourceAttribute.AcmBatch"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationAcmBatch
{
    /// <summary>Pointer to the Acm batch descriptor the source's jobs are added to.</summary>
    public void* PBatchInfo;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>The pair of rooms connected by a portal. Carried by <see cref="AudioPropagationPortalAttribute.Room"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationPortalRoom
{
    /// <summary>Handles of the two rooms this portal connects.</summary>
    public fixed ulong HRoom[2];
}

/// <summary>The creation settings for a portal, passed to the create call.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationPortalSettings
{
    /// <summary>The structure header. Set <see cref="SceAudioPropagationStructDescriptor.Id"/> to <see cref="AudioPropagationStructId.PortalSettings"/> and <see cref="SceAudioPropagationStructDescriptor.Size"/> to the size of this structure.</summary>
    public SceAudioPropagationStructDescriptor Desc;

    /// <summary>The portal's listener-relative position.</summary>
    public SceAudioPropagationVector3 Position;

    /// <summary>The portal's forward direction.</summary>
    public SceAudioPropagationVector3 Forward;

    /// <summary>The portal's upward direction.</summary>
    public SceAudioPropagationVector3 Upward;

    /// <summary>The portal's half-size along each axis.</summary>
    public SceAudioPropagationVector3 Extents;

    /// <summary>Handles of the two rooms this portal connects.</summary>
    public fixed ulong HRoom[2];
}

/// <summary>One entry in the attribute array passed to a set-attributes call.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioPropagationAttribute
{
    /// <summary>The attribute identifier, from one of <see cref="AudioPropagationSourceAttribute"/>, <see cref="AudioPropagationPortalAttribute"/>, or <see cref="AudioPropagationSystemAttribute"/>.</summary>
    public uint AttributeId;

    /// <summary>Pointer to the attribute payload.</summary>
    public void* Value;

    /// <summary>The size of the payload in bytes.</summary>
    public nuint ValueSize;

    /// <summary>Unused. Must be 0.</summary>
    public uint Pad;
}

/// <summary>
/// Sound propagation. The library takes source positions, room and portal topology, material data
/// and raycast results, and produces a set of specular audio paths plus a rendered mix per source in
/// the chosen output layout. A caller creates a system, registers materials, adds rooms, portals and
/// sources, feeds raycasts back to the system every frame, and calls the render entry point once per
/// audio block to fill destination buffers.
/// </summary>
public static unsafe partial class SceAudioPropagation
{
    private const string Lib = "libSceAudioPropagation";

    /// <summary>The maximum number of reflections in a single path.</summary>
    public const int MaxBounces = 2;

    /// <summary>The maximum number of paths a source may hold.</summary>
    public const int MaxPaths = 36;

    /// <summary>The maximum number of points in a path.</summary>
    public const int MaxPathPoints = 4;

    /// <summary>The library's operating sample rate in hertz.</summary>
    public const int SampleRate = 48000;

    /// <summary>The smallest render grain, in samples per channel.</summary>
    public const int MinGrain = 512;

    /// <summary>The largest render grain, in samples per channel.</summary>
    public const int MaxGrain = 4096;

    /// <summary>The maximum number of materials that can be registered at once.</summary>
    public const int MaxMaterials = 64;

    /// <summary>The maximum number of sources the library can process.</summary>
    public const int MaxSources = 64;

    /// <summary>The maximum number of portals the library supports.</summary>
    public const int MaxPortals = 32;

    /// <summary>The maximum number of rooms a portal can connect.</summary>
    public const int MaxPortalRooms = 2;

    /// <summary>The maximum number of rooms the library supports.</summary>
    public const int MaxRooms = 32;

    /// <summary>The minimum number of rays reported per source.</summary>
    public const int MinRaycasts = 6;

    /// <summary>The maximum number of rays reported per source.</summary>
    public const int MaxRaycasts = 6;

    /// <summary>The maximum length in bytes of a material name, excluding the trailing NUL.</summary>
    public const int MaterialNameMaxLen = 15;

    /// <summary>The handle value that represents no handle.</summary>
    public const ulong HandleNone = 0;

    /// <summary>The default speed of sound used by the library, in metres per second.</summary>
    public const float DefaultSpeedOfSound = 343.0f;

    /// <summary>The maximum speed of sound the library accepts, in metres per second.</summary>
    public const float MaxSpeedOfSound = DefaultSpeedOfSound * 4.0f;

    /// <summary>The maximum path distance between a source and the listener, in metres.</summary>
    public const float MaxPathDistance = MaxSpeedOfSound;

    /// <summary>The number of channels required for first-order Ambisonics output.</summary>
    public const int ChannelsAmbisonicsFirstOrder = 4;

    /// <summary>The number of channels required for second-order Ambisonics output.</summary>
    public const int ChannelsAmbisonicsSecondOrder = 9;

    /// <summary>The number of channels required for third-order Ambisonics output.</summary>
    public const int ChannelsAmbisonicsThirdOrder = 16;

    /// <summary>The number of channels required for 7.1 output.</summary>
    public const int Channels8Ch = 8;

    /// <summary>Reads the memory requirements the library needs to run with the given options.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemQueryMemory(SceAudioPropagationSystemOption* pOptions, SceAudioPropagationSystemMemory* pOutMemorySize);

    /// <summary>Creates a system context. The caller supplies the option and memory blocks and receives a system handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemCreate(SceAudioPropagationSystemOption* pOptions, SceAudioPropagationSystemMemory* pMemory, ulong* phOutSystemHandle);

    /// <summary>Destroys a system context and releases every resource it owned.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemDestroy(ulong hSystemHandle);

    /// <summary>Reads out the raycasts the library needs the caller to run this frame. The count is a bidirectional argument: the array's capacity going in, the number filled coming out.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemGetRays(ulong hSystemHandle, SceAudioPropagationRay* pRays, uint* puNumRays);

    /// <summary>Hands the completed raycasts back to the library.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemSetRays(ulong hSystemHandle, SceAudioPropagationRay* pRays, uint uNumRays);

    /// <summary>Sets system-level attributes such as the listener's current room.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemSetAttributes(ulong hSystemHandle, SceAudioPropagationAttribute* pAttributes, uint uNumAttributes);

    /// <summary>Renders one audio block for a batch of sources. Output is mixed on top of the existing contents of each destination buffer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceRender(ulong hSystemHandle, SceAudioPropagationSourceRenderInfo* pRenderInfo, uint uNumSources);

    /// <summary>Creates a source and returns its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceCreate(ulong hSystemHandle, ulong* phOutSourceHandle);

    /// <summary>Fills each entry in an attribute array with the library's default value for that attribute id.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationResetAttributes(SceAudioPropagationAttribute* pAttributes, uint uNumAttributes);

    /// <summary>Releases a source handle back to the library.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceDestroy(ulong hSystemHandle, ulong hSourceHandle);

    /// <summary>Sets the attributes of a source, such as its position, direction, rolloff and current room.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceSetAttributes(ulong hSourceHandle, SceAudioPropagationAttribute* pAttributes, uint uNumAttributes);

    /// <summary>Reads out the raycasts the library needs for one source's paths. The count is a bidirectional argument.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceGetRays(ulong hSourceHandle, SceAudioPropagationRay* pRays, uint* puNumRays);

    /// <summary>Uses raycast results to calculate specular audio paths between a source and the listener up to a given reflection order.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceCalculateAudioPaths(ulong hSourceHandle, SceAudioPropagationRay* pRays, uint uNumRays, uint uMaxOrder, SceAudioPropagationAudioPath* pPathsOut, uint uNumPaths);

    /// <summary>Reads how many audio paths a source currently holds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceGetAudioPathCount(ulong hSourceHandle, uint* puNumAudioPathsOut);

    /// <summary>Retrieves the handle of one audio path owned by a source, addressed by index.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceGetAudioPath(ulong hSourceHandle, uint uId, ulong* phAudioPathOut);

    /// <summary>Overwrites the point list of an audio path handle and sets its output gain.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSourceSetAudioPath(ulong hPathHandle, SceAudioPropagationAudioPath* pPath, float fGain);

    /// <summary>Reads how many points a given audio path currently holds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationPathGetNumPoints(ulong hPathHandle, uint* puNumPathPointsOut);

    /// <summary>Registers a caller-defined material and returns its handle. Path points may then reference the material to shape reflections.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemRegisterMaterial(ulong hSystemHandle, SceAudioPropagationMaterial* pMaterial, ulong* phMaterialHandleOut);

    /// <summary>Unregisters a previously registered material.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationSystemUnregisterMaterial(ulong hMaterialHandle);

    /// <summary>Creates a portal that connects two rooms and returns its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationPortalCreate(ulong hSystemHandle, SceAudioPropagationPortalSettings* pSettings, ulong* phPortalHandleOut);

    /// <summary>Destroys a portal.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationPortalDestroy(ulong hSystemHandle, ulong hPortalHandle);

    /// <summary>Sets attributes on a portal, such as its position, extents, forward and upward vectors, and connected rooms.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationPortalSetAttributes(ulong hPortalHandle, SceAudioPropagationAttribute* pAttributes, uint uNumAttributes);

    /// <summary>Creates a room and returns its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationRoomCreate(ulong hSystemHandle, ulong* phRoomHandleOut);

    /// <summary>Destroys a room.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioPropagationRoomDestroy(ulong hSystemHandle, ulong hRoomHandle);
}
