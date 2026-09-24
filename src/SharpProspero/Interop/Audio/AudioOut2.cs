// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Audio;

/// <summary>Which mix a port feeds.</summary>
public enum AudioOut2PortType : ushort
{
    /// <summary>The main mix.</summary>
    Main = 0,
    /// <summary>Background music, which the system lowers on its own.</summary>
    Bgm = 1,
    /// <summary>Speech.</summary>
    Voice = 2,
    /// <summary>The controller's own speaker.</summary>
    PadSpeaker = 3,
    /// <summary>One player's own output.</summary>
    Personal = 4,
    /// <summary>A side chain.</summary>
    Aux = 5,
    /// <summary>The controller's haptics.</summary>
    Vibration = 6,
    /// <summary>The main mix, as a placeable object rather than fixed channels.</summary>
    ObjectMain = (1 << 8) | Main,
    /// <summary>Speech, as a placeable object.</summary>
    ObjectVoice = (1 << 8) | Voice,
    /// <summary>One player's own output, as a placeable object.</summary>
    ObjectPersonal = (1 << 8) | Personal,
}

/// <summary>The sample form and channel count a port takes.</summary>
public enum AudioOut2DataFormat : uint
{
    /// <summary>One channel of 16-bit samples.</summary>
    I16Mono = 1 | (1 << 8),
    /// <summary>Two channels of 16-bit samples.</summary>
    I16Stereo = 1 | (2 << 8),
    /// <summary>Eight channels of 16-bit samples.</summary>
    I16EightChannel = 1 | (8 << 8),
    /// <summary>Eight channels of 16-bit samples in the standard channel order.</summary>
    I16EightChannelStandard = 1 | (1 << 7) | (8 << 8),
    /// <summary>One channel of floating-point samples.</summary>
    FloatMono = 0 | (1 << 8),
    /// <summary>Two channels of floating-point samples.</summary>
    FloatStereo = 0 | (2 << 8),
    /// <summary>Eight channels of floating-point samples.</summary>
    FloatEightChannel = 0 | (8 << 8),
    /// <summary>Eight channels of floating-point samples in the standard channel order.</summary>
    FloatEightChannelStandard = (1 << 7) | (8 << 8),
}

/// <summary>What one entry of an attribute list sets on a context.</summary>
public enum AudioOut2ContextAttribute : uint
{
    /// <summary>How wide an object sounds when the mix is folded down.</summary>
    DownmixSpreadRadius = 0,
    /// <summary>Whether that fold-down keeps height.</summary>
    DownmixSpreadHeightAware = 1,
    /// <summary>Whether the fold-down follows the machine's speaker setting.</summary>
    DownmixFollowSpeakerSetting = 2,
    /// <summary>Whether an ambisonic fold-down drops height.</summary>
    AmbisonicsDownmixSpreadHeightAwareOff = 3,
}

/// <summary>What one entry of an attribute list sets on a port.</summary>
public enum AudioOut2PortAttribute : uint
{
    /// <summary>The samples to play, as a <see cref="SceAudioOut2Pcm"/>.</summary>
    Pcm = 0,
    /// <summary>The port's level.</summary>
    Gain = 1,
    /// <summary>Which ports keep their own output when there are too many.</summary>
    Priority = 2,
    /// <summary>Where an object port sits, as a <see cref="SceAudioOut2Position"/>.</summary>
    Position = 3,
    /// <summary>How wide an object port sounds.</summary>
    Spread = 4,
    /// <summary>Sending the samples to one speaker untouched.</summary>
    Passthrough = 5,
    /// <summary>Clearing what the port has built up.</summary>
    ResetState = 6,
    /// <summary>A value the application gives its own meaning.</summary>
    ApplicationSpecific = 7,
    /// <summary>Which ambisonic channel the port carries.</summary>
    Ambisonics = 8,
    /// <summary>Whether the port is held back.</summary>
    Restricted = 9,
    /// <summary>How much of the port also reaches the main mix.</summary>
    MixToMainGain = 10,
}

/// <summary>Whether a push waits for room.</summary>
public enum AudioOut2Blocking : uint
{
    /// <summary>Return at once, whether or not the samples were taken.</summary>
    Async = 0,
    /// <summary>Wait until the samples are taken.</summary>
    Sync = 1,
}

/// <summary>Sending a port's samples to one speaker untouched.</summary>
public enum AudioOut2Passthrough : uint
{
    /// <summary>Mix it normally.</summary>
    None = 0,
    /// <summary>Send it to the left speaker alone.</summary>
    Left = 1,
    /// <summary>Send it to the right speaker alone.</summary>
    Right = 2,
}

/// <summary>How an ambisonic recording's channels are ordered.</summary>
public enum AudioOut2AmbisonicsChannelOrder : uint
{
    /// <summary>Ordered by channel number.</summary>
    Acn = 0,
    /// <summary>Ordered the older way.</summary>
    FuMa = 1,
}

/// <summary>Whether a speaker array corrects for speakers that are not really there.</summary>
public enum AudioOut2VbapCorrectionType : uint
{
    /// <summary>No correction.</summary>
    None = 0,
    /// <summary>Correct by adding a speaker that is not really there.</summary>
    VirtualSpeaker = 1,
}

/// <summary>Which output a mastering setting or measurement applies to.</summary>
public enum AudioOut2MasteringOutput : uint
{
    /// <summary>The speakers.</summary>
    Main = 0,
    /// <summary>The headphones.</summary>
    Headphone = 1,
    /// <summary>What a recording captures.</summary>
    Recording = 2,
}

/// <summary>What kind of speakers the machine is playing through.</summary>
public enum AudioOut2SpeakerType : uint
{
    /// <summary>A television.</summary>
    Television = 0,
    /// <summary>A receiver driving separate speakers.</summary>
    AvReceiver = 1,
    /// <summary>A single bar.</summary>
    SoundBar = 2,
    /// <summary>Headphones. Reported only when the query asks to follow them.</summary>
    Headphone = 3,
}

/// <summary>How much of a context there is to go round.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2ContextParam
{
    /// <summary>How many ports of any kind.</summary>
    public uint MaxPorts;
    /// <summary>How many of those may be placeable objects.</summary>
    public uint MaxObjectPorts;
    /// <summary>How many object ports are kept back for this context alone.</summary>
    public uint GuaranteeObjectPorts;
    /// <summary>How many pushes may be waiting at once.</summary>
    public uint QueueDepth;
    /// <summary>How many grains one push carries, counted at 48 kHz.</summary>
    public uint NumGrains;
    /// <summary>Set bit 0 to make this the main context.</summary>
    public uint Flags;
    /// <summary>Reserved. Leave zero.</summary>
    public fixed uint Reserved[10];
}

/// <summary>What one port carries.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2PortParam
{
    /// <summary>Which mix it feeds, from <see cref="AudioOut2PortType"/>.</summary>
    public ushort PortType;
    /// <summary>Padding. Leave zero.</summary>
    public ushort Pad;
    /// <summary>The sample form, from <see cref="AudioOut2DataFormat"/>.</summary>
    public uint DataFormat;
    /// <summary>Samples per second.</summary>
    public uint SamplingFreq;
    /// <summary>Set bit 0 to open the port held back.</summary>
    public uint Flags;
    /// <summary>Whose output this is, or zero for the application's own.</summary>
    public nuint UserHandle;
    /// <summary>Reserved. Leave zero.</summary>
    public fixed uint Reserved[10];
}

/// <summary>One thing being set on a context or a port.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2Attribute
{
    /// <summary>Which thing, from <see cref="AudioOut2ContextAttribute"/> or <see cref="AudioOut2PortAttribute"/>.</summary>
    public uint AttributeId;
    /// <summary>Padding. Leave zero.</summary>
    public uint Pad;
    /// <summary>What to set it to.</summary>
    public void* Value;
    /// <summary>How many bytes that is.</summary>
    public nuint ValueSize;
}

/// <summary>The samples a port is given, as the attribute value.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2Pcm
{
    /// <summary>The samples, in the port's own form.</summary>
    public void* Data;
}

/// <summary>Where an object port sits.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioOut2Position
{
    /// <summary>The first axis.</summary>
    public float X;
    /// <summary>The second axis.</summary>
    public float Y;
    /// <summary>The third axis.</summary>
    public float Z;
}

/// <summary>How loud the machine says the output is.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2SystemState
{
    /// <summary>The measured loudness.</summary>
    public float Loudness;
    /// <summary>Padding.</summary>
    public uint Pad;
    /// <summary>Reserved.</summary>
    public fixed ulong Reserved[7];
}

/// <summary>Where a port's samples are going and how loud.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2PortState
{
    /// <summary>Which outputs carry it, one bit each.</summary>
    public ushort Output;
    /// <summary>How many channels it carries.</summary>
    public byte NumChannels;
    /// <summary>Padding.</summary>
    public byte Pad1;
    /// <summary>Its level.</summary>
    public short Volume;
    /// <summary>Counts up each time the output it reaches changes.</summary>
    public ushort RerouteCounter;
    /// <summary>Bit 0 says three-dimensional output is available.</summary>
    public uint Flags;
    /// <summary>Padding.</summary>
    public uint Pad2;
    /// <summary>Reserved.</summary>
    public fixed ulong Reserved[6];
}

/// <summary>Correcting a speaker array for speakers that are not really there.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2VbapCorrectionParam
{
    /// <summary>Which correction, from <see cref="AudioOut2VbapCorrectionType"/>.</summary>
    public uint Type;
    /// <summary>How much of it to apply.</summary>
    public float Gain;
    /// <summary>Reserved. Leave zero.</summary>
    public fixed uint Reserved[6];
}

/// <summary>Where the speakers are, for working out per-speaker levels.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2SpeakerArrayParam
{
    /// <summary>Where each speaker sits.</summary>
    public SceAudioOut2Position* SpeakerPositions;
    /// <summary>How many there are, up to 32.</summary>
    public uint NumSpeakers;
    /// <summary>One when the positions carry height, nought when they are flat.</summary>
    public byte Is3d;
    /// <summary>Memory for the array, sized by <see cref="AudioOut2.sceAudioOut2GetSpeakerArrayMemorySize"/>.</summary>
    public void* Buffer;
    /// <summary>How many bytes that is.</summary>
    public nuint Size;
    /// <summary>Correcting for speakers that are not really there.</summary>
    public SceAudioOut2VbapCorrectionParam VbapCorrection;
}

/// <summary>How an ambisonic source is fed to a speaker array.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2AmbisonicsParam
{
    /// <summary>How the channels are ordered, from <see cref="AudioOut2AmbisonicsChannelOrder"/>.</summary>
    public uint AmbiChannelOrder;
    /// <summary>One to keep height, nought to drop it.</summary>
    public byte HeightAware;
    /// <summary>Padding. Leave zero.</summary>
    public byte Pad1;
    /// <summary>Padding. Leave zero.</summary>
    public ushort Pad2;
    /// <summary>Reserved. Leave zero.</summary>
    public fixed uint Reserved[6];
}

/// <summary>Where one speaker sits, as two angles.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioOut2SpeakerAngle
{
    /// <summary>How far round.</summary>
    public short Azimuth;
    /// <summary>How far up.</summary>
    public short Elevation;
}

/// <summary>What the machine is playing through and where its speakers are.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOut2SpeakerInfo
{
    /// <summary>Which kind, from <see cref="AudioOut2SpeakerType"/>.</summary>
    public byte Type;
    /// <summary>Padding.</summary>
    public byte Pad1;
    /// <summary>Padding.</summary>
    public ushort Pad2;
    /// <summary>Which of the sixteen angles below are filled in, one bit each.</summary>
    public uint AvailableBits;
    /// <summary>Bit 0 says three-dimensional output is available.</summary>
    public uint Flags;
    /// <summary>Padding.</summary>
    public uint Pad3;
    /// <summary>Where each speaker sits, two shorts each.</summary>
    public fixed short SpeakerAngle[32];
}

/// <summary>
/// The object-based output path. A context holds a pool of ports and a queue; a port carries one
/// stream of samples into a mix, and a port opened as an object is placed in space rather than fed to
/// fixed channels. Samples and placing are both set through the attribute list, so a frame is: set the
/// attributes on each port, advance the context, push it.
/// </summary>
/// <remarks>
/// This is a separate library out of the same module the older output path lives in, and the two are
/// alternatives rather than layers. An application uses one or the other.
/// </remarks>
public static unsafe partial class AudioOut2
{
    private const string Lib = "libSceAudioOut";

    /// <summary>The handle value that names no context.</summary>
    public const ulong InvalidContext = ulong.MaxValue;

    /// <summary>The handle value that names no port.</summary>
    public const ulong InvalidPort = ulong.MaxValue;

    /// <summary>Set on a port type to open it as a placeable object.</summary>
    public const int ObjectPortFlag = 1 << 8;

    /// <summary>
    /// Starts the service. Destroying every context is what gives its memory back; the library's own
    /// teardown entry point is left out here because nothing declares what it takes.
    /// </summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2Initialize();

    /// <summary>Fills <paramref name="params"/> with the context defaults.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2ContextResetParam(SceAudioOut2ContextParam* @params);

    /// <summary>How much memory a context described by <paramref name="params"/> needs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2ContextQueryMemory(
        SceAudioOut2ContextParam* @params, nuint* memorySize);

    /// <summary>Creates a context in caller-supplied memory.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2ContextCreate(
        SceAudioOut2ContextParam* @params, void* buffer, nuint bufferSize, ulong* context);

    /// <summary>Destroys a context and every port in it.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2ContextDestroy(ulong context);

    /// <summary>Sets one or more context attributes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2ContextSetAttributes(
        ulong context, SceAudioOut2Attribute* attributes, uint numAttributes);

    /// <summary>Moves the context on to the next block of samples.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2ContextAdvance(ulong context);

    /// <summary>Hands the block to the output, waiting for room or not.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2ContextPush(ulong context, AudioOut2Blocking blocking);

    /// <summary>Reads how many pushes are waiting and how many more will fit.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2ContextGetQueueLevel(
        ulong context, uint* queueLevel, uint* availableQueues);

    /// <summary>Opens a port on a context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2PortCreate(
        ulong context, SceAudioOut2PortParam* @params, ulong* port);

    /// <summary>Closes a port.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2PortDestroy(ulong port);

    /// <summary>Sets one or more port attributes, which is how samples and placing are supplied.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2PortSetAttributes(
        ulong port, SceAudioOut2Attribute* attributes, uint numAttributes);

    /// <summary>Reads where a port's samples are going and how loud.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2PortGetState(ulong port, SceAudioOut2PortState* state);

    /// <summary>How much memory a speaker array of the given shape needs.</summary>
    [LibraryImport(Lib)]
    public static partial nuint sceAudioOut2GetSpeakerArrayMemorySize(
        uint numSpeakers, byte is3d, byte isAmbisonics);

    /// <summary>
    /// Builds a speaker array. Pass <paramref name="ambisonicsParams"/> as null for a plain array.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2SpeakerArrayCreate(
        void** handle, SceAudioOut2SpeakerArrayParam* vbapParams, SceAudioOut2AmbisonicsParam* ambisonicsParams);

    /// <summary>Releases a speaker array.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2SpeakerArrayDestroy(void* handle);

    /// <summary>Works out the level for each speaker for a source at <paramref name="pos"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2GetSpeakerArrayCoefficients(
        void* handle, SceAudioOut2Position pos, float spread, float* coefficients, uint numCoefficients,
        byte heightAware, float downmixSpreadRadius);

    /// <summary>Works out the level for each speaker for one ambisonic channel.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2GetSpeakerArrayAmbisonicsCoefficients(
        void* handle, uint ambisonicsChannel, float* coefficients, uint numCoefficients);

    /// <summary>Reads how loud the machine says the output is.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2GetSystemState(SceAudioOut2SystemState* states);

    /// <summary>Reads what the machine is playing through and where its speakers are.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2GetSpeakerInfo(SceAudioOut2SpeakerInfo* info, uint flags);

    /// <summary>Opens a handle standing for one signed-in user, for a port of that user's own.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2UserCreate(uint userId, nuint* handle);

    /// <summary>Releases a user handle.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2UserDestroy(nuint handle);

    /// <summary>Reads which context and port attributes that user's output accepts.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2UserGetSupportedAttributes(
        nuint handle, uint* contextSupportedAttributes, uint* portSupportedAttributes);

    /// <summary>Allows chat audio alongside the application's own.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2EnableChat();

    /// <summary>Stops chat audio alongside the application's own.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2DisableChat();

    /// <summary>Starts the mastering pass over the finished mix.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2MasteringInit(uint flags);

    /// <summary>Stops the mastering pass.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2MasteringTerm();

    /// <summary>
    /// Sets what the mastering pass does to one output, from <see cref="AudioOut2MasteringOutput"/>.
    /// <paramref name="param"/> points at the header of one of the parameter blocks the mastering
    /// definitions declare.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2MasteringSetParam(
        void* param, AudioOut2MasteringOutput output, uint flags);

    /// <summary>
    /// Reads what the mastering pass measured on one output. <paramref name="user"/> is a handle from
    /// <see cref="sceAudioOut2UserCreate"/>, or zero for the application's own output.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2MasteringGetState(
        void* state, AudioOut2MasteringOutput output, nuint user);

    // Low-latency mirror of the context / port family. Every entry takes the same handles and the
    // same parameter blocks as its counterpart above; it drives the low-latency audio clock instead
    // of the shared one, with a shallow queue and a small grain so the output answers as soon as
    // the hardware clock will take it.

    /// <summary>Starts the low-latency service.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2LoInit();

    /// <summary>Stops the low-latency service.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2LoTerminate();

    /// <summary>How much memory a low-latency context described by <paramref name="params"/> needs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoContextQueryMemory(
        SceAudioOut2ContextParam* @params, nuint* memorySize);

    /// <summary>Creates a low-latency context in caller-supplied memory.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoContextCreate(
        SceAudioOut2ContextParam* @params, void* buffer, nuint bufferSize, ulong* context);

    /// <summary>Destroys a low-latency context and every port in it.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2LoContextDestroy(ulong context);

    /// <summary>Sets one or more low-latency context attributes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoContextSetAttributes(
        ulong context, SceAudioOut2Attribute* attributes, uint numAttributes);

    /// <summary>Moves the low-latency context on to the next block of samples.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2LoContextAdvance(ulong context);

    /// <summary>Hands the block to the low-latency output, waiting for room or not.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2LoContextPush(ulong context, AudioOut2Blocking blocking);

    /// <summary>Reads how many low-latency pushes are waiting and how many more will fit.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoContextGetQueueLevel(
        ulong context, uint* queueLevel, uint* availableQueues);

    /// <summary>Opens a low-latency port on a context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoPortCreate(
        ulong context, SceAudioOut2PortParam* @params, ulong* port);

    /// <summary>Closes a low-latency port.</summary>
    [LibraryImport(Lib)] public static partial int sceAudioOut2LoPortDestroy(ulong port);

    /// <summary>Sets one or more low-latency port attributes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoPortSetAttributes(
        ulong port, SceAudioOut2Attribute* attributes, uint numAttributes);

    /// <summary>Reads where a low-latency port's samples are going and how loud.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOut2LoPortGetState(
        ulong port, SceAudioOut2PortState* state);
}
