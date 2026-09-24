// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Audio;

/// <summary>The output port a handle drives.</summary>
public enum AudioOutPortType
{
    /// <summary>The main output.</summary>
    Main = 0,

    /// <summary>Background music.</summary>
    Bgm = 1,

    /// <summary>Voice chat.</summary>
    Voice = 2,

    /// <summary>A personal (per-user) output.</summary>
    Personal = 3,

    /// <summary>The controller speaker.</summary>
    PadSpeaker = 4,

    /// <summary>The controller vibration channel.</summary>
    Vibration = 10,

    /// <summary>An auxiliary output.</summary>
    Aux = 127,
}

/// <summary>The sample format of a port.</summary>
public enum AudioOutFormat : uint
{
    /// <summary>16-bit signed, one channel.</summary>
    S16Mono = 0,

    /// <summary>16-bit signed, two channels, interleaved.</summary>
    S16Stereo = 1,

    /// <summary>16-bit signed, eight channels.</summary>
    S16Eight = 2,

    /// <summary>32-bit float, one channel.</summary>
    FloatMono = 3,

    /// <summary>32-bit float, two channels, interleaved.</summary>
    FloatStereo = 4,

    /// <summary>32-bit float, eight channels.</summary>
    FloatEight = 5,
}

/// <summary>Which outputs a port's samples are reaching. Several bits can be set at once.</summary>
[Flags]
public enum AudioOutStateOutput : ushort
{
    /// <summary>Nothing is carrying the port.</summary>
    Unknown = 0,

    /// <summary>The main output.</summary>
    Primary = 1 << 0,

    /// <summary>The second output.</summary>
    Secondary = 1 << 1,

    /// <summary>The controller speaker.</summary>
    ControllerSpeaker = 1 << 2,

    /// <summary>A headset attached over USB or a wireless link.</summary>
    Headphone = 1 << 6,

    /// <summary>Something outside the machine: a recording, a remote session, a spectator.</summary>
    External = 1 << 7,
}

/// <summary>Which modules of the mastering chain are turned off.</summary>
/// <remarks>
/// Set the bits on the module bypass field inside a mastering-parameters struct before handing the
/// struct to <see cref="AudioOut.sceAudioOutMasteringSetParam"/>. A cleared field runs every module.
/// </remarks>
[Flags]
public enum AudioOutMasteringModuleBypass : uint
{
    /// <summary>Every module runs.</summary>
    None = 0,

    /// <summary>Skip the parametric equaliser.</summary>
    ParamEq = 1u << 0,

    /// <summary>Skip the multi-band compressor.</summary>
    Compressor = 1u << 1,

    /// <summary>Skip the master-volume module.</summary>
    MasterVolume = 1u << 2,

    /// <summary>Skip the peak limiter.</summary>
    Limiter = 1u << 3,

    /// <summary>Skip every module.</summary>
    All = 0xFFFFFFFFu,
}

/// <summary>Extra behaviour for the mastering chain, passed to init and to <see cref="AudioOut.sceAudioOutMasteringSetParam"/>.</summary>
[Flags]
public enum AudioOutMasteringFlags : uint
{
    /// <summary>No extra behaviour.</summary>
    None = 0,

    /// <summary>Run the compressor before the equaliser instead of after it.</summary>
    SwapEqCompressor = 1u << 0,
}

/// <summary>
/// Where a port's samples are going and how loud, as a status call fills it in.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceAudioOutPortState
{
    /// <summary>Which outputs carry the port, from <see cref="AudioOutStateOutput"/>.</summary>
    public ushort Output;

    /// <summary>How many channels those outputs take: 1, 2, 6 or 8, and 0 when nothing is attached.</summary>
    public byte Channel;

    private byte _reserved;

    /// <summary>The port's level.</summary>
    public short Volume;

    /// <summary>
    /// Counts up each time the output the port reaches changes. A different value from the last frame
    /// means the samples are now going somewhere else, which is when a mix built for a speaker layout
    /// has to be rebuilt.
    /// </summary>
    public ushort RerouteCounter;

    /// <summary>Reserved for future use.</summary>
    public ulong Flag;

    private fixed ulong _reserved64[2];
}

/// <summary>One entry of a multi-port push: which port, and the samples for it.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceAudioOutOutputParam
{
    /// <summary>The port handle.</summary>
    public int Handle;

    private int _pad;

    /// <summary>The block of samples for that port, in the port's own format.</summary>
    public void* Ptr;
}

/// <summary>
/// The output subsystem's overall state, as <see cref="AudioOut.sceAudioOutGetSystemState"/> fills it in.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 32)]
public unsafe struct SceAudioOutSystemState
{
    /// <summary>
    /// The measured loudness of the whole output mix, in LKFS. Reads no lower than
    /// <see cref="AudioOut.LoudnessMin"/> when the measurement has not yet settled or is disabled.
    /// </summary>
    public float Loudness;

    private fixed byte _reserved8[4];
    private fixed ulong _reserved64[3];
}

/// <summary>
/// The four-byte header every mastering-parameters struct starts with. A caller fills a larger
/// parameters struct (parametric-equaliser, compressor, master-volume, limiter, or the wrapper that
/// carries all four), then hands its address to <see cref="AudioOut.sceAudioOutMasteringSetParam"/> as
/// a pointer to this header.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioOutMasteringParamsHeader
{
    /// <summary>Which parameters struct follows the header. See <see cref="AudioOut.MasteringParamsIdDefault"/>.</summary>
    public uint ParamsId;
}

/// <summary>
/// The four-byte header every mastering-states struct starts with. A caller fills a larger states
/// struct, then hands its address to <see cref="AudioOut.sceAudioOutMasteringGetState"/> as a pointer
/// to this header; the call writes the running compressor and limiter meters back into it.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceAudioOutMasteringStatesHeader
{
    /// <summary>Which states struct follows the header. See <see cref="AudioOut.MasteringStatesIdDefault"/>.</summary>
    public uint StatesId;
}

/// <summary>
/// Audio-output bindings. Initialize the subsystem, open a port for a user with a grain (samples per
/// output block), a sample rate and a format, then push one block of samples at a time. Each output
/// call blocks until the queue has room for the block, which paces the caller to the audio clock.
/// The mastering group at the bottom of this class configures the finalizer chain (parametric
/// equaliser, multi-band compressor, master volume, peak limiter) that shapes every port's output
/// before it leaves the machine.
/// </summary>
/// <remarks>
/// This library publishes no way to ask how much room the queue has left, so a caller cannot decide
/// whether a push will block before making it. The object-based path in <see cref="AudioOut2"/> does
/// publish one - <see cref="AudioOut2.sceAudioOut2ContextGetQueueLevel"/> - and is the path to take when
/// output must never stall the caller.
/// </remarks>
public static unsafe partial class AudioOut
{
    private const string Lib = "libSceAudioOut";

    /// <summary>The 0 dB volume level (unattenuated).</summary>
    public const int Volume0Db = 0x8000;

    /// <summary>Smallest grain (samples per block).</summary>
    public const uint MinGrain = 256;

    /// <summary>Largest grain (samples per block).</summary>
    public const uint MaxGrain = 256 * 8;

    /// <summary>Left-channel select bit for the volume call.</summary>
    public const int VolumeFlagLeft = 1 << 0;

    /// <summary>Right-channel select bit for the volume call.</summary>
    public const int VolumeFlagRight = 1 << 1;

    /// <summary>The 0 dB mix level for <see cref="sceAudioOutSetMixLevelPadSpk"/> (unattenuated).</summary>
    public const int PadSpeakerMixLevel0Db = 0x8000;

    /// <summary>The system's default pad-speaker mix level, -9 dB.</summary>
    public const int PadSpeakerMixLevelDefault = 11626;

    /// <summary>The floor a <see cref="SceAudioOutSystemState.Loudness"/> reading reaches while the measurement is idle, in LKFS.</summary>
    public const float LoudnessMin = -70.0f;

    /// <summary>The parameters-struct identifier that goes in <see cref="SceAudioOutMasteringParamsHeader.ParamsId"/> for the default wrapper.</summary>
    public const uint MasteringParamsIdDefault = 1;

    /// <summary>The states-struct identifier that goes in <see cref="SceAudioOutMasteringStatesHeader.StatesId"/> for the default wrapper.</summary>
    public const uint MasteringStatesIdDefault = 1;

    /// <summary>Initializes the audio-output subsystem. Call once before opening a port.</summary>
    /// <returns>Zero on success, or a negative error code (including an already-initialized code).</returns>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutInit();

    /// <summary>Opens an output port. Returns a non-negative handle or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutOpen(int userId, int type, int index, uint length, uint freq, uint param);

    /// <summary>Closes a port.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutClose(int handle);

    /// <summary>
    /// Outputs one block of samples from <paramref name="ptr"/>, blocking until the queue has room for
    /// it. A null <paramref name="ptr"/> is the end-of-output case: the call waits for the block already
    /// queued and leaves the port idle instead of submitting another, which is how a port is emptied
    /// before it is closed.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutOutput(int handle, void* ptr);

    /// <summary>Sets the per-channel volume; <paramref name="flag"/> selects the channels in <paramref name="vol"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutSetVolume(int handle, int flag, int* vol);

    /// <summary>The most ports one <see cref="sceAudioOutOutputs"/> call may carry.</summary>
    public const int MaxOutputs = 8;

    /// <summary>
    /// Pushes a block to each of <paramref name="num"/> ports at once, so several ports stay in step
    /// rather than drifting apart as separate blocking pushes would let them.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutOutputs(SceAudioOutOutputParam* param, uint num);

    /// <summary>
    /// Reads the time of the port's last output, on the audio clock. Comparing successive readings says
    /// how far the output has advanced, which is what tells a caller how far behind its own mixing is.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutGetLastOutputTime(int handle, ulong* outputTime);

    /// <summary>Reads where a port's samples are going and how loud.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutGetPortState(int handle, SceAudioOutPortState* state);

    /// <summary>
    /// Reads the output subsystem's overall state into <paramref name="state"/>. The one field a caller
    /// reads is the measured loudness of the whole mix.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutGetSystemState(SceAudioOutSystemState* state);

    /// <summary>
    /// Sets how loud a controller-speaker port sounds when its samples are folded into a headset. The
    /// level is on the same 0-32768 scale as <see cref="sceAudioOutSetVolume"/>, with
    /// <see cref="PadSpeakerMixLevel0Db"/> for unattenuated and <see cref="PadSpeakerMixLevelDefault"/>
    /// for the system's own -9 dB starting point.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutSetMixLevelPadSpk(int handle, int mixLevel);

    /// <summary>
    /// Initialises the mastering chain (parametric equaliser, multi-band compressor, master volume,
    /// peak limiter) that finalises every port's output before it leaves the machine. Call once, before
    /// setting parameters or reading meters, and pair with <see cref="sceAudioOutMasteringTerm"/> at
    /// shutdown.
    /// </summary>
    /// <param name="flags">Extra behaviour, from <see cref="AudioOutMasteringFlags"/> (0 for the standard chain order).</param>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutMasteringInit(uint flags);

    /// <summary>
    /// Applies a mastering-parameters struct. The caller fills a wrapper struct (whose first field is
    /// <see cref="SceAudioOutMasteringParamsHeader"/>) with an equaliser, compressor, master-volume and
    /// limiter block, then hands its address here as a pointer to the header.
    /// </summary>
    /// <param name="param">A pointer to a parameters struct that starts with a header.</param>
    /// <param name="flags">Extra behaviour, from <see cref="AudioOutMasteringFlags"/> (0 for the standard chain order).</param>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutMasteringSetParam(SceAudioOutMasteringParamsHeader* param, uint flags);

    /// <summary>
    /// Reads the mastering chain's running meters back into the caller's states struct. The caller fills
    /// only the <see cref="SceAudioOutMasteringStatesHeader.StatesId"/> field of the header; the call
    /// then writes the compressor input-RMS and gain-reduction, and the limiter input, output and gain
    /// peaks into the rest of the struct.
    /// </summary>
    /// <param name="state">A pointer to a states struct that starts with a header.</param>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutMasteringGetState(SceAudioOutMasteringStatesHeader* state);

    /// <summary>Tears the mastering chain down. Balances a prior <see cref="sceAudioOutMasteringInit"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioOutMasteringTerm();
}
