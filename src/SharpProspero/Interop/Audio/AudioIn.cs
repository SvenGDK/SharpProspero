// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Audio;

/// <summary>The purpose of an input port, which selects how the system routes and processes the audio.</summary>
public enum AudioInType
{
    /// <summary>Voice chat, with the system's voice processing applied.</summary>
    VoiceChat = 0,

    /// <summary>General capture, for recording or analysis.</summary>
    General = 1,
}

/// <summary>The sample format of an input port.</summary>
public enum AudioInFormat : uint
{
    /// <summary>16-bit signed, one channel.</summary>
    S16Mono = 0x01,

    /// <summary>16-bit signed, two channels, interleaved.</summary>
    S16Stereo = 0x02,

    /// <summary>32-bit float, one channel.</summary>
    FloatMono = 0x11,

    /// <summary>32-bit float, two channels, interleaved.</summary>
    FloatStereo = 0x12,
}

/// <summary>
/// Audio-input bindings. Open a capture port for a signed-in user with a grain (samples per block), a
/// sample rate and a format, then pull one block of samples at a time. Each input call blocks until a
/// block is captured, which paces the caller to the audio clock, the same shape as audio output.
/// </summary>
public static unsafe partial class AudioIn
{
    private const string Lib = "libSceAudioIn";

    /// <summary>The 16 kHz sample rate, the default for voice.</summary>
    public const uint Freq16k = 16000;

    /// <summary>The 48 kHz sample rate, for higher-quality capture.</summary>
    public const uint Freq48k = 48000;

    /// <summary>The 128-sample grain.</summary>
    public const uint Grain128 = 128;

    /// <summary>The 256-sample grain.</summary>
    public const uint Grain256 = 256;

    /// <summary>
    /// The largest grain a port opened with <see cref="sceAudioInAsyncOpen"/> may use. Larger grains raise
    /// <c>SCE_AUDIO_IN_ERROR_INVALID_SIZE</c>.
    /// </summary>
    public const uint GrainMaxAsync = Grain128 * 3;

    /// <summary>Opens an input port. Returns a non-negative handle or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioInOpen(int userId, int type, int index, uint length, uint freq, uint param);

    /// <summary>
    /// Opens an input port on the low-latency path, for callers that must not drift behind the audio
    /// clock. The parameters match <see cref="sceAudioInOpen"/>, but <paramref name="timeLen"/> must not
    /// exceed <see cref="GrainMaxAsync"/>. Blocks on the port return in an average interval far shorter
    /// than a full grain, which is how a caller stays in step with a live stream.
    /// </summary>
    /// <returns>A non-negative handle, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAudioInAsyncOpen(int userId, int type, int index, uint timeLen, uint freq, uint param);

    /// <summary>
    /// Opens an input port on the higher-quality path (48 kHz, 128-sample grain). Kept for callers that
    /// were built against the earlier platform; new code opens a general 48 kHz port with
    /// <see cref="sceAudioInOpen"/> or a low-latency one with <see cref="sceAudioInAsyncOpen"/>.
    /// </summary>
    /// <returns>A non-negative handle, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAudioInHqOpen(int userId, int type, int index, uint timeLen, uint freq, uint param);

    /// <summary>Captures one block of samples into <paramref name="dest"/>; blocks until it is filled.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioInInput(int handle, void* dest);

    /// <summary>Reports whether the input is silent (muted at the hardware or by the system).</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioInGetSilentState(int handle);

    /// <summary>
    /// Reads the port's current linear input gain into <paramref name="gain"/>. A value of 1.0 is the
    /// unattenuated setting; smaller values attenuate; the call writes 1.0 into
    /// <paramref name="gain"/> before it checks the port so a caller sees a settled reading even when it
    /// fails.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAudioInGetGain(int handle, float* gain);

    /// <summary>
    /// Returns how many times the port's underlying capture device has been swapped since it was opened.
    /// A different value from the last frame means the port is now taking samples from a different
    /// device, which is when a caller must reset anything that depends on the source (echo cancellation,
    /// meter smoothing, per-microphone calibration).
    /// </summary>
    /// <returns>A non-negative count on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceAudioInGetRerouteCount(int handle);

    /// <summary>Closes a port.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAudioInClose(int handle);
}
