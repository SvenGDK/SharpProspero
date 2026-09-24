// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Audio;
using System;

namespace SharpProspero.Audio;

/// <summary>
/// A snapshot of the audio-output subsystem, as <see cref="AudioOutSystem.State"/> returns it. The
/// loudness reading covers the whole output mix and sits at <see cref="AudioOut.LoudnessMin"/> LKFS
/// while the measurement is idle.
/// </summary>
public readonly struct AudioOutSystemState
{
    internal AudioOutSystemState(float loudness) => Loudness = loudness;

    /// <summary>Measured integrated loudness of the mix, in LKFS.</summary>
    public float Loudness { get; }

    /// <summary>True when <see cref="Loudness"/> has settled to a real value above the idle floor.</summary>
    public bool HasLoudnessMeasurement => Loudness > AudioOut.LoudnessMin;
}

/// <summary>
/// The audio-output subsystem as a whole. Read <see cref="State"/> for a snapshot of the mix-wide
/// loudness meter.
/// </summary>
public static unsafe class AudioOutSystem
{
    /// <summary>A snapshot of the subsystem's overall state, including the whole-mix loudness reading.</summary>
    /// <exception cref="ProsperoException">The state could not be read.</exception>
    public static AudioOutSystemState State
    {
        get
        {
            SceAudioOutSystemState raw = default;
            SceResult.ThrowIfFailed(
                AudioOut.sceAudioOutGetSystemState(&raw),
                nameof(AudioOut.sceAudioOutGetSystemState));
            return new AudioOutSystemState(raw.Loudness);
        }
    }
}

/// <summary>
/// Controller-speaker mixing helpers. A port opened as <see cref="AudioOutPortType.PadSpeaker"/> has its
/// samples folded into a headset mix at a level chosen with <see cref="SetMixLevel"/>, on the same
/// 0-32768 scale as the ordinary port volume.
/// </summary>
public static class AudioOutPadSpeaker
{
    /// <summary>Unattenuated (0 dB) pad-speaker mix level.</summary>
    public const int MixLevel0Db = AudioOut.PadSpeakerMixLevel0Db;

    /// <summary>The system's default pad-speaker mix level, -9 dB.</summary>
    public const int MixLevelDefault = AudioOut.PadSpeakerMixLevelDefault;

    /// <summary>
    /// Sets how loud a controller-speaker port sounds when the port's samples are folded into a headset.
    /// <paramref name="handle"/> is a handle to a port opened as <see cref="AudioOutPortType.PadSpeaker"/>;
    /// <paramref name="level"/> is 0 (silent) to <see cref="MixLevel0Db"/> (unattenuated), and is clamped
    /// into range before the call.
    /// </summary>
    /// <exception cref="ProsperoException">The output refused the level change.</exception>
    public static void SetMixLevel(int handle, int level)
    {
        int clamped = Math.Clamp(level, 0, MixLevel0Db);
        SceResult.ThrowIfFailed(
            AudioOut.sceAudioOutSetMixLevelPadSpk(handle, clamped),
            nameof(AudioOut.sceAudioOutSetMixLevelPadSpk));
    }
}

/// <summary>
/// A running mastering chain - parametric equaliser, multi-band compressor, master volume, peak limiter -
/// that finalises every output port's samples before they leave the machine. Build one alongside an
/// <see cref="AudioOutDevice"/>, hand it a parameters struct that describes the chain, and read running
/// meters through <see cref="State"/>. <see cref="Dispose"/> tears the chain down.
/// </summary>
/// <remarks>
/// <para>
/// The chain is a system-wide finaliser: it shapes every output port's samples, not only those of the
/// device the wrapper was built for. Only one chain runs at a time, so build one instance for the
/// application and share it.
/// </para>
/// <para>
/// The parameters struct handed to <see cref="SetParams{T}"/> must start with
/// <see cref="SceAudioOutMasteringParamsHeader"/>; the wrapper reads the header's
/// <see cref="SceAudioOutMasteringParamsHeader.ParamsId"/> back into <see cref="ParamsId"/> so a caller
/// can tell which layout the running chain is on.
/// </para>
/// </remarks>
public sealed unsafe class AudioOutMastering : IDisposable
{
    // The default states struct is a 4-byte header, 12 bytes of reserved slots, a 3-band compressor state
    // of 208 bytes, and a limiter state of 112 bytes: 336 bytes altogether. The library writes only this
    // many, but the buffer is rounded to 512 so a caller may safely pass a wider states id in a later
    // library revision without overrunning the buffer.
    private const int StatesBufferBytes = 512;
    private const int DefaultStatesBytes = 336;

    // Byte offsets into a default states struct. The header (4) + reserved[3] (12) puts the compressor
    // states descriptor at 16; its own header (8) + reserved (8) puts the first meter array at 32.
    private const int CompressorInputRmsOffset = 32;
    private const int CompressorGainOffset = 128;
    private const int LimiterInputPeakOffset = 240;
    private const int LimiterOutputPeakOffset = 272;
    private const int LimiterGainPeakOffset = 304;

    private readonly AudioOutDevice _device;
    private bool _disposed;

    /// <summary>
    /// Starts the mastering chain for an existing audio-output device. <paramref name="flags"/> selects
    /// extra behaviour on the chain (for example, running the compressor before the equaliser instead of
    /// after it).
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="device"/> is null.</exception>
    /// <exception cref="ProsperoException">The chain could not be started.</exception>
    public AudioOutMastering(AudioOutDevice device, AudioOutMasteringFlags flags = AudioOutMasteringFlags.None)
    {
        ArgumentNullException.ThrowIfNull(device);
        _device = device;
        Flags = flags;
        SceResult.ThrowIfFailed(
            AudioOut.sceAudioOutMasteringInit((uint)flags),
            nameof(AudioOut.sceAudioOutMasteringInit));
        ParamsId = AudioOut.MasteringParamsIdDefault;
    }

    /// <summary>The extra behaviour selected when the chain was started.</summary>
    public AudioOutMasteringFlags Flags { get; }

    /// <summary>The output device the chain is finalising output for.</summary>
    public AudioOutDevice Device => _device;

    /// <summary>
    /// The identifier of the parameters struct last applied through <see cref="SetParams{T}"/>, or
    /// <see cref="AudioOut.MasteringParamsIdDefault"/> when the chain is still on its start-up defaults.
    /// </summary>
    public uint ParamsId { get; private set; }

    /// <summary>
    /// Applies a mastering-parameters struct. The struct must start with a
    /// <see cref="SceAudioOutMasteringParamsHeader"/> whose <see cref="SceAudioOutMasteringParamsHeader.ParamsId"/>
    /// field selects which fuller layout follows.
    /// </summary>
    /// <typeparam name="T">A blittable struct whose first field is <see cref="SceAudioOutMasteringParamsHeader"/>.</typeparam>
    /// <param name="parameters">The filled parameters struct.</param>
    /// <param name="flags">
    /// Extra behaviour on this call, from <see cref="AudioOutMasteringFlags"/>;
    /// <see cref="AudioOutMasteringFlags.None"/> keeps the chain in its standard order.
    /// </param>
    /// <exception cref="ObjectDisposedException">The chain has already been torn down.</exception>
    /// <exception cref="ProsperoException">The parameters were refused.</exception>
    public void SetParams<T>(ref T parameters, AudioOutMasteringFlags flags = AudioOutMasteringFlags.None)
        where T : unmanaged
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        fixed (T* p = &parameters)
        {
            var header = (SceAudioOutMasteringParamsHeader*)p;
            SceResult.ThrowIfFailed(
                AudioOut.sceAudioOutMasteringSetParam(header, (uint)flags),
                nameof(AudioOut.sceAudioOutMasteringSetParam));
            ParamsId = header->ParamsId;
        }
    }

    /// <summary>
    /// A snapshot of the chain's running meters - per-band compressor input RMS and gain reduction, and
    /// per-channel limiter input, output and gain peaks. Read each frame to drive a level meter.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The chain has already been torn down.</exception>
    /// <exception cref="ProsperoException">The meters could not be read.</exception>
    public AudioOutMasteringState State
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            byte* buffer = stackalloc byte[StatesBufferBytes];
            for (int i = 0; i < StatesBufferBytes; i++)
                buffer[i] = 0;

            var header = (SceAudioOutMasteringStatesHeader*)buffer;
            header->StatesId = AudioOut.MasteringStatesIdDefault;

            SceResult.ThrowIfFailed(
                AudioOut.sceAudioOutMasteringGetState(header),
                nameof(AudioOut.sceAudioOutMasteringGetState));

            return AudioOutMasteringState.FromBuffer(
                buffer,
                DefaultStatesBytes,
                CompressorInputRmsOffset,
                CompressorGainOffset,
                LimiterInputPeakOffset,
                LimiterOutputPeakOffset,
                LimiterGainPeakOffset);
        }
    }

    /// <summary>Tears the mastering chain down. Idempotent.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        AudioOut.sceAudioOutMasteringTerm();
    }
}

/// <summary>
/// A snapshot of the running mastering meters that <see cref="AudioOutMastering.State"/> hands back.
/// Compressor meters carry one value per band and per system channel; limiter meters carry one value per
/// channel. Unused channel slots read as zero.
/// </summary>
public readonly struct AudioOutMasteringState
{
    /// <summary>The bands the compressor reports meters for.</summary>
    public const int CompressorBands = 3;

    /// <summary>The system channels a meter array covers.</summary>
    public const int SystemChannels = 8;

    // Flat arrays kept private so a caller cannot mutate the snapshot. Compressor meters are laid out as
    // band-major: index = band * SystemChannels + channel. Limiter meters are one entry per channel.
    private readonly float[] _compressorInputRms;
    private readonly float[] _compressorGain;
    private readonly float[] _limiterInputPeak;
    private readonly float[] _limiterOutputPeak;
    private readonly float[] _limiterGainPeak;

    private AudioOutMasteringState(
        float[] compressorInputRms,
        float[] compressorGain,
        float[] limiterInputPeak,
        float[] limiterOutputPeak,
        float[] limiterGainPeak)
    {
        _compressorInputRms = compressorInputRms;
        _compressorGain = compressorGain;
        _limiterInputPeak = limiterInputPeak;
        _limiterOutputPeak = limiterOutputPeak;
        _limiterGainPeak = limiterGainPeak;
    }

    /// <summary>Reads one compressor band's input RMS on one system channel.</summary>
    /// <param name="band">Band index, 0 to <see cref="CompressorBands"/> - 1.</param>
    /// <param name="channel">Channel index, 0 to <see cref="SystemChannels"/> - 1.</param>
    public float GetCompressorInputRms(int band, int channel)
        => ReadBanded(_compressorInputRms, band, channel);

    /// <summary>Reads one compressor band's gain-reduction coefficient on one system channel.</summary>
    /// <param name="band">Band index, 0 to <see cref="CompressorBands"/> - 1.</param>
    /// <param name="channel">Channel index, 0 to <see cref="SystemChannels"/> - 1.</param>
    public float GetCompressorGain(int band, int channel)
        => ReadBanded(_compressorGain, band, channel);

    /// <summary>Reads the limiter's input peak on one system channel.</summary>
    public float GetLimiterInputPeak(int channel) => ReadChannel(_limiterInputPeak, channel);

    /// <summary>Reads the limiter's output peak on one system channel.</summary>
    public float GetLimiterOutputPeak(int channel) => ReadChannel(_limiterOutputPeak, channel);

    /// <summary>Reads the limiter's gain peak on one system channel.</summary>
    public float GetLimiterGainPeak(int channel) => ReadChannel(_limiterGainPeak, channel);

    /// <summary>The compressor input-RMS meters as one flat array, band-major.</summary>
    public ReadOnlySpan<float> CompressorInputRms => _compressorInputRms;

    /// <summary>The compressor gain-reduction meters as one flat array, band-major.</summary>
    public ReadOnlySpan<float> CompressorGain => _compressorGain;

    /// <summary>The limiter input-peak meter, one entry per system channel.</summary>
    public ReadOnlySpan<float> LimiterInputPeak => _limiterInputPeak;

    /// <summary>The limiter output-peak meter, one entry per system channel.</summary>
    public ReadOnlySpan<float> LimiterOutputPeak => _limiterOutputPeak;

    /// <summary>The limiter gain-peak meter, one entry per system channel.</summary>
    public ReadOnlySpan<float> LimiterGainPeak => _limiterGainPeak;

    private static float ReadBanded(float[] source, int band, int channel)
    {
        if (source is null)
            return 0f;
        if ((uint)band >= CompressorBands || (uint)channel >= SystemChannels)
            return 0f;
        return source[(band * SystemChannels) + channel];
    }

    private static float ReadChannel(float[] source, int channel)
    {
        if (source is null || (uint)channel >= (uint)source.Length)
            return 0f;
        return source[channel];
    }

    internal static unsafe AudioOutMasteringState FromBuffer(
        byte* buffer,
        int bufferBytes,
        int compressorInputRmsOffset,
        int compressorGainOffset,
        int limiterInputPeakOffset,
        int limiterOutputPeakOffset,
        int limiterGainPeakOffset)
    {
        // ReadFloats guards against a short buffer so a caller with a smaller states struct in a future
        // library version still gets a zero-padded snapshot rather than an out-of-bounds read.
        int bandedCount = CompressorBands * SystemChannels;
        return new AudioOutMasteringState(
            ReadFloats(buffer, compressorInputRmsOffset, bandedCount, bufferBytes),
            ReadFloats(buffer, compressorGainOffset, bandedCount, bufferBytes),
            ReadFloats(buffer, limiterInputPeakOffset, SystemChannels, bufferBytes),
            ReadFloats(buffer, limiterOutputPeakOffset, SystemChannels, bufferBytes),
            ReadFloats(buffer, limiterGainPeakOffset, SystemChannels, bufferBytes));
    }

    private static unsafe float[] ReadFloats(byte* buffer, int offset, int count, int bufferBytes)
    {
        float[] result = new float[count];
        for (int i = 0; i < count; i++)
        {
            int byteIndex = offset + (i * sizeof(float));
            if (byteIndex + sizeof(float) > bufferBytes)
                break;
            result[i] = *(float*)(buffer + byteIndex);
        }
        return result;
    }
}
