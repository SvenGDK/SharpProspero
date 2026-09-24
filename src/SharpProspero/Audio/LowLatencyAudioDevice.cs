// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Audio;
using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Audio;

/// <summary>
/// A stereo output on the low-latency path: the same see-into-the-queue contract as
/// <see cref="AudioQueueDevice"/>, but built over the low-latency context and port so a shallow
/// queue at a small grain answers as soon as the audio clock takes it. It is what an interactive
/// application reaches for when a couple of milliseconds one way or the other decides whether the
/// sound feels connected to what the user just did: a musical instrument, a hit-marker in a game,
/// live monitoring on a stream.
/// </summary>
/// <remarks>
/// <para>
/// The queue holds <see cref="QueueDepth"/> blocks of <see cref="Grain"/> frames each. At 48 kHz a
/// grain of 256 frames is about 5.3 ms, so a depth of one is a single block on the wire and about
/// 5 ms of buffered audio, a depth of two roughly 11 ms. Latency lives at the queue depth times
/// the grain; the low-latency path lets both go as small as the audio clock allows.
/// </para>
/// <para>
/// This is a separate output path from both <see cref="AudioOutDevice"/> and
/// <see cref="AudioQueueDevice"/>, and an application uses one of the three.
/// </para>
/// </remarks>
/// <example>
/// Keep the queue fed without ever blocking the frame:
/// <code>
/// while (device.FreeBlocks > 0)
/// {
///     mixer.Fill(block);
///     device.TryOutput(block);
/// }
/// </code>
/// </example>
public sealed unsafe partial class LowLatencyAudioDevice : IDisposable
{
    private const string Lib = "libSceAudioOut";
    private const int Channels = 2;

    // Set on a context to make it the one that feeds the main mix.
    private const uint MainContextFlag = 1u << 0;

    private readonly ulong _context;
    private readonly ulong _port;
    private readonly nuint _user;
    private readonly void* _memory;
    private readonly uint _grain;
    private readonly uint _queueDepth;
    private float _gain = 1f;
    private bool _disposed;

    private LowLatencyAudioDevice(ulong context, ulong port, nuint user, void* memory, uint grain, uint queueDepth)
    {
        _context = context;
        _port = port;
        _user = user;
        _memory = memory;
        _grain = grain;
        _queueDepth = queueDepth;
    }

    /// <summary>Frames (per-channel samples) in one block.</summary>
    public uint Grain => _grain;

    /// <summary>Samples in one block: the grain times the two channels.</summary>
    public int SamplesPerBlock => (int)_grain * Channels;

    /// <summary>How many blocks the queue holds when it is full.</summary>
    public uint QueueDepth => _queueDepth;

    /// <summary>
    /// Opens a stereo 16-bit output on the low-latency path with a queue of <paramref name="queueDepth"/>
    /// blocks.
    /// </summary>
    /// <param name="grain">
    /// Frames per block, in whole multiples of 256 from 256 to 2048, counted at 48 kHz.
    /// </param>
    /// <param name="sampleRate">The rate in hertz. The main output takes 48000 or 192000.</param>
    /// <param name="queueDepth">
    /// How many blocks may be waiting at once. One is the tightest, and answers as soon as the audio
    /// clock accepts the block; more trades latency for room to absorb a slow frame.
    /// </param>
    /// <param name="userId">Whose output this is. The system profile is the application's own.</param>
    /// <exception cref="ArgumentOutOfRangeException">A parameter is outside what the output accepts.</exception>
    /// <exception cref="ProsperoException">The output could not be opened.</exception>
    public static LowLatencyAudioDevice OpenStereo(
        uint grain = AudioOut.MinGrain, uint sampleRate = 48000, uint queueDepth = 1, int userId = SceUser.System)
    {
        // These are refused by the output rather than adjusted, and the refusal arrives as a number from
        // a call several layers down. Checking them here says which argument was wrong.
        if (grain < AudioOut.MinGrain || grain > AudioOut.MaxGrain || grain % AudioOut.MinGrain != 0)
            throw new ArgumentOutOfRangeException(nameof(grain),
                "Grain must be a whole multiple of 256 frames, from 256 to 2048.");
        if (sampleRate is not (48000 or 192000))
            throw new ArgumentOutOfRangeException(nameof(sampleRate),
                "The main output takes 48000 or 192000 hertz. Resample before playing anything else.");
        ArgumentOutOfRangeException.ThrowIfZero(queueDepth);

        // Starting the service is tolerant: a module may find it already started, which the return code
        // reports without preventing anything from opening. The module-level Initialize covers both the
        // high-level context path and the low-latency path.
        AudioOut2.sceAudioOut2Initialize();
        AudioOut2.sceAudioOut2LoInit();

        SceAudioOut2ContextParam contextParam = default;
        contextParam.MaxPorts = 1;
        contextParam.MaxObjectPorts = 0;
        contextParam.GuaranteeObjectPorts = 0;
        contextParam.NumGrains = grain;
        contextParam.QueueDepth = queueDepth;
        contextParam.Flags = MainContextFlag;

        nuint memorySize = 0;
        SceResult.ThrowIfFailed(
            AudioOut2.sceAudioOut2LoContextQueryMemory(&contextParam, &memorySize),
            nameof(AudioOut2.sceAudioOut2LoContextQueryMemory));

        // The context keeps the queued audio in this block, so it has to outlive every push. It is
        // unmanaged rather than pinned managed memory because it lives for the whole of the device.
        void* memory = NativeMemory.AllocZeroed(memorySize);
        ulong context = AudioOut2.InvalidContext;
        ulong port = AudioOut2.InvalidPort;
        nuint user = 0;
        try
        {
            SceResult.ThrowIfFailed(
                AudioOut2.sceAudioOut2LoContextCreate(&contextParam, memory, memorySize, &context),
                nameof(AudioOut2.sceAudioOut2LoContextCreate));

            SceResult.ThrowIfFailed(
                AudioOut2.sceAudioOut2UserCreate((uint)userId, &user),
                nameof(AudioOut2.sceAudioOut2UserCreate));

            SceAudioOut2PortParam portParam = default;
            portParam.PortType = (ushort)AudioOut2PortType.Main;
            portParam.DataFormat = (uint)AudioOut2DataFormat.I16Stereo;
            portParam.SamplingFreq = sampleRate;
            portParam.Flags = 0;
            portParam.UserHandle = user;
            SceResult.ThrowIfFailed(
                AudioOut2.sceAudioOut2LoPortCreate(context, &portParam, &port),
                nameof(AudioOut2.sceAudioOut2LoPortCreate));

            return new LowLatencyAudioDevice(context, port, user, memory, grain, queueDepth);
        }
        catch
        {
            Release(context, port, user, memory);
            throw;
        }
    }

    /// <summary>How many blocks are queued and waiting to play.</summary>
    /// <exception cref="ProsperoException">The queue could not be read.</exception>
    public uint QueuedBlocks
    {
        get
        {
            ReadQueue(out uint queued, out _);
            return queued;
        }
    }

    /// <summary>
    /// How many more blocks the queue will take right now. A push made while this is zero waits for the
    /// output; a push made while it is positive returns at once.
    /// </summary>
    /// <exception cref="ProsperoException">The queue could not be read.</exception>
    public uint FreeBlocks
    {
        get
        {
            ReadQueue(out _, out uint free);
            return free;
        }
    }

    /// <summary>Reads both the number of queued blocks and the room left, in one call.</summary>
    /// <exception cref="ProsperoException">The queue could not be read.</exception>
    public void ReadQueue(out uint queuedBlocks, out uint freeBlocks)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        uint queued = 0;
        uint free = 0;
        SceResult.ThrowIfFailed(
            AudioOut2.sceAudioOut2LoContextGetQueueLevel(_context, &queued, &free),
            nameof(AudioOut2.sceAudioOut2LoContextGetQueueLevel));
        queuedBlocks = queued;
        freeBlocks = free;
    }

    /// <summary>
    /// The level applied to the port, from 0 (silent) to 1 (unattenuated). Values above 1 amplify and
    /// can clip.
    /// </summary>
    public float Gain
    {
        get => _gain;
        set
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            _gain = value;
        }
    }

    /// <summary>
    /// Queues one block of interleaved stereo samples, waiting for room when the queue is full. The
    /// span must hold at least <see cref="SamplesPerBlock"/> shorts.
    /// </summary>
    /// <exception cref="ProsperoException">The output refused the block.</exception>
    public void Output(ReadOnlySpan<short> samples) => Push(samples, AudioOut2Blocking.Sync);

    /// <summary>
    /// Queues one block if the queue has room, and reports whether it did. Nothing is queued and nothing
    /// waits when the queue is full, which is what lets a frame loop mix only as much as the output can
    /// take.
    /// </summary>
    /// <returns>True when the block was queued.</returns>
    /// <exception cref="ProsperoException">The output refused the block.</exception>
    public bool TryOutput(ReadOnlySpan<short> samples)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ReadQueue(out _, out uint free);
        if (free == 0)
            return false;
        Push(samples, AudioOut2Blocking.Async);
        return true;
    }

    private void Push(ReadOnlySpan<short> samples, AudioOut2Blocking blocking)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (samples.Length < SamplesPerBlock)
            throw new ArgumentException($"A block needs at least {SamplesPerBlock} samples.", nameof(samples));

        float* gain = stackalloc float[Channels];
        gain[0] = _gain;
        gain[1] = _gain;

        fixed (short* pcmData = samples)
        {
            var pcm = new SceAudioOut2Pcm { Data = pcmData };
            SceAudioOut2Attribute* attributes = stackalloc SceAudioOut2Attribute[2];
            attributes[0] = new SceAudioOut2Attribute
            {
                AttributeId = (uint)AudioOut2PortAttribute.Gain,
                Value = gain,
                ValueSize = (nuint)(sizeof(float) * Channels),
            };
            attributes[1] = new SceAudioOut2Attribute
            {
                AttributeId = (uint)AudioOut2PortAttribute.Pcm,
                Value = &pcm,
                ValueSize = (nuint)sizeof(SceAudioOut2Pcm),
            };

            SceResult.ThrowIfFailed(
                AudioOut2.sceAudioOut2LoPortSetAttributes(_port, attributes, 2),
                nameof(AudioOut2.sceAudioOut2LoPortSetAttributes));
            SceResult.ThrowIfFailed(
                AudioOut2.sceAudioOut2LoContextAdvance(_context),
                nameof(AudioOut2.sceAudioOut2LoContextAdvance));
            SceResult.ThrowIfFailed(
                AudioOut2.sceAudioOut2LoContextPush(_context, blocking),
                nameof(AudioOut2.sceAudioOut2LoContextPush));
        }
    }

    /// <summary>Reads where the port's samples are going and how loud.</summary>
    /// <exception cref="ProsperoException">The state could not be read.</exception>
    public SceAudioOut2PortState GetPortState()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioOut2PortState state = default;
        SceResult.ThrowIfFailed(
            AudioOut2.sceAudioOut2LoPortGetState(_port, &state),
            nameof(AudioOut2.sceAudioOut2LoPortGetState));
        return state;
    }

    /// <summary>Closes the port and gives back the memory the queue was held in.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Release(_context, _port, _user, _memory);
    }

    // Unwinds whichever parts were built, in the reverse of the order they were built in, so a failure
    // part way through an open leaves nothing behind.
    private static void Release(ulong context, ulong port, nuint user, void* memory)
    {
        if (port != AudioOut2.InvalidPort)
            AudioOut2.sceAudioOut2LoPortDestroy(port);
        if (user != 0)
            AudioOut2.sceAudioOut2UserDestroy(user);
        if (context != AudioOut2.InvalidContext)
            AudioOut2.sceAudioOut2LoContextDestroy(context);
        if (memory is not null)
            NativeMemory.Free(memory);
    }
}
