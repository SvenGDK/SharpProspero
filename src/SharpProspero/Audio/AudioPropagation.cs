// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Audio;
using System;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpProspero.Audio;

/// <summary>
/// The settings a <see cref="PropagationSystem"/> is created with. Fill in <see cref="MaxSources"/> and
/// <see cref="MaxMaterials"/> to size the engine to what the game needs; leave the rest at their
/// defaults for typical use.
/// </summary>
public sealed record PropagationSystemOptions
{
    /// <summary>The most sources that can be rendered at once. Range 1 to <see cref="SceAudioPropagation.MaxSources"/>.</summary>
    public required int MaxSources { get; init; }

    /// <summary>The most materials that can be registered at once. Range 1 to <see cref="SceAudioPropagation.MaxMaterials"/>.</summary>
    public required int MaxMaterials { get; init; }

    /// <summary>The number of raycasts each source requests per update. Fixed at <see cref="SceAudioPropagation.MaxRaycasts"/>.</summary>
    public int RaycastsPerSource { get; init; } = SceAudioPropagation.MaxRaycasts;

    /// <summary>The most reflections in any path. Fixed at <see cref="SceAudioPropagation.MaxBounces"/>.</summary>
    public int MaxBouncesPerPath { get; init; } = SceAudioPropagation.MaxBounces;

    /// <summary>The render grain in samples per channel. Must be 512, 1024, 2048, or 4096.</summary>
    public int UpdateGrain { get; init; } = 1024;

    /// <summary>The speed of sound in metres per second. Range 0 to <see cref="SceAudioPropagation.MaxSpeedOfSound"/>.</summary>
    public float SpeedOfSound { get; init; } = SceAudioPropagation.DefaultSpeedOfSound;

    /// <summary>The longest path between a source and the listener in metres.</summary>
    public float MaxPathDistance { get; init; } = SceAudioPropagation.MaxPathDistance;
}

/// <summary>The directionality of a source, as a nested pair of coaxial cones.</summary>
/// <param name="InnerLevel">Gain inside the inner cone, from 0 to 2.</param>
/// <param name="InnerAngle">Inner cone angle in degrees, from 0 to 360.</param>
/// <param name="OuterLevel">Gain outside the outer cone, from 0 to 2.</param>
/// <param name="OuterAngle">Outer cone angle in degrees, from <paramref name="InnerAngle"/> to 360.</param>
public readonly record struct PropagationCone(float InnerLevel, float InnerAngle, float OuterLevel, float OuterAngle);

/// <summary>The parameters that describe how a source's volume attenuates with distance.</summary>
/// <param name="Model">The rolloff formula.</param>
/// <param name="MaxDistance">The distance past which no further rolloff occurs. Must be 0 or greater.</param>
/// <param name="RolloffFactor">The rolloff factor. Must be 0 or greater.</param>
/// <param name="ReferenceDistance">The reference distance, from 0 up to <paramref name="MaxDistance"/>.</param>
public readonly record struct PropagationRolloff(
    AudioPropagationRolloffModel Model,
    float MaxDistance,
    float RolloffFactor,
    float ReferenceDistance);

/// <summary>
/// A surface material used at reflection points. When a material is attached to a point on a path,
/// audio that reflects there is altered by the absorption coefficients at each frequency band.
/// </summary>
/// <param name="Name">Unique material name, up to fifteen bytes when encoded as UTF-8.</param>
/// <param name="Absorption125">Absorption at 125 Hz, from 0 to 1.</param>
/// <param name="Absorption250">Absorption at 250 Hz, from 0 to 1.</param>
/// <param name="Absorption500">Absorption at 500 Hz, from 0 to 1.</param>
/// <param name="Absorption1k">Absorption at 1 kHz, from 0 to 1.</param>
/// <param name="Absorption2k">Absorption at 2 kHz, from 0 to 1.</param>
/// <param name="Absorption4k">Absorption at 4 kHz, from 0 to 1.</param>
public readonly record struct PropagationMaterial(
    string Name,
    float Absorption125,
    float Absorption250,
    float Absorption500,
    float Absorption1k,
    float Absorption2k,
    float Absorption4k);

/// <summary>
/// A raycast the engine wants the caller to run against the game's geometry. The engine writes
/// <see cref="Start"/> and <see cref="Direction"/>; the caller writes <see cref="CollisionPosition"/>,
/// <see cref="CollisionNormal"/> and <see cref="CollisionMaterial"/> and hands the array back.
/// </summary>
public struct PropagationRay
{
    /// <summary>The start position of the ray, in listener-relative space.</summary>
    public Vector3 Start;

    /// <summary>The direction of the ray.</summary>
    public Vector3 Direction;

    /// <summary>The point where the ray hit geometry.</summary>
    public Vector3 CollisionPosition;

    /// <summary>The surface normal at the collision point.</summary>
    public Vector3 CollisionNormal;

    /// <summary>The material handle at the collision point, or <see cref="SceAudioPropagation.HandleNone"/> for no material.</summary>
    public ulong CollisionMaterial;
}

/// <summary>One point on an audio path: the position, the volume multiplier, and the material handle.</summary>
/// <param name="Position">Listener-relative position of the point.</param>
/// <param name="Gain">Volume multiplier applied to audio passing through this point.</param>
/// <param name="Material">Material handle at the point, or <see cref="SceAudioPropagation.HandleNone"/>.</param>
public readonly record struct PropagationPathPoint(Vector3 Position, float Gain, ulong Material);

/// <summary>
/// A route travelled by audio from a source to the listener. The first point is the source, the last
/// point is the listener at the origin, and intermediate points are reflections. The path is invalid
/// when <see cref="AudioPropagationPathFlags.Invalid"/> is set in <see cref="Flags"/>.
/// </summary>
/// <param name="Points">The active points along the path. Up to <see cref="SceAudioPropagation.MaxPathPoints"/> entries.</param>
/// <param name="Flags">Flags describing the path.</param>
public readonly record struct PropagationAudioPath(PropagationPathPoint[] Points, AudioPropagationPathFlags Flags)
{
    /// <summary>True when the path is a valid route between the source and the listener.</summary>
    public bool IsValid => (Flags & AudioPropagationPathFlags.Invalid) == 0 && Points is { Length: > 0 };
}

/// <summary>The creation settings for a <see cref="PropagationPortal"/>.</summary>
/// <param name="Position">Listener-relative position of the portal.</param>
/// <param name="Forward">Forward direction of the portal.</param>
/// <param name="Upward">Upward direction of the portal.</param>
/// <param name="Extents">Half-size along each axis.</param>
/// <param name="RoomA">The first room the portal connects.</param>
/// <param name="RoomB">The second room the portal connects.</param>
public readonly record struct PropagationPortalSettings(
    Vector3 Position,
    Vector3 Forward,
    Vector3 Upward,
    Vector3 Extents,
    PropagationRoom RoomA,
    PropagationRoom RoomB);

/// <summary>
/// Sound propagation. Register rooms, portals and sources with the system; feed raycasts back to it
/// each frame; and render one audio block per source every audio tick. The system owns its rooms,
/// portals and sources: disposing the system releases them all, but a caller may dispose one earlier
/// to free that handle back to the engine.
/// </summary>
/// <example>
/// <code>
/// using var system = PropagationSystem.Create(new PropagationSystemOptions { MaxSources = 4, MaxMaterials = 4 });
/// using var room1 = system.CreateRoom();
/// using var room2 = system.CreateRoom();
/// using var portal = system.CreatePortal(new PropagationPortalSettings(
///     Vector3.Zero, Vector3.UnitZ, Vector3.UnitY, new Vector3(0.5f), room1, room2));
/// using var source = system.CreateSource();
/// source.SetPosition(new Vector3(1, 0, 0));
/// source.SetRoom(room1);
/// source.SetPcm(pcm);
/// system.SetListenerRoom(room2);
/// float[] mix = source.Render(AudioPropagationOutputFormat.ChannelFloat8Ch);
/// </code>
/// </example>
public sealed unsafe class PropagationSystem : IDisposable
{
    private readonly ulong _handle;
    private readonly void* _cpuMem;
    private readonly int _updateGrain;
    private bool _disposed;

    private PropagationSystem(ulong handle, void* cpuMem, int updateGrain)
    {
        _handle = handle;
        _cpuMem = cpuMem;
        _updateGrain = updateGrain;
    }

    /// <summary>The underlying system handle.</summary>
    public ulong Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle;
        }
    }

    /// <summary>The render grain in samples per channel the system was created with.</summary>
    public int UpdateGrain => _updateGrain;

    /// <summary>
    /// Creates a system with the given options. The CPU memory block the engine needs is allocated,
    /// zero-initialised, and freed when the system is disposed.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A value in <paramref name="options"/> is out of range.</exception>
    /// <exception cref="ProsperoException">The engine rejected the settings or ran out of memory.</exception>
    public static PropagationSystem Create(PropagationSystemOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxSources);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaxSources, SceAudioPropagation.MaxSources);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxMaterials);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaxMaterials, SceAudioPropagation.MaxMaterials);
        ArgumentOutOfRangeException.ThrowIfNegative(options.SpeedOfSound);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.SpeedOfSound, SceAudioPropagation.MaxSpeedOfSound);
        ArgumentOutOfRangeException.ThrowIfNegative(options.MaxPathDistance);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaxPathDistance, SceAudioPropagation.MaxPathDistance);
        if (options.UpdateGrain is not (512 or 1024 or 2048 or 4096))
            throw new ArgumentOutOfRangeException(nameof(options), "UpdateGrain must be 512, 1024, 2048, or 4096.");
        ArgumentOutOfRangeException.ThrowIfNotEqual(options.RaycastsPerSource, SceAudioPropagation.MaxRaycasts, nameof(options));
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.MaxBouncesPerPath, SceAudioPropagation.MaxBounces, nameof(options));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaxBouncesPerPath, nameof(options));

        SceAudioPropagationSystemOption opt = new()
        {
            Desc = new SceAudioPropagationStructDescriptor
            {
                Id = (uint)AudioPropagationStructId.SystemOption,
                Size = (nuint)sizeof(SceAudioPropagationSystemOption),
            },
            MaxSources = (uint)options.MaxSources,
            MaxMaterials = (uint)options.MaxMaterials,
            MaxRaycasts = (uint)options.RaycastsPerSource,
            MaxBounces = (uint)options.MaxBouncesPerPath,
            UpdateGrain = (uint)options.UpdateGrain,
            SpeedOfSound = options.SpeedOfSound,
            MaxDistance = options.MaxPathDistance,
            Flags = (uint)AudioPropagationOptionFlags.None,
            Pad = 0,
        };

        SceAudioPropagationSystemMemory mem = new()
        {
            Desc = new SceAudioPropagationStructDescriptor
            {
                Id = (uint)AudioPropagationStructId.SystemMemory,
                Size = (nuint)sizeof(SceAudioPropagationSystemMemory),
            },
        };

        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSystemQueryMemory(&opt, &mem),
            nameof(SceAudioPropagation.sceAudioPropagationSystemQueryMemory));

        void* cpu = null;
        try
        {
            if (mem.SizeCpuMem > 0)
            {
                cpu = NativeMemory.AllocZeroed(mem.SizeCpuMem);
                mem.PCpuMem = cpu;
            }

            ulong handle = SceAudioPropagation.HandleNone;
            SceResult.ThrowIfFailed(
                SceAudioPropagation.sceAudioPropagationSystemCreate(&opt, &mem, &handle),
                nameof(SceAudioPropagation.sceAudioPropagationSystemCreate));

            PropagationSystem system = new(handle, cpu, options.UpdateGrain);
            cpu = null; // Ownership transferred to the system.
            return system;
        }
        finally
        {
            if (cpu != null)
                NativeMemory.Free(cpu);
        }
    }

    /// <summary>Creates a room in the system.</summary>
    /// <exception cref="ProsperoException">The engine could not create the room.</exception>
    public PropagationRoom CreateRoom()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ulong room = SceAudioPropagation.HandleNone;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationRoomCreate(_handle, &room),
            nameof(SceAudioPropagation.sceAudioPropagationRoomCreate));
        return new PropagationRoom(this, room);
    }

    /// <summary>Creates a portal connecting the two rooms in <paramref name="settings"/>.</summary>
    /// <exception cref="ArgumentException">A room in the settings belongs to a different system, or was disposed.</exception>
    /// <exception cref="ProsperoException">The engine could not create the portal.</exception>
    public PropagationPortal CreatePortal(PropagationPortalSettings settings)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (settings.RoomA is null)
            throw new ArgumentException("RoomA must be set.", nameof(settings));
        if (settings.RoomB is null)
            throw new ArgumentException("RoomB must be set.", nameof(settings));
        if (!ReferenceEquals(settings.RoomA.System, this) || !ReferenceEquals(settings.RoomB.System, this))
            throw new ArgumentException("The rooms must belong to this system.", nameof(settings));

        SceAudioPropagationPortalSettings wire = new()
        {
            Desc = new SceAudioPropagationStructDescriptor
            {
                Id = (uint)AudioPropagationStructId.PortalSettings,
                Size = (nuint)sizeof(SceAudioPropagationPortalSettings),
            },
            Position = ToSceVector(settings.Position),
            Forward = ToSceVector(settings.Forward),
            Upward = ToSceVector(settings.Upward),
            Extents = ToSceVector(settings.Extents),
        };
        wire.HRoom[0] = settings.RoomA.Handle;
        wire.HRoom[1] = settings.RoomB.Handle;

        ulong portal = SceAudioPropagation.HandleNone;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationPortalCreate(_handle, &wire, &portal),
            nameof(SceAudioPropagation.sceAudioPropagationPortalCreate));
        return new PropagationPortal(this, portal);
    }

    /// <summary>Creates a source in the system.</summary>
    /// <exception cref="ProsperoException">The engine could not create the source.</exception>
    public PropagationSource CreateSource()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ulong source = SceAudioPropagation.HandleNone;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSourceCreate(_handle, &source),
            nameof(SceAudioPropagation.sceAudioPropagationSourceCreate));
        return new PropagationSource(this, source);
    }

    /// <summary>Registers <paramref name="material"/> and returns its handle for use in path points.</summary>
    /// <exception cref="ArgumentException">The material name is empty, too long, or contains a null byte.</exception>
    /// <exception cref="ProsperoException">The engine rejected the material.</exception>
    public ulong RegisterMaterial(PropagationMaterial material)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(material.Name))
            throw new ArgumentException("Material name must not be empty.", nameof(material));

        SceAudioPropagationMaterial wire = new()
        {
            Desc = new SceAudioPropagationStructDescriptor
            {
                Id = (uint)AudioPropagationStructId.Material,
                Size = (nuint)sizeof(SceAudioPropagationMaterial),
            },
            Absorption125 = material.Absorption125,
            Absorption250 = material.Absorption250,
            Absorption500 = material.Absorption500,
            Absorption1k = material.Absorption1k,
            Absorption2k = material.Absorption2k,
            Absorption4k = material.Absorption4k,
            Pad = 0,
        };
        WriteMaterialName(material.Name, wire.Name);

        ulong handle = SceAudioPropagation.HandleNone;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSystemRegisterMaterial(_handle, &wire, &handle),
            nameof(SceAudioPropagation.sceAudioPropagationSystemRegisterMaterial));
        return handle;
    }

    /// <summary>Unregisters a material previously returned by <see cref="RegisterMaterial"/>.</summary>
    public void UnregisterMaterial(ulong materialHandle)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSystemUnregisterMaterial(materialHandle),
            nameof(SceAudioPropagation.sceAudioPropagationSystemUnregisterMaterial));
    }

    /// <summary>Sets the room the listener is inside, or clears it when <paramref name="room"/> is <c>null</c>.</summary>
    public void SetListenerRoom(PropagationRoom? room)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (room is not null && !ReferenceEquals(room.System, this))
            throw new ArgumentException("The room must belong to this system.", nameof(room));

        ulong value = room?.Handle ?? SceAudioPropagation.HandleNone;
        SceAudioPropagationAttribute attribute = new()
        {
            AttributeId = (uint)AudioPropagationSystemAttribute.Room,
            Value = &value,
            ValueSize = sizeof(ulong),
            Pad = 0,
        };
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSystemSetAttributes(_handle, &attribute, 1),
            nameof(SceAudioPropagation.sceAudioPropagationSystemSetAttributes));
    }

    /// <summary>
    /// Reads out the raycasts the engine wants for this frame across all sources. Fill in the
    /// collision fields on each returned ray and hand the array back with <see cref="SetRays"/>.
    /// </summary>
    /// <exception cref="ProsperoException">The engine could not report its raycasts.</exception>
    public PropagationRay[] GetRays()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        uint capacity = (uint)SceAudioPropagation.MaxSources * SceAudioPropagation.MaxRaycasts;
        SceAudioPropagationRay* buffer = stackalloc SceAudioPropagationRay[(int)capacity];
        uint count = capacity;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSystemGetRays(_handle, buffer, &count),
            nameof(SceAudioPropagation.sceAudioPropagationSystemGetRays));

        PropagationRay[] result = new PropagationRay[count];
        for (int i = 0; i < count; i++)
            result[i] = FromSceRay(buffer[i]);
        return result;
    }

    /// <summary>Passes the completed raycasts back to the engine.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="rays"/> holds more entries than the engine reported.</exception>
    /// <exception cref="ProsperoException">The engine rejected the raycasts.</exception>
    public void SetRays(ReadOnlySpan<PropagationRay> rays)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        uint capacity = (uint)SceAudioPropagation.MaxSources * SceAudioPropagation.MaxRaycasts;
        if ((uint)rays.Length > capacity)
            throw new ArgumentOutOfRangeException(nameof(rays), "Too many rays for the engine to accept in one call.");

        int count = rays.Length;
        SceAudioPropagationRay* buffer = stackalloc SceAudioPropagationRay[count == 0 ? 1 : count];
        for (int i = 0; i < count; i++)
            buffer[i] = ToSceRay(rays[i]);

        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSystemSetRays(_handle, buffer, (uint)count),
            nameof(SceAudioPropagation.sceAudioPropagationSystemSetRays));
    }

    /// <summary>Destroys the system and releases every resource it owned.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        SceAudioPropagation.sceAudioPropagationSystemDestroy(_handle);
        if (_cpuMem != null)
            NativeMemory.Free(_cpuMem);
    }

    internal bool IsDisposed => _disposed;

    internal static SceAudioPropagationVector3 ToSceVector(Vector3 v) => new()
    {
        X = v.X,
        Y = v.Y,
        Z = v.Z,
        Pad = 0,
    };

    internal static Vector3 FromSceVector(SceAudioPropagationVector3 v) => new(v.X, v.Y, v.Z);

    private static SceAudioPropagationRay ToSceRay(PropagationRay ray) => new()
    {
        Desc = new SceAudioPropagationStructDescriptor
        {
            Id = (uint)AudioPropagationStructId.Ray,
            Size = (nuint)sizeof(SceAudioPropagationRay),
        },
        Start = ToSceVector(ray.Start),
        Dir = ToSceVector(ray.Direction),
        CollisionPosition = ToSceVector(ray.CollisionPosition),
        CollisionNormal = ToSceVector(ray.CollisionNormal),
        CollisionMaterial = ray.CollisionMaterial,
    };

    private static PropagationRay FromSceRay(SceAudioPropagationRay ray) => new()
    {
        Start = FromSceVector(ray.Start),
        Direction = FromSceVector(ray.Dir),
        CollisionPosition = FromSceVector(ray.CollisionPosition),
        CollisionNormal = FromSceVector(ray.CollisionNormal),
        CollisionMaterial = ray.CollisionMaterial,
    };

    private static void WriteMaterialName(string name, byte* destination)
    {
        int maxBytes = SceAudioPropagation.MaterialNameMaxLen;
        int estimated = Encoding.UTF8.GetByteCount(name);
        if (estimated > maxBytes)
            throw new ArgumentException($"Material name is longer than {maxBytes} bytes when encoded as UTF-8.", nameof(name));

        Span<byte> temp = stackalloc byte[maxBytes + 1];
        temp.Clear();
        int written = Encoding.UTF8.GetBytes(name, temp[..maxBytes]);
        for (int i = 0; i < written; i++)
        {
            if (temp[i] == 0)
                throw new ArgumentException("Material name must not contain a null byte.", nameof(name));
            destination[i] = temp[i];
        }
        destination[written] = 0;
    }
}

/// <summary>
/// A room the listener or a source can be inside. Rooms are the vertices of the acoustic graph;
/// <see cref="PropagationPortal"/> connects two rooms. Disposing the room releases its handle back
/// to the engine.
/// </summary>
public sealed class PropagationRoom : IDisposable
{
    private readonly PropagationSystem _system;
    private readonly ulong _handle;
    private bool _disposed;

    internal PropagationRoom(PropagationSystem system, ulong handle)
    {
        _system = system;
        _handle = handle;
    }

    /// <summary>The system that owns this room.</summary>
    public PropagationSystem System => _system;

    /// <summary>The underlying room handle.</summary>
    public ulong Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle;
        }
    }

    /// <summary>Releases the room back to the engine. Safe to call after the system has been disposed.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (!_system.IsDisposed)
            SceAudioPropagation.sceAudioPropagationRoomDestroy(_system.Handle, _handle);
    }
}

/// <summary>
/// A portal connecting two rooms. Sound reaches the listener through a portal when the listener and
/// the source are in different rooms. Disposing the portal releases its handle back to the engine.
/// </summary>
public sealed unsafe class PropagationPortal : IDisposable
{
    private readonly PropagationSystem _system;
    private readonly ulong _handle;
    private bool _disposed;

    internal PropagationPortal(PropagationSystem system, ulong handle)
    {
        _system = system;
        _handle = handle;
    }

    /// <summary>The system that owns this portal.</summary>
    public PropagationSystem System => _system;

    /// <summary>The underlying portal handle.</summary>
    public ulong Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle;
        }
    }

    /// <summary>Sets the portal's listener-relative position.</summary>
    public void SetPosition(Vector3 position)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationVector3 value = PropagationSystem.ToSceVector(position);
        SetAttribute(AudioPropagationPortalAttribute.Position, &value, (nuint)sizeof(SceAudioPropagationVector3));
    }

    /// <summary>Sets the portal's forward direction.</summary>
    public void SetForward(Vector3 direction)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationVector3 value = PropagationSystem.ToSceVector(direction);
        SetAttribute(AudioPropagationPortalAttribute.Forwards, &value, (nuint)sizeof(SceAudioPropagationVector3));
    }

    /// <summary>Sets the portal's upward direction.</summary>
    public void SetUpward(Vector3 direction)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationVector3 value = PropagationSystem.ToSceVector(direction);
        SetAttribute(AudioPropagationPortalAttribute.Upwards, &value, (nuint)sizeof(SceAudioPropagationVector3));
    }

    /// <summary>Sets the portal's half-size along each axis.</summary>
    public void SetExtents(Vector3 extents)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationVector3 value = PropagationSystem.ToSceVector(extents);
        SetAttribute(AudioPropagationPortalAttribute.Extents, &value, (nuint)sizeof(SceAudioPropagationVector3));
    }

    /// <summary>Sets the two rooms the portal connects.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="roomA"/> or <paramref name="roomB"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">A room belongs to a different system.</exception>
    public void SetRooms(PropagationRoom roomA, PropagationRoom roomB)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(roomA);
        ArgumentNullException.ThrowIfNull(roomB);
        if (!ReferenceEquals(roomA.System, _system) || !ReferenceEquals(roomB.System, _system))
            throw new ArgumentException("The rooms must belong to this system.");

        SceAudioPropagationPortalRoom rooms = default;
        rooms.HRoom[0] = roomA.Handle;
        rooms.HRoom[1] = roomB.Handle;
        SetAttribute(AudioPropagationPortalAttribute.Room, &rooms, (nuint)sizeof(SceAudioPropagationPortalRoom));
    }

    private void SetAttribute(AudioPropagationPortalAttribute id, void* value, nuint valueSize)
    {
        SceAudioPropagationAttribute attribute = new()
        {
            AttributeId = (uint)id,
            Value = value,
            ValueSize = valueSize,
            Pad = 0,
        };
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationPortalSetAttributes(_handle, &attribute, 1),
            nameof(SceAudioPropagation.sceAudioPropagationPortalSetAttributes));
    }

    /// <summary>Releases the portal back to the engine.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (!_system.IsDisposed)
            SceAudioPropagation.sceAudioPropagationPortalDestroy(_system.Handle, _handle);
    }
}

/// <summary>
/// A sound source in the propagation graph. A source has a position, a direction, a rolloff, a cone,
/// a filter setting, an optional room, and a buffer of samples to emit. Set these once at load time
/// and update the ones that change per frame. Call <see cref="Render(AudioPropagationOutputFormat)"/>
/// once per audio block to produce the mixed output for the source.
/// </summary>
public sealed unsafe class PropagationSource : IDisposable
{
    private readonly PropagationSystem _system;
    private readonly ulong _handle;
    private void* _pcmBuffer;
    private uint _pcmByteSize;
    private AudioPropagationPcmType _pcmType;
    private bool _disposed;

    internal PropagationSource(PropagationSystem system, ulong handle)
    {
        _system = system;
        _handle = handle;
    }

    /// <summary>The system that owns this source.</summary>
    public PropagationSystem System => _system;

    /// <summary>The underlying source handle.</summary>
    public ulong Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _handle;
        }
    }

    /// <summary>Sets the source's listener-relative position.</summary>
    public void SetPosition(Vector3 position)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationVector3 value = PropagationSystem.ToSceVector(position);
        SetAttribute(AudioPropagationSourceAttribute.Position, &value, (nuint)sizeof(SceAudioPropagationVector3));
    }

    /// <summary>Sets the source's forward direction.</summary>
    public void SetDirection(Vector3 direction)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationVector3 value = PropagationSystem.ToSceVector(direction);
        SetAttribute(AudioPropagationSourceAttribute.Direction, &value, (nuint)sizeof(SceAudioPropagationVector3));
    }

    /// <summary>Sets the source's distance-based attenuation.</summary>
    public void SetRolloff(PropagationRolloff rolloff)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationRolloff value = new()
        {
            Model = (uint)rolloff.Model,
            MaxDistance = rolloff.MaxDistance,
            RolloffFactor = rolloff.RolloffFactor,
            ReferenceDistance = rolloff.ReferenceDistance,
        };
        SetAttribute(AudioPropagationSourceAttribute.Rolloff, &value, (nuint)sizeof(SceAudioPropagationRolloff));
    }

    /// <summary>Sets the source's directional cone.</summary>
    public void SetCone(PropagationCone cone)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationCone value = new()
        {
            InnerLevel = cone.InnerLevel,
            InnerAngle = cone.InnerAngle,
            OuterLevel = cone.OuterLevel,
            OuterAngle = cone.OuterAngle,
        };
        SetAttribute(AudioPropagationSourceAttribute.Cone, &value, (nuint)sizeof(SceAudioPropagationCone));
    }

    /// <summary>Sets the source's material-absorption filter kind.</summary>
    public void SetFilter(AudioPropagationFilterType filter)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceAudioPropagationFilter value = new()
        {
            Type = (int)filter,
            Pad = 0,
        };
        SetAttribute(AudioPropagationSourceAttribute.Filter, &value, (nuint)sizeof(SceAudioPropagationFilter));
    }

    /// <summary>Sets the room the source is inside, or clears it when <paramref name="room"/> is <c>null</c>.</summary>
    /// <exception cref="ArgumentException"><paramref name="room"/> belongs to a different system.</exception>
    public void SetRoom(PropagationRoom? room)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (room is not null && !ReferenceEquals(room.System, _system))
            throw new ArgumentException("The room must belong to this system.", nameof(room));

        ulong value = room?.Handle ?? SceAudioPropagation.HandleNone;
        SetAttribute(AudioPropagationSourceAttribute.Room, &value, sizeof(ulong));
    }

    /// <summary>
    /// Sets the block of 16-bit samples the source emits. The samples are copied into an unmanaged
    /// buffer the source owns; a subsequent call replaces that buffer, and <see cref="Dispose"/>
    /// releases it. Pass an empty span to clear the source.
    /// </summary>
    public void SetPcm(ReadOnlySpan<short> samples)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int bytes = samples.Length * sizeof(short);
        void* buffer = CopyToUnmanagedBuffer(MemoryMarshal.AsBytes(samples), bytes);
        try
        {
            AssignPcm(buffer, (uint)bytes, AudioPropagationPcmType.Int16);
            buffer = null;
        }
        finally
        {
            if (buffer != null)
                NativeMemory.Free(buffer);
        }
    }

    /// <summary>
    /// Sets the block of 32-bit floating-point samples the source emits. The samples are copied into
    /// an unmanaged buffer the source owns; a subsequent call replaces that buffer, and
    /// <see cref="Dispose"/> releases it. Pass an empty span to clear the source.
    /// </summary>
    public void SetPcm(ReadOnlySpan<float> samples)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int bytes = samples.Length * sizeof(float);
        void* buffer = CopyToUnmanagedBuffer(MemoryMarshal.AsBytes(samples), bytes);
        try
        {
            AssignPcm(buffer, (uint)bytes, AudioPropagationPcmType.Float);
            buffer = null;
        }
        finally
        {
            if (buffer != null)
                NativeMemory.Free(buffer);
        }
    }

    /// <summary>
    /// Reads out the raycasts the engine wants for this source's paths. Fill in the collision fields
    /// on each returned ray and hand the array to <see cref="CalculateAudioPaths"/>.
    /// </summary>
    /// <exception cref="ProsperoException">The engine could not report its raycasts.</exception>
    public PropagationRay[] GetRays()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        uint capacity = SceAudioPropagation.MaxRaycasts;
        SceAudioPropagationRay* buffer = stackalloc SceAudioPropagationRay[(int)capacity];
        uint count = capacity;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSourceGetRays(_handle, buffer, &count),
            nameof(SceAudioPropagation.sceAudioPropagationSourceGetRays));

        PropagationRay[] result = new PropagationRay[count];
        for (int i = 0; i < count; i++)
            result[i] = FromSceRay(buffer[i]);
        return result;
    }

    /// <summary>
    /// Uses the completed raycasts to calculate the audio paths between this source and the listener
    /// up to <paramref name="maxOrder"/> reflections. Returns up to <paramref name="maxPaths"/> paths;
    /// paths that could not be calculated carry <see cref="AudioPropagationPathFlags.Invalid"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">A count is out of range.</exception>
    /// <exception cref="ProsperoException">The engine could not calculate the paths.</exception>
    public PropagationAudioPath[] CalculateAudioPaths(
        ReadOnlySpan<PropagationRay> rays,
        int maxOrder = SceAudioPropagation.MaxBounces,
        int maxPaths = SceAudioPropagation.MaxPaths)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(maxOrder);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxOrder, SceAudioPropagation.MaxBounces);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxPaths);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxPaths, SceAudioPropagation.MaxPaths);

        int inCount = rays.Length;
        SceAudioPropagationRay* inRays = stackalloc SceAudioPropagationRay[inCount == 0 ? 1 : inCount];
        for (int i = 0; i < inCount; i++)
            inRays[i] = ToSceRay(rays[i]);

        SceAudioPropagationAudioPath* outPaths = stackalloc SceAudioPropagationAudioPath[maxPaths];
        for (int i = 0; i < maxPaths; i++)
        {
            outPaths[i] = default;
            outPaths[i].Desc = new SceAudioPropagationStructDescriptor
            {
                Id = (uint)AudioPropagationStructId.Path,
                Size = (nuint)sizeof(SceAudioPropagationAudioPath),
            };
        }

        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSourceCalculateAudioPaths(
                _handle, inRays, (uint)inCount, (uint)maxOrder, outPaths, (uint)maxPaths),
            nameof(SceAudioPropagation.sceAudioPropagationSourceCalculateAudioPaths));

        PropagationAudioPath[] result = new PropagationAudioPath[maxPaths];
        for (int i = 0; i < maxPaths; i++)
            result[i] = FromScePath(outPaths[i]);
        return result;
    }

    /// <summary>The number of audio paths the source currently holds.</summary>
    /// <exception cref="ProsperoException">The engine could not report the count.</exception>
    public int AudioPathCount
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            uint count = 0;
            SceResult.ThrowIfFailed(
                SceAudioPropagation.sceAudioPropagationSourceGetAudioPathCount(_handle, &count),
                nameof(SceAudioPropagation.sceAudioPropagationSourceGetAudioPathCount));
            return (int)count;
        }
    }

    /// <summary>Retrieves the handle of the audio path at <paramref name="index"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="index"/> is negative.</exception>
    /// <exception cref="ProsperoException">The engine could not report the handle.</exception>
    public ulong GetAudioPathHandle(int index)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ulong handle = SceAudioPropagation.HandleNone;
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSourceGetAudioPath(_handle, (uint)index, &handle),
            nameof(SceAudioPropagation.sceAudioPropagationSourceGetAudioPath));
        return handle;
    }

    /// <summary>
    /// Overwrites the point list of the audio path <paramref name="pathHandle"/> with
    /// <paramref name="path"/> and sets the output gain to <paramref name="gain"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="path"/> has too many points.</exception>
    public void SetAudioPath(ulong pathHandle, PropagationAudioPath path, float gain)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (path.Points is null)
            throw new ArgumentException("Points must not be null.", nameof(path));
        if (path.Points.Length > SceAudioPropagation.MaxPathPoints)
            throw new ArgumentException(
                $"A path holds up to {SceAudioPropagation.MaxPathPoints} points.", nameof(path));

        SceAudioPropagationAudioPath wire = default;
        wire.Desc = new SceAudioPropagationStructDescriptor
        {
            Id = (uint)AudioPropagationStructId.Path,
            Size = (nuint)sizeof(SceAudioPropagationAudioPath),
        };
        WritePathPoints(path.Points, ref wire);
        wire.NumPoints = (uint)path.Points.Length;
        wire.Flags = (uint)path.Flags;
        wire.Pad = 0;

        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSourceSetAudioPath(pathHandle, &wire, gain),
            nameof(SceAudioPropagation.sceAudioPropagationSourceSetAudioPath));
    }

    /// <summary>
    /// Renders one audio block for this source into a fresh managed buffer and returns it. The
    /// returned array holds <c>UpdateGrain * channels(format)</c> floats.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a supported output format.</exception>
    /// <exception cref="ProsperoException">The engine could not render the block.</exception>
    public float[] Render(AudioPropagationOutputFormat format)
    {
        int channels = ChannelCount(format);
        float[] buffer = new float[_system.UpdateGrain * channels];
        Render(format, buffer);
        return buffer;
    }

    /// <summary>
    /// Renders one audio block for this source, mixing on top of the existing contents of
    /// <paramref name="buffer"/>. The buffer must hold at least <c>UpdateGrain * channels(format)</c>
    /// floats; use the same buffer across sources to build a combined mix.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="format"/> is not a supported output format.</exception>
    /// <exception cref="ArgumentException"><paramref name="buffer"/> is smaller than one block.</exception>
    /// <exception cref="ProsperoException">The engine could not render the block.</exception>
    public void Render(AudioPropagationOutputFormat format, Span<float> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int channels = ChannelCount(format);
        int required = _system.UpdateGrain * channels;
        if (buffer.Length < required)
            throw new ArgumentException($"The buffer needs at least {required} floats.", nameof(buffer));

        fixed (float* p = buffer)
        {
            SceAudioPropagationSourceRenderInfo info = new()
            {
                Desc = new SceAudioPropagationStructDescriptor
                {
                    Id = (uint)AudioPropagationStructId.SourceRenderInfo,
                    Size = (nuint)sizeof(SceAudioPropagationSourceRenderInfo),
                },
                SourceHandle = _handle,
                Buffer = p,
                BufferSize = (nuint)(required * sizeof(float)),
                Format = (uint)format,
                Pad = 0,
            };
            SceResult.ThrowIfFailed(
                SceAudioPropagation.sceAudioPropagationSourceRender(_system.Handle, &info, 1),
                nameof(SceAudioPropagation.sceAudioPropagationSourceRender));
        }
    }

    /// <summary>Releases the source and frees any PCM buffer it holds.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (!_system.IsDisposed)
            SceAudioPropagation.sceAudioPropagationSourceDestroy(_system.Handle, _handle);
        if (_pcmBuffer != null)
        {
            NativeMemory.Free(_pcmBuffer);
            _pcmBuffer = null;
            _pcmByteSize = 0;
        }
    }

    private void SetAttribute(AudioPropagationSourceAttribute id, void* value, nuint valueSize)
    {
        SceAudioPropagationAttribute attribute = new()
        {
            AttributeId = (uint)id,
            Value = value,
            ValueSize = valueSize,
            Pad = 0,
        };
        SceResult.ThrowIfFailed(
            SceAudioPropagation.sceAudioPropagationSourceSetAttributes(_handle, &attribute, 1),
            nameof(SceAudioPropagation.sceAudioPropagationSourceSetAttributes));
    }

    private static void* CopyToUnmanagedBuffer(ReadOnlySpan<byte> source, int bytes)
    {
        if (bytes == 0)
            return null;
        void* buffer = NativeMemory.Alloc((nuint)bytes);
        source.CopyTo(new Span<byte>(buffer, bytes));
        return buffer;
    }

    private void AssignPcm(void* buffer, uint bytes, AudioPropagationPcmType type)
    {
        SceAudioPropagationPcm pcm = new()
        {
            Data = buffer,
            DataSizeBytes = bytes,
            DataType = (uint)type,
            Pad = 0,
        };
        // On failure the caller's try/finally frees the passed-in buffer. This method only takes
        // ownership after the attribute is set: the previous buffer is released, and the new one
        // is stashed. A caught-and-rethrown exception here would race the caller's finally on the
        // same address, so let the exception propagate as-is.
        SetAttribute(AudioPropagationSourceAttribute.Pcm, &pcm, (nuint)sizeof(SceAudioPropagationPcm));

        if (_pcmBuffer != null)
            NativeMemory.Free(_pcmBuffer);
        _pcmBuffer = buffer;
        _pcmByteSize = bytes;
        _pcmType = type;
    }

    private static int ChannelCount(AudioPropagationOutputFormat format) => format switch
    {
        AudioPropagationOutputFormat.AmbisonicsFirstOrder => SceAudioPropagation.ChannelsAmbisonicsFirstOrder,
        AudioPropagationOutputFormat.AmbisonicsSecondOrder => SceAudioPropagation.ChannelsAmbisonicsSecondOrder,
        AudioPropagationOutputFormat.AmbisonicsThirdOrder => SceAudioPropagation.ChannelsAmbisonicsThirdOrder,
        AudioPropagationOutputFormat.ChannelFloat8Ch => SceAudioPropagation.Channels8Ch,
        AudioPropagationOutputFormat.ChannelFloat8ChStd => SceAudioPropagation.Channels8Ch,
        _ => throw new ArgumentOutOfRangeException(nameof(format), $"Unknown output format {format}."),
    };

    private static SceAudioPropagationRay ToSceRay(PropagationRay ray) => new()
    {
        Desc = new SceAudioPropagationStructDescriptor
        {
            Id = (uint)AudioPropagationStructId.Ray,
            Size = (nuint)sizeof(SceAudioPropagationRay),
        },
        Start = PropagationSystem.ToSceVector(ray.Start),
        Dir = PropagationSystem.ToSceVector(ray.Direction),
        CollisionPosition = PropagationSystem.ToSceVector(ray.CollisionPosition),
        CollisionNormal = PropagationSystem.ToSceVector(ray.CollisionNormal),
        CollisionMaterial = ray.CollisionMaterial,
    };

    private static PropagationRay FromSceRay(SceAudioPropagationRay ray) => new()
    {
        Start = PropagationSystem.FromSceVector(ray.Start),
        Direction = PropagationSystem.FromSceVector(ray.Dir),
        CollisionPosition = PropagationSystem.FromSceVector(ray.CollisionPosition),
        CollisionNormal = PropagationSystem.FromSceVector(ray.CollisionNormal),
        CollisionMaterial = ray.CollisionMaterial,
    };

    private static PropagationAudioPath FromScePath(SceAudioPropagationAudioPath path)
    {
        int count = (int)Math.Min(path.NumPoints, (uint)SceAudioPropagation.MaxPathPoints);
        PropagationPathPoint[] points = new PropagationPathPoint[count];
        for (int i = 0; i < count; i++)
        {
            SceAudioPropagationAudioPathPoint point = i switch
            {
                0 => path.Point0,
                1 => path.Point1,
                2 => path.Point2,
                3 => path.Point3,
                _ => default,
            };
            points[i] = new PropagationPathPoint(
                PropagationSystem.FromSceVector(point.Pos),
                point.Gain,
                point.Material);
        }
        return new PropagationAudioPath(points, (AudioPropagationPathFlags)path.Flags);
    }

    private static void WritePathPoints(PropagationPathPoint[] points, ref SceAudioPropagationAudioPath path)
    {
        int count = points.Length;
        for (int i = 0; i < count; i++)
        {
            SceAudioPropagationAudioPathPoint entry = new()
            {
                Desc = new SceAudioPropagationStructDescriptor
                {
                    Id = (uint)AudioPropagationStructId.PathPoint,
                    Size = (nuint)sizeof(SceAudioPropagationAudioPathPoint),
                },
                Material = points[i].Material,
                Gain = points[i].Gain,
                Pos = PropagationSystem.ToSceVector(points[i].Position),
            };
            switch (i)
            {
                case 0: path.Point0 = entry; break;
                case 1: path.Point1 = entry; break;
                case 2: path.Point2 = entry; break;
                case 3: path.Point3 = entry; break;
            }
        }
    }
}
