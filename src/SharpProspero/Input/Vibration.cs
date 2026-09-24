// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Pad;
using System;
using System.Collections.Generic;

namespace SharpProspero.Input;

/// <summary>The two motor levels a controller accepts, each 0 (stop) through 255 (full).</summary>
public readonly struct VibrationLevels : IEquatable<VibrationLevels>
{
    /// <summary>Creates a pair with <paramref name="largeMotor"/> and <paramref name="smallMotor"/>.</summary>
    public VibrationLevels(byte largeMotor, byte smallMotor)
    {
        LargeMotor = largeMotor;
        SmallMotor = smallMotor;
    }

    /// <summary>Large (left) motor level.</summary>
    public byte LargeMotor { get; }

    /// <summary>Small (right) motor level.</summary>
    public byte SmallMotor { get; }

    /// <summary>Both motors stopped.</summary>
    public static VibrationLevels Zero => default;

    /// <summary>Both motors at full drive.</summary>
    public static VibrationLevels Full => new(255, 255);

    /// <summary>True when both motors are stopped.</summary>
    public bool IsZero => LargeMotor == 0 && SmallMotor == 0;

    /// <summary>
    /// The pair scaled by <paramref name="strength"/>, from 0 to 1. Values outside are clamped, so a caller
    /// can dial a full-drive pair down to a fraction of it without a further check.
    /// </summary>
    public VibrationLevels Scaled(float strength)
    {
        float clamped = Math.Clamp(strength, 0f, 1f);
        return new VibrationLevels(
            (byte)MathF.Round(LargeMotor * clamped),
            (byte)MathF.Round(SmallMotor * clamped));
    }

    /// <summary>
    /// Linearly interpolates between <paramref name="from"/> and <paramref name="to"/> at position
    /// <paramref name="t"/>, from 0 (from) to 1 (to). The position is clamped, so a caller running slightly
    /// past the end stays at the end value.
    /// </summary>
    public static VibrationLevels Lerp(VibrationLevels from, VibrationLevels to, float t)
    {
        float p = Math.Clamp(t, 0f, 1f);
        int large = (int)MathF.Round(from.LargeMotor + (to.LargeMotor - from.LargeMotor) * p);
        int small = (int)MathF.Round(from.SmallMotor + (to.SmallMotor - from.SmallMotor) * p);
        return new VibrationLevels(ClampByte(large), ClampByte(small));
    }

    private static byte ClampByte(int value) => (byte)Math.Clamp(value, 0, 255);

    /// <inheritdoc/>
    public bool Equals(VibrationLevels other) => LargeMotor == other.LargeMotor && SmallMotor == other.SmallMotor;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is VibrationLevels other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => (LargeMotor << 8) | SmallMotor;

    /// <inheritdoc/>
    public override string ToString() => $"L={LargeMotor} S={SmallMotor}";

    /// <summary>True when both pairs report identical motor levels.</summary>
    public static bool operator ==(VibrationLevels a, VibrationLevels b) => a.Equals(b);

    /// <summary>True when the pairs differ on either motor.</summary>
    public static bool operator !=(VibrationLevels a, VibrationLevels b) => !a.Equals(b);
}

/// <summary>What the animator is doing over time.</summary>
public enum VibrationMode
{
    /// <summary>One level pair that does not change.</summary>
    Solid = 0,

    /// <summary>Motors breathe between a low and a high fraction of the base levels.</summary>
    Pulse = 1,

    /// <summary>Motors switch between two level pairs once per period.</summary>
    Blink = 2,

    /// <summary>Levels travel from one pair to another over a duration.</summary>
    Ramp = 3,

    /// <summary>A queue of timed steps runs one after another.</summary>
    Sequence = 4,
}

/// <summary>
/// One entry in a vibration sequence: a target pair of motor levels and how long it lasts. A holding step
/// drives the target for the whole duration; a fading step travels to the target from whatever the motors
/// were doing when the step began.
/// </summary>
public readonly struct VibrationStep
{
    /// <summary>The motor levels this step ends on.</summary>
    public VibrationLevels Levels { get; init; }

    /// <summary>How long the step lasts, in seconds. Must be greater than zero.</summary>
    public float DurationSeconds { get; init; }

    /// <summary>True to travel to <see cref="Levels"/> across the step, false to drive the target at once.</summary>
    public bool Fade { get; init; }

    /// <summary>A step that drives <paramref name="levels"/> for <paramref name="seconds"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="seconds"/> is not greater than zero.</exception>
    public static VibrationStep Hold(VibrationLevels levels, float seconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(seconds);
        return new VibrationStep { Levels = levels, DurationSeconds = seconds, Fade = false };
    }

    /// <summary>
    /// A step that travels from the previous pair to <paramref name="levels"/> across
    /// <paramref name="seconds"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="seconds"/> is not greater than zero.</exception>
    public static VibrationStep FadeTo(VibrationLevels levels, float seconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(seconds);
        return new VibrationStep { Levels = levels, DurationSeconds = seconds, Fade = true };
    }

    /// <summary>A pause: both motors held stopped for <paramref name="seconds"/>.</summary>
    public static VibrationStep Rest(float seconds) => Hold(VibrationLevels.Zero, seconds);
}

/// <summary>
/// The motor levels a controller should be driven with, and how those levels move from frame to frame.
/// Nothing here touches a device: pick a state, call <see cref="Update"/> once per frame with the frame's
/// elapsed time, and read <see cref="Current"/>. <see cref="Vibration"/> drives one of these and writes
/// the result to a controller.
/// </summary>
public sealed class VibrationAnimator
{
    private const float Tau = MathF.PI * 2f;

    private VibrationMode _mode = VibrationMode.Solid;
    private VibrationLevels _current;
    private VibrationLevels _from;
    private VibrationLevels _to;
    private float _phase;
    private float _elapsed;
    private float _period = 1f;
    private float _duration = 1f;
    private float _dutyCycle = 0.5f;
    private float _minStrength;
    private float _maxStrength = 1f;
    private bool _loop;
    private bool _finished = true;

    private readonly List<VibrationStep> _steps = [];
    private int _stepIndex;
    private VibrationLevels _stepStartLevels;

    private VibrationLevels _lastTaken;
    private bool _hasTaken;

    /// <summary>What the animator is doing.</summary>
    public VibrationMode Mode => _mode;

    /// <summary>The motor levels for this frame.</summary>
    public VibrationLevels Current => _current;

    /// <summary>
    /// True when nothing is left to animate: a solid pair, a finished ramp, or a finished sequence. A
    /// pulse, a blink and anything looping never finish.
    /// </summary>
    public bool IsFinished => _finished;

    /// <summary>Drives <paramref name="levels"/> and stops animating.</summary>
    public void Solid(VibrationLevels levels)
    {
        _mode = VibrationMode.Solid;
        _current = levels;
        _loop = false;
        _finished = true;
        _steps.Clear();
    }

    /// <summary>Stops both motors and stops animating.</summary>
    public void Off() => Solid(VibrationLevels.Zero);

    /// <summary>
    /// Breathes <paramref name="levels"/> between <paramref name="minStrength"/> and
    /// <paramref name="maxStrength"/> (each 0 to 1) once every <paramref name="periodSeconds"/>. The cycle
    /// starts at the low end, reaches the high end at half the period and returns to the low end at the
    /// end of it.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The period is not greater than zero, a strength lies outside 0 to 1, or the low end is above the
    /// high end.
    /// </exception>
    public void Pulse(VibrationLevels levels, float periodSeconds, float minStrength = 0f, float maxStrength = 1f)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(periodSeconds);
        ArgumentOutOfRangeException.ThrowIfNegative(minStrength);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxStrength, 1f);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(minStrength, maxStrength);

        _mode = VibrationMode.Pulse;
        _from = levels;
        _period = periodSeconds;
        _minStrength = minStrength;
        _maxStrength = maxStrength;
        _phase = 0f;
        _loop = true;
        _finished = false;
        _steps.Clear();
        _current = levels.Scaled(minStrength);
    }

    /// <summary>
    /// Switches between <paramref name="onLevels"/> and <paramref name="offLevels"/> once every
    /// <paramref name="periodSeconds"/>. <paramref name="dutyCycle"/> is the share of the period the on
    /// pair holds, from 0 to 1. The cycle starts on the on pair.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The period is not greater than zero, or the duty cycle lies outside 0 to 1.
    /// </exception>
    public void Blink(VibrationLevels onLevels, VibrationLevels offLevels, float periodSeconds, float dutyCycle = 0.5f)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(periodSeconds);
        ArgumentOutOfRangeException.ThrowIfNegative(dutyCycle);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(dutyCycle, 1f);

        _mode = VibrationMode.Blink;
        _from = onLevels;
        _to = offLevels;
        _period = periodSeconds;
        _dutyCycle = dutyCycle;
        _phase = 0f;
        _loop = true;
        _finished = false;
        _steps.Clear();
        _current = dutyCycle > 0f ? onLevels : offLevels;
    }

    /// <summary>
    /// Travels from <paramref name="from"/> to <paramref name="to"/> across
    /// <paramref name="durationSeconds"/>. With <paramref name="loop"/> set the ramp restarts at
    /// <paramref name="from"/>; without it the ramp holds <paramref name="to"/> and reports finished.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The duration is not greater than zero.</exception>
    public void Ramp(VibrationLevels from, VibrationLevels to, float durationSeconds, bool loop = false)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(durationSeconds);

        _mode = VibrationMode.Ramp;
        _from = from;
        _to = to;
        _duration = durationSeconds;
        _elapsed = 0f;
        _loop = loop;
        _finished = false;
        _steps.Clear();
        _current = from;
    }

    /// <summary>
    /// Runs <paramref name="steps"/> in order. A fading step starts from the pair driving when it began,
    /// so the first one starts from <see cref="Current"/>. With <paramref name="loop"/> set the queue
    /// restarts once it runs out.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="steps"/> is null.</exception>
    /// <exception cref="ArgumentException">The queue is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A step lasts zero seconds or less.</exception>
    public void Sequence(IEnumerable<VibrationStep> steps, bool loop = false)
    {
        ArgumentNullException.ThrowIfNull(steps);

        _steps.Clear();
        _steps.AddRange(steps);
        if (_steps.Count == 0)
            throw new ArgumentException("A vibration sequence needs at least one step.", nameof(steps));

        foreach (VibrationStep step in _steps)
        {
            if (step.DurationSeconds <= 0f)
                throw new ArgumentOutOfRangeException(nameof(steps), "Every vibration step must last longer than zero seconds.");
        }

        _mode = VibrationMode.Sequence;
        _stepIndex = 0;
        _elapsed = 0f;
        _loop = loop;
        _finished = false;
        _stepStartLevels = _current;
        _current = _steps[0].Fade ? _stepStartLevels : _steps[0].Levels;
    }

    /// <summary>Advances the state by <paramref name="deltaSeconds"/> and recomputes <see cref="Current"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="deltaSeconds"/> is negative.</exception>
    public void Update(float deltaSeconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(deltaSeconds);

        switch (_mode)
        {
            case VibrationMode.Pulse:
                _phase = Wrap(_phase + deltaSeconds / _period);
                float level = _minStrength
                    + (_maxStrength - _minStrength) * (1f - MathF.Cos(_phase * Tau)) * 0.5f;
                _current = _from.Scaled(level);
                break;

            case VibrationMode.Blink:
                _phase = Wrap(_phase + deltaSeconds / _period);
                _current = _phase < _dutyCycle ? _from : _to;
                break;

            case VibrationMode.Ramp:
                AdvanceRamp(deltaSeconds);
                break;

            case VibrationMode.Sequence:
                AdvanceSequence(deltaSeconds);
                break;
        }
    }

    /// <summary>
    /// Reports <see cref="Current"/> only when it differs from the pair reported last, so a caller writes
    /// to a controller on the frames that changed rather than on every frame. The first call always
    /// reports.
    /// </summary>
    public bool TryTakeChangedLevels(out VibrationLevels levels)
    {
        if (_hasTaken && _lastTaken == _current)
        {
            levels = _current;
            return false;
        }

        _lastTaken = _current;
        _hasTaken = true;
        levels = _current;
        return true;
    }

    /// <summary>
    /// Forgets which pair was last reported, so the next <see cref="TryTakeChangedLevels"/> reports again.
    /// Use it after something else has driven the motors and the animator's record is stale.
    /// </summary>
    public void InvalidateTakenLevels() => _hasTaken = false;

    private void AdvanceRamp(float deltaSeconds)
    {
        _elapsed += deltaSeconds;
        float t;
        if (_elapsed >= _duration)
        {
            if (_loop)
            {
                _elapsed %= _duration;
                t = _elapsed / _duration;
            }
            else
            {
                _elapsed = _duration;
                t = 1f;
                _finished = true;
            }
        }
        else
        {
            t = _elapsed / _duration;
        }

        _current = VibrationLevels.Lerp(_from, _to, t);
    }

    private void AdvanceSequence(float deltaSeconds)
    {
        if (_finished)
            return;

        _elapsed += deltaSeconds;
        while (_elapsed >= _steps[_stepIndex].DurationSeconds)
        {
            VibrationStep done = _steps[_stepIndex];
            if (_stepIndex + 1 >= _steps.Count && !_loop)
            {
                _elapsed = done.DurationSeconds;
                _finished = true;
                _current = done.Levels;
                return;
            }

            _elapsed -= done.DurationSeconds;
            _stepStartLevels = done.Levels;
            _stepIndex = (_stepIndex + 1) % _steps.Count;
        }

        VibrationStep step = _steps[_stepIndex];
        _current = step.Fade
            ? VibrationLevels.Lerp(_stepStartLevels, step.Levels, _elapsed / step.DurationSeconds)
            : step.Levels;
    }

    private static float Wrap(float phase) => phase - MathF.Floor(phase);
}

/// <summary>
/// The vibration motors of one controller. Pick a state, then call <see cref="Update"/> once per frame;
/// the pair is written to the controller only on the frames it changed, because each write is a request
/// to the controller service and a frame loop must not spend one where nothing moved.
/// </summary>
/// <remarks>
/// Setting a pair and stopping the motors are the only operations an application can reach directly.
/// Everything else the frame loop needs - a pulse, a blink, a ramp, a queue of steps - is produced here
/// and written as a plain pair, which is why <see cref="Update"/> never blocks.
/// </remarks>
public sealed class Vibration
{
    private readonly GamePad _pad;
    private readonly VibrationAnimator _animator = new();
    private bool _idle = true;

    /// <summary>Binds a vibration driver to <paramref name="pad"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="pad"/> is null.</exception>
    public Vibration(GamePad pad)
    {
        ArgumentNullException.ThrowIfNull(pad);
        _pad = pad;
    }

    /// <summary>The pair the motors should be driven with this frame.</summary>
    public VibrationLevels Current => _animator.Current;

    /// <summary>What the driver is doing over time.</summary>
    public VibrationMode Mode => _animator.Mode;

    /// <summary>True once a ramp or a sequence has run out, and for a solid pair.</summary>
    public bool IsFinished => _animator.IsFinished;

    /// <summary>
    /// True while nothing has been driven yet, and again after <see cref="Stop"/> succeeds. In the idle
    /// state <see cref="Update"/> does no work and writes nothing.
    /// </summary>
    public bool IsIdle => _idle;

    /// <summary>Drives one pair that does not change.</summary>
    public void SetLevels(VibrationLevels levels)
    {
        _animator.Solid(levels);
        Resume();
    }

    /// <summary>Drives one pair of motor levels that do not change.</summary>
    public void SetLevels(byte largeMotor, byte smallMotor) => SetLevels(new VibrationLevels(largeMotor, smallMotor));

    /// <summary>
    /// Stops both motors, ends any animation, and writes the zero pair to the controller. Returns false
    /// when the controller does not accept the request.
    /// </summary>
    public bool Stop()
    {
        _animator.Off();
        _animator.InvalidateTakenLevels();
        _idle = true;
        return _pad.SetVibration(0, 0);
    }

    /// <summary>
    /// Breathes <paramref name="levels"/> between <paramref name="minStrength"/> and
    /// <paramref name="maxStrength"/> (each 0 to 1) once every <paramref name="periodSeconds"/>.
    /// </summary>
    public void Pulse(VibrationLevels levels, float periodSeconds, float minStrength = 0f, float maxStrength = 1f)
    {
        _animator.Pulse(levels, periodSeconds, minStrength, maxStrength);
        Resume();
    }

    /// <summary>
    /// Switches between <paramref name="onLevels"/> and <paramref name="offLevels"/> once every
    /// <paramref name="periodSeconds"/>, holding the on pair for <paramref name="dutyCycle"/> of it.
    /// </summary>
    public void Blink(VibrationLevels onLevels, VibrationLevels offLevels, float periodSeconds, float dutyCycle = 0.5f)
    {
        _animator.Blink(onLevels, offLevels, periodSeconds, dutyCycle);
        Resume();
    }

    /// <summary>Blinks <paramref name="levels"/> against a stopped motor pair.</summary>
    public void Blink(VibrationLevels levels, float periodSeconds) => Blink(levels, VibrationLevels.Zero, periodSeconds);

    /// <summary>
    /// Travels from <paramref name="from"/> to <paramref name="to"/> across
    /// <paramref name="durationSeconds"/>, restarting when <paramref name="loop"/> is set.
    /// </summary>
    public void Ramp(VibrationLevels from, VibrationLevels to, float durationSeconds, bool loop = false)
    {
        _animator.Ramp(from, to, durationSeconds, loop);
        Resume();
    }

    /// <summary>Runs <paramref name="steps"/> in order, restarting when <paramref name="loop"/> is set.</summary>
    public void Sequence(IEnumerable<VibrationStep> steps, bool loop = false)
    {
        _animator.Sequence(steps, loop);
        Resume();
    }

    /// <summary>
    /// Chooses how the controller drives its motors: the current-generation curve, or the earlier one
    /// that follows the previous controller family more closely. Both cover the same 0-255 pair the
    /// motors take; the perceived feel differs because the actuators respond to the value differently.
    /// </summary>
    /// <remarks>
    /// The mode tells the controller service how to interpret each pair passed to <see cref="Update"/>.
    /// When the driver is already running a state, this also re-sends the current pair so the change
    /// reaches the motors immediately instead of at the next level change.
    /// </remarks>
    /// <returns>False when the controller does not accept the request.</returns>
    public bool SetDriveMode(ScePadVibrationMode mode)
    {
        if (!SceResult.Succeeded(Pad.scePadSetVibrationMode(_pad.Handle, mode)))
            return false;

        // A running state has already handed its current pair to the controller under the previous
        // mode. Push the same pair through again so the new mode reaches the motors on this frame.
        if (!_idle)
        {
            VibrationLevels current = _animator.Current;
            _pad.SetVibration(current.LargeMotor, current.SmallMotor);
            _animator.InvalidateTakenLevels();
        }
        return true;
    }

    /// <summary>
    /// Advances the state by the frame's elapsed time and writes the pair when it changed. Returns false
    /// when a write was attempted and the controller refused it.
    /// </summary>
    public bool Update(float deltaSeconds)
    {
        if (_idle)
            return true;

        _animator.Update(deltaSeconds);
        if (!_animator.TryTakeChangedLevels(out VibrationLevels levels))
            return true;
        return _pad.SetVibration(levels.LargeMotor, levels.SmallMotor);
    }

    /// <summary>
    /// Weakens vibration and trigger effects across every controller while the built-in microphone is in
    /// use, so the motors are not what the microphone picks up.
    /// </summary>
    public static bool WeakenWhileMicrophoneInUse(bool enable)
        => SceResult.Succeeded(Pad.scePadSetVibrationTriggerEffectWeakWhileEmbeddedMicInUse(enable));

    private void Resume()
    {
        _idle = false;
        _animator.InvalidateTakenLevels();
    }
}
