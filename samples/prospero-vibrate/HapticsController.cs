// Prospero Vibrate - Haptics that move You.

using SampleApp.Patterns;
using SharpProspero.Input;
using System;
using System.Collections.Generic;

namespace SampleApp;

/// <summary>What the haptics controller is doing right now.</summary>
public enum HapticsState
{
    /// <summary>Motors are stopped and no pattern is queued.</summary>
    Idle = 0,

    /// <summary>A preset or custom pattern is running.</summary>
    Playing = 1,

    /// <summary>A pattern is running under a countdown that will stop it when it expires.</summary>
    Timed = 2,

    /// <summary>The live tab is driving one pair of motor levels.</summary>
    Live = 3,
}

/// <summary>
/// Drives the controller's vibration motors on behalf of the tabs and enforces the app-wide settings.
/// One instance is owned by the top-level app and shared between tabs so a change in one place
/// (a stop, a preset, a live drive) is observed everywhere.
/// </summary>
public sealed class HapticsController
{
    private GamePad? _pad;
    private AppSettings _settings;
    private VibrationPreset? _currentPreset;
    private float _timedRemaining;
    private VibrationLevels _liveLevels;

    /// <summary>Binds the controller and settings that the tabs will drive.</summary>
    public HapticsController(GamePad? pad, AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _pad = pad;
        _settings = settings;
    }

    /// <summary>What the controller is doing right now.</summary>
    public HapticsState State { get; private set; }

    /// <summary>The preset currently playing, or null when the controller is not playing one.</summary>
    public VibrationPreset? CurrentPreset => _currentPreset;

    /// <summary>The pair of motor levels reported by the animator this frame.</summary>
    public VibrationLevels CurrentLevels => _pad?.Vibration.Current ?? VibrationLevels.Zero;

    /// <summary>Seconds left on a timed play, or zero when nothing is timed.</summary>
    public float TimedRemainingSeconds => Math.Max(0f, _timedRemaining);

    /// <summary>Seconds a timed play was originally set to run for.</summary>
    public float TimedTotalSeconds { get; private set; }

    /// <summary>The pair driving in <see cref="HapticsState.Live"/>.</summary>
    public VibrationLevels LiveLevels => _liveLevels;

    /// <summary>True when a controller is attached and can be driven right now.</summary>
    public bool HasController => _pad is not null;

    /// <summary>Called with a short message each time playback state changes; the UI shows it as a toast.</summary>
    public Action<string>? Announced { get; set; }

    /// <summary>Swap the game pad this controller drives; used when the frame loop opens or drops one.</summary>
    public void SetPad(GamePad? pad)
    {
        if (ReferenceEquals(_pad, pad))
            return;
        Stop();
        _pad = pad;
    }

    /// <summary>Apply new settings and push mode/mic-weaken options at once.</summary>
    public void ApplySettings(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;

        if (_pad is not null)
            _pad.Vibration.SetDriveMode(_settings.DriveMode);
        Vibration.WeakenWhileMicrophoneInUse(_settings.WeakenWhileMicInUse);
    }

    /// <summary>Play <paramref name="preset"/> once (or forever if it loops), stopping any previous playback.</summary>
    public bool Play(VibrationPreset preset)
    {
        ArgumentNullException.ThrowIfNull(preset);
        if (_pad is null)
        {
            Announce("No controller connected.");
            return false;
        }

        IReadOnlyList<VibrationStep> steps = ScaleSteps(preset.Steps, _settings.Strength);
        _pad.Vibration.Sequence(steps, preset.Loop);
        _currentPreset = preset;
        State = HapticsState.Playing;
        _timedRemaining = 0f;
        TimedTotalSeconds = 0f;
        Announce($"Playing '{preset.Name}'.");
        return true;
    }

    /// <summary>Play <paramref name="preset"/> and stop after <paramref name="seconds"/> even if it loops.</summary>
    public bool PlayTimed(VibrationPreset preset, float seconds)
    {
        ArgumentNullException.ThrowIfNull(preset);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(seconds);
        if (!Play(preset))
            return false;

        State = HapticsState.Timed;
        _timedRemaining = seconds;
        TimedTotalSeconds = seconds;
        Announce($"'{preset.Name}' for {seconds:0.#}s.");
        return true;
    }

    /// <summary>
    /// Drive one pair of motor levels directly, ending any pattern playback. The pair is scaled by the
    /// master strength before it reaches the controller.
    /// </summary>
    public bool DriveLive(VibrationLevels levels)
    {
        if (_pad is null)
            return false;

        VibrationLevels scaled = levels.Scaled(_settings.Strength);
        _pad.Vibration.SetLevels(scaled);
        _currentPreset = null;
        _liveLevels = levels;
        State = HapticsState.Live;
        _timedRemaining = 0f;
        TimedTotalSeconds = 0f;
        return true;
    }

    /// <summary>Stop the motors and clear any playing state.</summary>
    public bool Stop()
    {
        if (_pad is null)
        {
            State = HapticsState.Idle;
            _currentPreset = null;
            _liveLevels = VibrationLevels.Zero;
            _timedRemaining = 0f;
            TimedTotalSeconds = 0f;
            return false;
        }

        bool accepted = _pad.Vibration.Stop();
        if (State != HapticsState.Idle)
            Announce("Stopped.");
        State = HapticsState.Idle;
        _currentPreset = null;
        _liveLevels = VibrationLevels.Zero;
        _timedRemaining = 0f;
        TimedTotalSeconds = 0f;
        return accepted;
    }

    /// <summary>
    /// Advance every frame: run any countdown, and push the animator's next pair to the controller. Call
    /// after any live-drive or preset-play from the tabs. Returns false when a write was refused.
    /// </summary>
    public bool Update(float deltaSeconds)
    {
        if (_pad is null)
            return true;

        if (State == HapticsState.Timed)
        {
            _timedRemaining -= deltaSeconds;
            if (_timedRemaining <= 0f)
            {
                Stop();
                return true;
            }
        }

        bool ok = _pad.Vibration.Update(deltaSeconds);

        // A one-shot sequence that reaches its end leaves the animator finished but the frame loop should
        // not keep reporting "Playing" after there is nothing to play.
        if (State == HapticsState.Playing && _pad.Vibration.IsFinished)
        {
            State = HapticsState.Idle;
            _currentPreset = null;
            Announce("Pattern finished.");
        }

        return ok;
    }

    /// <summary>Returns the steps of <paramref name="preset"/> multiplied by <paramref name="strength"/>.</summary>
    public static IReadOnlyList<VibrationStep> ScaleSteps(IReadOnlyList<VibrationStep> steps, float strength)
    {
        ArgumentNullException.ThrowIfNull(steps);
        float clamped = Math.Clamp(strength, 0f, 1f);
        if (clamped >= 0.999f)
            return steps;

        var scaled = new List<VibrationStep>(steps.Count);
        foreach (VibrationStep step in steps)
        {
            VibrationLevels reduced = step.Levels.Scaled(clamped);
            scaled.Add(step.Fade
                ? VibrationStep.FadeTo(reduced, step.DurationSeconds)
                : VibrationStep.Hold(reduced, step.DurationSeconds));
        }
        return scaled;
    }

    private void Announce(string message) => Announced?.Invoke(message);
}
