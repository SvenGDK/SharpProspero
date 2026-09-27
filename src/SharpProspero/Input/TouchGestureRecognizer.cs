// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;
using System.Numerics;

namespace SharpProspero.Input;

/// <summary>The kind of touch-pad gesture a <see cref="TouchGestureRecognizer"/> recognizes.</summary>
public enum TouchGestureKind
{
    /// <summary>A quick touch that does not move.</summary>
    Tap,
    /// <summary>A second tap soon after the first, in the same place.</summary>
    DoubleTap,
    /// <summary>A single contact held still past the hold time.</summary>
    Hold,
    /// <summary>A single contact moving across the pad. Raised each frame it moves.</summary>
    Drag,
    /// <summary>A fast drag released with speed, carrying its velocity.</summary>
    Flick,
    /// <summary>Two contacts moving together: the scale and rotation relative to where they started.</summary>
    Pinch,
}

/// <summary>
/// A recognized gesture. <see cref="Position"/> is the point (or the midpoint for two contacts) on the
/// touch pad. <see cref="Delta"/> is the movement for a drag, or the velocity in units per second for a
/// flick. <see cref="Scale"/> and <see cref="Rotation"/> carry the two-finger pinch scale (1 is no change)
/// and rotation in radians.
/// </summary>
public readonly record struct TouchGesture(TouchGestureKind Kind, Vector2 Position, Vector2 Delta, float Scale, float Rotation);

/// <summary>
/// Turns a stream of touch-pad samples into gestures - tap, double tap, hold, drag, flick and a two-finger
/// pinch-and-rotate - without a system module. Feed it each frame's <see cref="GamePadState"/> and it
/// returns the gestures that completed or advanced this frame. The thresholds are in touch-pad units and
/// milliseconds and can be tuned.
/// </summary>
public sealed class TouchGestureRecognizer
{
    /// <summary>The farthest a contact may move and still count as a tap, in touch-pad units.</summary>
    public int TapMovementLimit { get; set; } = 40;

    /// <summary>The longest a tap may last, in milliseconds.</summary>
    public long TapDurationLimit { get; set; } = 300;

    /// <summary>How long a still contact must be held to raise a hold, in milliseconds.</summary>
    public long HoldDuration { get; set; } = 500;

    /// <summary>The longest gap between the taps of a double tap, in milliseconds.</summary>
    public long DoubleTapGap { get; set; } = 300;

    /// <summary>The least release speed for a drag to become a flick, in units per second.</summary>
    public float FlickSpeed { get; set; } = 1500f;

    // The active single contact, tracked by its identifier.
    private bool _active;
    private byte _id;
    private Vector2 _start, _last, _prev;
    private ulong _startTime, _lastTime, _prevTime;
    private bool _moved, _held;
    private bool _hasTap;
    private ulong _lastTapTime;
    private Vector2 _lastTapPos;

    // The two-finger baseline.
    private bool _twoActive;
    private float _startDistance, _startAngle;

    /// <summary>Clears all in-progress tracking.</summary>
    public void Reset()
    {
        _active = false;
        _twoActive = false;
        _held = false;
        _moved = false;
        _hasTap = false;
    }

    /// <summary>Processes one frame and returns the gestures recognized during it.</summary>
    public IReadOnlyList<TouchGesture> Update(in GamePadState state)
    {
        var gestures = new List<TouchGesture>();
        ulong time = state.TimestampMicroseconds;

        // A sample the system intercepted (PS button opened the quick menu, another module has
        // the pad) arrives as GamePadState.Neutral: time == 0 and no active touches, while a
        // previous frame's touch is still in progress on the recognizer. Running the release
        // branch on that would treat the still-held contact as if it were lifted and emit a
        // spurious Tap or DoubleTap. Drop the in-progress tracking without emitting anything so
        // the recognizer resumes cleanly when real samples return. A legitimate first sample at
        // time==0 with an active touch enters the "contact began" branch below unchanged.
        bool suddenNeutralDuringTouch = time == 0
            && state.TouchCount == 0
            && !state.Touch1.IsActive
            && !state.Touch2.IsActive
            && (_active || _twoActive);
        if (suddenNeutralDuringTouch)
        {
            _active = false;
            _twoActive = false;
            _moved = false;
            _held = false;
            _hasTap = false;
            return gestures;
        }

        if (state.TouchCount >= 2 && state.Touch1.IsActive && state.Touch2.IsActive)
        {
            _active = false; // a single-contact gesture does not carry through a two-finger phase
            _held = false;
            _hasTap = false; // a two-finger gesture breaks any pending double tap
            var a = new Vector2(state.Touch1.X, state.Touch1.Y);
            var b = new Vector2(state.Touch2.X, state.Touch2.Y);
            float distance = Vector2.Distance(a, b);
            float angle = MathF.Atan2(b.Y - a.Y, b.X - a.X);
            if (!_twoActive)
            {
                _twoActive = true;
                _startDistance = distance > 1e-3f ? distance : 1e-3f;
                _startAngle = angle;
            }
            else
            {
                float scale = distance / _startDistance;
                float rotation = WrapAngle(angle - _startAngle);
                gestures.Add(new TouchGesture(TouchGestureKind.Pinch, (a + b) * 0.5f, Vector2.Zero, scale, rotation));
            }
            return gestures;
        }
        _twoActive = false;

        TouchPoint touch = state.Touch1.IsActive ? state.Touch1 : state.Touch2;
        bool oneActive = state.TouchCount >= 1 && touch.IsActive;

        if (oneActive && (!_active || touch.Id != _id))
        {
            // A contact began (or a new finger replaced the last).
            _active = true;
            _id = touch.Id;
            _start = _last = _prev = new Vector2(touch.X, touch.Y);
            _startTime = _lastTime = _prevTime = time;
            _moved = false;
            _held = false;
        }
        else if (oneActive)
        {
            var position = new Vector2(touch.X, touch.Y);
            _prev = _last;
            _prevTime = _lastTime;
            _last = position;
            _lastTime = time;
            if (Vector2.Distance(position, _start) > TapMovementLimit)
            {
                _moved = true;
                _hasTap = false; // a drag (and any flick it becomes) breaks a pending double tap
            }
            if (_moved)
                gestures.Add(new TouchGesture(TouchGestureKind.Drag, position, position - _prev, 1f, 0f));
            else if (!_held && DurationMs(_startTime, time) >= HoldDuration)
            {
                _held = true;
                _hasTap = false; // a hold breaks a pending double tap
                gestures.Add(new TouchGesture(TouchGestureKind.Hold, position, Vector2.Zero, 1f, 0f));
            }
        }
        else if (_active)
        {
            // The contact ended.
            _active = false;
            long duration = DurationMs(_startTime, time);
            if (_moved)
            {
                float dt = (_lastTime - _prevTime) / 1_000_000f;
                if (dt > 0)
                {
                    Vector2 velocity = (_last - _prev) / dt;
                    if (velocity.Length() >= FlickSpeed)
                        gestures.Add(new TouchGesture(TouchGestureKind.Flick, _last, velocity, 1f, 0f));
                }
            }
            else if (!_held && duration <= TapDurationLimit)
            {
                bool isDouble = _hasTap
                    && DurationMs(_lastTapTime, time) <= DoubleTapGap
                    && Vector2.Distance(_start, _lastTapPos) <= TapMovementLimit;
                gestures.Add(new TouchGesture(isDouble ? TouchGestureKind.DoubleTap : TouchGestureKind.Tap, _start, Vector2.Zero, 1f, 0f));
                _hasTap = !isDouble; // a completed double tap does not seed a third
                _lastTapTime = time;
                _lastTapPos = _start;
            }
        }
        return gestures;
    }

    private static long DurationMs(ulong from, ulong to) => to >= from ? (long)((to - from) / 1000) : 0;

    private static float WrapAngle(float radians)
    {
        while (radians > MathF.PI) radians -= 2 * MathF.PI;
        while (radians < -MathF.PI) radians += 2 * MathF.PI;
        return radians;
    }
}
