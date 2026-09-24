// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Input;
using SharpProspero.Interop.Pad;

namespace SharpProspero.Ui;

/// <summary>
/// Turns held controller directions into repeated moves, the way holding a key repeats it. Where
/// <see cref="UiInput.From(GamePadState, GamePadState, float)"/> reports each press once, this reports the first
/// press at once, then — while the direction is still held — again after a short wait and then at a
/// steady rate. Use it in place of <c>UiInput.From</c> so scrolling a long list or dragging a slider does
/// not need a press per step. Confirm, cancel and the scroll shortcuts are still reported once, so they
/// never repeat.
/// </summary>
/// <remarks>
/// Keep one per screen (it holds the hold timers between frames) and pass this frame's controller sample
/// and the time since the last frame. Call <see cref="Reset"/> when focus jumps somewhere new so a held
/// direction does not carry a repeat into it.
/// </remarks>
/// <example>
/// <code>
/// screen.Update(repeater.Update(context.Input, (float)context.DeltaSeconds));
/// </code>
/// </example>
public sealed class UiRepeater
{
    private bool _upHeld, _downHeld, _leftHeld, _rightHeld, _confirmHeld, _cancelHeld;
    private bool _pageUpHeld, _pageDownHeld, _homeHeld, _endHeld;
    private float _upTimer, _downTimer, _leftTimer, _rightTimer;

    /// <summary>How long a direction is held before the first repeat, in seconds. Default 0.4.</summary>
    public float InitialDelay { get; set; } = 0.4f;

    /// <summary>The time between repeats once they start, in seconds. Default 0.09.</summary>
    public float RepeatInterval { get; set; } = 0.09f;

    /// <summary>
    /// How far the left stick must lean past its centre before it counts as a held direction, from 0
    /// to 1. Below this the stick is treated as at rest, so a resting hand at a slight tilt does not
    /// drift the focus. Default 0.65 matches the edge-fire threshold in
    /// <see cref="UiInput.From(GamePadState, GamePadState, float)"/>.
    /// </summary>
    public float StickThreshold { get; set; } = 0.65f;

    /// <summary>
    /// Reads the navigation intent from this frame's controller sample, repeating held directions after
    /// <see cref="InitialDelay"/> and then every <see cref="RepeatInterval"/>. A direction is treated
    /// as held when either the d-pad button is pressed or the left analog stick is leaned past
    /// <see cref="StickThreshold"/>, so a stick-driven user gets the same repeat cadence as one holding
    /// the d-pad.
    /// </summary>
    public UiInput Update(GamePadState current, float deltaSeconds)
    {
        (float x, float y) = current.LeftStick;
        bool stickUp = y < -StickThreshold;
        bool stickDown = y > StickThreshold;
        bool stickLeft = x < -StickThreshold;
        bool stickRight = x > StickThreshold;

        bool up = Direction(current.IsPressed(ScePadButton.Up) || stickUp, ref _upHeld, ref _upTimer, deltaSeconds);
        bool down = Direction(current.IsPressed(ScePadButton.Down) || stickDown, ref _downHeld, ref _downTimer, deltaSeconds);
        bool left = Direction(current.IsPressed(ScePadButton.Left) || stickLeft, ref _leftHeld, ref _leftTimer, deltaSeconds);
        bool right = Direction(current.IsPressed(ScePadButton.Right) || stickRight, ref _rightHeld, ref _rightTimer, deltaSeconds);
        bool confirm = Edge(current.IsPressed(ScePadButton.Cross), ref _confirmHeld);
        bool cancel = Edge(current.IsPressed(ScePadButton.Circle), ref _cancelHeld);
        bool pageUp = Edge(current.IsPressed(ScePadButton.L1), ref _pageUpHeld);
        bool pageDown = Edge(current.IsPressed(ScePadButton.R1), ref _pageDownHeld);
        bool home = Edge(current.IsPressed(ScePadButton.L2), ref _homeHeld);
        bool end = Edge(current.IsPressed(ScePadButton.R2), ref _endHeld);
        return new UiInput(up, down, left, right, confirm, cancel)
        {
            PageUp = pageUp,
            PageDown = pageDown,
            Home = home,
            End = end,
        };
    }

    /// <summary>Forgets which buttons were held, so the next press starts fresh with no pending repeat.</summary>
    public void Reset()
    {
        _upHeld = _downHeld = _leftHeld = _rightHeld = _confirmHeld = _cancelHeld = false;
        _pageUpHeld = _pageDownHeld = _homeHeld = _endHeld = false;
        _upTimer = _downTimer = _leftTimer = _rightTimer = 0f;
    }

    // Fires on the frame the direction is first pressed, then once the initial delay has passed while it
    // is still held, then every interval after that. At most one repeat is reported per frame.
    private bool Direction(bool held, ref bool wasHeld, ref float timer, float deltaSeconds)
    {
        bool fire = false;
        if (held)
        {
            if (!wasHeld)
            {
                fire = true;
                timer = InitialDelay;
            }
            else if (deltaSeconds > 0f)
            {
                timer -= deltaSeconds;
                if (timer <= 0f)
                {
                    fire = true;
                    timer += RepeatInterval;
                }
            }
        }
        wasHeld = held;
        return fire;
    }

    // Confirm, cancel and the scroll shortcuts fire only as the button becomes pressed, so they are
    // never repeated.
    private static bool Edge(bool held, ref bool wasHeld)
    {
        bool fire = held && !wasHeld;
        wasHeld = held;
        return fire;
    }
}
