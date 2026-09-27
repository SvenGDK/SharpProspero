// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Input;
using SharpProspero.Interop.Pad;

namespace SharpProspero.Ui;

/// <summary>
/// One frame of navigation intent for the interface: the direction the user moved, whether they
/// confirmed or cancelled, and the scroll keys they used. Each field is edge-triggered, true only on
/// the frame the button becomes pressed, so holding a button moves once. Build it from two controller
/// samples with <see cref="From(GamePadState, GamePadState, float)"/> and hand it to
/// <see cref="UiScreen.Update"/>.
/// </summary>
/// <param name="Up">Move focus up (d-pad up pressed this frame).</param>
/// <param name="Down">Move focus down.</param>
/// <param name="Left">Move focus left.</param>
/// <param name="Right">Move focus right.</param>
/// <param name="Confirm">Activate the focused control (cross pressed this frame).</param>
/// <param name="Cancel">Go back (circle pressed this frame).</param>
public readonly record struct UiInput(bool Up, bool Down, bool Left, bool Right, bool Confirm, bool Cancel)
{
    /// <summary>No input this frame.</summary>
    public static UiInput None => default;

    /// <summary>Scroll the focused window one screenful upward (L1 pressed this frame).</summary>
    public bool PageUp { get; init; }

    /// <summary>Scroll the focused window one screenful downward (R1 pressed this frame).</summary>
    public bool PageDown { get; init; }

    /// <summary>Jump the focused window to its top (L2 pressed this frame).</summary>
    public bool Home { get; init; }

    /// <summary>Jump the focused window to its bottom (R2 pressed this frame).</summary>
    public bool End { get; init; }

    /// <summary>True when any of the four directions is set this frame.</summary>
    public bool HasDirection => Up || Down || Left || Right;

    /// <summary>The single direction this frame, or null when none (or more than one) is set.</summary>
    public UiDirection? Direction
    {
        get
        {
            int count = (Up ? 1 : 0) + (Down ? 1 : 0) + (Left ? 1 : 0) + (Right ? 1 : 0);
            if (count != 1)
                return null;
            if (Up) return UiDirection.Up;
            if (Down) return UiDirection.Down;
            if (Left) return UiDirection.Left;
            return UiDirection.Right;
        }
    }

    /// <summary>
    /// Reads the navigation intent from this frame's controller sample and the previous one, so each
    /// button counts once when it becomes pressed. The d-pad drives the four directions, cross confirms
    /// and circle cancels; the bumper and trigger buttons page and jump within a scrolling window. The
    /// left analog stick pulses the same four directions when it moves past
    /// <paramref name="stickThreshold"/> so a user who prefers the stick reaches every control the
    /// d-pad does.
    /// </summary>
    /// <param name="current">The controller sample taken this frame.</param>
    /// <param name="previous">The controller sample taken on the previous frame, used to edge-trigger.</param>
    /// <param name="stickThreshold">
    /// How far the stick must lean past its centre to fire a direction pulse, from 0 to 1. Below this
    /// the stick is treated as at rest, so a resting stick does not drift the focus around. Default
    /// 0.65 gives a firm push before firing.
    /// </param>
    public static UiInput From(GamePadState current, GamePadState previous, float stickThreshold = 0.65f)
    {
        bool Edge(ScePadButton button) => current.IsPressed(button) && !previous.IsPressed(button);

        (float curX, float curY) = current.LeftStick;
        (float prevX, float prevY) = previous.LeftStick;

        // A stick pulse fires when the stick crosses past the fire threshold, and to fire again the
        // stick must first return past the smaller release threshold. Without this hysteresis a hand
        // that jitters across the fire threshold on consecutive frames (say between -0.66 and -0.64
        // for a 0.65 threshold) re-arms the previous-frame test and fires a direction pulse on every
        // crossing. The release threshold sits at 70% of the fire threshold, so a small tremor
        // inside the deadzone never re-arms.
        float releaseThreshold = stickThreshold * 0.7f;
        bool stickUp = curY < -stickThreshold && prevY > -releaseThreshold;
        bool stickDown = curY > stickThreshold && prevY < releaseThreshold;
        bool stickLeft = curX < -stickThreshold && prevX > -releaseThreshold;
        bool stickRight = curX > stickThreshold && prevX < releaseThreshold;

        return new UiInput(
            Up: Edge(ScePadButton.Up) || stickUp,
            Down: Edge(ScePadButton.Down) || stickDown,
            Left: Edge(ScePadButton.Left) || stickLeft,
            Right: Edge(ScePadButton.Right) || stickRight,
            Confirm: Edge(ScePadButton.Cross),
            Cancel: Edge(ScePadButton.Circle))
        {
            PageUp = Edge(ScePadButton.L1),
            PageDown = Edge(ScePadButton.R1),
            Home = Edge(ScePadButton.L2),
            End = Edge(ScePadButton.R2),
        };
    }
}
