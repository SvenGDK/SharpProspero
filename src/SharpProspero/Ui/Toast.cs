// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A short message that appears over whatever is on screen and fades out on its own — "Saved",
/// "Copied", "Nothing to do". It takes no focus and no layout space, so it is not part of the control
/// tree: drive it from the frame loop and draw it after the screen, so it sits on top.
/// </summary>
/// <remarks>
/// <see cref="Update"/> takes the seconds since the last frame, which <c>FrameContext</c> reports, and
/// <see cref="Draw"/> takes the surface being drawn to rather than a laid-out rectangle. Showing a
/// second message while one is up replaces it.
/// </remarks>
/// <example>
/// <code>
/// toast.Update(frame.DeltaSeconds);
/// screen.Render(surface);
/// toast.Draw(surface, theme);
/// </code>
/// </example>
public sealed class Toast
{
    private const float FadeSeconds = 0.4f;

    private string _message = "";
    private float _remaining;
    private float _total;

    /// <summary>How far in from the bottom edge the banner sits, in pixels. Default 48.</summary>
    public int BottomMargin { get; set; } = 48;

    /// <summary>Whether a message is currently showing.</summary>
    public bool IsVisible => _remaining > 0f;

    /// <summary>The message showing, or an empty string when none is.</summary>
    public string Message => IsVisible ? _message : "";

    /// <summary>
    /// Shows <paramref name="message"/> for <paramref name="seconds"/>, replacing anything already up.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="seconds"/> is not positive.</exception>
    public void Show(string message, float seconds = 3f)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(seconds);
        _message = message ?? "";
        _total = seconds;
        _remaining = seconds;
    }

    /// <summary>Takes the message down straight away.</summary>
    public void Hide() => _remaining = 0f;

    /// <summary>Advances by <paramref name="deltaSeconds"/>; the message goes when its time runs out.</summary>
    public void Update(float deltaSeconds)
    {
        if (_remaining <= 0f || !float.IsFinite(deltaSeconds) || deltaSeconds <= 0f)
            return;
        _remaining -= deltaSeconds;
        if (_remaining < 0f)
            _remaining = 0f;
    }

    /// <summary>
    /// How solid the banner is drawn, from 0 to 1. It is full for most of its time and fades over the
    /// last moment, so a message leaves quietly rather than vanishing.
    /// </summary>
    public float Opacity
    {
        get
        {
            if (_remaining <= 0f)
                return 0f;
            float fade = Math.Min(FadeSeconds, _total);
            return _remaining >= fade ? 1f : _remaining / fade;
        }
    }

    /// <summary>Draws the banner across the bottom of <paramref name="surface"/>, if one is showing.</summary>
    public void Draw(Surface surface, UiTheme theme)
    {
        ArgumentNullException.ThrowIfNull(theme);
        if (!IsVisible)
            return;

        int textWidth = theme.MeasureText(_message);
        int textHeight = theme.LineHeight;
        int width = Math.Min(surface.Width - (2 * theme.Padding), textWidth + (4 * theme.Padding));
        int height = textHeight + (2 * theme.Padding);
        int x = (surface.Width - width) / 2;
        int y = surface.Height - BottomMargin - height;
        if (width <= 0 || height <= 0)
            return;

        // The fade is applied by blending towards the background rather than by an alpha channel, since
        // the surface it is drawn over is opaque.
        float opacity = Opacity;
        Color panel = Color.Lerp(theme.Background, theme.Panel, opacity);
        Color border = Color.Lerp(theme.Background, theme.Border, opacity);
        Color text = Color.Lerp(theme.Background, theme.Text, opacity);

        surface.FillRoundedRect(x, y, width, height, theme.Padding, panel);
        surface.DrawRoundedRect(x, y, width, height, theme.Padding, border);

        theme.DrawText(
            surface,
            TextLayout.Truncate(theme.Font, _message, width - (2 * theme.Padding)),
            x + ((width - Math.Min(textWidth, width - (2 * theme.Padding))) / 2),
            y + theme.Padding,
            text);
    }
}
