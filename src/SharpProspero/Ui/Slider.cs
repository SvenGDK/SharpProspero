// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A value the user adjusts with left and right, between a minimum and a maximum. It shows a track with
/// the current position and the value, and calls <see cref="Changed"/> with the new value each time it
/// moves. Up and down are left unused, so focus moves to a neighbor from either end.
/// </summary>
public sealed class Slider : UiElement
{
    /// <summary>Creates a slider labelled <paramref name="text"/> over the range and step given.</summary>
    public Slider(string text, float minimum, float maximum, float value, float step, Action<float>? changed = null)
    {
        Text = text ?? "";
        Minimum = minimum;
        Maximum = Math.Max(minimum, maximum);
        Step = step > 0 ? step : 1f;
        Value = Math.Clamp(value, Minimum, Maximum);
        Changed = changed;
    }

    /// <summary>The label shown at the left.</summary>
    public string Text { get; set; }

    /// <summary>The lowest value.</summary>
    public float Minimum { get; }

    /// <summary>The highest value.</summary>
    public float Maximum { get; }

    /// <summary>How far each press moves the value.</summary>
    public float Step { get; }

    private float _value;

    /// <summary>The current value, clamped to <see cref="Minimum"/>..<see cref="Maximum"/>.</summary>
    public float Value
    {
        get => _value;
        set => _value = Math.Clamp(value, Minimum, Maximum);
    }

    /// <summary>Called with the new value each time it moves.</summary>
    public Action<float>? Changed { get; set; }

    /// <inheritdoc />
    public override bool IsFocusable => Visible;

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        surface.FillRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, isFocused ? theme.PanelFocused : theme.Panel);
        if (isFocused)
            surface.DrawRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, theme.Accent);

        bool rtl = theme.IsRtl;
        int textY = CenterTextY(Bounds, theme);
        string valueText = Value.ToString("0.##");
        int valueWidth = theme.MeasureText(valueText);
        int room = Bounds.Width - (2 * theme.Padding);
        int valueShown = valueWidth < room ? valueWidth : room;

        // Truncate the label FIRST, then anchor by the truncated width — otherwise an overflowing
        // localized label under RTL would anchor at Bounds.Right - Padding - untruncatedWidth
        // and the drawn (shorter) string would visually shift left away from the intended right
        // anchor.
        string labelShown = TextLayout.Truncate(theme.Font, Text, room);
        int labelWidth = theme.MeasureText(labelShown);

        // Label sits on the reading-start side of the row; the value floats to the reading-end
        // side. In RTL that swaps so the label is on the visual right and the value on the
        // visual left, keeping the label under the eye that starts scanning.
        int labelX = rtl ? Bounds.Right - theme.Padding - labelWidth : Bounds.X + theme.Padding;
        int valueX = rtl ? Bounds.X + theme.Padding : Bounds.Right - theme.Padding - valueShown;
        theme.DrawText(surface, labelShown, labelX, textY, theme.Text);
        theme.DrawClipped(surface, valueText, valueX, textY, theme.Text, valueShown);

        int trackX0, trackX1;
        if (rtl)
        {
            // Value is on the visual left, label on the visual right, so the track spans between
            // them.
            trackX0 = Bounds.X + theme.Padding + valueWidth + theme.Padding;
            trackX1 = Bounds.Right - theme.Padding - labelWidth - theme.Padding;
        }
        else
        {
            trackX0 = Bounds.X + theme.Padding + labelWidth + theme.Padding;
            trackX1 = Bounds.Right - theme.Padding * 2 - valueWidth;
        }
        int trackY = Bounds.Y + Bounds.Height / 2;
        if (trackX1 > trackX0)
        {
            int trackWidth = trackX1 - trackX0;
            float fraction = Maximum > Minimum ? (Value - Minimum) / (Maximum - Minimum) : 0f;
            int fill = (int)(trackWidth * fraction);
            surface.FillRect(trackX0, trackY - 2, trackWidth, 4, theme.Border);
            // The fill grows from the reading-start end of the track (the left in LTR, the right
            // in RTL), so a full slider reads as "all the way there" no matter the direction.
            int fillX = rtl ? trackX1 - fill : trackX0;
            surface.FillRect(fillX, trackY - 2, fill, 4, theme.Accent);
            int knobX = rtl ? trackX1 - fill : trackX0 + fill;
            surface.FillCircle(knobX, trackY, 6, isFocused ? theme.Accent : theme.Text);
        }
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Left)
        {
            Adjust(-Step);
            return true;
        }
        if (input.Right)
        {
            Adjust(Step);
            return true;
        }
        return false;
    }

    private void Adjust(float delta)
    {
        float next = Math.Clamp(Value + delta, Minimum, Maximum);
        if (next == Value)
            return;
        Value = next;
        Changed?.Invoke(Value);
    }
}
