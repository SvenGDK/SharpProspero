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

    /// <summary>The current value.</summary>
    public float Value { get; set; }

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

        int textY = CenterTextY(Bounds, theme);
        theme.DrawClipped(surface, Text, Bounds.X + theme.Padding, textY, theme.Text, Bounds.Width - (2 * theme.Padding));

        string valueText = Value.ToString("0.##");
        int valueWidth = theme.MeasureText(valueText);
        int valueShown = valueWidth < (Bounds.Width - (2 * theme.Padding)) ? valueWidth : Bounds.Width - (2 * theme.Padding);
        theme.DrawClipped(surface, valueText, Bounds.Right - theme.Padding - valueShown, textY, theme.Text, valueShown);

        int labelWidth = theme.MeasureText(Text);
        int trackX0 = Bounds.X + theme.Padding + labelWidth + theme.Padding;
        int trackX1 = Bounds.X + Bounds.Width - theme.Padding * 2 - valueWidth;
        int trackY = Bounds.Y + Bounds.Height / 2;
        if (trackX1 > trackX0)
        {
            int trackWidth = trackX1 - trackX0;
            float fraction = Maximum > Minimum ? (Value - Minimum) / (Maximum - Minimum) : 0f;
            int fill = (int)(trackWidth * fraction);
            surface.FillRect(trackX0, trackY - 2, trackWidth, 4, theme.Border);
            surface.FillRect(trackX0, trackY - 2, fill, 4, theme.Accent);
            surface.FillCircle(trackX0 + fill, trackY, 6, isFocused ? theme.Accent : theme.Text);
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
