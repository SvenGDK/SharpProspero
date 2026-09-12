// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A whole-number value adjusted with left and right within a range, for a setting such as a volume level
/// or a count. It shows the label and the current value between arrows, clamps to its bounds (it does not
/// wrap), and calls <see cref="Changed"/> with the new value. A <see cref="Format"/> function turns the
/// value into the shown text, so it can read as "50%" or "x3".
/// </summary>
public sealed class Stepper : UiElement
{
    private long _value;

    /// <summary>Creates a stepper labelled <paramref name="text"/> over <paramref name="min"/>..<paramref name="max"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="min"/> exceeds <paramref name="max"/>, or the step is not positive.</exception>
    public Stepper(string text, long value, long min, long max, long step = 1, Func<long, string>? format = null, Action<long>? changed = null)
    {
        if (min > max)
            throw new ArgumentException("The minimum must not exceed the maximum.", nameof(min));
        if (step <= 0)
            throw new ArgumentException("The step must be positive.", nameof(step));
        Text = text ?? "";
        Minimum = min;
        Maximum = max;
        Step = step;
        Format = format;
        Changed = changed;
        _value = Math.Clamp(value, min, max);
    }

    /// <summary>The label shown at the left.</summary>
    public string Text { get; set; }
    /// <summary>The smallest allowed value.</summary>
    public long Minimum { get; }
    /// <summary>The largest allowed value.</summary>
    public long Maximum { get; }
    /// <summary>How much one press moves the value.</summary>
    public long Step { get; }
    /// <summary>Turns the value into the text shown; the plain number when null.</summary>
    public Func<long, string>? Format { get; set; }
    /// <summary>Called with the new value each time it changes.</summary>
    public Action<long>? Changed { get; set; }

    /// <summary>The current value; setting it clamps to the range.</summary>
    public long Value
    {
        get => _value;
        set => _value = Math.Clamp(value, Minimum, Maximum);
    }

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

        // Drawn with characters the font has: it covers printable text only and folds anything else to
        // a blank, so both ends were drawn blank and there was no telling a value that can still move
        // from one that has reached its limit.
        string left = _value > Minimum ? "<" : " ";
        string right = _value < Maximum ? ">" : " ";
        string shown = left + " " + (Format?.Invoke(_value) ?? _value.ToString()) + " " + right;
        int width = theme.MeasureText(shown);
        int room = Bounds.Right - theme.Padding - (Bounds.X + theme.Padding + theme.MeasureText(Text) + theme.Padding);
        if (room > 0)
        {
            int shownWidth = width < room ? width : room;
            theme.DrawClipped(surface, shown, Bounds.Right - theme.Padding - shownWidth, textY, theme.Text, shownWidth);
        }
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Left)
        {
            Move(-Step);
            return true;
        }
        if (input.Right)
        {
            Move(Step);
            return true;
        }
        return false;
    }

    private void Move(long delta)
    {
        // Widen the sum so a value within one step of long's range cannot overflow before the clamp.
        long next = (long)Int128.Clamp((Int128)_value + delta, Minimum, Maximum);
        if (next == _value)
            return;
        _value = next;
        Changed?.Invoke(_value);
    }
}
