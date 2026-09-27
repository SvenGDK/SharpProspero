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
    public long Minimum { get; private set; }
    /// <summary>The largest allowed value.</summary>
    public long Maximum { get; private set; }
    /// <summary>How much one press moves the value.</summary>
    public long Step { get; }
    /// <summary>Turns the value into the text shown; the plain number when null.</summary>
    public Func<long, string>? Format { get; set; }
    /// <summary>Called with the new value each time it changes.</summary>
    public Action<long>? Changed { get; set; }

    /// <summary>
    /// Widens or narrows the value range. The current value is clamped into the new range and, when the
    /// clamp moves it, <see cref="Changed"/> is raised so a caller mirroring the stepper hears the update.
    /// Use it to grow the editing range when the underlying data grows.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="min"/> exceeds <paramref name="max"/>.</exception>
    public void SetRange(long min, long max)
    {
        if (min > max)
            throw new ArgumentException("The minimum must not exceed the maximum.", nameof(min));
        Minimum = min;
        Maximum = max;
        long clamped = Math.Clamp(_value, min, max);
        if (clamped == _value)
            return;
        _value = clamped;
        Changed?.Invoke(_value);
    }

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

        bool rtl = theme.IsRtl;
        int textY = CenterTextY(Bounds, theme);
        int room = Bounds.Width - (2 * theme.Padding);

        // Truncate FIRST so the anchor computation reflects the drawn width — anchoring by the
        // full untruncated width would visually shift a truncated RTL label left off its right
        // anchor by the overflow amount.
        string labelShown = TextLayout.Truncate(theme.Font, Text, room);
        int labelWidth = theme.MeasureText(labelShown);

        // Label sits on the reading-start side; the value follows on the reading-end side. In RTL
        // the label moves to the visual right and the value block to the visual left so the pair
        // reads in the same order the surrounding paragraph does.
        int labelX = rtl ? Bounds.Right - theme.Padding - labelWidth : Bounds.X + theme.Padding;
        theme.DrawText(surface, labelShown, labelX, textY, theme.Text);

        // Drawn with characters the font has: it covers printable text only and folds anything else
        // to a blank, so both ends were drawn blank and there was no telling a value that can still
        // move from one that has reached its limit. The visual chevron on the "smaller side" is
        // "<" in LTR (values grow rightward, so smaller is to the left) and ">" in RTL (values
        // grow leftward, so smaller is to the right).
        bool canDecrement = _value > Minimum;
        bool canIncrement = _value < Maximum;
        string smallerChev = canDecrement ? (rtl ? ">" : "<") : " ";
        string largerChev = canIncrement ? (rtl ? "<" : ">") : " ";
        string leftChev = rtl ? largerChev : smallerChev;
        string rightChev = rtl ? smallerChev : largerChev;
        string shown = leftChev + " " + (Format?.Invoke(_value) ?? _value.ToString()) + " " + rightChev;
        int width = theme.MeasureText(shown);
        int valueRoom = rtl
            ? Bounds.Right - theme.Padding - labelWidth - theme.Padding - (Bounds.X + theme.Padding)
            : Bounds.Right - theme.Padding - (Bounds.X + theme.Padding + labelWidth + theme.Padding);
        if (valueRoom > 0)
        {
            int shownWidth = width < valueRoom ? width : valueRoom;
            int shownX = rtl ? Bounds.X + theme.Padding : Bounds.Right - theme.Padding - shownWidth;
            theme.DrawClipped(surface, shown, shownX, textY, theme.Text, shownWidth);
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
