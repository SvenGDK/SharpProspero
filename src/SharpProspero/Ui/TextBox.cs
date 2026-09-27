// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A field that shows an editable piece of text. Pressing confirm raises <see cref="Activated"/>, where
/// the application opens the on-screen keyboard (<see cref="Platform.TextInputDialog"/>) and, on a
/// result, sets <see cref="Text"/>. Keeping the keyboard in the application rather than the control lets
/// a screen stay simple and testable.
/// </summary>
/// <example>
/// <code>
/// var name = new TextBox("Name", placeholder: "Enter your name");
/// // The application opens the on-screen keyboard and stores the result back on the field.
/// name.Activated = box => box.Text = ReadWithOnScreenKeyboard(box.Text);
/// </code>
/// </example>
/// <remarks>Creates a field labelled <paramref name="label"/> holding <paramref name="text"/>.</remarks>
public sealed class TextBox(string label, string text = "", string placeholder = "", Action<TextBox>? activated = null) : UiElement
{

    /// <summary>The label shown at the left.</summary>
    public string Label { get; set; } = label ?? "";

    /// <summary>The current text.</summary>
    public string Text { get; set; } = text ?? "";

    /// <summary>The hint shown, muted, when the text is empty.</summary>
    public string Placeholder { get; set; } = placeholder ?? "";

    /// <summary>Called when the field is activated, so the application can open the keyboard to edit it.</summary>
    public Action<TextBox>? Activated { get; set; } = activated;

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

        // Truncate FIRST so the anchor uses the drawn width — anchoring by the untruncated width
        // under RTL would visually shift an overflowing label left off its intended right edge.
        string labelShown = TextLayout.Truncate(theme.Font, Label, room);
        int labelWidth = theme.MeasureText(labelShown);

        // Label sits on the reading-start side (visual left in LTR, visual right in RTL); the
        // value follows on the reading-end side, shortened to whatever room is left so a long
        // path never overwrites the label or spills off the field.
        int labelX = rtl ? Bounds.Right - theme.Padding - labelWidth : Bounds.X + theme.Padding;
        theme.DrawText(surface, labelShown, labelX, textY, theme.Text);

        bool empty = string.IsNullOrEmpty(Text);
        string shown = empty ? Placeholder : Text;
        int shownWidth = theme.MeasureText(shown);
        int valueRoom = rtl
            ? (Bounds.Right - theme.Padding - labelWidth - theme.Spacing) - (Bounds.X + theme.Padding)
            : Bounds.Right - theme.Padding - (Bounds.X + theme.Padding + labelWidth + theme.Spacing);
        if (valueRoom > 0)
        {
            int drawWidth = shownWidth < valueRoom ? shownWidth : valueRoom;
            int drawX = rtl ? Bounds.X + theme.Padding : Bounds.Right - theme.Padding - drawWidth;
            theme.DrawClipped(surface, shown, drawX, textY,
                empty ? theme.TextMuted : theme.Text, drawWidth);
        }
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Confirm)
        {
            Activated?.Invoke(this);
            return true;
        }
        return false;
    }
}
