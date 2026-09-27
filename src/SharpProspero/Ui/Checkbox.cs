// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// An on/off setting the user toggles with the confirm button. It shows a mark when checked and calls
/// <see cref="Changed"/> with the new state each time it flips.
/// </summary>
/// <remarks>Creates a checkbox labelled <paramref name="text"/>, initially <paramref name="checked"/>.</remarks>
public sealed class Checkbox(string text, bool @checked = false, Action<bool>? changed = null) : UiElement
{

    /// <summary>The label shown next to the mark.</summary>
    public string Text { get; set; } = text ?? "";

    /// <summary>Whether the setting is on.</summary>
    public bool Checked { get; set; } = @checked;

    /// <summary>Called with the new state each time the setting is toggled.</summary>
    public Action<bool>? Changed { get; set; } = changed;

    /// <inheritdoc />
    public override bool IsFocusable => Visible;

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme) => theme.RowHeight;

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        surface.FillRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, isFocused ? theme.PanelFocused : theme.Panel);
        if (isFocused)
            surface.DrawRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, theme.Accent);
        int textY = CenterTextY(Bounds, theme);
        int room = Bounds.Width - (2 * theme.Padding);

        // The state indicator and the label draw separately so a label that overflows the row is
        // truncated on its own, leaving the mark intact on either side. A merged string would
        // let the trailing-ellipsis truncation strip the mark in RTL, where the indicator sits
        // at the reading-end of the concatenated line.
        string mark = Checked ? "[X]" : "[ ]";
        int markWidth = theme.MeasureText(mark);
        int markGap = theme.Padding / 2;
        int labelRoom = Math.Max(0, room - markWidth - markGap);
        if (theme.IsRtl)
        {
            // The mark sits on the reading-start side of the row (the visual right in RTL) and
            // the label runs to its left, keeping the mark under the eye that starts scanning.
            int markX = Bounds.Right - theme.Padding - markWidth;
            theme.DrawText(surface, mark, markX, textY, theme.Text);
            if (labelRoom > 0)
            {
                string shown = TextLayout.Truncate(theme.Font, Text, labelRoom);
                int shownWidth = theme.MeasureText(shown);
                theme.DrawText(surface, shown, markX - markGap - shownWidth, textY, theme.Text);
            }
        }
        else
        {
            theme.DrawText(surface, mark, Bounds.X + theme.Padding, textY, theme.Text);
            if (labelRoom > 0)
            {
                theme.DrawClipped(surface, Text, Bounds.X + theme.Padding + markWidth + markGap, textY, theme.Text, labelRoom);
            }
        }
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Confirm)
        {
            Checked = !Checked;
            Changed?.Invoke(Checked);
            return true;
        }
        return false;
    }
}
