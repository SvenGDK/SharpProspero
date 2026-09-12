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
        string line = (Checked ? "[X] " : "[ ] ") + Text;
        theme.DrawClipped(surface, line, Bounds.X + theme.Padding, CenterTextY(Bounds, theme), theme.Text, Bounds.Width - (2 * theme.Padding));
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
