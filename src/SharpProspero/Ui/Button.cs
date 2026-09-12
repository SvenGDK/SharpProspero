// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A control the user activates with the confirm button. It highlights when focused and calls
/// <see cref="Activated"/> when confirmed. A disabled button cannot be focused or activated.
/// </summary>
/// <remarks>Creates a button labelled <paramref name="text"/> that calls <paramref name="activated"/> when confirmed.</remarks>
public sealed class Button(string text, Action? activated = null) : UiElement
{

    /// <summary>The button's label.</summary>
    public string Text { get; set; } = text ?? "";

    /// <summary>Called when the button is confirmed.</summary>
    public Action? Activated { get; set; } = activated;

    /// <summary>Whether the button can be focused and activated. Default true.</summary>
    public bool Enabled { get; set; } = true;

    /// <inheritdoc />
    public override bool IsFocusable => Visible && Enabled;

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme) => theme.RowHeight;

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        surface.FillRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, isFocused ? theme.PanelFocused : theme.Panel);
        if (isFocused)
            surface.DrawRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, theme.Accent);
        theme.DrawClipped(surface, Text, Bounds.X + theme.Padding, CenterTextY(Bounds, theme),
            Enabled ? theme.Text : theme.TextMuted, Bounds.Width - (2 * theme.Padding));
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Confirm && Enabled)
        {
            Activated?.Invoke();
            return true;
        }
        return false;
    }
}
