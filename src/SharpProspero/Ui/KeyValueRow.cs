// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;

namespace SharpProspero.Ui;

/// <summary>
/// A row showing a name on the left and its value on the right. A column of these is the readable way
/// to present what a tool has found: system details, file properties, or the fields of a record. The
/// value is shortened with a trailing marker when the row is too narrow for it, so a long value never
/// runs into the name.
/// </summary>
/// <remarks>Creates a row showing <paramref name="name"/> and <paramref name="value"/>.</remarks>
/// <param name="name">The name shown on the left.</param>
/// <param name="value">The value shown on the right.</param>
public sealed class KeyValueRow(string name, string value = "") : UiElement
{
    /// <summary>The name shown on the left.</summary>
    public string Name { get; set; } = name ?? "";

    /// <summary>The value shown on the right.</summary>
    public string Value { get; set; } = value ?? "";

    /// <summary>The color of the name, or null to use the theme's muted text color.</summary>
    public Color? NameColor { get; set; }

    /// <summary>The color of the value, or null to use the theme's text color.</summary>
    public Color? ValueColor { get; set; }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme) => theme.RowHeight;

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible)
            return;

        ITextFont font = Resolve(theme);
        int y = Bounds.Y + ((Bounds.Height - font.LineHeight) / 2);
        int left = Bounds.X + theme.Padding;
        int right = Bounds.Right - theme.Padding;

        // The name keeps the room it needs; the value takes what is left, shortened to fit.
        int nameWidth = font.MeasureText(Name);
        font.DrawText(surface, Name, left, y, NameColor ?? theme.TextMuted);

        int available = right - (left + nameWidth + theme.Spacing);
        if (available <= 0)
            return;

        string shown = TextLayout.Truncate(font, Value, available);
        int valueWidth = font.MeasureText(shown);
        font.DrawText(surface, shown, right - valueWidth, y, ValueColor ?? theme.Text);
    }

    // Every row draws with the theme's font.
    private static ITextFont Resolve(UiTheme theme) => theme.Font;
}
