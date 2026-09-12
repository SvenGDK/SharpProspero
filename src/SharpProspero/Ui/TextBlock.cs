// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;

namespace SharpProspero.Ui;

/// <summary>
/// A paragraph of text that wraps to the width it is given and grows as tall as it needs. Use it for a
/// description, a help note, or any message longer than the single line a <see cref="Label"/> draws.
/// Set <see cref="Font"/> to lay the text out with a loaded outline font instead of the built-in text.
/// </summary>
/// <remarks>Creates a block showing <paramref name="text"/>.</remarks>
/// <param name="text">The text to show; line breaks in it start a new line.</param>
public sealed class TextBlock(string text = "") : UiElement
{
    /// <summary>The text to show. Line breaks start a new line; the rest wraps to the width.</summary>
    public string Text { get; set; } = text ?? "";

    /// <summary>Where each line sits within the width. Default <see cref="TextAlignment.Left"/>.</summary>
    public TextAlignment Alignment { get; set; } = TextAlignment.Left;

    /// <summary>The text color, or null to use the theme's text color.</summary>
    public Color? TextColor { get; set; }

    /// <summary>The font to lay the text out with, or null to use the built-in text at the theme's scale.</summary>
    public ITextFont? Font { get; set; }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
        => TextLayout.MeasureWrapped(Resolve(theme), Text, width).Height;

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible)
            return;
        TextLayout.DrawWrapped(
            surface, Resolve(theme), Text, Bounds.X, Bounds.Y, Bounds.Width,
            TextColor ?? theme.Text, Alignment);
    }

    // An explicit font wins; otherwise the block draws with the theme's font.
    private ITextFont Resolve(UiTheme theme) => Font ?? theme.Font;
}
