// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics;

/// <summary>
/// Measures and draws a run of text. Both the built-in bitmap text and a loaded outline font present
/// this, so text layout and the interface controls work the same whichever one an application chooses.
/// </summary>
public interface ITextFont
{
    /// <summary>The distance, in pixels, from one line of text to the next.</summary>
    int LineHeight { get; }

    /// <summary>The width, in pixels, that <paramref name="text"/> occupies on one line.</summary>
    int MeasureText(ReadOnlySpan<char> text);

    /// <summary>
    /// Draws <paramref name="text"/> onto <paramref name="surface"/> in <paramref name="color"/>, with
    /// (<paramref name="x"/>, <paramref name="y"/>) at the top-left of the line.
    /// </summary>
    void DrawText(Surface surface, ReadOnlySpan<char> text, int x, int y, Color color);

    /// <summary>
    /// Whether the font has a renderable glyph for <paramref name="codepoint"/>. Used by a font
    /// cascade to decide whether to route the codepoint to this tier or fall through to the next.
    /// The default returns true so existing font implementations keep working; a tier that knows
    /// its coverage (a bitmap font with a fixed range, a system font backed by libSceFont)
    /// overrides this to report accurately.
    /// </summary>
    bool HasGlyph(int codepoint) => true;
}

/// <summary>
/// The built-in fixed-width text as an <see cref="ITextFont"/>, drawn at a whole-number scale. This
/// needs no font file and no system module, so it is the ready-to-use choice for a tool or an overlay.
/// </summary>
/// <remarks>Creates a font that draws the built-in glyphs at <paramref name="scale"/> times their size.</remarks>
/// <param name="scale">Whole-number magnification; values below one are treated as one.</param>
public sealed class BitmapTextFont(int scale = 1) : ITextFont
{
    /// <summary>The magnification applied to the built-in glyphs.</summary>
    public int Scale { get; } = scale < 1 ? 1 : scale;

    /// <inheritdoc/>
    public int LineHeight => BitmapFont.GlyphSize * Scale;

    /// <inheritdoc/>
    public int MeasureText(ReadOnlySpan<char> text) => Surface.MeasureText(text, Scale);

    /// <inheritdoc/>
    public void DrawText(Surface surface, ReadOnlySpan<char> text, int x, int y, Color color)
        => surface.DrawText(text, x, y, Scale, color);

    /// <inheritdoc/>
    public bool HasGlyph(int codepoint)
        => codepoint >= BitmapFont.FirstChar && codepoint <= BitmapFont.LastChar;
}
