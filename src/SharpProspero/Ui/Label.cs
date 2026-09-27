// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;

namespace SharpProspero.Ui;

/// <summary>A line of text. Not focusable; use it for titles, headings and read-only values.</summary>
/// <remarks>Creates a label showing <paramref name="text"/>.</remarks>
public sealed class Label(string text = "") : UiElement
{
    private BitmapTextFont? _bitmap;

    /// <summary>The text to show.</summary>
    public string Text { get; set; } = text ?? "";

    /// <summary>The text color, or null to use the theme's text color (the default).</summary>
    public Color? TextColor { get; set; }

    /// <summary>
    /// A whole-number size for the built-in bitmap text, or -1 to use the theme font (the default).
    /// Ignored when <see cref="Font"/> is set.
    /// </summary>
    public int Scale { get; set; } = -1;

    /// <summary>An outline font for this label, overriding both <see cref="Scale"/> and the theme font.</summary>
    public ITextFont? Font { get; set; }

    /// <summary>Whether to center the text within the label's width.</summary>
    public bool Centered { get; set; }

    // The font this label draws with: an explicit Font wins; an explicit whole-number Scale keeps the
    // built-in text at that size; otherwise the theme's font is used.
    private ITextFont Resolve(UiTheme theme)
    {
        if (Font is not null)
            return Font;
        if (Scale >= 1)
        {
            if (_bitmap is null || _bitmap.Scale != Scale)
                _bitmap = new BitmapTextFont(Scale);
            return _bitmap;
        }
        return theme.Font;
    }

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme) => Resolve(theme).LineHeight;

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (Bounds.Width <= 0)
            return;
        ITextFont font = Resolve(theme);
        Color color = TextColor ?? theme.Text;
        int textWidth = font.MeasureText(Text);
        if (Centered && textWidth <= Bounds.Width)
        {
            font.DrawText(surface, Text, Bounds.X + (Bounds.Width - textWidth) / 2, Bounds.Y, color);
            return;
        }
        // Reading-start alignment: the label anchors to the visual left in LTR and to the
        // visual right in RTL so it reads in the same direction as the surrounding text. A
        // label wider than its bounds is truncated first so the anchor computation reflects
        // the drawn (not the source) width.
        string shown = TextLayout.Truncate(font, Text, Bounds.Width);
        int shownWidth = font.MeasureText(shown);
        int x = theme.IsRtl ? Bounds.Right - shownWidth : Bounds.X;
        font.DrawText(surface, shown, x, Bounds.Y, color);
    }
}
