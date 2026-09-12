// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// The colors and spacing the interface draws with. Pass one to a <see cref="UiScreen"/>, or use
/// <see cref="Default"/> for a dark theme. Every value has a sensible default, so override only what
/// you want to change with an object initializer.
/// </summary>
public sealed class UiTheme
{
    /// <summary>The color behind the whole screen.</summary>
    public Color Background { get; init; } = Color.FromRgb(22, 24, 30);

    /// <summary>The fill of a control that is not focused.</summary>
    public Color Panel { get; init; } = Color.FromRgb(38, 41, 51);

    /// <summary>The fill of the control that holds focus.</summary>
    public Color PanelFocused { get; init; } = Color.FromRgb(48, 78, 140);

    /// <summary>The outline drawn around the focused control.</summary>
    public Color Accent { get; init; } = Color.FromRgb(90, 160, 255);

    /// <summary>The color of ordinary text.</summary>
    public Color Text { get; init; } = Color.FromRgb(236, 238, 243);

    /// <summary>The color of secondary or disabled text.</summary>
    public Color TextMuted { get; init; } = Color.FromRgb(150, 156, 170);

    /// <summary>A thin separator or track color.</summary>
    public Color Border { get; init; } = Color.FromRgb(70, 74, 88);

    /// <summary>The scale the built-in bitmap text is drawn at (the 8-pixel font times this).</summary>
    public int TextScale { get; init; } = 2;

    /// <summary>The gap left inside a control before its text, and between stacked controls.</summary>
    public int Padding { get; init; } = 10;

    /// <summary>The vertical gap between stacked controls.</summary>
    public int Spacing { get; init; } = 6;

    private ITextFont? _font;

    /// <summary>
    /// The font every control measures and draws its text with. It defaults to the built-in bitmap text
    /// at <see cref="TextScale"/>, so an interface that sets nothing looks exactly as it did before; set
    /// a <c>SystemFont</c> or <c>TrueTypeFont</c> here for crisp antialiased text. The default is cached
    /// for the theme's life. The interface draws on one thread, so no locking is needed.
    /// </summary>
    public ITextFont Font
    {
        get => _font ??= new BitmapTextFont(TextScale);
        init => _font = value;
    }

    /// <summary>The width, in pixels, that <paramref name="text"/> occupies in the theme font.</summary>
    public int MeasureText(ReadOnlySpan<char> text) => Font.MeasureText(text);

    /// <summary>Draws <paramref name="text"/> at (<paramref name="x"/>, <paramref name="y"/>) in the theme font.</summary>
    public void DrawText(Surface surface, ReadOnlySpan<char> text, int x, int y, Color color)
        => Font.DrawText(surface, text, x, y, color);

    /// <summary>
    /// Draws <paramref name="text"/> at (<paramref name="x"/>, <paramref name="y"/>) but within
    /// <paramref name="maxWidth"/> pixels, shortening it with a trailing marker when it will not fit, so
    /// a control's text never spills past its edge.
    /// </summary>
    public void DrawClipped(Surface surface, string text, int x, int y, Color color, int maxWidth)
    {
        if (maxWidth <= 0)
            return;
        Font.DrawText(surface, TextLayout.Truncate(Font, text, maxWidth), x, y, color);
    }

    /// <summary>The height of one line of text in the theme font.</summary>
    public int LineHeight => Font.LineHeight;

    /// <summary>The height of a control that holds a single line of text, with padding above and below.</summary>
    public int RowHeight => LineHeight + Padding;

    /// <summary>A dark theme suitable for the console.</summary>
    public static UiTheme Default => new();
}
