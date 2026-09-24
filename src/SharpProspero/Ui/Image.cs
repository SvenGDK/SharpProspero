// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A picture drawn from a <see cref="Surface"/>, for an image viewer or an icon. It draws the surface
/// at its top-left corner, optionally blending by alpha. Not focusable. The surface is a view over
/// pixels the caller owns, so keep those pixels (for example a decoded <c>PngImage</c>) alive while the
/// control is on screen.
/// </summary>
/// <remarks>
/// By default the picture draws at its source pixel size. Setting <see cref="MaxWidth"/> or
/// <see cref="MaxHeight"/> scales it down (aspect-preserving) so it fits, which is what a caller
/// wants for a large icon inside a right-hand details panel. Setting <see cref="FitToWidth"/>
/// scales the picture to the laid-out control width (again aspect-preserving), so the picture
/// fills a card whose width the parent decides.
/// </remarks>
/// <remarks>Creates an image control showing <paramref name="content"/>.</remarks>
/// <param name="content">The pixels to draw.</param>
/// <param name="blend">Whether to blend the source by its alpha (for a picture with transparency).</param>
public sealed unsafe class Image(Surface content, bool blend = false) : UiElement
{
    private Surface _content = content;

    /// <summary>Whether the picture is blended over the background by its alpha.</summary>
    public bool Blend { get; set; } = blend;

    /// <summary>
    /// The largest width the picture is drawn at, in pixels. Zero or negative means no cap; the
    /// picture keeps its own width. When set, the picture scales to fit both this cap and the
    /// laid-out width, aspect-preserving.
    /// </summary>
    public int MaxWidth { get; set; }

    /// <summary>
    /// The largest height the picture is drawn at, in pixels. Zero or negative means no cap; the
    /// picture keeps its own height. When set, the picture scales to fit both this cap and the
    /// laid-out width, aspect-preserving.
    /// </summary>
    public int MaxHeight { get; set; }

    /// <summary>
    /// When true, the picture scales to the laid-out width (aspect-preserving) instead of drawing
    /// at its own pixel width, so a large icon fills the column it sits in rather than overflowing
    /// or leaving a strip on the side.
    /// </summary>
    public bool FitToWidth { get; set; }

    /// <summary>Replaces the pictures's pixels.</summary>
    public void SetContent(Surface content) => _content = content;

    /// <summary>The source picture this control draws from.</summary>
    public Surface Content => _content;

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme)
    {
        if (_content.Width <= 0 || _content.Height <= 0)
            return 0;
        (int _, int drawHeight) = ResolveDrawSize(width);
        return drawHeight;
    }

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (_content.Width <= 0 || _content.Height <= 0)
            return;

        (int drawWidth, int drawHeight) = ResolveDrawSize(Bounds.Width);
        if (drawWidth <= 0 || drawHeight <= 0)
            return;

        // Centre the picture horizontally when the caller has laid out more width than the picture
        // needs, so an icon in a narrow column does not sit hard against the left edge.
        int drawX = Bounds.X + (Bounds.Width > drawWidth ? (Bounds.Width - drawWidth) / 2 : 0);
        int drawY = Bounds.Y;

        bool useScaled = drawWidth != _content.Width || drawHeight != _content.Height;
        if (Blend)
        {
            if (useScaled)
                surface.BlitScaledBlended(_content, drawX, drawY, drawWidth, drawHeight);
            else
                surface.BlitBlended(_content, drawX, drawY);
        }
        else
        {
            if (useScaled)
                surface.BlitScaled(_content, drawX, drawY, drawWidth, drawHeight);
            else
                surface.Blit(_content, drawX, drawY);
        }
    }

    // Resolves the width and height the picture draws at, given the laid-out width, honouring the
    // caps and the fit-to-width flag while preserving the source aspect ratio. A zero-sized source
    // reads as no picture at all and returns (0, 0).
    private (int Width, int Height) ResolveDrawSize(int availableWidth)
    {
        int srcW = _content.Width;
        int srcH = _content.Height;
        if (srcW <= 0 || srcH <= 0)
            return (0, 0);

        int limitW = availableWidth > 0 ? availableWidth : srcW;
        if (MaxWidth > 0 && MaxWidth < limitW)
            limitW = MaxWidth;

        int limitH = MaxHeight > 0 ? MaxHeight : int.MaxValue;

        int w = FitToWidth ? limitW : Math.Min(srcW, limitW);
        // Preserve aspect ratio: pick the smaller of the width-based and height-based scales so
        // both caps are honoured; then use that scaled width and height together.
        long widthScaled = (long)w;
        long heightAtWidth = widthScaled * srcH / srcW;
        if (heightAtWidth > limitH)
        {
            heightAtWidth = limitH;
            widthScaled = heightAtWidth * srcW / srcH;
        }
        return ((int)widthScaled, (int)heightAtWidth);
    }
}
