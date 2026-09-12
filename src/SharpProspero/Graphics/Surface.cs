// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics;

/// <summary>
/// A 32-bit drawing surface over a mapped framebuffer. The surface holds a pointer to the pixels and
/// the geometry; it owns nothing and allocates nothing. All coordinates are in pixels with the origin
/// at the top-left. Drawing operations clip to the surface bounds. The row stride can exceed the
/// width when the framebuffer pitch is padded; addressing uses the stride while drawing clips to the
/// width.
/// </summary>
/// <remarks>Creates a surface whose rows are <paramref name="stride"/> pixels apart.</remarks>
/// <param name="pixels">Pointer to the framebuffer pixels.</param>
/// <param name="width">Width in pixels.</param>
/// <param name="height">Height in pixels.</param>
/// <param name="stride">Pixels from the start of one row to the next; at least <paramref name="width"/>.</param>
/// <param name="opaque">
/// Whether the pixels are an opaque display back buffer (true, the default) or an off-screen target
/// that keeps its own alpha channel (false). It only affects how a blend combines the alpha of what is
/// drawn with what is already there.
/// </param>
public readonly unsafe partial struct Surface(uint* pixels, int width, int height, int stride, bool opaque = true)
{
    private readonly uint* _pixels = pixels;

    // True for a display back buffer, whose alpha is always left fully opaque; false for an off-screen
    // target (a PixelBuffer) that carries a real alpha channel, so a blend must compute the resulting
    // alpha rather than force it opaque.
    private readonly bool _opaque = opaque;

    /// <summary>Creates a surface over <paramref name="pixels"/> whose rows are packed (stride equals width).</summary>
    /// <param name="pixels">Pointer to <paramref name="width"/> * <paramref name="height"/> packed pixels.</param>
    /// <param name="width">Width in pixels.</param>
    /// <param name="height">Height in pixels.</param>
    public Surface(uint* pixels, int width, int height)
        : this(pixels, width, height, width)
    {
    }

    /// <summary>Width in pixels.</summary>
    public int Width { get; } = width;

    /// <summary>Height in pixels.</summary>
    public int Height { get; } = height;

    /// <summary>Pixels from the start of one row to the start of the next.</summary>
    public int Stride { get; } = stride < width ? width : stride;

    /// <summary>Pointer to the first pixel.</summary>
    public uint* Pixels => _pixels;

    private Span<uint> Row(int y) => new(_pixels + (long)y * Stride, Width);

    /// <summary>Fills the whole surface with <paramref name="color"/>.</summary>
    public void Clear(Color color)
    {
        uint value = color.Value;
        if (Stride == Width)
        {
            new Span<uint>(_pixels, checked(Width * Height)).Fill(value);
            return;
        }
        for (int y = 0; y < Height; y++)
            Row(y).Fill(value);
    }

    /// <summary>Sets a single pixel, ignoring out-of-bounds coordinates.</summary>
    public void SetPixel(int x, int y, Color color)
    {
        if ((uint)x >= (uint)Width || (uint)y >= (uint)Height)
            return;
        _pixels[(long)y * Stride + x] = color.Value;
    }

    /// <summary>
    /// Blends the color in the low 24 bits of <paramref name="rgb"/> over the pixel at
    /// (<paramref name="x"/>, <paramref name="y"/>) by <paramref name="alpha"/> (0 leaves the pixel, 255
    /// replaces it). Out-of-bounds coordinates are ignored. This is the per-pixel form used to composite
    /// an antialiased coverage image, such as a glyph, in a chosen color.
    /// </summary>
    public void BlendPixel(int x, int y, uint rgb, byte alpha)
    {
        if ((uint)x >= (uint)Width || (uint)y >= (uint)Height)
            return;
        uint* pixel = _pixels + (long)y * Stride + x;
        *pixel = Blend(((uint)alpha << 24) | (rgb & 0x00FFFFFFu), *pixel);
    }

    /// <summary>Fills the rectangle at (<paramref name="x"/>, <paramref name="y"/>), clipped to bounds.</summary>
    public void FillRect(int x, int y, int width, int height, Color color)
    {
        int x0 = Math.Max(0, x);
        int y0 = Math.Max(0, y);
        int x1 = Math.Min(Width, x + width);
        int y1 = Math.Min(Height, y + height);
        if (x1 <= x0 || y1 <= y0)
            return;
        uint value = color.Value;
        int span = x1 - x0;
        for (int py = y0; py < y1; py++)
            new Span<uint>(_pixels + (long)py * Stride + x0, span).Fill(value);
    }

    /// <summary>Draws a horizontal run of <paramref name="length"/> pixels, clipped to bounds.</summary>
    public void HLine(int x, int y, int length, Color color)
        => FillRect(x, y, length, 1, color);

    /// <summary>Draws a vertical run of <paramref name="length"/> pixels, clipped to bounds.</summary>
    public void VLine(int x, int y, int length, Color color)
        => FillRect(x, y, 1, length, color);

    /// <summary>Draws a one-pixel line between the two points, clipped to bounds.</summary>
    public void DrawLine(int x0, int y0, int x1, int y1, Color color)
    {
        int dx = Math.Abs(x1 - x0);
        int dy = -Math.Abs(y1 - y0);
        int sx = x0 < x1 ? 1 : -1;
        int sy = y0 < y1 ? 1 : -1;
        int err = dx + dy;
        while (true)
        {
            SetPixel(x0, y0, color);
            if (x0 == x1 && y0 == y1)
                return;
            int e2 = 2 * err;
            if (e2 >= dy) { err += dy; x0 += sx; }
            if (e2 <= dx) { err += dx; y0 += sy; }
        }
    }

    /// <summary>Draws the one-pixel outline of a rectangle, clipped to bounds.</summary>
    public void DrawRect(int x, int y, int width, int height, Color color)
    {
        if (width <= 0 || height <= 0)
            return;
        HLine(x, y, width, color);
        HLine(x, y + height - 1, width, color);
        VLine(x, y, height, color);
        VLine(x + width - 1, y, height, color);
    }

    /// <summary>Fills a disc centered at (<paramref name="cx"/>, <paramref name="cy"/>), clipped to bounds.</summary>
    public void FillCircle(int cx, int cy, int radius, Color color)
    {
        if (radius < 0)
            return;
        for (int dy = -radius; dy <= radius; dy++)
        {
            int dx = (int)Math.Sqrt((double)radius * radius - (double)dy * dy);
            HLine(cx - dx, cy + dy, 2 * dx + 1, color);
        }
    }

    /// <summary>Draws the one-pixel outline of a circle, clipped to bounds.</summary>
    public void DrawCircle(int cx, int cy, int radius, Color color)
    {
        if (radius < 0)
            return;
        int x = radius, y = 0, err = 1 - radius;
        while (x >= y)
        {
            PlotOctants(cx, cy, x, y, color);
            y++;
            if (err < 0)
            {
                err += 2 * y + 1;
            }
            else
            {
                x--;
                err += 2 * (y - x) + 1;
            }
        }
    }

    private void PlotOctants(int cx, int cy, int x, int y, Color color)
    {
        SetPixel(cx + x, cy + y, color); SetPixel(cx - x, cy + y, color);
        SetPixel(cx + x, cy - y, color); SetPixel(cx - x, cy - y, color);
        SetPixel(cx + y, cy + x, color); SetPixel(cx - y, cy + x, color);
        SetPixel(cx + y, cy - x, color); SetPixel(cx - y, cy - x, color);
    }

    /// <summary>Copies <paramref name="source"/> onto this surface at (<paramref name="x"/>, <paramref name="y"/>), clipped to bounds.</summary>
    public void Blit(Surface source, int x, int y)
    {
        int sx0 = Math.Max(0, -x);
        int sy0 = Math.Max(0, -y);
        int w = Math.Min(source.Width - sx0, Width - (x + sx0));
        int h = Math.Min(source.Height - sy0, Height - (y + sy0));
        if (w <= 0 || h <= 0)
            return;
        for (int r = 0; r < h; r++)
        {
            var src = new ReadOnlySpan<uint>(source._pixels + (long)(sy0 + r) * source.Stride + sx0, w);
            var dst = new Span<uint>(_pixels + (long)(y + sy0 + r) * Stride + (x + sx0), w);
            src.CopyTo(dst);
        }
    }

    /// <summary>
    /// Copies <paramref name="source"/> onto this surface at (<paramref name="x"/>, <paramref name="y"/>),
    /// blending each source pixel over the destination by its alpha. Fully opaque pixels copy directly and
    /// fully transparent pixels are skipped, so an image with an alpha channel composites as a sprite.
    /// </summary>
    public void BlitBlended(Surface source, int x, int y)
    {
        int sx0 = Math.Max(0, -x);
        int sy0 = Math.Max(0, -y);
        int w = Math.Min(source.Width - sx0, Width - (x + sx0));
        int h = Math.Min(source.Height - sy0, Height - (y + sy0));
        if (w <= 0 || h <= 0)
            return;
        for (int r = 0; r < h; r++)
        {
            uint* src = source._pixels + (long)(sy0 + r) * source.Stride + sx0;
            uint* dst = _pixels + (long)(y + sy0 + r) * Stride + (x + sx0);
            for (int c = 0; c < w; c++)
                dst[c] = Blend(src[c], dst[c]);
        }
    }

    // Source-over compositing of one pixel. On an opaque back buffer the destination alpha stays 0xFF;
    // on an off-screen target that carries alpha the result alpha is a + dst_a*(1-a) and the colour is
    // un-premultiplied against it, so compositing into a transparent buffer and blitting that buffer
    // later gives the same picture as drawing straight onto the screen.
    private uint Blend(uint src, uint dst)
    {
        uint a = src >> 24;
        if (a == 0)
            return dst;

        if (_opaque)
        {
            if (a == 255)
                return src;
            uint na0 = 255 - a;
            uint sr0 = (src >> 16) & 0xFF, sg0 = (src >> 8) & 0xFF, sb0 = src & 0xFF;
            uint dr0 = (dst >> 16) & 0xFF, dg0 = (dst >> 8) & 0xFF, db0 = dst & 0xFF;
            uint rr0 = (sr0 * a + dr0 * na0 + 127) / 255;
            uint rg0 = (sg0 * a + dg0 * na0 + 127) / 255;
            uint rb0 = (sb0 * a + db0 * na0 + 127) / 255;
            return 0xFF000000u | (rr0 << 16) | (rg0 << 8) | rb0;
        }

        uint da = dst >> 24;
        // Nothing under the pixel, or a fully opaque source: the source colour and alpha carry straight.
        if (da == 0 || a == 255)
            return src;

        uint na = 255 - a;
        uint dw = (da * na + 127) / 255;   // the destination's contribution weight, da*(1-a)
        uint outA = a + dw;                // the resulting coverage
        if (outA == 0)
            return 0;
        uint sr = (src >> 16) & 0xFF, sg = (src >> 8) & 0xFF, sb = src & 0xFF;
        uint dr = (dst >> 16) & 0xFF, dg = (dst >> 8) & 0xFF, db = dst & 0xFF;
        uint rr = (sr * a + dr * dw + outA / 2) / outA;
        uint rg = (sg * a + dg * dw + outA / 2) / outA;
        uint rb = (sb * a + db * dw + outA / 2) / outA;
        return (outA << 24) | (rr << 16) | (rg << 8) | rb;
    }

    /// <summary>Draws one glyph at (<paramref name="x"/>, <paramref name="y"/>) scaled by <paramref name="scale"/>.</summary>
    public void DrawGlyph(char c, int x, int y, int scale, Color color)
    {
        ReadOnlySpan<byte> glyph = BitmapFont.GetGlyph(c);
        for (int row = 0; row < BitmapFont.GlyphSize; row++)
        {
            byte bits = glyph[row];
            // Fill a run of consecutive set bits with a single rectangle rather than one per pixel.
            for (int bit = 0; bit < BitmapFont.GlyphSize; bit++)
            {
                if ((bits & (1 << bit)) == 0)
                    continue;
                int start = bit;
                while (bit < BitmapFont.GlyphSize && (bits & (1 << bit)) != 0)
                    bit++;
                FillRect(x + start * scale, y + row * scale, (bit - start) * scale, scale, color);
            }
        }
    }

    /// <summary>Width, in pixels, that <paramref name="text"/> occupies at <paramref name="scale"/>.</summary>
    public static int MeasureText(ReadOnlySpan<char> text, int scale)
        => text.Length * BitmapFont.GlyphSize * scale;

    /// <summary>Draws <paramref name="text"/> starting at (<paramref name="x"/>, <paramref name="y"/>).</summary>
    public void DrawText(ReadOnlySpan<char> text, int x, int y, int scale, Color color)
    {
        int step = BitmapFont.GlyphSize * scale;
        foreach (char c in text)
        {
            DrawGlyph(c, x, y, scale, color);
            x += step;
        }
    }

    /// <summary>
    /// Draws <paramref name="text"/> at (<paramref name="x"/>, <paramref name="y"/>) but within
    /// <paramref name="maxWidth"/> pixels, ending it with a trailing "..." when the whole string will not
    /// fit. Nothing is drawn past <paramref name="x"/> + <paramref name="maxWidth"/>. A control uses this
    /// so a long string cannot spill across its edge into a neighbour.
    /// </summary>
    public void DrawTextClipped(ReadOnlySpan<char> text, int x, int y, int scale, Color color, int maxWidth)
    {
        if (maxWidth <= 0)
            return;
        int step = BitmapFont.GlyphSize * scale;
        if (text.Length * step <= maxWidth)
        {
            DrawText(text, x, y, scale, color);
            return;
        }

        int maxGlyphs = maxWidth / step;
        if (maxGlyphs <= 0)
            return;

        // Too narrow even for the text plus a marker: draw only the glyphs that fit.
        const int ellipsisGlyphs = 3;
        if (maxGlyphs <= ellipsisGlyphs)
        {
            int cx0 = x;
            for (int i = 0; i < maxGlyphs; i++)
            {
                DrawGlyph(text[i], cx0, y, scale, color);
                cx0 += step;
            }
            return;
        }

        int keep = maxGlyphs - ellipsisGlyphs;
        int cx = x;
        for (int i = 0; i < keep; i++)
        {
            DrawGlyph(text[i], cx, y, scale, color);
            cx += step;
        }
        for (int i = 0; i < ellipsisGlyphs; i++)
        {
            DrawGlyph('.', cx, y, scale, color);
            cx += step;
        }
    }

    /// <summary>Draws <paramref name="text"/> horizontally centered at vertical position <paramref name="y"/>.</summary>
    public void DrawTextCentered(ReadOnlySpan<char> text, int y, int scale, Color color)
    {
        int x = (Width - MeasureText(text, scale)) / 2;
        DrawText(text, x, y, scale, color);
    }

    /// <summary>
    /// Draws <paramref name="text"/> in <paramref name="fill"/> over a one-pixel outline in
    /// <paramref name="outline"/>, so it stays readable over a photo, a video frame, or any busy
    /// background. It costs several passes, so use it for overlay text rather than a whole screen of it.
    /// </summary>
    public void DrawTextOutlined(ReadOnlySpan<char> text, int x, int y, int scale, Color fill, Color outline)
    {
        for (int dy = -1; dy <= 1; dy++)
        {
            for (int dx = -1; dx <= 1; dx++)
            {
                if (dx != 0 || dy != 0)
                    DrawText(text, x + dx, y + dy, scale, outline);
            }
        }
        DrawText(text, x, y, scale, fill);
    }
}
