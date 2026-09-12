// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics;

/// <summary>
/// Extended drawing: gradients, rounded rectangles, thick lines, filled triangles and polygons, scaled
/// and rotated image copies, and sub-region views. Every operation clips to the surface bounds.
/// </summary>
public readonly unsafe partial struct Surface
{
    /// <summary>
    /// A view over a rectangular sub-region of this surface, clamped to bounds. The view shares the same
    /// pixels; drawing on it clips to the region, so it acts as a clip rectangle or a panel to draw
    /// inside. Its origin is the region's top-left.
    /// </summary>
    public Surface Region(int x, int y, int width, int height)
    {
        int x0 = Math.Clamp(x, 0, Width);
        int y0 = Math.Clamp(y, 0, Height);
        // Combine origin and extent in 64-bit so an extreme width or height cannot wrap the sum negative
        // and collapse the view to nothing instead of clamping it to the surface edge.
        int x1 = (int)Math.Clamp((long)x + width, x0, Width);
        int y1 = (int)Math.Clamp((long)y + height, y0, Height);
        // The view keeps the parent's alpha behaviour so a blend into a sub-region of an off-screen
        // target composites the same way as a blend into the whole target.
        return new Surface(_pixels + (long)y0 * Stride + x0, x1 - x0, y1 - y0, Stride, _opaque);
    }

    /// <summary>Fills a rectangle with a top-to-bottom gradient from <paramref name="top"/> to <paramref name="bottom"/>.</summary>
    public void FillVerticalGradient(int x, int y, int width, int height, Color top, Color bottom)
    {
        if (width <= 0 || height <= 0)
            return;
        for (int row = 0; row < height; row++)
        {
            float t = height == 1 ? 0f : (float)row / (height - 1);
            FillRect(x, y + row, width, 1, Color.Lerp(top, bottom, t));
        }
    }

    /// <summary>Fills a rectangle with a left-to-right gradient from <paramref name="left"/> to <paramref name="right"/>.</summary>
    public void FillHorizontalGradient(int x, int y, int width, int height, Color left, Color right)
    {
        if (width <= 0 || height <= 0)
            return;
        for (int col = 0; col < width; col++)
        {
            float t = width == 1 ? 0f : (float)col / (width - 1);
            FillRect(x + col, y, 1, height, Color.Lerp(left, right, t));
        }
    }

    /// <summary>
    /// Fills a rectangle with a radial gradient from <paramref name="center"/> at the middle out to
    /// <paramref name="edge"/> at the farthest corner. Use it for a soft background, a spotlight, or a
    /// vignette (a light centre with a darker edge). Every pixel is computed, so it is a fill rather than
    /// a per-frame effect on a large area.
    /// </summary>
    public void FillRadialGradient(int x, int y, int width, int height, Color center, Color edge)
    {
        if (width <= 0 || height <= 0)
            return;
        float cx = x + (width / 2f), cy = y + (height / 2f);
        float maxDist = MathF.Sqrt(((float)width * width) + ((float)height * height)) / 2f;
        if (maxDist < 1e-3f)
            maxDist = 1f;

        int x0 = Math.Max(0, x), y0 = Math.Max(0, y);
        // Combine in 64-bit so an extreme width or height cannot wrap the clip rectangle negative.
        int x1 = (int)Math.Min((long)Width, (long)x + width), y1 = (int)Math.Min((long)Height, (long)y + height);
        for (int py = y0; py < y1; py++)
        {
            uint* dstRow = _pixels + (long)py * Stride;
            float dy = py + 0.5f - cy;
            for (int px = x0; px < x1; px++)
            {
                float dx = px + 0.5f - cx;
                float t = MathF.Sqrt((dx * dx) + (dy * dy)) / maxDist;
                dstRow[px] = Color.Lerp(center, edge, t).Value;
            }
        }
    }

    /// <summary>Fills a rectangle with rounded corners of the given <paramref name="radius"/>.</summary>
    public void FillRoundedRect(int x, int y, int width, int height, int radius, Color color)
    {
        if (width <= 0 || height <= 0)
            return;
        int r = Math.Clamp(radius, 0, Math.Min(width, height) / 2);
        if (r == 0)
        {
            FillRect(x, y, width, height, color);
            return;
        }

        // The straight middle band spans the full width; the top and bottom bands are inset by the
        // corner arc so the corners are rounded.
        FillRect(x, y + r, width, height - 2 * r, color);
        for (int dy = 0; dy < r; dy++)
        {
            int inset = r - (int)(Math.Sqrt((double)r * r - (double)(r - dy) * (r - dy)) + 0.5);
            FillRect(x + inset, y + dy, width - 2 * inset, 1, color);
            FillRect(x + inset, y + height - 1 - dy, width - 2 * inset, 1, color);
        }
    }

    /// <summary>Draws the one-pixel outline of a rounded rectangle.</summary>
    public void DrawRoundedRect(int x, int y, int width, int height, int radius, Color color)
    {
        if (width <= 0 || height <= 0)
            return;
        int r = Math.Clamp(radius, 0, Math.Min(width, height) / 2);
        if (r == 0)
        {
            DrawRect(x, y, width, height, color);
            return;
        }

        HLine(x + r, y, width - 2 * r, color);
        HLine(x + r, y + height - 1, width - 2 * r, color);
        VLine(x, y + r, height - 2 * r, color);
        VLine(x + width - 1, y + r, height - 2 * r, color);

        int cxL = x + r, cxR = x + width - 1 - r, cyT = y + r, cyB = y + height - 1 - r;
        int px = r, py = 0, err = 1 - r;
        while (px >= py)
        {
            SetPixel(cxR + px, cyB + py, color); SetPixel(cxL - px, cyB + py, color);
            SetPixel(cxR + px, cyT - py, color); SetPixel(cxL - px, cyT - py, color);
            SetPixel(cxR + py, cyB + px, color); SetPixel(cxL - py, cyB + px, color);
            SetPixel(cxR + py, cyT - px, color); SetPixel(cxL - py, cyT - px, color);
            py++;
            if (err < 0)
                err += 2 * py + 1;
            else { px--; err += 2 * (py - px) + 1; }
        }
    }

    /// <summary>Draws a line of the given <paramref name="thickness"/> in pixels between the two points.</summary>
    public void DrawLine(int x0, int y0, int x1, int y1, Color color, int thickness)
    {
        if (thickness <= 1)
        {
            DrawLine(x0, y0, x1, y1, color);
            return;
        }
        float dx = x1 - x0, dy = y1 - y0;
        float length = MathF.Sqrt(dx * dx + dy * dy);
        if (length < 1e-3f)
        {
            FillCircle(x0, y0, thickness / 2, color);
            return;
        }
        // Fill the line as a quad: offset each endpoint by the half-thickness along the line's normal.
        float nx = -dy / length, ny = dx / length;
        float h = thickness / 2f;
        int ax = (int)(x0 + nx * h), ay = (int)(y0 + ny * h);
        int bx = (int)(x0 - nx * h), by = (int)(y0 - ny * h);
        int cx = (int)(x1 - nx * h), cy = (int)(y1 - ny * h);
        int dx2 = (int)(x1 + nx * h), dy2 = (int)(y1 + ny * h);
        FillTriangle(ax, ay, bx, by, cx, cy, color);
        FillTriangle(ax, ay, cx, cy, dx2, dy2, color);
    }

    /// <summary>Fills the triangle with the given vertices.</summary>
    public void FillTriangle(int x0, int y0, int x1, int y1, int x2, int y2, Color color)
    {
        // Sort the vertices by ascending y so the fill splits into a flat-bottom and a flat-top half.
        if (y1 < y0) { (x0, y0, x1, y1) = (x1, y1, x0, y0); }
        if (y2 < y0) { (x0, y0, x2, y2) = (x2, y2, x0, y0); }
        if (y2 < y1) { (x1, y1, x2, y2) = (x2, y2, x1, y1); }

        int totalHeight = y2 - y0;
        if (totalHeight == 0)
            return;

        for (int y = y0; y <= y2; y++)
        {
            bool secondHalf = y > y1 || y1 == y0;
            int segmentHeight = secondHalf ? y2 - y1 : y1 - y0;
            float a = (float)(y - y0) / totalHeight;
            float b = segmentHeight == 0 ? 0f : (float)(y - (secondHalf ? y1 : y0)) / segmentHeight;
            int ax = x0 + (int)((x2 - x0) * a);
            int bx = secondHalf ? x1 + (int)((x2 - x1) * b) : x0 + (int)((x1 - x0) * b);
            if (ax > bx)
                (ax, bx) = (bx, ax);
            // Fill the half-open span [ax, bx): the right endpoint is exclusive so two triangles that
            // meet along an edge each own their own columns and the shared boundary is drawn once.
            HLine(ax, y, bx - ax, color);
        }
    }

    /// <summary>
    /// Fills the polygon described by <paramref name="points"/> (at least three), using the even-odd
    /// rule so simple concave shapes fill correctly.
    /// </summary>
    public void FillPolygon(ReadOnlySpan<(int X, int Y)> points, Color color)
    {
        if (points.Length < 3)
            return;

        int minY = int.MaxValue, maxY = int.MinValue;
        foreach ((int _, int py) in points)
        {
            if (py < minY) minY = py;
            if (py > maxY) maxY = py;
        }
        minY = Math.Max(minY, 0);
        maxY = Math.Min(maxY, Height - 1);

        Span<int> crossings = points.Length <= 64 ? stackalloc int[points.Length] : new int[points.Length];
        for (int y = minY; y <= maxY; y++)
        {
            float scan = y + 0.5f;
            int n = 0;
            for (int i = 0; i < points.Length; i++)
            {
                (int ax, int ay) = points[i];
                (int bx, int by) = points[(i + 1) % points.Length];
                // Count the edge when the scanline falls in its half-open vertical span.
                if ((ay <= scan && by > scan) || (by <= scan && ay > scan))
                {
                    float t = (scan - ay) / (by - ay);
                    crossings[n++] = (int)(ax + t * (bx - ax) + 0.5f);
                }
            }
            crossings[..n].Sort();
            // Fill each half-open span [left, right): the right crossing is exclusive so abutting spans
            // and shared edges are covered exactly once instead of overlapping by a column.
            for (int i = 0; i + 1 < n; i += 2)
                HLine(crossings[i], y, crossings[i + 1] - crossings[i], color);
        }
    }

    /// <summary>Copies <paramref name="source"/> scaled to fill the destination rectangle, nearest sampling.</summary>
    public void BlitScaled(Surface source, int destX, int destY, int destWidth, int destHeight)
        => BlitScaledCore(source, destX, destY, destWidth, destHeight, blended: false);

    /// <summary>Copies <paramref name="source"/> scaled to the destination rectangle, blending by source alpha.</summary>
    public void BlitScaledBlended(Surface source, int destX, int destY, int destWidth, int destHeight)
        => BlitScaledCore(source, destX, destY, destWidth, destHeight, blended: true);

    private void BlitScaledCore(Surface source, int destX, int destY, int destWidth, int destHeight, bool blended)
    {
        if (destWidth <= 0 || destHeight <= 0 || source.Width <= 0 || source.Height <= 0)
            return;
        int x0 = Math.Max(0, destX), y0 = Math.Max(0, destY);
        // Combine origin and extent in 64-bit so a far-off-screen destination cannot wrap the clip
        // rectangle, and back-map each pixel in 64-bit so the multiply cannot overflow into a bad sample.
        int x1 = (int)Math.Min((long)Width, (long)destX + destWidth);
        int y1 = (int)Math.Min((long)Height, (long)destY + destHeight);
        for (int py = y0; py < y1; py++)
        {
            long sy = ((long)py - destY) * source.Height / destHeight;
            if (sy >= source.Height) sy = source.Height - 1;
            uint* srcRow = source._pixels + sy * source.Stride;
            uint* dstRow = _pixels + (long)py * Stride;
            for (int px = x0; px < x1; px++)
            {
                long sx = ((long)px - destX) * source.Width / destWidth;
                if (sx >= source.Width) sx = source.Width - 1;
                dstRow[px] = blended ? Blend(srcRow[sx], dstRow[px]) : srcRow[sx];
            }
        }
    }

    /// <summary>
    /// Copies <paramref name="source"/> scaled to fill the destination rectangle with bilinear sampling,
    /// so an enlarged image looks smooth rather than blocky. Use it for a photo; <see cref="BlitScaled"/>
    /// is the faster nearest-sample form for pixel art or a slight resize.
    /// </summary>
    public void BlitScaledSmooth(Surface source, int destX, int destY, int destWidth, int destHeight)
    {
        if (destWidth <= 0 || destHeight <= 0 || source.Width <= 0 || source.Height <= 0)
            return;
        int x0 = Math.Max(0, destX), y0 = Math.Max(0, destY);
        // Combine in 64-bit so a far-off-screen destination cannot wrap the clip rectangle negative.
        int x1 = (int)Math.Min((long)Width, (long)destX + destWidth);
        int y1 = (int)Math.Min((long)Height, (long)destY + destHeight);
        float scaleX = (float)source.Width / destWidth;
        float scaleY = (float)source.Height / destHeight;

        for (int py = y0; py < y1; py++)
        {
            // Map the destination pixel's centre back into the source, then take the four samples around
            // it. The back-map subtracts in 64-bit so an extreme origin cannot overflow the offset.
            float syf = ((((long)py - destY) + 0.5f) * scaleY) - 0.5f;
            int sy0 = (int)MathF.Floor(syf);
            float fy = syf - sy0;
            uint* srcRow0 = source._pixels + (long)Math.Clamp(sy0, 0, source.Height - 1) * source.Stride;
            uint* srcRow1 = source._pixels + (long)Math.Clamp(sy0 + 1, 0, source.Height - 1) * source.Stride;
            uint* dstRow = _pixels + (long)py * Stride;

            for (int px = x0; px < x1; px++)
            {
                float sxf = ((((long)px - destX) + 0.5f) * scaleX) - 0.5f;
                int sx0 = (int)MathF.Floor(sxf);
                float fx = sxf - sx0;
                int a = Math.Clamp(sx0, 0, source.Width - 1);
                int b = Math.Clamp(sx0 + 1, 0, source.Width - 1);
                dstRow[px] = BilinearMix(srcRow0[a], srcRow0[b], srcRow1[a], srcRow1[b], fx, fy);
            }
        }
    }

    // Interpolates the four neighbouring source pixels. Colour is weighted by each texel's alpha
    // (interpolated in premultiplied form and divided back out), so a fully transparent texel adds no
    // colour and the soft edge of a sprite with transparency fades cleanly instead of darkening toward
    // black. Alpha is interpolated on its own, and the result is returned in the straight-alpha
    // 0xAARRGGBB layout the surface stores.
    private static uint BilinearMix(uint c00, uint c10, uint c01, uint c11, float fx, float fy)
    {
        float w00 = (1f - fx) * (1f - fy);
        float w10 = fx * (1f - fy);
        float w01 = (1f - fx) * fy;
        float w11 = fx * fy;

        float a00 = (c00 >> 24) & 0xFF, a10 = (c10 >> 24) & 0xFF;
        float a01 = (c01 >> 24) & 0xFF, a11 = (c11 >> 24) & 0xFF;
        float alpha = (a00 * w00) + (a10 * w10) + (a01 * w01) + (a11 * w11);
        uint outA = (uint)(alpha + 0.5f);
        if (outA == 0)
            return 0;

        uint Channel(int shift)
        {
            // Weight each colour by its own texel's alpha before interpolating, then divide the
            // interpolated alpha back out to recover the straight (un-premultiplied) colour.
            float sum = (((c00 >> shift) & 0xFF) * a00 * w00)
                      + (((c10 >> shift) & 0xFF) * a10 * w10)
                      + (((c01 >> shift) & 0xFF) * a01 * w01)
                      + (((c11 >> shift) & 0xFF) * a11 * w11);
            uint v = (uint)((sum / alpha) + 0.5f);
            return v > 0xFF ? 0xFFu : v;
        }

        return (outA << 24) | (Channel(16) << 16) | (Channel(8) << 8) | Channel(0);
    }

    /// <summary>
    /// Copies <paramref name="source"/> rotated by <paramref name="angleRadians"/> about its center,
    /// with that center placed at (<paramref name="centerX"/>, <paramref name="centerY"/>) on this
    /// surface. Source pixels are blended by their alpha, nearest sampling.
    /// </summary>
    public void BlitRotated(Surface source, int centerX, int centerY, float angleRadians)
    {
        if (source.Width <= 0 || source.Height <= 0)
            return;
        float cos = MathF.Cos(angleRadians), sin = MathF.Sin(angleRadians);
        float halfW = source.Width / 2f, halfH = source.Height / 2f;

        // The rotated source fits in a box whose half-extent is the projected corner distance.
        float boundX = MathF.Abs(halfW * cos) + MathF.Abs(halfH * sin);
        float boundY = MathF.Abs(halfW * sin) + MathF.Abs(halfH * cos);
        int extX = (int)(boundX + 1);
        int extY = (int)(boundY + 1);
        // Combine centre and extent in 64-bit so an extreme centre cannot wrap the clip rectangle.
        int x0 = (int)Math.Clamp((long)centerX - extX, 0, Width);
        int y0 = (int)Math.Clamp((long)centerY - extY, 0, Height);
        int x1 = (int)Math.Clamp((long)centerX + extX + 1, 0, Width);
        int y1 = (int)Math.Clamp((long)centerY + extY + 1, 0, Height);

        for (int py = y0; py < y1; py++)
        {
            uint* dstRow = _pixels + (long)py * Stride;
            for (int px = x0; px < x1; px++)
            {
                float dx = (long)px - centerX, dy = (long)py - centerY;
                // Map the destination point back into the source by the inverse rotation.
                int sx = (int)(cos * dx + sin * dy + halfW);
                int sy = (int)(-sin * dx + cos * dy + halfH);
                if ((uint)sx >= (uint)source.Width || (uint)sy >= (uint)source.Height)
                    continue;
                dstRow[px] = Blend(source._pixels[(long)sy * source.Stride + sx], dstRow[px]);
            }
        }
    }
}
