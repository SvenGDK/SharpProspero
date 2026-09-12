// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Graphics;

// Shapes and panel drawing that build on the basic operations: thick borders, ellipses, arcs and
// pies, connected lines, and the nine-part stretch that keeps a panel image crisp at any size.
public readonly unsafe partial struct Surface
{
    /// <summary>
    /// Draws a rectangle outline <paramref name="thickness"/> pixels wide, drawn inside the rectangle so
    /// the outer edge stays where it was asked for. Use this for a focus ring or a panel border.
    /// </summary>
    public void DrawRectThick(int x, int y, int width, int height, int thickness, Color color)
    {
        if (width <= 0 || height <= 0 || thickness <= 0)
            return;
        int t = Math.Min(thickness, Math.Min(width, height) / 2);
        if (t <= 0)
            t = 1;
        FillRect(x, y, width, t, color);
        FillRect(x, y + height - t, width, t, color);
        FillRect(x, y + t, t, height - (2 * t), color);
        FillRect(x + width - t, y + t, t, height - (2 * t), color);
    }

    /// <summary>Fills an ellipse centred at (<paramref name="cx"/>, <paramref name="cy"/>) with the given radii.</summary>
    public void FillEllipse(int cx, int cy, int radiusX, int radiusY, Color color)
    {
        if (radiusX <= 0 || radiusY <= 0)
            return;
        for (int dy = -radiusY; dy <= radiusY; dy++)
        {
            double t = (double)dy / radiusY;
            int half = (int)(radiusX * Math.Sqrt(Math.Max(0.0, 1.0 - (t * t))));
            HLine(cx - half, cy + dy, (2 * half) + 1, color);
        }
    }

    /// <summary>Draws the one-pixel outline of an ellipse centred at (<paramref name="cx"/>, <paramref name="cy"/>).</summary>
    public void DrawEllipse(int cx, int cy, int radiusX, int radiusY, Color color)
    {
        if (radiusX <= 0 || radiusY <= 0)
            return;
        int previous = -1;
        for (int dy = -radiusY; dy <= radiusY; dy++)
        {
            double t = (double)dy / radiusY;
            int half = (int)(radiusX * Math.Sqrt(Math.Max(0.0, 1.0 - (t * t))));

            // Where the edge steps in by more than one pixel between rows, fill the gap so the outline
            // stays joined across the flatter top and bottom.
            if (previous >= 0 && Math.Abs(half - previous) > 1)
            {
                int from = Math.Min(half, previous), to = Math.Max(half, previous);
                HLine(cx + from, cy + dy, to - from, color);
                HLine(cx - to, cy + dy, to - from, color);
            }
            SetPixel(cx - half, cy + dy, color);
            SetPixel(cx + half, cy + dy, color);
            previous = half;
        }
    }

    /// <summary>
    /// Draws <paramref name="source"/> into the rectangle at (<paramref name="x"/>, <paramref name="y"/>)
    /// as a panel: the four corners keep their own size, the four edges stretch along their run, and the
    /// middle stretches both ways. <paramref name="border"/> is how many pixels of the source form each
    /// corner. A rounded or bevelled panel image drawn this way stays crisp at any size.
    /// </summary>
    public void BlitNineSlice(Surface source, int x, int y, int width, int height, int border)
    {
        if (width <= 0 || height <= 0 || border < 0 || source.Width <= 0 || source.Height <= 0)
            return;

        int b = Math.Min(border, Math.Min(source.Width, source.Height) / 2);
        if (b <= 0)
        {
            BlitScaledBlended(source, x, y, width, height);
            return;
        }

        int innerW = width - (2 * b);
        int innerH = height - (2 * b);
        int srcInnerW = source.Width - (2 * b);
        int srcInnerH = source.Height - (2 * b);

        // Corners at their own size.
        BlitScaledBlended(source.Region(0, 0, b, b), x, y, b, b);
        BlitScaledBlended(source.Region(source.Width - b, 0, b, b), x + width - b, y, b, b);
        BlitScaledBlended(source.Region(0, source.Height - b, b, b), x, y + height - b, b, b);
        BlitScaledBlended(source.Region(source.Width - b, source.Height - b, b, b), x + width - b, y + height - b, b, b);

        // Edges stretch along one axis, the middle along both.
        if (innerW > 0 && srcInnerW > 0)
        {
            BlitScaledBlended(source.Region(b, 0, srcInnerW, b), x + b, y, innerW, b);
            BlitScaledBlended(source.Region(b, source.Height - b, srcInnerW, b), x + b, y + height - b, innerW, b);
        }
        if (innerH > 0 && srcInnerH > 0)
        {
            BlitScaledBlended(source.Region(0, b, b, srcInnerH), x, y + b, b, innerH);
            BlitScaledBlended(source.Region(source.Width - b, b, b, srcInnerH), x + width - b, y + b, b, innerH);
        }
        if (innerW > 0 && innerH > 0 && srcInnerW > 0 && srcInnerH > 0)
            BlitScaledBlended(source.Region(b, b, srcInnerW, srcInnerH), x + b, y + b, innerW, innerH);
    }

    /// <summary>Draws the three-sided outline of a triangle with the given vertices.</summary>
    public void DrawTriangle(int x0, int y0, int x1, int y1, int x2, int y2, Color color)
    {
        DrawLine(x0, y0, x1, y1, color);
        DrawLine(x1, y1, x2, y2, color);
        DrawLine(x2, y2, x0, y0, color);
    }

    /// <summary>
    /// Draws a run of connected line segments through <paramref name="points"/> in order, each
    /// <paramref name="thickness"/> pixels wide. The run is open: the last point is not joined back to
    /// the first. Use it for a chart line or a free path; for a closed outline use
    /// <see cref="FillPolygon"/> or the triangle and rectangle outlines.
    /// </summary>
    public void DrawPolyline(ReadOnlySpan<(int X, int Y)> points, Color color, int thickness = 1)
    {
        for (int i = 0; i + 1 < points.Length; i++)
            DrawLine(points[i].X, points[i].Y, points[i + 1].X, points[i + 1].Y, color, thickness);
    }

    /// <summary>
    /// Fills the annular sector (a slice of a ring) centred at (<paramref name="cx"/>,
    /// <paramref name="cy"/>) between <paramref name="innerRadius"/> and <paramref name="outerRadius"/>,
    /// starting at <paramref name="startRadians"/> and turning by <paramref name="sweepRadians"/>. Angles
    /// are measured clockwise from the positive x-axis (the screen's y grows downward). A full turn draws
    /// a complete ring; an inner radius of zero draws a pie slice. This is the basis for gauges, dials and
    /// the busy indicator.
    /// </summary>
    public void FillArcRing(int cx, int cy, int innerRadius, int outerRadius, float startRadians, float sweepRadians, Color color)
    {
        if (outerRadius <= 0 || innerRadius >= outerRadius)
            return;

        int inner = Math.Max(0, innerRadius);
        long inner2 = (long)inner * inner;
        long outer2 = (long)outerRadius * outerRadius;

        // A negative sweep turns the other way; fold it into a positive sweep from a shifted start so the
        // in-range test is a single comparison. The sweep is capped at a full turn.
        float sweep = sweepRadians;
        float start = startRadians;
        if (sweep < 0f)
        {
            start += sweep;
            sweep = -sweep;
        }
        if (sweep > MathF.Tau)
            sweep = MathF.Tau;
        bool fullTurn = sweep >= MathF.Tau - 1e-4f;

        // Combine centre and radius in 64-bit so an extreme centre or radius cannot wrap the scan
        // rectangle and silently skip pixels that are actually on the surface.
        int x0 = (int)Math.Max(0L, (long)cx - outerRadius);
        int y0 = (int)Math.Max(0L, (long)cy - outerRadius);
        int x1 = (int)Math.Min(Width - 1L, (long)cx + outerRadius);
        int y1 = (int)Math.Min(Height - 1L, (long)cy + outerRadius);

        for (int y = y0; y <= y1; y++)
        {
            int dy = y - cy;
            for (int x = x0; x <= x1; x++)
            {
                int dx = x - cx;
                long dist2 = (long)dx * dx + (long)dy * dy;
                if (dist2 < inner2 || dist2 > outer2)
                    continue;
                if (!fullTurn)
                {
                    float rel = MathF.Atan2(dy, dx) - start;
                    rel -= MathF.Tau * MathF.Floor(rel / MathF.Tau); // wrap into [0, tau)
                    if (rel > sweep)
                        continue;
                }
                _pixels[(long)y * Stride + x] = color.Value;
            }
        }
    }

    /// <summary>
    /// Fills a pie slice (a sector) of a disc centred at (<paramref name="cx"/>, <paramref name="cy"/>)
    /// with the given <paramref name="radius"/>, from <paramref name="startRadians"/> turning by
    /// <paramref name="sweepRadians"/>.
    /// </summary>
    public void FillPie(int cx, int cy, int radius, float startRadians, float sweepRadians, Color color)
        => FillArcRing(cx, cy, 0, radius, startRadians, sweepRadians, color);

    /// <summary>
    /// Draws the one-pixel outline of an arc centred at (<paramref name="cx"/>, <paramref name="cy"/>)
    /// with the given <paramref name="radius"/>, from <paramref name="startRadians"/> turning by
    /// <paramref name="sweepRadians"/>. A full turn draws a complete circle.
    /// </summary>
    public void DrawArc(int cx, int cy, int radius, float startRadians, float sweepRadians, Color color)
    {
        if (radius <= 0)
            return;

        // Enough samples that neighbouring points are at most about one pixel apart along the arc.
        int steps = Math.Max(1, (int)MathF.Ceiling(MathF.Abs(sweepRadians) * radius));
        for (int i = 0; i <= steps; i++)
        {
            float a = startRadians + (sweepRadians * i / steps);
            int px = cx + (int)MathF.Round(radius * MathF.Cos(a));
            int py = cy + (int)MathF.Round(radius * MathF.Sin(a));
            SetPixel(px, py, color);
        }
    }

    /// <summary>
    /// Draws a ring centred at (<paramref name="cx"/>, <paramref name="cy"/>): a circle of the given
    /// <paramref name="radius"/> with a border <paramref name="thickness"/> pixels wide, drawn inwards.
    /// </summary>
    public void DrawCircleThick(int cx, int cy, int radius, int thickness, Color color)
    {
        if (radius <= 0 || thickness <= 0)
            return;
        FillArcRing(cx, cy, radius - thickness, radius, 0f, MathF.Tau, color);
    }

    /// <summary>
    /// Fills a rectangle, blending each pixel over what is there by <paramref name="color"/>'s alpha, so a
    /// translucent panel or highlight shows what is behind it. A fully opaque colour fills directly.
    /// </summary>
    public void FillRectBlended(int x, int y, int width, int height, Color color)
    {
        if (width <= 0 || height <= 0 || color.A == 0)
            return;
        if (color.A == 255)
        {
            FillRect(x, y, width, height, color);
            return;
        }

        int x0 = Math.Max(0, x), y0 = Math.Max(0, y);
        int x1 = Math.Min(Width, x + width), y1 = Math.Min(Height, y + height);
        uint rgb = color.Value & 0x00FFFFFFu;
        byte alpha = color.A;
        for (int py = y0; py < y1; py++)
        {
            for (int px = x0; px < x1; px++)
                BlendPixel(px, py, rgb, alpha);
        }
    }

    /// <summary>
    /// Fills a disc, blending each pixel over what is there by <paramref name="color"/>'s alpha, so a soft
    /// or translucent dot — a particle, a glow — composites over the scene. A fully opaque colour fills
    /// directly.
    /// </summary>
    public void FillCircleBlended(int cx, int cy, int radius, Color color)
    {
        if (radius < 0 || color.A == 0)
            return;
        if (color.A == 255)
        {
            FillCircle(cx, cy, radius, color);
            return;
        }

        uint rgb = color.Value & 0x00FFFFFFu;
        byte alpha = color.A;
        for (int dy = -radius; dy <= radius; dy++)
        {
            int half = (int)Math.Sqrt(((double)radius * radius) - ((double)dy * dy));
            int y = cy + dy;
            for (int x = cx - half; x <= cx + half; x++)
                BlendPixel(x, y, rgb, alpha);
        }
    }
}
