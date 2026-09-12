// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;

namespace SharpProspero.Ui;

/// <summary>
/// A round meter that shows a fraction from 0 to 1 as a filled arc — a disk-usage dial, a battery ring,
/// a completion wheel. Where <see cref="ProgressBar"/> fills a straight bar and <see cref="Spinner"/>
/// turns without end, this fills a ring or a dial to a known amount. It takes no focus; set
/// <see cref="Value"/> each frame and draw it.
/// </summary>
public sealed class Gauge : UiElement
{
    private float _value;
    private int _lastPercent = -1;
    private string _percentLabel = "";

    /// <summary>Creates a gauge at <paramref name="value"/> (0 to 1).</summary>
    public Gauge(float value = 0f) => Value = value;

    /// <summary>How full the gauge is, from 0 to 1. Values outside the range are clamped.</summary>
    public float Value
    {
        get => _value;
        set => _value = Math.Clamp(value, 0f, 1f);
    }

    /// <summary>How wide and tall the gauge is drawn, in pixels. Default 96.</summary>
    public int Diameter { get; set; } = 96;

    /// <summary>How thick the ring is, or -1 to scale it with the diameter (the default).</summary>
    public int Thickness { get; set; } = -1;

    /// <summary>Where the fill begins, in radians. Default the top of the ring.</summary>
    public float StartRadians { get; set; } = -MathF.PI / 2f;

    /// <summary>How far a full gauge sweeps, in radians. Default a whole turn; use less for a dial.</summary>
    public float SweepRadians { get; set; } = MathF.Tau;

    /// <summary>The colour of the unfilled track, or null to use the theme's border.</summary>
    public Color? TrackColor { get; set; }

    /// <summary>The colour of the filled arc, or null to use the theme's accent.</summary>
    public Color? FillColor { get; set; }

    /// <summary>Whether to draw the rounded percentage in the middle. Default true.</summary>
    public bool ShowPercent { get; set; } = true;

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme) => Diameter;

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible || Diameter <= 1)
            return;

        int radius = Diameter / 2;
        int thickness = Thickness >= 1 ? Thickness : Math.Max(4, Diameter / 8);
        int inner = Math.Max(0, radius - thickness);
        int cx = Bounds.X + (Bounds.Width / 2);
        int cy = Bounds.Y + radius;

        surface.FillArcRing(cx, cy, inner, radius, StartRadians, SweepRadians, TrackColor ?? theme.Border);
        if (_value > 0f)
            surface.FillArcRing(cx, cy, inner, radius, StartRadians, SweepRadians * _value, FillColor ?? theme.Accent);

        if (ShowPercent)
        {
            // The label text is rebuilt only when the whole-number percentage changes, so a gauge redrawn
            // every frame allocates nothing while its value holds.
            int percent = (int)((_value * 100f) + 0.5f);
            if (percent != _lastPercent)
            {
                _lastPercent = percent;
                _percentLabel = percent.ToString() + "%";
            }
            int textWidth = theme.MeasureText(_percentLabel);
            theme.DrawText(surface, _percentLabel, cx - (textWidth / 2), cy - (theme.LineHeight / 2), theme.Text);
        }
    }
}
