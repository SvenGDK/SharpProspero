// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A container that places its children side by side, each taking a weighted share of the width.
/// Where <see cref="Row"/> gives every child the same width, this lets the caller name a wider
/// left panel and a narrower right panel (or the other way round). The panel is as tall as its
/// tallest child, and left and right move focus along it.
/// </summary>
public sealed class SplitPanel : UiElement
{
    private readonly List<UiElement> _children = [];
    private readonly List<int> _weights = [];

    /// <summary>The gap between children, or -1 to use the theme's spacing (the default).</summary>
    public int Spacing { get; set; } = -1;

    /// <summary>The children, in order from left to right.</summary>
    public IReadOnlyList<UiElement> Children => _children;

    /// <summary>
    /// Adds <paramref name="child"/> to the right of the panel with weight <paramref name="weight"/>
    /// (a positive integer). The child's laid-out width is its weight divided by the sum of every
    /// visible child's weight, minus the spacing between the panels.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="child"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="weight"/> is not positive.</exception>
    public SplitPanel Add(UiElement child, int weight = 1)
    {
        ArgumentNullException.ThrowIfNull(child);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(weight);
        _children.Add(child);
        _weights.Add(weight);
        return this;
    }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
    {
        int gap = Spacing >= 0 ? Spacing : theme.Spacing;
        Span<int> shownWeights = stackalloc int[_children.Count];
        int shown = 0;
        int totalWeight = 0;
        for (int i = 0; i < _children.Count; i++)
        {
            if (_children[i].Visible)
            {
                shownWeights[shown] = _weights[i];
                totalWeight += _weights[i];
                shown++;
            }
        }
        if (shown == 0)
            return 0;

        int usable = Math.Max(0, width - gap * (shown - 1));
        int tallest = 0;
        int childIndex = 0;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
                continue;
            int w = totalWeight == 0 ? 0 : usable * shownWeights[childIndex] / totalWeight;
            int height = child.Measure(w, theme);
            if (height > tallest)
                tallest = height;
            childIndex++;
        }
        return tallest;
    }

    /// <inheritdoc/>
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        Bounds = bounds;
        int gap = Spacing >= 0 ? Spacing : theme.Spacing;
        Span<int> shownWeights = stackalloc int[_children.Count];
        int shown = 0;
        int totalWeight = 0;
        for (int i = 0; i < _children.Count; i++)
        {
            if (_children[i].Visible)
            {
                shownWeights[shown] = _weights[i];
                totalWeight += _weights[i];
                shown++;
            }
        }
        if (shown == 0)
            return;

        int usable = Math.Max(0, bounds.Width - gap * (shown - 1));
        int childIndex = 0;
        bool rtl = theme.IsRtl;
        int x = rtl ? bounds.Right : bounds.X;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
                continue;

            int w;
            if (childIndex == shown - 1)
            {
                // The last visible child takes whatever is left, so a rounding shortfall never
                // opens a gap at the far edge — the right edge in LTR, the left edge in RTL.
                w = rtl ? x - bounds.X : bounds.Right - x;
            }
            else
            {
                w = totalWeight == 0 ? 0 : usable * shownWeights[childIndex] / totalWeight;
            }
            int childX = rtl ? x - w : x;
            child.Arrange(new UiRect(childX, bounds.Y, w, bounds.Height), theme);
            if (rtl)
                x -= w + gap;
            else
                x += w + gap;
            childIndex++;
        }
    }

    /// <inheritdoc/>
    internal override void CollectFocusables(List<UiElement> into)
    {
        foreach (UiElement child in _children)
        {
            if (child.Visible)
                child.CollectFocusables(into);
        }
    }

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible)
            return;
        foreach (UiElement child in _children)
        {
            if (child.Visible)
                child.Draw(surface, theme, focused);
        }
    }
}
