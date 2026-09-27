// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A container that places its children side by side, each an equal share of the width, with a gap
/// between them. Where <see cref="StackPanel"/> stacks downwards, this lays across: a pair of buttons
/// at the foot of a panel, or a set of columns. The row is as tall as its tallest child, and left and
/// right move focus along it.
/// </summary>
public sealed class Row : UiElement
{
    private readonly List<UiElement> _children = [];

    /// <summary>The gap between children, or -1 to use the theme's spacing (the default).</summary>
    public int Spacing { get; set; } = -1;

    /// <summary>The children, in order from left to right.</summary>
    public IReadOnlyList<UiElement> Children => _children;

    /// <summary>Adds <paramref name="child"/> to the right and returns this row, so calls can chain.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="child"/> is null.</exception>
    public Row Add(UiElement child)
    {
        ArgumentNullException.ThrowIfNull(child);
        _children.Add(child);
        return this;
    }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
    {
        int columnWidth = ColumnWidth(width, theme, out int shown);
        if (shown == 0)
            return 0;

        int tallest = 0;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
                continue;
            int height = child.Measure(columnWidth, theme);
            if (height > tallest)
                tallest = height;
        }
        return tallest;
    }

    /// <inheritdoc/>
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        Bounds = bounds;
        int gap = Spacing >= 0 ? Spacing : theme.Spacing;
        int columnWidth = ColumnWidth(bounds.Width, theme, out int shown);
        if (shown == 0)
            return;

        bool rtl = theme.IsRtl;
        int index = 0;
        int x = rtl ? bounds.Right : bounds.X;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
                continue;

            // The last logical column takes whatever is left, so rounding never leaves a gap at the
            // far edge. In RTL that far edge is the left one — the same "abut the boundary" rule
            // just mirrored.
            int width = index == shown - 1
                ? (rtl ? x - bounds.X : bounds.Right - x)
                : columnWidth;

            int childX = rtl ? x - width : x;
            child.Arrange(new UiRect(childX, bounds.Y, width, bounds.Height), theme);
            if (rtl)
                x -= width + gap;
            else
                x += width + gap;
            index++;
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

    // The width one column gets once the gaps between the shown children are taken out.
    private int ColumnWidth(int width, UiTheme theme, out int shown)
    {
        shown = 0;
        foreach (UiElement child in _children)
        {
            if (child.Visible)
                shown++;
        }
        if (shown == 0)
            return 0;

        int gap = Spacing >= 0 ? Spacing : theme.Spacing;
        return Math.Max(0, (width - (gap * (shown - 1))) / shown);
    }
}
