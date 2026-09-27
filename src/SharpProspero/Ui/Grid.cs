// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A container that arranges its children in a grid of a fixed number of columns, filling left to
/// right and wrapping to the next row. Each column is an equal share of the width; each row is as tall
/// as its own tallest child. Use it for a page of icons, a keypad, or a dashboard of tiles. Because
/// focus moves by where controls sit, the four directions step through the grid as the user expects.
/// </summary>
public sealed class Grid : UiElement
{
    private readonly List<UiElement> _children = [];
    private int _columns = 2;

    /// <summary>How many columns the grid has. At least one; the default is two.</summary>
    public int Columns
    {
        get => _columns;
        set => _columns = value < 1 ? 1 : value;
    }

    /// <summary>The gap between columns, or -1 to use the theme's spacing (the default).</summary>
    public int ColumnSpacing { get; set; } = -1;

    /// <summary>The gap between rows, or -1 to use the theme's spacing (the default).</summary>
    public int RowSpacing { get; set; } = -1;

    /// <summary>The children, in the order they fill the grid.</summary>
    public IReadOnlyList<UiElement> Children => _children;

    /// <summary>Adds <paramref name="child"/> to the next cell and returns this grid, so calls can chain.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="child"/> is null.</exception>
    public Grid Add(UiElement child)
    {
        ArgumentNullException.ThrowIfNull(child);
        _children.Add(child);
        return this;
    }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
    {
        int cellWidth = CellWidth(width, theme);
        int rowGap = RowSpacing >= 0 ? RowSpacing : theme.Spacing;

        int total = 0, rows = 0, rowHeight = 0, column = 0;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
                continue;
            rowHeight = Math.Max(rowHeight, child.Measure(cellWidth, theme));
            if (++column == _columns)
            {
                total += rowHeight;
                rows++;
                rowHeight = 0;
                column = 0;
            }
        }
        if (column > 0)   // a final, partly-filled row
        {
            total += rowHeight;
            rows++;
        }
        if (rows > 1)
            total += rowGap * (rows - 1);
        return total;
    }

    /// <inheritdoc/>
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        Bounds = bounds;
        int colGap = ColumnSpacing >= 0 ? ColumnSpacing : theme.Spacing;
        int rowGap = RowSpacing >= 0 ? RowSpacing : theme.Spacing;
        int cellWidth = CellWidth(bounds.Width, theme);

        // A row is placed once its cells are known, so its children are gathered first, then laid out
        // at the row's height (the tallest child), then the pen drops to the next row.
        var row = new List<UiElement>(_columns);
        int y = bounds.Y;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
                continue;
            row.Add(child);
            if (row.Count == _columns)
                y = PlaceRow(row, bounds, y, cellWidth, colGap, rowGap, theme);
        }
        if (row.Count > 0)
            PlaceRow(row, bounds, y, cellWidth, colGap, rowGap, theme);
    }

    private static int PlaceRow(List<UiElement> row, UiRect bounds, int y, int cellWidth, int colGap, int rowGap, UiTheme theme)
    {
        int rowHeight = 0;
        foreach (UiElement child in row)
            rowHeight = Math.Max(rowHeight, child.Measure(cellWidth, theme));

        bool rtl = theme.IsRtl;
        if (rtl)
        {
            // In RTL the first-added child owns the visual-right cell so the reading order matches
            // the surrounding text flow.
            int cellX = bounds.Right - cellWidth;
            foreach (UiElement child in row)
            {
                child.Arrange(new UiRect(cellX, y, cellWidth, rowHeight), theme);
                cellX -= cellWidth + colGap;
            }
        }
        else
        {
            int cellX = bounds.X;
            foreach (UiElement child in row)
            {
                child.Arrange(new UiRect(cellX, y, cellWidth, rowHeight), theme);
                cellX += cellWidth + colGap;
            }
        }
        row.Clear();
        return y + rowHeight + rowGap;
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

    private int CellWidth(int width, UiTheme theme)
    {
        int colGap = ColumnSpacing >= 0 ? ColumnSpacing : theme.Spacing;
        return Math.Max(0, (width - (colGap * (_columns - 1))) / _columns);
    }
}
