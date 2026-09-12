// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A vertical list the user moves through with up and down and opens an item with the confirm button.
/// It shows a window of rows and scrolls to keep the selection in view. Up at the top row and down at
/// the bottom row are left unused, so focus can move to a control above or below the list.
/// </summary>
public sealed class ListView : UiElement
{
    private readonly List<string> _items = [];
    private int _selectedIndex;
    private int _scroll;

    /// <summary>Creates an empty list.</summary>
    public ListView()
    {
    }

    /// <summary>Creates a list of <paramref name="items"/>.</summary>
    public ListView(IEnumerable<string> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        foreach (string item in items)
            _items.Add(item ?? "");
    }

    /// <summary>The items, in order.</summary>
    public IReadOnlyList<string> Items => _items;

    /// <summary>The most rows shown at once before the list scrolls. Default 6.</summary>
    public int VisibleRows { get; set; } = 6;

    /// <summary>Called with the index when an item is confirmed.</summary>
    public Action<int>? Activated { get; set; }

    /// <summary>Called with the index each time the selection moves.</summary>
    public Action<int>? SelectionChanged { get; set; }

    /// <summary>The index of the selected item. Setting it clamps to the list and scrolls it into view.</summary>
    public int SelectedIndex
    {
        get => _selectedIndex;
        set => SetSelected(value, notify: false);
    }

    /// <summary>The selected item's text, or null when the list is empty.</summary>
    public string? SelectedItem
        => _selectedIndex >= 0 && _selectedIndex < _items.Count ? _items[_selectedIndex] : null;

    /// <summary>Adds <paramref name="item"/> to the end and returns this list, so calls can chain.</summary>
    public ListView Add(string item)
    {
        _items.Add(item ?? "");
        return this;
    }

    /// <summary>Removes every item and resets the selection.</summary>
    public void Clear()
    {
        _items.Clear();
        _selectedIndex = 0;
        _scroll = 0;
    }

    /// <inheritdoc />
    public override bool IsFocusable => Visible && _items.Count > 0;

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme)
    {
        int rows = Math.Min(_items.Count == 0 ? 1 : _items.Count, Math.Max(1, VisibleRows));
        return rows * theme.RowHeight;
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (_items.Count == 0)
            return false;
        if (input.Confirm)
        {
            Activated?.Invoke(_selectedIndex);
            return true;
        }
        if (input.Up && _selectedIndex > 0)
        {
            SetSelected(_selectedIndex - 1, notify: true);
            return true;
        }
        if (input.Down && _selectedIndex < _items.Count - 1)
        {
            SetSelected(_selectedIndex + 1, notify: true);
            return true;
        }
        // At the top or bottom edge (or no vertical input): leave the input for the screen so focus can
        // move to a neighbor.
        return false;
    }

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        surface.FillRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, theme.Panel);

        int rowHeight = theme.RowHeight;
        int visible = Math.Max(1, VisibleRows);
        int last = Math.Min(_items.Count, _scroll + visible);
        for (int i = _scroll; i < last; i++)
        {
            var row = new UiRect(Bounds.X, Bounds.Y + (i - _scroll) * rowHeight, Bounds.Width, rowHeight);
            if (i == _selectedIndex)
            {
                surface.FillRect(row.X, row.Y, row.Width, row.Height, isFocused ? theme.PanelFocused : theme.Border);
                if (isFocused)
                    surface.DrawRect(row.X, row.Y, row.Width, row.Height, theme.Accent);
            }
            theme.DrawClipped(surface, _items[i], row.X + theme.Padding, CenterTextY(row, theme), theme.Text, row.Width - (2 * theme.Padding));
        }
    }

    private void SetSelected(int index, bool notify)
    {
        int clamped = _items.Count == 0 ? 0 : Math.Clamp(index, 0, _items.Count - 1);
        bool changed = clamped != _selectedIndex;
        _selectedIndex = clamped;

        int visible = Math.Max(1, VisibleRows);
        if (_selectedIndex < _scroll)
            _scroll = _selectedIndex;
        else if (_selectedIndex >= _scroll + visible)
            _scroll = _selectedIndex - visible + 1;

        if (changed && notify)
            SelectionChanged?.Invoke(_selectedIndex);
    }
}
