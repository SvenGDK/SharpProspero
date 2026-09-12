// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A horizontal strip of items with one in the middle, moved with left and right and chosen with confirm -
/// the shape a launcher uses to pick an app or a level. The middle tile is highlighted; the neighbours peek
/// at the sides. Moving wraps around at the ends. It calls <see cref="Changed"/> when the middle item
/// changes and <see cref="Activated"/> when the middle item is chosen.
/// </summary>
public sealed class Carousel : UiElement
{
    private readonly IReadOnlyList<string> _items;
    private int _index;

    /// <summary>Creates a carousel over <paramref name="items"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="items"/> is empty.</exception>
    public Carousel(IReadOnlyList<string> items, int selected = 0, Action<int>? changed = null, Action<int>? activated = null)
    {
        _items = items ?? throw new ArgumentNullException(nameof(items));
        if (items.Count == 0)
            throw new ArgumentException("A carousel needs at least one item.", nameof(items));
        _index = Math.Clamp(selected, 0, items.Count - 1);
        Changed = changed;
        Activated = activated;
    }

    /// <summary>The items.</summary>
    public IReadOnlyList<string> Items => _items;

    /// <summary>The index of the middle item; setting it clamps to the range.</summary>
    public int SelectedIndex
    {
        get => _index;
        set => _index = Math.Clamp(value, 0, _items.Count - 1);
    }

    /// <summary>The middle item's text.</summary>
    public string SelectedItem => _items[_index];

    /// <summary>Called with the new index when the middle item changes.</summary>
    public Action<int>? Changed { get; set; }

    /// <summary>Called with the index when the middle item is chosen.</summary>
    public Action<int>? Activated { get; set; }

    /// <inheritdoc />
    public override bool IsFocusable => Visible;

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme) => theme.RowHeight * 3;

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        int count = _items.Count;
        int gap = theme.Spacing;
        int tileWidth = (Bounds.Width - 2 * gap) / 3;
        int counterHeight = theme.LineHeight;
        int tileHeight = Bounds.Height - counterHeight - theme.Spacing;

        for (int offset = -1; offset <= 1; offset++)
        {
            if (count == 1 && offset != 0)
                continue;
            int index = ((_index + offset) % count + count) % count;
            int tileX = Bounds.X + (offset + 1) * (tileWidth + gap);
            bool middle = offset == 0;

            Color fill = middle ? (isFocused ? theme.PanelFocused : theme.Panel) : theme.Panel;
            surface.FillRect(tileX, Bounds.Y, tileWidth, tileHeight, fill);
            if (middle && isFocused)
                surface.DrawRect(tileX, Bounds.Y, tileWidth, tileHeight, theme.Accent);

            Color textColor = middle ? theme.Text : theme.TextMuted;
            DrawCentered(surface, theme, _items[index], tileX, tileWidth, Bounds.Y, tileHeight, textColor);
        }

        string counter = $"{_index + 1} / {count}";
        int counterY = Bounds.Y + tileHeight + theme.Spacing;
        DrawCentered(surface, theme, counter, Bounds.X, Bounds.Width, counterY, counterHeight, theme.TextMuted);
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Left)
        {
            Move(-1);
            return true;
        }
        if (input.Right)
        {
            Move(1);
            return true;
        }
        if (input.Confirm)
        {
            Activated?.Invoke(_index);
            return true;
        }
        return false;
    }

    private void Move(int delta)
    {
        int count = _items.Count;
        int next = ((_index + delta) % count + count) % count;
        if (next == _index)
            return;
        _index = next;
        Changed?.Invoke(_index);
    }

    // Draws text centred within (x, width, y, height), shortening it so it never spills past the tile.
    private static void DrawCentered(Surface surface, UiTheme theme, string text, int x, int width, int y, int height, Color color)
    {
        string shown = TextLayout.Truncate(theme.Font, text, width);
        int textWidth = theme.MeasureText(shown);
        int textX = x + (width - textWidth) / 2;
        int textY = y + (height - theme.LineHeight) / 2;
        theme.DrawText(surface, shown, textX, textY, color);
    }
}
