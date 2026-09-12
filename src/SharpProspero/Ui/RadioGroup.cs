// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// One choice from a fixed set, with every option shown at once and a filled dot marking the current
/// one. Up and down move the choice; the ends are left unused so focus can move to a control above or
/// below. Where an <see cref="OptionSelector"/> shows a single option cycled with left and right, this
/// shows them all — use it when the options are few and worth seeing together.
/// </summary>
public sealed class RadioGroup : UiElement
{
    private readonly List<string> _options = [];
    private int _selectedIndex;

    /// <summary>Creates a group over <paramref name="options"/> with <paramref name="selected"/> chosen.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="options"/> is empty.</exception>
    public RadioGroup(IEnumerable<string> options, int selected = 0, Action<int>? changed = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        foreach (string option in options)
            _options.Add(option ?? "");
        if (_options.Count == 0)
            throw new ArgumentException("A radio group needs at least one option.", nameof(options));
        _selectedIndex = Math.Clamp(selected, 0, _options.Count - 1);
        Changed = changed;
    }

    /// <summary>The options, in order.</summary>
    public IReadOnlyList<string> Options => _options;

    /// <summary>The index of the chosen option. Setting it clamps to the range and does not raise <see cref="Changed"/>.</summary>
    public int SelectedIndex
    {
        get => _selectedIndex;
        set => _selectedIndex = Math.Clamp(value, 0, _options.Count - 1);
    }

    /// <summary>The chosen option's text.</summary>
    public string SelectedOption => _options[_selectedIndex];

    /// <summary>Called with the new index each time the choice changes.</summary>
    public Action<int>? Changed { get; set; }

    /// <inheritdoc/>
    public override bool IsFocusable => Visible;

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme) => _options.Count * theme.RowHeight;

    /// <inheritdoc/>
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (input.Up && _selectedIndex > 0)
        {
            _selectedIndex--;
            Changed?.Invoke(_selectedIndex);
            return true;
        }
        if (input.Down && _selectedIndex < _options.Count - 1)
        {
            _selectedIndex++;
            Changed?.Invoke(_selectedIndex);
            return true;
        }
        // At the top or bottom edge, leave the input for the screen so focus can move to a neighbor.
        return false;
    }

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        surface.FillRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, isFocused ? theme.PanelFocused : theme.Panel);
        if (isFocused)
            surface.DrawRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, theme.Accent);

        int rowHeight = theme.RowHeight;
        int radius = Math.Max(3, theme.LineHeight / 2 - 2);
        int dotX = Bounds.X + theme.Padding + radius;
        int textX = Bounds.X + theme.Padding + (2 * radius) + theme.Padding;

        for (int i = 0; i < _options.Count; i++)
        {
            int rowY = Bounds.Y + (i * rowHeight);
            int dotY = rowY + (rowHeight / 2);
            surface.DrawCircle(dotX, dotY, radius, theme.Text);
            if (i == _selectedIndex)
                surface.FillCircle(dotX, dotY, radius - 3, theme.Accent);
            theme.DrawClipped(surface, _options[i], textX, rowY + ((rowHeight - theme.LineHeight) / 2), theme.Text, Bounds.Right - theme.Padding - textX);
        }
    }
}
