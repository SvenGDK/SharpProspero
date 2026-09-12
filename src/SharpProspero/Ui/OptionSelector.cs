// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// One choice from a fixed set, cycled with left and right, for a setting such as a difficulty or a
/// resolution. It shows the label and the current option between arrows, and calls <see cref="Changed"/>
/// with the new index each time it moves. Choosing wraps around at the ends.
/// </summary>
public sealed class OptionSelector : UiElement
{
    private int _selectedIndex;

    /// <summary>Creates a selector labelled <paramref name="text"/> over <paramref name="options"/>.</summary>
    public OptionSelector(string text, IReadOnlyList<string> options, int selected = 0, Action<int>? changed = null)
    {
        Text = text ?? "";
        Options = options ?? throw new ArgumentNullException(nameof(options));
        if (options.Count == 0)
            throw new ArgumentException("A selector needs at least one option.", nameof(options));
        _selectedIndex = Math.Clamp(selected, 0, options.Count - 1);
        Changed = changed;
    }

    /// <summary>The label shown at the left.</summary>
    public string Text { get; set; }

    /// <summary>The choices.</summary>
    public IReadOnlyList<string> Options { get; }

    /// <summary>The index of the chosen option.</summary>
    public int SelectedIndex
    {
        get => _selectedIndex;
        set => _selectedIndex = Math.Clamp(value, 0, Options.Count - 1);
    }

    /// <summary>The chosen option's text.</summary>
    public string SelectedOption => Options[_selectedIndex];

    /// <summary>Called with the new index each time the choice changes.</summary>
    public Action<int>? Changed { get; set; }

    /// <inheritdoc />
    public override bool IsFocusable => Visible;

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        bool isFocused = ReferenceEquals(focused, this);
        surface.FillRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, isFocused ? theme.PanelFocused : theme.Panel);
        if (isFocused)
            surface.DrawRect(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height, theme.Accent);

        int textY = CenterTextY(Bounds, theme);
        theme.DrawClipped(surface, Text, Bounds.X + theme.Padding, textY, theme.Text, Bounds.Width - (2 * theme.Padding));

        // Drawn with characters the font has. It covers printable text only and folds anything else
        // to a blank, so the arrows that were here were drawn as two empty cells that still took up
        // their width.
        string option = "< " + SelectedOption + " >";
        int optionWidth = theme.MeasureText(option);
        int optionRoom = Bounds.Right - theme.Padding - (Bounds.X + theme.Padding + theme.MeasureText(Text) + theme.Padding);
        if (optionRoom > 0)
        {
            int shownWidth = optionWidth < optionRoom ? optionWidth : optionRoom;
            theme.DrawClipped(surface, option, Bounds.Right - theme.Padding - shownWidth, textY, theme.Text, shownWidth);
        }
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
        return false;
    }

    private void Move(int delta)
    {
        int count = Options.Count;
        _selectedIndex = ((_selectedIndex + delta) % count + count) % count;
        Changed?.Invoke(_selectedIndex);
    }
}
