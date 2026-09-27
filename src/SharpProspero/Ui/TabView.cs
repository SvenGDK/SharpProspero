// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A row of named tabs with one page shown at a time. Focus lands on the tab row, where left and right
/// change the page; moving down goes into the page's own controls. Use it to divide a tool into
/// sections without a separate screen for each.
/// </summary>
public sealed class TabView : UiElement
{
    private readonly List<(string Title, UiElement Content)> _tabs = [];
    private int _selectedIndex;

    /// <summary>The tab titles, in the order they were added.</summary>
    public IReadOnlyList<string> Titles
    {
        get
        {
            var titles = new List<string>(_tabs.Count);
            foreach ((string title, UiElement _) in _tabs)
                titles.Add(title);
            return titles;
        }
    }

    /// <summary>How many tabs there are.</summary>
    public int Count => _tabs.Count;

    /// <summary>
    /// The tab being shown. Setting it outside the range of tabs clamps to the nearest one. Changing it
    /// raises <see cref="SelectionChanged"/>.
    /// </summary>
    public int SelectedIndex
    {
        get => _selectedIndex;
        set
        {
            if (_tabs.Count == 0)
            {
                _selectedIndex = 0;
                return;
            }
            int clamped = Math.Clamp(value, 0, _tabs.Count - 1);
            if (clamped == _selectedIndex)
                return;
            _selectedIndex = clamped;
            SelectionChanged?.Invoke(clamped);
        }
    }

    /// <summary>The page currently shown, or null when no tab has been added.</summary>
    public UiElement? SelectedContent => _tabs.Count == 0 ? null : _tabs[_selectedIndex].Content;

    /// <summary>Called with the new index when the shown tab changes.</summary>
    public Action<int>? SelectionChanged { get; set; }

    /// <summary>The tab row holds focus so left and right can change the page.</summary>
    public override bool IsFocusable => _tabs.Count > 1;

    /// <summary>Adds a tab titled <paramref name="title"/> showing <paramref name="content"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="content"/> is null.</exception>
    public void Add(string title, UiElement content)
    {
        ArgumentNullException.ThrowIfNull(content);
        _tabs.Add((title ?? "", content));
    }

    /// <summary>Removes every tab.</summary>
    public void Clear()
    {
        _tabs.Clear();
        _selectedIndex = 0;
    }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
    {
        int header = theme.RowHeight;
        UiElement? content = SelectedContent;
        return content is null || !content.Visible ? header : header + theme.Spacing + content.Measure(width, theme);
    }

    /// <inheritdoc/>
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (_tabs.Count <= 1)
            return false;
        if (input.Left && _selectedIndex > 0)
        {
            SelectedIndex = _selectedIndex - 1;
            return true;
        }
        if (input.Right && _selectedIndex < _tabs.Count - 1)
        {
            SelectedIndex = _selectedIndex + 1;
            return true;
        }
        return false;
    }

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible || _tabs.Count == 0)
            return;

        int headerHeight = theme.RowHeight;
        bool rowFocused = ReferenceEquals(focused, this);
        int tabWidth = Bounds.Width / _tabs.Count;
        bool rtl = theme.IsRtl;

        for (int i = 0; i < _tabs.Count; i++)
        {
            (int x, int width) = TabRect(i, tabWidth, rtl);
            bool active = i == _selectedIndex;

            Color background = active ? (rowFocused ? theme.PanelFocused : theme.Panel) : theme.Background;
            surface.FillRect(x, Bounds.Y, width, headerHeight, background);

            string title = TextLayout.Truncate(theme.Font, _tabs[i].Title, width - (2 * theme.Padding));
            int textWidth = theme.MeasureText(title);
            int textX = x + ((width - textWidth) / 2);
            int textY = Bounds.Y + ((headerHeight - theme.LineHeight) / 2);
            theme.DrawText(surface, title, textX, textY, active ? theme.Text : theme.TextMuted);

        }

        // The border sits along the bottom edge of every tab; the active tab's 2-pixel accent bar
        // is drawn LAST so it overpaints the border underneath it and reads as the intended
        // 2-pixel accent stripe rather than accent-over-border-over-accent.
        surface.FillRect(Bounds.X, Bounds.Y + headerHeight - 1, Bounds.Width, 1, theme.Border);
        {
            (int x, int width) = TabRect(_selectedIndex, tabWidth, rtl);
            surface.FillRect(x, Bounds.Y + headerHeight - 2, width, 2, theme.Accent);
        }
        SelectedContent?.Draw(surface, theme, focused);
    }

    // The screen-space rectangle for the tab at logical index <paramref name="i"/>. In RTL the
    // first tab sits at the visual right and the last at the visual left so the tab strip flows
    // in the same direction as the surrounding paragraph.
    private (int X, int Width) TabRect(int i, int tabWidth, bool rtl)
    {
        int last = _tabs.Count - 1;
        if (rtl)
        {
            int width = i == last ? Bounds.Width - (last * tabWidth) : tabWidth;
            int x = i == last ? Bounds.X : Bounds.Right - (i * tabWidth) - width;
            return (x, width);
        }
        else
        {
            int x = Bounds.X + (i * tabWidth);
            int width = i == last ? Bounds.Width - (i * tabWidth) : tabWidth;
            return (x, width);
        }
    }

    /// <inheritdoc/>
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        // Bounds anchor the tab row itself. Focus navigation from the tab row measures against this
        // narrow band so pressing down from the row moves into the first content control below,
        // instead of past it into the lower half of the whole area.
        int headerHeight = theme.RowHeight;
        Bounds = new UiRect(bounds.X, bounds.Y, bounds.Width, headerHeight);

        UiElement? content = SelectedContent;
        if (content is null || !content.Visible)
            return;

        int top = bounds.Y + headerHeight + theme.Spacing;
        int height = Math.Max(0, bounds.Bottom - top);
        content.Arrange(new UiRect(bounds.X, top, bounds.Width, height), theme);
    }

    /// <inheritdoc/>
    internal override void CollectFocusables(List<UiElement> into)
    {
        if (!Visible)
            return;
        if (IsFocusable)
            into.Add(this);

        // Only the page on show takes part in focus, so moving through the screen never reaches a
        // control the user cannot see.
        UiElement? content = SelectedContent;
        if (content is not null && content.Visible)
            content.CollectFocusables(into);
    }
}
