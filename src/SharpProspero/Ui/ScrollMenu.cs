// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A scrolling column of controls the user moves through with up and down, where more controls are
/// stacked than fit in the window. Unlike <see cref="ScrollView"/>, which scrolls read-only content as a
/// block, this keeps its controls individually focusable: up and down move a highlight from one control
/// to the next, the window scrolls to keep the focused control in view, and the confirm and adjust
/// presses reach whichever control is focused. Use it for a settings form or any panel with more buttons,
/// checkboxes and sliders than the screen has room for. Up on the first control and down on the last are
/// left unused, so focus can move to a control outside the window.
/// </summary>
/// <remarks>
/// The window holds focus as one unit in the screen and drives its own controls, so add the leaf controls
/// (buttons, checkboxes, sliders, selectors) directly rather than wrapping them in another container. The
/// controls are placed in the window's own coordinates and drawn through <see cref="Surface.Region"/>,
/// which clips them to the window.
///
/// The window also answers the bumper and trigger buttons: L1 and R1 page focus by roughly a window's
/// worth of controls, L2 jumps to the first focusable and R2 to the last. When the menu has non-focusable
/// rows past the focus (labels or separators between a small button set and the end of the content), the
/// arrow keys and page keys fall back to a plain scroll once focus cannot move further, so a long
/// diagnostics or status panel can still be read all the way through. The scrollbar is drawn from the
/// current offset and content height each frame, so a page, a jump or an arrow all show up on the next
/// frame with no cached geometry.
/// </remarks>
public sealed class ScrollMenu : UiElement
{
    private readonly List<UiElement> _children = [];
    private readonly List<int> _tops = []; // each child's top in content coordinates, filled by the layout pass
    private int _focusIndex;
    private int _scroll;
    private int _contentHeight;

    /// <summary>How tall the window is. Default 240 pixels.</summary>
    public int ViewHeight { get; set; } = 240;

    /// <summary>The gap between controls, or -1 to use the theme's spacing (the default).</summary>
    public int Spacing { get; set; } = -1;

    /// <summary>Whether to draw a bar on the right showing the position. Default true.</summary>
    public bool ShowScrollBar { get; set; } = true;

    /// <summary>The controls, in order.</summary>
    public IReadOnlyList<UiElement> Children => _children;

    /// <summary>Adds <paramref name="child"/> to the bottom and returns this menu, so calls can chain.</summary>
    public ScrollMenu Add(UiElement child)
    {
        ArgumentNullException.ThrowIfNull(child);
        _children.Add(child);
        return this;
    }

    /// <summary>How far down the content is scrolled, in pixels.</summary>
    public int ScrollOffset => _scroll;

    /// <summary>How far the content can scroll, in pixels. Zero when everything already fits.</summary>
    public int MaxScroll => Math.Max(0, _contentHeight - ViewHeight);

    /// <summary>The control the window currently highlights, or null when it has no focusable control.</summary>
    public UiElement? FocusedChild
        => _focusIndex >= 0 && _focusIndex < _children.Count && _children[_focusIndex].IsFocusable ? _children[_focusIndex] : null;

    /// <summary>The menu takes focus when it has at least one focusable control.</summary>
    public override bool IsFocusable => Visible && FirstFocusable(0, +1) >= 0;

    /// <inheritdoc />
    public override int Measure(int width, UiTheme theme) => ViewHeight;

    /// <inheritdoc />
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        Bounds = bounds;
        // Keep the highlight on a focusable control, then place the children with the current scroll.
        if (_focusIndex < 0 || _focusIndex >= _children.Count || !_children[_focusIndex].IsFocusable)
        {
            int first = FirstFocusable(0, +1);
            if (first >= 0)
                _focusIndex = first;
        }
        LayoutChildren(theme);
    }

    /// <inheritdoc />
    internal override void CollectFocusables(List<UiElement> into)
    {
        // The window is one focus stop for the screen; it drives its own controls from there.
        if (Visible && IsFocusable)
            into.Add(this);
    }

    /// <inheritdoc />
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        UiElement? child = FocusedChild;
        // Offer the input to the focused control first, so it can confirm, toggle or adjust itself.
        if (child is not null && child.HandleInput(input, theme))
            return true;

        // Arrow keys try to move focus; when there is no focus target in that direction, they fall back
        // to a plain content scroll so a menu with more rows than focusable controls (a status panel with
        // one action button) is still fully reachable. At the edge of both, the input escapes so focus
        // can move to a neighbor outside the window.
        int row = Spacing >= 0 ? Math.Max(1, Spacing) : theme.RowHeight;
        if (input.Up)
            return MoveFocus(-1, theme) || ScrollBy(-row, theme);
        if (input.Down)
            return MoveFocus(+1, theme) || ScrollBy(+row, theme);

        // Page keys jump focus by a window's worth of controls, then fall back to a content scroll for
        // menus where nothing focusable sits far enough away.
        if (input.PageUp)
            return PageFocus(-ViewHeight, theme) || ScrollBy(-ViewHeight, theme);
        if (input.PageDown)
            return PageFocus(+ViewHeight, theme) || ScrollBy(+ViewHeight, theme);

        // Home and end jump focus to the extremes, then fall back to a scroll when focus was already
        // there.
        if (input.Home)
            return JumpFocus(first: true, theme) || ScrollTo(0, theme);
        if (input.End)
            return JumpFocus(first: false, theme) || ScrollTo(MaxScroll, theme);

        return false;
    }

    /// <inheritdoc />
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible)
            return;

        bool menuFocused = ReferenceEquals(focused, this);
        UiElement? childFocus = menuFocused ? FocusedChild : null;

        Surface view = surface.Region(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height);
        foreach (UiElement child in _children)
        {
            if (child.Visible)
                child.Draw(view, theme, childFocus);
        }

        if (!ShowScrollBar || MaxScroll <= 0)
            return;

        // The scroll bar geometry is read fresh from the window's own state each frame, so a page or a
        // jump or an arrow-key move all show up on the next frame with no cached values.
        const int barWidth = 4;
        int trackX = Bounds.Right - barWidth;
        surface.FillRect(trackX, Bounds.Y, barWidth, Bounds.Height, theme.Border);
        int content = Math.Max(1, _contentHeight);
        int thumbHeight = Math.Max(theme.Spacing, (int)((long)Bounds.Height * Bounds.Height / content));
        int travel = Math.Max(0, Bounds.Height - thumbHeight);
        int max = Math.Max(1, MaxScroll);
        int thumbY = Bounds.Y + (int)((long)travel * _scroll / max);
        surface.FillRect(trackX, thumbY, barWidth, thumbHeight, menuFocused ? theme.Accent : theme.TextMuted);
    }

    // Places the children top to bottom in the window's own coordinates, shifted up by the scroll, and
    // records each child's top so the scroll can bring a focused control into view.
    private void LayoutChildren(UiTheme theme)
    {
        int gap = Spacing >= 0 ? Spacing : theme.Spacing;
        _tops.Clear();
        int y = 0;
        bool first = true;
        foreach (UiElement child in _children)
        {
            if (!child.Visible)
            {
                _tops.Add(y);
                continue;
            }
            if (!first)
                y += gap;
            first = false;
            _tops.Add(y);
            int height = child.Measure(Bounds.Width, theme);
            child.Arrange(new UiRect(0, y - _scroll, Bounds.Width, height), theme);
            y += height;
        }
        _contentHeight = y;
        _scroll = Math.Clamp(_scroll, 0, MaxScroll);
    }

    // Moves the highlight to the next focusable control in the given step direction. Returns false at the
    // edge so the input falls through to the plain content scroll (and then to the screen).
    private bool MoveFocus(int step, UiTheme theme)
    {
        int next = FirstFocusable(_focusIndex + step, step);
        if (next < 0)
            return false;
        _focusIndex = next;
        ScrollToChild(next, theme);
        return true;
    }

    // Moves focus by roughly one window height in the given direction. Walks forward or backward past
    // the closest focusable at or beyond the paged distance; when nothing sits that far, it takes the
    // last focusable in that direction so a partial page still advances focus. Returns false when no
    // focusable exists in the direction — the caller then falls back to a plain scroll.
    private bool PageFocus(int delta, UiTheme theme)
    {
        if (_children.Count == 0)
            return false;
        int currentTop = _focusIndex >= 0 && _focusIndex < _tops.Count ? _tops[_focusIndex] : 0;
        int target = currentTop + delta;
        int next = -1;
        int fallback = -1;

        if (delta > 0)
        {
            for (int i = _focusIndex + 1; i < _children.Count; i++)
            {
                if (!_children[i].Visible || !_children[i].IsFocusable)
                    continue;
                fallback = i;
                if (_tops[i] >= target)
                {
                    next = i;
                    break;
                }
            }
        }
        else
        {
            for (int i = _focusIndex - 1; i >= 0; i--)
            {
                if (!_children[i].Visible || !_children[i].IsFocusable)
                    continue;
                fallback = i;
                if (_tops[i] <= target)
                {
                    next = i;
                    break;
                }
            }
        }

        int destination = next >= 0 ? next : fallback;
        if (destination < 0 || destination == _focusIndex)
            return false;
        _focusIndex = destination;
        ScrollToChild(destination, theme);
        return true;
    }

    // Jumps focus to the first or last focusable child. Returns false when focus is already there so the
    // caller can fall back to a plain scroll.
    private bool JumpFocus(bool first, UiTheme theme)
    {
        int target = first
            ? FirstFocusable(0, +1)
            : FirstFocusable(_children.Count - 1, -1);
        if (target < 0 || target == _focusIndex)
            return false;
        _focusIndex = target;
        ScrollToChild(target, theme);
        return true;
    }

    // Adjusts the scroll so the child at the given index sits fully within the window, then re-lays the
    // children so the change shows on this frame rather than the next.
    private void ScrollToChild(int index, UiTheme theme)
    {
        if (index < 0 || index >= _tops.Count)
            return;
        int top = _tops[index];
        int height = _children[index].Visible ? _children[index].Measure(Bounds.Width, theme) : 0;
        if (top < _scroll)
            _scroll = top;
        else if (top + height > _scroll + ViewHeight)
            _scroll = top + height - ViewHeight;
        LayoutChildren(theme);
    }

    // Moves the content by a fixed pixel delta, clamped to the window and re-arranged so the change is
    // reflected on this frame. Returns false when the scroll cannot move (already at the edge, or the
    // whole content fits).
    private bool ScrollBy(int delta, UiTheme theme)
    {
        if (MaxScroll <= 0)
            return false;
        int target = Math.Clamp(_scroll + delta, 0, MaxScroll);
        if (target == _scroll)
            return false;
        _scroll = target;
        LayoutChildren(theme);
        return true;
    }

    // Moves the content to a specific offset, clamped to the window. Returns false when the position
    // would not change.
    private bool ScrollTo(int offset, UiTheme theme)
    {
        int target = Math.Clamp(offset, 0, MaxScroll);
        if (target == _scroll)
            return false;
        _scroll = target;
        LayoutChildren(theme);
        return true;
    }

    // The index of the first focusable, visible child at or after `start` stepping by `step`, or -1.
    private int FirstFocusable(int start, int step)
    {
        for (int i = start; i >= 0 && i < _children.Count; i += step)
            if (_children[i].Visible && _children[i].IsFocusable)
                return i;
        return -1;
    }
}
