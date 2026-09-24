// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK
using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A window onto content taller than the space available. The content is laid out at its full height
/// and drawn through the window, so anything past the edge is clipped; up and down move the content
/// when there is more to see, and are left unused at either end so focus can move on. Put a
/// <see cref="StackPanel"/> of read-only content inside it — labels, key-value rows, a paragraph — to
/// scroll a long block.
/// </summary>
/// <remarks>
/// The view scrolls as one: it holds focus itself and moves the content, and the controls inside it do
/// not take focus separately (they would scroll out from under the focus). For a long list the user
/// picks from, use <see cref="ListView"/>, which scrolls to keep the selection in view. The content is
/// placed relative to the window rather than the screen, so a control inside reads its
/// <see cref="UiElement.Bounds"/> in the window's own coordinates; drawing goes through
/// <see cref="Surface.Region"/>, which is what clips it.
///
/// The window listens to the bumper and trigger buttons as well as the d-pad: L1 and R1 page the
/// content by a full window height, L2 jumps to the top and R2 to the bottom. The scrollbar reads
/// the current offset and content height at draw time, so paging, jumping and a resized content
/// panel all show up on the next frame without cached geometry.
/// </remarks>
/// <param name="content">The content to show.</param>
public sealed class ScrollView(UiElement content) : UiElement
{
    private int _scroll;
    private int _contentHeight;

    /// <summary>The content shown through the window.</summary>
    public UiElement Content { get; set; } = content;

    /// <summary>How tall the window is. Default 240 pixels.</summary>
    public int ViewHeight { get; set; } = 240;

    /// <summary>How far one press moves the content, or -1 to use the theme's row height (the default).</summary>
    public int ScrollStep { get; set; } = -1;

    /// <summary>Whether to draw a bar on the right showing the position. Default true.</summary>
    public bool ShowScrollBar { get; set; } = true;

    /// <summary>How far down the content is scrolled, in pixels.</summary>
    public int ScrollOffset => _scroll;

    /// <summary>How far the content can scroll, in pixels. Zero when it already fits.</summary>
    public int MaxScroll => Math.Max(0, _contentHeight - ViewHeight);

    /// <summary>The window takes focus only when there is more content than fits.</summary>
    public override bool IsFocusable => MaxScroll > 0;

    /// <summary>Moves the content by <paramref name="delta"/> pixels, stopping at either end.</summary>
    /// <returns>True when the position actually changed.</returns>
    public bool ScrollBy(int delta)
    {
        int target = Math.Clamp(_scroll + delta, 0, MaxScroll);
        if (target == _scroll)
            return false;
        _scroll = target;
        return true;
    }

    /// <summary>Moves the content to <paramref name="offset"/> pixels from the top, clamped to the window.</summary>
    /// <returns>True when the position actually changed.</returns>
    public bool ScrollTo(int offset)
    {
        int target = Math.Clamp(offset, 0, MaxScroll);
        if (target == _scroll)
            return false;
        _scroll = target;
        return true;
    }

    /// <summary>Moves the content back to the top.</summary>
    public void ScrollToTop() => _scroll = 0;

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
    {
        _contentHeight = Content is null || !Content.Visible ? 0 : Content.Measure(width, theme);
        return ViewHeight;
    }

    /// <inheritdoc/>
    public override bool HandleInput(UiInput input, UiTheme theme)
    {
        if (MaxScroll <= 0)
            return false;
        int step = ScrollStep >= 0 ? ScrollStep : theme.RowHeight;
        if (input.Down)
            return ScrollBy(step);
        if (input.Up)
            return ScrollBy(-step);
        if (input.PageDown)
            return ScrollBy(ViewHeight);
        if (input.PageUp)
            return ScrollBy(-ViewHeight);
        if (input.Home)
            return ScrollTo(0);
        if (input.End)
            return ScrollTo(MaxScroll);
        return false;
    }

    /// <inheritdoc/>
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        Bounds = bounds;
        if (Content is null || !Content.Visible)
            return;

        _contentHeight = Content.Measure(bounds.Width, theme);
        _scroll = Math.Clamp(_scroll, 0, MaxScroll);

        // Placed in the window's own coordinates: the top of the content sits at minus the scroll
        // position, so drawing through the window shows the part that is in view.
        Content.Arrange(new UiRect(0, -_scroll, bounds.Width, _contentHeight), theme);
    }

    /// <inheritdoc/>
    internal override void CollectFocusables(List<UiElement> into)
    {
        if (!Visible)
            return;
        if (IsFocusable)
            into.Add(this);
    }

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible || Content is null || !Content.Visible)
            return;

        Surface view = surface.Region(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height);
        Content.Draw(view, theme, focused);

        if (!ShowScrollBar || MaxScroll <= 0)
            return;

        // A bar on the right whose length is the share of the content in view and whose position is how
        // far down that share sits. Every value is read fresh from the window's own state at draw time,
        // so a page, a jump or an arrow-key move all reflect on the next frame with no cached geometry.
        const int barWidth = 4;
        int trackX = Bounds.Right - barWidth;
        surface.FillRect(trackX, Bounds.Y, barWidth, Bounds.Height, theme.Border);

        int content = Math.Max(1, _contentHeight);
        int thumbHeight = Math.Max(theme.Spacing, (int)((long)Bounds.Height * Bounds.Height / content));
        int travel = Math.Max(0, Bounds.Height - thumbHeight);
        int max = Math.Max(1, MaxScroll);
        int thumbY = Bounds.Y + (int)((long)travel * _scroll / max);
        surface.FillRect(trackX, thumbY, barWidth, thumbHeight,
            ReferenceEquals(focused, this) ? theme.Accent : theme.TextMuted);
    }
}
