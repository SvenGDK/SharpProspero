// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// Holds a screen's usual content and, when asked, a panel on top of it. While a panel is open the
/// content behind is dimmed and takes no focus, so only the panel answers the controller — which is
/// what a confirmation needs before something is deleted or overwritten. Make this the root of a
/// screen and open a panel from a button.
/// </summary>
/// <remarks>
/// The panel is any control, so compose one from the controls already available: a
/// <see cref="StackPanel"/> holding a <see cref="TextBlock"/> and two <see cref="Button"/>s makes a
/// confirmation. Focus returns to the content when the panel closes.
/// </remarks>
/// <param name="content">The screen's usual content.</param>
public sealed class ModalHost(UiElement content) : UiElement
{
    private UiElement? _focusRestoreOnClose;
    private UiElement? _pendingFocusRestore;

    /// <summary>The screen's usual content, shown when no panel is open.</summary>
    public UiElement Content { get; set; } = content;

    /// <summary>The panel on top, or null when none is open.</summary>
    public UiElement? Modal { get; private set; }

    /// <summary>Whether a panel is currently open.</summary>
    public bool IsOpen => Modal is not null;

    /// <summary>How wide the panel is, as a share of the host. Default 0.7.</summary>
    public float ModalWidthFraction { get; set; } = 0.7f;

    /// <summary>How far the content behind is dimmed, from 0 (not at all) to 1. Default 0.6.</summary>
    public float DimAmount { get; set; } = 0.6f;

    /// <summary>Called after a panel closes.</summary>
    public Action? Closed { get; set; }

    /// <summary>Opens <paramref name="modal"/> on top of the content.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="modal"/> is null.</exception>
    public void Show(UiElement modal) => Show(modal, focusToRestoreOnClose: null);

    /// <summary>
    /// Opens <paramref name="modal"/> on top of the content and remembers
    /// <paramref name="focusToRestoreOnClose"/> so the underlying content's focus is restored once
    /// the modal closes. When null, focus falls back to the first focusable of the content on the
    /// following layout — matching the parameterless overload.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="modal"/> is null.</exception>
    public void Show(UiElement modal, UiElement? focusToRestoreOnClose)
    {
        ArgumentNullException.ThrowIfNull(modal);
        Modal = modal;
        _focusRestoreOnClose = focusToRestoreOnClose;
    }

    /// <summary>Closes the open panel, if any, and returns focus to the content.</summary>
    public void Close()
    {
        if (Modal is null)
            return;
        Modal = null;
        // Hand the saved element to the next layout pass through PopFocusRestoreCandidate so the
        // screen restores what was focused before Show ran, rather than snapping to the first
        // content focusable.
        _pendingFocusRestore = _focusRestoreOnClose;
        _focusRestoreOnClose = null;
        Closed?.Invoke();
    }

    /// <inheritdoc/>
    internal override bool HandleCancel()
    {
        // While a modal is open, cancel closes only the modal — the screen behind must not pop.
        if (Modal is null)
            return false;
        Close();
        return true;
    }

    /// <inheritdoc/>
    internal override UiElement? PopFocusRestoreCandidate()
    {
        UiElement? c = _pendingFocusRestore;
        _pendingFocusRestore = null;
        return c;
    }

    /// <inheritdoc/>
    public override int Measure(int width, UiTheme theme)
        => Content is null || !Content.Visible ? 0 : Content.Measure(width, theme);

    /// <inheritdoc/>
    internal override void Arrange(UiRect bounds, UiTheme theme)
    {
        Bounds = bounds;
        if (Content is not null && Content.Visible)
            Content.Arrange(bounds, theme);

        if (Modal is null || !Modal.Visible)
            return;

        // The panel is centred, as wide as its share of the host and as tall as it asks to be.
        int width = Math.Clamp((int)(bounds.Width * ModalWidthFraction), 1, bounds.Width);
        int inner = Math.Max(1, width - (2 * theme.Padding));
        int height = Math.Min(Modal.Measure(inner, theme) + (2 * theme.Padding), bounds.Height);
        int x = bounds.X + ((bounds.Width - width) / 2);
        int y = bounds.Y + ((bounds.Height - height) / 2);
        Modal.Arrange(new UiRect(x + theme.Padding, y + theme.Padding, inner, height - (2 * theme.Padding)), theme);
    }

    /// <inheritdoc/>
    internal override void CollectFocusables(List<UiElement> into)
    {
        if (!Visible)
            return;

        // While a panel is open only it answers the controller, so the content behind cannot be
        // reached by moving focus.
        if (Modal is not null && Modal.Visible)
        {
            Modal.CollectFocusables(into);
            return;
        }
        if (Content is not null && Content.Visible)
            Content.CollectFocusables(into);
    }

    /// <inheritdoc/>
    public override void Draw(Surface surface, UiTheme theme, UiElement? focused)
    {
        if (!Visible)
            return;
        if (Content is not null && Content.Visible)
            Content.Draw(surface, theme, focused);

        if (Modal is null || !Modal.Visible)
            return;

        surface.Region(Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height).Tint(Color.Black, DimAmount);

        // The panel's own rectangle is its arranged bounds grown by the padding it was inset by.
        UiRect m = Modal.Bounds;
        int pad = theme.Padding;
        surface.FillRoundedRect(m.X - pad, m.Y - pad, m.Width + (2 * pad), m.Height + (2 * pad), pad, theme.Panel);
        surface.DrawRoundedRect(m.X - pad, m.Y - pad, m.Width + (2 * pad), m.Height + (2 * pad), pad, theme.Border);
        Modal.Draw(surface, theme, focused);
    }
}
