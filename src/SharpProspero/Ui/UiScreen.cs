// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// Hosts a tree of controls: it lays them out into a rectangle, moves focus around with the controller,
/// and draws them. A typical screen wraps a <see cref="StackPanel"/> of labels, buttons and lists.
/// </summary>
/// <remarks>
/// Each frame, call <see cref="Layout"/> (or <see cref="Render"/>) to place the controls, then
/// <see cref="Update"/> with this frame's input, then <see cref="Draw"/>. The focused control is offered
/// the input first, so a list scrolls within itself and a button activates; whatever it does not use
/// moves focus to a neighbor, and the cancel button raises <see cref="Cancelled"/>.
/// </remarks>
/// <example>
/// <code>
/// var menu = new StackPanel()
///     .Add(new Label("Settings") { Scale = 3 })
///     .Add(new Button("Start", () => StartGame()))
///     .Add(new Checkbox("Fullscreen", true))
///     .Add(new Button("Quit", () => context.RequestExit()));
/// var screen = new UiScreen(menu);
///
/// // each frame:
/// screen.Layout(new UiRect(60, 60, surface.Width - 120, surface.Height - 120));
/// screen.Update(UiInput.From(context.Input, context.PreviousInput));
/// surface.Clear(screen.Theme.Background);
/// screen.Draw(surface);
/// </code>
/// </example>
public sealed class UiScreen
{
    private readonly List<UiElement> _focusables = [];

    /// <summary>Creates a screen showing <paramref name="root"/>, drawn with <paramref name="theme"/>.</summary>
    /// <param name="root">The top of the control tree, usually a <see cref="StackPanel"/>.</param>
    /// <param name="theme">The colors and spacing to draw with, or null for the default theme.</param>
    public UiScreen(UiElement root, UiTheme? theme = null)
    {
        ArgumentNullException.ThrowIfNull(root);
        Root = root;
        Theme = theme ?? UiTheme.Default;
    }

    /// <summary>The top of the control tree.</summary>
    public UiElement Root { get; }

    /// <summary>The colors and spacing the screen draws with.</summary>
    public UiTheme Theme { get; }

    /// <summary>The control that currently holds focus, or null when nothing is focusable.</summary>
    public UiElement? Focused { get; private set; }

    /// <summary>Called when the user presses cancel and no control used it (for going back).</summary>
    public Action? Cancelled { get; set; }

    /// <summary>
    /// Sets <paramref name="candidate"/> as the focus a following <see cref="Layout"/> call will
    /// try to hold onto. When the candidate is not in the next layout's focusable set, Layout
    /// falls back to the first focusable as usual; when it is, focus stays put.
    /// </summary>
    /// <remarks>
    /// Used across a rebuild of the same page: the caller re-creates the control tree, remembers
    /// the previously focused element (a field on the caller, so the reference identity survives
    /// the tree rebuild), and hands it back through this method so the arrow-key navigation the
    /// user was drawing on the old tree keeps working on the new one.
    /// </remarks>
    public void RestoreFocus(UiElement candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        Focused = candidate;
    }

    /// <summary>
    /// Places the control tree within <paramref name="area"/> and refreshes the set of focusable
    /// controls. Call this before <see cref="Update"/> whenever the tree or the area may have changed;
    /// it is cheap enough to call every frame.
    /// </summary>
    public void Layout(UiRect area)
    {
        Root.Arrange(area, Theme);
        _focusables.Clear();
        Root.CollectFocusables(_focusables);
        if (Focused is null || !_focusables.Contains(Focused))
            Focused = _focusables.Count > 0 ? _focusables[0] : null;
    }

    /// <summary>
    /// Routes one frame of <paramref name="input"/>: the focused control is offered it first, then
    /// anything left over moves focus in the pressed direction, and cancel raises <see cref="Cancelled"/>.
    /// </summary>
    public void Update(UiInput input)
    {
        if (Focused is not null && Focused.HandleInput(input, Theme))
            return;

        if (input.Direction is UiDirection direction)
        {
            UiElement? next = FocusNavigator.Next(_focusables, Focused, direction);
            if (next is not null)
                Focused = next;
            return;
        }

        if (input.Cancel)
            Cancelled?.Invoke();
    }

    /// <summary>Draws the control tree, highlighting the focused control.</summary>
    public void Draw(Surface surface)
    {
        if (Root.Visible)
            Root.Draw(surface, Theme, Focused);
    }

    /// <summary>
    /// Lays the tree out to fill <paramref name="surface"/> (leaving a <paramref name="margin"/> around
    /// the edge) and draws it, without clearing the background. Call <see cref="Update"/> before this to
    /// take the frame's input into account.
    /// </summary>
    public void Render(Surface surface, int margin = 0)
    {
        Layout(new UiRect(margin, margin, surface.Width - 2 * margin, surface.Height - 2 * margin));
        Draw(surface);
    }
}
