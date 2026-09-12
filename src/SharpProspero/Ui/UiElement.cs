// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System.Collections.Generic;

namespace SharpProspero.Ui;

/// <summary>
/// A control in the interface tree: a label, a button, a list, or a container of others. A screen lays
/// the tree out into rectangles, draws it, and routes the controller to the focused control. Derive
/// from this to add a control of your own; the built-in controls cover the common cases.
/// </summary>
public abstract class UiElement
{
    /// <summary>The rectangle the control was laid out into. Set by the layout pass; read it while drawing.</summary>
    public UiRect Bounds { get; internal set; }

    /// <summary>Whether the control takes part in layout, drawing and focus. Default true.</summary>
    public bool Visible { get; set; } = true;

    /// <summary>Whether the control can hold focus and receive the controller. Default false.</summary>
    public virtual bool IsFocusable => false;

    /// <summary>
    /// The height the control wants when laid out at <paramref name="width"/> pixels wide. A container
    /// returns the height its children need; a single-line control returns one row. Default: one row.
    /// </summary>
    public virtual int Measure(int width, UiTheme theme) => theme.RowHeight;

    /// <summary>
    /// Draws the control within its <see cref="Bounds"/>. <paramref name="focused"/> is the control that
    /// currently holds focus, so a control highlights itself when it is that one.
    /// </summary>
    public abstract void Draw(Surface surface, UiTheme theme, UiElement? focused);

    /// <summary>
    /// Handles a frame of input while the control holds focus. Return true when the input was used, so
    /// the screen does not also move focus with it. A list, for example, uses up and down to move its
    /// selection but leaves them unused at its top and bottom so focus can move to a neighbor. Default:
    /// the input is not used.
    /// </summary>
    public virtual bool HandleInput(UiInput input, UiTheme theme) => false;

    /// <summary>
    /// Adds this control and any focusable descendants to <paramref name="into"/>, in the order they are
    /// reached. A container overrides this to add its children.
    /// </summary>
    internal virtual void CollectFocusables(List<UiElement> into)
    {
        if (Visible && IsFocusable)
            into.Add(this);
    }

    /// <summary>
    /// Places the control (and any children) within <paramref name="bounds"/>. A container overrides
    /// this to position its children; a leaf keeps the bounds it was given.
    /// </summary>
    internal virtual void Arrange(UiRect bounds, UiTheme theme) => Bounds = bounds;

    /// <summary>Vertically centers a single line of the theme font's text within <paramref name="bounds"/>.</summary>
    private protected static int CenterTextY(UiRect bounds, UiTheme theme)
        => bounds.Y + (bounds.Height - theme.LineHeight) / 2;
}
