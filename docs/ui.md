---
title: Interface toolkit
parent: Application Modules
nav_order: 8
---

# Interface toolkit

`SharpProspero.Ui` builds screens out of controls — labels, buttons, lists, checkboxes and progress
bars — and drives them with the controller, so an application does not draw pixels by hand. Add the
controls to a screen, and each frame hand it the input and let it draw. It runs on the same drawing
surface as the rest of the SDK, so it composes with anything you draw yourself.

<details open markdown="block">
  <summary>On this page</summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## The idea

A `UiScreen` holds a tree of controls, usually a `StackPanel` of them. Each frame you:

1. **Lay it out** into a rectangle (`Layout`), which places every control and finds the focusable ones.
2. **Update** it with the frame's input (`Update`), which offers the input to the focused control and
   otherwise moves focus in the pressed direction.
3. **Draw** it (`Draw`), which renders the tree and highlights the focused control.

The controller drives it: the d-pad moves focus, cross confirms, and circle goes back.

## A screen in a frame loop

```csharp
using SharpProspero.Application;
using SharpProspero.Graphics;
using SharpProspero.Ui;

internal sealed class Menu : ProsperoApp
{
    private UiScreen _screen = null!;

    protected override void OnLoad()
    {
        var panel = new StackPanel()
            .Add(new Label("My Application") { Scale = 4 })
            .Add(new Button("Start", () => StartGame()))
            .Add(new Checkbox("Fullscreen", true))
            .Add(new Button("Quit", () => Exit()));

        _screen = new UiScreen(panel);
    }

    protected override void OnFrame(FrameContext context)
    {
        Surface surface = context.Surface;

        _screen.Layout(new UiRect(80, 80, surface.Width - 160, surface.Height - 160));
        _screen.Update(UiInput.From(context.Input, context.PreviousInput));

        surface.Clear(_screen.Theme.Background);
        _screen.Draw(surface);

        if (_exit)
            context.RequestExit();
    }

    private void StartGame() { /* ... */ }
    private void Exit() => _exit = true;
    private bool _exit;
}
```

`UiInput.From` reads the d-pad, cross and circle from this frame's sample and the previous one, so each
press counts once. `Render` combines the layout and draw steps when you do not need them apart.

## More than one screen

An application with more than one page — a main menu that opens settings, which opens a sub-page — uses
a `ScreenStack`. Push a screen to go forward and pop to go back; only the top screen is laid out, updated
and drawn, and by default cancel on a pushed screen returns to the one before it. Drive it exactly like a
single screen:

```csharp
var nav = new ScreenStack(mainMenu);
mainMenu.Cancelled = () => context.RequestExit();      // cancel on the first screen leaves the app
settingsButton.Activated = () => nav.Push(settingsScreen);

// each frame:
nav.Update(UiInput.From(context.Input, context.PreviousInput));
surface.Clear(nav.Current.Theme.Background);
nav.Render(surface, margin: 80);
```

`Push` gives a screen a cancel handler that pops the stack unless it already has one of its own, so back
navigation needs no wiring. `Replace` swaps the top screen without growing the stack, and `PopToRoot`
returns to the first screen.

## Controls

| Control | What it is |
|---|---|
| `Label` | A line of text, for titles and read-only values. Not focusable. |
| `Button` | Activates on confirm and calls its action. Can be disabled. |
| `Checkbox` | An on/off setting the user toggles with confirm. |
| `Slider` | A value between a minimum and a maximum, moved by a fixed step with left and right. The step is required; a step of zero or less is treated as one. |
| `Stepper` | A whole number in a range, adjusted with left and right; clamps at the ends and can format its value (for example "50%" or "x3"). |
| `OptionSelector` | One choice from a fixed set, cycled with left and right (wraps at the ends). |
| `Carousel` | A horizontal strip of items with one highlighted in the middle, moved with left and right and chosen with confirm - the shape a launcher uses. |
| `RadioGroup` | One choice from a fixed set with every option shown at once, moved with up and down. |
| `TextBox` | A field that raises its action on confirm, where the application opens the on-screen keyboard to edit the text. |
| `ListView` | A vertical list the user moves through and opens with confirm; it scrolls to keep the selection in view. |
| `ProgressBar` | A bar that fills from the left to show a fraction that is known. |
| `Gauge` | A round meter that fills a ring or a dial to a known fraction, with the percentage in the middle. Not focusable. |
| `Spinner` | A turning ring that shows work is under way with no known end. Call `Advance(deltaSeconds)` on it each frame or it draws stationary. Not focusable. |
| `Image` | A picture drawn from a surface (for example a decoded `PngImage`). |
| `TextBlock` | A paragraph that wraps to its width and grows as tall as it needs. Not focusable. |
| `Separator` | A rule that divides one group of controls from the next. Not focusable. |
| `TabView` | A row of named tabs showing one page at a time; left and right change the page. |
| `KeyValueRow` | A name on the left and its value on the right; the value is shortened when the row is too narrow. Not focusable. |
| `StackPanel` | Stacks its children top to bottom with a gap between them; the usual root of a screen. |
| `Row` | Places its children side by side, each an equal share of the width. |
| `Grid` | Arranges its children in a fixed number of columns, wrapping to the next row. |
| `ScrollView` | A window onto content taller than the space available; up and down move it. |
| `ScrollMenu` | A column of controls taller than the space available; up and down move a highlight through them, scrolling to keep it in view. |
| `ModalHost` | Holds the usual content and, when asked, a panel on top of it that takes the controller. |

`TextBlock` lays its text out with the built-in text at the theme's scale. Give it a `Font` to use a
loaded outline font instead:

```csharp
var notes = new TextBlock("A longer description that wraps to the width it is given.")
{
    Alignment = TextAlignment.Left,
    Font = myFont,          // any ITextFont; omit for the built-in text
};
```

`TabView` divides a tool into sections without a screen for each. Focus lands on the tab row, where left
and right change the page, and moving down goes into that page's controls:

```csharp
var tabs = new TabView();
tabs.Add("Files", filesPanel);
tabs.Add("System", systemPanel);
tabs.SelectionChanged = index => Log.Info($"tab {index}");
```

A column of `KeyValueRow` is the readable way to present what a tool has found, and a `ScrollView`
carries it when there is more than fits:

```csharp
var details = new StackPanel()
    .Add(new KeyValueRow("System version", version))
    .Add(new KeyValueRow("Free space", size));

var scroller = new ScrollView(details) { ViewHeight = 300 };
```

`ScrollView` takes focus only when there is more content than fits, and leaves up and down unused at
either end so focus moves on instead of getting stuck. Content inside it is placed relative to the
window rather than the screen, which is what clips it.

Before something is deleted or overwritten, ask first. Make `ModalHost` the root of the screen and open
a panel from a button; while it is open the content behind is dimmed and takes no focus, so the panel
is the only thing that answers:

```csharp
var host = new ModalHost(mainPanel);
var screen = new UiScreen(host);

deleteButton.Activated = () =>
{
    var confirm = new StackPanel()
        .Add(new TextBlock("Delete this save? This cannot be undone."))
        .Add(new Button("Delete", () => { Delete(); host.Close(); }))
        .Add(new Button("Cancel", host.Close));
    host.Show(confirm);
};
```

The panel is any control, so a confirmation is composed from the controls already available. `Closed`
is called after it closes, and focus returns to the content.

The two panels an application asks for most — a message to acknowledge and a question to answer — are
built by `MessageBox`, so the common case is one call instead of a hand-assembled panel:

```csharp
MessageBox.Confirm(host, "Delete?", "This cannot be undone.", onConfirm: Delete);
MessageBox.Alert(host, "Done", "The file was saved.");
```

Each button closes the panel and then runs what you passed. To let cancel dismiss it as well, point the
screen's cancel at the host: `screen.Cancelled = () => host.Close();`.

`StackPanel` stacks downwards; `Row` lays across, giving each child an equal share of the width. Put
the two together for a pair of buttons at the foot of a panel:

```csharp
var buttons = new Row()
    .Add(new Button("Delete", Delete))
    .Add(new Button("Cancel", host.Close));
```

The row is as tall as its tallest child, the last column takes any width left over by rounding, and
hidden children take no room. Left and right move focus along it.

## Telling the user something happened

`Toast` shows a short message over whatever is on screen and takes itself down — "Saved", "Copied",
"Nothing to do". It holds no focus and no layout space, so it is not part of the control tree: drive it
from the frame loop and draw it after the screen so it sits on top.

```csharp
var toast = new Toast();
saveButton.Activated = () => { Save(); toast.Show("Saved"); };

// each frame
toast.Update((float)context.DeltaSeconds);
screen.Render(surface);
toast.Draw(surface, screen.Theme);
```

`Show` replaces anything already up, `Hide` takes it down at once, and the banner fades over its last
moment rather than vanishing.

A `Spinner` is driven the same way — it is part of the control tree, but the turn is yours to advance:

```csharp
var busy = new Spinner();
// each frame, before the screen draws:
busy.Advance((float)context.DeltaSeconds);
busy.Visible = stillLoading;
```

A `ListView` handles up and down itself to move its selection, but leaves them unused at its top and
bottom rows, so pressing up on the first row or down on the last moves focus to the control above or
below the list. This is what lets a list sit among other controls.

## Focus moves the way you expect

Pressing a direction moves focus to the nearest focusable control that way, measured from the centers
and favouring one that stays on the line over one that drifts to the side. A screen laid out as a
column moves straight down it; a screen with controls side by side moves across. The focused control is
offered the input first, so a button activates and a list scrolls before focus moves.

`UiInput.From` reports each press once, so holding a direction moves one step. To let a held direction
repeat — for scrolling a long list or dragging a slider without a press per step — keep a `UiRepeater`
and read the input through it instead:

```csharp
var repeater = new UiRepeater();          // hold to repeat: one step, a pause, then a steady rate
// each frame:
screen.Update(repeater.Update(context.Input, (float)context.DeltaSeconds));
```

Confirm and cancel are still reported once, so they never repeat. Call `repeater.Reset()` when focus
jumps somewhere new so a held direction does not carry a repeat into it.

## More controls than fit

When a settings form has more controls than the screen has room for, put them in a `ScrollMenu`. It holds
focus as one unit and moves a highlight through its controls with up and down, scrolling to keep the
focused control in view; confirm and adjust reach whichever control is focused. Up on the first control
and down on the last are left for the screen, so focus can move out of the window.

Add the leaf controls — buttons, checkboxes, sliders, selectors — to the menu itself. The highlight only
visits its direct children, so a `StackPanel`, `Row` or `Grid` placed inside is drawn but never takes it,
and neither does anything within it.

```csharp
var options = new ScrollMenu { ViewHeight = 320 }
    .Add(new Checkbox("Fullscreen", true))
    .Add(new Slider("Volume", 0, 100, 80, step: 5))
    .Add(new Button("Reset", () => ResetSettings()));
var screen = new UiScreen(options);
```

`ScrollView` scrolls read-only content as a block and `ListView` scrolls a list of items to pick from;
`ScrollMenu` is for a column of controls the user operates in place.

## Theming

`UiTheme` holds the colors, spacing and font every control draws with. Use `UiTheme.Default` for a dark
theme, or change what you want with an object initializer and pass it to the screen:

```csharp
var theme = new UiTheme
{
    Accent = Color.FromRgb(255, 170, 60),
    TextScale = 3,
};
var screen = new UiScreen(panel, theme);
```

By default the interface draws with the built-in bitmap text at `TextScale`. Set `Font` to a loaded
outline font for crisp antialiased text everywhere - every control measures and draws through the theme
font, so one line changes the whole interface:

```csharp
using var module = SystemModule.Load(SystemModuleId.Font);
using var backend = SystemModule.Load(SystemModuleId.FontFt);
using var font = SystemFont.Open(SceFontSet.StdEuropeanW1G, pixelSize: 22);

var theme = new UiTheme { Font = font };   // controls now render in the system font
```

`LineHeight` and `RowHeight` follow the chosen font, so layouts size themselves to it. A `TrueTypeFont`
loaded from a file works the same way. Keep the font alive for as long as the theme is used.

## A control of your own

Derive from `UiElement` for a control the built-in set does not cover. Override `Measure` to say how
tall it wants to be, `Draw` to render within its `Bounds`, and, if it is interactive, `IsFocusable` and
`HandleInput`. Return true from `HandleInput` when you use the input so the screen does not also move
focus with it.

## Saving what is on screen

Anything drawn to a surface can be saved as a PNG with [`PngEncoder`](graphics.md#screenshots-and-photo-export), so a screen can
offer a screenshot:

```csharp
using var module = SystemModule.Load(SystemModuleId.PngEnc);
PngEncoder.Save(context.Surface, "/data/screenshot.png");
```
