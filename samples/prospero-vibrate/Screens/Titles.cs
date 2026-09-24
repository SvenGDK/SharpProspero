// Prospero Vibrate - Haptics that move You.

using SharpProspero.Graphics;
using SharpProspero.Ui;

namespace SampleApp.Screens;

/// <summary>
/// Shared helpers for building tab titles. When an outline title font is loaded the label uses it
/// directly; when it is not (the fallback path from the load failing) the label falls back to a
/// larger scale of the built-in bitmap text, so the tab still reads as a title.
/// </summary>
internal static class Titles
{
    public static Label BuildTitle(string text, ITextFont? titleFont)
    {
        if (titleFont is not null)
            return new Label(text) { Font = titleFont };
        return new Label(text) { Scale = 3 };
    }
}
