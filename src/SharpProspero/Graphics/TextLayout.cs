// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Globalization;
using SharpProspero.Globalization.Text;
using System;
using System.Collections.Generic;

namespace SharpProspero.Graphics;

/// <summary>Where a line of text sits within the width it is given.</summary>
public enum TextAlignment
{
    /// <summary>Against the left edge.</summary>
    Left,

    /// <summary>Centred in the width.</summary>
    Center,

    /// <summary>Against the right edge.</summary>
    Right,

    /// <summary>
    /// Against the reading-start edge — the left edge in a left-to-right paragraph, the right
    /// edge in a right-to-left one. Resolved against <see cref="Culture.Current"/> at draw time.
    /// </summary>
    Start,

    /// <summary>
    /// Against the reading-end edge — the right edge in a left-to-right paragraph, the left
    /// edge in a right-to-left one. Resolved against <see cref="Culture.Current"/> at draw time.
    /// </summary>
    End,
}

/// <summary>
/// Fits text to a width: breaking a paragraph into lines, shortening a label that will not fit, and
/// drawing either one aligned in a rectangle. Everything measures through an <see cref="ITextFont"/>,
/// so the same layout serves the built-in text and a loaded outline font.
/// </summary>
public static class TextLayout
{
    /// <summary>
    /// Breaks <paramref name="text"/> into lines no wider than <paramref name="maxWidth"/>, splitting at
    /// spaces. A line break in the text starts a new line. A single word too wide to fit is split across
    /// lines rather than overflowing.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="font"/> is null.</exception>
    public static List<string> Wrap(ITextFont font, string? text, int maxWidth)
    {
        ArgumentNullException.ThrowIfNull(font);
        var lines = new List<string>();
        if (string.IsNullOrEmpty(text))
            return lines;

        // Without a usable width there is nothing to fit to, so each paragraph stays whole.
        if (maxWidth <= 0)
        {
            foreach (string whole in text.Split('\n'))
                lines.Add(whole.TrimEnd('\r'));
            return lines;
        }

        foreach (string paragraph in text.Split('\n'))
            WrapParagraph(font, paragraph.TrimEnd('\r'), maxWidth, lines);
        return lines;
    }

    private static void WrapParagraph(ITextFont font, string paragraph, int maxWidth, List<string> lines)
    {
        ReadOnlySpan<char> span = paragraph;
        if (span.Length == 0)
        {
            lines.Add(string.Empty);
            return;
        }

        int lineStart = 0, lineEnd = 0, i = 0;
        while (i < span.Length)
        {
            int wordStart = i;
            while (wordStart < span.Length && span[wordStart] == ' ')
                wordStart++;
            if (wordStart >= span.Length)
                break;

            int wordEnd = wordStart;
            while (wordEnd < span.Length && span[wordEnd] != ' ')
                wordEnd++;

            if (font.MeasureText(span[lineStart..wordEnd]) <= maxWidth)
            {
                lineEnd = wordEnd;
                i = wordEnd;
                continue;
            }

            // The word pushes the line past the width. Close the line if it already holds something,
            // otherwise the word alone is too wide and is split so the layout still makes progress.
            if (lineEnd > lineStart)
            {
                lines.Add(span[lineStart..lineEnd].ToString());
                lineStart = lineEnd = wordStart;
                continue;
            }

            int fit = LargestPrefix(font, span[wordStart..wordEnd], maxWidth);
            lines.Add(span.Slice(wordStart, fit).ToString());
            lineStart = lineEnd = i = wordStart + fit;
        }

        if (lineEnd > lineStart)
            lines.Add(span[lineStart..lineEnd].ToString());
        else if (lines.Count == 0)
            lines.Add(string.Empty);
    }

    // The longest run from the start of the text that fits, never less than one character so a caller
    // splitting a word always advances.
    private static int LargestPrefix(ITextFont font, ReadOnlySpan<char> text, int maxWidth)
    {
        int low = 1, high = text.Length, best = 1;
        while (low <= high)
        {
            int mid = (low + high) / 2;
            if (font.MeasureText(text[..mid]) <= maxWidth)
            {
                best = mid;
                low = mid + 1;
            }
            else
            {
                high = mid - 1;
            }
        }
        return best;
    }

    /// <summary>
    /// The size the wrapped block of <paramref name="text"/> occupies: the widest line and the total
    /// height of every line.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="font"/> is null.</exception>
    public static (int Width, int Height) MeasureWrapped(ITextFont font, string? text, int maxWidth)
    {
        ArgumentNullException.ThrowIfNull(font);
        List<string> lines = Wrap(font, text, maxWidth);
        int widest = 0;
        foreach (string line in lines)
        {
            int width = font.MeasureText(line);
            if (width > widest)
                widest = width;
        }
        return (widest, lines.Count * font.LineHeight);
    }

    /// <summary>
    /// Draws <paramref name="text"/> wrapped to <paramref name="width"/> starting at
    /// (<paramref name="x"/>, <paramref name="y"/>), each line placed by <paramref name="alignment"/>.
    /// </summary>
    /// <returns>The height, in pixels, the drawn block occupies.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="font"/> is null.</exception>
    public static int DrawWrapped(
        Surface surface, ITextFont font, string? text, int x, int y, int width,
        Color color, TextAlignment alignment = TextAlignment.Left)
    {
        ArgumentNullException.ThrowIfNull(font);
        List<string> lines = Wrap(font, text, width);
        int lineY = y;
        foreach (string line in lines)
        {
            DrawAligned(surface, font, line, x, lineY, width, color, alignment);
            lineY += font.LineHeight;
        }
        return lines.Count * font.LineHeight;
    }

    /// <summary>
    /// Draws one line of <paramref name="text"/> placed by <paramref name="alignment"/> within
    /// <paramref name="width"/> starting at (<paramref name="x"/>, <paramref name="y"/>).
    /// <see cref="TextAlignment.Start"/> and <see cref="TextAlignment.End"/> resolve against
    /// <see cref="Culture.Current"/> so the same call places text on the reading-start edge in
    /// both directions.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="font"/> is null.</exception>
    public static void DrawAligned(
        Surface surface, ITextFont font, string? text, int x, int y, int width,
        Color color, TextAlignment alignment = TextAlignment.Left)
    {
        ArgumentNullException.ThrowIfNull(font);
        if (string.IsNullOrEmpty(text))
            return;
        int textWidth = font.MeasureText(text);
        int drawX = ResolveDrawX(alignment, x, width, textWidth, Culture.Current.Direction);
        font.DrawText(surface, text, drawX, y, color);
    }

    // The x-coordinate where a line of <paramref name="textWidth"/> pixels should start given the
    // requested alignment and the ambient paragraph direction. Start/End collapse to Left/Right
    // per direction; the other three alignments are direction-independent.
    private static int ResolveDrawX(TextAlignment alignment, int x, int width, int textWidth, TextDirection direction)
    {
        return alignment switch
        {
            TextAlignment.Left => x,
            TextAlignment.Center => x + ((width - textWidth) / 2),
            TextAlignment.Right => x + width - textWidth,
            TextAlignment.Start => direction == TextDirection.Rtl ? x + width - textWidth : x,
            TextAlignment.End => direction == TextDirection.Rtl ? x : x + width - textWidth,
            _ => x,
        };
    }

    /// <summary>
    /// Shortens <paramref name="text"/> so it fits <paramref name="maxWidth"/>, ending it with
    /// <paramref name="ellipsis"/> when anything was dropped. Text that already fits is returned as it is.
    /// Use this for a name in a list rather than letting it run past its column. The ellipsis is
    /// placed at the reading-end of the string, which is the trailing side in both directions: in
    /// LTR that is the visual right, in RTL the visual left, because RTL callers typically pass
    /// the source in logical order and the visual mirror is applied when the string is drawn.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="font"/> is null.</exception>
    public static string Truncate(ITextFont font, string? text, int maxWidth, string ellipsis = "...")
    {
        ArgumentNullException.ThrowIfNull(font);
        if (string.IsNullOrEmpty(text))
            return string.Empty;
        if (maxWidth <= 0)
            return string.Empty;
        if (font.MeasureText(text) <= maxWidth)
            return text;

        ellipsis ??= string.Empty;
        int ellipsisWidth = font.MeasureText(ellipsis);

        // No room for even the marker, so fall back to as much of the text as fits.
        if (ellipsisWidth >= maxWidth)
            return text[..LargestPrefix(font, text, maxWidth)];

        int room = maxWidth - ellipsisWidth;
        ReadOnlySpan<char> span = text;
        int low = 0, high = text.Length, best = 0;
        while (low <= high)
        {
            int mid = (low + high) / 2;
            if (font.MeasureText(span[..mid]) <= room)
            {
                best = mid;
                low = mid + 1;
            }
            else
            {
                high = mid - 1;
            }
        }
        return string.Concat(span[..best].TrimEnd(), ellipsis);
    }

    /// <summary>
    /// A single laid-out line yielded by <see cref="EnumerateLines"/>: the character range within
    /// the source paragraph the line covers and the resolved paragraph direction (used by the
    /// caller when placing runs).
    /// </summary>
    public readonly struct Line
    {
        internal Line(int startIndex, int length, TextDirection direction)
        {
            StartIndex = startIndex;
            Length = length;
            Direction = direction;
        }

        /// <summary>The index within the source string where this line begins.</summary>
        public int StartIndex { get; }

        /// <summary>The character count of this line.</summary>
        public int Length { get; }

        /// <summary>The paragraph direction the line inherits.</summary>
        public TextDirection Direction { get; }
    }

    /// <summary>
    /// Lays out <paramref name="text"/> into lines that fit <paramref name="maxWidth"/>. Breaks
    /// are chosen with the UAX #14 line-break iterator so hyphen/dash/zero-width-space/CJK
    /// boundaries all break correctly; mandatory breaks (BK, CR, LF, NL) start a new line no
    /// matter the width. The paragraph direction is resolved once (via
    /// <see cref="TextDirections.Resolve"/>) and stamped on every returned line so callers can
    /// place runs with a consistent base.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="font"/> is null.</exception>
    public static List<Line> EnumerateLines(
        ITextFont font, string? text, int maxWidth, LanguageTag? language = null, TextDirection direction = TextDirection.Auto)
    {
        ArgumentNullException.ThrowIfNull(font);
        var lines = new List<Line>();
        if (string.IsNullOrEmpty(text) || maxWidth <= 0)
            return lines;

        TextDirection resolved = TextDirections.Resolve(direction, text, language ?? Culture.Current.Language);

        // The UAX #14 iterator hands back every allowed break plus the mandatory ones; the greedy
        // walk below fits as many opportunities as the width allows before starting a new line.
        List<int> opportunities = new List<int>();
        HashSet<int> mandatory = new HashSet<int>();
        {
            var iter = new LineBreaker(text.AsSpan());
            while (iter.MoveNext())
            {
                opportunities.Add(iter.Current);
                if (iter.CurrentOpportunity == LineBreakOpportunity.Mandatory)
                    mandatory.Add(iter.Current);
            }
        }

        int lineStart = 0;
        int lastGoodEnd = 0;
        int oi = 0;
        while (oi < opportunities.Count)
        {
            int end = opportunities[oi];
            if (end <= lineStart)
            {
                oi++;
                continue;
            }
            bool isMandatory = mandatory.Contains(end);
            var window = text.AsSpan(lineStart, end - lineStart);
            int width = font.MeasureText(window);

            if (isMandatory)
            {
                // A mandatory break must not itself carry a line wider than the width. When the
                // segment past `lastGoodEnd` also over-runs, first emit the accumulated soft
                // break, then let the residual pass split the tail down to the mandatory position.
                if (width > maxWidth && lastGoodEnd > lineStart)
                {
                    lines.Add(new Line(lineStart, lastGoodEnd - lineStart, resolved));
                    lineStart = lastGoodEnd;
                    // Re-process the same mandatory opportunity at the new start.
                    continue;
                }
                lines.Add(new Line(lineStart, end - lineStart, resolved));
                lineStart = end;
                lastGoodEnd = end;
                oi++;
                continue;
            }

            if (width <= maxWidth)
            {
                lastGoodEnd = end;
                oi++;
                continue;
            }

            if (lastGoodEnd > lineStart)
            {
                lines.Add(new Line(lineStart, lastGoodEnd - lineStart, resolved));
                lineStart = lastGoodEnd;
                // Re-evaluate this break at the new start.
                continue;
            }

            // A single unbroken run wider than the width: hard-split at the char boundary that
            // still fits, so layout keeps progressing instead of stalling on the same run.
            int fit = LargestPrefix(font, text.AsSpan(lineStart, end - lineStart), maxWidth);
            lines.Add(new Line(lineStart, fit, resolved));
            lineStart += fit;
            lastGoodEnd = lineStart;
        }

        // The residual tail: emit whatever is left of the paragraph as one or more lines. An
        // uncommitted soft break in `lastGoodEnd` takes priority so a queued word boundary at
        // the tail is not lost to a needless hard-split.
        if (lastGoodEnd > lineStart)
        {
            var tail = text.AsSpan(lineStart, text.Length - lineStart);
            if (font.MeasureText(tail) > maxWidth)
            {
                lines.Add(new Line(lineStart, lastGoodEnd - lineStart, resolved));
                lineStart = lastGoodEnd;
            }
        }
        while (lineStart < text.Length)
        {
            int remaining = text.Length - lineStart;
            var window = text.AsSpan(lineStart, remaining);
            if (font.MeasureText(window) <= maxWidth)
            {
                lines.Add(new Line(lineStart, remaining, resolved));
                break;
            }
            int fit = LargestPrefix(font, window, maxWidth);
            lines.Add(new Line(lineStart, fit, resolved));
            lineStart += fit;
        }
        return lines;
    }
}
