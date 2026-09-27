// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Globalization.Text;

/// <summary>
/// UAX #29 grapheme cluster boundary iterator. Walks a string yielding the character index at
/// which each user-perceived grapheme starts, honouring the rules the interface actually needs:
/// CR+LF as one cluster, controls isolate, Hangul syllable rules (L/V/T/LV/LVT), Regional
/// Indicator pairs, Extend/SpacingMark grouping, and the emoji ZWJ chain rule GB11 (an
/// Extended_Pictographic followed by ZWJ then another Extended_Pictographic joins).
/// </summary>
public ref struct GraphemeIterator
{
    private readonly ReadOnlySpan<char> _text;
    private int _index;

    /// <summary>Creates an iterator positioned before the first grapheme.</summary>
    public GraphemeIterator(ReadOnlySpan<char> text)
    {
        _text = text;
        _index = 0;
        Current = 0;
    }

    /// <summary>The character index of the current grapheme's first codepoint.</summary>
    public int Current { get; private set; }

    /// <summary>Advances one grapheme and returns whether one was found.</summary>
    public bool MoveNext()
    {
        if (_index >= _text.Length)
            return false;
        Current = _index;
        _index = NextBoundary(_text, _index);
        return true;
    }

    /// <summary>
    /// Returns the character index just past the grapheme that starts at <paramref name="from"/>.
    /// Never splits a surrogate pair; never splits an emoji cluster.
    /// </summary>
    public static int NextBoundary(ReadOnlySpan<char> text, int from)
    {
        if (from >= text.Length)
            return text.Length;

        int i = from;
        int prevCp = ReadCodepoint(text, i, out int consumed);
        GraphemeBreakProperty prev = GraphemeBreakTable.PropertyOf(prevCp);
        i += consumed;
        bool inRi = prev == GraphemeBreakProperty.RegionalIndicator;
        int riCount = inRi ? 1 : 0;
        bool afterExtendedPictographic = prev == GraphemeBreakProperty.ExtendedPictographic;

        while (i < text.Length)
        {
            int cp = ReadCodepoint(text, i, out int step);
            GraphemeBreakProperty cur = GraphemeBreakTable.PropertyOf(cp);

            // GB3: CR × LF.
            if (prev == GraphemeBreakProperty.CR && cur == GraphemeBreakProperty.LF)
            { i += step; break; }
            // GB4: control ÷ any.
            if (prev == GraphemeBreakProperty.Control || prev == GraphemeBreakProperty.CR || prev == GraphemeBreakProperty.LF)
                break;
            // GB5: any ÷ control.
            if (cur == GraphemeBreakProperty.Control || cur == GraphemeBreakProperty.CR || cur == GraphemeBreakProperty.LF)
                break;

            // GB6: L × (L | V | LV | LVT).
            if (prev == GraphemeBreakProperty.L &&
                (cur == GraphemeBreakProperty.L || cur == GraphemeBreakProperty.V
                 || cur == GraphemeBreakProperty.LV || cur == GraphemeBreakProperty.LVT))
            { i += step; prev = cur; continue; }
            // GB7: (LV | V) × (V | T).
            if ((prev == GraphemeBreakProperty.LV || prev == GraphemeBreakProperty.V)
                && (cur == GraphemeBreakProperty.V || cur == GraphemeBreakProperty.T))
            { i += step; prev = cur; continue; }
            // GB8: (LVT | T) × T.
            if ((prev == GraphemeBreakProperty.LVT || prev == GraphemeBreakProperty.T)
                && cur == GraphemeBreakProperty.T)
            { i += step; prev = cur; continue; }

            // GB9: × (Extend | ZWJ).
            if (cur == GraphemeBreakProperty.Extend || cur == GraphemeBreakProperty.ZWJ)
            {
                i += step;
                // Extend before ZWJ keeps the pictographic marker.
                if (cur == GraphemeBreakProperty.Extend) prev = GraphemeBreakProperty.Extend;
                else prev = GraphemeBreakProperty.ZWJ;
                continue;
            }
            // GB9a: × SpacingMark.
            if (cur == GraphemeBreakProperty.SpacingMark)
            { i += step; prev = cur; continue; }
            // GB9b: Prepend × any.
            if (prev == GraphemeBreakProperty.Prepend)
            { i += step; prev = cur; afterExtendedPictographic = cur == GraphemeBreakProperty.ExtendedPictographic; continue; }

            // GB11: Extended_Pictographic × Extend* × ZWJ × Extended_Pictographic.
            if (prev == GraphemeBreakProperty.ZWJ && cur == GraphemeBreakProperty.ExtendedPictographic && afterExtendedPictographic)
            { i += step; prev = cur; afterExtendedPictographic = true; continue; }

            // GB12/GB13: Regional_Indicator pairing — an RI joins the previous RI only when the
            // count so far is odd (so a stream of RIs breaks after every pair).
            if (cur == GraphemeBreakProperty.RegionalIndicator && inRi && (riCount % 2) == 1)
            { i += step; riCount++; prev = cur; continue; }
            if (cur == GraphemeBreakProperty.RegionalIndicator) { inRi = true; riCount = 1; }
            else { inRi = false; riCount = 0; }

            // Otherwise: break.
            break;
        }
        return i;
    }

    /// <summary>Total number of graphemes in <paramref name="text"/>.</summary>
    public static int Count(ReadOnlySpan<char> text)
    {
        int n = 0;
        int i = 0;
        while (i < text.Length)
        {
            i = NextBoundary(text, i);
            n++;
        }
        return n;
    }

    private static int ReadCodepoint(ReadOnlySpan<char> text, int index, out int consumed)
    {
        char c = text[index];
        if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
        {
            consumed = 2;
            return char.ConvertToUtf32(c, text[index + 1]);
        }
        consumed = 1;
        return c;
    }
}
