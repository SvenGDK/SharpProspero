// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization.Text;

/// <summary>The kind of break opportunity at a particular character index.</summary>
public enum LineBreakOpportunity : byte
{
    /// <summary>The line must not break here.</summary>
    None,

    /// <summary>Layout may break here.</summary>
    Allowed,

    /// <summary>Layout must break here (BK, CR, LF, NL).</summary>
    Mandatory,
}

/// <summary>
/// UAX #14 line-break iterator. Walks a paragraph yielding the character indices at which the
/// layout may (or must) start a new line. The break-pair matrix carries the rules the interface
/// really hits: hard breaks (BK/CR/LF/NL), never-break-through-space (SP+CL/SP+CP/SP+EX), ZWSP
/// and soft hyphen as break opportunities, NBSP and Word Joiner as prohibitions, CJK
/// ideographs as break-either-side, and complex-script (Thai/Lao/Khmer) as opportunity-at-space
/// only (dictionary-driven segmentation is not implemented).
/// </summary>
public ref struct LineBreaker
{
    private readonly ReadOnlySpan<char> _text;
    private int _index;

    /// <summary>Creates an iterator over <paramref name="text"/>.</summary>
    public LineBreaker(ReadOnlySpan<char> text)
    {
        _text = text;
        _index = 0;
        Current = 0;
        CurrentOpportunity = LineBreakOpportunity.None;
    }

    /// <summary>The index the last-yielded opportunity applies to (character AFTER the break).</summary>
    public int Current { get; private set; }

    /// <summary>Whether the last-yielded opportunity is allowed or mandatory.</summary>
    public LineBreakOpportunity CurrentOpportunity { get; private set; }

    /// <summary>Advances to the next break opportunity; false when past the end of the text.</summary>
    public bool MoveNext()
    {
        while (_index < _text.Length)
        {
            int here = _index;
            int cp = ReadCodepoint(_text, here, out int step);
            LineBreakClass cls = LineBreakTable.ClassOf(cp);
            _index += step;

            // Mandatory-break classes: CR alone, CR+LF (join), LF, NL, BK.
            if (cls == LineBreakClass.BK || cls == LineBreakClass.LF || cls == LineBreakClass.NL)
            {
                Current = _index;
                CurrentOpportunity = LineBreakOpportunity.Mandatory;
                return true;
            }
            if (cls == LineBreakClass.CR)
            {
                // Consume the LF of a CR+LF pair before yielding.
                if (_index < _text.Length && _text[_index] == '\n') _index++;
                Current = _index;
                CurrentOpportunity = LineBreakOpportunity.Mandatory;
                return true;
            }

            if (_index >= _text.Length)
                break;

            // Look at the next character to decide the break-after.
            int nextCp = ReadCodepoint(_text, _index, out _);
            LineBreakClass next = LineBreakTable.ClassOf(nextCp);

            if (AllowsBreakBetween(cls, next))
            {
                Current = _index;
                CurrentOpportunity = LineBreakOpportunity.Allowed;
                return true;
            }
        }
        return false;
    }

    /// <summary>Fills <paramref name="breakIndicesOut"/> with the char indices of every break; returns count.</summary>
    public static int FindOpportunities(ReadOnlySpan<char> text, Span<int> breakIndicesOut)
    {
        int n = 0;
        var iter = new LineBreaker(text);
        while (iter.MoveNext())
        {
            if (n < breakIndicesOut.Length)
                breakIndicesOut[n] = iter.Current;
            n++;
        }
        return n;
    }

    /// <summary>Convenience: returns a fresh list of every break opportunity index.</summary>
    public static List<int> FindOpportunities(ReadOnlySpan<char> text)
    {
        var list = new List<int>();
        var iter = new LineBreaker(text);
        while (iter.MoveNext())
            list.Add(iter.Current);
        return list;
    }

    // ---- Compact pair matrix (subset of UAX #14 that the interface needs). ----

    private static bool AllowsBreakBetween(LineBreakClass a, LineBreakClass b)
    {
        // LB6/LB7 first: never break before space, and never break before ZW; SP never joins the
        // right side of a break-pair unless the right side is CL/CP/EX/IS/NS/ZW under LB18.
        if (b == LineBreakClass.SP) return false;
        if (b == LineBreakClass.ZW) return false;

        // LB4/LB5 are handled by the mandatory-break branch in MoveNext (CR/LF/BK/NL); nothing
        // to check here.

        // LB8a: never break after ZWJ (the ZWJ glues its two sides into one cluster). This must
        // sit BEFORE the ID broad rule so `emoji + ZWJ + ideograph` does not get broken.
        if (a == LineBreakClass.ZWJ) return false;

        // LB9: attachment rule for CM/ZWJ. A CM or ZWJ that follows a non-breaking base attaches;
        // never break BEFORE a CM/ZWJ. Excludes BK/CR/LF/NL/ZW/SP (LB10 says CM/ZWJ after those
        // "orphaned" bases behave like AL — handled by the SP branch below).
        if ((b == LineBreakClass.CM || b == LineBreakClass.ZWJ)
            && a != LineBreakClass.SP && a != LineBreakClass.ZW)
            return false;

        // LB11: WJ prohibits break on either side.
        if (a == LineBreakClass.WJ || b == LineBreakClass.WJ) return false;
        // LB12/LB12a: non-breaking glue prohibits break on either side (excluding SP+GL which
        // isn't a real code sequence).
        if (a == LineBreakClass.GL || b == LineBreakClass.GL) return false;

        // LB8: break AFTER ZW.
        if (a == LineBreakClass.ZW) return true;

        // LB30a: never break between adjacent regional-indicator flag components.
        if (a == LineBreakClass.RI && b == LineBreakClass.RI) return false;

        // LB18: break AFTER SP unless the right side is CL/CP/EX/IS/NS. An orphan CM/ZWJ after
        // SP behaves like AL and a break is allowed (LB10).
        if (a == LineBreakClass.SP)
        {
            if (b == LineBreakClass.CL || b == LineBreakClass.CP || b == LineBreakClass.EX
                || b == LineBreakClass.IS || b == LineBreakClass.NS)
                return false;
            return true;
        }

        // LB14: OP never allows break after. LB16: CL/CP never allows break before.
        if (a == LineBreakClass.OP) return false;
        if (b == LineBreakClass.CL || b == LineBreakClass.CP) return false;

        // LB21: never break before NS (non-starter attaches to preceding).
        if (b == LineBreakClass.NS) return false;

        // LB13: never break BEFORE EX or IS regardless of the class to the left. Sits ABOVE the
        // HY/BA/ID/B2 broad-break rules — a run like `漢!`, `text—!` or `abc-:` must not hand
        // out a break where the standard forbids one.
        if (b == LineBreakClass.EX || b == LineBreakClass.IS) return false;

        // LB19: never break around quotation marks.
        if (a == LineBreakClass.QU || b == LineBreakClass.QU) return false;

        // LB25 (subset): numbers stick to their internal separators — no break between NU and
        // IS (already handled above via `b == IS`) or between NU and NU.
        if (a == LineBreakClass.NU && b == LineBreakClass.NU) return false;
        if (a == LineBreakClass.AL && b == LineBreakClass.NU) return false;
        if (a == LineBreakClass.NU && b == LineBreakClass.AL) return false;

        // LB22 (partial): hyphen and dash break after unless the next class was already
        // prohibited above.
        if (a == LineBreakClass.HY) return true;
        if (a == LineBreakClass.BA) return true;

        // LB18a: em dash breaks either side.
        if (a == LineBreakClass.B2 || b == LineBreakClass.B2) return true;

        // LB18b: ideographs break either side. This runs AFTER the ZWJ/quotation/EX/IS gates so
        // `emoji-ZWJ-emoji`, `漢"`, and `漢!` all keep their cluster together.
        if (a == LineBreakClass.ID || b == LineBreakClass.ID) return true;

        // Complex-script (SA) — dictionary-free: attaches to itself; break only at surrounding
        // SP/ZW/BK which is handled above.
        if (a == LineBreakClass.SA && b == LineBreakClass.SA) return false;

        // Default for alphabetic + everything else: no break.
        return false;
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
