// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Globalization.Text;

/// <summary>The subset of UAX #14 line-break classes the iterator matches on.</summary>
public enum LineBreakClass : byte
{
    /// <summary>Alphabetic characters — the fallback.</summary>
    AL,

    /// <summary>Space (U+0020) — allows break after when not followed by NS/CL/CP.</summary>
    SP,

    /// <summary>Break after / opportunity to break after (hyphen-minus, em-dash).</summary>
    BA,

    /// <summary>Break before + break after (em-dash-like glue).</summary>
    B2,

    /// <summary>Hyphen (soft hyphen, minus sign) — allows break after when followed by AL/NU.</summary>
    HY,

    /// <summary>Ideographic (CJK) — allows break on either side.</summary>
    ID,

    /// <summary>Numeric (ASCII digits + Arabic-Indic digits).</summary>
    NU,

    /// <summary>Non-breaking (NBSP, word joiner) — prohibits break on both sides.</summary>
    GL,

    /// <summary>Zero-width space — mandatory break opportunity.</summary>
    ZW,

    /// <summary>Word joiner (U+2060) — prohibits break on both sides.</summary>
    WJ,

    /// <summary>Non-starter (small kana, hyphen bullet) — prohibits break before.</summary>
    NS,

    /// <summary>Opening punctuation (open brackets, opening quotes) — prohibits break after.</summary>
    OP,

    /// <summary>Closing punctuation.</summary>
    CL,

    /// <summary>Closing parenthesis (some scripts distinguish CP from CL).</summary>
    CP,

    /// <summary>Exclamation / question marks — prohibits break before, allows after.</summary>
    EX,

    /// <summary>Infix separator (colon, some slashes) — prohibits break before, allows after.</summary>
    IS,

    /// <summary>Mandatory break (BK) — always break after.</summary>
    BK,

    /// <summary>Carriage return.</summary>
    CR,

    /// <summary>Line feed.</summary>
    LF,

    /// <summary>Next line (U+0085).</summary>
    NL,

    /// <summary>Quotation (default: pair with surrounding text).</summary>
    QU,

    /// <summary>Combining mark — attaches to base character.</summary>
    CM,

    /// <summary>South-East Asian complex script (Thai/Lao/Khmer) — cluster-safe.</summary>
    SA,

    /// <summary>Regional indicator (emoji flag components).</summary>
    RI,

    /// <summary>Zero-width joiner.</summary>
    ZWJ,
}

/// <summary>Classifier + break-opportunity iterator for UAX #14.</summary>
public static class LineBreakTable
{
    /// <summary>Returns the line-break class of a codepoint.</summary>
    public static LineBreakClass ClassOf(int codepoint)
    {
        // Hard breaks.
        if (codepoint == 0x000D) return LineBreakClass.CR;
        if (codepoint == 0x000A) return LineBreakClass.LF;
        if (codepoint == 0x0085) return LineBreakClass.NL;
        if (codepoint == 0x000B || codepoint == 0x000C) return LineBreakClass.BK;
        if (codepoint == 0x2028) return LineBreakClass.BK;   // Line separator
        if (codepoint == 0x2029) return LineBreakClass.BK;   // Paragraph separator

        // Whitespace + special-purpose spaces.
        if (codepoint == 0x0020) return LineBreakClass.SP;
        if (codepoint == 0x00A0) return LineBreakClass.GL;   // NBSP
        if (codepoint == 0x2007) return LineBreakClass.GL;   // Figure space
        if (codepoint == 0x202F) return LineBreakClass.GL;   // Narrow NBSP
        if (codepoint >= 0x2000 && codepoint <= 0x2006) return LineBreakClass.BA;
        if (codepoint == 0x2008 || codepoint == 0x2009 || codepoint == 0x200A) return LineBreakClass.BA;
        if (codepoint == 0x205F) return LineBreakClass.BA;
        if (codepoint == 0x3000) return LineBreakClass.ID;   // CJK ideographic space — break either side
        if (codepoint == 0x200B) return LineBreakClass.ZW;   // ZWSP
        if (codepoint == 0x200C) return LineBreakClass.CM;
        if (codepoint == 0x200D) return LineBreakClass.ZWJ;
        if (codepoint == 0x2060 || codepoint == 0xFEFF) return LineBreakClass.WJ;

        // Digits.
        if (codepoint >= '0' && codepoint <= '9') return LineBreakClass.NU;
        if (codepoint >= 0x0660 && codepoint <= 0x0669) return LineBreakClass.NU;   // Arabic-Indic
        if (codepoint >= 0x06F0 && codepoint <= 0x06F9) return LineBreakClass.NU;

        // Latin punctuation.
        if (codepoint == '-') return LineBreakClass.HY;
        if (codepoint == 0x00AD) return LineBreakClass.BA;   // Soft hyphen — allow break
        if (codepoint == 0x2010) return LineBreakClass.BA;   // HYPHEN
        if (codepoint == 0x2011) return LineBreakClass.GL;   // NON-BREAKING HYPHEN — must not break either side
        if (codepoint == 0x2012 || codepoint == 0x2013) return LineBreakClass.BA;  // Figure/en dash
        if (codepoint == 0x2014) return LineBreakClass.B2;  // Em dash — breakable both sides
        if (codepoint == '!' || codepoint == '?' || codepoint == 0x203C || codepoint == 0x2049) return LineBreakClass.EX;
        if (codepoint == ':' || codepoint == ';') return LineBreakClass.IS;
        if (codepoint == '.' || codepoint == ',') return LineBreakClass.IS;
        if (codepoint == '(' || codepoint == '[' || codepoint == '{' || codepoint == 0x2018 || codepoint == 0x201C
         || codepoint == 0x00AB) return LineBreakClass.OP;
        if (codepoint == ')' || codepoint == ']' || codepoint == '}' || codepoint == 0x2019 || codepoint == 0x201D
         || codepoint == 0x00BB) return LineBreakClass.CP;
        if (codepoint == '"' || codepoint == '\'') return LineBreakClass.QU;

        // Regional indicators.
        if (codepoint >= 0x1F1E6 && codepoint <= 0x1F1FF) return LineBreakClass.RI;

        // Complex scripts (SA — Thai, Lao, Khmer, Myanmar).
        if (codepoint >= 0x0E00 && codepoint <= 0x0E7F) return LineBreakClass.SA;
        if (codepoint >= 0x0E80 && codepoint <= 0x0EFF) return LineBreakClass.SA;
        if (codepoint >= 0x1000 && codepoint <= 0x109F) return LineBreakClass.SA;
        if (codepoint >= 0x1780 && codepoint <= 0x17FF) return LineBreakClass.SA;

        // Combining marks.
        if (codepoint >= 0x0300 && codepoint <= 0x036F) return LineBreakClass.CM;
        if (codepoint >= 0x0591 && codepoint <= 0x05BD) return LineBreakClass.CM;
        if (codepoint >= 0x0610 && codepoint <= 0x061A) return LineBreakClass.CM;
        if (codepoint >= 0x064B && codepoint <= 0x065F) return LineBreakClass.CM;
        if (codepoint >= 0x0900 && codepoint <= 0x0903) return LineBreakClass.CM;
        if (codepoint == 0x093C || codepoint == 0x094D) return LineBreakClass.CM;

        // Non-starters (small kana + prolonged-sound mark + hyphen bullets). LB21 attaches
        // these to the preceding character; without the full set, wrapping would let a small
        // kana or the prolonged-sound mark start a new line detached from its base.
        // Small Hiragana: ぁ ぃ ぅ ぇ ぉ っ ゃ ゅ ょ ゎ.
        if (codepoint == 0x3041 || codepoint == 0x3043 || codepoint == 0x3045 || codepoint == 0x3047
            || codepoint == 0x3049 || codepoint == 0x3063 || codepoint == 0x3083 || codepoint == 0x3085
            || codepoint == 0x3087 || codepoint == 0x308E)
            return LineBreakClass.NS;
        // Small Katakana + prolonged mark + iteration marks + hyphen bullet:
        // ヽ ヾ ー ァ ィ ゥ ェ ォ ッ ャ ュ ョ ヮ ヵ ヶ and the middle dot.
        if (codepoint == 0x30FD || codepoint == 0x30FE || codepoint == 0x30FC || codepoint == 0x30A1
            || codepoint == 0x30A3 || codepoint == 0x30A5 || codepoint == 0x30A7 || codepoint == 0x30A9
            || codepoint == 0x30C3 || codepoint == 0x30E3 || codepoint == 0x30E5 || codepoint == 0x30E7
            || codepoint == 0x30EE || codepoint == 0x30F5 || codepoint == 0x30F6)
            return LineBreakClass.NS;
        if (codepoint == 0x30FB) return LineBreakClass.NS;

        // CJK ideographs — break either side.
        if (codepoint >= 0x3040 && codepoint <= 0x30FF) return LineBreakClass.ID; // Kana
        if (codepoint >= 0x3400 && codepoint <= 0x9FFF) return LineBreakClass.ID;
        if (codepoint >= 0xAC00 && codepoint <= 0xD7A3) return LineBreakClass.ID;
        if (codepoint >= 0xF900 && codepoint <= 0xFAFF) return LineBreakClass.ID;

        // Fallback.
        return LineBreakClass.AL;
    }
}
