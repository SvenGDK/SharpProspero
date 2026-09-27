// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Globalization.Text;

/// <summary>The UAX #29 Grapheme_Cluster_Break property values the boundary iterator matches on.</summary>
public enum GraphemeBreakProperty : byte
{
    /// <summary>Any other codepoint.</summary>
    Other,

    /// <summary>Carriage return (U+000D).</summary>
    CR,

    /// <summary>Line feed (U+000A).</summary>
    LF,

    /// <summary>C0/C1 control characters + line/paragraph separator + zero-width formatting.</summary>
    Control,

    /// <summary>Extending characters (combining marks, most format chars).</summary>
    Extend,

    /// <summary>Zero-width joiner (U+200D).</summary>
    ZWJ,

    /// <summary>Regional indicators (U+1F1E6..U+1F1FF, flag components).</summary>
    RegionalIndicator,

    /// <summary>Prepending characters (Arabic tatweel-like prefixes).</summary>
    Prepend,

    /// <summary>Spacing combining marks that visually take space next to the base.</summary>
    SpacingMark,

    /// <summary>Hangul leading consonant.</summary>
    L,

    /// <summary>Hangul vowel.</summary>
    V,

    /// <summary>Hangul trailing consonant.</summary>
    T,

    /// <summary>Hangul LV syllable.</summary>
    LV,

    /// <summary>Hangul LVT syllable.</summary>
    LVT,

    /// <summary>Extended_Pictographic (emoji base — GB11).</summary>
    ExtendedPictographic,
}

/// <summary>Classifies a codepoint into its UAX #29 grapheme-break property by block ranges.</summary>
public static class GraphemeBreakTable
{
    /// <summary>The Unicode version this classifier reflects.</summary>
    public const string UnicodeVersion = "15.0";

    /// <summary>Returns the grapheme-break property of a codepoint.</summary>
    public static GraphemeBreakProperty PropertyOf(int codepoint)
    {
        if (codepoint == 0x000D) return GraphemeBreakProperty.CR;
        if (codepoint == 0x000A) return GraphemeBreakProperty.LF;
        if (codepoint == 0x200D) return GraphemeBreakProperty.ZWJ;

        // Controls.
        if (codepoint < 0x20 || codepoint == 0x7F) return GraphemeBreakProperty.Control;
        if (codepoint >= 0x80 && codepoint <= 0x9F) return GraphemeBreakProperty.Control;
        if (codepoint == 0x2028 || codepoint == 0x2029) return GraphemeBreakProperty.Control;

        // Regional indicators.
        if (codepoint >= 0x1F1E6 && codepoint <= 0x1F1FF)
            return GraphemeBreakProperty.RegionalIndicator;

        // Extended_Pictographic (emoji ranges).
        if (IsExtendedPictographic(codepoint))
            return GraphemeBreakProperty.ExtendedPictographic;

        // Indic script Extend / SpacingMark / Virama coverage. The Devanagari branches below
        // are kept for backwards compatibility; the additional blocks here fill the gap for
        // Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam, Sinhala,
        // Tibetan and Myanmar so their virama / dependent-vowel / candrabindu codepoints
        // attach to their base per GB9 instead of breaking as Other clusters.
        // Bengali (0x09xx).
        if (codepoint >= 0x0981 && codepoint <= 0x0983) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x09BC) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x09BE && codepoint <= 0x09C4) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x09C7 || codepoint == 0x09C8) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x09CB && codepoint <= 0x09CD) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x09D7) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x09E2 || codepoint == 0x09E3) return GraphemeBreakProperty.Extend;
        // Gurmukhi (0x0Axx).
        if (codepoint >= 0x0A01 && codepoint <= 0x0A03) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x0A3C) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0A3E && codepoint <= 0x0A42) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0A47 || codepoint == 0x0A48) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0A4B && codepoint <= 0x0A4D) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0A51) return GraphemeBreakProperty.Extend;
        // Gujarati (0x0AXx).
        if (codepoint >= 0x0A81 && codepoint <= 0x0A83) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x0ABC) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0ABE && codepoint <= 0x0AC5) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0AC7 && codepoint <= 0x0AC9) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0ACB && codepoint <= 0x0ACD) return GraphemeBreakProperty.Extend;
        // Oriya (0x0Bxx).
        if (codepoint == 0x0B01) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0B02 || codepoint == 0x0B03) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x0B3C) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0B3E && codepoint <= 0x0B44) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0B47 || codepoint == 0x0B48) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0B4B && codepoint <= 0x0B4D) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0B56 || codepoint == 0x0B57) return GraphemeBreakProperty.Extend;
        // Tamil (0x0Bxx).
        if (codepoint == 0x0B82) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0BBE && codepoint <= 0x0BC2) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0BC6 && codepoint <= 0x0BC8) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0BCA && codepoint <= 0x0BCD) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0BD7) return GraphemeBreakProperty.Extend;
        // Telugu (0x0Cxx).
        if (codepoint >= 0x0C00 && codepoint <= 0x0C03) return GraphemeBreakProperty.SpacingMark;
        if (codepoint >= 0x0C3E && codepoint <= 0x0C44) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0C46 && codepoint <= 0x0C48) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0C4A && codepoint <= 0x0C4D) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0C55 && codepoint <= 0x0C56) return GraphemeBreakProperty.Extend;
        // Kannada (0x0Cxx).
        if (codepoint == 0x0C81) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0C82 || codepoint == 0x0C83) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x0CBC) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0CBE && codepoint <= 0x0CC4) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0CC6 && codepoint <= 0x0CC8) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0CCA && codepoint <= 0x0CCD) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0CD5 || codepoint == 0x0CD6) return GraphemeBreakProperty.Extend;
        // Malayalam (0x0Dxx).
        if (codepoint == 0x0D01) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0D02 || codepoint == 0x0D03) return GraphemeBreakProperty.SpacingMark;
        if (codepoint >= 0x0D3E && codepoint <= 0x0D44) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0D46 && codepoint <= 0x0D48) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0D4A && codepoint <= 0x0D4D) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0D57) return GraphemeBreakProperty.Extend;
        // Sinhala (0x0Dxx).
        if (codepoint == 0x0D82 || codepoint == 0x0D83) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x0DCA) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0DCF && codepoint <= 0x0DD4) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0DD6) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0DD8 && codepoint <= 0x0DDF) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0DF2 || codepoint == 0x0DF3) return GraphemeBreakProperty.Extend;
        // Tibetan (0x0Fxx).
        if (codepoint >= 0x0F71 && codepoint <= 0x0F7E) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0F80 && codepoint <= 0x0F84) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0F86 && codepoint <= 0x0F87) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0F8D && codepoint <= 0x0F97) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0F99 && codepoint <= 0x0FBC) return GraphemeBreakProperty.Extend;
        // Myanmar (0x1000..0x109F).
        if (codepoint >= 0x102B && codepoint <= 0x1032) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x1036 && codepoint <= 0x1037) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x1039 || codepoint == 0x103A) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x103D && codepoint <= 0x103E) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x1056 && codepoint <= 0x1059) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x105E && codepoint <= 0x1060) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x1062 && codepoint <= 0x1064) return GraphemeBreakProperty.SpacingMark;
        if (codepoint >= 0x1067 && codepoint <= 0x106D) return GraphemeBreakProperty.SpacingMark;
        if (codepoint >= 0x1071 && codepoint <= 0x1074) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x1082 || codepoint == 0x108D) return GraphemeBreakProperty.Extend;

        // Hangul.
        if (codepoint >= 0x1100 && codepoint <= 0x115F) return GraphemeBreakProperty.L;
        if (codepoint >= 0xA960 && codepoint <= 0xA97C) return GraphemeBreakProperty.L;
        if (codepoint >= 0x1160 && codepoint <= 0x11A7) return GraphemeBreakProperty.V;
        if (codepoint >= 0xD7B0 && codepoint <= 0xD7C6) return GraphemeBreakProperty.V;
        if (codepoint >= 0x11A8 && codepoint <= 0x11FF) return GraphemeBreakProperty.T;
        if (codepoint >= 0xD7CB && codepoint <= 0xD7FB) return GraphemeBreakProperty.T;
        if (codepoint >= 0xAC00 && codepoint <= 0xD7A3)
        {
            int syllableOffset = codepoint - 0xAC00;
            return (syllableOffset % 28) == 0
                ? GraphemeBreakProperty.LV
                : GraphemeBreakProperty.LVT;
        }

        // Extend (combining marks, format chars). Broad block coverage — narrow overlaps land as
        // Extend which is safe for boundary logic.
        if (codepoint >= 0x0300 && codepoint <= 0x036F) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0483 && codepoint <= 0x0489) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0591 && codepoint <= 0x05BD) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x05BF) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x05C1 && codepoint <= 0x05C2) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x05C4 && codepoint <= 0x05C5) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x05C7) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0610 && codepoint <= 0x061A) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x064B && codepoint <= 0x065F) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0670) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x06D6 && codepoint <= 0x06DC) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x06DF && codepoint <= 0x06E4) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x06E7 && codepoint <= 0x06E8) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x06EA && codepoint <= 0x06ED) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0711) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0730 && codepoint <= 0x074A) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x07A6 && codepoint <= 0x07B0) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0900 && codepoint <= 0x0902) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x093A) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x093C) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0941 && codepoint <= 0x0948) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x094D) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0951 && codepoint <= 0x0957) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x0962 || codepoint == 0x0963) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0E31 && codepoint <= 0x0E31) return GraphemeBreakProperty.Extend; // Thai mai han-akat
        if (codepoint >= 0x0E34 && codepoint <= 0x0E3A) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x0E47 && codepoint <= 0x0E4E) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x1AB0 && codepoint <= 0x1ACE) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x1DC0 && codepoint <= 0x1DFF) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x200C) return GraphemeBreakProperty.Extend;
        if (codepoint == 0x2060 || codepoint == 0xFEFF) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0x20D0 && codepoint <= 0x20F0) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0xFE00 && codepoint <= 0xFE0F) return GraphemeBreakProperty.Extend; // Variation Selectors
        if (codepoint >= 0xFE20 && codepoint <= 0xFE2F) return GraphemeBreakProperty.Extend;
        if (codepoint >= 0xE0100 && codepoint <= 0xE01EF) return GraphemeBreakProperty.Extend;

        // Emoji skin-tone modifiers land as Extend per GB9c-style treatment; they attach to the
        // preceding cluster.
        if (codepoint >= 0x1F3FB && codepoint <= 0x1F3FF) return GraphemeBreakProperty.Extend;

        // Prepend (small set — Arabic subtending marks).
        if (codepoint >= 0x0600 && codepoint <= 0x0605) return GraphemeBreakProperty.Prepend;
        if (codepoint == 0x06DD) return GraphemeBreakProperty.Prepend;
        if (codepoint == 0x070F) return GraphemeBreakProperty.Prepend;
        if (codepoint == 0x0890 || codepoint == 0x0891) return GraphemeBreakProperty.Prepend;

        // SpacingMark — Devanagari + Bengali + Tamil + Thai spacing vowels (representative subset).
        if (codepoint == 0x0903) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x093B || codepoint == 0x093E || codepoint == 0x093F) return GraphemeBreakProperty.SpacingMark;
        if (codepoint >= 0x0940 && codepoint <= 0x0940) return GraphemeBreakProperty.SpacingMark;
        if (codepoint >= 0x0949 && codepoint <= 0x094C) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x094E || codepoint == 0x094F) return GraphemeBreakProperty.SpacingMark;
        if (codepoint == 0x0E30 || codepoint == 0x0E32 || codepoint == 0x0E33) return GraphemeBreakProperty.SpacingMark;

        return GraphemeBreakProperty.Other;
    }

    private static bool IsExtendedPictographic(int cp)
    {
        // Condensed emoji ranges — covers the commonly used blocks.
        if (cp == 0x00A9 || cp == 0x00AE) return true;                             // ©, ®
        if (cp == 0x203C || cp == 0x2049) return true;                             // ‼ ⁉
        if (cp == 0x2122 || cp == 0x2139) return true;                             // ™ ℹ
        if (cp >= 0x2194 && cp <= 0x2199) return true;                             // arrows
        if (cp >= 0x21A9 && cp <= 0x21AA) return true;
        if (cp >= 0x2300 && cp <= 0x2328) return true;
        if (cp == 0x23CF) return true;
        if (cp >= 0x23E9 && cp <= 0x23F3) return true;
        if (cp >= 0x23F8 && cp <= 0x23FA) return true;
        if (cp == 0x24C2) return true;
        if (cp >= 0x25AA && cp <= 0x25AB) return true;
        if (cp == 0x25B6 || cp == 0x25C0) return true;
        if (cp >= 0x25FB && cp <= 0x25FE) return true;
        if (cp >= 0x2600 && cp <= 0x27EF) return true;                             // misc symbols + dingbats
        if (cp >= 0x2934 && cp <= 0x2935) return true;
        if (cp >= 0x2B05 && cp <= 0x2B07) return true;
        if (cp >= 0x2B1B && cp <= 0x2B1C) return true;
        if (cp == 0x2B50 || cp == 0x2B55) return true;
        if (cp == 0x3030 || cp == 0x303D) return true;
        if (cp == 0x3297 || cp == 0x3299) return true;
        if (cp >= 0x1F000 && cp <= 0x1FAFF) return true;                           // emoji blocks (broad)
        return false;
    }
}
