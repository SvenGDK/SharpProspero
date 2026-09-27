// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Globalization.Bidi;

/// <summary>
/// The Unicode bidirectional character class a codepoint carries per UAX #9. Values are the ones
/// the algorithm's resolution rules (W1..W7, N0..N2, I1..I2, X1..X8, L1..L2) match against;
/// there is one entry per standard class name.
/// </summary>
public enum BidiClass : byte
{
    /// <summary>Left-to-right strong (Latin letters, most CJK, most non-Arabic scripts).</summary>
    L,

    /// <summary>Right-to-left strong (Hebrew).</summary>
    R,

    /// <summary>Arabic letter (Arabic, Syriac, Thaana, N'Ko strong RTL).</summary>
    AL,

    /// <summary>European number (ASCII digits).</summary>
    EN,

    /// <summary>European number separator (plus and minus signs).</summary>
    ES,

    /// <summary>European number terminator (percent, currency, degree).</summary>
    ET,

    /// <summary>Arabic number (Arabic-Indic digits).</summary>
    AN,

    /// <summary>Common number separator (comma, period, colon, non-breaking hyphen).</summary>
    CS,

    /// <summary>Non-spacing mark (combining marks, virama).</summary>
    NSM,

    /// <summary>Boundary neutral (control characters, zero-width formatting).</summary>
    BN,

    /// <summary>Paragraph separator (U+2029 and equivalents).</summary>
    B,

    /// <summary>Segment separator (tab).</summary>
    S,

    /// <summary>Whitespace (space and most other whitespace characters).</summary>
    WS,

    /// <summary>Other neutral (punctuation, symbols, most brackets).</summary>
    ON,

    /// <summary>Left-to-right embedding (U+202A).</summary>
    LRE,

    /// <summary>Left-to-right override (U+202D).</summary>
    LRO,

    /// <summary>Right-to-left embedding (U+202B).</summary>
    RLE,

    /// <summary>Right-to-left override (U+202E).</summary>
    RLO,

    /// <summary>Pop directional formatting (U+202C).</summary>
    PDF,

    /// <summary>Left-to-right isolate (U+2066).</summary>
    LRI,

    /// <summary>Right-to-left isolate (U+2067).</summary>
    RLI,

    /// <summary>First strong isolate (U+2068).</summary>
    FSI,

    /// <summary>Pop directional isolate (U+2069).</summary>
    PDI,
}
