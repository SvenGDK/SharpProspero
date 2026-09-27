// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Collections.Generic;

namespace SharpProspero.Globalization.Bidi;

/// <summary>
/// Classifies a codepoint into its <see cref="BidiClass"/> by Unicode block ranges. The tables
/// cover every common script: Arabic (AL), Hebrew (R), Syriac (AL), Thaana (AL), NKo (R),
/// Arabic Presentation Forms (AL), Arabic-Indic digits (AN), Latin digits (EN), the paired
/// brackets, the explicit-embedding format characters (LRE/RLE/LRO/RLO/PDF), the isolate format
/// characters (LRI/RLI/FSI/PDI), and the common neutrals. Any codepoint that is not covered by
/// an explicit range or block resolves to <see cref="BidiClass.ON"/> (other-neutral); the LTR
/// resolution then falls out of the algorithm's neutral rules against the surrounding strong
/// context.
/// </summary>
public static class BidiClassTable
{
    /// <summary>The Unicode data version this classifier was baked against.</summary>
    public const string UnicodeVersion = "15.0";

    /// <summary>Returns the class of a codepoint.</summary>
    public static BidiClass ClassOf(int codepoint)
    {
        if ((uint)codepoint > 0x10FFFF)
            return BidiClass.ON;

        // Fast path for the ASCII range: ~85% of the text a Latin app renders.
        if (codepoint < 0x80)
            return AsciiClass[codepoint];

        // Explicit formatting codepoints — resolved by an exact match before the block ranges.
        switch (codepoint)
        {
            case 0x200E: return BidiClass.L;   // LRM
            case 0x200F: return BidiClass.R;   // RLM
            case 0x202A: return BidiClass.LRE;
            case 0x202B: return BidiClass.RLE;
            case 0x202C: return BidiClass.PDF;
            case 0x202D: return BidiClass.LRO;
            case 0x202E: return BidiClass.RLO;
            case 0x2066: return BidiClass.LRI;
            case 0x2067: return BidiClass.RLI;
            case 0x2068: return BidiClass.FSI;
            case 0x2069: return BidiClass.PDI;
            case 0x061C: return BidiClass.AL;  // Arabic letter mark
            case 0x0009: return BidiClass.S;   // TAB (also in AsciiClass but explicit)
            case 0x000A: return BidiClass.B;   // LF
            case 0x000D: return BidiClass.B;   // CR
            case 0x001C: return BidiClass.B;
            case 0x001D: return BidiClass.B;
            case 0x001E: return BidiClass.B;
            case 0x001F: return BidiClass.S;
            case 0x0085: return BidiClass.B;   // NEL
            case 0x2028: return BidiClass.WS;  // LINE SEPARATOR
            case 0x2029: return BidiClass.B;   // PARAGRAPH SEPARATOR
            case 0x00A0: return BidiClass.CS;  // NBSP
            case 0x00AD: return BidiClass.BN;  // SOFT HYPHEN
            case 0x2007: return BidiClass.CS;  // FIGURE SPACE
            case 0x202F: return BidiClass.CS;  // NARROW NBSP
        }

        // Block-based ranges. Order matters: the SPECIFIC codepoint / narrow-range checks
        // (NSM, AN, EN, BN, ET) run BEFORE the coarse strong-block returns so a combining mark
        // inside a strong-RTL script block is not misclassified as a letter. UAX #9 DerivedBidiClass
        // groups these overrides by codepoint, not by block, and the algorithm relies on the fine
        // grain to route weak-run resolution and neutral bracketing correctly.

        // Control-like boundary neutrals (checked first — U+FEFF sits inside Arabic Presentation
        // Forms-B and must not read as AL).
        if (codepoint == 0x200B || codepoint == 0x200C || codepoint == 0x200D) return BidiClass.BN; // ZWSP/ZWNJ/ZWJ
        if (codepoint == 0x2060 || codepoint == 0xFEFF) return BidiClass.BN;   // WJ, BOM/ZWNBSP
        if (codepoint >= 0x2062 && codepoint <= 0x2064) return BidiClass.BN;   // invisible math operators
        if (codepoint >= 0xFFF0 && codepoint <= 0xFFFB) return BidiClass.BN;

        // Arabic-Indic digits (AN) and Extended Arabic-Indic digits (EN) — these sit inside the
        // Arabic block, so they must be resolved BEFORE the Arabic AL blanket.
        if (codepoint >= 0x0660 && codepoint <= 0x0669) return BidiClass.AN;  // Arabic-Indic digits
        if (codepoint >= 0x066B && codepoint <= 0x066C) return BidiClass.AN;  // Arabic decimal + thousands separators
        if (codepoint == 0x066A) return BidiClass.ET;  // Arabic percent sign
        if (codepoint >= 0x06F0 && codepoint <= 0x06F9) return BidiClass.EN;  // Extended Arabic-Indic

        // Combining marks (NSM). These blocks are indexed as non-spacing marks and MUST be
        // resolved before any coarse strong-block blanket that could shadow them.
        if (codepoint >= 0x0300 && codepoint <= 0x036F) return BidiClass.NSM; // Combining Diacritical Marks
        if (codepoint >= 0x0483 && codepoint <= 0x0489) return BidiClass.NSM; // Cyrillic marks
        if (codepoint >= 0x0591 && codepoint <= 0x05BD) return BidiClass.NSM; // Hebrew marks
        if (codepoint == 0x05BF) return BidiClass.NSM; // Hebrew rafe
        if (codepoint == 0x05C1 || codepoint == 0x05C2) return BidiClass.NSM; // Hebrew shin dots
        if (codepoint == 0x05C4 || codepoint == 0x05C5) return BidiClass.NSM;
        if (codepoint == 0x05C7) return BidiClass.NSM; // Hebrew qamats qatan
        if (codepoint >= 0x0610 && codepoint <= 0x061A) return BidiClass.NSM; // Arabic marks
        if (codepoint >= 0x064B && codepoint <= 0x065F) return BidiClass.NSM; // Arabic vowel marks
        if (codepoint == 0x0670) return BidiClass.NSM; // Arabic superscript alef
        if (codepoint >= 0x06D6 && codepoint <= 0x06DC) return BidiClass.NSM;
        if (codepoint >= 0x06DF && codepoint <= 0x06E4) return BidiClass.NSM;
        if (codepoint >= 0x06E7 && codepoint <= 0x06E8) return BidiClass.NSM;
        if (codepoint >= 0x06EA && codepoint <= 0x06ED) return BidiClass.NSM;
        // Samaritan NSM subranges (inside the 0x0800..0x083F block).
        if (codepoint >= 0x0816 && codepoint <= 0x0819) return BidiClass.NSM;
        if (codepoint >= 0x081B && codepoint <= 0x0823) return BidiClass.NSM;
        if (codepoint >= 0x0825 && codepoint <= 0x0827) return BidiClass.NSM;
        if (codepoint >= 0x0829 && codepoint <= 0x082D) return BidiClass.NSM;
        // Mandaic NSM subranges (inside 0x0840..0x085F).
        if (codepoint >= 0x0859 && codepoint <= 0x085B) return BidiClass.NSM;
        // Arabic Extended-A NSM subranges (inside 0x08A0..0x08FF).
        if (codepoint >= 0x08D3 && codepoint <= 0x08E1) return BidiClass.NSM;
        if (codepoint >= 0x08E3 && codepoint <= 0x08FF) return BidiClass.NSM;
        if (codepoint >= 0x0900 && codepoint <= 0x0903) return BidiClass.NSM; // Devanagari marks (partial)
        if (codepoint == 0x093A) return BidiClass.NSM;
        if (codepoint == 0x093C) return BidiClass.NSM;
        if (codepoint >= 0x1AB0 && codepoint <= 0x1AFF) return BidiClass.NSM; // Combining Diacritical Marks Extended
        if (codepoint >= 0x1DC0 && codepoint <= 0x1DFF) return BidiClass.NSM;
        if (codepoint >= 0x20D0 && codepoint <= 0x20FF) return BidiClass.NSM; // Combining Diacritical Marks for Symbols
        if (codepoint >= 0xFE20 && codepoint <= 0xFE2F) return BidiClass.NSM; // Combining Half Marks
        // Hebrew Presentation Forms NSM + ES exceptions (must precede the FB1D..FB4F R blanket).
        if (codepoint == 0xFB1E) return BidiClass.NSM; // HEBREW POINT JUDEO-SPANISH VARIKA
        if (codepoint == 0xFB29) return BidiClass.ES;  // HEBREW LETTER ALTERNATIVE PLUS SIGN

        // Coarse strong-RTL blocks — resolved AFTER the specific-codepoint overrides above.
        if (codepoint >= 0x0590 && codepoint <= 0x05FF) return BidiClass.R;   // Hebrew
        if (codepoint >= 0x0600 && codepoint <= 0x06FF) return BidiClass.AL;  // Arabic
        if (codepoint >= 0x0700 && codepoint <= 0x074F) return BidiClass.AL;  // Syriac
        if (codepoint >= 0x0750 && codepoint <= 0x077F) return BidiClass.AL;  // Arabic Supplement
        if (codepoint >= 0x0780 && codepoint <= 0x07BF) return BidiClass.AL;  // Thaana
        if (codepoint >= 0x07C0 && codepoint <= 0x07FF) return BidiClass.R;   // NKo
        if (codepoint >= 0x0800 && codepoint <= 0x083F) return BidiClass.R;   // Samaritan
        if (codepoint >= 0x0840 && codepoint <= 0x085F) return BidiClass.R;   // Mandaic
        if (codepoint >= 0x08A0 && codepoint <= 0x08FF) return BidiClass.AL;  // Arabic Extended-A
        if (codepoint >= 0xFB1D && codepoint <= 0xFB4F) return BidiClass.R;   // Hebrew Presentation Forms
        if (codepoint >= 0xFB50 && codepoint <= 0xFDFF) return BidiClass.AL;  // Arabic Presentation Forms-A
        if (codepoint >= 0xFE70 && codepoint <= 0xFEFF) return BidiClass.AL;  // Arabic Presentation Forms-B
        if (codepoint >= 0x10800 && codepoint <= 0x10FFF) return BidiClass.R; // Ancient RTL scripts
        if (codepoint >= 0x1E800 && codepoint <= 0x1EFFF) return BidiClass.AL; // Arabic Math + Adlam

        // European number separators / terminators inside the general punctuation and Latin
        // supplement blocks.
        if (codepoint == 0x00B0 || codepoint == 0x00B1 || codepoint == 0x00B2 || codepoint == 0x00B3
         || codepoint == 0x00B9 || codepoint == 0x2030 || codepoint == 0x2031)
            return BidiClass.ET;
        if (codepoint >= 0x2074 && codepoint <= 0x2079) return BidiClass.EN;   // Superscript digits
        if (codepoint >= 0x2080 && codepoint <= 0x2089) return BidiClass.EN;   // Subscript digits

        // Whitespace.
        if (codepoint >= 0x2000 && codepoint <= 0x200A) return BidiClass.WS;   // Various spaces
        if (codepoint == 0x205F || codepoint == 0x3000) return BidiClass.WS;   // Medium math space, ideographic space

        // CJK / other LTR-strong blocks — explicit L to keep the algorithm from falling through
        // to an ON default when it must not.
        if (codepoint >= 0x0370 && codepoint <= 0x058F) return BidiClass.L;    // Greek, Cyrillic, Armenian
        if (codepoint >= 0x2C00 && codepoint <= 0x2DFF) return BidiClass.L;    // Glagolitic, Coptic, Georgian
        if (codepoint >= 0x3040 && codepoint <= 0x30FF) return BidiClass.L;    // Hiragana + Katakana
        if (codepoint >= 0x3400 && codepoint <= 0x4DBF) return BidiClass.L;    // CJK Ext A
        if (codepoint >= 0x4E00 && codepoint <= 0x9FFF) return BidiClass.L;    // CJK Unified
        if (codepoint >= 0xAC00 && codepoint <= 0xD7A3) return BidiClass.L;    // Hangul Syllables
        if (codepoint >= 0xF900 && codepoint <= 0xFAFF) return BidiClass.L;    // CJK Compatibility Ideographs
        if (codepoint >= 0x20000 && codepoint <= 0x2FFFF) return BidiClass.L;  // CJK Ext B..F + SIP

        // Default for uncovered codepoints — other neutrals.
        return BidiClass.ON;
    }

    /// <summary>True when a codepoint's class is L, R or AL (strong direction).</summary>
    public static bool IsStrong(BidiClass cls) => cls is BidiClass.L or BidiClass.R or BidiClass.AL;

    /// <summary>True when a codepoint is a mirrored paired bracket (used by rule N0).</summary>
    public static bool TryGetBracketPair(int codepoint, out int pairedWith, out bool opens)
    {
        if (BracketPairs.TryGetValue(codepoint, out (int paired, bool opens) info))
        {
            pairedWith = info.paired;
            opens = info.opens;
            return true;
        }
        pairedWith = 0;
        opens = false;
        return false;
    }

    /// <summary>
    /// Returns the mirror-glyph codepoint (used by rule L4), or 0 when none. The set covers the
    /// standard Unicode bidi-mirroring table for ASCII, common math and quotation, guillemets,
    /// tortoise-shell and angle brackets, fullwidth and halfwidth forms, small-form variants,
    /// arrows, and the mathematical bracket blocks — every codepoint the shipped interface can
    /// receive from user content, backup titles, and localized strings.
    /// </summary>
    public static int MirrorGlyph(int codepoint) => codepoint switch
    {
        // ASCII paired brackets + relational operators.
        '(' => ')',
        ')' => '(',
        '[' => ']',
        ']' => '[',
        '{' => '}',
        '}' => '{',
        '<' => '>',
        '>' => '<',

        // Guillemets — the standard European quotation for RTL locales.
        0x2039 => 0x203A,
        0x203A => 0x2039, // single '‹' '›'
        0x00AB => 0x00BB,
        0x00BB => 0x00AB, // double '«' '»'

        // Math relational + set operators.
        0x2208 => 0x220B,
        0x220B => 0x2208, // ∈ ∋
        0x2209 => 0x220C,
        0x220C => 0x2209, // ∉ ∌
        0x220A => 0x220D,
        0x220D => 0x220A, // ∊ ∍
        0x2215 => 0x29F5,
        0x29F5 => 0x2215, // ∕ ⧵
        0x223C => 0x223D,
        0x223D => 0x223C, // ∼ ∽
        0x2243 => 0x22CD,
        0x22CD => 0x2243, // ≃ ⋍
        0x2252 => 0x2253,
        0x2253 => 0x2252, // ≒ ≓
        0x2254 => 0x2255,
        0x2255 => 0x2254, // ≔ ≕
        0x2264 => 0x2265,
        0x2265 => 0x2264, // ≤ ≥
        0x2266 => 0x2267,
        0x2267 => 0x2266, // ≦ ≧
        0x2268 => 0x2269,
        0x2269 => 0x2268, // ≨ ≩
        0x226A => 0x226B,
        0x226B => 0x226A, // ≪ ≫
        0x226E => 0x226F,
        0x226F => 0x226E, // ≮ ≯
        0x2270 => 0x2271,
        0x2271 => 0x2270, // ≰ ≱
        0x2272 => 0x2273,
        0x2273 => 0x2272, // ≲ ≳
        0x2274 => 0x2275,
        0x2275 => 0x2274, // ≴ ≵
        0x2276 => 0x2277,
        0x2277 => 0x2276, // ≶ ≷
        0x2278 => 0x2279,
        0x2279 => 0x2278, // ≸ ≹
        0x227A => 0x227B,
        0x227B => 0x227A, // ≺ ≻
        0x227C => 0x227D,
        0x227D => 0x227C, // ≼ ≽
        0x227E => 0x227F,
        0x227F => 0x227E, // ≾ ≿
        0x2280 => 0x2281,
        0x2281 => 0x2280, // ⊀ ⊁
        0x2282 => 0x2283,
        0x2283 => 0x2282, // ⊂ ⊃
        0x2284 => 0x2285,
        0x2285 => 0x2284, // ⊄ ⊅
        0x2286 => 0x2287,
        0x2287 => 0x2286, // ⊆ ⊇
        0x2288 => 0x2289,
        0x2289 => 0x2288, // ⊈ ⊉
        0x228A => 0x228B,
        0x228B => 0x228A, // ⊊ ⊋
        0x228F => 0x2290,
        0x2290 => 0x228F, // ⊏ ⊐
        0x2291 => 0x2292,
        0x2292 => 0x2291, // ⊑ ⊒
        0x22A2 => 0x22A3,
        0x22A3 => 0x22A2, // ⊢ ⊣
        0x22A6 => 0x2ADE,
        0x2ADE => 0x22A6, // ⊦ ⫞
        0x22A8 => 0x2AE4,
        0x2AE4 => 0x22A8, // ⊨ ⫤
        0x22A9 => 0x2AE3,
        0x2AE3 => 0x22A9, // ⊩ ⫣
        0x22AB => 0x2AE5,
        0x2AE5 => 0x22AB, // ⊫ ⫥

        // Arrows.
        0x2190 => 0x2192,
        0x2192 => 0x2190, // ← →
        0x21A4 => 0x21A6,
        0x21A6 => 0x21A4, // ↤ ↦
        0x21A9 => 0x21AA,
        0x21AA => 0x21A9, // ↩ ↪
        0x21B0 => 0x21B1,
        0x21B1 => 0x21B0, // ↰ ↱
        0x21B2 => 0x21B3,
        0x21B3 => 0x21B2, // ↲ ↳
        0x21BC => 0x21C0,
        0x21C0 => 0x21BC, // ↼ ⇀
        0x21BD => 0x21C1,
        0x21C1 => 0x21BD, // ↽ ⇁
        0x21C7 => 0x21C9,
        0x21C9 => 0x21C7, // ⇇ ⇉
        0x21D0 => 0x21D2,
        0x21D2 => 0x21D0, // ⇐ ⇒
        0x21DA => 0x21DB,
        0x21DB => 0x21DA, // ⇚ ⇛

        // CJK angle / corner / tortoise-shell brackets.
        0x3008 => 0x3009,
        0x3009 => 0x3008, // 〈 〉
        0x300A => 0x300B,
        0x300B => 0x300A, // 《 》
        0x300C => 0x300D,
        0x300D => 0x300C, // 「 」
        0x300E => 0x300F,
        0x300F => 0x300E, // 『 』
        0x3010 => 0x3011,
        0x3011 => 0x3010, // 【 】
        0x3014 => 0x3015,
        0x3015 => 0x3014, // 〔 〕
        0x3016 => 0x3017,
        0x3017 => 0x3016, // 〖 〗
        0x3018 => 0x3019,
        0x3019 => 0x3018, // 〘 〙
        0x301A => 0x301B,
        0x301B => 0x301A, // 〚 〛

        // Small-form variants.
        0xFE59 => 0xFE5A,
        0xFE5A => 0xFE59, // ﹙ ﹚
        0xFE5B => 0xFE5C,
        0xFE5C => 0xFE5B, // ﹛ ﹜
        0xFE5D => 0xFE5E,
        0xFE5E => 0xFE5D, // ﹝ ﹞
        0xFE64 => 0xFE65,
        0xFE65 => 0xFE64, // ﹤ ﹥

        // Fullwidth / halfwidth brackets.
        0xFF08 => 0xFF09,
        0xFF09 => 0xFF08, // （ ）
        0xFF1C => 0xFF1E,
        0xFF1E => 0xFF1C, // ＜ ＞
        0xFF3B => 0xFF3D,
        0xFF3D => 0xFF3B, // ［ ］
        0xFF5B => 0xFF5D,
        0xFF5D => 0xFF5B, // ｛ ｝
        0xFF5F => 0xFF60,
        0xFF60 => 0xFF5F, // ｟ ｠
        0xFF62 => 0xFF63,
        0xFF63 => 0xFF62, // ｢ ｣

        // Mathematical brackets (Unicode block U+27C5..U+27EF, U+2983..U+2998).
        0x27C5 => 0x27C6,
        0x27C6 => 0x27C5, // ⟅ ⟆
        0x27E6 => 0x27E7,
        0x27E7 => 0x27E6, // ⟦ ⟧
        0x27E8 => 0x27E9,
        0x27E9 => 0x27E8, // ⟨ ⟩
        0x27EA => 0x27EB,
        0x27EB => 0x27EA, // ⟪ ⟫
        0x27EC => 0x27ED,
        0x27ED => 0x27EC, // ⟬ ⟭
        0x27EE => 0x27EF,
        0x27EF => 0x27EE, // ⟮ ⟯
        0x2983 => 0x2984,
        0x2984 => 0x2983, // ⦃ ⦄
        0x2985 => 0x2986,
        0x2986 => 0x2985, // ⦅ ⦆
        0x2987 => 0x2988,
        0x2988 => 0x2987, // ⦇ ⦈
        0x2989 => 0x298A,
        0x298A => 0x2989, // ⦉ ⦊
        0x298B => 0x298C,
        0x298C => 0x298B, // ⦋ ⦌
        0x298D => 0x2990,
        0x2990 => 0x298D, // ⦍ ⦐
        0x298F => 0x298E,
        0x298E => 0x298F, // ⦏ ⦎
        0x2991 => 0x2992,
        0x2992 => 0x2991, // ⦑ ⦒
        0x2993 => 0x2994,
        0x2994 => 0x2993, // ⦓ ⦔
        0x2995 => 0x2996,
        0x2996 => 0x2995, // ⦕ ⦖
        0x2997 => 0x2998,
        0x2998 => 0x2997, // ⦗ ⦘

        _ => 0,
    };

    // ---- Baked ASCII table (0..127). ----
    private static readonly BidiClass[] AsciiClass = BuildAsciiClass();

    private static BidiClass[] BuildAsciiClass()
    {
        var t = new BidiClass[128];
        for (int i = 0; i < 128; i++) t[i] = BidiClass.ON;

        // Controls.
        for (int i = 0; i < 32; i++) t[i] = BidiClass.BN;
        t[0x09] = BidiClass.S;
        t[0x0A] = BidiClass.B;
        t[0x0B] = BidiClass.S;
        t[0x0C] = BidiClass.WS;
        t[0x0D] = BidiClass.B;
        t[0x1C] = BidiClass.B;
        t[0x1D] = BidiClass.B;
        t[0x1E] = BidiClass.B;
        t[0x1F] = BidiClass.S;

        t[0x20] = BidiClass.WS;
        t[0x21] = BidiClass.ON;                     // !
        t[0x22] = BidiClass.ON;                     // "
        t[0x23] = BidiClass.ET;                     // # (per UAX)
        t[0x24] = BidiClass.ET;                     // $
        t[0x25] = BidiClass.ET;                     // %
        t[0x26] = BidiClass.ON;                     // &
        t[0x27] = BidiClass.ON;                     // '
        t[0x28] = BidiClass.ON;                     // (
        t[0x29] = BidiClass.ON;                     // )
        t[0x2A] = BidiClass.ON;                     // *
        t[0x2B] = BidiClass.ES;                     // +
        t[0x2C] = BidiClass.CS;                     // ,
        t[0x2D] = BidiClass.ES;                     // -
        t[0x2E] = BidiClass.CS;                     // .
        t[0x2F] = BidiClass.CS;                     // /

        for (int i = 0x30; i <= 0x39; i++) t[i] = BidiClass.EN;      // 0-9

        t[0x3A] = BidiClass.CS;                     // :
        t[0x3B] = BidiClass.ON;                     // ;
        t[0x3C] = BidiClass.ON;                     // <
        t[0x3D] = BidiClass.ON;                     // =
        t[0x3E] = BidiClass.ON;                     // >
        t[0x3F] = BidiClass.ON;                     // ?
        t[0x40] = BidiClass.ON;                     // @

        for (int i = 0x41; i <= 0x5A; i++) t[i] = BidiClass.L;       // A-Z
        t[0x5B] = BidiClass.ON;
        t[0x5C] = BidiClass.ON;
        t[0x5D] = BidiClass.ON;
        t[0x5E] = BidiClass.ON;
        t[0x5F] = BidiClass.ON;
        t[0x60] = BidiClass.ON;

        for (int i = 0x61; i <= 0x7A; i++) t[i] = BidiClass.L;       // a-z
        t[0x7B] = BidiClass.ON;
        t[0x7C] = BidiClass.ON;
        t[0x7D] = BidiClass.ON;
        t[0x7E] = BidiClass.ON;
        t[0x7F] = BidiClass.BN;
        return t;
    }

    // ---- Paired brackets for rule N0 (mirrored bracket pair matching). ----
    // The paired-bracket table N0 references. Includes ASCII parens/square/curly, CJK corner and
    // tortoise-shell brackets, the mathematical bracket blocks, small-form variants, and
    // fullwidth/halfwidth forms — every codepoint the Unicode BidiBrackets data lists as bidi
    // pair. Angle brackets '<' '>' are NOT in the paired-bracket set (they carry ON class and
    // are handled by N1 rather than N0).
    private static readonly Dictionary<int, (int paired, bool opens)> BracketPairs = new()
    {
        // ASCII.
        ['('] = (')', true),
        [')'] = ('(', false),
        ['['] = (']', true),
        [']'] = ('[', false),
        ['{'] = ('}', true),
        ['}'] = ('{', false),

        // Ogham feather marks (used as brackets in Ogham text).
        [0x169B] = (0x169C, true),
        [0x169C] = (0x169B, false),

        // CJK punctuation brackets.
        [0x3008] = (0x3009, true),
        [0x3009] = (0x3008, false),  // 〈 〉
        [0x300A] = (0x300B, true),
        [0x300B] = (0x300A, false),  // 《 》
        [0x300C] = (0x300D, true),
        [0x300D] = (0x300C, false),  // 「 」
        [0x300E] = (0x300F, true),
        [0x300F] = (0x300E, false),  // 『 』
        [0x3010] = (0x3011, true),
        [0x3011] = (0x3010, false),  // 【 】
        [0x3014] = (0x3015, true),
        [0x3015] = (0x3014, false),  // 〔 〕
        [0x3016] = (0x3017, true),
        [0x3017] = (0x3016, false),  // 〖 〗
        [0x3018] = (0x3019, true),
        [0x3019] = (0x3018, false),  // 〘 〙
        [0x301A] = (0x301B, true),
        [0x301B] = (0x301A, false),  // 〚 〛

        // Mathematical brackets.
        [0x27C5] = (0x27C6, true),
        [0x27C6] = (0x27C5, false),  // ⟅ ⟆
        [0x27E6] = (0x27E7, true),
        [0x27E7] = (0x27E6, false),  // ⟦ ⟧
        [0x27E8] = (0x27E9, true),
        [0x27E9] = (0x27E8, false),  // ⟨ ⟩
        [0x27EA] = (0x27EB, true),
        [0x27EB] = (0x27EA, false),  // ⟪ ⟫
        [0x27EC] = (0x27ED, true),
        [0x27ED] = (0x27EC, false),  // ⟬ ⟭
        [0x27EE] = (0x27EF, true),
        [0x27EF] = (0x27EE, false),  // ⟮ ⟯
        [0x2983] = (0x2984, true),
        [0x2984] = (0x2983, false),  // ⦃ ⦄
        [0x2985] = (0x2986, true),
        [0x2986] = (0x2985, false),  // ⦅ ⦆
        [0x2987] = (0x2988, true),
        [0x2988] = (0x2987, false),  // ⦇ ⦈
        [0x2989] = (0x298A, true),
        [0x298A] = (0x2989, false),  // ⦉ ⦊
        [0x298B] = (0x298C, true),
        [0x298C] = (0x298B, false),  // ⦋ ⦌
        [0x298D] = (0x2990, true),
        [0x2990] = (0x298D, false),  // ⦍ ⦐
        [0x298F] = (0x298E, true),
        [0x298E] = (0x298F, false),  // ⦏ ⦎
        [0x2991] = (0x2992, true),
        [0x2992] = (0x2991, false),  // ⦑ ⦒
        [0x2993] = (0x2994, true),
        [0x2994] = (0x2993, false),  // ⦓ ⦔
        [0x2995] = (0x2996, true),
        [0x2996] = (0x2995, false),  // ⦕ ⦖
        [0x2997] = (0x2998, true),
        [0x2998] = (0x2997, false),  // ⦗ ⦘

        // Small form variants.
        [0xFE59] = (0xFE5A, true),
        [0xFE5A] = (0xFE59, false),  // ﹙ ﹚
        [0xFE5B] = (0xFE5C, true),
        [0xFE5C] = (0xFE5B, false),  // ﹛ ﹜
        [0xFE5D] = (0xFE5E, true),
        [0xFE5E] = (0xFE5D, false),  // ﹝ ﹞

        // Fullwidth brackets.
        [0xFF08] = (0xFF09, true),
        [0xFF09] = (0xFF08, false),  // （ ）
        [0xFF3B] = (0xFF3D, true),
        [0xFF3D] = (0xFF3B, false),  // ［ ］
        [0xFF5B] = (0xFF5D, true),
        [0xFF5D] = (0xFF5B, false),  // ｛ ｝
        [0xFF5F] = (0xFF60, true),
        [0xFF60] = (0xFF5F, false),  // ｟ ｠

        // Halfwidth CJK brackets.
        [0xFF62] = (0xFF63, true),
        [0xFF63] = (0xFF62, false),  // ｢ ｣
    };
}
