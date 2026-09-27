// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Globalization.Text;

/// <summary>
/// The coarse script a codepoint belongs to, used by the font cascade to route a character to the
/// tier that carries a matching glyph. Fine-grained script data (Unicode's full Scripts.txt) is
/// not needed — the cascade only distinguishes between Latin (Tier 1), Cyrillic/Greek (Tier 2 —
/// still covered by European fonts), Arabic (needs Arabic font set), Hebrew (same), CJK (needs
/// CJK font set), Thai (needs Thai font set), Hangul (needs CJK universal), and the "other"
/// bucket that falls through to the universal blob.
/// </summary>
public enum FontScript : byte
{
    /// <summary>Anything the classifier does not recognise; routes to the universal blob.</summary>
    Other,

    /// <summary>Latin (Basic + Extended-A/B + Latin Supplement).</summary>
    Latin,

    /// <summary>Cyrillic (all supplements).</summary>
    Cyrillic,

    /// <summary>Greek + Coptic.</summary>
    Greek,

    /// <summary>Arabic + Syriac + Thaana + NKo + Arabic presentation forms.</summary>
    Arabic,

    /// <summary>Hebrew + Hebrew presentation forms.</summary>
    Hebrew,

    /// <summary>Devanagari.</summary>
    Devanagari,

    /// <summary>Thai + Lao + Khmer + Myanmar.</summary>
    Thai,

    /// <summary>CJK Unified Ideographs (all extensions) + Kanji.</summary>
    CjkUnified,

    /// <summary>Hangul (Korean).</summary>
    Hangul,

    /// <summary>Hiragana + Katakana.</summary>
    Kana,

    /// <summary>Emoji / Extended_Pictographic.</summary>
    ExtendedPictographic,
}

/// <summary>Classifies a codepoint into a <see cref="FontScript"/> for cascade routing.</summary>
public static class ScriptClassifier
{
    /// <summary>Returns the script of a codepoint.</summary>
    public static FontScript ClassifyCodepoint(int codepoint)
    {
        if (codepoint < 0x80)
        {
            if ((codepoint >= 'A' && codepoint <= 'Z') || (codepoint >= 'a' && codepoint <= 'z'))
                return FontScript.Latin;
            return FontScript.Other;
        }

        // Latin supplements.
        if (codepoint <= 0x02AF) return FontScript.Latin;
        if (codepoint >= 0x1E00 && codepoint <= 0x1EFF) return FontScript.Latin;
        if (codepoint >= 0x2C60 && codepoint <= 0x2C7F) return FontScript.Latin;
        if (codepoint >= 0xA720 && codepoint <= 0xA7FF) return FontScript.Latin;

        // Greek.
        if (codepoint >= 0x0370 && codepoint <= 0x03FF) return FontScript.Greek;
        if (codepoint >= 0x1F00 && codepoint <= 0x1FFF) return FontScript.Greek;

        // Cyrillic.
        if (codepoint >= 0x0400 && codepoint <= 0x04FF) return FontScript.Cyrillic;
        if (codepoint >= 0x0500 && codepoint <= 0x052F) return FontScript.Cyrillic;
        if (codepoint >= 0x2DE0 && codepoint <= 0x2DFF) return FontScript.Cyrillic;
        if (codepoint >= 0xA640 && codepoint <= 0xA69F) return FontScript.Cyrillic;

        // Hebrew.
        if (codepoint >= 0x0590 && codepoint <= 0x05FF) return FontScript.Hebrew;
        if (codepoint >= 0xFB1D && codepoint <= 0xFB4F) return FontScript.Hebrew;

        // Arabic.
        if (codepoint >= 0x0600 && codepoint <= 0x06FF) return FontScript.Arabic;
        if (codepoint >= 0x0700 && codepoint <= 0x077F) return FontScript.Arabic;   // Syriac, Arabic supplement
        if (codepoint >= 0x0780 && codepoint <= 0x07BF) return FontScript.Arabic;   // Thaana
        if (codepoint >= 0x07C0 && codepoint <= 0x07FF) return FontScript.Arabic;   // NKo
        if (codepoint >= 0x08A0 && codepoint <= 0x08FF) return FontScript.Arabic;
        if (codepoint >= 0xFB50 && codepoint <= 0xFDFF) return FontScript.Arabic;
        if (codepoint >= 0xFE70 && codepoint <= 0xFEFF) return FontScript.Arabic;

        // Devanagari + South Asian.
        if (codepoint >= 0x0900 && codepoint <= 0x097F) return FontScript.Devanagari;

        // Thai + Lao + Khmer + Myanmar (SA class).
        if (codepoint >= 0x0E00 && codepoint <= 0x0E7F) return FontScript.Thai;
        if (codepoint >= 0x0E80 && codepoint <= 0x0EFF) return FontScript.Thai;
        if (codepoint >= 0x1000 && codepoint <= 0x109F) return FontScript.Thai;
        if (codepoint >= 0x1780 && codepoint <= 0x17FF) return FontScript.Thai;

        // Kana.
        if (codepoint >= 0x3040 && codepoint <= 0x309F) return FontScript.Kana;
        if (codepoint >= 0x30A0 && codepoint <= 0x30FF) return FontScript.Kana;
        if (codepoint >= 0x31F0 && codepoint <= 0x31FF) return FontScript.Kana;

        // Hangul.
        if (codepoint >= 0xAC00 && codepoint <= 0xD7A3) return FontScript.Hangul;
        if (codepoint >= 0x1100 && codepoint <= 0x11FF) return FontScript.Hangul;
        if (codepoint >= 0xA960 && codepoint <= 0xA97F) return FontScript.Hangul;
        if (codepoint >= 0xD7B0 && codepoint <= 0xD7FF) return FontScript.Hangul;

        // CJK Unified Ideographs + extensions.
        if (codepoint >= 0x3400 && codepoint <= 0x4DBF) return FontScript.CjkUnified;
        if (codepoint >= 0x4E00 && codepoint <= 0x9FFF) return FontScript.CjkUnified;
        if (codepoint >= 0xF900 && codepoint <= 0xFAFF) return FontScript.CjkUnified;
        if (codepoint >= 0x20000 && codepoint <= 0x2FFFF) return FontScript.CjkUnified;

        // Extended_Pictographic — routes through the same table as GraphemeBreakTable's emoji
        // check.
        if (codepoint >= 0x1F000 && codepoint <= 0x1FAFF) return FontScript.ExtendedPictographic;

        return FontScript.Other;
    }

    /// <summary>
    /// Resolves the <see cref="LanguageTag"/> to the SceFont script + language pair the on-device
    /// font engine's <c>sceFontSetScriptLanguage</c> takes. Latin languages get the default Latin
    /// tag; Arabic maps to the Arabic default; CJK languages pick the matching regional glyph
    /// variant so han characters render with the right style.
    /// </summary>
    public static (ushort SceFontScript, ushort SceFontLanguage) ResolveFontScriptLanguage(LanguageTag tag)
    {
        if (tag is null || tag.IsRoot)
            return ((ushort)0x0100, (ushort)0x0100); // LATIN + LATIN_DEFAULT

        switch (tag.Language)
        {
            // The SceFontLanguage codes follow the on-device font engine's header (libfont.h)
            // exactly: LATIN base 0x0101 and its per-language variants, ARABIC 0x0601, PERSIAN
            // 0x0602, CJK Japanese 0x3011, CJK Simplified 0x3021, CJK Traditional 0x3022,
            // CJK Korean 0x3041. The LATIN and CJK script codes stay at 0x0100 / 0x3000.
            case "ar": return ((ushort)0x0600, (ushort)0x0601);
            case "fa": return ((ushort)0x0600, (ushort)0x0602);
            case "ja": return ((ushort)0x3000, (ushort)0x3011); // CJK Japanese
            case "zh":
                return string.Equals(tag.Script, "Hant", StringComparison.Ordinal)
                    ? ((ushort)0x3000, (ushort)0x3022)  // CJK Traditional Chinese
                    : ((ushort)0x3000, (ushort)0x3021); // CJK Simplified Chinese
            case "ko": return ((ushort)0x3000, (ushort)0x3041); // CJK Korean
            case "nl": return ((ushort)0x0100, (ushort)0x0101);
            case "tr": return ((ushort)0x0100, (ushort)0x0102);
            case "ro": return ((ushort)0x0100, (ushort)0x0103);
            case "af": return ((ushort)0x0100, (ushort)0x0105);
            default: return ((ushort)0x0100, (ushort)0x0100); // LATIN default
        }
    }
}
