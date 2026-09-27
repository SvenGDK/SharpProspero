// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Globalization;

/// <summary>The paragraph base direction the interface lays text out in.</summary>
public enum TextDirection : byte
{
    /// <summary>Left-to-right (Latin, Cyrillic, Greek, CJK).</summary>
    Ltr = 0,

    /// <summary>Right-to-left (Arabic, Hebrew, Persian, Urdu, Yiddish).</summary>
    Rtl = 1,

    /// <summary>Choose Ltr or Rtl per paragraph from the first strong character (UAX #9 rules P2/P3).</summary>
    Auto = 2,
}

/// <summary>Direction helpers driven from a <see cref="LanguageTag"/>.</summary>
public static class TextDirections
{
    /// <summary>
    /// The base direction a language is written in. Right-to-left is returned for Arabic, Hebrew,
    /// Persian, Urdu and Yiddish; every other language returns <see cref="TextDirection.Ltr"/>.
    /// A tag whose primary language is <see cref="LanguageTag.Root"/> also returns Ltr.
    /// </summary>
    public static TextDirection ForLanguage(LanguageTag tag)
    {
        if (tag is null || tag.IsRoot)
            return TextDirection.Ltr;
        string p = tag.Language;
        return p switch
        {
            "ar" or "he" or "fa" or "ur" or "yi" or "iw" or "ji" or "ps" or "sd" => TextDirection.Rtl,
            _ => TextDirection.Ltr,
        };
    }

    /// <summary>
    /// Resolves a preferred direction against a language and paragraph text. <see cref="TextDirection.Auto"/>
    /// is turned into Ltr or Rtl by scanning for the first strong-direction character in
    /// <paramref name="text"/>; when no strong character is present, the language's default
    /// direction is used.
    /// </summary>
    public static TextDirection Resolve(TextDirection preferred, ReadOnlySpan<char> text, LanguageTag language)
    {
        if (preferred != TextDirection.Auto)
            return preferred;

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            // Arabic (0x0600..0x06FF, 0x0750..0x077F), Hebrew (0x0590..0x05FF), Syriac (0x0700..0x074F),
            // Thaana (0x0780..0x07BF), NKo (0x07C0..0x07FF), plus the Arabic Presentation Forms
            // blocks (0xFB50..0xFDFF, 0xFE70..0xFEFF) resolve as strong RTL under UAX #9. Every
            // ASCII letter, most Latin-Extended and CJK codepoints resolve as strong LTR.
            if (IsStrongRtl(c))
                return TextDirection.Rtl;
            if (IsStrongLtr(c))
                return TextDirection.Ltr;
        }
        return ForLanguage(language);
    }

    /// <summary>True when the codepoint is a strong-RTL character per UAX #9 (R or AL class).</summary>
    public static bool IsStrongRtl(char c)
    {
        return (c >= 0x0590 && c <= 0x05FF)
            || (c >= 0x0600 && c <= 0x06FF)
            || (c >= 0x0700 && c <= 0x074F)
            || (c >= 0x0750 && c <= 0x077F)
            || (c >= 0x0780 && c <= 0x07BF)
            || (c >= 0x07C0 && c <= 0x07FF)
            || (c >= 0xFB1D && c <= 0xFB4F)
            || (c >= 0xFB50 && c <= 0xFDFF)
            || (c >= 0xFE70 && c <= 0xFEFF);
    }

    /// <summary>True when the codepoint is a strong-LTR character (L class) — the common ASCII/Latin/CJK letters.</summary>
    public static bool IsStrongLtr(char c)
    {
        return (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z')
            || (c >= 0x00C0 && c <= 0x02AF)   // Latin-1 supplement + Latin Extended-A/B
            || (c >= 0x0370 && c <= 0x03FF)   // Greek and Coptic
            || (c >= 0x0400 && c <= 0x04FF)   // Cyrillic
            || (c >= 0x3040 && c <= 0x30FF)   // Hiragana + Katakana
            || (c >= 0x3400 && c <= 0x9FFF)   // CJK Unified Ideographs (BMP)
            || (c >= 0xAC00 && c <= 0xD7A3);  // Hangul Syllables
    }
}
