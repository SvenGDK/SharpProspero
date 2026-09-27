// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization;

/// <summary>
/// Maps a <see cref="LanguageTag"/> to the on-screen keyboard's language bitmask value. The
/// bitmask is a 64-bit field with one bit per language and is passed to
/// <c>SceImeDialogParam.supportedLanguages</c> to restrict the keyboard to the languages a
/// title actually accepts. Passing zero defers to the console's configured input languages,
/// which is the usual choice for a general-purpose tool.
/// </summary>
/// <remarks>
/// The bitmask does not follow <see cref="SystemLanguageMap"/>'s ordinal order — Hungarian sits
/// at bit 32 (<c>0x1_00000000</c>), which is why every accessor returns a <see cref="ulong"/>
/// rather than a <see cref="uint"/>.
/// </remarks>
public static class ImeLanguageMap
{
    /// <summary>The single-language bit for Danish.</summary>
    public const ulong Danish = 0x0000000000000001UL;

    /// <summary>The single-language bit for German.</summary>
    public const ulong German = 0x0000000000000002UL;

    /// <summary>The single-language bit for English (United States).</summary>
    public const ulong EnglishUS = 0x0000000000000004UL;

    /// <summary>The single-language bit for Spanish (Spain).</summary>
    public const ulong Spanish = 0x0000000000000008UL;

    /// <summary>The single-language bit for French (France).</summary>
    public const ulong French = 0x0000000000000010UL;

    /// <summary>The single-language bit for Italian.</summary>
    public const ulong Italian = 0x0000000000000020UL;

    /// <summary>The single-language bit for Dutch.</summary>
    public const ulong Dutch = 0x0000000000000040UL;

    /// <summary>The single-language bit for Norwegian.</summary>
    public const ulong Norwegian = 0x0000000000000080UL;

    /// <summary>The single-language bit for Polish.</summary>
    public const ulong Polish = 0x0000000000000100UL;

    /// <summary>The single-language bit for Portuguese (Portugal).</summary>
    public const ulong PortuguesePortugal = 0x0000000000000200UL;

    /// <summary>The single-language bit for Russian.</summary>
    public const ulong Russian = 0x0000000000000400UL;

    /// <summary>The single-language bit for Finnish.</summary>
    public const ulong Finnish = 0x0000000000000800UL;

    /// <summary>The single-language bit for Swedish.</summary>
    public const ulong Swedish = 0x0000000000001000UL;

    /// <summary>The single-language bit for Japanese.</summary>
    public const ulong Japanese = 0x0000000000002000UL;

    /// <summary>The single-language bit for Korean.</summary>
    public const ulong Korean = 0x0000000000004000UL;

    /// <summary>The single-language bit for Simplified Chinese.</summary>
    public const ulong SimplifiedChinese = 0x0000000000008000UL;

    /// <summary>The single-language bit for Traditional Chinese.</summary>
    public const ulong TraditionalChinese = 0x0000000000010000UL;

    /// <summary>The single-language bit for Portuguese (Brazil).</summary>
    public const ulong PortugueseBrazil = 0x0000000000020000UL;

    /// <summary>The single-language bit for English (United Kingdom).</summary>
    public const ulong EnglishGB = 0x0000000000040000UL;

    /// <summary>The single-language bit for Turkish.</summary>
    public const ulong Turkish = 0x0000000000080000UL;

    /// <summary>The single-language bit for Spanish (Latin America).</summary>
    public const ulong SpanishLatinAmerica = 0x0000000000100000UL;

    /// <summary>The single-language bit for Arabic.</summary>
    public const ulong Arabic = 0x0000000001000000UL;

    /// <summary>The single-language bit for French (Canada).</summary>
    public const ulong FrenchCanada = 0x0000000002000000UL;

    /// <summary>The single-language bit for Thai.</summary>
    public const ulong Thai = 0x0000000004000000UL;

    /// <summary>The single-language bit for Czech.</summary>
    public const ulong Czech = 0x0000000008000000UL;

    /// <summary>The single-language bit for Greek.</summary>
    public const ulong Greek = 0x0000000010000000UL;

    /// <summary>The single-language bit for Indonesian.</summary>
    public const ulong Indonesian = 0x0000000020000000UL;

    /// <summary>The single-language bit for Vietnamese.</summary>
    public const ulong Vietnamese = 0x0000000040000000UL;

    /// <summary>The single-language bit for Romanian.</summary>
    public const ulong Romanian = 0x0000000080000000UL;

    /// <summary>The single-language bit for Hungarian — bit 32, above the 31-bit mark.</summary>
    public const ulong Hungarian = 0x0000000100000000UL;

    // Ordered list of (BCP-47 primary tag or full region tag, bitmask) pairs. Region-specific
    // tags are listed BEFORE the plain language so a lookup for "pt-BR" resolves to
    // PortugueseBrazil rather than to PortuguesePortugal.
    private static readonly (string Tag, ulong Bit)[] _pairs =
    [
        ("ja-JP", Japanese),
        ("en-US", EnglishUS),
        ("en-GB", EnglishGB),
        ("fr-CA", FrenchCanada),
        ("fr-FR", French),
        ("es-419", SpanishLatinAmerica),
        ("es-ES", Spanish),
        ("de-DE", German),
        ("it-IT", Italian),
        ("nl-NL", Dutch),
        ("pt-BR", PortugueseBrazil),
        ("pt-PT", PortuguesePortugal),
        ("ru-RU", Russian),
        ("ko-KR", Korean),
        ("zh-Hans", SimplifiedChinese),
        ("zh-Hant", TraditionalChinese),
        ("fi-FI", Finnish),
        ("sv-SE", Swedish),
        ("da-DK", Danish),
        ("no-NO", Norwegian),
        ("pl-PL", Polish),
        ("tr-TR", Turkish),
        ("ar-AE", Arabic),
        ("cs-CZ", Czech),
        ("hu-HU", Hungarian),
        ("el-GR", Greek),
        ("ro-RO", Romanian),
        ("th-TH", Thai),
        ("vi-VN", Vietnamese),
        ("id-ID", Indonesian),
    ];

    // Language-primary fallbacks used when a caller passes a bare "fr" or "pt" with no region.
    // Values are chosen to match the console's default variant for that language: fr → French
    // (France), pt → Portuguese (Portugal), zh → Simplified Chinese, en → English (US).
    private static readonly Dictionary<string, ulong> _primary = new(StringComparer.Ordinal)
    {
        { "ja", Japanese },
        { "en", EnglishUS },
        { "fr", French },
        { "es", Spanish },
        { "de", German },
        { "it", Italian },
        { "nl", Dutch },
        { "pt", PortuguesePortugal },
        { "ru", Russian },
        { "ko", Korean },
        { "zh", SimplifiedChinese },
        { "fi", Finnish },
        { "sv", Swedish },
        { "da", Danish },
        { "no", Norwegian },
        { "pl", Polish },
        { "tr", Turkish },
        { "ar", Arabic },
        { "cs", Czech },
        { "hu", Hungarian },
        { "el", Greek },
        { "ro", Romanian },
        { "th", Thai },
        { "vi", Vietnamese },
        { "id", Indonesian },
    };

    /// <summary>
    /// The single-language bit for <paramref name="tag"/>, or zero when the tag has no mapping.
    /// A caller building a bitmask OR-s the returned value into its accumulator.
    /// </summary>
    public static ulong ForLanguage(LanguageTag tag)
    {
        if (tag is null || tag.IsRoot)
            return 0UL;

        string canonical = tag.Canonical;
        foreach ((string t, ulong bit) in _pairs)
        {
            if (string.Equals(t, canonical, StringComparison.Ordinal))
                return bit;
        }
        return _primary.TryGetValue(tag.Language, out ulong primary) ? primary : 0UL;
    }

    /// <summary>
    /// The bitmask that covers every language in <paramref name="tags"/>. Duplicate tags fold
    /// into the same bit; a tag with no mapping contributes zero.
    /// </summary>
    public static ulong ForLanguages(IEnumerable<LanguageTag> tags)
    {
        ArgumentNullException.ThrowIfNull(tags);
        ulong mask = 0UL;
        foreach (LanguageTag tag in tags)
            mask |= ForLanguage(tag);
        return mask;
    }

    /// <summary>
    /// The bitmask that covers every language mapped in this table — passing it to the keyboard
    /// asks for every input language the console supports.
    /// </summary>
    public static ulong All()
    {
        ulong mask = 0UL;
        foreach ((_, ulong bit) in _pairs)
            mask |= bit;
        return mask;
    }
}
