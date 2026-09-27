// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Platform;
using System;

namespace SharpProspero.Globalization;

/// <summary>
/// The fixed 30-entry table between the numeric <see cref="SystemLanguage"/> the console reports
/// and canonical BCP-47 <see cref="LanguageTag"/>s. Ordinals 0..29 map one-for-one; an ordinal
/// outside the range falls back to <see cref="LanguageTag.Invariant"/> (en-US) so a firmware that
/// bumps the enum never wedges the boot path.
/// </summary>
public static class SystemLanguageMap
{
    // Order matches SystemLanguage: 0=Japanese, 1=EnglishUS, 2=French, ...
    private static readonly string[] _tags =
    [
        "ja-JP",  // 0  Japanese
        "en-US",  // 1  English (US)
        "fr-FR",  // 2  French
        "es-ES",  // 3  Spanish
        "de-DE",  // 4  German
        "it-IT",  // 5  Italian
        "nl-NL",  // 6  Dutch
        "pt-PT",  // 7  Portuguese (Portugal)
        "ru-RU",  // 8  Russian
        "ko-KR",  // 9  Korean
        "zh-Hant",// 10 Traditional Chinese
        "zh-Hans",// 11 Simplified Chinese
        "fi-FI",  // 12 Finnish
        "sv-SE",  // 13 Swedish
        "da-DK",  // 14 Danish
        "no-NO",  // 15 Norwegian
        "pl-PL",  // 16 Polish
        "pt-BR",  // 17 Portuguese (Brazil)
        "en-GB",  // 18 English (UK)
        "tr-TR",  // 19 Turkish
        "es-419", // 20 Spanish (Latin America)
        "ar-AE",  // 21 Arabic
        "fr-CA",  // 22 French (Canada)
        "cs-CZ",  // 23 Czech
        "hu-HU",  // 24 Hungarian
        "el-GR",  // 25 Greek
        "ro-RO",  // 26 Romanian
        "th-TH",  // 27 Thai
        "vi-VN",  // 28 Vietnamese
        "id-ID",  // 29 Indonesian
    ];

    private static readonly LanguageTag[] _cached = BuildCache();

    private static LanguageTag[] BuildCache()
    {
        var buf = new LanguageTag[_tags.Length];
        for (int i = 0; i < _tags.Length; i++)
            buf[i] = LanguageTag.Parse(_tags[i]);
        return buf;
    }

    /// <summary>How many entries the mapping table carries (30).</summary>
    public static int Count => _tags.Length;

    /// <summary>The canonical <see cref="LanguageTag"/> for a <see cref="SystemLanguage"/> ordinal.</summary>
    public static LanguageTag ToLanguageTag(SystemLanguage lang)
    {
        int i = (int)lang;
        return (uint)i < (uint)_cached.Length ? _cached[i] : LanguageTag.Invariant;
    }

    /// <summary>Reads the raw int ordinal a console returned; out-of-range returns false and Invariant.</summary>
    public static bool TryToLanguageTag(int rawIndex, out LanguageTag tag)
    {
        if ((uint)rawIndex < (uint)_cached.Length)
        {
            tag = _cached[rawIndex];
            return true;
        }
        tag = LanguageTag.Invariant;
        return false;
    }

    /// <summary>
    /// The reverse lookup: a tag whose canonical form matches one of the 30 entries returns the
    /// numeric <see cref="SystemLanguage"/>. A tag that only matches by primary language uses the
    /// first entry for that language (e.g. "en" -> EnglishUS, "es" -> Spanish). A handful of
    /// non-canonical primary tags with a well-defined mapping — Norwegian Bokmål ("nb") and
    /// Nynorsk ("nn") both resolve to the Norwegian entry — are matched via an alias table so
    /// they do not fall through to the default.
    /// </summary>
    public static bool TryFromLanguageTag(LanguageTag tag, out SystemLanguage lang)
    {
        if (tag is null || tag.IsRoot)
        {
            lang = SystemLanguage.EnglishUS;
            return false;
        }

        for (int i = 0; i < _cached.Length; i++)
            if (_cached[i] == tag)
            {
                lang = (SystemLanguage)i;
                return true;
            }

        // Primary-only match.
        for (int i = 0; i < _cached.Length; i++)
            if (string.Equals(_cached[i].Language, tag.Language, StringComparison.Ordinal))
            {
                lang = (SystemLanguage)i;
                return true;
            }

        // Alias table for primary tags that do not appear in the canonical set but map cleanly.
        switch (tag.Language)
        {
            case "nb":
            case "nn":
                lang = SystemLanguage.Norwegian;
                return true;
            case "iw":  // Legacy code for Hebrew — no Hebrew SystemLanguage exists yet.
            case "ji":  // Legacy code for Yiddish.
                break;
        }

        lang = SystemLanguage.EnglishUS;
        return false;
    }

    /// <summary>The canonical BCP-47 tags in the same order as <see cref="SystemLanguage"/>.</summary>
    public static ReadOnlySpan<LanguageTag> All => _cached;
}
