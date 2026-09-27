// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Globalization;

/// <summary>
/// The CLDR cardinal-plural categories the localizer dispatches over. Every language uses a
/// subset; a caller who does not want to author every category still supplies at least "other",
/// which every rule falls back to.
/// </summary>
public enum PluralClass : byte
{
    /// <summary>The universal category; every language uses this. The fallback when nothing else matches.</summary>
    Other = 0,

    /// <summary>Count of zero (Arabic).</summary>
    Zero = 1,

    /// <summary>Count of one (many languages, but not all — Chinese/Japanese/Korean/Thai use only Other).</summary>
    One = 2,

    /// <summary>Count of two (Arabic).</summary>
    Two = 3,

    /// <summary>Small plurals (Slavic, Arabic, Romanian).</summary>
    Few = 4,

    /// <summary>Large plurals or fractional (Slavic, Arabic).</summary>
    Many = 5,
}

/// <summary>Suffix conventions for CLDR plural sub-keys stored alongside a base string key.</summary>
public static class PluralClassSuffixes
{
    /// <summary>The literal suffix authors write into their string tables ("zero"/"one"/"two"/"few"/"many"/"other").</summary>
    public static string SuffixFor(PluralClass cls) => cls switch
    {
        PluralClass.Zero => "zero",
        PluralClass.One => "one",
        PluralClass.Two => "two",
        PluralClass.Few => "few",
        PluralClass.Many => "many",
        _ => "other",
    };
}
