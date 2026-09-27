// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;

namespace SharpProspero.Globalization;

/// <summary>
/// The CLDR-v45 plural-rule families the 30 canonical languages collapse into.
/// </summary>
public enum PluralRuleFamily : byte
{
    /// <summary>Every count uses Other. Members: ja, ko, zh, th, vi, id.</summary>
    OtherOnly,

    /// <summary>One when integer count equals 1 and there are no visible fraction digits; Other otherwise. Members: en, de, nl, sv, fi, it, pt (Portugal).</summary>
    OneOtherIntegerV0,

    /// <summary>One when `n = 1` (including 1.0, 1.00, etc. — no visible-fraction gate); Other otherwise. Members: es (both variants), tr, hu, el, nb, nn, no.</summary>
    OneOtherAbsoluteN1,

    /// <summary>Danish rule: One when `n = 1` OR when `t != 0 and i = 0..1`; Other otherwise.</summary>
    Danish,

    /// <summary>One when integer count is 0 or 1; Other otherwise. Members: fr, fr-CA, pt (plain), pt-BR.</summary>
    OneOtherIntegerZeroOne,

    /// <summary>Russian (also uk, be).</summary>
    Russian,

    /// <summary>Croatian family (One / Few / Other). Members: sr, hr, bs.</summary>
    Croatian,

    /// <summary>Polish.</summary>
    Polish,

    /// <summary>Czech.</summary>
    Czech,

    /// <summary>Romanian.</summary>
    Romanian,

    /// <summary>Arabic.</summary>
    Arabic,
}

/// <summary>
/// Classifies a numeric count into a <see cref="PluralClass"/> per the language's CLDR rules.
/// Every language is mapped to a <see cref="PluralRuleFamily"/>; classifying then runs the
/// family's rule against the count's operands (n, i, v, w, f, t per CLDR).
/// </summary>
public static class PluralRules
{
    /// <summary>The CLDR data snapshot pinned as source. Bumping to a newer CLDR requires a review of the rules below.</summary>
    public const string CldrVersion = "45";

    /// <summary>Returns the CLDR rule family that applies to <paramref name="tag"/>'s primary language.</summary>
    public static PluralRuleFamily FamilyOf(LanguageTag tag)
    {
        if (tag is null || tag.IsRoot)
            return PluralRuleFamily.OneOtherIntegerV0; // Root defaults to English's family.

        string primary = tag.Language;
        // CLDR-v45 puts plain 'pt' in the ZeroOne family; only pt-PT overrides to V0. Plain 'pt'
        // and pt-BR share the ZeroOne rule.
        if (primary == "pt")
            return string.Equals(tag.Region, "PT", StringComparison.Ordinal)
                ? PluralRuleFamily.OneOtherIntegerV0
                : PluralRuleFamily.OneOtherIntegerZeroOne;

        return primary switch
        {
            "ja" or "ko" or "zh" or "th" or "vi" or "id" => PluralRuleFamily.OtherOnly,
            "fr" => PluralRuleFamily.OneOtherIntegerZeroOne,
            // Absolute-n=1 languages: es/tr/hu/el and every Norwegian variant. These match 1.0,
            // 1.00, etc. (no v0 gate) which the V0 family does not.
            "es" or "tr" or "hu" or "el" or "nb" or "nn" or "no" => PluralRuleFamily.OneOtherAbsoluteN1,
            "da" => PluralRuleFamily.Danish,
            "ru" or "uk" or "be" => PluralRuleFamily.Russian,
            "sr" or "hr" or "bs" => PluralRuleFamily.Croatian,
            "pl" => PluralRuleFamily.Polish,
            "cs" or "sk" => PluralRuleFamily.Czech,
            "ro" or "mo" => PluralRuleFamily.Romanian,
            "ar" => PluralRuleFamily.Arabic,
            _ => PluralRuleFamily.OneOtherIntegerV0,
        };
    }

    /// <summary>Classifies an integer <paramref name="n"/> for <paramref name="tag"/>.</summary>
    public static PluralClass Classify(LanguageTag tag, long n)
    {
        PluralRuleFamily family = FamilyOf(tag);
        long i = n < 0 ? -n : n; // CLDR n is the absolute value; sign never affects the class.
        return family switch
        {
            PluralRuleFamily.OtherOnly => PluralClass.Other,
            PluralRuleFamily.OneOtherIntegerV0 => i == 1 ? PluralClass.One : PluralClass.Other,
            PluralRuleFamily.OneOtherAbsoluteN1 => i == 1 ? PluralClass.One : PluralClass.Other,
            PluralRuleFamily.Danish => i == 1 ? PluralClass.One : PluralClass.Other,
            PluralRuleFamily.OneOtherIntegerZeroOne => i is 0 or 1 ? PluralClass.One : PluralClass.Other,
            PluralRuleFamily.Russian => RussianRule(i),
            PluralRuleFamily.Croatian => CroatianRule(i),
            PluralRuleFamily.Polish => PolishRule(i),
            PluralRuleFamily.Czech => i == 1 ? PluralClass.One : i is >= 2 and <= 4 ? PluralClass.Few : PluralClass.Other,
            PluralRuleFamily.Romanian => RomanianRule(i),
            PluralRuleFamily.Arabic => ArabicRule(i),
            _ => PluralClass.Other,
        };
    }

    /// <summary>Classifies a decimal <paramref name="n"/> for <paramref name="tag"/>; visible fractions push most families to Other.</summary>
    public static PluralClass Classify(LanguageTag tag, decimal n)
    {
        int scale = (decimal.GetBits(n)[3] >> 16) & 0x7F;
        bool v0 = scale == 0;
        decimal absN = Math.Abs(n);
        long i = (long)Math.Truncate(absN);
        // f = the visible fraction digits treated as an integer, t = f with trailing zeros
        // stripped. Danish's `t != 0 and i = 0..1` needs `t` explicitly.
        decimal fracPart = absN - i;
        long t = 0;
        if (fracPart > 0m)
        {
            decimal shifted = fracPart;
            for (int s = 0; s < scale; s++) shifted *= 10m;
            long f = (long)Math.Round(shifted, MidpointRounding.AwayFromZero);
            while (f > 0 && f % 10 == 0) f /= 10;
            t = f;
        }

        PluralRuleFamily family = FamilyOf(tag);
        return family switch
        {
            PluralRuleFamily.OtherOnly => PluralClass.Other,
            // CLDR-v45 en/de/nl/sv/fi/it/pt-PT: One iff i=1 && v=0 (fractional 1.0/1.5 → Other).
            PluralRuleFamily.OneOtherIntegerV0 => v0 && i == 1 ? PluralClass.One : PluralClass.Other,
            // CLDR-v45 es/tr/hu/el/nb/nn/no: One iff n=1 (any fractional exact 1.0/1.00 counts as
            // One; 1.5 stays Other because n != 1).
            PluralRuleFamily.OneOtherAbsoluteN1 => absN == 1m ? PluralClass.One : PluralClass.Other,
            // CLDR-v45 da: One iff n=1 OR (t != 0 AND i in 0..1). So 0.5, 1.5, 1.0 are all One.
            PluralRuleFamily.Danish => (absN == 1m || (t != 0 && (i == 0 || i == 1)))
                ? PluralClass.One
                : PluralClass.Other,
            // CLDR-v45 fr/pt-BR: One iff i in 0..1 (no v gate). 0.5, 1.5 both One.
            PluralRuleFamily.OneOtherIntegerZeroOne => i is 0 or 1 ? PluralClass.One : PluralClass.Other,
            PluralRuleFamily.Russian => v0 ? RussianRule(i) : PluralClass.Other,
            PluralRuleFamily.Croatian => v0 ? CroatianRule(i) : PluralClass.Other,
            PluralRuleFamily.Polish => v0 ? PolishRule(i) : PluralClass.Other,
            PluralRuleFamily.Czech => v0
                ? (i == 1 ? PluralClass.One : i is >= 2 and <= 4 ? PluralClass.Few : PluralClass.Other)
                : PluralClass.Many,
            PluralRuleFamily.Romanian => v0 ? RomanianRule(i) : PluralClass.Few,
            // CLDR-v45 ar: rules run on n (the number itself), not on i. 0.0 → Zero because
            // n=0.0 matches 'n = 0'; 1.0 → One; 2.0 → Two; 3.5 → Few (n%100 = 3.5, in [3, 10]).
            PluralRuleFamily.Arabic => ArabicDecimalRule(absN, i),
            _ => PluralClass.Other,
        };
    }

    // CLDR-v45 sr/hr/bs: only One / Few / Other. Same modulo-10 shape as Russian's One rule but
    // "Many" collapses into Other.
    private static PluralClass CroatianRule(long i)
    {
        long mod10 = i % 10;
        long mod100 = i % 100;
        if (mod10 == 1 && mod100 != 11) return PluralClass.One;
        if (mod10 is >= 2 and <= 4 && !(mod100 is >= 12 and <= 14)) return PluralClass.Few;
        return PluralClass.Other;
    }

    private static PluralClass ArabicDecimalRule(decimal n, long i)
    {
        if (n == 0m) return PluralClass.Zero;
        if (n == 1m) return PluralClass.One;
        if (n == 2m) return PluralClass.Two;
        // n%100 for decimals: use decimal arithmetic to keep the fractional part.
        decimal mod100 = n - (Math.Truncate(n / 100m) * 100m);
        if (mod100 >= 3m && mod100 <= 10m) return PluralClass.Few;
        if (mod100 >= 11m && mod100 <= 99m) return PluralClass.Many;
        return PluralClass.Other;
    }

    /// <summary>Convenience alias that classifies a double by rounding down to the nearest integer.</summary>
    public static PluralClass Classify(LanguageTag tag, double n)
        => Classify(tag, (decimal)n);

    private static PluralClass RussianRule(long i)
    {
        long mod10 = i % 10;
        long mod100 = i % 100;
        if (mod10 == 1 && mod100 != 11) return PluralClass.One;
        if (mod10 is >= 2 and <= 4 && !(mod100 is >= 12 and <= 14)) return PluralClass.Few;
        if (mod10 == 0 || mod10 is >= 5 and <= 9 || mod100 is >= 11 and <= 14) return PluralClass.Many;
        return PluralClass.Other;
    }

    private static PluralClass PolishRule(long i)
    {
        long mod10 = i % 10;
        long mod100 = i % 100;
        if (i == 1) return PluralClass.One;
        if (mod10 is >= 2 and <= 4 && !(mod100 is >= 12 and <= 14)) return PluralClass.Few;
        if (i != 1 && (mod10 is 0 or 1
                        || mod10 is >= 5 and <= 9
                        || mod100 is >= 12 and <= 14))
            return PluralClass.Many;
        return PluralClass.Other;
    }

    private static PluralClass RomanianRule(long i)
    {
        if (i == 1) return PluralClass.One;
        long mod100 = i % 100;
        if (i == 0 || (i != 1 && mod100 is >= 1 and <= 19)) return PluralClass.Few;
        return PluralClass.Other;
    }

    private static PluralClass ArabicRule(long i)
    {
        if (i == 0) return PluralClass.Zero;
        if (i == 1) return PluralClass.One;
        if (i == 2) return PluralClass.Two;
        long mod100 = i % 100;
        if (mod100 is >= 3 and <= 10) return PluralClass.Few;
        if (mod100 is >= 11 and <= 99) return PluralClass.Many;
        return PluralClass.Other;
    }
}
