// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.Font;
using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization.Fonts;

/// <summary>
/// Maps a <see cref="LanguageTag"/> to the ordered list of <see cref="SceFontSet"/> ids the font
/// cascade tries when it needs coverage for that language. The list always ends with the
/// universal Asian-JPCJK-Thai-Arabic-Vietnamese blob so any codepoint the on-device font engine
/// can render eventually gets rendered.
/// </summary>
public static class ScriptFontPolicy
{
    /// <summary>The universal font set that carries every script the on-device engine knows.</summary>
    public const uint UniversalSet = SceFontSet.StdAsianJpCjkThArW1GVi;

    /// <summary>Returns the ordered list of SceFontSet ids the cascade tries for <paramref name="tag"/>.</summary>
    public static IReadOnlyList<uint> PreferredSets(LanguageTag tag)
    {
        if (tag is null || tag.IsRoot)
            return new uint[] { SceFontSet.StdEuropeanW1G, UniversalSet };

        return tag.Language switch
        {
            // Arabic: prepend the European+Arabic set so Arabic runs draw with proper joining,
            // then the universal blob as fallback for Latin + numbers embedded in Arabic text.
            "ar" or "he" or "fa" or "ur" or "yi"
                => new uint[] { SceFontSet.StdEuropeanArW1G, UniversalSet },

            // Thai / Lao / Khmer / Myanmar.
            "th" or "lo" or "km" or "my"
                => new uint[] { SceFontSet.StdThaiW1GVi, UniversalSet },

            // Vietnamese.
            "vi" => new uint[] { SceFontSet.StdVietnameseW1GVi, UniversalSet },

            // Japanese.
            "ja" => new uint[] { SceFontSet.StdJapaneseJpW1G, UniversalSet },

            // Simplified Chinese.
            "zh" when string.Equals(tag.Script, "Hans", StringComparison.Ordinal)
                => new uint[] { SceFontSet.StdSChineseGbW1G, UniversalSet },

            // Traditional Chinese, Korean, and any other CJK — route straight to the universal
            // blob (no dedicated Traditional-Chinese or Korean set ships).
            "zh" or "ko"
                => new uint[] { UniversalSet },

            // Every other language: European set first, universal fallback for scripts it lacks.
            _ => new uint[] { SceFontSet.StdEuropeanW1G, UniversalSet },
        };
    }
}
