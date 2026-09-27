// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Platform;
using SharpProspero.Storage.Sfo;
using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization.Metadata;

/// <summary>
/// Reads the per-language title from an application's <c>param.sfo</c>. The default title lives
/// at the <c>TITLE</c> key; every localized title lives at <c>TITLE_XX</c> where <c>XX</c> is
/// the two-digit ordinal of a <see cref="SystemLanguageMap"/> entry (00 = Japanese,
/// 01 = en-US, and so on through 29 = Indonesian). Titles that were not translated for a given
/// language fall back to the default <c>TITLE</c> so a caller always sees something.
/// </summary>
public static class LocalizedTitleReader
{
    private const string DefaultKey = "TITLE";
    private const int KeyPrefixLength = 6;  // "TITLE_"

    /// <summary>
    /// The title stored in <paramref name="sfo"/> for <paramref name="language"/>, falling back
    /// to the default <c>TITLE</c> entry when the specific language slot is empty or absent.
    /// Returns an empty string when neither is present.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="sfo"/> or <paramref name="language"/> is null.</exception>
    public static string Read(SfoFile sfo, LanguageTag language)
    {
        ArgumentNullException.ThrowIfNull(sfo);
        ArgumentNullException.ThrowIfNull(language);

        if (SystemLanguageMap.TryFromLanguageTag(language, out SystemLanguage sysLang))
        {
            string localizedKey = string.Concat(DefaultKey, "_", ((int)sysLang).ToString("D2"));
            string? localized = sfo.GetString(localizedKey);
            if (!string.IsNullOrEmpty(localized))
                return localized;
        }

        return sfo.GetString(DefaultKey) ?? string.Empty;
    }

    /// <summary>
    /// The title stored in the <c>param.sfo</c> at <paramref name="path"/> for
    /// <paramref name="language"/>, or an empty string when the file cannot be read or holds
    /// nothing for either the requested language or the default slot.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="path"/> is null or empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="language"/> is null.</exception>
    public static string ReadFromFile(string path, LanguageTag language)
    {
        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("The path must not be empty.", nameof(path));
        ArgumentNullException.ThrowIfNull(language);

        SfoFile? sfo = SfoFile.ReadFromFile(path);
        return sfo is null ? string.Empty : Read(sfo, language);
    }

    /// <summary>
    /// A snapshot of every localized title in <paramref name="sfo"/>: each entry maps a
    /// <see cref="SystemLanguage"/> that carries a non-empty <c>TITLE_XX</c> value to the value
    /// itself. The default <c>TITLE</c> is not included; call <see cref="Read"/> for the
    /// fallback path.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="sfo"/> is null.</exception>
    public static IReadOnlyDictionary<SystemLanguage, string> EnumerateLocalizedTitles(SfoFile sfo)
    {
        ArgumentNullException.ThrowIfNull(sfo);

        var results = new Dictionary<SystemLanguage, string>();
        foreach (SfoEntry entry in sfo.Entries)
        {
            if (entry.ValueType != SfoValueType.String)
                continue;
            string key = entry.Key;
            if (key.Length != KeyPrefixLength + 2)
                continue;
            if (!key.StartsWith(DefaultKey, StringComparison.Ordinal) || key[5] != '_')
                continue;
            if (!int.TryParse(key.AsSpan(KeyPrefixLength), out int ordinal))
                continue;
            if (ordinal < 0 || ordinal >= SystemLanguageMap.Count)
                continue;
            string value = entry.StringValue;
            if (string.IsNullOrEmpty(value))
                continue;
            results[(SystemLanguage)ordinal] = value;
        }
        return results;
    }
}
