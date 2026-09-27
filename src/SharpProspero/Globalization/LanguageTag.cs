// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization;

/// <summary>
/// A BCP-47 language tag: a primary language subtag (2 or 3 lowercase letters) plus optional
/// script (4 letters, title case), region (2 letters uppercase, or 3 digits per M.49) and variant
/// subtags. Parsing normalises case; comparison is ordinal on the canonical form. A tag maps back
/// to the numeric console language through <see cref="SystemLanguageMap"/>, and produces the
/// fallback chain the localizer walks when a key is missing in the current locale.
/// </summary>
/// <remarks>
/// A single <see cref="Root"/> tag represents the "no language" case and is what
/// <see cref="FallbackChain"/> ends at, so the walker always terminates. The canonical form of a
/// tag is what <see cref="ToString"/> and <see cref="Canonical"/> return; it is what is written to
/// disk (locale filenames) and read back.
/// </remarks>
public sealed class LanguageTag : IEquatable<LanguageTag>
{
    private readonly string _canonical;

    private LanguageTag(string canonical, string language, string script, string region, string[] variants)
    {
        _canonical = canonical;
        Language = language;
        Script = script;
        Region = region;
        Variants = variants;
    }

    /// <summary>The canonical text of this tag, e.g. "en-US", "zh-Hant", "es-419", "ar-AE".</summary>
    public string Canonical => _canonical;

    /// <summary>The lowercase primary language subtag, e.g. "en" or "yue". Empty for <see cref="Root"/>.</summary>
    public string Language { get; }

    /// <summary>The titlecase 4-letter script subtag, e.g. "Hant"; empty when absent.</summary>
    public string Script { get; }

    /// <summary>The uppercase alpha-2 or 3-digit UN M.49 region subtag, e.g. "US" or "419"; empty when absent.</summary>
    public string Region { get; }

    /// <summary>Every variant subtag in the order they appeared; empty when there is none.</summary>
    public IReadOnlyList<string> Variants { get; }

    /// <summary>True for the empty root tag returned when parsing fails or as the terminal fallback.</summary>
    public bool IsRoot => Language.Length == 0;

    /// <summary>The empty root tag; ordinal identity, so equality checks can compare by reference.</summary>
    public static LanguageTag Root { get; } = new(string.Empty, string.Empty, string.Empty, string.Empty, []);

    /// <summary>en-US, the SDK-wide invariant tag used when nothing else is available.</summary>
    public static LanguageTag Invariant { get; } = Parse("en-US");

    /// <summary>
    /// Parses a BCP-47 tag. Case is normalised (primary lowercase, script titlecase, region
    /// uppercase). An empty or malformed input returns <see cref="Root"/>; use
    /// <see cref="TryParse"/> to detect the malformed case.
    /// </summary>
    public static LanguageTag Parse(string tag)
    {
        TryParse(tag, out LanguageTag result);
        return result;
    }

    /// <summary>Parses a BCP-47 tag and reports whether the input was well-formed.</summary>
    public static bool TryParse(string? tag, out LanguageTag result)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            result = Root;
            return false;
        }

        // Accept both "-" and "_" as subtag separators so a file named "en_US.json" parses the
        // same as "en-US.json". Trim whitespace but reject any embedded space.
        string trimmed = tag.Trim();
        if (trimmed.Contains(' '))
        {
            result = Root;
            return false;
        }

        string[] parts = trimmed.Replace('_', '-').Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            result = Root;
            return false;
        }

        string primary = parts[0];
        if (!IsPrimarySubtag(primary))
        {
            result = Root;
            return false;
        }

        string language = primary.ToLowerInvariant();
        string script = string.Empty;
        string region = string.Empty;
        var variants = new List<string>();

        for (int i = 1; i < parts.Length; i++)
        {
            string p = parts[i];
            if (script.Length == 0 && region.Length == 0 && variants.Count == 0 && IsScriptSubtag(p))
                script = ToTitleCase(p);
            else if (region.Length == 0 && variants.Count == 0 && IsRegionSubtag(p))
                region = p.ToUpperInvariant();
            else if (IsVariantSubtag(p))
                variants.Add(p.ToLowerInvariant());
            else
            {
                // Unrecognised subtag (extension singleton x/i, private-use) — accepted verbatim
                // so a valid extended tag round-trips even if the SDK does not interpret it.
                variants.Add(p);
            }
        }

        string canonical = BuildCanonical(language, script, region, variants);
        result = new LanguageTag(canonical, language, script, region, variants.ToArray());
        return true;
    }

    private static string BuildCanonical(string language, string script, string region, List<string> variants)
    {
        int length = language.Length
            + (script.Length == 0 ? 0 : script.Length + 1)
            + (region.Length == 0 ? 0 : region.Length + 1);
        foreach (string v in variants) length += v.Length + 1;

        var sb = new System.Text.StringBuilder(length);
        sb.Append(language);
        if (script.Length > 0) sb.Append('-').Append(script);
        if (region.Length > 0) sb.Append('-').Append(region);
        foreach (string v in variants) sb.Append('-').Append(v);
        return sb.ToString();
    }

    private static bool IsPrimarySubtag(string s)
    {
        if (s.Length < 2 || s.Length > 3)
            return false;
        foreach (char c in s)
            if (!IsAsciiLetter(c))
                return false;
        return true;
    }

    private static bool IsScriptSubtag(string s)
    {
        if (s.Length != 4)
            return false;
        foreach (char c in s)
            if (!IsAsciiLetter(c))
                return false;
        return true;
    }

    private static bool IsRegionSubtag(string s)
    {
        if (s.Length == 2)
        {
            foreach (char c in s)
                if (!IsAsciiLetter(c))
                    return false;
            return true;
        }
        if (s.Length == 3)
        {
            foreach (char c in s)
                if (c < '0' || c > '9')
                    return false;
            return true;
        }
        return false;
    }

    private static bool IsVariantSubtag(string s)
    {
        // BCP-47 §2.2.5: a variant subtag is either 5..8 alphanumeric, or exactly 4 characters
        // starting with a digit. A 4-letter all-alphabetic variant is structurally invalid.
        if (s.Length < 4 || s.Length > 8)
            return false;
        foreach (char c in s)
            if (!IsAsciiLetter(c) && (c < '0' || c > '9'))
                return false;
        if (s.Length == 4 && (s[0] < '0' || s[0] > '9'))
            return false;
        return true;
    }

    private static bool IsAsciiLetter(char c)
        => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

    private static string ToTitleCase(string s)
    {
        Span<char> buf = stackalloc char[s.Length];
        buf[0] = char.ToUpperInvariant(s[0]);
        for (int i = 1; i < s.Length; i++)
            buf[i] = char.ToLowerInvariant(s[i]);
        return new string(buf);
    }

    /// <summary>
    /// Walks the RFC 4647 Lookup fallback: strip variants, then region, then script, then land at
    /// the primary language and finally at <see cref="Root"/>. Yields each intermediate tag,
    /// starting with <c>this</c>.
    /// </summary>
    public IEnumerable<LanguageTag> FallbackChain()
    {
        if (IsRoot)
        {
            yield return Root;
            yield break;
        }

        var current = this;
        yield return current;

        if (current.Variants.Count > 0)
        {
            current = new LanguageTag(
                BuildCanonical(current.Language, current.Script, current.Region, []),
                current.Language, current.Script, current.Region, []);
            yield return current;
        }
        if (current.Region.Length > 0)
        {
            current = new LanguageTag(
                BuildCanonical(current.Language, current.Script, string.Empty, []),
                current.Language, current.Script, string.Empty, []);
            yield return current;
        }
        if (current.Script.Length > 0)
        {
            current = new LanguageTag(
                BuildCanonical(current.Language, string.Empty, string.Empty, []),
                current.Language, string.Empty, string.Empty, []);
            yield return current;
        }
        yield return Root;
    }

    /// <summary>True when this tag's primary language matches the other's, ignoring script/region/variants.</summary>
    public bool LanguageEquals(LanguageTag other)
        => other is not null && string.Equals(Language, other.Language, StringComparison.Ordinal);

    /// <inheritdoc/>
    public bool Equals(LanguageTag? other)
        => other is not null && string.Equals(_canonical, other._canonical, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as LanguageTag);

    /// <inheritdoc/>
    public override int GetHashCode()
        => StringComparer.OrdinalIgnoreCase.GetHashCode(_canonical);

    /// <inheritdoc/>
    public override string ToString() => _canonical;

    /// <summary>Two tags are equal when their canonical forms are, ignoring case.</summary>
    public static bool operator ==(LanguageTag? left, LanguageTag? right)
        => left is null ? right is null : left.Equals(right);

    /// <summary>Inverse of <see cref="operator=="/>.</summary>
    public static bool operator !=(LanguageTag? left, LanguageTag? right) => !(left == right);
}
