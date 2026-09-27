// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;
using System.Globalization;

namespace SharpProspero.Platform;

/// <summary>
/// The user-facing text of an application, keyed by a stable identifier and looked up per language, so the
/// strings live in data rather than in code. A table has a locale, a set of key-to-text entries, and an
/// optional fallback table consulted when a key is missing — usually the default language. Load the entries
/// from the INI or JSON readers, or add them directly. The current user language comes from
/// <c>SystemParameters</c>.
/// </summary>
/// <example>
/// <code>
/// var en = new StringTable("en").Set("greeting", "Hello, {0}");
/// var fr = new StringTable("fr", fallback: en).Set("greeting", "Bonjour, {0}");
/// string text = fr.Format("greeting", playerName); // "Bonjour, Sven"
/// </code>
/// </example>
public sealed class StringTable
{
    private readonly Dictionary<string, string> _entries = new(StringComparer.Ordinal);
    // Preserved insertion order so a table read from JSON round-trips through a writer with a
    // predictable diff and a caller enumerating Entries sees them in the order the author wrote.
    private readonly List<string> _keys = new();
    private StringTable? _fallback;

    /// <summary>Creates a table for <paramref name="locale"/>, optionally chained to a <paramref name="fallback"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="locale"/> is null or empty.</exception>
    public StringTable(string locale, StringTable? fallback = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(locale);
        Locale = locale;
        _fallback = fallback;
    }

    /// <summary>The language tag this table holds, such as "en" or "fr".</summary>
    public string Locale { get; }

    /// <summary>The table consulted when a key is missing here, or null.</summary>
    public StringTable? Fallback => _fallback;

    /// <summary>
    /// Chains this table onto a new fallback after construction. Used by loaders that assemble a
    /// map of tables and only know the fallback link once every table has been read.
    /// </summary>
    public void SetFallback(StringTable? fallback) => _fallback = fallback;

    /// <summary>How many entries this table holds directly, not counting the fallback.</summary>
    public int Count => _entries.Count;

    /// <summary>The keys this table holds directly, in the order they were added.</summary>
    public IReadOnlyList<string> Keys => _keys;

    /// <summary>The direct entries in the order they were added.</summary>
    public IEnumerable<KeyValuePair<string, string>> Entries
    {
        get
        {
            foreach (string k in _keys)
                yield return new KeyValuePair<string, string>(k, _entries[k]);
        }
    }

    /// <summary>Adds or replaces one entry and returns this table so calls chain.</summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public StringTable Set(string key, string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        if (!_entries.ContainsKey(key))
            _keys.Add(key);
        _entries[key] = value;
        return this;
    }

    /// <summary>Adds or replaces many entries and returns this table so calls chain.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="entries"/> is null.</exception>
    public StringTable Add(IEnumerable<KeyValuePair<string, string>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        foreach (KeyValuePair<string, string> entry in entries)
            Set(entry.Key, entry.Value);
        return this;
    }

    /// <summary>
    /// Looks up a plural form: <paramref name="baseKey"/> plus the CLDR class suffix
    /// (<c>.one</c>, <c>.other</c>, ...). Returns whether a form was found in this table or its
    /// fallback chain.
    /// </summary>
    public bool TryGetPlural(string baseKey, string classSuffix, out string value)
    {
        ArgumentNullException.ThrowIfNull(baseKey);
        ArgumentNullException.ThrowIfNull(classSuffix);
        return TryGet($"{baseKey}.{classSuffix}", out value);
    }

    // Realistic locale chains never exceed a handful of steps (e.g. en-GB → en-US → root); the
    // cap catches a cyclic SetFallback wiring so the walk terminates instead of stack-overflowing
    // when a caller closes the chain into a loop by accident.
    private const int MaxFallbackDepth = 16;

    /// <summary>Whether <paramref name="key"/> resolves here or in the fallback chain.</summary>
    public bool Contains(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        StringTable? node = this;
        for (int depth = 0; node is not null && depth < MaxFallbackDepth; depth++, node = node._fallback)
        {
            if (node._entries.ContainsKey(key))
                return true;
        }
        return false;
    }

    /// <summary>Looks up <paramref name="key"/>, following the fallback chain; returns whether it was found.</summary>
    public bool TryGet(string key, out string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        StringTable? node = this;
        for (int depth = 0; node is not null && depth < MaxFallbackDepth; depth++, node = node._fallback)
        {
            if (node._entries.TryGetValue(key, out string? own))
            {
                value = own;
                return true;
            }
        }
        value = key;
        return false;
    }

    /// <summary>
    /// Returns the text for <paramref name="key"/>, following the fallback chain. When no table has the
    /// key, the key itself is returned so a missing string is visible rather than blank.
    /// </summary>
    public string Get(string key)
    {
        TryGet(key, out string value);
        return value;
    }

    /// <summary>
    /// Looks up <paramref name="key"/> and fills in the positional arguments with
    /// <see cref="string.Format(IFormatProvider, string, object?[])"/>. With no arguments the text is
    /// returned unchanged, so a template that itself contains braces is left alone.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="args"/> is null.</exception>
    public string Format(string key, params object[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        string template = Get(key);
        return args.Length == 0 ? template : string.Format(CultureInfo.CurrentCulture, template, args);
    }
}
