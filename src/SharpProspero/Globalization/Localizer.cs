// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Diagnostics;
using SharpProspero.Platform;
using SharpProspero.Storage;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace SharpProspero.Globalization;

/// <summary>
/// The top-level lookup surface widgets and application code call. Holds one
/// <see cref="StringTable"/> per loaded locale plus a default locale; <c>T(key)</c> walks
/// <see cref="Culture.Current"/>'s fallback chain (RFC 4647 Lookup) and returns the first hit.
/// A key that resolves nowhere returns the key itself so a missing string is visible on screen
/// rather than blank.
/// </summary>
public sealed class Localizer
{
    private static Localizer _current = new(LanguageTag.Invariant);

    private readonly Dictionary<string, StringTable> _tables = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>The ambient localizer. Swap it with <see cref="SetCurrent"/>.</summary>
    public static Localizer Current => _current;

    /// <summary>Sets the ambient localizer atomically so cross-thread reads never tear.</summary>
    public static void SetCurrent(Localizer localizer)
    {
        ArgumentNullException.ThrowIfNull(localizer);
        Interlocked.Exchange(ref _current, localizer);
    }

    /// <summary>Creates a localizer with the given default language and no tables.</summary>
    public Localizer(LanguageTag defaultLanguage)
    {
        DefaultLanguage = defaultLanguage ?? LanguageTag.Invariant;
    }

    /// <summary>The fallback locale to use when the current culture's chain runs dry.</summary>
    public LanguageTag DefaultLanguage { get; }

    /// <summary>What to do when a key resolves nowhere.</summary>
    public MissingKeyPolicy MissingKeyPolicy { get; set; } = MissingKeyPolicy.ReturnKey;

    /// <summary>Fires when a key was not found in any loaded table. Wired to a klog sink by default.</summary>
    public event Action<LanguageTag, string>? MissingKey;

    /// <summary>The locales currently loaded, in insertion order.</summary>
    public IReadOnlyCollection<LanguageTag> LoadedLocales
    {
        get
        {
            lock (_lock)
            {
                var list = new List<LanguageTag>(_tables.Count);
                foreach (KeyValuePair<string, StringTable> kv in _tables)
                    list.Add(LanguageTag.Parse(kv.Key));
                return list;
            }
        }
    }

    /// <summary>Adds or replaces a table.</summary>
    public void Add(LanguageTag locale, StringTable table)
    {
        ArgumentNullException.ThrowIfNull(locale);
        ArgumentNullException.ThrowIfNull(table);
        lock (_lock)
            _tables[locale.Canonical] = table;
    }

    /// <summary>Removes a table; a caller may want this when switching a shipped language set.</summary>
    public bool Remove(LanguageTag locale)
    {
        ArgumentNullException.ThrowIfNull(locale);
        lock (_lock)
            return _tables.Remove(locale.Canonical);
    }

    /// <summary>
    /// Returns the <see cref="StringTable"/> currently registered under <paramref name="locale"/>'s
    /// canonical form, or null when none is loaded. Used by callers that need to register a
    /// second alias for the same table without re-parsing the source JSON — the returned
    /// reference is safe to <c>Add(alias, sameTable)</c>.
    /// </summary>
    public StringTable? Get(LanguageTag locale)
    {
        ArgumentNullException.ThrowIfNull(locale);
        lock (_lock)
            return _tables.TryGetValue(locale.Canonical, out StringTable? t) ? t : null;
    }

    /// <summary>Returns the raw text for a key, or the key itself when nothing matches.</summary>
    public string T(string key) => Resolve(key, Culture.Current.Language);

    /// <summary>Formats a key with positional arguments through <see cref="MessageFormatter"/>.</summary>
    public string T(string key, params object?[] args)
    {
        string template = Resolve(key, Culture.Current.Language);
        return args is null || args.Length == 0 ? template : MessageFormatter.Format(Culture.Current, template, args);
    }

    /// <summary>Formats a key with a named-argument dictionary through <see cref="MessageFormatter"/>.</summary>
    public string T(string key, IReadOnlyDictionary<string, object?> named)
    {
        string template = Resolve(key, Culture.Current.Language);
        return MessageFormatter.Format(Culture.Current, template, named);
    }

    /// <summary>
    /// Formats a plural key. Looks up <c>&lt;baseKey&gt;.&lt;class&gt;</c> for the CLDR class
    /// selected by <paramref name="count"/> under <see cref="Culture.Current"/>'s language, then
    /// falls back to <c>&lt;baseKey&gt;.other</c>, then the raw base key. Numeric substitution
    /// happens via <c>{count}</c>, <c>{0}</c> or any placeholder resolved through
    /// <see cref="MessageFormatter"/>.
    /// </summary>
    public string Tp(string baseKey, long count, params object?[] args)
    {
        PluralClass cls = PluralRules.Classify(Culture.Current.Language, count);
        string template = ResolvePlural(baseKey, cls);
        object?[] effective = BuildEffectiveArgs(count, args);
        return MessageFormatter.Format(Culture.Current, template, effective, PluralNamedArgs(count));
    }

    /// <summary>Decimal overload for locales whose plural rules see fractional counts (French, Slavic).</summary>
    public string Tp(string baseKey, decimal count, params object?[] args)
    {
        PluralClass cls = PluralRules.Classify(Culture.Current.Language, count);
        string template = ResolvePlural(baseKey, cls);
        object?[] effective = BuildEffectiveArgs(count, args);
        return MessageFormatter.Format(Culture.Current, template, effective, PluralNamedArgs(count));
    }

    // The plural count lands at both `{0}` (positional) and `{count}` (named) so templates can
    // pick whichever the author preferred.
    private static object?[] BuildEffectiveArgs(object count, object?[]? args)
    {
        int extra = args?.Length ?? 0;
        var effective = new object?[extra + 1];
        effective[0] = count;
        if (extra > 0)
            Array.Copy(args!, 0, effective, 1, extra);
        return effective;
    }

    private static IReadOnlyDictionary<string, object?> PluralNamedArgs(object count)
        => new Dictionary<string, object?>(StringComparer.Ordinal) { ["count"] = count };

    private string ResolvePlural(string baseKey, PluralClass cls)
    {
        string suffix = PluralClassSuffixes.SuffixFor(cls);
        if (TryLookupWithFallback(baseKey + "." + suffix, Culture.Current.Language, out string template))
            return template;
        if (cls != PluralClass.Other
            && TryLookupWithFallback(baseKey + ".other", Culture.Current.Language, out template))
            return template;
        if (TryLookupWithFallback(baseKey, Culture.Current.Language, out template))
            return template;
        RaiseMissingKey(Culture.Current.Language, baseKey + "." + suffix);
        return ApplyMissingPolicy(baseKey);
    }

    private string Resolve(string key, LanguageTag language)
    {
        if (TryLookupWithFallback(key, language, out string value))
            return value;
        RaiseMissingKey(language, key);
        return ApplyMissingPolicy(key);
    }

    private bool TryLookupWithFallback(string key, LanguageTag language, out string value)
    {
        foreach (LanguageTag t in language.FallbackChain())
        {
            if (t.IsRoot)
                continue;
            if (TryGetTable(t.Canonical, out StringTable? table))
            {
                if (table!.TryGet(key, out value))
                    return true;
            }
        }
        // Try the default language's chain, in case current lives outside a loaded locale.
        if (!DefaultLanguage.IsRoot)
        {
            foreach (LanguageTag t in DefaultLanguage.FallbackChain())
            {
                if (t.IsRoot)
                    continue;
                if (TryGetTable(t.Canonical, out StringTable? table))
                {
                    if (table!.TryGet(key, out value))
                        return true;
                }
            }
        }
        value = key;
        return false;
    }

    private bool TryGetTable(string canonical, out StringTable? table)
    {
        lock (_lock)
            return _tables.TryGetValue(canonical, out table);
    }

    private void RaiseMissingKey(LanguageTag language, string key)
    {
        // Invoke every subscribed handler in isolation so a broken handler cannot short-circuit
        // the delegate chain and rob later handlers of their signal. Failures are still swallowed
        // because raising missing-key events is a diagnostic side channel, not a control flow the
        // caller can act on.
        Delegate[]? handlers = MissingKey?.GetInvocationList();
        if (handlers is null) return;
        for (int i = 0; i < handlers.Length; i++)
        {
            try { ((Action<LanguageTag, string>)handlers[i])(language, key); } catch { }
        }
    }

    private string ApplyMissingPolicy(string key) => MissingKeyPolicy switch
    {
        MissingKeyPolicy.ReturnMarkedKey => "!!" + key + "!!",
        MissingKeyPolicy.Throw => throw new KeyNotFoundException("String key not found: " + key),
        _ => key,
    };

    /// <summary>
    /// Loads every <c>*.json</c> file under <paramref name="directoryPath"/> as a locale table,
    /// filenames form the locale tag, and every table is chained to the default-language table so
    /// missing keys fall to it. When no default-language file exists an empty stub table is
    /// created so the fallback chain always terminates cleanly.
    /// </summary>
    /// <remarks>
    /// The directory is opened directly through the kernel's directory-listing call rather than
    /// probed first with a reachability check. A path that answers the listing exists; a path that
    /// refuses it does not, and the returned error code names the reason for the on-device log.
    /// A caller that ships a strings folder alongside its module and does not know whether the
    /// module sees it through the package-root prefix or through a plain top-level name should
    /// use <see cref="LoadFromDirectories"/> instead, which walks a candidate list and picks the
    /// first directory that yields any table.
    /// </remarks>
    public static Localizer LoadFromDirectory(string directoryPath, LanguageTag defaultLanguage)
    {
        ArgumentException.ThrowIfNullOrEmpty(directoryPath);
        ArgumentNullException.ThrowIfNull(defaultLanguage);

        var localizer = new Localizer(defaultLanguage);
        LoadInto(localizer, directoryPath, defaultLanguage);
        FinaliseDefaultTable(localizer, defaultLanguage, referencePath: directoryPath);
        return localizer;
    }

    /// <summary>
    /// Walks <paramref name="candidatePaths"/> in order, loading tables from the first directory
    /// that yields at least one entry. When every candidate refuses the listing the returned
    /// localizer holds only an empty stub table for <paramref name="defaultLanguage"/>, so a
    /// caller who mis-specified every candidate path still gets a usable localizer and every
    /// key returns its literal form.
    /// </summary>
    /// <remarks>
    /// The candidate list resolves how a module sees its own data folder: an absolute path such
    /// as <c>/app0/strings</c> works when the module reads through the package-root prefix, and
    /// a top-level name such as <c>strings</c> works when the module's own file view already has
    /// the package root as its root. Every attempt logs the outcome so the on-device log names
    /// which candidate answered and which did not.
    /// </remarks>
    public static Localizer LoadFromDirectories(IEnumerable<string> candidatePaths, LanguageTag defaultLanguage)
    {
        ArgumentNullException.ThrowIfNull(candidatePaths);
        ArgumentNullException.ThrowIfNull(defaultLanguage);

        var localizer = new Localizer(defaultLanguage);
        string? acceptedPath = null;
        foreach (string candidate in candidatePaths)
        {
            if (string.IsNullOrWhiteSpace(candidate))
                continue;
            int before = localizer._tables.Count;
            LoadInto(localizer, candidate, defaultLanguage);
            int after = localizer._tables.Count;
            if (after > before)
            {
                acceptedPath = candidate;
                Log.Information($"[l10n] loaded {after - before} table(s) from '{candidate}'.");
                break;
            }
        }
        FinaliseDefaultTable(localizer, defaultLanguage, referencePath: acceptedPath ?? "(no candidate answered)");
        return localizer;
    }

    // Loads every *.json file under `directoryPath` into `localizer`. Guards every step so a
    // failing enumeration or a single unreadable file does not stop the load. The listing runs
    // through the try-enumerate call so a kernel error is logged with its code rather than
    // thrown, and the caller can decide from the resulting table count whether to try another
    // candidate directory.
    private static void LoadInto(Localizer localizer, string directoryPath, LanguageTag defaultLanguage)
    {
        IReadOnlyList<DirectoryEntry> entries;
        int errorCode;
        try
        {
            if (!FileSystem.TryEnumerateDirectory(directoryPath, out entries, out errorCode))
            {
                Log.Warning($"[l10n] directory '{directoryPath}' could not be listed (code 0x{errorCode:X}).");
                return;
            }
        }
        catch (Exception e)
        {
            Log.Warning($"[l10n] directory '{directoryPath}' listing threw: {e.Message}");
            return;
        }

        int loaded = 0;
        foreach (DirectoryEntry entry in entries)
        {
            // A file system that leaves the entry kind out reports every record as Unknown, so
            // the .json extension check does the sieve rather than the kind; a directory that
            // ends in .json is ruled out below by the read/parse steps.
            if (entry.Type != FileEntryType.File && entry.Type != FileEntryType.Unknown)
                continue;
            string name = entry.Name;
            if (!name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                continue;

            string path = directoryPath.TrimEnd('/') + "/" + name;
            byte[] bytes;
            try { bytes = FileSystem.ReadAllBytes(path); }
            catch (Exception e)
            {
                Log.Warning($"[l10n] failed to read '{path}': {e.Message}");
                continue;
            }

            LanguageTag tag = LanguageTag.Parse(Path.GetFileNameWithoutExtension(name));
            if (tag.IsRoot)
            {
                Log.Warning($"[l10n] filename '{name}' under '{directoryPath}' does not parse as a BCP-47 tag; skipped.");
                continue;
            }

            StringTable table;
            try { table = StringTableJsonReader.Load(bytes, tag, name); }
            catch (Exception e)
            {
                Log.Warning($"[l10n] failed to parse '{path}': {e.Message}");
                continue;
            }

            localizer.Add(tag, table);
            loaded++;
        }

        if (loaded > 0)
            Log.Information($"[l10n] '{directoryPath}': loaded {loaded} table(s).");
    }

    // Ensures the default-language slot is present and every non-default table falls back to it.
    // A caller that shipped no default-language JSON still gets a terminating stub table so the
    // fallback chain never walks off the end and back into the ambient culture's own chain.
    private static void FinaliseDefaultTable(Localizer localizer, LanguageTag defaultLanguage, string referencePath)
    {
        StringTable? defaultTable = localizer.Get(defaultLanguage);
        if (defaultTable is null)
        {
            defaultTable = new StringTable(defaultLanguage.Canonical);
            localizer.Add(defaultLanguage, defaultTable);
            Log.Warning($"[l10n] default-language file for '{defaultLanguage.Canonical}' was not found under '{referencePath}'; loaded an empty stub table.");
        }
        foreach (LanguageTag tag in localizer.LoadedLocales)
        {
            if (tag == defaultLanguage)
                continue;
            if (localizer.TryGetTable(tag.Canonical, out StringTable? table))
                table!.SetFallback(defaultTable);
        }
    }
}

/// <summary>What the localizer does when a key resolves nowhere.</summary>
public enum MissingKeyPolicy : byte
{
    /// <summary>Return the key itself so the interface never draws blank. Default.</summary>
    ReturnKey,

    /// <summary>Return the key surrounded by "!!" so missing strings visibly stand out during authoring.</summary>
    ReturnMarkedKey,

    /// <summary>Throw a <see cref="System.Collections.Generic.KeyNotFoundException"/>. For strict authoring.</summary>
    Throw,
}
