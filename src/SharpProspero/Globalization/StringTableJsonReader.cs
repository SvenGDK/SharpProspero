// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Diagnostics;
using SharpProspero.Platform;
using SharpProspero.Storage;
using System;
using System.Text;

namespace SharpProspero.Globalization;

/// <summary>
/// Reads a JSON per-locale file into a <see cref="StringTable"/>. Filenames follow the convention
/// <c>&lt;bcp47&gt;.json</c> (case-insensitive): "en-US.json", "fr-FR.json", "zh-Hant.json".
/// The root JSON object holds dotted-namespace keys ("home.button.exit"), with plural variants
/// stored as sibling keys carrying a CLDR suffix ("cart.items.one", "cart.items.other").
/// </summary>
public static class StringTableJsonReader
{
    /// <summary>Loads a table from a file on disk. The tag is derived from the filename.</summary>
    public static StringTable Load(string path, LanguageTag locale, StringTable? fallback = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(locale);
        byte[] bytes = FileSystem.ReadAllBytes(path);
        return Load(bytes, locale, path, fallback);
    }

    /// <summary>Loads a table from raw UTF-8 bytes; <paramref name="sourceName"/> is used in error messages.</summary>
    public static StringTable Load(ReadOnlySpan<byte> utf8, LanguageTag locale, string sourceName, StringTable? fallback = null)
    {
        ArgumentNullException.ThrowIfNull(locale);
        JsonValue root = JsonValue.Parse(DecodeUtf8(utf8));
        if (root.Type != JsonType.Object)
            throw new StringTableFormatException($"{sourceName}: string table must be a JSON object at the root.");

        var table = new StringTable(locale.Canonical, fallback);
        foreach (string key in root.Keys)
        {
            JsonValue value = root[key];
            if (value.Type != JsonType.String)
            {
                // An author who forgot the quotes around a value ("app.version": 2 rather than
                // "2") would otherwise see the entry silently dropped and only notice at a
                // runtime lookup that returned the key literal. Log the mismatch so the load-time
                // gap is visible on device.
                Log.Warning($"[l10n] {sourceName}: key '{key}' has a non-string value ({value.Type}); skipped.");
                continue;
            }
            table.Set(key, value.AsString());
        }
        return table;
    }

    /// <summary>
    /// Loads a table when the caller knows only the filename (no folder). The stem is parsed as
    /// the locale tag; a malformed stem yields <see cref="LanguageTag.Root"/> and the caller can
    /// decide what to do with it.
    /// </summary>
    public static StringTable LoadFromFilename(string filenameOnly, ReadOnlySpan<byte> utf8, StringTable? fallback = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(filenameOnly);
        int dot = filenameOnly.LastIndexOf('.');
        string stem = dot < 0 ? filenameOnly : filenameOnly[..dot];
        LanguageTag tag = LanguageTag.Parse(stem);
        return Load(utf8, tag, filenameOnly, fallback);
    }

    private static string DecodeUtf8(ReadOnlySpan<byte> utf8)
    {
        if (utf8.Length >= 3 && utf8[0] == 0xEF && utf8[1] == 0xBB && utf8[2] == 0xBF)
            utf8 = utf8[3..];
        return Encoding.UTF8.GetString(utf8);
    }
}

/// <summary>Thrown when a JSON string-table file's shape is not what the reader expects.</summary>
public sealed class StringTableFormatException(string message) : Exception(message);
