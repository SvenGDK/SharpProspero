// Prospero Vibrate - Haptics that move You.

using SharpProspero.Storage;
using System;
using System.Collections.Generic;

namespace SampleApp.Patterns;

/// <summary>
/// Reads and writes user patterns and app settings under the writable data root. All storage sits under
/// one directory the class creates on first use; every file is JSON.
/// </summary>
public static class PatternStorage
{
    /// <summary>Root directory the app writes into.</summary>
    public const string RootDirectory = "/data/prospero-vibrate";

    /// <summary>Directory that holds each saved custom pattern as one file.</summary>
    public const string PatternsDirectory = RootDirectory + "/patterns";

    /// <summary>File that holds the settings.</summary>
    public const string SettingsFile = RootDirectory + "/settings.json";

    /// <summary>
    /// Creates the storage tree if it is missing. The device may refuse this - a title without write
    /// permission to <c>/data</c> - in which case a caller keeps working with the defaults.
    /// </summary>
    /// <returns>True when the tree is now present.</returns>
    public static bool TryEnsureStructure()
    {
        try
        {
            FileSystem.CreateDirectoryRecursive(PatternsDirectory);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Whether persistent storage is present and writable.</summary>
    public static bool IsAvailable => FileSystem.Exists(RootDirectory);

    /// <summary>Reads the settings file, or the built-in defaults when it is missing or unreadable.</summary>
    public static AppSettings LoadSettings()
    {
        try
        {
            if (!FileSystem.Exists(SettingsFile))
                return new AppSettings();
            return AppSettings.FromJson(JsonValue.Load(SettingsFile));
        }
        catch
        {
            return new AppSettings();
        }
    }

    /// <summary>Writes <paramref name="settings"/> to the settings file. Returns false when the write fails.</summary>
    public static bool TrySaveSettings(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        try
        {
            if (!TryEnsureStructure())
                return false;
            settings.ToJson().Save(SettingsFile);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>The names of every custom pattern on disk, in sorted order.</summary>
    public static IReadOnlyList<string> ListPatternNames()
    {
        if (!FileSystem.Exists(PatternsDirectory))
            return [];

        if (!FileSystem.TryEnumerateDirectory(PatternsDirectory, out IReadOnlyList<DirectoryEntry> entries, out _))
            return [];

        var names = new List<string>();
        foreach (DirectoryEntry entry in entries)
        {
            if (!entry.IsFile)
                continue;
            string name = entry.Name;
            if (name.Length <= 5 || !name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                continue;
            string stripped = name[..^5];
            if (string.IsNullOrWhiteSpace(stripped))
                continue;
            names.Add(stripped);
        }
        names.Sort(StringComparer.OrdinalIgnoreCase);
        return names;
    }

    /// <summary>Reads the named pattern, or null when the file is missing or malformed.</summary>
    public static VibrationPreset? LoadPattern(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        string path = PathFor(name);
        if (!FileSystem.Exists(path))
            return null;
        try
        {
            return VibrationPreset.FromJson(JsonValue.Load(path));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Writes <paramref name="preset"/> under its own file. Returns false when the write fails.</summary>
    public static bool TrySavePattern(VibrationPreset preset)
    {
        ArgumentNullException.ThrowIfNull(preset);
        ArgumentException.ThrowIfNullOrEmpty(preset.Name);
        try
        {
            if (!TryEnsureStructure())
                return false;
            preset.ToJson().Save(PathFor(preset.Name));
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Removes the named pattern. Returns false when nothing was on disk to remove.</summary>
    public static bool TryDeletePattern(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        string path = PathFor(name);
        if (!FileSystem.Exists(path))
            return false;
        try
        {
            FileSystem.DeleteFile(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// The file path the named pattern lives at. Characters unsafe in a POSIX filename are replaced with
    /// underscores so a name entered by the user always resolves to a legal file.
    /// </summary>
    public static string PathFor(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        return $"{PatternsDirectory}/{Sanitize(name)}.json";
    }

    /// <summary>
    /// The most characters a pattern name is allowed to carry. Anything longer is truncated as it passes
    /// through <see cref="Sanitize"/>, so a rogue length cannot overflow the stack or the filename limit.
    /// The on-screen keyboard already asks for at most 64.
    /// </summary>
    public const int MaxNameLength = 128;

    /// <summary>
    /// Replaces filesystem-hostile characters in <paramref name="name"/> with underscores and truncates
    /// to <see cref="MaxNameLength"/> characters, so a caller cannot smuggle an arbitrarily long string
    /// into a stack buffer or a filename.
    /// </summary>
    public static string Sanitize(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        int length = name.Length < MaxNameLength ? name.Length : MaxNameLength;
        Span<char> buffer = stackalloc char[MaxNameLength];
        for (int i = 0; i < length; i++)
        {
            char c = name[i];
            buffer[i] = c switch
            {
                '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' or '\0' => '_',
                _ when c < 0x20 => '_',
                _ => c,
            };
        }
        return new string(buffer[..length]);
    }
}
