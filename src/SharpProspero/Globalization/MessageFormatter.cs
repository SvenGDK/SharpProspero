// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace SharpProspero.Globalization;

/// <summary>
/// Turns a template with <c>{0}</c>, <c>{1}</c> or <c>{name}</c> placeholders into a formatted
/// string using the culture's number/date preferences. Escaped braces are written with
/// <c>{{</c> / <c>}}</c>. Values that implement <see cref="IFormattable"/> route their format
/// specifier (the text after a <c>:</c> inside the placeholder) through the culture; other values
/// fall back to <see cref="object.ToString"/>.
/// </summary>
public static class MessageFormatter
{
    /// <summary>Formats <paramref name="template"/> with positional <paramref name="args"/>.</summary>
    public static string Format(Culture culture, string template, params object?[] args)
    {
        ArgumentNullException.ThrowIfNull(culture);
        ArgumentNullException.ThrowIfNull(template);
        args ??= Array.Empty<object?>();
        var sb = new StringBuilder(template.Length + 16);
        AppendFormat(sb, culture, template.AsSpan(), args, null);
        return sb.ToString();
    }

    /// <summary>Formats <paramref name="template"/> with a name-keyed dictionary of arguments.</summary>
    public static string Format(Culture culture, string template, IReadOnlyDictionary<string, object?> named)
    {
        ArgumentNullException.ThrowIfNull(culture);
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(named);
        var sb = new StringBuilder(template.Length + 16);
        AppendFormat(sb, culture, template.AsSpan(), Array.Empty<object?>(), named);
        return sb.ToString();
    }

    /// <summary>
    /// Formats <paramref name="template"/> with BOTH positional arguments and a name-keyed
    /// dictionary. Placeholders that name an all-digits slot resolve against the positional
    /// array; placeholders that name a text key resolve against the dictionary. Used by
    /// <c>Localizer.Tp</c> to expose the plural count under both <c>{0}</c> and <c>{count}</c>.
    /// </summary>
    public static string Format(Culture culture, string template, object?[] positional, IReadOnlyDictionary<string, object?>? named)
    {
        ArgumentNullException.ThrowIfNull(culture);
        ArgumentNullException.ThrowIfNull(template);
        positional ??= Array.Empty<object?>();
        var sb = new StringBuilder(template.Length + 16);
        AppendFormat(sb, culture, template.AsSpan(), positional, named);
        return sb.ToString();
    }

    private static void AppendFormat(
        StringBuilder sb,
        Culture culture,
        ReadOnlySpan<char> template,
        object?[] positional,
        IReadOnlyDictionary<string, object?>? named)
    {
        IFormatProvider provider = CultureFormatProvider.For(culture);

        int i = 0;
        while (i < template.Length)
        {
            char c = template[i];
            if (c == '{')
            {
                if (i + 1 < template.Length && template[i + 1] == '{')
                {
                    sb.Append('{');
                    i += 2;
                    continue;
                }
                int closeAt = template[i..].IndexOf('}');
                if (closeAt < 0)
                {
                    // Unterminated placeholder — emit verbatim and stop.
                    sb.Append(template[i..]);
                    return;
                }
                closeAt += i;
                ReadOnlySpan<char> inner = template[(i + 1)..closeAt];
                AppendPlaceholder(sb, inner, positional, named, provider);
                i = closeAt + 1;
                continue;
            }
            if (c == '}')
            {
                if (i + 1 < template.Length && template[i + 1] == '}')
                {
                    sb.Append('}');
                    i += 2;
                    continue;
                }
                // A lone '}' in a template is treated as literal so a message never trips a
                // parse error on the user's screen.
                sb.Append('}');
                i++;
                continue;
            }
            sb.Append(c);
            i++;
        }
    }

    private static void AppendPlaceholder(
        StringBuilder sb,
        ReadOnlySpan<char> inner,
        object?[] positional,
        IReadOnlyDictionary<string, object?>? named,
        IFormatProvider provider)
    {
        int colon = inner.IndexOf(':');
        ReadOnlySpan<char> key = colon < 0 ? inner : inner[..colon];
        ReadOnlySpan<char> format = colon < 0 ? ReadOnlySpan<char>.Empty : inner[(colon + 1)..];

        object? value = ResolveValue(key, positional, named);
        if (value is null)
            return;

        if (value is IFormattable formattable)
            sb.Append(formattable.ToString(format.IsEmpty ? null : new string(format), provider));
        else
            sb.Append(value.ToString());
    }

    private static object? ResolveValue(ReadOnlySpan<char> key, object?[] positional, IReadOnlyDictionary<string, object?>? named)
    {
        // Positional {0}, {1}, ...
        if (key.Length > 0 && IsAllDigits(key)
            && int.TryParse(key, NumberStyles.None, CultureInfo.InvariantCulture, out int idx))
        {
            return idx >= 0 && idx < positional.Length ? positional[idx] : null;
        }

        // Named {name}
        if (named is not null && named.TryGetValue(new string(key), out object? value))
            return value;

        // Fall back to null; the caller renders nothing rather than a crash for a missing arg.
        return null;
    }

    private static bool IsAllDigits(ReadOnlySpan<char> s)
    {
        for (int i = 0; i < s.Length; i++)
            if (s[i] < '0' || s[i] > '9')
                return false;
        return true;
    }

    private sealed class CultureFormatProvider : IFormatProvider
    {
        private readonly Culture _culture;
        private CultureFormatProvider(Culture culture) => _culture = culture;
        public static CultureFormatProvider For(Culture culture) => new(culture);

        public object? GetFormat(Type? formatType)
        {
            // Number formatting for IFormattable/int/double/decimal etc. Map the culture's
            // separator preferences onto a NumberFormatInfo the BCL formatters read.
            if (formatType == typeof(NumberFormatInfo))
            {
                CultureFormatInfo info = CultureFormatInfo.For(_culture.Language);
                var nfi = (NumberFormatInfo)NumberFormatInfo.InvariantInfo.Clone();
                nfi.NumberDecimalSeparator = info.DecimalSeparator;
                nfi.NumberGroupSeparator = info.GroupSeparator;
                nfi.PercentSymbol = info.PercentSymbol;
                nfi.PercentDecimalSeparator = info.DecimalSeparator;
                nfi.PercentGroupSeparator = info.GroupSeparator;
                return nfi;
            }
            if (formatType == typeof(DateTimeFormatInfo))
            {
                CultureFormatInfo info = CultureFormatInfo.For(_culture.Language);
                var dfi = (DateTimeFormatInfo)DateTimeFormatInfo.InvariantInfo.Clone();
                dfi.MonthNames = info.MonthNames.Length == 12
                    ? [.. info.MonthNames, string.Empty]
                    : dfi.MonthNames;
                dfi.AbbreviatedMonthNames = info.MonthAbbrevs.Length == 12
                    ? [.. info.MonthAbbrevs, string.Empty]
                    : dfi.AbbreviatedMonthNames;
                dfi.DayNames = info.DayNames;
                dfi.AbbreviatedDayNames = info.DayAbbrevs;
                dfi.AMDesignator = info.AmDesignator;
                dfi.PMDesignator = info.PmDesignator;
                dfi.DateSeparator = info.DateSeparator;
                dfi.TimeSeparator = info.TimeSeparator;
                return dfi;
            }
            return null;
        }
    }
}
