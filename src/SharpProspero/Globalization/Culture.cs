// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Platform;
using System;
using System.Globalization;
using System.Threading;

namespace SharpProspero.Globalization;

/// <summary>
/// A snapshot of the user's language and date-time preferences: a <see cref="LanguageTag"/> plus
/// the console's date-format, time-format, timezone-offset and summer-time settings. Cultures are
/// immutable value-like references; the ambient <see cref="Current"/> is swapped atomically
/// through a single reference so the frame loop always reads a consistent snapshot.
/// </summary>
public sealed class Culture : IFormatProvider
{
    private static Culture _current = null!;

    /// <summary>The ambient culture. Reads are lock-free; writes go through <see cref="SetCurrent"/>.</summary>
    public static Culture Current => _current ?? InvariantCulture;

    /// <summary>en-US on Gregorian, YMD / 24h / UTC / no DST. The default before any refresh.</summary>
    public static Culture Invariant => InvariantCulture;
    private static readonly Culture InvariantCulture = new(
        LanguageTag.Invariant, DateFormat.YearMonthDay, TimeFormat.TwentyFourHour, 0, false);

    /// <summary>Creates a culture; use <see cref="ReadFromSystem"/> to build one from console settings.</summary>
    public Culture(LanguageTag language, DateFormat dateFormat, TimeFormat timeFormat, int tzMinutes, bool isSummerTime)
    {
        Language = language ?? LanguageTag.Root;
        DateFormat = dateFormat;
        TimeFormat = timeFormat;
        TimeZoneMinutes = tzMinutes;
        IsSummerTime = isSummerTime;
        Direction = TextDirections.ForLanguage(Language);
    }

    /// <summary>The language.</summary>
    public LanguageTag Language { get; }

    /// <summary>The date-part order the console prefers.</summary>
    public DateFormat DateFormat { get; }

    /// <summary>The 12- or 24-hour clock the console prefers.</summary>
    public TimeFormat TimeFormat { get; }

    /// <summary>The base timezone offset from UTC, in minutes.</summary>
    public int TimeZoneMinutes { get; }

    /// <summary>Whether daylight-saving time is in effect; adds one hour on top of <see cref="TimeZoneMinutes"/>.</summary>
    public bool IsSummerTime { get; }

    /// <summary>The base text direction for <see cref="Language"/> (LTR for Latin/CJK, RTL for Arabic/Hebrew).</summary>
    public TextDirection Direction { get; }

    /// <summary>The composite offset from UTC — base offset plus one hour when summer time is in effect.</summary>
    public TimeSpan UtcOffset => TimeSpan.FromMinutes(TimeZoneMinutes + (IsSummerTime ? 60 : 0));

    /// <summary>Returns a new culture with <paramref name="language"/> replacing this one's.</summary>
    public Culture With(LanguageTag language)
        => new(language, DateFormat, TimeFormat, TimeZoneMinutes, IsSummerTime);

    /// <summary>Returns a new culture with <paramref name="dateFormat"/> replacing this one's.</summary>
    public Culture With(DateFormat dateFormat)
        => new(Language, dateFormat, TimeFormat, TimeZoneMinutes, IsSummerTime);

    /// <summary>
    /// Reads the console's own settings once and composes a culture. Every read is guarded so a
    /// failing system-service call leaves the corresponding field at its invariant default rather
    /// than throwing on the boot path.
    /// </summary>
    public static Culture ReadFromSystem()
    {
        LanguageTag lang = TryGetLanguage(out LanguageTag readLang) ? readLang : LanguageTag.Invariant;
        DateFormat df = TryGet(() => SystemParameters.DateFormat, out DateFormat readDf) ? readDf : DateFormat.YearMonthDay;
        TimeFormat tf = TryGet(() => SystemParameters.TimeFormat, out TimeFormat readTf) ? readTf : TimeFormat.TwentyFourHour;
        int tz = TryGet(() => SystemParameters.TimeZoneMinutes, out int readTz) ? readTz : 0;
        bool dst = TryGet(() => SystemParameters.IsSummerTime, out bool readDst) && readDst;
        return new Culture(lang, df, tf, tz, dst);
    }

    /// <summary>Sets the ambient culture; publishes atomically so cross-thread reads see a consistent snapshot.</summary>
    public static void SetCurrent(Culture culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        Interlocked.Exchange(ref _current, culture);
    }

    /// <summary>Reads the console's language via <see cref="SystemParameters"/> and translates it to a tag.</summary>
    public static bool TryGetLanguage(out LanguageTag tag)
    {
        try
        {
            tag = SystemLanguageMap.ToLanguageTag(SystemParameters.Language);
            return true;
        }
        catch
        {
            tag = LanguageTag.Invariant;
            return false;
        }
    }

    private static bool TryGet<T>(Func<T> read, out T value)
    {
        try
        {
            value = read();
            return true;
        }
        catch
        {
            value = default!;
            return false;
        }
    }

    /// <summary>
    /// Serves format providers the BCL asks for when this <see cref="Culture"/> is passed as an
    /// <see cref="IFormatProvider"/>. In addition to the SDK's own <see cref="CultureFormatInfo"/>,
    /// requests for <see cref="NumberFormatInfo"/> and <see cref="DateTimeFormatInfo"/> are
    /// answered with instances derived from the same per-language table so
    /// <c>string.Format(Culture.Current, "{0:F1}", 1.5)</c> honours the language's decimal
    /// separator, and calls that ask for a <see cref="TimeSpan"/>/<see cref="DateTime"/> format
    /// pick up the language's separators, month and day names too.
    /// </summary>
    public object? GetFormat(Type? formatType)
    {
        if (formatType == typeof(CultureFormatInfo))
            return CultureFormatInfo.For(Language);
        if (formatType == typeof(NumberFormatInfo))
            return BuildNumberFormat(CultureFormatInfo.For(Language));
        if (formatType == typeof(DateTimeFormatInfo))
            return BuildDateTimeFormat(CultureFormatInfo.For(Language));
        return null;
    }

    private static NumberFormatInfo BuildNumberFormat(CultureFormatInfo info)
    {
        NumberFormatInfo nfi = (NumberFormatInfo)NumberFormatInfo.InvariantInfo.Clone();
        nfi.NumberDecimalSeparator = info.DecimalSeparator;
        nfi.NumberGroupSeparator = info.GroupSeparator;
        nfi.PercentDecimalSeparator = info.DecimalSeparator;
        nfi.PercentGroupSeparator = info.GroupSeparator;
        nfi.PercentSymbol = info.PercentSymbol;
        nfi.CurrencyDecimalSeparator = info.DecimalSeparator;
        nfi.CurrencyGroupSeparator = info.GroupSeparator;
        return nfi;
    }

    private static DateTimeFormatInfo BuildDateTimeFormat(CultureFormatInfo info)
    {
        DateTimeFormatInfo dfi = (DateTimeFormatInfo)DateTimeFormatInfo.InvariantInfo.Clone();
        dfi.DateSeparator = info.DateSeparator;
        dfi.TimeSeparator = info.TimeSeparator;
        dfi.AMDesignator = info.AmDesignator;
        dfi.PMDesignator = info.PmDesignator;
        dfi.MonthNames = ExtendTo13(info.MonthNames);
        dfi.AbbreviatedMonthNames = ExtendTo13(info.MonthAbbrevs);
        dfi.MonthGenitiveNames = ExtendTo13(info.MonthNames);
        dfi.AbbreviatedMonthGenitiveNames = ExtendTo13(info.MonthAbbrevs);
        dfi.DayNames = info.DayNames;
        dfi.AbbreviatedDayNames = info.DayAbbrevs;
        return dfi;
    }

    // DateTimeFormatInfo insists on 13 month names (the trailing entry is empty for the
    // Gregorian calendar). The SDK's month table is 12 entries; extend with an empty slot.
    private static string[] ExtendTo13(string[] months)
    {
        if (months.Length == 13) return months;
        var buf = new string[13];
        for (int i = 0; i < 12 && i < months.Length; i++) buf[i] = months[i];
        buf[12] = "";
        return buf;
    }
}
