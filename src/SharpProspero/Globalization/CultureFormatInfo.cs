// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Collections.Generic;
using System.Globalization;

namespace SharpProspero.Globalization;

/// <summary>
/// Per-language number and date presentation values: separators, AM/PM strings, month and day
/// names. Baked from a CLDR-v45 snapshot for the languages the SDK covers, with English as the
/// fallback for languages whose data has not been added yet. No dependency on
/// <see cref="CultureInfo"/> so the values are the same on device as in tests.
/// </summary>
public sealed class CultureFormatInfo
{
    private static readonly Dictionary<string, CultureFormatInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    // Guards concurrent For() calls: MessageFormatter.CultureFormatProvider.GetFormat can fire
    // from any thread that renders an IFormattable argument (a background Task.Run copying a
    // large ISO into a per-title folder while the UI thread simultaneously formats a rebuild
    // status line). Without synchronisation the Dictionary's internal resize can NREF or drop
    // a write.
    private static readonly object _cacheLock = new();

    /// <summary>The decimal point ("." or ",").</summary>
    public string DecimalSeparator { get; init; } = ".";

    /// <summary>The thousands separator ("," / " " / ".").</summary>
    public string GroupSeparator { get; init; } = ",";

    /// <summary>The percent symbol ("%").</summary>
    public string PercentSymbol { get; init; } = "%";

    /// <summary>The AM designator (usually "AM" or "a.m.").</summary>
    public string AmDesignator { get; init; } = "AM";

    /// <summary>The PM designator.</summary>
    public string PmDesignator { get; init; } = "PM";

    /// <summary>The date-part separator ("/" / "." / "-").</summary>
    public string DateSeparator { get; init; } = "/";

    /// <summary>The time-part separator (":").</summary>
    public string TimeSeparator { get; init; } = ":";

    /// <summary>Full month names, index 0 = January.</summary>
    public string[] MonthNames { get; init; } = _englishMonthNames;

    /// <summary>Abbreviated month names, index 0 = Jan.</summary>
    public string[] MonthAbbrevs { get; init; } = _englishMonthAbbrevs;

    /// <summary>Full day names, index 0 = Sunday.</summary>
    public string[] DayNames { get; init; } = _englishDayNames;

    /// <summary>Abbreviated day names, index 0 = Sun.</summary>
    public string[] DayAbbrevs { get; init; } = _englishDayAbbrevs;

    /// <summary>Returns the cached bundle for a language tag; unknown languages fall to en-US.</summary>
    public static CultureFormatInfo For(LanguageTag tag)
    {
        if (tag is null || tag.IsRoot)
            return English;

        string key = tag.Canonical;
        lock (_cacheLock)
        {
            if (_cache.TryGetValue(key, out CultureFormatInfo? cached))
                return cached;
            if (_cache.TryGetValue(tag.Language, out cached))
            {
                _cache[key] = cached;
                return cached;
            }
            CultureFormatInfo picked = SelectFor(tag);
            _cache[key] = picked;
            return picked;
        }
    }

    private static CultureFormatInfo SelectFor(LanguageTag tag)
    {
        return tag.Language switch
        {
            "en" => English,
            "fr" => French,
            "es" => Spanish,
            "de" => German,
            "pt" => Portuguese,
            "it" => Italian,
            "nl" => Dutch,
            "ru" => Russian,
            "ja" => Japanese,
            "ko" => Korean,
            "zh" => Chinese,
            "pl" => Polish,
            "cs" => Czech,
            "tr" => Turkish,
            "sv" => Swedish,
            "da" => Danish,
            "no" or "nb" or "nn" => Norwegian,
            "fi" => Finnish,
            "hu" => Hungarian,
            "el" => Greek,
            "ro" => Romanian,
            "ar" => Arabic,
            "th" => Thai,
            "vi" => Vietnamese,
            "id" => Indonesian,
            _ => English,
        };
    }

    // ============================================================================================
    //  Static per-language bundles. Data comes from a checked-in CLDR-v45 snapshot; a language
    //  whose data has not been added yet falls back to English.
    // ============================================================================================

    private static readonly string[] _englishMonthNames =
    [
        "January","February","March","April","May","June","July","August","September","October","November","December",
    ];
    private static readonly string[] _englishMonthAbbrevs =
    [
        "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec",
    ];
    private static readonly string[] _englishDayNames =
    [
        "Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",
    ];
    private static readonly string[] _englishDayAbbrevs =
    [
        "Sun","Mon","Tue","Wed","Thu","Fri","Sat",
    ];

    /// <summary>The English (US) bundle. Every non-covered language falls back to this.</summary>
    public static CultureFormatInfo English { get; } = new()
    {
        DecimalSeparator = ".",
        GroupSeparator = ",",
        PercentSymbol = "%",
        AmDesignator = "AM",
        PmDesignator = "PM",
        DateSeparator = "/",
        TimeSeparator = ":",
        MonthNames = _englishMonthNames,
        MonthAbbrevs = _englishMonthAbbrevs,
        DayNames = _englishDayNames,
        DayAbbrevs = _englishDayAbbrevs,
    };

    /// <summary>French.</summary>
    public static CultureFormatInfo French { get; } = new()
    {
        DecimalSeparator = ",",
        GroupSeparator = " ", // narrow non-breaking space
        PercentSymbol = "%",
        AmDesignator = "AM",
        PmDesignator = "PM",
        DateSeparator = "/",
        TimeSeparator = ":",
        MonthNames = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"],
        MonthAbbrevs = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."],
        DayNames = ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"],
        DayAbbrevs = ["dim.", "lun.", "mar.", "mer.", "jeu.", "ven.", "sam."],
    };

    /// <summary>Spanish.</summary>
    public static CultureFormatInfo Spanish { get; } = new()
    {
        DecimalSeparator = ",",
        GroupSeparator = ".",
        PercentSymbol = "%",
        AmDesignator = "a. m.",
        PmDesignator = "p. m.",
        DateSeparator = "/",
        TimeSeparator = ":",
        MonthNames = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"],
        MonthAbbrevs = ["ene.", "feb.", "mar.", "abr.", "may.", "jun.", "jul.", "ago.", "sept.", "oct.", "nov.", "dic."],
        DayNames = ["domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"],
        DayAbbrevs = ["dom.", "lun.", "mar.", "mié.", "jue.", "vie.", "sáb."],
    };

    /// <summary>German.</summary>
    public static CultureFormatInfo German { get; } = new()
    {
        DecimalSeparator = ",",
        GroupSeparator = ".",
        PercentSymbol = "%",
        AmDesignator = "AM",
        PmDesignator = "PM",
        DateSeparator = ".",
        TimeSeparator = ":",
        MonthNames = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"],
        MonthAbbrevs = ["Jan.", "Feb.", "März", "Apr.", "Mai", "Juni", "Juli", "Aug.", "Sept.", "Okt.", "Nov.", "Dez."],
        DayNames = ["Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"],
        DayAbbrevs = ["So.", "Mo.", "Di.", "Mi.", "Do.", "Fr.", "Sa."],
    };

    /// <summary>Portuguese (Portugal + Brazil share these day/month names; separators are the same).</summary>
    public static CultureFormatInfo Portuguese { get; } = new()
    {
        DecimalSeparator = ",",
        GroupSeparator = ".",
        PercentSymbol = "%",
        AmDesignator = "AM",
        PmDesignator = "PM",
        DateSeparator = "/",
        TimeSeparator = ":",
        MonthNames = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"],
        MonthAbbrevs = ["jan.", "fev.", "mar.", "abr.", "mai.", "jun.", "jul.", "ago.", "set.", "out.", "nov.", "dez."],
        DayNames = ["domingo", "segunda-feira", "terça-feira", "quarta-feira", "quinta-feira", "sexta-feira", "sábado"],
        DayAbbrevs = ["dom.", "seg.", "ter.", "qua.", "qui.", "sex.", "sáb."],
    };

    // The remaining bundles are shipped as English-fallback for now (correct separators + AM/PM),
    // so the widget layer never crashes but the localised names come along with a future data pass.
    private static CultureFormatInfo FallbackEuropean(string dec, string grp, string date)
        => new()
        {
            DecimalSeparator = dec,
            GroupSeparator = grp,
            DateSeparator = date,
            MonthNames = _englishMonthNames,
            MonthAbbrevs = _englishMonthAbbrevs,
            DayNames = _englishDayNames,
            DayAbbrevs = _englishDayAbbrevs
        };

    private static CultureFormatInfo Italian { get; } = FallbackEuropean(",", ".", "/");
    private static CultureFormatInfo Dutch { get; } = FallbackEuropean(",", ".", "-");
    private static CultureFormatInfo Russian { get; } = FallbackEuropean(",", " ", ".");
    private static CultureFormatInfo Japanese { get; } = FallbackEuropean(".", ",", "/");
    private static CultureFormatInfo Korean { get; } = FallbackEuropean(".", ",", ".");
    private static CultureFormatInfo Chinese { get; } = FallbackEuropean(".", ",", "/");
    private static CultureFormatInfo Polish { get; } = FallbackEuropean(",", " ", ".");
    private static CultureFormatInfo Czech { get; } = FallbackEuropean(",", " ", ".");
    private static CultureFormatInfo Turkish { get; } = FallbackEuropean(",", ".", ".");
    private static CultureFormatInfo Swedish { get; } = FallbackEuropean(",", " ", "-");
    private static CultureFormatInfo Danish { get; } = FallbackEuropean(",", ".", "-");
    private static CultureFormatInfo Norwegian { get; } = FallbackEuropean(",", " ", ".");
    private static CultureFormatInfo Finnish { get; } = FallbackEuropean(",", " ", ".");
    private static CultureFormatInfo Hungarian { get; } = FallbackEuropean(",", " ", ".");
    private static CultureFormatInfo Greek { get; } = FallbackEuropean(",", ".", "/");
    private static CultureFormatInfo Romanian { get; } = FallbackEuropean(",", ".", ".");
    private static CultureFormatInfo Arabic { get; } = FallbackEuropean(".", ",", "/");
    private static CultureFormatInfo Thai { get; } = FallbackEuropean(".", ",", "/");
    private static CultureFormatInfo Vietnamese { get; } = FallbackEuropean(",", ".", "/");
    private static CultureFormatInfo Indonesian { get; } = FallbackEuropean(",", ".", "/");
}
