// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Rtc;

/// <summary>A wall-clock time broken into calendar fields.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceRtcDateTime
{
    /// <summary>Year, four digits.</summary>
    public ushort Year;

    /// <summary>Month, 1 to 12.</summary>
    public ushort Month;

    /// <summary>Day of the month, 1 to 31.</summary>
    public ushort Day;

    /// <summary>Hour, 0 to 23.</summary>
    public ushort Hour;

    /// <summary>Minute, 0 to 59.</summary>
    public ushort Minute;

    /// <summary>Second, 0 to 59.</summary>
    public ushort Second;

    /// <summary>Microseconds within the second, 0 to 999,999.</summary>
    public uint Microsecond;
}

/// <summary>A 64-bit tick value counting microseconds since the epoch.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceRtcTick
{
    /// <summary>Raw tick count. Divide by <see cref="Rtc.sceRtcGetTickResolution"/> to obtain seconds.</summary>
    public ulong Tick;
}

/// <summary>
/// Real-time-clock bindings. Read the current wall-clock time as calendar fields or as a 64-bit tick.
/// The tick counts microseconds and the resolution call reports ticks per second.
/// </summary>
public static unsafe partial class Rtc
{
    private const string Lib = "libSceRtc";

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekSunday = 0;

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekMonday = 1;

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekTuesday = 2;

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekWednesday = 3;

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekThursday = 4;

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekFriday = 5;

    /// <summary>Day-of-week identifier returned by <see cref="sceRtcGetDayOfWeek"/>.</summary>
    public const int DayOfWeekSaturday = 6;

    /// <summary>
    /// Reads the current time into <paramref name="time"/> for the time zone offset
    /// <paramref name="timeZoneMinutes"/> in minutes; pass 0 for UTC.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetCurrentClock(SceRtcDateTime* time, int timeZoneMinutes);

    /// <summary>Reads the current time in the system's local time zone into <paramref name="time"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetCurrentClockLocalTime(SceRtcDateTime* time);

    /// <summary>Reads the current UTC time into <paramref name="tick"/> as a microsecond tick.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetCurrentTick(SceRtcTick* tick);

    /// <summary>Ticks per second, for interpreting a tick value.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceRtcGetTickResolution();

    /// <summary>Reads the current network-synchronised UTC time into <paramref name="tick"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetCurrentNetworkTick(SceRtcTick* tick);

    /// <summary>Converts a UTC tick into the local time zone.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcConvertUtcToLocalTime(SceRtcTick* utc, SceRtcTick* localTime);

    /// <summary>Converts a local-time tick into UTC.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcConvertLocalTimeToUtc(SceRtcTick* localTime, SceRtcTick* utc);

    /// <summary>Returns 1 when <paramref name="year"/> is a leap year, 0 otherwise, or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceRtcIsLeapYear(int year);

    /// <summary>Returns the number of days in <paramref name="month"/> of <paramref name="year"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetDaysInMonth(int year, int month);

    /// <summary>Returns the weekday for the given calendar date; see the <c>DayOfWeek*</c> constants.</summary>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetDayOfWeek(int year, int month, int day);

    /// <summary>Validates each field of <paramref name="time"/>; returns zero when in range, or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceRtcCheckValid(SceRtcDateTime* time);

    /// <summary>Sets the fields of <paramref name="time"/> from a POSIX <c>time_t</c> seconds count.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcSetTime_t(SceRtcDateTime* time, long secondsSinceEpoch);

    /// <summary>Writes the POSIX <c>time_t</c> seconds count of <paramref name="time"/> into <paramref name="secondsSinceEpoch"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetTime_t(SceRtcDateTime* time, long* secondsSinceEpoch);

    /// <summary>Sets the fields of <paramref name="time"/> from an MS-DOS packed date/time.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcSetDosTime(SceRtcDateTime* time, uint dosTime);

    /// <summary>Writes the MS-DOS packed date/time of <paramref name="time"/> into <paramref name="dosTime"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetDosTime(SceRtcDateTime* time, uint* dosTime);

    /// <summary>Sets the fields of <paramref name="time"/> from a Win32 FILETIME 100-nanosecond count.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcSetWin32FileTime(SceRtcDateTime* time, ulong win32Time);

    /// <summary>Writes the Win32 FILETIME 100-nanosecond count of <paramref name="time"/> into <paramref name="win32Time"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetWin32FileTime(SceRtcDateTime* time, ulong* win32Time);

    /// <summary>Sets the fields of <paramref name="time"/> from a tick value.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcSetTick(SceRtcDateTime* time, SceRtcTick* tick);

    /// <summary>Writes the tick value that corresponds to the fields of <paramref name="time"/> into <paramref name="tick"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcGetTick(SceRtcDateTime* time, SceRtcTick* tick);

    /// <summary>Adds <paramref name="ticksToAdd"/> raw ticks to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddTicks(SceRtcTick* result, SceRtcTick* source, long ticksToAdd);

    /// <summary>Adds <paramref name="microsecondsToAdd"/> microseconds to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddMicroseconds(SceRtcTick* result, SceRtcTick* source, long microsecondsToAdd);

    /// <summary>Adds <paramref name="secondsToAdd"/> seconds to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddSeconds(SceRtcTick* result, SceRtcTick* source, long secondsToAdd);

    /// <summary>Adds <paramref name="minutesToAdd"/> minutes to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddMinutes(SceRtcTick* result, SceRtcTick* source, long minutesToAdd);

    /// <summary>Adds <paramref name="hoursToAdd"/> hours to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddHours(SceRtcTick* result, SceRtcTick* source, int hoursToAdd);

    /// <summary>Adds <paramref name="daysToAdd"/> days to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddDays(SceRtcTick* result, SceRtcTick* source, int daysToAdd);

    /// <summary>Adds <paramref name="weeksToAdd"/> weeks to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddWeeks(SceRtcTick* result, SceRtcTick* source, int weeksToAdd);

    /// <summary>Adds <paramref name="monthsToAdd"/> months to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddMonths(SceRtcTick* result, SceRtcTick* source, int monthsToAdd);

    /// <summary>Adds <paramref name="yearsToAdd"/> years to <paramref name="source"/> and writes the result to <paramref name="result"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcTickAddYears(SceRtcTick* result, SceRtcTick* source, int yearsToAdd);

    /// <summary>Formats <paramref name="utc"/> as an RFC 2822 date/time string with the given time-zone offset.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcFormatRFC2822(byte* buffer, SceRtcTick* utc, int timeZoneMinutes);

    /// <summary>Formats <paramref name="utc"/> as an RFC 2822 date/time string in the system's local time zone.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcFormatRFC2822LocalTime(byte* buffer, SceRtcTick* utc);

    /// <summary>Formats <paramref name="utc"/> as an RFC 3339 (ISO 8601) date/time string with the given time-zone offset.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcFormatRFC3339(byte* buffer, SceRtcTick* utc, int timeZoneMinutes);

    /// <summary>Formats <paramref name="utc"/> as an RFC 3339 (ISO 8601) date/time string in the system's local time zone.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcFormatRFC3339LocalTime(byte* buffer, SceRtcTick* utc);

    /// <summary>Parses a date/time string in any recognised format into <paramref name="utc"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcParseDateTime(SceRtcTick* utc, byte* dateTime);

    /// <summary>Parses an RFC 3339 date/time string into <paramref name="utc"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceRtcParseRFC3339(SceRtcTick* utc, byte* dateTime);
}
