// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Timing;
using System;
using System.Collections.Generic;

namespace SharpProspero.Diagnostics;

/// <summary>How important a log message is. Messages below the configured minimum are dropped.</summary>
public enum LogLevel
{
    /// <summary>Fine-grained detail, off by default.</summary>
    Trace = 0,

    /// <summary>Diagnostic detail for development.</summary>
    Debug = 1,

    /// <summary>Normal progress.</summary>
    Information = 2,

    /// <summary>Something unexpected that the module handled.</summary>
    Warning = 3,

    /// <summary>A failure.</summary>
    Error = 4,

    /// <summary>Turns logging off when set as the minimum level.</summary>
    None = 5,
}

/// <summary>A destination log lines are written to, such as a file or the development console.</summary>
public interface ILogSink
{
    /// <summary>Writes one already-leveled message. Implementations should not throw.</summary>
    void Write(LogLevel level, string message);
}

/// <summary>
/// A small logging facility for a module: pick a minimum level, add one or more sinks (a file, the
/// development console), and write leveled messages. Messages below the minimum level, or when no sink
/// is attached, cost almost nothing. Logging never throws, so a failing sink cannot crash the module.
/// </summary>
/// <example>
/// <code>
/// Log.MinimumLevel = LogLevel.Debug;
/// Log.AddSink(FileLogSink.Open("/data/app.log"));
/// Log.Information("started");
/// Log.Error($"load failed: 0x{code:X8}");
/// </code>
/// </example>
public static class Log
{
    // The sink list is guarded by a lock so a registration change on one thread never races
    // with a Write foreach on another. Without this, List's version-checked enumerator throws
    // InvalidOperationException from Write, contradicting the class contract that logging
    // never throws.
    private static readonly List<ILogSink> Sinks = [];
    private static readonly object SinksLock = new();

    /// <summary>Messages below this level are dropped. The default is <see cref="LogLevel.Information"/>.</summary>
    public static LogLevel MinimumLevel { get; set; } = LogLevel.Information;

    /// <summary>Adds a destination for log lines.</summary>
    public static void AddSink(ILogSink sink)
    {
        ArgumentNullException.ThrowIfNull(sink);
        lock (SinksLock)
            Sinks.Add(sink);
    }

    /// <summary>Removes a previously added destination.</summary>
    public static void RemoveSink(ILogSink sink)
    {
        lock (SinksLock)
            Sinks.Remove(sink);
    }

    /// <summary>Removes every destination.</summary>
    public static void ClearSinks()
    {
        lock (SinksLock)
            Sinks.Clear();
    }

    /// <summary>Writes <paramref name="message"/> at <paramref name="level"/> to every sink, if it passes the minimum.</summary>
    public static void Write(LogLevel level, string message)
    {
        if (level < MinimumLevel)
            return;
        // Snapshot the sinks under the lock so a concurrent AddSink / RemoveSink cannot mutate
        // the collection while it is being enumerated. The sink calls themselves run outside the
        // lock so a slow sink never blocks registration changes.
        ILogSink[] snapshot;
        lock (SinksLock)
        {
            if (Sinks.Count == 0)
                return;
            snapshot = Sinks.ToArray();
        }
        message ??= string.Empty;
        for (int i = 0; i < snapshot.Length; i++)
        {
            // A sink failure must never propagate to the caller; logging is best-effort.
            try
            {
                snapshot[i].Write(level, message);
            }
            catch
            {
                // Ignore: a broken sink should not take down the module.
            }
        }
    }

    /// <summary>Writes a trace-level message.</summary>
    public static void Trace(string message) => Write(LogLevel.Trace, message);

    /// <summary>Writes a debug-level message.</summary>
    public static void Debug(string message) => Write(LogLevel.Debug, message);

    /// <summary>Writes an information-level message.</summary>
    public static void Information(string message) => Write(LogLevel.Information, message);

    /// <summary>Writes a warning-level message.</summary>
    public static void Warning(string message) => Write(LogLevel.Warning, message);

    /// <summary>Writes an error-level message.</summary>
    public static void Error(string message) => Write(LogLevel.Error, message);
}

/// <summary>Formats a log line as <c>HH:mm:ss.fff LVL message</c>, shared by the sinks.</summary>
internal static class LogFormat
{
    /// <summary>Builds the full log line, without a trailing newline.</summary>
    /// <remarks>
    /// The time is built from its parts rather than through a format string. Handing a format string
    /// to a date reaches the general formatter, which carries the time-zone specifiers, which asks for
    /// the local time zone, which reads a time-zone database off the file system. That database is not
    /// there, and the cost is not a failure at run time: the reader pulls in the process layer of the
    /// run-time support library, and thirteen of the names that layer needs are published by nothing,
    /// so any module that writes a log line fails to link. The failure names those thirteen and says
    /// nothing about a timestamp.
    /// </remarks>
    public static string Line(LogLevel level, string message)
    {
        string time;
        try
        {
            DateTime now = SystemClock.LocalNow;
            time = $"{Pad2(now.Hour)}:{Pad2(now.Minute)}:{Pad2(now.Second)}.{Pad3(now.Millisecond)}";
        }
        catch
        {
            // The clock is unavailable off-device or before it is ready; log without a timestamp.
            time = "--:--:--.---";
        }
        return $"{time} {Tag(level)} {message}";
    }

    private static string Pad2(int value) => value < 10 ? "0" + value.ToString() : value.ToString();

    private static string Pad3(int value) => value switch
    {
        < 10 => "00" + value.ToString(),
        < 100 => "0" + value.ToString(),
        _ => value.ToString(),
    };

    private static string Tag(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        _ => "---",
    };
}
