// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System;
using System.Collections.Generic;

namespace SharpProspero.Globalization.Fonts;

/// <summary>
/// An <see cref="ITextFont"/> that routes each codepoint to the first tier in a cascade whose
/// <see cref="ITextFont.HasGlyph"/> reports coverage. The final tier is always the ultimate
/// fallback (a bitmap font for ASCII, or a tofu glyph for anything else) so a missing codepoint
/// is drawn as a visible placeholder rather than skipped silently.
/// </summary>
/// <remarks>
/// The cascade splits a paragraph into runs whose characters all resolve to the same tier, then
/// asks each tier to measure and draw its own run. This keeps the on-device font engine's glyph
/// cache warm because Latin text stays on the Latin tier for the whole run rather than round-
/// tripping through the universal set. A single 16 K-entry <see cref="FontCoverageProbe"/> caches
/// the coverage answers so re-rendering the same paragraph is one lookup per unique codepoint.
/// </remarks>
public sealed class FontCascade : ITextFont, IDisposable
{
    private readonly ITextFont[] _fonts;
    private readonly ITextFont _finalFallback;
    private readonly FontCoverageProbe _probe;
    private bool _disposed;

    /// <summary>Creates a cascade over <paramref name="fontsInOrder"/> plus a fallback tier.</summary>
    /// <exception cref="ArgumentException">Any element of <paramref name="fontsInOrder"/> is null.</exception>
    public FontCascade(IReadOnlyList<ITextFont> fontsInOrder, ITextFont finalFallback)
    {
        ArgumentNullException.ThrowIfNull(fontsInOrder);
        ArgumentNullException.ThrowIfNull(finalFallback);
        _fonts = new ITextFont[fontsInOrder.Count];
        for (int i = 0; i < fontsInOrder.Count; i++)
        {
            // Reject a null tier at construction so the failure stack points at the caller that
            // supplied the bad list, not at the first frame that dereferences the null slot.
            if (fontsInOrder[i] is null)
                throw new ArgumentException($"Tier {i} in the cascade is null.", nameof(fontsInOrder));
            _fonts[i] = fontsInOrder[i];
        }
        _finalFallback = finalFallback;
        _probe = new FontCoverageProbe();
    }

    /// <summary>The number of tiers in this cascade (excluding the final fallback).</summary>
    public int FontCount => _fonts.Length;

    /// <summary>The tier at <paramref name="index"/>.</summary>
    public ITextFont FontAt(int index) => _fonts[index];

    /// <summary>The line height of the tallest tier (so mixed runs sit on a common baseline).</summary>
    public int LineHeight
    {
        get
        {
            int h = _finalFallback.LineHeight;
            for (int i = 0; i < _fonts.Length; i++)
                if (_fonts[i].LineHeight > h) h = _fonts[i].LineHeight;
            return h;
        }
    }

    /// <inheritdoc/>
    public bool HasGlyph(int codepoint)
    {
        for (int i = 0; i < _fonts.Length; i++)
            if (_probe.HasGlyph(i, _fonts[i], codepoint)) return true;
        return _finalFallback.HasGlyph(codepoint);
    }

    /// <inheritdoc/>
    public int MeasureText(ReadOnlySpan<char> text)
    {
        if (text.Length == 0) return 0;
        int total = 0;
        int start = 0;
        int currentTier = ResolveTier(FirstCodepointAt(text, 0));

        for (int i = FirstStep(text, 0); i < text.Length;)
        {
            int cp = ReadCodepoint(text, i, out int step);
            int tier = ResolveTier(cp);
            if (tier != currentTier)
            {
                total += MeasureRun(text[start..i], currentTier);
                start = i;
                currentTier = tier;
            }
            i += step;
        }
        total += MeasureRun(text[start..], currentTier);
        return total;
    }

    /// <inheritdoc/>
    public void DrawText(Surface surface, ReadOnlySpan<char> text, int x, int y, Color color)
    {
        if (text.Length == 0) return;
        int start = 0;
        int currentTier = ResolveTier(FirstCodepointAt(text, 0));

        for (int i = FirstStep(text, 0); i < text.Length;)
        {
            int cp = ReadCodepoint(text, i, out int step);
            int tier = ResolveTier(cp);
            if (tier != currentTier)
            {
                DrawRun(surface, text[start..i], x, y, color, currentTier);
                x += MeasureRun(text[start..i], currentTier);
                start = i;
                currentTier = tier;
            }
            i += step;
        }
        DrawRun(surface, text[start..], x, y, color, currentTier);
    }

    /// <summary>Discards the coverage cache.</summary>
    public void InvalidateCoverageCache() => _probe.Invalidate();

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Isolate each tier's Dispose so a throwing tier does not skip the remaining tiers or
        // the final fallback — every native handle must be released even when one dispose call
        // misbehaves at teardown.
        for (int i = 0; i < _fonts.Length; i++)
        {
            try { (_fonts[i] as IDisposable)?.Dispose(); }
            catch { }
        }
        try { (_finalFallback as IDisposable)?.Dispose(); }
        catch { }
    }

    // -1 == final fallback; 0..N-1 == tier index in _fonts.
    private int ResolveTier(int codepoint)
    {
        for (int i = 0; i < _fonts.Length; i++)
            if (_probe.HasGlyph(i, _fonts[i], codepoint)) return i;
        return -1;
    }

    private int MeasureRun(ReadOnlySpan<char> run, int tier)
    {
        ITextFont font = tier < 0 ? _finalFallback : _fonts[tier];
        return font.MeasureText(run);
    }

    private void DrawRun(Surface surface, ReadOnlySpan<char> run, int x, int y, Color color, int tier)
    {
        ITextFont font = tier < 0 ? _finalFallback : _fonts[tier];
        font.DrawText(surface, run, x, y, color);
    }

    private static int FirstCodepointAt(ReadOnlySpan<char> text, int index)
        => ReadCodepoint(text, index, out _);

    private static int FirstStep(ReadOnlySpan<char> text, int index)
    {
        ReadCodepoint(text, index, out int consumed);
        return index + consumed;
    }

    private static int ReadCodepoint(ReadOnlySpan<char> text, int index, out int consumed)
    {
        char c = text[index];
        if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
        {
            consumed = 2;
            return char.ConvertToUtf32(c, text[index + 1]);
        }
        consumed = 1;
        return c;
    }
}
