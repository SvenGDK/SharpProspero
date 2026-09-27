// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics;
using System.Collections.Generic;

namespace SharpProspero.Globalization.Fonts;

/// <summary>
/// Caches "does font N cover codepoint C" answers so a font-cascade walk over a long paragraph
/// does not re-probe the same character on every glyph. A miss is answered by the font's own
/// <see cref="ITextFont.HasGlyph"/>; hits stay in memory for the life of the probe.
/// </summary>
public sealed class FontCoverageProbe
{
    private readonly Dictionary<(int Font, int Codepoint), bool> _cache;
    private readonly int _capacity;

    /// <summary>Creates a probe with an entry cap; oldest half is dropped when the cap is hit.</summary>
    public FontCoverageProbe(int capacity = 16_384)
    {
        _capacity = capacity;
        _cache = new Dictionary<(int, int), bool>(capacity);
    }

    /// <summary>Number of (font, codepoint) pairs currently cached.</summary>
    public int CachedEntries => _cache.Count;

    /// <summary>
    /// Reports whether <paramref name="font"/> has a glyph for <paramref name="codepoint"/>.
    /// Cached on first probe.
    /// </summary>
    public bool HasGlyph(int fontIndex, ITextFont font, int codepoint)
    {
        var key = (fontIndex, codepoint);
        if (_cache.TryGetValue(key, out bool cached))
            return cached;
        bool answer = font.HasGlyph(codepoint);
        if (_cache.Count >= _capacity)
        {
            // Simple bounded-cache eviction: drop the first half (or at least one entry) in
            // enumeration order. Loses locality but keeps the cache bounded without an LRU heap.
            // Keys are buffered so the removal loop never mutates the collection it is iterating.
            // The `Math.Max(1, ...)` guard makes eviction fire even when capacity is 1 — without
            // it, Count/2 rounds to 0 and the cache would silently grow past capacity.
            int toDrop = System.Math.Max(1, _cache.Count / 2);
            var victims = new (int Font, int Codepoint)[toDrop];
            int filled = 0;
            foreach (var kv in _cache)
            {
                if (filled >= toDrop) break;
                victims[filled++] = kv.Key;
            }
            for (int i = 0; i < filled; i++)
                _cache.Remove(victims[i]);
        }
        _cache[key] = answer;
        return answer;
    }

    /// <summary>Discards every cached answer.</summary>
    public void Invalidate() => _cache.Clear();
}
