// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Font;
using System;

namespace SharpProspero.Graphics;

/// <summary>
/// One of the built-in system fonts, drawn as antialiased text onto a drawing surface in any color. It
/// needs no font file shipped with the application: it opens a font set already on the console, covering
/// Latin, Japanese, Chinese, Korean, Arabic, Thai and more depending on the set chosen. Open it once,
/// set the pixel size, draw as often as needed, and dispose it. Load the font modules
/// (<c>SystemModule.Load(SystemModuleId.Font)</c>, <c>SystemModuleId.FontFt</c> and
/// <c>SystemModuleId.FreeTypeOt</c>) before opening a font: the glyph renderer draws through the
/// FreeType OpenType backend, and leaving it out faults the process on an unresolved routine.
/// </summary>
/// <remarks>
/// The font set is one of the values on <see cref="SceFontSet"/>. The default is a standard European
/// face; pick a set with wider coverage (for example <see cref="SceFontSet.StdJapaneseJpW1G"/> or a full
/// set) when the text needs it. Only characters in the Basic Multilingual Plane are drawn.
/// </remarks>
public sealed unsafe class SystemFont : ScalableFont
{
    private readonly uint _fontSet;

    private SystemFont(SceFontMemory* memory, uint fontSet)
        : base(memory, null)
        => _fontSet = fontSet;

    /// <summary>
    /// Opens a built-in system font set and sets its pixel size.
    /// </summary>
    /// <param name="fontSet">The font set to open, a value from <see cref="SceFontSet"/>.</param>
    /// <param name="pixelSize">The size to render at, in pixels.</param>
    /// <exception cref="ProsperoException">The engine or the font could not be set up.</exception>
    public static SystemFont Open(uint fontSet = SceFontSet.StdEuropeanW1G, float pixelSize = 24f)
    {
        AllocateBuffers(ReadOnlySpan<byte>.Empty, out SceFontMemory* memory, out _);
        var font = new SystemFont(memory, fontSet);
        try
        {
            font.Initialize(pixelSize);
            return font;
        }
        catch
        {
            font.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    private protected override void* OpenFont(void* library)
    {
        // The library already supports the system fonts (set up before the open). A system font set is
        // opened as a stream with no open-detail, the way the font engine expects its resident sets to
        // be sourced.
        void* handle;
        SceResult.ThrowIfFailed(
            SceFont.sceFontOpenFontSet(library, _fontSet, SceFontOpenMode.FileStream, null, &handle),
            nameof(SceFont.sceFontOpenFontSet));
        return handle;
    }
}
