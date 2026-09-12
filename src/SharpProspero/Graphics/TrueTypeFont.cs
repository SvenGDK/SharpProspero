// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Font;
using System;

namespace SharpProspero.Graphics;

/// <summary>
/// A scalable TrueType or OpenType font, loaded from its file bytes, that draws antialiased text onto a
/// drawing surface in any color. It is the higher-quality alternative to the built-in bitmap font. Load
/// it once, set the pixel size, draw as often as needed, and dispose it. Load the font modules
/// (<c>SystemModule.Load(SystemModuleId.Font)</c>, <c>SystemModuleId.FontFt</c> and
/// <c>SystemModuleId.FreeTypeOt</c>) before loading a font: the glyph renderer draws through the
/// FreeType OpenType backend, and leaving it out faults the process on an unresolved routine.
/// </summary>
/// <remarks>
/// The origin passed to <see cref="ScalableFont.DrawText"/> is the top-left of the line;
/// <see cref="ScalableFont.DrawTextOnBaseline"/> takes the baseline instead. Only characters in the Basic
/// Multilingual Plane are drawn. Use <see cref="SystemFont"/> to draw with a built-in system font instead
/// of a font file.
/// </remarks>
public sealed unsafe class TrueTypeFont : ScalableFont
{
    private readonly uint _fontDataLength;

    private TrueTypeFont(SceFontMemory* memory, void* fontData, uint fontDataLength)
        : base(memory, fontData)
        => _fontDataLength = fontDataLength;

    /// <summary>
    /// Loads a font from the bytes of a <c>.ttf</c> or <c>.otf</c> file and sets its pixel size.
    /// </summary>
    /// <param name="fontFile">The font file bytes. A copy is kept for the font's lifetime.</param>
    /// <param name="pixelSize">The size to render at, in pixels.</param>
    /// <exception cref="ProsperoException">The engine or the font could not be set up.</exception>
    public static TrueTypeFont Load(ReadOnlySpan<byte> fontFile, float pixelSize = 24f)
    {
        if (fontFile.IsEmpty)
            throw new ArgumentException("The font file is empty.", nameof(fontFile));

        AllocateBuffers(fontFile, out SceFontMemory* memory, out void* fontData);
        var font = new TrueTypeFont(memory, fontData, (uint)fontFile.Length);
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
        // The library already supports external OpenType fonts (set up before the open). The font kept
        // resident in memory is opened from that buffer.
        var detail = new SceFontOpenDetail { DetailId = 0x0FD2, UniqueId = -1 };
        void* handle;
        SceResult.ThrowIfFailed(
            SceFont.sceFontOpenFontMemory(library, FontData, _fontDataLength, &detail, &handle),
            nameof(SceFont.sceFontOpenFontMemory));
        return handle;
    }
}
