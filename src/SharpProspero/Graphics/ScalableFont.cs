// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Font;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// The shared machinery for a scalable outline font that draws antialiased text onto a surface: the font
/// engine set-up, the pixel size, kerning-aware measuring and drawing, optional synthetic weight and
/// slant, and horizontal or vertical rendering. A concrete font supplies where its glyphs come from -
/// a font file held in memory (<see cref="TrueTypeFont"/>) or one of the built-in system fonts
/// (<see cref="SystemFont"/>). Load the font modules (<c>SystemModule.Load(SystemModuleId.Font)</c> and
/// <c>SystemModuleId.FontFt</c>) before creating one.
/// </summary>
/// <remarks>
/// Each glyph is rendered to an 8-bit coverage image and composited onto the surface in the requested
/// color, so text blends smoothly over whatever is already drawn. Only characters in the Basic
/// Multilingual Plane are drawn.
/// </remarks>
public abstract unsafe class ScalableFont : IDisposable, ITextFont
{
    private readonly SceFontMemory* _memory;
    private readonly void* _fontData;

    private protected void* Library;
    private protected void* Renderer;
    private protected void* FontHandle;

    // A scratch buffer the renderer draws each glyph into; its coverage output is composited onto the
    // target surface.
    private byte* _scratch;
    private int _scratchDim;

    // A ceiling on the render size, so the scratch dimension and its allocation cannot overflow.
    private const float MaxPixelSize = 1024f;

    // How many external font faces a library keeps open at once, and the size of the device cache the
    // rasterizer is given. Both match the values the font engine's own sample sets up.
    private const uint ExternalFontMax = 16;
    private const uint DeviceCacheBytes = 1 * 1024 * 1024;

    private float _pixelSize;
    private bool _disposed;

    /// <summary>The bytes of the font file this font keeps resident, or null for a system font.</summary>
    private protected void* FontData => _fontData;

    /// <summary>Creates the shared state over the unmanaged buffers a font owns.</summary>
    private protected ScalableFont(SceFontMemory* memory, void* fontData)
    {
        _memory = memory;
        _fontData = fontData;
    }

    /// <summary>The pixel size the font renders at. Setting it moves both the render and the layout scale.</summary>
    public float PixelSize
    {
        get => _pixelSize;
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            float size = Math.Clamp(value, 1f, MaxPixelSize);
            // A font handle keeps two scales: the render scale drives the glyph rasterizer, the layout
            // scale drives the line-metric queries. They are moved together so a measured line and a
            // drawn line agree.
            SceResult.ThrowIfFailed(
                SceFont.sceFontSetupRenderScalePixel(FontHandle, size, size),
                nameof(SceFont.sceFontSetupRenderScalePixel));
            SceResult.ThrowIfFailed(
                SceFont.sceFontSetScalePixel(FontHandle, size, size),
                nameof(SceFont.sceFontSetScalePixel));
            _pixelSize = size;
            EnsureScratch();
        }
    }

    /// <summary>
    /// A synthetic slant applied by the rasterizer, for a faux-italic when the font has no italic of its
    /// own. Zero is upright; a small positive ratio (around 0.2 to 0.3) leans the glyphs to the right.
    /// </summary>
    /// <exception cref="ProsperoException">The engine rejected the slant.</exception>
    public void SetSlant(float slantRatio)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceResult.ThrowIfFailed(SceFont.sceFontSetupRenderEffectSlant(FontHandle, slantRatio),
            nameof(SceFont.sceFontSetupRenderEffectSlant));
        SceResult.ThrowIfFailed(SceFont.sceFontSetEffectSlant(FontHandle, slantRatio),
            nameof(SceFont.sceFontSetEffectSlant));
    }

    /// <summary>
    /// A synthetic weight applied by the rasterizer, for a faux-bold when the font has no bold of its
    /// own. The engine thickens the glyph by the horizontal and vertical scales; larger values are
    /// heavier. <paramref name="mode"/> selects the engine's weighting mode and defaults to the standard
    /// one. Pass equal scales for an even weight.
    /// </summary>
    /// <exception cref="ProsperoException">The engine rejected the weight.</exception>
    public void SetWeight(float horizontalScale, float verticalScale, uint mode = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceResult.ThrowIfFailed(SceFont.sceFontSetupRenderEffectWeight(FontHandle, horizontalScale, verticalScale, mode),
            nameof(SceFont.sceFontSetupRenderEffectWeight));
        SceResult.ThrowIfFailed(SceFont.sceFontSetEffectWeight(FontHandle, horizontalScale, verticalScale, mode),
            nameof(SceFont.sceFontSetEffectWeight));
    }

    // What the font engine allocates through. Held for the life of the process because the engine keeps
    // the address it is given and calls back through it later.
    private static SceFontMemoryInterface _allocator = new()
    {
        Malloc = &FontMalloc,
        Free = &FontFree,
        Realloc = &FontRealloc,
        Calloc = &FontCalloc,
    };

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void* FontMalloc(void* _, uint size) => NativeMemory.Alloc(size);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void FontFree(void* _, void* block) => NativeMemory.Free(block);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void* FontRealloc(void* _, void* block, uint size) => NativeMemory.Realloc(block, size);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void* FontCalloc(void* _, uint count, uint size) => NativeMemory.AllocZeroed(count, size);

    // Allocates the engine's bookkeeping struct a font needs before its engine is set up, and, for a
    // font-file font, a resident copy of the file bytes. The engine allocates its working memory through
    // the routines in the memory interface, so no separate block is reserved.
    private protected static void AllocateBuffers(ReadOnlySpan<byte> fontFile,
        out SceFontMemory* memory, out void* fontData)
    {
        memory = (SceFontMemory*)NativeMemory.AllocZeroed((nuint)sizeof(SceFontMemory));
        fontData = null;
        try
        {
            if (!fontFile.IsEmpty)
            {
                fontData = NativeMemory.Alloc((nuint)fontFile.Length);
                fontFile.CopyTo(new Span<byte>(fontData, fontFile.Length));
            }
        }
        catch
        {
            NativeMemory.Free(memory);
            throw;
        }
    }

    // Sets up the engine, opens the concrete font's source, binds the renderer to the resulting handle,
    // and sets the pixel size. The library is made first and fully set up before a renderer is made or a
    // face is opened, the order the font engine's own sample follows: it is told to support the
    // system-installed fonts and the OpenType parser (which the system fonts and any external font are
    // both stored in), and given a device cache buffer for the rasterizer. A face opened before that
    // OpenType support is registered reaches an engine path that was never patched in and faults, so the
    // whole set-up is done here once, ahead of the open, for every scalable font.
    private protected void Initialize(float pixelSize)
    {
        fixed (SceFontMemoryInterface* allocator = &_allocator)
            SceResult.ThrowIfFailed(
                SceFont.sceFontMemoryInit(_memory, null, 0, allocator, null, null, null),
                nameof(SceFont.sceFontMemoryInit));

        void* librarySelection = SceFontFt.sceFontSelectLibraryFt(0);
        void* library;
        SceResult.ThrowIfFailed(
            SceFont.sceFontCreateLibraryWithEdition(_memory, librarySelection, SceFont.Edition, &library),
            nameof(SceFont.sceFontCreateLibraryWithEdition));
        Library = library;

        SceResult.ThrowIfFailed(
            SceFont.sceFontSupportSystemFonts(library), nameof(SceFont.sceFontSupportSystemFonts));
        SceResult.ThrowIfFailed(
            SceFont.sceFontSupportExternalFonts(library, ExternalFontMax, SceFont.FormatOpenType),
            nameof(SceFont.sceFontSupportExternalFonts));
        SceResult.ThrowIfFailed(
            SceFont.sceFontAttachDeviceCacheBuffer(library, null, DeviceCacheBytes),
            nameof(SceFont.sceFontAttachDeviceCacheBuffer));

        void* rendererSelection = SceFontFt.sceFontSelectRendererFt(0);
        void* renderer;
        SceResult.ThrowIfFailed(
            SceFont.sceFontCreateRendererWithEdition(_memory, rendererSelection, SceFont.Edition, &renderer),
            nameof(SceFont.sceFontCreateRendererWithEdition));
        Renderer = renderer;

        FontHandle = OpenFont(library);

        SceResult.ThrowIfFailed(SceFont.sceFontBindRenderer(FontHandle, renderer), nameof(SceFont.sceFontBindRenderer));
        PixelSize = pixelSize;
    }

    /// <summary>Opens the face this font draws from on <paramref name="library"/>, which is already set
    /// up to support the system and OpenType fonts.</summary>
    /// <returns>The opened font handle.</returns>
    private protected abstract void* OpenFont(void* library);

    /// <summary>The distance, in pixels, from one line of text to the next, as the font gives it.</summary>
    public int LineHeight => (int)(Layout().LineHeight + 0.5f);

    /// <summary>
    /// The distance, in pixels, from the top of a line down to its baseline. <see cref="DrawText"/> adds
    /// this so a caller works in line tops; <see cref="DrawTextOnBaseline"/> does not.
    /// </summary>
    public int BaselineOffset => (int)(Layout().BaseLineY + 0.5f);

    private SceFontHorizontalLayout Layout()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceFontHorizontalLayout layout = default;
        SceResult.ThrowIfFailed(
            SceFont.sceFontGetHorizontalLayout(FontHandle, &layout), nameof(SceFont.sceFontGetHorizontalLayout));
        return layout;
    }

    /// <summary>The width, in pixels, that <paramref name="text"/> occupies at the current size.</summary>
    public int MeasureText(ReadOnlySpan<char> text)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        float pen = 0f;
        uint previous = 0;
        foreach (char c in text)
        {
            pen += Advance(previous, c);
            previous = c;
        }
        return (int)(pen + 0.5f);
    }

    // The advance from the glyph before <paramref name="code"/> to the one after it: the kerning between
    // the pair, when there is a preceding glyph, plus the glyph's own advance. Measuring and drawing both
    // step the pen through this one place so a line's measured width and its drawn extent agree.
    private float Advance(uint previous, uint code)
    {
        float advance = 0f;
        if (previous != 0)
        {
            SceFontKerning kerning = default;
            if (SceResult.Succeeded(SceFont.sceFontGetRenderScaledKerning(FontHandle, previous, code, &kerning)))
                advance += kerning.OffsetX;
        }
        SceFontGlyphMetrics metrics = default;
        if (SceResult.Succeeded(SceFont.sceFontGetRenderCharGlyphMetrics(FontHandle, code, &metrics)))
            advance += metrics.HorizontalAdvance;
        return advance;
    }

    /// <summary>
    /// Draws <paramref name="text"/> onto <paramref name="surface"/> in <paramref name="color"/>, with
    /// (<paramref name="x"/>, <paramref name="y"/>) at the top-left of the line.
    /// </summary>
    public void DrawText(Surface surface, ReadOnlySpan<char> text, int x, int y, Color color)
        => DrawTextOnBaseline(surface, text, x, y + BaselineOffset, color);

    /// <summary>
    /// Draws <paramref name="text"/> onto <paramref name="surface"/> in <paramref name="color"/>, with
    /// (<paramref name="x"/>, <paramref name="y"/>) at the left end of the text baseline.
    /// </summary>
    public void DrawTextOnBaseline(Surface surface, ReadOnlySpan<char> text, int x, int y, Color color)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        float penX = x;
        uint previous = 0;
        foreach (char c in text)
        {
            if (previous != 0)
            {
                SceFontKerning kerning = default;
                if (SceResult.Succeeded(SceFont.sceFontGetRenderScaledKerning(FontHandle, previous, c, &kerning)))
                    penX += kerning.OffsetX;
            }
            previous = c;

            SceFontGlyphMetrics metrics = default;
            SceFontRenderResult result = default;
            SceFontRenderSurface renderSurface = default;
            new Span<byte>(_scratch, _scratchDim * _scratchDim).Clear();
            SceFont.sceFontRenderSurfaceInit(&renderSurface, _scratch, _scratchDim, 1, _scratchDim, _scratchDim);
            SceFont.sceFontRenderSurfaceSetScissor(&renderSurface, 0, 0, (uint)_scratchDim, (uint)_scratchDim);

            float scratchPenX = _scratchDim * 0.25f, scratchPenY = _scratchDim * 0.75f;
            int rc = SceFont.sceFontRenderCharGlyphImageHorizontal(FontHandle, c, &renderSurface, scratchPenX, scratchPenY, &metrics, &result);
            if (SceResult.Succeeded(rc))
            {
                CompositeCoverage(surface, result, color,
                    (int)(penX + 0.5f) - (int)scratchPenX, y - (int)scratchPenY);
                penX += metrics.HorizontalAdvance;
            }
            else
            {
                SceFontGlyphMetrics fallback = default;
                if (SceResult.Succeeded(SceFont.sceFontGetRenderCharGlyphMetrics(FontHandle, c, &fallback)))
                    penX += fallback.HorizontalAdvance;
            }
        }
    }

    // Blends one glyph's coverage over the surface in the chosen color. The render reports where in the
    // scratch it wrote and the region it changed; the placement carries that across to the target.
    private static void CompositeCoverage(Surface surface, SceFontRenderResult result, Color color, int originX, int originY)
    {
        int width = (int)result.UpdateW;
        int height = (int)result.UpdateH;
        byte* coverage = result.SurfaceImage.Address;
        if (width <= 0 || height <= 0 || coverage == null)
            return;

        int pitch = (int)result.SurfaceImage.WidthByte;
        int left = originX + (int)result.UpdateX;
        int top = originY + (int)result.UpdateY;
        uint rgb = color.Value & 0x00FFFFFFu;

        for (int row = 0; row < height; row++)
        {
            int py = top + row;
            if ((uint)py >= (uint)surface.Height)
                continue;
            byte* line = coverage + (long)row * pitch;
            for (int col = 0; col < width; col++)
            {
                byte alpha = line[col];
                if (alpha == 0)
                    continue;
                surface.BlendPixel(left + col, py, rgb, alpha);
            }
        }
    }

    // Sizes the scratch render buffer to hold a glyph at the current pixel size, with room for the
    // ascent and any overhang.
    private void EnsureScratch()
    {
        int dim = (int)(_pixelSize * 3f + 0.5f) + 8;
        if (dim <= _scratchDim && _scratch != null)
            return;
        var buffer = (byte*)NativeMemory.Alloc((nuint)((long)dim * dim));
        if (_scratch != null)
            NativeMemory.Free(_scratch);
        _scratch = buffer;
        _scratchDim = dim;
    }

    /// <summary>Releases the font, the engine objects and their memory.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        if (FontHandle != null)
        {
            SceFont.sceFontUnbindRenderer(FontHandle);
            SceFont.sceFontCloseFont(FontHandle);
            FontHandle = null;
        }
        if (Library != null)
        {
            void* library = Library;
            SceFont.sceFontDestroyLibrary(&library);
            Library = null;
        }
        if (Renderer != null)
        {
            void* renderer = Renderer;
            SceFont.sceFontDestroyRenderer(&renderer);
            Renderer = null;
        }
        SceFont.sceFontMemoryTerm(_memory);

        if (_scratch != null)
            NativeMemory.Free(_scratch);
        if (_fontData != null)
            NativeMemory.Free(_fontData);
        NativeMemory.Free(_memory);
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases the resources if the font was dropped without a <see cref="Dispose"/> call.</summary>
    ~ScalableFont() => Dispose();
}
