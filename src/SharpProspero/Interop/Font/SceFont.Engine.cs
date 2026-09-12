// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Font;

/// <summary>
/// The rest of the font-engine surface: system fonts, scaling and resolution read-back, synthetic
/// weight and slant effects, glyph objects and their outlines, style frames, and the shaping and
/// composition engine (text source, string, words, character iteration, writing and writing line).
/// These extend the core rendering calls in the companion file. Load <c>SystemModuleId.Font</c> and
/// <c>SystemModuleId.FontFt</c> before use.
/// </summary>
public static unsafe partial class SceFont
{
    // ---- Library, system fonts, device cache -------------------------------------------------

    /// <summary>Creates the font library over a memory block and a backend selection at the default edition.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCreateLibrary(SceFontMemory* memory, void* selection, void** pLibrary);

    /// <summary>Creates the glyph renderer over a memory block and a backend selection at the default edition.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCreateRenderer(SceFontMemory* memory, void* selection, void** pRenderer);

    /// <summary>Enables opening the built-in system fonts on this library.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSupportSystemFonts(void* library);

    /// <summary>Sets how the library opens fonts of a given target set.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetFontsOpenMode(void* library, uint openMode, uint targetFonts);

    /// <summary>Reads the library a font handle belongs to.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetLibrary(void* fontHandle, void** pLibrary);

    /// <summary>Reads the sub-pixel resolution the library renders at.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetPixelResolution(void* library, uint* subPixelCount);

    /// <summary>Attaches a device (GPU) cache buffer the library keeps rendered glyphs in.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontAttachDeviceCacheBuffer(void* library, void* buffer, uint size);

    /// <summary>Clears the attached device cache.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontClearDeviceCache(void* library);

    /// <summary>Detaches the device cache buffer, returning it and its size.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontDettachDeviceCacheBuffer(void* library, void** buffer, uint* size);

    /// <summary>Opens one of the built-in system font sets and writes its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontOpenFontSet(void* library, uint fontSetType, uint openMode,
        SceFontOpenDetail* detail, void** pFontHandle);

    /// <summary>Opens a font from a file path and writes its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontOpenFontFile(void* library, byte* fontPath, uint openMode,
        SceFontOpenDetail* detail, void** pFontHandle);

    /// <summary>Opens a second handle onto an already-open font, optionally from a template.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontOpenFontInstance(void* fontHandle, void* setupFont, void** pFontHandle);

    // ---- Renderer outline buffer ---------------------------------------------------------------

    /// <summary>Sets the renderer's outline-buffer growth policy and sizes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRendererSetOutlineBufferPolicy(void* renderer, ulong bufferPolicy,
        uint basalSize, uint limitSize);

    /// <summary>Reads the current outline-buffer size.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRendererGetOutlineBufferSize(void* renderer, uint* size);

    /// <summary>Resets the outline buffer to its basal size.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRendererResetOutlineBuffer(void* renderer);

    /// <summary>Rebinds a font handle to the renderer it was last bound to.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRebindRenderer(void* fontHandle);

    // ---- Handle attributes, script/language, typographic, info --------------------------------

    /// <summary>Sets a handle attribute, returning the previous value.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontDefineAttribute(void* fontHandle, int attribute, int* oldAttribute);

    /// <summary>Reads the current value of a handle attribute.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetAttribute(void* fontHandle, int attribute, int* nowAttribute);

    /// <summary>Selects the script and language a handle shapes and renders for.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetScriptLanguage(void* fontHandle, int fontScript, int fontLanguage);

    /// <summary>Reads the language selected for a script on this handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetScriptLanguage(void* fontHandle, int fontScript, int* fontLanguage);

    /// <summary>Sets a typographic design feature on this handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetTypographicDesign(void* fontHandle, int typographic, int feature);

    /// <summary>Reads a typographic design feature on this handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetTypographicDesign(void* fontHandle, int typographic, int* feature);

    /// <summary>Reads the font's design resolution and the pixel scale it maps to.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetFontResolution(void* fontHandle, uint* pResolution, float* pScalePixel);

    /// <summary>Reads how many glyphs the font contains.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetFontGlyphsCount(void* fontHandle, uint* glyphsCount);

    /// <summary>Reads the glyph code a character maps to in this font.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetCharGlyphCode(void* fontHandle, uint code, uint* glyphCode);

    // ---- Scale and resolution read-back, point setters ----------------------------------------

    /// <summary>Reads the dots per inch a point size is resolved against.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetResolutionDpi(void* fontHandle, uint* hDpi, uint* vDpi);

    /// <summary>Reads the layout scale in points.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetScalePoint(void* fontHandle, float* w, float* h);

    /// <summary>Sets the render scale in points, resolved through the current resolution.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetupRenderScalePoint(void* fontHandle, float w, float h);

    /// <summary>Reads the render scale in pixels.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetRenderScalePixel(void* fontHandle, float* w, float* h);

    /// <summary>Reads the render scale in points.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetRenderScalePoint(void* fontHandle, float* w, float* h);

    // ---- Synthetic effects (weight and slant) --------------------------------------------------

    /// <summary>Sets the synthetic weight (faux bold) at the layout scale.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetEffectWeight(void* fontHandle, float weightXScale, float weightYScale, uint mode);

    /// <summary>Reads the layout-scale synthetic weight.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetEffectWeight(void* fontHandle, float* weightXScale, float* weightYScale, uint* mode);

    /// <summary>Sets the synthetic slant (faux italic) at the layout scale.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetEffectSlant(void* fontHandle, float slantRatio);

    /// <summary>Reads the layout-scale synthetic slant.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetEffectSlant(void* fontHandle, float* slantRatio);

    /// <summary>Sets the synthetic slant applied by the glyph rasterizer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetupRenderEffectSlant(void* fontHandle, float slantRatio);

    /// <summary>Sets the synthetic weight applied by the glyph rasterizer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontSetupRenderEffectWeight(void* fontHandle, float weightXScale, float weightYScale, uint mode);

    /// <summary>Reads the render-scale synthetic slant.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetRenderEffectSlant(void* fontHandle, float* slantRatio);

    /// <summary>Reads the render-scale synthetic weight.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetRenderEffectWeight(void* fontHandle, float* weightXScale, float* weightYScale, uint* mode);

    // ---- Layout-scale metrics, kerning, vertical layout ---------------------------------------

    /// <summary>Reads a character's glyph metrics at the layout scale.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetCharGlyphMetrics(void* fontHandle, uint code, SceFontGlyphMetrics* metrics);

    /// <summary>Reads the kerning between two characters at the layout scale.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetKerning(void* fontHandle, uint preCode, uint code, SceFontKerning* kerning);

    /// <summary>Reads how a column of this font stacks for vertical writing.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGetVerticalLayout(void* fontHandle, SceFontVerticalLayout* layout);

    // ---- Character glyph render (default and vertical) ----------------------------------------

    /// <summary>Renders a character's glyph into <paramref name="surf"/>, writing mode chosen by attribute.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRenderCharGlyphImage(void* fontHandle, uint code,
        SceFontRenderSurface* surf, float x, float y, SceFontGlyphMetrics* metrics, SceFontRenderResult* result);

    /// <summary>Renders a character's glyph for vertical text into <paramref name="surf"/> at (x, y).</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRenderCharGlyphImageVertical(void* fontHandle, uint code,
        SceFontRenderSurface* surf, float x, float y, SceFontGlyphMetrics* metrics, SceFontRenderResult* result);

    // ---- Style frame ---------------------------------------------------------------------------

    /// <summary>Initializes a style frame to empty.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameInit(SceFontStyleFrame* styleFrame);

    /// <summary>Sets the resolution a point scale in the frame resolves against.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameSetResolutionDpi(SceFontStyleFrame* styleFrame, uint hDpi, uint vDpi);

    /// <summary>Sets the frame's scale in points.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameSetScalePoint(SceFontStyleFrame* styleFrame, float w, float h);

    /// <summary>Sets the frame's scale in pixels.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameSetScalePixel(SceFontStyleFrame* styleFrame, float w, float h);

    /// <summary>Sets the frame's synthetic weight.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameSetEffectWeight(SceFontStyleFrame* styleFrame, float weightXScale, float weightYScale, uint mode);

    /// <summary>Sets the frame's synthetic slant.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameSetEffectSlant(SceFontStyleFrame* styleFrame, float slantRatio);

    /// <summary>Clears the frame's scale so the handle's own scale is used.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameUnsetScale(SceFontStyleFrame* styleFrame);

    /// <summary>Clears the frame's synthetic slant.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameUnsetEffectSlant(SceFontStyleFrame* styleFrame);

    /// <summary>Clears the frame's synthetic weight.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameUnsetEffectWeight(SceFontStyleFrame* styleFrame);

    /// <summary>Reads the frame's resolution.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameGetResolutionDpi(SceFontStyleFrame* styleFrame, uint* hDpi, uint* vDpi);

    /// <summary>Reads the frame's point scale.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameGetScalePoint(SceFontStyleFrame* styleFrame, float* w, float* h);

    /// <summary>Reads the frame's pixel scale.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameGetScalePixel(SceFontStyleFrame* styleFrame, float* w, float* h);

    /// <summary>Reads the frame's synthetic weight.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameGetEffectWeight(SceFontStyleFrame* styleFrame, float* weightXScale, float* weightYScale, uint* mode);

    /// <summary>Reads the frame's synthetic slant.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStyleFrameGetEffectSlant(SceFontStyleFrame* styleFrame, float* slantRatio);

    /// <summary>Attaches a style frame to a render surface so a glyph render reads it.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontRenderSurfaceSetStyleFrame(SceFontRenderSurface* surf, SceFontStyleFrame* styleFrame);

    // ---- Glyph objects -------------------------------------------------------------------------

    /// <summary>Generates a glyph object for a character and writes its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGenerateCharGlyph(void* fontHandle, uint code,
        SceFontGenerateGlyphDetail* detail, void** pFontGlyph);

    /// <summary>Deletes a glyph object.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontDeleteGlyph(SceFontMemory* memory, void** pFontGlyph);

    /// <summary>Reads which outline form a glyph carries.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphGetGlyphForm(void* fontGlyph);

    /// <summary>Refers to a glyph's outline, or null if it has no public outline.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontGlyphOutline* sceFontGlyphRefersOutline(void* fontGlyph);

    /// <summary>Reads which metrics form a glyph carries.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphGetMetricsForm(void* fontGlyph);

    /// <summary>Refers to a glyph's full metrics.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontGlyphMetrics* sceFontGlyphRefersMetrics(void* fontGlyph);

    /// <summary>Refers to a glyph's horizontal metrics.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontGlyphMetricsHorizontal* sceFontGlyphRefersMetricsHorizontal(void* fontGlyph);

    /// <summary>Refers to a glyph's horizontal metrics without the height.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontGlyphMetricsHorizontalX* sceFontGlyphRefersMetricsHorizontalX(void* fontGlyph);

    /// <summary>Refers to a glyph's horizontal advance.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontGlyphMetricsHorizontalAdvance* sceFontGlyphRefersMetricsHorizontalAdvance(void* fontGlyph);

    /// <summary>Sets an attribute on a glyph object, returning the previous value.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphDefineAttribute(void* fontGlyph, int attribute, int* oldAttribute);

    /// <summary>Reads an attribute on a glyph object.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphGetAttribute(void* fontGlyph, int attribute, int* nowAttribute);

    /// <summary>Renders a glyph object, writing mode chosen by the frame and font attributes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphRenderImage(void* fontGlyph, SceFontStyleFrame* fontStyleFrame,
        void* fontRenderer, SceFontRenderSurface* surface, float x, float y, SceFontGlyphMetrics* metrics, SceFontRenderResult* result);

    /// <summary>Renders a glyph object for horizontal text.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphRenderImageHorizontal(void* fontGlyph, SceFontStyleFrame* fontStyleFrame,
        void* fontRenderer, SceFontRenderSurface* surface, float x, float y, SceFontGlyphMetrics* metrics, SceFontRenderResult* result);

    /// <summary>Renders a glyph object for vertical text.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontGlyphRenderImageVertical(void* fontGlyph, SceFontStyleFrame* fontStyleFrame,
        void* fontRenderer, SceFontRenderSurface* surface, float x, float y, SceFontGlyphMetrics* metrics, SceFontRenderResult* result);

    // ---- Text source ---------------------------------------------------------------------------

    /// <summary>
    /// Initializes a text source over a span of source text, with a parser callback that reads one
    /// code at a time. <paramref name="textParser"/> is a pointer to an unmanaged cdecl function.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceFontTextSourceInit(SceFontTextSource* fontTextSource,
        void* textAddress, uint textSizeByte, void* textParser, void* textObject);

    /// <summary>Sets the writing form the text source shapes for.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontTextSourceSetWritingForm(SceFontTextSource* fontTextSource, int writingForm);

    /// <summary>Sets the default font for codes the parser does not resolve to one.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontTextSourceSetDefaultFont(SceFontTextSource* fontTextSource, void* defaultFont);

    /// <summary>Rewinds the text source to its start.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontTextSourceRewind(SceFontTextSource* fontTextSource);

    // ---- String (shaping) ----------------------------------------------------------------------

    /// <summary>Shapes a text source into a string object and writes its handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCreateString(SceFontMemory* fontMemory,
        SceFontTextSource* fontTextSource, SceFontCreateStringDetail* stringDetail, void** pFontString);

    /// <summary>Destroys a string object.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontDestroyString(void** pFontString);

    /// <summary>Reads the writing form a shaped string resolved to.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontStringGetWritingForm(void* fontString);

    /// <summary>Reads the code that terminated the string's source.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceFontStringGetTerminateCode(void* fontString);

    /// <summary>Reads the ordering token at the string's terminator.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontStringGetTerminateOrder(void* fontString);

    /// <summary>Refers to the first text character of a string and its count.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontStringRefersTextCharacters(void* fontString, uint* characterCount);

    /// <summary>Refers to the render characters between two text characters and their count.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontStringRefersRenderCharacters(void* fontString,
        void* startCharacter, void* lastCharacter, uint* characterCount);

    // ---- Character iteration -------------------------------------------------------------------

    /// <summary>Refers to the next text character.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontCharacterRefersTextNext(void* textCharacter);

    /// <summary>Refers to the previous text character.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontCharacterRefersTextBack(void* textCharacter);

    /// <summary>Refers to the code step between two characters, filling <paramref name="textCodes"/>.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontCharactersRefersTextCodes(void* textCharacter, void* termCharacter, SceFontTextCodes* textCodes);

    /// <summary>Steps the code cursor forward.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontTextCodesStepNext(void* textCodesStep);

    /// <summary>Steps the code cursor back.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontTextCodesStepBack(void* textCodesStep);

    /// <summary>Reads a character's bidirectional level.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCharacterGetBidiLevel(void* textCharacter, int* bidiLevel);

    /// <summary>Reports whether a character is whitespace.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceFontCharacterLooksWhiteSpace(void* textCharacter);

    /// <summary>Reports whether a character is a formatting character.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceFontCharacterLooksFormatCharacters(void* textCharacter);

    /// <summary>Reads a character's font handle and code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCharacterGetTextFontCode(void* textCharacter, void** pFontHandle, uint* textCode);

    /// <summary>Reads a character's ordering token.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCharacterGetTextOrder(void* textCharacter, void** pTextOrder);

    /// <summary>Reads a character's syllable-cluster state in a complex script.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCharacterGetSyllableStringState(void* textCharacter, int* syllableStringState);

    // ---- Words (word breaking) -----------------------------------------------------------------

    /// <summary>Builds a word-breaking object over a text source.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCreateWords(SceFontMemory* fontMemory, SceFontTextSource* textSource, void* detail, void** pFontWords);

    /// <summary>Finds the characters of the next word from a start character.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWordsFindWordCharacters(void* fontWords,
        void* startCharacter, void* termCharacter, void** pLastCharacter, void** pNextCharacter);

    /// <summary>Destroys a word-breaking object.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontDestroyWords(void** pFontWords);

    // ---- Writing (glyph positioning) -----------------------------------------------------------

    /// <summary>Begins a writing pass over a shaped string from a character.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingInit(SceFontWriting* fontWriting, void* fontString, void* fontCharacter);

    /// <summary>Sets which invisible characters the writing pass skips.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingSetMaskInvisible(SceFontWriting* fontWriting, int mask);

    /// <summary>Advances the writing pass and refers to the current render step, or null at the end.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontWritingStep* sceFontWritingRefersRenderStep(SceFontWriting* fontWriting);

    /// <summary>Refers to the character and letter grouping of the current render step.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceFontWritingRefersRenderStepCharacter(SceFontWriting* fontWriting, SceFontWritingLetterStep** pLetterStep);

    /// <summary>Reads the advance and covered rectangle of the writing pass so far.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingGetRenderMetrics(SceFontWriting* fontWriting, SceFontWritingMetrics* writingMetrics);

    // ---- Writing line (composition and justification) -----------------------------------------

    /// <summary>Creates a writing line to compose ordered runs into.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontCreateWritingLine(SceFontMemory* fontMemory, int writingForm,
        SceFontCreateWritingLineDetail* writingLineDetail, void** pWritingLine);

    /// <summary>Writes an ordered run into the line with its attribute and metrics.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingLineWritesOrder(void* writingLine, ulong writingAttribute,
        SceFontWritingMetrics* writingMetrics, void* writingOrderer);

    /// <summary>Reads the head, inline, tail and advance spacing the line will apply.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingLineGetOrderingSpace(void* writingLine,
        float* headSpace, float* inlineSpace, float* tailSpace, float* advanceSpace);

    /// <summary>Clears the line's ordered runs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingLineClear(void* writingLine);

    /// <summary>Advances the line and refers to the current run's render step, or null at the end.</summary>
    [LibraryImport(Lib)]
    public static partial SceFontWritingLineStep* sceFontWritingLineRefersRenderStep(void* writingLine);

    /// <summary>Reads the composed line's advance and covered rectangle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontWritingLineGetRenderMetrics(void* writingLine, SceFontWritingMetrics* pWritingMetrics);

    /// <summary>Destroys a writing line.</summary>
    [LibraryImport(Lib)]
    public static partial int sceFontDestroyWritingLine(void** pWritingLine);
}
