// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

namespace SharpProspero.Interop.Font;

/// <summary>How a font is opened: from a stream or resident in memory, and for which sources.</summary>
public static class SceFontOpenMode
{
    /// <summary>The font image is resident in memory (external fonts).</summary>
    public const uint OnMemory = 1;

    /// <summary>The font is read from a file stream.</summary>
    public const uint FileStream = 2;

    /// <summary>The font is read from a memory stream.</summary>
    public const uint MemoryStream = 3;
}

/// <summary>How a library opens fonts of a given kind, set by <see cref="SceFont.sceFontSetFontsOpenMode"/>.</summary>
public static class SceFontFontsOpenMode
{
    /// <summary>The default open mode.</summary>
    public const uint Default = 0;

    /// <summary>Skip vertical metrics.</summary>
    public const uint IgnoreVerticalMetrics = 1;

    /// <summary>Parse metrics only as they are needed.</summary>
    public const uint AsNeededParseMetrics = 2;

    /// <summary>Any font.</summary>
    public const uint TargetFontsAny = 0x00;

    /// <summary>System fonts only.</summary>
    public const uint TargetFontsSystem = 0x10;

    /// <summary>External fonts only.</summary>
    public const uint TargetFontsExternal = 0x20;

    /// <summary>File-backed fonts only.</summary>
    public const uint TargetFontsFileAccess = 0x04;

    /// <summary>Memory-backed fonts only.</summary>
    public const uint TargetFontsMemoryAccess = 0x08;
}

/// <summary>The handle attributes set with <see cref="SceFont.sceFontDefineAttribute"/>.</summary>
public static class SceFontAttribute
{
    /// <summary>An invalid attribute, reported on error.</summary>
    public const int None = 0;

    /// <summary>Render detail: adjoin glyphs.</summary>
    public const int RenderDetailAdjoin = 0x11;

    /// <summary>Render detail: do not adjoin glyphs.</summary>
    public const int RenderDetailNoAdjoin = 0x10;

    /// <summary>Vertical: exclusive forms.</summary>
    public const int VerticalExclusive = 0x21;

    /// <summary>Vertical: no exclusive forms.</summary>
    public const int VerticalNoExclusive = 0x20;

    /// <summary>Vertical: disable glyph rotation.</summary>
    public const int VerticalRotationDisable = 0x31;

    /// <summary>Vertical: enable glyph rotation.</summary>
    public const int VerticalRotationEnable = 0x30;

    /// <summary>Write vertically.</summary>
    public const int WritingVertical = 0x41;

    /// <summary>Write horizontally.</summary>
    public const int WritingHorizontal = 0x40;
}

/// <summary>Script selectors for <see cref="SceFont.sceFontSetScriptLanguage"/>.</summary>
public static class SceFontScript
{
    /// <summary>The font's default script.</summary>
    public const int Default = 0x0000;

    /// <summary>Latin.</summary>
    public const int Latin = 0x0100;

    /// <summary>Arabic.</summary>
    public const int Arabic = 0x0600;

    /// <summary>CJK.</summary>
    public const int Cjk = 0x3000;
}

/// <summary>Language selectors for <see cref="SceFont.sceFontSetScriptLanguage"/>.</summary>
public static class SceFontLanguage
{
    /// <summary>The default language.</summary>
    public const int Default = 0x0000;

    /// <summary>Latin default.</summary>
    public const int LatinDefault = 0x0100;

    /// <summary>Dutch.</summary>
    public const int LatinNld = 0x0101;

    /// <summary>Turkish.</summary>
    public const int LatinTrk = 0x0102;

    /// <summary>Romanian.</summary>
    public const int LatinRom = 0x0103;

    /// <summary>Moldovan.</summary>
    public const int LatinMol = 0x0104;

    /// <summary>Afrikaans.</summary>
    public const int LatinAfk = 0x0105;

    /// <summary>Arabic default.</summary>
    public const int ArabicDefault = 0x0600;

    /// <summary>Arabic.</summary>
    public const int ArabicAra = 0x0601;

    /// <summary>Persian.</summary>
    public const int ArabicFar = 0x0602;

    /// <summary>CJK default.</summary>
    public const int CjkDefault = 0x3000;

    /// <summary>Japanese.</summary>
    public const int CjkJan = 0x3011;

    /// <summary>Simplified Chinese.</summary>
    public const int CjkZhs = 0x3021;

    /// <summary>Traditional Chinese.</summary>
    public const int CjkZht = 0x3022;

    /// <summary>Traditional Chinese (Hong Kong).</summary>
    public const int CjkZhh = 0x3023;

    /// <summary>Korean.</summary>
    public const int CjkKor = 0x3041;
}

/// <summary>Which optional forms a generated glyph should carry.</summary>
public static class SceFontGlyphForm
{
    /// <summary>Build no extra forms.</summary>
    public const ushort OptionNone = 0x0000;

    /// <summary>Build the glyph without allocating from the memory block.</summary>
    public const ushort OptionWithoutMemory = 0x0001;

    /// <summary>Build a packed private form.</summary>
    public const ushort OptionPrivatePacked = 0x0010;

    /// <summary>A private, engine-specific form.</summary>
    public const byte FormPrivate = 0x00;

    /// <summary>A public outline form.</summary>
    public const byte FormOutline = 0x01;

    /// <summary>Private metrics.</summary>
    public const byte MetricsFormPrivate = 0x00;

    /// <summary>Full metrics.</summary>
    public const byte MetricsFormNormal = 0x01;

    /// <summary>Horizontal metrics.</summary>
    public const byte MetricsFormHorizontal = 0x02;

    /// <summary>Horizontal metrics without height.</summary>
    public const byte MetricsFormHorizontalX = 0x03;

    /// <summary>Horizontal advance only.</summary>
    public const byte MetricsFormHorizontalAdvance = 0x04;
}

/// <summary>How a run of text is written: its direction, for the shaping and writing calls.</summary>
public static class SceFontWritingForm
{
    /// <summary>An invalid value.</summary>
    public const int None = 0x00;

    /// <summary>Horizontal, direction taken from the text.</summary>
    public const int Horizontal = 0x10;

    /// <summary>Horizontal, forced right to left.</summary>
    public const int HorizontalRtl = 0x11;

    /// <summary>Horizontal, forced left to right.</summary>
    public const int HorizontalLtr = 0x12;
}

/// <summary>The mask that hides invisible characters in a writing pass.</summary>
public static class SceFontWritingMask
{
    /// <summary>Show every character.</summary>
    public const int None = 0;

    /// <summary>Hide format characters.</summary>
    public const int FormatCharacters = 1;
}

/// <summary>The syllable states a character reports in a complex script.</summary>
public static class SceFontSyllableString
{
    /// <summary>Not part of a syllable cluster.</summary>
    public const int NonDetection = 0;

    /// <summary>Starts a syllable cluster.</summary>
    public const int Starting = 1;

    /// <summary>Follows within a syllable cluster.</summary>
    public const int Following = 2;

    /// <summary>Depends on the cluster.</summary>
    public const int Depending = 3;

    /// <summary>Connects the cluster.</summary>
    public const int Connecting = 4;
}

/// <summary>The renderer outline-buffer growth policy.</summary>
public static class SceFontBufferPolicy
{
    /// <summary>Keep a temporary buffer in addition to the resident one.</summary>
    public const ulong PlusTemporary = 1UL << 24;

    /// <summary>Grow the buffer as needed.</summary>
    public const ulong Expand = 2UL << 24;
}

/// <summary>
/// The built-in system font sets an application can open with
/// <see cref="SceFont.sceFontOpenFontSet"/> once <see cref="SceFont.sceFontSupportSystemFonts"/> is on.
/// Each value selects a family, character coverage and weight; the names read family, coverage then
/// weight. These need no font file shipped with the application.
/// </summary>
public static class SceFontSet
{
    /// <summary>Standard European, light.</summary>
    public const uint StdEuropeanW1GLight = 0x18070043;

    /// <summary>Standard European, light italic.</summary>
    public const uint StdEuropeanW1GLightItalic = 0x18170043;

    /// <summary>Standard European, regular.</summary>
    public const uint StdEuropeanW1G = 0x18070044;

    /// <summary>Standard European, italic.</summary>
    public const uint StdEuropeanW1GItalic = 0x18170044;

    /// <summary>Standard European, medium.</summary>
    public const uint StdEuropeanW1GMedium = 0x18070045;

    /// <summary>Standard European, medium italic.</summary>
    public const uint StdEuropeanW1GMediumItalic = 0x18170045;

    /// <summary>Standard European, bold.</summary>
    public const uint StdEuropeanW1GBold = 0x18070047;

    /// <summary>Standard European, bold italic.</summary>
    public const uint StdEuropeanW1GBoldItalic = 0x18170047;

    /// <summary>Standard European with Japanese coverage.</summary>
    public const uint StdEuropeanJpW1G = 0x18070444;

    /// <summary>Standard European with Japanese coverage, bold.</summary>
    public const uint StdEuropeanJpW1GBold = 0x18070447;

    /// <summary>Fixed-pitch European.</summary>
    public const uint TypewriterEuropeanW1G = 0x18370044;

    /// <summary>Fixed-pitch European, bold.</summary>
    public const uint TypewriterEuropeanW1GBold = 0x18370047;

    /// <summary>Standard European with Arabic coverage.</summary>
    public const uint StdEuropeanArW1G = 0x180700C4;

    /// <summary>Standard European with Arabic coverage, bold.</summary>
    public const uint StdEuropeanArW1GBold = 0x180700C7;

    /// <summary>Standard Vietnamese.</summary>
    public const uint StdVietnameseW1GVi = 0x18070054;

    /// <summary>Standard Vietnamese, bold.</summary>
    public const uint StdVietnameseW1GViBold = 0x18070057;

    /// <summary>Standard Thai.</summary>
    public const uint StdThaiW1GVi = 0x18071054;

    /// <summary>Standard Thai, bold.</summary>
    public const uint StdThaiW1GViBold = 0x18071057;

    /// <summary>Standard Japanese.</summary>
    public const uint StdJapaneseJpW1G = 0x18080444;

    /// <summary>Standard Japanese, bold.</summary>
    public const uint StdJapaneseJpW1GBold = 0x18080447;

    /// <summary>Standard Simplified Chinese.</summary>
    public const uint StdSChineseGbW1G = 0x180C8044;

    /// <summary>Standard Simplified Chinese, Arabic coverage.</summary>
    public const uint StdSChineseGbArW1G = 0x180C80C4;

    /// <summary>Full-coverage European (Japanese, CJK, Thai, Arabic).</summary>
    public const uint StdEuropeanJpCjkThArW1GVi = 0x1807B4D4;

    /// <summary>Full-coverage Asian (Japanese, CJK, Thai, Arabic).</summary>
    public const uint StdAsianJpCjkThArW1GVi = 0x1808B4D4;
}
