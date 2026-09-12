// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Font;

/// <summary>How a font's lines stack when written top to bottom in vertical columns.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontVerticalLayout
{
    /// <summary>How far in from the leading edge of a column its baseline sits, in pixels.</summary>
    public float BaseLineX;

    /// <summary>The distance from one column to the next, in pixels.</summary>
    public float LineWidth;

    /// <summary>How much wider a column becomes once the font's effects are applied.</summary>
    public float EffectWidth;
}

/// <summary>
/// A reusable set of scale, resolution and effect settings that a glyph render reads from instead of
/// the font handle's own state. The block is opaque; it is prepared through the style-frame calls and
/// handed to <see cref="SceFont.sceFontRenderSurfaceSetStyleFrame"/> or a glyph render.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 96)]
public unsafe struct SceFontStyleFrame
{
    private fixed uint _systemUse[24];
}

/// <summary>How a glyph object is generated: which forms of outline and metrics it should carry.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontGenerateGlyphDetail
{
    /// <summary>The detail identifier. 0x0FD3.</summary>
    public ushort DetailId;

    /// <summary>Reserved. Zero.</summary>
    public ushort Reserved;

    /// <summary>Which optional forms to build (packed flags).</summary>
    public ushort FormOptions;

    /// <summary>Whether the glyph carries a private form or a public outline.</summary>
    public byte GlyphForm;

    /// <summary>Which metrics form the glyph carries.</summary>
    public byte MetricsForm;

    /// <summary>The memory the glyph is generated into, or null to use the renderer's.</summary>
    public SceFontMemory* Memory;

    /// <summary>Reserved. Null.</summary>
    public void* Reserved2;

    /// <summary>Reserved. Null.</summary>
    public void* Reserved1;
}

/// <summary>One point of a glyph outline, in the font's design units scaled to the current size.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontOutlinePoint
{
    /// <summary>Horizontal position.</summary>
    public float X;

    /// <summary>Vertical position.</summary>
    public float Y;
}

/// <summary>The outline of one glyph as contours of on- and off-curve points.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontGlyphOutline
{
    /// <summary>The number of closed contours.</summary>
    public short ContoursCount;

    /// <summary>The total number of points across every contour.</summary>
    public short PointsCount;

    /// <summary>Outline flags.</summary>
    public uint Flags;

    /// <summary>The point coordinates, <see cref="PointsCount"/> of them.</summary>
    public SceFontOutlinePoint* Points;

    /// <summary>One tag per point marking it on- or off-curve.</summary>
    public byte* PointTags;

    /// <summary>The index one past the last point of each contour, <see cref="ContoursCount"/> of them.</summary>
    public ushort* ContourIndexes;
}

/// <summary>A glyph's metrics with horizontal bearings and advance, but no vertical set.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontGlyphMetricsHorizontal
{
    /// <summary>Glyph width.</summary>
    public float Width;

    /// <summary>Glyph height.</summary>
    public float Height;

    /// <summary>Horizontal left bearing.</summary>
    public float HorizontalBearingX;

    /// <summary>Horizontal top bearing.</summary>
    public float HorizontalBearingY;

    /// <summary>Horizontal advance.</summary>
    public float HorizontalAdvance;
}

/// <summary>A glyph's horizontal metrics without the height, for a tighter query.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontGlyphMetricsHorizontalX
{
    /// <summary>Glyph width.</summary>
    public float Width;

    /// <summary>Horizontal left bearing.</summary>
    public float HorizontalBearingX;

    /// <summary>Horizontal advance.</summary>
    public float HorizontalAdvance;
}

/// <summary>A glyph's horizontal advance alone, for a layout pass that needs nothing else.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontGlyphMetricsHorizontalAdvance
{
    /// <summary>Horizontal advance.</summary>
    public float HorizontalAdvance;
}

/// <summary>
/// The text a shaping pass reads from. It carries the span of the source, a cursor, and the parser
/// that walks it a code at a time yielding the font and character code for each. The block is set up
/// once through <see cref="SceFont.sceFontTextSourceInit"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontTextSource
{
    /// <summary>Engine use.</summary>
    public ulong SystemUse0;

    /// <summary>The first byte of the source text.</summary>
    public void* Start;

    /// <summary>One past the last byte of the source text.</summary>
    public void* End;

    /// <summary>The current read position.</summary>
    public void* Current;

    /// <summary>The parser that reads one code from the source and reports its font and code.</summary>
    public delegate* unmanaged[Cdecl]<SceFontTextSource*, void**, SceFontTextParseResult*, int> TextParser;

    /// <summary>A caller object passed to the parser.</summary>
    public void* TextObject;

    /// <summary>The font used for a code the parser does not itself resolve to a font.</summary>
    public void* DefaultFont;

    private fixed ulong _systemUse[5];
}

/// <summary>
/// What one call to a text parser produced: a font and code, a terminate marker, or an error. The
/// engine reads only the view that matches the parser's return value.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 32)]
public unsafe struct SceFontTextParseResult
{
    /// <summary>The font a resolved code belongs to.</summary>
    [FieldOffset(0)] public void* Font;

    /// <summary>The resolved character code.</summary>
    [FieldOffset(8)] public uint Code;

    /// <summary>The code that ended the source, when the parser reports termination.</summary>
    [FieldOffset(8)] public uint TerminateCode;

    /// <summary>The error code, when the parser reports an error.</summary>
    [FieldOffset(8)] public int ErrorCode;
}

/// <summary>How a shaped string is built: its default font and an optional ordering callback.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontCreateStringDetail
{
    /// <summary>The detail identifier. 0x0FD4.</summary>
    public ushort DetailId;

    /// <summary>The detail type. 0x01.</summary>
    public byte DetailType;

    /// <summary>The detections flags. 0x01.</summary>
    public byte Detections;

    /// <summary>Optional variant and ligature ordering options.</summary>
    public uint OrdersOption;

    /// <summary>The font used when a character carries none of its own.</summary>
    public void* DefaultFont;

    /// <summary>An optional ordering callback, or null.</summary>
    public void* OrdersFunction;

    /// <summary>The ordering callback's object.</summary>
    public void* OrdersObject;
}

/// <summary>
/// One step over the character codes of a shaped string. The engine hands back a pointer to this and
/// steps it forward or back; the <see cref="Code"/> view is the one to read.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 64)]
public unsafe struct SceFontTextCodes
{
    /// <summary>The ordering token for this code.</summary>
    public void* Order;

    /// <summary>The character code.</summary>
    public uint Code;
}

/// <summary>
/// The state a writing pass keeps as it steps glyph by glyph along a shaped string. The block is
/// opaque; it is set up through <see cref="SceFont.sceFontWritingInit"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 256)]
public unsafe struct SceFontWriting
{
    private fixed ulong _systemUse[32];
}

/// <summary>One glyph's placement and metrics as a writing pass steps along a line.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontWritingStep
{
    /// <summary>The pen position where this glyph is placed.</summary>
    public float X;

    /// <summary>The pen position where this glyph is placed.</summary>
    public float Y;

    /// <summary>The pen advance after this glyph, horizontally.</summary>
    public float AdvanceX;

    /// <summary>The pen advance after this glyph, vertically.</summary>
    public float AdvanceY;

    /// <summary>The font this glyph is drawn from.</summary>
    public void* Font;

    /// <summary>Packed: bits 0-7 the character count for the step, bit 8 whether the glyph is invisible.</summary>
    public uint Profile;

    /// <summary>The glyph code to render.</summary>
    public uint GlyphCode;

    /// <summary>An additional per-glyph position offset applied on top of the pen, horizontal.</summary>
    public float PositioningX;

    /// <summary>An additional per-glyph position offset applied on top of the pen, vertical.</summary>
    public float PositioningY;

    /// <summary>The glyph's metrics at the current scale.</summary>
    public SceFontGlyphMetrics GlyphMetrics;

    /// <summary>The number of source characters this step covers.</summary>
    public readonly uint CharacterCount => Profile & 0xFFu;

    /// <summary>Whether this step's glyph is invisible and should not be drawn.</summary>
    public readonly bool InvisibleGlyph => (Profile & 0x100u) != 0;
}

/// <summary>The rectangle a writing pass's rendered content covers, relative to its origin.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontWritingExtent
{
    /// <summary>The top edge.</summary>
    public float Top;

    /// <summary>The bottom edge.</summary>
    public float Bottom;

    /// <summary>The left edge.</summary>
    public float Left;

    /// <summary>The right edge.</summary>
    public float Right;
}

/// <summary>The advance and covered rectangle a writing pass reports for a stretch of text.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontWritingMetrics
{
    /// <summary>Total horizontal advance.</summary>
    public float AdvanceX;

    /// <summary>Total vertical advance.</summary>
    public float AdvanceY;

    /// <summary>The rectangle the rendered content covers.</summary>
    public SceFontWritingExtent Extent;
}

/// <summary>The per-letter grouping a writing pass reports alongside a render step.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceFontWritingLetterStep
{
    /// <summary>The pen position for this letter.</summary>
    public float X;

    /// <summary>The pen position for this letter.</summary>
    public float Y;

    /// <summary>The horizontal advance after this letter.</summary>
    public float AdvanceX;

    /// <summary>The vertical advance after this letter.</summary>
    public float AdvanceY;

    /// <summary>The number of text characters that opened at this letter.</summary>
    public uint TextsCount;

    /// <summary>The index of the first of those text characters.</summary>
    public uint TextsIndex;

    /// <summary>The number of glyphs in this letter.</summary>
    public uint GlyphsCount;

    /// <summary>The index of the first glyph of this letter.</summary>
    public uint GlyphsIndex;

    /// <summary>The number of base components.</summary>
    public byte BaseComponentsCount;

    /// <summary>The index of the first base component.</summary>
    public byte BaseComponentsIndex;

    /// <summary>The number of base focus components.</summary>
    public byte BaseFocusCount;

    /// <summary>The index of the first base focus component.</summary>
    public byte BaseFocusIndex;

    /// <summary>Whether the letter runs against the base writing direction.</summary>
    public byte OppositeDirection;

    /// <summary>The number of characters in this letter.</summary>
    public byte CharacterTextCount;

    /// <summary>The number of base characters.</summary>
    public byte BaseTextCount;

    /// <summary>The number of mark characters.</summary>
    public byte MarkTextCount;

    /// <summary>The total number of mark characters.</summary>
    public uint MarksTextCount;

    /// <summary>The index of this letter's marks.</summary>
    public uint MarksTextNumber;

    private uint _reserved0;
    private uint _reserved1;
    private uint _reserved2;

    /// <summary>The offset of this letter within the text.</summary>
    public int TextLetterOffset;
}

/// <summary>How a composed line is prepared before order entries are written into it.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontCreateWritingLineDetail
{
    /// <summary>The detail identifier. 0x0FD5.</summary>
    public ushort DetailId;

    /// <summary>Reserved. Zero.</summary>
    public ushort Reserved0;

    /// <summary>Reserved. Zero.</summary>
    public ushort Reserved1;

    /// <summary>Reserved. Zero.</summary>
    public ushort Reserved2;

    private void* _reserved3;
    private void* _reserved4;
    private void* _reserved5;
}

/// <summary>One step over a composed line, giving each ordered run's placement and metrics.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceFontWritingLineStep
{
    /// <summary>The pen position of this run.</summary>
    public float X;

    /// <summary>The pen position of this run.</summary>
    public float Y;

    /// <summary>The horizontal advance after this run.</summary>
    public float AdvanceX;

    /// <summary>The vertical advance after this run.</summary>
    public float AdvanceY;

    /// <summary>How far justification has stretched the line so far.</summary>
    public float SpacingProgress;

    /// <summary>The order token written for this run.</summary>
    public void* WritingOrderer;

    /// <summary>A per-run position adjustment, horizontal.</summary>
    public float AdjustingX;

    /// <summary>A per-run position adjustment, vertical.</summary>
    public float AdjustingY;

    /// <summary>This run's advance and covered rectangle.</summary>
    public SceFontWritingMetrics Metrics;
}
