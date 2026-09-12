// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Storage;
using System;
using System.Collections.Generic;

namespace SharpProspero.Graphics;

/// <summary>How the frame area is treated after a frame is shown, before the next one is drawn.</summary>
public enum GifDisposal
{
    /// <summary>No disposal specified; the next frame draws over this one as it stands.</summary>
    None = 0,

    /// <summary>Leave the frame in place; the next frame draws over it.</summary>
    DoNotDispose = 1,

    /// <summary>Clear the frame's area to the transparent background before the next frame.</summary>
    RestoreBackground = 2,

    /// <summary>Restore the area to what it showed before this frame, before the next frame.</summary>
    RestorePrevious = 3,
}

/// <summary>
/// One frame to encode into an animated GIF: the pixels to show, how long to show them, and how the
/// frame is cleared before the next one. The pixels are the display's B8-G8-R8-A8 format; a fully
/// transparent pixel (zero alpha) is written through the GIF's transparent colour, and every other
/// pixel is treated as opaque.
/// </summary>
/// <remarks>Describes a source frame for <see cref="GifEncoder.EncodeAnimation"/>.</remarks>
/// <param name="surface">The pixels to encode, in the display's B8-G8-R8-A8 format.</param>
/// <param name="delayMilliseconds">
/// How long to show the frame before the next one. GIF stores the delay in hundredths of a second, so
/// the value is rounded to the nearest ten milliseconds.
/// </param>
/// <param name="disposal">How the frame's area is cleared before the next frame is drawn.</param>
public readonly struct GifFrameSource(Surface surface, int delayMilliseconds = 100, GifDisposal disposal = GifDisposal.None)
{
    /// <summary>The pixels to encode, in the display's B8-G8-R8-A8 format.</summary>
    public Surface Surface { get; } = surface;

    /// <summary>How long to show the frame before the next one, in milliseconds.</summary>
    public int DelayMilliseconds { get; } = delayMilliseconds < 0 ? 0 : delayMilliseconds;

    /// <summary>How the frame's area is cleared before the next frame is drawn.</summary>
    public GifDisposal Disposal { get; } = disposal;
}

/// <summary>
/// Encodes a drawing surface to GIF bytes — a single still image or an animation — with no system module.
/// The pixels are reduced to a colour table of at most 256 entries (used exactly when the image already
/// has 256 or fewer colours, or picked by median-cut quantization when it has more), and the image data
/// is LZW compressed. An animation shares one global colour table across its frames and repeats for the
/// requested loop count. The surface is the display's B8-G8-R8-A8 format, so a framebuffer or an
/// off-screen buffer encodes directly.
/// </summary>
/// <example>
/// <code>
/// // A still image.
/// GifEncoder.Save(surface, "/data/capture.gif");
///
/// // A two-frame loop.
/// GifEncoder.SaveAnimation(
///     [new GifFrameSource(first, 100), new GifFrameSource(second, 100)],
///     "/data/spinner.gif", loopCount: 0);
/// </code>
/// </example>
public static unsafe class GifEncoder
{
    // GIF stores the screen and each image with 16-bit dimensions, and a decoder holds the whole image in
    // memory, so the pixel count is kept within the same realistic bound the decoder enforces.
    private const long MaxPixels = 16L * 1024 * 1024;

    /// <summary>
    /// Whether an image of <paramref name="width"/> by <paramref name="height"/> can be written as a GIF.
    /// The dimensions must be positive, each fit the 16-bit fields a GIF stores them in, and the pixel
    /// count stay within the bound a decoder is expected to hold in memory.
    /// </summary>
    /// <param name="width">The image width in pixels.</param>
    /// <param name="height">The image height in pixels.</param>
    /// <returns><see langword="true"/> when a GIF of this size can be written.</returns>
    public static bool CanEncode(int width, int height)
        => width > 0 && height > 0 && width <= 0xFFFF && height <= 0xFFFF && (long)width * height <= MaxPixels;

    /// <summary>
    /// Encodes <paramref name="surface"/> to the bytes of a single-frame GIF file. Fully transparent
    /// pixels (zero alpha) are written through the GIF's transparent colour; every other pixel is opaque.
    /// </summary>
    /// <param name="surface">The pixels to encode, in the display's B8-G8-R8-A8 format.</param>
    /// <exception cref="ArgumentException">The surface has no pixels.</exception>
    /// <exception cref="ProsperoException">The image size is invalid or too large.</exception>
    public static byte[] Encode(Surface surface)
    {
        if (surface.Width <= 0 || surface.Height <= 0)
            throw new ArgumentException("The surface has no pixels to encode.", nameof(surface));
        return EncodeCore([new GifFrameSource(surface, 0, GifDisposal.None)], loopCount: 0, animated: false);
    }

    /// <summary>
    /// Encodes <paramref name="surface"/> and writes it to the file at <paramref name="path"/>, for
    /// saving a picture (for example <c>/data/capture.gif</c>).
    /// </summary>
    /// <exception cref="ProsperoException">Encoding or writing the file failed.</exception>
    public static void Save(Surface surface, string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        FileSystem.WriteAllBytes(path, Encode(surface));
    }

    /// <summary>
    /// Encodes a sequence of frames into the bytes of an animated GIF. Every frame must have the same
    /// size, which becomes the animation's size. The frames share one colour table built from all of
    /// their pixels, each frame carries its own delay and disposal, and the animation repeats
    /// <paramref name="loopCount"/> times.
    /// </summary>
    /// <param name="frames">The frames in order; at least one is required.</param>
    /// <param name="loopCount">How many times the animation repeats, or 0 to repeat forever.</param>
    /// <exception cref="ArgumentException">No frames were given, or the frames differ in size.</exception>
    /// <exception cref="ProsperoException">The image size is invalid or too large.</exception>
    public static byte[] EncodeAnimation(IReadOnlyList<GifFrameSource> frames, int loopCount = 0)
    {
        ArgumentNullException.ThrowIfNull(frames);
        if (frames.Count == 0)
            throw new ArgumentException("An animation needs at least one frame.", nameof(frames));
        return EncodeCore(frames, loopCount, animated: frames.Count > 1);
    }

    /// <summary>
    /// Encodes a sequence of frames and writes the animated GIF to the file at <paramref name="path"/>.
    /// </summary>
    /// <exception cref="ProsperoException">Encoding or writing the file failed.</exception>
    public static void SaveAnimation(IReadOnlyList<GifFrameSource> frames, string path, int loopCount = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        FileSystem.WriteAllBytes(path, EncodeAnimation(frames, loopCount));
    }

    private static byte[] EncodeCore(IReadOnlyList<GifFrameSource> frames, int loopCount, bool animated)
    {
        Surface first = frames[0].Surface;
        int width = first.Width;
        int height = first.Height;
        ValidateDimensions(width, height);
        for (int i = 1; i < frames.Count; i++)
        {
            Surface s = frames[i].Surface;
            if (s.Width != width || s.Height != height)
                throw new ArgumentException("Every frame of an animation must have the same size.", nameof(frames));
        }

        GlobalPalette palette = BuildGlobalPalette(frames);
        int minCodeSize = Math.Max(2, palette.TableBits);

        var output = new List<byte>();

        // Header and logical screen descriptor.
        output.AddRange("GIF89a"u8.ToArray());
        WriteU16(output, width);
        WriteU16(output, height);
        // Global colour table present; the colour-resolution and table-size fields both carry the table's
        // bit depth, so the table holds 2^tableBits entries.
        output.Add((byte)(0x80 | ((palette.TableBits - 1) << 4) | (palette.TableBits - 1)));
        output.Add(0x00); // background colour index
        output.Add(0x00); // pixel aspect ratio
        output.AddRange(palette.ColorTable);

        // Loop-count application extension, only for a genuine multi-frame animation.
        if (animated)
        {
            int loop = loopCount < 0 ? 0 : Math.Min(loopCount, 0xFFFF);
            output.Add(0x21);
            output.Add(0xFF);
            output.Add(0x0B);
            output.AddRange("NETSCAPE2.0"u8.ToArray());
            output.Add(0x03);
            output.Add(0x01);
            WriteU16(output, loop);
            output.Add(0x00);
        }

        foreach (GifFrameSource frame in frames)
        {
            // Graphic-control extension: delay, disposal and the transparent colour. It is written when
            // any of those matter, and always for an animation so each frame carries its own delay.
            int centiseconds = Math.Min((frame.DelayMilliseconds + 5) / 10, 0xFFFF);
            int disposal = (int)frame.Disposal & 0x07;
            bool hasTransparency = palette.TransparentIndex >= 0;
            if (animated || hasTransparency || centiseconds > 0 || disposal != 0)
            {
                output.Add(0x21);
                output.Add(0xF9);
                output.Add(0x04);
                output.Add((byte)((disposal << 2) | (hasTransparency ? 0x01 : 0x00)));
                WriteU16(output, centiseconds);
                output.Add((byte)(hasTransparency ? palette.TransparentIndex : 0));
                output.Add(0x00);
            }

            // Image descriptor: the whole screen, drawn from the global colour table, not interlaced.
            output.Add(0x2C);
            WriteU16(output, 0);
            WriteU16(output, 0);
            WriteU16(output, width);
            WriteU16(output, height);
            output.Add(0x00);

            byte[] indices = MapFrame(frame.Surface, palette);
            output.Add((byte)minCodeSize);
            byte[] compressed = LzwEncode(indices, minCodeSize);
            for (int offset = 0; offset < compressed.Length; offset += 255)
            {
                int size = Math.Min(255, compressed.Length - offset);
                output.Add((byte)size);
                for (int i = 0; i < size; i++)
                    output.Add(compressed[offset + i]);
            }

            output.Add(0x00); // block terminator
        }

        output.Add(0x3B); // trailer
        return [.. output];
    }

    private static void ValidateDimensions(int width, int height)
    {
        if (!CanEncode(width, height))
            throw new ProsperoException("The GIF image size is invalid or too large.", -1);
    }

    // Builds one colour table for every frame: an exact table when the frames use at most the available
    // number of colours, and a median-cut selection otherwise. Fully transparent pixels claim a reserved
    // table entry so the animation can show through them.
    private static GlobalPalette BuildGlobalPalette(IReadOnlyList<GifFrameSource> frames)
    {
        var histogram = new Dictionary<uint, int>();
        bool hasTransparency = false;
        foreach (GifFrameSource frame in frames)
        {
            Surface s = frame.Surface;
            for (int y = 0; y < s.Height; y++)
            {
                uint* row = s.Pixels + (long)y * s.Stride;
                for (int x = 0; x < s.Width; x++)
                {
                    uint pixel = row[x];
                    if ((pixel >> 24) == 0)
                    {
                        hasTransparency = true;
                        continue;
                    }

                    uint rgb = pixel & 0x00FFFFFFu;
                    histogram.TryGetValue(rgb, out int count);
                    histogram[rgb] = count + 1;
                }
            }
        }

        int maxColors = hasTransparency ? 255 : 256;
        var indexOf = new Dictionary<uint, int>(histogram.Count);
        uint[] colors;
        if (histogram.Count <= maxColors)
        {
            colors = new uint[histogram.Count];
            int i = 0;
            foreach (uint rgb in histogram.Keys)
                colors[i++] = rgb;
            Array.Sort(colors); // a stable, repeatable table order
            for (i = 0; i < colors.Length; i++)
                indexOf[colors[i]] = i;
        }
        else
        {
            colors = MedianCut(histogram, maxColors);
            foreach (uint rgb in histogram.Keys)
                indexOf[rgb] = Nearest(rgb, colors);
        }

        int transparentIndex = hasTransparency ? colors.Length : -1;
        int used = Math.Max(1, colors.Length + (hasTransparency ? 1 : 0));
        int tableBits = 1;
        while ((1 << tableBits) < used)
            tableBits++;

        byte[] table = new byte[(1 << tableBits) * 3];
        for (int i = 0; i < colors.Length; i++)
        {
            uint rgb = colors[i];
            table[i * 3] = (byte)(rgb >> 16);     // R
            table[i * 3 + 1] = (byte)(rgb >> 8);  // G
            table[i * 3 + 2] = (byte)rgb;         // B
        }
        // The transparent entry and any padding stay black; a decoder never paints through them.

        return new GlobalPalette(table, tableBits, transparentIndex, indexOf);
    }

    // Turns one frame's pixels into colour-table indices. A fully transparent pixel takes the reserved
    // transparent index; every other pixel maps through the table built for all frames.
    private static byte[] MapFrame(Surface surface, GlobalPalette palette)
    {
        int width = surface.Width;
        int height = surface.Height;
        byte[] indices = new byte[width * height];
        int k = 0;
        for (int y = 0; y < height; y++)
        {
            uint* row = surface.Pixels + (long)y * surface.Stride;
            for (int x = 0; x < width; x++)
            {
                uint pixel = row[x];
                indices[k++] = (pixel >> 24) == 0
                    ? (byte)palette.TransparentIndex
                    : (byte)palette.IndexOf[pixel & 0x00FFFFFFu];
            }
        }

        return indices;
    }

    // Median-cut colour quantization: repeatedly split the box holding the most colours along its widest
    // channel at the median, then take each box's pixel-weighted average as a table colour.
    private static uint[] MedianCut(Dictionary<uint, int> histogram, int maxColors)
    {
        int n = histogram.Count;
        uint[] colors = new uint[n];
        int[] weights = new int[n];
        int k = 0;
        foreach (KeyValuePair<uint, int> entry in histogram)
        {
            colors[k] = entry.Key;
            weights[k] = entry.Value;
            k++;
        }

        int[] order = new int[n];
        for (int i = 0; i < n; i++)
            order[i] = i;

        var boxes = new List<(int Start, int End)> { (0, n) };
        while (boxes.Count < maxColors)
        {
            int chosen = -1, chosenSize = 1;
            for (int i = 0; i < boxes.Count; i++)
            {
                int size = boxes[i].End - boxes[i].Start;
                if (size > chosenSize)
                {
                    chosenSize = size;
                    chosen = i;
                }
            }

            if (chosen < 0)
                break; // every box holds a single colour

            (int start, int end) = boxes[chosen];
            int rMin = 255, rMax = 0, gMin = 255, gMax = 0, bMin = 255, bMax = 0;
            for (int i = start; i < end; i++)
            {
                uint c = colors[order[i]];
                int r = (int)((c >> 16) & 0xFF), g = (int)((c >> 8) & 0xFF), b = (int)(c & 0xFF);
                if (r < rMin) rMin = r;
                if (r > rMax) rMax = r;
                if (g < gMin) gMin = g;
                if (g > gMax) gMax = g;
                if (b < bMin) bMin = b;
                if (b > bMax) bMax = b;
            }

            int rRange = rMax - rMin, gRange = gMax - gMin, bRange = bMax - bMin;
            int channel = 0;
            if (gRange >= rRange && gRange >= bRange)
                channel = 1;
            else if (bRange >= rRange && bRange >= gRange)
                channel = 2;

            Array.Sort(order, start, end - start,
                Comparer<int>.Create((x, y) => Component(colors[x], channel) - Component(colors[y], channel)));

            int mid = start + (end - start) / 2;
            boxes[chosen] = (start, mid);
            boxes.Add((mid, end));
        }

        uint[] palette = new uint[boxes.Count];
        for (int i = 0; i < boxes.Count; i++)
        {
            (int start, int end) = boxes[i];
            long sumR = 0, sumG = 0, sumB = 0, sumW = 0;
            for (int j = start; j < end; j++)
            {
                uint c = colors[order[j]];
                int w = weights[order[j]];
                sumR += (long)((c >> 16) & 0xFF) * w;
                sumG += (long)((c >> 8) & 0xFF) * w;
                sumB += (long)(c & 0xFF) * w;
                sumW += w;
            }

            if (sumW == 0)
                sumW = 1;
            byte r = (byte)((sumR + sumW / 2) / sumW);
            byte g = (byte)((sumG + sumW / 2) / sumW);
            byte b = (byte)((sumB + sumW / 2) / sumW);
            palette[i] = ((uint)r << 16) | ((uint)g << 8) | b;
        }

        return palette;
    }

    private static int Component(uint rgb, int channel) => channel switch
    {
        0 => (int)((rgb >> 16) & 0xFF),
        1 => (int)((rgb >> 8) & 0xFF),
        _ => (int)(rgb & 0xFF),
    };

    private static int Nearest(uint rgb, uint[] palette)
    {
        int r = (int)((rgb >> 16) & 0xFF), g = (int)((rgb >> 8) & 0xFF), b = (int)(rgb & 0xFF);
        int best = 0, bestDistance = int.MaxValue;
        for (int i = 0; i < palette.Length; i++)
        {
            uint c = palette[i];
            int dr = r - (int)((c >> 16) & 0xFF);
            int dg = g - (int)((c >> 8) & 0xFF);
            int db = b - (int)(c & 0xFF);
            int distance = dr * dr + dg * dg + db * db;
            if (distance < bestDistance)
            {
                bestDistance = distance;
                best = i;
                if (distance == 0)
                    break;
            }
        }

        return best;
    }

    // LZW compression for the GIF image data: a leading clear code, variable-width codes that grow as the
    // dictionary fills, and a trailing end code. The code width grows one entry after the value it names
    // is added, matching the point a compliant decoder widens its own reads; once the dictionary is full
    // it is kept as it stands, which a decoder mirrors by freezing at the same point.
    private static byte[] LzwEncode(byte[] indices, int minCodeSize)
    {
        int clearCode = 1 << minCodeSize;
        int endCode = clearCode + 1;
        int codeSize = minCodeSize + 1;
        int available = clearCode + 2;
        var table = new Dictionary<int, int>();
        var writer = new BitWriter();

        writer.Write(clearCode, codeSize);

        if (indices.Length == 0)
        {
            writer.Write(endCode, codeSize);
            return writer.Finish();
        }

        int current = indices[0];
        for (int i = 1; i < indices.Length; i++)
        {
            int next = indices[i];
            int key = (current << 8) | next;
            if (table.TryGetValue(key, out int combined))
            {
                current = combined;
            }
            else
            {
                writer.Write(current, codeSize);
                if (available < 4096)
                {
                    table[key] = available;
                    available++;
                    if (available == (1 << codeSize) + 1 && codeSize < 12)
                        codeSize++;
                }

                current = next;
            }
        }

        writer.Write(current, codeSize);
        writer.Write(endCode, codeSize);
        return writer.Finish();
    }

    private static void WriteU16(List<byte> output, int value)
    {
        output.Add((byte)(value & 0xFF));
        output.Add((byte)((value >> 8) & 0xFF));
    }

    private readonly struct GlobalPalette(byte[] colorTable, int tableBits, int transparentIndex, Dictionary<uint, int> indexOf)
    {
        public byte[] ColorTable { get; } = colorTable;
        public int TableBits { get; } = tableBits;
        public int TransparentIndex { get; } = transparentIndex;
        public Dictionary<uint, int> IndexOf { get; } = indexOf;
    }

    // Packs codes least-significant-bit first into a byte stream, the bit order GIF's LZW data uses.
    private sealed class BitWriter
    {
        private readonly List<byte> _bytes = [];
        private int _buffer;
        private int _count;

        public void Write(int code, int size)
        {
            _buffer |= code << _count;
            _count += size;
            while (_count >= 8)
            {
                _bytes.Add((byte)(_buffer & 0xFF));
                _buffer >>= 8;
                _count -= 8;
            }
        }

        public byte[] Finish()
        {
            if (_count > 0)
                _bytes.Add((byte)(_buffer & 0xFF));
            return [.. _bytes];
        }
    }
}
