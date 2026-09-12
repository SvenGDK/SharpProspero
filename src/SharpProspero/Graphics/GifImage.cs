// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// One fully-composed frame of a decoded GIF: its pixels and how long to show it. Draw its
/// <see cref="AsSurface"/> like any other surface. The pixels are already composited with the frames
/// before it, so an animation is just the frames drawn in order for their delays.
/// </summary>
public sealed unsafe class GifFrame : IDisposable
{
    private void* _pixels;

    internal GifFrame(void* pixels, int width, int height, int delayMilliseconds)
    {
        _pixels = pixels;
        Width = width;
        Height = height;
        DelayMilliseconds = delayMilliseconds;
    }

    /// <summary>The frame width in pixels (the GIF's logical screen width).</summary>
    public int Width { get; }

    /// <summary>The frame height in pixels (the GIF's logical screen height).</summary>
    public int Height { get; }

    /// <summary>How long to show this frame before the next, in milliseconds.</summary>
    public int DelayMilliseconds { get; }

    /// <summary>A surface over the frame's pixels. Valid until the owning <see cref="GifImage"/> is disposed.</summary>
    public Surface AsSurface() => new((uint*)_pixels, Width, Height);

    /// <summary>Releases the frame's pixels.</summary>
    public void Dispose()
    {
        if (_pixels != null)
        {
            NativeMemory.Free(_pixels);
            _pixels = null;
        }

        GC.SuppressFinalize(this);
    }

    ~GifFrame() => Dispose();
}

/// <summary>
/// Decodes a GIF image — static or animated — into fully-composed frames, with no system module. It reads
/// the common forms (GIF87a and GIF89a, global and local colour tables, interlacing, transparency, and the
/// frame-disposal methods), so an animated GIF comes back as a list of ready-to-draw frames. Decode once,
/// draw the frames, and dispose it to release their pixels.
/// </summary>
/// <example>
/// <code>
/// using GifImage gif = GifImage.Decode(FileSystem.ReadAllBytes("/app0/spinner.gif"));
/// GifFrame frame = gif.Frames[index % gif.Frames.Count];
/// surface.BlitBlended(frame.AsSurface(), x, y);
/// </code>
/// </example>
public sealed unsafe class GifImage : IDisposable
{
    private GifFrame[] _frames;

    private GifImage(int width, int height, int loopCount, GifFrame[] frames)
    {
        Width = width;
        Height = height;
        LoopCount = loopCount;
        _frames = frames;
    }

    /// <summary>The logical screen width in pixels.</summary>
    public int Width { get; }

    /// <summary>The logical screen height in pixels.</summary>
    public int Height { get; }

    /// <summary>How many times the animation repeats, or 0 for forever. One for a still image.</summary>
    public int LoopCount { get; }

    /// <summary>The decoded frames in order.</summary>
    public IReadOnlyList<GifFrame> Frames => _frames;

    /// <summary>The first (or only) frame, for a still image.</summary>
    public GifFrame First => _frames[0];

    /// <summary>Decodes GIF data into its frames.</summary>
    /// <exception cref="ProsperoException">The data is not a supported GIF.</exception>
    public static GifImage Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length < 13 ||
            data[0] != 'G' || data[1] != 'I' || data[2] != 'F' || data[3] != '8' ||
            (data[4] != '7' && data[4] != '9') || data[5] != 'a')
        {
            throw new ProsperoException("The data is not a GIF.", -1);
        }

        int width = data[6] | (data[7] << 8);
        int height = data[8] | (data[9] << 8);
        // Cap the screen at a realistic size so a tiny header cannot force a multi-gigabyte allocation.
        if (width <= 0 || height <= 0 || (long)width * height > 16L * 1024 * 1024)
            throw new ProsperoException("The GIF screen size is invalid or too large.", -1);

        byte packed = data[10];
        int position = 13;
        uint[] globalTable = (packed & 0x80) != 0
            ? ReadColorTable(data, ref position, 2 << (packed & 0x07))
            : [];

        var frames = new List<GifFrame>();
        int loopCount = 1;
        int canvasSize = width * height;
        uint[] canvas = new uint[canvasSize];   // transparent (0) background
        uint[] previous = new uint[canvasSize];

        // Graphic-control state that applies to the next image.
        int delay = 0;
        int transparentIndex = -1;
        int disposal = 0;

        try
        {
            while (position < data.Length)
            {
                byte block = data[position++];
                if (block == 0x3B) // trailer
                    break;

                if (block == 0x21) // extension
                {
                    byte label = position < data.Length ? data[position++] : (byte)0;
                    if (label == 0xF9) // graphic control
                    {
                        // block size (4), packed, delay (2), transparent index, terminator
                        if (position + 6 > data.Length)
                            break;
                        byte flags = data[position + 1];
                        disposal = (flags >> 2) & 0x07;
                        delay = (data[position + 2] | (data[position + 3] << 8)) * 10; // 1/100 s -> ms
                        transparentIndex = (flags & 0x01) != 0 ? data[position + 4] : -1;
                        position += 6;
                    }
                    else if (label == 0xFF) // application (NETSCAPE loop count)
                    {
                        int loop = ReadLoopCount(data, ref position);
                        if (loop >= 0)
                            loopCount = loop;
                    }
                    else
                    {
                        SkipSubBlocks(data, ref position);
                    }

                    continue;
                }

                if (block != 0x2C) // anything but an image descriptor is unexpected; stop cleanly
                    break;

                if (frames.Count >= 4096) // bound the frame count for an untrusted, retained-frame decode
                    throw new ProsperoException("The GIF has too many frames.", -1);

                DecodeFrame(data, ref position, globalTable, canvas, previous, width, height,
                    transparentIndex, disposal, delay, frames, out disposal);

                // Reset per-image graphic-control state.
                delay = 0;
                transparentIndex = -1;
            }
        }
        catch
        {
            foreach (GifFrame frame in frames)
                frame.Dispose();
            throw;
        }

        if (frames.Count == 0)
            throw new ProsperoException("The GIF has no frames.", -1);

        return new GifImage(width, height, loopCount, [.. frames]);
    }

    /// <summary>Releases every frame's pixels.</summary>
    public void Dispose()
    {
        foreach (GifFrame frame in _frames)
            frame.Dispose();
        _frames = [];
        GC.SuppressFinalize(this);
    }

    ~GifImage() => Dispose();

    private static void DecodeFrame(
        ReadOnlySpan<byte> data, ref int position, uint[] globalTable, uint[] canvas, uint[] previous,
        int screenWidth, int screenHeight, int transparentIndex, int disposal, int delay,
        List<GifFrame> frames, out int nextDisposal)
    {
        if (position + 9 > data.Length)
            throw new ProsperoException("The GIF image descriptor is truncated.", -1);

        int left = data[position] | (data[position + 1] << 8);
        int top = data[position + 2] | (data[position + 3] << 8);
        int frameWidth = data[position + 4] | (data[position + 5] << 8);
        int frameHeight = data[position + 6] | (data[position + 7] << 8);
        byte packed = data[position + 8];
        position += 9;

        bool interlaced = (packed & 0x40) != 0;
        uint[] table = (packed & 0x80) != 0
            ? ReadColorTable(data, ref position, 2 << (packed & 0x07))
            : globalTable;
        if (table.Length == 0)
            throw new ProsperoException("The GIF frame has no colour table.", -1);

        if (left < 0 || top < 0 || frameWidth < 0 || frameHeight < 0 ||
            left + frameWidth > screenWidth || top + frameHeight > screenHeight)
        {
            throw new ProsperoException("The GIF frame lies outside the screen.", -1);
        }

        if (position >= data.Length)
            throw new ProsperoException("The GIF image data is truncated.", -1);
        int minCodeSize = data[position++];
        byte[] compressed = GatherSubBlocks(data, ref position);
        byte[] indices = new byte[frameWidth * frameHeight];
        DecodeLzw(compressed, minCodeSize, indices);

        // Save the canvas in case this frame asks to restore to it afterward.
        canvas.CopyTo(previous, 0);

        // For an interlaced frame the rows arrive in four passes rather than top to bottom; map each row
        // in decode order to its row in the frame once, so the paint loop stays constant-time per row.
        int[]? interlaceRows = interlaced ? BuildInterlaceSchedule(frameHeight) : null;

        // Paint the frame's opaque pixels onto the canvas, honouring interlacing and transparency.
        for (int row = 0; row < frameHeight; row++)
        {
            int sourceRow = interlaced ? interlaceRows![row] : row;
            int canvasBase = ((top + sourceRow) * screenWidth) + left;
            int indexBase = row * frameWidth;
            for (int column = 0; column < frameWidth; column++)
            {
                byte index = indices[indexBase + column];
                if (index == transparentIndex)
                    continue;
                canvas[canvasBase + column] = index < table.Length ? table[index] : 0xFF000000u;
            }
        }

        // Snapshot the composed canvas as this frame's pixels.
        int canvasSize = screenWidth * screenHeight;
        void* pixels = NativeMemory.Alloc((nuint)canvasSize * sizeof(uint));
        var destination = new Span<uint>(pixels, canvasSize);
        canvas.AsSpan().CopyTo(destination);
        frames.Add(new GifFrame(pixels, screenWidth, screenHeight, delay));

        // Apply this frame's disposal to prepare the canvas for the next one.
        if (disposal == 2) // restore the frame's area to the background (transparent)
        {
            for (int row = 0; row < frameHeight; row++)
            {
                int canvasBase = ((top + row) * screenWidth) + left;
                canvas.AsSpan(canvasBase, frameWidth).Clear();
            }
        }
        else if (disposal == 3) // restore the canvas as it was before this frame
        {
            previous.CopyTo(canvas, 0);
        }

        nextDisposal = 0;
    }

    private static uint[] ReadColorTable(ReadOnlySpan<byte> data, ref int position, int entries)
    {
        if (position + (entries * 3) > data.Length)
            throw new ProsperoException("The GIF colour table is truncated.", -1);
        uint[] table = new uint[entries];
        for (int i = 0; i < entries; i++)
        {
            byte r = data[position];
            byte g = data[position + 1];
            byte b = data[position + 2];
            table[i] = 0xFF000000u | ((uint)r << 16) | ((uint)g << 8) | b;
            position += 3;
        }

        return table;
    }

    private static byte[] GatherSubBlocks(ReadOnlySpan<byte> data, ref int position)
    {
        var output = new List<byte>();
        while (position < data.Length)
        {
            int size = data[position++];
            if (size == 0)
                break;
            if (position + size > data.Length)
                throw new ProsperoException("The GIF image data is truncated.", -1);
            for (int i = 0; i < size; i++)
                output.Add(data[position + i]);
            position += size;
        }

        return [.. output];
    }

    private static void SkipSubBlocks(ReadOnlySpan<byte> data, ref int position)
    {
        while (position < data.Length)
        {
            int size = data[position++];
            if (size == 0)
                break;
            position += size;
        }
    }

    private static int ReadLoopCount(ReadOnlySpan<byte> data, ref int position)
    {
        int start = position;
        int loop = -1;
        if (position < data.Length && data[position] == 11 &&
            position + 12 <= data.Length &&
            data.Slice(position + 1, 11).SequenceEqual("NETSCAPE2.0"u8))
        {
            position += 12; // block size + identifier
            while (position < data.Length)
            {
                int size = data[position++];
                if (size == 0)
                    break;
                if (size == 3 && position + 3 <= data.Length && data[position] == 1)
                    loop = data[position + 1] | (data[position + 2] << 8);
                position += size;
            }

            return loop;
        }

        position = start;
        SkipSubBlocks(data, ref position);
        return -1;
    }

    private static int[] BuildInterlaceSchedule(int height)
    {
        // The four interlace passes start at rows 0, 4, 2, 1 and step by 8, 8, 4, 2. Walking them in
        // order yields, for each row in the order it appears in the image data, its row in the frame.
        // Every frame row is assigned exactly once, so the whole schedule is built in a single linear
        // pass and each later lookup is constant time.
        int[] schedule = new int[height];
        ReadOnlySpan<int> starts = [0, 4, 2, 1];
        ReadOnlySpan<int> steps = [8, 8, 4, 2];
        int index = 0;
        for (int pass = 0; pass < 4; pass++)
            for (int row = starts[pass]; row < height; row += steps[pass])
                schedule[index++] = row;
        return schedule;
    }

    private static void DecodeLzw(ReadOnlySpan<byte> data, int minCodeSize, byte[] output)
    {
        if (minCodeSize is < 2 or > 8)
            throw new ProsperoException("The GIF image has an invalid code size.", -1);

        const int MaxCodes = 4096;
        int clearCode = 1 << minCodeSize;
        int endCode = clearCode + 1;
        int[] prefix = new int[MaxCodes];
        byte[] suffix = new byte[MaxCodes];
        byte[] stack = new byte[MaxCodes + 1];
        for (int i = 0; i < clearCode; i++)
            suffix[i] = (byte)i;

        int codeSize = minCodeSize + 1;
        int available = clearCode + 2;
        int oldCode = -1;
        byte firstByte = 0;
        int bitBuffer = 0;
        int bitCount = 0;
        int dataPos = 0;
        int outPos = 0;

        while (outPos < output.Length)
        {
            while (bitCount < codeSize)
            {
                if (dataPos >= data.Length)
                    return; // out of input; leave the rest as index 0
                bitBuffer |= data[dataPos++] << bitCount;
                bitCount += 8;
            }

            int code = bitBuffer & ((1 << codeSize) - 1);
            bitBuffer >>= codeSize;
            bitCount -= codeSize;

            if (code == clearCode)
            {
                codeSize = minCodeSize + 1;
                available = clearCode + 2;
                oldCode = -1;
                continue;
            }

            if (code == endCode)
                return;

            // A first code must be a literal, and no code may exceed the next free dictionary slot;
            // otherwise a crafted stream could build a self-referencing prefix chain and walk the decode
            // stack out of bounds.
            if (code > available || (oldCode == -1 && code >= clearCode))
                throw new ProsperoException("The GIF LZW stream is corrupt.", -1);

            if (oldCode == -1)
            {
                firstByte = suffix[code];
                output[outPos++] = firstByte;
                oldCode = code;
                continue;
            }

            int inCode = code;
            int stackTop = 0;
            if (code >= available)
            {
                stack[stackTop++] = firstByte;
                code = oldCode;
            }

            while (code >= clearCode)
            {
                stack[stackTop++] = suffix[code];
                code = prefix[code];
            }

            firstByte = suffix[code];
            stack[stackTop++] = firstByte;

            if (available < MaxCodes)
            {
                prefix[available] = oldCode;
                suffix[available] = firstByte;
                available++;
                if (available == (1 << codeSize) && codeSize < 12)
                    codeSize++;
            }

            oldCode = inCode;

            while (stackTop > 0 && outPos < output.Length)
                output[outPos++] = stack[--stackTop];
        }
    }
}
