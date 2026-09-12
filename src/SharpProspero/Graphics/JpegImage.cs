// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Image;
using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// A decoded JPEG image held as B8-G8-R8-A8 pixels, the layout the display surface uses, so it blits
/// straight onto a framebuffer. Decode once, draw its <see cref="AsSurface"/> as often as needed, and
/// dispose it to release the pixels. Load the JPEG-decode module
/// (<c>SystemModule.Load(SystemModuleId.JpegDec)</c>) before decoding.
/// </summary>
public sealed unsafe class JpegImage : IDisposable
{
    private void* _pixels;
    private bool _disposed;

    private JpegImage(void* pixels, int width, int height)
    {
        _pixels = pixels;
        Width = width;
        Height = height;
    }

    /// <summary>Width in pixels.</summary>
    public int Width { get; }

    /// <summary>Height in pixels.</summary>
    public int Height { get; }

    /// <summary>Views the decoded pixels as a drawing surface.</summary>
    public Surface AsSurface() => new((uint*)_pixels, Width, Height);

    /// <summary>Decodes <paramref name="jpeg"/> into a B8-G8-R8-A8 image.</summary>
    /// <remarks>
    /// A camera writes an image in the sensor's readout order and records how it should be turned upright
    /// in an EXIF orientation tag. The decoder produces the pixels as stored, so the tag is read here and
    /// the pixels are flipped or rotated to match. A file without the tag decodes as-is.
    /// </remarks>
    /// <exception cref="ProsperoException">Parsing, sizing, or decoding failed.</exception>
    public static JpegImage Decode(ReadOnlySpan<byte> jpeg)
    {
        if (jpeg.IsEmpty)
            throw new ArgumentException("The JPEG data is empty.", nameof(jpeg));

        int orientation = ReadExifOrientation(jpeg);

        fixed (byte* source = jpeg)
        {
            SceJpegDecImageInfo info = default;
            var parse = new SceJpegDecParseParam { JpegMemAddr = source, JpegMemSize = (uint)jpeg.Length, DecodeMode = 0, DownScale = 1 };
            SceResult.ThrowIfFailed(JpegDec.sceJpegDecParseHeader(&parse, &info), nameof(JpegDec.sceJpegDecParseHeader));

            ulong width = info.OutputImageWidth;
            ulong height = info.OutputImageHeight;
            ulong imageBytes = width * 4 * height;
            if (width == 0 || height == 0 || imageBytes > uint.MaxValue)
                throw new ProsperoException(nameof(JpegDec.sceJpegDecParseHeader), unchecked((int)0x80650020));

            // Which sampling the decoder is created for, taken from what the header reports rather than
            // assumed. Most files need the ordinary set of layouts; some need the full one, and a
            // decoder created for the ordinary set refuses those. The parse says which, and the answer
            // was being read and thrown away. It reports nothing for a colour space it does not know,
            // and only the two values are accepted, so anything else falls back to the ordinary set.
            var create = new SceJpegDecCreateParam
            {
                ThisSize = (uint)sizeof(SceJpegDecCreateParam),
                Attribute = info.SuitableCscAttribute == 2 ? 2u : 1u,
                MaxImageWidth = info.ImageWidth,
            };
            int workSize = JpegDec.sceJpegDecQueryMemorySize(&create);
            SceResult.ThrowIfFailed(workSize, nameof(JpegDec.sceJpegDecQueryMemorySize));

            void* work = NativeMemory.Alloc((nuint)workSize);
            void* handle = null;
            void* image = null;
            void* coefficient = null;
            try
            {
                SceResult.ThrowIfFailed(JpegDec.sceJpegDecCreate(&create, work, (uint)workSize, &handle), nameof(JpegDec.sceJpegDecCreate));

                image = NativeMemory.Alloc((nuint)imageBytes);
                if (info.CoefficientMemSize > 0)
                    coefficient = NativeMemory.Alloc(info.CoefficientMemSize);

                SceJpegDecImageInfo outInfo = default;
                var decode = new SceJpegDecDecodeParam
                {
                    JpegMemAddr = source,
                    ImageMemAddr = image,
                    CoefficientMemAddr = coefficient,
                    JpegMemSize = (uint)jpeg.Length,
                    ImageMemSize = (uint)imageBytes,
                    CoefficientMemSize = info.CoefficientMemSize,
                    DecodeMode = 0,
                    DownScale = 1,
                    PixelFormat = (ushort)JpegPixelFormat.Bgra8,
                    AlphaValue = 255,
                    ImagePitch = (uint)(width * 4),
                };
                SceResult.ThrowIfFailed(JpegDec.sceJpegDecDecode(handle, &decode, &outInfo), nameof(JpegDec.sceJpegDecDecode));
            }
            catch
            {
                if (coefficient != null)
                    NativeMemory.Free(coefficient);
                if (image != null)
                    NativeMemory.Free(image);
                if (handle != null)
                    JpegDec.sceJpegDecDelete(handle);
                NativeMemory.Free(work);
                throw;
            }

            if (coefficient != null)
                NativeMemory.Free(coefficient);
            JpegDec.sceJpegDecDelete(handle);
            NativeMemory.Free(work);

            // The pixels are upright already when the file carries no orientation, or an orientation of 1.
            if (orientation == 1)
                return new JpegImage(image, (int)width, (int)height);

            return Reorient(image, (int)width, (int)height, orientation);
        }
    }

    /// <summary>
    /// Produces an upright copy of a just-decoded image for an EXIF orientation of 2 through 8, frees the
    /// decoded pixels, and returns the copy. The decoded buffer is packed B8-G8-R8-A8 with rows the width
    /// apart. On any failure the decoded pixels are released so nothing leaks.
    /// </summary>
    private static JpegImage Reorient(void* image, int width, int height, int orientation)
    {
        (int outWidth, int outHeight) = OrientedSize(width, height, orientation);
        long count = (long)width * height;
        void* upright;
        try
        {
            upright = NativeMemory.Alloc((nuint)(count * 4));
        }
        catch
        {
            NativeMemory.Free(image);
            throw;
        }

        try
        {
            TransformOrientation(new ReadOnlySpan<uint>(image, (int)count), width, height, orientation, new Span<uint>(upright, (int)count), outWidth);
        }
        catch
        {
            NativeMemory.Free(upright);
            NativeMemory.Free(image);
            throw;
        }

        NativeMemory.Free(image);
        return new JpegImage(upright, outWidth, outHeight);
    }

    /// <summary>
    /// The dimensions an image takes after an EXIF orientation is applied. Orientations 5 through 8 turn
    /// the image onto its side, exchanging width and height; the rest keep the original dimensions.
    /// </summary>
    internal static (int Width, int Height) OrientedSize(int width, int height, int orientation)
        => orientation is >= 5 and <= 8 ? (height, width) : (width, height);

    /// <summary>
    /// Copies <paramref name="source"/> into <paramref name="destination"/> applying an EXIF orientation
    /// (2 through 8; any other value is treated as upright). The source is <paramref name="width"/> by
    /// <paramref name="height"/> packed pixels; the destination is packed with rows
    /// <paramref name="destinationWidth"/> pixels apart, which is the oriented width from
    /// <see cref="OrientedSize"/>. The eight cases are the identity, the horizontal and vertical mirrors,
    /// the 180-degree rotation, the two diagonal transposes, and the 90-degree rotations either way.
    /// </summary>
    internal static void TransformOrientation(ReadOnlySpan<uint> source, int width, int height, int orientation, Span<uint> destination, int destinationWidth)
    {
        for (int y = 0; y < height; y++)
        {
            int sourceRow = y * width;
            for (int x = 0; x < width; x++)
            {
                int destinationX, destinationY;
                switch (orientation)
                {
                    case 2: destinationX = width - 1 - x; destinationY = y; break;                    // mirror horizontally
                    case 3: destinationX = width - 1 - x; destinationY = height - 1 - y; break;        // rotate 180
                    case 4: destinationX = x; destinationY = height - 1 - y; break;                    // mirror vertically
                    case 5: destinationX = y; destinationY = x; break;                                 // transpose (main diagonal)
                    case 6: destinationX = height - 1 - y; destinationY = x; break;                    // rotate 90 clockwise
                    case 7: destinationX = height - 1 - y; destinationY = width - 1 - x; break;         // transverse (anti-diagonal)
                    case 8: destinationX = y; destinationY = width - 1 - x; break;                      // rotate 90 counter-clockwise
                    default: destinationX = x; destinationY = y; break;                                // upright
                }
                destination[destinationY * destinationWidth + destinationX] = source[sourceRow + x];
            }
        }
    }

    /// <summary>
    /// Reads the EXIF orientation of a JPEG, a value 1 through 8, or 1 when the file carries no EXIF
    /// orientation or the metadata is malformed. The marker segments are walked to find the EXIF
    /// application segment, whose embedded directory holds the orientation tag. Every read is bounded so
    /// truncated or crafted metadata is rejected rather than read past its end.
    /// </summary>
    internal static int ReadExifOrientation(ReadOnlySpan<byte> jpeg)
    {
        // A JPEG opens with the start-of-image marker; without it there is nothing to read.
        if (jpeg.Length < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8)
            return 1;

        int offset = 2;
        // Each marker is a 0xFF byte and a code; most are followed by a two-byte big-endian length that
        // counts itself. Walk them until the scan data begins or a byte is not where a marker should be.
        while (offset + 2 <= jpeg.Length)
        {
            if (jpeg[offset] != 0xFF)
                return 1;

            byte marker = jpeg[offset + 1];

            // A run of 0xFF bytes is padding before the next marker code.
            if (marker == 0xFF)
            {
                offset++;
                continue;
            }

            // Standalone markers with no length payload: start/end of image and the restart markers.
            if (marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7))
            {
                offset += 2;
                continue;
            }

            // Start of scan begins entropy-coded data; no more header segments follow.
            if (marker == 0xDA)
                return 1;

            if (offset + 4 > jpeg.Length)
                return 1;
            int length = (jpeg[offset + 2] << 8) | jpeg[offset + 3];
            if (length < 2 || offset + 2 + length > jpeg.Length)
                return 1;

            // The APP1 segment carries EXIF when its payload opens with the "Exif\0\0" identifier.
            if (marker == 0xE1)
            {
                ReadOnlySpan<byte> payload = jpeg.Slice(offset + 4, length - 2);
                int orientation = ReadOrientationFromApp1(payload);
                if (orientation != 0)
                    return orientation;
            }

            offset += 2 + length;
        }
        return 1;
    }

    /// <summary>
    /// Reads the orientation tag out of an APP1 segment payload, returning a value 1 through 8, or 0 when
    /// the payload is not EXIF or the tag is absent or unreadable (so the caller keeps scanning).
    /// </summary>
    private static int ReadOrientationFromApp1(ReadOnlySpan<byte> payload)
    {
        // The EXIF identifier is "Exif" followed by two zero bytes.
        if (payload.Length < 6 || payload[0] != 0x45 || payload[1] != 0x78 || payload[2] != 0x69 || payload[3] != 0x66 || payload[4] != 0x00 || payload[5] != 0x00)
            return 0;

        ReadOnlySpan<byte> tiff = payload.Slice(6);
        if (tiff.Length < 8)
            return 0;

        // The header byte order governs every multi-byte field that follows: "II" little-endian, "MM"
        // big-endian.
        bool little;
        if (tiff[0] == 0x49 && tiff[1] == 0x49)
            little = true;
        else if (tiff[0] == 0x4D && tiff[1] == 0x4D)
            little = false;
        else
            return 0;

        // Confirm the fixed 42 marker, then follow the offset to the first image file directory.
        if (ReadUInt16(tiff, 2, little) != 42)
            return 0;
        uint directoryOffset = ReadUInt32(tiff, 4, little);
        if (directoryOffset < 8 || (long)directoryOffset + 2 > tiff.Length)
            return 0;

        int entryCount = ReadUInt16(tiff, (int)directoryOffset, little);
        int firstEntry = (int)directoryOffset + 2;
        // Each directory entry is twelve bytes: a tag, a type, a count, then a value or an offset. A
        // short value sits in the first two bytes of the four-byte value field, so it is read in place.
        for (int i = 0; i < entryCount; i++)
        {
            long entry = (long)firstEntry + (long)i * 12;
            if (entry + 12 > tiff.Length)
                return 0;
            int tag = ReadUInt16(tiff, (int)entry, little);
            if (tag == 0x0112)
            {
                int value = ReadUInt16(tiff, (int)entry + 8, little);
                return value is >= 1 and <= 8 ? value : 0;
            }
        }
        return 0;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int index, bool little)
        => little
            ? (ushort)(data[index] | (data[index + 1] << 8))
            : (ushort)((data[index] << 8) | data[index + 1]);

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int index, bool little)
        => little
            ? (uint)(data[index] | (data[index + 1] << 8) | (data[index + 2] << 16) | (data[index + 3] << 24))
            : (uint)((data[index] << 24) | (data[index + 1] << 16) | (data[index + 2] << 8) | data[index + 3]);

    /// <summary>Releases the decoded pixels.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_pixels != null)
        {
            NativeMemory.Free(_pixels);
            _pixels = null;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases the pixels if the image was dropped without a <see cref="Dispose"/> call.</summary>
    ~JpegImage() => Dispose();
}
