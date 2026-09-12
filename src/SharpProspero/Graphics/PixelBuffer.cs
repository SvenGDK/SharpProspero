// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// A drawing surface of its own, off the screen — its pixels live in memory this buffer owns, in the same
/// B8-G8-R8-A8 layout the display uses. Draw into it as you would the back buffer, then blit it onto the
/// screen. Use it to build an image once and draw it many times (a pre-rendered sprite, a cached
/// background), to compose a picture before showing it, or to build something to encode to PNG or JPEG.
/// Dispose it to release the pixels.
/// </summary>
/// <remarks>
/// It starts fully transparent (all zero), so a frame drawn onto it with alpha composites cleanly when
/// blitted. Get a <see cref="Surface"/> over it with <see cref="AsSurface"/>; that surface is only valid
/// while the buffer is alive.
/// </remarks>
/// <example>
/// <code>
/// using var cache = new PixelBuffer(256, 64);
/// Surface s = cache.AsSurface();
/// s.FillRoundedRect(0, 0, 256, 64, 12, theme.Panel);
/// s.DrawText("Ready", 16, 20, 3, Color.White);
/// // later, every frame:
/// display.BackBuffer.BlitBlended(cache.AsSurface(), x, y);
/// </code>
/// </example>
public sealed unsafe class PixelBuffer : IDisposable
{
    private void* _pixels;
    private bool _disposed;

    /// <summary>Creates a transparent buffer of the given size.</summary>
    /// <exception cref="ArgumentOutOfRangeException">A dimension is not positive, or the buffer would be too large.</exception>
    public PixelBuffer(int width, int height)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(width);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(height);

        // Size the allocation in unsigned 64-bit so the product is exact and cannot wrap past the check.
        ulong bytes = (ulong)width * 4 * (ulong)height;
        if (bytes > uint.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(width), "The buffer would be larger than four gigabytes.");

        _pixels = NativeMemory.AllocZeroed((nuint)bytes);
        Width = width;
        Height = height;
    }

    /// <summary>Width in pixels.</summary>
    public int Width { get; }

    /// <summary>Height in pixels.</summary>
    public int Height { get; }

    /// <summary>Views the buffer as a drawing surface. The surface is valid only while the buffer is alive.</summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed.</exception>
    public Surface AsSurface()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        // An off-screen target keeps its own alpha channel, so blends composite alpha correctly rather
        // than forcing it opaque as they would on the display back buffer.
        return new Surface((uint*)_pixels, Width, Height, Width, opaque: false);
    }

    /// <summary>Fills the whole buffer with <paramref name="color"/>.</summary>
    public void Clear(Color color) => AsSurface().Clear(color);

    /// <summary>Releases the pixels.</summary>
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

    /// <summary>Releases the pixels if the buffer was dropped without a <see cref="Dispose"/> call.</summary>
    ~PixelBuffer() => Dispose();
}
