// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics.Agc;
using SharpProspero.Interop;
using SharpProspero.Interop.VideoOut;
using SharpProspero.Memory;
using System;

namespace SharpProspero.Graphics;

/// <summary>
/// A double- or triple-buffered display attached to the main output. The device opens the output,
/// allocates its framebuffers from direct memory, registers them, and presents frames on the
/// vertical blank. Draw into <see cref="BackBuffer"/>, then call <see cref="Present"/>.
/// </summary>
public sealed unsafe class DisplayDevice : IDisposable
{
    private const int BytesPerPixel = 4;
    private const nuint Alignment = 2 * 1024 * 1024;
    /// <summary>What the display answers when it will not take the layout it was offered.</summary>
    private const int VideoOutInvalidTilingMode = unchecked((int)0x80290007);

    // The answer to a size the output does not take, and to one it takes only on a console set up for
    // it. The two are told apart by the check below, which knows the list.
    private const int VideoOutInvalidResolution = unchecked((int)0x80290005);

    // The output takes only so many flips at once; asked for one more it says so, and the answer is to
    // wait rather than to give up.
    private const int VideoOutFlipQueueFull = unchecked((int)0x80290012);

    private readonly int _handle;
    private readonly DirectMemoryRegion[] _regions;
    // Only when the scan-out buffers are tiled. A tiled buffer has no rows to write along, so anything
    // drawn a pixel at a time is drawn here, in row order, and rearranged into the scan-out buffer as
    // the frame is presented. Empty when the scan-out buffers are row-major and can be written directly.
    private readonly DirectMemoryRegion[] _staging;
    private readonly AgcSurfaceDescription _layout;
    private readonly int _stagingBytes;
    // The scan-out buffer's tiled footprint, in bytes. The CPU-cache writeback pass before a flip
    // walks this many bytes of the buffer, matching the byte range the display scan-out engine reads.
    // Comes from AgcSurface.Compute at open time, so it agrees with what the buffers were allocated
    // to hold.
    private readonly nuint _scanoutBytes;
    private int _index;
    private long _frame;
    private bool _disposed;

    private DisplayDevice(int handle, int width, int height, DirectMemoryRegion[] regions,
        DirectMemoryRegion[] staging, AgcSurfaceDescription layout, int stagingBytes, nuint scanoutBytes)
    {
        _handle = handle;
        Width = width;
        Height = height;
        _regions = regions;
        _staging = staging;
        _layout = layout;
        _stagingBytes = stagingBytes;
        _scanoutBytes = scanoutBytes;
    }

    /// <summary>How the scan-out buffers are laid out in memory.</summary>
    public VideoOutTilingMode Tiling => _staging.Length == 0 ? VideoOutTilingMode.Linear : VideoOutTilingMode.Tiled;

    /// <summary>Width in pixels.</summary>
    public int Width { get; }

    /// <summary>Height in pixels.</summary>
    public int Height { get; }

    /// <summary>Number of framebuffers in the swap chain.</summary>
    public int BufferCount => _regions.Length;

    /// <summary>
    /// The framebuffer to draw the next frame into, a pixel at a time. When the scan-out buffers are
    /// tiled this is a row-major surface of its own, rearranged into the scan-out buffer by
    /// <see cref="Present"/>; a tiled buffer has no rows, so writing one directly scatters the image.
    /// </summary>
    public Surface BackBuffer =>
        (_staging.Length == 0 ? _regions[_index] : _staging[_index]).AsSurface(Width, Height);

    /// <summary>
    /// The graphics-visible address of the framebuffer to draw the next frame into. The 3D renderer
    /// points a render target at this so the graphics processor draws straight into the scan-out buffer.
    /// </summary>
    public unsafe void* BackBufferAddress => _regions[_index].Pointer;

    /// <summary>The index of the framebuffer being drawn, within the swap chain.</summary>
    public int CurrentBufferIndex => _index;

    /// <summary>The output handle, for the renderer's flip.</summary>
    public int OutputHandle => _handle;

    /// <summary>
    /// Opens the main output and builds a swap chain of <paramref name="bufferCount"/> framebuffers.
    /// </summary>
    /// <param name="width">Width in pixels, from the sizes the output accepts (see the remarks).</param>
    /// <param name="height">Height in pixels, from the sizes the output accepts (see the remarks).</param>
    /// <param name="bufferCount">How many framebuffers the swap chain holds. Two or more.</param>
    /// <param name="userId">The user the output is opened for.</param>
    /// <param name="tiling">
    /// How the scan-out buffers are laid out. Tiled is the layout the output accepts unconditionally
    /// and is what the graphics processor draws into; row-major is accepted only while the machine's
    /// debug settings allow it, and is worth asking for when frames are drawn a pixel at a time,
    /// because it is then written straight into the scan-out buffer with nothing to rearrange.
    /// </param>
    /// <remarks>
    /// The output takes a fixed set of sizes and refuses anything else: 1920x1080, 3840x2160, 720x480
    /// and 720x576, or a width that is a multiple of 32 from 1280 to 1888 with a height sixteen-ninths
    /// narrower than it, which is the widescreen ladder below 1080. Of those only 1920x1080 is accepted
    /// on any machine; the rest need the console set up for them, and are refused with the same answer
    /// as a size that is not on the list at all.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The size is not one the output takes.</exception>
    /// <exception cref="ProsperoException">Opening the output or registering the buffers failed.</exception>
    public static DisplayDevice Open(int width = 1920, int height = 1080, int bufferCount = 2,
        int userId = SceUser.System, VideoOutTilingMode tiling = VideoOutTilingMode.Tiled)
    {
        if (bufferCount < 2)
            throw new ArgumentOutOfRangeException(nameof(bufferCount), "At least two buffers are required.");
        // A size the output does not take is refused when the buffers are registered, by which point
        // the output is open and the memory is allocated, and the answer says only that the size was
        // wrong. Checking here says which sizes there are.
        if (!IsSizeTheOutputTakes(width, height))
            throw new ArgumentOutOfRangeException(nameof(width),
                $"{width}x{height} is not a size the output takes. It takes 1920x1080, 3840x2160, " +
                "720x480 and 720x576, or a width that is a multiple of 32 from 1280 to 1888 with a " +
                "height of that width times nine sixteenths.");

        int handle = VideoOut.sceVideoOutOpen(userId, (int)VideoOutBusType.Main, 0, null);
        SceResult.ThrowIfFailed(handle, nameof(VideoOut.sceVideoOutOpen));
        VideoOut.sceVideoOutSetFlipRate(handle, 0);

        bool tiled = tiling == VideoOutTilingMode.Tiled;
        // The one arrangement the output scans out. Its size is not width times height times four: the
        // buffer is carried in blocks and the last row of blocks is whole, so it reaches past the last
        // visible row. Asking the layout for the size is what keeps the two agreeing.
        var desc = new AgcSurfaceDescription(
            tiled ? AgcTileMode.RenderTarget : AgcTileMode.Linear,
            AgcSurfaceDimension.TwoD, (uint)width, (uint)height, BytesPerPixel);
        AgcSurfaceLayout layout = AgcSurface.Compute(desc);

        var regions = new DirectMemoryRegion[bufferCount];
        var staging = new DirectMemoryRegion[tiled ? bufferCount : 0];
        int stagingBytes = width * height * BytesPerPixel;
        try
        {
            nuint frameBytes = (nuint)layout.TotalSizeBytes;
            nuint align = Math.Max((nuint)layout.BaseAlignBytes, Alignment);
            SceVideoOutBuffers* addresses = stackalloc SceVideoOutBuffers[bufferCount];
            for (int i = 0; i < bufferCount; i++)
            {
                regions[i] = DirectMemoryRegion.Allocate(frameBytes, align);
                // A tiled buffer holds more bytes than a plain width x height image because the last
                // block-row is whole even when the visible rectangle does not fill it. The tile pass
                // walks only the visible pixels, so the padding bytes stay whatever the memory pool
                // handed the region. Zeroing the whole thing here settles them to a known value, so a
                // partial hardware read that reaches into a padded byte gets a defined result instead
                // of leftover pool content.
                new Span<byte>(regions[i].Pointer, checked((int)regions[i].Size)).Clear();
                if (tiled)
                {
                    staging[i] = DirectMemoryRegion.Allocate((nuint)stagingBytes, Alignment);
                    new Span<byte>(staging[i].Pointer, stagingBytes).Clear();
                }
                addresses[i] = default;
                addresses[i].Data = regions[i].Pointer;
            }

            SceVideoOutBufferAttribute2 attribute = default;
            VideoOut.sceVideoOutSetBufferAttribute2(
                &attribute, VideoOutPixelFormat.Bgra8Srgb, (uint)tiling,
                (uint)width, (uint)height, VideoOutBufferAttributeOption.None, 0, 0);
            // The row pitch is left as the call above leaves it, which is zero. It is the one field of
            // the description that call does not write - it clears the whole thing and then fills in
            // every other field - and registering a description that names a pitch is refused outright,
            // whatever the number. Naming the width looked reasonable and cost a build: the display
            // opened, the buffers were refused, and the application ended before it drew a frame.
            int rc = VideoOut.sceVideoOutRegisterBuffers2(
                handle, 0, 0, addresses, bufferCount, &attribute, (int)VideoOutBufferCategory.Uncompressed, null);
            // A row-major buffer is a development-only layout for the display, and the machine keeps it
            // behind a setting rather than a capability the application can ask for. Refused, it says so
            // on the machine's own output and nowhere the application can read, so the failure arrives
            // here as a bare number and the application ends without ever saying what was wrong. Name it.
            if (rc == VideoOutInvalidTilingMode)
                throw new ProsperoException(
                    nameof(VideoOut.sceVideoOutRegisterBuffers2) +
                    " refused a row-major buffer. That layout is only accepted while " +
                    "\"Enhanced Display Buffer Attribute\" is turned on in the machine's debug settings. " +
                    "Turn it on, or open the display tiled, which is accepted either way", rc);
            // A size on the list that this console is not set up for is refused with the same answer
            // as one that is not on the list, and the console says why only on its own output.
            if (rc == VideoOutInvalidResolution)
                throw new ProsperoException(
                    nameof(VideoOut.sceVideoOutRegisterBuffers2) +
                    $" refused {width}x{height}. Every size except 1920x1080 needs the console set up " +
                    "for it; open the display at 1920x1080, which is accepted either way", rc);
            SceResult.ThrowIfFailed(rc, nameof(VideoOut.sceVideoOutRegisterBuffers2));
        }
        catch
        {
            foreach (DirectMemoryRegion? region in regions)
                region?.Dispose();
            foreach (DirectMemoryRegion? region in staging)
                region?.Dispose();
            VideoOut.sceVideoOutClose(handle);
            throw;
        }

        return new DisplayDevice(handle, width, height, regions, staging, desc, stagingBytes, (nuint)layout.TotalSizeBytes);
    }

    // The sizes the output takes: four named ones, and the widescreen ladder below 1080, which is any
    // width that is a multiple of 32 from 1280 to 1888 with a height of nine sixteenths of it.
    private static bool IsSizeTheOutputTakes(int width, int height) =>
        (width, height) is (1920, 1080) or (3840, 2160) or (720, 480) or (720, 576)
        || ((width % 32) == 0 && width is >= 1280 and <= 1888 && height == width / 32 * 18);

    /// <summary>
    /// Presents <see cref="BackBuffer"/> and advances to the next framebuffer. Returns the presented
    /// frame index. The wait for a buffer to become free again is done at the start of the next
    /// present, not at the end of this one, so the processor draws frame N + 1 while the output
    /// scans out frame N.
    /// </summary>
    /// <remarks>
    /// The wait at the start of a present is on the output's own account of which flip is showing,
    /// not on a vertical blank: a blank happens whether or not a flip retired, so waiting one and
    /// moving on hands the next frame to a buffer the output may still be reading. When the flip
    /// queue is full the submission is retried rather than treated as a failure, which is what a
    /// full queue means.
    /// </remarks>
    /// <exception cref="ProsperoException">The flip could not be submitted.</exception>
    public long Present(VideoOutFlipMode mode = VideoOutFlipMode.VSync)
    {
        // The buffer the next flip carries was last submitted for the flip _frame - _regions.Length,
        // and the output is still scanning it out as long as that flip is what the compositor
        // reports on screen. Wait until the compositor has moved past it — one flip later — so the
        // tile pass cannot touch a buffer the output is still reading. Only from the
        // _regions.Length'th frame onward is there an earlier flip to wait for at all; the first
        // pass around every buffer starts unused, so the check gates the wait out then.
        if (_frame >= _regions.Length)
            WaitUntilOnScreen(_frame - _regions.Length + 1);

        RearrangeIfDrawnInRows();
        // Direct memory is cached, so the CPU stores from user drawing (linear path) or from the tile
        // pass above (tiled path) sit in L1/L2 until the lines evict naturally. The scan-out engine
        // reads DRAM through the memory controller, not through the CPU coherency domain, so the flip
        // must not run until those stores are in memory. Skipping the writeback shows the display a
        // mixture of the previous frame's bytes and only the lines that happened to be evicted, which
        // reads as granular noise concentrated where the CPU wrote last.
        CpuCache.WriteBack(_regions[_index].Pointer, _scanoutBytes);
        int rc;
        while ((rc = VideoOut.sceVideoOutSubmitFlip(_handle, _index, (uint)mode, _frame)) == VideoOutFlipQueueFull)
            SceResult.ThrowIfFailed(VideoOut.sceVideoOutWaitVblank(_handle), nameof(VideoOut.sceVideoOutWaitVblank));
        SceResult.ThrowIfFailed(rc, nameof(VideoOut.sceVideoOutSubmitFlip));
        long presented = _frame;
        _index = (_index + 1) % _regions.Length;
        _frame++;
        return presented;
    }

    /// <summary>The output's account of how far it has got through the flips submitted to it.</summary>
    public SceVideoOutFlipStatus FlipStatus
    {
        get
        {
            SceVideoOutFlipStatus status;
            SceResult.ThrowIfFailed(
                VideoOut.sceVideoOutGetFlipStatus(_handle, &status), nameof(VideoOut.sceVideoOutGetFlipStatus));
            return status;
        }
    }

    // Waits until the output says the flip carrying this frame number is the one showing. Frames are
    // numbered upwards and never reused, so a later number means this one has already been passed.
    private void WaitUntilOnScreen(long frame)
    {
        while (FlipStatus.FlipArg < frame)
            SceResult.ThrowIfFailed(VideoOut.sceVideoOutWaitVblank(_handle), nameof(VideoOut.sceVideoOutWaitVblank));
    }

    /// <summary>
    /// Moves what was drawn in rows into the arrangement the output scans out, when the two differ.
    /// Nothing to do when the scan-out buffer is itself row-major, or when the frame was drawn by the
    /// graphics processor straight into the scan-out buffer, which leaves the row-major one untouched.
    /// </summary>
    /// <remarks>
    /// This walks every pixel of the frame on the processor, so a frame drawn a pixel at a time costs
    /// the drawing and this pass on top. Where that is too slow, ask for a row-major display and turn
    /// the matching debug setting on, or draw through the graphics processor and skip both.
    /// </remarks>
    private void RearrangeIfDrawnInRows()
    {
        if (_staging.Length == 0) return;
        AgcTiler.Tile(
            new Span<byte>(_regions[_index].Pointer, checked((int)_regions[_index].Size)),
            new ReadOnlySpan<byte>(_staging[_index].Pointer, _stagingBytes),
            _layout);
    }

    /// <summary>The running frame counter, used as a flip argument.</summary>
    public long FrameIndex => _frame;

    /// <summary>
    /// Waits until the frame just recorded is on screen and advances to the next framebuffer, for a
    /// caller that recorded the flip on the graphics timeline itself rather than through
    /// <see cref="Present"/>. Returns the presented frame index.
    /// </summary>
    /// <remarks>
    /// A frame drawn entirely on the graphics processor needs no CPU-side cache writeback: the flip
    /// packet on the graphics timeline retires an end-of-pipe cache-invalidate first. A caller that
    /// also touches the scan-out buffer from the CPU before its flip must call
    /// <see cref="CpuCache.WriteBack"/> on the touched range itself, before the flip; this method
    /// does not, because the CPU stores may have finished many frames ago.
    /// </remarks>
    public long AdvanceFrame()
    {
        WaitUntilOnScreen(_frame);
        long presented = _frame;
        _index = (_index + 1) % _regions.Length;
        _frame++;
        return presented;
    }

    /// <summary>Unregisters the buffers, releases their memory and closes the output.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        // A flip still in the queue is one the output is about to read these buffers for, so the
        // buffers are not taken away until it has finished with them.
        while (VideoOut.sceVideoOutIsFlipPending(_handle) > 0)
            VideoOut.sceVideoOutWaitVblank(_handle);

        VideoOut.sceVideoOutUnregisterBuffers(_handle, 0);
        foreach (DirectMemoryRegion region in _regions)
            region.Dispose();
        foreach (DirectMemoryRegion region in _staging)
            region.Dispose();
        VideoOut.sceVideoOutClose(_handle);
    }
}
