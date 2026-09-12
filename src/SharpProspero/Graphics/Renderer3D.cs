// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Graphics.Agc;
using SharpProspero.Interop;
using SharpProspero.Interop.Agc;
using SharpProspero.Interop.VideoOut;
using SharpProspero.Memory;
using System;
using System.Numerics;
using System.Runtime.InteropServices;

namespace SharpProspero.Graphics;

/// <summary>
/// Draws 3D meshes with the graphics processor. It renders straight into the display's framebuffers with
/// the built-in mesh shaders: give it a <see cref="MeshBuffer"/> and a model-view-projection matrix, and
/// it transforms and lights the mesh. Create one for a display, call <see cref="DrawMesh"/> each frame,
/// dispose it at shutdown.
/// </summary>
/// <remarks>
/// The renderer records one draw per frame into a command buffer and presents through the display. It
/// binds the mesh as a structured buffer the vertex program reads by index, and passes the matrices in a
/// constant buffer; both descriptors and the combined register state live in graphics-readable memory
/// because the processor reads them while it runs. The render target is linear, matching the display's
/// framebuffers, so no separate scan-out set-up is needed.
/// </remarks>
public sealed unsafe class Renderer3D : IDisposable
{
    // Two 4x4 matrices: model-view-projection, then model (for transforming normals).
    [StructLayout(LayoutKind.Sequential)]
    private struct Constants
    {
        public Matrix4x4 Mvp;
        public Matrix4x4 Model;
    }

    private const uint TargetMaskOffset = 0x008E;          // CB_TARGET_MASK
    private const uint PrimitiveTriangleList = 4;          // the primitive type a triangle list is drawn as
    private const byte Index32Bit = 1;

    // What the shader-link step fills. On the context side: one interpolant register per parameter the
    // pixel program can read, then the enable that says which shader units run and the output primitive
    // type. On the user-config side: the geometry-engine control, the user-VGPR enable, and the
    // primitive type.
    private const int ShaderLinkageRegisterCount = 34;
    private const int PrimitiveStateRegisterCount = 3;

    private readonly DisplayDevice _display;
    private readonly ShaderBinary _vsBinary, _psBinary;
    private PreparedShader _vs, _ps;
    // One set of command buffer and register/constant memory per frame in flight, so a frame does not
    // overwrite memory a still-running earlier frame is reading. The set rotates with the display's
    // framebuffers.
    private readonly DrawCommandBuffer[] _dcb;
    private readonly DirectMemoryRegion[] _contextState;   // combined Cx registers the GPU loads
    private readonly DirectMemoryRegion[] _shaderState;    // combined Sh registers
    private readonly DirectMemoryRegion[] _primitiveState; // the Uc registers the link step fills
    private readonly DirectMemoryRegion[] _constants;      // the two matrices
    private readonly int _maxContext, _maxShader, _framesInFlight;
    private int _slot;
    private bool _disposed;

    /// <summary>
    /// Builds a renderer for a display, using the built-in mesh shaders. The display's framebuffers are
    /// the render targets.
    /// </summary>
    /// <exception cref="Interop.ProsperoException">The graphics device or a shader could not be prepared.</exception>
    public Renderer3D(DisplayDevice display, int commandBufferBytes = 256 * 1024)
    {
        ArgumentNullException.ThrowIfNull(display);
        _display = display;
        AgcDevice.Initialize();

        _vsBinary = BuiltInShaders.MeshVertex();
        _psBinary = BuiltInShaders.MeshPixel();
        _vs = _vsBinary.Prepare();
        _ps = _psBinary.Prepare();

        // The combined register state: the target, the viewport, the write mask, the shader linkage, and
        // each shader's own registers. Sized for the block registers plus both shaders' registers.
        _maxContext = CxRenderTarget.RegisterCount + AgcViewport.RegisterCount + 1 + ShaderLinkageRegisterCount
                      + _vs.Shader.ContextRegisters.Length + _ps.Shader.ContextRegisters.Length;
        _maxShader = _vs.Shader.ShaderRegisters.Length + _ps.Shader.ShaderRegisters.Length;

        // One set per frame in flight, matching the display's framebuffer count, so recording a frame
        // never touches memory an earlier frame's draw is still reading.
        _framesInFlight = Math.Max(2, _display.BufferCount);
        _dcb = new DrawCommandBuffer[_framesInFlight];
        _contextState = new DirectMemoryRegion[_framesInFlight];
        _shaderState = new DirectMemoryRegion[_framesInFlight];
        _primitiveState = new DirectMemoryRegion[_framesInFlight];
        _constants = new DirectMemoryRegion[_framesInFlight];
        for (int i = 0; i < _framesInFlight; i++)
        {
            _dcb[i] = DrawCommandBuffer.Allocate((uint)commandBufferBytes);
            _contextState[i] = DirectMemoryRegion.Allocate((nuint)(_maxContext * sizeof(CxRegister)));
            _shaderState[i] = DirectMemoryRegion.Allocate((nuint)(_maxShader * sizeof(CxRegister)));
            _primitiveState[i] = DirectMemoryRegion.Allocate((nuint)(PrimitiveStateRegisterCount * sizeof(CxRegister)));
            _constants[i] = DirectMemoryRegion.Allocate((nuint)sizeof(Constants));
        }
    }

    /// <summary>
    /// Draws a mesh this frame, transformed by <paramref name="mvp"/> (world to clip) with
    /// <paramref name="model"/> used to orient its normals, and presents the frame. Call once per frame.
    /// </summary>
    public void DrawMesh(MeshBuffer mesh, in Matrix4x4 mvp, in Matrix4x4 model)
    {
        ArgumentNullException.ThrowIfNull(mesh);
        ObjectDisposedException.ThrowIf(_disposed, this);

        // The set of graphics-readable memory this frame records into. It rotates with the framebuffers so
        // recording never overwrites memory an earlier frame's draw is still reading.
        DrawCommandBuffer dcbObj = _dcb[_slot];
        DirectMemoryRegion contextRegion = _contextState[_slot];
        DirectMemoryRegion shaderRegion = _shaderState[_slot];
        DirectMemoryRegion primitiveRegion = _primitiveState[_slot];
        DirectMemoryRegion constantsRegion = _constants[_slot];

        // The matrices the vertex program reads. The program uses the second matrix only to orient the
        // normals, so it receives the normal matrix, not the model matrix itself: correct normal
        // transformation is by the inverse-transpose of the model, which keeps normals perpendicular to
        // the surface under a non-uniform scale. For a rigid or uniformly-scaled model this equals the
        // model's rotation. A degenerate (non-invertible) model falls back to the model matrix.
        Constants* constants = (Constants*)constantsRegion.Pointer;
        constants->Mvp = mvp;
        constants->Model = Matrix4x4.Invert(model, out Matrix4x4 inverseModel)
            ? Matrix4x4.Transpose(inverseModel)
            : model;

        // The colour target points at the framebuffer being drawn, and has to describe it the way the
        // display was opened: the processor writes where it is told, so a target that disagrees with
        // the registered buffer scatters the image rather than shifting it. Reading the arrangement
        // back from the display is what keeps the two from drifting apart when either is changed.
        //
        // The channel order matches the buffer the display registers, which carries blue first. Saying
        // the ordinary one puts what the program wrote as red into the byte the output reads as blue,
        // so the picture comes out with those two exchanged and nothing reports a fault.
        var target = new CxRenderTarget().Init(RegisterDefaults.RenderTargetBlock());
        var spec = new RenderTargetSpec(
            CxRenderTarget.Format.k8_8_8_8, CxRenderTarget.ChannelType.kUNorm, CxRenderTarget.ChannelOrder.kAlt,
            (uint)_display.Width, (uint)_display.Height, (ulong)_display.BackBufferAddress,
            _display.Tiling == VideoOutTilingMode.Tiled
                ? CxRenderTarget.TileMode.kRenderTarget
                : CxRenderTarget.TileMode.kLinear);
        AgcRenderTargetSetup.Initialize(target, spec);

        var viewport = new AgcViewport();
        viewport.SetViewport(0, 0, _display.Width, _display.Height);

        // Assemble the combined context register state into graphics-readable memory.
        int cx = 0;
        CxRegister* contextBase = (CxRegister*)contextRegion.Pointer;
        var context = new Span<CxRegister>(contextRegion.Pointer, _maxContext);
        target.Registers.CopyTo(context[cx..]); cx += CxRenderTarget.RegisterCount;
        cx += viewport.WriteTo(context[cx..]);
        context[cx++] = new CxRegister((ushort)TargetMaskOffset, 0xF);            // write all four channels of target 0

        // Link the two programs. This is what pairs the pixel program's inputs with the vertex program's
        // outputs and derives the shader-unit enable, the output primitive type and the geometry-engine
        // state from the programs themselves and the primitive being drawn. Left undone, those registers
        // keep their reset values and the draw produces nothing; written by hand they would have to
        // repeat a derivation the library already performs from the programs in front of it. The slot is
        // reserved before the programs' own registers so that anything a program sets wins.
        void* linkage = contextBase + cx;
        cx += ShaderLinkageRegisterCount;
        SceResult.ThrowIfFailed(
            SceAgc.sceAgcLinkShaders(
                linkage, primitiveRegion.Pointer, null, _vs.Shader.Handle, _ps.Shader.Handle, PrimitiveTriangleList),
            nameof(SceAgc.sceAgcLinkShaders));

        _vs.Shader.ContextRegisters.CopyTo(context[cx..]); cx += _vs.Shader.ContextRegisters.Length;
        _ps.Shader.ContextRegisters.CopyTo(context[cx..]); cx += _ps.Shader.ContextRegisters.Length;

        int sh = 0;
        var shader = new Span<CxRegister>(shaderRegion.Pointer, _maxShader);
        _vs.Shader.ShaderRegisters.CopyTo(shader[sh..]); sh += _vs.Shader.ShaderRegisters.Length;
        _ps.Shader.ShaderRegisters.CopyTo(shader[sh..]); sh += _ps.Shader.ShaderRegisters.Length;

        // The descriptors the vertex program reads its constants and vertices through.
        AgcBufferDescriptor cbDescriptor = AgcBufferDescriptor.Constant((ulong)constantsRegion.Pointer, (uint)sizeof(Constants));
        AgcBufferDescriptor vbDescriptor = AgcBufferDescriptor.Structured((ulong)mesh.VertexAddress, (uint)MeshBuffer.VertexStride, (uint)mesh.VertexCount);

        void* dcb = dcbObj.Handle;
        dcbObj.Reset();
        dcbObj.WaitUntilSafeForDisplay(_display.OutputHandle, (uint)_display.CurrentBufferIndex);

        SceAgc.sceAgcDcbSetCxRegistersIndirect(dcb, contextRegion.Pointer, (uint)cx);
        SceAgc.sceAgcDcbSetShRegistersIndirect(dcb, shaderRegion.Pointer, (uint)sh);
        SceAgc.sceAgcDcbSetUcRegistersIndirect(dcb, primitiveRegion.Pointer, (uint)PrimitiveStateRegisterCount);

        BindResource(dcb, ShaderResourceKind.ConstantBuffer, cbDescriptor);
        BindResource(dcb, ShaderResourceKind.ReadOnly, vbDescriptor);

        dcbObj.SetIndexSize(Index32Bit);
        dcbObj.SetIndexBuffer(mesh.IndexAddress);
        dcbObj.SetIndexCount((uint)mesh.IndexCount);
        dcbObj.DrawIndex((uint)mesh.IndexCount, mesh.IndexAddress);

        // Record the flip on the graphics timeline so it runs after the draw completes (not immediately on
        // the processor as a display-side flip would), then pace to the vertical blank and rotate the set.
        SceAgc.sceAgcDcbSetFlip(dcb, (uint)_display.OutputHandle, _display.CurrentBufferIndex, VideoOutFlipModeVSync, (long)_display.FrameIndex);
        AgcDevice.Submit(dcbObj);
        _display.AdvanceFrame();
        _slot = (_slot + 1) % _framesInFlight;
    }

    // Writes a resource descriptor into the vertex program's user data at the slot the program declares.
    private void BindResource(void* dcb, ShaderResourceKind kind, in AgcBufferDescriptor descriptor)
    {
        if (!_vs.Shader.TryGetResourceSlot(kind, 0, out int dwordOffset, out _))
            return; // the program does not read a resource of this kind
        uint* words = stackalloc uint[4];
        descriptor.WriteTo(new Span<uint>(words, 4));
        SceAgc.sceAgcCbSetShRegisterRangeDirect(dcb, AgcShader.GsUserDataBaseOffset + (uint)dwordOffset, words, 4);
    }

    private const uint VideoOutFlipModeVSync = 1;

    /// <summary>Releases the shaders, command buffer, and state memory.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _vs.Dispose();
        _ps.Dispose();
        for (int i = 0; i < _framesInFlight; i++)
        {
            _dcb[i].Dispose();
            _contextState[i].Dispose();
            _shaderState[i].Dispose();
            _primitiveState[i].Dispose();
            _constants[i].Dispose();
        }
    }
}
