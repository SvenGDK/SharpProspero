// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Agc;

/// <summary>
/// Graphics command bindings (libSceAgc). This is the flat-C command layer of the console graphics API:
/// packet builders that append draw, dispatch, register-write, and synchronization packets to a
/// command buffer, plus shader creation/linking and register defaults. Each builder takes the command
/// buffer object as its first argument and returns the advanced write cursor; a paired GetSize call
/// reports the packet size in bytes so the caller can reserve room. Signatures were recovered from the
/// module; the structures behind the pointer arguments are modelled by the managed layer that wraps this.
/// </summary>
public static unsafe partial class SceAgc
{
    private const string Lib = "libSceAgc";

    /// <summary>Appends an AcquireMem GPU cache-flush/sync packet to an async compute command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbAcquireMem(void* commandBuffer, uint coherency, ulong gpuAddr, ulong size, ulong pollValue);

    /// <summary>Returns the AcquireMem packet size in bytes (0x20 or 0x40 depending on a config flag).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbAcquireMemGetSize();

    /// <summary>Appends a GDS (global data share) atomic-operation packet to an async compute command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbAtomicGds(void* commandBuffer, uint atomicOp, uint gdsOffset, uint size, uint count, ulong srcData, ushort dstSelect, uint value, uint value2, void* gpuAddr, void* returnAddr);

    /// <summary>Returns the GDS atomic packet size in bytes (0x2C).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbAtomicGdsGetSize();

    /// <summary>Appends a memory atomic-operation packet (op on a GPU address) to an async compute command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbAtomicMem(void* commandBuffer, uint atomicOp, uint dstSelect, void* dstAddr, byte flags, ulong srcData, ulong cmpData, uint size);

    /// <summary>Returns the memory atomic packet size in bytes (0x24).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbAtomicMemGetSize();

    /// <summary>Appends a conditional-execution packet that gates the following dwords on a GPU predicate address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbCondExec(void* commandBuffer, void* gpuAddr, uint execCount);

    /// <summary>Returns the conditional-execution packet size in bytes (0x14).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbCondExecGetSize();

    /// <summary>Appends a CopyData packet that copies between GPU registers/memory sources to a destination.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbCopyData(void* commandBuffer, uint dstSelect, byte engine, void* dstAddr, uint srcSelect, uint countSelect, void* srcAddr, byte wrConfirm, byte flags);

    /// <summary>Returns the CopyData packet size in bytes (0x18).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbCopyDataGetSize();

    /// <summary>Appends an indirect compute dispatch packet that sources thread-group dimensions from a GPU address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbDispatchIndirect(void* commandBuffer, void* argsAddr, uint dispatchModifier);

    /// <summary>Returns the indirect dispatch packet size in bytes (0x10).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbDispatchIndirectGetSize();

    /// <summary>Appends a DMA-data transfer packet (memory-to-memory copy via the CP) to an async compute command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbDmaData(void* commandBuffer, uint dstSelect, byte engine, void* dstAddr, uint srcSelect, byte flags, void* srcAddr, uint size, byte wrConfirm, byte cpSync);

    /// <summary>Returns the DMA-data packet size in bytes (0x1C).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbDmaDataGetSize();

    /// <summary>Appends an EventWrite packet that emits a GPU pipeline event of the given type.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbEventWrite(void* commandBuffer, uint eventType);

    /// <summary>Returns the EventWrite packet size in bytes (8).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbEventWriteGetSize();

    /// <summary>Appends a Jump packet redirecting command-buffer execution to another GPU address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbJump(void* commandBuffer, byte flags, void* jumpAddr, uint dwordCount);

    /// <summary>Returns the Jump packet size in bytes (0x10).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbJumpGetSize();

    /// <summary>Appends a memory-semaphore packet (signal/wait on a GPU memory address) to an async compute command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbMemSemaphore(void* commandBuffer, void* gpuAddr, byte signalOp, byte mailbox, uint value);

    /// <summary>Appends a pop-debug-marker packet closing the current annotation region in the command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbPopMarker(void* commandBuffer);

    /// <summary>Appends a PrimeUTCL2 packet that pre-warms the GPU L2 translation cache for a memory range.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbPrimeUtcl2(void* commandBuffer, byte primeMode, byte engine, void* gpuAddr, uint requestCount);

    /// <summary>Returns the PrimeUTCL2 packet size in bytes (0x14).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbPrimeUtcl2GetSize();

    /// <summary>Appends a push-debug-marker packet opening a named annotation region in the command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbPushMarker(void* commandBuffer, void* markerName, uint color);

    /// <summary>Returns the queue end-of-shader-action packet size in bytes (0x20).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbQueueEndOfShaderActionGetSize();

    /// <summary>Appends a packet that resets the compute queue state in the command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbResetQueue(void* commandBuffer, ushort queueArg, uint value);

    /// <summary>Appends a Rewind packet controlling command-processor prefetch/rewind behaviour.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbRewind(void* commandBuffer, uint count, byte flags);

    /// <summary>Returns the Rewind packet size in bytes (8).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbRewindGetSize();

    /// <summary>Appends a SetFlip packet that schedules a video-out buffer flip from the command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbSetFlip(void* commandBuffer, uint videoOutHandle, uint bufferIndex, uint flipMode, ulong flipArg);

    /// <summary>Appends a set-debug-marker packet emitting a single named annotation in the command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbSetMarker(void* commandBuffer, void* markerName, uint color);

    /// <summary>Returns the WaitOnAddress packet size in bytes for the given number of wait entries.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcAcbWaitOnAddressGetSize(uint count);

    /// <summary>Appends a WaitRegMem packet that stalls the GPU until a register/memory value satisfies a compare test.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbWaitRegMem(void* commandBuffer, uint compareFunc, byte memSpace, byte engine, void* gpuAddr, ulong refValue, ulong mask, uint pollInterval);

    /// <summary>Appends packets that stall until a video-out buffer is safe to render into (flip completed).</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbWaitUntilSafeForRendering(void* commandBuffer, uint videoOutHandle, uint bufferIndex);

    /// <summary>Appends a WriteData packet that writes an inline dword payload to a GPU memory/register destination.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcAcbWriteData(void* commandBuffer, uint dstSelect, byte engine, void* dstAddr, void* srcData, uint dwordCount, byte wrConfirm, byte flags);

    /// <summary>Patches the command-address field of a previously-written async conditional-execute (ACB) packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcAsyncCondExecPatchSetCommandAddress(void* packet, void* commandAddress);

    /// <summary>Patches the end pointer (used to derive the block size) of an async conditional-execute packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcAsyncCondExecPatchSetEnd(void* packet, void* endAddress);

    /// <summary>Patches the 1-bit rewind-state flag of an async rewind packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcAsyncRewindPatchSetRewindState(void* packet, byte rewindState);

    /// <summary>Patches the 64-bit compare address of a branch packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcBranchPatchSetCompareAddress(void* packet, void* compareAddress);

    /// <summary>Patches the else-branch target address and its 20-bit size field of a branch packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcBranchPatchSetElseTarget(void* packet, void* elseTarget, uint size);

    /// <summary>Patches the then-branch target address and its 20-bit size field of a branch packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcBranchPatchSetThenTarget(void* packet, void* thenTarget, uint size);

    /// <summary>Appends a branch / indirect-buffer (predicated jump) packet to a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbBranch(void* commandBuffer, uint modifier, uint predicate, void* targetAddr, ulong arg5, ulong arg6, byte arg7, void* arg8Addr, uint arg9, byte arg10, void* arg11Addr, uint arg12);

    /// <summary>Returns the size in bytes of a Cb branch packet (constant 0x38).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbBranchGetSize();

    /// <summary>Appends a conditional-write packet (poll an address, then write on match) to a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbCondWrite(void* commandBuffer, uint function, uint space, void* pollAddr, uint reference, void* writeAddr, uint mask, uint value);

    /// <summary>Returns the size in bytes of a Cb conditional-write packet (constant 0x24).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbCondWriteGetSize();

    /// <summary>Appends a compute dispatch packet (X/Y/Z threadgroup counts) to a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbDispatch(void* commandBuffer, uint threadGroupX, uint threadGroupY, uint threadGroupZ, uint modifier);

    /// <summary>Returns the size in bytes of a Cb dispatch packet (constant 0x14).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbDispatchGetSize();

    /// <summary>Appends a memory-semaphore (signal/wait) GPU-sync packet to a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbMemSemaphore(void* commandBuffer, void* semaphoreAddr, uint operation, uint modifier, uint value);

    /// <summary>Appends dwordCount NOP dwords to a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbNop(void* commandBuffer, uint dwordCount);

    /// <summary>Returns the size in bytes of a Cb NOP packet of the given dword count (dwordCount * 4).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbNopGetSize(uint dwordCount);

    /// <summary>Returns the size in bytes of a Cb queue end-of-pipe action packet (constant 0x20).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbQueueEndOfPipeActionGetSize();

    /// <summary>Appends a release-memory (end-of-pipe event write) GPU-sync packet to a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbReleaseMem(void* commandBuffer, uint eventType, uint arg3, uint arg4, byte dataSel, void* dstAddr, uint arg7, ulong value, ushort arg9, ushort arg10, byte arg11, uint arg12);

    /// <summary>Writes a contiguous range of shader (SH) registers directly into a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbSetShRegisterRangeDirect(void* commandBuffer, uint regOffset, void* values, uint count);

    /// <summary>Returns the size in bytes of a Cb set-SH-register-range packet for count registers (count * 4 + 8).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbSetShRegisterRangeDirectGetSize(uint count);

    /// <summary>Writes a set of shader (SH) register/value pairs directly into a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbSetShRegistersDirect(void* commandBuffer, void* regValuePairs, ulong count);

    /// <summary>Returns the size in bytes of a Cb set-SH-registers (pairs) packet for count pairs (count * 12).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbSetShRegistersDirectGetSize(uint count);

    /// <summary>Writes a contiguous range of user-config (UC) registers directly into a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbSetUcRegisterRangeDirect(void* commandBuffer, uint regOffset, void* values, uint count);

    /// <summary>Returns the size in bytes of a Cb set-UC-register-range packet for count registers (count * 4 + 8).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbSetUcRegisterRangeDirectGetSize(uint count);

    /// <summary>Writes a set of user-config (UC) register/value pairs directly into a generic command buffer and returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcCbSetUcRegistersDirect(void* commandBuffer, void* regValuePairs, ulong count);

    /// <summary>Returns the size in bytes of a Cb set-UC-registers (pairs) packet for count pairs (count * 12).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcCbSetUcRegistersDirectGetSize(uint count);

    /// <summary>Patches the command-address field of a conditional-execute packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcCondExecPatchSetCommandAddress(void* packet, void* commandAddress);

    /// <summary>Patches the end pointer (used to derive the block size) of a conditional-execute packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcCondExecPatchSetEnd(void* packet, void* endAddress);

    /// <summary>
    /// Fills a block of thirty-two context registers that map the pixel program's input parameters onto
    /// the geometry program's outputs, by matching their semantics.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcCreateInterpolantMapping(void* cxInterpolantMapping, void* geometryShader, void* pixelShader);

    /// <summary>
    /// Fills the primitive state the two register spaces carry: the shader-unit enable and the output
    /// primitive type on the context side, and the geometry-engine control, user-VGPR enable and
    /// primitive type on the user-config side. The output primitive type comes from the primitive being
    /// drawn, not from the geometry program.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcCreatePrimState(void* cxPrimitiveState, void* ucPrimitiveState, void* hullShader, void* geometryShader, uint primitiveType);

    /// <summary>Creates a shader object from a shader binary/header and its GPU address; writes the handle to outShader and returns a status.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcCreateShader(void* outShader, void* shaderHeader, void* gpuAddress);

    /// <summary>Appends an ACQUIRE_MEM GPU cache/sync packet to the draw command buffer, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbAcquireMem(void* commandBuffer, byte engine, uint coherCntl, uint coherSize, ulong coherSizeHi, void* baseAddr, uint pollInterval);

    /// <summary>Returns the size in dwords of an ACQUIRE_MEM packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbAcquireMemGetSize();

    /// <summary>Appends an ATOMIC_GDS packet performing an atomic operation on Global Data Share, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbAtomicGds(void* commandBuffer, uint engine, uint atomicOp, uint gdsOffset, uint count, uint gdsMemOffset, ushort atomicCmp, ushort atomicSrc, uint value, uint modifier, ulong srcData, ulong cmpData);

    /// <summary>Returns the size in dwords of an ATOMIC_GDS packet (0x2c bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbAtomicGdsGetSize();

    /// <summary>Appends an ATOMIC_MEM packet performing an atomic operation on GPU memory, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbAtomicMem(void* commandBuffer, uint engine, uint atomicOp, uint command, byte cachePolicy, void* dstAddr, ulong srcData, ulong cmpData, uint value);

    /// <summary>Returns the size in dwords of an ATOMIC_MEM packet (0x24 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbAtomicMemGetSize();

    /// <summary>Returns the packet size for a BeginOcclusionQuery command, which varies by the query mode argument.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbBeginOcclusionQueryGetSize(uint queryMode);

    /// <summary>Appends a CLEAR_STATE packet resetting GPU context state, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbClearState(void* commandBuffer, uint command);

    /// <summary>Appends a COND_EXEC packet that conditionally executes the following dwords, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbCondExec(void* commandBuffer, void* gpuAddr, uint execCount);

    /// <summary>Returns the size in dwords of a COND_EXEC packet (0x14 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbCondExecGetSize();

    /// <summary>Appends a context-state operation packet (save/restore/clear context registers), returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbContextStateOp(void* commandBuffer, uint op);

    /// <summary>Returns the size in dwords of a context-state operation packet for the given op.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbContextStateOpGetSize(uint op);

    /// <summary>Appends a COPY_DATA packet moving a value between register/memory/GDS sources and destinations, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbCopyData(void* commandBuffer, byte engine, byte dstSel, void* dstAddr, uint srcSel, uint countSel, void* srcAddr, byte wrConfirm, byte engineSel);

    /// <summary>Returns the size in dwords of a COPY_DATA packet (0x18 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbCopyDataGetSize();

    /// <summary>Appends an indirect compute dispatch packet sourcing thread-group counts from GPU memory; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDispatchIndirect(void* commandBuffer, uint argOffset, uint modifier);

    /// <summary>Returns the packet size for a DispatchIndirect command (constant 0xc bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDispatchIndirectGetSize();

    /// <summary>Appends a DMA_DATA packet performing a GPU DMA copy/fill between memory or register sources and destinations, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDmaData(void* commandBuffer, byte engine, uint dstSel, byte dstParam, void* dstAddr, uint srcSel, byte srcParam, void* srcAddr, uint numBytes, byte sizeMode, byte srcCachePolicy, byte dstCachePolicy);

    /// <summary>Returns the size in dwords of a DMA_DATA packet (0x1c bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDmaDataGetSize();

    /// <summary>Appends an indexed draw packet (index count + index buffer address) to a draw command buffer; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndex(void* commandBuffer, uint indexCount, void* indexAddr, ulong modifier);

    /// <summary>Appends an auto-index draw packet (auto-generated indices) to a draw command buffer; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndexAuto(void* commandBuffer, uint indexCount, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndexAuto command (constant 0xc bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndexAutoGetSize();

    /// <summary>Returns the packet size for a DrawIndex command (constant 0x18 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndexGetSize();

    /// <summary>Appends an indirect indexed draw packet sourcing arguments from GPU memory; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndexIndirect(void* commandBuffer, uint argOffset, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndexIndirect command (constant 0x14 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndexIndirectGetSize();

    /// <summary>Appends a multi-draw indirect indexed draw packet (multiple draws from an indirect args array); returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndexIndirectMulti(void* commandBuffer, uint argOffset, byte flags, uint count, void* countAddr, uint stride, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndexIndirectMulti command (computed from the user-data packet size).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndexIndirectMultiGetSize();

    /// <summary>Appends a multi-instanced indexed draw packet (index buffer drawn numInstances times); returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndexMultiInstanced(void* commandBuffer, uint indexCount, void* indexAddr, void* dataAddr, uint numInstances, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndexMultiInstanced command (computed from the user-data packet size).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndexMultiInstancedGetSize();

    /// <summary>Appends an indexed draw packet starting at an index offset within the bound index buffer; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndexOffset(void* commandBuffer, uint indexOffset, uint indexCount, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndexOffset command (constant 0x14 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndexOffsetGetSize();

    /// <summary>Appends an indirect (non-indexed) draw packet sourcing arguments from GPU memory; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndirect(void* commandBuffer, uint argOffset, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndirect command (constant 0x14 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndirectGetSize();

    /// <summary>Appends a multi-draw indirect (non-indexed) draw packet (multiple draws from an indirect args array); returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbDrawIndirectMulti(void* commandBuffer, uint argOffset, byte flags, uint count, void* countAddr, uint stride, ulong modifier);

    /// <summary>Returns the packet size for a DrawIndirectMulti command (computed from the user-data packet size).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbDrawIndirectMultiGetSize();

    /// <summary>Returns the packet size for an EndOcclusionQuery command (constant 0x10 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbEndOcclusionQueryGetSize();

    /// <summary>Appends an EVENT_WRITE GPU synchronization packet for the given event type, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbEventWrite(void* commandBuffer, uint eventType, ulong eventControl);

    /// <summary>Returns the size in dwords of an EVENT_WRITE packet for the given event type.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbEventWriteGetSize(byte eventType);

    /// <summary>Appends a packet configuring GPU LOD (level-of-detail) statistics gathering to an output address; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbGetLodStats(void* commandBuffer, byte enable, void* address, uint arg4, uint arg5, uint arg6, byte arg7, uint arg8);

    /// <summary>Returns the packet size for a GetLodStats command (constant 0x14 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbGetLodStatsGetSize();

    /// <summary>Appends an INDIRECT_BUFFER/jump packet redirecting command processing to another address, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbJump(void* commandBuffer, uint engine, byte flags, void* jumpAddr, uint dwordCount);

    /// <summary>Returns the size in dwords of a jump packet (0x10 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbJumpGetSize();

    /// <summary>Appends a MEM_SEMAPHORE packet that signals or waits on a memory semaphore, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbMemSemaphore(void* commandBuffer, void* semaphoreAddr, byte op, byte signal, uint value);

    /// <summary>Appends a debug pop-marker packet closing the current annotated command-buffer region, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbPopMarker(void* commandBuffer);

    /// <summary>Appends a PRIME_UTCL2 packet pre-warming the UTCL2 translation cache for a memory range, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbPrimeUtcl2(void* commandBuffer, byte engine, byte ctrl, void* address, uint requestedPages);

    /// <summary>Returns the size in dwords of a PRIME_UTCL2 packet (0x14 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbPrimeUtcl2GetSize();

    /// <summary>Appends a debug push-marker packet opening a named/colored annotated command-buffer region, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbPushMarker(void* commandBuffer, void* markerName, uint color);

    /// <summary>Returns the size in dwords of a queue end-of-shader action packet (0x20 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbQueueEndOfShaderActionGetSize();

    /// <summary>Appends a packet that resets the specified GPU queue, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbResetQueue(void* commandBuffer, ushort queueId, uint resetMode);

    /// <summary>Appends a REWIND packet reserving/aligning space in the draw command buffer, returning the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbRewind(void* commandBuffer, uint dwordCount);

    /// <summary>Returns the size in dwords of a REWIND packet (8 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbRewindGetSize();

    /// <summary>Returns the packet size for a SetBaseIndirectArgs (dispatch) command (constant 0x10 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetBaseDispatchIndirectArgsGetSize();

    /// <summary>Returns the packet size for a SetBaseIndirectArgs (draw) command (constant 0x10 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetBaseDrawIndirectArgsGetSize();

    /// <summary>Appends a packet setting the base GPU address of the indirect-args buffer (argType selects draw vs dispatch); returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetBaseIndirectArgs(void* commandBuffer, uint argType, void* baseAddr);

    /// <summary>Returns the size in dwords (0x10) of a Dcb bool-predication-enable packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetBoolPredicationEnableGetSize();

    /// <summary>Appends a packet to the draw command buffer that directly writes a CF (config) register.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetCfRegisterDirect(void* commandBuffer, ulong packedRegValue);

    /// <summary>Appends a packet directly writing a contiguous range of CF (config) registers from an inline value array.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetCfRegisterRangeDirect(void* commandBuffer, uint regOffset, void* values, uint count);

    /// <summary>Appends a packet that directly writes a CX (context) register into the draw command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetCxRegisterDirect(void* commandBuffer, ulong packedRegValue);

    /// <summary>Returns the size in dwords (0xc) of a direct CX (context) register write packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetCxRegisterDirectGetSize();

    /// <summary>Appends a packet that writes CX (context) registers indirectly from a GPU memory address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetCxRegistersIndirect(void* commandBuffer, void* regDataAddr, uint count);

    /// <summary>Returns the size in dwords (0x14) of an indirect CX (context) register write packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetCxRegistersIndirectGetSize();

    /// <summary>
    /// Appends a flip request packet to the draw command buffer to present a display buffer. Answers
    /// where the packets were written. The buffer index is signed because a negative one is a variant
    /// the processor accepts rather than a mistake.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetFlip(void* commandBuffer, uint videoOutHandle, int displayBufferIndex, uint flipMode, long flipArg);

    /// <summary>Appends a packet binding the index buffer GPU address; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetIndexBuffer(void* commandBuffer, void* indexAddr);

    /// <summary>Returns the packet size for a SetIndexBuffer command (constant 0xc bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetIndexBufferGetSize();

    /// <summary>Appends a packet setting the index count for the next indexed draw; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetIndexCount(void* commandBuffer, uint indexCount);

    /// <summary>Returns the packet size for a SetIndexCount command (constant 8 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetIndexCountGetSize();

    /// <summary>Appends a packet setting the index buffer address and count used for indirect-args indexed draws; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetIndexIndirectArgs(void* commandBuffer, void* indexAddr, uint indexCount);

    /// <summary>Returns the packet size for a SetIndexIndirectArgs command (constant 0x10 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetIndexIndirectArgsGetSize();

    /// <summary>Appends a packet setting the index element size and cache policy; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetIndexSize(void* commandBuffer, byte indexSize, byte cachePolicy);

    /// <summary>Returns the packet size for a SetIndexSize command (constant 0xc bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetIndexSizeGetSize();

    /// <summary>Appends a debug marker (named string) packet into the draw command buffer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcDcbSetMarker(void* commandBuffer, void* markerString, uint color);

    /// <summary>Appends a packet setting the instance count for subsequent draws; returns the advanced write cursor.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetNumInstances(void* commandBuffer, uint numInstances);

    /// <summary>Returns the packet size for a SetNumInstances command (constant 8 bytes).</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetNumInstancesGetSize();

    /// <summary>Appends a predication packet that gates subsequent draws on a predicate value in GPU memory.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetPredication(void* commandBuffer, uint predicationOp, uint hint, uint action, void* predicateAddr);

    /// <summary>Returns the size in dwords (0x10) of a predication-disable packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetPredicationDisableGetSize();

    /// <summary>Appends a packet that directly writes a single shader (SH) register.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetShRegisterDirect(void* commandBuffer, ulong packedRegValue);

    /// <summary>Returns the size in dwords (0xc) of a direct shader (SH) register write packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetShRegisterDirectGetSize();

    /// <summary>Appends a packet that writes shader (SH) registers indirectly from a GPU memory address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetShRegistersIndirect(void* commandBuffer, void* regDataAddr, uint count);

    /// <summary>Returns the size in dwords (0x14) of an indirect shader (SH) register write packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetShRegistersIndirectGetSize();

    /// <summary>Appends a packet that directly writes a single UC (uconfig) register.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetUcRegisterDirect(void* commandBuffer, ulong packedRegValue);

    /// <summary>Returns the size in dwords (0xc) of a direct UC (uconfig) register write packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetUcRegisterDirectGetSize();

    /// <summary>Appends a packet that writes UC (uconfig) registers indirectly from a GPU memory address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbSetUcRegistersIndirect(void* commandBuffer, void* regDataAddr, uint count);

    /// <summary>Returns the size in dwords (0x14) of an indirect UC (uconfig) register write packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetUcRegistersIndirectGetSize();

    /// <summary>Returns the size in dwords (0x10) of a Z-pass predication-enable packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbSetZPassPredicationEnableGetSize();

    /// <summary>Appends a packet that stalls the command buffer parser until prior work drains.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbStallCommandBufferParser(void* commandBuffer);

    /// <summary>Returns the size in dwords (8) of a command-buffer-parser stall packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbStallCommandBufferParserGetSize();

    /// <summary>Returns the size in dwords of a wait-on-address packet for the given count.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbWaitOnAddressGetSize(uint count);

    /// <summary>Appends a WAIT_REG_MEM sync packet that stalls the GPU until a register or memory value satisfies a compare.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcDcbWaitRegMem(void* commandBuffer, uint engine, byte function, uint operation, byte cachePolicy, ulong pollAddr, ulong reference, ulong mask, uint pollInterval);

    /// <summary>
    /// Appends packets that stall the draw command buffer until the display has released the given
    /// buffer, so the processor may render into it. Answers where the packets were written. The two
    /// arguments name the display and which of its buffers, not how to wait: with zeros the display
    /// lookup fails and no wait packet is written at all.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbWaitUntilSafeForRendering(void* commandBuffer, uint videoOutHandle, int displayBufferIndex);

    /// <summary>Appends a WRITE_DATA packet that copies inline dwords into a GPU memory address.</summary>
    [LibraryImport(Lib)]
    public static partial uint* sceAgcDcbWriteData(void* commandBuffer, uint destSel, byte cachePolicy, void* dstAddr, void* srcData, uint dwordCount, byte writeConfirm, byte flags);

    /// <summary>Returns the size in dwords (dwordCount*4 + 0x10) of a WRITE_DATA packet.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcDcbWriteDataGetSize(uint dwordCount);

    /// <summary>
    /// Patches the destination address or offset of a DMA-data packet, the mirror of the source call
    /// below. The value is a second argument: the packet is checked and the value stored into it, so
    /// declaring only the packet left whatever the register happened to hold as the destination.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcDmaDataPatchSetDstAddressOrOffset(void* packet, ulong dstData);

    /// <summary>Patches the source address/offset/immediate value field of a DMA-data packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcDmaDataPatchSetSrcAddressOrOffsetOrImmediate(void* packet, ulong srcData);

    /// <summary>Fuses two shader halves into one fused shader written into the provided buffer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcFuseShaderHalves(void* outFused, void* shaderLo, void* shaderHi, void* buffer);

    /// <summary>Computes the payload address of a data packet (packet+4, +4 more if flag set) and writes it to outAddress.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcGetDataPacketPayloadAddress(void* outAddress, void* packet, uint flag);

    /// <summary>Computes the byte size required for a fused shader and writes it to outSize; returns a status.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcGetFusedShaderSize(void* outSize, void* shaderLo, void* shaderHi);

    /// <summary>Returns the size in dwords of a command packet decoded from its header.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceAgcGetPacketSize(void* packet);

    /// <summary>Returns a pointer to the current default register state table.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceAgcGetRegisterDefaults();

    /// <summary>Returns a pointer to a default register state table selected by index.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceAgcGetRegisterDefaults2(uint index);

    /// <summary>Internal variant returning a default register state table selected by index.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceAgcGetRegisterDefaults2Internal(uint index);

    /// <summary>Internal variant returning a pointer to the current default register state table.</summary>
    [LibraryImport(Lib)]
    public static partial void* sceAgcGetRegisterDefaultsInternal();

    /// <summary>
    /// Prepares the graphics library. Takes a word of its own to keep state in and the revision of the
    /// register defaults to start from, and answers a status. The revision selects between distinct
    /// default tables, so it is not a value to leave unset.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcInit(void* state, uint defaultsRevision);

    /// <summary>Patches the jump target address and its 20-bit size field of a jump packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcJumpPatchSetTarget(void* packet, void* target, uint size);

    /// <summary>
    /// Links the programs of a draw: it writes a thirty-four register context block (the interpolant
    /// mapping, the shader-unit enable and the output primitive type) and a three register user-config
    /// block (the geometry-engine control, the user-VGPR enable and the primitive type). Pass a null
    /// hull program when there is no tessellation.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcLinkShaders(void* cxShaderLinkage, void* ucPrimitiveState, void* hullShader, void* geometryShader, void* pixelShader, uint primitiveType);

    /// <summary>Patches the write-back address of an end-of-pipe action packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcQueueEndOfPipeActionPatchAddress(void* packet, void* address);

    /// <summary>Patches the 64-bit write-back data value of an end-of-pipe action packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcQueueEndOfPipeActionPatchData(void* packet, ulong data);

    /// <summary>Patches the 12-bit GCR-control field of an end-of-pipe action packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcQueueEndOfPipeActionPatchGcrCntl(void* packet, uint gcrCntl);

    /// <summary>Patches the action/event-type field of an end-of-pipe action packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcQueueEndOfPipeActionPatchType(void* packet, byte actionType);

    /// <summary>Patches the 1-bit rewind-state flag of a rewind packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcRewindPatchSetRewindState(void* packet, byte rewindState);

    /// <summary>Adds to the 14-bit register count of a context (CX) indirect register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetCxRegIndirectPatchAddRegisters(void* packet, uint numRegisters);

    /// <summary>Patches the indirect data address of a context (CX) register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetCxRegIndirectPatchSetAddress(void* packet, void* address);

    /// <summary>Patches the 14-bit register count of a context (CX) indirect register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetCxRegIndirectPatchSetNumRegisters(void* packet, uint numRegisters);

    /// <summary>Writes a NOP opcode into a command packet/buffer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetNop(void* commandBuffer);

    /// <summary>Sets the predication enable bit (bit 0) on a command packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetPacketPredication(void* packet, uint enable);

    /// <summary>Sets predication bits across a range of command packets from begin to end.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetRangePredication(void* begin, void* end, byte enable);

    /// <summary>Adds to the 14-bit register count of a shader (SH) indirect register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetShRegIndirectPatchAddRegisters(void* packet, uint numRegisters);

    /// <summary>Patches the indirect data address of a shader (SH) register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetShRegIndirectPatchSetAddress(void* packet, void* address);

    /// <summary>Patches the 14-bit register count of a shader (SH) indirect register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetShRegIndirectPatchSetNumRegisters(void* packet, uint numRegisters);

    /// <summary>Sets the global command submission mode (thin thunk to an internal routine).</summary>
    [LibraryImport(Lib)]
    public static partial void sceAgcSetSubmitMode();

    /// <summary>Adds to the 14-bit register count of a user-config (UC) indirect register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetUcRegIndirectPatchAddRegisters(void* packet, uint numRegisters);

    /// <summary>Patches the indirect data address of a user-config (UC) register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetUcRegIndirectPatchSetAddress(void* packet, void* address);

    /// <summary>Patches the 14-bit register count of a user-config (UC) indirect register-set packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSetUcRegIndirectPatchSetNumRegisters(void* packet, uint numRegisters);

    /// <summary>Emits/handles a GPU suspend point and returns a status.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSuspendPoint();

    /// <summary>Emits a suspend point and writes the resulting status to outStatus.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcSuspendPointAndCheckStatus(void* outStatus);

    /// <summary>Updates an existing interpolant mapping in place from two shader programs.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcUpdateInterpolantMapping(void* mapping, void* vsShader, void* psShader);

    /// <summary>Updates a primitive state object with a new primitive/topology type.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcUpdatePrimState(void* primState, void* shader, uint primType);

    /// <summary>Patches the polled register/memory address of a wait-reg-mem GPU-sync packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcWaitRegMemPatchAddress(void* packet, void* address);

    /// <summary>Patches the compare-function field of a wait-reg-mem GPU-sync packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcWaitRegMemPatchCompareFunction(void* packet, byte compareFunction);

    /// <summary>Patches the compare mask of a wait-reg-mem GPU-sync packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcWaitRegMemPatchMask(void* packet, uint mask);

    /// <summary>Patches the reference value of a wait-reg-mem GPU-sync packet.</summary>
    [LibraryImport(Lib)]
    public static partial int sceAgcWaitRegMemPatchReference(void* packet, uint reference);
}
