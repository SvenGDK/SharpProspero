// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// The result of one asynchronous request: the byte count the underlying read or write would have
/// returned, or a negative error number, and the state the request is in.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct SceKernelAioResult
{
    /// <summary>What the underlying read or write returned, once <see cref="State"/> reports completion.</summary>
    public long ReturnValue;

    /// <summary>The current state of the request, one of the <c>AioState*</c> values on <see cref="KernelAio"/>.</summary>
    public uint State;

    private uint _pad0;
}

/// <summary>
/// Scheduling parameters for one priority class of the asynchronous engine. The engine keeps three of
/// these (low, mid, high) and applies the one that matches the request's priority.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 20)]
public struct SceKernelAioSchedulingParam
{
    /// <summary>How many requests the engine may look at when it picks the next one to run.</summary>
    public int SchedulingWindowSize;

    /// <summary>How many pending completions the engine may accumulate before it delays new ones.</summary>
    public int DelayedCountLimit;

    /// <summary>Non-zero to split large requests across the engine's workers, zero to leave them whole.</summary>
    public uint EnableSplit;

    /// <summary>The upper bound on a request's size that still triggers a split.</summary>
    public uint SplitSize;

    /// <summary>The size of one chunk a split request is cut into.</summary>
    public uint SplitChunkSize;
}

/// <summary>
/// The three scheduling parameter sets the engine uses, one for each priority.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 60)]
public struct SceKernelAioParam
{
    /// <summary>Scheduling settings for the low priority class.</summary>
    public SceKernelAioSchedulingParam Low;

    /// <summary>Scheduling settings for the mid priority class.</summary>
    public SceKernelAioSchedulingParam Mid;

    /// <summary>Scheduling settings for the high priority class.</summary>
    public SceKernelAioSchedulingParam High;
}

/// <summary>
/// One asynchronous read or write request: where to read from or write to, how many bytes, the buffer,
/// where to put the outcome, and the file descriptor.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 40)]
public unsafe struct SceKernelAioRWRequest
{
    /// <summary>The byte offset within the file the operation runs at.</summary>
    public long Offset;

    /// <summary>The byte count to transfer.</summary>
    public nuint NByte;

    /// <summary>The address of the caller-provided buffer.</summary>
    public void* Buffer;

    /// <summary>The address of the result block the engine fills when the request completes.</summary>
    public SceKernelAioResult* Result;

    /// <summary>The file descriptor the operation runs on.</summary>
    public int Fd;

    private int _pad0;
}

/// <summary>
/// Asynchronous request bindings. A submit call hands the engine a batch of read or write requests
/// and gets back a submission identifier; the engine runs them on its own worker threads and reports
/// completion through the result block each request carries and, optionally, through wait or poll on
/// the identifier. Split, delete, cancel and poll all take the identifier the submit call returned.
/// </summary>
public static unsafe partial class KernelAio
{
    private const string Lib = "libkernel";

    /// <summary>Low priority request class. Value 1.</summary>
    public const int PriorityLow = 1;

    /// <summary>Mid priority request class. Value 2.</summary>
    public const int PriorityMid = 2;

    /// <summary>High priority request class. Value 3.</summary>
    public const int PriorityHigh = 3;

    /// <summary>Wait for every identifier in the batch to reach the requested state. Value 0x01.</summary>
    public const uint WaitAnd = 0x01;

    /// <summary>Wait for any identifier in the batch to reach the requested state. Value 0x02.</summary>
    public const uint WaitOr = 0x02;

    /// <summary>Bit ORed into a state result when a notification carried it.</summary>
    public const uint StateNotified = 0x10000;

    /// <summary>The request has been accepted for scheduling. Value 1.</summary>
    public const uint StateSubmitted = 1;

    /// <summary>The request is currently running on a worker. Value 2.</summary>
    public const uint StateProcessing = 2;

    /// <summary>The request has finished successfully. Value 3.</summary>
    public const uint StateCompleted = 3;

    /// <summary>The request was cancelled or dropped before it completed. Value 4.</summary>
    public const uint StateAborted = 4;

    /// <summary>The largest scheduling window the engine will accept. Value 128.</summary>
    public const int SchedWindowMax = 128;

    /// <summary>The largest delayed-count limit the engine will accept. Value 128.</summary>
    public const int DelayedCountMax = 128;

    /// <summary>Bit that turns on split-across-workers scheduling. Value 1.</summary>
    public const int EnableSplit = 1;

    /// <summary>Bit that turns off split-across-workers scheduling. Value 0.</summary>
    public const int DisableSplit = 0;

    /// <summary>The largest split-size ceiling the engine will accept. Value 0x1000000.</summary>
    public const int SplitSizeMax = 0x1000000;

    /// <summary>The largest split-chunk-size ceiling the engine will accept. Value 0x1000000.</summary>
    public const int SplitChunkSizeMax = 0x1000000;

    /// <summary>The scheduling window the engine uses when the caller does not override it. Value 32.</summary>
    public const int SchedWindowDefault = 32;

    /// <summary>The delayed-count limit the engine uses when the caller does not override it. Value 32.</summary>
    public const int DelayedCountDefault = 32;

    /// <summary>The split-size ceiling the engine uses when the caller does not override it. Value 0x100000.</summary>
    public const int SplitSizeDefault = 0x100000;

    /// <summary>The split-chunk-size ceiling the engine uses when the caller does not override it. Value 0x100000.</summary>
    public const int SplitChunkSizeDefault = 0x100000;

    /// <summary>Ceiling on the number of requests one submit batch may carry. Value 128.</summary>
    public const int RequestNumMax = 128;

    /// <summary>Ceiling on the number of identifiers one wait, poll or cancel batch may carry. Value 128.</summary>
    public const int IdNumMax = 128;

    /// <summary>
    /// Configures the engine with the scheduling parameters in <paramref name="param"/>; the
    /// <paramref name="size"/> is the byte count of what <paramref name="param"/> covers, so a caller
    /// with an older <see cref="SceKernelAioParam"/> lay-out still binds.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioInitializeImpl(void* param, int size);

    /// <summary>
    /// Fills <paramref name="param"/> with the default settings. A caller that only wants to override a
    /// field or two starts from this rather than zero-initialising the block.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial void sceKernelAioInitializeParam(SceKernelAioParam* param);

    /// <summary>
    /// Sets every field of <paramref name="param"/> at once, so a caller who has all five values in hand
    /// does not have to touch each field.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioSetParam(
        SceKernelAioSchedulingParam* param,
        int schedulingWindowSize,
        int delayedCountLimit,
        uint enableSplit,
        uint splitSize,
        uint splitChunkSize);

    /// <summary>
    /// Submits <paramref name="size"/> read requests at <paramref name="req"/> under
    /// <paramref name="prio"/>. On success the batch identifier is written to
    /// <paramref name="id"/>. The caller reads or waits on that identifier to learn when the batch is done.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioSubmitReadCommands(
        SceKernelAioRWRequest* req, int size, int prio, int* id);

    /// <summary>
    /// Submits <paramref name="size"/> read requests as separate submissions; on success one identifier
    /// per request is written to <paramref name="id"/>. Use it when the requests need to complete
    /// independently rather than as a single batch.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioSubmitReadCommandsMultiple(
        SceKernelAioRWRequest* req, int size, int prio, int* id);

    /// <summary>
    /// Submits <paramref name="size"/> write requests at <paramref name="req"/> under
    /// <paramref name="prio"/>. On success the batch identifier is written to <paramref name="id"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioSubmitWriteCommands(
        SceKernelAioRWRequest* req, int size, int prio, int* id);

    /// <summary>
    /// Submits <paramref name="size"/> write requests as separate submissions; on success one identifier
    /// per request is written to <paramref name="id"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioSubmitWriteCommandsMultiple(
        SceKernelAioRWRequest* req, int size, int prio, int* id);

    /// <summary>
    /// Waits until every identifier in <paramref name="id"/> has completed, up to
    /// <paramref name="usec"/> microseconds; a null pointer waits forever. The state of each
    /// identifier is written to <paramref name="state"/>. <paramref name="mode"/> combines the wait
    /// mode (<see cref="WaitAnd"/> or <see cref="WaitOr"/>) with any extra bits.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioWaitRequests(
        int* id, int num, int* state, uint mode, uint* usec);

    /// <summary>
    /// Waits on one identifier for up to <paramref name="usec"/> microseconds. The completion state is
    /// written to <paramref name="state"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioWaitRequest(int id, int* state, uint* usec);

    /// <summary>
    /// Reads the state of every identifier in <paramref name="id"/> without blocking. The state per
    /// identifier is written to <paramref name="state"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioPollRequests(int* id, int num, int* state);

    /// <summary>Reads the state of one identifier without blocking.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioPollRequest(int id, int* state);

    /// <summary>
    /// Cancels every identifier in <paramref name="id"/>. Requests that had not started move to the
    /// aborted state; running requests are stopped where the engine can, and their state is written to
    /// <paramref name="state"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioCancelRequests(int* id, int num, int* state);

    /// <summary>Cancels one identifier and writes the resulting state to <paramref name="state"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioCancelRequest(int id, int* state);

    /// <summary>
    /// Discards every identifier in <paramref name="id"/> once it has completed, so its slot may be
    /// reused. Undone identifiers stay reserved. Per-identifier outcomes are written to
    /// <paramref name="ret"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioDeleteRequests(int* id, int num, int* ret);

    /// <summary>Discards one identifier and writes the outcome to <paramref name="ret"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceKernelAioDeleteRequest(int id, int* ret);
}
