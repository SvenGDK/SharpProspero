// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Payload.Kernel;

/// <summary>
/// NPDRM RIF (Rights Information File) record. Total size is 0x400 (1024) bytes.
/// The kernel-side handler reads specific fields from the RIF blob to validate
/// license state; the offsets below match the layout the crypto ladder handler
/// walks when validating a debug RIF (cmd 5/6 on the NPDRM mailbox).
/// </summary>
/// <remarks>
/// Type discriminates retail vs debug RIFs at byte offset 0x38, not at 2 as an
/// earlier revision assumed; the retail path never reads bytes 0x00-0x37, so a
/// swap at offset 2 silently misclassified every RIF.
/// </remarks>
[StructLayout(LayoutKind.Explicit, Size = 0x400)]
public unsafe struct NpdrmRifRecord
{
    /// <summary>RIF magic (4 bytes). First bytes of the record.</summary>
    [FieldOffset(0x00)] public uint Magic;

    /// <summary>RIF version.</summary>
    [FieldOffset(0x04)] public uint Version;

    /// <summary>RIF format type (1 = retail, 2 = debug).</summary>
    [FieldOffset(0x38)] public ushort Type;

    /// <summary>License flags.</summary>
    [FieldOffset(0x3A)] public ulong Flags;

    /// <summary>Content identifier (48 bytes).</summary>
    [FieldOffset(0x42)] public fixed byte ContentId[48];

    // The remainder of the RIF (timestamps, psnid, iv, secret, signature) is
    // consumed by the kernel-side handler and is not accessed from managed code;
    // future callers that need those fields should extend this struct with
    // explicit [FieldOffset] entries against the on-device layout.
}

/// <summary>
/// CCP (Crypto Coprocessor) message buffer. The kernel builds these messages on
/// the stack when submitting XTS or HMAC operations through the CCP; the crypto
/// bypass reads them from <c>[r12]</c> at the interception point. The message is
/// a plain 21-qword array (168 bytes); fields are addressed by index.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><c>MsgData[0]</c>: opcode / flags. XTS matches <c>(v &amp; 0x7FFFF7FF) == 0x2108000</c>; HMAC matches <c>(v &amp; 0x7FFFFFFF) == 0x9132000</c>.</item>
///   <item><c>MsgData[1]</c>: count / data size.</item>
///   <item><c>MsgData[2]</c>: source physical address.</item>
///   <item><c>MsgData[3]</c>: destination physical address (HMAC requires <c>MsgData[3] == MsgData[1] * 8</c>).</item>
///   <item><c>MsgData[4]</c>: start sector (XTS).</item>
///   <item><c>MsgData[5]</c>: XTS key handle.</item>
///   <item><c>MsgData[20]</c>: HMAC key handle.</item>
/// </list>
/// </remarks>
[StructLayout(LayoutKind.Sequential, Size = 168)]
public unsafe struct CcpMessage
{
    /// <summary>Raw 21-qword message payload. Index by opcode-specific slot.</summary>
    public fixed ulong MsgData[21];
}
