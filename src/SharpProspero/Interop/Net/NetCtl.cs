// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Net;

/// <summary>Where the network connection is.</summary>
public enum NetCtlState
{
    /// <summary>Not connected.</summary>
    Disconnected = 0,

    /// <summary>Connecting to the network.</summary>
    Connecting = 1,

    /// <summary>Connected; obtaining an address.</summary>
    IpObtaining = 2,

    /// <summary>Connected with an address. This is the state a working connection reports.</summary>
    IpObtained = 3,
}

/// <summary>The kind of network device in use.</summary>
public enum NetCtlDevice
{
    /// <summary>A wired connection.</summary>
    Wired = 0,

    /// <summary>A wireless connection.</summary>
    Wireless = 1,
}

/// <summary>A six-byte Ethernet address used for the local NIC and for BSSIDs.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetEtherAddr
{
    /// <summary>The six bytes of the address, in transmission order.</summary>
    public fixed byte Data[6];
}

/// <summary>A four-byte IPv4 address in network byte order.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceNetInAddr
{
    /// <summary>The address as a 32-bit value, network byte order.</summary>
    public uint SAddr;
}

/// <summary>An IPv6 address in printable form together with its prefix length.</summary>
/// <remarks>
/// The address is a NUL-terminated string of at most forty-five characters, filling a forty-six
/// byte field; <see cref="PrefixLen"/> holds the routing prefix length, one to a hundred and
/// twenty-eight.
/// </remarks>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct SceNetCtlIpv6Addr
{
    /// <summary>The forty-six byte NUL-terminated address string.</summary>
    public fixed byte Address[46];

    /// <summary>The prefix length, one to a hundred and twenty-eight.</summary>
    public byte PrefixLen;
}

/// <summary>The buffer <see cref="NetCtl.sceNetCtlGetInfoV6"/> fills, one field selected by info code.</summary>
/// <remarks>
/// A two hundred and fifty-six byte union: the requested member is written at offset zero and the
/// remaining bytes are left untouched, so a caller reads whichever field matches the code they
/// asked for.
/// </remarks>
[StructLayout(LayoutKind.Explicit, Size = 256)]
public unsafe struct SceNetCtlInfoV6
{
    /// <summary>The IPv6 address with its prefix length, for <see cref="NetCtl.InfoV6IpAddress"/>.</summary>
    [FieldOffset(0)] public SceNetCtlIpv6Addr IpAddress;

    /// <summary>The link-local address with its prefix length, for <see cref="NetCtl.InfoV6LinkLocalAddress"/>.</summary>
    [FieldOffset(0)] public SceNetCtlIpv6Addr LinkLocalAddress;

    /// <summary>The full two hundred and fifty-six byte payload for raw access.</summary>
    [FieldOffset(0)] public fixed byte Reserved[256];
}

/// <summary>The byte counters and device kind for the currently selected interface.</summary>
/// <remarks>
/// Fifty-six bytes: a device word, four bytes of padding to align the counters, two eight-byte
/// counters, then a thirty-two byte reserved region.
/// </remarks>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetCtlIfStat
{
    /// <summary>The device kind, one of <see cref="NetCtlDevice"/>.</summary>
    public uint Device;

    private uint _pad;

    /// <summary>Bytes transmitted since the counter was last cleared.</summary>
    public ulong TxBytes;

    /// <summary>Bytes received since the counter was last cleared.</summary>
    public ulong RxBytes;

    /// <summary>Thirty-two reserved bytes, held as eight thirty-two bit words.</summary>
    public fixed uint Reserved[8];
}

/// <summary>The address translation state observed by the box: STUN outcome, NAT type, mapped address.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceNetCtlNatInfo
{
    /// <summary>The size of this structure, filled by the caller.</summary>
    public uint Size;

    /// <summary>The STUN check outcome; see <see cref="NetCtl.NatInfoStunUnchecked"/>.</summary>
    public int StunStatus;

    /// <summary>The NAT type; see <see cref="NetCtl.NatInfoNatType1"/>.</summary>
    public int NatType;

    /// <summary>The address the router presents on the outside.</summary>
    public SceNetInAddr MappedAddr;
}

/// <summary>
/// Network status bindings. Each fact about the connection is read one at a time by code into a
/// buffer; the union the service fills is 256 bytes and writes the requested member at its start.
/// </summary>
public static unsafe partial class NetCtl
{
    private const string Lib = "libSceNetCtl";

    /// <summary>The size of the buffer <see cref="sceNetCtlGetInfo"/> fills.</summary>
    public const int InfoSize = 256;

    /// <summary>A call was made before <see cref="sceNetCtlInit"/> ran.</summary>
    public const int NotInitialized = unchecked((int)0x80412101);

    // The info codes, one per field of the connection.
    public const int InfoDevice = 1;
    public const int InfoEtherAddr = 2;
    public const int InfoMtu = 3;
    public const int InfoLink = 4;
    public const int InfoBssid = 5;
    public const int InfoSsid = 6;
    public const int InfoWifiSecurity = 7;
    public const int InfoRssiDbm = 8;
    public const int InfoRssiPercentage = 9;
    public const int InfoChannel = 10;
    public const int InfoIpConfig = 11;
    public const int InfoIpAddress = 14;
    public const int InfoNetmask = 15;
    public const int InfoDefaultRoute = 16;
    public const int InfoPrimaryDns = 17;
    public const int InfoSecondaryDns = 18;

    // The IPv6 info codes, one per field of the IPv6 connection.
    public const int InfoV6IpAddress = 1;
    public const int InfoV6LinkLocalAddress = 2;
    public const int InfoV6DefaultRoute = 3;
    public const int InfoV6PrimaryDns = 4;
    public const int InfoV6SecondaryDns = 5;

    // The event types delivered to a registered callback.
    public const int EventTypeDisconnected = 1;
    public const int EventTypeDisconnectReqFinished = 2;
    public const int EventTypeIpObtained = 3;

    /// <summary>The maximum number of IPv4 callbacks that may be registered at once.</summary>
    public const int CallbackMax = 8;

    /// <summary>The maximum number of IPv6 callbacks that may be registered at once.</summary>
    public const int V6CallbackMax = 8;

    // The STUN outcomes reported inside a NAT info block.
    public const int NatInfoStunUnchecked = 0;
    public const int NatInfoStunFailed = 1;
    public const int NatInfoStunOk = 2;

    // The NAT types reported inside a NAT info block.
    public const int NatInfoNatType1 = 1;
    public const int NatInfoNatType2 = 2;
    public const int NatInfoNatType3 = 3;

    /// <summary>
    /// Starts the network status service. This is the first network call an application makes; nothing
    /// precedes it. Zero on success, or a negative error code.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlInit();

    /// <summary>Stops the network status service.</summary>
    [LibraryImport(Lib)]
    public static partial void sceNetCtlTerm();

    /// <summary>Reads the connection state into <paramref name="state"/> (a <see cref="NetCtlState"/>).</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetState(int* state);

    /// <summary>
    /// Reads one fact about the connection, named by <paramref name="code"/>, into
    /// <paramref name="info"/>, which must point at a <see cref="InfoSize"/>-byte buffer.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetInfo(int code, void* info);

    /// <summary>
    /// Delivers any pending events from the callbacks registered on this thread. Callbacks fire from
    /// the thread that runs this call, so an application drives the check itself.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlCheckCallback();

    /// <summary>
    /// Registers a callback that fires when the IPv4 connection state changes. Zero on success; the
    /// slot the callback took is written into <paramref name="cid"/> for later unregistration.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlRegisterCallback(
        delegate* unmanaged[Cdecl]<int, void*, void> func,
        void* arg,
        int* cid);

    /// <summary>Removes a callback registered with <see cref="sceNetCtlRegisterCallback"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlUnregisterCallback(int cid);

    /// <summary>
    /// Reads the error code that accompanies the most recent callback event of the given type. Called
    /// from inside a callback body to learn why the state changed.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetResult(int eventType, int* errorCode);

    /// <summary>Reads the IPv6 connection state into <paramref name="state"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetStateV6(int* state);

    /// <summary>
    /// Reads one fact about the IPv6 connection, named by <paramref name="code"/>, into
    /// <paramref name="info"/>, whose two hundred and fifty-six byte payload receives the requested
    /// field at offset zero.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetInfoV6(int code, SceNetCtlInfoV6* info);

    /// <summary>
    /// Reads the error code that accompanies the most recent IPv6 callback event of the given type.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetResultV6(int eventType, int* errorCode);

    /// <summary>Reads the byte counters and device kind for the current interface.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetIfStat(SceNetCtlIfStat* ifStat);

    /// <summary>Reads the outward address translation state: STUN outcome, NAT type, and mapped address.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlGetNatInfo(SceNetCtlNatInfo* natInfo);
}
