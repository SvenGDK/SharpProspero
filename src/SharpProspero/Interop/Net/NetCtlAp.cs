// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Net;

/// <summary>Where the access-point runtime is in its softAP lifecycle.</summary>
public enum NetCtlApState
{
    /// <summary>The access point is not running.</summary>
    Stopped = 0,

    /// <summary>A start request has been accepted; the runtime is waiting to begin.</summary>
    Waiting = 1,

    /// <summary>The wireless access point is being brought up.</summary>
    ApStarting = 2,

    /// <summary>The LAN side of the access point is being configured.</summary>
    LanSetting = 3,

    /// <summary>The access point is running and accepting client associations.</summary>
    Started = 4,
}

/// <summary>
/// The read-back block <see cref="NetCtlAp.sceNetCtlApGetInfo"/> fills for the running access point:
/// BSSID, SSID, channel, wireless security kind, DHCP state, and the IPv4 address and mask the
/// service is handing out.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 152)]
public unsafe struct SceNetCtlApInfo
{
    /// <summary>The size of this structure, filled by the caller before the call. Offset 0.</summary>
    public nuint Size;

    /// <summary>The BSSID the access point is broadcasting. Offset 8.</summary>
    public SceNetEtherAddr Bssid;

    /// <summary>The NUL-terminated SSID, up to thirty-two bytes plus a terminator. Offset 14.</summary>
    public fixed byte Ssid[33];

    /// <summary>The wireless channel the access point is using. Offset 47.</summary>
    public byte Channel;

    /// <summary>The wireless security kind, one of <see cref="NetCtlAp.WifiSecurityNoAuth"/> and friends. Offset 48.</summary>
    public uint WifiSecurity;

    /// <summary>Non-zero when the DHCP server is running on the access-point interface. Offset 52.</summary>
    public byte DhcpsEnabled;

    /// <summary>The NUL-terminated dotted-quad IPv4 address of the access-point interface. Offset 53.</summary>
    public fixed byte IpAddress[16];

    /// <summary>The NUL-terminated dotted-quad IPv4 netmask of the access-point interface. Offset 69.</summary>
    public fixed byte Netmask[16];

    /// <summary>Sixty-four bytes reserved for the service and read back as sixteen thirty-two-bit words. Offset 88.</summary>
    public fixed uint Reserved[16];
}

/// <summary>
/// The block <see cref="NetCtlAp.sceNetCtlApGetConnectInfo"/> fills describing the credentials a
/// client should present to join the access point: the SSID, the wireless security kind, and the
/// pre-shared key.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 184)]
public unsafe struct SceNetCtlApConnectInfo
{
    /// <summary>The size of this structure, filled by the caller before the call. Offset 0.</summary>
    public nuint Size;

    /// <summary>The NUL-terminated SSID a client sees. Offset 8.</summary>
    public fixed byte Ssid[33];

    /// <summary>The wireless security kind, one of <see cref="NetCtlAp.WifiSecurityNoAuth"/> and friends. Offset 44.</summary>
    public uint WifiSecurity;

    /// <summary>The NUL-terminated pre-shared key, up to sixty-four bytes plus a terminator. Offset 48.</summary>
    public fixed byte WifiSecurityKey[65];

    /// <summary>Sixty-four bytes reserved for the service and read back as sixteen thirty-two-bit words. Offset 116.</summary>
    public fixed uint Reserved[16];
}

/// <summary>
/// Access-point control bindings. The runtime brings a softAP up on the wireless interface so a
/// client can associate to the console; a caller starts the flow through the dialog, reads back
/// the access-point's own state and the credentials it publishes, receives callbacks when the
/// state changes, and tears the access point down.
/// </summary>
public static unsafe partial class NetCtlAp
{
    private const string Lib = "libSceNetCtlAp";

    /// <summary>The size the caller writes into <see cref="SceNetCtlApInfo.Size"/> before the call.</summary>
    public const int InfoSize = 152;

    /// <summary>The size the caller writes into <see cref="SceNetCtlApConnectInfo.Size"/> before the call.</summary>
    public const int ConnectInfoSize = 184;

    /// <summary>The longest SSID the runtime accepts, excluding the terminator.</summary>
    public const int SsidLen = 32;

    /// <summary>The longest pre-shared key the runtime accepts, excluding the terminator.</summary>
    public const int WifiSecurityKeyLen = 64;

    /// <summary>The length of the IPv4 address string field, including the terminator.</summary>
    public const int Ipv4AddrStrLen = 16;

    /// <summary>The longest option string the runtime accepts, excluding the terminator.</summary>
    public const int OptStrLen = 8;

    /// <summary>The maximum number of callbacks that may be registered at once.</summary>
    public const int CallbackMax = 8;

    /// <summary>The value the runtime writes into a callback id that has not been claimed.</summary>
    public const int InvalidCid = -1;

    // The event types delivered to a registered callback.
    public const int EventTypeStopped = 1;
    public const int EventTypeStartReqFinished = 2;
    public const int EventTypeStopReqFinished = 3;
    public const int EventTypeStarted = 4;

    // The wireless security kinds the access point may publish.
    public const int WifiSecurityNoAuth = 0;
    public const int WifiSecurityWep = 1;
    public const int WifiSecurityReserved01 = 2;
    public const int WifiSecurityWpaPskTkip = 3;
    public const int WifiSecurityWpaPskAes = 4;
    public const int WifiSecurityWpa2PskTkip = 5;
    public const int WifiSecurityWpa2PskAes = 6;
    public const int WifiSecurityWpa3Sae = 7;
    public const int WifiSecurityWpa2Wpa3 = 8;

    /// <summary>A call was made before the access point was started.</summary>
    public const int ErrorNotStarted = unchecked((int)0x8041298F);

    /// <summary>A caller passed an event type the runtime does not know.</summary>
    public const int ErrorInvalidType = unchecked((int)0x80412990);

    /// <summary>A caller passed a null or unreadable pointer.</summary>
    public const int ErrorInvalidAddr = unchecked((int)0x80412991);

    /// <summary>The client role tried to join an access point on a channel that conflicts with the softAP.</summary>
    public const int ErrorChannelConflict = unchecked((int)0x80412992);

    /// <summary>An operation was cancelled because <see cref="sceNetCtlApStop"/> was called.</summary>
    public const int ErrorStopReq = unchecked((int)0x80412993);

    /// <summary>A call was made before <see cref="sceNetCtlApInit"/> ran.</summary>
    public const int ErrorNotInitialized = unchecked((int)0x80412994);

    /// <summary>The registration would exceed <see cref="CallbackMax"/> live callbacks.</summary>
    public const int ErrorCallbackMax = unchecked((int)0x80412995);

    /// <summary>A caller passed a callback id the runtime does not know.</summary>
    public const int ErrorInvalidId = unchecked((int)0x80412996);

    /// <summary>The callback id the caller passed has no live registration.</summary>
    public const int ErrorIdNotFound = unchecked((int)0x80412997);

    /// <summary>The size field of the structure the caller passed is not the expected value.</summary>
    public const int ErrorInvalidSize = unchecked((int)0x80412998);

    /// <summary>The option string the caller passed is not one the runtime accepts.</summary>
    public const int ErrorInvalidOptStr = unchecked((int)0x80412901);

    /// <summary>The access point was stopped by the system because the application was suspended.</summary>
    public const int ErrorAppProcessSuspend = unchecked((int)0x80412902);

    /// <summary>The address the client role tried to assign collides with the access-point LAN.</summary>
    public const int ErrorIpAddrConflict = unchecked((int)0x80412903);

    /// <summary>The frequency band the client role is using conflicts with the access-point band.</summary>
    public const int ErrorFreqBandConflict = unchecked((int)0x80412904);

    /// <summary>
    /// Starts the access-point control service. This runs before any other call in this class. Zero
    /// on success, or a negative error code.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApInit();

    /// <summary>Stops the access-point control service.</summary>
    [LibraryImport(Lib)]
    public static partial void sceNetCtlApTerm();

    /// <summary>
    /// Delivers any pending events to the callbacks registered on this thread. Callbacks fire from
    /// the thread that runs this call, so an application drives the check itself.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApCheckCallback();

    /// <summary>Clears the last-known result the runtime holds for the given event type.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApClearEvent(int eventType);

    /// <summary>
    /// Registers a callback that fires when the access-point state changes. Zero on success; the
    /// slot the callback took is written into <paramref name="cid"/> for later unregistration.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApRegisterCallback(
        delegate* unmanaged[Cdecl]<int, void*, void> func,
        void* arg,
        int* cid);

    /// <summary>Removes a callback registered with <see cref="sceNetCtlApRegisterCallback"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApUnregisterCallback(int cid);

    /// <summary>
    /// Reads the error code that accompanies the most recent callback event of the given type.
    /// Called from inside a callback body to learn why the state changed.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApGetResult(int eventType, int* errorCode);

    /// <summary>
    /// Reads the running access-point block into <paramref name="info"/>. The caller writes
    /// <see cref="InfoSize"/> into <see cref="SceNetCtlApInfo.Size"/> before the call.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApGetInfo(SceNetCtlApInfo* info);

    /// <summary>Reads the current access-point state into <paramref name="state"/> (a <see cref="NetCtlApState"/>).</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApGetState(int* state);

    /// <summary>Brings the running access point down.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApStop();

    /// <summary>
    /// Reads the credentials a client should present to join the access point. The
    /// <paramref name="optStr"/> parameter names the credential set the caller wants; the caller
    /// writes <see cref="ConnectInfoSize"/> into <see cref="SceNetCtlApConnectInfo.Size"/> before
    /// the call.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetCtlApGetConnectInfo(byte* optStr, SceNetCtlApConnectInfo* connectInfo);
}
