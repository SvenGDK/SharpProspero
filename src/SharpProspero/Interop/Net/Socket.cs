// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Net;

/// <summary>An IPv4 socket address. The port and address are held in network byte order.</summary>
/// <remarks>
/// The layout matches the service's <c>sockaddr_in</c>: a length byte, a family byte, a port, the
/// address, a virtual port, then padding, sixteen bytes in all. The higher-level
/// <see cref="Platform.SocketAddress"/> fills and reads it, so callers rarely touch it directly.
/// </remarks>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetSockaddrIn
{
    /// <summary>The length of this address, sixteen.</summary>
    public byte Len;

    /// <summary>The address family, <see cref="Socket.AfInet"/> for IPv4.</summary>
    public byte Family;

    /// <summary>The port, in network byte order.</summary>
    public ushort Port;

    /// <summary>The IPv4 address, in network byte order.</summary>
    public uint Addr;

    /// <summary>The virtual port, zero for an ordinary socket.</summary>
    public ushort VPort;

    private fixed byte _zero[6];
}

/// <summary>A generic socket address, the sixteen-byte form the send and receive calls take.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetSockaddr
{
    /// <summary>The length of this address.</summary>
    public byte Len;

    /// <summary>The address family.</summary>
    public byte Family;

    private fixed byte _data[14];
}

/// <summary>A single IPv6 address, held as its sixteen-byte network-byte-order value.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetIn6Addr
{
    /// <summary>The address bytes, in network byte order.</summary>
    public fixed byte S6Addr[16];
}

/// <summary>A pointer/length pair passed to the scatter/gather send and receive calls.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetIovec
{
    /// <summary>The buffer.</summary>
    public void* Base;

    /// <summary>Its length.</summary>
    public nuint Length;
}

/// <summary>The message the scatter/gather send and receive calls take.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetMsghdr
{
    /// <summary>An optional address (for a datagram) or null.</summary>
    public void* Name;

    /// <summary>The length of the address.</summary>
    public uint NameLen;

    /// <summary>The scatter/gather list.</summary>
    public SceNetIovec* Iov;

    /// <summary>How many entries the list has.</summary>
    public int IovLen;

    /// <summary>Ancillary data, or null.</summary>
    public void* Control;

    /// <summary>Its length.</summary>
    public uint ControlLen;

    /// <summary>Flags reported by the receive path.</summary>
    public int Flags;
}

/// <summary>The pair of DNS server addresses the resolver falls back to when none are learnt.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceNetDnsInfo
{
    /// <summary>The primary DNS server, in network byte order.</summary>
    public SceNetInAddr Primary;

    /// <summary>The secondary DNS server, in network byte order.</summary>
    public SceNetInAddr Secondary;
}

/// <summary>The state of one memory pool.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceNetMemoryPoolStats
{
    /// <summary>The pool size, in bytes.</summary>
    public nuint PoolSize;

    /// <summary>The most bytes ever in use since the pool was created.</summary>
    public nuint MaxInuseSize;

    /// <summary>The bytes in use now.</summary>
    public nuint CurrentInuseSize;

    /// <summary>Reserved.</summary>
    public int Reserved;
}

/// <summary>Byte counters for the active interface.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetInterfaceStats
{
    /// <summary>Bytes sent since the interface came up.</summary>
    public ulong TxBytes;

    /// <summary>Bytes received since the interface came up.</summary>
    public ulong RxBytes;

    private fixed uint _reserved[12];
}

/// <summary>Coarse counters for the network stack.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceNetStatisticsInfo
{
    /// <summary>Bytes still available in the kernel network pool.</summary>
    public int KernelMemFreeSize;

    /// <summary>The smallest that kernel-side value has ever been.</summary>
    public int KernelMemFreeMin;

    /// <summary>Packets outstanding in the kernel.</summary>
    public int PacketCount;

    /// <summary>Packets outstanding in the QoS queues.</summary>
    public int PacketQosCount;

    /// <summary>Bytes still available in the library pool.</summary>
    public int LibnetMemFreeSize;

    /// <summary>The smallest that library-side value has ever been.</summary>
    public int LibnetMemFreeMin;
}

/// <summary>Per-socket detail the network stack reports.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetSockInfo
{
    /// <summary>The debug name, null-terminated.</summary>
    public fixed byte Name[32];

    /// <summary>The owning process id.</summary>
    public int Pid;

    /// <summary>The socket id.</summary>
    public int S;

    /// <summary>The socket type (stream, datagram, and so on).</summary>
    public sbyte SocketType;

    /// <summary>The traffic policy set for the socket.</summary>
    public sbyte Policy;

    /// <summary>The priority set for the socket.</summary>
    public sbyte Priority;

    private sbyte _reserved8;

    /// <summary>Bytes waiting to be read.</summary>
    public int RecvQueueLength;

    /// <summary>Bytes queued for send.</summary>
    public int SendQueueLength;

    /// <summary>The local address bound to the socket.</summary>
    public SceNetInAddr LocalAdr;

    /// <summary>The remote address the socket is connected to.</summary>
    public SceNetInAddr RemoteAdr;

    /// <summary>The local port.</summary>
    public ushort LocalPort;

    /// <summary>The remote port.</summary>
    public ushort RemotePort;

    /// <summary>The local virtual port.</summary>
    public ushort LocalVPort;

    /// <summary>The remote virtual port.</summary>
    public ushort RemoteVPort;

    /// <summary>The connection state, one of the SCE_NET_SOCKINFO_STATE_* values.</summary>
    public int State;

    /// <summary>The status bits, a combination of the SCE_NET_SOCKINFO_F_* values.</summary>
    public int Flags;

    /// <summary>Send-side throughput, bits per second.</summary>
    public int TxBps;

    /// <summary>Receive-side throughput, bits per second.</summary>
    public int RxBps;

    /// <summary>The largest send-side throughput observed.</summary>
    public int MaxTxBps;

    /// <summary>The largest receive-side throughput observed.</summary>
    public int MaxRxBps;

    /// <summary>Send-side throughput on the virtual port.</summary>
    public int TxVBps;

    /// <summary>Receive-side throughput on the virtual port.</summary>
    public int RxVBps;

    /// <summary>The receive buffer size, in bytes.</summary>
    public int RecvBufferSize;

    /// <summary>The send buffer size, in bytes.</summary>
    public int SendBufferSize;

    private fixed int _reserved6[8];

    /// <summary>Send-side drops.</summary>
    public int TxDrops;

    /// <summary>Receive-side drops.</summary>
    public int RxDrops;

    /// <summary>The count of threads waiting to send on this socket.</summary>
    public int TxWait;

    private fixed int _reserved[2];
}

/// <summary>Per-socket detail for a socket that may hold an IPv4 or an IPv6 address.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetSockInfo6
{
    /// <summary>The debug name, null-terminated.</summary>
    public fixed byte Name[32];

    /// <summary>The owning process id.</summary>
    public int Pid;

    /// <summary>The socket id.</summary>
    public int S;

    /// <summary>The socket type (stream, datagram, and so on).</summary>
    public sbyte SocketType;

    /// <summary>The traffic policy set for the socket.</summary>
    public sbyte Policy;

    /// <summary>The priority set for the socket.</summary>
    public sbyte Priority;

    private sbyte _reserved8;

    /// <summary>Bytes waiting to be read.</summary>
    public int RecvQueueLength;

    /// <summary>Bytes queued for send.</summary>
    public int SendQueueLength;

    /// <summary>The local IPv4 address if the socket is IPv4-only.</summary>
    public SceNetInAddr LocalAdr;

    /// <summary>The remote IPv4 address if the socket is IPv4-only.</summary>
    public SceNetInAddr RemoteAdr;

    /// <summary>The local port.</summary>
    public ushort LocalPort;

    /// <summary>The remote port.</summary>
    public ushort RemotePort;

    /// <summary>The local virtual port.</summary>
    public ushort LocalVPort;

    /// <summary>The remote virtual port.</summary>
    public ushort RemoteVPort;

    /// <summary>The connection state, one of the SCE_NET_SOCKINFO_STATE_* values.</summary>
    public int State;

    /// <summary>The status bits, a combination of the SCE_NET_SOCKINFO_F_* values.</summary>
    public int Flags;

    /// <summary>Send-side throughput, bits per second.</summary>
    public int TxBps;

    /// <summary>Receive-side throughput, bits per second.</summary>
    public int RxBps;

    /// <summary>The largest send-side throughput observed.</summary>
    public int MaxTxBps;

    /// <summary>The largest receive-side throughput observed.</summary>
    public int MaxRxBps;

    /// <summary>Send-side throughput on the virtual port.</summary>
    public int TxVBps;

    /// <summary>Receive-side throughput on the virtual port.</summary>
    public int RxVBps;

    /// <summary>The receive buffer size, in bytes.</summary>
    public int RecvBufferSize;

    /// <summary>The send buffer size, in bytes.</summary>
    public int SendBufferSize;

    /// <summary>The local IPv6 address.</summary>
    public SceNetIn6Addr LocalAdr6;

    /// <summary>The remote IPv6 address.</summary>
    public SceNetIn6Addr RemoteAdr6;

    /// <summary>Send-side drops.</summary>
    public int TxDrops;

    /// <summary>Receive-side drops.</summary>
    public int RxDrops;

    /// <summary>The count of threads waiting to send on this socket.</summary>
    public int TxWait;

    private fixed int _reserved[2];
}

/// <summary>An address record the resolver's connect helper carries: either an IPv4 or an IPv6 address.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
public unsafe struct SceNetResolverAddrExUn
{
    /// <summary>The IPv4 address.</summary>
    [FieldOffset(0)] public SceNetInAddr Addr;

    /// <summary>The IPv6 address.</summary>
    [FieldOffset(0)] public SceNetIn6Addr Addr6;
}

/// <summary>One address the resolver found, tagged with its family.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetResolverAddrEx
{
    /// <summary>The address.</summary>
    public SceNetResolverAddrExUn Un;

    /// <summary>The address family: <see cref="Socket.AfInet"/> or <see cref="Socket.AfInet6"/>.</summary>
    public int Af;

    private fixed int _reserved[3];
}

/// <summary>The full set of addresses the resolver found for one name.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetResolverInfoEx
{
    /// <summary>The addresses. <see cref="Records"/> gives how many are valid.</summary>
    public SceNetResolverAddrEx Addr0;
    public SceNetResolverAddrEx Addr1;
    public SceNetResolverAddrEx Addr2;
    public SceNetResolverAddrEx Addr3;
    public SceNetResolverAddrEx Addr4;
    public SceNetResolverAddrEx Addr5;
    public SceNetResolverAddrEx Addr6;
    public SceNetResolverAddrEx Addr7;
    public SceNetResolverAddrEx Addr8;
    public SceNetResolverAddrEx Addr9;

    /// <summary>How many entries in the address list are valid.</summary>
    public int Records;

    /// <summary>How many of them are IPv4.</summary>
    public int Dns4Records;

    /// <summary>How many of them are IPv6.</summary>
    public int Dns6Records;

    /// <summary>The IPv6 resolver id used, when both were consulted.</summary>
    public int Rid6;

    private fixed int _reserved[12];
}

/// <summary>The state block the resolver's connect helper fills and passes forward.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetResolverConnectInfo
{
    /// <summary>The resolved-name records.</summary>
    public SceNetResolverInfoEx Info;

    private fixed int _reserved1[10];
    private fixed int _reserved2[6];

    /// <summary>The IPv4 socket the helper opened.</summary>
    public int S4;

    /// <summary>The IPv6 socket the helper opened.</summary>
    public int S6;

    /// <summary>The memory pool used.</summary>
    public int MemId;

    /// <summary>The IPv4 resolver id.</summary>
    public int Rid;

    /// <summary>The poller id.</summary>
    public int Eid;

    /// <summary>The address the helper picked from the list.</summary>
    public int Index;

    /// <summary>Bits describing the helper's state.</summary>
    public int Flags;

    /// <summary>The IPv6 resolver id.</summary>
    public int Rid6;

    private fixed int _reserved[4];
}

/// <summary>The timeouts and flags <see cref="Resolver.sceNetResolverConnect"/> follows.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceNetResolverConnectParam
{
    /// <summary>The connect timeout, in microseconds.</summary>
    public int ConnectTimeout;

    /// <summary>The name-resolution timeout, in microseconds.</summary>
    public int Timeout;

    /// <summary>How many times name resolution is retried.</summary>
    public int Retry;

    /// <summary>Flags.</summary>
    public int Flags;

    private fixed int _reserved[4];
}

/// <summary>The user cookie carried alongside a readiness event.</summary>
[StructLayout(LayoutKind.Explicit, Size = 8)]
public unsafe struct SceNetEpollData
{
    /// <summary>The cookie as a pointer.</summary>
    [FieldOffset(0)] public void* Ptr;

    /// <summary>The cookie as a 32-bit value.</summary>
    [FieldOffset(0)] public uint U32;

    /// <summary>The cookie as a 64-bit value.</summary>
    [FieldOffset(0)] public ulong U64;

    /// <summary>The cookie as a socket id.</summary>
    [FieldOffset(0)] public int Fd;
}

/// <summary>One readiness event reported by the poller: which events fired and the cookie for the socket.</summary>
/// <remarks>
/// Twenty-four bytes, not sixteen. The identifier between the padding and the cookie is easy to miss
/// and costly to omit: leaving it out puts the cookie eight bytes early, so every cookie read back is
/// the wrong half of the record, and the poller filling a caller's array writes eight bytes past each
/// entry it was given room for - past the end of the array on the last one.
/// </remarks>
[StructLayout(LayoutKind.Sequential)]
public struct SceNetEpollEvent
{
    /// <summary>The events that fired, a combination of <see cref="Socket.EpollIn"/> and the others.</summary>
    public uint Events;

    private uint _pad;

    /// <summary>What the event is about, reported by the poller.</summary>
    public ulong Ident;

    /// <summary>The cookie registered for the socket.</summary>
    public SceNetEpollData Data;
}

/// <summary>
/// Socket bindings: create sockets, connect or listen and accept, send and receive, and multiplex many
/// sockets in one thread through the poller. The address family is IPv4. These calls return a
/// non-negative value on success and a negative value on failure; on failure the per-thread error is
/// available through <see cref="sceNetErrnoLoc"/>. The higher-level wrappers in
/// <see cref="Platform"/> present a friendlier surface over these.
/// </summary>
public static unsafe partial class Socket
{
    private const string Lib = "libSceNet";

    /// <summary>The IPv4 address family.</summary>
    public const int AfInet = 2;

    /// <summary>The IPv6 address family.</summary>
    public const int AfInet6 = 28;

    /// <summary>A reliable byte-stream socket (TCP).</summary>
    public const int SockStream = 1;

    /// <summary>A datagram socket (UDP).</summary>
    public const int SockDgram = 2;

    /// <summary>A raw socket.</summary>
    public const int SockRaw = 3;

    /// <summary>A peer-to-peer datagram socket.</summary>
    public const int SockDgramP2p = 6;

    /// <summary>A peer-to-peer stream socket.</summary>
    public const int SockStreamP2p = 10;

    /// <summary>The IP protocol group.</summary>
    public const int IpProtoIp = 0;

    /// <summary>The ICMP protocol.</summary>
    public const int IpProtoIcmp = 1;

    /// <summary>The IGMP protocol.</summary>
    public const int IpProtoIgmp = 2;

    /// <summary>The TCP protocol.</summary>
    public const int IpProtoTcp = 6;

    /// <summary>The UDP protocol.</summary>
    public const int IpProtoUdp = 17;

    /// <summary>The socket-level option group.</summary>
    public const int SolSocket = 0xffff;

    /// <summary>Option: allow a local address to be reused right away.</summary>
    public const int SoReuseAddr = 0x00000004;

    /// <summary>Option: keep an idle connection alive.</summary>
    public const int SoKeepAlive = 0x00000008;

    /// <summary>Option: allow broadcast datagrams.</summary>
    public const int SoBroadcast = 0x00000020;

    /// <summary>Option: linger on close.</summary>
    public const int SoLinger = 0x00000080;

    /// <summary>Option: allow multiple listeners to share the same address and port.</summary>
    public const int SoReusePort = 0x00000200;

    /// <summary>Option: the send buffer size.</summary>
    public const int SoSndBuf = 0x1001;

    /// <summary>Option: the receive buffer size.</summary>
    public const int SoRcvBuf = 0x1002;

    /// <summary>Option: the pending error, cleared by reading it.</summary>
    public const int SoError = 0x1007;

    /// <summary>Option: the socket type as an integer.</summary>
    public const int SoType = 0x1008;

    /// <summary>Option: the send timeout, in microseconds.</summary>
    public const int SoSndTimeo = 0x1105;

    /// <summary>Option: the receive timeout, in microseconds.</summary>
    public const int SoRcvTimeo = 0x1106;

    /// <summary>Option: the extended per-socket error.</summary>
    public const int SoErrorEx = 0x1107;

    /// <summary>Option: the accept timeout, in microseconds.</summary>
    public const int SoAcceptTimeo = 0x1108;

    /// <summary>Option: the connect timeout, in microseconds.</summary>
    public const int SoConnectTimeo = 0x1109;

    /// <summary>Option: non-blocking mode, a non-zero value to enable.</summary>
    public const int SoNbio = 0x1200;

    /// <summary>Option: the socket's traffic policy.</summary>
    public const int SoPolicy = 0x1201;

    /// <summary>Option: the socket's debug name.</summary>
    public const int SoName = 0x1202;

    /// <summary>Option: the socket's send priority.</summary>
    public const int SoPriority = 0x1203;

    /// <summary>Receive flag: read without removing the data from the queue.</summary>
    public const int MsgPeek = 0x00000002;

    /// <summary>Receive flag: fill the whole buffer.</summary>
    public const int MsgWaitAll = 0x00000040;

    /// <summary>Send or receive flag: do not block.</summary>
    public const int MsgDontWait = 0x00000080;

    /// <summary>Shutdown selector: further receives.</summary>
    public const int ShutRd = 0;

    /// <summary>Shutdown selector: further sends.</summary>
    public const int ShutWr = 1;

    /// <summary>Shutdown selector: both directions.</summary>
    public const int ShutRdWr = 2;

    /// <summary>Abort flag: keep the receive queue when the abort completes.</summary>
    public const int SocketAbortFlagRcvPreservation = 0x00000001;

    /// <summary>Abort flag: keep the send queue when the abort completes.</summary>
    public const int SocketAbortFlagSndPreservation = 0x00000002;

    /// <summary>Abort flag: apply the send-queue preservation again on the next abort.</summary>
    public const int SocketAbortFlagSndPreservationAgain = 0x00000004;

    /// <summary>Sock-info state: unknown.</summary>
    public const int SockInfoStateUnknown = 0;

    /// <summary>Sock-info state: closed.</summary>
    public const int SockInfoStateClosed = 1;

    /// <summary>Sock-info state: opened.</summary>
    public const int SockInfoStateOpened = 2;

    /// <summary>Sock-info state: listen.</summary>
    public const int SockInfoStateListen = 3;

    /// <summary>Sock-info state: SYN sent.</summary>
    public const int SockInfoStateSynSent = 4;

    /// <summary>Sock-info state: SYN received.</summary>
    public const int SockInfoStateSynReceived = 5;

    /// <summary>Sock-info state: established.</summary>
    public const int SockInfoStateEstablished = 6;

    /// <summary>Sock-info state: fin-wait-1.</summary>
    public const int SockInfoStateFinWait1 = 7;

    /// <summary>Sock-info state: fin-wait-2.</summary>
    public const int SockInfoStateFinWait2 = 8;

    /// <summary>Sock-info state: close-wait.</summary>
    public const int SockInfoStateCloseWait = 9;

    /// <summary>Sock-info state: closing.</summary>
    public const int SockInfoStateClosing = 10;

    /// <summary>Sock-info state: last-ack.</summary>
    public const int SockInfoStateLastAck = 11;

    /// <summary>Sock-info state: time-wait.</summary>
    public const int SockInfoStateTimeWait = 12;

    /// <summary>Sock-info flag: the socket belongs to the current process.</summary>
    public const int SockInfoFSelf = 0x00000001;

    /// <summary>Sock-info flag: the socket belongs to the kernel.</summary>
    public const int SockInfoFKernel = 0x00000002;

    /// <summary>Sock-info flag: the socket belongs to another process.</summary>
    public const int SockInfoFOthers = 0x00000004;

    /// <summary>Sock-info flag: a thread is blocked on receive.</summary>
    public const int SockInfoFRecvWait = 0x00010000;

    /// <summary>Sock-info flag: a thread is blocked on send.</summary>
    public const int SockInfoFSendWait = 0x00020000;

    /// <summary>Sock-info flag: an error-marked receive is pending.</summary>
    public const int SockInfoFRecvEwait = 0x00040000;

    /// <summary>Sock-info flag: an error-marked send is pending.</summary>
    public const int SockInfoFSendEwait = 0x00080000;

    /// <summary>Sock-info flag: the socket is in non-blocking mode.</summary>
    public const int SockInfoFNonblock = 0x00200000;

    /// <summary>Sock-info flag: the socket is disabled.</summary>
    public const int SockInfoFDisabled = 0x00800000;

    /// <summary>Sock-info flag: the socket is suspended.</summary>
    public const int SockInfoFSuspended = 0x01000000;

    /// <summary>Sock-info flag: the socket is closed.</summary>
    public const int SockInfoFClosed = 0x02000000;

    /// <summary>Sock-info flag: the socket holds an IPv6 endpoint.</summary>
    public const int SockInfoFIpv6 = 0x00400000;

    /// <summary>Sock-info request flag: also list sockets in the TIME_WAIT state.</summary>
    public const int SockInfoTimeWait = 0x00000040;

    /// <summary>Sock-info-6 request flag: report both IPv4 and IPv6 sockets.</summary>
    public const int SockInfo6Ipv46 = 0x00001000;

    /// <summary>Poller readiness: readable, or a pending connection on a listening socket.</summary>
    public const uint EpollIn = 0x00000001;

    /// <summary>Poller readiness: writable, or a completed connect.</summary>
    public const uint EpollOut = 0x00000002;

    /// <summary>Poller readiness: an error occurred.</summary>
    public const uint EpollErr = 0x00000008;

    /// <summary>Poller readiness: the peer hung up.</summary>
    public const uint EpollHup = 0x00000010;

    /// <summary>Poller readiness: this event carries a descriptor id (used by the resolver).</summary>
    public const uint EpollDescId = 0x00010000;

    /// <summary>Poller operation: add a socket to the set.</summary>
    public const int EpollCtlAdd = 1;

    /// <summary>Poller operation: change a socket's interest.</summary>
    public const int EpollCtlMod = 2;

    /// <summary>Poller operation: remove a socket from the set.</summary>
    public const int EpollCtlDel = 3;

    /// <summary>Creates a socket. <paramref name="name"/> is a label for diagnostics.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetSocket(string name, int domain, int type, int protocol);

    /// <summary>Binds a socket to a local address.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetBind(int s, SceNetSockaddr* addr, uint addrlen);

    /// <summary>Puts a stream socket into the listening state with the given accept backlog.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetListen(int s, int backlog);

    /// <summary>Accepts one pending connection, returning a new socket id. The peer address may be null.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetAccept(int s, SceNetSockaddr* addr, uint* addrlen);

    /// <summary>Connects a socket to a remote address.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetConnect(int s, SceNetSockaddr* name, uint namelen);

    /// <summary>Sends on a connected socket, returning the number of bytes sent.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSend(int s, void* msg, nuint len, int flags);

    /// <summary>Sends a datagram to an explicit destination.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSendto(int s, void* msg, nuint len, int flags, SceNetSockaddr* to, uint tolen);

    /// <summary>Sends a scatter/gather message. The caller fills <see cref="SceNetMsghdr"/> and passes its pointer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSendmsg(int s, SceNetMsghdr* msg, int flags);

    /// <summary>Receives on a connected socket; returns the byte count, or zero at an orderly close.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetRecv(int s, void* buf, nuint len, int flags);

    /// <summary>Receives a datagram and reports the sender address.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetRecvfrom(int s, void* buf, nuint len, int flags, SceNetSockaddr* from, uint* fromlen);

    /// <summary>Receives a scatter/gather message. The caller fills <see cref="SceNetMsghdr"/> and passes its pointer.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetRecvmsg(int s, SceNetMsghdr* msg, int flags);

    /// <summary>Closes a socket.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSocketClose(int s);

    /// <summary>Half- or fully closes a connection; <paramref name="how"/> selects the direction.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetShutdown(int s, int how);

    /// <summary>Cancels a blocking call on a socket so it can be closed promptly.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSocketAbort(int s, int flags);

    /// <summary>Sets a socket option.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSetsockopt(int s, int level, int optname, void* optval, uint optlen);

    /// <summary>Reads a socket option.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetsockopt(int s, int level, int optname, void* optval, uint* optlen);

    /// <summary>Reads the local address a socket is bound to.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetsockname(int s, SceNetSockaddr* name, uint* namelen);

    /// <summary>Reads the remote address of a connected socket.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetpeername(int s, SceNetSockaddr* name, uint* namelen);

    /// <summary>
    /// Reads out per-socket detail. <paramref name="info"/> points at an array of <paramref name="n"/>
    /// entries the call fills, and the return value is how many entries were written.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetSockInfo(int s, SceNetSockInfo* info, int n, int flags);

    /// <summary>
    /// Reads out per-socket detail for a socket that may hold an IPv4 or an IPv6 endpoint. The layout is
    /// wider than <see cref="SceNetSockInfo"/>: it carries the IPv6 addresses in place.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetSockInfo6(int s, SceNetSockInfo6* info, int n, int flags);

    /// <summary>Returns the per-thread error pointer read after a socket call fails.</summary>
    [LibraryImport(Lib)]
    public static partial int* sceNetErrnoLoc();

    /// <summary>Creates a poller instance, returning its id.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetEpollCreate(string name, int flags);

    /// <summary>Adds, changes or removes a socket in the poller set.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetEpollControl(int eid, int op, int id, SceNetEpollEvent* @event);

    /// <summary>Waits for readiness; returns the number of events written to <paramref name="events"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetEpollWait(int eid, SceNetEpollEvent* events, int maxevents, int timeout);

    /// <summary>Destroys a poller instance.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetEpollDestroy(int eid);

    /// <summary>Unblocks a thread waiting in the poller so a server can shut down cleanly.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetEpollAbort(int eid, int flags);
}

/// <summary>
/// Ethernet-address helpers: the six-byte hardware address, its dotted string form, and the read of
/// the interface's own address.
/// </summary>
public static unsafe partial class Ether
{
    private const string Lib = "libSceNet";

    /// <summary>The number of bytes in an Ethernet address, six.</summary>
    public const int AddrLen = 6;

    /// <summary>The length of the dotted string form, including the terminator (eighteen).</summary>
    public const int AddrStrLen = 18;

    /// <summary>
    /// Parses a colon-separated MAC address, writing the six bytes into <paramref name="n"/>.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetEtherStrton(string str, SceNetEtherAddr* n);

    /// <summary>
    /// Formats a MAC address into colon-separated form. <paramref name="len"/> is the size of
    /// <paramref name="str"/> and must reach <see cref="AddrStrLen"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetEtherNtostr(SceNetEtherAddr* n, byte* str, nuint len);

    /// <summary>Reads the interface's own MAC address.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetMacAddress(SceNetEtherAddr* addr, int flags);
}

/// <summary>
/// IP-address helpers: parse and format the four- and sixteen-byte forms, and swap between host and
/// network byte order.
/// </summary>
public static unsafe partial class Inet
{
    private const string Lib = "libSceNet";

    /// <summary>The length of an IPv4 address in its dotted string form, including the terminator (sixteen).</summary>
    public const int InetAddrStrLen = 16;

    /// <summary>
    /// Formats an address into <paramref name="dst"/> in its family's canonical string form. Returns
    /// a pointer to the destination when it fits, or null when it does not.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial byte* sceNetInetNtop(int af, void* src, byte* dst, uint size);

    /// <summary>
    /// Parses an address in its family's canonical string form into <paramref name="dst"/>.
    /// Returns 1 on success, 0 on a parse failure, or a negative value on an internal error.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetInetPton(int af, string src, void* dst);

    /// <summary>Turns a thirty-two bit value from host byte order into network byte order.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceNetHtonl(uint host32);

    /// <summary>Turns a sixteen-bit value from host byte order into network byte order.</summary>
    [LibraryImport(Lib)]
    public static partial ushort sceNetHtons(ushort host16);

    /// <summary>Turns a thirty-two bit value from network byte order into host byte order.</summary>
    [LibraryImport(Lib)]
    public static partial uint sceNetNtohl(uint net32);

    /// <summary>Turns a sixteen-bit value from network byte order into host byte order.</summary>
    [LibraryImport(Lib)]
    public static partial ushort sceNetNtohs(ushort net16);
}

/// <summary>DNS bindings: point the resolver at a chosen server pair, or flush what the resolver has cached.</summary>
public static unsafe partial class NetDns
{
    private const string Lib = "libSceNet";

    /// <summary>The number of DNS server entries <see cref="SceNetDnsInfo"/> carries, two.</summary>
    public const int AddrMax = 2;

    /// <summary>Sets the primary and secondary DNS servers the resolver falls back to.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetSetDnsInfo(SceNetDnsInfo* info, int flags);

    /// <summary>Drops the resolver's DNS cache.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetClearDnsCache(int flags);
}

/// <summary>Network-side statistics: byte counters for the active interface and the state of a memory pool.</summary>
public static unsafe partial class NetStats
{
    private const string Lib = "libSceNet";

    /// <summary>Reads the byte counters for the active interface.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetInterfaceStats(SceNetInterfaceStats* stats, int flags);

    /// <summary>Reads the current, peak and total sizes of a memory pool.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetGetMemoryPoolStats(int memid, SceNetMemoryPoolStats* stat);
}

/// <summary>Resolver bindings: turn a host name into an IPv4 or IPv6 address. The resolver draws on a network pool.</summary>
public static unsafe partial class Resolver
{
    private const string Lib = "libSceNet";

    /// <summary>The longest host name the resolver accepts.</summary>
    public const int HostnameMax = 255;

    /// <summary>The most records one lookup returns.</summary>
    public const int MultipleRecordsMax = 10;

    /// <summary>The port the resolver contacts on the DNS server, 53.</summary>
    public const int Port = 53;

    /// <summary>Resolver-create flag: run the lookups asynchronously.</summary>
    public const int Async = 0x00000001;

    /// <summary>Resolver-start-ntoa flag: reject a request whose argument is already a numeric address.</summary>
    public const int StartNtoaDisableIpAddress = 0x00010000;

    /// <summary>Resolver-abort flag: keep any pending ntoa (forward) lookups.</summary>
    public const int AbortFlagNtoaPreservation = 0x00000001;

    /// <summary>Resolver-abort flag: keep any pending aton (reverse) lookups.</summary>
    public const int AbortFlagAtonPreservation = 0x00000002;

    /// <summary>Creates a resolver over a network pool, returning its id.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetResolverCreate(string name, int memId, int flags);

    /// <summary>Resolves an IPv4 host name to an address written into <paramref name="addr"/>.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetResolverStartNtoa(int rid, string hostname, uint* addr, int timeout, int retry, int flags);

    /// <summary>
    /// Reverse-resolves an IPv4 address, writing the name into <paramref name="hostname"/>.
    /// <paramref name="len"/> is the size of that buffer.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetResolverStartAton(int rid, SceNetInAddr* addr, byte* hostname, int len, int timeout, int retry, int flags);

    /// <summary>Resolves an IPv6 host name to an address written into <paramref name="addr"/>.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetResolverStartNtoa6(int rid, string hostname, SceNetIn6Addr* addr, int timeout, int retry, int flags);

    /// <summary>
    /// Reverse-resolves an IPv6 address, writing the name into <paramref name="hostname"/>.
    /// <paramref name="len"/> is the size of that buffer.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetResolverStartAton6(int rid, SceNetIn6Addr* addr, byte* hostname, int len, int timeout, int retry, int flags);

    /// <summary>
    /// Reads out the resolver's last error into <paramref name="result"/>. A negative return value
    /// says the read itself failed.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetResolverGetError(int rid, int* result);

    /// <summary>Destroys a resolver.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetResolverDestroy(int rid);

    /// <summary>Cancels any blocking lookups on a resolver so it can be closed promptly.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetResolverAbort(int rid, int flags);

    /// <summary>
    /// Resolves <paramref name="hostname"/> and returns a socket already connected to it on
    /// <paramref name="port"/>. <paramref name="rcinfo"/> was created by the corresponding create call
    /// and holds the state the helper walks. Returns the new socket id, or a negative value on failure.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetResolverConnect(SceNetResolverConnectInfo* rcinfo, string hostname, ushort port, SceNetResolverConnectParam* rcparam);
}
