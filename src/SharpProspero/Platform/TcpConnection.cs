// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Net;
using System;

namespace SharpProspero.Platform;

/// <summary>
/// One end of a TCP connection: send bytes, receive bytes, close. Get one by connecting to a server
/// with <see cref="Connect"/>, or by accepting a client on a <see cref="TcpListener"/>. Calls block by
/// default; switch to non-blocking with <see cref="Blocking"/> to drive it from a <see cref="SocketPoller"/>.
/// </summary>
/// <example>
/// <code>
/// using var conn = TcpConnection.Connect(SocketAddress.Parse("192.168.1.10", 80));
/// conn.SendAll("GET / HTTP/1.0\r\n\r\n"u8);
/// Span&lt;byte&gt; buffer = stackalloc byte[1024];
/// int read = conn.Receive(buffer);
/// </code>
/// </example>
public sealed unsafe class TcpConnection : IDisposable
{
    private int _socket;
    private bool _disposed;

    internal TcpConnection(int socket) => _socket = socket;

    /// <summary>The underlying socket id, for registering the connection with a <see cref="SocketPoller"/>.</summary>
    public int Handle => _socket;

    /// <summary>Opens a connection to <paramref name="address"/> and returns it once connected.</summary>
    /// <exception cref="ProsperoException">The socket could not be created or the connect failed.</exception>
    public static TcpConnection Connect(SocketAddress address)
    {
        int socket = SocketError.Check(
            Socket.sceNetSocket("sp_tcp", Socket.AfInet, Socket.SockStream, Socket.IpProtoTcp),
            nameof(Socket.sceNetSocket));

        SceNetSockaddrIn native = address.ToNative();
        int result = Socket.sceNetConnect(socket, (SceNetSockaddr*)&native, 16);
        if (result < 0)
        {
            // Capture the connect error before closing the socket, since the close would replace the
            // per-thread network error the exception reports.
            ProsperoException error = SocketError.Failure(result, nameof(Socket.sceNetConnect));
            Socket.sceNetSocketClose(socket);
            throw error;
        }
        return new TcpConnection(socket);
    }

    /// <summary>
    /// Creates a non-blocking TCP socket and starts connecting to <paramref name="address"/>. The
    /// connection may complete immediately on loopback, or remain in progress for a remote host.
    /// Register <see cref="Handle"/> in a <see cref="SocketPoller"/> for <see cref="PollEvents.Write"/>
    /// and call <see cref="GetSocketError"/> when it fires to confirm the outcome.
    /// </summary>
    /// <exception cref="ProsperoException">The socket could not be created, or the connect failed for a
    /// reason other than being in progress.</exception>
    public static TcpConnection BeginConnect(SocketAddress address)
    {
        int socket = SocketError.Check(
            Socket.sceNetSocket("sp_tcp", Socket.AfInet, Socket.SockStream, Socket.IpProtoTcp),
            nameof(Socket.sceNetSocket));

        SocketOptions.SetBlocking(socket, false);

        SceNetSockaddrIn native = address.ToNative();
        int result = Socket.sceNetConnect(socket, (SceNetSockaddr*)&native, 16);
        if (result < 0)
        {
            int err = SocketError.Last();
            // EINPROGRESS (36 on FreeBSD) is expected for a non-blocking connect.
            if (err != 36)
            {
                ProsperoException error = SocketError.Failure(result, nameof(Socket.sceNetConnect));
                Socket.sceNetSocketClose(socket);
                throw error;
            }
        }
        return new TcpConnection(socket);
    }

    /// <summary>
    /// Reads and clears the pending error on this socket. Returns zero when no error is pending, which
    /// after a non-blocking connect means the connection succeeded. A non-zero value is the error code.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The connection is disposed.</exception>
    public int GetSocketError()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (int)SocketOptions.GetUInt(_socket, Socket.SolSocket, Socket.SoError);
    }

    /// <summary>
    /// Sends up to the length of <paramref name="data"/> and returns how many bytes were accepted,
    /// which may be fewer than offered. Use <see cref="SendAll"/> to send everything.
    /// </summary>
    /// <exception cref="ProsperoException">The send failed.</exception>
    public int Send(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (data.IsEmpty)
            return 0;
        fixed (byte* p = data)
            return SocketError.Check(Socket.sceNetSend(_socket, p, (nuint)data.Length, 0), nameof(Socket.sceNetSend));
    }

    /// <summary>Sends every byte of <paramref name="data"/>, repeating until all of it is accepted.</summary>
    /// <exception cref="ProsperoException">The send failed.</exception>
    public void SendAll(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int sent = 0;
        while (sent < data.Length)
        {
            fixed (byte* p = data)
            {
                int n = SocketError.Check(
                    Socket.sceNetSend(_socket, p + sent, (nuint)(data.Length - sent), 0), nameof(Socket.sceNetSend));
                if (n == 0)
                    throw new ProsperoException(nameof(Socket.sceNetSend), 0);
                sent += n;
            }
        }
    }

    /// <summary>
    /// Receives into <paramref name="buffer"/> and returns the number of bytes read, or zero when the
    /// peer has closed the connection.
    /// </summary>
    /// <exception cref="ProsperoException">The receive failed.</exception>
    public int Receive(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.IsEmpty)
            return 0;
        fixed (byte* p = buffer)
            return SocketError.Check(Socket.sceNetRecv(_socket, p, (nuint)buffer.Length, 0), nameof(Socket.sceNetRecv));
    }

    /// <summary>Whether the connection blocks (the default) or returns immediately when no data is ready.</summary>
    /// <exception cref="ProsperoException">The mode could not be changed.</exception>
    public bool Blocking
    {
        set => SocketOptions.SetBlocking(_socket, value);
    }

    /// <summary>Sets the receive timeout, in microseconds; zero waits forever.</summary>
    /// <exception cref="ProsperoException">The option could not be set.</exception>
    public void SetReceiveTimeout(uint microseconds) =>
        SocketOptions.SetUInt(_socket, Socket.SolSocket, Socket.SoRcvTimeo, microseconds);

    /// <summary>The remote endpoint, or a zero address when it cannot be read.</summary>
    public SocketAddress RemoteAddress
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            SceNetSockaddrIn native = default;
            uint length = 16;
            if (Socket.sceNetGetpeername(_socket, (SceNetSockaddr*)&native, &length) < 0)
                return default;
            return SocketAddress.FromNative(native);
        }
    }

    /// <summary>Stops sends, receives, or both, without closing the socket.</summary>
    public void Shutdown(bool receives = true, bool sends = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int how = receives && sends ? Socket.ShutRdWr : sends ? Socket.ShutWr : Socket.ShutRd;
        Socket.sceNetShutdown(_socket, how);
    }

    /// <summary>Closes the connection.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_socket >= 0)
        {
            Socket.sceNetSocketClose(_socket);
            _socket = -1;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>Closes the socket if the connection was dropped without a <see cref="Dispose"/> call.</summary>
    ~TcpConnection() => Dispose();
}
