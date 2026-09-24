// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop.Net;

namespace SharpProspero.Platform;

/// <summary>Sets socket options that the connection and listener wrappers expose in friendlier terms.</summary>
internal static unsafe class SocketOptions
{
    /// <summary>Sets a 32-bit socket option.</summary>
    public static void SetUInt(int socket, int level, int option, uint value) =>
        SocketError.Check(
            Socket.sceNetSetsockopt(socket, level, option, &value, sizeof(uint)),
            nameof(Socket.sceNetSetsockopt));

    /// <summary>Turns blocking mode on or off.</summary>
    public static void SetBlocking(int socket, bool blocking) =>
        SetUInt(socket, Socket.SolSocket, Socket.SoNbio, blocking ? 0u : 1u);

    /// <summary>Reads a 32-bit socket option.</summary>
    public static uint GetUInt(int socket, int level, int option)
    {
        uint value = 0;
        uint len = sizeof(uint);
        SocketError.Check(
            Socket.sceNetGetsockopt(socket, level, option, &value, &len),
            nameof(Socket.sceNetGetsockopt));
        return value;
    }

    /// <summary>Allows the local address to be reused immediately, so a server can restart without waiting.</summary>
    public static void SetReuseAddress(int socket, bool enabled) =>
        SetUInt(socket, Socket.SolSocket, Socket.SoReuseAddr, enabled ? 1u : 0u);
}
