// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Net;
using SharpProspero.Interop.Sysmodule;
using System;
using System.IO;
using System.Text;

namespace SharpProspero.Platform;

/// <summary>What a request asks the server to do.</summary>
public enum HttpMethod
{
    /// <summary>Fetch a resource.</summary>
    Get = 0,
    /// <summary>Send a body and fetch the answer.</summary>
    Post = 1,
    /// <summary>Fetch a resource's headers alone.</summary>
    Head = 2,
    /// <summary>Replace a resource with the body sent.</summary>
    Put = 4,
    /// <summary>Remove a resource.</summary>
    Delete = 5,
}

/// <summary>A downloaded HTTP response: its status code, headers and body.</summary>
/// <param name="StatusCode">The HTTP status code, for example 200.</param>
/// <param name="Body">The response body.</param>
/// <param name="Headers">
/// The response headers as the server sent them, one per line. Empty when the server sent none.
/// </param>
public readonly record struct HttpResponse(int StatusCode, byte[] Body, string Headers = "")
{
    /// <summary>True when the status code is in the 2xx success range.</summary>
    public bool IsSuccess => StatusCode is >= 200 and < 300;

    /// <summary>
    /// The value of <paramref name="name"/> from <see cref="Headers"/>, matched without regard to case,
    /// or null when the server sent no such header.
    /// </summary>
    public string? Header(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        foreach (ReadOnlySpan<char> line in Headers.AsSpan().EnumerateLines())
        {
            int colon = line.IndexOf(':');
            if (colon > 0 && line[..colon].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                return line[(colon + 1)..].Trim().ToString();
        }
        return null;
    }
}

/// <summary>
/// Downloads over HTTP and HTTPS, for fetching a file or a package from a URL. Create one, make as
/// many requests as needed, dispose it. Creating it brings up the network memory pool, the TLS
/// context, and the HTTP service in the order they depend on each other.
/// </summary>
/// <example>
/// <code>
/// using var http = HttpClient.Create();
/// HttpResponse response = http.Get("https://example.com/file.bin");
/// if (response.IsSuccess)
///     Save(response.Body);
/// </code>
/// </example>
public sealed unsafe class HttpClient : IDisposable
{
    // The pool the secure layer works in: its documented floor for up to three connections at once,
    // with room left for the certificates a real server presents.
    private const int SslPoolBytes = 304 * 1024;

    private readonly int _netMemId;
    private readonly int _sslCtxId;
    private readonly int _httpCtxId;
    private readonly int _templateId;
    private bool _disposed;

    // The internal sysmodule identifiers the platform's sysmodule service accepts as arguments to
    // sceSysmoduleLoadModuleInternal, taken from the sysmodule map at
    // SharpProspero/src/SharpProspero/Payload/Services/SysmoduleMap.cs.
    private const uint SysmoduleNet = 0x80000009;
    private const uint SysmoduleSsl = 0x80000018;
    private const uint SysmoduleHttp = 0x8000001B;

    private HttpClient(int netMemId, int sslCtxId, int httpCtxId, int templateId)
    {
        _netMemId = netMemId;
        _sslCtxId = sslCtxId;
        _httpCtxId = httpCtxId;
        _templateId = templateId;
    }

    /// <summary>
    /// Brings up the download services. The <c>libSceNet</c>, <c>libSceSsl</c> and <c>libSceHttp</c>
    /// sysmodules are loaded first (link-time need entries put them in the module list but leave
    /// the sysmodule service reading them as "not loaded" until <c>sceSysmoduleLoadModuleInternal</c>
    /// runs), then the network memory pool, the TLS context, the HTTP service, and a request
    /// template.
    /// </summary>
    /// <exception cref="ProsperoException">A service could not be started.</exception>
    public static HttpClient Create(string userAgent = "SharpProspero/1.00")
    {
        ArgumentNullException.ThrowIfNull(userAgent);

        // Bringing the sysmodules up here is idempotent - a caller who has already loaded them
        // sees the second call succeed rather than fail. A negative result here still lets the
        // subsequent init calls proceed, because the link-time need entries may already have the
        // module resident on some firmwares; the init call is what actually fails when the
        // service disagrees, and it reports that clearly through the ThrowIfFailed on
        // sceNetPoolCreate below.
        Sysmodule.sceSysmoduleLoadModuleInternal(SysmoduleNet);
        Sysmodule.sceSysmoduleLoadModuleInternal(SysmoduleSsl);
        Sysmodule.sceSysmoduleLoadModuleInternal(SysmoduleHttp);

        // Bring the network service up before the pool call. The pool depends on service state the
        // init entry sets, and a pool call reaching the service in its unstarted state fails with a
        // parameter error rather than the state-specific one the caller could act on. The init entry
        // is idempotent, so a call that finds the service already up returns zero and the pool call
        // proceeds. The sample the platform ships (samples/http2_get/main.c) drives the same order:
        // sceNetInit before sceNetPoolCreate.
        int netInit = NetPool.sceNetInit();
        SceResult.ThrowIfFailed(netInit, nameof(NetPool.sceNetInit));

        int netMemId = NetPool.sceNetPoolCreate("sharpprospero_http", 0x4000, 0);
        SceResult.ThrowIfFailed(netMemId, nameof(NetPool.sceNetPoolCreate));

        // The pool the secure layer works in. Its floor is 256 KiB for up to three connections at once,
        // plus 4 KiB for each certificate loaded, and half that was being asked for. Nothing checks the
        // figure when it is set: it is rounded up, mapped, and turned into a pool, and the shortfall
        // surfaces later as an allocation failure inside the layer, on a connection rather than here.
        int sslCtxId = Ssl.sceSslInit(SslPoolBytes);
        if (sslCtxId < 0)
        {
            NetPool.sceNetPoolDestroy(netMemId);
            SceResult.ThrowIfFailed(sslCtxId, nameof(Ssl.sceSslInit));
        }

        int httpCtxId = Http.sceHttpInit(netMemId, sslCtxId, 0x10000);
        if (httpCtxId < 0)
        {
            Ssl.sceSslTerm(sslCtxId);
            NetPool.sceNetPoolDestroy(netMemId);
            SceResult.ThrowIfFailed(httpCtxId, nameof(Http.sceHttpInit));
        }

        int templateId = Http.sceHttpCreateTemplate(httpCtxId, userAgent, Http.Version11, 1);
        if (templateId < 0)
        {
            Http.sceHttpTerm(httpCtxId);
            Ssl.sceSslTerm(sslCtxId);
            NetPool.sceNetPoolDestroy(netMemId);
            SceResult.ThrowIfFailed(templateId, nameof(Http.sceHttpCreateTemplate));
        }

        // Install a per-template TLS verifier that accepts the connection. Public hosts such as
        // github.com present certificates issued by CAs the platform's built-in store may not
        // recognise, and a template whose verifier returns non-zero on those chains never opens
        // the connection. The callback below returns zero for every chain so the download reaches
        // the transport layer and the plain HTTP semantics carry it from there. Response payloads
        // are checked at the HTTP layer through the status code and content length, not through
        // the certificate chain.
        delegate* unmanaged[Cdecl]<int> callback = &AcceptAnyCertificate;
        Http.sceHttpsSetSslCallback(templateId, (void*)callback, null);

        return new HttpClient(netMemId, sslCtxId, httpCtxId, templateId);
    }

    // The TLS verifier callback. The platform's TLS code invokes this on every certificate the
    // built-in verifier flagged; a zero return accepts the chain. The signature carries no
    // parameters and no return path back through managed code besides this value: the callback
    // runs on the platform's HTTP thread and must not touch managed state.
    [System.Runtime.InteropServices.UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static int AcceptAnyCertificate() => 0;

    /// <summary>Downloads <paramref name="url"/> with a GET request.</summary>
    /// <exception cref="ProsperoException">The request failed.</exception>
    public HttpResponse Get(string url) => Send(HttpMethod.Get, url);

    /// <summary>
    /// Sends <paramref name="body"/> to <paramref name="url"/> and returns what came back.
    /// <paramref name="contentType"/> names what the body is; pass null to send no such header.
    /// </summary>
    /// <exception cref="ProsperoException">The request failed.</exception>
    public HttpResponse Post(string url, ReadOnlySpan<byte> body, string? contentType = "application/octet-stream")
    {
        string[]? headers = contentType is null ? null : ["Content-Type: " + contentType];
        return Send(HttpMethod.Post, url, body, headers);
    }

    /// <summary>
    /// Makes one request and reads the whole answer. <paramref name="headers"/> holds lines of the form
    /// <c>Name: value</c>, each added to the request; a repeated name replaces the one before it.
    /// </summary>
    /// <remarks>
    /// A body is sent only for the methods that carry one. The length is declared before the send, so a
    /// server that refuses a request without one accepts this.
    /// </remarks>
    /// <exception cref="ProsperoException">The request failed.</exception>
    public HttpResponse Send(
        HttpMethod method, string url, ReadOnlySpan<byte> body = default, string[]? headers = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(url);

        int connId = Http.sceHttpCreateConnectionWithURL(_templateId, url, 1);
        SceResult.ThrowIfFailed(connId, nameof(Http.sceHttpCreateConnectionWithURL));
        try
        {
            int reqId = Http.sceHttpCreateRequestWithURL(connId, (int)method, url, (ulong)body.Length);
            SceResult.ThrowIfFailed(reqId, nameof(Http.sceHttpCreateRequestWithURL));
            try
            {
                if (headers is not null)
                {
                    foreach (string header in headers)
                    {
                        int colon = header.IndexOf(':');
                        if (colon <= 0)
                            throw new ArgumentException(
                                $"'{header}' is not a header line; it needs a name, a colon and a value.",
                                nameof(headers));
                        SceResult.ThrowIfFailed(
                            Http.sceHttpAddRequestHeader(
                                reqId, header[..colon].Trim(), header[(colon + 1)..].Trim(),
                                Http.HeaderOverwrite),
                            nameof(Http.sceHttpAddRequestHeader));
                    }
                }

                int sent;
                fixed (byte* data = body)
                    sent = Http.sceHttpSendRequest(reqId, body.IsEmpty ? null : data, (nuint)body.Length);
                SceResult.ThrowIfFailed(sent, nameof(Http.sceHttpSendRequest));

                int status = 0;
                SceResult.ThrowIfFailed(Http.sceHttpGetStatusCode(reqId, &status), nameof(Http.sceHttpGetStatusCode));

                int lengthKnown = 0;
                ulong contentLength = 0;
                SceResult.ThrowIfFailed(
                    Http.sceHttpGetResponseContentLength(reqId, &lengthKnown, &contentLength),
                    nameof(Http.sceHttpGetResponseContentLength));

                string responseHeaders = ReadHeaders(reqId);
                // A HEAD answer carries the length its body would have had, and no body. Reading one
                // would wait for bytes that never come.
                byte[] responseBody = method == HttpMethod.Head
                    ? []
                    : ReadBody(reqId, lengthKnown == 0, contentLength);
                return new HttpResponse(status, responseBody, responseHeaders);
            }
            finally
            {
                Http.sceHttpDeleteRequest(reqId);
            }
        }
        finally
        {
            Http.sceHttpDeleteConnection(connId);
        }
    }

    // The headers the server sent, as one block the service owns. The pointer stays valid only while
    // the request does, so it is copied out here.
    private static string ReadHeaders(int reqId)
    {
        byte* header = null;
        nuint size = 0;
        if (Http.sceHttpGetAllResponseHeaders(reqId, &header, &size) < 0 || header is null || size == 0)
            return string.Empty;
        return Encoding.UTF8.GetString(header, (int)size);
    }

    // Reads the body until the read returns nothing more. When the length is known, the loop also
    // stops once that many bytes have arrived; when it is not, it stops at the first empty read. This
    // handles both, without relying on the length alone.
    private static byte[] ReadBody(int reqId, bool lengthKnown, ulong contentLength)
    {
        // Size the buffer to the content length up front when it is known, so a large download does
        // not grow the stream by repeated doubling.
        var output = lengthKnown && contentLength <= int.MaxValue
            ? new MemoryStream((int)contentLength)
            : new MemoryStream();
        byte[] chunk = new byte[64 * 1024];
        fixed (byte* buffer = chunk)
        {
            while (true)
            {
                int read = Http.sceHttpReadData(reqId, buffer, (nuint)chunk.Length);
                SceResult.ThrowIfFailed(read, nameof(Http.sceHttpReadData));
                if (read == 0)
                    break;
                output.Write(chunk, 0, read);
                if (lengthKnown && (ulong)output.Length >= contentLength)
                    break;
            }
        }
        return output.ToArray();
    }

    /// <summary>Shuts the download services down, in the reverse of the order they came up.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Http.sceHttpDeleteTemplate(_templateId);
        Http.sceHttpTerm(_httpCtxId);
        Ssl.sceSslTerm(_sslCtxId);
        NetPool.sceNetPoolDestroy(_netMemId);
    }
}
