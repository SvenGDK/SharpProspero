// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Net;

/// <summary>The HTTP version a request template negotiates for.</summary>
public enum SceHttp2HttpVersion : int
{
    /// <summary>HTTP/1.0.</summary>
    Http10 = 1,

    /// <summary>HTTP/1.1.</summary>
    Http11 = 2,

    /// <summary>HTTP/2.</summary>
    Http20 = 3,
}

/// <summary>How <see cref="Http2.sceHttp2AddRequestHeader"/> treats a header of the same name.</summary>
public enum SceHttp2AddHeaderMode : uint
{
    /// <summary>Replace any header of the same name.</summary>
    Overwrite = 0,

    /// <summary>Append, leaving any header of the same name in place.</summary>
    Add = 1,
}

/// <summary>The authentication scheme a challenge picked.</summary>
public enum SceHttp2AuthType : int
{
    /// <summary>HTTP Basic.</summary>
    Basic = 0,

    /// <summary>HTTP Digest.</summary>
    Digest = 1,

    /// <summary>Reserved. Do not use.</summary>
    Reserved0 = 2,

    /// <summary>Reserved. Do not use.</summary>
    Reserved1 = 3,

    /// <summary>Reserved. Do not use.</summary>
    Reserved2 = 4,
}

/// <summary>What <see cref="Http2.sceHttp2GetResponseContentLength"/> reports for the body length.</summary>
public enum SceHttp2ContentLengthType : int
{
    /// <summary>The response carries a Content-Length header.</summary>
    Exist = 0,

    /// <summary>No length header is present and the length is not known up front.</summary>
    NotFound = 1,

    /// <summary>The body is chunked-encoded; its total length is only known after the last chunk.</summary>
    ChunkEncoded = 2,
}

/// <summary>How much of an HTTP/2 context pool is committed at the moment.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceHttp2MemoryPoolStats
{
    /// <summary>The pool's total size in bytes.</summary>
    public nuint PoolSize;

    /// <summary>The high-water mark for allocations against this pool.</summary>
    public nuint MaxInuseSize;

    /// <summary>How many bytes are in use right now.</summary>
    public nuint CurrentInuseSize;

    /// <summary>Reserved. Leave zero.</summary>
    public int Reserved;
}

/// <summary>How much of a cookie box is committed at the moment.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceHttp2CookieStats
{
    /// <summary>How many bytes are currently held by cookies in the box.</summary>
    public nuint CurrentInuseSize;

    /// <summary>How many cookies the box currently holds.</summary>
    public uint CurrentInuseNum;

    /// <summary>The high-water mark for bytes used.</summary>
    public nuint MaxInuseSize;

    /// <summary>The high-water mark for the cookie count.</summary>
    public uint MaxInuseNum;

    /// <summary>How many cookies the box has evicted since it was created.</summary>
    public uint RemovedNum;

    /// <summary>Reserved. Leave zero.</summary>
    public int Reserved;
}

/// <summary>
/// HTTP/2 client bindings. A working sequence is: create a network pool and a TLS context, start the
/// service with those two ids, create a template, create a request off that template, send it, then
/// read the status and the body. Cookies live in a box the service creates on request and that a
/// template or a specific request can be attached to.
/// </summary>
public static unsafe partial class Http2
{
    private const string Lib = "libSceHttp2";

    /// <summary>The GET/POST/etc. method the request template will use, given by name.</summary>
    public const uint HeaderOverwrite = 0;

    /// <summary>Append, leaving any header of the same name in place.</summary>
    public const uint HeaderAdd = 1;

    /// <summary>The lowest cookie-pool size the service accepts.</summary>
    public const uint CookiePoolSizeMin = 64 * 1024;

    /// <summary>The default keep-alive timeout for a connection, in microseconds.</summary>
    public const uint DefaultKeepaliveTimeout = 7 * 1000 * 1000U;

    /// <summary>The default overall request timeout, in microseconds.</summary>
    public const uint DefaultTimeout = 120 * 1000 * 1000U;

    /// <summary>The default connect timeout, in microseconds.</summary>
    public const uint DefaultConnectTimeout = 30 * 1000 * 1000U;

    /// <summary>The default send timeout, in microseconds.</summary>
    public const uint DefaultSendTimeout = 120 * 1000 * 1000U;

    /// <summary>The default receive timeout, in microseconds.</summary>
    public const uint DefaultRecvTimeout = 120 * 1000 * 1000U;

    /// <summary>The default recv-block size, in bytes.</summary>
    public const uint DefaultRecvBlockSize = 2 * 1024U;

    /// <summary>The default cap on how many redirects a request will follow itself.</summary>
    public const uint DefaultRedirectMax = 6U;

    /// <summary>The default cap on how many times authentication is retried.</summary>
    public const uint DefaultTryAuthMax = 6U;

    /// <summary>The cap on how large a fixed HTTP/1.x response header block can be, in bytes.</summary>
    public const uint FixedHttp1ResponseHeaderMax = 64 * 1024U;

    /// <summary>An invalid id returned when a create call fails without setting an error further.</summary>
    public const int InvalidId = 0;

    /// <summary>Require the server certificate to be present and parseable.</summary>
    public const uint SslFlagServerVerify = 0x01;

    /// <summary>Require the certificate's name to match the host.</summary>
    public const uint SslFlagCnCheck = 0x04;

    /// <summary>Reject an expired certificate.</summary>
    public const uint SslFlagNotAfterCheck = 0x08;

    /// <summary>Reject a certificate that is not yet valid.</summary>
    public const uint SslFlagNotBeforeCheck = 0x10;

    /// <summary>Require the chain to end at a trusted certificate authority.</summary>
    public const uint SslFlagKnownCaCheck = 0x20;

    /// <summary>Breaks a request off. The call blocked in send or read returns instead of waiting for the server.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2AbortRequest(int reqId);

    /// <summary>Files a cookie into a cookie box under the origin <paramref name="url"/> gives.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttp2AddCookie(int cookieBoxId, string url, string cookie, nuint cookieLength);

    /// <summary>
    /// Adds a request header. <paramref name="mode"/> is <see cref="HeaderOverwrite"/> or
    /// <see cref="HeaderAdd"/>.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttp2AddRequestHeader(int id, string name, string value, uint mode);

    /// <summary>Drops what the service has cached from earlier authentication challenges on this context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2AuthCacheFlush(int libhttpCtxId);

    /// <summary>
    /// Serialises a cookie box into <paramref name="buffer"/>. Call once with a null buffer to learn
    /// the size through <paramref name="exportSize"/>, then again with a buffer that large.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2CookieExport(int cookieBoxId, void* buffer, nuint bufferSize, nuint* exportSize);

    /// <summary>Discards every cookie a box currently holds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2CookieFlush(int cookieBoxId);

    /// <summary>Restores a cookie box from bytes <see cref="sceHttp2CookieExport"/> wrote earlier.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2CookieImport(int cookieBoxId, void* buffer, nuint bufferSize);

    /// <summary>
    /// Creates a cookie box backed by a pool of <paramref name="poolSize"/> bytes and returns its id.
    /// The pool cannot be smaller than <see cref="CookiePoolSizeMin"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2CreateCookieBox(nuint poolSize);

    /// <summary>
    /// Creates a request on <paramref name="tmplId"/> using <paramref name="method"/> against
    /// <paramref name="url"/>, returning the request id.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttp2CreateRequestWithURL(int tmplId, string method, string url, ulong contentLength);

    /// <summary>Discards a cookie box.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2DeleteCookieBox(int cookieBoxId);

    /// <summary>
    /// Points <paramref name="header"/> at the response header block. The block belongs to the request
    /// and dies with it, so anything wanted from it is copied out first.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2GetAllResponseHeaders(int reqId, byte** header, nuint* headerSize);

    /// <summary>
    /// Reads the cookies a box would send with a request to <paramref name="url"/> and writes them into
    /// <paramref name="cookie"/>. Call once with a null buffer to learn the required size through
    /// <paramref name="required"/>, then again with a buffer that large in <paramref name="prepared"/>.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttp2GetCookie(int cookieBoxId, string url, byte* cookie, nuint* required, nuint prepared);

    /// <summary>Reads how much of the cookie box is in use.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2GetCookieStats(int cookieBoxId, SceHttp2CookieStats* stats);

    /// <summary>Reads how much of the HTTP/2 context pool is in use.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2GetMemoryPoolStats(int libhttp2CtxId, SceHttp2MemoryPoolStats* currentStat);

    /// <summary>
    /// Reads the response body length. <paramref name="result"/> is a <see cref="SceHttp2ContentLengthType"/>
    /// telling the caller whether the length is meaningful.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2GetResponseContentLength(int reqId, int* result, ulong* contentLength);

    /// <summary>Reads the response status code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2GetStatusCode(int reqId, int* statusCode);

    /// <summary>Reads up to <paramref name="size"/> bytes of the response body. Returns bytes read, or 0 at the end.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2ReadData(int reqId, void* data, nuint size);

    /// <summary>Drops what the service has cached from earlier redirect resolutions on this context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2RedirectCacheFlush(int libhttpCtxId);

    /// <summary>Removes a request header the caller added, or one the service adds by default.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttp2RemoveRequestHeader(int id, string name);

    /// <summary>Sends a request, with optional body data.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SendRequest(int reqId, void* postData, nuint size);

    /// <summary>Turns HTTP authentication on or off for a template or a specific request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetAuthEnabled(int templateOrReqid, int isEnable);

    /// <summary>
    /// Runs the authentication decision through the caller's routine. The callback receives the request
    /// id, the challenge type, the realm, and out-buffers for the credentials and body it can supply;
    /// returning zero lets the service continue, and a non-zero return propagates as the request's error.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetAuthInfoCallback(int templateOrReqid,
        delegate* unmanaged[Cdecl]<int, SceHttp2AuthType, byte*, byte*, byte*, int, byte**, nuint*, int*, void*, int> cbfunc,
        void* userArg);

    /// <summary>Sets the connect timeout, in microseconds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetConnectTimeOut(int id, uint usec);

    /// <summary>Caps the total number of cookies a box holds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetCookieMaxNum(int cookieBoxId, uint num);

    /// <summary>Caps how many cookies a single origin can put in a box.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetCookieMaxNumPerDomain(int cookieBoxId, uint num);

    /// <summary>Caps how large a single cookie can be, in bytes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetCookieMaxSize(int cookieBoxId, uint size);

    /// <summary>
    /// Runs the receipt of a Set-Cookie header through the caller's routine. The callback gets the
    /// request id, the origin URL, the header value, and its length; returning zero accepts the cookie,
    /// non-zero rejects it.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetCookieRecvCallback(int templateOrReqid,
        delegate* unmanaged[Cdecl]<int, byte*, byte*, nuint, void*, int> cbfunc,
        void* userArg);

    /// <summary>
    /// Runs the emission of a Cookie header through the caller's routine. The callback gets the request
    /// id, the URL, and the header the service is about to send; returning zero sends it, non-zero
    /// suppresses that cookie.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetCookieSendCallback(int templateOrReqid,
        delegate* unmanaged[Cdecl]<int, byte*, byte*, void*, int> cbfunc,
        void* userArg);

    /// <summary>
    /// Has the service decompress a gzip-encoded response, so <see cref="sceHttp2ReadData"/> yields the
    /// decoded bytes. Only 0 and 1 are accepted.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetInflateGZIPEnabled(int id, int isEnable);

    /// <summary>
    /// Runs the decision to follow a redirect through the caller's routine. The callback gets the
    /// request id, the response's status code, an in/out pointer to the method to use, and the target
    /// URL; returning zero follows the redirect, non-zero refuses it.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetRedirectCallback(int id,
        delegate* unmanaged[Cdecl]<int, int, byte**, byte*, void*, int> cbfunc,
        void* userArg);

    /// <summary>Sets the body length after the request was created.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttp2SetRequestContentLength(int id, ulong contentLength);
}
