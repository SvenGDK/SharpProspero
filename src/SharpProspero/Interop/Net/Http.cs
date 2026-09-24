// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Net;

/// <summary>The network memory pool the HTTP and SSL services draw from.</summary>
public static partial class NetPool
{
    private const string Lib = "libSceNet";

    /// <summary>
    /// Brings the network service into a state where a pool can be created against it. Called once
    /// per process, before any other <c>libSceNet</c> entry. Returns zero when the service has come
    /// up or was already up; a nonzero return means the pool call would fail if it followed.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNetInit();

    /// <summary>Creates a memory pool, returning its id. This is the first network call.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceNetPoolCreate(string name, int size, int flags);

    /// <summary>Destroys a memory pool.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNetPoolDestroy(int memId);
}

/// <summary>A length-carrying byte blob: a certificate, a key, or a chain member.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSslData
{
    /// <summary>The bytes.</summary>
    public byte* Ptr;

    /// <summary>Their length.</summary>
    public nuint Size;
}

/// <summary>The lowest protocol version a connection will negotiate.</summary>
public enum SceSslVersion : int
{
    /// <summary>Leave the service's own floor in place.</summary>
    None = 0,

    /// <summary>SSL 2.0.</summary>
    Ssl20 = 1,

    /// <summary>SSL 3.0.</summary>
    Ssl30 = 2,

    /// <summary>TLS 1.0.</summary>
    Tls10 = 3,

    /// <summary>TLS 1.1.</summary>
    Tls11 = 4,

    /// <summary>TLS 1.2.</summary>
    Tls12 = 5,
}

/// <summary>The hash a certificate fingerprint is computed with.</summary>
public enum SceSslFingerprintHashAlgorithm : int
{
    /// <summary>MD5, producing a 16-byte digest.</summary>
    Md5 = 0,

    /// <summary>SHA-1, producing a 20-byte digest.</summary>
    Sha1 = 1,

    /// <summary>SHA-224, producing a 28-byte digest.</summary>
    Sha224 = 2,

    /// <summary>SHA-256, producing a 32-byte digest.</summary>
    Sha256 = 3,

    /// <summary>SHA-384, producing a 48-byte digest.</summary>
    Sha384 = 4,

    /// <summary>SHA-512, producing a 64-byte digest.</summary>
    Sha512 = 5,
}

/// <summary>How much of the TLS memory pool the service is currently holding.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceSslMemoryPoolStats
{
    /// <summary>The pool's total size, as it was given to <see cref="Ssl.sceSslInit"/>.</summary>
    public nuint PoolSize;

    /// <summary>The highest amount the service has held at once since it was started.</summary>
    public nuint MaxInuseSize;

    /// <summary>The amount it is holding right now.</summary>
    public nuint CurrentInuseSize;

    /// <summary>Reserved. Leave zero.</summary>
    public int Reserved;
}

/// <summary>
/// A list of the certificate-authority certificates the service is holding, as opaque handles. Read
/// with <see cref="Ssl.sceSslGetCaList"/> and released with <see cref="Ssl.sceSslFreeCaList"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSslCaList
{
    /// <summary>An array of certificate handles, each usable with the certificate readers.</summary>
    public void** CaCerts;

    /// <summary>How many entries <see cref="CaCerts"/> has.</summary>
    public int CaNum;
}

/// <summary>
/// A list of the certificate-authority certificates the service is holding, as encoded bytes. Read
/// with <see cref="Ssl.sceSslGetCaCerts"/> and released with <see cref="Ssl.sceSslFreeCaCerts"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSslCaCerts
{
    /// <summary>An array of length-carrying byte blobs, one per certificate.</summary>
    public SceSslData* CertData;

    /// <summary>How many entries <see cref="CertData"/> has.</summary>
    public nuint CertDataNum;

    /// <summary>The pool the entries were allocated from. The service owns it.</summary>
    public void* Pool;
}

/// <summary>
/// TLS bindings. The service is started once for the process and hands back a context id; the HTTP
/// service takes that id, and a connection can also be run directly over a socket the network bindings
/// already opened: create a connection over the socket id and the host name, set the options wanted,
/// handshake, then send and receive.
/// </summary>
public static unsafe partial class Ssl
{
    private const string Lib = "libSceSsl";

    /// <summary>Require the peer certificate to be present and parseable.</summary>
    public const uint FlagServerVerify = 0x00000001;

    /// <summary>Require the certificate's name to match the host name the connection was created with.</summary>
    public const uint FlagCnCheck = 0x00000004;

    /// <summary>Reject a certificate that has expired.</summary>
    public const uint FlagNotAfterCheck = 0x00000008;

    /// <summary>Reject a certificate that is not yet valid.</summary>
    public const uint FlagNotBeforeCheck = 0x00000010;

    /// <summary>Require the chain to end at a certificate authority the service already trusts.</summary>
    public const uint FlagKnownCaCheck = 0x00000020;

    /// <summary>Reject a certificate signed with SHA-1.</summary>
    public const uint FlagNotSha1CertCheck = 0x00002000;

    /// <summary>Let a read return as soon as any bytes are available rather than filling the buffer.</summary>
    public const uint MsgFlagPartialRead = 0x00000001;

    /// <summary>Read without consuming: the same bytes are returned by the next read.</summary>
    public const uint MsgFlagPeek = 0x00000003;

    /// <summary>The size, in bytes, of an MD5 fingerprint.</summary>
    public const uint FingerprintMd5DigestSize = 16;

    /// <summary>The size, in bytes, of a SHA-1 fingerprint.</summary>
    public const uint FingerprintSha1DigestSize = 20;

    /// <summary>The size, in bytes, of a SHA-224 fingerprint.</summary>
    public const uint FingerprintSha224DigestSize = 28;

    /// <summary>The size, in bytes, of a SHA-256 fingerprint.</summary>
    public const uint FingerprintSha256DigestSize = 32;

    /// <summary>The size, in bytes, of a SHA-384 fingerprint.</summary>
    public const uint FingerprintSha384DigestSize = 48;

    /// <summary>The size, in bytes, of a SHA-512 fingerprint.</summary>
    public const uint FingerprintSha512DigestSize = 64;

    /// <summary>Starts the TLS service with a pool of <paramref name="poolSize"/> bytes, returning a context id.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslInit(nuint poolSize);

    /// <summary>Stops the TLS service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslTerm(int sslCtxId);

    /// <summary>
    /// Wraps an already-connected socket, returning a connection id. <paramref name="hostname"/> is what
    /// the certificate's name is checked against and what is sent as the server-name indication.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceSslCreateConnection(int sslCtxId, int sockId, string hostname);

    /// <summary>Releases a connection id. The socket itself stays open.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslDeleteConnection(int sslConnectionId);

    /// <summary>Runs the handshake, including whatever verification the options left enabled.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslConnect(int sslConnectionId);

    /// <summary>Sends the close notification and shuts the secure channel down.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslClose(int sslConnectionId);

    /// <summary>Writes <paramref name="len"/> bytes. Returns the number written.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslWrite(int sslConnectionId, void* buf, nuint len, int flags);

    /// <summary>Reads up to <paramref name="len"/> bytes. Returns the number read, or 0 at the end.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslRead(int sslConnectionId, void* buf, nuint len, int flags);

    /// <summary>Writes with no flags, and does not return until the whole buffer is sent.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslSend(int sslConnectionId, void* msg, nuint fulllen);

    /// <summary>Reads with no flags, and does not return until the buffer is full or the peer closes.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslRecv(int sslConnectionId, void* buf, nuint fulllen);

    /// <summary>
    /// Turns verification checks on for a connection. Set these before the handshake; afterwards they
    /// have nothing left to reject.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslEnableVerifyOption(int sslConnectionId, uint option);

    /// <summary>Turns verification checks off for a connection.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslDisableVerifyOption(int sslConnectionId, uint option);

    /// <summary>Refuses to negotiate anything below <paramref name="version"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslSetMinSslVersion(int sslConnectionId, SceSslVersion version);

    /// <summary>
    /// Runs the verification decision through the caller's routine. It receives the context id, the bits
    /// describing what failed, the chain, and its own object; returning a negative value fails the
    /// handshake with that value.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslSetVerifyCallback(int sslConnectionId,
        delegate* unmanaged[Cdecl]<int, uint, void**, int, void*, int> cbfunc, void* userArg);

    /// <summary>Offers the protocol list, in the wire form, for application-layer protocol negotiation.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceSslSetAlpn(int sslConnectionId, string proto);

    /// <summary>Reads back which protocol the peer chose, or null if none was negotiated.</summary>
    [LibraryImport(Lib)]
    public static partial byte* sceSslGetAlpnSelected(int sslConnectionId);

    /// <summary>Reuses a completed session on a freshly connected socket, skipping the full handshake.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslReuseConnection(int sslConnectionId, int sockId);

    /// <summary>
    /// Adds certificate authorities, and optionally a client certificate and its private key, to the
    /// context. Everything given here applies to connections created afterwards.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslLoadCert(int sslCtxId, int caCertNum, SceSslData** caList,
        SceSslData* cert, SceSslData* privKey);

    /// <summary>Drops what <see cref="sceSslLoadCert"/> added.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslUnloadCert(int sslCtxId);

    /// <summary>Reads how much of the TLS memory pool is in use right now, and how much has ever been.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetMemoryPoolStats(int sslCtxId, SceSslMemoryPoolStats* currentStat);

    /// <summary>
    /// Fills <paramref name="caList"/> with the certificate-authority certificates the context is holding,
    /// each as an opaque handle usable with the certificate readers. Release with
    /// <see cref="sceSslFreeCaList"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetCaList(int sslCtxId, SceSslCaList* caList);

    /// <summary>Releases what <see cref="sceSslGetCaList"/> filled in.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslFreeCaList(int sslCtxId, SceSslCaList* caList);

    /// <summary>
    /// Returns a handle to the certificate's subject name. The handle belongs to the context and must be
    /// released with <see cref="sceSslFreeSslCertName"/> when finished.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial void* sceSslGetSubjectName(int sslCtxId, void* sslCert);

    /// <summary>
    /// Returns a handle to the certificate's issuer name. The handle belongs to the context and must be
    /// released with <see cref="sceSslFreeSslCertName"/> when finished.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial void* sceSslGetIssuerName(int sslCtxId, void* sslCert);

    /// <summary>Reads the last moment at which the certificate is still valid, as a microsecond tick.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetNotAfter(int sslCtxId, void* sslCert, ulong* limit);

    /// <summary>Reads the first moment at which the certificate becomes valid, as a microsecond tick.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetNotBefore(int sslCtxId, void* sslCert, ulong* begin);

    /// <summary>Reads how many entries a certificate name carries. Returns the count, or a negative error code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetNameEntryCount(int sslCtxId, void* certName);

    /// <summary>
    /// Reads one entry of a certificate name into caller-provided buffers. <paramref name="entryNum"/>
    /// selects the entry; <paramref name="oidname"/> receives its OID as text of up to
    /// <paramref name="maxOidnameLen"/> bytes; <paramref name="value"/> receives its value, of up to
    /// <paramref name="maxValueLen"/> bytes, and <paramref name="valueLen"/> reports how many bytes the
    /// value actually took.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetNameEntryInfo(int sslCtxId, void* certName, int entryNum,
        byte* oidname, nuint maxOidnameLen, byte* value, nuint maxValueLen, nuint* valueLen);

    /// <summary>Releases a certificate-name handle returned by the subject or issuer reader.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslFreeSslCertName(int sslCtxId, void* certName);

    /// <summary>
    /// Writes the certificate's fingerprint into <paramref name="fingerprint"/>. The buffer must hold at
    /// least the number of bytes given by the matching <c>FingerprintXxxDigestSize</c> for
    /// <paramref name="hashType"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetFingerprint(int sslCtxId, void* sslCert, int hashType, byte* fingerprint);

    /// <summary>
    /// Writes the certificate's serial number, in DER form, into <paramref name="sboData"/>. On entry
    /// <paramref name="sboLen"/> holds the buffer size, and on return it holds how many bytes were written.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetSerialNumber(int sslCtxId, void* sslCert, byte* sboData, nuint* sboLen);

    /// <summary>
    /// Fills <paramref name="caCerts"/> with the certificate-authority certificates the context is
    /// holding, each as its own encoded byte blob. Release with <see cref="sceSslFreeCaCerts"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSslGetCaCerts(int sslCtxId, SceSslCaCerts* caCerts);

    /// <summary>Releases what <see cref="sceSslGetCaCerts"/> filled in.</summary>
    [LibraryImport(Lib)]
    public static partial int sceSslFreeCaCerts(int sslCtxId, SceSslCaCerts* caCerts);
}

/// <summary>
/// A URL broken into its parts. The strings point into the pool handed to <see cref="Http.sceHttpUriParse"/>,
/// so they stay valid only as long as that pool does.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceHttpUriElement
{
    /// <summary>Non-zero when the URL has no hierarchical part and only <see cref="Path"/> is meaningful.</summary>
    public int Opaque;

    /// <summary>The scheme, without the colon.</summary>
    public byte* Scheme;

    /// <summary>The user name, or null.</summary>
    public byte* Username;

    /// <summary>The password, or null.</summary>
    public byte* Password;

    /// <summary>The host name.</summary>
    public byte* Hostname;

    /// <summary>The path.</summary>
    public byte* Path;

    /// <summary>The query, including its leading question mark.</summary>
    public byte* Query;

    /// <summary>The fragment, including its leading hash.</summary>
    public byte* Fragment;

    /// <summary>The port, or 0 when the URL did not carry one.</summary>
    public ushort Port;

    /// <summary>Reserved. Leave zero.</summary>
    public fixed byte Reserved[10];
}

/// <summary>Reports pool use by the HTTP context.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceHttpMemoryPoolStats
{
    /// <summary>The whole pool.</summary>
    public nuint PoolSize;

    /// <summary>The largest amount ever taken at once.</summary>
    public nuint MaxInuseSize;

    /// <summary>The amount taken right now.</summary>
    public nuint CurrentInuseSize;

    /// <summary>Reserved. Leave zero.</summary>
    public int Reserved;
}

/// <summary>Reports cookie-store use by the HTTP context.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceHttpCookieStats
{
    /// <summary>The bytes stored right now.</summary>
    public nuint CurrentInuseSize;

    /// <summary>The cookies stored right now.</summary>
    public uint CurrentInuseNum;

    /// <summary>The largest amount ever stored at once.</summary>
    public nuint MaxInuseSize;

    /// <summary>The largest number of cookies ever stored at once.</summary>
    public uint MaxInuseNum;

    /// <summary>The number of cookies dropped to stay within limits.</summary>
    public uint RemovedNum;

    /// <summary>Reserved. Leave zero.</summary>
    public int Reserved;
}

/// <summary>HTTP client bindings.</summary>
public static unsafe partial class Http
{
    private const string Lib = "libSceHttp";

    /// <summary>HTTP/1.1.</summary>
    public const int Version11 = 2;

    /// <summary>The GET method.</summary>
    public const int MethodGet = 0;

    /// <summary>The POST method.</summary>
    public const int MethodPost = 1;

    /// <summary>The HEAD method.</summary>
    public const int MethodHead = 2;

    /// <summary>The OPTIONS method.</summary>
    public const int MethodOptions = 3;

    /// <summary>The PUT method.</summary>
    public const int MethodPut = 4;

    /// <summary>The DELETE method.</summary>
    public const int MethodDelete = 5;

    /// <summary>The TRACE method.</summary>
    public const int MethodTrace = 6;

    /// <summary>The CONNECT method.</summary>
    public const int MethodConnect = 7;

    /// <summary>Replace any header of the same name.</summary>
    public const uint HeaderOverwrite = 0;

    /// <summary>Append, leaving any header of the same name in place.</summary>
    public const uint HeaderAdd = 1;

    /// <summary>The longest URL the URI helpers accept, excluding the terminator.</summary>
    public const int MaxUriLength = (16 * 1024) - 1;

    /// <summary>Build the scheme into the output URL.</summary>
    public const uint UriBuildWithScheme = 0x01;

    /// <summary>Build the host name into the output URL.</summary>
    public const uint UriBuildWithHostname = 0x02;

    /// <summary>Build the port into the output URL.</summary>
    public const uint UriBuildWithPort = 0x04;

    /// <summary>Build the path into the output URL.</summary>
    public const uint UriBuildWithPath = 0x08;

    /// <summary>Build the user name into the output URL.</summary>
    public const uint UriBuildWithUsername = 0x10;

    /// <summary>Build the password into the output URL.</summary>
    public const uint UriBuildWithPassword = 0x20;

    /// <summary>Build the query into the output URL.</summary>
    public const uint UriBuildWithQuery = 0x40;

    /// <summary>Build the fragment into the output URL.</summary>
    public const uint UriBuildWithFragment = 0x80;

    /// <summary>Build every part that is present.</summary>
    public const uint UriBuildWithAll = 0xFFFF;

    /// <summary>Require the server certificate to be present and parseable.</summary>
    public const uint SslFlagServerVerify = 0x01;

    /// <summary>Require a client certificate exchange.</summary>
    public const uint SslFlagClientVerify = 0x02;

    /// <summary>Require the certificate's name to match the host.</summary>
    public const uint SslFlagCnCheck = 0x04;

    /// <summary>Reject an expired certificate.</summary>
    public const uint SslFlagNotAfterCheck = 0x08;

    /// <summary>Reject a certificate that is not yet valid.</summary>
    public const uint SslFlagNotBeforeCheck = 0x10;

    /// <summary>Require the chain to end at a trusted certificate authority.</summary>
    public const uint SslFlagKnownCaCheck = 0x20;

    /// <summary>Allow a previous session to be resumed.</summary>
    public const uint SslFlagSessionReuse = 0x40;

    /// <summary>Send the server-name indication.</summary>
    public const uint SslFlagSni = 0x80;

    /// <summary>Starts the HTTP service on a net pool and a TLS context, returning a context id.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpInit(int netMemId, int sslCtxId, nuint poolSize);

    /// <summary>Stops the HTTP service.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpTerm(int httpCtxId);

    /// <summary>Creates a request template, returning its id.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateTemplate(int httpCtxId, string userAgent, int httpVer, int isAutoProxyConf);

    /// <summary>Deletes a template.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpDeleteTemplate(int tmplId);

    /// <summary>Creates a connection to the host in <paramref name="url"/>, returning its id.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateConnectionWithURL(int tmplId, string url, int isEnableKeepalive);

    /// <summary>Deletes a connection.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpDeleteConnection(int connId);

    /// <summary>Creates a request on a connection, returning its id.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateRequestWithURL(int connId, int method, string url, ulong contentLength);

    /// <summary>
    /// Creates a request whose method is given by name rather than by one of the numbered methods, which
    /// is how a method outside that set is issued.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateRequestWithURL2(int connId, string method, string url, ulong contentLength);

    /// <summary>Deletes a request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpDeleteRequest(int reqId);

    /// <summary>Sets the body length after the request was created.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetRequestContentLength(int id, ulong contentLength);

    /// <summary>Sends the body in chunks instead of declaring a length up front.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetChunkedTransferEnabled(int id, int isEnable);

    /// <summary>
    /// Has the service decompress a gzip-encoded response, so <see cref="sceHttpReadData"/> yields the
    /// decoded bytes. Only 0 and 1 are accepted.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetInflateGZIPEnabled(int id, int isEnable);

    /// <summary>Sends a request, with optional body data.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSendRequest(int reqId, void* postData, nuint size);

    /// <summary>
    /// Breaks a request off. The call blocked in send or read returns instead of waiting for the server.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpAbortRequest(int reqId);

    /// <summary>
    /// Adds a request header. <paramref name="mode"/> is <see cref="HeaderOverwrite"/> or
    /// <see cref="HeaderAdd"/>.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpAddRequestHeader(int id, string name, string value, uint mode);

    /// <summary>Removes a request header the caller added, or one the service adds by default.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpRemoveRequestHeader(int id, string name);

    /// <summary>
    /// Points <paramref name="header"/> at the response header block. The block belongs to the request and
    /// dies with it, so anything wanted from it is copied out first.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetAllResponseHeaders(int reqId, byte** header, nuint* headerSize);

    /// <summary>
    /// Finds one field in a header block and points <paramref name="fieldValue"/> at its value. The value
    /// is not terminated; <paramref name="valueLen"/> gives its length.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpParseResponseHeader(byte* header, nuint headerLen, string fieldStr,
        byte** fieldValue, nuint* valueLen);

    /// <summary>Splits a status line into its version, code and reason phrase.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpParseStatusLine(byte* statusLine, nuint lineLen, int* httpMajorVer,
        int* httpMinorVer, int* responseCode, byte** reasonPhrase, nuint* phraseLen);

    /// <summary>Caps how large a response header block the service will accept.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetResponseHeaderMaxSize(int id, nuint headerSize);

    /// <summary>Follows 3xx responses itself rather than handing them to the caller.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetAutoRedirect(int id, int isEnable);

    /// <summary>Reads back whether redirects are being followed.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetAutoRedirect(int id, int* isEnable);

    /// <summary>Reads the error the transport last reported for a request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetLastErrno(int reqId, int* errNum);

    /// <summary>Reads the response status code.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetStatusCode(int reqId, int* statusCode);

    /// <summary>
    /// Reads the response body length. <paramref name="result"/> reports whether the length is known.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetResponseContentLength(int reqId, int* result, ulong* contentLength);

    /// <summary>Reads up to <paramref name="size"/> bytes of the response body. Returns bytes read, or 0 at the end.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpReadData(int reqId, void* data, nuint size);

    /// <summary>Sets the connect timeout, in microseconds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetConnectTimeOut(int id, uint usec);

    /// <summary>Sets the receive timeout, in microseconds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetRecvTimeOut(int id, uint usec);

    /// <summary>Sets the send timeout, in microseconds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetSendTimeOut(int id, uint usec);

    /// <summary>Sets the name-resolution timeout, in microseconds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetResolveTimeOut(int id, uint usec);

    /// <summary>Sets how many times name resolution is retried.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpSetResolveRetry(int id, int retry);

    /// <summary>Turns TLS checks on for a template, connection or request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsEnableOption(int id, uint sslFlags);

    /// <summary>Turns TLS checks off for a template, connection or request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsDisableOption(int id, uint sslFlags);

    /// <summary>Reads why the TLS handshake failed, with the verification bits in <paramref name="detail"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsGetSslError(int id, int* errNum, uint* detail);

    /// <summary>Adds certificate authorities, and optionally a client certificate and key, to the context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsLoadCert(int httpCtxId, int caCertNum, SceSslData** caList,
        SceSslData* cert, SceSslData* privKey);

    /// <summary>Drops what <see cref="sceHttpsLoadCert"/> added.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsUnloadCert(int httpCtxId);

    /// <summary>Refuses to negotiate anything below <paramref name="version"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsSetSslVersion(int id, SceSslVersion version);

    /// <summary>
    /// Installs a per-template callback that decides how the TLS handshake handles a certificate
    /// the built-in verifier flagged. The callback receives the verification context; returning
    /// zero accepts the connection, and any non-zero value refuses it. Passing a callback that
    /// returns zero lets a public host present a certificate whose issuer is not in the
    /// platform's built-in CA store.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpsSetSslCallback(int id, void* callback, void* arg);

    /// <summary>
    /// Splits a URL into <paramref name="output"/>, with the strings written into
    /// <paramref name="pool"/>. Call once with a null pool to learn the size through
    /// <paramref name="require"/>, then again with a pool that large.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpUriParse(SceHttpUriElement* output, string srcUrl, void* pool,
        nuint* require, nuint prepare);

    /// <summary>
    /// Assembles a URL from the parts <paramref name="option"/> selects. As with the parser, a null
    /// output reports the length needed through <paramref name="require"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpUriBuild(byte* output, nuint* require, nuint prepare,
        SceHttpUriElement* srcElement, uint option);

    /// <summary>Resolves a relative URL against a base one.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpUriMerge(byte* mergedUrl, string url, string relativeUrl,
        nuint* require, nuint prepare, uint option);

    /// <summary>Percent-encodes a string for use inside a URL.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpUriEscape(byte* output, nuint* require, nuint prepare, string input);

    /// <summary>Reverses <see cref="sceHttpUriEscape"/>.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpUriUnescape(byte* output, nuint* require, nuint prepare, string input);

    /// <summary>Collapses the dot segments in a path.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpUriSweepPath(byte* dst, string src, nuint srcSize);

    /// <summary>Reads pool use by the HTTP context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetMemoryPoolStats(int httpCtxId, SceHttpMemoryPoolStats* currentStat);

    /// <summary>
    /// Creates a connection to <paramref name="serverName"/> on the named <paramref name="scheme"/>
    /// and <paramref name="port"/>, returning its id.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateConnection(int tmplId, string serverName, string scheme,
        ushort port, int isEnableKeepalive);

    /// <summary>Creates a request on a connection with the given path, returning its id.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateRequest(int connId, int method, string path, ulong contentLength);

    /// <summary>
    /// Creates a request whose method is given by name rather than by one of the numbered methods,
    /// which is how a method outside that set is issued.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpCreateRequest2(int connId, string method, string path, ulong contentLength);

    /// <summary>Reads back whether authentication is on for a template, connection or request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetAuthEnabled(int id, int* isEnable);

    /// <summary>Drops what the service cached during authentication challenges.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpAuthCacheFlush(int httpCtxId);

    /// <summary>Drops what the service cached while following redirects.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpRedirectCacheFlush(int httpCtxId);

    /// <summary>Reads back whether cookies are on for a template, connection or request.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetCookieEnabled(int id, int* isEnable);

    /// <summary>
    /// Reads cookies for <paramref name="url"/> in the wire form used inside a request's Cookie header,
    /// writing into <paramref name="cookie"/>. Call once with a null buffer to learn the size through
    /// <paramref name="required"/>, then again with a buffer that large. <paramref name="isSecure"/>
    /// includes cookies flagged Secure.
    /// </summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpGetCookie(int httpCtxId, string url, byte* cookie, nuint* required,
        nuint prepared, int isSecure);

    /// <summary>Adds a cookie for <paramref name="url"/>, taking its wire form as <paramref name="cookie"/>.</summary>
    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int sceHttpAddCookie(int httpCtxId, string url, string cookie, nuint cookieLength);

    /// <summary>
    /// Serializes the whole cookie store into <paramref name="buffer"/>. Call once with a null buffer to
    /// learn the size through <paramref name="exportSize"/>, then again with a buffer that large.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpCookieExport(int httpCtxId, void* buffer, nuint bufferSize,
        nuint* exportSize);

    /// <summary>Replaces the cookie store with the contents of <paramref name="buffer"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpCookieImport(int httpCtxId, void* buffer, nuint bufferSize);

    /// <summary>Drops every cookie in the store.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpCookieFlush(int httpCtxId);

    /// <summary>Reads cookie-store use by the HTTP context.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetCookieStats(int httpCtxId, SceHttpCookieStats* stats);

    /// <summary>Creates an epoll handle for non-blocking requests, writing it to <paramref name="eh"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpCreateEpoll(int httpCtxId, void** eh);

    /// <summary>Destroys an epoll handle.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpDestroyEpoll(int httpCtxId, void* eh);

    /// <summary>
    /// Reads back the epoll handle a request or connection is bound to, and the caller's object that
    /// was set with it.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpGetEpoll(int id, void** eh, void** userArg);

    /// <summary>Breaks the wait on an epoll handle, so any call blocked in it returns.</summary>
    [LibraryImport(Lib)]
    public static partial int sceHttpAbortWaitRequest(void* eh);
}
