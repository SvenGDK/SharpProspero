// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Globalization;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpProspero.Interop.Np;

/// <summary>
/// A BCP-47 language tag as delivered by the account service. The struct's binary form matches
/// <c>SceNpLanguageCode2</c> in the on-device header: a 36-byte NUL-terminated ASCII code
/// followed by 12 bytes of padding, so the field packs into 48 bytes total.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 48)]
public unsafe struct SceNpLanguageCode2
{
    /// <summary>The 35-character maximum length the wire format allows for the code payload.</summary>
    public const int MaxLength = 35;

    /// <summary>The 36-byte code buffer (35 payload characters plus a NUL terminator).</summary>
    public fixed byte Code[MaxLength + 1];

    private fixed byte _padding[12];

    /// <summary>Reads the code as a managed string, stopping at the first NUL byte.</summary>
    public readonly string Read()
    {
        fixed (byte* p = Code)
        {
            int length = 0;
            while (length <= MaxLength && p[length] != 0)
                length++;
            return length == 0 ? string.Empty : Encoding.ASCII.GetString(p, length);
        }
    }
}

/// <summary>
/// The ISO 3166-1 alpha-2 country code the account service returns. The struct's binary form
/// matches <c>SceNpCountryCode</c> in the on-device header: two payload characters, one NUL
/// terminator, and one byte of padding.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 4)]
public unsafe struct SceNpCountryCode
{
    /// <summary>The two-character payload.</summary>
    public fixed byte Data[2];

    /// <summary>The trailing NUL byte the wire format carries.</summary>
    public byte Term;

    private byte _padding;

    /// <summary>Reads the code as a managed string, or an empty string when the payload is unset.</summary>
    public readonly string Read()
    {
        fixed (byte* p = Data)
        {
            if (p[0] == 0)
                return string.Empty;
            int length = p[1] == 0 ? 1 : 2;
            return Encoding.ASCII.GetString(p, length);
        }
    }
}

/// <summary>
/// Bindings for the account-language and account-country calls in <c>libSceNpCommon</c>.
/// <see cref="TryGetAccountLanguage"/> wraps the async request in a bounded wait so a caller
/// can ask for the signed-in user's preferred language without owning the request loop.
/// </summary>
public static unsafe partial class NpAccount
{
    private const string Lib = "libSceNpCommon";

    /// <summary>The zero value the header uses when a wait should not time out.</summary>
    public const uint TimeoutNoEffect = 0;

    /// <summary>The async-request result value that means the operation completed.</summary>
    public const int PollAsyncFinished = 0;

    /// <summary>The async-request result value that means the operation is still running.</summary>
    public const int PollAsyncRunning = 1;

    /// <summary>
    /// Creates a synchronous request slot; the returned integer is the request id passed to the
    /// other calls. Synchronous requests populate their result inline when the API function
    /// returns and are NOT polled with <see cref="sceNpPollAsync"/> — the poll functions belong
    /// to the async-request family created via <see cref="sceNpCreateAsyncRequest"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNpCreateRequest();

    /// <summary>Parameters passed to <see cref="sceNpCreateAsyncRequest"/> when the caller wants an async request.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SceNpCreateAsyncRequestParameter
    {
        /// <summary>Size of the parameter struct in bytes — the caller must set this to <c>sizeof(SceNpCreateAsyncRequestParameter)</c>.</summary>
        public nuint Size;

        /// <summary>Bitmask of CPU cores the worker thread may run on; zero picks the default set.</summary>
        public ulong CpuAffinityMask;

        /// <summary>Thread priority; zero picks the default.</summary>
        public int ThreadPriority;

        private int _padding;
    }

    /// <summary>Creates an ASYNC request slot for the poll/wait API family.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNpCreateAsyncRequest(SceNpCreateAsyncRequestParameter* param);

    /// <summary>Releases a request slot; every successful <see cref="sceNpCreateRequest"/> or <see cref="sceNpCreateAsyncRequest"/> pairs with one call to this.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNpDeleteRequest(int reqId);

    /// <summary>Sets the resolve/connect/send/receive timeouts on the request in microseconds.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNpSetTimeout(int reqId, int resolveRetry, uint resolveTimeout, uint connTimeout, uint sendTimeout, uint recvTimeout);

    /// <summary>Reads the ISO 3166-1 country code the user's account is registered against.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNpGetAccountCountryA(int userId, SceNpCountryCode* countryCode);

    /// <summary>Kicks the async request to read the user's account language.</summary>
    [LibraryImport(Lib)]
    public static partial int sceNpGetAccountLanguage2(int reqId, int userId, SceNpLanguageCode2* languageCode2);

    /// <summary>
    /// Polls an async request without blocking. Returns <see cref="PollAsyncFinished"/> when the
    /// request completed (with the operation's own result written through <paramref name="result"/>),
    /// <see cref="PollAsyncRunning"/> while it is still in flight, or a negative value on error.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNpPollAsync(int reqId, int* result);

    /// <summary>
    /// Waits for an async request to finish, blocking the calling thread until it does or the
    /// request errors. Exposed for completeness; the bounded helpers on this type use the
    /// non-blocking <see cref="sceNpPollAsync"/> path instead so the caller's timeout is enforced.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceNpWaitAsync(int reqId, int* result);

    /// <summary>
    /// Reads the account language for <paramref name="userId"/> via an ASYNC NP request bounded
    /// by <paramref name="timeoutSeconds"/> real seconds. Returns <c>true</c> when the code was
    /// read and could be parsed, in which case <paramref name="tag"/> carries the language;
    /// false when the service was not reachable, the wait timed out, or the returned string was
    /// empty or not a valid tag. The wait is a non-blocking poll loop bounded by the timeout;
    /// every iteration yields the thread. Use this variant when the caller cannot block on the
    /// network stack (e.g. a UI thread).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="timeoutSeconds"/> is not positive.</exception>
    public static bool TryGetAccountLanguage(int userId, double timeoutSeconds, out LanguageTag tag)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutSeconds);
        tag = LanguageTag.Invariant;

        // sceNpCreateAsyncRequest is the correct pair for sceNpPollAsync; sceNpCreateRequest
        // creates a SYNCHRONOUS slot whose sceNpGetAccountLanguage2 call populates its result
        // inline. Mixing the sync request with a poll loop would either spin forever (nothing
        // to poll) or return an invalid-argument error from the poll function.
        SceNpCreateAsyncRequestParameter param = default;
        param.Size = (nuint)sizeof(SceNpCreateAsyncRequestParameter);
        int reqId = sceNpCreateAsyncRequest(&param);
        if (reqId < 0)
            return false;

        try
        {
            SceNpLanguageCode2 code = default;
            int rc = sceNpGetAccountLanguage2(reqId, userId, &code);
            if (rc < 0)
                return false;

            var start = System.Diagnostics.Stopwatch.StartNew();
            int result = 0;
            while (true)
            {
                int poll = sceNpPollAsync(reqId, &result);
                if (poll < 0)
                    return false;
                if (poll == PollAsyncFinished)
                    break;
                if (start.Elapsed.TotalSeconds >= timeoutSeconds)
                    return false;
                System.Threading.Thread.Sleep(10);
            }
            if (result < 0)
                return false;

            string codeText = code.Read();
            if (string.IsNullOrEmpty(codeText))
                return false;
            return LanguageTag.TryParse(codeText, out tag!);
        }
        finally
        {
            sceNpDeleteRequest(reqId);
        }
    }

    /// <summary>
    /// Reads the country code for <paramref name="userId"/>. Returns <c>true</c> and the
    /// two-letter ISO code in <paramref name="country"/> on success, false when the call fails
    /// or the returned buffer is empty.
    /// </summary>
    public static bool TryGetAccountCountry(int userId, out string country)
    {
        SceNpCountryCode code = default;
        int rc = sceNpGetAccountCountryA(userId, &code);
        if (rc < 0)
        {
            country = string.Empty;
            return false;
        }
        country = code.Read();
        return country.Length > 0;
    }
}
