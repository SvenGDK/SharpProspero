// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpProspero.Interop.SystemService;

/// <summary>
/// System-service bindings. Covers the small set an application module needs at startup: dismissing
/// the boot splash and reading system parameters.
/// </summary>
public static unsafe partial class SystemService
{
    private const string Lib = "libSceSystemService";

    /// <summary>Parameter id for the system language.</summary>
    public const int ParamIdLanguage = 1;

    /// <summary>Parameter id for the date display format.</summary>
    public const int ParamIdDateFormat = 2;

    /// <summary>Parameter id for the time display format.</summary>
    public const int ParamIdTimeFormat = 3;

    /// <summary>Parameter id for the time-zone offset in minutes.</summary>
    public const int ParamIdTimeZone = 4;

    /// <summary>Parameter id for the summer-time flag.</summary>
    public const int ParamIdSummerTime = 5;

    /// <summary>Parameter id for the console's system name (a string).</summary>
    public const int ParamIdSystemName = 6;

    /// <summary>Event type: the application has resumed from a suspended state.</summary>
    public const int EventOnResume = 0x10000000;

    /// <summary>Event type: another application was launched over this one.</summary>
    public const int EventLaunchApp = 0x10000007;

    /// <summary>Event type: game live-streaming status changed.</summary>
    public const int EventGameLiveStreamingStatusUpdate = 0x10000001;

    /// <summary>Event type: a session invitation was received.</summary>
    public const int EventSessionInvitation = 0x10000002;

    /// <summary>Event type: an entitlement was added or updated.</summary>
    public const int EventEntitlementUpdate = 0x10000003;

    /// <summary>Event type: custom game data was received.</summary>
    public const int EventGameCustomData = 0x10000004;

    /// <summary>Event type: the display safe-area ratio changed.</summary>
    public const int EventDisplaySafeAreaUpdate = 0x10000005;

    /// <summary>Event type: a URL was opened.</summary>
    public const int EventUrlOpen = 0x10000006;

    /// <summary>Event type: an app-launch link was received.</summary>
    public const int EventAppLaunchLink = 0x10000008;

    /// <summary>Event type: add-on content finished installing.</summary>
    public const int EventAddcontentInstall = 0x10000009;

    /// <summary>Event type: the VR tracking position was reset.</summary>
    public const int EventResetVrPosition = 0x1000000A;

    /// <summary>Event type: a multiplayer join request was received.</summary>
    public const int EventJoinEvent = 0x1000000B;

    /// <summary>Event type: a PlayGo locus was updated.</summary>
    public const int EventPlaygoLocusUpdate = 0x1000000C;

    /// <summary>Event type: a Play Together host request was received.</summary>
    public const int EventPlayTogetherHost = 0x1000000D;

    /// <summary>Event type: the share menu was opened.</summary>
    public const int EventOpenShareMenu = 0x30000000;

    /// <summary>An internal failure inside the service. Value 0x80A10001.</summary>
    public const int ErrorInternal = unchecked((int)0x80A10001);

    /// <summary>The service cannot be used in the current state. Value 0x80A10002.</summary>
    public const int ErrorUnavailable = unchecked((int)0x80A10002);

    /// <summary>An argument was outside what the call accepts. Value 0x80A10003.</summary>
    public const int ErrorParameter = unchecked((int)0x80A10003);

    /// <summary>Nothing is waiting in the event queue. Value 0x80A10004.</summary>
    public const int ErrorNoEvent = unchecked((int)0x80A10004);

    /// <summary>The call was refused for the calling process. Value 0x80A10005.</summary>
    public const int ErrorRejected = unchecked((int)0x80A10005);

    /// <summary>The safe-area ratio has not been chosen yet. Value 0x80A10006.</summary>
    public const int ErrorNeedDisplaySafeAreaSettings = unchecked((int)0x80A10006);

    /// <summary>A URI argument exceeded the maximum length. Value 0x80A10007.</summary>
    public const int ErrorInvalidUriLen = unchecked((int)0x80A10007);

    /// <summary>A URI argument used an unsupported scheme (only http, https, psno are accepted). Value 0x80A10008.</summary>
    public const int ErrorInvalidUriScheme = unchecked((int)0x80A10008);

    /// <summary>No application information was found for the given app id. Value 0x80A10009.</summary>
    public const int ErrorNoAppInfo = unchecked((int)0x80A10009);

    /// <summary>The application's param.sfo is missing a required launch flag. Value 0x816B000D.</summary>
    public const int ErrorLaunchNotFlagInParamSfo = unchecked((int)0x816B000D);

    /// <summary>The application is suspended and cannot be launched. Value 0x816B000E.</summary>
    public const int ErrorLaunchSuspended = unchecked((int)0x816B000E);

    /// <summary>The application is not installed. Value 0x816B000F.</summary>
    public const int ErrorLaunchNotInstalled = unchecked((int)0x816B000F);

    /// <summary>The application could not be booted. Value 0x816B0010.</summary>
    public const int ErrorLaunchCouldNotBoot = unchecked((int)0x816B0010);

    /// <summary>GPU load emulation off, so the GPU runs at its own pace.</summary>
    public const int GpuLoadEmulationModeOff = 0;

    /// <summary>GPU load emulation at the standard profile.</summary>
    public const int GpuLoadEmulationModeNormal = 1;

    /// <summary>Removes the boot splash so the first rendered frame is shown.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceHideSplashScreen();

    /// <summary>Reads an integer system parameter identified by <paramref name="paramId"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceParamGetInt(int paramId, int* value);

    /// <summary>Reads a string system parameter into <paramref name="buf"/> of <paramref name="bufSize"/> bytes.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceParamGetString(int paramId, byte* buf, nuint bufSize);

    /// <summary>
    /// Starts the installed application <paramref name="titleId"/> (a 9-character id). The running
    /// application is replaced by it. <paramref name="argv"/> is a null-terminated array of argument
    /// strings, or null; <paramref name="param"/> carries launch options, or null for the defaults.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceLaunchApp(byte* titleId, byte** argv, void* param);

    /// <summary>
    /// Replaces the running module with the executable at <paramref name="path"/>. <paramref name="argv"/>
    /// is a null-terminated array of argument strings, or null.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceLoadExec(byte* path, byte** argv);

    /// <summary>Resets the idle-shutdown timer, keeping the console awake during a long operation.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServicePowerTick();

    /// <summary>Reads the next pending system event, if any, into <paramref name="event"/>.</summary>
    /// <returns>Zero on success, or a negative error code (including a no-event code).</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceReceiveEvent(SceSystemServiceEvent* @event);

    /// <summary>Reads the current service status into <paramref name="status"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetStatus(SceSystemServiceStatus* status);

    /// <summary>Reads the display's safe-area ratio into <paramref name="info"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetDisplaySafeAreaInfo(SceSystemServiceDisplaySafeAreaInfo* info);

    /// <summary>
    /// Selects the GPU load emulation profile, one of the <c>GpuLoadEmulationMode*</c> values. The
    /// profile shapes how much GPU work the system lets through, which is what the machine's power and
    /// heat budget follows.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceSetGpuLoadEmulationMode(int mode);

    /// <summary>
    /// Reads the GPU load emulation profile in effect. Returns one of the <c>GpuLoadEmulationMode*</c>
    /// values rather than a result code, and reports the standard profile when the state is unreadable.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetGpuLoadEmulationMode();

    /// <summary>
    /// Ends the process and records it as an abnormal termination. <paramref name="info"/> must be
    /// null; any other value is refused with <see cref="ErrorParameter"/>. On acceptance the call does
    /// not return, because the process is raised into a fault and torn down.
    /// </summary>
    /// <returns>A negative error code. It never returns on acceptance.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceReportAbnormalTermination(void* info);

    /// <summary>Stops the background media player, so this module has the audio output to itself.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceDisableMediaPlay();

    /// <summary>Allows the background media player to run again.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceReenableMediaPlay();

    /// <summary>
    /// Returns the application id of the foreground game. A negative value means no game
    /// is running.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetAppIdOfRunningBigApp();

    /// <summary>
    /// Terminates the application with the given <paramref name="appId"/>. Wraps
    /// <c>sceLncUtilKillApp</c> with error remapping.
    /// </summary>
    /// <param name="appId">Application id (from <see cref="sceSystemServiceGetAppIdOfRunningBigApp"/>).</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceKillApp(uint appId);

    /// <summary>
    /// Navigates the shell to the home screen, dismissing the foreground application.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceNavigateToGoHome();

    /// <summary>
    /// Converts a title identifier string to its application id.
    /// </summary>
    /// <param name="titleId">A NUL-terminated UTF-8 title identifier (e.g. "PPSA01234\0").</param>
    /// <returns>A non-negative application id on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetAppId(byte* titleId);

    /// <summary>
    /// Converts an application id to its title identifier string.
    /// </summary>
    /// <param name="appId">The application id.</param>
    /// <param name="titleId">A buffer of at least 10 bytes to receive the NUL-terminated title id.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetAppTitleId(int appId, byte* titleId);

    /// <summary>
    /// Reads the title identifier for an application id through the launch-notification utility
    /// path.
    /// </summary>
    /// <param name="appId">The application id.</param>
    /// <param name="titleId">A buffer of at least 10 bytes to receive the NUL-terminated title id.</param>
    [LibraryImport(Lib)]
    public static partial void sceLncUtilGetAppTitleId(uint appId, byte* titleId);

    /// <summary>
    /// Terminates the application with the given <paramref name="appId"/> through the
    /// launch-notification utility path.
    /// </summary>
    /// <param name="appId">The application id.</param>
    /// <returns>Zero on success, or a non-zero error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceLncUtilKillApp(uint appId);

    /// <summary>
    /// Terminates the application with the given <paramref name="appId"/> and a reason code
    /// through the launch-notification utility path.
    /// </summary>
    /// <param name="appId">The application id.</param>
    /// <param name="reason">Reason code for the termination.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceLncUtilKillAppWithReason(uint appId, int reason);

    /// <summary>
    /// Launches an application with detailed launch parameters through the launch-notification
    /// utility path. Takes a <see cref="LncAppParam"/> with user id, application options,
    /// and launch flags.
    /// </summary>
    /// <param name="titleId">A NUL-terminated title identifier.</param>
    /// <param name="argv">A null-terminated array of argument strings, or null.</param>
    /// <param name="param">Launch parameters, or null for defaults.</param>
    [LibraryImport(Lib)]
    public static partial int sceLncUtilLaunchApp(byte* titleId, byte** argv, LncAppParam* param);

    /// <summary>
    /// Queries the detailed status of an application by its app id. The output is a 16-byte
    /// <see cref="SceSystemServiceAppStatus"/> containing the application identifier, its status
    /// flags, and its current state.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetAppStatus(SceSystemServiceAppStatus* status);

    /// <summary>
    /// Registers a local process entry with the system service. Wraps
    /// <c>sceLncUtilAddLocalProcess</c> with option translation.
    /// </summary>
    /// <param name="appId">Application id to register the process under.</param>
    /// <param name="path">NUL-terminated UTF-8 path to the executable.</param>
    /// <param name="argv">A null-terminated array of argument strings, or null.</param>
    /// <param name="opt">Optional launch parameters structure, or null for defaults.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceAddLocalProcess(uint appId, byte* path, byte** argv, void* opt);

    /// <summary>
    /// Fills <paramref name="list"/> with the status of every running application, including daemon
    /// processes. Each entry occupies 0x8C (140) bytes. <paramref name="count"/> receives the
    /// number of entries written.
    /// </summary>
    /// <param name="list">
    /// Caller-allocated buffer of at least <see cref="MaxAppStatusEntries"/> entries.
    /// </param>
    /// <param name="filter">Filter value passed to the underlying launcher utility.</param>
    /// <param name="count">Receives the number of entries written.</param>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetAppStatusListContainsDaemon(
        SceSystemServiceAppStatusEntry* list, int filter, uint* count);

    /// <summary>
    /// Reads the status of the application that currently has input focus.
    /// </summary>
    /// <param name="status">Receives the focused application's status.</param>
    /// <returns>Zero on success, <see cref="ErrorNoAppInfo"/> when no application has focus,
    /// or another negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetAppFocusedAppStatus(SceSystemServiceAppStatus* status);

    /// <summary>Maximum number of entries the status list can return.</summary>
    public const int MaxAppStatusEntries = 32;

    /// <summary>
    /// Returns the status of every running application, including daemon processes.
    /// </summary>
    /// <param name="filter">Filter value passed to the underlying launcher utility.</param>
    /// <param name="result">Zero on success, or a negative error code.</param>
    /// <returns>An array of application statuses. Empty when the call fails or no applications
    /// are running.</returns>
    public static IReadOnlyList<SceSystemServiceAppStatus> GetAppStatusList(int filter, out int result)
    {
        SceSystemServiceAppStatusEntry* buf = stackalloc SceSystemServiceAppStatusEntry[MaxAppStatusEntries];
        uint count = 0;
        result = sceSystemServiceGetAppStatusListContainsDaemon(buf, filter, &count);
        if (result < 0 || count == 0)
            return System.Array.Empty<SceSystemServiceAppStatus>();

        if (count > MaxAppStatusEntries)
            count = MaxAppStatusEntries;

        var list = new SceSystemServiceAppStatus[count];
        for (uint i = 0; i < count; i++)
        {
            list[i] = new SceSystemServiceAppStatus
            {
                AppId = buf[i].AppId,
                Status = buf[i].Status,
                State = buf[i].State,
            };
        }
        return list;
    }

    /// <summary>
    /// Stops the background music player, so this module has the audio output to itself. Superseded by
    /// <see cref="sceSystemServiceDisableMediaPlay"/> and kept for older callers.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceDisableMusicPlayer();

    /// <summary>
    /// Allows the background music player to run again. Superseded by
    /// <see cref="sceSystemServiceReenableMediaPlay"/> and kept for older callers.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceReenableMusicPlayer();

    /// <summary>
    /// Reads the display's HDR tone-map luminance parameters (maximum full-frame, maximum, and minimum
    /// luminance in candela per square metre) into <paramref name="hdrToneMapLuminance"/>. The tone-map
    /// curve a renderer applies should reference these values when the panel is running in an HDR
    /// output mode.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetHdrToneMapLuminance(SceSystemServiceHdrToneMapLuminance* hdrToneMapLuminance);

    /// <summary>
    /// Reads the notice-screen skip flag for this application. A non-zero byte at <paramref name="value"/>
    /// means the application may skip its introductory notice screen on this boot. The output is a single
    /// byte holding a C <c>_Bool</c>.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceGetNoticeScreenSkipFlag(byte* value);

    /// <summary>
    /// Prevents the system from setting the notice-screen skip flag automatically for this run. After
    /// this call the application controls the flag through <see cref="sceSystemServiceSetNoticeScreenSkipFlag"/>.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceDisableNoticeScreenSkipFlagAutoSet();

    /// <summary>Sets the notice-screen skip flag for the running application.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceSetNoticeScreenSkipFlag();

    /// <summary>
    /// Fills <paramref name="param"/> with default values. The caller then chooses the
    /// <see cref="SceSystemServicePlayerDialogParam.Mode"/>, <see cref="SceSystemServicePlayerDialogParam.UserId"/>,
    /// and <see cref="SceSystemServicePlayerDialogParam.TargetAccountId"/> fields before invoking
    /// <see cref="sceSystemServiceLaunchPlayerDialog"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial void sceSystemServiceInitializePlayerDialogParam(SceSystemServicePlayerDialogParam* param);

    /// <summary>
    /// Launches the system player dialog against the target account described by <paramref name="param"/>.
    /// The dialog can present the send-friend-request flow, the block-user flow, or the profile page
    /// depending on <see cref="SceSystemServicePlayerDialogParam.Mode"/>.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int sceSystemServiceLaunchPlayerDialog(SceSystemServicePlayerDialogParam* param);

}

/// <summary>
/// Shell-core utility bindings for device management.
/// </summary>
public static unsafe partial class ShellCoreUtil
{
    private const string Lib = "libSceShellCoreUtil";

    /// <summary>
    /// Ejects a removable media device at the given path.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int sceShellCoreUtilRequestEjectDevice(byte* path);
}

/// <summary>
/// Launch parameters for <see cref="SystemService.sceLncUtilLaunchApp"/>.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct LncAppParam
{
    /// <summary>Structure size in bytes. Set to <c>sizeof(LncAppParam)</c> before calling.</summary>
    public uint Size;

    /// <summary>The user id to launch on behalf of.</summary>
    public int UserId;

    /// <summary>Application option flags.</summary>
    public uint AppOpt;

    /// <summary>Crash report setting.</summary>
    public ulong CrashReport;

    /// <summary>Launch check flags (skip launch check, skip system update check, VR mode, etc.).</summary>
    public uint CheckFlag;
}

/// <summary>The current state of the system service, as <see cref="SystemService.sceSystemServiceGetStatus"/> reports it.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSystemServiceStatus
{
    /// <summary>The number of events waiting to be received.</summary>
    public int EventNum;

    /// <summary>Non-zero when a system dialog is drawn over the application.</summary>
    public byte IsSystemUiOverlaid;

    /// <summary>Non-zero when the application is running in the background.</summary>
    public byte IsInBackgroundExecution;

    private fixed byte _reserved[128];
}

/// <summary>The display's safe-area ratio, as <see cref="SystemService.sceSystemServiceGetDisplaySafeAreaInfo"/> reports it.</summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSystemServiceDisplaySafeAreaInfo
{
    /// <summary>The fraction of the screen, 0 to 1, that is safe to draw important content in.</summary>
    public float Ratio;

    private fixed byte _reserved[128];
}

/// <summary>
/// Status of a running application, as reported by the status query and focused-app query APIs.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceSystemServiceAppStatus
{
    /// <summary>Application identifier.</summary>
    public ulong AppId;

    /// <summary>Application status flags.</summary>
    public uint Status;

    /// <summary>Application state.</summary>
    public uint State;
}

/// <summary>
/// One entry in the application status list returned by
/// <see cref="SystemService.sceSystemServiceGetAppStatusListContainsDaemon"/>. The first 16 bytes
/// carry the <see cref="AppId"/>, <see cref="Status"/>, and <see cref="State"/> fields; the
/// remaining bytes are reserved. Each entry occupies 0x8C (140) bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 0x8C)]
public struct SceSystemServiceAppStatusEntry
{
    /// <summary>Application identifier.</summary>
    public ulong AppId;

    /// <summary>Application status flags.</summary>
    public uint Status;

    /// <summary>Application state.</summary>
    public uint State;
}

/// <summary>
/// One system event. The first four bytes hold the event type, and the remaining 8192 bytes
/// are a union whose contents depend on the type. Messaging events (such as
/// <see cref="SystemService.EventLaunchApp"/>) carry a payload; flag events (such as
/// <see cref="SystemService.EventOnResume"/>) leave the union zeroed.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 8196)]
public unsafe struct SceSystemServiceEvent
{
    /// <summary>The event type, one of the <c>SystemService.Event*</c> values.</summary>
    public int EventType;

    private fixed byte _unionData[8192];

    /// <summary>
    /// Reads the launch argument from a <see cref="SystemService.EventLaunchApp"/> event.
    /// The argument is the UTF-8 string that was passed to
    /// <see cref="SystemService.sceSystemServiceLaunchApp"/>.
    /// </summary>
    /// <param name="arg">Receives the argument string when the event type matches.</param>
    /// <returns><c>true</c> when the event is a launch-app event and <paramref name="arg"/> was
    /// populated; <c>false</c> otherwise.</returns>
    public bool TryGetLaunchAppArg(out string arg)
    {
        if (EventType != SystemService.EventLaunchApp)
        {
            arg = string.Empty;
            return false;
        }
        fixed (byte* p = _unionData)
        {
            int len = 0;
            while (len < 8192 && p[len] != 0) len++;
            arg = len > 0 ? Encoding.UTF8.GetString(p, len) : string.Empty;
        }
        return true;
    }

    /// <summary>
    /// Reads the URI from a <see cref="SystemService.EventAppLaunchLink"/> event. The link is a
    /// NUL-terminated UTF-8 URI that was delivered by the shell.
    /// </summary>
    /// <param name="link">Receives the URI when the event type matches.</param>
    /// <returns><c>true</c> when the event is an app-launch-link event and <paramref name="link"/>
    /// was populated; <c>false</c> otherwise.</returns>
    public bool TryGetAppLaunchLink(out string link)
    {
        if (EventType != SystemService.EventAppLaunchLink)
        {
            link = string.Empty;
            return false;
        }
        fixed (byte* p = _unionData)
        {
            int len = 0;
            while (len < 8192 && p[len] != 0) len++;
            link = len > 0 ? Encoding.UTF8.GetString(p, len) : string.Empty;
        }
        return true;
    }

    /// <summary>
    /// Returns a pointer to the 8192-byte union payload and its maximum length. The caller must
    /// check <see cref="EventType"/> to decide how to interpret the bytes. The pointer is valid
    /// only while this struct is pinned or on the stack.
    /// </summary>
    /// <param name="length">Receives 8192, the union's total byte count.</param>
    /// <returns>A pointer to the first byte of the payload.</returns>
    public byte* GetPayloadPtr(out int length)
    {
        length = 8192;
        fixed (byte* p = _unionData)
        {
            return p;
        }
    }
}

/// <summary>
/// Which flow the system player dialog runs against the target account, as
/// <see cref="SystemService.sceSystemServiceLaunchPlayerDialog"/> reads it from
/// <see cref="SceSystemServicePlayerDialogParam.Mode"/>.
/// </summary>
public enum SceSystemServicePlayerDialogMode : int
{
    /// <summary>Present the send-friend-request flow for the target account.</summary>
    SendFriendRequest = 0,

    /// <summary>Present the block-user flow for the target account.</summary>
    BlockUser = 1,

    /// <summary>Open the target account's profile page.</summary>
    LaunchProfile = 2,
}

/// <summary>
/// Parameters for <see cref="SystemService.sceSystemServiceLaunchPlayerDialog"/>. Fill through
/// <see cref="SystemService.sceSystemServiceInitializePlayerDialogParam"/> before setting the fields
/// the caller wants to change.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public unsafe struct SceSystemServicePlayerDialogParam
{
    /// <summary>Structure size in bytes.</summary>
    public nuint Size;

    /// <summary>Which flow the dialog presents.</summary>
    public SceSystemServicePlayerDialogMode Mode;

    /// <summary>The user id the dialog runs on behalf of (a <c>SceUserServiceUserId</c>, or -1 for none).</summary>
    public int UserId;

    /// <summary>The target account's identifier.</summary>
    public ulong TargetAccountId;

    private fixed byte _reserved[40];
}

/// <summary>
/// The display's HDR tone-map luminance parameters, as
/// <see cref="SystemService.sceSystemServiceGetHdrToneMapLuminance"/> reports them. All three values are
/// candela-per-square-metre luminances the renderer's tone-map curve should reference when the panel is
/// running in an HDR output mode.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct SceSystemServiceHdrToneMapLuminance
{
    /// <summary>Maximum full-frame tone-mapped luminance in candela per square metre.</summary>
    public float MaxFullFrameToneMapLuminance;

    /// <summary>Maximum tone-mapped luminance in candela per square metre.</summary>
    public float MaxToneMapLuminance;

    /// <summary>Minimum tone-mapped luminance in candela per square metre.</summary>
    public float MinToneMapLuminance;
}
