// SharpProspero.Prx - module inspection and stub generation.
// Copyright (C) 2026 SvenGDK

using System.Collections.Generic;

namespace SharpProspero.Prx;

/// <summary>
/// The set of modules an application module imports from, and the function names each provides. A link
/// generates one stub per entry, so a reference to any listed name resolves to the module that carries
/// it without an outside stub file. Entries cover the interop bindings and the operating-system and C
/// runtime functions the compiled image reaches. Extend an entry when a link reports a name as
/// unresolved: add it under the module that exports it.
/// </summary>
public static class StubCatalog
{
    /// <summary>One module and the names it provides.</summary>
    /// <param name="Library">The library base name (the module file is this name with a <c>.prx</c> suffix).</param>
    /// <param name="Exports">The function names the module provides.</param>
    /// <param name="ModuleVersion">
    /// The module version the library publishes, major in the high byte. An import records this, and
    /// the loader binds only when it matches, so an entry that publishes something other than the
    /// common value names it here. Most modules publish 1.1.
    /// </param>
    /// <param name="LibraryVersion">The library version the module publishes. Almost always 1.</param>
    /// <param name="ModuleName">
    /// The module name the providing module publishes, when it differs from <paramref name="Library"/>.
    /// Null means it is the same as the library name, which is the usual case.
    /// </param>
    /// <param name="Soname">
    /// The module file name the loader loads, when it differs from <c>&lt;Library&gt;.prx</c>. Null
    /// means the library name with a <c>.prx</c> suffix, which is the usual case.
    /// </param>
    public readonly record struct Entry(
        string Library,
        IReadOnlyList<string> Exports,
        ushort ModuleVersion = PrxStubEmitter.DefaultModuleVersion,
        ushort LibraryVersion = PrxStubEmitter.DefaultLibraryVersion,
        string? ModuleName = null,
        string? Soname = null);

    /// <summary>The modules the SDK links against, in order.</summary>
    public static IReadOnlyList<Entry> Core =>
    [
        new Entry("libkernel", Kernel),
        // One module, a second library: the same file publishes both.
        new Entry("libScePosix", Posix, ModuleName: "libkernel", Soname: "libkernel.prx"),
        // A third library out of the same file. The console identifier is published under this name and
        // not under the kernel's own, so asking the kernel for it asks for something nothing publishes.
        new Entry("libSceOpenPsId", OpenPsId, ModuleName: "libkernel", Soname: "libkernel.prx"),
        new Entry("libc", C),
        new Entry("libSceVideoOut", VideoOut),
        new Entry("libScePad", Pad),
        new Entry("libSceUserService", UserService),
        new Entry("libSceSystemService", SystemService),
        new Entry("libSceAudioOut", AudioOut),
        // A second library out of the same module as the one above, and an alternative to it rather
        // than a layer over it.
        new Entry("libSceAudioOut2", AudioOut2, ModuleName: "libSceAudioOut", Soname: "libSceAudioOut.prx"),
        new Entry("libSceSysmodule", Sysmodule),
        new Entry("libScePngDec", PngDec),
        new Entry("libScePngEnc", PngEnc),
        new Entry("libSceJpegDec", JpegDec),
        new Entry("libSceJpegEnc", JpegEnc),
        new Entry("libSceAudioIn", AudioIn),
        // The decoder publishes its library under the plain name but the loader loads the file with
        // the dotted one; ten launching titles record exactly this pairing.
        new Entry("libSceAudiodec", Audiodec, Soname: "libSceAudiodec.native.prx"),
        new Entry("libSceM4aacEnc", M4aacEnc),
        new Entry("libSceAt9Enc", At9Enc),
        new Entry("libSceNgs2", Ngs2),
        new Entry("libSceAudio3d", Audio3d),
        // Named the same way as the decoder: library and module libSceAjm, file libSceAjm.native.prx.
        // Fifty-five launching titles record this pairing.
        new Entry("libSceAjm", Ajm, Soname: "libSceAjm.native.prx"),
        // The module publishes these under a library whose name is not the module's, and the file it
        // lives in is not named after the module either. Naming the module as the library asked the
        // loader for a library nothing publishes, out of a file that does not exist, and a module
        // whose imports do not all bind never reaches its first instruction - so any application
        // touching this area failed at load rather than at the call.
        new Entry("libSceVideoRecordingP", VideoRecording,
            ModuleName: "libSceVideoRecording", Soname: "libSceVideoRecording.native.prx"),
        // The character-set converter names all three apart: the file keeps the converter's name, and
        // the library and module are named for the set of them.
        new Entry("libSceCes", Ces, ModuleName: "libSceCes", Soname: "libSceCesCs-module.prx"),
        new Entry("libSceDepth2", Depth2),
        // Published by the bus module, under a library of its own rather than the bus library.
        new Entry("libSceDeviceService", DeviceService, ModuleName: "libSceMbus", Soname: "libSceMbus.prx"),
        new Entry("libSceVideodec2", Videodec2),
        new Entry("libSceRtc", Rtc),
        new Entry("libSceRandom", Random),
        new Entry("libSceZlib", Zlib),
        new Entry("libSceNet", Net),
        // This library publishes module version 2.1.
        new Entry("libSceSsl", Ssl, ModuleVersion: 0x0201),
        new Entry("libSceHttp", Http),
        new Entry("libSceHttp2", Http2),
        new Entry("libkernel_sys", KernelSys, ModuleName: "libkernel", Soname: "libkernel.prx"),
        new Entry("libSceContentDelete", ContentDelete),
        new Entry("libSceContentExport", ContentExport),
        // This library publishes module version 1.0, like the media player and play-go.
        new Entry("libSceContentSearch", ContentSearch, ModuleVersion: 0x0100),
        // This library publishes module version 1.0, like the media player and content search.
        new Entry("libScePlayGo", PlayGo, ModuleVersion: 0x0100),
        // The module publishes a library under a shorter name than its own: library libSceAppContent,
        // module libSceAppContentUtil, file libSceAppContent.prx. Sixty-six launching titles agree.
        new Entry("libSceAppContent", AppContent, ModuleName: "libSceAppContentUtil"),
        new Entry("libSceNetCtl", NetCtl),
        // The save-data module names its file with a dot but its module and library with an
        // underscore, so the file name is given explicitly and the two names default from the library.
        new Entry("libSceSaveData_native", SaveData, Soname: "libSceSaveData.native.prx"),
        new Entry("libSceKeyboard", Keyboard),
        new Entry("libSceMouse", Mouse),
        new Entry("libSceCommonDialog", CommonDialog),
        new Entry("libSceImeDialog", ImeDialog),
        new Entry("libSceErrorDialog", ErrorDialog),
        // This module publishes its library under a name that differs from its module name and its
        // file, so all three are named: library libSceMsgDialog.native, module libSceMsgDialog, file
        // libSceMsgDialog.native.prx (the soname defaults from the library name).
        new Entry("libSceMsgDialog.native", MsgDialog, ModuleName: "libSceMsgDialog"),
        // Names split the same way as the message dialog: library libSceSaveDataDialog.native, module
        // libSceSaveDataDialog, file libSceSaveDataDialog.native.prx.
        new Entry("libSceSaveDataDialog.native", SaveDataDialog, ModuleName: "libSceSaveDataDialog"),
        new Entry("libSceWebBrowserDialog", WebBrowserDialog),
        // This library publishes module version 1.0, the one module in this set that does not use 1.1.
        // This library publishes module version 1.0, the one module in this set that does not use 1.1,
        // and the loader loads the dotted file. Thirty-three launching titles record this pairing.
        new Entry("libSceAvPlayer", AvPlayer, ModuleVersion: 0x0100, Soname: "libSceAvPlayer.native.prx"),
        // The font engine calls its library and its module the same thing and its file something else.
        // Both font files carry a name that is not the library's, and each module says so itself: the
        // file is what the loader loads and the library is what an import binds to.
        new Entry("libSceFont", Font, Soname: "libSceFont-module.prx"),
        new Entry("libSceFontFt", FontFt, Soname: "libSceFontFt-module.prx"),
        new Entry("libSceShare", Share),
        new Entry("libSceNpTrophy2", Trophy2),
        new Entry("libSceNpUniversalDataSystem", UniversalDataSystem),
        new Entry("libSceNotification", Notification),
        new Entry("libSceBluetoothHid", BluetoothHid),
        new Entry("libSceCffMgr", CffMgr),
        // The camera module publishes this library under a name of its own: library libSceCamera2,
        // module libSceCamera, file libSceCamera.prx.
        new Entry("libSceCamera2", Camera2, ModuleName: "libSceCamera", Soname: "libSceCamera.prx"),
        // A fourth library out of the kernel module, alongside the kernel's own, the POSIX one and the
        // console identifier.
        new Entry("libSceCoredump", Coredump, ModuleName: "libkernel", Soname: "libkernel.prx"),
        new Entry("libSceAgc", Agc),
        new Entry("libSceAgcDriver", AgcDriver),
        new Entry("libSceShellCoreUtil", ShellCoreUtil,
            ModuleName: "libSceSystemService", Soname: "libSceSystemService.prx"),
        new Entry("libSceSysUtil", SysUtil),
        new Entry("libSceSystemStateMgr", SystemStateMgr,
            ModuleName: "libSceSystemService", Soname: "libSceSystemService.prx"),
        new Entry("libSceFsInternalForVsh", FsInternalForVsh),
    ];

    /// <summary>
    /// Libraries the SDK resolves by name at run time rather than linking against (the package
    /// installer and USB storage). They are not linked, so they are kept out of <see cref="Core"/> and
    /// the linker never generates a stub for them; the offsets tool matches a supplied module against
    /// them as well, so a contributor can read a run-time service's coverage on a firmware. The names
    /// here are the ones the run-time wrappers resolve, kept in step with the SDK's own registry.
    /// </summary>
    public static IReadOnlyList<Entry> RuntimeResolved =>
    [
        new Entry("libSceAppInstUtil", AppInstUtil),
        // This module publishes version 1.0 and three libraries: libSceUsbStorage, libSceUsbStorageAux
        // and libSceUsbStorageForShellUI. Of the names below, sceUsbStorageGetMountPointOfShellCore is
        // the one the library named here does not carry - the other two publish it. It is reached by
        // name at run time rather than bound at link time, so which library carries it does not decide
        // whether it resolves.
        new Entry("libSceUsbStorage", UsbStorage, ModuleVersion: 0x0100),
        new Entry("libSceAvcap2", Avcap2),
    ];

    // The console's own identifier, published by the kernel module under a library of its own.
    private static readonly string[] OpenPsId =
    [
        "sceKernelGetOpenPsId",
    ];

    // Kernel: direct memory, files, timing, module control, and the thread, synchronization, memory,
    // and thread-local primitives the platform layer forwards to.
    private static readonly string[] Kernel =
    [
        "__error", "__stack_chk_fail", "__tls_get_addr", "sceKernelAllocateDirectMemory",
        // Three the console publishes that the link-time archives leave out. They are here because the
        // console is what an application binds against; without them the calls that read the system
        // version and the settings could never be reached at all.
        "sceKernelGetProsperoSystemSwVersion", "sceKernelGetAllowedSdkVersionOnSystem", "sysctlbyname",
        "sceKernelAvailableDirectMemorySize", "sceKernelAvailableFlexibleMemorySize", "sceKernelCheckReachability", "sceKernelClockGettime",
        "sceKernelClose", "sceKernelDlsym", "sceKernelGetCurrentCpu", "sceKernelGetDirectMemorySize",
        "sceKernelGetProcessTime",
        "sceKernelGetdents", "sceKernelGetdirentries", "sceKernelLoadStartModule", "sceKernelLseek", "sceKernelMapDirectMemory",
        "sceKernelConfiguredFlexibleMemorySize",
        "sceKernelReserveVirtualRange", "sceKernelQueryMemoryProtection",
        "sceKernelMapFlexibleMemory", "sceKernelMapNamedFlexibleMemory", "sceKernelMemoryPoolCommit",
        "sceKernelMemoryPoolDecommit", "sceKernelMemoryPoolExpand", "sceKernelMemoryPoolReserve",
        "sceKernelMkdir", "sceKernelMprotect",
        "sceKernelMunmap", "sceKernelOpen", "sceKernelRead", "sceKernelReleaseDirectMemory",
        "sceKernelReleaseFlexibleMemory", "sceKernelRename", "sceKernelRmdir", "sceKernelSendNotificationRequest",
        "sceKernelStopUnloadModule", "sceKernelTruncate", "sceKernelUnlink", "sceKernelUsleep",
        "sceKernelGetAppInfo",
        "sceKernelVirtualQuery", "sceKernelWrite",
        "scePthreadGetthreadid",
        "scePthreadCondattrInit", "scePthreadCondattrDestroy",
        "scePthreadMutexattrInit", "scePthreadMutexattrSettype", "scePthreadMutexattrDestroy",
        "scePthreadCondBroadcast", "scePthreadCondDestroy",
        "scePthreadCondInit", "scePthreadCondSignal", "scePthreadCondWait", "scePthreadCreate",
        "scePthreadDetach", "scePthreadExit", "scePthreadGetspecific", "scePthreadJoin",
        "scePthreadKeyCreate", "scePthreadKeyDelete", "scePthreadMutexDestroy", "scePthreadMutexInit",
        "scePthreadMutexLock", "scePthreadMutexTrylock", "scePthreadMutexUnlock", "scePthreadRename",
        "scePthreadCondattrSetclock", "scePthreadGetaffinity", "scePthreadSetaffinity",
        "scePthreadSelf", "scePthreadSetspecific",
        "scePthreadYield",
        // Fine-grained timing: a counter far smaller than the microsecond the process-time call reports,
        // the processor's own cycle counter, the frequencies that turn either into seconds, the sleep
        // that takes nanoseconds, and the smallest step a clock can report.
        "sceKernelGetProcessTimeCounter", "sceKernelGetProcessTimeCounterFrequency",
        "sceKernelReadTsc", "sceKernelGetTscFrequency",
        "sceKernelNanosleep", "sceKernelClockGetres",
        // Placing work on a processor. The affinity pair above says where a thread may run; these say how
        // urgently it is served once it is there.
        "scePthreadSetprio", "scePthreadGetprio",
        // The event queue: one place a thread waits for timers, descriptor readiness, file changes and
        // events the application raises itself, instead of polling each source in turn.
        "sceKernelCreateEqueue", "sceKernelDeleteEqueue", "sceKernelWaitEqueue",
        "sceKernelAddTimerEvent", "sceKernelDeleteTimerEvent",
        "sceKernelAddHRTimerEvent", "sceKernelDeleteHRTimerEvent",
        "sceKernelAddReadEvent", "sceKernelDeleteReadEvent",
        "sceKernelAddWriteEvent", "sceKernelDeleteWriteEvent",
        "sceKernelAddFileEvent", "sceKernelDeleteFileEvent",
        "sceKernelAddUserEvent", "sceKernelAddUserEventEdge", "sceKernelDeleteUserEvent",
        "sceKernelTriggerUserEvent",
        "sceKernelGetEventFilter", "sceKernelGetEventId", "sceKernelGetEventData",
        "sceKernelGetEventFflags", "sceKernelGetEventError", "sceKernelGetEventUserData",
        // Event flags and counting semaphores. Both keep state the platform's scheduler knows about, so
        // a thread blocked on either is visible to the system rather than only to the runtime.
        "sceKernelCreateEventFlag", "sceKernelDeleteEventFlag", "sceKernelWaitEventFlag",
        "sceKernelPollEventFlag", "sceKernelSetEventFlag", "sceKernelClearEventFlag",
        "sceKernelCancelEventFlag",
        "sceKernelCreateSema", "sceKernelDeleteSema", "sceKernelWaitSema", "sceKernelPollSema",
        "sceKernelSignalSema", "sceKernelCancelSema",
        // Scheduling policy and the attribute block a thread's settings are chosen from before it starts.
        "scePthreadGetschedparam", "scePthreadSetschedparam", "scePthreadGetcpuclockid",
        "scePthreadEqual",
        "scePthreadAttrInit", "scePthreadAttrDestroy", "scePthreadAttrGet",
        "scePthreadAttrSetstacksize", "scePthreadAttrGetstacksize", "scePthreadAttrGetstack",
        "scePthreadAttrSetguardsize", "scePthreadAttrGetguardsize",
        "scePthreadAttrSetdetachstate", "scePthreadAttrGetdetachstate",
        "scePthreadAttrSetaffinity", "scePthreadAttrGetaffinity",
        "scePthreadAttrSetschedparam", "scePthreadAttrGetschedparam",
        "scePthreadAttrSetschedpolicy", "scePthreadAttrGetschedpolicy",
        "scePthreadAttrSetinheritsched", "scePthreadAttrGetinheritsched",
        // Reading the address space back: what covers an address, what backs it, what it is named, and
        // how many page-table entries are left. A build that maps many small ranges exhausts those
        // before it exhausts memory.
        "sceKernelDirectMemoryQuery", "sceKernelGetDirectMemoryType", "sceKernelIsStack",
        "sceKernelSetVirtualRangeName", "sceKernelGetPageTableStats",
        "sceKernelMsync", "sceKernelMtypeprotect",
        "sceKernelAllocateMainDirectMemory", "sceKernelMapNamedDirectMemory",
        "sceKernelCheckedReleaseDirectMemory", "sceKernelMemoryPoolGetBlockStats",
        // What the process is and what it was started with.
        "getargc", "getargv", "sceKernelUuidCreate",
        // The event queue's direct entries. An application that manages its own event sources
        // through the queue's descriptor rather than the higher-level wrappers above reaches for
        // these. The wrappers do not expose the process filter, so an application that needs it
        // has to ask by name.
        "kqueue", "kevent",
    ];

    // The portable operating-system interface the platform layer forwards to. These are published
    // by the same module as the kernel entry points above but under a library of their own, so an
    // import naming the kernel library for one of them does not resolve.
    private static readonly string[] Posix =
    [
        "chmod", "clock_gettime", "close", "fchmod",
        // The socket calls under their plain names, which the interop bindings declare and an application
        // module links against directly.
        "socket", "bind", "listen", "accept", "connect", "send", "recv", "setsockopt", "shutdown",
        "fcntl", "flock", "fstat", "fsync",
        "ftruncate", "getdents", "getpid", "getsockopt", "gettimeofday",
        "lseek", "madvise", "mkdir", "mlock",
        "mprotect", "msync", "munlock", "munmap",
        "nanosleep", "open", "pread", "preadv",
        "pthread_attr_destroy", "pthread_attr_get_np", "pthread_attr_getstack", "pthread_attr_init",
        "pthread_attr_setdetachstate",
        "pthread_attr_setstacksize", "pthread_cond_broadcast", "pthread_cond_destroy", "pthread_cond_init",
        "pthread_cond_signal", "pthread_cond_timedwait", "pthread_cond_wait", "pthread_condattr_destroy",
        // The older pair of timestamp routines, which the finer pair the runtime asks for stands on.
        "utimes", "futimes",
        "pthread_condattr_init", "pthread_condattr_setclock", "pthread_create", "pthread_getspecific",
        "pthread_key_create",
        "pthread_mutex_destroy", "pthread_mutex_init", "pthread_mutex_lock", "pthread_mutex_unlock",
        "pthread_mutexattr_destroy", "pthread_mutexattr_init", "pthread_mutexattr_settype", "pthread_rwlock_rdlock",
        "pthread_rwlock_unlock", "pthread_rwlock_wrlock", "pthread_self", "pthread_setcancelstate",
        "pthread_setspecific", "pthread_sigmask", "pwrite", "pwritev",
        "read", "rename", "rmdir", "sched_yield",
        "stat", "sync", "unlink", "write",
        // Sizes the system imposes on the process, and the priority bounds a policy accepts. These four
        // are published here only: the kernel library carries no spelling of its own for them.
        "getpagesize", "getdtablesize", "sched_get_priority_max", "sched_get_priority_min",
        // Pinning the whole address space. The per-range pair above is listed already; these two act on
        // everything at once and are refused for a process that has not been granted the right.
        "mlockall", "munlockall",
        // Naming a thread. The compat object forwards to this one rather than to the kernel library's
        // own, because this one answers a plain error number and the other wraps it into a code.
        "pthread_rename_np",
        "sysctl", "getmntinfo", "ptrace", "wait4", "waitpid", "getuid", "geteuid",
    ];

    // C runtime: the allocation, memory, string, control, formatting, and unwind functions the
    // compiled image and its runtime reach.
    private static readonly string[] C =
    [
        // The rest of the arithmetic the C library publishes. The framework's own maths surface
        // reaches these by name, so a program that takes a cube root or a base-two logarithm
        // fails to link without them rather than at the call.
        "acos", "acosf", "acosh", "acoshf",
        "asin", "asinf", "asinh", "asinhf",
        "atan", "atanf", "atanh", "atanhf",
        "cbrt", "cbrtf", "copysign", "copysignf",
        "cosh", "coshf", "exp2", "exp2f",
        "expm1", "expm1f", "fdim", "fdimf",
        "fma", "fmaf", "fmax", "fmaxf",
        "fmin", "fminf", "hypot", "hypotf",
        "ilogb", "ilogbf", "log10", "log10f",
        "log1p", "log1pf", "log2", "log2f",
        "logb", "logbf", "modf", "modff",
        "nearbyint", "nearbyintf", "nextafter", "nextafterf",
        "remainder", "remainderf", "remquo", "remquof",
        "rint", "rintf", "scalbn", "scalbnf",
        "sinh", "sinhf", "tanh", "tanhf",
        "_Unwind_Resume", "__cxa_allocate_exception", "__cxa_atexit", "__cxa_begin_catch",
        "__cxa_end_catch", "__cxa_finalize", "__cxa_free_exception", "__cxa_guard_acquire",
        "__cxa_guard_release", "__cxa_rethrow", "__cxa_throw", "abort",
        "aligned_alloc", "asprintf", "atan2", "atan2f",
        "atexit", "bcmp", "bsearch", "calloc",
        "catchReturnFromMain", "Need_sceLibc",
        "ceil", "ceilf", "cos", "cosf",
        "exit", "exp", "expf", "fabs",
        "fabsf", "fclose", "fflush", "fileno", "floor",
        "floorf", "fmod", "fmodf", "fopen",
        "fprintf", "fputs", "free", "fwrite",
        "log", "logf", "longjmp", "lrand48",
        "malloc", "malloc_usable_size", "memchr", "memcmp",
        "memcpy", "memmove", "memset", "posix_memalign",
        "pow", "powf", "qsort", "realloc",
        "round", "roundf", "setjmp", "sin",
        "sinf", "snprintf", "sqrt", "sqrtf",
        "srand48", "sscanf", "strcasecmp", "strcat",
        "strchr", "strcmp", "strcpy", "strdup",
        "strerror", "strerror_r", "strlen", "strncat",
        "vfprintf",
        "strncmp", "strncpy", "strrchr", "strstr",
        "strtok_r", "strtol", "strtoll", "strtoul",
        "strtoull", "tan", "tanf", "time",
        "trunc", "truncf", "vsnprintf",
        "__stderrp", "__stdoutp", "__stdinp",
        "_init_env",
    ];

    private static readonly string[] VideoOut =
    [
        "sceVideoOutOpen",
        "sceVideoOutClose",
        "sceVideoOutSetBufferAttribute2",
        "sceVideoOutRegisterBuffers2",
        "sceVideoOutUnregisterBuffers",
        "sceVideoOutSetFlipRate",
        "sceVideoOutSubmitFlip",
        "sceVideoOutIsFlipPending",
        "sceVideoOutGetFlipStatus",
        "sceVideoOutWaitVblank",
        "sceVideoOutGetVblankStatus",
        "sceVideoOutAddFlipEvent",
        "sceVideoOutAddVblankEvent",
        "sceVideoOutDeleteFlipEvent",
        "sceVideoOutDeleteVblankEvent",
        "sceVideoOutAddPreVblankStartEvent",
        "sceVideoOutDeletePreVblankStartEvent",
        "sceVideoOutConfigureOutput",
        "sceVideoOutIsOutputSupported",
    ];

    private static readonly string[] Pad =
    [
        "scePadInit",
        "scePadOpen",
        "scePadClose",
        "scePadReadState",
        "scePadSetVibration",
        "scePadSetLightBar",
        "scePadResetLightBar",
        "scePadGetControllerInformation",
        "scePadGetHandle",
        "scePadGetTriggerEffectState",
        "scePadRead",
        "scePadResetOrientation",
        "scePadSetAngularVelocityDeadbandState",
        "scePadSetMotionSensorState",
        "scePadSetTiltCorrectionState",
        "scePadSetTriggerEffect",
        "scePadSetVibrationMode",
        "scePadSetVibrationTriggerEffectWeakWhileEmbeddedMicInUse",
        "scePadSetProcessPrivilege",
    ];

    private static readonly string[] UserService =
    [
        "sceUserServiceInitialize",
        "sceUserServiceTerminate",
        "sceUserServiceGetInitialUser",
        "sceUserServiceGetLoginUserIdList",
        "sceUserServiceGetUserName",
        "sceUserServiceGetUserNumber",
        "sceUserServiceGetAccessibilityChatTranscription",
        "sceUserServiceGetAccessibilityPressAndHoldDelay",
        "sceUserServiceGetAccessibilityTriggerEffect",
        "sceUserServiceGetAccessibilityVibration",
        "sceUserServiceGetAgeLevel",
        "sceUserServiceGetEvent",
        "sceUserServiceGetGamePresets",
        "sceUserServiceInitialize2",
        "sceUserServiceGetForegroundUser",
    ];

    private static readonly string[] SystemService =
    [
        "sceSystemServiceHideSplashScreen",
        "sceSystemServiceParamGetInt",
        "sceSystemServiceParamGetString",
        "sceSystemServiceLaunchApp",
        "sceSystemServiceLoadExec",
        "sceSystemServicePowerTick",
        "sceSystemServiceReceiveEvent",
        "sceSystemServiceGetStatus",
        "sceSystemServiceGetDisplaySafeAreaInfo",
        "sceSystemServiceDisableMediaPlay",
        "sceSystemServiceReenableMediaPlay",
        "sceSystemServiceSetGpuLoadEmulationMode",
        "sceSystemServiceGetGpuLoadEmulationMode",
        "sceSystemServiceReportAbnormalTermination",
        "sceSystemServiceLaunchWebBrowser",
        "sceSystemServiceGetAppIdOfRunningBigApp",
        "sceSystemServiceKillApp",
        "sceSystemServiceNavigateToGoHome",
        "sceSystemServiceGetAppId",
        "sceSystemServiceGetAppTitleId",
        "sceLncUtilGetAppTitleId",
        "sceLncUtilKillApp",
        "sceLncUtilKillAppWithReason",
        "sceLncUtilLaunchApp",
        "sceSystemServiceGetAppStatus",
        "sceSystemServiceAddLocalProcess",
    ];

    private static readonly string[] AudioOut =
    [
        "sceAudioOutInit",
        "sceAudioOutOpen",
        "sceAudioOutClose",
        "sceAudioOutOutput",
        "sceAudioOutOutputs",
        "sceAudioOutSetVolume",
        // What a port will say about itself: where its samples are going, and how far the output has got.
        "sceAudioOutGetPortState",
        "sceAudioOutGetLastOutputTime",
    ];

    // The object-based output path: ports placed in space rather than fed to fixed channels.
    private static readonly string[] AudioOut2 =
    [
        "sceAudioOut2Initialize",
        "sceAudioOut2ContextResetParam",
        "sceAudioOut2ContextQueryMemory",
        "sceAudioOut2ContextCreate",
        "sceAudioOut2ContextDestroy",
        "sceAudioOut2ContextSetAttributes",
        "sceAudioOut2ContextAdvance",
        "sceAudioOut2ContextPush",
        "sceAudioOut2ContextGetQueueLevel",
        "sceAudioOut2PortCreate",
        "sceAudioOut2PortDestroy",
        "sceAudioOut2PortSetAttributes",
        "sceAudioOut2PortGetState",
        "sceAudioOut2GetSpeakerArrayMemorySize",
        "sceAudioOut2SpeakerArrayCreate",
        "sceAudioOut2SpeakerArrayDestroy",
        "sceAudioOut2GetSpeakerArrayCoefficients",
        "sceAudioOut2GetSpeakerArrayAmbisonicsCoefficients",
        "sceAudioOut2GetSystemState",
        "sceAudioOut2GetSpeakerInfo",
        "sceAudioOut2UserCreate",
        "sceAudioOut2UserDestroy",
        "sceAudioOut2UserGetSupportedAttributes",
        "sceAudioOut2EnableChat",
        "sceAudioOut2DisableChat",
        "sceAudioOut2MasteringInit",
        "sceAudioOut2MasteringTerm",
        "sceAudioOut2MasteringSetParam",
        "sceAudioOut2MasteringGetState",
    ];

    private static readonly string[] Sysmodule =
    [
        "sceSysmoduleLoadModule",
        "sceSysmoduleUnloadModule",
        "sceSysmoduleLoadModuleInternal",
        "sceSysmoduleUnloadModuleInternal",
        "sceSysmoduleLoadModuleByNameInternal",
        "sceSysmoduleIsLoaded",
    ];

    private static readonly string[] PngDec =
    [
        "scePngDecCreate",
        "scePngDecDelete",
        "scePngDecParseHeader",
        "scePngDecQueryMemorySize",
        "scePngDecDecode",
    ];

    private static readonly string[] PngEnc =
    [
        "scePngEncQueryMemorySize",
        "scePngEncCreate",
        "scePngEncEncode",
        "scePngEncDelete",
    ];

    // The scalable-font engine.
    private static readonly string[] Font =
    [
        "sceFontMemoryInit",
        "sceFontMemoryTerm",
        "sceFontCreateLibraryWithEdition",
        "sceFontDestroyLibrary",
        "sceFontSupportExternalFonts",
        "sceFontSupportSystemFonts",
        "sceFontAttachDeviceCacheBuffer",
        "sceFontOpenFontMemory",
        "sceFontOpenFontSet",
        "sceFontCloseFont",
        "sceFontCreateRendererWithEdition",
        "sceFontDestroyRenderer",
        "sceFontBindRenderer",
        "sceFontUnbindRenderer",
        "sceFontSetupRenderScalePixel",
        "sceFontGetRenderCharGlyphMetrics",
        "sceFontGetHorizontalLayout",
        "sceFontRenderCharGlyphImageHorizontal",
        "sceFontRenderSurfaceInit",
        "sceFontRenderSurfaceSetScissor",
        "sceFontGetRenderScaledKerning",
        "sceFontGetScalePixel",
        "sceFontSetResolutionDpi",
        "sceFontSetScalePixel",
        "sceFontSetScalePoint",
    ];

    // The FreeType backend for the font engine.
    private static readonly string[] FontFt =
    [
        "sceFontSelectLibraryFt",
        "sceFontSelectRendererFt",
    ];

    // Screenshot and video-clip capture of the composited output.
    private static readonly string[] Share =
    [
        "sceShareInitialize",
        "sceShareTerminate",
        "sceShareCaptureScreenshot",
        "sceShareCaptureVideoClip",
        "sceShareGetCurrentStatus",
        "sceShareSetScreenshotOverlayImage",
        "sceShareFeaturePermit",
        "sceShareFeatureProhibit",
    ];

    private static readonly string[] Trophy2 =
    [
        "sceNpTrophy2CreateHandle",
        "sceNpTrophy2DestroyHandle",
        "sceNpTrophy2AbortHandle",
        "sceNpTrophy2CreateContext",
        "sceNpTrophy2DestroyContext",
        "sceNpTrophy2RegisterContext",
        "sceNpTrophy2RegisterUnlockCallback",
        "sceNpTrophy2UnregisterUnlockCallback",
        "sceNpTrophy2GetGameInfo",
        "sceNpTrophy2GetGroupInfo",
        "sceNpTrophy2GetGroupInfoArray",
        "sceNpTrophy2GetTrophyInfo",
        "sceNpTrophy2GetTrophyInfoArray",
        "sceNpTrophy2GetGameIcon",
        "sceNpTrophy2GetGroupIcon",
        "sceNpTrophy2GetTrophyIcon",
        "sceNpTrophy2GetRewardIcon",
        "sceNpTrophy2ShowTrophyList",
    ];

    private static readonly string[] UniversalDataSystem =
    [
        "sceNpUniversalDataSystemInitialize",
        "sceNpUniversalDataSystemTerminate",
        "sceNpUniversalDataSystemGetMemoryStat",
        "sceNpUniversalDataSystemCreateContext",
        "sceNpUniversalDataSystemDestroyContext",
        "sceNpUniversalDataSystemRegisterContext",
        "sceNpUniversalDataSystemCreateHandle",
        "sceNpUniversalDataSystemDestroyHandle",
        "sceNpUniversalDataSystemAbortHandle",
        "sceNpUniversalDataSystemPostEvent",
        "sceNpUniversalDataSystemCreateEvent",
        "sceNpUniversalDataSystemDestroyEvent",
        "sceNpUniversalDataSystemEventEstimateSize",
        "sceNpUniversalDataSystemEventToString",
        "sceNpUniversalDataSystemCreateEventPropertyObject",
        "sceNpUniversalDataSystemDestroyEventPropertyObject",
        "sceNpUniversalDataSystemEventPropertyObjectSetString",
        "sceNpUniversalDataSystemEventPropertyObjectSetInt32",
        "sceNpUniversalDataSystemEventPropertyObjectSetUInt32",
        "sceNpUniversalDataSystemEventPropertyObjectSetInt64",
        "sceNpUniversalDataSystemEventPropertyObjectSetUInt64",
        "sceNpUniversalDataSystemEventPropertyObjectSetFloat32",
        "sceNpUniversalDataSystemEventPropertyObjectSetFloat64",
        "sceNpUniversalDataSystemEventPropertyObjectSetBool",
        "sceNpUniversalDataSystemEventPropertyObjectSetBinary",
        "sceNpUniversalDataSystemEventPropertyObjectSetObject",
        "sceNpUniversalDataSystemEventPropertyObjectSetArray",
        "sceNpUniversalDataSystemCreateEventPropertyArray",
        "sceNpUniversalDataSystemDestroyEventPropertyArray",
        "sceNpUniversalDataSystemEventPropertyArraySetString",
        "sceNpUniversalDataSystemEventPropertyArraySetInt32",
        "sceNpUniversalDataSystemEventPropertyArraySetUInt32",
        "sceNpUniversalDataSystemEventPropertyArraySetInt64",
        "sceNpUniversalDataSystemEventPropertyArraySetUInt64",
        "sceNpUniversalDataSystemEventPropertyArraySetFloat32",
        "sceNpUniversalDataSystemEventPropertyArraySetFloat64",
        "sceNpUniversalDataSystemEventPropertyArraySetBool",
        "sceNpUniversalDataSystemEventPropertyArraySetBinary",
        "sceNpUniversalDataSystemEventPropertyArraySetObject",
        "sceNpUniversalDataSystemEventPropertyArraySetArray",
        "sceNpUniversalDataSystemGetStorageStat",
    ];

    private static readonly string[] Notification =
    [
        "sceNotificationSend",
        "sceNotificationSendById",
        "sceNotificationShowPsButtonPersistentBanner",
        "sceNotificationHidePsButtonPersistentBanner",
    ];

    private static readonly string[] BluetoothHid =
    [
        "sceBluetoothHidInit",
        "sceBluetoothHidParamInitialize",
        "sceBluetoothHidThreadParamInitialize",
        "sceBluetoothHidRegisterCallback",
        "sceBluetoothHidUnregisterCallback",
        "sceBluetoothHidRegisterDevice",
        "sceBluetoothHidUnregisterDevice",
        "sceBluetoothHidGetReportDescriptor",
        "sceBluetoothHidGetDeviceName",
        "sceBluetoothHidGetDeviceInfo",
        "sceBluetoothHidGetInputReport",
        "sceBluetoothHidGetFeatureReport",
        "sceBluetoothHidSetOutputReport",
        "sceBluetoothHidSetFeatureReport",
        "sceBluetoothHidInterruptOutput",
        "sceBluetoothHidDisconnectDevice",
        "sceBluetoothHidDebugGetVersion",
    ];

    private static readonly string[] CffMgr =
    [
        "sceConsoleFeatureFlagManagerIsOn",
        "sceConsoleFeatureFlagManagerIsWaitingReboot",
    ];

    private static readonly string[] JpegDec =
    [
        "sceJpegDecCreate",
        "sceJpegDecDelete",
        "sceJpegDecParseHeader",
        "sceJpegDecQueryMemorySize",
        "sceJpegDecDecode",
    ];

    private static readonly string[] JpegEnc =
    [
        "sceJpegEncQueryMemorySize",
        "sceJpegEncCreate",
        "sceJpegEncEncode",
        "sceJpegEncDelete",
    ];

    // Microphone and other audio capture.
    private static readonly string[] AudioIn =
    [
        "sceAudioInOpen",
        "sceAudioInInput",
        "sceAudioInGetSilentState",
        "sceAudioInClose",
    ];

    private static readonly string[] Audiodec =
    [
        "sceAudiodecInitLibrary",
        "sceAudiodecTermLibrary",
        "sceAudiodecCreateDecoder",
        "sceAudiodecDeleteDecoder",
        "sceAudiodecDecode",
        "sceAudiodecClearContext",
    ];

    private static readonly string[] M4aacEnc =
    [
        "sceM4aacEncCreateEncoder",
        "sceM4aacEncDeleteEncoder",
        "sceM4aacEncEncode",
        "sceM4aacEncFlush",
        "sceM4aacEncClearContext",
    ];

    private static readonly string[] At9Enc =
    [
        "sceAt9EncQueryMemSize",
        "sceAt9EncCreateEncoder",
        "sceAt9EncEncode",
        "sceAt9EncFlush",
        "sceAt9EncClearContext",
    ];

    private static readonly string[] Ngs2 =
    [
        "sceNgs2SystemEnumHandles",
        "sceNgs2SystemResetOption",
        "sceNgs2SystemQueryBufferSize",
        "sceNgs2SystemCreate",
        "sceNgs2SystemCreateWithAllocator",
        "sceNgs2SystemDestroy",
        "sceNgs2SystemRunCommands",
        "sceNgs2SystemQueryInfo",
        "sceNgs2SystemLock",
        "sceNgs2SystemUnlock",
        "sceNgs2SystemSetUserData",
        "sceNgs2SystemGetUserData",
        "sceNgs2SystemGetInfo",
        "sceNgs2SystemSetGrainSamples",
        "sceNgs2SystemSetSampleRate",
        "sceNgs2SystemEnumRackHandles",
        "sceNgs2SystemRender",
        "sceNgs2RackQueryBufferSize",
        "sceNgs2RackCreate",
        "sceNgs2RackCreateWithAllocator",
        "sceNgs2RackDestroy",
        "sceNgs2RackRunCommands",
        "sceNgs2RackQueryInfo",
        "sceNgs2RackLock",
        "sceNgs2RackUnlock",
        "sceNgs2RackSetUserData",
        "sceNgs2RackGetUserData",
        "sceNgs2RackGetInfo",
        "sceNgs2RackGetVoiceHandle",
        "sceNgs2VoiceRunCommands",
        "sceNgs2VoiceQueryInfo",
        "sceNgs2VoiceControl",
        "sceNgs2VoiceGetStateFlags",
        "sceNgs2VoiceGetState",
        "sceNgs2VoiceGetOwner",
        "sceNgs2VoiceGetMatrixInfo",
        "sceNgs2VoiceGetPortInfo",
        "sceNgs2StreamResetOption",
        "sceNgs2StreamQueryBufferSize",
        "sceNgs2StreamCreate",
        "sceNgs2StreamCreateWithAllocator",
        "sceNgs2StreamDestroy",
        "sceNgs2StreamRunCommands",
        "sceNgs2StreamQueryInfo",
        "sceNgs2ParseWaveformData",
        "sceNgs2ParseWaveformFile",
        "sceNgs2ParseWaveformUser",
        "sceNgs2CalcWaveformBlock",
        "sceNgs2GetWaveformFrameInfo",
        "sceNgs2JobSchedulerResetOption",
        "sceNgs2GeomResetListenerParam",
        "sceNgs2GeomResetSourceParam",
        "sceNgs2GeomCalcListener",
        "sceNgs2GeomApply",
        "sceNgs2PanInit",
        "sceNgs2PanGetVolumeMatrix",
        "sceNgs2ReportRegisterHandler",
        "sceNgs2ReportUnregisterHandler",
        "sceNgs2CustomRackGetModuleInfo",
    ];

    private static readonly string[] Audio3d =
    [
        "sceAudio3dInitialize",
        "sceAudio3dTerminate",
        "sceAudio3dPortOpen",
        "sceAudio3dPortClose",
        "sceAudio3dPortSetAttribute",
        "sceAudio3dPortAdvance",
        "sceAudio3dPortPush",
        "sceAudio3dPortGetAttributesSupported",
        "sceAudio3dPortGetQueueLevel",
        "sceAudio3dObjectReserve",
        "sceAudio3dObjectUnreserve",
        "sceAudio3dObjectSetAttributes",
        "sceAudio3dBedWrite",
        "sceAudio3dBedWrite2",
        "sceAudio3dGetSpeakerArrayMemorySize",
        "sceAudio3dCreateSpeakerArray",
        "sceAudio3dDeleteSpeakerArray",
        "sceAudio3dGetSpeakerArrayMixCoefficients",
        "sceAudio3dGetSpeakerArrayMixCoefficients2",
        "sceAudio3dAudioOutOpen",
        "sceAudio3dAudioOutClose",
        "sceAudio3dAudioOutOutput",
        "sceAudio3dAudioOutOutputs",
        "sceAudio3dPortCreate",
        "sceAudio3dPortDestroy",
        "sceAudio3dPortFlush",
    ];

    private static readonly string[] Ajm =
    [
        "sceAjmInitialize",
        "sceAjmFinalize",
        "sceAjmMemoryRegister",
        "sceAjmMemoryUnregister",
        "sceAjmModuleRegister",
        "sceAjmModuleUnregister",
        "sceAjmInstanceCreate",
        "sceAjmInstanceExtend",
        "sceAjmInstanceSwitch",
        "sceAjmInstanceDestroy",
        "sceAjmBatchInitialize",
        "sceAjmBatchJobInitialize",
        "sceAjmBatchJobClearContext",
        "sceAjmBatchJobDecode",
        "sceAjmBatchJobDecodeSingle",
        "sceAjmBatchJobDecodeSplit",
        "sceAjmBatchJobEncode",
        "sceAjmBatchJobGetInfo",
        "sceAjmBatchJobGetCodecInfo",
        "sceAjmBatchJobSetGaplessDecode",
        "sceAjmBatchJobGetGaplessDecode",
        "sceAjmBatchJobSetResampleParameters",
        "sceAjmBatchJobSetResampleParametersEx",
        "sceAjmBatchJobGetResampleInfo",
        "sceAjmBatchStart",
        "sceAjmBatchWait",
        "sceAjmBatchCancel",
        "sceAjmBatchErrorDump",
        "sceAjmBatchJobGetStatistics",
        "sceAjmBatchJobControl",
        "sceAjmBatchJobRun",
        "sceAjmBatchJobRunSplit",
    ];

    private static readonly string[] VideoRecording =
    [
        "sceVideoRecordingGetStatus",
        "sceVideoRecordingQueryMemSize",
        "sceVideoRecordingOpen",
        "sceVideoRecordingStart",
        "sceVideoRecordingStop",
        "sceVideoRecordingClose",
    ];

    private static readonly string[] Ces =
    [
        "sceCesEucJpToUtf8",
        "sceCesEucKrToUtf8",
        "sceCesBig5ToUtf8",
        "sceCesUhcToUtf8",
        // The conversions take a profile and refuse a null one, so the routines that build a profile
        // are as necessary as the conversions themselves.
        "sceCesUcsProfileInitEucJpX0208",
        "sceCesUcsProfileInitEucJpX0208Ss2",
        "sceCesUcsProfileInitEucJpX0208Ss2Ss3",
        "sceCesUcsProfileInitEucJpCp51932",
        "sceCesUcsProfileInitEucKr",
        "sceCesUcsProfileInitBig5Cp950",
        "sceCesUcsProfileInitUhc",
    ];

    private static readonly string[] Depth2 =
    [
        "sceDepth2QueryMemory",
        "sceDepth2Initialize",
        "sceDepth2Terminate",
        "sceDepth2SetCommand",
        "sceDepth2Submit",
        "sceDepth2WaitAndExecutePostProcess",
        "sceDepth2SetRoi",
        "sceDepth2GetImage",
    ];

    // The device-enquiry library. It is published by the bus module rather than by one of its own, so an
    // import names that module's file while naming this library - the two are different words, and
    // naming the bus library instead produces an import the bus library cannot answer.
    private static readonly string[] DeviceService =
    [
        "sceDeviceServiceInitialize",
        "sceDeviceServiceTerminate",
        "sceDeviceServiceGetGeneration",
        "sceDeviceServiceGetEventState",
        "sceDeviceServiceQueryDeviceInfo_",
    ];

    private static readonly string[] Videodec2 =
    [
        "sceVideodec2QueryComputeMemoryInfo",
        "sceVideodec2AllocateComputeQueue",
        "sceVideodec2ReleaseComputeQueue",
        "sceVideodec2QueryDecoderMemoryInfo",
        "sceVideodec2CreateDecoder",
        "sceVideodec2DeleteDecoder",
        "sceVideodec2Decode",
        "sceVideodec2Flush",
        "sceVideodec2Reset",
    ];

    private static readonly string[] Rtc =
    [
        "sceRtcGetCurrentClock",
        "sceRtcGetCurrentClockLocalTime",
        "sceRtcGetCurrentTick",
        "sceRtcGetCurrentNetworkTick",
        "sceRtcGetTickResolution",
        "sceRtcConvertUtcToLocalTime",
        "sceRtcConvertLocalTimeToUtc",
        "sceRtcSetTick",
        "sceRtcGetTick",
    ];

    private static readonly string[] Random =
    [
        "sceRandomGetRandomNumber",
    ];

    // Save data: enumerate, mount, read parameters, delete.
    private static readonly string[] SaveData =
    [
        "sceSaveDataInitialize3",
        "sceSaveDataTerminate",
        "sceSaveDataMount3",
        "sceSaveDataUmount2",
        "sceSaveDataGetMountInfo",
        "sceSaveDataDelete",
        "sceSaveDataDirNameSearch",
        "sceSaveDataBackup",
        "sceSaveDataCommit",
        "sceSaveDataCreateTransactionResource",
        "sceSaveDataDeleteTransactionResource",
        "sceSaveDataGetParam",
        "sceSaveDataLoadIcon",
        "sceSaveDataPrepare",
        "sceSaveDataSaveIcon",
        "sceSaveDataSaveIconByPath",
        "sceSaveDataSetParam",
    ];

    // Install and download progress.
    private static readonly string[] PlayGo =
    [
        "scePlayGoInitialize",
        "scePlayGoTerminate",
        "scePlayGoOpen",
        "scePlayGoClose",
        "scePlayGoGetLocus",
        "scePlayGoGetProgress",
    ];

    // Additional content and application parameters.
    private static readonly string[] AppContent =
    [
        "sceAppContentInitialize",
        "sceAppContentAppParamGetInt",
        "sceAppContentAddcontEnqueueDownload",
        "sceAppContentAddcontMount",
        "sceAppContentAddcontUnmount",
        "sceAppContentDownloadDataFormat",
        "sceAppContentDownloadDataGetAvailableSpaceKb",
        "sceAppContentGetAddcontDownloadProgress",
        "sceAppContentTemporaryDataFormat",
        "sceAppContentTemporaryDataGetAvailableSpaceKb",
        "sceAppContentTemporaryDataMount2",
        "sceAppContentTemporaryDataUnmount",
    ];

    // Content deletion (captures and other content).
    private static readonly string[] ContentDelete =
    [
        "sceContentDeleteInitialize",
        "sceContentDeleteTerminate",
        "sceContentDeleteById",
        "sceContentDeleteByPath",
    ];

    // Content export (copy a file into the content library).
    private static readonly string[] ContentExport =
    [
        "sceContentExportInit2",
        "sceContentExportTerm",
        "sceContentExportStart",
        "sceContentExportFinish",
        "sceContentExportFromFile",
        "sceContentExportCancel",
        "sceContentExportGetProgress",
        "sceContentExportFromData",
        "sceContentExportFromDataWithThumbnail",
        "sceContentExportFromFileWithThumbnail",
    ];

    // Content search (the library of captures and imported media).
    private static readonly string[] ContentSearch =
    [
        "sceContentSearchInit",
        "sceContentSearchTerm",
        "sceContentSearchGetContentLastUpdateId",
        "sceContentSearchGetNumOfContent",
        "sceContentSearchGetTotalContentSize",
        "sceContentSearchSearchContent",
        "sceContentSearchOpenMetadata",
        "sceContentSearchOpenMetadataByContentId",
        "sceContentSearchCloseMetadata",
        "sceContentSearchGetMetadataFieldInfo",
        "sceContentSearchGetMetadataValue",
    ];

    // The network library: the memory pool the HTTP and TLS services draw from, the BSD-style socket
    // calls, the poller, and the name resolver.
    private static readonly string[] Net =
    [
        "sceNetPoolCreate",
        "sceNetPoolDestroy",
        "sceNetSocket",
        "sceNetBind",
        "sceNetListen",
        "sceNetAccept",
        "sceNetConnect",
        "sceNetSend",
        "sceNetSendto",
        "sceNetRecv",
        "sceNetRecvfrom",
        "sceNetSocketClose",
        "sceNetShutdown",
        "sceNetSocketAbort",
        "sceNetSetsockopt",
        "sceNetGetsockopt",
        "sceNetGetsockname",
        "sceNetGetpeername",
        "sceNetErrnoLoc",
        "sceNetEpollCreate",
        "sceNetEpollControl",
        "sceNetEpollWait",
        "sceNetEpollDestroy",
        "sceNetEpollAbort",
        "sceNetResolverCreate",
        "sceNetResolverStartNtoa",
        "sceNetResolverDestroy",
        "sceNetInit",
    ];

    // The TLS context the HTTP service uses.
    private static readonly string[] Ssl =
    [
        "sceSslInit",
        "sceSslTerm",
        "sceSslClose",
        "sceSslConnect",
        "sceSslCreateConnection",
        "sceSslDeleteConnection",
        "sceSslDisableVerifyOption",
        "sceSslEnableVerifyOption",
        "sceSslGetAlpnSelected",
        "sceSslLoadCert",
        "sceSslRead",
        "sceSslRecv",
        "sceSslReuseConnection",
        "sceSslSend",
        "sceSslSetAlpn",
        "sceSslSetMinSslVersion",
        "sceSslSetVerifyCallback",
        "sceSslUnloadCert",
        "sceSslWrite",
    ];

    // HTTP downloads.
    private static readonly string[] Http =
    [
        "sceHttpInit",
        "sceHttpTerm",
        "sceHttpCreateTemplate",
        "sceHttpDeleteTemplate",
        "sceHttpCreateConnectionWithURL",
        "sceHttpDeleteConnection",
        "sceHttpCreateRequestWithURL",
        "sceHttpDeleteRequest",
        "sceHttpSendRequest",
        "sceHttpGetStatusCode",
        "sceHttpGetResponseContentLength",
        "sceHttpReadData",
        "sceHttpSetConnectTimeOut",
        "sceHttpSetRecvTimeOut",
        "sceHttpAbortRequest",
        "sceHttpAddRequestHeader",
        "sceHttpCreateRequestWithURL2",
        "sceHttpGetAllResponseHeaders",
        "sceHttpGetAutoRedirect",
        "sceHttpGetLastErrno",
        "sceHttpParseResponseHeader",
        "sceHttpParseStatusLine",
        "sceHttpRemoveRequestHeader",
        "sceHttpSetAutoRedirect",
        "sceHttpSetChunkedTransferEnabled",
        "sceHttpSetInflateGZIPEnabled",
        "sceHttpSetRequestContentLength",
        "sceHttpSetResolveRetry",
        "sceHttpSetResolveTimeOut",
        "sceHttpSetResponseHeaderMaxSize",
        "sceHttpSetSendTimeOut",
        "sceHttpUriBuild",
        "sceHttpUriEscape",
        "sceHttpUriMerge",
        "sceHttpUriParse",
        "sceHttpUriSweepPath",
        "sceHttpUriUnescape",
        "sceHttpsDisableOption",
        "sceHttpsEnableOption",
        "sceHttpsGetSslError",
        "sceHttpsLoadCert",
        "sceHttpsSetSslVersion",
        "sceHttpsUnloadCert",
    ];

    // HTTP/2 client. Used by the http2_get template for HTTP/2 requests.
    private static readonly string[] Http2 =
    [
        "sceHttp2Init", "sceHttp2Term",
        "sceHttp2CreateTemplate", "sceHttp2DeleteTemplate",
        "sceHttp2CreateRequestWithURL", "sceHttp2DeleteRequest",
        "sceHttp2SendRequest", "sceHttp2GetStatusCode", "sceHttp2ReadData",
    ];

    // Hardware information from the kernel system-level interface.
    private static readonly string[] KernelSys =
    [
        "sceKernelGetHwModelName", "sceKernelGetHwSerialNumber",
        "sceKernelGetCpuFrequency", "sceKernelGetCpuTemperature",
        "sceKernelGetSocSensorTemperature",
        "sceKernelGetCurrentFanDuty",
        "sceKernelPrepareToSuspendProcess", "sceKernelSuspendProcess",
        "sceKernelPrepareToResumeProcess", "sceKernelResumeProcess",
        "sceKernelTerminateProcess", "sceKernelSpawn",
    ];

    // Asynchronous zlib decompression.
    private static readonly string[] Zlib =
    [
        "sceZlibInitialize",
        "sceZlibFinalize",
        "sceZlibInflate",
        "sceZlibWaitForDone",
        "sceZlibGetResult",
    ];

    // Network connection status.
    private static readonly string[] NetCtl =
    [
        "sceNetCtlInit",
        "sceNetCtlTerm",
        "sceNetCtlGetState",
        "sceNetCtlGetInfo",
    ];

    // USB keyboard input.
    private static readonly string[] Keyboard =
    [
        "sceKeyboardInit",
        "sceKeyboardOpen",
        "sceKeyboardClose",
        "sceKeyboardReadState",
        "sceKeyboardRead",
        "sceKeyboardGetKey2Char",
    ];

    // USB mouse input.
    private static readonly string[] Mouse =
    [
        "sceMouseInit",
        "sceMouseOpen",
        "sceMouseClose",
        "sceMouseRead",
    ];

    // The shared dialog subsystem every common dialog is brought up on before it opens.
    private static readonly string[] CommonDialog =
    [
        "sceCommonDialogInitialize",
        "sceCommonDialogIsUsed",
    ];

    // The system message dialog (progress bar, buttons, system messages).
    private static readonly string[] MsgDialog =
    [
        "sceMsgDialogInitialize",
        "sceMsgDialogTerminate",
        "sceMsgDialogOpen",
        "sceMsgDialogClose",
        "sceMsgDialogUpdateStatus",
        "sceMsgDialogGetStatus",
        "sceMsgDialogGetResult",
        "sceMsgDialogProgressBarInc",
        "sceMsgDialogProgressBarSetValue",
        "sceMsgDialogProgressBarSetMsg",
    ];

    // The system error dialog.
    private static readonly string[] ErrorDialog =
    [
        "sceErrorDialogInitialize",
        "sceErrorDialogTerminate",
        "sceErrorDialogOpen",
        "sceErrorDialogClose",
        "sceErrorDialogUpdateStatus",
        "sceErrorDialogGetStatus",
    ];

    // The save-data dialog (list, confirm and report on saves).
    private static readonly string[] SaveDataDialog =
    [
        "sceSaveDataDialogInitialize",
        "sceSaveDataDialogTerminate",
        "sceSaveDataDialogUpdateStatus",
        "sceSaveDataDialogGetStatus",
        "sceSaveDataDialogOpen",
        "sceSaveDataDialogGetResult",
        "sceSaveDataDialogClose",
        "sceSaveDataDialogIsReadyToDisplay",
    ];

    // The on-screen keyboard.
    private static readonly string[] ImeDialog =
    [
        "sceImeDialogInit",
        "sceImeDialogGetStatus",
        "sceImeDialogGetResult",
        "sceImeDialogAbort",
        "sceImeDialogTerm",
        "sceImeDialogGetPanelSizeExtended",
        "sceImeDialogGetPanelPositionAndForm",
    ];

    private static readonly string[] WebBrowserDialog =
    [
        "sceWebBrowserDialogInitialize",
        "sceWebBrowserDialogOpen",
        "sceWebBrowserDialogUpdateStatus",
        "sceWebBrowserDialogGetStatus",
        "sceWebBrowserDialogGetResult",
        "sceWebBrowserDialogClose",
        "sceWebBrowserDialogTerminate",
        "sceWebBrowserDialogResetCookie",
    ];

    private static readonly string[] AvPlayer =
    [
        "sceAvPlayerInit",
        "sceAvPlayerInitEx",
        "sceAvPlayerPostInit",
        "sceAvPlayerAddSource",
        "sceAvPlayerStart",
        "sceAvPlayerStop",
        "sceAvPlayerPause",
        "sceAvPlayerResume",
        "sceAvPlayerIsActive",
        "sceAvPlayerSetLooping",
        "sceAvPlayerGetAudioData",
        "sceAvPlayerGetVideoDataEx",
        "sceAvPlayerCurrentTime",
        "sceAvPlayerJumpToTime",
        "sceAvPlayerStreamCount",
        "sceAvPlayerGetStreamInfo",
        "sceAvPlayerEnableStream",
        "sceAvPlayerDisableStream",
        "sceAvPlayerChangeStream",
        "sceAvPlayerSetLogCallback",
        "sceAvPlayerClose",
    ];

    // The package installer, resolved by name at run time (Platform.PackageInstaller). Kept in step
    // with the SDK's own registry entry for the installer.
    private static readonly string[] AppInstUtil =
    [
        "sceAppInstUtilInitialize",
        "sceAppInstUtilTerminate",
        "sceAppInstUtilAppInstallPkg",
        "sceAppInstUtilAppExists",
        "sceAppInstUtilAppGetSize",
        "sceAppInstUtilAppUnInstall",
        "sceAppInstUtilAppUnInstall2",
        "sceAppInstUtilAppInstallTitleDir",
        "sceAppInstUtilAppInstallAll",
        "sceAppInstUtilInstallByPackage",
    ];

    // USB mass storage, resolved by name at run time (Platform.UsbStorage). Kept in step with the
    // SDK's own registry entry for USB storage.
    private static readonly string[] UsbStorage =
    [
        "sceUsbStorageInit",
        "sceUsbStorageTerm",
        "sceUsbStorageGetDeviceList",
        "sceUsbStorageGetMountPointOfShellCore",
        "sceUsbStorageRequestMap",
        "sceUsbStorageRequestUnmap",
    ];

    // The system-composited AV-capture service. Resolved at run time and reached only by a process with
    // the privilege for it, so it is not linked; the names let the offsets tool report its coverage.
    private static readonly string[] Avcap2 =
    [
        "sceAvcap2Initialize",
        "sceAvcap2Terminate",
        "sceAvcap2OpenAudio",
        "sceAvcap2OpenVideo",
        "sceAvcap2Close",
        "sceAvcap2Start",
        "sceAvcap2Stop",
        "sceAvcap2ReadAudio",
        "sceAvcap2ReadVideo",
        "sceAvcap2GetFramePitch",
        "sceAvcap2GetSupportInformation",
        "sceAvcap2GetVideoOutMode",
        "sceAvcap2GetRecProhibit",
        "sceAvcap2GetNonVclNalUnitStream",
        "sceAvcap2GetNonVclNalUnitStream2",
        "sceAvcap2Select",
        "sceAvcap2MapMemory",
        "sceAvcap2LockInputDataBuffer",
        "sceAvcap2UnlockInputDataBuffer",
        "sceAvcap2SetVideoEncodeConfig",
        "sceAvcap2QueryVideoEncoderMemorySize",
        "sceAvcap2AllocateVideoEncoderMemory",
        "sceAvcap2FreeEncoderVideoMemory",
        "sceAvcap2SetInvalidFrame",
        "sceAvcap2SetPrivacyGuard",
        "sceAvcap2SetAudioOutVolume",
        "sceAvcap2SetAudioOutVolumeForRec",
        "sceAvcap2SetMicVolumeForRec",
        "sceAvcap2SetChapterOpenLevel",
        "sceAvcap2SetChapterPermissionLevel",
    ];

    // The front camera, published by the camera module under a library of its own.
    private static readonly string[] Camera2 =
    [
        "sceCamera2Close",
        "sceCamera2Finalize",
        "sceCamera2GetAttribute",
        "sceCamera2GetAutoExposureGain",
        "sceCamera2GetAutoWhiteBalance",
        "sceCamera2GetConfig",
        "sceCamera2GetExposureGain",
        "sceCamera2GetFieldOfView",
        "sceCamera2GetFrameData",
        "sceCamera2GetWhiteBalance",
        "sceCamera2Initialize",
        "sceCamera2IsAttached",
        "sceCamera2IsValidFrameData",
        "sceCamera2Open",
        "sceCamera2SetAttribute",
        "sceCamera2SetAutoExposureGain",
        "sceCamera2SetAutoWhiteBalance",
        "sceCamera2SetConfig",
        "sceCamera2SetExposureGain",
        "sceCamera2SetVideoSync",
        "sceCamera2SetWhiteBalance",
        "sceCamera2Start",
        "sceCamera2Stop",
    ];

    // Crash reporting: what an application adds to the report the system writes when it faults.
    private static readonly string[] Coredump =
    [
        "sceCoredumpAttachMemoryRegion",
        "sceCoredumpAttachMemoryRegionAsUserFile",
        "sceCoredumpAttachUserFile",
        "sceCoredumpAttachUserMemoryFile",
        "sceCoredumpConfigDumpMode",
        "sceCoredumpDebugTextOut",
        "sceCoredumpGetStopInfoCpu",
        "sceCoredumpGetStopInfoGpu",
        "sceCoredumpGetThreadContextInfo",
        "sceCoredumpRegisterCoredumpHandler",
        "sceCoredumpUnregisterCoredumpHandler",
        "sceCoredumpWriteUserData",
    ];

    private static readonly string[] Agc =
    [
        "sceAgcAcbAcquireMem",
        "sceAgcAcbAcquireMemGetSize",
        "sceAgcAcbAtomicGds",
        "sceAgcAcbAtomicGdsGetSize",
        "sceAgcAcbAtomicMem",
        "sceAgcAcbAtomicMemGetSize",
        "sceAgcAcbCondExec",
        "sceAgcAcbCondExecGetSize",
        "sceAgcAcbCopyData",
        "sceAgcAcbCopyDataGetSize",
        "sceAgcAcbDispatchIndirect",
        "sceAgcAcbDispatchIndirectGetSize",
        "sceAgcAcbDmaData",
        "sceAgcAcbDmaDataGetSize",
        "sceAgcAcbEventWrite",
        "sceAgcAcbEventWriteGetSize",
        "sceAgcAcbJump",
        "sceAgcAcbJumpGetSize",
        "sceAgcAcbMemSemaphore",
        "sceAgcAcbPopMarker",
        "sceAgcAcbPrimeUtcl2",
        "sceAgcAcbPrimeUtcl2GetSize",
        "sceAgcAcbPushMarker",
        "sceAgcAcbQueueEndOfShaderActionGetSize",
        "sceAgcAcbResetQueue",
        "sceAgcAcbRewind",
        "sceAgcAcbRewindGetSize",
        "sceAgcAcbSetFlip",
        "sceAgcAcbSetMarker",
        "sceAgcAcbWaitOnAddressGetSize",
        "sceAgcAcbWaitRegMem",
        "sceAgcAcbWaitUntilSafeForRendering",
        "sceAgcAcbWriteData",
        "sceAgcAsyncCondExecPatchSetCommandAddress",
        "sceAgcAsyncCondExecPatchSetEnd",
        "sceAgcAsyncRewindPatchSetRewindState",
        "sceAgcBranchPatchSetCompareAddress",
        "sceAgcBranchPatchSetElseTarget",
        "sceAgcBranchPatchSetThenTarget",
        "sceAgcCbBranch",
        "sceAgcCbBranchGetSize",
        "sceAgcCbCondWrite",
        "sceAgcCbCondWriteGetSize",
        "sceAgcCbDispatch",
        "sceAgcCbDispatchGetSize",
        "sceAgcCbMemSemaphore",
        "sceAgcCbNop",
        "sceAgcCbNopGetSize",
        "sceAgcCbQueueEndOfPipeActionGetSize",
        "sceAgcCbReleaseMem",
        "sceAgcCbSetShRegisterRangeDirect",
        "sceAgcCbSetShRegisterRangeDirectGetSize",
        "sceAgcCbSetShRegistersDirect",
        "sceAgcCbSetShRegistersDirectGetSize",
        "sceAgcCbSetUcRegisterRangeDirect",
        "sceAgcCbSetUcRegisterRangeDirectGetSize",
        "sceAgcCbSetUcRegistersDirect",
        "sceAgcCbSetUcRegistersDirectGetSize",
        "sceAgcCondExecPatchSetCommandAddress",
        "sceAgcCondExecPatchSetEnd",
        "sceAgcCreateInterpolantMapping",
        "sceAgcCreatePrimState",
        "sceAgcCreateShader",
        "sceAgcDcbAcquireMem",
        "sceAgcDcbAcquireMemGetSize",
        "sceAgcDcbAtomicGds",
        "sceAgcDcbAtomicGdsGetSize",
        "sceAgcDcbAtomicMem",
        "sceAgcDcbAtomicMemGetSize",
        "sceAgcDcbBeginOcclusionQueryGetSize",
        "sceAgcDcbClearState",
        "sceAgcDcbCondExec",
        "sceAgcDcbCondExecGetSize",
        "sceAgcDcbContextStateOp",
        "sceAgcDcbContextStateOpGetSize",
        "sceAgcDcbCopyData",
        "sceAgcDcbCopyDataGetSize",
        "sceAgcDcbDispatchIndirect",
        "sceAgcDcbDispatchIndirectGetSize",
        "sceAgcDcbDmaData",
        "sceAgcDcbDmaDataGetSize",
        "sceAgcDcbDrawIndex",
        "sceAgcDcbDrawIndexAuto",
        "sceAgcDcbDrawIndexAutoGetSize",
        "sceAgcDcbDrawIndexGetSize",
        "sceAgcDcbDrawIndexIndirect",
        "sceAgcDcbDrawIndexIndirectGetSize",
        "sceAgcDcbDrawIndexIndirectMulti",
        "sceAgcDcbDrawIndexIndirectMultiGetSize",
        "sceAgcDcbDrawIndexMultiInstanced",
        "sceAgcDcbDrawIndexMultiInstancedGetSize",
        "sceAgcDcbDrawIndexOffset",
        "sceAgcDcbDrawIndexOffsetGetSize",
        "sceAgcDcbDrawIndirect",
        "sceAgcDcbDrawIndirectGetSize",
        "sceAgcDcbDrawIndirectMulti",
        "sceAgcDcbDrawIndirectMultiGetSize",
        "sceAgcDcbEndOcclusionQueryGetSize",
        "sceAgcDcbEventWrite",
        "sceAgcDcbEventWriteGetSize",
        "sceAgcDcbGetLodStats",
        "sceAgcDcbGetLodStatsGetSize",
        "sceAgcDcbJump",
        "sceAgcDcbJumpGetSize",
        "sceAgcDcbMemSemaphore",
        "sceAgcDcbPopMarker",
        "sceAgcDcbPrimeUtcl2",
        "sceAgcDcbPrimeUtcl2GetSize",
        "sceAgcDcbPushMarker",
        "sceAgcDcbQueueEndOfShaderActionGetSize",
        "sceAgcDcbResetQueue",
        "sceAgcDcbRewind",
        "sceAgcDcbRewindGetSize",
        "sceAgcDcbSetBaseDispatchIndirectArgsGetSize",
        "sceAgcDcbSetBaseDrawIndirectArgsGetSize",
        "sceAgcDcbSetBaseIndirectArgs",
        "sceAgcDcbSetBoolPredicationEnableGetSize",
        "sceAgcDcbSetCfRegisterDirect",
        "sceAgcDcbSetCfRegisterRangeDirect",
        "sceAgcDcbSetCxRegisterDirect",
        "sceAgcDcbSetCxRegisterDirectGetSize",
        "sceAgcDcbSetCxRegistersIndirect",
        "sceAgcDcbSetCxRegistersIndirectGetSize",
        "sceAgcDcbSetFlip",
        "sceAgcDcbSetIndexBuffer",
        "sceAgcDcbSetIndexBufferGetSize",
        "sceAgcDcbSetIndexCount",
        "sceAgcDcbSetIndexCountGetSize",
        "sceAgcDcbSetIndexIndirectArgs",
        "sceAgcDcbSetIndexIndirectArgsGetSize",
        "sceAgcDcbSetIndexSize",
        "sceAgcDcbSetIndexSizeGetSize",
        "sceAgcDcbSetMarker",
        "sceAgcDcbSetNumInstances",
        "sceAgcDcbSetNumInstancesGetSize",
        "sceAgcDcbSetPredication",
        "sceAgcDcbSetPredicationDisableGetSize",
        "sceAgcDcbSetShRegisterDirect",
        "sceAgcDcbSetShRegisterDirectGetSize",
        "sceAgcDcbSetShRegistersIndirect",
        "sceAgcDcbSetShRegistersIndirectGetSize",
        "sceAgcDcbSetUcRegisterDirect",
        "sceAgcDcbSetUcRegisterDirectGetSize",
        "sceAgcDcbSetUcRegistersIndirect",
        "sceAgcDcbSetUcRegistersIndirectGetSize",
        "sceAgcDcbSetZPassPredicationEnableGetSize",
        "sceAgcDcbStallCommandBufferParser",
        "sceAgcDcbStallCommandBufferParserGetSize",
        "sceAgcDcbWaitOnAddressGetSize",
        "sceAgcDcbWaitRegMem",
        "sceAgcDcbWaitUntilSafeForRendering",
        "sceAgcDcbWriteData",
        "sceAgcDcbWriteDataGetSize",
        "sceAgcDmaDataPatchSetDstAddressOrOffset",
        "sceAgcDmaDataPatchSetSrcAddressOrOffsetOrImmediate",
        "sceAgcFuseShaderHalves",
        "sceAgcGetDataPacketPayloadAddress",
        "sceAgcGetFusedShaderSize",
        "sceAgcGetPacketSize",
        "sceAgcGetRegisterDefaults",
        "sceAgcGetRegisterDefaults2",
        "sceAgcGetRegisterDefaults2Internal",
        "sceAgcGetRegisterDefaultsInternal",
        "sceAgcInit",
        "sceAgcJumpPatchSetTarget",
        "sceAgcLinkShaders",
        "sceAgcQueueEndOfPipeActionPatchAddress",
        "sceAgcQueueEndOfPipeActionPatchData",
        "sceAgcQueueEndOfPipeActionPatchGcrCntl",
        "sceAgcQueueEndOfPipeActionPatchType",
        "sceAgcRewindPatchSetRewindState",
        "sceAgcSetCxRegIndirectPatchAddRegisters",
        "sceAgcSetCxRegIndirectPatchSetAddress",
        "sceAgcSetCxRegIndirectPatchSetNumRegisters",
        "sceAgcSetNop",
        "sceAgcSetPacketPredication",
        "sceAgcSetRangePredication",
        "sceAgcSetShRegIndirectPatchAddRegisters",
        "sceAgcSetShRegIndirectPatchSetAddress",
        "sceAgcSetShRegIndirectPatchSetNumRegisters",
        "sceAgcSetSubmitMode",
        "sceAgcSetUcRegIndirectPatchAddRegisters",
        "sceAgcSetUcRegIndirectPatchSetAddress",
        "sceAgcSetUcRegIndirectPatchSetNumRegisters",
        "sceAgcSuspendPoint",
        "sceAgcSuspendPointAndCheckStatus",
        "sceAgcUpdateInterpolantMapping",
        "sceAgcUpdatePrimState",
        "sceAgcWaitRegMemPatchAddress",
        "sceAgcWaitRegMemPatchCompareFunction",
        "sceAgcWaitRegMemPatchMask",
        "sceAgcWaitRegMemPatchReference",
    ];

    private static readonly string[] AgcDriver =
    [
        "sceAgcDriverAddEqEvent",
        "sceAgcDriverAgrSubmitDcb",
        "sceAgcDriverAgrSubmitMultiDcbs",
        "sceAgcDriverCreateQueue",
        "sceAgcDriverCwsrResumeAcq",
        "sceAgcDriverCwsrSuspendAcq",
        "sceAgcDriverDebugHardwareStatus",
        "sceAgcDriverDeleteEqEvent",
        "sceAgcDriverDestroyQueue",
        "sceAgcDriverFindResourcesPublic",
        "sceAgcDriverGetEqContextId",
        "sceAgcDriverGetEqEventType",
        "sceAgcDriverGetGpuRefClks",
        "sceAgcDriverGetHsOffchipParam",
        "sceAgcDriverGetOwnerName",
        "sceAgcDriverGetRegShadowInfo",
        "sceAgcDriverGetRegShadowInfoAgr",
        "sceAgcDriverGetReservedDmemForAgc",
        "sceAgcDriverGetResourceBaseAddressAndSizeInBytes",
        "sceAgcDriverGetResourceName",
        "sceAgcDriverGetResourceShaderGuid",
        "sceAgcDriverGetResourceType",
        "sceAgcDriverGetResourceUserData",
        "sceAgcDriverGetSetFlipPacketSizeInDwords",
        "sceAgcDriverGetSetWorkloadCompletePacketSize",
        "sceAgcDriverGetSetWorkloadsActivePacketSize",
        "sceAgcDriverGetTFRing",
        "sceAgcDriverGetTraceInitiator",
        "sceAgcDriverGetWaitRenderingPacketSizeInDwords",
        "sceAgcDriverGetWorkloadStreamInfo",
        "sceAgcDriverIDHSSubmit",
        "sceAgcDriverInitResourceRegistration",
        "sceAgcDriverIsCaptureInProgress",
        "sceAgcDriverIsSubmitValidationEnabled",
        "sceAgcDriverIsTraceInProgress",
        "sceAgcDriverModuleRegistration",
        "sceAgcDriverNotifyDefaultStates",
        "sceAgcDriverPassInfoDownward",
        "sceAgcDriverPatchClearState",
        "sceAgcDriverQueryResourceRegistrationUserMemoryRequirements",
        "sceAgcDriverRegisterGdsResource",
        "sceAgcDriverRegisterOwner",
        "sceAgcDriverRegisterResource",
        "sceAgcDriverRegisterWorkloadStream",
        "sceAgcDriverRequestCaptureStart",
        "sceAgcDriverRequestCaptureStop",
        "sceAgcDriverSetFlip",
        "sceAgcDriverSetHsOffchipParam",
        "sceAgcDriverSetResourceUserData",
        "sceAgcDriverSetTFRing",
        "sceAgcDriverSetWorkloadComplete",
        "sceAgcDriverSetWorkloadsActive",
        "sceAgcDriverSetupRegisterShadow",
        "sceAgcDriverSubmitAcb",
        "sceAgcDriverSubmitCommandBuffer",
        "sceAgcDriverSubmitDcb",
        "sceAgcDriverSubmitMultiAcbs",
        "sceAgcDriverSubmitMultiCommandBuffers",
        "sceAgcDriverSubmitMultiDcbs",
        "sceAgcDriverSuspendPointSubmit",
        "sceAgcDriverSysEnableSubmitDone45Exception",
        "sceAgcDriverSysGetClientNumber",
        "sceAgcDriverSysIsGameClosed",
        "sceAgcDriverSysSubmitFlipHandleProxy",
        "sceAgcDriverTmpInitIdhs",
        "sceAgcDriverTriggerCapture",
        "sceAgcDriverUnregisterAllResourcesForOwner",
        "sceAgcDriverUnregisterOwnerAndResources",
        "sceAgcDriverUnregisterResource",
        "sceAgcDriverUnregisterWorkloadStream",
        "sceAgcDriverUserDataGetPacketSize",
        "sceAgcDriverUserDataImmediateWrite",
        "sceAgcDriverUserDataWritePacket",
        "sceAgcDriverUserDataWritePopMarker",
        "sceAgcDriverUserDataWritePushMarker",
        "sceAgcDriverUserDataWriteSetMarker",
        "sceAgcDriverWaitUntilSafeForRendering",
    ];

    private static readonly string[] ShellCoreUtil =
    [
        "sceShellCoreUtilRequestEjectDevice",
    ];

    private static readonly string[] SysUtil =
    [
        "sceSysUtilSendSystemNotificationWithText",
    ];

    private static readonly string[] SystemStateMgr =
    [
        "sceSystemStateMgrEnterStandby",
    ];

    private static readonly string[] FsInternalForVsh =
    [
        "sceFsInitMountSaveDataOpt",
        "sceFsMountSaveData",
        "sceFsInitUmountSaveDataOpt",
        "sceFsUmountSaveData",
    ];
}
