// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using System.Runtime.InteropServices;

namespace SharpProspero.Interop.Kernel;

/// <summary>
/// A scheduling priority. The policy calls take and return this one-field block rather than a bare
/// integer.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 4)]
public struct SceKernelSchedParam
{
    /// <summary>
    /// The priority. A smaller number is served first, between
    /// <see cref="KernelThread.PriorityHighest"/> and <see cref="KernelThread.PriorityLowest"/>.
    /// </summary>
    public int Priority;
}

/// <summary>
/// Scheduling, thread-attribute, cancellation, and synchronisation-primitive bindings. A thread's
/// policy and priority can be changed while it runs through the calls that take a thread handle, or
/// settled before it starts through an attribute block. The block is a handle rather than a
/// structure the caller lays out: prepare it with <see cref="scePthreadAttrInit"/>, set what is
/// wanted on it, hand it to the thread-creation call, and release it with
/// <see cref="scePthreadAttrDestroy"/>. The same file also carries the mutex, condition-variable,
/// read/write-lock, semaphore, thread-specific-key, and cancellation calls that share the pthread
/// family conventions.
/// </summary>
/// <remarks>
/// A block is read when the thread starts, so changing it afterwards does not reach a running thread.
/// A block also has to be told to use its own settings rather than inherit the creator's - see
/// <see cref="scePthreadAttrSetinheritsched"/> - or its policy and priority are ignored.
/// </remarks>
public static unsafe partial class KernelScheduling
{
    private const string Lib = "libkernel";

    /// <summary>First-in first-out within a priority: a thread runs until it blocks or yields. Value 1.</summary>
    public const int SchedFifo = 1;

    /// <summary>The time-shared policy threads run under by default. Value 2.</summary>
    public const int SchedOther = 2;

    /// <summary>Round-robin within a priority: equal-priority threads take turns. Value 3.</summary>
    public const int SchedRoundRobin = 3;

    /// <summary>A thread created from the block can be joined. Value 0.</summary>
    public const int CreateJoinable = 0;

    /// <summary>A thread created from the block cleans itself up and cannot be joined. Value 1.</summary>
    public const int CreateDetached = 1;

    /// <summary>The block's own policy and priority are used. Value 0.</summary>
    public const int ExplicitSched = 0;

    /// <summary>The creating thread's policy and priority are used, and the block's are ignored. Value 4.</summary>
    public const int InheritSched = 4;

    /// <summary>A mutex that reports a re-lock or an unlock-by-non-owner as an error. Value 1.</summary>
    public const int MutexErrorCheck = 1;

    /// <summary>A mutex the owner may lock more than once; unlocked once per lock. Value 2.</summary>
    public const int MutexRecursive = 2;

    /// <summary>A mutex that skips ownership checks entirely. Value 3.</summary>
    public const int MutexNormal = 3;

    /// <summary>A mutex that spins briefly before it parks on contention. Value 4.</summary>
    public const int MutexAdaptive = 4;

    /// <summary>The default mutex type, an alias for <see cref="MutexErrorCheck"/>. Value 1.</summary>
    public const int MutexDefault = MutexErrorCheck;

    /// <summary>The read/write lock treats readers and writers symmetrically. Value 1.</summary>
    public const int RwlockNormal = 1;

    /// <summary>The read/write lock hands the lock to a reader when both are queued. Value 2.</summary>
    public const int RwlockPreferReader = 2;

    /// <summary>Ordering rule for a mutex: priority is not tracked through the mutex. Value 0.</summary>
    public const int PrioNone = 0;

    /// <summary>Ordering rule for a mutex: the owner inherits the highest waiter's priority. Value 1.</summary>
    public const int PrioInherit = 1;

    /// <summary>Ordering rule for a mutex: the owner is raised to the mutex's ceiling. Value 2.</summary>
    public const int PrioProtect = 2;

    /// <summary>Cancellation delivery is allowed for the calling thread. Value 0.</summary>
    public const int CancelEnable = 0;

    /// <summary>Cancellation delivery is held back for the calling thread. Value 1.</summary>
    public const int CancelDisable = 1;

    /// <summary>A cancellation request is only acted on at a cancellation point. Value 0.</summary>
    public const int CancelDeferred = 0;

    /// <summary>A cancellation request interrupts the thread as soon as it lands. Value 2.</summary>
    public const int CancelAsynchronous = 2;

    /// <summary>Reads the policy and priority <paramref name="thread"/> is running under.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadGetschedparam(nint thread, int* policy, SceKernelSchedParam* param);

    /// <summary>Sets the policy and priority of <paramref name="thread"/> in one call.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadSetschedparam(nint thread, int policy, SceKernelSchedParam* param);

    /// <summary>
    /// Reads the identifier of the clock that counts only the processor time
    /// <paramref name="thread"/> has consumed, which
    /// <see cref="KernelClock.sceKernelClockGettime"/> then reads.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadGetcpuclockid(nint thread, int* clockId);

    /// <summary>Reports whether two handles name the same thread.</summary>
    /// <returns>Non-zero when they do.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadEqual(nint first, nint second);

    /// <summary>
    /// Detaches <paramref name="thread"/>, so it releases itself when it ends and can no longer be
    /// joined.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadDetach(nint thread);

    /// <summary>Prepares an attribute block and writes its handle to <paramref name="attr"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrInit(nint* attr);

    /// <summary>Releases an attribute block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrDestroy(nint* attr);

    /// <summary>Fills <paramref name="attr"/> with the settings <paramref name="thread"/> is running under.</summary>
    /// <remarks>
    /// The block must already be prepared. This is the route to reading a running thread's stack bounds
    /// and detach state, which have no call of their own.
    /// </remarks>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGet(nint thread, nint* attr);

    /// <summary>Sets the stack size a thread created from the block is given.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetstacksize(nint* attr, nuint stackSize);

    /// <summary>Reads the stack size the block asks for.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetstacksize(nint* attr, nuint* stackSize);

    /// <summary>Reads the base and size of the stack the block describes.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetstack(nint* attr, void** stackAddress, nuint* stackSize);

    /// <summary>Sets the untouched region placed past the end of the stack to catch an overrun.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetguardsize(nint* attr, nuint guardSize);

    /// <summary>Reads the size of the region placed past the end of the stack.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetguardsize(nint* attr, nuint* guardSize);

    /// <summary>Chooses whether a thread created from the block can be joined.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetdetachstate(nint* attr, int state);

    /// <summary>Reads whether a thread created from the block can be joined.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetdetachstate(nint* attr, int* state);

    /// <summary>Confines a thread created from the block to the processors named by <paramref name="mask"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetaffinity(nint* attr, ulong mask);

    /// <summary>Reads the processors a thread created from the block would be allowed to run on.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetaffinity(nint* attr, ulong* mask);

    /// <summary>Sets the priority a thread created from the block starts at.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetschedparam(nint* attr, SceKernelSchedParam* param);

    /// <summary>Reads the priority a thread created from the block would start at.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetschedparam(nint* attr, SceKernelSchedParam* param);

    /// <summary>Sets the policy a thread created from the block runs under.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetschedpolicy(nint* attr, int policy);

    /// <summary>Reads the policy a thread created from the block would run under.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetschedpolicy(nint* attr, int* policy);

    /// <summary>
    /// Chooses between <see cref="InheritSched"/> and <see cref="ExplicitSched"/>. A block left at the
    /// former ignores whatever policy and priority were set on it.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrSetinheritsched(nint* attr, int inheritSched);

    /// <summary>Reads where a thread created from the block takes its policy and priority from.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadAttrGetinheritsched(nint* attr, int* inheritSched);

    /// <summary>
    /// Blocks until <paramref name="thread"/> ends and writes its exit value to
    /// <paramref name="value"/>. The joined thread's storage is released once the call returns.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadJoin(nint thread, void** value);

    /// <summary>
    /// Copies <paramref name="thread"/>'s name into the caller-supplied null-terminated UTF-8 buffer
    /// <paramref name="name"/>.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadGetname(nint thread, byte* name);

    /// <summary>Marks <paramref name="thread"/> for cancellation.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    /// <remarks>
    /// A cancellation request is delivered under whatever mode the target has settled through
    /// <see cref="scePthreadSetcancelstate"/> and <see cref="scePthreadSetcanceltype"/>.
    /// </remarks>
    [LibraryImport(Lib)]
    public static partial int scePthreadCancel(nint thread);

    /// <summary>
    /// Sets whether the calling thread accepts a cancellation, returning the old choice to
    /// <paramref name="oldState"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSetcancelstate(int state, int* oldState);

    /// <summary>
    /// Sets when the calling thread acts on a cancellation, returning the old choice to
    /// <paramref name="oldType"/>.
    /// </summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSetcanceltype(int type, int* oldType);

    /// <summary>Acts on a pending cancellation for the calling thread, if any.</summary>
    [LibraryImport(Lib)]
    public static partial void scePthreadTestcancel();

    /// <summary>
    /// Prepares <paramref name="key"/> as a thread-specific slot and installs
    /// <paramref name="destructor"/> to run over each thread's value when the thread ends.
    /// <paramref name="destructor"/> is null when no cleanup is needed.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadKeyCreate(int* key, delegate* unmanaged[Cdecl]<void*, void> destructor);

    /// <summary>Releases <paramref name="key"/>; existing values are not run through the destructor.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadKeyDelete(int key);

    /// <summary>Reads the calling thread's value for <paramref name="key"/>, or null when none is set.</summary>
    [LibraryImport(Lib)]
    public static partial void* scePthreadGetspecific(int key);

    /// <summary>Sets the calling thread's value for <paramref name="key"/> to <paramref name="value"/>.</summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadSetspecific(int key, void* value);

    /// <summary>
    /// Runs <paramref name="init"/> the first time this call is made against
    /// <paramref name="once"/>, and does nothing on later calls. Callers that race the first
    /// invocation are held until it returns.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadOnce(void* once, delegate* unmanaged[Cdecl]<void> init);

    /// <summary>Prepares a mutex-attribute block and writes its handle to <paramref name="attr"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrInit(nint* attr);

    /// <summary>Releases a mutex-attribute block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrDestroy(nint* attr);

    /// <summary>Reads the mutex type a mutex created from the block would carry.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrGettype(nint* attr, int* type);

    /// <summary>Sets the mutex type a mutex created from the block will carry.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrSettype(nint* attr, int type);

    /// <summary>Reads the priority-ordering rule the block records.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrGetprotocol(nint* attr, int* protocol);

    /// <summary>Sets the priority-ordering rule a mutex created from the block will use.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrSetprotocol(nint* attr, int protocol);

    /// <summary>Reads the priority ceiling recorded on the block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrGetprioceiling(nint* attr, int* prio);

    /// <summary>Sets the priority ceiling a mutex created from the block will carry.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexattrSetprioceiling(nint* attr, int prio);

    /// <summary>
    /// Prepares a mutex named <paramref name="name"/> (null-terminated UTF-8) from
    /// <paramref name="attr"/> and writes its handle to <paramref name="mutex"/>.
    /// <paramref name="attr"/> is null for the defaults.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexInit(nint* mutex, nint* attr, byte* name);

    /// <summary>Releases a mutex. The mutex must not be held or waited on.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexDestroy(nint* mutex);

    /// <summary>
    /// Blocks until the calling thread owns <paramref name="mutex"/>. A recursive mutex counts one
    /// nested lock; an error-check mutex refuses a second lock from the same thread.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexLock(nint* mutex);

    /// <summary>Takes <paramref name="mutex"/> when it is free without blocking.</summary>
    /// <returns>Zero when the lock was taken, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexTrylock(nint* mutex);

    /// <summary>
    /// Waits up to <paramref name="usec"/> microseconds for <paramref name="mutex"/> to be free.
    /// </summary>
    /// <returns>Zero when the lock was taken, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexTimedlock(nint* mutex, uint usec);

    /// <summary>Releases <paramref name="mutex"/>. A recursive mutex only unlocks when the last lock is undone.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadMutexUnlock(nint* mutex);

    /// <summary>Prepares a condition-variable-attribute block and writes its handle to <paramref name="attr"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondattrInit(nint* attr);

    /// <summary>Releases a condition-variable-attribute block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondattrDestroy(nint* attr);

    /// <summary>
    /// Prepares a condition variable named <paramref name="name"/> (null-terminated UTF-8) from
    /// <paramref name="attr"/> and writes its handle to <paramref name="cond"/>.
    /// <paramref name="attr"/> is null for the defaults.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondInit(nint* cond, nint* attr, byte* name);

    /// <summary>Releases a condition variable. No thread may still be waiting on it.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondDestroy(nint* cond);

    /// <summary>
    /// Releases <paramref name="mutex"/> and blocks the calling thread on <paramref name="cond"/>;
    /// when the thread is released, <paramref name="mutex"/> is taken again before returning.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondWait(nint* cond, nint* mutex);

    /// <summary>
    /// Waits up to <paramref name="usec"/> microseconds on <paramref name="cond"/>, then reclaims
    /// <paramref name="mutex"/> whether the wait was released or timed out.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondTimedwait(nint* cond, nint* mutex, uint usec);

    /// <summary>Releases one waiter on <paramref name="cond"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondSignal(nint* cond);

    /// <summary>Releases <paramref name="thread"/> from <paramref name="cond"/> when it is waiting there.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondSignalto(nint* cond, nint thread);

    /// <summary>Releases every waiter on <paramref name="cond"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadCondBroadcast(nint* cond);

    /// <summary>Prepares a read/write-lock-attribute block and writes its handle to <paramref name="attr"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockattrInit(nint* attr);

    /// <summary>Releases a read/write-lock-attribute block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockattrDestroy(nint* attr);

    /// <summary>Reads the read/write-lock variant the block records.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockattrGettype(nint* attr, int* type);

    /// <summary>Sets the read/write-lock variant a lock created from the block will use.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockattrSettype(nint* attr, int type);

    /// <summary>
    /// Prepares a read/write lock named <paramref name="name"/> (null-terminated UTF-8) from
    /// <paramref name="attr"/> and writes its handle to <paramref name="rwlock"/>.
    /// <paramref name="attr"/> is null for the defaults.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockInit(nint* rwlock, nint* attr, byte* name);

    /// <summary>Releases a read/write lock. No thread may still hold or wait on it.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockDestroy(nint* rwlock);

    /// <summary>Takes <paramref name="rwlock"/> for reading, blocking until every writer has released it.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockRdlock(nint* rwlock);

    /// <summary>Takes <paramref name="rwlock"/> for reading only if that would not block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockTryrdlock(nint* rwlock);

    /// <summary>Waits up to <paramref name="usec"/> microseconds for a read hold on <paramref name="rwlock"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockTimedrdlock(nint* rwlock, uint usec);

    /// <summary>Takes <paramref name="rwlock"/> for writing, blocking until every reader has released it.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockWrlock(nint* rwlock);

    /// <summary>Takes <paramref name="rwlock"/> for writing only if that would not block.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockTrywrlock(nint* rwlock);

    /// <summary>Waits up to <paramref name="usec"/> microseconds for a write hold on <paramref name="rwlock"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockTimedwrlock(nint* rwlock, uint usec);

    /// <summary>Releases <paramref name="rwlock"/> from the caller's read or write hold.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadRwlockUnlock(nint* rwlock);

    /// <summary>
    /// Prepares a POSIX semaphore holding <paramref name="value"/> and named <paramref name="name"/>
    /// (null-terminated UTF-8) in the caller-supplied storage <paramref name="sem"/>.
    /// <paramref name="flag"/> is zero for a process-private semaphore.
    /// </summary>
    /// <returns>Zero on success, or a negative error code.</returns>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemInit(void* sem, int flag, uint value, byte* name);

    /// <summary>Releases the POSIX semaphore at <paramref name="sem"/>. No thread may still be waiting.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemDestroy(void* sem);

    /// <summary>Reads the current count of the semaphore at <paramref name="sem"/> into <paramref name="sval"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemGetvalue(void* sem, int* sval);

    /// <summary>Adds one unit to the semaphore at <paramref name="sem"/>, releasing a waiter if any.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemPost(void* sem);

    /// <summary>Takes one unit from the semaphore at <paramref name="sem"/>, blocking until it is free.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemWait(void* sem);

    /// <summary>Takes one unit from the semaphore at <paramref name="sem"/> only if it is free.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemTrywait(void* sem);

    /// <summary>Waits up to <paramref name="usec"/> microseconds for a unit at <paramref name="sem"/>.</summary>
    [LibraryImport(Lib)]
    public static partial int scePthreadSemTimedwait(void* sem, uint usec);

    /// <summary>
    /// The highest priority number <paramref name="policy"/> accepts, or -1 with an error number set.
    /// </summary>
    /// <remarks>
    /// This is the libc-style call, so it fails by returning -1 rather than by returning a service code.
    /// It reports the numeric bounds of the policy; which end of that range runs first is the thread
    /// priority convention, where the smaller number is served first.
    /// </remarks>
    [LibraryImport(Lib)]
    public static partial int sched_get_priority_max(int policy);

    /// <summary>The lowest priority number <paramref name="policy"/> accepts, or -1 with an error number set.</summary>
    [LibraryImport(Lib)]
    public static partial int sched_get_priority_min(int policy);

    /// <summary>Gives up the rest of the calling thread's slice. Returns zero, or -1 with an error number set.</summary>
    [LibraryImport(Lib)]
    public static partial int sched_yield();
}
