---
title: Payload API
parent: Payloads
nav_order: 7
---

# Payload API

Everything a payload calls from managed code lives under the `SharpProspero.Payload` namespace.
This page groups the surface by what it does, names the wrapper class, and shows one call for
each.

## CRT functions

`PayloadCrt` provides the CRT-emitted functions the toolchain statically links into every
payload: the kernel log, the raw syscall gateway, and the payload arguments accessor.

```csharp
// Kernel log
PayloadCrt.Klog("hello from payload\n\0"u8);

// Raw FreeBSD syscall (e.g. SYS_close = 6)
PayloadCrt.Syscall(PayloadCrt.SYS_close, fd);

// Payload arguments
PayloadArgs* args = PayloadCrt.GetPayloadArgs();
```

These symbols live in the payload's own `.text` section, not in an SPRX module. The library
name `"libScePosix"` on the `[LibraryImport]` attribute is a DirectPInvoke placeholder that
the linker resolves at compile time — it never reaches the on-device loader.

All `PayloadCrt` methods carry `[SuppressGCTransition]` because the CRT functions are thin
in-process trampolines (a handful of instructions, no blocking). SPRX-resolved functions
(like `sceUserServiceInitialize`) may block and should NOT carry `[SuppressGCTransition]`.

### DirectPInvoke resolution

NativeAOT resolves `[LibraryImport]` calls at link time by searching ALL libraries declared
as `<DirectPInvoke>` targets in `Prospero.Payload.props` — currently `libkernel`, `libc`,
and `libScePosix`. The linker matches the entry point against every declared library's exports
and binds the first match. This means a `[LibraryImport("libc", EntryPoint = "getpid")]` still
resolves to `libkernel.so`'s `getpid` export, because the linker searches `libkernel.so` and
finds it there. The SDK wrappers use the correct library names for clarity; a wrong name links
but is misleading.

## Entry point and arguments

| Type | What it holds |
|---|---|
| `PayloadEntryPoint` | The loader-supplied arguments the CRT captured. `PayloadEntryPoint.Args` returns the `PayloadArgs*` — null when the loader did not supply one. |
| `PayloadArgs` | The struct the loader hands the payload: the resolver entry, the pipe primitive descriptors, and the kernel data base. |

```csharp
PayloadArgs* args = PayloadEntryPoint.Args;
if (args == null) { /* loader did not supply args */ }
```

## Kernel

| Class | What it does |
|---|---|
| `PayloadKernel` | Process-oriented helpers: walk the process list, promote a running application (credentials, capabilities, filesystem view), cache the root vnode. See [Kernel access](payload-kernel.md). |
| `PayloadKernelIo` | The raw read/write surface: `ReadU64`/`U32`/`U16`/`U8`, `WriteU64`/`U32`/`U16`/`U8`, bulk `Read`/`Write`, and `TryRead*`/`TryWrite*` for a soft failure. |

## Networking

```csharp
int listener = PayloadNetwork.Listen(9069, backlog: 8);
int client   = PayloadNetwork.Accept(listener);
Span<byte> buf = stackalloc byte[1024];
long n = PayloadNetwork.Receive(client, buf);
PayloadNetwork.SendAll(client, buf.Slice(0, (int)n));
PayloadNetwork.Close(client);
PayloadNetwork.Close(listener);

// Outbound
int s = PayloadNetwork.Connect(192, 168, 1, 10, 9069);
```

The socket API routes through the POSIX interop layer, which binds to `libSceNet.sprx` at run
time via the payload's `DT_NEEDED` list. `libSceNet.sprx` is one of the default entries, so a
payload calls the socket surface without any extra project declaration.

## Filesystem

`PayloadFileSystem` wraps directory traversal, file management, and recursive operations:

```csharp
// Traverse a directory
void* dir = PayloadFileSystem.opendir(path);
FreeBsdDirent* entry = PayloadFileSystem.readdir(dir);
PayloadFileSystem.closedir(dir);

// File status and type checks
PayloadFileSystem.stat(path, &statBuf);
bool isDir = PayloadFileSystem.IsDirectory(statBuf.st_mode);
bool isLink = PayloadFileSystem.IsSymlink(statBuf.st_mode);

// File operations
PayloadFileSystem.mkdir(path, 0x1FF);      // 0777
PayloadFileSystem.rename(from, to);
PayloadFileSystem.unlink(path);
PayloadFileSystem.rmdir(path);
PayloadFileSystem.chmod(path, mode);
PayloadFileSystem.lstat(path, &statBuf);   // does not follow symlinks
PayloadFileSystem.ftruncate(fd, length);

// Convenience: copy and remove entire trees
PayloadFileSystem.CopyFile(src, dst);
PayloadFileSystem.CopyDirectory(src, dst);
PayloadFileSystem.RemoveDirectory(path);
```

Every path operates within the host process's filesystem view, which is the per-title sandbox by
default. A companion daemon promotes another process to lift that view — see
[Promoting a running application](payload-promotion.md).

## Low-level I/O

`PayloadIo` provides POSIX file descriptor operations for payloads that need direct control:

```csharp
int fd = PayloadIo.open(path, PayloadFileSystem.O_RDWR | PayloadFileSystem.O_CREAT, 0x1B6);
long n = PayloadIo.read(fd, buf, len);
PayloadIo.write(fd, buf, (nuint)n);
PayloadIo.lseek(fd, 0, PayloadIo.SeekSet);
PayloadIo.pread(fd, buf, len, offset);     // positional read
PayloadIo.fstat(fd, &statBuf);
PayloadIo.ioctl(fd, request, arg);         // device control
PayloadIo.pipe(fildes);                    // create pipe pair
PayloadIo.dup2(oldfd, newfd);
PayloadIo.fcntl(fd, PayloadIo.F_SETFL, PayloadIo.O_NONBLOCK);
PayloadIo.close(fd);
```

## Mount operations

`PayloadMount` wraps the FreeBSD `nmount` interface with convenience helpers:

```csharp
// Raw nmount for full control
PayloadMount.nmount(iov, niov, flags);
PayloadMount.unmount(path, flags);
PayloadMount.statfs(path, &statBuf);

// Convenience: bind-mount with nullfs
PayloadMount.MountNullfs(source, target);

// Convenience: make a system partition writable
PayloadMount.RemountReadWrite(path);

// Check whether a path is a mount point
bool mounted = PayloadMount.IsMounted(path);
```

`PayloadPfsMount` adds PFS image mounting through `libSceFsInternalForVsh`:

```csharp
MountSaveDataOpt opt = default;
PayloadPfsMount.sceFsInitMountSaveDataOpt(&opt);
PayloadPfsMount.sceFsMountSaveData(&opt, volumePath, mountPath, key);
```

## Events

`PayloadEvent` wraps the FreeBSD `kqueue`/`kevent` mechanism for event-driven I/O:

```csharp
int kq = PayloadEvent.kqueue();
FreeBsdKevent ev = default;
PayloadEvent.EvSet(&ev, (nuint)pid, PayloadEvent.EvfiltProc,
                   PayloadEvent.EvAdd, PayloadEvent.NoteExit, 0, null);
PayloadEvent.kevent(kq, &ev, 1, &ev, 1, null);
```

Filter constants cover processes (`EvfiltProc`), file descriptors (`EvfiltRead`, `EvfiltWrite`),
vnodes (`EvfiltVnode`), signals (`EvfiltSignal`), and timers (`EvfiltTimer`).

## Process control

`PayloadProcessControl` provides POSIX signal delivery and process identification:

```csharp
PayloadProcessControl.kill(pid, PayloadProcessControl.SigTerm);
int myPid = PayloadProcessControl.getpid();
PayloadProcessControl.sceKernelGetProcessName(pid, nameBuf);
```

`PayloadSysctl` extends this with process discovery:

```csharp
int pid = PayloadSysctl.FindPidByName(processName);
```

## Process

```csharp
int rc = PayloadProcess.GetAppInfo(pid, out PayloadAppInfo info);
// info.AppId, info.AppType, info.TitleId (10-byte identifier)
```

`PayloadAppInfo` exposes `AppId`, `AppType`, and the ten-byte `TitleId` identifier for the
running process. Use `PayloadKernel.FindProcessByComm(...)` or `FindProcessByTitleId(...)` to walk
the process list and locate the target of a credential-write.

## Notifications

```csharp
PayloadNotification.SendKernelNotification("unjail: daemon ready"u8);
PayloadNotification.SendNotification(userId: 1, isLogged: true, jsonPayload: "..."u8);
PayloadNotification.SendNotificationById(userId: 1, isLogged: true,
                                         id: "myEventId"u8, jsonData: "{...}"u8);
PayloadNotification.SendSystemNotification(messageType: 0, message: "Hello"u8);
```

Four notification paths are available: the kernel toast (no extra SPRX), the JSON notification
service (via `libSceNotification`), the by-id variant, and the system-utility text notification
(via `libSceSysUtil`).

## Dynamic library loading

```csharp
void* handle = PayloadDlfcn.Dlopen(nameUtf8, PayloadDlfcn.RtldLazy);
void* sym    = PayloadDlfcn.Dlsym(handle, "someSymbol"u8);
PayloadDlfcn.Dlclose(handle);
```

`PayloadDlfcn` covers `dlopen`, `dlsym`, `dlclose`, and `dlerror` for a module the payload has to
load itself instead of declaring in the project. The mode constants are `PayloadDlfcn.RtldLazy`
and `PayloadDlfcn.RtldNow`.

## Random bytes

```csharp
Span<byte> buffer = stackalloc byte[32];
int rc = PayloadRandom.GetRandomBytes(buffer);
```

`GetRandomBytes` fills the buffer through the system random library (`libSceRandom.sprx`); the
call is capped at 64 bytes. `GetRandomBytesFull` loops for larger requests until every byte is
filled.

## Threading

`PayloadThread` provides thread lifecycle management:

```csharp
nint thread;
PayloadThread.scePthreadCreate(&thread, null, entry, arg, "worker"u8);
PayloadThread.scePthreadJoin(thread, null);      // wait for completion
PayloadThread.scePthreadDetach(thread);          // fire-and-forget
PayloadThread.sleep(5);                          // seconds
PayloadThread.usleep(1000);                      // microseconds
PayloadThread.nanosleep(&requested, &remaining); // precise
```

## Network utilities

`PayloadNetworkUtil` adds I/O multiplexing and address conversion:

```csharp
// Poll for events on multiple descriptors
PollFd fds = new() { Fd = sockfd, Events = PayloadNetworkUtil.PollIn };
int ready = PayloadNetworkUtil.poll(&fds, 1, timeout: 5000);

// Byte-order conversion (inline, no library call)
ushort netPort = PayloadNetworkUtil.Htons(9069);
uint netAddr = PayloadNetworkUtil.Htonl(0x7F000001);

// Address conversion
byte* dst = stackalloc byte[PayloadNetworkUtil.Inet4AddrStrLen];
PayloadNetworkUtil.inet_ntop(PayloadNetworkUtil.AfInet, &addr, dst, 16);
PayloadNetworkUtil.inet_pton(PayloadNetworkUtil.AfInet, addrStr, &addr);

// Socket inspection
PayloadNetworkUtil.getsockname(sockfd, addr, &addrLen);
```

## Network status

`PayloadNetCtl` queries the connection state through `libSceNetCtl`:

```csharp
PayloadNetCtl.sceNetCtlInit();
byte* info = stackalloc byte[PayloadNetCtl.InfoSize];
PayloadNetCtl.sceNetCtlGetInfo(PayloadNetCtl.InfoIpAddress, info);
PayloadNetCtl.sceNetCtlTerm();
```

## SFO parsing

`PayloadSfo` reads `param.sfo` files in place without allocations:

```csharp
var reader = new SfoReader(data, length);
if (reader.IsValid)
{
    ReadOnlySpan<byte> titleId = reader.GetStringByKey("TITLE_ID"u8);
    int appVer = reader.GetInt32ByKey("APP_VER"u8);
}
```

## sysctl

`PayloadSysctl` wraps `sysctl` and `getmntinfo` for reading kernel-published state, and
provides `FindPidByName` for locating a running process by its command name.

## Hardware information

```csharp
int rc = PayloadHardwareInfo.GetModelName(out string model);
int rc = PayloadHardwareInfo.GetSerialNumber(out string serial);
int rc = PayloadHardwareInfo.GetCpuTemperature(out int celsius);
int rc = PayloadHardwareInfo.GetSocSensorTemperature(sensor: 0, out int celsius);
int rc = PayloadHardwareInfo.GetCurrentFanDuty(out int duty);
```

The hardware-info reads are behind `libkernel_sys.sprx`, so a payload that uses them sets
`<ProsperoKernelSprx>libkernel_sys.sprx</ProsperoKernelSprx>`.

## Multi-firmware kernel offsets

`KernelOffsets` provides firmware-versioned kernel data addresses covering FW 1.00 through 12.70:

```csharp
uint fw = PayloadKernel.GetFirmwareVersion(io);
if (KernelOffsets.IsSupported(fw))
{
    ulong kdata = KernelOffsets.KdataBase(fw);
    ulong allproc = kdata + KernelOffsets.Allproc(fw);
    ulong rootvnode = kdata + KernelOffsets.Rootvnode(fw);
    ulong secFlags = kdata + KernelOffsets.SecurityFlags(fw);
    ulong qaFlags = kdata + KernelOffsets.QaFlags(fw);
}
```

`KernelOffsets1001` remains available for FW 10.01 absolute addresses and process-structure
field offsets that are firmware-invariant (credential fields, file-descriptor table, etc.).

## Signal handling

`PayloadSignal` provides POSIX signal handling and non-local jumps:

```csharp
FreeBsdSigaction sa = default;
sa.Handler = &MyHandler;
sa.Flags = PayloadSignal.SaRestart;
PayloadSignal.sigaction(PayloadProcessControl.SigSegv, &sa, null);

// Non-local jump for fault recovery
FreeBsdJmpBuf env;
if (PayloadSignal.setjmp(&env) == 0) { /* normal */ }
else { /* recovered from fault */ }
```

Also provides `select` for I/O multiplexing, `setenv`/`unsetenv` for environment variables,
`setsid`/`setpgid` for session management, and `execve` for process replacement.

## ELF reader and NID resolution

`PayloadElfReader` parses ELF 64-bit headers from memory or from another process:

```csharp
if (PayloadElfReader.IsValidElf(data, length))
{
    Elf64Ehdr* hdr = PayloadElfReader.GetHeader(data);
    ulong base = PayloadElfReader.GetBaseAddress(data, hdr);
    Elf64Phdr* dyn = PayloadElfReader.FindProgramHeader(data, hdr, ElfConstants.PtDynamic);
}
```

`PayloadNid` computes symbol identifiers for function resolution:

```csharp
string nid = PayloadNid.Compute("sceKernelSleep"u8);
ulong raw = PayloadNid.ComputeRaw("sceKernelSleep"u8);
```

## Process memory and pattern scanning

`PayloadProcessMemory` reads and writes another process's address space:

```csharp
PayloadProcessMemory.Attach(pid);
ulong val = PayloadProcessMemory.ReadU64(pid, addr);
nint match = PayloadProcessMemory.PatternScan(pid, start, length, pattern, mask);
PayloadProcessMemory.Detach(pid);
```

## Image mount dispatch

`PayloadImageMount` detects image files and mounts them through the correct device path:

```csharp
var type = PayloadImageMount.DetectType(path);
int unit = PayloadImageMount.MdAttach(imagePath, 512, readOnly: true, mediaSize: fileSize);
int devId = PayloadImageMount.LvdAttach(2048, imageType, deviceSize);
```

## Cryptography

`Aes128` provides AES-128 with CBC and XTS modes for PFS content encryption:

```csharp
var cipher = new Aes128(key);
cipher.EncryptCbc(data, iv);
cipher.DecryptXts(data, tweak, tweakCipher);
```

`Rsa2048` handles RSA-2048 private key operations with CRT optimization.
`PayloadPfsCrypto` ties these together for PFS sector-level encrypt/decrypt.

## Kernel infrastructure

Advanced kernel operations through the pipe primitive and kekcall:

```csharp
ulong pa = KernelPaging.VirtToPhys(io, cr3, dmapBase, kernelVa);
KernelPaging.PhysCopyin(io, cr3, dmapBase, kva, src, len);
KernelSysent.WriteSvFlags(io, sysentvecAddr, KernelSysent.SvFlagsDisabled);
ulong gate = KernelIdt.ReadGateTarget(io, idtBase, vector);
ulong result = PayloadKfncall.Call(io, sysentsAddr, kfnAddr, arg1, arg2);
```

`KernelOffsetsDetailed` provides per-firmware sysent, sysentvec, copyin/copyout,
malloc, and p_sysent offsets for FW 3.00 through 12.70.

## Bypass hooks

`PayloadFselfBypass` installs debug register watchpoints for unsigned SELF loading.
`PayloadFpkgBypass` registers fake PFS keys for fake-signed package content.
`PayloadNpdrmBypass` decrypts RIF debug keys for license bypass.

## Process injection

`PayloadElfLoader` maps a PIE ELF into a target process via JIT shared memory.
`PayloadProcessSpawner` creates and elevates new processes for code injection.
`PayloadDetour` installs x86-64 inline hooks (14-byte absolute jumps).

## Services

`PayloadFtpServer`, `PayloadKlogRelay`, `PayloadDiscordRpc` provide TCP-based
services. `PayloadIpcProtocol` defines the daemon IPC command set.
`PayloadCheatManager` searches and writes process memory values.
`PayloadShellUiPatcher` patches trophy availability checks.
`PayloadShellCorePatcher` applies per-firmware binary patches.

## User service

```csharp
PayloadUserService.Initialize();
int rc = PayloadUserService.GetInitialUser(out int userId);
PayloadUserService.Terminate();
```

`PayloadUserService` is the read-side of the user-account service. Add
`<ProsperoSprx Include="libSceUserService.sprx" />` in the project.

## Browser

```csharp
int rc = PayloadBrowser.LaunchWebBrowser("https://example.local/"u8);
```

Launches the system browser at the URL. Add both `libSceSystemService.sprx` and
`libSceUserService.sprx` to the project.

## HTTP/2

```csharp
int rc = PayloadHttp2.InitStack("prospero"u8,
                                netPoolSize: 0x40000,
                                sslPoolSize: 0x40000,
                                httpPoolSize: 0x40000,
                                out int netMem,
                                out int sslCtx,
                                out int httpCtx);
// ... request setup, send, receive ...
PayloadHttp2.Cleanup(reqId: 0, tmplId: 0, httpCtx, sslCtx, netMem);
```

The HTTP/2 stack is bigger than the raw socket API but handles TLS through `libSceSsl`. Add both
`libSceHttp2.sprx` and `libSceSsl.sprx` in the project.

## Package install

```csharp
int rc = PayloadAppInstaller.InstallFromDirectory("PPSA99099\0"u8, "/user/app/\0"u8);
int rc = PayloadAppInstaller.Uninstall("PPSA99099\0"u8);
int rc = PayloadAppInstaller.InstallAll();
```

`InstallFromDirectory` hands a prepared folder to the package installer for the named title id.
`Uninstall` removes a previously installed title. `InstallAll` initialises the installer and
installs all pending content in one call.

## Debug

`PayloadDebug` collects the CRT breadcrumb emitters, the `sp:*` string helpers, and small
diagnostic hooks. A production payload leaves them out; a diagnostic build (see
`-DiagnosticBreadcrumbs` in [Building a payload](payload-build.md)) uses them to walk the
bring-up sequence.

## Layout

Every wrapper class is a plain static class with `[LibraryImport]` interop declarations. The
source is organised under `src/SharpProspero/Payload/` in domain-specific sub-namespaces:
`Kernel/`, `IO/`, `Net/`, `Process/`, `Debug/`, `Elf/`, `Posix/`, `Services/`, `Bypass/`, and
`Orchestration/`. A missing wrapper for a symbol the payload needs is usually one of two things:
add a `LibraryImport` in the payload's `Program.cs` (fast path), or add the wrapper to the SDK
(permanent path, with the matching SPRX declaration).
