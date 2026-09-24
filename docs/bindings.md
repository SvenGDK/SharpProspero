---
title: Bindings
parent: References
nav_order: 1
---

# Bindings

The SDK talks to the device through interop bindings in `SharpProspero.Interop`. A binding is a
`partial` class of `[LibraryImport]` methods, plus the enums, structures and constants that go with
the service. The name in the attribute is a library, not a module file; a stub the linker generates
records both, and which module carries the library comes from the catalog. See below.

## How a binding is shaped

```csharp
public static unsafe partial class VideoOut
{
    private const string Lib = "libSceVideoOut";

    [LibraryImport(Lib)]
    public static partial int sceVideoOutOpen(int userId, int busType, int index, void* param);
}
```

Rules that keep bindings compatible with ahead-of-time compilation:

- Use blittable parameter and return types: the integer types, `nuint` for `size_t`, `long` for
  `off_t`, pointers for `void*` and `T*`. Blittable signatures generate no marshalling code. The one
  worthwhile exception is a NUL-terminated string argument: add
  `StringMarshalling = StringMarshalling.Utf8` to the attribute and take a `string`, which the
  generator converts without a runtime marshaller.
- Keep methods `static partial` in a `partial` class; the source generator writes the call.
- Pass buffers as pointers and let the caller pin or stack-allocate them.
- Match structure layout exactly with `[StructLayout(LayoutKind.Sequential)]` and the fields in
  header order, including reserved and padding fields.

## Direct imports

Each module an application uses is declared a direct import in `build/Prospero.App.props`:

```xml
<DirectPInvoke Include="libSceVideoOut" />
```

This turns the binding call into a direct symbol reference the linker resolves against the stub it
generates for `libSceVideoOut`. The linker generates a stub for each entry in its catalog, so a
service already covered needs only its `DirectPInvoke` entry. To add one the catalog does not yet
cover, list its export names under a new entry; a link then reports any name still missing so it can
be added.

### A module is not a library

A catalog entry is a **library**, not a module, and one module can publish several. `libkernel.prx`
publishes both `libkernel` and the portable-interface library `libScePosix`, so the catalog carries
two entries that name the same module file:

```csharp
new Entry("libkernel", Kernel),
new Entry("libScePosix", Posix, ModuleName: "libkernel", Soname: "libkernel.prx"),
```

An import records the module it comes from *and* the library within it, and the two are numbered
separately. A module publishing two libraries is named once in the needed list and carries an
import-library record for each.

Getting this wrong does not fail the link — it produces a module whose imports the loader cannot bind,
which installs, starts, and never reaches its first instruction with nothing written to any log.

**Only list a name a module really publishes.** A catalog entry asserts that it does, so a name listed
there that nothing publishes becomes exactly that unbindable import. A name the platform does not offer
belongs in the compat object instead, where it gets a definition — a forward, a fixed answer, or a
refusal its caller handles. A link reports what it cannot resolve rather than writing a module that
cannot load, and a test holds the line: every name the SDK imports is either named by the catalog or
defined by the compat object.

## Generating bindings from a module

The primary path needs nothing but the module you interact with. The generator reads a `.prx`,
computes the identifier for each name you list, verifies it is exported, and writes a wrapper. See
[modules.md](modules.md) for the full workflow:

```
dotnet run --project tools/SharpProspero.Bindings.Generator -- \
  prx --module mylib.prx --names names.txt --class MyLib --namespace My.App --out MyLib.g.cs
```

This makes no external calls and needs no headers.

## Response files for header processing

For projects that already process headers separately, the generator can also write a response file
per module from a catalog (`modules.json`). It only writes the files; it invokes nothing.

```
pwsh tools/SharpProspero.Bindings.Generator/generate.ps1 -SdkInclude <folder>
```

`-SdkInclude` names the header tree. Without it the script reads `PROSPERO_SDK_DIR` and appends
`target/include`; with neither set it stops and says so. Running the tool directly takes the same
folder as `--sdk`, plus `--modules` for another catalog and `--responses` for another destination.

Each response file names the header to parse, the output namespace (`SharpProspero.Interop.<Name>`),
the method class name, and the library. The response files land under
`src/SharpProspero/Interop/Generated/responses`.

## Built-in bindings

| Namespace | Service | Key entry points |
|---|---|---|
| `Interop.Kernel` | Thread bindings | the calling thread's own handle, read and set the processors a thread may run on |
| `Interop.Kernel` (crash reports) | What an application adds to the report the system writes when it faults | register and unregister a handler, attach memory and files, write user data, read the stop information and a thread's registers |
| `Interop.Kernel` | Direct and flexible memory, memory queries | reserve, map, release direct memory; the extended allocator; map, release, protect flexible memory (with an optional per-mapping name); available flexible and direct memory; virtual query; apply a run of map, unmap and protect operations in one call; the PRT aperture window |
| `Interop.Kernel` (files) | Files, directories and the light-weight file system | open, read, write, seek, close; the flag word an opendir sends and both `getdents` variants; make and remove a directory, unlink, rename, truncate, reachability; status by path or by descriptor; scatter and gather read and write, positional read and write; fsync; permission bits by path or by descriptor; the light-weight file system's block reserve, trim, seek and write; F_GETFL and F_SETFL through fcntl |
| `Interop.Kernel` (timing) | Time and processor readouts | process time in microseconds and in the raw process counter with its frequency; the CPU cycle counter and its frequency; the processor the caller is running on; get and get-resolution for a clock identifier; sleep in seconds, microseconds and nanoseconds |
| `Interop.Kernel` (modules and identity) | Modules, system version and identity | load and query a module; the system software version; the highest SDK version the running system will accept; a system value by MIB path or by dotted name; the calling thread's error-number address; the debug-pin drive and read (devkit-only); the console identifier, which the same module publishes under `libSceOpenPsId` rather than `libkernel` |
| `Interop.Kernel` (async I/O) | Asynchronous read and write engine | initialize and set the scheduling parameters for the three priority classes; submit read or write batches under one identifier or one identifier per request; wait or poll one or many identifiers; cancel; delete a completed identifier so its slot may be reused |
| `Interop.Kernel` (scheduling and sync) | Scheduling and synchronization primitives | a thread's policy, priority, clock, equality, detach and join; an attribute block covering stack size and address, guard size, detach state, affinity, priority, policy and inheritance; cancellation state and delivery; thread-specific keys, per-thread values and one-time initialization; the mutex, condition variable, read/write lock and POSIX semaphore families, each with its attribute block, lock/unlock, a timed variant and where it applies broadcast or signal; `sched_get_priority_max`, `sched_get_priority_min`, `sched_yield` |
| `Interop.Kernel` (mount) | Filesystem mount and unmount | `nmount` for a name/value pair list (`KernelMount.SetPair` / `SetFlag` builders keep the `SceIovec` layout right), `unmount`, and the `MntUpdate` flag |
| `Interop.VideoOut` | Display output | open, set attribute, register, submit flip, wait vblank; the full type surface — pixel formats (RGBA/BGRA including sRGB and BT.2100-PQ, half-float, 10:10:10:2), buffer-attribute flags, output modes, event and status flags, DCC control, refresh-rate and dynamic-range enums, and both primary and FPD parameter blocks |
| `Interop.Pad` | Controller | init, open, read, vibration, light bar, close; adaptive trigger effects and their state, motion and orientation, controller and touch-pad information |
| `Interop.Keyboard` | USB keyboard | init, open, read state, close |
| `Interop.Mouse` | USB mouse | init, open, read, close |
| `Interop.Net` | Network status, sockets, HTTP download, TLS | status (IPv4 and IPv6, interface byte counters, NAT and STUN); socket, bind, listen, accept, connect, send, receive, scatter/gather, poller, per-socket detail, name resolver with the connect helper; pool, ssl, request, read; URI parsing and building, cookies, epoll |
| `Interop.Net` (HTTP/2) | HTTP/2 client | request lifecycle, headers, body, cookie boxes and their I/O, authentication and Set-Cookie callbacks, redirect interception, gzip inflate, timeouts, pool accounting |
| `Interop.Net` (softAP) | Wireless access-point hosting | init/term, state and info readout, credentials the joiner presents, state-change callbacks, tear-down; the on-screen dialog for the connect flow that brings the access point up |
| `Interop.Audio` | Audio output, input, decode, encode, synthesis | output: init, open, output, set volume; input: open, capture, silent state, close; decode (AAC/ATRAC9/MP3) create, decode; encode AAC-LC and ATRAC9; Ngs2 synthesis and mixing (system, rack, voice, stream) |
| `Interop.Audio` (spatial) | Object-based spatial audio (Audio3d) | initialize, open a port, reserve objects, set position and attributes, write a bed, mix to the audio-out |
| `Interop.Audio` (jobs) | The audio job manager (Ajm) | initialize, register memory and modules, create instances, build/start/wait batches for Opus, AAC, MP3, ATRAC9 decode and encode |
| `Interop.Audio` (object-based) | The object-based output path (AudioOut2) | initialize, create a context, open ports of each type, set attributes, advance and push, speaker arrays and speaker info, per-user handles, mastering |
| `Interop.Audio` (propagation) | Acoustic propagation through rooms and portals (`libSceAudioPropagation`) | 24 entries: create and destroy a system, add and remove rooms and portals, register sources, hand a caller-owned PCM buffer, advance the model |
| `Interop.Text` | Character-encoding conversion (Ces) | EUC-JP, EUC-KR, Big5 and UHC to UTF-8 (use `System.Text.Encoding` between the Unicode forms) |
| `Interop.Video` | Video decode and recording | decode: create decoder, decode, flush, reset, query memory (H.264 and HEVC via the codec type); recording: status, query memory, open, start, stop, close, plus the parameter-query entry |
| `Interop.Video` (Videodec2) | Second-generation video decoder | picture-info getters for H.264, HEVC and VP9 alongside the generic getter |
| `Interop.Video` (software) | Software video decoder (`libSceVdecsw`) | 18 entries covering H.264, HEVC and VP9 software decode; picture-info structs pad-corrected so VUI and frame-crop fields land at the right offsets |
| `Interop.Vision` | Camera depth and capture | depth: query memory, initialize, set command, set region, submit, wait, get image; camera: initialize, open, configure, start, read frames, exposure and white balance, field of view, close |
| `Interop.AvCapture` | Video capture | open a video channel, start, read frames, stop, close |
| `Interop.Device` | Message-bus device service | initialize, generation counter, event state, query device info |
| `Interop.Sysmodule` | System modules | load, unload, is-loaded |
| `Interop.Image` | Image decode and encode | PNG and JPEG decode; PNG and JPEG encode (for a screenshot) |
| `Interop.Font` | Scalable text | load a TrueType or OpenType font, scale it by pixel, point or resolution, kerning, render antialiased glyphs |
| `Interop.Rtc` | Real-time clock and calendar arithmetic | current clock, current local-time clock, current UTC tick, current network-synchronized tick, tick resolution; UTC-to-local and local-to-UTC conversion; leap-year, days-in-month, day-of-week and check-valid predicates; convert between the broken-down calendar and a POSIX `time_t`, an MS-DOS packed time, a Win32 FILETIME and a tick; add ticks, microseconds, seconds, minutes, hours, days, weeks, months or years to a tick; format and parse a date/time as RFC 2822 or RFC 3339 (with a time-zone offset or in local time) |
| `Interop.Random` | Entropy | random bytes |
| `Interop.Dialog` | Common dialog subsystem, browser dialog, on-screen keyboard, message dialog, error dialog, save-data dialog | initialize subsystem, open, status, result, close; the browser dialog adds `SetCookie` / `ResetCookie` and an opener for pre-determined content; the save-data dialog adds a directory-name getter and ready-to-display readouts for progress and text |
| `Interop.Dialog` (login) | Signing a user in from a dialog | 7 `LoginDialog` entries: initialize / terminate / open / close / get status / get result / update, with `OpenParam`, `Result` and `Status` types |
| `Interop.Dialog` (sign-in) | Signing in from a dialog | 7 `SigninDialog` entries covering the same lifecycle |
| `Interop.Dialog` (play-go) | Install-progress dialog | 7 `PlayGoDialog` entries covering the same lifecycle |
| `Interop.Dialog` (invitations) | Player invitation dialog | 7 `PlayerInvitationDialog` entries covering the same lifecycle |
| `Interop.Dialog` (player selection) | Player selection dialog | 7 `PlayerSelectionDialog` entries covering the same lifecycle |
| `Interop.Media` | Media playback (`libSceAvPlayer`) | 28 entries: add source in both basic and extended form, start, get and change stream info, disable a stream, per-tick get audio and video frames, av-sync mode, trick speed, bandwidth hint, log callback, close |
| `Interop.UserService` | Users | initialize, initial user, the signed-in users, a user's name, sign-in and sign-out events, accessibility settings, terminate |
| `Interop.SystemService` | System | hide splash, read a parameter, launch another title, keep awake, receive events, read status, safe area, load an executable, plus the app-status list surface for foreground and daemon queries and the app-launch/URI error constants |
| `Interop.SaveData` | Save data | 23 entries covering the full lifecycle: mount, transferring mount, read and write the parameters and the icon, search directories, transactions, back up, delete, plus the memory-region surface (setup, sync, get, set) and the event-result readout |
| `Interop.AppContent` | Additional content | initialize, read the boot parameters, mount and unmount additional content, queue a download and read its progress, the writable scratch area, `GetStringParam`, `GetAddcontInfoList`, `GetAddcontInfo` |
| `Interop.AppInstUtil` | Package installer | 7 entries covering install by package (3-arg form), install-progress readout, cancel, pause, resume, uninstall by title id and uninstall-type family |
| `Interop.PlayGo` | Install progress | initialize, open, read the install progress |
| `Interop.Compression` | Compression | inflate a zlib or deflate stream |
| `Interop.Pfs` | PFS memory-to-memory decompression | the workspace buffer size; validate a PFS buffer (header only, or header plus block table); the original uncompressed byte count; read a range of the uncompressed view directly out of a buffer |
| `Interop.Content` | Content library | delete by path or id, count, size, search photos and videos, export a file or a block of memory, with or without a thumbnail |
| `Interop.Share` | System capture | initialize, capture a screenshot or a video clip of the composited screen, recording status, screenshot overlay, permit or prohibit a feature |
| `Interop.Notification` | Notification service | send a message, send by id, show and hide the persistent PS-button banner |
| `Interop.Np` | Trophies and events | trophy2: contexts, game and group and trophy info, icons, show list; universal data system: post named events with properties |
| `Interop.Bluetooth` | Bluetooth HID driver | init; register callback and device; get report descriptor, device name, device info; get and set reports; interrupt output; disconnect (low-level, privileged) |
| `Interop.FeatureFlag` | Console feature flags | is a feature on, is it waiting for a reboot |
| `Interop.Agc` | Graphics command layer | 192 command builders: draw, dispatch, register writes, synchronization, shader create/link, register defaults, packet patching |
| `Interop.Agc` (driver) | Graphics submission | 79 driver calls: submit, queue management, display flip, wait-until-safe, resource registration, workload streams |
| `Interop.Agc` (Ampr) | Async memory paging / remap type surface (`SceAmpr`) | constants, command-buffer layouts, wait comparisons, priority levels and result codes — no `LibraryImport` entries because the module's callable entry points are exposed only through a C++ interface |
| `Interop.Debug` (RazorCpu) | CPU profiler markers (`libSceRazorCpu`) | 19 entries: push and pop markers, static-label push, plot values, bookmarks, sync and named-sync events, data-sampler tag storage, tag array and buffer, logical-file access begin and end, flush-occurred query, is-capturing query |
| `Interop.Debug` (RazorCpu debug) | CPU profiler capture control (`libSceRazorCpu_debug`) | 2 entries: start capture, stop capture — both return `ErrorHostNotListening` (`0x8058000C`) when the host is not listening |

## Result codes

Service calls return a 32-bit result. Non-negative is success; negative is an error. `SceResult`
interprets them: `Succeeded`, `Failed`, and `ThrowIfFailed`, which raises a `ProsperoException`
carrying the operation name and raw code.
