---
title: Build pipeline
nav_order: 2
parent: Toolchain
---

# Build pipeline

An application goes through a fixed sequence to become a package: compile the C# to an object, link the
object into an ELF module, gather and check what travels with it, settle the system version, wrap the
module, and write the output. The compile and the link are driven by MSBuild files in `build/`; the
steps after them are toolchain commands, and the last hands the folder to the packager.
`build/build-app.ps1` runs the whole sequence. Every project copied from a sample
ship a `build.ps1` that forwards to it.

## Inputs

Nothing outside the .NET SDK is set up. `build-app.ps1` gathers the ahead-of-time runtime from the .NET
SDK's own runtime pack (restored by the compile step) and links through the SDK's own linker,
which supplies its own start object, a compat object for the C-library names the runtime needs that the
device does not publish, and stubs for the service modules. So there is no runtime pack to assemble, no
`PROSPERO_RUNTIME_PACK` to set, and no separate linker, start file, or stub library.

The one host requirement is that the compile step runs on Linux (see step 1). On Windows `build-app.ps1`
runs that step through WSL automatically, so a Windows user builds in place.

## Step 1: compile

An application imports `build/Prospero.App.props`, which configures the ahead-of-time compile:

- Trimming is set to full and the size preference is on, so unused framework surface does not survive.
- Framework features an on-device module never uses are switched off: globalization data, resource
  strings, event sources, the metadata updater, activity propagation and the debugger hooks.
- The garbage collector is the workstation, non-concurrent collector, with a hard ceiling baked into
  the image through `System.GC.HeapHardLimit`. Set the ceiling per project with
  `ProsperoHeapHardLimitBytes`.
- Every service module is declared a direct import (`DirectPInvoke`), so each binding call becomes a
  direct reference the linker resolves against a stub it generates for that module.

Publish with an x86_64 runtime identifier:

```
dotnet publish -c Release -r linux-x64
```

The compiler writes an object under `obj/Release/net10.0/linux-x64/native`. It targets the x86_64
instruction set; the runtime it links against (below) matches the device ABI.

One constraint on this step: the ahead-of-time compiler emits an object only for the operating system
it runs on, so it does not cross-compile to Linux from a Windows host. `build-app.ps1` therefore runs the
publish through WSL on Windows — the object still lands in the project's `obj` folder, which both sides
share — and runs it directly on Linux. The link and pack steps below are the toolchain itself and run
wherever the script is started.

## Step 2: link

`build/Prospero.App.targets` defines the `ProsperoLink` target. It is not part of a normal build, so
`dotnet build` never touches it; run it directly or through `build-app.ps1`. The target:

1. Checks the runtime archives and the compiled object exist, stopping with a specific message if one
   is missing.
2. Passes `--kind eboot` to the SDK's linker along with the application object and the runtime
   archives. The linker supplies its own start object (which carries the `_start` entry point) and
   its own stubs for the modules the SDK imports from. It reads each object and archive, resolves the
   symbol graph, lays the sections into segments, applies the relocations, and writes `eboot.bin` —
   the exception-frame index and the thread-local template included. The kind is always named
   explicitly; a self-contained link that omits it is refused.

A project can add stubs for its own modules through `ProsperoUserStubLibrary` (generated from a `.prx`
by the stub tool); those let an application link against libraries it supplies. Run the target
directly like this:

```
dotnet msbuild samples/prospero-app/SampleApp.csproj /t:ProsperoLink ^
  /p:ProsperoObjectFile=<path-to-object> /p:ProsperoRuntimePack=<runtime-archive-folder> ^
  /p:OutputPath=<module-folder>/
```

`ProsperoRuntimePack` names the folder holding the gathered runtime archives. The target stops with a
message when neither it nor `ProsperoRuntimeLibraries` is set, so a manual link has to pass one of them.

Override the runtime input list and its order with `ProsperoRuntimeLibraries` (semicolon-separated)
when the default folder scan is not the order you want. The list holds both forms: an entry ending in
`.o` reaches the linker as an object, everything else as an archive. The linker takes an object whole
and draws from an archive only for the names still wanted. Setting the property replaces the folder
scan, so name the runtime's bring-up object in the list too: nothing asks for a name it defines, and
a list of archives alone leaves the module with nothing to start.

### What the linker lays out

The module the linker writes carries five load segments, in this order:

| Segment | Protection asked for | Holds |
|---|---|---|
| Code | **execute only** | the compiled code and the procedure-linkage table |
| Read-only | read | read-only data, the call-frame records, and the frame index |
| Bound-then-constant | read + write | the global-offset table, the process parameters, the constructor array and the thread-local template |
| Writable | read + write | the data the application writes to, and what it reserves past what it stores |
| Linking | **none** | the symbol, string and hash tables, both relocation tables, the module note, and the dynamic table |

Two of those protections look wrong at first glance and are not.

The code segment asks for **execute without read**. A load segment that asks for read and execute
together is refused and the module does not start, so the read bit has to be left off; the loader
grants the read access the processor needs when it maps the segment. The practical consequence is
that read-only data must live in the read-only segment and never beside code.

The last one is the part that is easy to get wrong. It is a load segment that requests no memory
protection at all, and that is exactly what marks it as linking data rather than image content: the
loader reads it to bind the module instead of mapping it into the running process. **A module that
names a dynamic table without also carrying this segment does not start.** Its program headers are
scanned before any of its code runs, the pair is found inconsistent, and the launch is refused with a
segment-header error while the application sits on a splash screen.

Alongside it, two placements are equally load-bearing: the dynamic table and the module note must
both lie *inside* that linking segment, and the process parameters must lie inside a writable load
segment.

The rest of what the loader insists on, in one list:

- A load segment asks for exactly one of: nothing, execute, read, or read and write. Read together
  with execute is refused.
- At least one load segment is executable and at least one other is writable without being executable.
- Every load segment that is actually mapped — that is, every one asking for some protection — has its
  address, file offset and alignment all on a `0x4000` boundary. The linking segment is exempt, since
  it is never mapped.
- Physical address matches virtual address, and memory size is never smaller than file size.
- A relro header has to match a writable load segment on offset, address and stored size. Its memory
  size rounds up to the page, because the loader protects whole pages — it does not match the load's
  memory size, and a module built by the toolchain the format comes from carries that rounding.

Sections are placed one **output section** at a time, not one object at a time: every object's
contribution to a name is gathered into one run, and a name the compiler splits (`.text.f`) belongs to
its prefix (`.text`). The order within each segment is the one a built module uses:

| Segment | Order |
|---|---|
| Code | `.init`, `.text`, `.fini`, then the rest, then the linkage table |
| Read-only | `.rodata`, `.eh_frame`, then the rest, then the frame index |
| Bound-then-constant | `.data.rel.ro`, `.got`, `.got.plt`, `.ctors`, `.dtors`, `.init_array`, `.fini_array`, `.sce_process_param`, `__modules`, then the thread-local template aligned to 32 |
| Writable | `.shader_header`, `.data`, `.bss`, then the rest — what it stores before what it only reserves |

Gathering by name is what makes a name a contiguous run, which two things depend on: the call-frame
records are read as one chain, and the constructor array is named by one address and one length.

Where the linking segment goes is fixed too. Its address is where the writable segment's memory ends,
so it falls inside the pages that segment is mapped over, and its file offset is never page-aligned —
it carries the same page offset as its address, at the first such offset past the writable segment's
stored bytes. Rounding it up to its own page instead produces a module that does not start.

Every mapped segment stores something. A segment that stores nothing is carried by the container as a
pair of zero-length entries sharing one file offset with whatever follows, which the loader turns away.
A module with no writable data of its own is where this happens: the group is still there, and it still
has to store a word. The container refuses such a segment as well, so it cannot be reached from either
direction.

The linking group's tables come in one order: the **string table at the group's base address**, then the
symbol table, the binding records, the relocation table, the hash, the note, and the dynamic table last.
Any other order leaves the module unable to start. Each table begins where the one before it ends,
rounded up to eight — four for the note — with no padding beyond that.

Three more things the linker writes that are easy to leave out, and that only show up much later:

- **Sixteen bytes are reserved in front of the code**, filled with the one-byte trap. An address of
  zero reads back as "none" wherever a routine or a table is optional, so nothing the module publishes
  may sit there.
- **The call-frame records end with a terminating zero**, and the records from every input are laid end
  to end. They are read one after another until that zero; a gap between two of them ends the chain
  early, and no zero at all sends a reader off the last record into whatever follows.
- **The module names its regions in a section table.** Every module measured carries one. The container
  drops it along with everything else outside the segments, so it costs nothing at run time — and it
  means a module can be read back by the same tools that read a built one.

### What the relro header covers, and what it must not

Everything the relro header covers is made read-only once the loader has finished binding the module.
That is what the global-offset table is for — it is written during binding and never again — and the
process parameters go with it.

**The data an application writes to has to stay outside it.** The linker keeps two writable segments
for exactly this reason: the first holds the table and the parameters and is covered by the header,
the second holds `.data` and the uninitialized data and stays writable for the life of the process.
A build that covers both with one header produces an application that maps, binds and then faults on
its first write to a static — with the fault landing before anything the application could log.

The second segment reserves more memory than it stores, so uninitialized data costs no file bytes:

```
LOAD       RW  va=0xec000  fsz=0xdf8   msz=0xdf8     table, parameters, constructors, thread template
GNU_RELRO  R   va=0xec000  fsz=0xdf8   msz=0x4000    rounded to the page
LOAD       RW  va=0xf0000  fsz=0x1240  msz=0x1c420   data, writable throughout
LOAD       --  va=0x10c410 fsz=0x5408  msz=0x5408    linking data, packed against the memory above
```

The sections that store nothing are grouped after the ones that do, so an uninitialized section between
two initialized ones costs no file bytes. Placing them in the order the objects carry them would force
the segment to store the whole span and write out zeros it could have reserved.

### The dynamic table

Reading the dynamic table is the last thing the loader does before binding the module, and it is as
strict as the segment checks:

- **Twelve ordinary tags are mandatory whatever their value**: the hash, the string table and its
  size, the symbol table and its entry size, the relocations with their size and entry size, and the
  linkage table with its size, type and relocations. The relocation trio is the one that catches
  people out — a module with nothing to relocate still has to name an empty table rather than leave
  the tags out.
- Two size tags a module carries for itself, covering the hash and the symbol table, are also
  required, and a library additionally has to record its own file name and module information.
- **The module-specific aliases for the symbol, string and relocation tables must not appear.** They
  name data the ordinary tags already name; the loader routes both to the same handler, reads the
  alias as a duplicate, and refuses the module.
- Anything the tables point at resolves inside the linking segment, and both relocation sizes are
  whole multiples of the entry size.
- Only the RELA relocation form is accepted; the older REL form is refused outright.

You do not configure any of this — the linker always produces this shape. It is documented because
it is what the loader checks, so it is what a hand-built or externally produced module has to match
to launch. Confirm a module's shape with the inspector:

```
sharpprospero-bindgen elf --file eboot.bin
```

## Step 3: gather the modules the application carries

Most modules an application imports from are published by the system: the application names one and
the loader finds it. A small set is different — the application carries its own copy in `sce_module`,
and the system publishes nothing to bind against.

**This is the failure mode with no symptom.** An application that names one of these and does not
carry it passes every structural check, installs cleanly, and then hangs the console when launched.
There is no error and nothing in the log, because the loader resolves the module before any of the
application's code runs. Recovering needs a power cycle.

The build therefore checks it and refuses to produce a package otherwise:

```
== Modules ==
  libc.prx: present
```

Put a copy in the project's `sce_module` folder and it is used as-is. To have the build fetch them
instead, point `ProsperoModuleFolder` (or the `PROSPERO_MODULES` environment variable) at a folder
holding them, and the line reads `gathered` rather than `present`. If a required module is neither
present nor available the build stops with the list, rather than handing you a package that wedges a
console.

Check a built module yourself at any time:

```
sharpprospero-bindgen modules --module eboot.bin --folder sce_module
```

A module the application carries also raises the system version the application requires, which Step 3d
settles.

## Step 3b: check the application's metadata

`sce_sys/param.json` describes the title to the system — what kind of title it is, what it is called,
and what it is allowed to do. The build reads it and fills in anything a finished title carries that
yours does not:

```
== Metadata ==
  kind                           Game (0)

  Nothing missing.

Wrote out/module/sce_sys/param.json (contentBadgeType, gameIntent)
```

Run the command without `--apply` to see what is missing before it is filled in:

```
  contentBadgeType               incomplete Absent. It settles the badge drawn on the icon.
  gameIntent                     incomplete Absent. It names the ways the title may be started.
```

A field carrying a value the system does not recognise — a kind of title outside the ten it knows, a
malformed content id, a rights model that is not one of the five — stops the build instead. None of it
reports itself on the console: the home screen simply draws the title wrongly, or a service it expected
to reach is never offered to it.

The fields, the kinds of title, and what the checks are looking for are described in
[the param.json fields](param-json.md). Check a folder yourself at any time:

```
sharpprospero-bindgen param --folder out/module
```

## Step 3c: emit matching DDS textures

The console renders the launch-panel and store artwork from DDS textures alongside the PNG files a
project ships in `sce_sys`. After gathering the folder, the build walks it for any file whose name
begins with `icon` or `pic` and writes a matching `.dds` next to each one - a DX10-header BC7
texture with the 148-byte layout the loader accepts:

```
== Textures ==
```

Nothing is written when no PNG files match, and a PNG that already has an up-to-date DDS beside it
is left alone. The step runs the `sharpprospero-bindgen sceassets` command; run it against a folder
of your own at any time:

```
sharpprospero-bindgen sceassets --folder sce_sys
```

## Step 3d: settle the system version

A module records the system it was built against, and the application has to require at least as much or
the system installs it and then fails to load the module. The build reads every module it gathered and,
by default, raises the requirement to the highest:

```
sharpprospero-bindgen sysver --folder out/module --policy match --apply
```

`-SystemVersionPolicy` on `build-app.ps1` picks between the four policies, which [Modules and
libraries](modules.md) describes; `--version` supplies the version `upgrade` and `downgrade` move to.
The command exits 4 when a module is left needing more than the result, which the build reports rather
than treats as a failure. The result is written to `sce_sys/param.json`, so a library module with no
metadata of its own skips the step.

## Step 4: wrap the module

The linker's output is a plain ELF, and **a plain ELF does not launch** — the loader authenticates a
module's container header before running any of its code, so an unwrapped `eboot.bin` is turned away
and the application never starts. The build therefore wraps the module it produced, after settling
the system version and before either output is written:

```
== Sign ==
Wrote .../module/eboot.bin (1090320 bytes, signed container).
```

Every module is wrapped, the one built here and the ones the application carries: a copy taken from
a module folder is an unwrapped ELF and is turned away exactly as an unwrapped `eboot.bin` is. The
step leaves an already-wrapped file untouched, so re-running a build is safe.

### What the header carries

The writer produces the header shape built around the magic `0xEEF51454`: a metadata region ending in a
`0x200`-byte signature area, which for the twelve entries a module carries makes the region `0x610`
bytes. The magic and the region length go together — a container that mixes one magic with the other's
region length matches nothing that has been measured — so the two are written as a pair and never
separately.

A module's **version records** live in a segment nothing maps, so no container segment carries them.
They follow the last stored segment instead, past the size the header declares, and reading a container
back puts them where the program header places them.

A module already wrapped in either header shape is left alone. Modules carrying either mark load, so
re-wrapping one would replace a container that works:

```
sce_module/libc.prx is already wrapped; left unchanged.
```

The packager reports the result as part of its launch-readiness summary:

```
Launch readiness: ready
  module:      wrapped for the loader, contents readable
```

If that line reads *a plain ELF*, the module was not wrapped and the application will not start.
[Unsigned and signed](signed-and-unsigned.md) covers the forms in full.

## Step 5: output

The build gathers `eboot.bin` next to the `sce_sys` metadata and any `sce_module` libraries, then
writes one of two outputs. `build-app.ps1` picks with `-Output`:

```
pwsh build/build-app.ps1 -ProjectPath MyApp.csproj                    # Package (the default)
pwsh build/build-app.ps1 -ProjectPath MyApp.csproj -Output Folder     # every file in one folder
```

| Parameter | What it does | Default |
|---|---|---|
| `-ProjectPath` | The application project to build. | required |
| `-Output` | `Package` writes an installable file; `Folder` leaves every file in one folder. | `Package` |
| `-OutputFolder` | Where the result is written. | an `out` folder next to the project |
| `-Configuration` | Build configuration. | `Release` |
| `-TitleId` | The title this build carries, when it should differ from the one the project's metadata names. Four letters and five digits, for example `PPSA99098`. | the project's own |
| `-SdkRoot` | The SDK folder. | the folder above the script, then `SHARPPROSPERO_ROOT` |
| `-Payload` | Link a payload instead of a module and stop there. See [Payloads](#payloads). | off |
| `-DiagnosticBreadcrumbs` | When used with `-Payload`, includes the CRT's `sp:*` klog checkpoints in the built ELF. Useful for bring-up; omit for production. | off |
| `-SystemVersionPolicy` | How the system version the application requires is settled. See [Modules and libraries](modules.md). | `Match` |
| `-SystemVersion` | The version `Upgrade` and `Downgrade` move to, as NN.NN. | none |

`-TitleId` changes the gathered copy only; the project's own metadata is left alone. An installer treats
a title already on the machine as present and declines to replace it, so a build meant to sit beside the
last one needs a title of its own.

**Package** hands the folder to the packager and writes an installable `*.pkg`:

```
dotnet run --project tools/SharpProspero.Packager -- --in <module-folder> --out <output-folder>
```

`build-app.ps1` passes `--in` and `--out`. Running the packager directly takes six more options:

| Option | What it sets | Default |
|---|---|---|
| `--in`, `--out` | The gathered module folder, and the folder the package is written to. | required |
| `--module` | The module file to take from the input folder. It is always packed as `eboot.bin`. | `eboot.bin` |
| `--content-id` | The 36-character content id the package is built for. | the `contentId` in `sce_sys/param.json`; the build stops when neither supplies one |
| `--passcode` | The 32-character passcode the package is built with. | thirty-two zeros |
| `--title` | The display name written into a `param.json` the packager generates because the folder carries none. A `param.json` already in the folder keeps its own title, and this option then changes nothing. | the title id taken from the content id |
| `--version` | The content version, `NN.NN`, which also names the output file. | the `masterVersion` in `sce_sys/param.json`, otherwise `01.00` |
| `--keep-staging` | Keeps the assembled working tree beside the output instead of deleting it. | off |

**Folder** stops after gathering, leaving `eboot.bin`, `sce_sys` and `sce_module` together in one
folder ready to copy or inspect. Nothing is packed, so none of the packaging options above apply.

## Where the runtime comes from

The linked module needs the ahead-of-time runtime — the garbage collector, exception handling, and the
bootstrap that runs before the managed entry. These are the standard runtime archives, and
the `dotnet publish` compile step restores them into the .NET SDK's package cache as its own runtime
pack. `build-app.ps1` gathers those archives from the cache and hands them to the linker, so nothing is
assembled or downloaded separately.

The runtime archives call a set of C-library and operating-system functions. The device's own C and
kernel modules already publish most of them (the whole `pthread` family, the memory and file calls,
timing, and the C library), so the linker resolves those as ordinary imports against the module stubs.
The rest — a small set the runtime asks for by a name the device does not publish, such as the
large-file variants of the file calls — are provided by a compat object the linker emits itself: each
is a thin forwarder to the name the device does publish, or a fixed result an application module can
accept. A `--kind payload` link builds a variant of the compat object tuned for that environment: a
wider memory-protection commit that covers the runtime's straddled bookkeeping page, a
`pthread_create` wrapper that installs a thread-local block on every new thread (the dynamic linker
that does this for a module is absent in a payload), and no libc marker (see
[Modules and payloads](modules-and-payloads.md)). The upshot is that the runtime's operating-system
surface is satisfied entirely by the device modules and the toolchain, with no platform layer to
build.

The linker also defines the section-boundary symbols the runtime reads to walk its own managed-code and
module tables (`__start_<section>` / `__stop_<section>`), the way the system linker does. A table slot
holding one of those addresses gets a load-time fixup like any other: the runtime registers that range
with itself as it starts, and a slot left at zero measures a range of nothing, which registration
refuses.

Two of the forwarders in the compat object are worth knowing about, because they do more than forward:

- **Memory** comes from the flexible pool. The device publishes the calls that change protection and
  release memory, but not the one that takes it, so a module brings its own — and its own protection
  change too, because the two have to agree. Asking for no access holds address room without spending
  the pool. The protection change then asks the device what is behind that address before it does
  anything: a range carrying no protection at all, and none of the kinds that already hold memory, gets
  memory mapped over it pinned to the addresses it already holds; every other range, and any range the
  query cannot report on, gets a plain protection change. Trying one call and watching it fail does not
  separate the two cases — a protection change over a held-but-empty range *succeeds* and attaches
  nothing, and a pinned mapping over a live range throws away what it held. Both round to whole pages,
  because the pool refuses any length that is not a multiple of one, while the ordinary call answers a
  request for a few hundred bytes with a page.
- **The module's own address** is reported by reading the image start instruction-relative, which is
  the only way a module can learn where it was placed. The runtime uses that as the handle identifying
  the module, so answering "not found" would register it under a handle no address matches.

The compat object also carries helpers the SDK itself calls. `SharpProspero.Memory.CpuCache.WriteBack`
is one — a 29-byte body the emitter appends to an application module's compat object (never the
payload variant, so app-vs-payload separation stays strict). The build declares
`libSharpProsperoCompat` as a `DirectPInvoke` in `Prospero.App.props`, so the ahead-of-time compiler
emits a direct call to the entry-point symbol rather than a runtime module lookup: the library name
never reaches the loader. A missing symbol fails the link rather than becoming a silent runtime no-op.

A plain `dotnet build` of the solution and the tests need none of this; it applies only to the link
step, which runs after the compile step has restored the runtime pack.

## Payloads

Besides an application module and a library, the linker builds a *payload*: a position-independent
executable a small loader maps into an existing process at run time and jumps to, over a network
connection. A payload is not signed and not packaged; it has no dynamic linker, so it resolves the
functions it calls at run time rather than importing them from modules. [Modules and
payloads](modules-and-payloads.md) covers how the two forms differ and which one to build; this section
covers the build command.

Build one with `build-app.ps1` and the `-Payload` switch:

```
pwsh build/build-app.ps1 -ProjectPath MyServer.csproj -Payload -Output Folder
```

Or call the linker directly:

```
sharpprospero-bindgen link --kind payload --self-contained --obj app.o --lib runtime.a --out app.elf
```

Every reference the objects leave open becomes a name the payload resolves at start-up through the
resolver the loader hands it; the start code fills a table of these before calling `main`. The output is
a plain shared-object executable with base-relative relocations only.

A payload that calls functions from additional system libraries declares them in the project file as
`<ProsperoSprx>` items. The build passes each as a `--sprx` flag so the linker emits the
corresponding `DT_NEEDED` entries. A payload that needs a kernel module other than the default
`libkernel_web.sprx` sets `<ProsperoKernelSprx>` in the project (for example
`libkernel_sys.sprx` for process-level access). See [Modules and payloads](modules-and-payloads.md)
for the project-file syntax.

Pass `-DiagnosticBreadcrumbs` alongside `-Payload` to include the CRT's `sp:*` klog checkpoints in
the built ELF. These trace each bring-up step in the device log; omit the switch for production builds.

Send a built payload to a listening loader:

```
sharpprospero-bindgen payload --send --host 192.168.1.10 --file app.elf
```

The loader reads the whole file, maps it, applies the relocations, and runs it. The default port is 9021.

{: .note }
> The file format of both an application module and a payload is checked against the console's own loader
> and libraries: the header identification, the segment and dynamic-table layout, and the relocation
> section are the forms the loader accepts. The payload start code resolves its references through a
> three-handle cascade (`0x1` / `0x2` / `0x2001`) using `sys_dynlib_dlsym`, allocates and installs the
> managed runtime's thread-local storage with TCB canary forwarding, runs the global constructors,
> and marks the C runtime threaded before the managed entry. The managed entry point is
> `[UnmanagedCallersOnly(EntryPoint = "__managed__Main")]`; `libbootstrapper.o` initializes the
> NativeAOT runtime and calls it. Producing, sending, and running the file is the complete path; the
> thread-local set-up runs on the entry thread and is exercised on hardware.

## Keeping the heap in bounds

Memory maps are limited, so the heap ceiling matters. `build/Prospero.App.props` sets three properties
that go into the image as runtime configuration; override any of them per project.

| Property | What it sets | Default |
|---|---|---|
| `ProsperoHeapHardLimitBytes` | The managed heap ceiling (`System.GC.HeapHardLimit`). | 268435456 (256 MiB) |
| `ProsperoHeapRegionRangeBytes` | The address space the collector holds for its regions (`System.GC.RegionRange`). Left unset it asks for five times the ceiling in one unbroken run, which the pool will not hand out, and the collector refuses to start. The figure is used exactly as given, so it has to be a whole number of pages. | 402653184 (384 MiB) |
| `ProsperoThreadStackBytes` | The stack a runtime thread is created with (`System.Threading.DefaultStackSize`), read as a decimal count of bytes. Left unset a thread gets 64 KiB, which the collector's own threads overrun. | 1048576 (1 MiB) |

Read usage at runtime with `SharpProspero.Memory.HeapMonitor`, and prefer drawing into pre-allocated
framebuffers and reusing buffers over allocating each frame.
