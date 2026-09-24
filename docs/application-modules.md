---
title: Application Modules
nav_order: 4
has_children: true
---

# Application Modules

An **application module** is a homebrew title the console installs and launches from the home screen.
Write it in C#, derive from `ProsperoApp`, override `OnFrame`, and call `Run`. The toolchain compiles
it ahead of time to an `eboot.bin`, packs it with its `sce_sys` metadata, and produces an installable
package — everything an installable title needs. See [Payloads](payloads.md) for the other executable
form the toolchain builds.

## What an application module is

An application module runs as its own process with a full lifecycle: install, launch, run, exit. The
console's own program loader binds every device-service import by name, sets up the module's
thread-local storage, registers the exception frames, and runs the global constructors before the
entry point. That means an application module can reach the full device-service surface — graphics,
input, audio, media, networking, memory, save data, dialogs, trophies, capture, package install,
firmware compatibility — because the loader connects it to those services.

The pages under this section cover the API surface an application module builds against.

## The API surface

| Area | What it covers |
|---|---|
| [Application host](application.md) | `ProsperoApp`, the frame loop, timing, threading, diagnostics, and animation. |
| [Graphics](graphics.md) | The 2D drawing surface, images, fonts, [2D scenes](graphics-scene.md), and the [GPU command layer](graphics-gpu.md). |
| [Input](input.md) | The controller, motion and touch, rumble and light bar, keyboard, and mouse. |
| [Audio](audio.md) | Output and microphone, decoding, encoding, filters, envelopes, synthesis, and mixing. |
| [Media](media.md) | Playing a media file, reading a track's tags, and decoding video. |
| [Networking](networking.md) | TCP and UDP sockets, a poller, an HTTP client and server, and downloads; the low-level [network bindings](net.md) for HTTP/2, softAP hosting, IPv6, and DNS. |
| [Memory](memory.md) | Direct and flexible memory, the managed heap, pooling, and an asset cache. |
| [Interface toolkit](ui.md) | Building screens from labels, buttons, lists, and other controls. |
| [Data and utilities](data.md) | [Files](storage.md), [numerics](numerics.md), [buffers](buffers.md), [text](text.md), [XML](xml.md), [compression](compression.md), and [hashing](hashing.md). |
| [System services](system-services.md) | [System info](system.md), [dialogs](dialogs.md), [save data](save-data.md), [trophies](trophies.md), [capture](content-capture.md), [packages and devices](packages-devices.md), and [firmware](firmware.md). |
| [Modules and libraries](modules.md) | Loading a `.prx` at run time and building one. |
| [Samples](app-samples.md) | Ready-to-build sample projects for each kind of application module. |
| [Promoting an application](app-promotion.md) | Asking a companion payload to lift the module's credential, capability, and filesystem-view state past the per-title bounds. |

## The build path

The default `build-app.ps1` invocation compiles, links, and packs an application module:

```
pwsh build/build-app.ps1 -ProjectPath MyGame/MyGame.csproj
```

- `-Output Folder` writes the loose `eboot.bin`, `sce_sys`, and any `sce_module` files into
  `MyGame/out/module` instead of a `*.pkg`.
- `-TitleId <PPSAxxxxx>` overrides the title id and the title portion of the content id, so a build
  can sit beside the last one on the console.

The three-step pipeline is documented in [Build pipeline](build-pipeline.md).

## The lifecycle

An application module has a distinct install-launch-run-exit lifecycle. Between installs, the console
re-applies the module's sandbox before each launch: on every run the module is confined to `/app0`
(its own package files, read-only) and its writable per-title folder. A payload the user ran once
does not persist across a launch, because launching a new process starts with a fresh sandbox. That
is why promoting an application is a runtime call to a companion payload rather than a persistent
setting — see [Promoting an application](app-promotion.md).
