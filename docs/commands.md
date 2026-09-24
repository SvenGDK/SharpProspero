---
title: Command reference
parent: References
nav_order: 4
---

# Command reference

Every command the toolchain offers, in one place. Run any of them with `--help` for its options.

```
sharpprospero-bindgen <command> [options]
sharpprospero-bindgen <command> --help
```

`sharpprospero-bindgen` is the program `tools/SharpProspero.Bindings.Generator` produces; the name works
once that build output is on `PATH`. From a checkout, reach the same commands through the project:

```
dotnet run --project tools/SharpProspero.Bindings.Generator -- <command> [options]
```

Both forms run the same program, and the pages linked below use either one.

Building an application does not need any of these directly — `build/build-app.ps1` runs the ones it
needs. They are here for when you want to look at what was built, work with a module you were given, or
build a piece by hand.

## Building a module

| Command | What it does | More |
|---|---|---|
| `link` | Links objects into an `eboot.bin`, a `.prx` library, or a payload. | [Build pipeline](build-pipeline.md) |
| `crt` | Writes the start object that carries the program entry point. | [Build pipeline](build-pipeline.md) |
| `compat` | Writes the compatibility object that bridges the runtime's C calls to what the device publishes. | [Build pipeline](build-pipeline.md) |
| `stub` | Builds an import library for a module, either from the module itself or from a name list. | [Modules and libraries](modules.md) |
| `self` | Signs, extracts, or reports the form of a container. | [Signed and unsigned](signed-and-unsigned.md) |
| `payload` | Sends a payload built with `link --kind payload` to a listening loader. | [Modules and payloads](modules-and-payloads.md) |

`crt` writes the start object an executable link uses; `compat` writes the compatibility object a link adds
once it pulls in the runtime archives. Writing them out lets another linker take the same inputs. `compat`
always writes the application-module form; a `--kind prx` link builds a library variant, and a `--kind
payload` link builds a payload variant (wider memory-protection commit, thread-block management on new
threads, no libc marker). A payload link also supplies its own start object through `PayloadCrtEmitter`.

```
sharpprospero-bindgen compat --out compat.o
sharpprospero-bindgen crt    --out crt.o
```

## Looking at a module

| Command | What it does | More |
|---|---|---|
| `elf` | Prints a module's header, program headers, dependencies and exports; also its loadable size, symbols, strings, or a stripped copy. | [Signed and unsigned](signed-and-unsigned.md) |
| `prx` | Lists a module's exports with their identifiers, or generates a C# wrapper for it. | [Modules and libraries](modules.md) |
| `diff` | Reports the exports added, removed and moved between two modules. | [Working with module offsets](offsets.md) |
| `nid` | Computes the export identifier for a name, so a name you know maps to an export you can confirm. | [Modules and libraries](modules.md) |
| `offsets` | Dumps a module's export identifiers and addresses, and how they cover the names the SDK needs. | [Working with module offsets](offsets.md) |
| `shader` | Reports a compiled shader binary: its kind, version, sizes and register writes. | [Graphics on the GPU](graphics-gpu.md) |

A module this toolchain writes names its regions in a section table, so the tools that read a module
built any other way read one of these too — listing sections or disassembling a range needs no extra
step.

## Packaging and metadata

| Command | What it does | More |
|---|---|---|
| `param` | Reads and repairs `sce_sys/param.json`, and lists the kinds of title. | [The param.json fields](param-json.md) |
| `modules` | Checks that every module an application has to carry travels with it, and gathers the missing ones. | [Modules and libraries](modules.md) |
| `sysver` | Settles the system version an application records against the modules it ships. | [Firmware](firmware.md) |
| `retarget` | Rewrites a module's recorded version so one built for a newer system loads on an older one. | [Firmware](firmware.md) |

## Content

| Command | What it does | More |
|---|---|---|
| `gnf` | Turns a PNG, TGA or BMP into a texture the graphics processor samples; also reports one. | [Graphics on the GPU](graphics-gpu.md) |
| `vag` | Converts a 16-bit PCM WAV to compact sound-effect audio, and back. | [Audio](audio.md) |
| `sceassets` | Walks a `sce_sys` folder and writes a DX10-header BC7 `.dds` next to each `icon*.png` and `pic*.png`, so the launch panel and store art render from the DDS the loader accepts. Run automatically by `build-app.ps1`. | [Build pipeline](build-pipeline.md) |

## Bindings

| Command | What it does | More |
|---|---|---|
| the generator's binding mode (no verb) | Turns the SDK headers into response files describing a header-to-C# run, from the catalog named by `--modules` (default `modules.json` next to the tool). | [Bindings](bindings.md) |

Run `sharpprospero-bindgen --help` for the command list, or `<command> --help` for one command's options.
