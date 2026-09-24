---
title: Samples
parent: Application Modules
nav_order: 12
---

# Samples

Ready-to-build starting points for an application module. Each is a project directory under
`samples/` in the SDK. Copy the folder into your own workspace, adjust the identity fields in
`sce_sys/param.json`, and build.

## The samples

| Sample | Creates | Start here for |
|---|---|---|
| `prospero-app` | A frame-loop application that draws to the screen and reads the controller. | A demo, or any application that draws its own screen. |
| `prospero-game` | A real-time game paced by the frame time: a paddle and a ball, a score, and a frame-rate overlay. | A game or anything with delta-timed movement, physics, and a live score. |
| `prospero-ui` | An application built from the interface toolkit (labels, buttons, sliders, steppers, carousels, option pickers). | A menu-driven application, a settings screen, a launcher. |
| `prospero-launcher` | An app launcher: a carousel of entries that launches the chosen title id. | A homebrew launcher or a front-end that starts other applications. |
| `prospero-filemanager` | A file browser that walks the file system with the controller, opening folders. | A file explorer, a save-data browser, a content picker. |
| `prospero-tool` | A toolbox application that shows a checksum, the console name, and the network status. | A system utility or toolbox that uses the SDK's tool surfaces. |
| `prospero-media` | A media player that plays a bundled file, drawing the video and pacing the loop to the decoded audio. | A video or music player, or anything that plays a media file. |
| `prospero-server` | A network service that serves an HTTP control panel and a JSON status endpoint from the frame loop. | A control panel, a file browser, or any service reached over the network. |
| `prospero-input` | An input tester that draws the live controller, keyboard, and mouse state each frame. | A hardware test, a controller-heavy application, or learning the input API. |
| `prospero-vibrate` | A haptics studio with Live, Presets, Custom, Timer and Settings tabs: direct motor control, a preset library, an eight-step custom-pattern editor, timed play, and a drive-mode picker. Persists to JSON under `/data/prospero-vibrate/`. | A rumble tester, a signal-feedback tool, or anywhere you need programmable vibration on the controller. |
| `prospero-scene` | A scrolling 2D scene: a camera that follows a sprite, a tile map with collision, and a particle burst. | A 2D game or a map viewer with a moving camera. |
| `prospero-synth` | An audio synthesizer that generates and mixes tones and streams them to the output. | A soundboard, an instrument, or anything that makes sound rather than plays a file. |
| `prospero-savedata` | A save browser that mounts a save, reads a counter, increments it, and writes it back. | A save manager or a save editor. |
| `prospero-dialog` | A menu that opens the system message, on-screen keyboard, and error dialogs and pumps them to completion. | Wiring the system overlays into an application. |
| `prospero-dashboard` | A tabbed read-out of system, user, network, memory, and firmware facts, built from the interface toolkit. | A diagnostics or monitoring application. |
| `prospero-3d` | A spinning, lit cube rendered on the graphics processor with the built-in mesh shaders. | A 3D application: a model viewer, a scene, or a game with real geometry. |
| `prospero-prx` | A relocatable library module (`.prx`) that exports functions for another module to load. | A shared library you load at run time from an application. |

## Start from a sample

Copy the sample folder to a new location outside `samples/`, then adjust its identity:

```
cp -r $SHARPPROSPERO_ROOT/samples/prospero-app MyGame
cd MyGame
```

Edit `sce_sys/param.json`:

- `titleId` — nine characters, four letters then five digits (e.g. `PPSA99099`).
- `contentId` — the full 36-character content id. The middle segment carries the title id.
- `contentVersion`, `masterVersion` — the version strings.
- `localizedParameters.en-US.titleName` — the display name.

See [The sce_sys/param.json fields](param-json.md) for every metadata field. Replace the icon
under `sce_sys/icon0.png` with your own.

## Build a sample

Point the environment at the SDK once, then build with `build-app.ps1`:

```
setx SHARPPROSPERO_ROOT "<sdk>"     # or export on Linux
pwsh $SHARPPROSPERO_ROOT/build/build-app.ps1 -ProjectPath MyGame/SampleApp.csproj
```

An application module writes an installable `*.pkg` (or a folder with `-Output Folder`); a library
writes its `<name>.prx`, which you copy into an application's `sce_module` folder and load by name
— see [Modules and libraries](modules.md).

## What each sample contains

- **Applications** (`prospero-app`, `prospero-game`, `prospero-ui`, `prospero-launcher`,
  `prospero-filemanager`, `prospero-tool`, `prospero-media`, `prospero-server`, `prospero-input`,
  `prospero-vibrate`, `prospero-scene`, `prospero-synth`, `prospero-savedata`, `prospero-dialog`,
  `prospero-dashboard`, `prospero-3d`): `Program.cs`, the `sce_sys` package metadata
  (`param.json`, `icon0.png`), and a `SampleApp.csproj`.
- **Library** (`prospero-prx`): `Library.cs` with `[UnmanagedCallersOnly]` exported functions, the
  matching `<ProsperoExportSymbol>` entries in the project file. Add a function and its export
  symbol for each entry point.

For the payload samples, see [Payloads → Samples](payload-samples.md).
