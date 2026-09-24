# Samples

Ready-to-build sample projects, one for each kind. Copy the folder from `samples/` into your own
workspace, adjust the identity fields in `sce_sys/param.json`, and build with the shared pipeline.
Full documentation is in [docs/app-samples.md](../docs/app-samples.md) and
[docs/payload-samples.md](../docs/payload-samples.md).

## The samples

| Sample | Creates |
|---|---|
| `prospero-app` | A frame-loop application that draws to the screen and reads the controller. |
| `prospero-game` | A real-time game paced by the frame time: a paddle and a ball, a score, and a frame-rate overlay. |
| `prospero-ui` | An application built from the interface toolkit (labels, buttons, sliders, pickers). |
| `prospero-launcher` | A carousel that starts the chosen title, for a homebrew launcher front end. |
| `prospero-filemanager` | A file browser: walks the file system with the controller, opening folders. |
| `prospero-tool` | A toolbox application that shows a checksum, the console name and the network status. |
| `prospero-media` | A media player that plays a bundled file, drawing the video and pacing to the audio. |
| `prospero-server` | A network service that serves an HTTP control panel and a JSON status endpoint. |
| `prospero-input` | An input tester that draws the live controller, keyboard and mouse state each frame. |
| `prospero-vibrate` | A haptics studio: live motor control, a preset library, a custom-pattern editor, and timed play. |
| `prospero-scene` | A scrolling 2D scene: a camera that follows a sprite, a tile map with collision, and a particle burst. |
| `prospero-synth` | An audio synthesizer that generates and mixes tones and streams them to the output. |
| `prospero-savedata` | A save browser that mounts a save, reads a counter, increments it, and writes it back. |
| `prospero-dialog` | A menu that opens the system message, on-screen keyboard and error dialogs and pumps them to completion. |
| `prospero-dashboard` | A tabbed read-out of system, user, network, memory and firmware facts. |
| `prospero-3d` | A spinning, lit cube rendered on the graphics processor with the built-in mesh shaders. |
| `prospero-payload-httpd` | A payload web service that answers requests with a status page. |
| `prospero-payload-unjail` | A daemon payload that listens on a TCP port and widens the filesystem view of an application module on request. |
| `prospero-prx` | A relocatable library module (`.prx`) that exports functions for another module. |

## Start from a sample

Copy the sample folder to your own workspace and rename it:

```
cp -r <sdk>/samples/prospero-app MyGame
cd MyGame
```

Then edit `sce_sys/param.json` to set the display title and identifiers. The full field reference
is in [docs/param-json.md](../docs/param-json.md); the fields to change first are:

- `titleId` — nine characters, four letters then five digits (e.g. `PPSA99099`).
- `contentId` — the full 36-character content id. Carries the title id in its middle segment.
- `contentVersion`, `masterVersion` — the version strings.
- `localizedParameters.en-US.titleName` — the display name.

Replace `sce_sys/icon0.png` with your own icon. The library sample (`prospero-prx`) needs no
`sce_sys` metadata; it takes only an assembly name.

## Build it

Point the environment at the SDK once, then build with `build-app.ps1`:

```
setx SHARPPROSPERO_ROOT "<sdk>"
pwsh $SHARPPROSPERO_ROOT/build/build-app.ps1 -ProjectPath MyGame/SampleApp.csproj
```

`build-app.ps1` runs the shared pipeline: publish, link, and pack (an application) or leave the
built `.prx` in a folder (a library). Run the SDK's `doctor.ps1` first to confirm the toolchain
and paths.

## Build a payload sample

Payload samples build with the `-Payload` switch:

```
pwsh $SHARPPROSPERO_ROOT/build/build-app.ps1 -ProjectPath <sdk>/samples/prospero-payload-httpd/SampleApp.csproj -Payload -Output Folder
```

The output is a single `.elf` under the sample's `out/` folder. Send it to a listening loader —
see [docs/payload-deploy.md](../docs/payload-deploy.md).
