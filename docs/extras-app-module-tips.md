---
title: Tips for application modules
parent: Extras
nav_order: 1
---

# Tips for application modules

Everyday recipes for building homebrew application modules. Each is a self-contained pattern the
SDK ships wrapper types for, so a module can pull it in without extra scaffolding.

## Load the modules a feature needs

Some services are not resident until loaded. Load them once at startup and dispose at shutdown;
loading an already-loaded module succeeds, so this is safe to repeat.

```csharp
using var pngEnc = SystemModule.Load(SystemModuleId.PngEnc);   // needed by PngEncoder
using var jpegEnc = SystemModule.Load(SystemModuleId.JpegEnc); // needed by JpegEncoder
using var font = SystemModule.Load(SystemModuleId.Font);       // needed by TrueTypeFont
using var fontFt = SystemModule.Load(SystemModuleId.FontFt);
```

`SystemModule.IsLoaded(id)` reports whether one is present. The drawing surface, controller, audio
out, kernel and system services are always available and need no load.

## Read the files bundled with your module

Assets you ship live under the package root `/app0`. Read them with the file APIs:

```csharp
byte[] level = FileSystem.ReadAllBytes("/app0/assets/level.bin");
using var logo = PngImage.Decode(FileSystem.ReadAllBytes("/app0/assets/logo.png"));
```

Writable storage is elsewhere (for example `/data`); the package root is read-only.

## Keep memory in bounds

The console's memory maps are limited, so cap the managed heap and avoid churn:

- Set `<ProsperoHeapHardLimitBytes>` in the project to the largest heap the module should use. The
  default is 256 MiB.
- Raise `<ProsperoHeapRegionRangeBytes>` alongside it — the unbroken address run the collector
  holds for its regions, 384 MiB by default, so keep it above the ceiling. Without a figure the
  collector would hold five times the ceiling, more than the console hands out, and refuses to
  start when it cannot get it. Give it a whole number of megabytes.
- `<ProsperoThreadStackBytes>` is the stack a runtime thread gets, 1 MiB by default; the console's
  own 64 KiB is too small for the collector's threads. It is read as a decimal count of bytes.
- Read usage at run time with `SharpProspero.Memory.HeapMonitor`.
- Draw into the pre-allocated back buffer each frame and reuse buffers rather than allocating in
  the frame loop. Pull GPU-visible buffers from `SharpProspero.Memory.DirectMemoryRegion`.

## Animate a value over time

`SharpProspero.Animation` moves a number from one value to another over a set time along an easing
curve, so a panel slides in, a bar fills, or a colour fades without hand-written per-frame maths. A
`Tween` holds no reference to what it drives, so the same one can move a position, an alpha, or a
colour channel.

```csharp
using SharpProspero.Animation;

var slideIn = new Tween(from: -200, to: 0, durationSeconds: 0.3f, Ease.OutCubic);

// each frame, in OnFrame:
int x = (int)slideIn.Update((float)context.DeltaSeconds);
panel.DrawAt(x, y);
if (slideIn.IsComplete) { /* settled */ }
```

`Ease` picks the curve — `Linear`, the quad/cubic/sine `In`/`Out`/`InOut` pairs, the springy
`OutBack`, or `OutBounce`. `TweenMode` decides the end: `Once` settles and reports `IsComplete`,
`Loop` repeats, `PingPong` runs out and back. For a one-off reading without a tween,
`Easing.Interpolate(from, to, t, ease)` gives the eased value at a fraction `t`.

## Log while developing

Attach a file sink at startup and read the log back after a run:

```csharp
Log.MinimumLevel = LogLevel.Debug;
Log.AddSink(FileLogSink.Open("/data/app.log"));
Log.AddSink(new ConsoleLogSink());   // also to the development console, if attached
Log.Information("started");
```

See [Diagnostics](diagnostics.md) for the full logging surface.

## Run across firmware versions

A module built with the SDK targets the earliest supported system and runs on later ones. Read the
running version, and resolve services by name so one build adapts instead of pinning an address:

```csharp
FirmwareVersion version = FirmwareSupport.Current;
FirmwareSupport.EnsureSupported();          // throws when the system is outside the supported range

FirmwareValidation? check = FirmwareSupport.Validate("Package installer");
if (check is null || !check.IsValid)
    ShowUnsupported(check?.ToString());     // names the exports this system does not provide
```

The string is the service name from `FirmwareRegistry.DynamicLibraries`; the registered names are
"Package installer" and "USB mass storage". Pass a `SystemLibraryDescriptor` to the other
`Validate` overload for a service resolved outside the registry.

See [Firmware compatibility](firmware.md).

## Deploy to the console

- Build a `*.pkg` and install it on a console in the mode that accepts unsigned packages, then
  launch it from the home screen.
- While iterating, build with `-Output Folder` to get `eboot.bin`, `sce_sys` and any `sce_module`
  together in one folder to copy directly or inspect with the `elf` tool.
- An installer treats a title already on the machine as present and declines to replace it, so give
  a build meant to sit beside the last one a title of its own:
  `pwsh build/build-app.ps1 -ProjectPath MyGame/MyGame.csproj -TitleId PPSA99098`. Only the
  gathered copy changes — `titleId` and the title inside `contentId` — and the project's own
  `param.json` is left alone. The id is four letters then five digits.

## Ship a library with your application

Build the library as a `.prx` (the `prospero-prx` sample), drop it in the application's
`sce_module` folder, and load it by name:

```csharp
using PrxModule lib = PrxModule.LoadFromPackage("mylib.prx");
nint doThing = lib.GetExport("myLibDoThing");
```

See [Modules and libraries](modules.md).

## Read the controller

Inside a `ProsperoApp`, the frame context already carries this frame's controller sample as a
`GamePadState`, with the previous one for edge detection. Read sticks and triggers as recentred
floats, and test buttons with `ScePadButton`:

```csharp
GamePadState pad = context.Input;
(float x, float y) = pad.LeftStick;              // -1..1, 0 at rest
if (context.Pressed(ScePadButton.Cross)) Jump(); // true only on the frame it goes down
```

Start from `prospero-input` for a full tester, and see [Input](input.md) for motion, touch, rumble,
the light bar, and named-action mapping.

## Drive the vibration motors

Reach for `GamePad.Vibration` before writing a per-frame pair by hand. It runs a frame-driven animator
on top of the controller service, keeps a change detector so a pair reaches the motors only on the
frames it changed, and covers a solid pair, a pulse, a blink, a ramp, and a queue of timed steps.

```csharp
Vibration v = gamePad.Vibration;
v.Sequence([
    VibrationStep.Hold(new VibrationLevels(200, 100), 0.15f),
    VibrationStep.Rest(0.10f),
    VibrationStep.FadeTo(new VibrationLevels(0, 240), 0.30f),
]);

// each frame in OnFrame:
v.Update((float)context.DeltaSeconds);
```

`v.Stop()` stops the motors and ends any animation; `v.SetDriveMode(mode)` picks between the full range
of the current controller generation and the earlier reduced range, and re-sends the current pair so a
mid-playback mode change reaches the motors on the same frame. `Vibration.WeakenWhileMicrophoneInUse`
weakens motors and trigger effects across every controller while the built-in microphone is in use.
Start from `prospero-vibrate` for a live tester, a preset library, a custom-pattern editor and timed
play.

## Let the analog stick drive the menu

Every screen built from the interface toolkit accepts the left analog stick as well as the d-pad.
`UiInput.From` and `UiRepeater` fold the stick into their held-direction tables, so a user who
prefers the stick lands on every focusable control the d-pad does. The threshold is 0.65 by default
(the third argument on `UiInput.From`, the `StickThreshold` property on `UiRepeater`) so a resting
hand at a slight tilt does not drift the focus around. See [Interface toolkit](ui.md) for the full
navigation surface.

## Make and mix sound

Generate tones with a `ToneGenerator`, layer them with an `AudioMixer`, and stream the mix to an
`AudioOutDevice`. Because writing a block blocks until it plays, run the mix loop on its own
thread. Start from `prospero-synth`, and see [Audio](audio.md) for decoding, encoding, and the
microphone.

## Save and load player data

Mount the user's save area, read and write files under the mount point, and let the `using` block
commit on unmount:

```csharp
using var saves = SaveDataManager.Open();
using MountedSave slot = saves.Mount("save0", readOnly: false);
string path = slot.MountPoint + "/state.json";
FileSystem.WriteAllText(path, json);
```

Start from `prospero-savedata`, and see [Save data](save-data.md).

## Show a system dialog

The on-screen dialogs are opened, then pumped to completion in the frame loop — one at a time, so
the loop never blocks:

```csharp
_dialog ??= MessageDialog.ShowMessage("Delete this save?", MessageDialogButtons.YesNo);
if (_dialog.Update() == MessageDialogState.Finished)
{
    if (_dialog.ChosenButton == MsgDialogButtonId.Ok) Delete();  // Ok is the Yes/first button
    _dialog.Dispose();
    _dialog = null;
}
```

Start from `prospero-dialog`, and see [Dialogs and overlays](dialogs.md).

## Do work without stalling the frame loop

Long work — decoding a large file, a network round-trip — must not run inside `OnFrame`. Hand it to
a `BackgroundOperation` or a `WorkQueue` and poll the result each frame, marshalling anything that
touches the screen back with a `Dispatcher`. See [Threading](threading.md).

## Shape a sound with a filter and an envelope

Raw tones sound harsh. Run them through a `BiquadFilter` to tame the tone, and multiply each voice
by an `AdsrEnvelope` so notes swell in and fade out instead of clicking. Both keep their state
between calls, so they work on a running stream.

```csharp
var lowpass = new BiquadFilter(BiquadType.LowPass, 48000, frequency: 1200);
var env = new AdsrEnvelope { Attack = 0.02f, Decay = 0.1f, Sustain = 0.6f, Release = 0.3f };
env.NoteOn();

// each block:
mixer.Mix(block);
lowpass.ProcessBlock(block);                 // soften everything above 1.2 kHz
float gain = env.Process(block.Length / 48000f);
for (int i = 0; i < block.Length; i++) block[i] = (short)(block[i] * gain);
```

See [Audio](audio.md) for the filter shapes and the envelope phases.

## Follow the player with a smooth camera

A camera that snaps to the player is jarring. `Vector2.SmoothDamp` eases toward a target and settles
without overshooting; keep its velocity in a field and pass it by reference each frame.

```csharp
Vector2 _cameraVelocity;   // survives between frames

camera.Position = Vector2.SmoothDamp(camera.Position, player.Position,
    ref _cameraVelocity, smoothTime: 0.25f, (float)context.DeltaSeconds);
```

`MathUtil.SmoothDamp` does the same for a single value, and `SmoothDampAngle` for a heading. See
[Numerics and vectors](numerics.md).

## Weight a random drop

For loot that is not evenly likely, a `WeightedTable<T>` gives each entry a weight and draws in
proportion. It draws through a `GameRandom`, so a seeded run repeats.

```csharp
var drops = new WeightedTable<string>()
    .Add("gold", 70)
    .Add("gem", 25)
    .Add("relic", 5);

string reward = drops.Pick(rng);   // "gold" about 70% of the time
```

## Cache decoded assets without unbounded growth

Decoding a texture or sound every time it is needed is wasteful; keeping every one forever runs the
heap out. An `LruCache<TKey, TValue>` keeps a fixed number of the most recently used and drops the
rest.

```csharp
var images = new LruCache<string, PngImage>(capacity: 32);
images.Evicted += (key, image) => image.Dispose();      // free the dropped one

PngImage icon = images.GetOrAdd(path, p => PngImage.Decode(FileSystem.ReadAllBytes(p)));
```

See [Memory](memory.md).

## Build a sprite sheet from separate images

Packing many small images into one texture cuts the number of draws and binds. `RectPacker` finds a
non-overlapping spot for each piece; copy the image in and record where it landed.

```csharp
using var atlas = new PixelBuffer(1024, 1024);
Surface sheet = atlas.AsSurface();
var packer = new RectPacker(1024, 1024);

foreach ((int id, Surface image) in sprites)
    if (packer.Insert(image.Width, image.Height, id) is { } r)
        sheet.Blit(image, r.X, r.Y);                  // remember (r.X, r.Y, r.Width, r.Height)
```

Turn the finished atlas into a texture file with the `gnf` command; see
[Building a texture file](graphics-gpu.md#building-a-texture-file).

## Store and read settings

For a handful of options, an `IniFile` is the least ceremony; for structured data reach for JSON.
Both live in `SharpProspero.Storage`. `IniFile` reads typed values with `GetString`, `GetInt` and
`GetBool`, and writes back with `Save`.

```csharp
var settings = IniFile.Load("/data/settings.ini");
int volume = settings.GetInt("audio", "volume", 80);
settings.Set("audio", "volume", 60);
settings.Save("/data/settings.ini");
```

See [Files and storage](storage.md) for JSON, CSV, tables, and versioned saves.

## Pack a custom binary format

When a file format needs fields that are not a whole number of bytes wide, `BitWriter` and
`BitReader` pack and unpack them most-significant bit first, so what one writes the other reads
straight back.

```csharp
var w = new BitWriter();
w.WriteBits(version, 4);
w.WriteBit(compressed);
w.WriteBits(length, 20);
byte[] header = w.ToArray();

var r = new BitReader(header);
uint ver = r.ReadBits(4);
bool zip = r.ReadBit();
uint len = r.ReadBits(20);
```

See [Buffers and encodings](buffers.md).

## Promote the application for extended access

The per-title credential set and sandbox keep the module inside `/app0` and its writable folder,
with the credential and capability values the console handed it. Add a button that asks a
companion payload to promote the application — see [Promoting an application](app-promotion.md)
for the complete pattern.

## General tips

- Keep `OnFrame` allocation-free: build strings and buffers once, reuse them each frame.
- Prefer the interface toolkit ([UI](ui.md)) over drawing menus by hand; it handles layout and focus.
- Use `Surface.Region` to draw a panel in its own local coordinates and clip to it.
- Verify a module's exports with `elf --file <module> --exports` before depending on them.
- Run `doctor.ps1` first on any new machine; it tells you exactly what is missing.
- Seed a `GameRandom` from a fixed number for a reproducible level or replay, and from
  `FromEntropy()` when you want a different run each time.
- Pool short-lived objects with `ObjectPool<T>` and roll a history with `RingBuffer<T>` rather than
  allocating inside the frame loop; see [Memory](memory.md).
- Reach for `MathUtil` before hand-writing arithmetic: `Clamp01`, `Remap`, `Lerp`, `WrapAngle` and
  `PingPong` cover most of what a frame update needs.
- Drive timing off `context.DeltaSeconds`, never a fixed step, so behaviour holds if a frame runs
  long; `FixedTimestep` gives physics a steady tick on top of a variable frame.
- Press `s` on any documentation page to search the whole site; every page names the namespace it
  covers.
- Pick the decoder that matches the asset: `PngImage.Decode`, `JpegImage.Decode`, `BmpImage.Decode`,
  `TgaImage.Decode` and `GifImage.Decode` all take the file bytes and return a disposable image.
- Keep a build reproducible: the same C# and toolchain version produce the same `eboot.bin`, so
  check the toolchain version into source control alongside the project.
