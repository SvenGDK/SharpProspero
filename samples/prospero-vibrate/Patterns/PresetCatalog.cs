// Prospero Vibrate - Haptics that move You.

using SharpProspero.Input;
using System.Collections.Generic;

namespace SampleApp.Patterns;

/// <summary>The curated set of built-in vibration patterns the app ships with.</summary>
public static class PresetCatalog
{
    private static VibrationLevels L(byte large, byte small) => new(large, small);

    /// <summary>Every built-in preset, in the order they are shown to the user.</summary>
    public static IReadOnlyList<VibrationPreset> All { get; } =
    [
        Heartbeat(),
        DoubleTap(),
        Alarm(),
        DistressSos(),
        DrumRoll(),
        RumbleWarmup(),
        RumbleCooldown(),
        Earthquake(),
        Gunfire(),
        Ratchet(),
        Chirp(),
        MetronomeSlow(),
        MetronomeFast(),
        ThreePulseBurst(),
        LowGrowl(),
        HighBuzz(),
        WaveIn(),
        WaveOut(),
    ];

    /// <summary>
    /// A short reference pattern used by the Settings tab so the user can feel the current drive mode
    /// on demand. It ramps both motors from silence to a strong hold and back down again in about a
    /// second, which is enough to sense the difference between the two modes without dragging on.
    /// </summary>
    public static VibrationPreset DriveModeTest() => VibrationPreset.Create(
        "Drive-mode test",
        "A ramp up and back down that lets the user feel the current drive mode.",
        [
            VibrationStep.FadeTo(L(220, 180), 0.35f),
            VibrationStep.Hold(L(220, 180), 0.30f),
            VibrationStep.FadeTo(L(0, 0), 0.40f),
            VibrationStep.Rest(0.15f),
        ],
        loop: false);

    /// <summary>A steady, unhurried two-thump rhythm at chest-monitor speed.</summary>
    public static VibrationPreset Heartbeat() => VibrationPreset.Create(
        "Heartbeat",
        "A slow two-thump rhythm at rest.",
        [
            VibrationStep.Hold(L(200, 0), 0.09f),
            VibrationStep.Rest(0.08f),
            VibrationStep.Hold(L(140, 0), 0.09f),
            VibrationStep.Rest(0.74f),
        ],
        loop: true);

    /// <summary>Two quick taps, then a pause. Useful as a notification cue.</summary>
    public static VibrationPreset DoubleTap() => VibrationPreset.Create(
        "Double Tap",
        "Two quick taps followed by silence.",
        [
            VibrationStep.Hold(L(180, 180), 0.06f),
            VibrationStep.Rest(0.07f),
            VibrationStep.Hold(L(180, 180), 0.06f),
            VibrationStep.Rest(0.81f),
        ],
        loop: true);

    /// <summary>An urgent on/off alarm at 4 hertz.</summary>
    public static VibrationPreset Alarm() => VibrationPreset.Create(
        "Alarm",
        "Steady on/off at four hertz.",
        [
            VibrationStep.Hold(L(220, 220), 0.125f),
            VibrationStep.Rest(0.125f),
        ],
        loop: true);

    /// <summary>Morse SOS: three short, three long, three short, then a pause.</summary>
    public static VibrationPreset DistressSos() => VibrationPreset.Create(
        "Distress SOS",
        "Morse code for SOS at signal speed.",
        [
            VibrationStep.Hold(L(220, 200), 0.12f), VibrationStep.Rest(0.12f),
            VibrationStep.Hold(L(220, 200), 0.12f), VibrationStep.Rest(0.12f),
            VibrationStep.Hold(L(220, 200), 0.12f), VibrationStep.Rest(0.36f),

            VibrationStep.Hold(L(220, 200), 0.36f), VibrationStep.Rest(0.12f),
            VibrationStep.Hold(L(220, 200), 0.36f), VibrationStep.Rest(0.12f),
            VibrationStep.Hold(L(220, 200), 0.36f), VibrationStep.Rest(0.36f),

            VibrationStep.Hold(L(220, 200), 0.12f), VibrationStep.Rest(0.12f),
            VibrationStep.Hold(L(220, 200), 0.12f), VibrationStep.Rest(0.12f),
            VibrationStep.Hold(L(220, 200), 0.12f), VibrationStep.Rest(1.20f),
        ],
        loop: true);

    /// <summary>A short, dense flurry of hits.</summary>
    public static VibrationPreset DrumRoll() => VibrationPreset.Create(
        "Drum Roll",
        "A dense flurry of quick hits.",
        [
            VibrationStep.Hold(L(180, 90), 0.03f), VibrationStep.Rest(0.03f),
            VibrationStep.Hold(L(180, 90), 0.03f), VibrationStep.Rest(0.03f),
            VibrationStep.Hold(L(180, 90), 0.03f), VibrationStep.Rest(0.03f),
            VibrationStep.Hold(L(180, 90), 0.03f), VibrationStep.Rest(0.03f),
            VibrationStep.Hold(L(180, 90), 0.03f), VibrationStep.Rest(0.03f),
            VibrationStep.Hold(L(200, 200), 0.20f), VibrationStep.Rest(0.50f),
        ],
        loop: true);

    /// <summary>A slow, smooth ramp from silence to full - a warm-up.</summary>
    public static VibrationPreset RumbleWarmup() => VibrationPreset.Create(
        "Rumble Warmup",
        "Silence to full over two seconds.",
        [ VibrationStep.FadeTo(L(255, 255), 2.0f) ],
        loop: false);

    /// <summary>A slow, smooth ramp from full to silence - a cooldown.</summary>
    public static VibrationPreset RumbleCooldown() => VibrationPreset.Create(
        "Rumble Cooldown",
        "Full to silence over two seconds.",
        [
            VibrationStep.Hold(L(255, 255), 0.05f),
            VibrationStep.FadeTo(L(0, 0), 2.0f),
        ],
        loop: false);

    /// <summary>Uneven, chunky low-frequency rumble - a distant tremor.</summary>
    public static VibrationPreset Earthquake() => VibrationPreset.Create(
        "Earthquake",
        "Uneven low-frequency rumble.",
        [
            VibrationStep.FadeTo(L(200, 40), 0.35f),
            VibrationStep.FadeTo(L(80,  20), 0.28f),
            VibrationStep.FadeTo(L(240, 60), 0.32f),
            VibrationStep.FadeTo(L(120, 30), 0.24f),
            VibrationStep.FadeTo(L(220, 50), 0.40f),
            VibrationStep.FadeTo(L(60,  10), 0.20f),
        ],
        loop: true);

    /// <summary>Loud, snappy bursts with silence between them - firearm feedback.</summary>
    public static VibrationPreset Gunfire() => VibrationPreset.Create(
        "Gunfire",
        "Sharp bursts with a return kick.",
        [
            VibrationStep.Hold(L(255, 255), 0.05f),
            VibrationStep.FadeTo(L(0, 0),   0.10f),
            VibrationStep.Rest(0.35f),
        ],
        loop: true);

    /// <summary>A stepped click - one hit, wait, repeat - like turning a lever.</summary>
    public static VibrationPreset Ratchet() => VibrationPreset.Create(
        "Ratchet",
        "One firm click every two hundred milliseconds.",
        [
            VibrationStep.Hold(L(120, 200), 0.05f),
            VibrationStep.Rest(0.20f),
        ],
        loop: true);

    /// <summary>A short, high-motor chirp - the way small notifications feel.</summary>
    public static VibrationPreset Chirp() => VibrationPreset.Create(
        "Chirp",
        "A short high-motor chirp.",
        [
            VibrationStep.Hold(L(0, 220), 0.06f),
            VibrationStep.Rest(0.40f),
        ],
        loop: true);

    /// <summary>A metronome tick every half second.</summary>
    public static VibrationPreset MetronomeSlow() => VibrationPreset.Create(
        "Metronome (slow)",
        "One firm tick every half second.",
        [
            VibrationStep.Hold(L(180, 100), 0.04f),
            VibrationStep.Rest(0.46f),
        ],
        loop: true);

    /// <summary>A metronome tick four times a second.</summary>
    public static VibrationPreset MetronomeFast() => VibrationPreset.Create(
        "Metronome (fast)",
        "A tick four times a second.",
        [
            VibrationStep.Hold(L(160, 90), 0.03f),
            VibrationStep.Rest(0.22f),
        ],
        loop: true);

    /// <summary>Three quick pulses of rising strength, then a pause.</summary>
    public static VibrationPreset ThreePulseBurst() => VibrationPreset.Create(
        "Three-Pulse Burst",
        "Three rising pulses with a rest.",
        [
            VibrationStep.Hold(L(80,  80),  0.10f), VibrationStep.Rest(0.08f),
            VibrationStep.Hold(L(160, 160), 0.10f), VibrationStep.Rest(0.08f),
            VibrationStep.Hold(L(240, 240), 0.14f), VibrationStep.Rest(0.60f),
        ],
        loop: true);

    /// <summary>Continuous low-motor pressure, held steady.</summary>
    public static VibrationPreset LowGrowl() => VibrationPreset.Create(
        "Low Growl",
        "Continuous large-motor pressure.",
        [
            VibrationStep.FadeTo(L(180, 0), 0.30f),
            VibrationStep.Hold(L(180, 0), 1.20f),
            VibrationStep.FadeTo(L(220, 0), 0.30f),
            VibrationStep.Hold(L(220, 0), 1.20f),
        ],
        loop: true);

    /// <summary>Continuous high-motor buzz, held steady.</summary>
    public static VibrationPreset HighBuzz() => VibrationPreset.Create(
        "High Buzz",
        "Continuous small-motor buzz.",
        [
            VibrationStep.FadeTo(L(0, 200), 0.30f),
            VibrationStep.Hold(L(0, 200), 1.50f),
        ],
        loop: true);

    /// <summary>A soft, growing wave - motors ramp in over a second.</summary>
    public static VibrationPreset WaveIn() => VibrationPreset.Create(
        "Wave In",
        "Soft growth over a second.",
        [
            VibrationStep.FadeTo(L(200, 200), 1.0f),
            VibrationStep.Hold(L(200, 200), 0.30f),
            VibrationStep.FadeTo(L(0, 0), 0.30f),
            VibrationStep.Rest(0.40f),
        ],
        loop: true);

    /// <summary>A retreating wave - motors ramp out from a hit.</summary>
    public static VibrationPreset WaveOut() => VibrationPreset.Create(
        "Wave Out",
        "A hit and a slow fade.",
        [
            VibrationStep.Hold(L(240, 180), 0.15f),
            VibrationStep.FadeTo(L(0, 0), 1.2f),
            VibrationStep.Rest(0.30f),
        ],
        loop: true);
}
