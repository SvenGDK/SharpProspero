// Prospero Vibrate - Haptics that move You.

using SharpProspero.Interop.Pad;
using SharpProspero.Storage;
using System;

namespace SampleApp.Patterns;

/// <summary>User-tweakable settings for the app: drive mode, master intensity, motor link, mic weakening.</summary>
public sealed class AppSettings
{
    /// <summary>
    /// The drive-mode preset the pad service uses. The earlier-generation curve is the default because
    /// it drives every attached controller family; the current-generation curve is left as an option
    /// but is only meaningful on controllers with the newer actuator hardware.
    /// </summary>
    public ScePadVibrationMode DriveMode { get; set; } = ScePadVibrationMode.Compatible;

    /// <summary>
    /// A 0-100 percentage applied to every level before it reaches the motors. 100 leaves the pattern
    /// unchanged; lower values ease the entire session without editing patterns individually.
    /// </summary>
    public int MasterIntensityPercent { get; set; } = 100;

    /// <summary>When true, the live tab moves both sliders together.</summary>
    public bool LinkMotors { get; set; }

    /// <summary>Whether to weaken vibration and trigger effects while the built-in microphone is in use.</summary>
    public bool WeakenWhileMicInUse { get; set; }

    /// <summary>The default seconds a timer-run pattern lasts before it stops.</summary>
    public int DefaultTimerSeconds { get; set; } = 10;

    /// <summary>Returns the strength scale to apply to a pattern level, from 0 to 1.</summary>
    public float Strength => Math.Clamp(MasterIntensityPercent, 0, 100) / 100f;

    /// <summary>Turns the settings into a JSON value.</summary>
    public JsonValue ToJson()
    {
        JsonValue root = JsonValue.NewObject();
        root["driveMode"] = (int)DriveMode;
        root["masterIntensityPercent"] = MasterIntensityPercent;
        root["linkMotors"] = LinkMotors;
        root["weakenWhileMicInUse"] = WeakenWhileMicInUse;
        root["defaultTimerSeconds"] = DefaultTimerSeconds;
        return root;
    }

    /// <summary>Rebuilds settings from JSON; missing keys keep their defaults.</summary>
    public static AppSettings FromJson(JsonValue value)
    {
        var settings = new AppSettings();
        if (value.Type != JsonType.Object)
            return settings;

        int mode = value.GetInt("driveMode", (int)ScePadVibrationMode.Compatible);
        settings.DriveMode = mode == (int)ScePadVibrationMode.Advanced
            ? ScePadVibrationMode.Advanced
            : ScePadVibrationMode.Compatible;
        settings.MasterIntensityPercent = Math.Clamp(value.GetInt("masterIntensityPercent", 100), 0, 100);
        settings.LinkMotors = value.GetBool("linkMotors");
        settings.WeakenWhileMicInUse = value.GetBool("weakenWhileMicInUse");
        settings.DefaultTimerSeconds = Math.Clamp(value.GetInt("defaultTimerSeconds", 10), 1, 3600);
        return settings;
    }
}
