// ProsperoVibrate.Tests

using SampleApp;
using SampleApp.Patterns;
using SharpProspero.Input;
using System.Collections.Generic;
using Xunit;

namespace ProsperoVibrate.Tests;

public sealed class HapticsControllerScaleTests
{
    [Fact]
    public void ScaleSteps_Full_ReturnsOriginalReference()
    {
        IReadOnlyList<VibrationStep> original =
        [
            VibrationStep.Hold(new VibrationLevels(200, 100), 0.5f),
            VibrationStep.FadeTo(new VibrationLevels(0, 240), 0.75f),
        ];
        IReadOnlyList<VibrationStep> scaled = HapticsController.ScaleSteps(original, 1f);
        Assert.Same(original, scaled);
    }

    [Fact]
    public void ScaleSteps_ClampsStrengthToUnitRange()
    {
        IReadOnlyList<VibrationStep> original =
        [
            VibrationStep.Hold(new VibrationLevels(200, 100), 0.5f),
        ];
        IReadOnlyList<VibrationStep> below = HapticsController.ScaleSteps(original, -1f);
        Assert.Equal(0, below[0].Levels.LargeMotor);
        Assert.Equal(0, below[0].Levels.SmallMotor);

        IReadOnlyList<VibrationStep> above = HapticsController.ScaleSteps(original, 2f);
        Assert.Equal(200, above[0].Levels.LargeMotor);
        Assert.Equal(100, above[0].Levels.SmallMotor);
    }

    [Fact]
    public void ScaleSteps_ReducesEveryLevelProportionally()
    {
        IReadOnlyList<VibrationStep> original =
        [
            VibrationStep.Hold(new VibrationLevels(200, 100), 0.5f),
            VibrationStep.FadeTo(new VibrationLevels(0, 200), 0.75f),
        ];
        IReadOnlyList<VibrationStep> half = HapticsController.ScaleSteps(original, 0.5f);
        Assert.Equal(2, half.Count);
        Assert.Equal(100, half[0].Levels.LargeMotor);
        Assert.Equal(50, half[0].Levels.SmallMotor);
        Assert.Equal(0, half[1].Levels.LargeMotor);
        Assert.Equal(100, half[1].Levels.SmallMotor);
    }

    [Fact]
    public void ScaleSteps_KeepsDurationAndFadeFlags()
    {
        IReadOnlyList<VibrationStep> original =
        [
            VibrationStep.Hold(new VibrationLevels(200, 100), 0.25f),
            VibrationStep.FadeTo(new VibrationLevels(50, 50), 1.5f),
        ];
        IReadOnlyList<VibrationStep> scaled = HapticsController.ScaleSteps(original, 0.4f);
        Assert.Equal(0.25f, scaled[0].DurationSeconds);
        Assert.False(scaled[0].Fade);
        Assert.Equal(1.5f, scaled[1].DurationSeconds);
        Assert.True(scaled[1].Fade);
    }
}

public sealed class PatternStoragePathTests
{
    [Fact]
    public void Sanitize_ReplacesReservedCharacters()
    {
        Assert.Equal("____", PatternStorage.Sanitize("////"));
        Assert.Equal("a_b_c", PatternStorage.Sanitize("a/b\\c"));
        Assert.Equal("hello", PatternStorage.Sanitize("hello"));
        // Spaces are legal in the on-device filesystem and are kept verbatim.
        Assert.Equal("with space", PatternStorage.Sanitize("with space"));
        Assert.Equal("path_traversal.._", PatternStorage.Sanitize("path/traversal../"));
    }

    [Fact]
    public void Sanitize_ReplacesControlCharactersWithUnderscore()
    {
        string dirty = "clean\t\x01name";
        string sanitized = PatternStorage.Sanitize(dirty);
        Assert.Equal("clean__name", sanitized);
    }

    [Fact]
    public void PathFor_UsesSanitizedName()
    {
        Assert.Equal("/data/prospero-vibrate/patterns/My_Pattern.json", PatternStorage.PathFor("My/Pattern"));
    }

    [Fact]
    public void Sanitize_TruncatesToMaxNameLength()
    {
        string huge = new string('a', 500_000);
        string sanitized = PatternStorage.Sanitize(huge);
        Assert.Equal(PatternStorage.MaxNameLength, sanitized.Length);
        Assert.All(sanitized, c => Assert.Equal('a', c));
    }

    [Fact]
    public void Sanitize_KeepsShortNamesIntact()
    {
        string keep = new string('b', 100);
        Assert.Equal(keep, PatternStorage.Sanitize(keep));
    }
}

public sealed class VibrationPresetLengthCapTests
{
    [Fact]
    public void FromJson_CapsNameAndDescriptionLength()
    {
        var root = SharpProspero.Storage.JsonValue.NewObject();
        root["name"] = new string('n', 5_000);
        root["description"] = new string('d', 10_000);
        root["loop"] = false;
        var steps = SharpProspero.Storage.JsonValue.NewArray();
        var step = SharpProspero.Storage.JsonValue.NewObject();
        step["large"] = 10;
        step["small"] = 10;
        step["seconds"] = 0.5;
        step["fade"] = false;
        steps.Add(step);
        root["steps"] = steps;

        VibrationPreset preset = VibrationPreset.FromJson(root);
        Assert.Equal(PatternStorage.MaxNameLength, preset.Name.Length);
        Assert.Equal(VibrationPreset.MaxDescriptionLength, preset.Description.Length);
    }
}

public sealed class AppSettingsTests
{
    [Fact]
    public void RoundTrip_PreservesEveryField()
    {
        var settings = new AppSettings
        {
            DriveMode = SharpProspero.Interop.Pad.ScePadVibrationMode.Compatible,
            MasterIntensityPercent = 60,
            LinkMotors = true,
            WeakenWhileMicInUse = true,
            DefaultTimerSeconds = 42,
        };

        var restored = AppSettings.FromJson(settings.ToJson());
        Assert.Equal(settings.DriveMode, restored.DriveMode);
        Assert.Equal(settings.MasterIntensityPercent, restored.MasterIntensityPercent);
        Assert.Equal(settings.LinkMotors, restored.LinkMotors);
        Assert.Equal(settings.WeakenWhileMicInUse, restored.WeakenWhileMicInUse);
        Assert.Equal(settings.DefaultTimerSeconds, restored.DefaultTimerSeconds);
    }

    [Fact]
    public void FromJson_ClampsOutOfRangeValuesToDefaults()
    {
        var root = SharpProspero.Storage.JsonValue.NewObject();
        root["driveMode"] = 999;
        root["masterIntensityPercent"] = 500;
        root["defaultTimerSeconds"] = 100000;
        AppSettings settings = AppSettings.FromJson(root);
        Assert.Equal(SharpProspero.Interop.Pad.ScePadVibrationMode.Compatible, settings.DriveMode);
        Assert.Equal(100, settings.MasterIntensityPercent);
        Assert.Equal(3600, settings.DefaultTimerSeconds);
    }

    [Fact]
    public void AppSettings_DriveModeDefault_IsCompatible()
    {
        var fresh = new AppSettings();
        Assert.Equal(SharpProspero.Interop.Pad.ScePadVibrationMode.Compatible, fresh.DriveMode);
    }

    [Fact]
    public void Strength_ScalesMasterIntensity()
    {
        var settings = new AppSettings { MasterIntensityPercent = 25 };
        Assert.Equal(0.25f, settings.Strength);
    }
}
