// ProsperoVibrate.Tests

using SampleApp.Patterns;
using SharpProspero.Input;
using SharpProspero.Storage;
using System.Collections.Generic;
using Xunit;

namespace ProsperoVibrate.Tests;

public sealed class PresetCatalogTests
{
    [Fact]
    public void AllPresets_HaveNameDescriptionAndSteps()
    {
        Assert.NotEmpty(PresetCatalog.All);
        foreach (VibrationPreset preset in PresetCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(preset.Name), $"preset has empty name");
            Assert.False(string.IsNullOrWhiteSpace(preset.Description), $"'{preset.Name}' has empty description");
            Assert.NotEmpty(preset.Steps);
            foreach (VibrationStep step in preset.Steps)
                Assert.True(step.DurationSeconds > 0f, $"'{preset.Name}' holds a zero-length step");
        }
    }

    [Fact]
    public void AllPresets_HaveUniqueNames()
    {
        var seen = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        foreach (VibrationPreset preset in PresetCatalog.All)
            Assert.True(seen.Add(preset.Name), $"'{preset.Name}' is not unique");
    }

    [Fact]
    public void LoopingPresets_TotalSecondsReportsZero()
    {
        foreach (VibrationPreset preset in PresetCatalog.All)
        {
            if (!preset.Loop)
                continue;
            Assert.Equal(0f, preset.TotalSeconds);
        }
    }

    [Fact]
    public void DriveModeTest_IsAShortNonLoopingRampWithRest()
    {
        VibrationPreset test = PresetCatalog.DriveModeTest();
        Assert.False(test.Loop);
        Assert.Equal(4, test.Steps.Count);
        Assert.True(test.Steps[0].Fade);
        Assert.False(test.Steps[1].Fade);
        Assert.True(test.Steps[2].Fade);
        Assert.True(test.Steps[3].Levels.IsZero);
        Assert.InRange(test.TotalSeconds, 1.0f, 1.5f);
    }

    [Fact]
    public void RumbleWarmup_RampsFromSilenceToFull()
    {
        VibrationPreset warmup = PresetCatalog.RumbleWarmup();
        Assert.False(warmup.Loop);
        Assert.Single(warmup.Steps);
        VibrationStep step = warmup.Steps[0];
        Assert.True(step.Fade);
        Assert.Equal(255, step.Levels.LargeMotor);
        Assert.Equal(255, step.Levels.SmallMotor);
        Assert.Equal(2.0f, step.DurationSeconds);
    }

    [Fact]
    public void DistressSos_HasNineHitsPerCycle()
    {
        VibrationPreset sos = PresetCatalog.DistressSos();
        int hits = 0;
        foreach (VibrationStep step in sos.Steps)
        {
            if (!step.Levels.IsZero)
                hits++;
        }
        Assert.Equal(9, hits);
    }

    [Fact]
    public void Heartbeat_TotalIsUnderOneSecondPerCycle()
    {
        VibrationPreset hb = PresetCatalog.Heartbeat();
        Assert.True(hb.Loop);
        float sum = 0f;
        foreach (VibrationStep step in hb.Steps)
            sum += step.DurationSeconds;
        Assert.InRange(sum, 0.9f, 1.1f);
    }
}

public sealed class VibrationPresetJsonTests
{
    [Fact]
    public void RoundTrip_PreservesNameLoopSteps()
    {
        VibrationPreset original = VibrationPreset.Create(
            "My Test Pattern",
            "Round-trip test.",
            [
                VibrationStep.Hold(new VibrationLevels(200, 100), 0.25f),
                VibrationStep.Rest(0.10f),
                VibrationStep.FadeTo(new VibrationLevels(0, 240), 0.50f),
            ],
            loop: true);

        JsonValue json = original.ToJson();
        string text = json.Write(indented: true);

        VibrationPreset restored = VibrationPreset.FromJson(JsonValue.Parse(text));

        Assert.Equal(original.Name, restored.Name);
        Assert.Equal(original.Description, restored.Description);
        Assert.Equal(original.Loop, restored.Loop);
        Assert.Equal(original.Steps.Count, restored.Steps.Count);
        for (int i = 0; i < original.Steps.Count; i++)
        {
            Assert.Equal(original.Steps[i].Levels, restored.Steps[i].Levels);
            Assert.Equal(original.Steps[i].DurationSeconds, restored.Steps[i].DurationSeconds, precision: 4);
            Assert.Equal(original.Steps[i].Fade, restored.Steps[i].Fade);
        }
    }

    [Fact]
    public void FromJson_RejectsZeroDurationStep()
    {
        JsonValue root = JsonValue.NewObject();
        root["name"] = "bad";
        root["loop"] = false;
        JsonValue steps = JsonValue.NewArray();
        JsonValue step = JsonValue.NewObject();
        step["large"] = 100;
        step["small"] = 100;
        step["seconds"] = 0.0;
        step["fade"] = false;
        steps.Add(step);
        root["steps"] = steps;

        Assert.Throws<System.ArgumentException>(() => VibrationPreset.FromJson(root));
    }

    [Fact]
    public void FromJson_ClampsMotorLevelsToByteRange()
    {
        JsonValue root = JsonValue.NewObject();
        root["name"] = "clamp";
        root["loop"] = false;
        JsonValue steps = JsonValue.NewArray();
        JsonValue step = JsonValue.NewObject();
        step["large"] = 999;
        step["small"] = -5;
        step["seconds"] = 0.5;
        step["fade"] = true;
        steps.Add(step);
        root["steps"] = steps;

        VibrationPreset preset = VibrationPreset.FromJson(root);
        Assert.Equal(255, preset.Steps[0].Levels.LargeMotor);
        Assert.Equal(0, preset.Steps[0].Levels.SmallMotor);
        Assert.True(preset.Steps[0].Fade);
    }
}
