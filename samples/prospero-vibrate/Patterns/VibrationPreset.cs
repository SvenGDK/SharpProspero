// Prospero Vibrate - Haptics that move You.

using SharpProspero.Input;
using SharpProspero.Storage;
using System;
using System.Collections.Generic;

namespace SampleApp.Patterns;

/// <summary>
/// One named vibration pattern: a display name, a short description of what it feels like, an ordered list
/// of steps, and whether the sequence loops. Presets are read-only entries in the built-in catalog; the
/// user's own patterns are round-tripped as JSON with the same shape.
/// </summary>
public sealed class VibrationPreset
{
    /// <summary>The name shown to the user.</summary>
    public string Name { get; set; } = "";

    /// <summary>A short description of what the pattern feels like.</summary>
    public string Description { get; set; } = "";

    /// <summary>The ordered steps that make up the pattern.</summary>
    public IReadOnlyList<VibrationStep> Steps { get; set; } = [];

    /// <summary>Whether the sequence repeats when it runs out.</summary>
    public bool Loop { get; set; }

    /// <summary>
    /// The total wall-clock length in seconds when the pattern is not looping, or zero when
    /// <see cref="Loop"/> is set (a loop has no natural end).
    /// </summary>
    public float TotalSeconds
    {
        get
        {
            if (Loop || Steps.Count == 0)
                return 0f;
            float total = 0f;
            foreach (VibrationStep step in Steps)
                total += step.DurationSeconds;
            return total;
        }
    }

    /// <summary>Turns the preset into a JSON object suitable for saving.</summary>
    public JsonValue ToJson()
    {
        JsonValue array = JsonValue.NewArray();
        foreach (VibrationStep step in Steps)
        {
            JsonValue node = JsonValue.NewObject();
            node["large"] = step.Levels.LargeMotor;
            node["small"] = step.Levels.SmallMotor;
            node["seconds"] = step.DurationSeconds;
            node["fade"] = step.Fade;
            array.Add(node);
        }

        JsonValue root = JsonValue.NewObject();
        root["name"] = Name;
        root["description"] = Description;
        root["loop"] = Loop;
        root["steps"] = array;
        return root;
    }

    /// <summary>Rebuilds a preset from a JSON value written by <see cref="ToJson"/>.</summary>
    /// <exception cref="ArgumentException">The value is not a valid preset object.</exception>
    public static VibrationPreset FromJson(JsonValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Type != JsonType.Object)
            throw new ArgumentException("A preset must be a JSON object.", nameof(value));

        var steps = new List<VibrationStep>();
        JsonValue stepArray = value["steps"];
        for (int i = 0; i < stepArray.Count; i++)
        {
            JsonValue node = stepArray[i];
            int large = Math.Clamp(node.GetInt("large"), 0, 255);
            int small = Math.Clamp(node.GetInt("small"), 0, 255);
            float seconds = (float)node.GetNumber("seconds");
            if (seconds <= 0f)
                throw new ArgumentException($"Step {i} must last longer than zero seconds.", nameof(value));
            bool fade = node.GetBool("fade");
            var levels = new VibrationLevels((byte)large, (byte)small);
            steps.Add(fade ? VibrationStep.FadeTo(levels, seconds) : VibrationStep.Hold(levels, seconds));
        }

        return new VibrationPreset
        {
            Name = CapLength(value.GetString("name", "").Trim(), PatternStorage.MaxNameLength),
            Description = CapLength(value.GetString("description", ""), MaxDescriptionLength),
            Loop = value.GetBool("loop"),
            Steps = steps,
        };
    }

    /// <summary>The most characters a pattern description keeps when read from disk.</summary>
    public const int MaxDescriptionLength = 512;

    private static string CapLength(string value, int max) => value.Length <= max ? value : value[..max];

    /// <summary>Builds a preset from a name, description, loop flag and step list.</summary>
    public static VibrationPreset Create(string name, string description, IReadOnlyList<VibrationStep> steps, bool loop = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(steps);
        if (steps.Count == 0)
            throw new ArgumentException("A preset needs at least one step.", nameof(steps));

        return new VibrationPreset
        {
            Name = name,
            Description = description ?? "",
            Steps = steps,
            Loop = loop,
        };
    }
}
