// Prospero Vibrate - Haptics that move You.

using SampleApp.Patterns;
using SharpProspero.Graphics;
using SharpProspero.Ui;
using System;

namespace SampleApp.Screens;

/// <summary>
/// The presets tab. A vertical list of the built-in patterns; the confirm button plays the selected one
/// and the cancel button stops any running preset. A description under the list explains what the
/// currently focused pattern feels like.
/// </summary>
public sealed class PresetsTab
{
    private readonly HapticsController _haptics;
    private readonly ListView _list;
    private readonly Label _description;
    private readonly Label _status;

    /// <summary>The tab's root element.</summary>
    public UiElement Root { get; }

    /// <summary>Creates the tab bound to <paramref name="haptics"/>.</summary>
    public PresetsTab(HapticsController haptics, ITextFont? titleFont = null)
    {
        ArgumentNullException.ThrowIfNull(haptics);
        _haptics = haptics;

        _description = new Label(DescriptionFor(0)) { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };
        _status = new Label("") { TextColor = Color.FromRgb(0x4C, 0xC2, 0xFF) };

        _list = new ListView();
        foreach (VibrationPreset preset in PresetCatalog.All)
            _list.Add(preset.Name);
        _list.VisibleRows = 8;
        _list.Activated = Play;
        _list.SelectionChanged = i => _description.Text = DescriptionFor(i);

        Root = new StackPanel()
            .Add(Titles.BuildTitle("Presets", titleFont))
            .Add(new Label("D-pad browses, Cross plays, Stop below ends the pattern.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) })
            .Add(_list)
            .Add(_description)
            .Add(new Button("Stop", () => _haptics.Stop()))
            .Add(_status);
    }

    /// <summary>Update the visible status once per frame.</summary>
    public void OnFrame()
    {
        VibrationPreset? playing = _haptics.CurrentPreset;
        _status.Text = _haptics.State switch
        {
            HapticsState.Idle => "",
            HapticsState.Live => "",
            HapticsState.Playing when playing is not null => $"Now playing: {playing.Name}",
            HapticsState.Timed when playing is not null => $"Timed: {playing.Name} ({_haptics.TimedRemainingSeconds:0.0}s left)",
            _ => "",
        };
    }

    private void Play(int index)
    {
        if ((uint)index >= (uint)PresetCatalog.All.Count)
            return;
        _haptics.Play(PresetCatalog.All[index]);
    }

    private static string DescriptionFor(int index)
    {
        if ((uint)index >= (uint)PresetCatalog.All.Count)
            return "";
        VibrationPreset p = PresetCatalog.All[index];
        return p.Loop
            ? $"{p.Description} (loops until stopped)"
            : $"{p.Description} ({p.TotalSeconds:0.#}s total)";
    }
}
