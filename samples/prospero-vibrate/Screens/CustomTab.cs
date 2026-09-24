// Prospero Vibrate - Haptics that move You.

using SampleApp.Patterns;
using SharpProspero.Graphics;
using SharpProspero.Input;
using SharpProspero.Ui;
using System;
using System.Collections.Generic;

namespace SampleApp.Screens;

/// <summary>
/// The custom-pattern tab. The user builds a sequence of up to <see cref="MaxSteps"/> steps: for each
/// step, the two motor levels, a duration in milliseconds and whether the step fades. The pattern can be
/// played, saved by name, loaded from a saved list, or deleted. The pattern's name is edited through the
/// on-screen keyboard, opened by the top-level app when <see cref="KeyboardRequested"/> is raised.
/// </summary>
public sealed class CustomTab
{
    /// <summary>The most steps a custom pattern can hold.</summary>
    public const int MaxSteps = 8;

    private readonly HapticsController _haptics;
    private readonly List<VibrationStep> _steps = [];
    private int _editingIndex;
    private string _patternName = "My Pattern";
    private string _lastMessage = "";
    private bool _loopFlag;

    private readonly Stepper _countStepper;
    private readonly Stepper _stepStepper;
    private readonly Slider _large;
    private readonly Slider _small;
    private readonly Slider _duration;
    private readonly Checkbox _fade;
    private readonly Checkbox _loop;
    private readonly Label _name;
    private readonly Label _stats;
    private readonly Label _status;
    private readonly Button _renameButton;
    private readonly ListView _savedList;
    private readonly Label _savedHeader;

    /// <summary>The tab's root element.</summary>
    public UiElement Root { get; }

    /// <summary>
    /// Raised when the tab needs the top-level app to open the on-screen keyboard for the pattern's
    /// name. The current name is passed in; the callback returns the new name, or the same one if the
    /// user cancels.
    /// </summary>
    public event Action? KeyboardRequested;

    /// <summary>Creates the tab bound to <paramref name="haptics"/>.</summary>
    public CustomTab(HapticsController haptics, ITextFont? titleFont = null)
    {
        ArgumentNullException.ThrowIfNull(haptics);
        _haptics = haptics;

        _steps.Add(VibrationStep.Hold(new VibrationLevels(200, 100), 0.20f));
        _steps.Add(VibrationStep.Rest(0.10f));
        _steps.Add(VibrationStep.Hold(new VibrationLevels(200, 100), 0.20f));

        _countStepper = new Stepper("Step count", _steps.Count, 1, MaxSteps, changed: OnCountChanged);
        _stepStepper = new Stepper("Editing step", 1, 1, _steps.Count, format: i => "#" + i, changed: OnEditIndexChanged);
        _large = new Slider("Large motor", 0, 255, _steps[0].Levels.LargeMotor, step: 5, changed: _ => WriteEditedStep());
        _small = new Slider("Small motor", 0, 255, _steps[0].Levels.SmallMotor, step: 5, changed: _ => WriteEditedStep());
        _duration = new Slider("Duration (ms)", 20, 4000, _steps[0].DurationSeconds * 1000f, step: 20, changed: _ => WriteEditedStep());
        _fade = new Checkbox("Fade from previous", _steps[0].Fade, on => WriteEditedStep());
        _loop = new Checkbox("Loop the pattern", false, on => _loopFlag = on);
        _name = new Label("Name: " + _patternName);
        _stats = new Label(BuildStats()) { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };
        _status = new Label("") { TextColor = Color.FromRgb(0x4C, 0xC2, 0xFF) };
        _renameButton = new Button("Rename...", () => KeyboardRequested?.Invoke());

        _savedHeader = new Label("Saved patterns:") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };
        _savedList = new ListView();
        _savedList.VisibleRows = 4;
        _savedList.Activated = LoadSavedByIndex;

        var play = new Button("Play", PlayCurrent);
        var stop = new Button("Stop", () => _haptics.Stop());
        var save = new Button("Save", SaveCurrent);
        var delete = new Button("Delete saved", DeleteFocusedSaved);

        Root = new StackPanel()
            .Add(Titles.BuildTitle("Custom pattern", titleFont))
            .Add(new Label("Build a sequence of up to 8 steps.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) })
            .Add(_name)
            .Add(new Row().Add(_renameButton).Add(_countStepper).Add(_stepStepper))
            .Add(_large)
            .Add(_small)
            .Add(_duration)
            .Add(new Row().Add(_fade).Add(_loop))
            .Add(new Row().Add(play).Add(stop).Add(save))
            .Add(_stats)
            .Add(_status)
            .Add(_savedHeader)
            .Add(_savedList)
            .Add(delete);

        RefreshSavedList();
    }

    /// <summary>The pattern's editable name, shown in the header.</summary>
    public string PatternName
    {
        get => _patternName;
        set
        {
            if (string.IsNullOrWhiteSpace(value))
                return;
            _patternName = value.Trim();
            _name.Text = "Name: " + _patternName;
        }
    }

    /// <summary>Update the visible status and playback time once per frame.</summary>
    public void OnFrame()
    {
        // A timed / one-shot preset that finishes elsewhere while this tab is on screen leaves the status
        // reading stale until the next explicit action - refresh it here so a pattern that ran out shows
        // as stopped.
        if (_haptics.State == HapticsState.Idle && !string.IsNullOrEmpty(_lastMessage))
        {
            _status.Text = _lastMessage;
        }
    }

    /// <summary>Rebuild the saved-pattern list; call this after loading, saving or deleting.</summary>
    public void RefreshSavedList()
    {
        _savedList.Clear();
        foreach (string name in PatternStorage.ListPatternNames())
            _savedList.Add(name);
    }

    private void PlayCurrent()
    {
        try
        {
            VibrationPreset preset = VibrationPreset.Create(_patternName, "Custom pattern", _steps, _loopFlag);
            _haptics.Play(preset);
            SetStatus($"Playing '{preset.Name}'.");
        }
        catch (Exception e)
        {
            SetStatus("Could not play: " + e.Message);
        }
    }

    private void SaveCurrent()
    {
        try
        {
            VibrationPreset preset = VibrationPreset.Create(_patternName, "Custom pattern", _steps, _loopFlag);
            if (PatternStorage.TrySavePattern(preset))
            {
                RefreshSavedList();
                SetStatus($"Saved '{preset.Name}'.");
            }
            else
            {
                SetStatus("Save refused. Check writable storage.");
            }
        }
        catch (Exception e)
        {
            SetStatus("Could not save: " + e.Message);
        }
    }

    private void LoadSavedByIndex(int index)
    {
        if ((uint)index >= (uint)_savedList.Items.Count)
            return;
        string name = _savedList.Items[index];
        if (string.IsNullOrWhiteSpace(name))
        {
            SetStatus("The selected entry has no name.");
            return;
        }

        VibrationPreset? preset;
        try
        {
            preset = PatternStorage.LoadPattern(name);
        }
        catch (Exception e)
        {
            SetStatus("Could not read " + name + ": " + e.Message);
            return;
        }
        if (preset is null)
        {
            SetStatus("Could not read " + name + ".");
            return;
        }

        LoadFromPreset(preset);
        SetStatus("Loaded '" + preset.Name + "'.");
    }

    private void DeleteFocusedSaved()
    {
        if (_savedList.Items.Count == 0)
        {
            SetStatus("Nothing saved to delete.");
            return;
        }
        int index = _savedList.SelectedIndex;
        if ((uint)index >= (uint)_savedList.Items.Count)
            return;

        string name = _savedList.Items[index];
        if (string.IsNullOrWhiteSpace(name))
        {
            SetStatus("The selected entry has no name.");
            return;
        }

        bool deleted;
        try
        {
            deleted = PatternStorage.TryDeletePattern(name);
        }
        catch (Exception e)
        {
            SetStatus("Delete refused for " + name + ": " + e.Message);
            return;
        }

        if (!deleted)
        {
            SetStatus("Delete refused for " + name + ".");
            return;
        }
        RefreshSavedList();
        SetStatus("Deleted '" + name + "'.");
    }

    private void LoadFromPreset(VibrationPreset preset)
    {
        _steps.Clear();
        int loaded = 0;
        foreach (VibrationStep step in preset.Steps)
        {
            if (loaded == MaxSteps)
                break;
            _steps.Add(step);
            loaded++;
        }
        if (_steps.Count == 0)
            _steps.Add(VibrationStep.Hold(VibrationLevels.Zero, 0.5f));

        _patternName = preset.Name;
        _name.Text = "Name: " + _patternName;
        _loopFlag = preset.Loop;
        _loop.Checked = preset.Loop;

        _countStepper.Value = _steps.Count;
        RebindStepBounds();
        _editingIndex = 0;
        _stepStepper.Value = 1;
        PullEditedStep();
    }

    private void OnCountChanged(long newCount)
    {
        int count = Math.Clamp((int)newCount, 1, MaxSteps);
        while (_steps.Count < count)
        {
            var last = _steps[^1];
            _steps.Add(VibrationStep.Hold(last.Levels, last.DurationSeconds));
        }
        while (_steps.Count > count)
            _steps.RemoveAt(_steps.Count - 1);

        RebindStepBounds();
        if (_editingIndex >= count)
        {
            _editingIndex = count - 1;
            _stepStepper.Value = _editingIndex + 1;
            PullEditedStep();
        }
        _stats.Text = BuildStats();
    }

    private void OnEditIndexChanged(long newIndex)
    {
        int idx = Math.Clamp((int)newIndex - 1, 0, _steps.Count - 1);
        if (idx == _editingIndex)
            return;
        _editingIndex = idx;
        PullEditedStep();
    }

    private void RebindStepBounds()
    {
        // Grow (or shrink) the editing-step range so every step in the list can be reached.
        _stepStepper.SetRange(1, _steps.Count);
    }

    private void PullEditedStep()
    {
        VibrationStep s = _steps[_editingIndex];
        _large.Value = s.Levels.LargeMotor;
        _small.Value = s.Levels.SmallMotor;
        _duration.Value = s.DurationSeconds * 1000f;
        _fade.Checked = s.Fade;
        _stats.Text = BuildStats();
    }

    private void WriteEditedStep()
    {
        if (_editingIndex >= _steps.Count)
            return;
        float ms = _duration.Value;
        if (ms < 20f)
            ms = 20f;
        float seconds = ms / 1000f;
        var levels = new VibrationLevels((byte)_large.Value, (byte)_small.Value);
        VibrationStep step = _fade.Checked
            ? VibrationStep.FadeTo(levels, seconds)
            : VibrationStep.Hold(levels, seconds);
        _steps[_editingIndex] = step;
        _stats.Text = BuildStats();
    }

    private string BuildStats()
    {
        float total = 0f;
        foreach (VibrationStep s in _steps)
            total += s.DurationSeconds;
        return $"Total: {total:0.##}s across {_steps.Count} step{(_steps.Count == 1 ? "" : "s")}.";
    }

    private void SetStatus(string text)
    {
        _lastMessage = text;
        _status.Text = text;
    }
}
