// Prospero Vibrate - Haptics that move You.

using SampleApp.Patterns;
using SharpProspero.Graphics;
using SharpProspero.Ui;
using System;
using System.Collections.Generic;

namespace SampleApp.Screens;

/// <summary>
/// The timed-play tab. The user picks a preset (from the built-in catalog and every saved custom
/// pattern) and a duration; the app plays it and stops the motors when the countdown expires. Useful
/// for a fixed-length signal - a warmup, a break reminder, a wake-up.
/// </summary>
public sealed class TimerTab
{
    private readonly HapticsController _haptics;
    private readonly Patterns.AppSettings _settings;
    private readonly Carousel _pickerCarousel;
    private readonly Slider _secondsSlider;
    private readonly Label _status;
    private readonly Label _remaining;

    private readonly List<VibrationPreset> _library = new();
    private readonly List<string> _carouselNames = new();

    /// <summary>The tab's root element.</summary>
    public UiElement Root { get; }

    /// <summary>Creates the tab bound to <paramref name="haptics"/> and <paramref name="settings"/>.</summary>
    public TimerTab(HapticsController haptics, Patterns.AppSettings settings, ITextFont? titleFont = null)
    {
        ArgumentNullException.ThrowIfNull(haptics);
        ArgumentNullException.ThrowIfNull(settings);
        _haptics = haptics;
        _settings = settings;

        Refresh();
        SyncNames();
        _pickerCarousel = new Carousel(_carouselNames, activated: _ => StartTimed());
        _secondsSlider = new Slider("Seconds", 1, 300, settings.DefaultTimerSeconds, step: 1, changed: v => _settings.DefaultTimerSeconds = (int)v);
        _status = new Label("Pick a pattern and press Cross to start.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };
        _remaining = new Label("") { TextColor = Color.FromRgb(0x4C, 0xC2, 0xFF) };

        var play = new Button("Start timed play", StartTimed);
        var stop = new Button("Stop", () => _haptics.Stop());
        var refresh = new Button("Refresh library", () =>
        {
            Refresh();
            SyncNames();
            if (_pickerCarousel.SelectedIndex >= _carouselNames.Count)
                _pickerCarousel.SelectedIndex = 0;
        });

        Root = new StackPanel()
            .Add(Titles.BuildTitle("Timed play", titleFont))
            .Add(new Label("Play a preset (or saved pattern) for the chosen number of seconds.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) })
            .Add(_pickerCarousel)
            .Add(_secondsSlider)
            .Add(play)
            .Add(stop)
            .Add(refresh)
            .Add(_status)
            .Add(_remaining);
    }

    /// <summary>Update the countdown readout each frame.</summary>
    public void OnFrame()
    {
        if (_haptics.State == HapticsState.Timed && _haptics.CurrentPreset is not null)
        {
            float total = _haptics.TimedTotalSeconds;
            float left = _haptics.TimedRemainingSeconds;
            _remaining.Text = $"{_haptics.CurrentPreset.Name}: {left:0.0}s left of {total:0.#}s.";
        }
        else if (_haptics.State == HapticsState.Idle)
        {
            _remaining.Text = "";
        }
    }

    private void StartTimed()
    {
        if (_library.Count == 0)
        {
            _status.Text = "No patterns to play.";
            return;
        }

        int index = _pickerCarousel.SelectedIndex;
        if ((uint)index >= (uint)_library.Count)
        {
            _status.Text = "No pattern picked.";
            return;
        }

        VibrationPreset preset = _library[index];
        int seconds = Math.Clamp((int)_secondsSlider.Value, 1, 3600);
        if (_haptics.PlayTimed(preset, seconds))
            _status.Text = $"Playing '{preset.Name}' for {seconds}s.";
        else
            _status.Text = "Could not start timed play.";
    }

    private void Refresh()
    {
        _library.Clear();
        foreach (VibrationPreset built in PresetCatalog.All)
            _library.Add(built);
        foreach (string name in PatternStorage.ListPatternNames())
        {
            VibrationPreset? saved = PatternStorage.LoadPattern(name);
            if (saved is not null)
                _library.Add(saved);
        }
    }

    private void SyncNames()
    {
        _carouselNames.Clear();
        if (_library.Count == 0)
        {
            _carouselNames.Add("(no patterns)");
            return;
        }
        foreach (VibrationPreset p in _library)
            _carouselNames.Add(p.Name);
    }
}
