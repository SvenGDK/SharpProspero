// Prospero Vibrate - Haptics that move You.

using SampleApp.Patterns;
using SharpProspero.Graphics;
using SharpProspero.Interop.Pad;
using SharpProspero.Ui;
using System;

namespace SampleApp.Screens;

/// <summary>
/// The settings tab. Adjusts app-wide options: drive mode, master intensity, motor link, microphone
/// weakening, and the default timer duration. Every change is applied to the shared controller and
/// written to disk immediately, so nothing is lost when the app closes. A test button plays a short
/// pattern in the current mode so the user can feel the difference between the two curves without
/// leaving the tab.
/// </summary>
public sealed class SettingsTab
{
    private readonly HapticsController _haptics;
    private readonly AppSettings _settings;
    private readonly Label _status;
    private readonly Label _driveModeHint;
    private readonly Checkbox _linkBox;

    /// <summary>The tab's root element.</summary>
    public UiElement Root { get; }

    /// <summary>Creates the tab bound to the shared <paramref name="haptics"/> and <paramref name="settings"/>.</summary>
    public SettingsTab(HapticsController haptics, AppSettings settings, ITextFont? titleFont = null)
    {
        ArgumentNullException.ThrowIfNull(haptics);
        ArgumentNullException.ThrowIfNull(settings);
        _haptics = haptics;
        _settings = settings;

        _driveModeHint = new Label(HintFor(settings.DriveMode)) { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };

        var driveMode = new OptionSelector("Drive mode", ["Advanced", "Compatible"],
            settings.DriveMode == ScePadVibrationMode.Advanced ? 0 : 1, changed: idx =>
            {
                _settings.DriveMode = idx == 0 ? ScePadVibrationMode.Advanced : ScePadVibrationMode.Compatible;
                _driveModeHint.Text = HintFor(_settings.DriveMode);
                Apply();
            });

        var driveModeTest = new Button("Play a test pattern in this mode", PlayDriveModeTest);

        var master = new Slider("Master intensity (%)", 0, 100, settings.MasterIntensityPercent, step: 5, changed: v =>
        {
            _settings.MasterIntensityPercent = (int)v;
            Apply();
        });

        _linkBox = new Checkbox("Link both motors on the live tab", settings.LinkMotors, on =>
        {
            _settings.LinkMotors = on;
            Apply();
        });

        var mic = new Checkbox("Weaken while microphone in use", settings.WeakenWhileMicInUse, on =>
        {
            _settings.WeakenWhileMicInUse = on;
            Apply();
        });

        var timerDefault = new Stepper("Default timer (seconds)", settings.DefaultTimerSeconds, 1, 3600, 1, changed: v =>
        {
            _settings.DefaultTimerSeconds = (int)v;
            Apply();
        });

        _status = new Label("") { TextColor = Color.FromRgb(0x4C, 0xC2, 0xFF) };

        var restore = new Button("Restore defaults", () =>
        {
            _settings.DriveMode = ScePadVibrationMode.Compatible;
            _settings.MasterIntensityPercent = 100;
            _settings.LinkMotors = false;
            _settings.WeakenWhileMicInUse = false;
            _settings.DefaultTimerSeconds = 10;
            driveMode.SelectedIndex = 1;
            _driveModeHint.Text = HintFor(_settings.DriveMode);
            master.Value = 100;
            _linkBox.Checked = false;
            mic.Checked = false;
            timerDefault.Value = 10;
            Apply();
            _status.Text = "Restored defaults.";
        });

        Root = new StackPanel()
            .Add(Titles.BuildTitle("Settings", titleFont))
            .Add(new Label("Every change is applied at once and saved automatically.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) })
            .Add(driveMode)
            .Add(_driveModeHint)
            .Add(driveModeTest)
            .Add(master)
            .Add(_linkBox)
            .Add(mic)
            .Add(timerDefault)
            .Add(restore)
            .Add(_status);
    }

    /// <summary>Frame update - mirrors settings edited elsewhere back into the visible controls.</summary>
    public void OnFrame()
    {
        // The link toggle is exposed on the live tab too; if a change came from there, redraw the
        // checkbox on this tab so the two views cannot disagree.
        if (_linkBox.Checked != _settings.LinkMotors)
            _linkBox.Checked = _settings.LinkMotors;
    }

    private void PlayDriveModeTest()
    {
        _haptics.Play(PresetCatalog.DriveModeTest());
        _status.Text = "Playing test pattern in " + (_settings.DriveMode == ScePadVibrationMode.Advanced ? "Advanced" : "Compatible") + " mode.";
    }

    private static string HintFor(ScePadVibrationMode mode) => mode == ScePadVibrationMode.Advanced
        ? "Advanced: the current-generation drive curve. Precise and covers subtle to strong; small values may feel gentle."
        : "Compatible: the earlier-generation drive curve. Buzzier response; the same values feel more percussive.";

    private void Apply()
    {
        _haptics.ApplySettings(_settings);
        bool saved = PatternStorage.TrySaveSettings(_settings);
        _status.Text = saved ? "Saved." : "Saved in memory (disk unavailable).";
    }
}
