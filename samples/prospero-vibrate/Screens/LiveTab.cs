// Prospero Vibrate - Haptics that move You.

using SampleApp.Patterns;
using SharpProspero.Graphics;
using SharpProspero.Input;
using SharpProspero.Ui;
using System;

namespace SampleApp.Screens;

/// <summary>
/// The live tab. Two sliders drive the two motors, and the analog sticks drive the same motors when
/// pushed - the left stick controls the large motor and the right stick controls the small motor. Both
/// paths write the same live pair, so the user picks whichever feels natural: sliders for a set value,
/// sticks for a live-tuned burst. Buttons stop both motors, ramp both to full, or link them.
/// </summary>
public sealed class LiveTab
{
    private readonly HapticsController _haptics;
    private readonly Patterns.AppSettings _settings;

    private readonly Slider _large;
    private readonly Slider _small;
    private readonly Label _status;
    private readonly Label _liveReadout;

    // Whether the last input driving the motors came from the analog sticks. When true the sliders
    // read as the current stick values on the frame the user releases them; this avoids the sliders
    // snapping back to their old values while the sticks are being pushed.
    private bool _stickDriven;

    /// <summary>The tab's root element, to add to a <see cref="TabView"/>.</summary>
    public UiElement Root { get; }

    /// <summary>Creates the tab bound to <paramref name="haptics"/> and <paramref name="settings"/>.</summary>
    public LiveTab(HapticsController haptics, Patterns.AppSettings settings, ITextFont? titleFont = null)
    {
        ArgumentNullException.ThrowIfNull(haptics);
        ArgumentNullException.ThrowIfNull(settings);
        _haptics = haptics;
        _settings = settings;

        _large = new Slider("Large motor", 0, 255, 0, step: 5, changed: _ => OnSliderChanged(largeChanged: true));
        _small = new Slider("Small motor", 0, 255, 0, step: 5, changed: _ => OnSliderChanged(largeChanged: false));
        _status = new Label("Move sliders left/right to drive the motors.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };
        _liveReadout = new Label("Live L=0 / S=0") { TextColor = Color.FromRgb(0x4C, 0xC2, 0xFF) };

        var help = new Label("Sticks drive the motors. Left stick = large, right stick = small. Sliders work too.") { TextColor = Color.FromRgb(0x8A, 0x94, 0xA0) };

        var stop = new Button("Release both motors", () =>
        {
            _large.Value = 0;
            _small.Value = 0;
            Push();
        });

        var full = new Button("Full drive (both motors 255)", () =>
        {
            _large.Value = 255;
            _small.Value = 255;
            Push();
        });

        var link = new Checkbox("Link motors (both slide together)", settings.LinkMotors, on =>
        {
            settings.LinkMotors = on;
            if (on)
            {
                // Equalize the slider values, push the linked pair to hardware, and let LiveLevels catch
                // up. Slider.Value's setter is silent, so Push() has to be called explicitly.
                _small.Value = _large.Value;
                Push();
            }
            PatternStorage.TrySaveSettings(settings);
        });

        Root = new StackPanel()
            .Add(Titles.BuildTitle("Live control", titleFont))
            .Add(_status)
            .Add(help)
            .Add(_large)
            .Add(_small)
            .Add(link)
            .Add(stop)
            .Add(full)
            .Add(_liveReadout);
    }

    /// <summary>Called every frame; updates the readout and applies the sliders' values.</summary>
    public void OnFrame()
    {
        var current = _haptics.LiveLevels;
        _liveReadout.Text = $"Live L={current.LargeMotor} / S={current.SmallMotor}";

        if (!_haptics.HasController)
            _status.Text = "No controller connected.";
        else if (_stickDriven)
            _status.Text = "Driving from analog sticks.";
        else if (_haptics.State == HapticsState.Live)
            _status.Text = "Driving from live sliders.";
        else if (_haptics.State == HapticsState.Idle)
            _status.Text = "Motors stopped.";
        else
            _status.Text = "A pattern is running from another tab; the sliders and sticks drive live when moved.";
    }

    /// <summary>
    /// Reads the analog sticks from <paramref name="pad"/> and drives the motors when either stick is
    /// pushed past its rest zone. Called every frame while this tab is the active one, before the
    /// interface updates, so the sticks reach the motors without also pulsing focus on the tab row.
    /// </summary>
    public void ApplySticks(GamePadState pad)
    {
        // Positive Y on a stick means the stick is down. The user's expectation is push-up = drive-up,
        // so the sign is flipped and negative Y (up) is the full drive.
        (_, float leftY) = pad.LeftStick;
        (_, float rightY) = pad.RightStick;

        // A rest deadzone below the stick threshold keeps a slightly-off-centre stick from starting to
        // drive the motors on its own.
        const float rest = 0.10f;
        bool leftActive = MathF.Abs(leftY) > rest;
        bool rightActive = MathF.Abs(rightY) > rest;

        if (!leftActive && !rightActive)
        {
            if (_stickDriven)
            {
                // The user let both sticks return to rest. Stop the motors so a resting hand does not
                // keep the pair at whatever value the last frame ended at.
                _large.Value = 0;
                _small.Value = 0;
                _haptics.DriveLive(VibrationLevels.Zero);
                _stickDriven = false;
            }
            return;
        }

        // The stick is centred at 0 and pushed to +/-1 at full. Negative Y is up, which the user reads
        // as "more drive"; the value is clamped to 0..1 and scaled into the 0-255 pair.
        float largeDrive = leftActive ? MathF.Max(0f, -leftY) : 0f;
        float smallDrive = rightActive ? MathF.Max(0f, -rightY) : 0f;

        byte largeLevel = (byte)MathF.Round(largeDrive * 255f);
        byte smallLevel = (byte)MathF.Round(smallDrive * 255f);

        if (_settings.LinkMotors)
        {
            // The Live-tab link setting equalises the two motors; take the stronger of the two sticks
            // so a user with a single stick still reaches full drive.
            byte together = largeLevel > smallLevel ? largeLevel : smallLevel;
            largeLevel = together;
            smallLevel = together;
        }

        // Mirror the values back to the sliders so the on-screen readout follows the sticks.
        _large.Value = largeLevel;
        _small.Value = smallLevel;

        _haptics.DriveLive(new VibrationLevels(largeLevel, smallLevel));
        _stickDriven = true;
    }

    private void OnSliderChanged(bool largeChanged)
    {
        if (_settings.LinkMotors)
        {
            if (largeChanged)
                _small.Value = _large.Value;
            else
                _large.Value = _small.Value;
        }
        Push();
    }

    private void Push()
    {
        var levels = new VibrationLevels((byte)_large.Value, (byte)_small.Value);
        _haptics.DriveLive(levels);
    }
}
