// Prospero Vibrate - Haptics that move You.
// A controller-vibration studio: live drive, curated presets, custom patterns and timed play.

using SampleApp.Patterns;
using SampleApp.Screens;
using SharpProspero.Application;
using SharpProspero.Diagnostics;
using SharpProspero.Graphics;
using SharpProspero.Input;
using SharpProspero.Interop;
using SharpProspero.Interop.Dialog;
using SharpProspero.Interop.Font;
using SharpProspero.Interop.Pad;
using SharpProspero.Interop.Sysmodule;
using SharpProspero.Modules;
using SharpProspero.Platform;
using SharpProspero.Ui;
using System;

namespace SampleApp;

internal sealed class Game : ProsperoApp
{
    private static readonly Color Background = Color.FromRgb(0x0F, 0x14, 0x1B);
    private static readonly Color Accent = Color.FromRgb(0x4C, 0xC2, 0xFF);
    private static readonly Color Muted = Color.FromRgb(0x8A, 0x94, 0xA0);

    private readonly AppSettings _settings;
    private readonly HapticsController _haptics;
    private LiveTab? _live;
    private PresetsTab? _presets;
    private CustomTab? _custom;
    private TimerTab? _timer;
    private SettingsTab? _settingsTab;
    private UiScreen? _screen;
    private TabView? _tabs;
    private UiTheme _theme = UiTheme.Default;

    // The outline fonts every part of the interface draws with. Loaded once at start-up and held for
    // the life of the process. When the load fails we fall back to the built-in bitmap text so the app
    // still runs, only less crisp.
    private SystemModule? _fontModule;
    private SystemModule? _fontFtModule;
    private SystemModule? _freeTypeOtModule;
    private SystemFont? _bodyFont;
    private SystemFont? _titleFont;
    private SystemFont? _brandFont;
    private ITextFont _headerFont = new BitmapTextFont(3);
    private ITextFont _hintFont = new BitmapTextFont(2);

    // Modal keyboard, opened when the custom tab asks to rename the pattern.
    private TextInputDialog? _keyboard;

    // The controller reference the run loop last handed us; used to detect a pad that opens mid-run.
    private GamePad? _lastPad;

    // A rolling status line under the tabs, cleared after a short time.
    private string _toast = "";
    private float _toastRemaining;

    private bool _exit;

    public Game() : base(new AppConfig { HideSplashScreen = true })
    {
        PatternStorage.TryEnsureStructure();
        _settings = PatternStorage.LoadSettings();
        _haptics = new HapticsController(null, _settings)
        {
            Announced = SetToast,
        };
    }

    protected override void OnLoad()
    {
        LoadFonts();
        _haptics.SetPad(GamePad);
        _haptics.ApplySettings(_settings);
        _lastPad = GamePad;
        _screen = BuildScreen();
    }

    private void LoadFonts()
    {
        try
        {
            // Font handles the glyph engine, FontFt supplies the FreeType face reader, and the OpenType
            // backend the renderer walks glyphs through has to be resident too - opening a scalable face
            // without it faults the process at the first render call.
            _fontModule = SystemModule.Load(SystemModuleId.Font);
            _fontFtModule = SystemModule.Load(SystemModuleId.FontFt);
            _freeTypeOtModule = SystemModule.Load(SystemModuleId.FreeTypeOt);

            _bodyFont = SystemFont.Open(SceFontSet.StdEuropeanW1G, pixelSize: 22f);
            _titleFont = SystemFont.Open(SceFontSet.StdEuropeanW1G, pixelSize: 40f);
            _brandFont = SystemFont.Open(SceFontSet.StdEuropeanW1G, pixelSize: 44f);
            _headerFont = _brandFont;
            _hintFont = _bodyFont;
            _theme = new UiTheme { Font = _bodyFont };
        }
        catch (ProsperoException failure)
        {
            Log.Warning("Scalable fonts unavailable, falling back to bitmap text: " + failure.Message);
            DisposeFonts();
        }
    }

    protected override void OnFrame(FrameContext context)
    {
        Surface surface = context.Surface;
        float delta = (float)context.DeltaSeconds;

        // A pad that opens after the loop began (a user signed in, a controller paired) needs to reach
        // the haptics controller so patterns can drive it.
        if (!ReferenceEquals(GamePad, _lastPad))
        {
            _haptics.SetPad(GamePad);
            _haptics.ApplySettings(_settings);
            _lastPad = GamePad;
        }

        _haptics.Update(delta);

        surface.Clear(Background);

        // A modal on-screen keyboard is running: stay in the presentation loop and let it draw itself.
        // The screen behind it is dimmed so the field stands out.
        if (_keyboard is not null)
        {
            DrawBackdrop(surface);
            AdvanceKeyboard();
        }
        else if (_screen is not null)
        {
            DrawScreen(surface, context);
        }

        UpdateToast(delta);
        DrawToast(surface);

        if (context.Pressed(ScePadButton.Options))
            _exit = true;
        if (_exit)
        {
            _haptics.Stop();
            context.RequestExit();
        }
    }

    private void DrawScreen(Surface surface, FrameContext context)
    {
        int margin = 60;

        // The header uses two font sizes: the brand line and a muted hint under it. Its total height
        // depends on the loaded font so it does not push the tabs off the screen.
        int titleBaseY = margin;
        _headerFont.DrawText(surface, "Prospero Vibrate - Haptics that move You", margin, titleBaseY, Color.White);
        int hintY = titleBaseY + _headerFont.LineHeight + 4;
        _hintFont.DrawText(surface, "Press Options to exit.", margin, hintY, Muted);

        int contentTop = hintY + _hintFont.LineHeight + 24;
        int footerHeight = 96;
        var area = new UiRect(margin, contentTop, surface.Width - 2 * margin, surface.Height - contentTop - margin - footerHeight);
        _screen!.Layout(area);

        // On the live tab the sticks drive the motors, so their movement must not also pulse focus
        // direction on the tab row. Feed the interface a sample with the sticks re-centred while the
        // live tab is on screen; the tab itself reads the real sticks from the frame context below.
        bool liveTabActive = _tabs is not null && _tabs.SelectedIndex == LiveTabIndex;
        GamePadState uiCurrent = liveTabActive ? WithCentredSticks(context.Input) : context.Input;
        GamePadState uiPrevious = liveTabActive ? WithCentredSticks(context.PreviousInput) : context.PreviousInput;
        _screen.Update(UiInput.From(uiCurrent, uiPrevious));

        _screen.Draw(surface);

        if (liveTabActive)
            _live?.ApplySticks(context.Input);
        _live?.OnFrame();
        _presets?.OnFrame();
        _custom?.OnFrame();
        _timer?.OnFrame();
        _settingsTab?.OnFrame();

        DrawFooter(surface);
    }

    private const int LiveTabIndex = 0;

    private static GamePadState WithCentredSticks(GamePadState state) => state with
    {
        LeftStickX = 128,
        LeftStickY = 128,
        RightStickX = 128,
        RightStickY = 128,
    };

    private void DrawFooter(Surface surface)
    {
        int y = surface.Height - _hintFont.LineHeight - 30;
        _hintFont.DrawText(surface, "State: " + StateName(_haptics.State), 60, y, Muted);

        int motorsX = 60 + _hintFont.MeasureText("State: Playing pattern ") + 40;
        if (_haptics.HasController)
        {
            var levels = _haptics.CurrentLevels;
            _hintFont.DrawText(surface, "Motors L=" + levels.LargeMotor + " S=" + levels.SmallMotor, motorsX, y, Accent);
        }
        else
        {
            _hintFont.DrawText(surface, "No controller connected", motorsX, y, Muted);
        }

        int barX = surface.Width - 380;
        int barY = y + 4;
        int barW = 300;
        int barH = 20;
        var lv = _haptics.CurrentLevels;
        surface.DrawRect(barX, barY, barW, barH, Muted);
        surface.FillRect(barX, barY, lv.LargeMotor * barW / 255, barH, Accent);
        surface.DrawRect(barX, barY + barH + 6, barW, barH, Muted);
        surface.FillRect(barX, barY + barH + 6, lv.SmallMotor * barW / 255, barH, Accent);
    }

    private static string StateName(HapticsState state) => state switch
    {
        HapticsState.Idle => "Idle",
        HapticsState.Playing => "Playing pattern",
        HapticsState.Timed => "Timed play",
        HapticsState.Live => "Live drive",
        _ => "Idle",
    };

    private void DrawBackdrop(Surface surface)
    {
        int y = surface.Height / 2 - _headerFont.LineHeight - 20;
        int titleWidth = _headerFont.MeasureText("Editing pattern name...");
        _headerFont.DrawText(surface, "Editing pattern name...", (surface.Width - titleWidth) / 2, y, Color.White);

        int hintY = y + _headerFont.LineHeight + 12;
        int hintWidth = _hintFont.MeasureText("Use the on-screen keyboard.");
        _hintFont.DrawText(surface, "Use the on-screen keyboard.", (surface.Width - hintWidth) / 2, hintY, Muted);
    }

    private void AdvanceKeyboard()
    {
        if (_keyboard is null)
            return;
        TextInputState state;
        try
        {
            state = _keyboard.Update();
        }
        catch (ProsperoException failure)
        {
            SetToast("Keyboard error: " + failure.Message);
            DisposeKeyboard();
            return;
        }
        if (state != TextInputState.Finished)
            return;

        if (_keyboard.EndStatus == ImeDialogEndStatus.Ok)
        {
            string typed = _keyboard.Text.Trim();
            if (typed.Length > 0 && _custom is not null)
            {
                _custom.PatternName = typed;
                SetToast("Renamed to '" + typed + "'.");
            }
        }
        else
        {
            SetToast("Rename canceled.");
        }
        DisposeKeyboard();
    }

    private void DisposeKeyboard()
    {
        _keyboard?.Dispose();
        _keyboard = null;
    }

    private UiScreen BuildScreen()
    {
        _live = new LiveTab(_haptics, _settings, _titleFont);
        _presets = new PresetsTab(_haptics, _titleFont);
        _custom = new CustomTab(_haptics, _titleFont);
        _custom.KeyboardRequested += OpenPatternNameKeyboard;
        _timer = new TimerTab(_haptics, _settings, _titleFont);
        _settingsTab = new SettingsTab(_haptics, _settings, _titleFont);

        _tabs = new TabView();
        _tabs.Add("Live", _live.Root);
        _tabs.Add("Presets", _presets.Root);
        _tabs.Add("Custom", _custom.Root);
        _tabs.Add("Timer", _timer.Root);
        _tabs.Add("Settings", _settingsTab.Root);

        return new UiScreen(_tabs, _theme) { Cancelled = () => _exit = true };
    }

    private void OpenPatternNameKeyboard()
    {
        if (_keyboard is not null || _custom is null)
            return;
        try
        {
            _keyboard = TextInputDialog.Open(
                title: "Pattern name",
                maxLength: 64,
                initialText: _custom.PatternName,
                placeholder: "Enter a name");
        }
        catch (ProsperoException failure)
        {
            SetToast("Keyboard failed to open: " + failure.Message);
        }
    }

    private void SetToast(string message)
    {
        _toast = message ?? "";
        _toastRemaining = string.IsNullOrEmpty(message) ? 0f : 3.5f;
    }

    private void UpdateToast(float delta)
    {
        if (_toastRemaining <= 0f)
            return;
        _toastRemaining -= delta;
        if (_toastRemaining <= 0f)
            _toast = "";
    }

    private void DrawToast(Surface surface)
    {
        if (string.IsNullOrEmpty(_toast))
            return;
        int textWidth = _hintFont.MeasureText(_toast);
        int y = surface.Height - _hintFont.LineHeight - 8;
        _hintFont.DrawText(surface, _toast, (surface.Width - textWidth) / 2, y, Color.White);
    }

    protected override void OnUnload()
    {
        DisposeKeyboard();
        _haptics.Stop();
        DisposeFonts();
    }

    private void DisposeFonts()
    {
        _bodyFont?.Dispose();
        _titleFont?.Dispose();
        _brandFont?.Dispose();
        _bodyFont = null;
        _titleFont = null;
        _brandFont = null;

        // The modules must outlive every scalable font they support, so unload them after the fonts.
        _freeTypeOtModule?.Dispose();
        _fontFtModule?.Dispose();
        _fontModule?.Dispose();
        _freeTypeOtModule = null;
        _fontFtModule = null;
        _fontModule = null;

        // Reset the direct-draw fonts to the bitmap fallbacks so any remaining draw does not follow a
        // disposed pointer.
        _headerFont = new BitmapTextFont(3);
        _hintFont = new BitmapTextFont(2);
    }
}

internal static class Program
{
    private static void Main()
    {
        using (var app = new Game())
            app.Run();

        // Returning from here is reported to the platform as a fault and the user is shown the
        // box that says the application closed unexpectedly, even when everything went as
        // intended. The process is ended through the C library instead.
        ProcessExit.Exit();
    }
}
