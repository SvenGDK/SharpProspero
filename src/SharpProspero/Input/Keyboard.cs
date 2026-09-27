// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Keyboard;
using SharpProspero.Platform;
using System;
using Native = SharpProspero.Interop.Keyboard.Keyboard;

namespace SharpProspero.Input;

/// <summary>The keys held on a keyboard at one moment, plus the modifiers.</summary>
public readonly ref struct KeyboardState
{
    private readonly ReadOnlySpan<ushort> _keys;

    internal KeyboardState(bool connected, KeyModifier modifiers, KeyboardLed leds, ReadOnlySpan<ushort> keys)
    {
        Connected = connected;
        Modifiers = modifiers;
        Leds = leds;
        _keys = keys;
    }

    /// <summary>True while a keyboard is connected.</summary>
    public bool Connected { get; }

    /// <summary>The modifier keys held.</summary>
    public KeyModifier Modifiers { get; }

    /// <summary>
    /// The lock keys that are on. Turning a key press into a character needs these as well as the
    /// modifiers: caps lock decides the case of a letter and num lock decides what the number pad
    /// produces, and neither is a key that is held.
    /// </summary>
    public KeyboardLed Leds { get; }

    /// <summary>The USB HID usage codes of the keys held, newest last. Empty when none are held.</summary>
    public ReadOnlySpan<ushort> Keys => _keys;

    /// <summary>True when <paramref name="usageCode"/> is among the keys held. Zero is not a key.</summary>
    public bool IsKeyDown(int usageCode)
    {
        if (usageCode == 0)
            return false;
        foreach (ushort key in _keys)
        {
            if (key == usageCode)
                return true;
        }
        return false;
    }
}

/// <summary>
/// A USB keyboard. Open it for a user at startup, read its state each frame, and dispose it at
/// shutdown. This is the input a file explorer or a browser wants beyond the controller.
/// </summary>
/// <example>
/// <code>
/// using var keyboard = Keyboard.Open();
/// KeyboardState state = keyboard.Read();
/// if (state.Modifiers.HasFlag(KeyModifier.LeftControl)) { }
/// </code>
/// </example>
public sealed unsafe class Keyboard : IDisposable
{
    private readonly int _handle;
    private bool _disposed;

    private Keyboard(int handle) => _handle = handle;

    /// <summary>
    /// Starts the keyboard service and opens the keyboard for <paramref name="userId"/> (the
    /// signed-in user by default).
    /// </summary>
    /// <remarks>
    /// The device belongs to a signed-in user. The platform registers the handle against the user it
    /// was opened for and routes that user's samples to it, so a handle opened for the system user is
    /// accepted and then never delivers anything.
    /// </remarks>
    /// <exception cref="ProsperoException">
    /// The user could not be read, or the service or the keyboard could not be opened.
    /// </exception>
    public static Keyboard Open(int userId = SceUser.Invalid)
    {
        if (userId == SceUser.Invalid)
            userId = Users.InitialUserId;
        SceResult.ThrowIfFailed(Native.sceKeyboardInit(), nameof(Native.sceKeyboardInit));
        int handle = Native.sceKeyboardOpen(userId, Native.PortTypeStandard, 0, null);
        SceResult.ThrowIfFailed(handle, nameof(Native.sceKeyboardOpen));
        return new Keyboard(handle);
    }

    /// <summary>Reads the keys held right now.</summary>
    /// <remarks>The returned state borrows a buffer valid until the next read; copy what you keep.</remarks>
    public KeyboardState Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceKeyboardData data;
        if (SceResult.Failed(Native.sceKeyboardReadState(_handle, &data)))
            return new KeyboardState(false, KeyModifier.None, KeyboardLed.None, []);

        // A sample marked Intercepted means the system took the keyboard for its own UI (an on-
        // screen IME, a system dialog). The keys, modifiers and LEDs in that sample are meant for
        // the system, not for the application; forwarding them would let a user typing into the
        // IME hit shortcuts in the app behind. Report an empty state so the app sees the keyboard
        // as idle for the duration of the interception.
        if (data.Intercepted)
            return new KeyboardState(data.Connected, KeyModifier.None, KeyboardLed.None, []);

        // The count that comes back is never less than one, even with nothing held and even with no
        // keyboard there, and the entry it counts is then a code of zero - which is not a key. Copying
        // it verbatim meant the set of held keys was never empty and asking whether key zero was held
        // always answered yes. Only real codes are carried.
        int count = Math.Clamp(data.Length, 0, Native.MaxKeyCodes);
        int held = 0;
        for (int i = 0; i < count; i++)
            if (data.KeyCode[i] != 0)
                held++;

        var keys = new ushort[held];
        for (int i = 0, k = 0; i < count; i++)
            if (data.KeyCode[i] != 0)
                keys[k++] = data.KeyCode[i];
        return new KeyboardState(data.Connected, data.ModifierKey, data.Led, keys);
    }

    /// <summary>Closes the keyboard.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Native.sceKeyboardClose(_handle);
    }
}
