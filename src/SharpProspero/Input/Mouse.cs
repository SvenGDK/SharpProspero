// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using SharpProspero.Interop.Mouse;
using SharpProspero.Platform;
using System;
using Native = SharpProspero.Interop.Mouse.Mouse;

namespace SharpProspero.Input;

/// <summary>The mouse's movement and buttons at one moment.</summary>
public readonly record struct MouseState(bool Connected, MouseButton Buttons, int DeltaX, int DeltaY, int Wheel, int Tilt)
{
    /// <summary>True when <paramref name="button"/> is held.</summary>
    public bool IsButtonDown(MouseButton button) => (Buttons & button) != 0;
}

/// <summary>
/// A USB mouse. Open it for a user at startup, read its movement each frame, and dispose it at
/// shutdown. The movement is relative: it is how far the mouse moved since the last read, which an
/// application accumulates into a cursor position of its own.
/// </summary>
/// <example>
/// <code>
/// using var mouse = Mouse.Open();
/// MouseState state = mouse.Read();
/// cursorX += state.DeltaX;
/// if (state.IsButtonDown(MouseButton.Primary)) { }
/// </code>
/// </example>
public sealed unsafe class Mouse : IDisposable
{
    private readonly int _handle;
    private bool _disposed;
    // The last reading the device actually produced, so a still mouse keeps reporting what it holds.
    private MouseState _last = new(false, MouseButton.None, 0, 0, 0, 0);

    private Mouse(int handle) => _handle = handle;

    /// <summary>
    /// Starts the mouse service and opens the mouse for <paramref name="userId"/> (the signed-in user
    /// by default). Every mouse is merged into one handle.
    /// </summary>
    /// <remarks>
    /// The device belongs to a signed-in user. The platform registers the handle against the user it
    /// was opened for and routes that user's samples to it, so a handle opened for the system user is
    /// accepted and then never delivers anything.
    /// </remarks>
    /// <exception cref="ProsperoException">
    /// The user could not be read, or the service or the mouse could not be opened.
    /// </exception>
    public static Mouse Open(int userId = SceUser.Invalid)
    {
        if (userId == SceUser.Invalid)
            userId = Users.InitialUserId;
        SceResult.ThrowIfFailed(Native.sceMouseInit(), nameof(Native.sceMouseInit));

        var param = new SceMouseOpenParam { BehaviorFlag = Native.OpenMerged };
        int handle = Native.sceMouseOpen(userId, 0, 0, &param);
        SceResult.ThrowIfFailed(handle, nameof(Native.sceMouseOpen));
        return new Mouse(handle);
    }

    /// <summary>
    /// Reads the latest movement and buttons. A mouse that has not moved since the last read reports
    /// its buttons unchanged and no movement, rather than reporting itself absent.
    /// </summary>
    public MouseState Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        SceMouseData data;
        int read = Native.sceMouseRead(_handle, &data, 1);

        // How many readings were available, not whether the mouse is there. None available means the
        // mouse has not moved and no button has changed since the last read, which is what a still
        // mouse does for as long as it is still - and it leaves the buffer untouched, so there is
        // nothing to read out of it. Treating that as absent made the pointer vanish whenever it
        // stopped, and made a held button read as released.
        if (read == 0)
            return _last with { DeltaX = 0, DeltaY = 0, Wheel = 0, Tilt = 0 };
        if (read < 0)
            return _last = new MouseState(false, MouseButton.None, 0, 0, 0, 0);

        // A sample marked Intercepted is the system driving the pointer for its own UI. Its
        // deltas, buttons, wheel and tilt are meant for the system, not for the application; the
        // cached last-real-sample is what the app should keep seeing until real samples resume.
        // Do not update _last, and never return the intercepted sample's state.
        if ((data.Buttons & MouseButton.Intercepted) != 0)
            return _last with { DeltaX = 0, DeltaY = 0, Wheel = 0, Tilt = 0 };

        return _last = new MouseState(
            data.Connected, data.Buttons, data.XAxis, data.YAxis, data.Wheel, data.Tilt);
    }

    /// <summary>Closes the mouse.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Native.sceMouseClose(_handle);
    }
}
