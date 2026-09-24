// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpProspero.Platform;

/// <summary>USB hotplug event reported through a registered callback.</summary>
public enum UsbCallbackEvent : uint
{
    /// <summary>A USB mass-storage device was mounted.</summary>
    Mount = 1,

    /// <summary>A USB mass-storage device was unmounted.</summary>
    Unmount = 2,
}

/// <summary>A connected USB mass-storage device and where the system mounted it.</summary>
/// <param name="Id">The device id the system assigns it.</param>
/// <param name="MountPath">The path it is mounted at, for example <c>/mnt/usb0</c>, or empty.</param>
public readonly record struct UsbDevice(uint Id, string MountPath);

/// <summary>
/// Detailed information about a connected USB mass-storage device, returned by
/// <see cref="UsbStorage.GetDeviceInfo"/>. The underlying service struct is 824 bytes (0x338);
/// fields whose purpose has not been determined are exposed as <c>Reserved</c> properties so no
/// information is lost.
/// </summary>
/// <remarks>
/// The struct layout was recovered from the service module's <c>sceUsbStorageGetDeviceInfo</c>
/// function. It contains three 256-byte null-terminated string regions (vendor, product, serial)
/// separated by numeric fields, with a header and a trailing flags field whose raw value the service
/// masks with 0xd0 before writing.
/// </remarks>
public sealed class UsbDeviceInfo
{
    internal const int StructSize = 0x338; // 824 bytes.
    private const int StringFieldLength = 256;

    /// <summary>Volume size reported by the device, in bytes. At struct offset 0x000.</summary>
    public ulong VolumeSize { get; }

    /// <summary>Reserved 8-byte field at struct offset 0x008. Meaning not yet determined.</summary>
    public ulong Reserved0 { get; }

    /// <summary>Reserved 4-byte field at struct offset 0x010. Meaning not yet determined.</summary>
    public uint Reserved1 { get; }

    /// <summary>Reserved 2-byte field at struct offset 0x014. Meaning not yet determined.</summary>
    public ushort Reserved2 { get; }

    /// <summary>Vendor name reported by the device. At struct offset 0x016 (256 bytes).</summary>
    public string Vendor { get; }

    /// <summary>Reserved 8-byte field at struct offset 0x118. Meaning not yet determined.</summary>
    public ulong Reserved3 { get; }

    /// <summary>Product name reported by the device. At struct offset 0x120 (256 bytes).</summary>
    public string Product { get; }

    /// <summary>Reserved 8-byte field at struct offset 0x220. Meaning not yet determined.</summary>
    public ulong Reserved4 { get; }

    /// <summary>Serial number reported by the device, or empty when it does not provide one. At struct offset 0x228 (256 bytes).</summary>
    public string Serial { get; }

    /// <summary>Reserved 8-byte field at struct offset 0x328. Meaning not yet determined.</summary>
    public ulong Reserved5 { get; }

    /// <summary>
    /// Device flags at struct offset 0x330. The service masks the raw value with 0xd0 before writing,
    /// so only bits 4, 6 and 7 are populated.
    /// </summary>
    public ulong Flags { get; }

    private UsbDeviceInfo(ulong volumeSize, ulong reserved0, uint reserved1, ushort reserved2,
        string vendor, ulong reserved3, string product, ulong reserved4,
        string serial, ulong reserved5, ulong flags)
    {
        VolumeSize = volumeSize;
        Reserved0 = reserved0;
        Reserved1 = reserved1;
        Reserved2 = reserved2;
        Vendor = vendor;
        Reserved3 = reserved3;
        Product = product;
        Reserved4 = reserved4;
        Serial = serial;
        Reserved5 = reserved5;
        Flags = flags;
    }

    internal static unsafe UsbDeviceInfo FromNative(byte* data)
    {
        return new UsbDeviceInfo(
            volumeSize: *(ulong*)(data + 0x000),
            reserved0: *(ulong*)(data + 0x008),
            reserved1: *(uint*)(data + 0x010),
            reserved2: *(ushort*)(data + 0x014),
            vendor: ReadNullTerminated(data + 0x016, StringFieldLength),
            reserved3: *(ulong*)(data + 0x118),
            product: ReadNullTerminated(data + 0x120, StringFieldLength),
            reserved4: *(ulong*)(data + 0x220),
            serial: ReadNullTerminated(data + 0x228, StringFieldLength),
            reserved5: *(ulong*)(data + 0x328),
            flags: *(ulong*)(data + 0x330));
    }

    private static unsafe string ReadNullTerminated(byte* start, int maxLength)
    {
        int length = 0;
        while (length < maxLength && start[length] != 0)
            length++;
        return length == 0 ? string.Empty : Encoding.UTF8.GetString(start, length);
    }
}

/// <summary>
/// Finds connected USB mass-storage devices and the path each is mounted at, so a module can browse a
/// USB drive. Read the mount path, then read the files under it with the file APIs. Open it, list the
/// devices, dispose it.
/// </summary>
/// <remarks>
/// The service is not part of the module set a title links against, so it is loaded at run time and
/// its entry points are resolved by name. Reading a mounted path still depends on the process holding
/// the permission for it.
/// </remarks>
/// <example>
/// <code>
/// using var usb = UsbStorage.Open();
/// foreach (UsbDevice device in usb.ListDevices())
///     foreach (DirectoryEntry entry in FileSystem.EnumerateDirectory(device.MountPath))
///         Console.WriteLine(entry.Name);
/// </code>
/// </example>
public sealed unsafe class UsbStorage : IDisposable
{
    /// <summary>The module that carries the USB storage service.</summary>
    public const string ModulePath = "/system/common/lib/libSceUsbStorage.sprx";

    // The service reports at most eight devices; the buffer is sized above that.
    private const int MaxDevices = 16;
    private const int MountPathLength = 128;

    private readonly SystemLibrary _library;
    private readonly delegate* unmanaged<int> _term;
    private readonly delegate* unmanaged<uint*, int*, int> _getDeviceList;
    private readonly delegate* unmanaged<uint, byte*, int> _getMountPoint;
    private readonly delegate* unmanaged<uint, byte*, int, ulong, byte*, ulong*, void*, nuint, int> _requestMap;
    private readonly delegate* unmanaged<uint, byte*, int> _requestUnmap;
    private readonly delegate* unmanaged<uint, byte*, int> _getDeviceInfo;
    private readonly delegate* unmanaged<uint, nint, nint, int> _registerCallback;
    private readonly delegate* unmanaged<uint, nint, int> _unregisterCallback;

    // Callback state: a GCHandle keeps the managed Action alive while the service holds a reference to
    // the static native trampoline, and the function-pointer nint identifies the registration for
    // unregistering later.
    private GCHandle _callbackHandle;
    private nint _callbackFuncPtr;
    private bool _disposed;

    private UsbStorage(SystemLibrary library, delegate* unmanaged<int> term,
        delegate* unmanaged<uint*, int*, int> getDeviceList,
        delegate* unmanaged<uint, byte*, int> getMountPoint,
        delegate* unmanaged<uint, byte*, int, ulong, byte*, ulong*, void*, nuint, int> requestMap,
        delegate* unmanaged<uint, byte*, int> requestUnmap,
        delegate* unmanaged<uint, byte*, int> getDeviceInfo,
        delegate* unmanaged<uint, nint, nint, int> registerCallback,
        delegate* unmanaged<uint, nint, int> unregisterCallback)
    {
        _library = library;
        _term = term;
        _getDeviceList = getDeviceList;
        _getMountPoint = getMountPoint;
        _requestMap = requestMap;
        _requestUnmap = requestUnmap;
        _getDeviceInfo = getDeviceInfo;
        _registerCallback = registerCallback;
        _unregisterCallback = unregisterCallback;
    }

    /// <summary>
    /// The param struct the service passes to the registered callback. Layout confirmed from the
    /// intermediate callback dispatchers in the service module.
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct NativeCallbackParam
    {
        /// <summary>1 = mount, 2 = unmount.</summary>
        [FieldOffset(0)] public uint Event;
        /// <summary>The device id the system assigns to the device.</summary>
        [FieldOffset(4)] public uint DeviceId;
        /// <summary>Device flags (masked with 0xd0 by the dispatcher).</summary>
        [FieldOffset(8)] public ulong Flags;
    }

    /// <summary>
    /// Static trampoline that the service calls on mount/unmount events. The <paramref name="userData"/>
    /// carries a <see cref="GCHandle"/> to the managed <see cref="Action{T1, T2}"/>.
    /// </summary>
    [UnmanagedCallersOnly]
    private static void NativeCallback(NativeCallbackParam* param, nint userData)
    {
        // The callback runs on the automounter's IPC thread. An uncaught managed exception here would
        // crash the process, so the handler invocation is wrapped completely.
        try
        {
            if (userData == 0)
                return;
            var handle = GCHandle.FromIntPtr(userData);
            if (handle.Target is Action<UsbCallbackEvent, uint> action)
                action((UsbCallbackEvent)param->Event, param->DeviceId);
        }
        catch
        {
            // Swallowed: the managed handler is responsible for its own error handling.
        }
    }

    /// <summary>Loads the USB storage service and starts it.</summary>
    /// <exception cref="ProsperoException">The service could not be loaded or started.</exception>
    public static UsbStorage Open()
    {
        SystemLibrary library = SystemLibrary.Open(ModulePath);
        try
        {
            var initialize = (delegate* unmanaged<void*, int>)library.GetFunction("sceUsbStorageInit");
            var term = (delegate* unmanaged<int>)library.GetFunction("sceUsbStorageTerm");
            var getDeviceList = (delegate* unmanaged<uint*, int*, int>)library.GetFunction("sceUsbStorageGetDeviceList");
            var getMountPoint = (delegate* unmanaged<uint, byte*, int>)library.GetFunction("sceUsbStorageGetMountPointOfShellCore");
            var requestMap = (delegate* unmanaged<uint, byte*, int, ulong, byte*, ulong*, void*, nuint, int>)library.GetFunction("sceUsbStorageRequestMap");
            var requestUnmap = (delegate* unmanaged<uint, byte*, int>)library.GetFunction("sceUsbStorageRequestUnmap");
            var getDeviceInfo = (delegate* unmanaged<uint, byte*, int>)library.GetFunction("sceUsbStorageGetDeviceInfo");
            var registerCallback = (delegate* unmanaged<uint, nint, nint, int>)library.GetFunction("sceUsbStorageRegisterCallback");
            var unregisterCallback = (delegate* unmanaged<uint, nint, int>)library.GetFunction("sceUsbStorageUnregisterCallback");

            // The parameter is a thread attribute for the service's own thread; null takes the defaults.
            SceResult.ThrowIfFailed(initialize(null), "sceUsbStorageInit");
            return new UsbStorage(library, term, getDeviceList, getMountPoint, requestMap, requestUnmap,
                getDeviceInfo, registerCallback, unregisterCallback);
        }
        catch
        {
            library.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Lists the connected USB mass-storage devices and where each is mounted. An empty list means no
    /// device is connected.
    /// </summary>
    /// <exception cref="ProsperoException">The device list could not be read.</exception>
    public IReadOnlyList<UsbDevice> ListDevices()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        uint* ids = stackalloc uint[MaxDevices];
        int count = 0;
        SceResult.ThrowIfFailed(_getDeviceList(ids, &count), "sceUsbStorageGetDeviceList");
        if (count < 0)
            count = 0;
        else if (count > MaxDevices)
            count = MaxDevices;

        var devices = new List<UsbDevice>(count);
        byte* path = stackalloc byte[MountPathLength];
        for (int i = 0; i < count; i++)
        {
            new Span<byte>(path, MountPathLength).Clear();
            int rc = _getMountPoint(ids[i], path);
            string mount = rc == 0 ? ReadUtf8(path, MountPathLength) : string.Empty;
            devices.Add(new UsbDevice(ids[i], mount));
        }
        return devices;
    }

    /// <summary>
    /// Queries the service for detailed information about the device with the given
    /// <paramref name="deviceId"/>. Returns <see langword="null"/> when the call fails, which
    /// typically means the device is not connected or the service rejected the query.
    /// </summary>
    /// <param name="deviceId">The device id from <see cref="ListDevices"/>.</param>
    public UsbDeviceInfo? GetDeviceInfo(uint deviceId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        byte* buf = stackalloc byte[UsbDeviceInfo.StructSize];
        new Span<byte>(buf, UsbDeviceInfo.StructSize).Clear();

        int rc = _getDeviceInfo(deviceId, buf);
        if (rc < 0)
            return null;

        return UsbDeviceInfo.FromNative(buf);
    }

    /// <summary>
    /// Registers a callback that the service invokes on USB mount and unmount events. Only one callback
    /// can be active at a time on this instance; dispose the returned token to unregister it before
    /// registering another.
    /// </summary>
    /// <param name="handler">
    /// Called with the event type (<see cref="UsbCallbackEvent.Mount"/> or
    /// <see cref="UsbCallbackEvent.Unmount"/>) and the device id. The handler runs on the service's
    /// own IPC thread, so it should return quickly and not throw.
    /// </param>
    /// <returns>A token that unregisters the callback when disposed.</returns>
    /// <exception cref="InvalidOperationException">A callback is already registered on this instance.</exception>
    /// <exception cref="ProsperoException">The service rejected the registration.</exception>
    public IDisposable RegisterCallback(Action<UsbCallbackEvent, uint> handler)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(handler);

        if (_callbackHandle.IsAllocated)
            throw new InvalidOperationException(
                "A callback is already registered. Dispose the previous token first.");

        var gcHandle = GCHandle.Alloc(handler);
        nint userData = GCHandle.ToIntPtr(gcHandle);
        nint funcPtr = (nint)(delegate* unmanaged<NativeCallbackParam*, nint, void>)&NativeCallback;

        // Register for both mount (1) and unmount (2) events so the handler receives everything.
        int rcMount = _registerCallback(1, funcPtr, userData);
        if (rcMount < 0)
        {
            gcHandle.Free();
            SceResult.ThrowIfFailed(rcMount, "sceUsbStorageRegisterCallback(Mount)");
        }

        int rcUnmount = _registerCallback(2, funcPtr, userData);
        if (rcUnmount < 0)
        {
            // Mount succeeded but unmount failed; roll back the mount registration.
            _unregisterCallback(1, funcPtr);
            gcHandle.Free();
            SceResult.ThrowIfFailed(rcUnmount, "sceUsbStorageRegisterCallback(Unmount)");
        }

        _callbackHandle = gcHandle;
        _callbackFuncPtr = funcPtr;
        return new CallbackToken(this);
    }

    /// <summary>
    /// Asks the system to map a connected USB mass-storage device at the given directory path so it
    /// appears in <see cref="ListDevices"/>. On success the mount point the system assigned and a mount
    /// identifier are returned. The system also maps a device on its own, so this is needed only to
    /// request a mapping explicitly.
    /// </summary>
    /// <param name="deviceId">The device id from <see cref="ListDevices"/>.</param>
    /// <param name="directory">The directory path to mount on the device, for example <c>"/"</c>.</param>
    /// <param name="mountId">Receives the mount identifier the system assigned.</param>
    /// <param name="flags">Mount flags; zero for the defaults.</param>
    /// <param name="volSize">Volume size hint; zero lets the system decide.</param>
    /// <returns>The mount point path the system assigned, for example <c>/mnt/usb0</c>.</returns>
    /// <exception cref="ProsperoException">The request was rejected.</exception>
    public string RequestMap(uint deviceId, string directory, out ulong mountId,
        int flags = 0, ulong volSize = 0)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(directory);

        int dirLen = Encoding.UTF8.GetByteCount(directory);
        byte* dir = stackalloc byte[dirLen + 1];
        Encoding.UTF8.GetBytes(directory, new Span<byte>(dir, dirLen));
        dir[dirLen] = 0;

        byte* mountBuf = stackalloc byte[MountPathLength];
        new Span<byte>(mountBuf, MountPathLength).Clear();
        ulong mid = 0;

        SceResult.ThrowIfFailed(
            _requestMap(deviceId, dir, flags, volSize, mountBuf, &mid, null, 0),
            "sceUsbStorageRequestMap");

        mountId = mid;
        return ReadUtf8(mountBuf, MountPathLength);
    }

    /// <summary>Unmaps <paramref name="device"/> from its mount path.</summary>
    /// <exception cref="ProsperoException">The request was rejected.</exception>
    public void RequestUnmap(UsbDevice device)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrEmpty(device.MountPath);

        int count = Encoding.UTF8.GetByteCount(device.MountPath);
        byte* directory = stackalloc byte[count + 1];
        Encoding.UTF8.GetBytes(device.MountPath, new Span<byte>(directory, count));
        directory[count] = 0;
        SceResult.ThrowIfFailed(_requestUnmap(device.Id, directory), "sceUsbStorageRequestUnmap");
    }

    /// <summary>Stops the service and unloads the module. Any registered callback is unregistered first.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        UnregisterCallbackInternal();
        _term();
        _library.Dispose();
    }

    private void UnregisterCallbackInternal()
    {
        if (!_callbackHandle.IsAllocated)
            return;

        _unregisterCallback(1, _callbackFuncPtr);
        _unregisterCallback(2, _callbackFuncPtr);

        _callbackHandle.Free();
        _callbackHandle = default;
        _callbackFuncPtr = 0;
    }

    private static string ReadUtf8(byte* start, int maxLength)
    {
        int length = 0;
        while (length < maxLength && start[length] != 0)
            length++;
        return length == 0 ? string.Empty : Encoding.UTF8.GetString(start, length);
    }

    /// <summary>
    /// Disposable token returned by <see cref="RegisterCallback"/>. Disposing it unregisters the
    /// callback from the service.
    /// </summary>
    private sealed class CallbackToken : IDisposable
    {
        private UsbStorage? _owner;

        internal CallbackToken(UsbStorage owner) => _owner = owner;

        public void Dispose()
        {
            UsbStorage? owner = _owner;
            if (owner is null)
                return;
            _owner = null;
            owner.UnregisterCallbackInternal();
        }
    }
}

/// <summary>The codes the USB storage service returns when it refuses a request.</summary>
public static class SceUsbStorageError
{
    /// <summary>An argument was outside what the call accepts, or a required pointer was null.</summary>
    public const int InvalidArg = unchecked((int)0x80f40002);

    /// <summary>The IPC client session is not valid.</summary>
    public const int ClientNotValid = unchecked((int)0x80f40009);

    /// <summary>The number of active mappings has reached the system limit.</summary>
    public const int MapLimit = unchecked((int)0x80f40015);
}
